#!/usr/bin/env python3
"""Generate a weekly, client-facing Security Operations Report from Jira on demand.

Pulls incident (Security Alert + Security Incident) and Vulnerability data from a
client's SECOPS Jira project, reads the manually-added MTTD / MTTR custom fields,
and renders a self-contained HTML report (print to PDF for the client copy).
Device / endpoint / availability data is not in Jira — pass it via ``--supplemental``.

    python generate_report.py --project-key NSO --client Neuro \
        --environment Production --tenant neuro.athenasecuritygrp.com \
        --week-start monday --out reports/neuro.html

    python generate_report.py --sample --out reports/sample.html   # no Jira needed
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import webbrowser
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

try:  # only needed for live Jira runs, not for --sample
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

try:
    from dotenv import load_dotenv
except ImportError:  # optional
    def load_dotenv(*_a, **_k):  # type: ignore
        return False

import render

INC_TYPES = 'issuetype in ("Security Alert", "Security Incident")'
VULN_TYPE = 'issuetype = Vulnerability'
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
SEV_ORDER = ("Critical", "High", "Medium", "Low")


def _env(name: str, default: str) -> str:
    return (os.getenv(name) or default).strip().strip('"')


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().strip('"').lower() in {"1", "true", "yes", "y", "on"}


def _configured_incident_labels(label_to_values: Dict[str, List[str]]) -> List[str]:
    raw = _env("REPORT_INCIDENT_SEVERITIES", "CRITICAL,HIGH")
    if raw.strip().lower() in {"*", "all"}:
        return [label for label in SEV_ORDER if label in label_to_values]
    wanted = {part.strip().upper() for part in re.split(r"[,\s]+", raw) if part.strip()}
    labels = [label for label in SEV_ORDER if label in label_to_values and label.upper() in wanted]
    return labels or [label for label in ("Critical", "High") if label in label_to_values]


def _configured_vuln_labels(label_to_values: Dict[str, List[str]]) -> List[str]:
    # REPORT_VULN_SEVERITIES, falling back to REPORT_INCIDENT_SEVERITIES; if neither set, show all.
    raw = (os.getenv("REPORT_VULN_SEVERITIES") or os.getenv("REPORT_INCIDENT_SEVERITIES") or "").strip().strip('"')
    if not raw or raw.lower() in {"*", "all"}:
        return [label for label in SEV_ORDER if label in label_to_values]
    wanted = {part.strip().upper() for part in re.split(r"[,\s]+", raw) if part.strip()}
    labels = [label for label in SEV_ORDER if label in label_to_values and label.upper() in wanted]
    return labels or [label for label in SEV_ORDER if label in label_to_values]


def section_enablement() -> Dict[str, bool]:
    return {
        "device": _env_bool("REPORT_ENABLE_DEVICE_MANAGEMENT", True),
        "endpoint": _env_bool("REPORT_ENABLE_ENDPOINT_MANAGEMENT", True),
        "vuln": _env_bool("REPORT_ENABLE_VULNERABILITY_STATUS", True),
        "availability": _env_bool("REPORT_ENABLE_SYSTEM_AVAILABILITY", True),
    }


def _sev_maps(pairs: Sequence[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """pairs = [(label, sev_value)] in priority order (Critical first).
    Returns (value->label, label->[values]). First label to claim a value wins."""
    value_to_label: Dict[str, str] = {}
    label_to_values: Dict[str, List[str]] = {}
    for label, val in pairs:
        if not val:
            continue
        value_to_label.setdefault(val, label)
        label_to_values.setdefault(label, [])
        if val not in label_to_values[label]:
            label_to_values[label].append(val)
    return value_to_label, label_to_values


def _sev_display(value_to_label: Dict[str, str]) -> Tuple[List[str], Dict[str, List[str]]]:
    """Distinct labels actually in use, in severity order, each with its Sev values."""
    present = set(value_to_label.values())
    labels = [lab for lab in SEV_ORDER if lab in present]
    return labels, {lab: [v for v, l in value_to_label.items() if l == lab] for lab in labels}


def incident_sev_maps() -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Alerts/incidents — mirrors Palace's JIRA_SEVERITY_*_VALUE. Sev-1 = confirmed compromise (Critical).
    Default Athena/SECOPS mapping: Critical=Sev-2, High=Sev-3, Medium/Low=Sev-4."""
    return _sev_maps([
        ("Critical", _env("JIRA_SEVERITY_CONFIRMED_VALUE", "Sev-1")),
        ("Critical", _env("JIRA_SEVERITY_CRITICAL_VALUE", "Sev-2")),
        ("High", _env("JIRA_SEVERITY_HIGH_VALUE", "Sev-3")),
        ("Medium", _env("JIRA_SEVERITY_MEDIUM_VALUE", "Sev-4")),
        ("Low", _env("JIRA_SEVERITY_LOW_VALUE", "Sev-4")),
    ])


def vulnerability_sev_maps() -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Vulnerabilities — Snyk import mapping (natural): Critical=Sev-1 … Low=Sev-4."""
    return _sev_maps([
        ("Critical", _env("JIRA_VULN_SEVERITY_CRITICAL_VALUE", "Sev-1")),
        ("High", _env("JIRA_VULN_SEVERITY_HIGH_VALUE", "Sev-2")),
        ("Medium", _env("JIRA_VULN_SEVERITY_MEDIUM_VALUE", "Sev-3")),
        ("Low", _env("JIRA_VULN_SEVERITY_LOW_VALUE", "Sev-4")),
    ])


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Jira client
# --------------------------------------------------------------------------- #

class JiraError(RuntimeError):
    pass


class JiraClient:
    def __init__(self, site_url: str, email: str, token: str):
        if requests is None:
            raise JiraError("The 'requests' package is required for live Jira runs. Run: pip install -r requirements.txt")
        self.base = site_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (email, token)
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._fields: Optional[List[Dict[str, Any]]] = None

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = self.session.request(method, self.base + path, timeout=90, **kw)
        if r.status_code not in (200, 201):
            raise JiraError(f"{method} {path} -> HTTP {r.status_code}\n{r.text[:800]}")
        return r.json() if r.content else None

    def fields(self) -> List[Dict[str, Any]]:
        if self._fields is None:
            self._fields = self._req("GET", "/rest/api/3/field")
        return self._fields

    def field_id(self, name: str) -> Optional[str]:
        if name.startswith("customfield_") or name in ("created", "resolutiondate", "status", "summary", "issuetype", "components", "labels"):
            return name
        want = name.strip().lower()
        for f in self.fields():
            if f.get("name", "").strip().lower() == want:
                return f["id"]
        return None

    def count(self, jql: str) -> int:
        try:
            data = self._req("POST", "/rest/api/3/search/approximate-count", json={"jql": jql})
            return int(data.get("count", 0))
        except JiraError:
            data = self._req("GET", "/rest/api/3/search", params={"jql": jql, "maxResults": 0})
            return int(data.get("total", 0))

    def search(self, jql: str, fields: Sequence[str], limit: int = 1000) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        token: Optional[str] = None
        while len(out) < limit:
            body = {"jql": jql, "fields": list(fields), "maxResults": min(100, limit - len(out))}
            if token:
                body["nextPageToken"] = token
            try:
                data = self._req("POST", "/rest/api/3/search/jql", json=body)
            except JiraError:
                data = self._req("GET", "/rest/api/3/search",
                                 params={"jql": jql, "fields": ",".join(fields), "maxResults": min(100, limit - len(out)), "startAt": len(out)})
            out.extend(data.get("issues", []))
            token = data.get("nextPageToken")
            if data.get("isLast", True) or not data.get("issues") or (not token and "startAt" not in data):
                break
            if "startAt" in data and len(out) >= data.get("total", 0):
                break
        return out[:limit]


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

def parse_jira_dt(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+0000"
    m = re.search(r"([+-]\d{2})(\d{2})$", v)
    if m and ":" not in v[-6:]:
        v = v[:-5] + m.group(1) + ":" + m.group(2)
    try:
        return dt.datetime.fromisoformat(v)
    except ValueError:
        try:
            return dt.datetime.fromisoformat(v.split(".")[0])
        except ValueError:
            return None


def coerce_seconds(value: Any, unit: str) -> Optional[float]:
    """Interpret an MTTR/MTTD field value as seconds."""
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        value = value.get("value") or value.get("name") or ""
    if isinstance(value, (int, float)):
        return float(value) * {"seconds": 1, "minutes": 60, "hours": 3600}.get(unit, 60)
    s = str(value).strip()
    iso = re.fullmatch(r"P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?", s, re.IGNORECASE)
    if iso and any(iso.groups()):
        d, h, m, sec = (int(g or 0) for g in iso.groups())
        return ((d * 24 + h) * 60 + m) * 60 + sec
    total, found = 0.0, False
    for num, u in re.findall(r"(\d+(?:\.\d+)?)\s*([dhms])", s, re.IGNORECASE):
        found = True
        total += float(num) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[u.lower()]
    if found:
        return total
    try:
        return float(s) * {"seconds": 1, "minutes": 60, "hours": 3600}.get(unit, 60)
    except ValueError:
        return None


def fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = int(round(seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m"
    return "<1m"


def fmt_age(created: Optional[dt.datetime], now: dt.datetime) -> str:
    if not created:
        return "—"
    secs = (now - created).total_seconds()
    d, rem = divmod(int(secs), 86400)
    h, _ = divmod(rem, 3600)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h"
    return f"{max(int(secs // 60), 1)}m"


def delta_html(cur: Optional[float], prev: Optional[float], *, favorable: Optional[str], unit: str = "") -> str:
    """favorable: 'up' | 'down' | None. Returns the delta span '... vs last week'."""
    if cur is None or prev is None:
        return "vs last week"
    diff = cur - prev
    if diff == 0:
        return "no change vs last week"
    arrow = "▲" if diff > 0 else "▼"
    mag = abs(diff)
    mag_s = f"{mag:g}{unit}" if unit else f"{int(mag):,}"
    cls = ""
    if favorable == "up":
        cls = "up" if diff > 0 else "down"
    elif favorable == "down":
        cls = "up" if diff < 0 else "down"
    span = f'<b class="{cls}">{arrow} {mag_s}</b>' if cls else f"<b>{arrow} {mag_s}</b>"
    return f"{span} vs last week"


# --------------------------------------------------------------------------- #
# Week window
# --------------------------------------------------------------------------- #

def week_window(anchor: dt.date, week_start: str) -> Tuple[dt.date, dt.date]:
    target = 6 if week_start.lower().startswith("sun") else 0  # Mon=0 .. Sun=6
    offset = (anchor.weekday() - target) % 7
    start = anchor - dt.timedelta(days=offset)
    return start, start + dt.timedelta(days=7)


def d(day: dt.date) -> str:
    return day.strftime("%Y-%m-%d")


def strip_leading_zero(text: str) -> str:
    return re.sub(r"\b0(\d)", r"\1", text)


def period_label(start: dt.date, end: dt.date) -> str:
    last = end - dt.timedelta(days=1)
    return strip_leading_zero(f"{start:%a %d %b} – {last:%a %d %b %Y}")


# --------------------------------------------------------------------------- #
# Jira report builder
# --------------------------------------------------------------------------- #

def build_from_jira(cli: JiraClient, args: argparse.Namespace) -> Dict[str, Any]:
    key = args.project_key
    now = dt.datetime.now(dt.timezone.utc)
    anchor = dt.date.fromisoformat(args.week_of) if args.week_of else (now.date() - dt.timedelta(days=7))
    start, end = week_window(anchor, args.week_start)
    p_start, p_end = start - dt.timedelta(days=7), start  # prior week

    sev_field = cli.field_id(args.severity_field) or "Severity"
    mttr_field = cli.field_id(args.mttr_field)
    mttd_field = cli.field_id(args.mttd_field)
    itime_field = cli.field_id(args.incident_time_field)
    log(f"Fields: severity={sev_field} mttr={mttr_field} mttd={mttd_field} incident_time={itime_field}")

    inc_v2l, inc_all_label_values = incident_sev_maps()
    inc_labels, inc_label_values = _sev_display(inc_v2l)
    inc_filter_labels = _configured_incident_labels(inc_all_label_values)
    inc_filter_values = [value for label in inc_filter_labels for value in inc_all_label_values.get(label, [])]
    inc_labels = [label for label in inc_labels if any(value in inc_filter_values for value in inc_label_values[label])]
    vuln_v2l, vuln_all_label_values = vulnerability_sev_maps()
    vuln_labels, vuln_label_values = _sev_display(vuln_v2l)
    vuln_filter_labels = _configured_vuln_labels(vuln_all_label_values)
    vuln_filter_values = [value for label in vuln_filter_labels for value in vuln_all_label_values.get(label, [])]
    vuln_labels = [label for label in vuln_labels if any(value in vuln_filter_values for value in vuln_label_values[label])]
    log(f"Incident severities: {inc_label_values} · Vulnerability severities: {vuln_label_values}")
    log(f"Incident filter: {', '.join(inc_filter_labels)} · Vulnerability filter: {', '.join(vuln_filter_labels)}")

    def sev_in(values: Sequence[str]) -> str:
        return f'"{args.severity_field}" in (' + ", ".join(f'"{v}"' for v in values) + ")"

    def scoped(*clauses: str) -> str:
        return " AND ".join([f"project = {key}", *clauses])

    def incidents_only(jql: str) -> str:
        return jql + " AND " + sev_in(inc_filter_values)

    def opened(types: str, s: dt.date, e: dt.date) -> str:
        return scoped(types, f'created >= "{d(s)}"', f'created < "{d(e)}"')

    def closed(types: str, s: dt.date, e: dt.date) -> str:
        return scoped(types, f'resolutiondate >= "{d(s)}"', f'resolutiondate < "{d(e)}"')

    def open_at(types: str, e: dt.date) -> str:
        return scoped(types, f'created < "{d(e)}"', f'(resolutiondate is EMPTY OR resolutiondate >= "{d(e)}")')

    # ---- exec counts ----
    opened_n = cli.count(incidents_only(opened(INC_TYPES, start, end)))
    closed_n = cli.count(incidents_only(closed(INC_TYPES, start, end)))
    open_n = cli.count(incidents_only(open_at(INC_TYPES, end)))
    p_opened, p_closed, p_open = (cli.count(incidents_only(opened(INC_TYPES, p_start, p_end))),
                                  cli.count(incidents_only(closed(INC_TYPES, p_start, p_end))),
                                  cli.count(incidents_only(open_at(INC_TYPES, p_start))))

    # ---- severity of opened this week ----
    inc_sev = [(label, cli.count(opened(INC_TYPES, start, end) + " AND " + sev_in(inc_label_values[label]))) for label in inc_labels]

    # ---- MTTD / MTTR (Jira fields, fallback to timestamps) ----
    def avg_metric(jql: str, field_id: Optional[str], kind: str) -> Optional[float]:
        want = [f for f in ["created", "resolutiondate", field_id, itime_field] if f]
        issues = cli.search(jql, want, limit=2000)
        vals: List[float] = []
        for it in issues:
            f = it.get("fields", {})
            sec = coerce_seconds(f.get(field_id), args.duration_unit) if field_id else None
            if sec is None:  # fallback compute
                created = parse_jira_dt(f.get("created"))
                if kind == "mttr":
                    resolved = parse_jira_dt(f.get("resolutiondate"))
                    sec = (resolved - created).total_seconds() if created and resolved else None
                else:  # mttd
                    itime = parse_jira_dt(f.get(itime_field)) if itime_field else None
                    sec = (created - itime).total_seconds() if created and itime else None
            if sec is not None and sec >= 0:
                vals.append(sec)
        return sum(vals) / len(vals) if vals else None

    mttr = avg_metric(incidents_only(closed(INC_TYPES, start, end)), mttr_field, "mttr")
    mttd = avg_metric(incidents_only(opened(INC_TYPES, start, end)), mttd_field, "mttd")
    p_mttr = avg_metric(incidents_only(closed(INC_TYPES, p_start, p_end)), mttr_field, "mttr")
    p_mttd = avg_metric(incidents_only(opened(INC_TYPES, p_start, p_end)), mttd_field, "mttd")

    # ---- 6-week trend ----
    trend = []
    for i in range(6):
        ws = start - dt.timedelta(days=7 * (5 - i))
        we = ws + dt.timedelta(days=7)
        trend.append({
            "label": "This wk" if i == 5 else f"W-{5 - i}",
            "opened": cli.count(incidents_only(opened(INC_TYPES, ws, we))),
            "closed": cli.count(incidents_only(closed(INC_TYPES, ws, we))),
            "open": cli.count(incidents_only(open_at(INC_TYPES, we))),
        })

    # ---- severity over time (opened per week by severity) ----
    sev_trend = []
    for i in range(6):
        ws = start - dt.timedelta(days=7 * (5 - i))
        we = ws + dt.timedelta(days=7)
        row: Dict[str, Any] = {"label": "This wk" if i == 5 else f"W-{5 - i}"}
        for label in inc_labels:
            row[label] = cli.count(opened(INC_TYPES, ws, we) + " AND " + sev_in(inc_label_values[label]))
        sev_trend.append(row)

    # ---- open incidents detail ----
    src_field = cli.field_id(args.source_field) if args.source_field not in ("components", "labels") else args.source_field
    det_fields = ["summary", "issuetype", "status", "created", "components", "labels", sev_field]
    if src_field and src_field not in det_fields:
        det_fields.append(src_field)
    open_issues = cli.search(
        incidents_only(scoped(INC_TYPES, "statusCategory != Done", "resolution is EMPTY")) + f' ORDER BY "{args.severity_field}" ASC, created ASC',
        det_fields, limit=args.max_open_rows)

    def source_of(f: Dict[str, Any]) -> str:
        if args.source_field == "components":
            comps = f.get("components") or []
            return comps[0]["name"] if comps else "—"
        if args.source_field == "labels":
            labs = f.get("labels") or []
            return labs[0] if labs else "—"
        val = f.get(src_field) if src_field else None
        if isinstance(val, dict):
            val = val.get("value") or val.get("name")
        return val or "—"

    def sev_label(f: Dict[str, Any]) -> Tuple[str, str]:
        raw = f.get(sev_field)
        raw = raw.get("value") if isinstance(raw, dict) else raw
        label = inc_v2l.get(raw) or (inc_labels[-1] if inc_labels else "Medium")
        return label, render.SEV_CLASS[label]

    open_rows = []
    for it in open_issues:
        f = it.get("fields", {})
        lbl, cls = sev_label(f)
        created = parse_jira_dt(f.get("created"))
        open_rows.append({
            "ref": it["key"], "ref_url": f"{cli.base}/browse/{it['key']}",
            "type": (f.get("issuetype") or {}).get("name", "").replace("Security ", ""),
            "sev": lbl, "sev_class": cls,
            "summary": f.get("summary", ""), "source": source_of(f),
            "opened": strip_leading_zero(created.strftime("%d %b %H:%M")) if created else "—",
            "age": fmt_age(created, now), "status": (f.get("status") or {}).get("name", ""),
        })

    # ---- closed selected ----
    closed_fields = ["summary", "issuetype", sev_field] + ([mttr_field] if mttr_field else []) + ["created", "resolutiondate", "components", "labels"]
    closed_issues = cli.search(
        incidents_only(closed(INC_TYPES, start, end)) + f' ORDER BY "{args.severity_field}" ASC, resolutiondate DESC',
        closed_fields, limit=args.max_closed_rows)
    closed_rows = []
    for it in closed_issues:
        f = it.get("fields", {})
        lbl, cls = sev_label(f)
        sec = coerce_seconds(f.get(mttr_field), args.duration_unit) if mttr_field else None
        if sec is None:
            c, r = parse_jira_dt(f.get("created")), parse_jira_dt(f.get("resolutiondate"))
            sec = (r - c).total_seconds() if c and r else None
        closed_rows.append({
            "ref": it["key"], "ref_url": f"{cli.base}/browse/{it['key']}",
            "type": (f.get("issuetype") or {}).get("name", "").replace("Security ", ""),
            "sev": lbl, "sev_class": cls, "summary": f.get("summary", ""),
            "source": source_of(f), "ttr": fmt_duration(sec),
        })

    # ---- vulnerabilities ----
    vuln_sev, total_open, counts_by_label = [], 0, {}
    for label in vuln_labels:
        c = cli.count(scoped(VULN_TYPE, "statusCategory != Done", "resolution is EMPTY", sev_in(vuln_label_values[label])))
        counts_by_label[label] = c
        vuln_sev.append((label, c))
        total_open += c
    v_resolved = cli.count(closed(VULN_TYPE, start, end))
    v_new = cli.count(opened(VULN_TYPE, start, end))
    v_resolved_prev = cli.count(closed(VULN_TYPE, p_start, p_end))
    top_crit = top_cves(cli, scoped(VULN_TYPE, "statusCategory != Done", sev_in(vuln_label_values.get("Critical", ["Sev-1"]))), args, "crit")
    top_high = top_cves(cli, scoped(VULN_TYPE, "statusCategory != Done", sev_in(vuln_label_values.get("High", ["Sev-2"]))), args, "high")

    data: Dict[str, Any] = {
        "client": args.client, "environment": args.environment, "tenant": args.tenant,
        "period_label": period_label(start, end), "week_start": "Sunday" if args.week_start.lower().startswith("sun") else "Monday",
        "_period_end": (end - dt.timedelta(days=1)).isoformat(),
        "generated": strip_leading_zero(now.strftime("%d %b %Y, %H:%M UTC")),
        "support_email": args.support_email or f"alerts@{args.tenant}",
        "preview_note": None,
        "exec": {
            "opened": opened_n, "opened_delta": delta_html(opened_n, p_opened, favorable=None),
            "closed": closed_n, "closed_delta": delta_html(closed_n, p_closed, favorable="up"),
            "open": open_n, "open_delta": delta_html(open_n, p_open, favorable="down"),
            "mttd": fmt_duration(mttd), "mttd_delta": _dur_delta(mttd, p_mttd),
            "mttr": fmt_duration(mttr), "mttr_delta": _dur_delta(mttr, p_mttr),
            "uptime": (args.supplemental_data.get("availability", {}).get("uptime", "—") if args.supplemental_data else "—"),
            "uptime_note": (f'SLA {args.supplemental_data.get("availability", {}).get("sla", "")} · met' if args.supplemental_data and args.supplemental_data.get("availability") else "provided separately"),
        },
        "inc_severity": inc_sev, "inc_total_opened": opened_n,
        "trend": trend, "sev_trend": sev_trend, "sev_trend_labels": inc_labels,
        "inc_summary_line": f"We closed <b>{closed_n:,} of {opened_n:,}</b> items raised this week — ending the week with {open_n:,} open, all in active handling below." if opened_n else "",
        "open_rows": open_rows, "closed_count": closed_n, "closed_rows": closed_rows,
        "closed_more": max(closed_n - len(closed_rows), 0),
        "vuln": {
            "crit_open": counts_by_label.get("Critical", 0), "high_open": counts_by_label.get("High", 0),
            "high_note": "", "resolved": v_resolved,
            "resolved_delta": delta_html(v_resolved, v_resolved_prev, favorable="up"),
            "new": v_new, "net": v_new - v_resolved, "severity": vuln_sev,
            "total_open": total_open, "top_crit": top_crit, "top_high": top_high, "note": "",
        },
        "_sections_enabled": section_enablement(),
    }
    # supplemental (device / endpoint / availability)
    if args.supplemental_data:
        for section in ("device", "endpoint", "availability"):
            if section in args.supplemental_data:
                data[section] = args.supplemental_data[section]
    return data


def _dur_delta(cur: Optional[float], prev: Optional[float]) -> str:
    if cur is None or prev is None:
        return "vs last week"
    diff = cur - prev
    if abs(diff) < 30:
        return "no change vs last week"
    arrow = "▲" if diff > 0 else "▼"
    cls = "down" if diff > 0 else "up"  # faster (down) is favorable
    return f'<b class="{cls}">{arrow} {fmt_duration(abs(diff))}</b> vs last week'


def top_cves(cli: JiraClient, jql: str, args: argparse.Namespace, kind: str) -> List[Tuple[str, str, Any]]:
    vid_field = cli.field_id(args.vuln_id_field)
    fields = ["summary"] + ([vid_field] if vid_field else [])
    counts: Dict[str, int] = {}
    for it in cli.search(jql, fields, limit=1000):
        f = it.get("fields", {})
        text = " ".join(str(f.get(x, "")) for x in ["summary", vid_field] if x)
        for cve in {m.upper() for m in CVE_RE.findall(text)}:
            counts[cve] = counts.get(cve, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    return [(cve, f"{cli.base}/issues/?jql=" + urllib.parse.quote(f'text ~ "{cve}"'), n) for cve, n in top]


# --------------------------------------------------------------------------- #
# Sample data (matches the approved template preview)
# --------------------------------------------------------------------------- #

def sample_data() -> Dict[str, Any]:
    return {
        "client": "Neuro", "environment": "Production", "tenant": "neuro.athenasecuritygrp.com",
        "period_label": "Mon 29 Jun – Sun 5 Jul 2026", "week_start": "Monday", "_period_end": "2026-07-05",
        "generated": "6 Jul 2026, 09:01 UTC", "support_email": "alerts@neuro.athenasecuritygrp.com",
        "preview_note": ("<strong>Template preview.</strong> Illustrative sample data — run "
                         "<code>generate_report.py</code> against a client's SECOPS Jira project for live figures."),
        "exec": {
            "opened": 72, "opened_delta": '<b class="up">▲ 14</b> vs last week',
            "closed": 66, "closed_delta": '<b class="up">▲ 6</b> vs last week',
            "open": 6, "open_delta": '<b class="up">▼ 5</b> vs last week',
            "mttd": "14 min", "mttd_delta": '<b class="up">▼ 3 min</b> vs last week',
            "mttr": "3h 42m", "mttr_delta": '<b class="up">▼ 22 min</b> vs last week',
            "uptime": "99.98%", "uptime_note": "SLA 99.9% · met",
        },
        "inc_severity": [("Critical", 8), ("High", 27), ("Medium", 37)],
        "inc_total_opened": 72,
        "trend": [
            {"label": "W-5", "opened": 54, "closed": 49, "open": 9},
            {"label": "W-4", "opened": 61, "closed": 58, "open": 12},
            {"label": "W-3", "opened": 48, "closed": 52, "open": 8},
            {"label": "W-2", "opened": 69, "closed": 64, "open": 13},
            {"label": "W-1", "opened": 58, "closed": 60, "open": 11},
            {"label": "This wk", "opened": 72, "closed": 66, "open": 6},
        ],
        "sev_trend_labels": ["Critical", "High", "Medium"],
        "sev_trend": [
            {"label": "W-5", "Critical": 6, "High": 21, "Medium": 27},
            {"label": "W-4", "Critical": 8, "High": 24, "Medium": 29},
            {"label": "W-3", "Critical": 5, "High": 18, "Medium": 25},
            {"label": "W-2", "Critical": 9, "High": 26, "Medium": 34},
            {"label": "W-1", "Critical": 7, "High": 22, "Medium": 29},
            {"label": "This wk", "Critical": 8, "High": 27, "Medium": 37},
        ],
        "inc_summary_line": "We closed <b>66 of 72</b> items raised this week and cleared 5 from prior backlog — ending the week with 6 open, all in active handling below.",
        "open_rows": [
            {"ref": "NSO-4821", "type": "Incident", "sev": "Critical", "sev_class": "crit", "summary": "Outbound C2 beaconing blocked at WAF (185.220.101.44)", "source": "NIDS", "opened": "4 Jul 09:12", "age": "1d 4h", "status": "Work in progress"},
            {"ref": "NSO-4835", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Repeated failed admin sign-ins — Microsoft 365", "source": "Office 365", "opened": "4 Jul 22:40", "age": "14h", "status": "Pending"},
            {"ref": "NSO-4840", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Defender real-time protection off (LAP-014)", "source": "Defender", "opened": "5 Jul 07:05", "age": "6h", "status": "Work in progress"},
            {"ref": "NSO-4844", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Suspicious PowerShell execution (WKS-233)", "source": "Endpoint", "opened": "5 Jul 10:22", "age": "3h", "status": "Monitoring"},
            {"ref": "NSO-4849", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Cloudflare WAF rule triggered — SQL-injection attempt", "source": "Cloudflare", "opened": "5 Jul 11:48", "age": "1h", "status": "Work in progress"},
            {"ref": "NSO-4852", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Phishing email quarantined — sender rule tuned", "source": "Office 365", "opened": "5 Jul 13:10", "age": "20m", "status": "Monitoring"},
        ],
        "closed_count": 66,
        "closed_rows": [
            {"ref": "NSO-4790", "type": "Incident", "sev": "Critical", "sev_class": "crit", "summary": "Ransomware-pattern process quarantined (WKS-101)", "source": "Endpoint", "ttr": "2h 10m"},
            {"ref": "NSO-4805", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Brute-force source IP blocked at firewall", "source": "NIDS", "ttr": "38m"},
            {"ref": "NSO-4812", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Impossible-travel sign-in reviewed & cleared", "source": "Office 365", "ttr": "1h 05m"},
            {"ref": "NSO-4818", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Phishing email quarantined & rule tuned", "source": "Office 365", "ttr": "12m"},
        ],
        "closed_more": 62,
        "device": {
            "total": 87, "enrolled": 84, "outstanding": 3, "compliant": 79, "win": 61, "mac": 23,
            "meters": [["Policies deployed", 84, 84, "ok"], ["Definitions current", 82, 84, "ok"],
                       ["OS updates current", 81, 84, "ok"], ["Disk encryption on", 84, 84, "ok"]],
            "note": "3 endpoints outstanding (macOS, with client); 3 behind on OS updates — scheduled through Intune this week.",
        },
        "endpoint": {
            "protected": 84, "healthy": 82, "at_risk": 2, "at_risk_note": "LAP-014 · SRV-DB-02", "inactive": 2,
            "meters": [["Real-time protection", 82, 84, "ok"], ["Agent checking in", 82, 84, "ok"],
                       ["Signatures current", 84, 84, "ok"], ["Tamper protection", 84, 84, "ok"]],
            "inactive_agents": [["LAP-014", "Windows 11", "4 Jul 22:15 UTC", "34h"],
                                 ["dev-nrm-01", "Ubuntu 22.04", "4 Jul 18:25 UTC", "38h"]],
        },
        "vuln": {
            "crit_open": 4, "high_open": 31, "high_note": "across 12 assets", "resolved": 47,
            "resolved_delta": '<b class="up">▲ 12</b> vs last week', "new": 22, "net": -25,
            "severity": [("Critical", 4), ("High", 31), ("Medium", 96), ("Low", 140)], "total_open": 271,
            "top_crit": [("CVE-2026-13775", "#", "SRV-DB-02"), ("CVE-2026-13780", "#", "SRV-DB-02"),
                         ("CVE-2026-13781", "#", "SRV-APP-01"), ("CVE-2026-13796", "#", "SRV-APP-01")],
            "top_high": [("CVE-2026-43701", "#", 8), ("CVE-2026-43715", "#", 8),
                         ("CVE-2025-47273", "#", 5), ("CVE-2024-6345", "#", 5)],
            "note": "The 4 critical findings are all patchable and scheduled this week; the OpenSSL cluster on SRV-DB-02 is prioritized via NSO-4851.",
        },
        "availability": {"uptime": "99.98%", "sla": "99.9%", "outages": 0, "outages_note": "none recorded",
                          "maintenance": 1, "maint_note": "8 min · off-hours", "monitoring": "24 / 7"},
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a weekly Security Operations Report from Jira.")
    p.add_argument("--sample", action="store_true", help="Render with built-in sample data (no Jira needed).")
    p.add_argument("--out", help="Explicit output path. Default: <out-dir>/<client>-<week-end>.html")
    p.add_argument("--out-dir", help="Directory for auto-named output (relative paths stay in this repo). Env: REPORT_OUTPUT_DIR (default: reports).")
    p.add_argument("--open", dest="open_after", action="store_true", help="Open the report when done.")
    p.add_argument("--env-file", help="Path to a .env file (e.g. .env.neuro).")

    # These fall back to .env (JIRA_PROJECT_KEY / REPORT_*) when omitted — see resolve_config().
    p.add_argument("--project-key", help="Jira project key for the client (e.g. NSO). Env: JIRA_PROJECT_KEY.")
    p.add_argument("--client", help="Client display name. Env: REPORT_CLIENT.")
    p.add_argument("--environment", help="Env: REPORT_ENVIRONMENT (default: Production).")
    p.add_argument("--tenant", help="Env: REPORT_TENANT.")
    p.add_argument("--support-email", help="Env: REPORT_SUPPORT_EMAIL.")

    p.add_argument("--week-start", choices=["monday", "sunday", "mon", "sun"], help="Day the week starts on. Env: REPORT_WEEK_START (default: monday).")
    p.add_argument("--week-of", help="Any date (YYYY-MM-DD) inside the target week. Default: last complete week.")

    p.add_argument("--severity-field", default="Severity")
    p.add_argument("--mttr-field", default="MTTR (Minutes)")
    p.add_argument("--mttd-field", default="MTTD (Minutes)")
    p.add_argument("--incident-time-field", default="Incident Time")
    p.add_argument("--vuln-id-field", default="Vulnerability ID(s)")
    p.add_argument("--source-field", default="components", help="'components', 'labels', or a custom field name for the alert source.")
    p.add_argument("--duration-unit", default="minutes", choices=["seconds", "minutes", "hours"], help="Unit of a numeric MTTR/MTTD field.")
    p.add_argument("--max-open-rows", type=int, default=40)
    p.add_argument("--max-closed-rows", type=int, default=6)

    p.add_argument("--supplemental", help="JSON file with device/endpoint/availability data (not in Jira).")
    return p.parse_args(argv)


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "report").lower()).strip("-") or "report"


def anchor(path: str) -> str:
    """Keep relative output inside this repo, regardless of the current directory."""
    return path if os.path.isabs(path) else os.path.join(SCRIPT_DIR, path)


def resolve_config(args: argparse.Namespace, site: str) -> None:
    """Fill client/project config from CLI, falling back to .env, then defaults."""
    args.project_key = args.project_key or os.getenv("JIRA_PROJECT_KEY")
    args.client = args.client or os.getenv("REPORT_CLIENT") or args.project_key
    args.environment = args.environment or os.getenv("REPORT_ENVIRONMENT") or "Production"
    args.tenant = args.tenant or os.getenv("REPORT_TENANT") or site.replace("https://", "").replace("http://", "")
    args.support_email = args.support_email or os.getenv("REPORT_SUPPORT_EMAIL") or ""
    ws = (args.week_start or os.getenv("REPORT_WEEK_START") or "monday").lower()
    args.week_start = "sunday" if ws.startswith("sun") else "monday"


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    load_dotenv(args.env_file, override=True) if args.env_file else load_dotenv()
    out_dir = args.out_dir or os.getenv("REPORT_OUTPUT_DIR") or "reports"

    args.supplemental_data = {}
    if args.supplemental:
        with open(args.supplemental, "r", encoding="utf-8") as fh:
            args.supplemental_data = json.load(fh)

    if args.sample:
        data = sample_data()
    else:
        site = os.getenv("JIRA_SITE_URL")
        email = os.getenv("JIRA_EMAIL")
        token = os.getenv("JIRA_API_TOKEN")
        missing = [n for n, v in [("JIRA_SITE_URL", site), ("JIRA_EMAIL", email), ("JIRA_API_TOKEN", token)] if not v]
        if missing:
            log(f"Missing env: {', '.join(missing)}. Set them in .env or the environment.")
            return 2
        resolve_config(args, site)
        if not args.project_key:
            log("No project key. Pass --project-key or set JIRA_PROJECT_KEY in .env.")
            return 2
        cli = JiraClient(site, email, token)
        data = build_from_jira(cli, args)

    data.setdefault("_sections_enabled", section_enablement())

    # Output stays inside this repo unless an absolute --out is given.
    html_path = anchor(args.out) if args.out else anchor(os.path.join(out_dir, f"{slugify(data['client'])}-{data.get('_period_end', 'report')}.html"))
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render.render_report(data))
    log(f"Wrote {os.path.relpath(html_path, SCRIPT_DIR)}")
    log("For a PDF: open the HTML and Print → Save as PDF.")
    if args.open_after:
        webbrowser.open("file://" + os.path.abspath(html_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
