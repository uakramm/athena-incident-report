#!/usr/bin/env python3
"""Generate a weekly, client-facing Security Operations Report from OpenSearch on demand.

Pulls Jira-linked incident and vulnerability data from the tenant's
``pallas-incidents`` index, reads the mirrored lifecycle fields, and renders a
self-contained HTML report (print to PDF for the client copy). Device / endpoint /
availability data is not in the incident index - pass it via ``--supplemental``.

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
import time
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

import base64

import charts
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
    raw = (os.getenv("REPORT_VULN_SEVERITIES", "CRITICAL,HIGH") or os.getenv("REPORT_INCIDENT_SEVERITIES", "CRITICAL,HIGH") or "").strip().strip('"')
    if not raw or raw.lower() in {"*", "all"}:
        return [label for label in SEV_ORDER if label in label_to_values]
    wanted = {part.strip().upper() for part in re.split(r"[,\s]+", raw) if part.strip()}
    labels = [label for label in SEV_ORDER if label in label_to_values and label.upper() in wanted]
    return labels or [label for label in SEV_ORDER if label in label_to_values]


def section_enablement() -> Dict[str, bool]:
    return {
        "device": _env_bool("REPORT_ENABLE_DEVICE_MANAGEMENT", False),
        "endpoint": _env_bool("REPORT_ENABLE_ENDPOINT_MANAGEMENT", False),
        "agent_status": _env_bool("REPORT_ENABLE_AGENT_STATUS", True),
        "vuln": _env_bool("REPORT_ENABLE_VULNERABILITY_STATUS", True),
        "availability": _env_bool("REPORT_ENABLE_SYSTEM_AVAILABILITY", False),
        "soc2": _env_bool("REPORT_ENABLE_SOC2_COMPLIANCE", True),
    }


_SLA_DEFAULT_MINUTES = {"Critical": 240, "High": 480, "Medium": 1440, "Low": 4320}


def sla_targets() -> Dict[str, float]:
    """Per-severity resolution SLA in seconds. Override via REPORT_SLA_<LEVEL>_MINUTES."""
    out: Dict[str, float] = {}
    for label, default_min in _SLA_DEFAULT_MINUTES.items():
        raw = os.getenv(f"REPORT_SLA_{label.upper()}_MINUTES")
        try:
            minutes = float(raw) if raw not in (None, "") else float(default_min)
        except ValueError:
            minutes = float(default_min)
        out[label] = minutes * 60
    return out


_VULN_SLA_DEFAULT_DAYS = {"Critical": 7, "High": 14, "Medium": 30, "Low": 90}


def vuln_sla_targets() -> Dict[str, float]:
    """Per-severity vulnerability remediation SLA in seconds. Override via REPORT_VULN_SLA_<LEVEL>_DAYS."""
    out: Dict[str, float] = {}
    for label, default_days in _VULN_SLA_DEFAULT_DAYS.items():
        raw = os.getenv(f"REPORT_VULN_SLA_{label.upper()}_DAYS")
        try:
            days = float(raw) if raw not in (None, "") else float(default_days)
        except ValueError:
            days = float(default_days)
        out[label] = days * 86400
    return out


def fmt_sla_target(seconds: float) -> str:
    minutes = int(round(seconds / 60))
    if minutes and minutes % 1440 == 0:
        return f"{minutes // 1440}d"
    if minutes and minutes % 60 == 0:
        return f"{minutes // 60}h"
    if minutes >= 60:
        return f"{minutes // 60}h {minutes % 60:02d}m"
    return f"{minutes}m"


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
    """Standard alerts/incidents: Jira Sev-1 through Sev-4 map naturally."""
    return _sev_maps([
        ("Critical", _env("JIRA_SEVERITY_CRITICAL_VALUE", "Sev-1")),
        ("High", _env("JIRA_SEVERITY_HIGH_VALUE", "Sev-2")),
        ("Medium", _env("JIRA_SEVERITY_MEDIUM_VALUE", "Sev-3")),
        ("Low", _env("JIRA_SEVERITY_LOW_VALUE", "Sev-4")),
    ])


def nids_incident_sev_maps() -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """SURICATA/NIDS alerts: confirmed and critical are separate Jira severities."""
    return _sev_maps([
        ("Critical", _env("JIRA_NIDS_SEVERITY_CONFIRMED_VALUE", "Sev-1")),
        ("Critical", _env("JIRA_NIDS_SEVERITY_CRITICAL_VALUE", "Sev-2")),
        ("High", _env("JIRA_NIDS_SEVERITY_HIGH_VALUE", "Sev-3")),
        ("Medium", _env("JIRA_NIDS_SEVERITY_MEDIUM_VALUE", "Sev-4")),
        ("Low", _env("JIRA_NIDS_SEVERITY_LOW_VALUE", "Sev-4")),
    ])


def is_nids_summary(summary: Any) -> bool:
    """NIDS tickets carry a [SURICATA] marker in their Jira summary."""
    return bool(re.search(r"\[\s*SURICATA\s*\]", str(summary or ""), re.IGNORECASE))


def incident_severity_label(fields: Dict[str, Any], severity_field: str,
                            standard_map: Optional[Dict[str, str]] = None,
                            nids_map: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Resolve an incident's report severity using its source-specific mapping."""
    raw = fields.get(severity_field)
    raw = raw.get("value") if isinstance(raw, dict) else raw
    if standard_map is None:
        standard_map, _ = incident_sev_maps()
    if nids_map is None:
        nids_map, _ = nids_incident_sev_maps()
    mapping = nids_map if is_nids_summary(fields.get("summary")) else standard_map
    return mapping.get(raw)


def vulnerability_sev_maps() -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Vulnerabilities — Snyk import mapping (natural): Critical=Sev-1 … Low=Sev-4."""
    return _sev_maps([
        ("Critical", _env("JIRA_VULN_SEVERITY_CRITICAL_VALUE", "Sev-1")),
        ("High", _env("JIRA_VULN_SEVERITY_HIGH_VALUE", "Sev-2")),
        ("Medium", _env("JIRA_VULN_SEVERITY_MEDIUM_VALUE", "Sev-3")),
        ("Low", _env("JIRA_VULN_SEVERITY_LOW_VALUE", "Sev-4")),
    ])


_LOG_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARN": 30,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}


def _configured_log_level() -> str:
    raw = (os.getenv("REPORT_LOG_LEVEL") or os.getenv("LOG_LEVEL") or "INFO").strip().strip('"').upper()
    return raw if raw in _LOG_LEVELS else "INFO"


def _log_enabled(level: str) -> bool:
    configured = _LOG_LEVELS[_configured_log_level()]
    requested = _LOG_LEVELS.get((level or "INFO").upper(), _LOG_LEVELS["INFO"])
    return requested >= configured


def log(msg: str, level: str = "INFO") -> None:
    if _log_enabled(level):
        print(msg, file=sys.stderr, flush=True)


def debug(msg: str) -> None:
    log(msg, level="DEBUG")


# --------------------------------------------------------------------------- #
# Jira client
# --------------------------------------------------------------------------- #

class JiraError(RuntimeError):
    pass


class OpenSearchError(RuntimeError):
    pass


class WazuhManagerError(RuntimeError):
    pass


# Atlassian OAuth 2.0 endpoints.
ATLASSIAN_AUTH_URL = "https://auth.atlassian.com/oauth/token"
ATLASSIAN_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"
ATLASSIAN_API_BASE = "https://api.atlassian.com/ex/jira"


def fetch_jira_oauth(client_id: str, client_secret: str, cloud_id: str = "",
                     timeout: int = 30) -> Tuple[str, str, str]:
    """Atlassian OAuth 2.0 client-credentials, mirroring athena-pallas: get a Bearer
    token from auth.atlassian.com, then auto-discover the Jira cloud id via
    accessible-resources when not provided. Returns (access_token, cloud_id,
    site_url) — site_url is the human-facing site (e.g. https://x.atlassian.net),
    empty when a cloud id was supplied and no discovery ran."""
    if requests is None:
        raise JiraError("The 'requests' package is required for OAuth. Run: pip install -r requirements.txt")
    debug("Jira OAuth token request start.")
    started = time.perf_counter()
    resp = requests.post(ATLASSIAN_AUTH_URL, json={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }, timeout=timeout)
    debug(f"Jira OAuth token request done: HTTP {resp.status_code} in {time.perf_counter() - started:.2f}s.")
    if resp.status_code != 200:
        raise JiraError(f"Jira OAuth token request failed: HTTP {resp.status_code}\n{resp.text[:400]}")
    token = (resp.json() or {}).get("access_token")
    if not token:
        raise JiraError("Jira OAuth token response did not include access_token.")
    site_url = ""
    if not cloud_id:
        debug("Jira OAuth cloud-id discovery start.")
        started = time.perf_counter()
        r = requests.get(ATLASSIAN_RESOURCES_URL, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        debug(f"Jira OAuth cloud-id discovery done: HTTP {r.status_code} in {time.perf_counter() - started:.2f}s.")
        if r.status_code != 200:
            raise JiraError(f"Jira cloud-id discovery failed: HTTP {r.status_code}\n{r.text[:400]}")
        sites = r.json() or []
        if not sites:
            raise JiraError("No accessible Jira sites for this OAuth app — check the service account's access.")
        cloud_id = sites[0]["id"]
        site_url = sites[0].get("url", "")
    return token, cloud_id, site_url


class JiraClient:
    def __init__(self, site_url: str, *, email: Optional[str] = None,
                 token: Optional[str] = None, bearer: Optional[str] = None,
                 browse_base: Optional[str] = None):
        if requests is None:
            raise JiraError("The 'requests' package is required for live Jira runs. Run: pip install -r requirements.txt")
        self.base = site_url.rstrip("/")
        # Human-facing site URL for clickable ticket/search links (in OAuth mode the
        # API base is api.atlassian.com/ex/jira/… which does not open in a browser).
        self.browse_base = (browse_base or site_url).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if bearer:
            self.session.headers["Authorization"] = f"Bearer {bearer}"
        elif email and token:
            self.session.auth = (email, token)
        else:
            raise JiraError("No Jira credentials. Set JIRA_EMAIL + JIRA_API_TOKEN, or "
                            "JIRA_OAUTH_CLIENT_ID + JIRA_OAUTH_CLIENT_SECRET + JIRA_OAUTH_TOKEN_URL.")
        self._fields: Optional[List[Dict[str, Any]]] = None

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        started = time.perf_counter()
        debug(f"Jira HTTP start: {method} {path}")
        r = self.session.request(method, self.base + path, timeout=90, **kw)
        debug(f"Jira HTTP done: {method} {path} -> HTTP {r.status_code} in {time.perf_counter() - started:.2f}s")
        if r.status_code not in (200, 201):
            raise JiraError(f"{method} {path} -> HTTP {r.status_code}\n{r.text[:800]}")
        return r.json() if r.content else None

    def fields(self) -> List[Dict[str, Any]]:
        if self._fields is None:
            debug("Jira fields load start.")
            self._fields = self._req("GET", "/rest/api/3/field")
            debug(f"Jira fields load done: {len(self._fields)} field(s).")
        return self._fields

    def project_name(self, key: str) -> Optional[str]:
        try:
            data = self._req("GET", "/rest/api/3/project/" + urllib.parse.quote(key))
            return (data or {}).get("name")
        except Exception:
            return None

    def field_id(self, name: str) -> Optional[str]:
        if name.startswith("customfield_") or name in ("created", "resolutiondate", "status", "summary", "issuetype", "components", "labels"):
            return name
        want = name.strip().lower()
        for f in self.fields():
            if f.get("name", "").strip().lower() == want:
                return f["id"]
        return None

    def count(self, jql: str) -> int:
        started = time.perf_counter()
        debug(f"Jira count start: {jql}")
        try:
            data = self._req("POST", "/rest/api/3/search/approximate-count", json={"jql": jql})
            count = int(data.get("count", 0))
        except JiraError:
            data = self._req("GET", "/rest/api/3/search", params={"jql": jql, "maxResults": 0})
            count = int(data.get("total", 0))
        debug(f"Jira count done: {count} result(s) in {time.perf_counter() - started:.2f}s.")
        return count

    def search(self, jql: str, fields: Sequence[str], limit: int = 1000) -> List[Dict[str, Any]]:
        started = time.perf_counter()
        debug(f"Jira search start: limit={limit} fields={list(fields)} jql={jql}")
        out: List[Dict[str, Any]] = []
        token: Optional[str] = None
        page = 0
        while len(out) < limit:
            page += 1
            body = {"jql": jql, "fields": list(fields), "maxResults": min(100, limit - len(out))}
            if token:
                body["nextPageToken"] = token
            try:
                data = self._req("POST", "/rest/api/3/search/jql", json=body)
            except JiraError:
                data = self._req("GET", "/rest/api/3/search",
                                 params={"jql": jql, "fields": ",".join(fields), "maxResults": min(100, limit - len(out)), "startAt": len(out)})
            issues = data.get("issues", [])
            out.extend(issues)
            debug(f"Jira search page {page}: fetched={len(issues)} accumulated={len(out)}.")
            token = data.get("nextPageToken")
            if data.get("isLast", True) or not data.get("issues") or (not token and "startAt" not in data):
                break
            if "startAt" in data and len(out) >= data.get("total", 0):
                break
        result = out[:limit]
        debug(f"Jira search done: returned={len(result)} in {time.perf_counter() - started:.2f}s.")
        return result


class OpenSearchClient:
    """Expose pallas-incidents through the small Jira-like interface used below.

    Keeping the compatibility boundary here lets the established report metrics
    and rendering code operate on Jira's authoritative state mirrored into
    OpenSearch without making any Jira API calls.
    """

    FIELD_IDS = {
        "severity": "severity",
        "mttd (minutes)": "mttd_minutes",
        "mttt (minutes)": "mttt_minutes",
        "mttr (minutes)": "mttr_minutes",
        "mttc (minutes)": "mttc_minutes",
        "incident time (eastern time - et)": "event_timestamp",
        "alert generated time": "alert_generated_at",
        "first response time": "first_response_at",
        "type of incident": "incident_type",
        "vulnerability id(s)": "vulnerability_ids",
        "source": "source",
    }

    def __init__(self, base_url: str, username: str, password: str, *,
                 index: str = "pallas-incidents", verify_ssl: bool = False,
                 browse_base: str = "", project_name: str = "",
                 documents: Optional[Sequence[Dict[str, Any]]] = None):
        if not base_url:
            raise OpenSearchError("OPENSEARCH_URL is required.")
        if not username:
            raise OpenSearchError("OPENSEARCH_USERNAME is required.")
        if not password:
            raise OpenSearchError("OPENSEARCH_PASSWORD is required.")
        if requests is None and documents is None:
            raise OpenSearchError(
                "The 'requests' package is required for OpenSearch. "
                "Run: pip install -r requirements.txt"
            )
        self.base = base_url.rstrip("/")
        self.index = index or "pallas-incidents"
        self.verify_ssl = verify_ssl
        self.browse_base = browse_base.rstrip("/")
        self._project_name = project_name
        self.session = requests.Session() if requests is not None else None
        if self.session is not None:
            self.session.auth = (username, password)
            self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._issues: Optional[List[Dict[str, Any]]] = (
            self._documents_to_issues(documents) if documents is not None else None
        )

    @classmethod
    def from_env(cls) -> "OpenSearchClient":
        return cls(
            _env("OPENSEARCH_URL", ""),
            _env("OPENSEARCH_USERNAME", ""),
            os.getenv("OPENSEARCH_PASSWORD") or "",
            index=_env("OPENSEARCH_INDEX", "pallas-incidents") or "pallas-incidents",
            verify_ssl=_env_bool("OPENSEARCH_VERIFY_SSL", False),
            browse_base=jira_site_url(),
            project_name=_env("REPORT_PROJECT_NAME", ""),
        )

    def _req(self, method: str, path: str, **kwargs: Any) -> Any:
        if self.session is None:
            raise OpenSearchError("The 'requests' package is required for OpenSearch.")
        started = time.perf_counter()
        debug(f"OpenSearch HTTP start: {method} {path}")
        try:
            response = self.session.request(
                method, self.base + path, timeout=90, verify=self.verify_ssl, **kwargs
            )
        except requests.RequestException as exc:
            raise OpenSearchError(f"OpenSearch request failed for {self.base}: {exc}") from exc
        debug(
            f"OpenSearch HTTP done: {method} {path} -> HTTP {response.status_code} "
            f"in {time.perf_counter() - started:.2f}s"
        )
        if response.status_code not in (200, 201):
            raise OpenSearchError(
                f"{method} {path} -> HTTP {response.status_code}\n{response.text[:800]}"
            )
        return response.json() if response.content else None

    def query_index(self, index: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Run a read-only search against another index on the tenant indexer."""
        safe_index = urllib.parse.quote(index, safe="*-_.")
        return self._req("POST", f"/{safe_index}/_search", json=body)

    def _load_issues(self) -> List[Dict[str, Any]]:
        if self._issues is not None:
            return self._issues
        log(f"OpenSearch load start: endpoint={self.base} index={self.index}")
        documents: List[Dict[str, Any]] = []
        search_after: Optional[List[Any]] = None
        page = 0
        while True:
            page += 1
            body: Dict[str, Any] = {
                "size": 500,
                "query": {"exists": {"field": "jira_ticket_id"}},
                "sort": [
                    {"jira_ticket_id": {"order": "asc", "unmapped_type": "keyword"}},
                    {"incident_id": {"order": "asc", "unmapped_type": "keyword"}},
                ],
            }
            if search_after:
                body["search_after"] = search_after
            data = self._req("POST", f"/{urllib.parse.quote(self.index, safe='-_,*')}/_search", json=body)
            hits = ((data or {}).get("hits") or {}).get("hits") or []
            for hit in hits:
                source = dict(hit.get("_source") or {})
                source.setdefault("_doc_id", hit.get("_id"))
                documents.append(source)
            debug(f"OpenSearch page {page}: fetched={len(hits)} accumulated={len(documents)}")
            if len(hits) < body["size"]:
                break
            next_sort = hits[-1].get("sort")
            if not next_sort or next_sort == search_after:
                raise OpenSearchError("OpenSearch pagination did not advance.")
            search_after = next_sort
        self._issues = self._documents_to_issues(documents)
        log(
            "OpenSearch load done: "
            f"Jira-linked documents={len(documents)} unique_tickets={len(self._issues)}"
        )
        return self._issues

    @staticmethod
    def _document_freshness(doc: Dict[str, Any]) -> Tuple[float, int]:
        timestamps: List[float] = []
        for key in ("jira_updated_at", "jira_synced_at", "updated_at", "closed_at"):
            parsed = parse_jira_dt(str(doc.get(key) or ""))
            if parsed:
                timestamps.append(parsed.timestamp())
        populated = sum(1 for value in doc.values() if value not in (None, "", [], {}))
        return (max(timestamps) if timestamps else 0.0, populated)

    @classmethod
    def _documents_to_issues(cls, documents: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use one mirrored document per Jira ticket, preferring the freshest copy."""
        selected: Dict[str, Dict[str, Any]] = {}
        for doc in documents:
            key = str(doc.get("jira_ticket_id") or "").strip()
            if not key:
                continue
            current = selected.get(key)
            if current is None or cls._document_freshness(doc) > cls._document_freshness(current):
                selected[key] = doc
        duplicates = len(documents) - len(selected)
        if duplicates:
            log(f"OpenSearch deduplication: removed={duplicates} duplicate Jira ticket documents")
        return [cls._to_issue(doc) for doc in selected.values()]

    @staticmethod
    def _is_vulnerability(doc: Dict[str, Any]) -> bool:
        alert_data = doc.get("alert_data") if isinstance(doc.get("alert_data"), dict) else {}
        context = " ".join([
            str(doc.get("rule_description") or ""),
            " ".join(str(item) for item in (doc.get("rule_groups") or [])),
            json.dumps(alert_data, default=str),
        ]).lower()
        sources = {
            re.sub(r"[^a-z0-9]+", "", str(value or "").lower())
            for value in (
                doc.get("alert_source"),
                alert_data.get("vendor_source"),
                alert_data.get("source"),
            )
            if value
        }
        # Pallas routes GitHub Dependabot/security-advisory findings to Jira's
        # Vulnerability issue type. This source is authoritative for that route.
        if "github" in sources or re.search(
            r"\bgithub\b|repository_vulnerability_alert|\bghsa-[a-z0-9-]+\b", context
        ):
            return True
        explicit_types = (
            doc.get("jira_issue_type"),
            doc.get("jira_request_type"),
            doc.get("issue_type"),
            alert_data.get("jira_issue_type"),
            alert_data.get("request_type"),
        )
        for value in explicit_types:
            if isinstance(value, dict):
                value = value.get("name") or value.get("value")
            normalized = re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()
            if normalized in {"vulnerability", "vulnerability finding"}:
                return True

        groups: List[str] = [str(item) for item in (doc.get("rule_groups") or []) if item]
        for key in ("rule_groups", "groups"):
            value = alert_data.get(key)
            if isinstance(value, (list, tuple)):
                groups.extend(str(item) for item in value if item)
            elif value:
                groups.extend(part.strip() for part in str(value).split(",") if part.strip())
        category = alert_data.get("category")
        if category:
            groups.extend(part.strip() for part in str(category).split(",") if part.strip())
        normalized_groups = {
            re.sub(r"[^a-z0-9]+", "_", group.lower()).strip("_") for group in groups
        }
        # Vendor endpoint alerts can include vulnerability context/groups while
        # Pallas still routes them to Security Alert. Only the Wazuh detector
        # pipeline and explicit Jira/GitHub routes represent Jira Vulnerability.
        vendor_sources = sources - {"wazuh", "local", "unknown"}
        if not vendor_sources and "wazuh" in sources and normalized_groups & {
            "vulnerability", "vulnerability_detector"
        }:
            return True

        # Legacy vulnerability-detector documents did not always preserve
        # rule_groups in pallas-incidents. Their generated rule title is still
        # deterministic; unlike a generic incident narrative, it begins with a
        # CVE and the word "affects".
        descriptions = (
            doc.get("rule_description"),
            alert_data.get("rule_description"),
            alert_data.get("description"),
        )
        has_other_vendor_context = bool(re.search(
            r"\b(?:defender|sophos|cloudflare|intune|guard\s*duty|office\s*365)\b",
            context,
        ))
        return not vendor_sources and not has_other_vendor_context and "wazuh" in sources and any(
            re.match(r"^\s*CVE-\d{4}-\d{3,7}\s+affects\b", str(value or ""), re.IGNORECASE)
            for value in descriptions
        )

    @staticmethod
    def _is_nids(doc: Dict[str, Any]) -> bool:
        groups = " ".join(str(item) for item in (doc.get("rule_groups") or []))
        source = f"{doc.get('alert_source', '')} {groups}".lower()
        return "suricata" in source or "nids" in source

    @staticmethod
    def _severity_value(doc: Dict[str, Any], vulnerability: bool, nids: bool) -> str:
        label = str(doc.get("severity") or "").strip().lower()
        standard = {
            "critical": _env("JIRA_SEVERITY_CRITICAL_VALUE", "Sev-1"),
            "high": _env("JIRA_SEVERITY_HIGH_VALUE", "Sev-2"),
            "medium": _env("JIRA_SEVERITY_MEDIUM_VALUE", "Sev-3"),
            "low": _env("JIRA_SEVERITY_LOW_VALUE", "Sev-4"),
        }
        vuln = {
            "critical": _env("JIRA_VULN_SEVERITY_CRITICAL_VALUE", "Sev-1"),
            "high": _env("JIRA_VULN_SEVERITY_HIGH_VALUE", "Sev-2"),
            "medium": _env("JIRA_VULN_SEVERITY_MEDIUM_VALUE", "Sev-3"),
            "low": _env("JIRA_VULN_SEVERITY_LOW_VALUE", "Sev-4"),
        }
        nids_values = {
            "confirmed": _env("JIRA_NIDS_SEVERITY_CONFIRMED_VALUE", "Sev-1"),
            "critical": _env("JIRA_NIDS_SEVERITY_CRITICAL_VALUE", "Sev-2"),
            "high": _env("JIRA_NIDS_SEVERITY_HIGH_VALUE", "Sev-3"),
            "medium": _env("JIRA_NIDS_SEVERITY_MEDIUM_VALUE", "Sev-4"),
            "low": _env("JIRA_NIDS_SEVERITY_LOW_VALUE", "Sev-4"),
        }
        mapping = vuln if vulnerability else (nids_values if nids else standard)
        return mapping.get(label, standard.get(label, "Sev-4"))

    @staticmethod
    def _source(doc: Dict[str, Any], summary: str = "") -> str:
        alert_data = doc.get("alert_data") if isinstance(doc.get("alert_data"), dict) else {}
        raw = (
            alert_data.get("vendor_source")
            or alert_data.get("source")
            or doc.get("alert_source")
            or "Unknown"
        )
        raw_text = str(raw).strip()
        normalized = re.sub(r"[^a-z0-9]+", "", raw_text.lower())
        source_names = {
            "office365": "Office 365",
            "microsoft365": "Office 365",
            "m365": "Office 365",
            "awsguardduty": "GuardDuty",
            "guardduty": "GuardDuty",
            "suricata": "Suricata",
            "nids": "Suricata",
            "microsoftdefender": "Microsoft Defender",
            "defender": "Microsoft Defender",
            "sophos": "Sophos",
            "cloudflare": "Cloudflare",
            "intune": "Intune",
            "snyk": "Snyk",
            "github": "GitHub",
            "crowdstrike": "CrowdStrike",
        }
        if normalized in source_names:
            return source_names[normalized]

        context = " ".join([
            summary,
            str(doc.get("rule_description") or ""),
            " ".join(str(item) for item in (doc.get("rule_groups") or [])),
            json.dumps(alert_data, default=str),
        ]).lower()
        patterns = (
            (r"\bsuricata\b|\bnids\b", "Suricata"),
            (r"\bguard\s*duty\b|\baws_guardduty\b", "GuardDuty"),
            (r"\boffice\s*365\b|\bmicrosoft\s*365\b|\bexchange online protection\b", "Office 365"),
            (r"\bmicrosoft defender\b|\bdefender for (?:office|endpoint)\b", "Microsoft Defender"),
            (r"\bsophos\b", "Sophos"),
            (r"\bcloudflare\b", "Cloudflare"),
            (r"\bintune\b", "Intune"),
            (r"\bsnyk\b", "Snyk"),
            (r"\bgithub\b", "GitHub"),
            (r"\bcrowdstrike\b", "CrowdStrike"),
        )
        for pattern, name in patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return name
        return raw_text.replace("_", " ").strip().title() or "Unknown"

    @staticmethod
    def _incident_type(
        doc: Dict[str, Any], alert_data: Dict[str, Any], source: str, vulnerability: bool
    ) -> str:
        if vulnerability:
            return "Vulnerability"
        explicit = alert_data.get("incident_type") or alert_data.get("type_of_incident")
        if explicit:
            value = str(explicit).strip()
            if not ("," in value or "_" in value) and value.lower() not in {
                "defender", "wazuh", "suricata", "office365", "office 365"
            }:
                return value
        raw = " ".join([
            str(explicit or ""),
            str(alert_data.get("category") or ""),
            str(alert_data.get("rule_group") or ""),
            " ".join(str(item) for item in (doc.get("rule_groups") or [])),
            source,
        ]).lower()
        categories = (
            (r"\bsysmon\b|\bdefender\b", "Endpoint detection"),
            (r"\boffice\s*365\b|\bthreatintelligence\b", "Email threat"),
            (r"\bsuricata\b|\bnids\b", "Network intrusion"),
            (r"\bguard\s*duty\b|\baws_guardduty\b", "Cloud threat"),
            (r"\bgithub\b|\bsnyk\b", "Software supply chain"),
            (r"\bwindows_system\b", "Windows security event"),
        )
        for pattern, name in categories:
            if re.search(pattern, raw, re.IGNORECASE):
                return name
        fallback = str(alert_data.get("category") or alert_data.get("rule_group") or source).strip()
        if "," in fallback:
            fallback = fallback.split(",", 1)[0]
        return fallback.replace("_", " ").strip().title() or "Unclassified"

    @staticmethod
    def _metric_minutes(doc: Dict[str, Any], kind: str) -> Any:
        """Prefer Pallas's precise seconds over its analyst-facing rounded minutes."""
        seconds = doc.get(f"{kind}_seconds")
        try:
            return float(seconds) / 60 if seconds not in (None, "") else doc.get(f"{kind}_minutes")
        except (TypeError, ValueError):
            return doc.get(f"{kind}_minutes")

    @classmethod
    def _to_issue(cls, doc: Dict[str, Any]) -> Dict[str, Any]:
        alert_data = doc.get("alert_data") if isinstance(doc.get("alert_data"), dict) else {}
        vulnerability = cls._is_vulnerability(doc)
        nids = cls._is_nids(doc)
        raw_severity = str(doc.get("severity") or "").strip().upper() or "LOW"
        summary = (
            alert_data.get("summary")
            or alert_data.get("rule_description")
            or alert_data.get("description")
            or doc.get("rule_description")
            or doc.get("alert_id")
            or "Security alert"
        )
        summary = str(summary)
        source = cls._source(doc, summary)
        if nids and not is_nids_summary(summary):
            summary = f"[{raw_severity}] [SURICATA] {summary}"
        elif not nids:
            if source not in {"Wazuh", "Unknown"}:
                summary = re.sub(
                    r"^(\s*\[[^\]]+\]\s*)\[(?:Wazuh|Unknown|Local)\]",
                    rf"\1[{source}]",
                    summary,
                    count=1,
                    flags=re.IGNORECASE,
                )
            if not re.match(r"^\s*\[", summary):
                summary = f"[{raw_severity}] [{source}] {summary}"

        status_name = str(doc.get("jira_status") or doc.get("status") or "Open")
        status_category = str(doc.get("jira_status_category") or "")
        done = status_category.lower() == "done" or status_name.lower() in {
            "done", "closed", "resolved", "complete", "completed"
        }
        resolved_at = doc.get("jira_resolved_at") or doc.get("closed_at")
        if done and not resolved_at:
            resolved_at = doc.get("jira_status_category_changed_at")
        if resolved_at:
            done = True

        full_text = " ".join([
            str(doc.get("rule_description") or ""),
            json.dumps(alert_data, default=str),
            str(doc.get("resolution_notes") or ""),
        ])
        cves = sorted(_find_cves(full_text))
        incident_type = cls._incident_type(doc, alert_data, source, vulnerability)
        key = str(doc.get("jira_ticket_id") or "").strip()
        return {
            "key": key,
            "_opensearch": doc,
            "fields": {
                "summary": summary,
                "issuetype": {"name": "Vulnerability" if vulnerability else "Security Alert"},
                "severity": {"value": cls._severity_value(doc, vulnerability, nids)},
                "created": doc.get("jira_created_at") or doc.get("created_at"),
                "resolutiondate": resolved_at,
                "status": {"name": status_name, "statusCategory": {"name": "Done" if done else "In Progress"}},
                "assignee": {
                    "displayName": str(doc.get("jira_assignee") or "").strip()
                } if doc.get("jira_assignee") else None,
                "components": [{"name": source}],
                "labels": [str(item) for item in (doc.get("rule_groups") or [])],
                "source": source,
                "mttd_minutes": cls._metric_minutes(doc, "mttd"),
                "mttt_minutes": cls._metric_minutes(doc, "mttt"),
                "mttr_minutes": cls._metric_minutes(doc, "mttr"),
                "mttc_minutes": cls._metric_minutes(doc, "mttc"),
                "event_timestamp": doc.get("event_timestamp"),
                "alert_generated_at": doc.get("alert_generated_at") or doc.get("alert_timestamp"),
                "first_response_at": doc.get("first_response_at"),
                "incident_type": incident_type,
                "vulnerability_ids": ", ".join(cves),
                "description": full_text,
                "comment": {"comments": []},
            },
        }

    def field_id(self, name: str) -> Optional[str]:
        if name in {
            "created", "resolutiondate", "status", "summary", "issuetype",
            "components", "labels", "description", "comment", "assignee",
        }:
            return name
        return self.FIELD_IDS.get(name.strip().lower(), name if name in self.FIELD_IDS.values() else None)

    def project_name(self, _key: str) -> Optional[str]:
        return self._project_name or None

    @staticmethod
    def _date(value: Any) -> Optional[dt.datetime]:
        parsed = parse_jira_dt(str(value)) if value else None
        if parsed and parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed

    @classmethod
    def _matches(cls, issue: Dict[str, Any], jql: str) -> bool:
        fields = issue.get("fields", {})
        lower = jql.lower()
        issue_type = (fields.get("issuetype") or {}).get("name", "")
        if "issuetype = vulnerability" in lower and issue_type != "Vulnerability":
            return False
        if "issuetype in" in lower and "security alert" in lower and issue_type == "Vulnerability":
            return False

        severity_match = re.search(r'"[^"\n]*severity[^"\n]*"\s+in\s*\(([^)]*)\)', jql, re.IGNORECASE)
        if severity_match:
            allowed = {item.strip().strip('"\'') for item in severity_match.group(1).split(",")}
            severity = fields.get("severity") or {}
            severity = severity.get("value") if isinstance(severity, dict) else severity
            if severity not in allowed:
                return False

        created = cls._date(fields.get("created"))
        resolved = cls._date(fields.get("resolutiondate"))
        for op, raw in re.findall(r'\bcreated\s*(>=|<)\s*"(\d{4}-\d{2}-\d{2})"', jql, re.IGNORECASE):
            boundary = dt.datetime.combine(dt.date.fromisoformat(raw), dt.time.min, tzinfo=dt.timezone.utc)
            if created is None or (op == ">=" and created < boundary) or (op == "<" and created >= boundary):
                return False

        open_at = re.search(
            r'\(\s*resolutiondate\s+is\s+empty\s+or\s+resolutiondate\s*>=\s*"(\d{4}-\d{2}-\d{2})"\s*\)',
            jql, re.IGNORECASE,
        )
        if open_at:
            boundary = dt.datetime.combine(
                dt.date.fromisoformat(open_at.group(1)), dt.time.min, tzinfo=dt.timezone.utc
            )
            if resolved is not None and resolved < boundary:
                return False
        else:
            for op, raw in re.findall(r'\bresolutiondate\s*(>=|<)\s*"(\d{4}-\d{2}-\d{2})"', jql, re.IGNORECASE):
                boundary = dt.datetime.combine(dt.date.fromisoformat(raw), dt.time.min, tzinfo=dt.timezone.utc)
                if resolved is None or (op == ">=" and resolved < boundary) or (op == "<" and resolved >= boundary):
                    return False

        if "resolution is empty" in lower and resolved is not None:
            return False
        if "statuscategory != done" in lower:
            category = ((fields.get("status") or {}).get("statusCategory") or {}).get("name", "")
            if category.lower() == "done":
                return False
        return True

    def search(self, jql: str, fields: Sequence[str], limit: int = 1000) -> List[Dict[str, Any]]:
        del fields
        matches = [issue for issue in self._load_issues() if self._matches(issue, jql)]
        debug(f"OpenSearch compatibility query: matched={len(matches)} limit={limit} jql={jql}")
        return matches[:limit]

    def count(self, jql: str) -> int:
        return len(self.search(jql, [], limit=1000000))


def jira_search_url(cli: Any, jql: str) -> str:
    base = str(getattr(cli, "browse_base", "") or "").rstrip("/")
    return f"{base}/issues/?{urllib.parse.urlencode({'jql': jql})}" if base else ""


def _wazuh_manager_base_url() -> str:
    raw_host = _env("WAZUH_HOST", "")
    if not raw_host:
        raise WazuhManagerError("WAZUH_HOST is required for the Agent Status section.")
    if "://" not in raw_host:
        raw_host = f"https://{raw_host}"
    parsed = urllib.parse.urlsplit(raw_host)
    if not parsed.hostname:
        raise WazuhManagerError("WAZUH_HOST must be a valid hostname or URL.")
    if parsed.port is None:
        try:
            port = int(_env("WAZUH_PORT", "55000"))
        except ValueError as exc:
            raise WazuhManagerError("WAZUH_PORT must be a number.") from exc
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        netloc = f"{host}:{port}"
    else:
        netloc = parsed.netloc
    return urllib.parse.urlunsplit((parsed.scheme or "https", netloc, parsed.path.rstrip("/"), "", ""))


def _wazuh_manager_agents() -> List[Dict[str, Any]]:
    if requests is None:
        raise WazuhManagerError(
            "The 'requests' package is required for Wazuh Manager. "
            "Run: pip install -r requirements.txt"
        )
    user = _env("WAZUH_USER", "")
    password = os.getenv("WAZUH_PASS") or ""
    if not user or not password:
        raise WazuhManagerError(
            "WAZUH_USER and WAZUH_PASS are required for the Agent Status section."
        )
    base_url = _wazuh_manager_base_url()
    verify_ssl = _env_bool("WAZUH_VERIFY_SSL", True)
    try:
        timeout = max(float(_env("WAZUH_TIMEOUT_SECONDS", "30")), 1.0)
    except ValueError:
        timeout = 30.0
    try:
        page_size = min(max(int(_env("WAZUH_AGENT_PAGE_SIZE", "500")), 1), 10000)
    except ValueError:
        page_size = 500

    session = requests.Session()
    log(f"Wazuh Manager agent load start: endpoint={base_url}")
    try:
        auth_response = session.post(
            f"{base_url}/security/user/authenticate",
            auth=(user, password),
            timeout=timeout,
            verify=verify_ssl,
        )
        if auth_response.status_code not in (200, 201):
            raise WazuhManagerError(
                f"Wazuh Manager authentication failed with HTTP {auth_response.status_code}."
            )
        try:
            token = str(((auth_response.json().get("data") or {}).get("token")) or "")
        except (TypeError, ValueError) as exc:
            raise WazuhManagerError("Wazuh Manager authentication returned invalid JSON.") from exc
        if not token:
            raise WazuhManagerError("Wazuh Manager authentication did not return a token.")

        session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        agents: List[Dict[str, Any]] = []
        offset = 0
        while True:
            response = session.get(
                f"{base_url}/agents",
                params={
                    "limit": page_size,
                    "offset": offset,
                    "select": "id,name,status,lastKeepAlive,os.name,os.platform,os.version",
                    "sort": "+id",
                },
                timeout=timeout,
                verify=verify_ssl,
            )
            if response.status_code != 200:
                raise WazuhManagerError(
                    f"Wazuh Manager agent query failed with HTTP {response.status_code}."
                )
            try:
                data = response.json().get("data") or {}
                page = data.get("affected_items") or []
                total = int(data.get("total_affected_items") or len(page))
            except (AttributeError, TypeError, ValueError) as exc:
                raise WazuhManagerError("Wazuh Manager agent query returned invalid JSON.") from exc
            if not isinstance(page, list):
                raise WazuhManagerError("Wazuh Manager agent query returned an invalid agent list.")
            agents.extend(item for item in page if isinstance(item, dict))
            offset += len(page)
            if not page or offset >= total:
                break
        log(f"Wazuh Manager agent load done: agents={len(agents)}")
        return agents
    except requests.RequestException as exc:
        raise WazuhManagerError(f"Wazuh Manager request failed for {base_url}: {exc}") from exc
    finally:
        session.close()


def _wazuh_timestamp(value: Any) -> Optional[dt.datetime]:
    if value in (None, ""):
        return None
    raw = str(value).strip()
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def agent_status_snapshot(_cli: Any, now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Build the same heartbeat snapshot used by the Agent Summary report.

    Agents seen in the last 24 hours are active. Inactive agents are grouped into
    24-72 hour, 3-7 day, and 7-14 day buckets; records older than 14 days are
    intentionally excluded to match the established report definition.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    active = 0
    inactive_agents: List[Dict[str, Any]] = []
    bucket_counts = {"inactive_24_72": 0, "inactive_3_7d": 0, "inactive_7_14d": 0}
    agents = _wazuh_manager_agents()
    for agent in agents:
        if str(agent.get("id") or "") == "000" and not _env_bool("REPORT_AGENT_INCLUDE_MANAGER", False):
            continue
        last_seen = _wazuh_timestamp(agent.get("lastKeepAlive"))
        if last_seen is None:
            continue
        hours = max((now - last_seen).total_seconds() / 3600, 0)
        if hours > 336:
            continue
        if hours <= 24:
            active += 1
            continue
        if hours >= 168:
            category, key, priority = "Inactive 7-14 days", "inactive_7_14d", 3
        elif hours >= 72:
            category, key, priority = "Inactive 3-7 days", "inactive_3_7d", 2
        else:
            category, key, priority = "Inactive 24-72 hours", "inactive_24_72", 1
        bucket_counts[key] += 1
        os_data = agent.get("os") if isinstance(agent.get("os"), dict) else {}
        os_name = str(
            (os_data or {}).get("name")
            or (os_data or {}).get("platform")
            or (os_data or {}).get("version")
            or "Unknown"
        )
        inactive_agents.append({
            "name": str(agent.get("name") or "Unknown"),
            "id": str(agent.get("id") or "-"),
            "os": os_name,
            "last_seen": fmt_report_dt(last_seen),
            "inactive": fmt_age(last_seen, now),
            "hours": hours,
            "category": category,
            "priority": priority,
        })
    inactive_agents.sort(key=lambda item: (-item["priority"], -item["hours"], item["name"].lower()))
    try:
        max_rows = max(int(_env("REPORT_AGENT_MAX_ROWS", "10")), 0)
    except ValueError:
        max_rows = 10
    inactive = len(inactive_agents)
    total = active + inactive
    dashboard_url = _env("REPORT_AGENT_STATUS_URL", "")
    if not dashboard_url:
        dashboard_base = _env("DASHBOARD_BASE_URL", "").rstrip("/")
        if dashboard_base:
            dashboard_url = f"{dashboard_base}/app/endpoints-summary#/agents-preview/"
    return {
        "total": total,
        "active": active,
        "inactive": inactive,
        **bucket_counts,
        "inactive_agents": inactive_agents[:max_rows],
        "inactive_more": max(inactive - max_rows, 0),
        "dashboard_url": dashboard_url,
        "source": "wazuh-manager",
    }


def soc2_compliance_snapshot(
    cli: Any, start: dt.date, end: dt.date,
) -> Dict[str, Any]:
    """Summarize Wazuh alerts mapped to SOC 2 Trust Services Criteria.

    This is operational monitoring evidence, not an audit opinion. A single
    alert can map to multiple TSC controls, so control bucket counts can exceed
    the number of alert documents.
    """
    index = _env("OPENSEARCH_ALERT_INDEX", "wazuh-alerts-*") or "wazuh-alerts-*"
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
                    {"exists": {"field": "rule.tsc"}},
                ]
            }
        },
        "aggs": {
            "unique_controls": {"cardinality": {"field": "rule.tsc"}},
            "top_controls": {"terms": {"field": "rule.tsc", "size": 6}},
            "affected_agents": {"cardinality": {"field": "agent.name"}},
            "severity": {
                "range": {
                    "field": "rule.level",
                    "ranges": [
                        {"key": "Low", "to": 7},
                        {"key": "Medium", "from": 7, "to": 12},
                        {"key": "High", "from": 12, "to": 15},
                        {"key": "Critical", "from": 15},
                    ],
                }
            },
        },
    }
    response = cli.query_index(index, body)
    hits_total = ((response.get("hits") or {}).get("total") or 0)
    if isinstance(hits_total, dict):
        hits_total = hits_total.get("value", 0)
    aggs = response.get("aggregations") or {}
    severity_buckets = {
        str(bucket.get("key")): int(bucket.get("doc_count", 0) or 0)
        for bucket in ((aggs.get("severity") or {}).get("buckets") or [])
        if isinstance(bucket, dict)
    }
    severity = [
        (label, severity_buckets.get(label, 0))
        for label in ("Critical", "High", "Medium", "Low")
    ]
    critical_high = severity_buckets.get("Critical", 0) + severity_buckets.get("High", 0)
    total_alerts = int(hits_total or 0)
    if critical_high:
        status, status_kind = "Attention required", "red"
        status_note = f"{critical_high:,} critical/high TSC-mapped alerts require review."
    elif total_alerts:
        status, status_kind = "Monitoring", "amber"
        status_note = "TSC-mapped activity was recorded with no critical/high alerts."
    else:
        status, status_kind = "No mapped alerts", "green"
        status_note = "No TSC-mapped alerts were recorded during this reporting period."
    top_controls = [
        (str(bucket.get("key") or "Unspecified"), int(bucket.get("doc_count", 0) or 0))
        for bucket in ((aggs.get("top_controls") or {}).get("buckets") or [])
        if isinstance(bucket, dict)
    ]
    return {
        "status": status,
        "status_kind": status_kind,
        "status_note": status_note,
        "total_alerts": total_alerts,
        "critical_high": critical_high,
        "unique_controls": int((aggs.get("unique_controls") or {}).get("value", 0) or 0),
        "affected_agents": int((aggs.get("affected_agents") or {}).get("value", 0) or 0),
        "severity": severity,
        "top_controls": top_controls,
        "dashboard_url": _env("REPORT_SOC2_COMPLIANCE_URL", ""),
        "source": index,
    }


SOC2_MET, SOC2_ATTENTION, SOC2_NO_DATA = "met", "attention", "none"


def _soc2_target(name: str, default: float) -> float:
    try:
        raw = _env(name, "")
        return float(raw) if raw else float(default)
    except ValueError:
        return float(default)


def _pct(value: str) -> Optional[float]:
    """'99.98%' -> 99.98. None when the string is not a percentage."""
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return None


def soc2_criteria(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Map the period's own metrics onto the TSC criteria they evidence.

    Each row names a control, states what the week's data shows, and marks it
    'met' when the control operated with no exception in the data, 'attention'
    when it operated but the numbers show a gap, or 'none' when the source was
    enabled but had nothing to read. Rows whose source section is switched off
    are left out — the report never claims evidence it did not gather.

    This is operational evidence of SOC activity, not an audit opinion: nothing
    here asserts that a criterion is satisfied for attestation purposes.
    """
    sections = data.get("_sections_enabled", {})
    exec_ = data.get("exec") or {}
    sla = data.get("sla") or {}
    compliance = data.get("soc2") or {}
    agents = data.get("agent_status") or {}
    vuln = data.get("vuln") or {}
    availability = data.get("availability") or {}
    sla_target = _soc2_target("REPORT_SOC2_SLA_TARGET_PCT", 95)
    coverage_target = _soc2_target("REPORT_SOC2_COVERAGE_TARGET_PCT", 95)
    rows: List[Dict[str, str]] = []

    def row(criterion: str, control: str, status: str, evidence: str) -> None:
        rows.append({"criterion": criterion, "control": control,
                     "status": status, "evidence": evidence})

    # CC7.1 — detection: TSC-mapped alerting off the Wazuh estate.
    if compliance.get("unavailable"):
        row("CC7.1", "Threat and anomaly detection", SOC2_NO_DATA,
            "TSC-mapped alert data could not be read for this period.")
    else:
        alerts = int(compliance.get("total_alerts", 0) or 0)
        critical_high = int(compliance.get("critical_high", 0) or 0)
        if alerts:
            # Detection that surfaces critical alerts is the control working, not
            # failing — the response to them is judged by CC7.3 / CC7.4 below.
            controls = int(compliance.get("unique_controls", 0) or 0)
            seen_on = int(compliance.get("affected_agents", 0) or 0)
            # Wazuh rule level, not the Jira severity behind the incident counts —
            # say so, so the two numbers are not read as the same funnel.
            detail = f"{alerts:,} TSC-mapped alerts across {controls:,} control(s) on {seen_on:,} agent(s)"
            row("CC7.1", "Threat and anomaly detection", SOC2_MET,
                f"{detail}; {critical_high:,} at critical/high Wazuh rule level" if critical_high
                else f"{detail}; none at critical/high rule level")
        else:
            row("CC7.1", "Threat and anomaly detection", SOC2_MET,
                "Detection pipeline operational; no TSC-mapped alerts recorded this period.")

    # CC7.1 — the other half of detection: what scanning found, and how fast it was fixed.
    if sections.get("vuln", True) and vuln:
        v_sla = (vuln.get("sla") or {}).get("overall")
        total_open = int(vuln.get("total_open", 0) or 0)
        resolved = int(vuln.get("resolved", 0) or 0)
        control = "Vulnerability identification and remediation"
        found = (f'{total_open:,} open ({int(vuln.get("crit_open", 0) or 0):,} critical, '
                 f'{int(vuln.get("high_open", 0) or 0):,} high); ')
        if resolved and v_sla is not None:
            row("CC7.1", control, SOC2_MET if v_sla >= sla_target else SOC2_ATTENTION,
                f"{found}{resolved:,} remediated this period, {v_sla}% within remediation SLA")
        elif resolved:
            row("CC7.1", control, SOC2_MET, f"{found}{resolved:,} remediated this period")
        elif total_open:
            # Identification ran, remediation did not: a week that closes nothing
            # while exposure is open has no remediation evidence to show.
            row("CC7.1", control, SOC2_ATTENTION, f"{found}none remediated this period")
        else:
            row("CC7.1", control, SOC2_MET,
                "No open vulnerabilities outstanding at the reporting cut-off.")

    # CC7.2 — monitoring coverage: an agent that stopped reporting is a blind spot.
    if sections.get("agent_status", True):
        total_agents = int(agents.get("total", 0) or 0)
        if agents.get("unavailable") or not total_agents:
            row("CC7.2", "Continuous security monitoring", SOC2_NO_DATA,
                "Agent heartbeat data could not be read for this period.")
        else:
            active = int(agents.get("active", 0) or 0)
            coverage = round(active / total_agents * 100)
            row("CC7.2", "Continuous security monitoring",
                SOC2_MET if coverage >= coverage_target else SOC2_ATTENTION,
                f"{active:,} of {total_agents:,} agents reporting within 24h ({coverage}%)")

    # CC7.3 — every alert that mattered became a ticket an analyst worked.
    opened = int(exec_.get("opened", 0) or 0)
    timings = [f"{label} {exec_.get(key)}" for key, label in
               (("mttd", "mean time to detect"), ("mttt", "mean time to ticket"))
               if exec_.get(key) and exec_.get(key) != "—"]
    if opened:
        detail = f"{opened:,} incidents raised and triaged"
        row("CC7.3", "Security event evaluation and ticketing", SOC2_MET,
            f"{detail}; {', '.join(timings)}" if timings else detail)
    else:
        row("CC7.3", "Security event evaluation and ticketing", SOC2_MET,
            "No security events required evaluation this period.")

    # CC7.4 — response speed, against the severity SLA the report already publishes.
    overall = sla.get("overall")
    if overall is None:
        row("CC7.4", "Incident response within SLA", SOC2_NO_DATA,
            "No incidents were resolved this period, so SLA attainment is not evidenced.")
    else:
        resolved_total = int(sla.get("total", 0) or 0)
        row("CC7.4", "Incident response within SLA",
            SOC2_MET if overall >= sla_target else SOC2_ATTENTION,
            f'{overall}% of {resolved_total:,} resolved incidents met their severity SLA '
            f'({int(sla.get("met", 0) or 0):,}/{resolved_total:,})')

    # CC7.5 — recovery: a backlog that keeps pace, not a demand for a zeroed queue.
    closed = int(exec_.get("closed", 0) or 0)
    still_open = int(exec_.get("open", 0) or 0)
    closure_target = _soc2_target("REPORT_SOC2_CLOSURE_TARGET_PCT", 90)
    closure_rate = round(closed / opened * 100) if opened else 100
    recovery = (f"{closed:,} closed against {opened:,} raised ({closure_rate}%); "
                f"{still_open:,} open at the reporting cut-off")
    if exec_.get("mttc") and exec_.get("mttc") != "—":
        recovery += f'; mean time to close {exec_["mttc"]}'
    row("CC7.5", "Incident resolution and recovery",
        SOC2_MET if closure_rate >= closure_target else SOC2_ATTENTION, recovery)

    # A1.2 — availability, only when the client's monitoring feed is in the report.
    if sections.get("availability", True) and availability:
        uptime, target = availability.get("uptime", ""), availability.get("sla", "")
        uptime_pct, target_pct = _pct(uptime), _pct(target)
        detail = f"{uptime} uptime against a {target} target" if target else f"{uptime} uptime"
        outages = int(availability.get("outages", 0) or 0)
        detail += f"; {outages:,} outage(s) recorded"
        if uptime_pct is None or target_pct is None:
            row("A1.2", "Monitored system availability", SOC2_NO_DATA,
                "Availability data could not be read for this period.")
        else:
            row("A1.2", "Monitored system availability",
                SOC2_MET if uptime_pct >= target_pct and not outages else SOC2_ATTENTION, detail)
    return rows


def jira_site_url() -> str:
    """Jira site URL, from JIRA_SITE_URL (or JIRA_BASE_URL, as athena-pallas names it)."""
    return _env("JIRA_SITE_URL", "") or _env("JIRA_BASE_URL", "")


def build_jira_client(site_url: str) -> JiraClient:
    """Authenticate to Jira, auto-detecting the mode from env — same precedence as
    the athena-pallas backend:
      1. OAuth 2.0 service account: JIRA_CLIENT_ID + JIRA_CLIENT_SECRET (+ optional
         JIRA_CLOUD_ID; auto-discovered otherwise).
      2. Bearer service token:      JIRA_SITE_URL + JIRA_SERVICE_TOKEN.
      3. API token (basic):         JIRA_SITE_URL + JIRA_EMAIL + JIRA_API_TOKEN."""
    client_id = _env("JIRA_CLIENT_ID", "")
    client_secret = os.getenv("JIRA_CLIENT_SECRET") or ""
    if client_id and client_secret:
        log("Jira auth: OAuth 2.0 client credentials (service account).")
        token, cloud_id, discovered_site = fetch_jira_oauth(client_id, client_secret, _env("JIRA_CLOUD_ID", ""))
        # Ticket/search links must point at the real site, not the api.atlassian.com
        # gateway. Prefer an explicit JIRA_SITE_URL, else the discovered site.
        browse = site_url or discovered_site
        if not browse:
            log("Warning: no site URL for ticket links — set JIRA_SITE_URL for clickable links.", level="WARN")
        return JiraClient(f"{ATLASSIAN_API_BASE}/{cloud_id}", bearer=token, browse_base=browse)

    service_token = os.getenv("JIRA_SERVICE_TOKEN")
    if site_url and service_token:
        log("Jira auth: Bearer service token.")
        return JiraClient(site_url, bearer=service_token)

    email = _env("JIRA_EMAIL", "") or _env("JIRA_USER_EMAIL", "")
    token = os.getenv("JIRA_API_TOKEN")
    if site_url and email and token:
        log("Jira auth: API token.")
        return JiraClient(site_url, email=email, token=token)

    raise JiraError("No Jira credentials. Set JIRA_CLIENT_ID + JIRA_CLIENT_SECRET (OAuth), "
                    "or JIRA_SITE_URL + JIRA_SERVICE_TOKEN (Bearer), "
                    "or JIRA_SITE_URL + JIRA_EMAIL + JIRA_API_TOKEN (API token).")


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
    """Interpret a lifecycle duration field value as seconds."""
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


def lifecycle_seconds(fields: Dict[str, Any], duration_field: Optional[str],
                      start_field: Optional[str], end_field: Optional[str],
                      duration_unit: str = "minutes") -> Optional[float]:
    """Read a lifecycle duration, falling back to a semantically matching timestamp interval."""
    sec = coerce_seconds(fields.get(duration_field), duration_unit) if duration_field else None
    if sec is None and start_field and end_field:
        start_at = parse_jira_dt(fields.get(start_field))
        end_at = parse_jira_dt(fields.get(end_field))
        sec = (end_at - start_at).total_seconds() if start_at and end_at else None
    return sec if sec is not None and sec >= 0 else None


def lifecycle_value_is_usable(kind: str, seconds: Optional[float]) -> bool:
    """Reject Pallas's zero-MTTD fallback while retaining valid zeroes elsewhere."""
    return seconds is not None and not (kind == "mttd" and seconds == 0)


def fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return "<1m"
    total_minutes = int((seconds + 30) // 60)
    d, rem = divmod(total_minutes, 1440)
    h, m = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m:02d}m"
    return f"{m}m"


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
    """Strip a leading zero at the start of a date/time component, not after punctuation."""
    return re.sub(r"(?<!\S)0(\d)", r"\1", text)


def report_timezone() -> dt.tzinfo:
    """REPORT_TIMEZONE as a tzinfo (default US Eastern), falling back to UTC when
    the name is unknown or the platform has no zone database."""
    tz_name = _env("REPORT_TIMEZONE", "America/New_York")
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz_name)
    except Exception:
        return dt.timezone.utc


def zone_label(when: dt.datetime) -> str:
    """Zone abbreviation for a moment, generalised across US daylight saving:
    EDT/EST -> ET, CDT/CST -> CT, MDT/MST -> MT, PDT/PST -> PT."""
    abbr = when.strftime("%Z") or "UTC"
    us = {"EST": "ET", "EDT": "ET", "CST": "CT", "CDT": "CT",
          "MST": "MT", "MDT": "MT", "PST": "PT", "PDT": "PT"}
    return us.get(abbr, abbr)


def fmt_report_dt(when: dt.datetime, fmt: str = "%d %b %Y, %H:%M") -> str:
    """A moment in REPORT_TIMEZONE, zone-labelled — e.g. '4 Aug 2026, 11:40 ET'.

    Every timestamp the report shows a reader goes through here, so the client
    reads one clock throughout instead of mixing UTC with their own zone.
    """
    local = when.astimezone(report_timezone())
    return f"{strip_leading_zero(local.strftime(fmt))} {zone_label(local)}"


def generated_string() -> str:
    """Now, in REPORT_TIMEZONE (default US Eastern), e.g. '6 Jul 2026, 09:01 ET'."""
    return fmt_report_dt(dt.datetime.now(report_timezone()))


def period_label(start: dt.date, end: dt.date) -> str:
    last = end - dt.timedelta(days=1)
    return strip_leading_zero(f"{start:%a %d %b} – {last:%a %d %b %Y}")


# --------------------------------------------------------------------------- #
# Jira report builder
# --------------------------------------------------------------------------- #

def auto_commentary(*, opened_n: int, closed_n: int, open_n: int, prev_open: Optional[int],
                    mttc_secs: Optional[float], prev_mttc_secs: Optional[float] = None,
                    inc_sla: Optional[Dict[str, Any]],
                    type_breakdown: Sequence[Tuple[str, int]], open_rows: Sequence[Dict[str, Any]],
                    include_vuln: bool, v_resolved: int, v_new: int,
                    vuln_sla: Optional[Dict[str, Any]]) -> str:
    """Assemble a factual 2-paragraph narrative from the week's computed metrics.

    Deterministic (no LLM / network) — every figure traces to data already in the
    report. Used as the default when no manual commentary is supplied; the analyst
    can still override via supplemental JSON or REPORT_COMMENTARY.
    """
    def worst(sla: Optional[Dict[str, Any]]) -> Optional[Tuple[str, int]]:
        rows = (sla or {}).get("rows") or []
        cand = sorted((met / total, label) for label, met, total, _ in rows if total)
        if not cand:
            return None
        frac, label = cand[0]
        return label.split(" ≤")[0], round(frac * 100)

    p1 = [
        f"During the week, <b>{opened_n:,}</b> incident{'' if opened_n == 1 else 's'} opened "
        f"and <b>{closed_n:,}</b> closed"
    ]
    if open_n:
        p1.append(f", leaving {open_n:,} open at the reporting cut-off")
        if prev_open is not None and open_n != prev_open:
            p1.append(f" (down from {prev_open:,} the week prior)" if open_n < prev_open
                      else f" (up from {prev_open:,} the week prior)")
    else:
        p1.append(", clearing the incident queue entirely")
    p1.append(".")
    if mttc_secs:
        # Only "held" when it actually held — the tile beside this line shows the
        # week-on-week delta, and the two must not tell different stories.
        moved = (None if prev_mttc_secs in (None, 0)
                 else (mttc_secs - prev_mttc_secs) / prev_mttc_secs)
        if moved is None or abs(moved) < 0.10:
            p1.append(f" Mean time to close held at {fmt_duration(mttc_secs)}.")
        else:
            direction = "rose to" if moved > 0 else "improved to"
            p1.append(f" Mean time to close {direction} {fmt_duration(mttc_secs)} "
                      f"from {fmt_duration(prev_mttc_secs)} the week prior.")
    if inc_sla and inc_sla.get("overall") is not None:
        p1.append(f" Overall <b>{inc_sla['overall']}%</b> of resolved incidents met their severity SLA")
        w = worst(inc_sla)
        if w and w[1] < 95:
            p1.append(f" — though {w[0]} resolution, at {w[1]}%, fell short of target and is our focus "
                      "for the coming week")
        p1.append(".")

    p2: List[str] = []
    if open_rows:
        top = open_rows[0]
        p2.append(f"The most significant item open at week end was <b>{render.esc(top['ref'])}</b> — "
                  f"{render.esc(top['summary'])} ({render.esc(top['sev'])}).")
    if type_breakdown:
        label, cnt = type_breakdown[0]
        p2.append(f" The most common classification this week was {render.esc(label)} ({cnt:,}).")
    if include_vuln:
        vt = (f" On exposure, we remediated <b>{v_resolved:,}</b> "
              f"vulnerabilit{'y' if v_resolved == 1 else 'ies'} against {v_new:,} newly detected")
        if vuln_sla and vuln_sla.get("overall") is not None:
            vt += f", {vuln_sla['overall']}% of them within the patch-management SLA"
        vt += "."
        p2.append(vt)

    out = [f"<p>{''.join(p1)}</p>"]
    if p2:
        out.append(f"<p>{''.join(p2)}</p>")
    return "".join(out)


def build_report(cli: Any, args: argparse.Namespace) -> Dict[str, Any]:
    key = args.project_key
    now = dt.datetime.now(dt.timezone.utc)
    anchor = dt.date.fromisoformat(args.week_of) if args.week_of else (now.date() - dt.timedelta(days=7))
    start, end = week_window(anchor, args.week_start)
    p_start, p_end = start - dt.timedelta(days=7), start  # prior week
    build_started = time.perf_counter()
    log(
        "Report build start: "
        f"project={key} client={args.client} tenant={args.tenant} "
        f"period={d(start)}..{d(end)} prior={d(p_start)}..{d(p_end)}"
    )

    log("Report build phase: resolve mirrored field ids.")
    sev_field = cli.field_id(args.severity_field) or "Severity"
    mttd_field = cli.field_id(args.mttd_field)
    mttt_field = cli.field_id(args.mttt_field)
    mttr_field = cli.field_id(args.mttr_field)
    mttc_field = cli.field_id(args.mttc_field)
    itime_field = cli.field_id(args.incident_time_field)
    alert_time_field = cli.field_id(args.alert_time_field)
    first_response_time_field = cli.field_id(args.first_response_time_field)
    log(
        "Fields: "
        f"severity={sev_field} mttd={mttd_field} mttt={mttt_field} "
        f"mttr={mttr_field} mttc={mttc_field} incident_time={itime_field} "
        f"alert_time={alert_time_field} first_response_time={first_response_time_field}"
    )

    inc_v2l, inc_standard_label_values = incident_sev_maps()
    inc_nids_v2l, inc_nids_label_values = nids_incident_sev_maps()
    inc_all_label_values = {
        label: list(dict.fromkeys(inc_standard_label_values.get(label, []) + inc_nids_label_values.get(label, [])))
        for label in SEV_ORDER
        if inc_standard_label_values.get(label) or inc_nids_label_values.get(label)
    }
    inc_filter_labels = _configured_incident_labels(inc_all_label_values)
    inc_filter_values = [value for label in inc_filter_labels for value in inc_all_label_values.get(label, [])]
    inc_filter_values = list(dict.fromkeys(inc_filter_values))
    inc_labels = [label for label in SEV_ORDER if label in inc_filter_labels]
    vuln_v2l, vuln_all_label_values = vulnerability_sev_maps()
    vuln_labels, vuln_label_values = _sev_display(vuln_v2l)
    vuln_filter_labels = _configured_vuln_labels(vuln_all_label_values)
    vuln_filter_values = [value for label in vuln_filter_labels for value in vuln_all_label_values.get(label, [])]
    vuln_labels = [label for label in vuln_labels if any(value in vuln_filter_values for value in vuln_label_values[label])]
    log(
        f"Incident severities: standard={inc_standard_label_values} "
        f"nids={inc_nids_label_values} · Vulnerability severities: {vuln_label_values}"
    )
    log(f"Incident filter: {', '.join(inc_filter_labels)} · Vulnerability filter: {', '.join(vuln_filter_labels)}")

    def sev_in(values: Sequence[str]) -> str:
        return f'"{args.severity_field}" in (' + ", ".join(f'"{v}"' for v in values) + ")"

    def scoped(*clauses: str) -> str:
        return " AND ".join([f"project = {key}", *clauses])

    def incidents_only(jql: str) -> str:
        return jql + " AND " + sev_in(inc_filter_values)

    def incident_label(fields: Dict[str, Any]) -> Optional[str]:
        return incident_severity_label(fields, sev_field, inc_v2l, inc_nids_v2l)

    def incident_search(jql: str, fields: Sequence[str], limit: int = 2000) -> List[Dict[str, Any]]:
        requested_fields = list(dict.fromkeys([*fields, "summary", sev_field]))
        issues = cli.search(incidents_only(jql), requested_fields, limit=limit)
        return [it for it in issues if incident_label(it.get("fields", {})) in inc_filter_labels]

    def incident_count(jql: str) -> int:
        return len(incident_search(jql, [], limit=5000))

    def opened(types: str, s: dt.date, e: dt.date) -> str:
        return scoped(types, f'created >= "{d(s)}"', f'created < "{d(e)}"')

    def closed(types: str, s: dt.date, e: dt.date) -> str:
        return scoped(types, f'resolutiondate >= "{d(s)}"', f'resolutiondate < "{d(e)}"')

    def open_at(types: str, e: dt.date) -> str:
        return scoped(types, f'created < "{d(e)}"', f'(resolutiondate is EMPTY OR resolutiondate >= "{d(e)}")')

    opened_incident_jql = incidents_only(opened(INC_TYPES, start, end))
    closed_incident_jql = incidents_only(closed(INC_TYPES, start, end))
    open_incident_jql = incidents_only(open_at(INC_TYPES, end))
    # Everything the week touched: raised in the period, or resolved in it after
    # being raised earlier — the ticket list behind the week's summary line.
    week_incident_jql = incidents_only(scoped(
        INC_TYPES,
        f'((created >= "{d(start)}" AND created < "{d(end)}") '
        f'OR (resolutiondate >= "{d(start)}" AND resolutiondate < "{d(end)}"))',
    )) + " ORDER BY created DESC"
    incident_links = {
        "opened": jira_search_url(cli, opened_incident_jql),
        "week": jira_search_url(cli, week_incident_jql),
        "closed": jira_search_url(cli, closed_incident_jql),
        "open": jira_search_url(cli, open_incident_jql),
        "lifecycle_opened": jira_search_url(cli, opened_incident_jql),
        "lifecycle_closed": jira_search_url(cli, closed_incident_jql),
        "severity": jira_search_url(cli, opened_incident_jql),
        "trend": jira_search_url(cli, incidents_only(opened(INC_TYPES, start - dt.timedelta(days=35), end))),
        "type": jira_search_url(cli, opened_incident_jql),
        "sla": jira_search_url(cli, closed_incident_jql),
    }

    # ---- exec counts ----
    log("Report build phase: executive incident counts.")
    opened_n = incident_count(opened(INC_TYPES, start, end))
    closed_n = incident_count(closed(INC_TYPES, start, end))
    open_n = incident_count(open_at(INC_TYPES, end))
    p_opened, p_closed, p_open = (incident_count(opened(INC_TYPES, p_start, p_end)),
                                  incident_count(closed(INC_TYPES, p_start, p_end)),
                                  incident_count(open_at(INC_TYPES, p_end)))
    log(
        "Executive incident counts done: "
        f"opened={opened_n} closed={closed_n} open={open_n} "
        f"prior_opened={p_opened} prior_closed={p_closed} prior_open={p_open}"
    )

    # ---- severity of opened this week ----
    log("Report build phase: incident severity counts.")
    opened_issues = incident_search(opened(INC_TYPES, start, end), [])
    inc_sev = [(label, sum(1 for it in opened_issues if incident_label(it.get("fields", {})) == label))
               for label in inc_labels]
    log(f"Incident severity counts done: {inc_sev}")

    # ---- incident lifecycle: event -> alert -> ticket -> response -> close ----
    def avg_metric(jql: str, field_id: Optional[str], kind: str,
                   start_field: Optional[str], end_field: Optional[str]) -> Optional[float]:
        debug(
            f"Report build metric start: {kind} duration_field={field_id} "
            f"start_field={start_field} end_field={end_field} jql={jql}"
        )
        want = [f for f in [field_id, start_field, end_field] if f]
        issues = incident_search(jql, want, limit=2000)
        vals: List[float] = []
        unusable_zero = 0
        for it in issues:
            f = it.get("fields", {})
            sec = lifecycle_seconds(f, field_id, start_field, end_field, args.duration_unit)
            # A zero MTTD in Pallas means the original vendor event timestamp
            # was unavailable and alert_generated_at was used for both bounds.
            # Reporting it as "<1m" would turn missing data into a performance claim.
            if not lifecycle_value_is_usable(kind, sec):
                if kind == "mttd" and sec == 0:
                    unusable_zero += 1
                continue
            vals.append(sec)
        avg = sum(vals) / len(vals) if vals else None
        log(
            f"Report build metric done: {kind} issue_count={len(issues)} "
            f"usable_values={len(vals)} zero_fallback_values={unusable_zero} avg_seconds={avg}"
        )
        return avg

    log("Report build phase: lifecycle metrics.")
    lifecycle_specs = {
        "mttd": (mttd_field, itime_field, alert_time_field, opened),
        "mttt": (mttt_field, alert_time_field, "created", opened),
        "mttr": (mttr_field, "created", first_response_time_field, opened),
        "mttc": (mttc_field, itime_field, "resolutiondate", closed),
    }
    lifecycle: Dict[str, Optional[float]] = {}
    prior_lifecycle: Dict[str, Optional[float]] = {}
    for kind, (duration_field, start_field, end_field, window) in lifecycle_specs.items():
        lifecycle[kind] = avg_metric(
            window(INC_TYPES, start, end), duration_field, kind, start_field, end_field)
        prior_lifecycle[kind] = avg_metric(
            window(INC_TYPES, p_start, p_end), duration_field, kind, start_field, end_field)
    mttd, mttt, mttr, mttc = (lifecycle[k] for k in ("mttd", "mttt", "mttr", "mttc"))
    p_mttd, p_mttt, p_mttr, p_mttc = (prior_lifecycle[k] for k in ("mttd", "mttt", "mttr", "mttc"))
    log(
        "Lifecycle metrics done: "
        f"mttd={fmt_duration(mttd)} mttt={fmt_duration(mttt)} "
        f"mttr={fmt_duration(mttr)} mttc={fmt_duration(mttc)}"
    )

    # ---- 6-week trend ----
    log("Report build phase: 6-week incident trend.")
    trend = []
    for i in range(6):
        ws = start - dt.timedelta(days=7 * (5 - i))
        we = ws + dt.timedelta(days=7)
        trend.append({
            "label": "This wk" if i == 5 else f"W-{5 - i}",
            "opened": incident_count(opened(INC_TYPES, ws, we)),
            "closed": incident_count(closed(INC_TYPES, ws, we)),
            "open": incident_count(open_at(INC_TYPES, we)),
        })
    log(f"6-week incident trend done: {trend}")

    # ---- severity over time (opened per week by severity) ----
    log("Report build phase: severity trend.")
    sev_trend = []
    for i in range(6):
        ws = start - dt.timedelta(days=7 * (5 - i))
        we = ws + dt.timedelta(days=7)
        row: Dict[str, Any] = {"label": "This wk" if i == 5 else f"W-{5 - i}"}
        week_issues = incident_search(opened(INC_TYPES, ws, we), [])
        for label in inc_labels:
            row[label] = sum(1 for it in week_issues if incident_label(it.get("fields", {})) == label)
        sev_trend.append(row)
    log(f"Severity trend done: {sev_trend}")

    # ---- open incidents detail ----
    log("Report build phase: open incident detail.")
    src_field = cli.field_id(args.source_field) if args.source_field not in ("components", "labels") else args.source_field
    det_fields = [
        "summary", "issuetype", "status", "assignee", "created", "components", "labels", sev_field,
    ]
    if src_field and src_field not in det_fields:
        det_fields.append(src_field)
    open_issues = incident_search(open_at(INC_TYPES, end), det_fields, limit=2000)
    if isinstance(cli, OpenSearchClient):
        status_counts: Dict[str, int] = {}
        source_counts: Dict[str, int] = {}
        for issue in open_issues:
            fields = issue.get("fields", {})
            status = str((fields.get("status") or {}).get("name") or "Unknown")
            source = str(fields.get("source") or "Unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1
        debug(
            "Open incident diagnostics: "
            f"status_counts={status_counts} source_counts={source_counts}"
        )

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
        label = incident_label(f) or (inc_labels[-1] if inc_labels else "Medium")
        return label, render.SEV_CLASS[label]

    def assignee_of(f: Dict[str, Any]) -> str:
        value = f.get("assignee")
        if isinstance(value, dict):
            value = (
                value.get("displayName")
                or value.get("name")
                or value.get("value")
                or value.get("emailAddress")
                or value.get("accountId")
            )
        return str(value).strip() if value else "Unassigned"

    open_issues.sort(key=lambda it: (
        SEV_ORDER.index(incident_label(it.get("fields", {})) or "Low"),
        parse_jira_dt(it.get("fields", {}).get("created")) or now,
    ))
    open_detail_count = len(open_issues)
    open_issues = open_issues[:args.max_open_rows]
    report_end_at = dt.datetime.combine(end, dt.time.min, tzinfo=dt.timezone.utc)
    age_as_of = min(now, report_end_at)
    open_rows = []
    for it in open_issues:
        f = it.get("fields", {})
        lbl, cls = sev_label(f)
        created = parse_jira_dt(f.get("created"))
        open_rows.append({
            "ref": it["key"], "ref_url": f"{cli.browse_base}/browse/{it['key']}",
            "type": (f.get("issuetype") or {}).get("name", "").replace("Security ", ""),
            "sev": lbl, "sev_class": cls,
            "summary": f.get("summary", ""), "source": source_of(f),
            "opened": fmt_report_dt(created, "%d %b %H:%M") if created else "—",
            "age": fmt_age(created, age_as_of), "assignee": assignee_of(f),
            "status": (f.get("status") or {}).get("name", ""),
        })
    log(
        "Open incident detail done: "
        f"week_end_count={open_detail_count} row_count={len(open_rows)} as_of={end.isoformat()}"
    )

    # ---- closed selected ----
    log("Report build phase: closed incident detail.")
    closed_fields = (
        ["summary", "issuetype", "assignee", sev_field]
        + [f for f in [mttc_field, itime_field] if f]
        + ["created", "resolutiondate", "components", "labels"]
    )
    closed_issues = incident_search(closed(INC_TYPES, start, end), closed_fields, limit=2000)
    closed_issues.sort(key=lambda it: (
        SEV_ORDER.index(incident_label(it.get("fields", {})) or "Low"),
        -(parse_jira_dt(it.get("fields", {}).get("resolutiondate")) or dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)).timestamp(),
    ))
    closed_issues = closed_issues[:args.max_closed_rows]
    closed_rows = []
    for it in closed_issues:
        f = it.get("fields", {})
        lbl, cls = sev_label(f)
        sec = lifecycle_seconds(f, mttc_field, itime_field, "resolutiondate", args.duration_unit)
        closed_rows.append({
            "ref": it["key"], "ref_url": f"{cli.browse_base}/browse/{it['key']}",
            "type": (f.get("issuetype") or {}).get("name", "").replace("Security ", ""),
            "sev": lbl, "sev_class": cls, "summary": f.get("summary", ""),
            "source": source_of(f), "assignee": assignee_of(f), "ttc": fmt_duration(sec),
        })
    log(f"Closed incident detail done: issue_count={len(closed_issues)} row_count={len(closed_rows)}")

    # ---- incidents by type (opened this week, grouped by the Type-of-Incident field) ----
    log("Report build phase: incident type breakdown.")
    type_field = cli.field_id(args.incident_type_field)
    type_breakdown: List[Tuple[str, int]] = []
    if type_field:
        tally: Dict[str, int] = {}
        for it in incident_search(opened(INC_TYPES, start, end), [type_field], limit=2000):
            val = it.get("fields", {}).get(type_field)
            names: List[str] = []
            if isinstance(val, list):  # multi-select
                for item in val:
                    name = item.get("value") if isinstance(item, dict) else item
                    if name:
                        names.append(str(name))
            elif isinstance(val, dict):
                name = val.get("value") or val.get("name")
                if name:
                    names.append(str(name))
            elif val:
                names.append(str(val))
            for name in (names or ["Unclassified"]):
                tally[name] = tally.get(name, 0) + 1
        type_breakdown = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    log(f"Incident type breakdown done: type_field={type_field} rows={type_breakdown}")

    # ---- response SLA attainment (of incidents closed this week, % resolved within target) ----
    log("Report build phase: incident SLA.")
    sla_secs = sla_targets()
    sla_buckets: Dict[str, List[int]] = {label: [0, 0] for label in inc_labels}  # label -> [met, total]
    for it in incident_search(closed(INC_TYPES, start, end),
                              [f for f in [sev_field, mttc_field, itime_field, "resolutiondate"] if f],
                              limit=2000):
        f = it.get("fields", {})
        lbl, _ = sev_label(f)
        if lbl not in sla_buckets:
            continue
        sec = lifecycle_seconds(f, mttc_field, itime_field, "resolutiondate", args.duration_unit)
        if sec is None:
            continue
        sla_buckets[lbl][1] += 1
        if sec <= sla_secs.get(lbl, float("inf")):
            sla_buckets[lbl][0] += 1
    sla_rows: List[Tuple[str, int, int, str]] = []
    sla_met = sla_total = 0
    for label in inc_labels:
        met, total = sla_buckets[label]
        if total == 0:
            continue
        sla_met += met
        sla_total += total
        pct = met / total
        kind = "ok" if pct >= 0.95 else ("warn" if pct >= 0.8 else "bad")
        sla_rows.append((f"{label} ≤ {fmt_sla_target(sla_secs[label])}", met, total, kind))
    sla = ({"rows": sla_rows, "met": sla_met, "total": sla_total,
            "overall": round(sla_met / sla_total * 100)} if sla_rows else None)
    log(f"Incident SLA done: {sla}")

    # ---- vulnerabilities ----
    log("Report build phase: vulnerability counts.")
    vuln_sev, total_open, counts_by_label = [], 0, {}
    for label in vuln_labels:
        c = cli.count(scoped(VULN_TYPE, "statusCategory != Done", "resolution is EMPTY", sev_in(vuln_label_values[label])))
        counts_by_label[label] = c
        vuln_sev.append((label, c))
        total_open += c
    v_resolved = cli.count(closed(VULN_TYPE, start, end))
    v_new = cli.count(opened(VULN_TYPE, start, end))
    v_resolved_prev = cli.count(closed(VULN_TYPE, p_start, p_end))
    if isinstance(cli, OpenSearchClient):
        new_vuln_sources: Dict[str, int] = {}
        new_vuln_types: Dict[str, int] = {}
        for issue in cli.search(opened(VULN_TYPE, start, end), ["source", "incident_type"], limit=5000):
            fields = issue.get("fields", {})
            source = str(fields.get("source") or "Unknown")
            incident_type = str(fields.get("incident_type") or "Unknown")
            new_vuln_sources[source] = new_vuln_sources.get(source, 0) + 1
            new_vuln_types[incident_type] = new_vuln_types.get(incident_type, 0) + 1
        debug(
            "Vulnerability new diagnostics: "
            f"source_counts={new_vuln_sources} type_counts={new_vuln_types}"
        )
    log(
        "Vulnerability counts done: "
        f"severity={vuln_sev} total_open={total_open} resolved={v_resolved} "
        f"new={v_new} prior_resolved={v_resolved_prev}"
    )

    # ---- vulnerability remediation SLA (of vulns resolved this week, % remediated within target) ----
    log("Report build phase: vulnerability SLA.")
    vuln_sla_secs = vuln_sla_targets()
    vuln_sla_buckets: Dict[str, List[int]] = {label: [0, 0] for label in vuln_labels}  # label -> [met, total]
    for it in cli.search(closed(VULN_TYPE, start, end), [sev_field, "created", "resolutiondate"], limit=2000):
        f = it.get("fields", {})
        raw = f.get(sev_field)
        raw = raw.get("value") if isinstance(raw, dict) else raw
        lbl = vuln_v2l.get(raw)
        if lbl not in vuln_sla_buckets:
            continue
        c, r = parse_jira_dt(f.get("created")), parse_jira_dt(f.get("resolutiondate"))
        sec = (r - c).total_seconds() if c and r else None
        if sec is None:
            continue
        vuln_sla_buckets[lbl][1] += 1
        if sec <= vuln_sla_secs.get(lbl, float("inf")):
            vuln_sla_buckets[lbl][0] += 1
    vuln_sla_rows: List[Tuple[str, int, int, str]] = []
    vsla_met = vsla_total = 0
    for label in vuln_labels:
        met, total = vuln_sla_buckets[label]
        if total == 0:
            continue
        vsla_met += met
        vsla_total += total
        pct = met / total
        kind = "ok" if pct >= 0.95 else ("warn" if pct >= 0.8 else "bad")
        vuln_sla_rows.append((f"{label} ≤ {fmt_sla_target(vuln_sla_secs[label])}", met, total, kind))
    vuln_sla = ({"rows": vuln_sla_rows, "met": vsla_met, "total": vsla_total,
                 "overall": round(vsla_met / vsla_total * 100)} if vuln_sla_rows else None)
    log(f"Vulnerability SLA done: {vuln_sla}")

    # ---- analyst commentary: manual override wins, else auto-generate from the metrics ----
    log("Report build phase: commentary.")
    include_vuln = section_enablement().get("vuln", True)
    manual_commentary = ((args.supplemental_data or {}).get("commentary") or os.getenv("REPORT_COMMENTARY") or "").strip()
    if manual_commentary:
        commentary = manual_commentary
    elif _env_bool("REPORT_COMMENTARY_AUTO", True):
        commentary = auto_commentary(
            opened_n=opened_n, closed_n=closed_n, open_n=open_n, prev_open=p_open,
            mttc_secs=mttc, prev_mttc_secs=p_mttc, inc_sla=sla, type_breakdown=type_breakdown, open_rows=open_rows,
            include_vuln=include_vuln, v_resolved=v_resolved, v_new=v_new, vuln_sla=vuln_sla)
    else:
        commentary = ""
    log(f"Commentary done: source={'manual' if manual_commentary else ('auto' if commentary else 'empty')} length={len(commentary)}")

    log("Report build phase: top CVEs.")
    top_crit = top_cves(cli, scoped(VULN_TYPE, "statusCategory != Done", sev_in(vuln_label_values.get("Critical", ["Sev-1"]))), args, "crit")
    top_high = top_cves(cli, scoped(VULN_TYPE, "statusCategory != Done", sev_in(vuln_label_values.get("High", ["Sev-2"]))), args, "high")
    log(f"Top CVEs done: critical={top_crit} high={top_high}")

    log("Report build phase: project metadata.")
    project_name = os.getenv("REPORT_PROJECT_NAME") or cli.project_name(key) or ""
    log(f"Project metadata done: project_name={project_name}")

    sections_enabled = section_enablement()
    agent_data = (args.supplemental_data or {}).get("agent_status")
    if sections_enabled.get("agent_status", True) and agent_data is None:
        log("Report build phase: agent heartbeat status.")
        try:
            agent_data = agent_status_snapshot(cli, now)
            log(
                "Agent heartbeat status done: "
                f"total={agent_data['total']} active={agent_data['active']} inactive={agent_data['inactive']}"
            )
        except (WazuhManagerError, OpenSearchError, AttributeError, TypeError, ValueError) as exc:
            log(f"Agent heartbeat status unavailable: {exc}", level="WARNING")
            agent_data = {"unavailable": True}

    soc2_data = (args.supplemental_data or {}).get("soc2")
    if sections_enabled.get("soc2", True) and soc2_data is None:
        log("Report build phase: SOC 2 TSC monitoring status.")
        try:
            soc2_data = soc2_compliance_snapshot(cli, start, end)
            log(
                "SOC 2 TSC monitoring status done: "
                f"alerts={soc2_data['total_alerts']} "
                f"critical_high={soc2_data['critical_high']} "
                f"controls={soc2_data['unique_controls']}"
            )
        except (OpenSearchError, AttributeError, TypeError, ValueError) as exc:
            log(f"SOC 2 TSC monitoring status unavailable: {exc}", level="WARNING")
            soc2_data = {"unavailable": True}

    vuln_open_jql = scoped(VULN_TYPE, "statusCategory != Done", "resolution is EMPTY", sev_in(vuln_filter_values))
    vuln_closed_jql = closed(VULN_TYPE, start, end)
    vuln_new_jql = opened(VULN_TYPE, start, end)
    vuln_links = {
        "critical": jira_search_url(cli, scoped(VULN_TYPE, "statusCategory != Done", "resolution is EMPTY", sev_in(vuln_label_values.get("Critical", ["Sev-1"])))),
        "high": jira_search_url(cli, scoped(VULN_TYPE, "statusCategory != Done", "resolution is EMPTY", sev_in(vuln_label_values.get("High", ["Sev-2"])))),
        "resolved": jira_search_url(cli, vuln_closed_jql),
        "new": jira_search_url(cli, vuln_new_jql),
        "severity": jira_search_url(cli, vuln_open_jql),
        "sla": jira_search_url(cli, vuln_closed_jql),
    }
    data: Dict[str, Any] = {
        "client": args.client, "environment": args.environment, "tenant": args.tenant,
        "project_key": key, "project_name": project_name,
        "period_label": period_label(start, end), "week_start": "Sunday" if args.week_start.lower().startswith("sun") else "Monday",
        "_period_end": (end - dt.timedelta(days=1)).isoformat(),
        "generated": generated_string(),
        "support_email": args.support_email or f"alerts@{args.tenant}",
        "preview_note": None,
        "exec": {
            "opened": opened_n, "opened_delta": delta_html(opened_n, p_opened, favorable=None),
            "closed": closed_n, "closed_delta": delta_html(closed_n, p_closed, favorable="up"),
            "open": open_n, "open_delta": delta_html(open_n, p_open, favorable="down"),
            "mttd": fmt_duration(mttd),
            "mttd_delta": (
                "source event time unavailable" if mttd is None else _dur_delta(mttd, p_mttd)
            ),
            "mttt": fmt_duration(mttt), "mttt_delta": _dur_delta(mttt, p_mttt),
            "mttr": fmt_duration(mttr), "mttr_delta": _dur_delta(mttr, p_mttr),
            "mttc": fmt_duration(mttc), "mttc_delta": _dur_delta(mttc, p_mttc),
            "uptime": (args.supplemental_data.get("availability", {}).get("uptime", "—") if args.supplemental_data else "—"),
            "uptime_note": (f'SLA {args.supplemental_data.get("availability", {}).get("sla", "")} · met' if args.supplemental_data and args.supplemental_data.get("availability") else "provided separately"),
            "links": incident_links,
        },
        "commentary": commentary,
        "inc_severity": inc_sev, "inc_total_opened": opened_n,
        "type_breakdown": type_breakdown, "sla": sla,
        "trend": trend, "sev_trend": sev_trend, "sev_trend_labels": inc_labels,
        "inc_links": incident_links,
        "inc_src": "Athena Pallas · Jira-synced Security Alert + Security Incident",
        "inc_summary_line": (
            f"During the week, <b>{opened_n:,}</b> incidents opened and <b>{closed_n:,}</b> closed. "
            f"At the reporting cut-off, <b>{open_n:,}</b> remained open."
            if opened_n or closed_n else ""
        ),
        "open_count": open_n, "open_rows": open_rows,
        "open_more": max(open_detail_count - len(open_rows), 0),
        "closed_count": closed_n, "closed_rows": closed_rows,
        "closed_more": max(closed_n - len(closed_rows), 0),
        "vuln": {
            "crit_open": counts_by_label.get("Critical", 0), "high_open": counts_by_label.get("High", 0),
            "critical_note": "", "high_note": "", "resolved": v_resolved,
            "resolved_delta": delta_html(v_resolved, v_resolved_prev, favorable="up"),
            "new": v_new, "net": v_new - v_resolved, "severity": vuln_sev,
            "total_open": total_open, "top_crit": top_crit, "top_high": top_high, "sla": vuln_sla,
            "links": vuln_links, "note": "",
        },
        "agent_status": agent_data,
        "soc2": soc2_data,
        "soc2_src": "Wazuh · Trust Services Criteria (TSC) monitoring",
        "vuln_src": "Athena Pallas · Jira-synced vulnerabilities",
        "_sections_enabled": sections_enabled,
    }
    # Supplemental data can override generated sections for previews or offline runs.
    if args.supplemental_data:
        for section in ("device", "endpoint", "agent_status", "soc2", "availability"):
            if section in args.supplemental_data:
                data[section] = args.supplemental_data[section]
    # Last, so the criteria read the finished metrics — including any supplemental override.
    if sections_enabled.get("soc2", True):
        criteria = soc2_criteria(data)
        data["soc2"] = {**(data.get("soc2") or {}), "criteria": criteria}
        log(f"SOC 2 criteria done: rows={len(criteria)} "
            f"met={sum(1 for r in criteria if r['status'] == SOC2_MET)}")
    log(f"Report build done: elapsed={time.perf_counter() - build_started:.2f}s sections={sections_enabled}")
    return data


def _dur_delta(cur: Optional[float], prev: Optional[float]) -> str:
    if cur is None or prev is None:
        return "no prior-week data"
    diff = cur - prev
    if abs(diff) < 30:
        return "no change vs last week"
    arrow = "▲" if diff > 0 else "▼"
    cls = "down" if diff > 0 else "up"  # faster (down) is favorable
    return f'<b class="{cls}">{arrow} {fmt_duration(abs(diff))}</b> vs last week'


def _adf_text(node: Any) -> str:
    """Flatten Atlassian Document Format (rich text used by description/comments in
    Jira REST v3) into plain text so a CVE regex can run over it."""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        return (node.get("text") or "") + " " + " ".join(_adf_text(c) for c in node.get("content") or [])
    if isinstance(node, list):
        return " ".join(_adf_text(c) for c in node)
    return ""


def _find_cves(text: str) -> set:
    return {m.upper() for m in CVE_RE.findall(text or "")}


def top_cves(cli: Any, jql: str, args: argparse.Namespace, kind: str) -> List[Tuple[str, str, Any]]:
    """Per ticket, take CVEs from the Vulnerability ID(s) field first; if that field
    has none, fall back to the description, then to the comments."""
    vid_field = cli.field_id(args.vuln_id_field)
    fields = ["description", "comment"] + ([vid_field] if vid_field else [])
    counts: Dict[str, int] = {}
    for it in cli.search(jql, fields, limit=1000):
        f = it.get("fields", {})
        cves = _find_cves(str(f.get(vid_field) or "")) if vid_field else set()
        if not cves:
            cves = _find_cves(_adf_text(f.get("description")))
        if not cves:
            comments = (f.get("comment") or {}).get("comments") or []
            cves = _find_cves(" ".join(_adf_text(c.get("body")) for c in comments))
        for cve in cves:
            counts[cve] = counts.get(cve, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    return [(cve, f"{cli.browse_base}/issues/?jql=" + urllib.parse.quote(f'text ~ "{cve}"'), n) for cve, n in top]


# --------------------------------------------------------------------------- #
# Sample data (matches the approved template preview)
# --------------------------------------------------------------------------- #

def sample_data() -> Dict[str, Any]:
    jira_filter = "https://example.atlassian.net/issues/?jql=project%3DNSO"
    incident_links = {
        key: jira_filter for key in (
            "opened", "closed", "open", "week", "lifecycle_opened", "lifecycle_closed",
            "severity", "trend", "type", "sla",
        )
    }
    vuln_links = {key: jira_filter for key in ("critical", "high", "resolved", "new", "severity", "sla")}
    sample: Dict[str, Any] = {
        "client": "Neuro", "environment": "Production", "tenant": "neuro.athenasecuritygrp.com",
        "project_key": "NSO", "project_name": "Neuro Security Operations",
        "period_label": "Mon 29 Jun – Sun 5 Jul 2026", "week_start": "Monday", "_period_end": "2026-07-05",
        "_sections_enabled": {
            "device": False,
            "endpoint": False,
            "agent_status": True,
            "vuln": True,
            "availability": False,
            "soc2": True,
        },
        "generated": "6 Jul 2026, 9:01 ET", "support_email": "alerts@neuro.athenasecuritygrp.com",
        "preview_note": ("<strong>Template preview.</strong> Illustrative sample data — run "
                         "<code>generate_report.py</code> against a client's pallas-incidents index for live figures."),
        "exec": {
            "opened": 72, "opened_delta": '<b class="up">▲ 14</b> vs last week',
            "closed": 66, "closed_delta": '<b class="up">▲ 6</b> vs last week',
            "open": 6, "open_delta": '<b class="up">▼ 5</b> vs last week',
            "mttd": "14 min", "mttd_delta": '<b class="up">▼ 3 min</b> vs last week',
            "mttt": "2 min", "mttt_delta": '<b class="up">▼ 1 min</b> vs last week',
            "mttr": "11 min", "mttr_delta": '<b class="up">▼ 4 min</b> vs last week',
            "mttc": "3h 42m", "mttc_delta": '<b class="up">▼ 22 min</b> vs last week',
            "uptime": "99.98%", "uptime_note": "SLA 99.9% · met",
            "links": incident_links,
        },
        "commentary": (
            "<p>A steadier week overall. Alert volume rose 24% on the back of a phishing wave targeting "
            "finance mailboxes — all quarantined at the gateway, none reached inboxes. We tuned two "
            "detection rules to cut the noise and cleared five items carried over from last week.</p>"
            "<p>The one item worth your attention: <b>NSO-4821</b>, outbound C2 beaconing blocked at the WAF. "
            "The affected host (LAP-014) is isolated and under review; no data movement was observed. "
            "During the week, 72 incidents opened and 66 closed; 6 remained open at the reporting cut-off.</p>"
        ),
        "inc_severity": [("Critical", 8), ("High", 27), ("Medium", 37)],
        "inc_total_opened": 72,
        "type_breakdown": [
            ("Phishing", 24), ("Malware", 14), ("Suspicious sign-in", 11),
            ("Policy violation", 9), ("Unauthorized access", 7), ("Data exposure", 4), ("Other", 3),
        ],
        "sla": {
            "rows": [("Critical ≤ 4h", 8, 8, "ok"), ("High ≤ 8h", 25, 27, "ok"), ("Medium ≤ 24h", 33, 37, "warn")],
            "met": 66, "total": 72, "overall": 92,
        },
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
        "inc_src": "Athena Pallas · Jira-synced Security Alert + Security Incident",
        "inc_links": incident_links,
        "inc_summary_line": "During the week, <b>72</b> incidents opened and <b>66</b> closed. At the reporting cut-off, <b>6</b> remained open.",
        "open_count": 6,
        "open_rows": [
            {"ref": "NSO-4821", "type": "Incident", "sev": "Critical", "sev_class": "crit", "summary": "Outbound C2 beaconing blocked at WAF (185.220.101.44)", "source": "NIDS", "opened": "4 Jul 09:12", "age": "1d 4h", "assignee": "Shelly Peralta", "status": "Work in progress"},
            {"ref": "NSO-4835", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Repeated failed admin sign-ins — Microsoft 365", "source": "Office 365", "opened": "4 Jul 22:40", "age": "14h", "assignee": "Shelly Peralta", "status": "Pending"},
            {"ref": "NSO-4840", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Defender real-time protection off (LAP-014)", "source": "Defender", "opened": "5 Jul 07:05", "age": "6h", "assignee": "Joseph Khoury", "status": "Work in progress"},
            {"ref": "NSO-4844", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Suspicious PowerShell execution (WKS-233)", "source": "Endpoint", "opened": "5 Jul 10:22", "age": "3h", "assignee": "Unassigned", "status": "Monitoring"},
            {"ref": "NSO-4849", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Cloudflare WAF rule triggered — SQL-injection attempt", "source": "Cloudflare", "opened": "5 Jul 11:48", "age": "1h", "assignee": "Joseph Khoury", "status": "Work in progress"},
            {"ref": "NSO-4852", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Phishing email quarantined — sender rule tuned", "source": "Office 365", "opened": "5 Jul 13:10", "age": "20m", "assignee": "Shelly Peralta", "status": "Monitoring"},
        ],
        "closed_count": 66,
        "closed_rows": [
            {"ref": "NSO-4790", "type": "Incident", "sev": "Critical", "sev_class": "crit", "summary": "Ransomware-pattern process quarantined (WKS-101)", "source": "Endpoint", "assignee": "Shelly Peralta", "ttc": "2h 10m"},
            {"ref": "NSO-4805", "type": "Alert", "sev": "High", "sev_class": "high", "summary": "Brute-force source IP blocked at firewall", "source": "NIDS", "assignee": "Joseph Khoury", "ttc": "38m"},
            {"ref": "NSO-4812", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Impossible-travel sign-in reviewed & cleared", "source": "Office 365", "assignee": "Shelly Peralta", "ttc": "1h 05m"},
            {"ref": "NSO-4818", "type": "Alert", "sev": "Medium", "sev_class": "med", "summary": "Phishing email quarantined & rule tuned", "source": "Office 365", "assignee": "Shelly Peralta", "ttc": "12m"},
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
            "inactive_agents": [["LAP-014", "Windows 11", "4 Jul 18:15 ET", "34h"],
                                 ["dev-nrm-01", "Ubuntu 22.04", "4 Jul 14:25 ET", "38h"]],
        },
        "agent_status": {
            "total": 84, "active": 78, "inactive": 6,
            "inactive_24_72": 2, "inactive_3_7d": 3, "inactive_7_14d": 1,
            "dashboard_url": "https://neuro.athenasecuritygrp.com/app/endpoints-summary#/agents-preview/",
            "inactive_agents": [
                {"name": "LAP-014", "id": "041", "os": "Windows 11", "last_seen": "4 Jul 2026, 18:15 ET", "inactive": "34h", "category": "Inactive 24-72 hours"},
                {"name": "dev-nrm-01", "id": "057", "os": "Ubuntu 22.04", "last_seen": "1 Jul 2026, 14:25 ET", "inactive": "3d 19h", "category": "Inactive 3-7 days"},
                {"name": "WKS-233", "id": "063", "os": "Windows 11", "last_seen": "26 Jun 2026, 5:10 ET", "inactive": "9d 4h", "category": "Inactive 7-14 days"},
            ],
            "inactive_more": 3,
        },
        "soc2": {
            "status": "Attention required",
            "status_kind": "red",
            "status_note": "3 critical/high TSC-mapped alerts require review.",
            "total_alerts": 42,
            "critical_high": 3,
            "unique_controls": 8,
            "affected_agents": 12,
            "severity": [("Critical", 1), ("High", 2), ("Medium", 14), ("Low", 25)],
            "top_controls": [("CC6.1", 12), ("CC7.2", 9), ("CC7.3", 7), ("CC8.1", 5)],
            "dashboard_url": "https://neuro.athenasecuritygrp.com/app/discover#/",
            "source": "wazuh-alerts-*",
        },
        "soc2_src": "Wazuh · Trust Services Criteria (TSC) monitoring",
        "vuln": {
            "crit_open": 4, "high_open": 31, "critical_note": "across the estate",
            "high_note": "across 12 assets", "resolved": 47,
            "resolved_delta": '<b class="up">▲ 12</b> vs last week', "new": 22, "net": -25,
            "severity": [("Critical", 4), ("High", 31), ("Medium", 96), ("Low", 140)], "total_open": 271,
            "sla": {
                "rows": [("Critical ≤ 7d", 5, 5, "ok"), ("High ≤ 14d", 18, 19, "ok"),
                         ("Medium ≤ 30d", 20, 23, "warn")],
                "met": 43, "total": 47, "overall": 91,
            },
            "top_crit": [("CVE-2026-13775", "#", 9), ("CVE-2026-13780", "#", 8),
                         ("CVE-2026-13781", "#", 7), ("CVE-2026-13796", "#", 6),
                         ("CVE-2026-13802", "#", 5), ("CVE-2026-13818", "#", 4)],
            "top_high": [("CVE-2026-43701", "#", 8), ("CVE-2026-43715", "#", 8),
                         ("CVE-2025-47273", "#", 5), ("CVE-2024-6345", "#", 5),
                         ("CVE-2026-43722", "#", 4), ("CVE-2025-51904", "#", 3)],
            "links": vuln_links,
            "note": "The OpenSSL cluster on SRV-DB-02 is prioritized via NSO-4851.",
        },
        "vuln_src": "Athena Pallas · Jira-synced vulnerabilities",
        "availability": {"uptime": "99.98%", "sla": "99.9%", "outages": 0, "outages_note": "none recorded",
                          "maintenance": 1, "maint_note": "8 min · off-hours", "monitoring": "24 / 7"},
    }
    sample["soc2"]["criteria"] = soc2_criteria(sample)
    return sample


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a weekly Security Operations Report from OpenSearch.")
    p.add_argument("--sample", action="store_true", help="Render with built-in sample data (no OpenSearch needed).")
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
    p.add_argument("--mttd-field", help="Duration field for event-to-alert detection time. Env: JIRA_MTTD_FIELD.")
    p.add_argument("--mttt-field", help="Duration field for alert-to-Jira-ticket time. Env: JIRA_MTTT_FIELD.")
    p.add_argument("--mttr-field", help="Duration field for Jira-ticket-to-first-response time. Env: JIRA_MTTR_FIELD.")
    p.add_argument("--mttc-field", help="Duration field for endpoint-event-to-close time. Env: JIRA_MTTC_FIELD.")
    p.add_argument("--incident-time-field", help="Event occurrence timestamp field. Env: JIRA_INCIDENT_TIME_FIELD.")
    p.add_argument("--alert-time-field", help="Athena Core alert generation timestamp field. Env: JIRA_ALERT_TIME_FIELD.")
    p.add_argument("--first-response-time-field", help="First analyst response timestamp field. Env: JIRA_FIRST_RESPONSE_TIME_FIELD.")
    p.add_argument("--incident-type-field", default="Type of Incident", help="Field driving the 'Incidents by type' breakdown.")
    p.add_argument("--vuln-id-field", default="Vulnerability ID(s)")
    p.add_argument("--source-field", default="components", help="'components', 'labels', or a custom field name for the alert source.")
    p.add_argument("--duration-unit", default="minutes", choices=["seconds", "minutes", "hours"], help="Unit of numeric lifecycle duration fields.")
    p.add_argument("--max-open-rows", type=int, default=40)
    p.add_argument("--max-closed-rows", type=int, default=6)

    p.add_argument(
        "--supplemental",
        help="JSON file with optional device/endpoint/agent-status/SOC-2/availability overrides.",
    )
    p.add_argument("--email", action="store_true",
                   help="Also write an email-safe HTML version (<out>-email.html) for pasting into Outlook.")

    p.add_argument("--send-email", action="store_true",
                   help="Send the report through Microsoft Graph. Opt-in — never sent automatically. "
                        "Requires ENTRA_* and REPORT_EMAIL_* in .env.")
    p.add_argument("--email-dry-run", action="store_true",
                   help="Compose the email and print subject/recipients without sending or connecting to Graph.")
    p.add_argument("--email-to", help="Comma-separated recipient override. Env: REPORT_EMAIL_TO.")
    p.add_argument("--email-cc", help="Comma-separated Cc override. Env: REPORT_EMAIL_CC.")
    p.add_argument("--email-bcc", help="Comma-separated Bcc override. Env: REPORT_EMAIL_BCC.")
    p.add_argument("--email-subject", help="Subject template ({client} {period} {environment} {tenant}). Env: REPORT_EMAIL_SUBJECT.")
    p.add_argument("--email-body", choices=["email", "full"],
                   help="Inline body: 'email' = table-based, renders everywhere (default); "
                        "'full' = the SVG report inline (charts/colours break in Outlook & Gmail). Env: REPORT_EMAIL_BODY.")
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
    args.support_email = args.support_email or os.getenv("REPORT_SUPPORT_EMAIL") or f"secops@{args.tenant}"
    # Pallas writes these four lifecycle values to pallas-incidents in minutes.
    args.mttd_field = args.mttd_field or os.getenv("JIRA_MTTD_FIELD") or "MTTD (Minutes)"
    args.mttt_field = args.mttt_field or os.getenv("JIRA_MTTT_FIELD") or "MTTT (Minutes)"
    args.mttr_field = args.mttr_field or os.getenv("JIRA_MTTR_FIELD") or "MTTR (Minutes)"
    args.mttc_field = args.mttc_field or os.getenv("JIRA_MTTC_FIELD") or "MTTC (Minutes)"
    args.incident_time_field = args.incident_time_field or os.getenv("JIRA_INCIDENT_TIME_FIELD") or "Incident Time (Eastern Time - ET)"
    args.alert_time_field = args.alert_time_field or os.getenv("JIRA_ALERT_TIME_FIELD") or "Alert Generated Time"
    args.first_response_time_field = args.first_response_time_field or os.getenv("JIRA_FIRST_RESPONSE_TIME_FIELD") or "First Response Time"
    ws = (args.week_start or os.getenv("REPORT_WEEK_START") or "monday").lower()
    args.week_start = "sunday" if ws.startswith("sun") else "monday"


def main(argv: Sequence[str]) -> int:
    main_started = time.perf_counter()
    log(f"Report main start: log_level={_configured_log_level()} argv_flags={[arg for arg in argv if str(arg).startswith('--')]}")
    args = parse_args(argv)
    log(
        "Report args parsed: "
        f"sample={args.sample} out_dir={args.out_dir} week_of={args.week_of} "
        f"send_email={args.send_email} email_dry_run={args.email_dry_run} "
        f"email_preview={args.email} project_key={args.project_key} client={args.client} tenant={args.tenant}"
    )
    load_dotenv(args.env_file, override=True) if args.env_file else load_dotenv()
    log(f"Dotenv load done: explicit_env_file={bool(args.env_file)}")
    out_dir = args.out_dir or os.getenv("REPORT_OUTPUT_DIR") or "reports"
    log(f"Output directory resolved: {out_dir}")

    args.supplemental_data = {}
    if args.supplemental:
        log(f"Supplemental load start: {args.supplemental}")
        with open(args.supplemental, "r", encoding="utf-8") as fh:
            args.supplemental_data = json.load(fh)
        log(f"Supplemental load done: keys={sorted(args.supplemental_data.keys())}")

    if args.sample:
        log("Sample data build start.")
        data = sample_data()
        log("Sample data build done.")
    else:
        site = jira_site_url()
        resolve_config(args, site)
        log(
            "Report config resolved: "
            f"project_key={args.project_key} client={args.client} tenant={args.tenant} "
            f"environment={args.environment} support_email={args.support_email} week_start={args.week_start}"
        )
        if not args.project_key:
            log("No project key. Pass --project-key or set JIRA_PROJECT_KEY in .env.", level="ERROR")
            return 2
        try:
            log("OpenSearch client build start.")
            cli = OpenSearchClient.from_env()
            log("OpenSearch client build done.")
        except OpenSearchError as exc:
            log(str(exc), level="ERROR")
            return 2
        data = build_report(cli, args)

    data.setdefault("_sections_enabled", section_enablement())

    # Output stays inside this repo unless an absolute --out is given.
    html_path = anchor(args.out) if args.out else anchor(os.path.join(out_dir, f"{slugify(data['client'])}-{data.get('_period_end', 'report')}.html"))
    log(f"Render start: html_path={html_path}")
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    report_html = render.render_report(data)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(report_html)
    log(f"Wrote {os.path.relpath(html_path, SCRIPT_DIR)}")
    log("For a PDF: open the HTML and Print → Save as PDF.")

    # Charts as PNG so they render inside email clients (Outlook/Gmail strip SVG).
    log("Chart render start.")
    charts_png = charts.build_charts(data)
    log(f"Chart render done: chart_count={len(charts_png)} chart_names={sorted(charts_png)}")

    email_path = None
    if args.email:
        log("Email preview render start.")
        import render_email
        # Self-contained preview: embed PNGs as data: URIs so the file stands alone.
        data["_chart_src"] = {n: "data:image/png;base64," + base64.b64encode(b).decode("ascii")
                              for n, b in charts_png.items()}
        email_path = re.sub(r"\.html?$", "", html_path) + "-email.html"
        with open(email_path, "w", encoding="utf-8") as fh:
            fh.write(render_email.render_email(data))
        data.pop("_chart_src", None)
        log(f"Wrote {os.path.relpath(email_path, SCRIPT_DIR)} (email-safe — open it, select all, copy, paste into Outlook).")

    if args.send_email or args.email_dry_run:
        log(f"Email step start: send_email={args.send_email} dry_run={args.email_dry_run}")
        import mailer
        attachment = (os.path.basename(html_path), report_html)
        try:
            mailer.send_report_email(data, args, log=log, attachment=attachment, charts=charts_png)
        except mailer.MailerError as exc:
            log(f"Email not sent: {exc}", level="ERROR")
            return 2
        log("Email step done.")

    if args.open_after:
        webbrowser.open("file://" + os.path.abspath(email_path or html_path))
    log(f"Report main done: elapsed={time.perf_counter() - main_started:.2f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
