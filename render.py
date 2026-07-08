"""Render a weekly Security Operations Report to standalone HTML.

Pure presentation: takes a plain ``data`` dict (see ``sample_data`` for the shape)
and returns an HTML string. No Jira / network access lives here, so the same
renderer serves ``--sample`` and live runs alike.
"""
from __future__ import annotations

import html
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

SEV_ORDER = ("Critical", "High", "Medium", "Low")
SEV_CLASS = {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low"}
SEV_VAR = {"crit": "var(--crit)", "high": "var(--high)", "med": "var(--med)", "low": "var(--low)"}

_STYLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_style.css")


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def load_css() -> str:
    with open(_STYLE_PATH, "r", encoding="utf-8") as handle:
        return handle.read()


# --------------------------------------------------------------------------- #
# Chart geometry
# --------------------------------------------------------------------------- #

_NICE = [1, 2, 2.5, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000, 10000]


def _nice_step(raw: float) -> float:
    for step in _NICE:
        if step >= raw:
            return step
    return _NICE[-1]


def _axis_max(max_value: float, intervals: int) -> Tuple[float, List[float]]:
    """Return (axis_max, tick_values) leaving headroom so labels never overflow."""
    target = max(max_value, 1) * 1.08 / intervals
    step = _nice_step(target)
    axis_max = step * intervals
    ticks = [step * i for i in range(intervals + 1)]
    return axis_max, ticks


def _fmt_tick(value: float) -> str:
    return f"{int(value):,}" if value == int(value) else f"{value:,g}"


def hbar_svg(rows: Sequence[Tuple[str, int, str]]) -> str:
    """Horizontal severity bars. rows = [(label, value, sev_class), ...]."""
    x0, x1 = 110.0, 545.0
    span = x1 - x0
    top, rowh, barh = 12, 40, 20
    n = len(rows)
    grid_y2 = 20 + (n - 1) * rowh + barh + 10
    ticks_y = grid_y2 + 18
    svg_h = ticks_y + 12
    max_val = max((v for _, v, _ in rows), default=1)
    axis_max, ticks = _axis_max(max_val, 3)

    def tx(v: float) -> float:
        return x0 + (v / axis_max) * span

    parts: List[str] = [
        f'<svg viewBox="0 0 560 {svg_h}" role="img" '
        f'aria-label="{esc("; ".join(f"{lbl} {val}" for lbl, val, _ in rows))}">'
    ]
    parts.append('<g class="g-grid">')
    for t in ticks:
        parts.append(f'<line x1="{tx(t):.1f}" y1="{top}" x2="{tx(t):.1f}" y2="{grid_y2}"/>')
    parts.append("</g>")
    parts.append('<g class="g-tick" text-anchor="middle">')
    for t in ticks:
        parts.append(f'<text x="{tx(t):.1f}" y="{ticks_y}">{_fmt_tick(t)}</text>')
    parts.append("</g>")
    for i, (label, value, sev) in enumerate(rows):
        by = 20 + i * rowh
        base = by + 14
        w = max(tx(value) - x0, 2)
        parts.append(f'<text class="g-cat" x="100" y="{base}" text-anchor="end">{esc(label)}</text>')
        parts.append(f'<rect x="{x0:.0f}" y="{by}" width="{w:.1f}" height="{barh}" rx="4" fill="{SEV_VAR.get(sev, "var(--low)")}"/>')
        parts.append(f'<text class="g-val" x="{x0 + w + 8:.1f}" y="{base}">{value:,}</text>')
    parts.append(f'<line class="g-axis" x1="{x0:.0f}" y1="{top}" x2="{x0:.0f}" y2="{grid_y2}"/>')
    parts.append("</svg>")
    return "".join(parts)


def _ellipsize(text: Any, max_chars: int) -> str:
    """Trim over-long category labels so they never spill past the chart gutter."""
    s = str(text)
    return s if len(s) <= max_chars else s[: max_chars - 1].rstrip() + "…"


def catbar_svg(rows: Sequence[Tuple[str, int]], color: str = "var(--brand)") -> str:
    """Categorical horizontal bars in a single accent colour. rows = [(label, value), ...].

    The label gutter (0..x0) is wide because 'Type of Incident' values can be long
    (e.g. 'Attempted Administrator Privilege Gain'); anything past ~38 chars is
    ellipsized, with the full text kept in a <title> for hover/accessibility.
    """
    x0, x1 = 280.0, 545.0
    lab_x = x0 - 12
    max_label = 38
    span = x1 - x0
    top, rowh, barh = 12, 32, 18
    n = len(rows)
    grid_y2 = 20 + (n - 1) * rowh + barh + 10
    ticks_y = grid_y2 + 18
    svg_h = ticks_y + 12
    max_val = max((v for _, v in rows), default=1)
    axis_max, ticks = _axis_max(max_val, 3)

    def tx(v: float) -> float:
        return x0 + (v / axis_max) * span

    parts: List[str] = [
        f'<svg viewBox="0 0 560 {svg_h}" role="img" '
        f'aria-label="{esc("; ".join(f"{lbl} {val}" for lbl, val in rows))}">'
    ]
    parts.append('<g class="g-grid">')
    for t in ticks:
        parts.append(f'<line x1="{tx(t):.1f}" y1="{top}" x2="{tx(t):.1f}" y2="{grid_y2}"/>')
    parts.append("</g>")
    parts.append('<g class="g-tick" text-anchor="middle">')
    for t in ticks:
        parts.append(f'<text x="{tx(t):.1f}" y="{ticks_y}">{_fmt_tick(t)}</text>')
    parts.append("</g>")
    for i, (label, value) in enumerate(rows):
        by = 20 + i * rowh
        base = by + 13
        w = max(tx(value) - x0, 2)
        parts.append(
            f'<text class="g-cat" x="{lab_x:.0f}" y="{base}" text-anchor="end">'
            f'<title>{esc(label)}</title>{esc(_ellipsize(label, max_label))}</text>'
        )
        parts.append(f'<rect x="{x0:.0f}" y="{by}" width="{w:.1f}" height="{barh}" rx="4" fill="{color}"/>')
        parts.append(f'<text class="g-val" x="{x0 + w + 8:.1f}" y="{base}">{value:,}</text>')
    parts.append(f'<line class="g-axis" x1="{x0:.0f}" y1="{top}" x2="{x0:.0f}" y2="{grid_y2}"/>')
    parts.append("</svg>")
    return "".join(parts)


def lines_svg(weeks: Sequence[Dict[str, Any]], series: Sequence[Tuple[str, str]], label: str = "Six-week trend") -> str:
    """Multi-line week chart. series = [(key, color), ...]; weeks carry those keys + 'label'."""
    n = len(weeks)
    x_left, x_right = 60.0, 500.0
    top, bottom = 28.0, 208.0
    step_x = (x_right - x_left) / max(n - 1, 1)
    all_vals = [w[k] for w in weeks for k, _ in series]
    axis_max, ticks = _axis_max(max(all_vals, default=1), 4)

    def px(i: int) -> float:
        return x_left + i * step_x

    def py(v: float) -> float:
        return bottom - (v / axis_max) * (bottom - top)

    parts: List[str] = [f'<svg viewBox="0 0 560 232" role="img" aria-label="{esc(label)}">']
    parts.append('<g class="g-grid">')
    for t in ticks:
        parts.append(f'<line x1="42" y1="{py(t):.1f}" x2="500" y2="{py(t):.1f}"/>')
    parts.append("</g>")
    parts.append('<g class="g-tick" text-anchor="end">')
    for t in ticks:
        parts.append(f'<text x="34" y="{py(t) + 4:.1f}">{_fmt_tick(t)}</text>')
    parts.append("</g>")
    parts.append('<g class="g-tick" text-anchor="middle">')
    for i, w in enumerate(weeks):
        parts.append(f'<text x="{px(i):.1f}" y="226">{esc(w["label"])}</text>')
    parts.append("</g>")
    for key, color in series:
        pts = " ".join(f"{px(i):.1f},{py(w[key]):.1f}" for i, w in enumerate(weeks))
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="{pts}"/>')
    ends = []
    for key, color in series:
        ends.append({"color": color, "val": weeks[-1][key], "y": py(weeks[-1][key])})
        parts.append(f'<circle cx="500" cy="{py(weeks[-1][key]):.1f}" r="4" fill="{color}" stroke="var(--chart-surface)" stroke-width="2"/>')
    placed: List[float] = []
    for end in sorted(ends, key=lambda e: e["y"]):
        ly = end["y"]
        while any(abs(ly - p) < 13 for p in placed):
            ly += 1
        placed.append(ly)
        parts.append(f'<text class="g-end" x="510" y="{ly + 4:.1f}" fill="{end["color"]}">{end["val"]:,}</text>')
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# HTML sections
# --------------------------------------------------------------------------- #

def _pill(sev_class: str, label: str) -> str:
    return f'<span class="pill {sev_class}">{esc(label)}</span>'


def _tile(cls: str, lab: str, num: str, delta_html: str, small: bool = False) -> str:
    sm = " sm" if small else ""
    cls_attr = f" {cls}" if cls else ""
    return (
        f'<div class="tile{cls_attr}"><div class="lab">{esc(lab)}</div>'
        f'<div class="num{sm}">{esc(num)}</div><div class="delta">{delta_html}</div></div>'
    )


def _legend(items: Sequence[Tuple[str, str]]) -> str:
    spans = "".join(f'<span><i class="swatch" style="background:{color}"></i>{esc(label)}</span>' for label, color in items)
    return f'<div class="legend">{spans}</div>'


def _meters(meters: Sequence[Sequence[Any]]) -> str:
    out = []
    for label, got, total, kind in meters:
        pct = 0 if not total else round(got / total * 100)
        fill_cls = {"ok": "", "warn": " warn", "bad": " bad", "blue": " blue"}.get(kind, "")
        out.append(
            f'<div class="meter-row"><span class="ml">{esc(label)}</span>'
            f'<span class="track"><span class="fill{fill_cls}" style="width:{pct}%"></span></span>'
            f'<span class="mv">{got:,} / {total:,}</span></div>'
        )
    return "".join(out)


def _stat_cls(pct: float) -> str:
    return "ok" if pct >= 95 else ("warn" if pct >= 80 else "bad")


def _sla_meters(rows: Sequence[Sequence[Any]]) -> str:
    """SLA-attainment rows: label, a coloured bar, the attainment % (the headline), then the count."""
    out = []
    for label, met, total, kind in rows:
        pct = 0 if not total else round(met / total * 100)
        cls = kind if kind in ("ok", "warn", "bad", "blue") else "ok"
        out.append(
            '<div class="sla-row">'
            f'<span class="sla-lab">{esc(label)}</span>'
            f'<span class="sla-track"><span class="sla-fill {cls}" style="width:{pct}%"></span></span>'
            f'<span class="sla-pct {cls}">{pct}%</span>'
            f'<span class="sla-cnt">{met:,} / {total:,}</span>'
            "</div>"
        )
    return "".join(out)


def _sec_head(eyebrow: str, title: str, src: str) -> str:
    return (
        f'<div class="sec-head"><span class="eyebrow">{esc(eyebrow)}</span>'
        f'<h2>{esc(title)}</h2><span class="src">{esc(src)}</span></div>'
    )


def _exec(d: Dict[str, Any], n: int = 1) -> str:
    e = d["exec"]
    tiles = [
        _tile("blue", "Incidents opened", f'{e["opened"]:,}', e["opened_delta"]),
        _tile("green", "Incidents closed", f'{e["closed"]:,}', e["closed_delta"]),
        _tile("red", "Open at week end", f'{e["open"]:,}', e["open_delta"]),
        _tile("", "Mean time to detect", e["mttd"], e["mttd_delta"], small=True),
        _tile("", "Mean time to resolve", e["mttr"], e["mttr_delta"], small=True),
        _tile("green", "System availability", e["uptime"], e["uptime_note"], small=True),
    ]
    return (
        "<section>" + _sec_head(f"{n:02d} · This week at a glance", "Executive summary", "") +
        '<div class="tiles t6">' + "".join(tiles) + "</div>"
        '<p class="caption">Running totals across the full reporting week, not a snapshot. '
        "▲/▼ compare to the prior week; green marks the favorable direction.</p></section>"
    )


def _commentary(d: Dict[str, Any]) -> str:
    """Analyst narrative — the human read on the week. Operator-authored, may contain light HTML."""
    text = (d.get("commentary") or "").strip()
    if not text:
        return ""
    return (
        '<section><div class="comment">'
        '<div class="comment-h"><span class="eyebrow">From your SOC team</span>'
        "<h3>This week in summary</h3></div>"
        f'<div class="comment-body">{text}</div></div></section>'
    )


def _inc_open_rows(rows: Sequence[Dict[str, Any]]) -> str:
    out = []
    for r in rows:
        ref = f'<a class="id" href="{esc(r.get("ref_url", "#"))}">{esc(r["ref"])}</a>' if r.get("ref_url") else f'<span class="id">{esc(r["ref"])}</span>'
        out.append(
            "<tr>"
            f"<td>{ref}</td>"
            f'<td><span class="tag">{esc(r["type"])}</span></td>'
            f'<td>{_pill(r["sev_class"], r["sev"])}</td>'
            f'<td class="sum">{esc(r["summary"])}</td>'
            f"<td>{esc(r['source'])}</td>"
            f'<td class="num-cell">{esc(r["opened"])}</td>'
            f'<td class="num-cell">{esc(r["age"])}</td>'
            f"<td>{esc(r['status'])}</td>"
            "</tr>"
        )
    return "".join(out)


def _inc_closed_rows(rows: Sequence[Dict[str, Any]], more: int) -> str:
    out = []
    for r in rows:
        ref = f'<a class="id" href="{esc(r.get("ref_url", "#"))}">{esc(r["ref"])}</a>' if r.get("ref_url") else f'<span class="id">{esc(r["ref"])}</span>'
        out.append(
            "<tr>"
            f"<td>{ref}</td>"
            f'<td><span class="tag">{esc(r["type"])}</span></td>'
            f'<td>{_pill(r["sev_class"], r["sev"])}</td>'
            f'<td class="sum">{esc(r["summary"])}</td>'
            f"<td>{esc(r['source'])}</td>"
            f'<td class="r num-cell">{esc(r["ttr"])}</td>'
            "</tr>"
        )
    if more > 0:
        out.append(f'<tr><td colspan="6" class="subtle" style="text-align:center;">+ {more:,} further items resolved this week — full log available on request</td></tr>')
    return "".join(out)


def _incidents(d: Dict[str, Any], n: int = 2) -> str:
    sev_rows = [(lbl, val, SEV_CLASS[lbl]) for lbl, val in d["inc_severity"]]
    open_rows = _inc_open_rows(d["open_rows"])
    closed_rows = _inc_closed_rows(d["closed_rows"], d.get("closed_more", 0))
    status_series = [("opened", "var(--s-opened)"), ("closed", "var(--s-closed)"), ("open", "var(--s-open)")]
    status_legend = _legend([("Opened", "var(--s-opened)"), ("Closed", "var(--s-closed)"), ("Open at week end", "var(--s-open)")])
    # Severity-over-time (Peter's "severity over time") — full-width card, when present.
    sev_card = ""
    sev_labels = d.get("sev_trend_labels", [])
    if d.get("sev_trend") and sev_labels:
        sev_series = [(lbl, SEV_VAR[SEV_CLASS[lbl]]) for lbl in sev_labels]
        sev_card = (
            '<div class="card" style="margin-top:16px;"><p class="card-h">Severity over time</p>'
            '<p class="caption" style="margin:2px 0 6px;">Incidents opened per week, by severity</p>'
            + _legend(sev_series) + lines_svg(d["sev_trend"], sev_series, "Severity over time") + "</div>"
        )
    # Incidents-by-type + response-SLA attainment — paired row, each shown only when present.
    type_card = ""
    if d.get("type_breakdown"):
        type_card = (
            '<div class="card"><p class="card-h">Incidents by type</p>'
            '<p class="caption" style="margin:2px 0 6px;">Opened this week, by classification</p>'
            f'<div class="chart-fill">{catbar_svg(d["type_breakdown"])}</div></div>'
        )
    sla_card = ""
    sla = d.get("sla")
    if sla and sla.get("rows"):
        overall = sla.get("overall")
        overall_line = (
            f'<p class="caption" style="margin-top:12px;">Overall <b class="txt-{_stat_cls(overall)}">{overall}%</b> '
            f'of the {sla.get("total", 0):,} incidents resolved this week met their severity SLA.</p>'
            if overall is not None else ""
        )
        sla_card = (
            '<div class="card"><p class="card-h">Response SLA attainment</p>'
            '<p class="caption" style="margin:2px 0 10px;">Share resolved within target time, by severity '
            '<span class="subtle">— green ≥ 95%, amber ≥ 80%, red below</span></p>'
            + _sla_meters(sla["rows"]) + overall_line + "</div>"
        )
    extra = ""
    if type_card:  # full-width: long 'Type of Incident' labels need the room
        extra += f'<div style="margin-top:16px;">{type_card}</div>'
    if sla_card:
        extra += f'<div style="margin-top:16px;">{sla_card}</div>'
    return (
        "<section>" + _sec_head(f"{n:02d} · Detection & response", "Incident management", d.get("inc_src", "Jira SECOPS · Security Alert + Security Incident")) +
        '<div class="grid2">'
        '<div class="card"><p class="card-h">Opened by severity</p>'
        f'<p class="caption" style="margin:2px 0 6px;">This week · {sum(val for _, val in d["inc_severity"]):,} shown</p>'
        f'<div class="chart-fill">{hbar_svg(sev_rows)}</div></div>'
        '<div class="card"><p class="card-h">Six-week trend</p>'
        '<p class="caption" style="margin:2px 0 6px;">Opened, closed &amp; still-open per week</p>'
        + status_legend + f'<div class="chart-fill">{lines_svg(d["trend"], status_series, "Opened, closed and open per week")}</div></div></div>'
        + sev_card + extra +
        f'<p class="caption">{d.get("inc_summary_line", "")}</p>'
        f'<h3 style="font-size:13px;margin:20px 0 9px;font-weight:680;">Open — currently in handling ({len(d["open_rows"])})</h3>'
        '<div class="tbl-wrap"><table><thead><tr>'
        "<th>Ref</th><th>Type</th><th>Severity</th><th>Summary</th><th>Source</th><th>Opened</th><th>Age</th><th>Status</th>"
        f"</tr></thead><tbody>{open_rows}</tbody></table></div>"
        f'<h3 style="font-size:13px;margin:20px 0 9px;font-weight:680;">Closed this week ({d["closed_count"]:,}) — selected</h3>'
        '<div class="tbl-wrap"><table><thead><tr>'
        '<th>Ref</th><th>Type</th><th>Severity</th><th>Summary</th><th>Source</th><th class="r">Time to resolve</th>'
        f"</tr></thead><tbody>{closed_rows}</tbody></table></div></section>"
    )


def _device(d: Dict[str, Any], n: int = 3) -> str:
    dev = d.get("device")
    head = _sec_head(f"{n:02d} · Managed estate", "Device management", "Microsoft Intune")
    if not dev:
        return "<section>" + head + _pending("Intune") + "</section>"
    total = dev.get("total", dev.get("managed", 0))
    enrolled = dev.get("enrolled", dev.get("compliant", 0))
    outstanding = dev.get("outstanding", dev.get("pending", 0))
    tiles = (
        _tile("blue", "Total endpoints", f"{total:,}", f'Windows {dev.get("win", 0)} · macOS {dev.get("mac", 0)}') +
        _tile("green", "Enrolled", f"{enrolled:,}", f'<b class="up">{round(enrolled / max(total, 1) * 100)}%</b> of estate') +
        _tile("amber", "Outstanding", f"{outstanding:,}", "not yet enrolled") +
        _tile("", "Compliant", f'{dev.get("compliant", 0):,}', "policy compliant")
    )
    return (
        "<section>" + head +
        '<div class="grid2"><div class="tiles t2">' + tiles + "</div>"
        '<div class="card"><p class="card-h" style="margin-bottom:8px;">Policies, definitions &amp; deployment</p>' +
        _meters(dev.get("meters", [])) +
        (f'<p class="caption" style="margin-top:12px;">{esc(dev.get("note", ""))}</p>' if dev.get("note") else "") +
        "</div></div></section>"
    )


def _endpoint(d: Dict[str, Any], n: int = 4) -> str:
    ep = d.get("endpoint")
    head = _sec_head(f"{n:02d} · Endpoint protection", "Endpoint management", "Defender · Athena agent status")
    if not ep:
        return "<section>" + head + _pending("Defender / agent status") + "</section>"
    tiles = (
        _tile("blue", "Protected endpoints", f'{ep["protected"]:,}', "Defender + Athena agent") +
        _tile("green", "Agents healthy", f'{ep["healthy"]:,}', f'<b class="up">{round(ep["healthy"] / max(ep["protected"], 1) * 100)}%</b> reporting') +
        _tile("red", "Endpoints at risk", f'{ep["at_risk"]:,}', ep.get("at_risk_note", "")) +
        _tile("amber", "Inactive agents", f'{ep["inactive"]:,}', "no heartbeat &gt; 24h")
    )
    inactive_tbl = ""
    if ep.get("inactive_agents"):
        rows = "".join(
            f'<tr><td><a href="#">{esc(a[0])}</a></td><td>{esc(a[1])}</td>'
            f'<td class="num-cell">{esc(a[2])}</td><td class="r"><span class="pill high">{esc(a[3])}</span></td></tr>'
            for a in ep["inactive_agents"]
        )
        inactive_tbl = (
            '<div class="tbl-wrap" style="margin-top:14px;">'
            f'<div class="callout-h">Agents needing attention — no heartbeat &gt; 24h ({len(ep["inactive_agents"])})</div>'
            '<table><thead><tr><th>Agent</th><th>Host OS</th><th>Last seen</th><th class="r">Inactive</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )
    return (
        "<section>" + head +
        '<div class="grid2"><div class="tiles t2">' + tiles + "</div>"
        '<div class="card"><p class="card-h" style="margin-bottom:8px;">Protection coverage</p>' +
        _meters(ep.get("meters", [])) + "</div></div>" + inactive_tbl + "</section>"
    )


def _vuln(d: Dict[str, Any], n: int = 5) -> str:
    v = d.get("vuln")
    head = _sec_head(f"{n:02d} · Exposure", "Vulnerability status", "Athena scanning · Jira SECOPS · Vulnerability")
    if not v:
        return "<section>" + head + _pending("Athena scanning") + "</section>"
    crit_cap = "none open" if v["crit_open"] == 0 else "all patchable"
    high_cap = v.get("high_note") or ("none open" if v["high_open"] == 0 else "across the estate")
    tiles = (
        _tile("red", "Critical open", f'{v["crit_open"]:,}', crit_cap) +
        _tile("amber", "High open", f'{v["high_open"]:,}', high_cap) +
        _tile("green", "Resolved this week", f'{v["resolved"]:,}', v["resolved_delta"]) +
        _tile("blue", "Newly detected", f'{v["new"]:,}', f'net <b>{v["net"]:+,}</b> open')
    )
    sev_rows = [(lbl, val, SEV_CLASS[lbl]) for lbl, val in v["severity"]]
    crit_rows = "".join(f'<tr><td><a href="{esc(u)}">{esc(c)}</a></td><td class="r cnt-crit">{esc(x)}</td></tr>' for c, u, x in v.get("top_crit", []))
    high_rows = "".join(f'<tr><td><a href="{esc(u)}">{esc(c)}</a></td><td class="r cnt-high">{esc(x)}</td></tr>' for c, u, x in v.get("top_high", []))
    sla = v.get("sla")
    sla_card = ""
    if sla and sla.get("rows"):
        overall = sla.get("overall")
        overall_line = (
            f'<p class="caption" style="margin-top:12px;">Overall <b class="txt-{_stat_cls(overall)}">{overall}%</b> '
            f'of the {sla.get("total", 0):,} vulnerabilities remediated this week met their patch-management SLA.</p>'
            if overall is not None else ""
        )
        sla_card = (
            '<div class="card" style="margin-top:16px;"><p class="card-h">Remediation SLA attainment</p>'
            '<p class="caption" style="margin:2px 0 10px;">Share remediated within target time, by severity '
            '<span class="subtle">— green ≥ 95%, amber ≥ 80%, red below</span></p>'
            + _sla_meters(sla["rows"]) + overall_line + "</div>"
        )
    return (
        "<section>" + head +
        '<div class="tiles t4" style="margin-bottom:16px;">' + tiles + "</div>"
        '<div class="grid2"><div class="card"><p class="card-h">Open vulnerabilities by severity</p>'
        f'<p class="caption" style="margin:2px 0 6px;">{v["total_open"]:,} open across the estate</p>'
        f'<div class="chart-fill">{hbar_svg(sev_rows)}</div></div>'
        '<div class="tbl-wrap"><div style="display:grid;grid-template-columns:1fr 1fr;">'
        f'<div class="cvebar crit">Top Critical CVEs · {v["crit_open"]:,} open</div>'
        f'<div class="cvebar high">Top High CVEs · {v["high_open"]:,} open</div></div>'
        '<div style="display:grid;grid-template-columns:1fr 1fr;">'
        f'<div><table style="min-width:0;"><tbody>{crit_rows}</tbody></table></div>'
        f'<div style="border-left:1px solid var(--line);"><table style="min-width:0;"><tbody>{high_rows}</tbody></table></div>'
        "</div></div></div>" + sla_card +
        (f'<p class="caption">{esc(v.get("note", ""))}</p>' if v.get("note") else "") +
        "</section>"
    )


def _availability(d: Dict[str, Any], n: int = 6) -> str:
    a = d.get("availability")
    head = _sec_head(f"{n:02d} · Service levels", "System availability", "Athena platform monitoring")
    if not a:
        return "<section>" + head + _pending("platform monitoring") + "</section>"
    tiles = (
        _tile("green", "Uptime this week", a["uptime"], f'SLA target {esc(a.get("sla", ""))}', small=True) +
        _tile("", "Unplanned outages", f'{a["outages"]:,}', a.get("outages_note", "none recorded"), small=True) +
        _tile("", "Planned maintenance", str(a.get("maintenance", 0)), a.get("maint_note", ""), small=True) +
        _tile("blue", "Monitoring", a.get("monitoring", "24 / 7"), "continuous", small=True)
    )
    return "<section>" + head + '<div class="tiles t4">' + tiles + "</div></section>"


def _pending(source: str) -> str:
    return (
        '<div class="card"><p class="caption" style="margin:0;">Provided separately from '
        f"{esc(source)} — supply via <b>--supplemental</b> to include this section.</p></div>"
    )


def _footer(d: Dict[str, Any]) -> str:
    email = d.get("support_email", "")
    return (
        '<div class="foot"><div class="defs">'
        "<div><b>MTTD</b> — Mean time to detect: event occurrence (Incident Time) to the work item being raised.</div>"
        "<div><b>MTTR</b> — Mean time to resolve: work item raised to Resolved / Closed.</div>"
        "<div><b>Severity</b> — from the Jira Sev-1…Sev-4 field, mapped per the platform's severity classification.</div>"
        "<div><b>Reporting period</b> — one week.</div>"
        '</div><div class="footbar"><div class="org">Athena Security Group</div>'
        f'<div class="lnks">🌐 <a href="#">Website</a> &nbsp;|&nbsp; 📄 <a href="#">Docs</a> &nbsp;|&nbsp; ✉️ <a href="#">{esc(email)}</a></div>'
        '<div class="gen">Prepared by the Athena SOC team · Confidential — for the named client only · Do not reply to this report.</div>'
        "</div></div>"
    )


def render_report(data: Dict[str, Any], css: Optional[str] = None) -> str:
    if css is None:
        css = load_css()
    note = ""
    if data.get("preview_note"):
        note = f'<div class="note">{data["preview_note"]}</div>'
    pname, pkey = (data.get("project_name") or "").strip(), (data.get("project_key") or "").strip()
    proj = f"{pname} ({pkey})" if pname and pkey else (pname or pkey)
    proj_span = f' · Jira project <b>{esc(proj)}</b>' if proj else ""
    band = (
        '<div class="band"><div class="ey">Athena Security Group · Managed Detection &amp; Response</div>'
        "<h1>Weekly Security Operations Report</h1>"
        f'<div class="sub"><b>{esc(data["client"])}</b> ({esc(data["tenant"])})</div>'
        f'<div class="sub">Reporting period: <b>{esc(data["period_label"])}</b></div></div>'
        f'<div class="metaline"><span>Prepared by <b>Athena SOC Team</b>{proj_span}</span>'
        f'<span>Generated <b>{esc(data["generated"])}</b> · Confidential</span></div>'
    )
    sections = data.get("_sections_enabled", {})
    counter = {"n": 0}

    def nxt() -> int:
        counter["n"] += 1
        return counter["n"]

    body = note + band + _exec(data, nxt()) + _commentary(data) + _incidents(data, nxt())
    if sections.get("device", True):
        body += _device(data, nxt())
    if sections.get("endpoint", True):
        body += _endpoint(data, nxt())
    if sections.get("vuln", True):
        body += _vuln(data, nxt())
    if sections.get("availability", True):
        body += _availability(data, nxt())
    body += _footer(data)
    return (
        "<title>Weekly Security Operations Report</title>\n"
        f"<style>{css}</style>\n<div class=\"wrap\">{body}</div>\n"
    )
