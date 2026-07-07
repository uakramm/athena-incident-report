"""Render the weekly Security Operations Report as email-safe HTML.

Outlook (Word engine) and Gmail strip SVG, CSS variables, flexbox/grid and most
``<style>`` rules, so this renderer produces the *same* report using only what
survives an email client: nested ``<table>`` layout, inline styles, hardcoded
hex colours, and bar charts built from coloured table cells (no SVG). Paste the
output straight into an Outlook compose window and send.

Takes the same ``data`` dict as ``render.render_report`` (see ``sample_data``).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from render import esc  # identical HTML escaping

# --------------------------------------------------------------------------- #
# Palette (mirrors report_style.css :root, resolved to hex — no CSS variables)
# --------------------------------------------------------------------------- #

INK, INK2, MUTED = "#1f2733", "#4b5563", "#8a92a0"
PAPER, PANEL, PAGE = "#ffffff", "#f7f8fa", "#f4f5f7"
LINE, LINE_STRONG, LINK = "#e6e8ee", "#d5dae2", "#2660c8"
BRAND, BRAND_INK, BRAND_SUB = "#2f4b9b", "#ffffff", "#c7d2ee"

SEV_FILL = {"Critical": "#d13438", "High": "#d9820f", "Medium": "#2e6fd6", "Low": "#6b7789"}
SEV_BG = {"Critical": "#fdeceb", "High": "#fdf4e6", "Medium": "#eaf1fc", "Low": "#eef0f4"}
SEV_TX = {"Critical": "#bf2b2f", "High": "#b1660a", "Medium": "#2457ad", "Low": "#5a6577"}

KIND_FILL = {"ok": "#1e9e57", "warn": "#d9820f", "bad": "#d13438", "blue": "#2f4b9b"}
KIND_TX = {"ok": "#137a41", "warn": "#b1660a", "bad": "#bf2b2f", "blue": "#2f4b9b"}
STATUS = {"opened": BRAND, "closed": "#1e9e57", "open": "#d9820f"}

TILE = {  # (background, border, number-colour)
    "blue": ("#eef2fb", "#d3ddf3", BRAND),
    "green": ("#eafaf0", "#cdeeda", "#137a41"),
    "red": ("#fdeceb", "#f4cfce", "#bf2b2f"),
    "amber": ("#fdf4e6", "#f3e1bb", "#b1660a"),
    "": (PAPER, LINE, INK),
}

FONT = "font-family:Segoe UI,Helvetica,Arial,sans-serif;"
TRACK = "#eef0f4"


def _inline(html_str: str) -> str:
    """Swap the few CSS classes used inside data strings for inline styles."""
    repl = {
        "up": "color:#137a41;font-weight:bold;",
        "down": "color:#bf2b2f;font-weight:bold;",
        "txt-ok": "color:#137a41;",
        "txt-warn": "color:#b1660a;",
        "txt-bad": "color:#bf2b2f;",
    }
    for cls, style in repl.items():
        html_str = html_str.replace(f'class="{cls}"', f'style="{style}"')
    return html_str


def _stat_cls(pct: float) -> str:
    return "ok" if pct >= 95 else ("warn" if pct >= 80 else "bad")


# --------------------------------------------------------------------------- #
# Primitive builders
# --------------------------------------------------------------------------- #

def _bar(pct: float, fill: str, height: int = 16) -> str:
    """A single horizontal bar as a 2-cell table (fill + track). Email-safe."""
    pct = max(0.0, min(100.0, pct))
    cells = ""
    if pct > 0:
        cells += (f'<td width="{pct:.0f}%" bgcolor="{fill}" '
                  f'style="font-size:0;line-height:0;height:{height}px;">&nbsp;</td>')
    if pct < 100:
        cells += (f'<td width="{100 - pct:.0f}%" bgcolor="{TRACK}" '
                  f'style="font-size:0;line-height:0;height:{height}px;">&nbsp;</td>')
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="border:1px solid {LINE};border-collapse:collapse;"><tr>{cells}</tr></table>')


def _bar_rows(rows: Sequence[Tuple[str, int, str]], max_val: Optional[int] = None) -> str:
    """Label | bar | value rows. rows = [(label, value, fill_hex), ...]."""
    mx = max_val or max((v for _, v, _ in rows), default=1) or 1
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">']
    for label, value, fill in rows:
        out.append(
            "<tr>"
            f'<td width="150" style="{FONT}font-size:12px;color:{INK2};padding:5px 10px 5px 0;">{esc(label)}</td>'
            f'<td style="padding:5px 0;">{_bar(value / mx * 100, fill)}</td>'
            f'<td width="46" align="right" style="{FONT}font-size:13px;font-weight:bold;color:{INK};'
            f'padding:5px 0 5px 10px;">{value:,}</td>'
            "</tr>"
        )
    out.append("</table>")
    return "".join(out)


def _sla_rows(rows: Sequence[Sequence[Any]]) -> str:
    """SLA rows: label | bar | big % | count — colour-coded by kind."""
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">']
    for label, met, total, kind in rows:
        pct = 0 if not total else round(met / total * 100)
        fill, tx = KIND_FILL.get(kind, KIND_FILL["ok"]), KIND_TX.get(kind, KIND_TX["ok"])
        out.append(
            "<tr>"
            f'<td width="132" style="{FONT}font-size:12px;color:{INK2};padding:6px 10px 6px 0;">{esc(label)}</td>'
            f'<td style="padding:6px 0;">{_bar(pct, fill)}</td>'
            f'<td width="46" align="right" style="{FONT}font-size:14px;font-weight:bold;color:{tx};'
            f'padding:6px 0 6px 10px;">{pct}%</td>'
            f'<td width="66" align="right" style="{FONT}font-size:12px;color:{MUTED};padding:6px 0 6px 8px;">'
            f'{met:,} / {total:,}</td>'
            "</tr>"
        )
    out.append("</table>")
    return "".join(out)


def _card(title: str, caption: str, body: str, top: int = 0) -> str:
    cap = (f'<div style="{FONT}font-size:12px;color:{MUTED};padding:0 0 10px;">{caption}</div>'
           if caption else "")
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:{top}px;"><tr><td bgcolor="{PAPER}" '
        f'style="border:1px solid {LINE};border-radius:10px;padding:16px 18px;">'
        f'<div style="{FONT}font-size:12.5px;font-weight:bold;color:{INK};padding:0 0 4px;">{esc(title)}</div>'
        f"{cap}{body}</td></tr></table>"
    )


def _sec_head(eyebrow: str, title: str, src: str) -> str:
    right = (f'<td align="right" style="{FONT}font-size:11px;color:{MUTED};vertical-align:bottom;">{esc(src)}</td>'
             if src else "<td></td>")
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin:22px 0 12px;border-bottom:2px solid {LINE};"><tr>'
        f'<td style="padding-bottom:8px;">'
        f'<div style="{FONT}font-size:10.5px;letter-spacing:1px;text-transform:uppercase;font-weight:bold;color:{BRAND};">{esc(eyebrow)}</div>'
        f'<div style="{FONT}font-size:18px;font-weight:bold;color:{INK};padding-top:2px;">{esc(title)}</div></td>'
        f'{right}</tr></table>'
    )


def _tile(kind: str, label: str, num: str, delta_html: str) -> str:
    bg, bd, ink = TILE.get(kind, TILE[""])
    return (
        f'<td width="33%" valign="top" style="padding:5px;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td bgcolor="{bg}" style="border:1px solid {bd};border-radius:10px;padding:12px 14px;">'
        f'<div style="{FONT}font-size:10px;letter-spacing:0.5px;text-transform:uppercase;font-weight:bold;color:{MUTED};">{esc(label)}</div>'
        f'<div style="{FONT}font-size:24px;font-weight:bold;color:{ink};padding-top:4px;">{esc(num)}</div>'
        f'<div style="{FONT}font-size:11px;color:{MUTED};padding-top:5px;">{_inline(delta_html)}</div>'
        f'</td></tr></table></td>'
    )


def _tile_grid(tiles: Sequence[str], per_row: int = 3) -> str:
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">']
    for i in range(0, len(tiles), per_row):
        out.append("<tr>" + "".join(tiles[i:i + per_row]) + "</tr>")
    out.append("</table>")
    return "".join(out)


def _num_table(headers: Sequence[str], rows: Sequence[Sequence[str]], first_col_w: int = 120,
               dot_colors: Optional[Sequence[str]] = None) -> str:
    """Compact numeric table — used where the web report has a line chart."""
    ths = f'<td style="{FONT}font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:{MUTED};font-weight:bold;padding:8px 10px;border-bottom:1px solid {LINE};">{esc(headers[0])}</td>'
    for h in headers[1:]:
        ths += f'<td align="right" style="{FONT}font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:{MUTED};font-weight:bold;padding:8px 10px;border-bottom:1px solid {LINE};">{esc(h)}</td>'
    body = []
    for ri, row in enumerate(rows):
        dot = ""
        if dot_colors and ri < len(dot_colors):
            dot = (f'<span style="display:inline-block;width:9px;height:9px;background:{dot_colors[ri]};'
                   f'border-radius:2px;">&nbsp;</span> ')
        tds = (f'<td style="{FONT}font-size:12px;color:{INK2};font-weight:600;padding:7px 10px;'
               f'border-bottom:1px solid {LINE};">{dot}{esc(row[0])}</td>')
        for cell in row[1:]:
            tds += (f'<td align="right" style="{FONT}font-size:12px;color:{INK};padding:7px 10px;'
                    f'border-bottom:1px solid {LINE};">{esc(cell)}</td>')
        body.append(f"<tr>{tds}</tr>")
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'bgcolor="{PAPER}" style="border:1px solid {LINE};border-radius:10px;border-collapse:separate;">'
        f'<tr><td width="{first_col_w}"></td>{"".join("<td></td>" for _ in headers[1:])}</tr>'
        f'<tr>{ths}</tr>{"".join(body)}</table>'
    )


def _pill(sev: str, label: str) -> str:
    bg, tx = SEV_BG.get(sev, SEV_BG["Low"]), SEV_TX.get(sev, SEV_TX["Low"])
    return (f'<span style="{FONT}font-size:11px;font-weight:bold;color:{tx};background:{bg};'
            f'padding:2px 8px;border-radius:10px;white-space:nowrap;">{esc(label)}</span>')


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #

def _band(d: Dict[str, Any]) -> str:
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{BRAND}" '
        f'style="border-radius:10px 10px 0 0;"><tr><td align="center" style="padding:24px;">'
        f'<div style="{FONT}font-size:11px;letter-spacing:2px;text-transform:uppercase;color:{BRAND_SUB};font-weight:bold;">Athena Security Group &middot; Managed Detection &amp; Response</div>'
        f'<div style="{FONT}font-size:24px;font-weight:bold;color:{BRAND_INK};padding-top:8px;">Weekly Security Operations Report</div>'
        f'<div style="{FONT}font-size:13px;color:{BRAND_SUB};padding-top:8px;"><b style="color:{BRAND_INK};">{esc(d["client"])}</b> &middot; {esc(d["environment"])} &middot; Tenant: {esc(d["tenant"])}</div>'
        f'<div style="{FONT}font-size:13px;color:{BRAND_SUB};padding-top:2px;">Reporting period: <b style="color:{BRAND_INK};">{esc(d["period_label"])}</b> &middot; week starts {esc(d["week_start"])}</div>'
        f'</td></tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAPER}" '
        f'style="border:1px solid {LINE};border-top:none;border-radius:0 0 10px 10px;"><tr>'
        f'<td style="{FONT}font-size:11.5px;color:{MUTED};padding:9px 16px;">Prepared by <b style="color:{INK2};">Athena SOC Team</b></td>'
        f'<td align="right" style="{FONT}font-size:11.5px;color:{MUTED};padding:9px 16px;">Generated <b style="color:{INK2};">{esc(d["generated"])}</b> &middot; Confidential</td>'
        f'</tr></table>'
    )


def _exec(d: Dict[str, Any]) -> str:
    e = d["exec"]
    tiles = [
        _tile("blue", "Incidents opened", f'{e["opened"]:,}', e["opened_delta"]),
        _tile("green", "Incidents closed", f'{e["closed"]:,}', e["closed_delta"]),
        _tile("red", "Open at week end", f'{e["open"]:,}', e["open_delta"]),
        _tile("", "Mean time to detect", e["mttd"], e["mttd_delta"]),
        _tile("", "Mean time to resolve", e["mttr"], e["mttr_delta"]),
        _tile("green", "System availability", e["uptime"], e["uptime_note"]),
    ]
    return (
        _sec_head("01 · This week at a glance", "Executive summary", "")
        + _tile_grid(tiles, 3)
        + f'<div style="{FONT}font-size:12px;color:{MUTED};padding:10px 2px 0;">Running totals across the full '
          "reporting week, not a snapshot. &#9650;/&#9660; compare to the prior week.</div>"
    )


def _commentary(d: Dict[str, Any]) -> str:
    text = (d.get("commentary") or "").strip()
    if not text:
        return ""
    body = _inline(text)
    body = body.replace("<p>", f'<p style="{FONT}font-size:13px;color:{INK2};margin:0 0 8px;line-height:1.6;">')
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:16px;">'
        f'<tr><td bgcolor="{PAPER}" style="border:1px solid {LINE};border-left:4px solid {BRAND};border-radius:10px;padding:16px 18px;">'
        f'<div style="{FONT}font-size:10.5px;letter-spacing:1px;text-transform:uppercase;font-weight:bold;color:{BRAND};">From your SOC team</div>'
        f'<div style="{FONT}font-size:15px;font-weight:bold;color:{INK};padding:2px 0 8px;">This week in summary</div>'
        f'{body}</td></tr></table>'
    )


def _legend(items: Sequence[Tuple[str, str]]) -> str:
    spans = "".join(
        f'<span style="{FONT}font-size:12px;color:{INK2};padding-right:16px;">'
        f'<span style="display:inline-block;width:10px;height:10px;background:{color};border-radius:2px;">&nbsp;</span> {esc(label)}</span>'
        for label, color in items
    )
    return f'<div style="padding:2px 0 8px;">{spans}</div>'


def _incident_table(rows: Sequence[Dict[str, Any]], closed: bool, more: int = 0) -> str:
    if closed:
        heads = ["Ref", "Type", "Severity", "Summary", "Source", "Time to resolve"]
        aligns = ["left", "left", "left", "left", "left", "right"]
    else:
        heads = ["Ref", "Type", "Severity", "Summary", "Source", "Opened", "Age", "Status"]
        aligns = ["left"] * 5 + ["left", "left", "left"]
    th = "".join(
        f'<td align="{a}" style="{FONT}font-size:10px;text-transform:uppercase;letter-spacing:0.5px;'
        f'color:{MUTED};font-weight:bold;padding:9px 10px;background:{PANEL};border-bottom:1px solid {LINE};">{esc(h)}</td>'
        for h, a in zip(heads, aligns)
    )
    body = []
    for r in rows:
        ref = (f'<a href="{esc(r.get("ref_url", "#"))}" style="color:{LINK};font-weight:bold;text-decoration:none;">{esc(r["ref"])}</a>'
               if r.get("ref_url") else f'<b style="color:{LINK};">{esc(r["ref"])}</b>')
        cells = [
            ref,
            f'<span style="{FONT}font-size:10.5px;border:1px solid {LINE_STRONG};color:{INK2};background:{PANEL};padding:1px 7px;border-radius:4px;">{esc(r["type"])}</span>',
            _pill(r["sev"], r["sev"]),
            f'<span style="color:{INK};">{esc(r["summary"])}</span>',
            esc(r["source"]),
        ]
        if closed:
            cells.append(esc(r["ttr"]))
        else:
            cells += [esc(r["opened"]), esc(r["age"]), esc(r["status"])]
        tds = "".join(
            f'<td align="{a}" valign="top" style="{FONT}font-size:12px;color:{INK2};padding:9px 10px;border-bottom:1px solid {LINE};">{c}</td>'
            for c, a in zip(cells, aligns)
        )
        body.append(f"<tr>{tds}</tr>")
    if more > 0:
        body.append(
            f'<tr><td colspan="{len(heads)}" align="center" style="{FONT}font-size:12px;color:{MUTED};'
            f'padding:9px 10px;">+ {more:,} further items resolved this week — full log available on request</td></tr>'
        )
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAPER}" '
        f'style="border:1px solid {LINE};border-radius:10px;border-collapse:collapse;">'
        f'<tr>{th}</tr>{"".join(body)}</table>'
    )


def _sub_head(text: str) -> str:
    return f'<div style="{FONT}font-size:13px;font-weight:bold;color:{INK};padding:18px 0 8px;">{esc(text)}</div>'


def _incidents(d: Dict[str, Any]) -> str:
    parts = [_sec_head("02 · Detection &amp; response", "Incident management",
                       d.get("inc_src", "Jira SECOPS · Security Alert + Security Incident"))]

    sev_rows = [(lbl, val, SEV_FILL[lbl]) for lbl, val in d["inc_severity"]]
    parts.append(_card("Opened by severity", f'This week &middot; {sum(v for _, v in d["inc_severity"]):,} shown',
                       _bar_rows(sev_rows)))

    # 6-week trend (line chart on web) → numeric table
    weeks = d["trend"]
    headers = [""] + [w["label"] for w in weeks]
    trend_rows = [
        ["Opened"] + [str(w["opened"]) for w in weeks],
        ["Closed"] + [str(w["closed"]) for w in weeks],
        ["Open at week end"] + [str(w["open"]) for w in weeks],
    ]
    parts.append(_card("Six-week trend", "Opened, closed &amp; still-open per week",
                       _num_table(headers, trend_rows, dot_colors=[STATUS["opened"], STATUS["closed"], STATUS["open"]]), top=16))

    if d.get("type_breakdown"):
        type_rows = [(lbl, val, BRAND) for lbl, val in d["type_breakdown"]]
        parts.append(_card("Incidents by type", "Opened this week, by classification", _bar_rows(type_rows), top=16))

    sla = d.get("sla")
    if sla and sla.get("rows"):
        ov = sla.get("overall")
        body = _sla_rows(sla["rows"])
        if ov is not None:
            body += (f'<div style="{FONT}font-size:12px;color:{MUTED};padding-top:10px;">Overall '
                     f'<b style="color:{KIND_TX[_stat_cls(ov)]};">{ov}%</b> of the {sla.get("total", 0):,} '
                     "incidents resolved this week met their severity SLA.</div>")
        parts.append(_card("Response SLA attainment",
                           "Share resolved within target time, by severity — green &ge; 95%, amber &ge; 80%, red below",
                           body, top=16))

    if d.get("inc_summary_line"):
        parts.append(f'<div style="{FONT}font-size:12px;color:{MUTED};padding:14px 2px 0;">{_inline(d["inc_summary_line"])}</div>')

    parts.append(_sub_head(f'Open — currently in handling ({len(d["open_rows"])})'))
    parts.append(_incident_table(d["open_rows"], closed=False))
    parts.append(_sub_head(f'Closed this week ({d["closed_count"]:,}) — selected'))
    parts.append(_incident_table(d["closed_rows"], closed=True, more=d.get("closed_more", 0)))
    return "".join(parts)


def _meter_rows(meters: Sequence[Sequence[Any]]) -> str:
    rows = []
    for label, got, total, kind in meters:
        pct = 0 if not total else round(got / total * 100)
        rows.append((label, pct, KIND_FILL.get(kind, KIND_FILL["ok"]), f"{got:,} / {total:,}"))
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">']
    for label, pct, fill, val in rows:
        out.append(
            "<tr>"
            f'<td width="150" style="{FONT}font-size:12px;color:{INK2};padding:5px 10px 5px 0;">{esc(label)}</td>'
            f'<td style="padding:5px 0;">{_bar(pct, fill)}</td>'
            f'<td width="74" align="right" style="{FONT}font-size:12px;font-weight:bold;color:{INK};padding:5px 0 5px 10px;">{esc(val)}</td>'
            "</tr>"
        )
    out.append("</table>")
    return "".join(out)


def _pending(source: str) -> str:
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
            f'<td bgcolor="{PAPER}" style="border:1px solid {LINE};border-radius:10px;padding:16px 18px;'
            f'{FONT}font-size:12px;color:{MUTED};">Provided separately from {esc(source)} — supply via '
            "<b>--supplemental</b> to include this section.</td></tr></table>")


def _device(d: Dict[str, Any]) -> str:
    dev = d.get("device")
    head = _sec_head("03 · Managed estate", "Device management", "Microsoft Intune")
    if not dev:
        return head + _pending("Intune")
    total = dev.get("total", dev.get("managed", 0))
    enrolled = dev.get("enrolled", dev.get("compliant", 0))
    tiles = [
        _tile("blue", "Total endpoints", f"{total:,}", f'Windows {dev.get("win", 0)} &middot; macOS {dev.get("mac", 0)}'),
        _tile("green", "Enrolled", f"{enrolled:,}", f'{round(enrolled / max(total, 1) * 100)}% of estate'),
        _tile("amber", "Outstanding", f'{dev.get("outstanding", dev.get("pending", 0)):,}', "not yet enrolled"),
        _tile("", "Compliant", f'{dev.get("compliant", 0):,}', "policy compliant"),
    ]
    body = _meter_rows(dev.get("meters", []))
    if dev.get("note"):
        body += f'<div style="{FONT}font-size:12px;color:{MUTED};padding-top:10px;">{esc(dev["note"])}</div>'
    return head + _tile_grid(tiles, 2) + _card("Policies, definitions &amp; deployment", "", body, top=12)


def _endpoint(d: Dict[str, Any]) -> str:
    ep = d.get("endpoint")
    head = _sec_head("04 · Endpoint protection", "Endpoint management", "Defender · Athena agent status")
    if not ep:
        return head + _pending("Defender / agent status")
    tiles = [
        _tile("blue", "Protected endpoints", f'{ep["protected"]:,}', "Defender + Athena agent"),
        _tile("green", "Agents healthy", f'{ep["healthy"]:,}', f'{round(ep["healthy"] / max(ep["protected"], 1) * 100)}% reporting'),
        _tile("red", "Endpoints at risk", f'{ep["at_risk"]:,}', ep.get("at_risk_note", "")),
        _tile("amber", "Inactive agents", f'{ep["inactive"]:,}', "no heartbeat &gt; 24h"),
    ]
    return head + _tile_grid(tiles, 2) + _card("Protection coverage", "", _meter_rows(ep.get("meters", [])), top=12)


def _vuln(d: Dict[str, Any]) -> str:
    v = d.get("vuln")
    head = _sec_head("05 · Exposure", "Vulnerability status", "Athena scanning · Jira SECOPS · Vulnerability")
    if not v:
        return head + _pending("Athena scanning")
    tiles = [
        _tile("red", "Critical open", f'{v["crit_open"]:,}', "all patchable"),
        _tile("amber", "High open", f'{v["high_open"]:,}', v.get("high_note", "")),
        _tile("green", "Resolved this week", f'{v["resolved"]:,}', v["resolved_delta"]),
        _tile("blue", "Newly detected", f'{v["new"]:,}', f'net <b>{v["net"]:+,}</b> open'),
    ]
    parts = [head, _tile_grid(tiles, 2)]
    sev_rows = [(lbl, val, SEV_FILL[lbl]) for lbl, val in v["severity"]]
    parts.append(_card("Open vulnerabilities by severity", f'{v["total_open"]:,} open across the estate',
                       _bar_rows(sev_rows), top=12))
    # top CVEs
    def cve_list(title: str, tint: str, items: Sequence[Sequence[Any]]) -> str:
        rows = "".join(
            f'<tr><td style="{FONT}font-size:12px;padding:7px 12px;border-bottom:1px solid {LINE};">'
            f'<a href="{esc(u)}" style="color:{LINK};text-decoration:none;">{esc(c)}</a></td>'
            f'<td align="right" style="{FONT}font-size:12px;font-weight:bold;color:{tint};padding:7px 12px;border-bottom:1px solid {LINE};">{esc(x)}</td></tr>'
            for c, u, x in items
        )
        return (f'<td width="50%" valign="top" style="padding:0 6px;">'
                f'<div style="{FONT}font-size:11.5px;font-weight:bold;color:#fff;background:{tint};padding:8px 12px;border-radius:6px 6px 0 0;">{title}</div>'
                f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAPER}" '
                f'style="border:1px solid {LINE};border-top:none;border-collapse:collapse;">{rows}</table></td>')
    parts.append(
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:12px;"><tr>'
        + cve_list(f'Top Critical CVEs &middot; {v["crit_open"]:,} open', SEV_FILL["Critical"], v.get("top_crit", []))
        + cve_list(f'Top High CVEs &middot; {v["high_open"]:,} open', SEV_FILL["High"], v.get("top_high", []))
        + "</tr></table>"
    )
    sla = v.get("sla")
    if sla and sla.get("rows"):
        ov = sla.get("overall")
        body = _sla_rows(sla["rows"])
        if ov is not None:
            body += (f'<div style="{FONT}font-size:12px;color:{MUTED};padding-top:10px;">Overall '
                     f'<b style="color:{KIND_TX[_stat_cls(ov)]};">{ov}%</b> of the {sla.get("total", 0):,} '
                     "vulnerabilities remediated this week met their patch-management SLA.</div>")
        parts.append(_card("Remediation SLA attainment",
                           "Share remediated within target time, by severity — green &ge; 95%, amber &ge; 80%, red below",
                           body, top=12))
    if v.get("note"):
        parts.append(f'<div style="{FONT}font-size:12px;color:{MUTED};padding:12px 2px 0;">{esc(v["note"])}</div>')
    return "".join(parts)


def _availability(d: Dict[str, Any]) -> str:
    a = d.get("availability")
    head = _sec_head("06 · Service levels", "System availability", "Athena platform monitoring")
    if not a:
        return head + _pending("platform monitoring")
    tiles = [
        _tile("green", "Uptime this week", a["uptime"], f'SLA target {esc(a.get("sla", ""))}'),
        _tile("", "Unplanned outages", f'{a["outages"]:,}', a.get("outages_note", "none recorded")),
        _tile("", "Planned maintenance", str(a.get("maintenance", 0)), a.get("maint_note", "")),
    ]
    return head + _tile_grid(tiles, 3)


def _footer(d: Dict[str, Any]) -> str:
    email = d.get("support_email", "")
    defs = [
        "<b>MTTD</b> — Mean time to detect: event occurrence to the work item being raised.",
        "<b>MTTR</b> — Mean time to resolve: work item raised to Resolved / Closed.",
        "<b>Severity</b> — from the Jira Sev-1…Sev-4 field, mapped per the platform's classification.",
        "<b>Reporting period</b> — one week; start day configurable (Monday or Sunday).",
    ]
    defs_html = "".join(
        f'<div style="{FONT}font-size:11.5px;color:{MUTED};line-height:1.7;padding:2px 0;">{x}</div>' for x in defs
    )
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:24px;border-top:1px solid {LINE};">'
        f'<tr><td style="padding:16px 2px 10px;">{defs_html}</td></tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PANEL}" '
        f'style="border:1px solid {LINE};border-radius:8px;"><tr><td align="center" style="padding:14px;">'
        f'<div style="{FONT}font-size:12.5px;font-weight:bold;color:{INK};">Athena Security Group</div>'
        f'<div style="{FONT}font-size:12px;color:{MUTED};padding:5px 0 8px;">&#9993; <a href="mailto:{esc(email)}" style="color:{LINK};text-decoration:none;">{esc(email)}</a></div>'
        f'<div style="{FONT}font-size:11px;color:{MUTED};">Prepared by the Athena SOC team &middot; Confidential — for the named client only &middot; Do not reply to this report.</div>'
        f'</td></tr></table>'
    )


def render_email(data: Dict[str, Any]) -> str:
    sections = data.get("_sections_enabled", {})
    body = [_band(data), _exec(data), _commentary(data), _incidents(data)]
    if sections.get("device", True):
        body.append(_device(data))
    if sections.get("endpoint", True):
        body.append(_endpoint(data))
    if sections.get("vuln", True):
        body.append(_vuln(data))
    if sections.get("availability", True):
        body.append(_availability(data))
    body.append(_footer(data))
    inner = "".join(body)
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Weekly Security Operations Report</title></head>"
        f'<body style="margin:0;padding:0;background:{PAGE};">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAGE}"><tr>'
        '<td align="center" style="padding:20px 12px;">'
        '<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" style="width:680px;max-width:680px;">'
        f'<tr><td>{inner}</td></tr></table>'
        "</td></tr></table></body></html>"
    )
