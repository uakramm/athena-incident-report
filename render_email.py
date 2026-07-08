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

FONT = "font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
TRACK = "#eef0f4"
SHADOW = "0 1px 2px rgba(31,39,51,0.04), 0 4px 16px rgba(31,39,51,0.06)"


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

def _bar(pct: float, fill: str, height: int = 14) -> str:
    """A rounded pill bar — a rounded track with a rounded fill, matching the HTML
    .sla-track/.sla-fill. Rounded corners render in modern clients (new Outlook,
    Apple Mail, Gmail) and degrade to a clean square bar in classic Outlook."""
    pct = max(0.0, min(100.0, pct))
    r = height // 2
    inner = ""
    if pct > 0:
        inner = (f'<div style="height:{height}px;width:{pct:.1f}%;min-width:2px;'
                 f'background:{fill};border-radius:{r}px 0 0 {r}px;font-size:0;line-height:0;">&nbsp;</div>')
    return (f'<div style="height:{height}px;background:{PANEL};border:1px solid {LINE};'
            f'border-radius:{r}px;overflow:hidden;font-size:0;line-height:0;">{inner}</div>')


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


def _card(title: str, caption: str, body: str, top: int = 0, height: Optional[int] = None) -> str:
    cap = (f'<div style="{FONT}font-size:12px;color:{MUTED};padding:0 0 10px;">{caption}</div>'
           if caption else "")
    table_height = f' height="{height}"' if height else ""
    td_height = f'height:{height}px;' if height else ""
    return (
        f'<table role="presentation" width="100%"{table_height} cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:{top}px;{td_height}"><tr><td bgcolor="{PAPER}" '
        f'style="border:1px solid {LINE};border-radius:12px;padding:18px;box-shadow:{SHADOW};{td_height}" valign="top">'
        f'<div style="{FONT}font-size:12.5px;font-weight:680;color:{INK};padding:0 0 4px;">{esc(title)}</div>'
        f"{cap}{body}</td></tr></table>"
    )


def _two_col(left: str, right: str, top: int = 16) -> str:
    """Two equal cards side by side — the email-safe equivalent of the HTML .grid2."""
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:{top}px;table-layout:fixed;"><tr>'
        f'<td width="50%" valign="top" style="padding-right:8px;">{left}</td>'
        f'<td width="50%" valign="top" style="padding-left:8px;">{right}</td>'
        f'</tr></table>'
    )


def _spacer(px: int) -> str:
    """A fixed-height vertical spacer that survives Outlook."""
    return f'<div style="height:{px}px;font-size:0;line-height:0;">&nbsp;</div>' if px > 0 else ""


# Rendered display height (px, in the fixed 960px layout) of a chart inside a
# _two_col_cards cell: the card inner width is ~436px and the PNG aspect is 560:svg_h.
def _chart_display_h(svg_h: float) -> int:
    return round(436 * svg_h / 560)


def _two_col_cards(cells: Sequence[Tuple[str, str, str]], top: int = 16) -> str:
    """Two cards that are the CELLS of a single table row, so the table forces them
    to equal height (the taller sets the height; the shorter's paper cell fills the
    rest). cells = [(title, caption, body), ...]. Widths are explicit against the
    fixed 960px body: 472 + 16 gutter + 472. To vertically centre a shorter card's
    body, pre-pad it with _spacer() before passing it in."""
    card_td = (f'valign="top" bgcolor="{PAPER}" style="border:1px solid {LINE};border-radius:12px;'
               f'box-shadow:{SHADOW};padding:18px;')
    tds = []
    for title, caption, body in cells:
        cap = (f'<div style="{FONT}font-size:12px;color:{MUTED};padding:0 0 10px;">{caption}</div>'
               if caption else "")
        tds.append(
            f'<td width="472" {card_td}">'
            f'<div style="{FONT}font-size:12.5px;font-weight:680;color:{INK};padding:0 0 4px;">{esc(title)}</div>'
            f'{cap}{body}</td>'
        )
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:{top}px;table-layout:fixed;"><tr>'
        f'{tds[0]}<td width="16" style="width:16px;font-size:0;line-height:0;">&nbsp;</td>{tds[1]}'
        f'</tr></table>'
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


def _tile(kind: str, label: str, num: str, delta_html: str, small: bool = False) -> str:
    """Returns the tile card (no outer <td>); _tile_grid places it in a sized cell."""
    bg, bd, ink = TILE.get(kind, TILE[""])
    num_size = 22 if small else 28
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" height="100%">'
        f'<tr><td bgcolor="{bg}" valign="top" style="border:1px solid {bd};border-radius:12px;padding:14px 15px;box-shadow:{SHADOW};">'
        f'<div style="{FONT}font-size:10.5px;letter-spacing:0.05em;text-transform:uppercase;font-weight:700;color:{MUTED};">{esc(label)}</div>'
        f'<div style="{FONT}font-size:{num_size}px;line-height:1;font-weight:750;color:{ink};padding-top:5px;">{esc(num)}</div>'
        f'<div style="{FONT}font-size:11.5px;color:{MUTED};padding-top:7px;">{_inline(delta_html)}</div>'
        f'</td></tr></table>'
    )


def _tile_grid(tiles: Sequence[str], per_row: int = 3) -> str:
    # Explicit pixel widths summing to the fixed 960px body — percentage widths that
    # round over 100% (e.g. 6 x 16.67%) make Outlook wrap the last tile to a new row.
    cell = 960 // per_row
    out = ['<table role="presentation" width="960" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed;width:960px;">']
    for i in range(0, len(tiles), per_row):
        row = tiles[i:i + per_row]
        cells = "".join(f'<td width="{cell}" valign="top" style="width:{cell}px;padding:6px;">{t}</td>' for t in row)
        # Pad the last row so cells keep their width.
        cells += "".join(f'<td width="{cell}" style="width:{cell}px;padding:6px;"></td>' for _ in range(per_row - len(row)))
        out.append("<tr>" + cells + "</tr>")
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


def _sparkline_svg(series: Sequence[Tuple[str, Sequence[float]]], labels: Sequence[str],
                   width: int = 632, height: int = 96) -> str:
    """Multi-line sparkline as a small, flat inline SVG (Apple Mail / new Outlook /
    browser render it; classic Outlook strips it — the numeric table below is the
    fallback). Ported from athena-integrations reports_compliance.generateSparklineSvg.
    """
    all_vals = [v for _, vals in series for v in vals]
    if not all_vals or len(labels) < 2:
        return ""
    max_val = max(all_vals) or 1
    pad_l, pad_r, pad_t, pad_b = 6, 6, 8, 18
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    n = len(labels)
    def _x(i: int) -> float:
        return pad_l + (i / (n - 1)) * plot_w
    def _y(v: float) -> float:
        return pad_t + plot_h - (v / max_val) * plot_h
    parts = [f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
             f'xmlns="http://www.w3.org/2000/svg" style="max-width:100%;">']
    # faint baseline
    parts.append(f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{width - pad_r}" '
                 f'y2="{pad_t + plot_h}" stroke="{LINE}" stroke-width="1"/>')
    for label, vals in series:
        color = series_color(label)
        pts = " ".join(f"{_x(i):.1f},{_y(v):.1f}" for i, v in enumerate(vals))
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" '
                     f'points="{pts}"/>')
        # end marker
        parts.append(f'<circle cx="{_x(n - 1):.1f}" cy="{_y(vals[-1]):.1f}" r="3" fill="{color}"/>')
    # x labels
    for i, lab in enumerate(labels):
        anchor = "start" if i == 0 else ("end" if i == n - 1 else "middle")
        parts.append(f'<text x="{_x(i):.1f}" y="{height - 4}" text-anchor="{anchor}" '
                     f'font-family="Segoe UI,Arial,sans-serif" font-size="9" fill="{MUTED}">{esc(lab)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def series_color(label: str) -> str:
    key = label.strip().lower()
    if key.startswith("open") and "week" not in key:
        return STATUS["opened"]
    if key.startswith("closed"):
        return STATUS["closed"]
    return STATUS["open"]


def _stacked_sev_svg(rows: Sequence[Tuple[str, int]], width: int = 632, height: int = 18) -> str:
    """A single stacked severity bar (crit/high/med/…) as a flat inline SVG.
    Ported from athena-integrations reports_compliance.generateMiniBarSvg.
    """
    total = sum(v for _, v in rows) or 0
    if total <= 0:
        return ""
    parts = [f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
             f'xmlns="http://www.w3.org/2000/svg" style="max-width:100%;">']
    x = 0.0
    last = len(rows) - 1
    for i, (label, val) in enumerate(rows):
        w = (val / total) * width
        rx = 3 if (i == 0 or i == last) else 0
        parts.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="{height}" '
                     f'rx="{rx}" fill="{SEV_FILL.get(label, SEV_FILL["Low"])}"/>')
        x += w
    parts.append("</svg>")
    return "".join(parts)


def _chart_img(d: Dict[str, Any], name: str, alt: str) -> Optional[str]:
    """If a rendered PNG chart is available for this slot, return an <img> for it;
    otherwise None so the caller falls back to the table/SVG rendering. src is a
    data: URI (self-contained preview) or cid: reference (inline email image)."""
    src = (d.get("_chart_src") or {}).get(name)
    if not src:
        return None
    # width:100% so the chart fills its card (the PNG is rendered at 2x, so it
    # scales down crisply); no fixed max-width that would leave right-side gaps.
    return (f'<div style="padding:2px 0 4px;"><img src="{esc(src)}" alt="{esc(alt)}" '
            f'width="100%" style="display:block;width:100%;max-width:100%;height:auto;border:0;"></div>')


def _pill(sev: str, label: str) -> str:
    bg, tx = SEV_BG.get(sev, SEV_BG["Low"]), SEV_TX.get(sev, SEV_TX["Low"])
    return (f'<span style="{FONT}font-size:11px;font-weight:bold;color:{tx};background:{bg};'
            f'padding:2px 8px;border-radius:10px;white-space:nowrap;">{esc(label)}</span>')


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #

def _project_label(d: Dict[str, Any]) -> str:
    """'Name (KEY)' — or just the key/name if only one is known."""
    name, key = (d.get("project_name") or "").strip(), (d.get("project_key") or "").strip()
    return f"{name} ({key})" if name and key else (name or key)


def _band(d: Dict[str, Any]) -> str:
    proj = _project_label(d)
    proj_cell = (f' &middot; Jira project <b style="color:{INK2};">{esc(proj)}</b>' if proj else "")
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{BRAND}" '
        f'style="border-radius:12px 12px 0 0;"><tr><td align="center" style="padding:26px 24px 24px;">'
        f'<div style="{FONT}font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:{BRAND_SUB};font-weight:600;">Athena Security Group &middot; Managed Detection &amp; Response</div>'
        f'<div style="{FONT}font-size:26px;font-weight:700;color:{BRAND_INK};padding-top:10px;">Weekly Security Operations Report</div>'
        f'<div style="{FONT}font-size:13px;color:{BRAND_SUB};padding-top:8px;"><b style="color:{BRAND_INK};">{esc(d["client"])}</b> ({esc(d["tenant"])})</div>'
        f'<div style="{FONT}font-size:13px;color:{BRAND_SUB};padding-top:2px;">Reporting period: <b style="color:{BRAND_INK};">{esc(d["period_label"])}</b></div>'
        f'</td></tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAPER}" '
        f'style="border:1px solid {LINE};border-top:none;border-radius:0 0 12px 12px;box-shadow:{SHADOW};"><tr>'
        f'<td style="{FONT}font-size:11.5px;color:{MUTED};padding:9px 16px;">Prepared by <b style="color:{INK2};">Athena SOC Team</b>{proj_cell}</td>'
        f'<td align="right" style="{FONT}font-size:11.5px;color:{MUTED};padding:9px 16px;">Generated <b style="color:{INK2};">{esc(d["generated"])}</b> &middot; Confidential</td>'
        f'</tr></table>'
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
        _sec_head(f"{n:02d} · This week at a glance", "Executive summary", "")
        + _tile_grid(tiles, 6)
        + f'<div style="{FONT}font-size:12px;color:{MUTED};padding:10px 2px 0;">Running totals across the full '
          "reporting week, not a snapshot. &#9650;/&#9660; compare to the prior week; green marks the favorable direction.</div>"
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
        f'<span style="{FONT}font-size:12px;color:{INK2};font-weight:550;padding-right:16px;">'
        f'<span style="display:inline-block;width:11px;height:11px;background:{color};border-radius:3px;">&nbsp;</span> {esc(label)}</span>'
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


def _incidents(d: Dict[str, Any], n: int = 2) -> str:
    parts = [_sec_head(f"{n:02d} · Detection & response", "Incident management",
                       d.get("inc_src", "Jira SECOPS · Security Alert + Security Incident"))]

    sev_rows = [(lbl, val, SEV_FILL[lbl]) for lbl, val in d["inc_severity"]]
    sev_body = _chart_img(d, "inc_severity", "Incidents opened by severity") or _bar_rows(sev_rows)
    sev_caption = f'This week &middot; {sum(v for _, v in d["inc_severity"]):,} shown'

    # 6-week trend (line chart on web) → numeric table
    weeks = d["trend"]
    headers = [""] + [w["label"] for w in weeks]
    trend_rows = [
        ["Opened"] + [str(w["opened"]) for w in weeks],
        ["Closed"] + [str(w["closed"]) for w in weeks],
        ["Open at week end"] + [str(w["open"]) for w in weeks],
    ]
    trend_img = _chart_img(d, "trend", "Six-week trend: opened, closed and still-open per week")
    if trend_img:
        # HTML legend above the chart image (matches the report; keeps it fixed-size).
        trend_body = _legend([("Opened", STATUS["opened"]), ("Closed", STATUS["closed"]),
                              ("Open at week end", STATUS["open"])]) + trend_img
        # The trend card is taller (legend ~26px + a 232-tall line chart) than the
        # severity bars, so centre the shorter severity chart by pre-padding it with
        # half the gap; the equal-height table row supplies the matching space below.
        n_sev = max(len(d["inc_severity"]), 1)
        gap = (26 + _chart_display_h(232)) - _chart_display_h(80 + (n_sev - 1) * 40)
        if d.get("_chart_src", {}).get("inc_severity") and gap > 0:
            sev_body = _spacer(gap // 2) + sev_body
    else:
        spark = _sparkline_svg(
            [("Opened", [w["opened"] for w in weeks]),
             ("Closed", [w["closed"] for w in weeks]),
             ("Open at week end", [w["open"] for w in weeks])],
            [w["label"] for w in weeks])
        trend_body = _legend([("Opened", STATUS["opened"]), ("Closed", STATUS["closed"]),
                              ("Open at week end", STATUS["open"])])
        if spark:
            trend_body += f'<div style="padding:2px 0 10px;">{spark}</div>'
        trend_body += _num_table(headers, trend_rows,
                                 dot_colors=[STATUS["opened"], STATUS["closed"], STATUS["open"]])
    parts.append(_two_col_cards([
        ("Opened by severity", sev_caption, sev_body),
        ("Six-week trend", "Opened, closed &amp; still-open per week", trend_body),
    ]))

    # Severity over time — full-width line chart, mirrors the HTML report.
    sev_trend_img = _chart_img(d, "sev_trend", "Incidents opened per week, by severity")
    if sev_trend_img:
        sev_legend = _legend([(lbl, SEV_FILL[lbl]) for lbl in d.get("sev_trend_labels", [])])
        parts.append(_card("Severity over time", "Incidents opened per week, by severity",
                           sev_legend + sev_trend_img, top=16))

    if d.get("type_breakdown"):
        type_rows = [(lbl, val, BRAND) for lbl, val in d["type_breakdown"]]
        type_body = _chart_img(d, "inc_type", "Incidents by type") or _bar_rows(type_rows)
        parts.append(_card("Incidents by type", "Opened this week, by classification", type_body, top=16))

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


def _device(d: Dict[str, Any], n: int = 3) -> str:
    dev = d.get("device")
    head = _sec_head(f"{n:02d} · Managed estate", "Device management", "Microsoft Intune")
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
    return head + _tile_grid(tiles, 4) + _card("Policies, definitions &amp; deployment", "", body, top=12)


def _endpoint(d: Dict[str, Any], n: int = 4) -> str:
    ep = d.get("endpoint")
    head = _sec_head(f"{n:02d} · Endpoint protection", "Endpoint management", "Defender · Athena agent status")
    if not ep:
        return head + _pending("Defender / agent status")
    tiles = [
        _tile("blue", "Protected endpoints", f'{ep["protected"]:,}', "Defender + Athena agent"),
        _tile("green", "Agents healthy", f'{ep["healthy"]:,}', f'{round(ep["healthy"] / max(ep["protected"], 1) * 100)}% reporting'),
        _tile("red", "Endpoints at risk", f'{ep["at_risk"]:,}', ep.get("at_risk_note", "")),
        _tile("amber", "Inactive agents", f'{ep["inactive"]:,}', "no heartbeat &gt; 24h"),
    ]
    return head + _tile_grid(tiles, 4) + _card("Protection coverage", "", _meter_rows(ep.get("meters", [])), top=12)


def _vuln(d: Dict[str, Any], n: int = 5) -> str:
    v = d.get("vuln")
    head = _sec_head(f"{n:02d} · Exposure", "Vulnerability status", "Athena scanning · Jira SECOPS · Vulnerability")
    if not v:
        return head + _pending("Athena scanning")
    crit_cap = "none open" if v["crit_open"] == 0 else "all patchable"
    high_cap = v.get("high_note") or ("none open" if v["high_open"] == 0 else "across the estate")
    tiles = [
        _tile("red", "Critical open", f'{v["crit_open"]:,}', crit_cap),
        _tile("amber", "High open", f'{v["high_open"]:,}', high_cap),
        _tile("green", "Resolved this week", f'{v["resolved"]:,}', v["resolved_delta"]),
        _tile("blue", "Newly detected", f'{v["new"]:,}', f'net <b>{v["net"]:+,}</b> open'),
    ]
    parts = [head, _tile_grid(tiles, 4)]
    sev_rows = [(lbl, val, SEV_FILL[lbl]) for lbl, val in v["severity"]]
    v_sev_body = _chart_img(d, "vuln_severity", "Open vulnerabilities by severity") or _bar_rows(sev_rows)
    crit_items = list(v.get("top_crit", []))
    high_items = list(v.get("top_high", []))
    HDR_H, ROW_H = 34, 37

    # The two cards are the CELLS of a single table row, so they are forced to equal
    # height by the table itself — no pixel estimation, no height:100% (which Outlook
    # strips). The taller card sets the row height; the shorter one's cell fills the
    # rest with its paper background. Widths are explicit (fixed 960px body): the
    # section is 960 → 472 + 16 gutter + 472.
    sev_inner = (
        f'<div style="{FONT}font-size:12.5px;font-weight:680;color:{INK};">Open vulnerabilities by severity</div>'
        f'<div style="{FONT}font-size:12px;color:{MUTED};padding-top:2px;">{v["total_open"]:,} open across the estate</div>'
        f'<div style="padding-top:12px;">{v_sev_body}</div>'
    )

    def cve_rows(items: Sequence[Sequence[Any]], tint: str) -> str:
        rows = []
        last = len(items) - 1
        for i, (name, url, val) in enumerate(items):
            bb = "" if i == last else f"border-bottom:1px solid {LINE};"
            rows.append(
                f'<tr><td nowrap="nowrap" height="{ROW_H}" style="{FONT}font-size:12.5px;color:{INK2};'
                f'padding:0 14px;line-height:{ROW_H}px;height:{ROW_H}px;{bb}white-space:nowrap;">'
                f'<a href="{esc(url)}" style="color:{LINK};text-decoration:none;white-space:nowrap;">{esc(name)}</a></td>'
                f'<td nowrap="nowrap" align="right" height="{ROW_H}" style="{FONT}font-size:12.5px;font-weight:bold;'
                f'color:{tint};padding:0 14px;line-height:{ROW_H}px;height:{ROW_H}px;{bb}white-space:nowrap;">{esc(val)}</td></tr>'
            )
        return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
                f'style="border-collapse:collapse;">{"".join(rows)}</table>')

    crit_title = f'Top Critical CVEs &middot; {v["crit_open"]:,} open'
    high_title = f'Top High CVEs &middot; {v["high_open"]:,} open'
    cve_hdr = (f'{FONT}font-size:11.5px;font-weight:bold;color:#fff;padding:0 14px;white-space:nowrap;'
               f'letter-spacing:0.01em;line-height:{HDR_H}px;height:{HDR_H}px;')
    # Inner CVE table fills its card cell; body cells valign top so rows sit under the
    # coloured headers and the paper background fills any slack below.
    cve_inner = (
        f'<table role="presentation" width="100%" height="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="height:100%;border-collapse:separate;table-layout:fixed;">'
        f'<tr>'
        f'<td width="50%" height="{HDR_H}" style="{cve_hdr}background:{SEV_FILL["Critical"]};border-radius:12px 0 0 0;">{crit_title}</td>'
        f'<td width="50%" height="{HDR_H}" style="{cve_hdr}background:{SEV_FILL["High"]};border-radius:0 12px 0 0;">{high_title}</td>'
        f'</tr>'
        f'<tr>'
        f'<td width="50%" valign="top" bgcolor="{PAPER}">{cve_rows(crit_items, SEV_FILL["Critical"])}</td>'
        f'<td width="50%" valign="top" bgcolor="{PAPER}" style="border-left:1px solid {LINE};">{cve_rows(high_items, SEV_FILL["High"])}</td>'
        f'</tr></table>'
    )

    card_td = (f'valign="top" bgcolor="{PAPER}" style="border:1px solid {LINE};border-radius:12px;'
               f'box-shadow:{SHADOW};')
    vuln_row = (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="margin-top:12px;table-layout:fixed;"><tr>'
        f'<td width="472" {card_td}padding:18px;">{sev_inner}</td>'
        f'<td width="16" style="width:16px;font-size:0;line-height:0;">&nbsp;</td>'
        f'<td width="472" {card_td}padding:0;overflow:hidden;">{cve_inner}</td>'
        f'</tr></table>'
    )
    parts.append(vuln_row)
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


def _availability(d: Dict[str, Any], n: int = 6) -> str:
    a = d.get("availability")
    head = _sec_head(f"{n:02d} · Service levels", "System availability", "Athena platform monitoring")
    if not a:
        return head + _pending("platform monitoring")
    tiles = [
        _tile("green", "Uptime this week", a["uptime"], f'SLA target {esc(a.get("sla", ""))}', small=True),
        _tile("", "Unplanned outages", f'{a["outages"]:,}', a.get("outages_note", "none recorded"), small=True),
        _tile("", "Planned maintenance", str(a.get("maintenance", 0)), a.get("maint_note", ""), small=True),
        _tile("blue", "Monitoring", a.get("monitoring", "24 / 7"), "continuous", small=True),
    ]
    return head + _tile_grid(tiles, 4)


def _footer(d: Dict[str, Any]) -> str:
    email = d.get("support_email", "")
    defs = [
        "<b>MTTD</b> — Mean time to detect: event occurrence (Incident Time) to the work item being raised.",
        "<b>MTTR</b> — Mean time to resolve: work item raised to Resolved / Closed.",
        "<b>Severity</b> — from the Jira Sev-1…Sev-4 field, mapped per the platform's severity classification.",
        "<b>Reporting period</b> — one week.",
    ]
    defs_html = (
        '<tr>'
        f'<td width="50%" valign="top" style="{FONT}font-size:11.5px;color:{MUTED};line-height:1.7;padding:0 18px 6px 2px;">{defs[0]}</td>'
        f'<td width="50%" valign="top" style="{FONT}font-size:11.5px;color:{MUTED};line-height:1.7;padding:0 2px 6px 18px;">{defs[1]}</td>'
        '</tr><tr>'
        f'<td width="50%" valign="top" style="{FONT}font-size:11.5px;color:{MUTED};line-height:1.7;padding:0 18px 0 2px;">{defs[2]}</td>'
        f'<td width="50%" valign="top" style="{FONT}font-size:11.5px;color:{MUTED};line-height:1.7;padding:0 2px 0 18px;">{defs[3]}</td>'
        '</tr>'
    )
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:24px;border-top:1px solid {LINE};">'
        f'<tr><td style="padding:16px 0 10px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed;">{defs_html}</table></td></tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PANEL}" '
        f'style="border:1px solid {LINE};border-radius:10px;"><tr><td align="center" style="padding:14px;">'
        f'<div style="{FONT}font-size:12.5px;font-weight:bold;color:{INK};">Athena Security Group</div>'
        f'<div style="{FONT}font-size:12px;color:{MUTED};padding:5px 0 8px;">🌐 <a href="#" style="color:{LINK};text-decoration:none;">Website</a> &nbsp;|&nbsp; 📄 <a href="#" style="color:{LINK};text-decoration:none;">Docs</a> &nbsp;|&nbsp; ✉️ <a href="mailto:{esc(email)}" style="color:{LINK};text-decoration:none;">{esc(email)}</a></div>'
        f'<div style="{FONT}font-size:11px;color:{MUTED};">Prepared by the Athena SOC team &middot; Confidential — for the named client only &middot; Do not reply to this report.</div>'
        f'</td></tr></table>'
    )


def render_email(data: Dict[str, Any]) -> str:
    sections = data.get("_sections_enabled", {})
    counter = {"n": 0}

    def nxt() -> int:
        counter["n"] += 1
        return counter["n"]

    body = [_band(data), _exec(data, nxt()), _commentary(data), _incidents(data, nxt())]
    if sections.get("device", True):
        body.append(_device(data, nxt()))
    if sections.get("endpoint", True):
        body.append(_endpoint(data, nxt()))
    if sections.get("vuln", True):
        body.append(_vuln(data, nxt()))
    if sections.get("availability", True):
        body.append(_availability(data, nxt()))
    body.append(_footer(data))
    inner = "".join(body)
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Weekly Security Operations Report</title></head>"
        f'<body style="margin:0;padding:0;background:{PAGE};">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAGE}"><tr>'
        '<td align="center" style="padding:24px 18px 64px;">'
        '<table role="presentation" width="960" cellpadding="0" cellspacing="0" border="0" style="width:960px;max-width:960px;">'
        f'<tr><td>{inner}</td></tr></table>'
        "</td></tr></table></body></html>"
    )
