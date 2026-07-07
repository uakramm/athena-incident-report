"""Render report charts to PNG bytes with matplotlib.

Email clients (Outlook, Gmail) strip inline SVG and modern CSS, so charts drawn
that way never survive. The fix — the same one used by athena-integrations
(`reporting/reports_incident.py`) — is to render each chart as a **PNG image**:
images render in every client. The email references them as inline ``cid:``
attachments; the self-contained preview HTML embeds them as ``data:`` URIs.

``build_charts(data)`` returns ``{name: png_bytes}`` (empty dict if matplotlib is
unavailable, so the caller falls back to the table-based rendering). Colours mirror
render_email's palette so the PNGs match the rest of the report.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

# Palette — kept in step with render_email.py
INK, INK2, MUTED = "#1f2733", "#4b5563", "#8a92a0"
LINE, LINE_STRONG, TRACK = "#e6e8ee", "#d5dae2", "#eef0f4"
SEV_FILL = {"Critical": "#d13438", "High": "#d9820f", "Medium": "#2e6fd6", "Low": "#6b7789"}
STATUS = {"Opened": "#2f4b9b", "Closed": "#1e9e57", "Open at week end": "#d9820f"}
BRAND = "#2f4b9b"

# Display widths (CSS px). Figures are rendered at 2x for retina then downscaled by
# the <img> width, exactly like Rizwan's report.
_DPI = 200
FONT = "Segoe UI"


def _available():
    try:
        import logging
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # noqa: F401
        # Segoe UI is Windows-only; silence the fallback warning on macOS/Linux.
        logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
        return True
    except Exception:
        return False


def _resolve_font() -> str:
    """Pick a clean sans-serif that matches the email body stack
    (Segoe UI → Helvetica → Arial). Prefer a real .ttf over macOS .ttc
    collections, which matplotlib often mis-renders (falling back to DejaVu)."""
    import os
    import matplotlib.font_manager as fm
    prefer = ["Segoe UI", "Arial", "Liberation Sans", "Arimo", "Helvetica Neue",
              "Helvetica", "Verdana", "DejaVu Sans"]
    usable = {}
    for f in fm.fontManager.ttflist:
        if f.name not in usable and os.path.splitext(f.fname)[1].lower() == ".ttf":
            usable[f.name] = f.fname
    for name in prefer:
        if name in usable:
            return name
    return "DejaVu Sans"


_FONT_NAME = None


def _new_ax(w_in: float, h_in: float):
    global _FONT_NAME
    import matplotlib.pyplot as plt
    if _FONT_NAME is None:
        _FONT_NAME = _resolve_font()
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": [_FONT_NAME, "Arial", "DejaVu Sans"],
        "font.size": 11, "text.color": INK, "axes.edgecolor": LINE,
        "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": INK2,
        "figure.dpi": _DPI,
    })
    fig, ax = plt.subplots(figsize=(w_in, h_in), dpi=_DPI)
    return fig, ax


def _to_png(fig) -> bytes:
    from io import BytesIO
    import matplotlib.pyplot as plt
    buf = BytesIO()
    fig.savefig(buf, format="png", transparent=True, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    return buf.getvalue()


# Nice-number axis ticks — identical to render.py so the PNG axes match the SVG.
_NICE = [1, 2, 2.5, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000, 10000]


def _nice_step(raw: float) -> float:
    for step in _NICE:
        if step >= raw:
            return step
    return _NICE[-1]


def _axis_max(max_value: float, intervals: int):
    target = max(max_value, 1) * 1.08 / intervals
    step = _nice_step(target)
    return step * intervals, [step * i for i in range(intervals + 1)]


def _fmt_tick(v: float) -> str:
    return f"{int(v):,}" if v == int(v) else f"{v:,g}"


# The SVG charts use a 560-wide viewBox; these convert an SVG px size into the
# equivalent matplotlib points for a 6.3in-wide figure, so the PNG's line weights,
# fonts and markers match the HTML SVG proportionally at any display width.
_FIG_W = 6.3
_VBOX_W = 560.0
def _pt(svg_px: float) -> float:
    return svg_px * (_FIG_W * 72.0 / _VBOX_W)   # px/560 * (fig_in*72)

TICK_PT = _pt(11)     # .g-tick 11px
VAL_PT = _pt(12)      # .g-val 12px
CAT_PT = _pt(12)      # .g-cat 12px
END_PT = _pt(11.5)    # .g-end 11.5px
LINE_LW = _pt(2)      # polyline stroke-width 2
GRID_LW = _pt(1)      # .g-grid stroke-width 1
DOT_MS = _pt(8)       # circle r=4 → diameter 8


def _svg_height(rows_px: float) -> float:
    """Figure height (inches) for a chart whose SVG viewBox is 560 x rows_px."""
    return _FIG_W * rows_px / _VBOX_W


def _rounded_barh(ax, fig, ys, widths, height, colors, round_frac=0.42):
    """Horizontal bars with rounded corners (SVG rx). round_frac is the corner
    radius as a fraction of bar height, matched to the SVG (rx 4 on a 20px bar)."""
    from matplotlib.patches import FancyBboxPatch
    fig.canvas.draw()
    bb = ax.get_window_extent()
    x0, x1 = ax.get_xlim()
    y0, y1 = ax.get_ylim()
    px_x = bb.width / (x1 - x0)
    px_y = bb.height / (y1 - y0)
    r_disp = round_frac * height * px_y          # corner radius in display px
    aspect = px_x / px_y                          # keeps the corner circular
    for y, w, c in zip(ys, widths, colors):
        if w <= 0:
            continue
        # Clamp the radius to half the (smaller) bar dimension so narrow bars
        # stay pill-shaped instead of collapsing into a lens — as SVG rx does.
        r_bar = min(r_disp, 0.5 * w * px_x, 0.5 * height * px_y)
        ax.add_patch(FancyBboxPatch(
            (0, y - height / 2), w, height,
            boxstyle=f"round,pad=0,rounding_size={r_bar / px_x}",
            mutation_aspect=aspect, linewidth=0, facecolor=c, edgecolor="none",
            zorder=3, clip_on=False))


def _hbar(rows: Sequence[Tuple[str, int]], colors: Sequence[str],
          rowh_px: float, barh_px: float) -> bytes:
    """Horizontal bars matching hbar_svg/catbar_svg. rowh_px/barh_px are the SVG
    row-height and bar-height so the figure aspect and bar thickness match."""
    labels = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    n = len(rows)
    svg_h = 20 + (n - 1) * rowh_px + barh_px + 40   # grid + tick label band
    fig, ax = _new_ax(_FIG_W, _svg_height(svg_h))
    y = list(range(n))[::-1]                         # first row on top
    axis_max, ticks = _axis_max(max(vals, default=1), 3)
    ax.set_xlim(0, axis_max)
    ax.set_ylim(-0.7, n - 0.3)
    for t in ticks:
        ax.axvline(t, color=LINE, linewidth=GRID_LW, zorder=0)
    ax.set_xticks(ticks)
    ax.set_xticklabels([_fmt_tick(t) for t in ticks], fontsize=TICK_PT, color=MUTED)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=CAT_PT, color=INK2)
    _rounded_barh(ax, fig, y, vals, barh_px / rowh_px, colors)
    for yi, v in zip(y, vals):
        ax.text(v + axis_max * 0.012, yi, f"{v:,}", va="center", ha="left",
                fontsize=VAL_PT, fontweight="bold", color=INK)
    for s in ("top", "right", "bottom"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color(LINE_STRONG)         # SVG g-axis line
    ax.spines["left"].set_linewidth(GRID_LW)
    ax.tick_params(length=0)
    return _to_png(fig)


def _sev_bar(rows: Sequence[Tuple[str, int]]) -> bytes:
    return _hbar(rows, [SEV_FILL.get(l, SEV_FILL["Low"]) for l, _ in rows],
                 rowh_px=40, barh_px=20)          # hbar_svg spec


def _type_bar(rows: Sequence[Tuple[str, int]]) -> bytes:
    return _hbar(rows, [BRAND] * len(rows), rowh_px=32, barh_px=18)  # catbar_svg spec


def _line_chart(weeks: Sequence[Dict[str, Any]], series: Sequence[Tuple[str, str]]) -> bytes:
    """Multi-line week chart matching lines_svg (viewBox 560x232): clean lines with
    no midpoint markers, an end dot with white ring, a bold colour-matched end value,
    faint y gridlines. Legend is rendered as HTML in the card (like the report), not
    baked into the image. series = [(data_key, colour), ...]."""
    fig, ax = _new_ax(_FIG_W, _svg_height(232))
    n = len(weeks)
    x = list(range(n))
    all_vals = [w[k] for w in weeks for k, _ in series]
    axis_max, ticks = _axis_max(max(all_vals, default=1), 4)
    for key, color in series:
        ys = [w[key] for w in weeks]
        ax.plot(x, ys, color=color, linewidth=LINE_LW, solid_capstyle="round",
                solid_joinstyle="round", zorder=3)
        ax.plot([x[-1]], [ys[-1]], marker="o", markersize=DOT_MS, markerfacecolor=color,
                markeredgecolor="#ffffff", markeredgewidth=GRID_LW * 1.4, zorder=4)
        ax.annotate(f"{ys[-1]:,}", (x[-1], ys[-1]), textcoords="offset points",
                    xytext=(7, 0), va="center", ha="left", fontsize=END_PT,
                    fontweight="bold", color=color, annotation_clip=False)
    ax.set_ylim(0, axis_max)
    ax.set_yticks(ticks)
    ax.set_yticklabels([_fmt_tick(t) for t in ticks], fontsize=TICK_PT, color=MUTED)
    ax.set_xlim(-0.15, n - 1 + 0.55)
    ax.set_xticks(x)
    ax.set_xticklabels([w["label"] for w in weeks], fontsize=TICK_PT, color=MUTED)
    for t in ticks:
        ax.axhline(t, color=LINE, linewidth=GRID_LW, zorder=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    return _to_png(fig)


def _trend(weeks: Sequence[Dict[str, Any]]) -> bytes:
    return _line_chart(weeks, [("opened", STATUS["Opened"]),
                               ("closed", STATUS["Closed"]),
                               ("open", STATUS["Open at week end"])])


def _multiline(weeks: Sequence[Dict[str, Any]], labels: Sequence[str],
               colors: Sequence[str]) -> bytes:
    return _line_chart(weeks, [(lab, c) for lab, c in zip(labels, colors)])


def build_charts(data: Dict[str, Any]) -> Dict[str, bytes]:
    """Render the report's charts to PNG. Empty dict if matplotlib is unavailable."""
    if not _available():
        return {}
    out: Dict[str, bytes] = {}
    try:
        if data.get("inc_severity"):
            out["inc_severity"] = _sev_bar(data["inc_severity"])
        if data.get("trend"):
            out["trend"] = _trend(data["trend"])
        if data.get("sev_trend") and data.get("sev_trend_labels"):
            labels = data["sev_trend_labels"]
            out["sev_trend"] = _multiline(
                data["sev_trend"], labels,
                [SEV_FILL.get(l, SEV_FILL["Low"]) for l in labels])
        if data.get("type_breakdown"):
            out["inc_type"] = _type_bar(data["type_breakdown"])
        v = data.get("vuln")
        if v and v.get("severity"):
            out["vuln_severity"] = _sev_bar(v["severity"])
    except Exception:
        # Charts are a nicety; never let them break report generation.
        return out
    return out
