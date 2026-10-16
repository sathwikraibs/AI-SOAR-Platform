"""
Autonomous incident report generator.

Every REPORT_INTERVAL_SECONDS (default 20), this:
  1. Pulls the full alert list from the existing GET /alerts endpoint.
  2. Filters to alerts created since the last report (tracked by highest
     alert `id` seen so far -- no backend changes needed for this).
  3. If there's anything new, builds a proper, human-readable incident
     report PDF -- cover/KPI banner, real charts (severity pie + attack-type
     bar chart), a severity-grouped narrative, a compact detail table, and
     dynamic recommendations -- entirely from data the pipeline already
     produced. No fabricated numbers anywhere: every figure, chart slice and
     recommendation is computed from the actual alerts passed in.
  4. Saves it into reports/ as report_<timestamp>.pdf.

This does not require any changes to backend/main.py's alert pipeline.
The two small additions needed on the backend side to make these
downloadable from the dashboard are `GET /reports` (list) and
`GET /reports/{filename}` (download) -- see backend_reports_endpoint.py.

Run: python3 report-generator/generate_report.py
(backend must already be running at API_URL)
"""

import os
import time
from collections import Counter
from datetime import datetime, timezone

import requests
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

API_URL = "http://localhost:8000/alerts"
REPORT_INTERVAL_SECONDS = 20
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
REQUEST_TIMEOUT = 5

os.makedirs(REPORTS_DIR, exist_ok=True)

_last_seen_id = 0

# ---------------------------------------------------------------------------
# Shared visual language -- same severity/status colors the dashboard uses
# (frontend-dashboard/app/globals.css's COLORS), so a printed report and the
# live dashboard always agree on what "Critical" or "Rejected" looks like.
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_HEX = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#3b82f6"}
SEVERITY_COLORS = {k: colors.HexColor(v) for k, v in SEVERITY_HEX.items()}
UNKNOWN_HEX = "#94a3b8"

STATUS_LABELS = {
    "auto_resolved": "Auto-Resolved",
    "pending_approval": "Pending Approval",
    "approved_and_executed": "Approved & Executed",
    "rejected": "Rejected",
}
STATUS_HEX = {
    "auto_resolved": "#22c55e",
    "pending_approval": "#a855f7",
    "approved_and_executed": "#2dd4bf",
    "rejected": "#ef4444",
}

NAVY = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#0ea5e9")
SLATE = colors.HexColor("#64748b")
LIGHT_ROW = colors.HexColor("#f1f5f9")


def fetch_alerts() -> list[dict]:
    try:
        resp = requests.get(API_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print(f"[report-generator] WARNING: could not reach {API_URL} ({exc})")
        return []


# ---------------------------------------------------------------------------
# Small real-data helpers -- every one of these reads only fields the
# backend's pipeline actually populates (see backend/main.py's
# alert_to_dict()); nothing here invents a number.
# ---------------------------------------------------------------------------

def _risk(a: dict):
    # Some legacy alerts predate the risk_score column and have it
    # explicitly None, not just missing -- `or 0` (not .get(..., 0)) is what
    # makes sorted() safe against comparing None to an int.
    return a.get("risk_score") or 0


def _attack_type_counts(alerts: list[dict]) -> list[tuple[str, int]]:
    """
    Groups by the human-readable half of the real MITRE technique string
    the backend already computed (threat_intel.py's map_to_mitre(), e.g.
    "T1110 - Brute Force" -> "Brute Force") -- same real categorization the
    dashboard's "Top attack types" panel uses, not a fabricated label set.
    """
    counts: Counter = Counter()
    for a in alerts:
        tech = (a.get("mitre_technique") or "").strip()
        name = tech.split(" - ", 1)[1] if " - " in tech else (tech or "Uncategorized")
        counts[name] += 1
    return counts.most_common(6)


def _severity_hex(sev: str | None) -> str:
    return SEVERITY_HEX.get(sev or "", UNKNOWN_HEX)


def _status_hex(status: str | None) -> str:
    return STATUS_HEX.get(status or "", UNKNOWN_HEX)


def _status_label(status: str | None) -> str:
    return STATUS_LABELS.get(status or "", status or "Unknown")


# ---------------------------------------------------------------------------
# Visual charts -- real Drawing flowables built from actual counts, not
# decorative placeholders.
# ---------------------------------------------------------------------------

def _severity_pie(severity_counts: Counter) -> Drawing:
    present = [(s, severity_counts[s]) for s in SEVERITY_ORDER if severity_counts.get(s)]
    present += [(s, c) for s, c in severity_counts.items() if s not in SEVERITY_ORDER and c]
    d = Drawing(230, 150)
    if not present:
        return d
    pie = Pie()
    pie.x, pie.y = 20, 10
    pie.width = pie.height = 130
    pie.data = [c for _, c in present]
    pie.labels = None
    pie.sideLabels = 0
    pie.simpleLabels = 0
    for i, (sev, _) in enumerate(present):
        pie.slices[i].fillColor = colors.HexColor(_severity_hex(sev))
        pie.slices[i].strokeColor = colors.white
        pie.slices[i].strokeWidth = 1.2
    d.add(pie)
    return d


def _attack_type_bar(pairs: list[tuple[str, int]]) -> Drawing:
    d = Drawing(260, 150)
    if not pairs:
        return d
    names = [p[0] for p in pairs]
    values = [p[1] for p in pairs]
    chart = VerticalBarChart()
    chart.x, chart.y = 35, 34
    chart.width, chart.height = 210, 100
    chart.data = [values]
    chart.categoryAxis.categoryNames = [n[:13] for n in names]
    chart.categoryAxis.labels.angle = 28
    chart.categoryAxis.labels.fontSize = 6.2
    chart.categoryAxis.labels.dy = -10
    chart.categoryAxis.labels.dx = -4
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 6.5
    chart.bars[0].fillColor = ACCENT
    chart.barWidth = 10
    d.add(chart)
    return d


def _legend_row(pairs: list[tuple[str, str, int]], style: ParagraphStyle) -> Paragraph:
    """pairs = [(hex_color, label, count), ...] -- rendered as a single line
    of colored square + label, so a chart's meaning is legible without
    fighting reportlab's built-in (often overlapping) pie/bar labels."""
    chunks = []
    for hexcolor, label, count in pairs:
        chunks.append(f'<font color="{hexcolor}">■</font> {label} ({count})')
    return Paragraph("&nbsp;&nbsp;&nbsp;".join(chunks), style)


# ---------------------------------------------------------------------------
# Cover / KPI banner
# ---------------------------------------------------------------------------

def _cover_banner(title: str, subtitle: str, report_id: str, generated_at: str) -> Table:
    eyebrow_style = ParagraphStyle("Eyebrow", fontSize=8, textColor=colors.HexColor("#38bdf8"), fontName="Helvetica-Bold", spaceAfter=3, tracking=1)
    title_style = ParagraphStyle("CoverTitle", fontSize=19, textColor=colors.white, fontName="Helvetica-Bold", leading=22)
    sub_style = ParagraphStyle("CoverSub", fontSize=9.5, textColor=colors.HexColor("#cbd5e1"), leading=13, spaceBefore=4)
    meta_style = ParagraphStyle("CoverMeta", fontSize=7.5, textColor=colors.HexColor("#94a3b8"), leading=11, alignment=TA_RIGHT)
    left = [Paragraph("AI-SOAR PLATFORM", eyebrow_style), Paragraph(title, title_style), Paragraph(subtitle, sub_style)]
    right = [Paragraph(f"Report ID<br/><b>{report_id}</b>", meta_style), Spacer(1, 6), Paragraph(f"Generated<br/><b>{generated_at}</b>", meta_style)]
    t = Table([[left, right]], colWidths=[4.9 * inch, 2.1 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 18),
        ("RIGHTPADDING", (-1, 0), (-1, 0), 18),
        ("TOPPADDING", (0, 0), (-1, -1), 16),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
    ]))
    return t


def _kpi_row(alerts: list[dict]) -> Table:
    total = len(alerts)
    crit = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    pending = sum(1 for a in alerts if a.get("status") == "pending_approval" or a.get("response_status") == "pending_approval")
    risks = [a.get("risk_score") for a in alerts if a.get("risk_score") is not None]
    avg_risk = f"{sum(risks) / len(risks):.1f}" if risks else "N/A"

    tiles = [
        ("TOTAL ALERTS", str(total), colors.HexColor("#334155")),
        ("CRITICAL", str(crit), SEVERITY_COLORS["Critical"]),
        ("HIGH", str(high), SEVERITY_COLORS["High"]),
        ("PENDING APPROVAL", str(pending), colors.HexColor("#a855f7")),
        ("AVG RISK SCORE", avg_risk, ACCENT),
    ]
    label_style = ParagraphStyle("TileLabel", fontSize=6.3, textColor=colors.white, alignment=TA_CENTER, fontName="Helvetica-Bold", leading=8)
    value_style = ParagraphStyle("TileValue", fontSize=19, textColor=colors.white, alignment=TA_CENTER, fontName="Helvetica-Bold", spaceBefore=3)

    # Each cell is a 2-item list (label Paragraph, value Paragraph) -- Table
    # renders a cell that's itself a list of flowables stacked vertically,
    # so this is one table row of `len(tiles)` label-over-value cells.
    row = [[Paragraph(label, label_style), Paragraph(value, value_style)] for label, value, _ in tiles]
    t = Table([row], colWidths=[1.4 * inch] * len(tiles))
    style_cmds = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, (_, _, bg) in enumerate(tiles):
        style_cmds.append(("BACKGROUND", (i, 0), (i, 0), bg))
    t.setStyle(TableStyle(style_cmds))
    return t


# ---------------------------------------------------------------------------
# Executive summary + recommendations -- short, plain-English, generated
# entirely from the real counts above (no canned filler text that doesn't
# match what's actually in the report).
# ---------------------------------------------------------------------------

def _executive_summary(alerts: list[dict], subtitle: str, empty_message: str) -> str:
    if not alerts:
        return empty_message
    crit = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    top_types = _attack_type_counts(alerts)
    top_line = f" The most frequent pattern was <b>{top_types[0][0]}</b> ({top_types[0][1]} occurrence(s))." if top_types else ""
    urgent = f" {crit} of these are Critical and {high} are High severity, warranting prompt review." if (crit or high) else " None reached Critical or High severity this period."
    return f"{subtitle}{urgent}{top_line}"


def _recommendations(alerts: list[dict]) -> list[str]:
    recs = []
    crit = [a for a in alerts if a.get("severity") == "Critical"]
    pending = [a for a in alerts if (a.get("status") or a.get("response_status")) == "pending_approval"]
    if crit:
        ids = ", ".join(f"#{a.get('id')}" for a in crit[:6])
        recs.append(f"Review the {len(crit)} Critical-severity alert(s) immediately ({ids}) -- these are the platform's highest-confidence, highest-impact detections.")
    if pending:
        recs.append(f"{len(pending)} alert(s) have response steps awaiting analyst approval in the Response Center -- approve or reject them before closing this reporting period.")
    malicious_ips = sorted({a.get("ip") for a in alerts if a.get("ip") and str(a.get("ip_reputation", "")).lower() == "malicious"})
    if malicious_ips:
        recs.append("Source IP(s) flagged <b>Malicious</b> by threat intelligence: " + ", ".join(malicious_ips[:6]) + " -- consider a perimeter block if one isn't already in place.")
    top_types = _attack_type_counts(alerts)
    if top_types:
        name, count = top_types[0]
        recs.append(f"The most frequent pattern this period was '<b>{name}</b>' ({count} occurrence(s)) -- check the matching Runbook entry for the standard response steps.")
    if not recs:
        recs.append("No immediate action required -- no Critical-severity alerts and nothing pending approval this period.")
    recs.append("This report was generated automatically by the AI-SOAR platform's autonomous reporting pipeline directly from live alert data -- no manual data entry.")
    return recs


# ---------------------------------------------------------------------------
# Page footer with real page numbers (Page X of Y) -- the standard two-pass
# reportlab technique: buffer every page, then stamp the final total once
# the full page count is known, right before writing the file out.
# ---------------------------------------------------------------------------

class _NumberedCanvas(pdfcanvas.Canvas):
    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total_pages)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_footer(self, total_pages: int) -> None:
        self.setFont("Helvetica", 7)
        self.setFillColor(SLATE)
        self.drawString(0.6 * inch, 0.4 * inch, "AI-SOAR Platform — Auto-Generated Incident Report — Confidential")
        self.drawRightString(LETTER[0] - 0.6 * inch, 0.4 * inch, f"Page {self._pageNumber} of {total_pages}")


def _table_style(zebra: bool = True) -> TableStyle:
    cmds = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
    ]
    if zebra:
        cmds.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_ROW]))
    return TableStyle(cmds)


def build_pdf(new_alerts: list[dict], filepath: str, title: str = "AI-SOAR Incident Report", subtitle: str | None = None, empty_message: str = "No new alerts this cycle.") -> None:
    """
    title/subtitle/empty_message let generate_daily_report.py reuse this
    exact layout for its 24-hour digest instead of duplicating the whole
    PDF-building code -- the per-cycle script below still gets its
    original wording by default.
    """
    styles = getSampleStyleSheet()
    heading_style = ParagraphStyle("HeadingStyle", parent=styles["Heading2"], spaceBefore=16, spaceAfter=6, textColor=NAVY)
    sub_heading_style = ParagraphStyle("SubHeadingStyle", fontSize=10.5, fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4, textColor=NAVY)
    normal = ParagraphStyle("ReportNormal", parent=styles["Normal"], fontSize=8.7, leading=12.5)
    caption_style = ParagraphStyle("Caption", fontSize=7.5, textColor=SLATE, alignment=TA_CENTER, spaceBefore=2)
    table_cell = ParagraphStyle("TableCell", fontSize=7.3, leading=9)

    subtitle_text = subtitle or f"Covers {len(new_alerts)} new alert(s) since the previous report cycle."
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    doc = SimpleDocTemplate(filepath, pagesize=LETTER, topMargin=0.5 * inch, bottomMargin=0.65 * inch, leftMargin=0.55 * inch, rightMargin=0.55 * inch)
    story = []

    # --- cover banner + KPI strip ---
    story.append(_cover_banner(title, subtitle_text, report_id, generated_at))
    story.append(Spacer(1, 0.18 * inch))
    story.append(_kpi_row(new_alerts))
    story.append(Spacer(1, 0.12 * inch))

    # --- executive summary ---
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(_executive_summary(new_alerts, subtitle_text, empty_message), normal))

    if new_alerts:
        # --- at-a-glance charts: severity split + top attack types ---
        story.append(Paragraph("At a Glance", heading_style))
        severity_counts = Counter(a.get("severity", "Unknown") for a in new_alerts)
        attack_pairs = _attack_type_counts(new_alerts)

        chart_row = Table(
            [[_severity_pie(severity_counts), _attack_type_bar(attack_pairs)]],
            colWidths=[3.5 * inch, 3.5 * inch],
        )
        chart_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(chart_row)

        sev_legend_pairs = [(_severity_hex(s), s, c) for s, c in severity_counts.items()]
        caption_row = Table(
            [[_legend_row(sev_legend_pairs, caption_style), Paragraph("Top real attack patterns by MITRE technique", caption_style)]],
            colWidths=[3.5 * inch, 3.5 * inch],
        )
        caption_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(caption_row)
        story.append(Spacer(1, 0.1 * inch))

        # --- response status breakdown (small horizontal legend + counts) ---
        status_counts = Counter(a.get("status") or a.get("response_status") or "Unknown" for a in new_alerts)
        status_pairs = [(_status_hex(s), _status_label(s), c) for s, c in status_counts.items()]
        story.append(Paragraph("Response Status", sub_heading_style))
        story.append(_legend_row(status_pairs, normal))
        story.append(Spacer(1, 0.15 * inch))

        # --- compact detail table ---
        story.append(Paragraph("Alert Detail Table", heading_style))
        header = ["ID", "Severity", "Risk", "MITRE Technique", "IP Rep.", "Hash Rep.", "Response", "Status"]
        rows = [header]
        for a in sorted(new_alerts, key=_risk, reverse=True):
            risk_display = a.get("risk_score") if a.get("risk_score") is not None else "N/A"
            sev = a.get("severity") or "Unknown"
            status = a.get("status") or a.get("response_status")
            rows.append([
                Paragraph(f"#{a.get('id', '')}", table_cell),
                Paragraph(f'<font color="{_severity_hex(sev)}"><b>{sev}</b></font>', table_cell),
                Paragraph(str(risk_display), table_cell),
                Paragraph((a.get("mitre_technique") or "—")[:30], table_cell),
                Paragraph(a.get("ip_reputation") or "—", table_cell),
                Paragraph(a.get("hash_reputation") or "—", table_cell),
                Paragraph((a.get("response_action") or "—")[:24], table_cell),
                Paragraph(f'<font color="{_status_hex(status)}">{_status_label(status)}</font>', table_cell),
            ])
        detail_table = Table(rows, hAlign="LEFT", repeatRows=1, colWidths=[0.42 * inch, 0.62 * inch, 0.42 * inch, 1.55 * inch, 0.72 * inch, 0.72 * inch, 1.2 * inch, 0.95 * inch])
        detail_table.setStyle(_table_style())
        story.append(detail_table)
        story.append(Spacer(1, 0.15 * inch))

        # --- severity-grouped narrative (readable, not a raw data dump) ---
        story.append(Paragraph("Incident Narrative", heading_style))
        by_sev: dict[str, list[dict]] = {}
        for a in new_alerts:
            by_sev.setdefault(a.get("severity") or "Unknown", []).append(a)
        ordered_keys = [s for s in SEVERITY_ORDER if s in by_sev] + [s for s in by_sev if s not in SEVERITY_ORDER]
        for sev in ordered_keys:
            group = sorted(by_sev[sev], key=_risk, reverse=True)
            hexcolor = _severity_hex(sev)
            story.append(Paragraph(f'<font color="{hexcolor}">■</font>&nbsp;&nbsp;{sev} Severity ({len(group)})', sub_heading_style))
            for a in group:
                risk_display = a.get("risk_score") if a.get("risk_score") is not None else "N/A"
                status = a.get("status") or a.get("response_status")
                line = (
                    f"<b>#{a.get('id')}</b> — risk {risk_display} — {a.get('description', '')}<br/>"
                    f"<font size=7 color='#64748b'>Source: {a.get('ip') or a.get('source') or '—'} &nbsp;|&nbsp; "
                    f"MITRE: {a.get('mitre_technique') or '—'} &nbsp;|&nbsp; "
                    f"IP rep: {a.get('ip_reputation') or '—'} &nbsp;|&nbsp; Hash rep: {a.get('hash_reputation') or '—'} &nbsp;|&nbsp; "
                    f"Response: {a.get('response_action') or '—'} "
                    f"(<font color='{_status_hex(status)}'>{_status_label(status)}</font>)</font>"
                )
                story.append(Paragraph(line, normal))
                story.append(Spacer(1, 5))
            story.append(Spacer(1, 3))

        # --- recommendations ---
        story.append(Paragraph("Recommended Next Steps", heading_style))
        for rec in _recommendations(new_alerts):
            story.append(Paragraph(f"• {rec}", normal))
            story.append(Spacer(1, 3))

    doc.build(story, canvasmaker=_NumberedCanvas)


def run_cycle() -> str | None:
    global _last_seen_id

    all_alerts = fetch_alerts()
    new_alerts = [a for a in all_alerts if a.get("id", 0) > _last_seen_id]
    if all_alerts:
        _last_seen_id = max(a.get("id", 0) for a in all_alerts)

    if not new_alerts:
        return None  # nothing new -- skip writing an empty report this cycle

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    build_pdf(new_alerts, filepath)
    print(f"[report-generator] Wrote {filename} ({len(new_alerts)} new alert(s))")
    return filename


def main():
    print(f"[report-generator] Polling {API_URL} every {REPORT_INTERVAL_SECONDS}s, writing PDFs to {REPORTS_DIR}")
    try:
        while True:
            run_cycle()
            time.sleep(REPORT_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[report-generator] Stopped.")


if __name__ == "__main__":
    main()
