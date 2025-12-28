from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Sequence
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Line, PolyLine, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ...models import Finding, Scan
from .report_insights import ReportInsights

MAX_CRITICAL_FINDINGS = 10
MAX_PRIORITY_FINDINGS = 8
TREND_MAX_SCANS = 12

# Color palette - Modern dark theme inspired
COLORS = {
    "primary": colors.HexColor("#00d768"),  # Neon mint
    "primary_dark": colors.HexColor("#00a855"),
    "dark": colors.HexColor("#0f172a"),
    "dark_alt": colors.HexColor("#1e293b"),
    "text": colors.HexColor("#0f172a"),
    "text_secondary": colors.HexColor("#475569"),
    "text_muted": colors.HexColor("#94a3b8"),
    "border": colors.HexColor("#e2e8f0"),
    "white": colors.HexColor("#ffffff"),
    # Severity colors
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#d97706"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#6b7280"),
}


class HorizontalRule(Flowable):
    """Custom flowable for horizontal divider lines."""

    def __init__(self, width: float, color=None, thickness: float = 0.5):
        super().__init__()
        self.width = width
        self.color = color or COLORS["border"]
        self.thickness = thickness

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)

    def wrap(self, available_width, available_height):
        return self.width, self.thickness + 4


class SeverityBadge(Flowable):
    """Colored badge for severity level."""

    def __init__(self, severity: str, width: float = 60, height: float = 16):
        super().__init__()
        self.severity = severity.lower()
        self.badge_width = width
        self.badge_height = height
        self.color = COLORS.get(self.severity, COLORS["info"])

    def draw(self):
        # Draw rounded rectangle background
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.badge_width, self.badge_height, 3, fill=1, stroke=0)
        # Draw text
        self.canv.setFillColor(COLORS["white"])
        self.canv.setFont("Helvetica-Bold", 8)
        text_width = self.canv.stringWidth(self.severity.upper(), "Helvetica-Bold", 8)
        x = (self.badge_width - text_width) / 2
        self.canv.drawString(x, 4, self.severity.upper())

    def wrap(self, available_width, available_height):
        return self.badge_width, self.badge_height


def build_scan_report_pdf(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
    insights: ReportInsights | None = None,
) -> bytes:
    generated_at = datetime.now(timezone.utc)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=40,
        title="ScanGuard AI Report",
    )

    styles = _build_styles()
    story = []
    page_width = A4[0] - 80  # Account for margins

    # Header with branding
    story.extend(_build_header(scan, generated_at, styles, page_width))
    story.append(Spacer(1, 16))

    # Scan Overview section
    story.append(HorizontalRule(page_width, COLORS["primary"], 2))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Scan Overview", styles["SectionHeading"]))
    story.extend(_build_scan_overview(scan, styles, page_width))
    story.append(Spacer(1, 16))

    # Stats Summary section
    story.append(HorizontalRule(page_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Summary Statistics", styles["SectionHeading"]))
    story.extend(_build_stats_summary(scan, findings, styles, page_width))
    story.append(Spacer(1, 16))

    # Executive Summary section (AI Insights)
    if insights:
        story.append(HorizontalRule(page_width))
        story.append(Spacer(1, 12))
        story.append(
            Paragraph("Executive Summary (AI Insights)", styles["SectionHeading"])
        )
        story.extend(_build_insights_section(insights, styles))
        story.append(Spacer(1, 16))

    # AI Decisioning section
    story.append(HorizontalRule(page_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("AI Decisioning Summary", styles["SectionHeading"]))
    story.append(Paragraph(_ai_summary_text(), styles["Body"]))
    story.append(Spacer(1, 16))

    # Critical Findings section
    story.append(HorizontalRule(page_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Critical Findings (AI Reviewed)", styles["SectionHeading"]))
    story.extend(_build_critical_findings(findings, styles, page_width))
    story.append(Spacer(1, 16))

    # Remediation Priorities section
    story.append(HorizontalRule(page_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Remediation Priorities", styles["SectionHeading"]))
    story.extend(_build_remediation_priorities(findings, styles, page_width))
    story.append(Spacer(1, 16))

    # Trend Chart section
    story.append(HorizontalRule(page_width))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Trend Chart", styles["SectionHeading"]))
    story.extend(_build_trend_chart_section(trend_scans, styles))

    doc.build(
        story,
        onFirstPage=lambda c, d: _add_page_elements(c, d, generated_at, is_first=True),
        onLaterPages=lambda c, d: _add_page_elements(c, d, generated_at, is_first=False),
    )
    return buffer.getvalue()


def _build_styles() -> dict[str, ParagraphStyle]:
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Heading1"],
            fontSize=22,
            textColor=COLORS["dark"],
            spaceAfter=4,
            fontName="Helvetica-Bold",
        )
    )
    styles.add(
        ParagraphStyle(
            name="Meta",
            parent=styles["BodyText"],
            fontSize=9,
            textColor=COLORS["text_secondary"],
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=4,
            spaceAfter=8,
            textColor=COLORS["dark"],
            fontName="Helvetica-Bold",
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["BodyText"],
            fontSize=10,
            leading=14,
            textColor=COLORS["text"],
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            textColor=COLORS["text_secondary"],
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading3"],
            fontSize=11,
            spaceAfter=4,
            textColor=COLORS["dark"],
            fontName="Helvetica-Bold",
        )
    )
    styles.add(
        ParagraphStyle(
            name="StatLabel",
            parent=styles["BodyText"],
            fontSize=9,
            textColor=COLORS["text_muted"],
        )
    )
    styles.add(
        ParagraphStyle(
            name="StatValue",
            parent=styles["BodyText"],
            fontSize=16,
            textColor=COLORS["dark"],
            fontName="Helvetica-Bold",
        )
    )
    return styles


def _build_header(
    scan: Scan,
    generated_at: datetime,
    styles: dict[str, ParagraphStyle],
    page_width: float,
) -> list:
    """Build report header with branding."""
    blocks = []

    # Title and subtitle
    blocks.append(Paragraph("ScanGuard AI", styles["ReportTitle"]))
    blocks.append(
        Paragraph(
            f"Security Scan Report &bull; Generated {_format_datetime(generated_at)}",
            styles["Meta"],
        )
    )

    return blocks


def _build_scan_overview(
    scan: Scan, styles: dict[str, ParagraphStyle], page_width: float
) -> list:
    """Build scan overview as a clean table."""
    data = [
        ["Scan ID", str(scan.id)],
        ["Status", scan.status.upper()],
        ["Scan Type", scan.scan_type.upper()],
        ["Trigger", scan.trigger],
    ]
    if scan.repo_url:
        data.append(["Repository", scan.repo_url])
    if scan.target_url:
        data.append(["Target URL", scan.target_url])
    if scan.scan_type != "dast":
        data.append(["Branch", scan.branch])
    data.append(["Created", _format_datetime(scan.created_at)])
    if scan.commit_sha:
        data.append(["Commit", scan.commit_sha[:12]])
    if scan.pr_url:
        data.append(["Pull Request", scan.pr_url])

    table = Table(data, colWidths=[120, page_width - 140])
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), COLORS["text_secondary"]),
                ("TEXTCOLOR", (1, 0), (1, -1), COLORS["text"]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return [table]


def _build_stats_summary(
    scan: Scan,
    findings: Sequence[Finding],
    styles: dict[str, ParagraphStyle],
    page_width: float,
) -> list:
    """Build stats summary with colored boxes."""
    total = scan.total_findings or 0
    filtered = scan.filtered_findings or 0
    noise_pct = _noise_reduction_pct(scan)
    counts = _severity_counts(findings)

    # Build stats data
    stats_data = [
        [
            _stat_cell("Total Findings", str(total), styles),
            _stat_cell("Filtered", str(filtered), styles),
            _stat_cell("Noise Reduction", f"{noise_pct}%", styles, highlight=True),
        ]
    ]

    col_width = (page_width - 20) / 3
    stats_table = Table(stats_data, colWidths=[col_width, col_width, col_width])
    stats_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("BACKGROUND", (0, 0), (-1, -1), COLORS["border"]),
                ("BOX", (0, 0), (-1, -1), 0.5, COLORS["border"]),
            ]
        )
    )

    blocks = [stats_table, Spacer(1, 12)]

    # Severity breakdown
    if counts:
        severity_items = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = counts.get(sev, 0)
            if count > 0:
                severity_items.append(f'<font color="{COLORS[sev].hexval()}">{sev}: {count}</font>')
        if severity_items:
            blocks.append(
                Paragraph(
                    f"<b>Severity breakdown:</b> {' &bull; '.join(severity_items)}",
                    styles["Body"],
                )
            )

    # Additional stats
    extra_stats = []
    if scan.scan_type != "sast" and scan.dast_findings:
        extra_stats.append(f"DAST findings: {scan.dast_findings}")
    if scan.scanned_files is not None:
        extra_stats.append(f"Files scanned: {scan.scanned_files}")
    if scan.detected_languages:
        extra_stats.append(f"Languages: {', '.join(scan.detected_languages)}")

    if extra_stats:
        blocks.append(Paragraph(" &bull; ".join(extra_stats), styles["BodySmall"]))

    return blocks


def _stat_cell(label: str, value: str, styles: dict[str, ParagraphStyle], highlight: bool = False) -> list:
    """Create a stat cell with label and value."""
    return [
        Paragraph(label, styles["StatLabel"]),
        Paragraph(
            f'<font color="{COLORS["primary"].hexval() if highlight else COLORS["dark"].hexval()}">{value}</font>',
            styles["StatValue"],
        ),
    ]


def _ai_summary_text() -> str:
    return (
        "AI triage reviews each finding with code context, exploitability signals, "
        "reachability checks, and dynamic evidence when available. Findings marked "
        "as false positives are excluded from this report. Priority ordering blends "
        "AI severity, confidence, and confirmed exploitability."
    )


def _build_insights_section(
    insights: ReportInsights, styles: dict[str, ParagraphStyle]
) -> list:
    blocks: list = []
    blocks.append(
        Paragraph(_clean_text(insights.executive_summary, 900), styles["Body"])
    )
    blocks.append(Spacer(1, 6))
    blocks.append(
        Paragraph(
            f"<b>Risk posture:</b> {_clean_text(insights.risk_posture, 220)}",
            styles["Body"],
        )
    )
    blocks.append(Spacer(1, 6))
    blocks.append(
        Paragraph(
            f"<b>Business impact:</b> {_clean_text(insights.business_impact, 240)}",
            styles["Body"],
        )
    )
    blocks.append(Spacer(1, 6))
    blocks.append(
        Paragraph(
            "<b>Key risks:</b><br/>" + _format_bullets(insights.key_risks),
            styles["Body"],
        )
    )
    blocks.append(Spacer(1, 6))
    blocks.append(
        Paragraph(
            "<b>Recommended actions:</b><br/>"
            + _format_bullets(insights.recommended_actions),
            styles["Body"],
        )
    )
    if insights.assurance_notes:
        blocks.append(Spacer(1, 6))
        blocks.append(
            Paragraph(
                f"<b>Coverage notes:</b> {_clean_text(insights.assurance_notes, 240)}",
                styles["BodySmall"],
            )
        )
    if insights.confidence is not None:
        confidence_pct = int(round(insights.confidence * 100))
        blocks.append(
            Paragraph(
                f"AI confidence: {confidence_pct}%",
                styles["BodySmall"],
            )
        )
    return blocks


def _format_bullets(items: Sequence[str]) -> str:
    if not items:
        return "- n/a"
    safe_items = [f"- {_clean_text(item, 200)}" for item in items if item]
    if not safe_items:
        return "- n/a"
    return "<br/>".join(safe_items)


def _build_critical_findings(
    findings: Sequence[Finding], styles: dict[str, ParagraphStyle], page_width: float
) -> list:
    critical = [finding for finding in findings if _is_critical(finding)]
    critical.sort(key=_priority_sort_key, reverse=True)
    if not critical:
        return [
            Paragraph(
                "No critical findings were confirmed for this scan.",
                styles["Body"],
            )
        ]

    blocks = []
    for index, finding in enumerate(critical[:MAX_CRITICAL_FINDINGS], start=1):
        label = _finding_label(finding)
        location = _finding_location(finding)
        severity = _severity_label(finding)
        priority = _priority_label(finding)
        reasoning = _fallback_text(finding.ai_reasoning, "AI reasoning not available.")
        exploitability = _fallback_text(finding.exploitability, "Exploitability notes not available.")
        remediation = _fallback_text(finding.remediation, "Remediation guidance not available.")
        reachability = _reachability_label(finding)

        # Finding card with left border color
        finding_content = [
            Paragraph(f"<b>#{index}</b> {_clean_text(label)}", styles["FindingTitle"]),
            Spacer(1, 4),
            _build_finding_meta(severity, priority, finding.finding_type, location, reachability, styles),
            Spacer(1, 6),
            Paragraph(f"<b>AI Reasoning:</b> {_clean_text(reasoning, 400)}", styles["Body"]),
            Spacer(1, 4),
            Paragraph(f"<b>Exploitability:</b> {_clean_text(exploitability, 300)}", styles["Body"]),
            Spacer(1, 4),
            Paragraph(f"<b>Remediation:</b> {_clean_text(remediation, 300)}", styles["Body"]),
            Spacer(1, 8),
        ]

        blocks.append(KeepTogether(finding_content))
        blocks.append(HorizontalRule(page_width * 0.5, COLORS["border"], 0.3))
        blocks.append(Spacer(1, 8))

    if len(critical) > MAX_CRITICAL_FINDINGS:
        blocks.append(
            Paragraph(
                f"Only the top {MAX_CRITICAL_FINDINGS} critical findings are shown.",
                styles["BodySmall"],
            )
        )
    return blocks


def _build_finding_meta(
    severity: str,
    priority: str,
    finding_type: str,
    location: str,
    reachability: str,
    styles: dict[str, ParagraphStyle],
) -> Paragraph:
    """Build metadata line for a finding with colored severity."""
    sev_color = COLORS.get(severity.lower(), COLORS["info"]).hexval()
    return Paragraph(
        f'<font color="{sev_color}"><b>{severity.upper()}</b></font> &bull; '
        f"Priority: {priority} &bull; Type: {finding_type}<br/>"
        f"<font color=\"{COLORS['text_secondary'].hexval()}\">Location: {_clean_text(location)} &bull; {reachability}</font>",
        styles["BodySmall"],
    )


def _build_remediation_priorities(
    findings: Sequence[Finding], styles: dict[str, ParagraphStyle], page_width: float
) -> list:
    ordered = sorted(findings, key=_priority_sort_key, reverse=True)
    ordered = [finding for finding in ordered if finding.priority_score is not None and finding.priority_score > 0]

    if not ordered:
        return [
            Paragraph(
                "No remediation priorities are available yet.",
                styles["Body"],
            )
        ]

    blocks = []
    for index, finding in enumerate(ordered[:MAX_PRIORITY_FINDINGS], start=1):
        label = _finding_label(finding)
        location = _finding_location(finding)
        severity = _severity_label(finding)
        priority = _priority_label(finding)
        remediation = _fallback_text(finding.remediation, f"Review and address: {label}")

        sev_color = COLORS.get(severity.lower(), COLORS["info"]).hexval()
        blocks.append(
            KeepTogether(
                [
                    Paragraph(
                        f"<b>{index}.</b> {_clean_text(label)}",
                        styles["Body"],
                    ),
                    Paragraph(
                        f'<font color="{sev_color}">{severity.upper()}</font> &bull; '
                        f"Priority: {priority} &bull; {_clean_text(location)}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"<i>{_clean_text(remediation, 300)}</i>",
                        styles["BodySmall"],
                    ),
                    Spacer(1, 8),
                ]
            )
        )

    if len(ordered) > MAX_PRIORITY_FINDINGS:
        blocks.append(
            Paragraph(
                f"Only the top {MAX_PRIORITY_FINDINGS} priorities are shown.",
                styles["BodySmall"],
            )
        )
    return blocks


def _build_trend_chart_section(
    trend_scans: Sequence[Scan], styles: dict[str, ParagraphStyle]
) -> list:
    scans = list(trend_scans)[-TREND_MAX_SCANS:]
    chart = _build_trend_chart(scans)
    if not chart:
        return [
            Paragraph(
                "Not enough completed scans to render a trend chart.",
                styles["Body"],
            )
        ]
    return [
        Paragraph(
            "Noise reduction percentage across recent completed scans.",
            styles["BodySmall"],
        ),
        Spacer(1, 8),
        chart,
    ]


def _build_trend_chart(scans: Sequence[Scan]) -> Drawing | None:
    completed = [scan for scan in scans if scan.status == "completed"]
    if len(completed) < 2:
        return None

    completed = sorted(completed, key=lambda scan: scan.created_at)
    values = [_noise_reduction_pct(scan) for scan in completed]
    labels = [_format_short_date(scan.created_at) for scan in completed]

    width = 450
    height = 180
    padding_left = 40
    padding_right = 24
    padding_top = 24
    padding_bottom = 32
    chart_width = width - padding_left - padding_right
    chart_height = height - padding_top - padding_bottom

    drawing = Drawing(width, height)

    # Background
    drawing.add(
        Rect(0, 0, width, height, fillColor=COLORS["white"], strokeColor=None)
    )

    # Grid lines
    grid_color = COLORS["border"]
    for pct in [0, 25, 50, 75, 100]:
        y = padding_bottom + (chart_height * pct / 100)
        drawing.add(
            Line(padding_left, y, width - padding_right, y, strokeColor=grid_color, strokeWidth=0.5)
        )
        drawing.add(
            String(padding_left - 8, y - 3, f"{pct}%", fontSize=7, fillColor=COLORS["text_muted"], textAnchor="end")
        )

    # Axes
    axis_color = COLORS["text_secondary"]
    drawing.add(
        Line(padding_left, padding_bottom, padding_left, height - padding_top, strokeColor=axis_color, strokeWidth=1)
    )
    drawing.add(
        Line(padding_left, padding_bottom, width - padding_right, padding_bottom, strokeColor=axis_color, strokeWidth=1)
    )

    # Data points and line
    points = []
    for index, value in enumerate(values):
        x = padding_left + (chart_width * index / (len(values) - 1))
        y = padding_bottom + (chart_height * value / 100)
        points.append((x, y))

    # Line
    drawing.add(PolyLine(points, strokeColor=COLORS["primary"], strokeWidth=2))

    # Points
    for x, y in points:
        drawing.add(Circle(x, y, 4, fillColor=COLORS["primary"], strokeColor=COLORS["white"], strokeWidth=1))

    # X-axis labels
    drawing.add(
        String(padding_left, 8, labels[0], fontSize=8, fillColor=COLORS["text_muted"])
    )
    drawing.add(
        String(width - padding_right, 8, labels[-1], fontSize=8, fillColor=COLORS["text_muted"], textAnchor="end")
    )

    # Chart title
    drawing.add(
        String(width / 2, height - 10, "Noise Reduction Trend", fontSize=9, fillColor=COLORS["text_secondary"], textAnchor="middle")
    )

    return drawing


def _severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        label = _severity_label(finding)
        counts[label] = counts.get(label, 0) + 1
    return counts


def _severity_label(finding: Finding) -> str:
    if finding.ai_severity:
        return str(finding.ai_severity)
    mapping = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }
    return mapping.get(str(finding.semgrep_severity), "info")


def _is_critical(finding: Finding) -> bool:
    if str(finding.ai_severity or "").lower() == "critical":
        return True
    if finding.priority_score is not None and finding.priority_score >= 90:
        return True
    return False


def _priority_sort_key(finding: Finding) -> tuple[int, int]:
    priority = finding.priority_score or 0
    severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    severity = _severity_label(finding)
    return (priority, severity_rank.get(severity, 0))


def _priority_label(finding: Finding) -> str:
    return str(finding.priority_score) if finding.priority_score is not None else "n/a"


def _finding_label(finding: Finding) -> str:
    rule = finding.rule_id or "finding"
    message = finding.rule_message or ""
    if message:
        return f"{rule}: {message}"
    return rule


def _finding_location(finding: Finding) -> str:
    if finding.line_start and finding.line_start > 0:
        return f"{finding.file_path}:{finding.line_start}"
    return finding.file_path


def _reachability_label(finding: Finding) -> str:
    if finding.is_reachable is False:
        reason = _fallback_text(finding.reachability_reason, "not reachable")
        return f"{reason}"
    if finding.reachability_score is not None:
        score = max(0.0, min(1.0, float(finding.reachability_score)))
        return f"reachable ({int(round(score * 100))}% confidence)"
    return "reachable"


def _noise_reduction_pct(scan: Scan) -> int:
    total = scan.total_findings or 0
    filtered = scan.filtered_findings or 0
    if total <= 0:
        return 0
    ratio = 1 - filtered / total
    ratio = max(0.0, min(1.0, ratio))
    return int(round(ratio * 100))


def _format_datetime(value: datetime | None) -> str:
    if not value:
        return "n/a"
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _format_short_date(value: datetime | None) -> str:
    if not value:
        return "n/a"
    return value.strftime("%m/%d")


def _clean_text(value: str | None, limit: int | None = None) -> str:
    if value is None:
        return "n/a"
    if hasattr(value, "value"):
        value = value.value
    compact = " ".join(str(value).split())
    if not compact:
        return "n/a"
    if limit and len(compact) > limit:
        compact = f"{compact[: max(0, limit - 3)]}..."
    return escape(compact)


def _fallback_text(value: str | None, fallback: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, str) and not value.strip():
        return fallback
    return value


def _add_page_elements(canvas, doc, generated_at: datetime, is_first: bool = True) -> None:
    """Add header and footer to each page."""
    canvas.saveState()
    page_width = doc.pagesize[0]

    # Header on subsequent pages
    if not is_first:
        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(COLORS["text_secondary"])
        canvas.drawString(40, doc.pagesize[1] - 30, "ScanGuard AI Report")

    # Footer with page number and branding
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(COLORS["text_muted"])
    canvas.drawString(40, 20, f"Generated: {_format_datetime(generated_at)}")
    canvas.drawRightString(page_width - 40, 20, f"Page {doc.page}")

    # Bottom accent line
    canvas.setStrokeColor(COLORS["primary"])
    canvas.setLineWidth(2)
    canvas.line(40, 35, page_width - 40, 35)

    canvas.restoreState()
