from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Sequence
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Circle, Drawing, Line, PolyLine, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer

from ...models import Finding, Scan

MAX_CRITICAL_FINDINGS = 10
MAX_PRIORITY_FINDINGS = 8
TREND_MAX_SCANS = 12


def build_scan_report_pdf(
    scan: Scan,
    findings: Sequence[Finding],
    trend_scans: Sequence[Scan],
) -> bytes:
    generated_at = datetime.now(timezone.utc)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=36,
        bottomMargin=36,
        title="ScanGuard AI Report",
    )

    styles = _build_styles()
    story = []

    story.append(Paragraph("ScanGuard AI Report", styles["Title"]))
    story.append(
        Paragraph(
            f"Generated: {_format_datetime(generated_at)}",
            styles["Meta"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scan Overview", styles["SectionHeading"]))
    story.extend(_build_scan_overview(scan, styles))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scan Stats", styles["SectionHeading"]))
    story.extend(_build_scan_stats(scan, findings, styles))
    story.append(Spacer(1, 12))

    story.append(Paragraph("AI Decisioning Summary", styles["SectionHeading"]))
    story.append(Paragraph(_ai_summary_text(), styles["Body"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Critical Findings (AI Reviewed)", styles["SectionHeading"]))
    story.extend(_build_critical_findings(findings, styles))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Remediation Priorities", styles["SectionHeading"]))
    story.extend(_build_remediation_priorities(findings, styles))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Trend Chart", styles["SectionHeading"]))
    story.extend(_build_trend_chart_section(trend_scans, styles))

    doc.build(story, onFirstPage=_add_footer, onLaterPages=_add_footer)
    return buffer.getvalue()


def _build_styles() -> dict[str, ParagraphStyle]:
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Meta",
            parent=styles["BodyText"],
            fontSize=9,
            textColor=colors.HexColor("#475569"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontSize=13,
            spaceBefore=6,
            spaceAfter=6,
            textColor=colors.HexColor("#0f172a"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Body",
            parent=styles["BodyText"],
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#0f172a"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#1f2937"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="FindingTitle",
            parent=styles["Heading3"],
            fontSize=11,
            spaceAfter=2,
            textColor=colors.HexColor("#111827"),
        )
    )
    return styles


def _build_scan_overview(scan: Scan, styles: dict[str, ParagraphStyle]) -> list:
    lines = [
        ("Scan ID", str(scan.id)),
        ("Status", scan.status),
        ("Scan type", scan.scan_type),
        ("Trigger", scan.trigger),
        ("Repository", scan.repo_url or "n/a"),
        ("Target URL", scan.target_url or "n/a"),
        ("Branch", scan.branch if scan.scan_type != "dast" else "n/a"),
        ("Created", _format_datetime(scan.created_at)),
        ("Last updated", _format_datetime(scan.updated_at)),
    ]
    if scan.commit_sha:
        lines.append(("Commit", scan.commit_sha))
    if scan.pr_url:
        lines.append(("Pull request", scan.pr_url))

    blocks = []
    for label, value in lines:
        blocks.append(
            Paragraph(f"<b>{_clean_text(label)}:</b> {_clean_text(value)}", styles["Body"])
        )
    return blocks


def _build_scan_stats(
    scan: Scan, findings: Sequence[Finding], styles: dict[str, ParagraphStyle]
) -> list:
    total = scan.total_findings or 0
    filtered = scan.filtered_findings or 0
    noise_pct = _noise_reduction_pct(scan)
    lines = [
        ("Total findings", str(total)),
        ("Filtered findings", str(filtered)),
        ("Noise reduction", f"{noise_pct}%"),
    ]
    if scan.scan_type != "sast":
        lines.append(("DAST findings", str(scan.dast_findings or 0)))
    if scan.scanned_files is not None:
        lines.append(("Files scanned", str(scan.scanned_files)))
    if scan.detected_languages:
        lines.append(("Languages", ", ".join(scan.detected_languages)))
    if scan.rulesets:
        lines.append(("Rulesets", ", ".join(scan.rulesets)))
    if scan.semgrep_version:
        lines.append(("Semgrep version", scan.semgrep_version))

    blocks = []
    for label, value in lines:
        blocks.append(
            Paragraph(f"<b>{_clean_text(label)}:</b> {_clean_text(value)}", styles["Body"])
        )

    counts = _severity_counts(findings)
    if counts:
        blocks.append(Spacer(1, 6))
        breakdown = ", ".join(
            f"{key}: {value}"
            for key, value in [
                ("critical", counts.get("critical", 0)),
                ("high", counts.get("high", 0)),
                ("medium", counts.get("medium", 0)),
                ("low", counts.get("low", 0)),
                ("info", counts.get("info", 0)),
            ]
        )
        blocks.append(
            Paragraph(
                f"<b>Severity breakdown:</b> {_clean_text(breakdown)}",
                styles["Body"],
            )
        )
    return blocks


def _ai_summary_text() -> str:
    return (
        "AI triage reviews each finding with code context, exploitability signals, "
        "reachability checks, and dynamic evidence when available. Findings marked "
        "as false positives are excluded from this report. Priority ordering blends "
        "AI severity, confidence, and confirmed exploitability."
    )


def _build_critical_findings(
    findings: Sequence[Finding], styles: dict[str, ParagraphStyle]
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
        reasoning = _fallback_text(
            finding.ai_reasoning, "AI reasoning not available."
        )
        exploitability = _fallback_text(
            finding.exploitability, "Exploitability notes not available."
        )
        remediation = _fallback_text(
            finding.remediation, "Remediation guidance not available."
        )
        reachability = _reachability_label(finding)

        blocks.append(
            KeepTogether(
                [
                    Paragraph(
                        f"Finding {index}: {_clean_text(label)}",
                        styles["FindingTitle"],
                    ),
                    Paragraph(
                        f"<b>Severity:</b> {_clean_text(severity)} "
                        f"<b>Priority:</b> {_clean_text(priority)} "
                        f"<b>Type:</b> {_clean_text(finding.finding_type)}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"<b>Location:</b> {_clean_text(location)}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"<b>Reachability:</b> {_clean_text(reachability)}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"<b>AI reasoning:</b> {_clean_text(reasoning, 420)}",
                        styles["Body"],
                    ),
                    Paragraph(
                        f"<b>Exploitability:</b> {_clean_text(exploitability, 320)}",
                        styles["Body"],
                    ),
                    Paragraph(
                        f"<b>Remediation:</b> {_clean_text(remediation, 320)}",
                        styles["Body"],
                    ),
                    Spacer(1, 8),
                ]
            )
        )

    if len(critical) > MAX_CRITICAL_FINDINGS:
        blocks.append(
            Paragraph(
                f"Only the top {MAX_CRITICAL_FINDINGS} critical findings are shown.",
                styles["BodySmall"],
            )
        )
    return blocks


def _build_remediation_priorities(
    findings: Sequence[Finding], styles: dict[str, ParagraphStyle]
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
        remediation = _fallback_text(
            finding.remediation,
            f"Review and address: {label}",
        )
        blocks.append(
            KeepTogether(
                [
                    Paragraph(
                        f"{index}. {_clean_text(label)}",
                        styles["Body"],
                    ),
                    Paragraph(
                        f"<b>Severity:</b> {_clean_text(severity)} "
                        f"<b>Priority:</b> {_clean_text(priority)} "
                        f"<b>Location:</b> {_clean_text(location)}",
                        styles["BodySmall"],
                    ),
                    Paragraph(
                        f"<b>Recommended action:</b> {_clean_text(remediation, 320)}",
                        styles["BodySmall"],
                    ),
                    Spacer(1, 6),
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
        Spacer(1, 6),
        chart,
    ]


def _build_trend_chart(scans: Sequence[Scan]) -> Drawing | None:
    completed = [scan for scan in scans if scan.status == "completed"]
    if len(completed) < 2:
        return None

    completed = sorted(completed, key=lambda scan: scan.created_at)
    values = [_noise_reduction_pct(scan) for scan in completed]
    labels = [_format_short_date(scan.created_at) for scan in completed]

    width = 420
    height = 160
    padding = 24
    chart_width = width - (padding * 2)
    chart_height = height - (padding * 2)

    drawing = Drawing(width, height)
    axis_color = colors.HexColor("#cbd5f5")
    line_color = colors.HexColor("#0ea5e9")

    drawing.add(
        Line(padding, padding, padding, padding + chart_height, strokeColor=axis_color)
    )
    drawing.add(
        Line(padding, padding, padding + chart_width, padding, strokeColor=axis_color)
    )

    points = []
    for index, value in enumerate(values):
        x = padding + (chart_width * index / (len(values) - 1))
        y = padding + (chart_height * value / 100)
        points.append((x, y))

    drawing.add(PolyLine(points, strokeColor=line_color, strokeWidth=1.4))
    for x, y in points:
        drawing.add(Circle(x, y, 2, fillColor=line_color, strokeColor=line_color))

    drawing.add(
        String(
            padding,
            height - 12,
            "Noise reduction (%)",
            fontSize=8,
            fillColor=colors.HexColor("#475569"),
        )
    )
    drawing.add(
        String(
            padding,
            6,
            labels[0],
            fontSize=7,
            fillColor=colors.HexColor("#64748b"),
        )
    )
    drawing.add(
        String(
            width - padding - 40,
            6,
            labels[-1],
            fontSize=7,
            fillColor=colors.HexColor("#64748b"),
        )
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
    return value.strftime("%Y-%m-%d")


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


def _add_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    page_label = f"Page {doc.page}"
    canvas.drawRightString(doc.pagesize[0] - 36, 20, page_label)
    canvas.restoreState()
