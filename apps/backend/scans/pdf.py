from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b42318"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#b7791f"),
    "LOW": colors.HexColor("#15803d"),
    "INFO": colors.HexColor("#1d4ed8"),
    "UNKNOWN": colors.HexColor("#64748b"),
}


def write_scan_pdf(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _styles()
    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="SAST Scan Security Report",
        author="SAST Scan",
    )
    story: list[Flowable] = []

    _add_cover(story, report, styles)
    _add_summary(story, report, styles)
    _add_scanner_details(story, report, styles)
    _add_findings(story, report, styles)

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)


def _add_cover(story: list[Flowable], report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    metadata = report.get("metadata", {})
    summary = report.get("summary", {})

    story.append(Paragraph("SAST Scan Security Report", styles["cover_title"]))
    story.append(Paragraph("OpenGrep + Trivy vulnerability assessment", styles["cover_subtitle"]))
    story.append(Spacer(1, 12 * mm))
    story.append(_status_band(report.get("status", "UNKNOWN")))
    story.append(Spacer(1, 8 * mm))

    story.append(_key_value_table([
        ("Scan ID", metadata.get("scan_id", "-")),
        ("Target", metadata.get("target", "-")),
        ("Target Type", metadata.get("target_kind", "-")),
        ("Started At", metadata.get("started_at", "-")),
        ("Duration", f"{metadata.get('duration_seconds', '-')} seconds"),
        ("Policy Fail On", report.get("policy_fail_on", "-")),
        ("Policy Failed", "Yes" if report.get("policy_failed") else "No"),
    ], styles))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Finding Severity Summary", styles["h2"]))
    story.append(_severity_table(summary, styles))
    story.append(PageBreak())


def _add_summary(story: list[Flowable], report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    coverage = report.get("coverage", {})
    integrity = report.get("integrity", {})

    story.append(Paragraph("Scan Coverage", styles["h1"]))
    story.append(_key_value_table([
        ("Files Scanned", coverage.get("files_scanned", 0)),
        ("Lines Scanned", coverage.get("lines_scanned", 0)),
        ("Bytes Scanned", coverage.get("bytes_scanned", 0)),
        ("Binary Files Skipped For Line Count", coverage.get("binary_files_skipped_for_line_count", 0)),
        ("Languages", _format_mapping(coverage.get("languages", {}))),
        ("Extensions", _format_mapping(coverage.get("extensions", {}))),
    ], styles))

    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("Report Integrity", styles["h1"]))
    story.append(_key_value_table([
        ("Raw Findings From Scanners", integrity.get("scanner_raw_finding_count", 0)),
        ("Parsed Findings", integrity.get("scanner_parsed_finding_count", 0)),
        ("Final Report Findings", integrity.get("final_report_finding_count", 0)),
        ("Dropped Findings", integrity.get("dropped_finding_count", 0)),
        ("All Parsed Findings Included", "Yes" if integrity.get("all_parsed_findings_included") else "No"),
    ], styles))
    story.append(Spacer(1, 6 * mm))


def _add_scanner_details(story: list[Flowable], report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    story.append(Paragraph("Scanner Runs", styles["h1"]))
    rows = [[
        Paragraph("Scanner", styles["table_header"]),
        Paragraph("Status", styles["table_header"]),
        Paragraph("Version", styles["table_header"]),
        Paragraph("Raw", styles["table_header"]),
        Paragraph("Parsed", styles["table_header"]),
        Paragraph("Dropped", styles["table_header"]),
        Paragraph("Duration", styles["table_header"]),
    ]]

    for scanner in report.get("scanners", []):
        rows.append([
            Paragraph(_text(scanner.get("scanner")), styles["cell"]),
            Paragraph(_text(scanner.get("status")), styles["cell"]),
            Paragraph(_text(scanner.get("version")), styles["cell"]),
            Paragraph(str(scanner.get("raw_finding_count", 0)), styles["cell"]),
            Paragraph(str(scanner.get("parsed_finding_count", 0)), styles["cell"]),
            Paragraph(str(scanner.get("dropped_finding_count", 0)), styles["cell"]),
            Paragraph(f"{scanner.get('duration_seconds', 0)}s", styles["cell"]),
        ])

    story.append(_table(rows, [30 * mm, 24 * mm, 42 * mm, 18 * mm, 20 * mm, 22 * mm, 24 * mm]))
    story.append(Spacer(1, 8 * mm))


def _add_findings(story: list[Flowable], report: dict[str, Any], styles: dict[str, ParagraphStyle]) -> None:
    findings = report.get("findings", [])
    story.append(Paragraph("Vulnerability Findings", styles["h1"]))

    if not findings:
        story.append(Paragraph("No vulnerabilities were included in the final report.", styles["body"]))
        return

    for index, finding in enumerate(findings, start=1):
        story.append(_finding_block(index, finding, styles))


def _finding_block(index: int, finding: dict[str, Any], styles: dict[str, ParagraphStyle]) -> Flowable:
    severity = _text(finding.get("severity"), "UNKNOWN").upper()
    title = _text(finding.get("title") or finding.get("description") or finding.get("rule_id") or finding.get("cve"), "Untitled finding")
    rule = _text(finding.get("rule_id") or finding.get("cve"))
    cwe = ", ".join(finding.get("cwe") or []) or "-"
    owasp = ", ".join(finding.get("owasp") or []) or "-"
    location = f"{_text(finding.get('file'))}:{finding.get('line_start') or '-'}"
    scanner = _text(finding.get("scanner"))
    category = _text(finding.get("category"))
    description = _text(finding.get("description") or finding.get("title"))
    remediation = _text(finding.get("remediation"), "Review the scanner finding, validate exploitability, and apply a secure fix.")
    snippet = _plain_text(finding.get("code_snippet"), "")
    references = finding.get("references") or []

    title_style = ParagraphStyle(
        name=f"finding_title_{index}",
        parent=styles["finding_title"],
        textColor=SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"]),
    )
    rows = [
        [
            Paragraph(f"{index}. {severity}", title_style),
            Paragraph(title, styles["finding_title"]),
        ],
        [
            Paragraph("Scanner", styles["label"]),
            Paragraph(scanner, styles["cell"]),
        ],
        [
            Paragraph("Rule / CVE", styles["label"]),
            Paragraph(rule, styles["cell"]),
        ],
        [
            Paragraph("Location", styles["label"]),
            Paragraph(location, styles["cell"]),
        ],
        [
            Paragraph("Category", styles["label"]),
            Paragraph(category, styles["cell"]),
        ],
        [
            Paragraph("CWE", styles["label"]),
            Paragraph(cwe, styles["cell"]),
        ],
        [
            Paragraph("OWASP", styles["label"]),
            Paragraph(owasp, styles["cell"]),
        ],
        [
            Paragraph("Problem", styles["label"]),
            Paragraph(description, styles["cell"]),
        ],
        [
            Paragraph("Remediation", styles["label"]),
            Paragraph(remediation, styles["cell"]),
        ],
    ]

    elements: list[Flowable] = [
        _table(rows, [32 * mm, 146 * mm], header_rows=0, severity=severity),
    ]
    if snippet:
        elements.extend([
            Spacer(1, 2 * mm),
            Paragraph("Evidence", styles["label_block"]),
            Preformatted(snippet[:1800], styles["code"]),
        ])
    if references:
        elements.extend([
            Spacer(1, 2 * mm),
            Paragraph("References", styles["label_block"]),
            Paragraph(", ".join(_text(reference) for reference in references[:5]), styles["cell"]),
        ])
    elements.append(Spacer(1, 6 * mm))
    return KeepTogether(elements)


def _status_band(status: str) -> Table:
    status_text = _text(status, "UNKNOWN").upper()
    color = colors.HexColor("#16a34a")
    if status_text in {"FAILED", "ERROR"}:
        color = colors.HexColor("#dc2626")
    elif status_text == "PARTIAL":
        color = colors.HexColor("#d97706")

    table = Table([[Paragraph(f"Overall Status: {status_text}", ParagraphStyle(
        "status",
        fontName="Helvetica-Bold",
        fontSize=15,
        textColor=colors.white,
        alignment=TA_CENTER,
        leading=18,
    ))]], colWidths=[178 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("BOX", (0, 0), (-1, -1), 0.5, color),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def _severity_table(summary: dict[str, Any], styles: dict[str, ParagraphStyle]) -> Table:
    headers = ["Critical", "High", "Medium", "Low", "Info", "Total"]
    keys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL"]
    rows = [
        [Paragraph(header, styles["table_header"]) for header in headers],
        [Paragraph(str(summary.get(key, 0)), styles["severity_count"]) for key in keys],
    ]
    table = Table(rows, colWidths=[29 * mm] * 6)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7dee9")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    for index, key in enumerate(keys[:-1]):
        style.append(("BACKGROUND", (index, 0), (index, 0), SEVERITY_COLORS[key]))
        style.append(("TEXTCOLOR", (index, 0), (index, 0), colors.white))
    style.append(("BACKGROUND", (5, 0), (5, 0), colors.HexColor("#334155")))
    style.append(("TEXTCOLOR", (5, 0), (5, 0), colors.white))
    table.setStyle(TableStyle(style))
    return table


def _key_value_table(items: list[tuple[str, Any]], styles: dict[str, ParagraphStyle]) -> Table:
    rows = [[Paragraph(label, styles["label"]), Paragraph(_text(value), styles["cell"])] for label, value in items]
    return _table(rows, [45 * mm, 133 * mm], header_rows=0)


def _table(rows: list[list[Any]], col_widths: list[float], header_rows: int = 1, severity: str | None = None) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=header_rows)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d7dee9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ]
    if header_rows:
        style.extend([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ])
    if severity:
        style.append(("LINEBEFORE", (0, 0), (0, -1), 4, SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])))
    table.setStyle(TableStyle(style))
    return table


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("cover_title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=26, leading=31, textColor=colors.HexColor("#0f172a"), alignment=TA_LEFT),
        "cover_subtitle": ParagraphStyle("cover_subtitle", parent=base["Normal"], fontSize=12, leading=16, textColor=colors.HexColor("#475569")),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=colors.HexColor("#0f172a"), spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=colors.HexColor("#1e293b"), spaceAfter=6),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12, textColor=colors.HexColor("#1e293b")),
        "label": ParagraphStyle("label", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.HexColor("#475569")),
        "label_block": ParagraphStyle("label_block", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.HexColor("#334155"), spaceAfter=3),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=8.5, leading=11, textColor=colors.HexColor("#0f172a")),
        "table_header": ParagraphStyle("table_header", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white, alignment=TA_CENTER),
        "severity_count": ParagraphStyle("severity_count", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=16, leading=19, alignment=TA_CENTER, textColor=colors.HexColor("#0f172a")),
        "finding_title": ParagraphStyle("finding_title", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=colors.HexColor("#0f172a")),
        "code": ParagraphStyle("code", parent=base["Code"], fontName="Courier", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#111827"), backColor=colors.HexColor("#f8fafc"), borderColor=colors.HexColor("#d7dee9"), borderWidth=0.5, borderPadding=5),
    }


def _footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(16 * mm, 9 * mm, "SAST Scan - OpenGrep + Trivy")
    canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def _text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return escape(text) if text else default


def _plain_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _format_mapping(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return "-"
    return ", ".join(f"{key}={count}" for key, count in sorted(value.items()))
