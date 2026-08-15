from __future__ import annotations

from pathlib import Path

from sast_scan.correlation.risk import category_counts
from sast_scan.models.scan import ScanReport


class ConsoleReporter:
    def render(self, report: ScanReport) -> str:
        lines = [
            "=" * 60,
            "SAST-SCAN SECURITY REPORT",
            "=" * 60,
            "",
            f"Target: {report.metadata.target}",
            f"Status: {report.status}",
            f"Scan ID: {report.metadata.scan_id}",
            f"Duration: {report.metadata.duration_seconds}s",
            f"Files scanned: {report.coverage.files_scanned}",
            f"Lines scanned: {report.coverage.lines_scanned}",
            "",
            "Scanners:",
        ]
        for scanner in report.scanners:
            marker = "OK" if scanner.status == "SUCCESS" else scanner.status
            lines.append(
                f"  {scanner.scanner:10} {marker:8} "
                f"raw={scanner.raw_finding_count} parsed={scanner.parsed_finding_count} dropped={scanner.dropped_finding_count}"
            )
        lines.extend(["", "Findings:"])
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN", "TOTAL"]:
            lines.append(f"  {severity:10} {report.summary.get(severity, 0)}")
        lines.extend(["", "Categories:"])
        for category, count in sorted(category_counts(report.findings).items()):
            lines.append(f"  {category:18} {count}")
        if report.coverage.languages:
            lines.extend(["", "Coverage:"])
            for language, count in sorted(report.coverage.languages.items(), key=lambda item: (-item[1], item[0]))[:8]:
                lines.append(f"  {language:18} {count} files")

        important = [finding for finding in report.findings if finding.severity in {"CRITICAL", "HIGH"}][:10]
        if important:
            lines.extend(["", "Highest Risk Findings:"])
            for finding in important:
                location = f" ({finding.file}:{finding.line_start})" if finding.file and finding.line_start else ""
                lines.append(f"  [{finding.severity}] {finding.title}{location}")

        if report.errors:
            lines.extend(["", "Errors:"])
            lines.extend(f"  {error}" for error in report.errors[:5])
        output_dir = report.config.get("report", {}).get("output_dir", "reports")
        lines.extend([
            "",
            "Reports:",
            f"  {Path(output_dir) / 'scan.html'}",
            f"  {Path(output_dir) / 'scan.json'}",
            f"  {Path(output_dir) / 'scan.sarif'}",
            "=" * 60,
        ])
        return "\n".join(lines)
