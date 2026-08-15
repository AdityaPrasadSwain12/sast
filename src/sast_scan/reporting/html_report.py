from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from sast_scan.correlation.risk import category_counts
from sast_scan.models.finding import Finding
from sast_scan.models.scan import ScanReport


class HtmlReporter:
    def write(self, report: ScanReport, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")

    def render(self, report: ScanReport) -> str:
        findings = "\n".join(_finding_section(finding) for finding in report.findings) or "<p>No findings reported by enabled scanners.</p>"
        severity_rows = "\n".join(
            f"<tr><td>{severity}</td><td>{count}</td><td>{_percentage(count, report.summary.get('TOTAL', 0))}</td></tr>"
            for severity, count in report.summary.items()
            if severity != "TOTAL"
        )
        category_rows = "\n".join(f"<tr><td>{html.escape(category)}</td><td>{count}</td></tr>" for category, count in category_counts(report.findings).items())
        scanner_rows = "\n".join(
            f"<tr><td>{html.escape(scanner.scanner)}</td><td>{html.escape(scanner.status)}</td><td>{html.escape(scanner.version or '')}</td><td>{scanner.raw_finding_count}</td><td>{scanner.parsed_finding_count}</td><td>{scanner.dropped_finding_count}</td><td>{scanner.duration_seconds}s</td></tr>"
            for scanner in report.scanners
        )
        language_rows = "\n".join(
            f"<tr><td>{html.escape(language)}</td><td>{count}</td></tr>"
            for language, count in sorted(report.coverage.languages.items(), key=lambda item: (-item[1], item[0]))
        )
        error_block = "".join(f"<li>{html.escape(error)}</li>" for error in report.errors)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>sast-scan report</title>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; color: #18212f; background: #f5f7fa; }}
    header {{ background: #172033; color: white; padding: 28px 40px; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px 20px 48px; }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    section {{ margin: 22px 0; background: white; border: 1px solid #dfe5ee; border-radius: 8px; padding: 22px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
    .metric {{ border: 1px solid #dfe5ee; border-radius: 8px; padding: 16px; background: #fbfcfe; }}
    .metric strong {{ display: block; font-size: 26px; margin-top: 6px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #e6ebf2; text-align: left; padding: 10px; vertical-align: top; }}
    th {{ background: #f0f3f8; }}
    .sev-CRITICAL {{ color: #8f1111; font-weight: 700; }}
    .sev-HIGH {{ color: #b13f00; font-weight: 700; }}
    .sev-MEDIUM {{ color: #8a6500; font-weight: 700; }}
    .sev-LOW {{ color: #2f6b2f; font-weight: 700; }}
    .finding {{ border-top: 4px solid #c8d1dd; }}
    pre {{ white-space: pre-wrap; background: #101828; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }}
    footer {{ color: #64748b; text-align: center; padding: 24px; }}
  </style>
</head>
<body>
  <header>
    <h1>Security Assessment Report</h1>
    <div>{html.escape(report.metadata.target)} | {html.escape(report.status)} | Scan {html.escape(report.metadata.scan_id)}</div>
  </header>
  <main>
    <section>
      <h2>Executive Summary</h2>
      <div class="grid">
        <div class="metric">Overall Status<strong>{html.escape(report.status)}</strong></div>
        <div class="metric">Total Findings<strong>{report.summary.get('TOTAL', 0)}</strong></div>
        <div class="metric">Critical<strong>{report.summary.get('CRITICAL', 0)}</strong></div>
        <div class="metric">High<strong>{report.summary.get('HIGH', 0)}</strong></div>
        <div class="metric">Files Scanned<strong>{report.coverage.files_scanned}</strong></div>
        <div class="metric">Lines Scanned<strong>{report.coverage.lines_scanned}</strong></div>
        <div class="metric">Duration<strong>{report.metadata.duration_seconds}s</strong></div>
      </div>
      <p><strong>Project/Repository:</strong> {html.escape(report.metadata.target)}</p>
      <p><strong>Scan Date:</strong> {html.escape(report.metadata.started_at)}</p>
      <p><strong>Policy:</strong> fail on {html.escape(report.policy_fail_on)}</p>
    </section>
    <section>
      <h2>Scan Coverage</h2>
      <table>
        <tbody>
          <tr><th>Target Type</th><td>{html.escape(report.metadata.target_kind)}</td></tr>
          <tr><th>Scan Root</th><td>{html.escape(report.metadata.scan_root)}</td></tr>
          <tr><th>Files Scanned</th><td>{report.coverage.files_scanned}</td></tr>
          <tr><th>Lines Scanned</th><td>{report.coverage.lines_scanned}</td></tr>
          <tr><th>Bytes Scanned</th><td>{report.coverage.bytes_scanned}</td></tr>
          <tr><th>Binary Files Skipped For Line Count</th><td>{report.coverage.binary_files_skipped_for_line_count}</td></tr>
        </tbody>
      </table>
      <h3>Detected Languages / File Types</h3>
      <table><thead><tr><th>Language or File Type</th><th>Files</th></tr></thead><tbody>{language_rows}</tbody></table>
      <h3>Scanner Execution</h3>
      <table><thead><tr><th>Scanner</th><th>Status</th><th>Version</th><th>Raw Findings</th><th>Parsed Findings</th><th>Dropped Findings</th><th>Duration</th></tr></thead><tbody>{scanner_rows}</tbody></table>
    </section>
    <section>
      <h2>Severity Summary</h2>
      <table><thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead><tbody>{severity_rows}</tbody></table>
      <h3>Category Distribution</h3>
      <table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>{category_rows}</tbody></table>
    </section>
    <section>
      <h2>Detailed Findings</h2>
      {findings}
    </section>
    <section>
      <h2>Remediation Summary</h2>
      <ol>
        <li>Fix all critical findings immediately.</li>
        <li>Fix high severity dependency and SAST findings before release.</li>
        <li>Rotate any exposed secrets and remove them from source history.</li>
        <li>Resolve infrastructure and configuration issues according to scanner guidance.</li>
      </ol>
    </section>
    {"<section><h2>Scanner Errors</h2><ul>" + error_block + "</ul></section>" if report.errors else ""}
  </main>
  <footer>Generated by sast-scan at {datetime.now(timezone.utc).isoformat()}</footer>
</body>
</html>"""


def _finding_section(finding: Finding) -> str:
    refs = "".join(f"<li><a href=\"{html.escape(ref)}\">{html.escape(ref)}</a></li>" for ref in finding.references)
    related = ", ".join(finding.related_finding_ids)
    snippet_text = _snippet_to_text(finding.code_snippet)
    snippet = f"<pre>{html.escape(snippet_text)}</pre>" if snippet_text else ""
    fields = [
        ("Finding ID", finding.finding_id),
        ("Severity", finding.severity),
        ("Scanner", finding.scanner),
        ("Rule ID", finding.rule_id),
        ("Category", finding.category),
        ("File", finding.file),
        ("Line", str(finding.line_start) if finding.line_start else None),
        ("Package", finding.package),
        ("Installed Version", finding.installed_version),
        ("Fixed Version", finding.fixed_version),
        ("CVE", finding.cve),
        ("CWE", ", ".join(finding.cwe) if finding.cwe else None),
        ("OWASP", ", ".join(finding.owasp) if finding.owasp else None),
        ("CVSS", str(finding.cvss) if finding.cvss is not None else None),
        ("Secret Type", finding.secret_type),
        ("Related Findings", related or None),
    ]
    rows = "".join(f"<tr><th>{html.escape(name)}</th><td>{html.escape(value)}</td></tr>" for name, value in fields if value)
    remediation = html.escape(finding.remediation or "Review scanner guidance and apply the least-risk secure fix.")
    description = html.escape(finding.description or "No scanner description provided.")
    return f"""
      <article class="finding">
        <h3><span class="sev-{html.escape(finding.severity)}">[{html.escape(finding.severity)}]</span> {html.escape(finding.title)}</h3>
        <table>{rows}</table>
        <h4>Description</h4><p>{description}</p>
        <h4>Security Impact</h4><p>This finding may increase application or supply-chain risk. Validate exploitability in context and prioritize according to severity, exposure, and business impact.</p>
        <h4>Remediation</h4><p>{remediation}</p>
        {snippet}
        {"<h4>References</h4><ul>" + refs + "</ul>" if refs else ""}
      </article>
    """


def _percentage(count: int, total: int) -> str:
    if total <= 0:
        return "0%"
    return f"{(count / total) * 100:.1f}%"


def _snippet_to_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)
