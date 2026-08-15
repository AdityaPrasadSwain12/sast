from __future__ import annotations

from sast_scan.models.finding import Finding


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "NOTE": "INFO",
    "UNKNOWN": "UNKNOWN",
}


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        original = finding.severity or finding.original_severity or "UNKNOWN"
        finding.original_severity = finding.original_severity or original
        finding.severity = SEVERITY_MAP.get(str(original).upper(), "UNKNOWN")
        finding.category = str(finding.category).upper()
        finding.finalize()
    return findings
