from __future__ import annotations

from collections import Counter

from sast_scan.models.finding import Finding


ORDER = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
SUMMARY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def apply_policy(findings: list[Finding], fail_on: str) -> bool:
    threshold = ORDER.get(fail_on.upper(), ORDER["HIGH"])
    return any(ORDER.get(finding.severity, 0) >= threshold for finding in findings)


def filter_by_minimum_severity(findings: list[Finding], minimum: str | None) -> list[Finding]:
    if not minimum:
        return findings
    threshold = ORDER.get(minimum.upper(), 0)
    return [finding for finding in findings if ORDER.get(finding.severity, 0) >= threshold]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    counts["TOTAL"] = len(findings)
    return {severity: counts.get(severity, 0) for severity in [*SUMMARY_ORDER, "TOTAL"]}


def category_counts(findings: list[Finding]) -> dict[str, int]:
    return dict(Counter(finding.category for finding in findings))
