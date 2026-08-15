from __future__ import annotations

import re
from collections import defaultdict

from sast_scan.models.finding import Finding


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[_correlation_key(finding)].append(finding)

    for group in groups.values():
        if len(group) < 2:
            continue
        ids = [finding.finding_id for finding in group]
        for finding in group:
            finding.related_finding_ids = sorted(other for other in ids if other != finding.finding_id)
    return findings


def _correlation_key(finding: Finding) -> str:
    if finding.cve and finding.package:
        return f"cve:{finding.package}:{finding.cve}"
    if finding.file and finding.line_start and (finding.rule_id or finding.cwe):
        cwe = ",".join(sorted(finding.cwe))
        return f"loc:{finding.file}:{finding.line_start}:{finding.rule_id or cwe}"
    normalized_title = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return f"title:{finding.category}:{finding.file}:{normalized_title}:{finding.package or ''}"
