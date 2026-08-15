from __future__ import annotations

import json
from pathlib import Path

from sast_scan.models.scan import ScanReport


class SarifReporter:
    def write(self, report: ScanReport, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        rules = {}
        results = []
        for finding in report.findings:
            rule_id = finding.rule_id or finding.finding_id
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "helpUri": finding.references[0] if finding.references else None,
                "properties": {"category": finding.category, "scanner": finding.scanner, "severity": finding.severity},
            }
            location = {}
            if finding.file:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {
                            "startLine": finding.line_start or 1,
                            "startColumn": finding.column_start or 1,
                            "endLine": finding.line_end or finding.line_start or 1,
                            "endColumn": finding.column_end or finding.column_start or 1,
                        },
                    }
                }
            results.append({
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description or finding.title},
                "locations": [location] if location else [],
                "partialFingerprints": {"sastScanFingerprint": finding.fingerprint or finding.finding_id},
                "properties": finding.to_dict(),
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "sast-scan",
                        "version": report.metadata.scanner_versions.get("sast-scan"),
                        "informationUri": "https://github.com/opengrep/opengrep",
                        "rules": [rule for rule in rules.values()],
                    }
                },
                "invocations": [{"executionSuccessful": report.status in {"SUCCESS", "FAILED"}}],
                "properties": {"coverage": report.to_dict()["coverage"], "summary": report.summary},
                "results": results,
            }],
        }
        with path.open("w", encoding="utf-8") as handle:
            json.dump(sarif, handle, indent=2)


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    if severity in {"LOW", "INFO"}:
        return "note"
    return "none"
