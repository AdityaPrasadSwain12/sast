from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sast_scan.models.finding import Finding


def parse_opengrep_json(path: Path) -> list[Finding]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    findings: list[Finding] = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        start = item.get("start", {}) or {}
        end = item.get("end", {}) or {}
        rule_id = item.get("check_id")
        finding = Finding(
            finding_id="",
            scanner="OpenGrep",
            category="SAST",
            rule_id=rule_id,
            title=extra.get("message") or rule_id or "OpenGrep finding",
            description=extra.get("message"),
            severity=extra.get("severity", "UNKNOWN"),
            original_severity=extra.get("severity"),
            confidence=_string_or_none(metadata.get("confidence")),
            file=item.get("path"),
            line_start=start.get("line"),
            line_end=end.get("line"),
            column_start=start.get("col"),
            column_end=end.get("col"),
            code_snippet=_extract_snippet(extra),
            cwe=_listify(metadata.get("cwe")),
            owasp=_listify(metadata.get("owasp")),
            remediation=_string_or_none(metadata.get("fix")) or _string_or_none(metadata.get("remediation")),
            references=_listify(metadata.get("references")),
            original_category=_string_or_none(metadata.get("category")),
            raw_metadata=_safe_raw_metadata(item, metadata),
        )
        findings.append(finding.finalize())
    return findings


def parse_opengrep_diagnostics(path: Path) -> tuple[list[str], list[str]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    errors = [str(error) for error in payload.get("errors", []) or []]
    warnings: list[str] = []
    for skipped_rule in payload.get("skipped_rules", []) or []:
        warnings.append(f"OpenGrep skipped rule: {skipped_rule}")
    for skipped_target in payload.get("skipped_targets", []) or []:
        warnings.append(f"OpenGrep skipped target: {skipped_target}")
    return errors, warnings


def count_opengrep_results(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return len(payload.get("results", []) or [])


def _extract_snippet(extra: dict[str, Any]) -> str | None:
    lines = extra.get("lines")
    if isinstance(lines, str):
        return lines[:2000]
    return None


def _listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _string_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None


def _safe_raw_metadata(item: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    extra = item.get("extra", {}) or {}
    return {
        "scanner_fingerprint": extra.get("fingerprint"),
        "validation_state": extra.get("validation_state"),
        "engine_kind": extra.get("engine_kind"),
        "original_path": item.get("path"),
        "metadata": {str(key): value for key, value in metadata.items()},
    }
