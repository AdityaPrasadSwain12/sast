from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sast_scan.models.finding import Finding


def parse_trivy_json(path: Path) -> list[Finding]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    findings: list[Finding] = []
    for result in payload.get("Results", []):
        target = result.get("Target")
        result_type = result.get("Type")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(_parse_vulnerability(target, result_type, vuln).finalize())
        for secret in result.get("Secrets", []) or []:
            findings.append(_parse_secret(target, result_type, secret).finalize())
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append(_parse_misconfiguration(target, result_type, misconfig).finalize())
    return findings


def count_trivy_results(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    count = 0
    for result in payload.get("Results", []) or []:
        count += len(result.get("Vulnerabilities", []) or [])
        count += len(result.get("Secrets", []) or [])
        count += len(result.get("Misconfigurations", []) or [])
    return count


def _parse_vulnerability(target: str | None, result_type: str | None, vuln: dict[str, Any]) -> Finding:
    references = vuln.get("References") or []
    cvss = _best_cvss(vuln.get("CVSS") or {})
    return Finding(
        finding_id="",
        scanner="Trivy",
        category="SCA",
        rule_id=vuln.get("VulnerabilityID"),
        title=vuln.get("Title") or vuln.get("VulnerabilityID") or "Dependency vulnerability",
        description=vuln.get("Description"),
        severity=vuln.get("Severity", "UNKNOWN"),
        original_severity=vuln.get("Severity"),
        file=target,
        package=vuln.get("PkgName"),
        installed_version=vuln.get("InstalledVersion"),
        fixed_version=vuln.get("FixedVersion"),
        cve=vuln.get("VulnerabilityID"),
        cwe=_listify(vuln.get("CweIDs")),
        cvss=cvss,
        remediation=_upgrade_text(vuln),
        references=[str(ref) for ref in references],
        original_category=result_type,
        raw_metadata=_without_keys(vuln, {"Description", "References"}),
    )


def _parse_secret(target: str | None, result_type: str | None, secret: dict[str, Any]) -> Finding:
    return Finding(
        finding_id="",
        scanner="Trivy",
        category="SECRETS",
        rule_id=secret.get("RuleID"),
        title=secret.get("Title") or secret.get("RuleID") or "Secret detected",
        description=secret.get("Message") or "Potential secret detected. The matched value was redacted.",
        severity=secret.get("Severity", "UNKNOWN"),
        original_severity=secret.get("Severity"),
        file=target,
        line_start=secret.get("StartLine"),
        line_end=secret.get("EndLine"),
        code_snippet="[REDACTED]",
        secret_type=secret.get("Category") or secret.get("RuleID"),
        remediation="Rotate the credential if real, revoke the exposed value, and remove it from source history.",
        original_category=result_type,
        raw_metadata=_without_keys(secret, {"Match", "Secret", "Code"}),
    )


def _parse_misconfiguration(target: str | None, result_type: str | None, misconfig: dict[str, Any]) -> Finding:
    cause = misconfig.get("CauseMetadata") or {}
    return Finding(
        finding_id="",
        scanner="Trivy",
        category="MISCONFIGURATION",
        rule_id=misconfig.get("ID"),
        title=misconfig.get("Title") or misconfig.get("ID") or "Misconfiguration",
        description=misconfig.get("Description"),
        severity=misconfig.get("Severity", "UNKNOWN"),
        original_severity=misconfig.get("Severity"),
        file=target,
        line_start=(cause.get("StartLine") or None),
        line_end=(cause.get("EndLine") or None),
        code_snippet=(cause.get("Code") or {}).get("Lines") if isinstance(cause.get("Code"), dict) else None,
        remediation=misconfig.get("Resolution"),
        references=_listify(misconfig.get("References")),
        original_category=result_type,
        raw_metadata=_without_keys(misconfig, {"CauseMetadata"}),
    )


def _best_cvss(cvss: dict[str, Any]) -> float | None:
    for value in cvss.values():
        if isinstance(value, dict) and "V3Score" in value:
            try:
                return float(value["V3Score"])
            except (TypeError, ValueError):
                continue
    return None


def _upgrade_text(vuln: dict[str, Any]) -> str | None:
    fixed = vuln.get("FixedVersion")
    if fixed:
        return f"Upgrade {vuln.get('PkgName', 'the affected package')} to {fixed} or later."
    return "Review vendor advisories and upgrade to a non-vulnerable version when available."


def _listify(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _without_keys(value: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in keys}
