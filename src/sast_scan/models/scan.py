from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from sast_scan.models.finding import Finding


@dataclass
class ScanMetadata:
    scan_id: str
    target: str
    target_kind: str
    scan_root: str
    started_at: str
    duration_seconds: float
    scanner_versions: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanCoverage:
    files_scanned: int = 0
    lines_scanned: int = 0
    bytes_scanned: int = 0
    binary_files_skipped_for_line_count: int = 0
    extensions: dict[str, int] = field(default_factory=dict)
    languages: dict[str, int] = field(default_factory=dict)
    excluded_patterns: list[str] = field(default_factory=list)


@dataclass
class ScannerRunResult:
    scanner: str
    status: str
    version: str | None = None
    raw_output_path: str | None = None
    raw_finding_count: int = 0
    parsed_finding_count: int = 0
    dropped_finding_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass
class ScanReport:
    metadata: ScanMetadata
    coverage: ScanCoverage
    status: str
    policy_failed: bool
    policy_fail_on: str
    scanners: list[ScannerRunResult]
    findings: list[Finding]
    summary: dict[str, int]
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        raw_finding_count = sum(scanner.raw_finding_count for scanner in self.scanners)
        parsed_finding_count = sum(scanner.parsed_finding_count for scanner in self.scanners)
        dropped_finding_count = sum(scanner.dropped_finding_count for scanner in self.scanners)
        return {
            "metadata": asdict(self.metadata),
            "coverage": asdict(self.coverage),
            "integrity": {
                "scanner_raw_finding_count": raw_finding_count,
                "scanner_parsed_finding_count": parsed_finding_count,
                "final_report_finding_count": len(self.findings),
                "dropped_finding_count": dropped_finding_count,
                "all_parsed_findings_included": parsed_finding_count == len(self.findings),
            },
            "status": self.status,
            "policy_failed": self.policy_failed,
            "policy_fail_on": self.policy_fail_on,
            "scanners": [scanner.to_dict() for scanner in self.scanners],
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "warnings": self.warnings,
            "config": self.config,
        }
