from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sast_scan import __version__
from sast_scan.correlation.deduplicator import correlate_findings
from sast_scan.correlation.risk import apply_policy, filter_by_minimum_severity, severity_counts
from sast_scan.core.config import AppConfig
from sast_scan.core.workspace import WorkspaceManager
from sast_scan.engines.opengrep import OpenGrepScanner
from sast_scan.engines.trivy import TrivyScanner
from sast_scan.models.scan import ScanMetadata, ScanReport, ScannerRunResult
from sast_scan.normalization.normalizer import normalize_findings
from sast_scan.reporting.html_report import HtmlReporter
from sast_scan.reporting.json_report import JsonReporter
from sast_scan.reporting.sarif_report import SarifReporter
from sast_scan.utils.filesystem import collect_scan_coverage


class ScanOrchestrator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.workspace_manager = WorkspaceManager()

    def scan(self, target: str) -> ScanReport:
        started = time.monotonic()
        scan_id = str(uuid.uuid4())
        output_dir = self.config.report.output_dir
        raw_dir = output_dir / "raw" / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        raw_dir.mkdir(parents=True, exist_ok=True)

        workspace = self.workspace_manager.prepare(target)
        scanner_results: list[ScannerRunResult] = []
        findings = []
        errors: list[str] = []
        warnings: list[str] = []
        versions: dict[str, str] = {"sast-scan": __version__}
        target_relative = workspace.container_target.removeprefix("/src/") if workspace.target_kind == "file" else None
        coverage = collect_scan_coverage(workspace.scan_root, self.config.scan.exclude, target_relative)

        try:
            scanners = []
            if self.config.opengrep.enabled:
                scanners.append(OpenGrepScanner(self.config.opengrep, self.config))
            if self.config.trivy.enabled:
                scanners.append(TrivyScanner(self.config.trivy, self.config))

            for scanner in scanners:
                result = scanner.scan(workspace, raw_dir)
                scanner_results.append(result)
                if result.version:
                    versions[scanner.name()] = result.version
                findings.extend(result.findings)
                errors.extend(result.errors)
                warnings.extend(result.warnings)
        finally:
            workspace.cleanup()

        normalized = normalize_findings(findings)
        correlated = correlate_findings(normalized)
        report_findings = filter_by_minimum_severity(correlated, self.config.report.minimum_severity)
        policy_failed = apply_policy(correlated, self.config.policy.fail_on)

        duration = time.monotonic() - started
        scanner_statuses = [result.status for result in scanner_results]
        if not scanner_results or all(status == "ERROR" for status in scanner_statuses):
            status = "ERROR"
        elif any(status != "SUCCESS" for status in scanner_statuses):
            status = "PARTIAL"
        elif policy_failed:
            status = "FAILED"
        else:
            status = "SUCCESS"

        metadata = ScanMetadata(
            scan_id=scan_id,
            target=target,
            target_kind=workspace.target_kind,
            scan_root=str(workspace.scan_root),
            started_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 3),
            scanner_versions=versions,
        )
        report = ScanReport(
            metadata=metadata,
            coverage=coverage,
            status=status,
            policy_failed=policy_failed,
            policy_fail_on=self.config.policy.fail_on,
            scanners=scanner_results,
            findings=report_findings,
            summary=severity_counts(report_findings),
            errors=errors,
            warnings=warnings,
            config=self._safe_config_snapshot(),
        )
        self._write_reports(report, output_dir)
        return report

    def _write_reports(self, report: ScanReport, output_dir: Path) -> None:
        if "json" in self.config.report.formats:
            JsonReporter().write(report, output_dir / "scan.json")
        if "html" in self.config.report.formats:
            HtmlReporter().write(report, output_dir / "scan.html")
        if "sarif" in self.config.report.formats:
            SarifReporter().write(report, output_dir / "scan.sarif")

    def _safe_config_snapshot(self) -> dict:
        return json.loads(json.dumps({
            "scanners": {
                "opengrep": {
                    "enabled": self.config.opengrep.enabled,
                    "image": self.config.opengrep.image,
                    "config": [str(path) for path in self.config.opengrep.config],
                    "network": self.config.opengrep.network,
                    "auto_select_rule_sources": self.config.opengrep.auto_select_rule_sources,
                },
                "trivy": {
                    "enabled": self.config.trivy.enabled,
                    "image": self.config.trivy.image,
                    "scanners": self.config.trivy.scanners,
                    "network": self.config.trivy.network,
                    "skip_db_update": self.config.trivy.skip_db_update,
                },
            },
            "scan": {"exclude": self.config.scan.exclude},
            "policy": {"fail_on": self.config.policy.fail_on},
            "report": {"formats": self.config.report.formats, "output_dir": str(self.config.report.output_dir)},
        }))
