from __future__ import annotations

import time
from pathlib import Path

from sast_scan.core.config import AppConfig, TrivyConfig
from sast_scan.core.workspace import PreparedWorkspace
from sast_scan.engines.base import HealthCheck
from sast_scan.models.scan import ScannerRunResult
from sast_scan.parsers.trivy_parser import count_trivy_results, parse_trivy_json
from sast_scan.utils.process import ProcessRunner


class TrivyScanner:
    def __init__(self, scanner_config: TrivyConfig, app_config: AppConfig, runner: ProcessRunner | None = None) -> None:
        self.scanner_config = scanner_config
        self.app_config = app_config
        self.runner = runner or ProcessRunner()

    def name(self) -> str:
        return "Trivy"

    def version(self) -> str | None:
        result = self.runner.run(self._docker_prefix([]) + [self.scanner_config.image, "--version"], timeout_seconds=30)
        return result.stdout.strip().splitlines()[0] if result.exit_code == 0 and result.stdout.strip() else None

    def health_check(self) -> HealthCheck:
        result = self.runner.run(["docker", "image", "inspect", self.scanner_config.image, "--format", "{{.Id}}"], timeout_seconds=20)
        if result.exit_code != 0:
            return HealthCheck("WARN", diagnostic=f"Trivy image unavailable locally; Docker can pull it during scan: {self.scanner_config.image}")
        return HealthCheck("OK", version=self.version())

    def scan(self, workspace: PreparedWorkspace, raw_output_dir: Path) -> ScannerRunResult:
        started = time.monotonic()
        output_path = raw_output_dir / "trivy.json"
        cache_dir = self.app_config.base_dir / ".sast-scan-cache" / "trivy"
        cache_dir.mkdir(parents=True, exist_ok=True)
        result = self.runner.run(self._build_scan_command(workspace, output_path, cache_dir), timeout_seconds=self.scanner_config.timeout_seconds)
        findings = []
        errors = []
        warnings = []
        raw_finding_count = 0
        status = "SUCCESS"

        if output_path.exists():
            try:
                raw_finding_count = count_trivy_results(output_path)
                findings = parse_trivy_json(output_path)
            except Exception as exc:  # noqa: BLE001
                status = "ERROR"
                errors.append(f"Trivy parser failed: {exc}")
        if result.exit_code != 0:
            status = "ERROR" if not findings else "PARTIAL"
            errors.append(_clean_stderr(result.stderr) or f"Trivy exited with code {result.exit_code}")
        if result.timed_out:
            status = "ERROR"
            errors.append("Trivy timed out")

        return ScannerRunResult(
            scanner=self.name(),
            status=status,
            version=self.version(),
            raw_output_path=str(output_path),
            raw_finding_count=raw_finding_count,
            parsed_finding_count=len(findings),
            dropped_finding_count=max(raw_finding_count - len(findings), 0),
            findings=findings,
            errors=errors,
            warnings=warnings,
            duration_seconds=round(time.monotonic() - started, 3),
        )

    def _build_scan_command(self, workspace: PreparedWorkspace, output_path: Path, cache_dir: Path) -> list[str]:
        command = self._docker_prefix([
            "--mount", f"type=bind,src={workspace.scan_root},dst=/src,readonly",
            "--mount", f"type=bind,src={output_path.parent},dst=/out",
            "--mount", f"type=bind,src={cache_dir},dst=/cache",
            "--workdir", "/src",
        ])
        command.extend([
            self.scanner_config.image,
            "fs",
            "--format", "json",
            "--output", "/out/trivy.json",
            "--exit-code", "0",
            "--cache-dir", "/cache",
            "--scanners", ",".join(self.scanner_config.scanners),
        ])
        if self.scanner_config.skip_db_update:
            command.append("--skip-db-update")
        for exclusion in self.app_config.scan.exclude:
            command.extend(["--skip-dirs", f"/src/{exclusion}"])
        command.append(workspace.container_target)
        return command

    def _docker_prefix(self, extra: list[str]) -> list[str]:
        return [
            "docker", "run", "--rm",
            "--network", self.scanner_config.network,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
            *extra,
        ]


def _clean_stderr(stderr: str) -> str:
    return "\n".join(line for line in stderr.splitlines() if "secret" not in line.lower())[:4000]
