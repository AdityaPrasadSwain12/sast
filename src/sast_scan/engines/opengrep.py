from __future__ import annotations

import time
from pathlib import Path

from sast_scan.core.config import AppConfig, OpenGrepConfig
from sast_scan.core.workspace import PreparedWorkspace
from sast_scan.engines.base import HealthCheck
from sast_scan.models.scan import ScannerRunResult
from sast_scan.parsers.opengrep_parser import count_opengrep_results, parse_opengrep_diagnostics, parse_opengrep_json
from sast_scan.utils.filesystem import collect_scan_coverage
from sast_scan.utils.process import ProcessRunner


COMMUNITY_LANGUAGE_MAP = {
    "Apex": {"apex"},
    "C": {"c"},
    "C#": {"csharp"},
    "C++": {"c"},
    "C/C++ Header": {"c"},
    "Clojure": {"clojure"},
    "Dockerfile": {"dockerfile"},
    "Elixir": {"elixir"},
    "Go": {"go"},
    "HTML": {"html"},
    "Java": {"java"},
    "Java Dependencies": {"java"},
    "JavaScript": {"javascript"},
    "JSON": {"json"},
    "Kotlin": {"kotlin"},
    "Node Dependencies": {"javascript", "typescript"},
    "PHP": {"php"},
    "Python": {"python"},
    "Python Dependencies": {"python"},
    "Ruby": {"ruby"},
    "Rust": {"rust"},
    "Scala": {"scala"},
    "Shell": {"bash"},
    "Swift": {"swift"},
    "Terraform": {"terraform"},
    "TypeScript": {"typescript"},
    "YAML": {"yaml"},
}


class OpenGrepScanner:
    def __init__(self, scanner_config: OpenGrepConfig, app_config: AppConfig, runner: ProcessRunner | None = None) -> None:
        self.scanner_config = scanner_config
        self.app_config = app_config
        self.runner = runner or ProcessRunner()

    def name(self) -> str:
        return "OpenGrep"

    def version(self) -> str | None:
        result = self.runner.run(self._docker_prefix([]) + [self.scanner_config.image, "opengrep", "--version"], timeout_seconds=30)
        return result.stdout.strip() or None if result.exit_code == 0 else None

    def health_check(self) -> HealthCheck:
        result = self.runner.run(["docker", "image", "inspect", self.scanner_config.image, "--format", "{{.Id}}"], timeout_seconds=20)
        if result.exit_code != 0:
            return HealthCheck("WARN", diagnostic=f"OpenGrep image unavailable: {self.scanner_config.image}")
        version = self.version()
        return HealthCheck("OK", version=version)

    def scan(self, workspace: PreparedWorkspace, raw_output_dir: Path) -> ScannerRunResult:
        started = time.monotonic()
        output_path = raw_output_dir / "opengrep.json"
        command = self._build_scan_command(workspace, output_path)
        result = self.runner.run(command, timeout_seconds=self.scanner_config.timeout_seconds)
        findings = []
        errors = []
        selected_rule_sources = self._selected_rule_sources(workspace)
        warnings = self._rule_source_warnings(selected_rule_sources)
        raw_finding_count = 0
        status = "SUCCESS"

        if output_path.exists():
            try:
                raw_finding_count = count_opengrep_results(output_path)
                findings = parse_opengrep_json(output_path)
                json_errors, json_warnings = parse_opengrep_diagnostics(output_path)
                errors.extend(json_errors)
                warnings.extend(json_warnings)
                for finding in findings:
                    if finding.file and finding.file.startswith("/src/"):
                        finding.file = finding.file.removeprefix("/src/")
            except Exception as exc:  # noqa: BLE001
                status = "ERROR"
                errors.append(f"OpenGrep parser failed: {exc}")
        if result.exit_code != 0:
            status = "ERROR" if not findings else "PARTIAL"
            errors.append(_clean_stderr(result.stderr) or f"OpenGrep exited with code {result.exit_code}")
        if result.timed_out:
            status = "ERROR"
            errors.append("OpenGrep timed out")

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

    def _build_scan_command(self, workspace: PreparedWorkspace, output_path: Path) -> list[str]:
        command = self._docker_prefix([
            "--mount", f"type=bind,src={workspace.scan_root},dst=/src,readonly",
            "--mount", f"type=bind,src={output_path.parent},dst=/out",
            "--workdir", "/src",
        ])
        rules_root = self.app_config.base_dir / "rules"
        if rules_root.exists():
            command.extend(["--mount", f"type=bind,src={rules_root},dst=/rules,readonly"])
        command.extend([self.scanner_config.image, "opengrep", "scan", "--json", "--output", "/out/opengrep.json"])
        for rule_path in self._selected_rule_sources(workspace):
            if rule_path.exists():
                command.extend(["-f", _container_rule_path(rule_path, rules_root)])
        for exclusion in self.app_config.scan.exclude:
            command.extend(["--exclude", exclusion])
        command.append(workspace.container_target)
        return command

    def _selected_rule_sources(self, workspace: PreparedWorkspace) -> list[Path]:
        if not self.scanner_config.auto_select_rule_sources:
            return self.scanner_config.config

        target_relative = workspace.container_target.removeprefix("/src/") if workspace.target_kind == "file" else None
        coverage = collect_scan_coverage(workspace.scan_root, self.app_config.scan.exclude, target_relative)
        selected_community_names = {"generic", "problem-based-packs"}
        for language in coverage.languages:
            selected_community_names.update(COMMUNITY_LANGUAGE_MAP.get(language, set()))
        if coverage.languages and selected_community_names == {"generic", "problem-based-packs"}:
            selected_community_names.update(_all_community_source_names(self.scanner_config.config))

        selected: list[Path] = []
        for path in self.scanner_config.config:
            source_name = _community_source_name(path)
            if source_name is None or source_name in selected_community_names:
                selected.append(path)
        return selected or self.scanner_config.config

    def _rule_source_warnings(self, selected_rule_sources: list[Path]) -> list[str]:
        missing = [str(path) for path in selected_rule_sources if not path.exists()]
        if not missing:
            return []
        warnings = ["Missing OpenGrep rule source(s): " + ", ".join(missing)]
        if len(missing) == len(selected_rule_sources):
            warnings.append("No OpenGrep rule sources are available; SAST coverage will be empty.")
        return warnings

    def _docker_prefix(self, extra: list[str]) -> list[str]:
        return [
            "docker", "run", "--rm",
            "--network", self.scanner_config.network,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "512",
            "--env", "HOME=/home/scanner",
            "--env", "XDG_CACHE_HOME=/home/scanner/.cache",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
            "--tmpfs", "/home/scanner/.cache:rw,exec,nosuid,size=512m",
            "--tmpfs", "/home/scanner/.opengrep:rw,noexec,nosuid,size=32m",
            *extra,
        ]


def _container_rule_path(rule_path: Path, rules_root: Path) -> str:
    try:
        return "/rules/" + rule_path.resolve().relative_to(rules_root.resolve()).as_posix()
    except ValueError:
        return str(rule_path)


def _community_source_name(path: Path) -> str | None:
    parts = path.parts
    for index, part in enumerate(parts):
        if part == "community" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _all_community_source_names(paths: list[Path]) -> set[str]:
    return {name for path in paths if (name := _community_source_name(path))}


def _clean_stderr(stderr: str) -> str:
    return "\n".join(line for line in stderr.splitlines() if "secret" not in line.lower())[:4000]
