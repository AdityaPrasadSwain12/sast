from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class OpenGrepConfig:
    enabled: bool = True
    image: str = "sast-scan/opengrep:latest"
    config: list[Path] = field(default_factory=lambda: [
        Path("rules/opengrep/community/apex"),
        Path("rules/opengrep/community/bash"),
        Path("rules/opengrep/community/c"),
        Path("rules/opengrep/community/clojure"),
        Path("rules/opengrep/community/csharp"),
        Path("rules/opengrep/community/dockerfile"),
        Path("rules/opengrep/community/elixir"),
        Path("rules/opengrep/community/generic"),
        Path("rules/opengrep/community/go"),
        Path("rules/opengrep/community/html"),
        Path("rules/opengrep/community/java"),
        Path("rules/opengrep/community/javascript"),
        Path("rules/opengrep/community/json"),
        Path("rules/opengrep/community/kotlin"),
        Path("rules/opengrep/community/php"),
        Path("rules/opengrep/community/python"),
        Path("rules/opengrep/community/ruby"),
        Path("rules/opengrep/community/rust"),
        Path("rules/opengrep/community/scala"),
        Path("rules/opengrep/community/solidity"),
        Path("rules/opengrep/community/swift"),
        Path("rules/opengrep/community/terraform"),
        Path("rules/opengrep/community/typescript"),
        Path("rules/opengrep/community/yaml"),
        Path("rules/opengrep/community/problem-based-packs"),
        Path("rules/opengrep/custom/security.yaml"),
    ])
    timeout_seconds: int = 900
    network: str = "none"
    auto_select_rule_sources: bool = True


@dataclass
class TrivyConfig:
    enabled: bool = True
    image: str = "aquasec/trivy:latest"
    scanners: list[str] = field(default_factory=lambda: ["vuln", "secret", "misconfig"])
    timeout_seconds: int = 600
    network: str = "bridge"
    skip_db_update: bool = False


@dataclass
class ScanConfig:
    timeout_seconds: int = 600
    exclude: list[str] = field(default_factory=lambda: [".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target"])


@dataclass
class PolicyConfig:
    fail_on: str = "HIGH"


@dataclass
class ReportConfig:
    formats: list[str] = field(default_factory=lambda: ["console", "json", "html", "sarif"])
    output_dir: Path = Path("reports")
    minimum_severity: str | None = None


@dataclass
class AppConfig:
    base_dir: Path
    opengrep: OpenGrepConfig = field(default_factory=OpenGrepConfig)
    trivy: TrivyConfig = field(default_factory=TrivyConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


def _resolve_config_paths(paths: list[str], base_dir: Path) -> list[Path]:
    resolved: list[Path] = []
    for raw in paths:
        path = Path(raw)
        resolved.append(path if path.is_absolute() else (base_dir / path).resolve())
    return resolved


DEFAULT_OPENGREP_CONFIG = [str(path) for path in OpenGrepConfig().config]


def load_config(path: Path) -> AppConfig:
    config_path = path.resolve()
    base_dir = config_path.parent.parent if config_path.parent.name == "configs" else config_path.parent
    data: dict[str, Any] = {}
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}

    scanners = data.get("scanners", {})
    opengrep_data = scanners.get("opengrep", {})
    trivy_data = scanners.get("trivy", {})
    scan_data = data.get("scan", {})
    policy_data = data.get("policy", {})
    report_data = data.get("report", {})

    return AppConfig(
        base_dir=base_dir,
        opengrep=OpenGrepConfig(
            enabled=bool(opengrep_data.get("enabled", True)),
            image=str(opengrep_data.get("image", "sast-scan/opengrep:latest")),
            config=_resolve_config_paths(opengrep_data.get("config", DEFAULT_OPENGREP_CONFIG), base_dir),
            timeout_seconds=int(opengrep_data.get("timeout_seconds", 900)),
            network=str(opengrep_data.get("network", "none")),
            auto_select_rule_sources=bool(opengrep_data.get("auto_select_rule_sources", True)),
        ),
        trivy=TrivyConfig(
            enabled=bool(trivy_data.get("enabled", True)),
            image=str(trivy_data.get("image", "aquasec/trivy:latest")),
            scanners=list(trivy_data.get("scanners", ["vuln", "secret", "misconfig"])),
            timeout_seconds=int(trivy_data.get("timeout_seconds", 600)),
            network=str(trivy_data.get("network", "bridge")),
            skip_db_update=bool(trivy_data.get("skip_db_update", False)),
        ),
        scan=ScanConfig(
            timeout_seconds=int(scan_data.get("timeout_seconds", 600)),
            exclude=list(scan_data.get("exclude", [".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "target"])),
        ),
        policy=PolicyConfig(fail_on=str(policy_data.get("fail_on", "HIGH")).upper()),
        report=ReportConfig(
            formats=list(report_data.get("formats", ["console", "json", "html", "sarif"])),
            output_dir=(base_dir / report_data.get("output_dir", "reports")).resolve(),
        ),
    )
