from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path

from sast_scan import __version__
from sast_scan.core.config import load_config
from sast_scan.core.orchestrator import ScanOrchestrator
from sast_scan.engines.opengrep import OpenGrepScanner
from sast_scan.engines.trivy import TrivyScanner
from sast_scan.reporting.console import ConsoleReporter
from sast_scan.utils.process import ProcessRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sast-scan", description="Containerized OpenGrep + Trivy security scanner")
    parser.add_argument("--version", action="version", version=f"sast-scan {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a file, directory, local repository, or public GitHub URL")
    scan.add_argument("target")
    scan.add_argument("--config", default="configs/scanner.yaml")
    scan.add_argument("--output-dir", default=None)
    scan.add_argument("--output", action="append", choices=["console", "json", "html", "sarif"], dest="outputs")
    scan.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"])
    scan.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"], help="Minimum severity to include in reports")

    subparsers.add_parser("doctor", help="Check local scanner prerequisites")
    subparsers.add_parser("version", help="Show sast-scan version")
    return parser


def run_scan(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    if args.output_dir:
        config.report.output_dir = Path(args.output_dir).expanduser().resolve()
    if args.outputs:
        config.report.formats = args.outputs
    if args.fail_on:
        config.policy.fail_on = args.fail_on
    if args.severity:
        config.report.minimum_severity = args.severity

    orchestrator = ScanOrchestrator(config=config)
    report = orchestrator.scan(args.target)

    if "console" in config.report.formats:
        print(ConsoleReporter().render(report))

    if report.policy_failed:
        return 1
    if report.status == "ERROR":
        return 2
    return 0


def run_doctor() -> int:
    runner = ProcessRunner()
    checks: list[tuple[str, str, str, str]] = []
    checks.append(("Python", "OK", platform.python_version(), sys.executable))

    for name, command in [
        ("Docker CLI", ["docker", "--version"]),
        ("Docker daemon", ["docker", "info", "--format", "{{.ServerVersion}}"]),
        ("Git", ["git", "--version"]),
    ]:
        result = runner.run(command, timeout_seconds=20)
        status = "OK" if result.exit_code == 0 else "FAIL"
        version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        diagnostic = result.stderr.strip() if result.exit_code != 0 else ""
        checks.append((name, status, version, diagnostic))

    config = load_config(Path("configs/scanner.yaml"))
    existing_rule_sources = [path for path in config.opengrep.config if path.exists()]
    missing_rule_sources = [path for path in config.opengrep.config if not path.exists()]
    checks.append((
        "OpenGrep rules",
        "OK" if existing_rule_sources else "FAIL",
        f"{len(existing_rule_sources)} configured source(s) available",
        f"{len(missing_rule_sources)} missing source(s)" if missing_rule_sources else "",
    ))
    for scanner_name, image in [
        ("OpenGrep image", config.opengrep.image),
        ("Trivy image", config.trivy.image),
    ]:
        result = runner.run(["docker", "image", "inspect", image, "--format", "{{.Id}}"], timeout_seconds=20)
        status = "OK" if result.exit_code == 0 else "WARN"
        diagnostic = "" if status == "OK" else f"Image not present locally: {image}"
        if scanner_name == "OpenGrep image" and status != "OK":
            diagnostic += " (build with: docker build -t sast-scan/opengrep:latest .\\docker\\opengrep)"
        checks.append((scanner_name, status, image, diagnostic))

    for scanner in [OpenGrepScanner(config.opengrep, config), TrivyScanner(config.trivy, config)]:
        health = scanner.health_check()
        checks.append((f"{scanner.name()} runtime", health.status, health.version or "", health.diagnostic or ""))

    print("SAST-SCAN DOCTOR")
    print("=" * 60)
    for component, status, version, diagnostic in checks:
        print(f"{component:18} {status:5} {version}")
        if diagnostic:
            print(f"{'':18}       {diagnostic}")
    return 0 if all(status in {"OK", "WARN"} for _, status, _, _ in checks) else 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "doctor":
        return run_doctor()
    if args.command == "version":
        print(f"sast-scan {__version__}")
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
