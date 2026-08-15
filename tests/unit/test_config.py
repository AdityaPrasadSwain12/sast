from pathlib import Path

from sast_scan.core.config import load_config


def test_load_default_config():
    config = load_config(Path("configs/scanner.yaml"))
    assert config.opengrep.enabled
    assert "vuln" in config.trivy.scanners
    assert config.policy.fail_on == "HIGH"
