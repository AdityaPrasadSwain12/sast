import json

from sast_scan.parsers.opengrep_parser import count_opengrep_results, parse_opengrep_diagnostics, parse_opengrep_json


def test_parse_opengrep_json(tmp_path):
    payload = {
        "results": [{
            "check_id": "python.sql",
            "path": "app.py",
            "start": {"line": 10, "col": 5},
            "end": {"line": 10, "col": 30},
            "extra": {
                "message": "SQL injection",
                "severity": "ERROR",
                "fingerprint": "scanner-fp",
                "metadata": {"cwe": "CWE-89"},
            },
        }]
    }
    path = tmp_path / "opengrep.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_opengrep_json(path)
    assert findings[0].scanner == "OpenGrep"
    assert findings[0].category == "SAST"
    assert findings[0].cwe == ["CWE-89"]
    assert findings[0].raw_metadata["scanner_fingerprint"] == "scanner-fp"
    assert count_opengrep_results(path) == 1


def test_parse_opengrep_diagnostics(tmp_path):
    payload = {"results": [], "errors": [{"message": "bad rule"}], "skipped_rules": ["rule-a"]}
    path = tmp_path / "opengrep.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    errors, warnings = parse_opengrep_diagnostics(path)
    assert "bad rule" in errors[0]
    assert warnings == ["OpenGrep skipped rule: rule-a"]
