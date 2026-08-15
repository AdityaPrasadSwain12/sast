import json

from sast_scan.parsers.trivy_parser import count_trivy_results, parse_trivy_json


def test_parse_trivy_vulnerability_and_secret(tmp_path):
    payload = {
        "Results": [{
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-1234",
                "PkgName": "demo",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Severity": "CRITICAL",
                "Title": "demo vuln",
            }],
            "Secrets": [{
                "RuleID": "aws-access-key-id",
                "Severity": "HIGH",
                "StartLine": 4,
                "Match": "AKIA1234567890SECRET",
            }],
        }]
    }
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_trivy_json(path)
    assert len(findings) == 2
    assert findings[0].category == "SCA"
    assert findings[1].code_snippet == "[REDACTED]"
    assert "Match" not in findings[1].raw_metadata
    assert count_trivy_results(path) == 2
