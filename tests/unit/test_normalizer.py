from sast_scan.models.finding import Finding
from sast_scan.normalization.normalizer import normalize_findings


def test_normalizes_opengrep_error_to_high():
    finding = Finding(finding_id="", scanner="OpenGrep", category="SAST", severity="ERROR").finalize()
    assert normalize_findings([finding])[0].severity == "HIGH"
