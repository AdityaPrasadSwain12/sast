from sast_scan.correlation.risk import apply_policy
from sast_scan.models.finding import Finding


def test_policy_fails_on_threshold():
    finding = Finding(finding_id="", scanner="Trivy", category="SCA", severity="HIGH").finalize()
    assert apply_policy([finding], "HIGH")
    assert not apply_policy([finding], "CRITICAL")
