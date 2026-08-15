from sast_scan.correlation.deduplicator import correlate_findings
from sast_scan.models.finding import Finding


def test_correlates_same_cve_package():
    first = Finding(finding_id="a", scanner="Trivy", category="SCA", package="flask", cve="CVE-1", title="one").finalize()
    second = Finding(finding_id="b", scanner="Trivy", category="SCA", package="flask", cve="CVE-1", title="two").finalize()
    correlated = correlate_findings([first, second])
    assert correlated[0].related_finding_ids == ["b"]
    assert correlated[1].related_finding_ids == ["a"]
