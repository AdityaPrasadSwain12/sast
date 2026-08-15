from sast_scan.utils.filesystem import collect_scan_coverage


def test_collect_scan_coverage_counts_files_and_lines(tmp_path):
    (tmp_path / "app.py").write_text("print('one')\nprint('two')\n", encoding="utf-8")
    excluded = tmp_path / "node_modules"
    excluded.mkdir()
    (excluded / "ignored.js").write_text("console.log('skip')\n", encoding="utf-8")

    coverage = collect_scan_coverage(tmp_path, ["node_modules"])

    assert coverage.files_scanned == 1
    assert coverage.lines_scanned == 2
    assert coverage.languages == {"Python": 1}
