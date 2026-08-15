from sast_scan.core.workspace import GITHUB_URL_RE, WorkspaceManager


def test_github_url_validation():
    assert GITHUB_URL_RE.match("https://github.com/example/project")
    assert not GITHUB_URL_RE.match("https://evil.example.com/example/project")


def test_prepare_file(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("print('hello')", encoding="utf-8")
    workspace = WorkspaceManager().prepare(str(target))
    assert workspace.target_kind == "file"
    assert workspace.container_target == "/src/app.py"
