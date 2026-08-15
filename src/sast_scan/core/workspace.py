from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sast_scan.core.exceptions import WorkspaceError
from sast_scan.utils.process import ProcessRunner


GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


@dataclass
class PreparedWorkspace:
    original_target: str
    scan_root: Path
    container_target: str
    target_kind: str
    temp_dir: Path | None = None

    def cleanup(self) -> None:
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)


class WorkspaceManager:
    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self.runner = runner or ProcessRunner()

    def prepare(self, target: str) -> PreparedWorkspace:
        if GITHUB_URL_RE.match(target):
            return self._prepare_github(target)

        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise WorkspaceError(f"Target does not exist: {target}")

        if path.is_file():
            return PreparedWorkspace(
                original_target=target,
                scan_root=path.parent,
                container_target=f"/src/{path.name}",
                target_kind="file",
            )
        if path.is_dir():
            return PreparedWorkspace(original_target=target, scan_root=path, container_target="/src", target_kind="directory")
        raise WorkspaceError(f"Unsupported target type: {target}")

    def _prepare_github(self, url: str) -> PreparedWorkspace:
        temp_dir = Path(tempfile.mkdtemp(prefix="sast-scan-repo-"))
        repo_dir = temp_dir / "repo"
        result = self.runner.run(["git", "clone", "--depth", "1", url, str(repo_dir)], timeout_seconds=180)
        if result.exit_code != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise WorkspaceError(f"Failed to clone {url}: {result.stderr.strip()}")
        return PreparedWorkspace(original_target=url, scan_root=repo_dir, container_target="/src", target_kind="github", temp_dir=temp_dir)
