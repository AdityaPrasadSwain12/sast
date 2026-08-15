from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from sast_scan.core.workspace import PreparedWorkspace
from sast_scan.models.scan import ScannerRunResult


@dataclass
class HealthCheck:
    status: str
    version: str | None = None
    diagnostic: str | None = None


class BaseScanner(Protocol):
    def name(self) -> str:
        ...

    def version(self) -> str | None:
        ...

    def health_check(self) -> HealthCheck:
        ...

    def scan(self, workspace: PreparedWorkspace, raw_output_dir: Path) -> ScannerRunResult:
        ...
