from __future__ import annotations

import json
from pathlib import Path

from sast_scan.models.scan import ScanReport


class JsonReporter:
    def write(self, report: ScanReport, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(report.to_dict(), handle, indent=2, sort_keys=True)
