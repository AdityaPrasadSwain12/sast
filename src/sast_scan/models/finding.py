from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    finding_id: str
    scanner: str
    category: str
    rule_id: str | None = None
    title: str = "Untitled finding"
    description: str | None = None
    severity: str = "UNKNOWN"
    original_severity: str | None = None
    confidence: str | None = None
    status: str = "OPEN"
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    code_snippet: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve: str | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cvss: float | None = None
    secret_type: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    related_finding_ids: list[str] = field(default_factory=list)
    original_category: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "Finding":
        if not self.fingerprint:
            identity = {
                "scanner": self.scanner,
                "category": self.category,
                "rule_id": self.rule_id,
                "file": self.file,
                "line_start": self.line_start,
                "package": self.package,
                "cve": self.cve,
                "title": self.title.lower().strip(),
            }
            self.fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()[:24]
        if not self.finding_id:
            self.finding_id = f"{self.scanner.lower()}-{self.fingerprint}"
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
