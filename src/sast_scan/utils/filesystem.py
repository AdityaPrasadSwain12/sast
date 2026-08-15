from __future__ import annotations

import fnmatch
from pathlib import Path

from sast_scan.models.scan import ScanCoverage


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".cc": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".rs": "Rust",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".scala": "Scala",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".toml": "TOML",
    ".xml": "XML",
    ".tf": "Terraform",
    ".dockerfile": "Dockerfile",
    ".sql": "SQL",
    ".sh": "Shell",
    ".ps1": "PowerShell",
}


SPECIAL_FILENAMES = {
    "Dockerfile": "Dockerfile",
    "requirements.txt": "Python Dependencies",
    "package.json": "Node Dependencies",
    "package-lock.json": "Node Dependencies",
    "pom.xml": "Java Dependencies",
    "build.gradle": "Java Dependencies",
    "go.mod": "Go Dependencies",
    "Cargo.toml": "Rust Dependencies",
}


def collect_scan_coverage(root: Path, exclusions: list[str], target_relative: str | None = None) -> ScanCoverage:
    files = _iter_candidate_files(root, exclusions, target_relative)
    coverage = ScanCoverage(excluded_patterns=exclusions)
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        coverage.files_scanned += 1
        coverage.bytes_scanned += stat.st_size

        extension = path.suffix.lower() or path.name
        coverage.extensions[extension] = coverage.extensions.get(extension, 0) + 1
        language = _language_for(path)
        coverage.languages[language] = coverage.languages.get(language, 0) + 1

        line_count = _count_text_lines(path)
        if line_count is None:
            coverage.binary_files_skipped_for_line_count += 1
        else:
            coverage.lines_scanned += line_count
    coverage.extensions = dict(sorted(coverage.extensions.items()))
    coverage.languages = dict(sorted(coverage.languages.items()))
    return coverage


def _iter_candidate_files(root: Path, exclusions: list[str], target_relative: str | None) -> list[Path]:
    if target_relative:
        path = root / target_relative
        return [path] if path.is_file() and not _is_excluded(path.relative_to(root), exclusions) else []

    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if _is_excluded(relative, exclusions):
            continue
        candidates.append(path)
    return candidates


def _is_excluded(relative: Path, exclusions: list[str]) -> bool:
    relative_posix = relative.as_posix()
    parts = set(relative.parts)
    for pattern in exclusions:
        normalized = pattern.replace("\\", "/")
        if normalized in parts or fnmatch.fnmatch(relative_posix, normalized) or fnmatch.fnmatch(relative_posix, f"{normalized}/**"):
            return True
    return False


def _count_text_lines(path: Path) -> int | None:
    try:
        chunk = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in chunk[:4096]:
        return None
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = chunk.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _language_for(path: Path) -> str:
    if path.name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[path.name]
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "Other")
