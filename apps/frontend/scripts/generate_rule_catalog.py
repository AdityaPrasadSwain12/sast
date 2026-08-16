from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPOSITORY_ROOT / "configs" / "scanner.yaml"
OUTPUT_PATH = FRONTEND_ROOT / "public" / "rules-catalog.json"
INACTIVE_COMMUNITY_PACKS = ("ai", "ocaml")


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for item in value:
            result.extend(_list(item))
        return result
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item is not None]
    text = str(value).strip()
    return [text] if text else []


def _text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    if isinstance(value, str):
        return value.strip() or fallback
    return str(value).strip() or fallback


def _rule_revision() -> str | None:
    result = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT / "rules" / "opengrep" / "community"), "rev-parse", "HEAD"],
        capture_output=True,
        check=False,
        text=True,
    )
    revision = result.stdout.strip()
    return revision if result.returncode == 0 and revision else None


def _source_spec(source: str, *, enabled: bool) -> dict[str, Any]:
    path = (REPOSITORY_ROOT / source).resolve()
    if "rules/opengrep/custom" in source.replace("\\", "/"):
        source_kind = "custom"
        pack = "custom"
    else:
        source_kind = "community"
        parts = source.replace("\\", "/").split("/")
        pack = parts[3] if len(parts) > 3 else path.stem
    return {"path": path, "pack": pack, "source": source_kind, "enabled": enabled}


def _yaml_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted({*path.rglob("*.yaml"), *path.rglob("*.yml")})


def build_catalog() -> dict[str, Any]:
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) or {}
    opengrep = config.get("scanners", {}).get("opengrep", {})
    configured_sources = [_text(item) for item in opengrep.get("config", []) if _text(item)]
    source_specs = [_source_spec(source, enabled=True) for source in configured_sources]
    source_specs.extend(
        _source_spec(f"rules/opengrep/community/{pack}", enabled=False)
        for pack in INACTIVE_COMMUNITY_PACKS
    )

    missing_sources = [
        spec["path"].relative_to(REPOSITORY_ROOT).as_posix()
        for spec in source_specs
        if not spec["path"].exists()
    ]
    empty_sources = [
        spec["path"].relative_to(REPOSITORY_ROOT).as_posix()
        for spec in source_specs
        if spec["path"].exists() and not _yaml_files(spec["path"])
    ]
    if missing_sources or empty_sources:
        details = [*(f"missing: {source}" for source in missing_sources), *(f"no YAML rules: {source}" for source in empty_sources)]
        raise RuntimeError(
            "Rule catalogue generation requires every configured and bundled source. "
            "Initialize the community rules submodule before building:\n"
            + "\n".join(details)
        )

    records: list[dict[str, Any]] = []
    parsed_files: set[str] = set()
    enabled_files: set[str] = set()
    fixture_files: set[str] = set()
    excluded_fixture_rules = 0
    parse_errors: list[str] = []

    for spec in source_specs:
        for yaml_path in _yaml_files(spec["path"]):
            relative_path = yaml_path.relative_to(REPOSITORY_ROOT).as_posix()
            lower_name = yaml_path.name.lower()
            fixture_file = spec["enabled"] and (".test." in lower_name or ".fixed." in lower_name)
            try:
                documents = list(yaml.safe_load_all(yaml_path.read_text(encoding="utf-8")))
            except Exception as exc:  # noqa: BLE001
                parse_errors.append(f"{relative_path}: {exc}")
                continue

            file_had_rules = False
            for document_index, document in enumerate(documents):
                if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
                    continue
                for rule_index, rule in enumerate(document["rules"]):
                    if not isinstance(rule, dict) or not _text(rule.get("id")):
                        continue
                    if fixture_file:
                        excluded_fixture_rules += 1
                        fixture_files.add(relative_path)
                        continue
                    file_had_rules = True
                    metadata = rule.get("metadata") if isinstance(rule.get("metadata"), dict) else {}
                    rule_id = _text(rule.get("id"), "unnamed-rule")
                    message = _text(rule.get("message"), rule_id)
                    title = _text(metadata.get("name"), message)
                    if len(title) > 180:
                        title = title[:177].rstrip() + "…"
                    mode = _text(rule.get("mode"), "search").lower()
                    languages = sorted(set(_list(rule.get("languages")))) or ["generic"]
                    references = _list(metadata.get("references") or metadata.get("reference"))
                    remediation = _text(
                        rule.get("fix")
                        or metadata.get("fix")
                        or metadata.get("remediation")
                        or metadata.get("solution")
                    )
                    record: dict[str, Any] = {
                        "key": f"{relative_path}:{document_index}:{rule_index}",
                        "id": rule_id,
                        "title": title,
                        "description": _text(metadata.get("description"), message),
                        "severity": _text(rule.get("severity"), "UNKNOWN").upper(),
                        "languages": languages,
                        "category": _text(metadata.get("category"), "uncategorized"),
                        "mode": mode,
                        "cwe": _list(metadata.get("cwe")),
                        "owasp": _list(metadata.get("owasp")),
                        "pack": spec["pack"],
                        "source": spec["source"],
                        "path": relative_path,
                        "configured": spec["enabled"],
                    }
                    optional_text = {
                        "confidence": _text(metadata.get("confidence")),
                        "likelihood": _text(metadata.get("likelihood")),
                        "impact": _text(metadata.get("impact")),
                        "subcategory": ", ".join(_list(metadata.get("subcategory"))),
                        "remediation": remediation,
                    }
                    for key, value in optional_text.items():
                        if value:
                            record[key] = value
                    technologies = _list(metadata.get("technology") or metadata.get("technologies"))
                    if technologies:
                        record["technologies"] = technologies
                    if references:
                        record["references"] = references[:8]
                    records.append(record)

            if file_had_rules:
                parsed_files.add(relative_path)
                if spec["enabled"]:
                    enabled_files.add(relative_path)

    if parse_errors:
        raise RuntimeError("Rule catalogue generation failed:\n" + "\n".join(parse_errors))

    enabled_id_counts = Counter(record["id"] for record in records if record["configured"])
    all_id_counts = Counter(record["id"] for record in records)
    for record in records:
        record["duplicate_count"] = all_id_counts[record["id"]]

    records.sort(key=lambda item: (not item["configured"], item["pack"], item["id"], item["path"], item["key"]))
    enabled_records = [record for record in records if record["configured"]]
    inactive_records = [record for record in records if not record["configured"]]
    severity_counts = Counter(record["severity"] for record in enabled_records)
    mode_counts = Counter(record["mode"] for record in enabled_records)
    pack_counts = Counter(record["pack"] for record in enabled_records)

    trivy = config.get("scanners", {}).get("trivy", {})
    return {
        "schema_version": 1,
        "generated_from": CONFIG_PATH.relative_to(REPOSITORY_ROOT).as_posix(),
        "counting_method": "ID-bearing top-level rule entries, excluding *.test.* and *.fixed.* YAML fixtures",
        "config_sha256": hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest(),
        "rule_revision": _rule_revision(),
        "summary": {
            "configured_production_rules": len(enabled_records),
            "raw_configured_rule_entries": len(enabled_records) + excluded_fixture_rules,
            "excluded_fixture_rules": excluded_fixture_rules,
            "excluded_fixture_files": len(fixture_files),
            "inactive_bundled_rules": len(inactive_records),
            "configured_rule_files": len(enabled_files),
            "catalogued_rule_files": len(parsed_files),
            "configured_community_sources": sum("/community/" in source.replace("\\", "/") for source in configured_sources),
            "configured_custom_sources": sum("/custom/" in source.replace("\\", "/") for source in configured_sources),
            "duplicate_configured_rule_ids": sum(count > 1 for count in enabled_id_counts.values()),
            "severity_counts": dict(sorted(severity_counts.items())),
            "mode_counts": dict(sorted(mode_counts.items())),
            "pack_counts": dict(sorted(pack_counts.items())),
        },
        "configuration": {
            "auto_select_rule_sources": bool(opengrep.get("auto_select_rule_sources", False)),
            "policy_fail_on": _text(config.get("policy", {}).get("fail_on"), "HIGH").upper(),
            "opengrep_image": _text(opengrep.get("image")),
            "opengrep_timeout_seconds": opengrep.get("timeout_seconds"),
            "trivy_image": _text(trivy.get("image")),
            "trivy_timeout_seconds": trivy.get("timeout_seconds"),
            "trivy_scanners": _list(trivy.get("scanners")),
            "configured_sources": configured_sources,
            "inactive_bundled_packs": list(INACTIVE_COMMUNITY_PACKS),
        },
        "rules": records,
    }


def main() -> None:
    catalog = build_catalog()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(catalog, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    summary = catalog["summary"]
    print(
        f"Generated {OUTPUT_PATH.relative_to(REPOSITORY_ROOT)} with "
        f"{summary['configured_production_rules']} configured and {summary['inactive_bundled_rules']} inactive rules."
    )


if __name__ == "__main__":
    main()
