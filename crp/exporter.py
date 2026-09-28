"""Batch/rule management and immutable, versioned de-identified export.

Offline only: source data is imported from local CSV files. The platform does
not connect to any hospital system.
"""

from __future__ import annotations

import csv
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .deid import (
    TextScrubber,
    read_csv,
    scrubbing_stats,
    transform_table,
)
from .mapping import SubjectMapping
from .rules import RuleSet
from .storage import Project, ProjectError, read_json, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_batch(project: Project, batch_id: str, title: str, description: str = "") -> dict[str, Any]:
    if project.batch_path(batch_id).exists():
        raise ProjectError(f"batch already exists: {batch_id}")
    safe = batch_id.strip()
    if not safe or not all(c.isalnum() or c in "_-" for c in safe):
        raise ProjectError("batch id may contain only letters, digits, '_' and '-'")
    batch = {
        "id": safe,
        "title": title,
        "description": description,
        "created_at": _now(),
        "rule_version": 0,
        "current_rules": None,
        "tables": {},
        "latest_version": 0,
        "version_notes": [],
    }
    project.save_batch(batch)
    return batch


def put_rules(project: Project, batch_id: str, rules_payload: dict[str, Any]) -> int:
    """Validate and store a new current rule set.

    Rules are versioned independently of exports; every export keeps a copy of
    the exact rule version used, so old version explanations remain intact.
    """
    batch = project.load_batch(batch_id)
    rules = RuleSet.from_dict(rules_payload)  # validation only
    new_version = int(batch["rule_version"]) + 1
    path = project.private / "rules" / batch_id / f"rules-v{new_version:06d}.json"
    write_json(path, rules.to_dict())
    batch["rule_version"] = new_version
    batch["current_rules"] = str(path.relative_to(project.private))
    project.save_batch(batch)
    return new_version


def load_current_rules(project: Project, batch_id: str) -> RuleSet:
    batch = project.load_batch(batch_id)
    if not batch.get("current_rules"):
        raise ProjectError(f"no field rules defined for batch {batch_id!r}")
    path = project.private / batch["current_rules"]
    return RuleSet.from_dict(read_json(path))


def import_table(project: Project, batch_id: str, table: str, csv_path: str | Path) -> dict[str, Any]:
    project.load_batch(batch_id)
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise ProjectError(f"source file not found: {csv_path}")
    headers, rows = read_csv(csv_path)
    target_dir = project.raw_dir(batch_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{table}.csv"
    shutil.copyfile(csv_path, target)
    target.chmod(0o600)
    batch = project.load_batch(batch_id)
    batch["tables"][table] = {
        "file": str(target.relative_to(project.private)),
        "rows": len(rows),
        "columns": len(headers),
        "imported_at": _now(),
    }
    project.save_batch(batch)
    return {"table": table, "rows": len(rows), "columns": len(headers)}


def _write_public_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    path.chmod(0o644)


def _scan_public_leaks(export_dir: Path, raw_ids: list[str], terms: list[str]) -> list[str]:
    """Final safety scan: raw subject ids and sensitive phrases must never
    appear byte-for-byte in any public file."""
    leaks: list[str] = []
    needles = sorted(set(raw_ids + [t for t in terms if len(t) >= 2]), key=len, reverse=True)
    for path in sorted(export_dir.rglob("*")):
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        for needle in needles:
            if needle and needle in content:
                leaks.append(f"{path.relative_to(export_dir)} contains private value {needle!r}")
    return leaks


def run_export(project: Project, batch_id: str, note: str) -> dict[str, Any]:
    batch = project.load_batch(batch_id)
    rules = load_current_rules(project, batch_id)
    rule_version = int(batch["rule_version"])
    version = int(batch.get("latest_version", 0)) + 1
    out_dir = project.export_version_dir(batch_id, version)
    if out_dir.exists():
        raise ProjectError(f"export version already exists: {out_dir}")
    out_dir.mkdir(parents=True)

    mapping = SubjectMapping(project, batch_id)
    scrubber = TextScrubber(rules.sensitive_terms)
    table_stats: dict[str, Any] = {}

    if set(rules.tables) != set(batch["tables"]):
        raise ProjectError(
            "rules and imported tables differ: "
            f"rules={sorted(rules.tables)} imported={sorted(batch['tables'])}"
        )

    for table, rule in sorted(rules.tables.items()):
        raw_path = project.private / batch["tables"][table]["file"]
        headers, rows = read_csv(raw_path)
        rules.check_headers(table, headers)
        result = transform_table(table, rule, rows, headers, mapping, scrubber)
        _write_public_csv(out_dir / f"{table}.csv", result.headers, result.rows)
        table_stats[table] = {
            "rows": result.rows_out,
            "columns_in": len(headers),
            "columns_out": len(result.headers),
            "dropped_columns": result.dropped_columns,
            "unparseable_dates": result.bad_dates,
        }

    mapping.save()

    stats = scrubbing_stats(scrubber)
    leaks = _scan_public_leaks(out_dir, mapping.raw_ids(), rules.sensitive_terms)
    if leaks:
        raise ProjectError("refusing export: private values detected in public output: " + "; ".join(leaks[:5]))

    manifest = {
        "batch_id": batch_id,
        "version": version,
        "created_at": _now(),
        "note": note,
        "rule_version": rule_version,
        "rules": rules.public_snapshot(),
        "tables": table_stats,
        "text_scrubbing": {
            "listed_term_hit_count": stats["listed_term_total"],
            "pattern_hit_count": stats["pattern_total"],
            "pattern_hits": stats["pattern_hits"],
        },
        "subject_count": len(mapping.raw_ids()),
        "private_mapping": "stored only in .crp-private/mappings/ and never exported",
    }
    write_json(out_dir / "manifest.json", manifest, mode=0o644)

    # Private metadata retains the full explanation and exact rule snapshot.
    private_meta = {
        "batch_id": batch_id,
        "version": version,
        "created_at": manifest["created_at"],
        "note": note,
        "rule_version": rule_version,
        "rule_snapshot": str(
            project.rule_snapshot_path(batch_id, rule_version).relative_to(project.private)
        ),
        "export_dir": str(out_dir.relative_to(project.root)),
        "tables": table_stats,
        "text_scrubbing": stats,
    }
    meta_path = project.version_meta_path(batch_id, version)
    write_json(meta_path, private_meta)

    batch["latest_version"] = version
    batch["version_notes"].append({"version": version, "note": note, "created_at": manifest["created_at"]})
    project.save_batch(batch)
    return manifest
