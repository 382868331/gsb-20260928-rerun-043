"""Cross-table reference checks and repeated-export reconciliation.

Both checks operate on what an external analyst could observe (public CSVs),
plus private mapping metadata only when reporting subject-level diagnostics.
No hospital system is contacted.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .storage import Project, ProjectError, read_json


def _load_export_table(export_dir: Path, table: str) -> tuple[list[str], list[dict[str, str]]]:
    path = export_dir / f"{table}.csv"
    if not path.exists():
        raise ProjectError(f"export missing table file: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def load_manifest(export_dir: Path) -> dict[str, Any]:
    return read_json(export_dir / "manifest.json")


@dataclass
class ReferenceReport:
    subject_field: str
    tables: dict[str, int]
    subjects_per_table: dict[str, set[str]]
    orphan_tables: dict[str, list[str]]
    consistent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_field": self.subject_field,
            "rows_per_table": self.tables,
            "subjects_per_table": {k: len(v) for k, v in self.subjects_per_table.items()},
            "orphan_subject_ids": self.orphan_tables,
            "consistent": self.consistent,
        }


def check_cross_table_references(export_dir: Path | str) -> ReferenceReport:
    """Every pseudonym appearing in a child table must exist in the
    demographics/anchor table, and one subject keeps one pseudonym across all
    table kinds.
    """
    export_dir = Path(export_dir)
    manifest = load_manifest(export_dir)
    rule_tables = manifest["rules"]["tables"]
    anchor = None
    for name, tr in rule_tables.items():
        if tr["subject_field"] in {"subject_id", tr.get("subject_field")} and name == "demographics":
            anchor = name
    if anchor is None:
        anchor = sorted(rule_tables)[0]

    subjects: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    fields: dict[str, str] = {}
    for table, tr in rule_tables.items():
        sf = tr["subject_field"]
        _, rows = _load_export_table(export_dir, table)
        ids = {row[sf].strip() for row in rows if row.get(sf, "").strip()}
        if any("" == row.get(sf, "").strip() for row in rows):
            raise ProjectError(f"empty pseudonym found in exported table {table!r}")
        subjects[table] = ids
        counts[table] = len(rows)
        fields[table] = sf

    anchor_ids = subjects[anchor]
    orphans: dict[str, list[str]] = {}
    for table, ids in subjects.items():
        if table == anchor:
            continue
        extra = sorted(ids - anchor_ids)
        if extra:
            orphans[table] = extra
    return ReferenceReport(
        subject_field=fields[anchor],
        tables=counts,
        subjects_per_table=subjects,
        orphan_tables=orphans,
        consistent=not any(orphans.values()),
    )


@dataclass
class ReconcileReport:
    old_version: int
    new_version: int
    added_subjects: list[str]
    removed_subjects: list[str]
    common_subjects: int
    changed_files: list[str]
    identical: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_version": self.old_version,
            "new_version": self.new_version,
            "added_subject_count": len(self.added_subjects),
            "removed_subject_count": len(self.removed_subjects),
            "common_subject_count": self.common_subjects,
            "changed_files": self.changed_files,
            "identical": self.identical,
        }


def _pseudonym_sets(project: Project, batch_id: str) -> tuple[set[str], dict[int, set[str]]]:
    from .mapping import SubjectMapping

    mapping = SubjectMapping(project, batch_id)
    all_ids = set(mapping.pseudonyms().values())
    per_version: dict[int, set[str]] = {}
    for meta in project.list_versions(batch_id):
        version = meta["version"]
        export_dir = project.export_version_dir(batch_id, version)
        report = check_cross_table_references(export_dir)
        ids: set[str] = set()
        for table_ids in report.subjects_per_table.values():
            ids |= table_ids
        per_version[version] = ids
    return all_ids, per_version


def reconcile_exports(project: Project, batch_id: str, old: int, new: int) -> ReconcileReport:
    """Compare two immutable exports.

    Subjects shared by both versions must keep identical pseudonyms (this is
    structural: pseudonyms are HMAC-derived and persisted), and only true
    additions/removals are reported. File-by-file changes are listed as well.
    """
    old_dir = project.export_version_dir(batch_id, old)
    new_dir = project.export_version_dir(batch_id, new)
    if not old_dir.is_dir() or not new_dir.is_dir():
        raise ProjectError("both export versions must exist before reconciliation")
    old_report = check_cross_table_references(old_dir)
    new_report = check_cross_table_references(new_dir)
    old_ids: set[str] = set().union(*old_report.subjects_per_table.values())
    new_ids: set[str] = set().union(*new_report.subjects_per_table.values())

    changed = []
    files = {p.name for p in old_dir.iterdir() if p.is_file()}
    files |= {p.name for p in new_dir.iterdir() if p.is_file()}
    for name in sorted(files):
        op = old_dir / name
        np = new_dir / name
        if not op.exists() or not np.exists():
            if name != "manifest.json":
                changed.append(name)
        elif name != "manifest.json" and op.read_bytes() != np.read_bytes():
            changed.append(name)
    return ReconcileReport(
        old_version=old,
        new_version=new,
        added_subjects=sorted(new_ids - old_ids),
        removed_subjects=sorted(old_ids - new_ids),
        common_subjects=len(old_ids & new_ids),
        changed_files=changed,
        identical=not changed and not (new_ids ^ old_ids),
    )
