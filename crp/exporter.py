"""去标识导出与不可变导出版本管理。

导出内容只包含去标识后的 CSV 与 manifest.json；伪名/日期偏移映射保存在独立的
private/ 目录，绝不写入版本目录。每次导出都会做泄露自检。规则或数据未变时重复导出幂等，
字段规则更新后生成新版本，旧版本及其说明原样保留。

溯源口径：一次导出的执行身份由"真正生效的字段规则"与"真正生效的原始输入"共同决定。
只有两者指纹都与某既有版本一致时，才允许复用该版本；规则变更即使对当前数据没有产生任何
字节差异，也必须形成新的独立版本，manifest 中同时记录规则/输入/输出指纹。两次导出之间
可用 :func:`compare_exports` 区分规则变化、数据变化与最终内容变化。
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crp.audit import scan_leaks
from crp.batch import Batch, BatchStore
from crp.dates import shift_date
from crp.paths import Store
from crp.pseudonym import SubjectMapping
from crp.redact import Redactor
from crp.rules import FieldRule
from crp.util import fingerprint, read_csv, read_json, sha256_file, write_csv, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class TableExport:
    table: str
    fieldnames: list[str]
    rows: list[dict[str, str]]


@dataclass(frozen=True)
class ExportResult:
    batch_id: str
    version: int
    version_dir: Path
    reused: bool
    rules_version: int
    note: str
    content_reused_from: int | None = None


@dataclass(frozen=True)
class ExportComparison:
    batch_id: str
    left_version: int
    right_version: int
    left_rules_version: int
    right_rules_version: int
    rules_changed: bool
    source_changed: bool
    output_changed: bool
    table_changes: dict[str, str]

    def describe(self) -> str:
        reasons: list[str] = []
        if self.rules_changed:
            reasons.append(
                f"规则变化（v{self.left_rules_version} -> v{self.right_rules_version}）"
            )
        if self.source_changed:
            reasons.append("原始数据变化")
        if not reasons:
            reasons.append("规则与输入均未变化")
        content = "最终内容变化" if self.output_changed else "最终内容字节相同"
        return "；".join(reasons) + "；" + content


class Exporter:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.batches = BatchStore(store)

    def _rule_map(self, batch: Batch) -> dict[str, dict[str, FieldRule]]:
        return {table: {rule.field: rule for rule in rules} for table, rules in batch.rules.items()}

    def transform(self, batch: Batch) -> list[TableExport]:
        mapping = SubjectMapping.load_or_create(self.store, batch.batch_id)
        raw_rows: dict[str, list[dict[str, str]]] = {}
        all_subjects: set[str] = set()
        for table in batch.tables:
            rows = read_csv(self.store.raw_dir(batch.batch_id) / f"{table}.csv")
            raw_rows[table] = rows
            for row in rows:
                sid = row.get(batch.subject_field, "").strip()
                if sid:
                    all_subjects.add(sid)
        for sid in sorted(all_subjects):
            mapping.register(sid)
        mapping.save(self.store)

        redactor = Redactor.from_batch(self.store.raw_dir(batch.batch_id))
        rule_map = self._rule_map(batch)
        exports: list[TableExport] = []
        for table in batch.tables:
            rows = raw_rows[table]
            with (self.store.raw_dir(batch.batch_id) / f"{table}.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as fh:
                columns = next(csv.reader(fh))
            table_rules = rule_map.get(table, {})
            for name in table_rules:
                if name not in columns:
                    raise ValueError(f"表 {table} 的规则字段不存在: {name}")
            if batch.subject_field not in columns:
                raise ValueError(f"表 {table} 缺少受试者关联列 {batch.subject_field}")
            subject_rule = table_rules.get(batch.subject_field)
            if subject_rule is not None and subject_rule.action == "drop":
                raise ValueError(f"受试者关联列 {batch.subject_field} 不能删除，否则跨表关联会丢失")
            output_columns = [
                column for column in columns
                if (rule := table_rules.get(column)) is None or rule.action != "drop"
            ]
            out_rows: list[dict[str, str]] = []
            for row in rows:
                real_sid = row[batch.subject_field].strip()
                pseudo_sid, offset_days = mapping.register(real_sid)
                out: dict[str, str] = {}
                for column in output_columns:
                    value = row.get(column, "")
                    if column == batch.subject_field:
                        out[column] = pseudo_sid
                        continue
                    rule = table_rules.get(column)
                    if rule is None or rule.action == "keep":
                        out[column] = value
                    elif rule.action == "date_shift":
                        out[column] = shift_date(value, offset_days)
                    elif rule.action == "redact_text":
                        out[column] = redactor.redact(value, real_sid)
                    else:
                        raise AssertionError(rule.action)
                out_rows.append(out)
            exports.append(TableExport(table=table, fieldnames=output_columns, rows=out_rows))
        return exports

    def calculate_fingerprints(self, batch: Batch, tables: list[TableExport]) -> tuple[str, str, str]:
        raw_parts: list[tuple[str, str]] = []
        out_parts: list[tuple[str, str]] = []
        for table in batch.tables:
            raw_path = self.store.raw_dir(batch.batch_id) / f"{table}.csv"
            raw_parts.append((table, raw_path.read_text(encoding="utf-8-sig")))
        for exported in tables:
            lines = [",".join(exported.fieldnames)]
            for row in exported.rows:
                lines.append(",".join(row.get(name, "") for name in exported.fieldnames))
            out_parts.append((exported.table, chr(10).join(lines) + chr(10)))
        rules_canonical = read_json(self.store.batch_file(batch.batch_id))["history"][-1]["rules_hash"]
        return rules_canonical, fingerprint(raw_parts), fingerprint(out_parts)

    def export_batch(self, batch_id: str, note: str = "") -> ExportResult:
        batch = self.batches.load(batch_id)
        tables = self.transform(batch)
        rules_fp, source_fp, output_fp = self.calculate_fingerprints(batch, tables)
        index = self._load_index(batch_id)
        for entry in index["versions"]:
            # 幂等复用要求规则与输入都完全一致。只看输出字节会在"规则变了但恰好不影响
            # 当前数据"时把新执行错误地并入旧版本，造成规则版本溯源错配。
            if (
                entry["rules_fingerprint"] == rules_fp
                and entry["source_fingerprint"] == source_fp
                and entry["output_fingerprint"] == output_fp
            ):
                version = int(entry["version"])
                version_dir = self.store.version_dir(batch_id, version)
                self._verify_checksums(version_dir, entry["files"])
                return ExportResult(batch_id, version, version_dir, True,
                                    int(entry["rules_version"]), entry["note"])

        content_source = next(
            (
                int(entry["version"])
                for entry in index["versions"]
                if entry["output_fingerprint"] == output_fp
            ),
            None,
        )
        version = int(index.get("latest", 0)) + 1
        version_dir = self.store.version_dir(batch_id, version)
        version_dir.mkdir(parents=True, exist_ok=False)
        files: dict[str, str] = {}
        for exported in tables:
            target = version_dir / f"{exported.table}.csv"
            write_csv(target, exported.rows, exported.fieldnames)
            files[f"{exported.table}.csv"] = sha256_file(target)
        manifest = {
            "batch_id": batch_id,
            "version": version,
            "created_at": _now(),
            "rules_version": batch.rules_version,
            "note": note or f"字段规则 v{batch.rules_version} 导出",
            "subject_field": batch.subject_field,
            "tables": batch.tables,
            "rules_fingerprint": rules_fp,
            "source_fingerprint": source_fp,
            "output_fingerprint": output_fp,
            # 输出字节可能与旧版本完全相同，但执行身份（规则/输入）不同；
            # 仅记录内容可复用的来源，绝不与该版本合并。
            "content_derived_from": content_source,
            "files": dict(sorted(files.items())),
        }
        write_json(version_dir / "manifest.json", manifest)
        final_files = {
            name: sha256_file(version_dir / name)
            for name in sorted(list(files) + ["manifest.json"])
        }
        entry = {
            "version": version,
            "created_at": manifest["created_at"],
            "rules_version": batch.rules_version,
            "rules_fingerprint": rules_fp,
            "source_fingerprint": source_fp,
            "output_fingerprint": output_fp,
            "content_derived_from": content_source,
            "note": manifest["note"],
            "dir": version_dir.name,
            "files": final_files,
        }
        index["batch_id"] = batch_id
        index["latest"] = version
        index["versions"].append(entry)
        write_json(self.store.export_index(batch_id), index)
        findings = scan_leaks(self.store, batch_id, version)
        if findings:
            raise RuntimeError("导出结果泄露自检失败: " + "; ".join(findings))
        return ExportResult(
            batch_id, version, version_dir, False, batch.rules_version,
            manifest["note"], content_reused_from=content_source,
        )

    def compare_exports(
        self, batch_id: str, left_version: int, right_version: int
    ) -> ExportComparison:
        """比较两次导出，区分规则变化、数据变化和最终内容变化。

        - ``rules_changed``：两次导出生效的字段规则指纹不同（含规则版本变化）；
        - ``source_changed``：两次导出消费的原始输入指纹不同（数据增删改）；
        - ``output_changed``：公开输出指纹不同；规则/数据变化都可能因实际无影响而为否；
        - ``table_changes``：逐表给出 added / removed / changed / unchanged。
        """

        def manifest_of(version: int) -> dict[str, Any]:
            path = self.store.version_dir(batch_id, version) / "manifest.json"
            if not path.exists():
                raise FileNotFoundError(f"导出版本不存在: {path}")
            return read_json(path)

        left = manifest_of(left_version)
        right = manifest_of(right_version)
        left_tables = set(left["tables"])
        right_tables = set(right["tables"])
        left_files = left.get("files", {})
        right_files = right.get("files", {})
        table_changes: dict[str, str] = {}
        for name in sorted(left_tables | right_tables):
            if name not in right_tables:
                table_changes[name] = "removed"
            elif name not in left_tables:
                table_changes[name] = "added"
            elif left_files.get(f"{name}.csv") != right_files.get(f"{name}.csv"):
                table_changes[name] = "changed"
            else:
                table_changes[name] = "unchanged"
        return ExportComparison(
            batch_id=batch_id,
            left_version=left_version,
            right_version=right_version,
            left_rules_version=int(left["rules_version"]),
            right_rules_version=int(right["rules_version"]),
            rules_changed=left["rules_fingerprint"] != right["rules_fingerprint"],
            source_changed=left["source_fingerprint"] != right["source_fingerprint"],
            output_changed=left["output_fingerprint"] != right["output_fingerprint"],
            table_changes=table_changes,
        )

    def _load_index(self, batch_id: str) -> dict[str, Any]:
        path = self.store.export_index(batch_id)
        if path.exists():
            return read_json(path)
        return {"batch_id": batch_id, "latest": 0, "versions": []}

    def _verify_checksums(self, version_dir: Path, files: dict[str, str]) -> None:
        for name, expected in files.items():
            actual = sha256_file(version_dir / name)
            if actual != expected:
                raise RuntimeError(f"重复导出核对失败，已发布版本被改动: {version_dir / name}")
