"""去标识导出与不可变导出版本管理。

导出内容只包含去标识后的 CSV 与 manifest.json；伪名/日期偏移映射保存在独立的
private/ 目录，绝不写入版本目录。每次导出都会做泄露自检。

复用规则（区分执行身份与文件内容）：
- 规则指纹与输入指纹都未变时，重复导出幂等：复用同一执行版本并做字节级核对；
- 规则或输入任一变化都会产生**新的执行身份**（新版本目录、新 manifest、新版本说明），
  即使去标识后的最终字节恰好与某个旧版本完全一致，也不得合并为旧版本；
  此时通过 ``content_reused_from`` 记录内容与哪一版字节相同，溯源仍指向本次真正生效的
  规则与输入；
- ``compare_versions`` 比较两次导出，分别报告规则变化、输入数据变化与最终内容变化。

旧版本目录及其说明永不覆盖。
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crp.audit import scan_leaks
from crp.batch import Batch, BatchStore, RuleRevision, revision_plan
from crp.dates import shift_date
from crp.paths import Store
from crp.pseudonym import SubjectMapping
from crp.redact import Redactor
from crp.rules import FieldRule
from crp.scope import Scope, record_key
from crp.util import fingerprint, read_csv, read_json, sha256_file, write_csv, write_json
from crp.util import stable_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class TableExport:
    table: str
    fieldnames: list[str]
    rows: list[dict[str, str]]


@dataclass(frozen=True)
class RecordBasis:
    """公开溯源：一条原始记录本次导出采用了哪次规则决定、为何采用。"""

    table: str
    record_key: str
    subject_pseudonym: str
    rules_version: int
    revision_note: str
    matched_by: str
    scope: dict[str, Any]
    actions: dict[str, str]
    date_shift_fields: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "record_key": self.record_key,
            "subject_id": self.subject_pseudonym,
            "rules_version": self.rules_version,
            "revision_note": self.revision_note,
            "matched_by": self.matched_by,
            "scope": self.scope,
            "actions": dict(sorted(self.actions.items())),
            "date_shift_fields": list(self.date_shift_fields),
        }


@dataclass(frozen=True)
class ScopePreviewRow:
    table: str
    record_key: str
    subject_id: str
    rules_version: int
    matched: bool
    matched_by: str
    revision_note: str


def _public_scope(scope: Scope) -> dict[str, Any]:
    """公开溯源中的范围描述：明确集合只给数量，不暴露真实记录键。"""
    payload = scope.to_dict()
    records = payload.get("records")
    if records:
        payload["records"] = {
            table: {"count": len(keys)} for table, keys in sorted(records.items())
        }
    return payload


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
class VersionComparison:
    """两次导出之间的影响比较，三类变化互不混淆。"""

    batch_id: str
    from_version: int
    to_version: int
    rules_changed: bool
    scope_changed: bool
    source_changed: bool
    output_changed: bool
    rules_config_equal: bool
    output_equal: bool
    same_execution: bool
    rules_version_from: int
    rules_version_to: int
    rules_fingerprint_from: str
    rules_fingerprint_to: str
    scope_fingerprint_from: str
    scope_fingerprint_to: str
    source_fingerprint_from: str
    source_fingerprint_to: str
    output_fingerprint_from: str
    output_fingerprint_to: str
    added_files: tuple[str, ...]
    removed_files: tuple[str, ...]
    changed_files: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "rules_changed": self.rules_changed,
            "scope_changed": self.scope_changed,
            "source_changed": self.source_changed,
            "output_changed": self.output_changed,
            "rules_config_equal": self.rules_config_equal,
            "output_equal": self.output_equal,
            "same_execution": self.same_execution,
            "rules_version": {"from": self.rules_version_from, "to": self.rules_version_to},
            "rules_fingerprint": {
                "from": self.rules_fingerprint_from,
                "to": self.rules_fingerprint_to,
            },
            "scope_fingerprint": {
                "from": self.scope_fingerprint_from,
                "to": self.scope_fingerprint_to,
            },
            "source_fingerprint": {
                "from": self.source_fingerprint_from,
                "to": self.source_fingerprint_to,
            },
            "output_fingerprint": {
                "from": self.output_fingerprint_from,
                "to": self.output_fingerprint_to,
            },
            "added_files": list(self.added_files),
            "removed_files": list(self.removed_files),
            "changed_files": list(self.changed_files),
        }


class Exporter:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.batches = BatchStore(store)

    def _rule_map(self, batch: Batch) -> dict[str, dict[str, FieldRule]]:
        return {table: {rule.field: rule for rule in rules} for table, rules in batch.rules.items()}

    def _revisions(self, batch: Batch) -> list[RuleRevision]:
        revisions = revision_plan(batch.history)
        if not revisions:
            raise RuntimeError(f"批次 {batch.batch_id} 缺少规则修订历史")
        return revisions

    def resolve_plan(
        self, batch: Batch
    ) -> tuple[dict[str, list[tuple[dict[str, str], RuleRevision, str]]], list[RuleRevision]]:
        """逐条原始记录解析本次生效的规则修订及范围命中原因。

        沿修订号从早到晚判定：修订只对其范围内的记录生效，范围外的记录
        继续沿用更早的有效修订。来源新增记录在此刻重新参与范围判断，
        不借用任何历史执行的结论。
        """
        revisions = self._revisions(batch)
        decisions: dict[str, list[tuple[dict[str, str], RuleRevision, str]]] = {}
        for table in batch.tables:
            rows = read_csv(self.store.raw_dir(batch.batch_id) / f"{table}.csv")
            chosen: list[tuple[dict[str, str], RuleRevision, str]] = []
            for row in rows:
                winner = revisions[0]
                reason = "all"
                for revision in revisions[1:]:
                    matched, matched_by = revision.scope.match(table, row)
                    if matched:
                        winner, reason = revision, matched_by
                chosen.append((row, winner, reason))
            decisions[table] = chosen
        return decisions, revisions

    def transform(
        self, batch: Batch
    ) -> tuple[list[TableExport], list[RecordBasis]]:
        mapping = SubjectMapping.load_or_create(self.store, batch.batch_id)
        decisions, revisions = self.resolve_plan(batch)
        all_subjects: set[str] = set()
        for table in batch.tables:
            for row, _revision, _reason in decisions[table]:
                sid = row.get(batch.subject_field, "").strip()
                if sid:
                    all_subjects.add(sid)
        for sid in sorted(all_subjects):
            mapping.register(sid)
        mapping.save(self.store)

        redactor = Redactor.from_batch(self.store.raw_dir(batch.batch_id))
        exports: list[TableExport] = []
        bases: list[RecordBasis] = []
        for table in batch.tables:
            rows = [item[0] for item in decisions[table]]
            with (self.store.raw_dir(batch.batch_id) / f"{table}.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as fh:
                columns = next(csv.reader(fh))
            revision_rules = [
                {rule.field: rule for rule in revision.rules.get(table, [])}
                for revision in revisions
            ]
            all_rule_fields: set[str] = set()
            for table_rule_map in revision_rules:
                all_rule_fields.update(table_rule_map)
            for name in all_rule_fields:
                if name not in columns:
                    raise ValueError(f"表 {table} 的规则字段不存在: {name}")
            if batch.subject_field not in columns:
                raise ValueError(f"表 {table} 缺少受试者关联列 {batch.subject_field}")
            if any(
                table_rule_map.get(batch.subject_field) is not None
                and table_rule_map[batch.subject_field].action == "drop"
                for table_rule_map in revision_rules
            ):
                raise ValueError(f"受试者关联列 {batch.subject_field} 不能删除，否则跨表关联会丢失")
            def _kept_by_revision(revision: RuleRevision, column: str) -> bool:
                if column == batch.subject_field:
                    return True
                field_rule = next(
                    (
                        field_rule for field_rule in revision.rules.get(table, [])
                        if field_rule.field == column
                    ),
                    None,
                )
                return field_rule is None or field_rule.action != "drop"

            output_columns = [
                column for column in columns
                if any(
                    _kept_by_revision(chosen_revision, column)
                    for _chosen_row, chosen_revision, _chosen_reason in decisions[table]
                )
            ]
            out_rows: list[dict[str, str]] = []
            for row, revision, matched_by in decisions[table]:
                real_sid = row[batch.subject_field].strip()
                pseudo_sid, offset_days = mapping.register(real_sid)
                table_rules = {
                    rule.field: rule for rule in revision.rules.get(table, [])
                }
                out: dict[str, str] = {}
                actions: dict[str, str] = {}
                date_shift_fields: list[str] = []
                for column in output_columns:
                    value = row.get(column, "")
                    if column == batch.subject_field:
                        out[column] = pseudo_sid
                        actions[column] = "pseudonymize"
                        continue
                    rule = table_rules.get(column)
                    if rule is None or rule.action == "keep":
                        out[column] = value
                        actions[column] = "keep"
                    elif rule.action == "date_shift":
                        out[column] = shift_date(value, offset_days)
                        actions[column] = (
                            f"date_shift(offset_days={offset_days},per_subject_fixed)"
                        )
                        date_shift_fields.append(column)
                    elif rule.action == "redact_text":
                        out[column] = redactor.redact(value, real_sid)
                        actions[column] = "redact_text"
                    elif rule.action == "drop":
                        out[column] = ""
                        actions[column] = "drop"
                    else:
                        raise AssertionError(rule.action)
                out_rows.append(out)
                for column in columns:
                    if column in output_columns:
                        continue
                    actions[column] = "drop"
                    rule = table_rules.get(column)
                    if rule is not None and rule.action == "date_shift":
                        date_shift_fields.append(column)
                bases.append(
                    RecordBasis(
                        table=table,
                        record_key=mapping.record_ref(table, record_key(row)),
                        subject_pseudonym=pseudo_sid,
                        rules_version=revision.version,
                        revision_note=revision.note,
                        matched_by=matched_by,
                        scope=_public_scope(revision.scope),
                        actions=actions,
                        date_shift_fields=tuple(sorted(set(date_shift_fields))),
                    )
                )
            exports.append(TableExport(table=table, fieldnames=output_columns, rows=out_rows))
        return exports, bases

    def preview_scope(self, batch_id: str, rules_version: int) -> list[ScopePreviewRow]:
        """预览某次修订的适用范围：命中记录采用新规则，范围外沿用旧规则。"""
        batch = self.batches.load(batch_id)
        revisions = self._revisions(batch)
        target = next(
            (revision for revision in revisions if revision.version == rules_version), None
        )
        if target is None:
            raise ValueError(f"规则修订不存在: v{rules_version}")
        preview: list[ScopePreviewRow] = []
        for table in batch.tables:
            rows = read_csv(self.store.raw_dir(batch.batch_id) / f"{table}.csv")
            for row in rows:
                matched, matched_by = target.scope.match(table, row)
                winner = target
                if not matched:
                    earlier = [
                        revision for revision in revisions
                        if revision.version < rules_version
                    ]
                    winner = earlier[-1] if earlier else revisions[0]
                    matched_by = f"out_of_scope:continues_v{winner.version}"
                preview.append(
                    ScopePreviewRow(
                        table=table,
                        record_key=record_key(row),
                        subject_id=row.get(batch.subject_field, "").strip(),
                        rules_version=winner.version,
                        matched=matched,
                        matched_by=matched_by,
                        revision_note=winner.note,
                    )
                )
        return preview

    def calculate_fingerprints(
        self,
        batch: Batch,
        tables: list[TableExport],
        bases: list[RecordBasis],
        revisions: list[RuleRevision],
    ) -> tuple[str, str, str, str, str]:
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
        # 规则内容指纹：每条记录实际采用的字段规则（含字段动作）多重集合。
        # 规则配置退回早期内容时此指纹相同；适用对象不同则不影响该值，二者分开报告。
        rule_lines: set[str] = set()
        # 适用范围指纹：每条记录最终由哪次修订决定（修订号+命中原因），
        # 体现范围扩大/缩小以及新增记录落入哪一批。
        scope_lines: list[str] = []
        # 执行计划指纹：修订号、规则内容与范围声明的完整快照。
        # 即使规则内容与历史相同（配置退回）、范围不同，计划也不同，执行身份绝不合并。
        plan_lines: list[str] = []
        for revision in revisions:
            plan_lines.append(
                stable_json({
                    "version": revision.version,
                    "rules": {
                        table: [rule.to_dict() for rule in table_rules]
                        for table, table_rules in sorted(revision.rules.items())
                    },
                    "scope": revision.scope.to_dict(),
                })
            )
        for basis in sorted(bases, key=lambda item: (item.table, item.record_key)):
            revision = next(
                revision for revision in revisions if revision.version == basis.rules_version
            )
            rule_lines.add(
                stable_json({
                    "table": basis.table,
                    "rules": [
                        rule.to_dict()
                        for rule in revision.rules.get(basis.table, [])
                    ],
                })
            )
            scope_lines.append(
                f"{basis.table}\0{basis.record_key}\0v{basis.rules_version}\0{basis.matched_by}"
            )
        rules_content_fp = hashlib.sha256(
            ("\n".join(sorted(rule_lines))).encode("utf-8")
        ).hexdigest()
        scope_fp = hashlib.sha256(
            ("\n".join(sorted(scope_lines))).encode("utf-8")
        ).hexdigest()
        plan_fp = hashlib.sha256(
            ("\n".join(plan_lines)).encode("utf-8")
        ).hexdigest()
        return rules_content_fp, scope_fp, plan_fp, fingerprint(raw_parts), fingerprint(out_parts)

    def export_batch(self, batch_id: str, note: str = "") -> ExportResult:
        batch = self.batches.load(batch_id)
        tables, bases = self.transform(batch)
        decisions, revisions = self.resolve_plan(batch)
        rules_fp, scope_fp, plan_fp, source_fp, output_fp = self.calculate_fingerprints(
            batch, tables, bases, revisions
        )
        index = self._load_index(batch_id)
        # 执行身份由「完整规则计划（修订号+规则内容+适用范围）+ 输入指纹」唯一确定：
        # 规则退回旧配置或范围扩大/缩小都会前进计划指纹，必须产生新执行。
        for entry in index["versions"]:
            if (
                entry.get("plan_fingerprint", "") == plan_fp
                and entry["source_fingerprint"] == source_fp
            ):
                version = int(entry["version"])
                version_dir = self.store.version_dir(batch_id, version)
                self._verify_checksums(version_dir, entry["files"])
                if entry["output_fingerprint"] != output_fp:
                    raise RuntimeError(
                        f"同一次执行重跑结果不一致: v{version:03d} 输出指纹发生变化"
                    )
                return ExportResult(batch_id, version, version_dir, True,
                                    int(entry["rules_version"]), entry["note"])

        existing = [
            int(path.name[1:])
            for path in self.store.export_dir(batch_id).glob("v[0-9][0-9][0-9]")
        ]
        version = max(existing + [int(entry["version"]) for entry in index["versions"]], default=0) + 1
        version_dir = self.store.version_dir(batch_id, version)
        version_dir.mkdir(parents=True, exist_ok=False)
        try:
            content_reused_from = self._commit_version(
                batch, tables, bases, version, version_dir, index,
                rules_fp, scope_fp, plan_fp, source_fp, output_fp, note,
            )
        except BaseException:
            # 中断/自检失败后清掉不完整目录，下次重试得到干净的新版本号，旧执行不受影响。
            shutil.rmtree(version_dir, ignore_errors=True)
            raise
        return ExportResult(batch_id, version, version_dir, False, batch.rules_version,
                            note or f"字段规则 v{batch.rules_version} 导出", content_reused_from)

    def _commit_version(
        self, batch: Batch, tables: list[TableExport], bases: list[RecordBasis],
        version: int, version_dir: Path, index: dict[str, Any],
        rules_fp: str, scope_fp: str, plan_fp: str,
        source_fp: str, output_fp: str, note: str,
    ) -> int | None:
        files: dict[str, str] = {}
        for exported in tables:
            target = version_dir / f"{exported.table}.csv"
            write_csv(target, exported.rows, exported.fieldnames)
            files[f"{exported.table}.csv"] = sha256_file(target)
        # 公开溯源：逐条记录说明本次采用的规则修订、范围命中依据与日期处理。
        basis_path = version_dir / "basis.jsonl"
        with basis_path.open("w", encoding="utf-8", newline="") as fh:
            for basis in sorted(bases, key=lambda item: (item.table, item.record_key)):
                fh.write(json.dumps(basis.to_dict(), ensure_ascii=False, sort_keys=True))
                fh.write("\n")
        files["basis.jsonl"] = sha256_file(basis_path)
        # 规则/输入已变，但最终字节可能恰好与旧版本一致：记录内容来源而非合并执行身份。
        content_reused_from = self._match_output_version(index, output_fp)
        if content_reused_from is not None:
            self._verify_reused_content(index, batch.batch_id, content_reused_from, files)
        manifest_note = note or f"字段规则 v{batch.rules_version} 导出"
        manifest = {
            "batch_id": batch.batch_id,
            "version": version,
            "created_at": _now(),
            "rules_version": batch.rules_version,
            "note": manifest_note,
            "subject_field": batch.subject_field,
            "tables": batch.tables,
            "rules_fingerprint": rules_fp,
            "scope_fingerprint": scope_fp,
            "plan_fingerprint": plan_fp,
            "source_fingerprint": source_fp,
            "output_fingerprint": output_fp,
            "content_reused_from": content_reused_from,
            "reused_content": content_reused_from is not None,
            "files": dict(sorted(files.items())),
        }
        write_json(version_dir / "manifest.json", manifest)
        findings = scan_leaks(self.store, batch.batch_id, version)
        if findings:
            raise RuntimeError("导出结果泄露自检失败: " + "; ".join(findings))
        final_files = {
            name: sha256_file(version_dir / name)
            for name in sorted(list(files) + ["manifest.json"])
        }
        entry = {
            "version": version,
            "created_at": manifest["created_at"],
            "rules_version": batch.rules_version,
            "rules_fingerprint": rules_fp,
            "scope_fingerprint": scope_fp,
            "plan_fingerprint": plan_fp,
            "source_fingerprint": source_fp,
            "output_fingerprint": output_fp,
            "content_reused_from": content_reused_from,
            "note": manifest_note,
            "dir": version_dir.name,
            "files": final_files,
        }
        index["batch_id"] = batch.batch_id
        index["latest"] = version
        index["versions"].append(entry)
        write_json(self.store.export_index(batch.batch_id), index)
        return content_reused_from

    def _load_index(self, batch_id: str) -> dict[str, Any]:
        path = self.store.export_index(batch_id)
        index = read_json(path) if path.exists() else {
            "batch_id": batch_id, "latest": 0, "versions": [],
        }
        entries = {int(entry["version"]): entry for entry in index.get("versions", [])}
        changed = False
        export_root = self.store.export_dir(batch_id)
        if export_root.exists():
            for version_dir in sorted(export_root.glob("v[0-9][0-9][0-9]")):
                version_number = int(version_dir.name[1:])
                manifest_path = version_dir / "manifest.json"
                entry = entries.get(version_number)
                if entry is None and not manifest_path.exists():
                    # 无 manifest 的目录只能是中断残留，删除后本次可重用该版本号重试。
                    shutil.rmtree(version_dir, ignore_errors=True)
                    changed = True
                    continue
                if entry is None and manifest_path.exists():
                    # 迁移历史记录（index.json 缺失/不全）：从不可变版本目录重建索引。
                    entries[version_number] = self._entry_from_manifest(version_number, manifest_path)
                    changed = True
                    continue
                if entry is not None:
                    present = {
                        p.name: sha256_file(p)
                        for p in version_dir.iterdir() if p.is_file()
                    }
                    if entry.get("files") != present or not manifest_path.exists():
                        # 目录不完整（中断残留/文件被删改）：不计入有效执行；无 manifest 则无法恢复，删除。
                        del entries[version_number]
                        changed = True
                        if not manifest_path.exists():
                            shutil.rmtree(version_dir, ignore_errors=True)
        ordered = [entries[key] for key in sorted(entries)]
        latest = max(entries, default=0)
        if changed or list(index.get("versions", [])) != ordered or int(index.get("latest", 0)) != latest:
            index = {"batch_id": batch_id, "latest": latest, "versions": ordered}
            write_json(path, index)
        return index

    def _entry_from_manifest(self, version: int, manifest_path: Path) -> dict[str, Any]:
        manifest = read_json(manifest_path)
        version_dir = manifest_path.parent
        return {
            "version": version,
            "created_at": manifest["created_at"],
            "rules_version": int(manifest["rules_version"]),
            "rules_fingerprint": manifest["rules_fingerprint"],
            "scope_fingerprint": manifest.get("scope_fingerprint", ""),
            "plan_fingerprint": manifest.get(
                "plan_fingerprint",
                # 迁移自旧版本（无范围概念）：用规则修订号充当计划指纹，保证身份不被错误合并。
                f"legacy:v{int(manifest['rules_version'])}",
            ),
            "source_fingerprint": manifest["source_fingerprint"],
            "output_fingerprint": manifest["output_fingerprint"],
            "content_reused_from": manifest.get("content_reused_from"),
            "note": manifest["note"],
            "dir": version_dir.name,
            "files": {
                p.name: sha256_file(p) for p in sorted(version_dir.iterdir()) if p.is_file()
            },
        }

    def _verify_checksums(self, version_dir: Path, files: dict[str, str]) -> None:
        for name, expected in files.items():
            actual = sha256_file(version_dir / name)
            if actual != expected:
                raise RuntimeError(f"重复导出核对失败，已发布版本被改动: {version_dir / name}")

    def _match_output_version(self, index: dict[str, Any], output_fp: str) -> int | None:
        """在旧版本中找到输出字节完全一致的最近一版（只代表内容相同，不代表身份相同）。"""
        for entry in reversed(index["versions"]):
            if entry["output_fingerprint"] == output_fp:
                return int(entry["version"])
        return None

    def _verify_reused_content(
        self, index: dict[str, Any], batch_id: str, source_version: int,
        files: dict[str, str],
    ) -> None:
        """确认本次新写入的 CSV 与被引用版本逐文件字节一致。"""
        source_dir = self.store.version_dir(batch_id, source_version)
        source_entry = next(
            entry for entry in index["versions"] if int(entry["version"]) == source_version
        )
        for name, expected in files.items():
            if not name.endswith(".csv"):
                # 内容复用仅指公开 CSV 字节一致；溯源 basis.jsonl 属于本次执行，允许不同。
                continue
            actual = sha256_file(source_dir / name)
            if actual != expected or source_entry["files"].get(name) != expected:
                raise RuntimeError(
                    f"内容复用核对失败: v{source_version:03d} 的 {name} 与当前输出不一致"
                )

    def compare_versions(
        self, batch_id: str, version_a: int, version_b: int
    ) -> VersionComparison:
        """比较两次导出在规则、输入数据、最终内容三个维度上的差异。"""
        index = self._load_index(batch_id)
        entries = {int(entry["version"]): entry for entry in index["versions"]}
        if version_a not in entries:
            raise ValueError(f"版本不存在: v{version_a:03d}")
        if version_b not in entries:
            raise ValueError(f"版本不存在: v{version_b:03d}")
        left, right = entries[version_a], entries[version_b]
        left_files = {
            name: checksum for name, checksum in left["files"].items() if name.endswith(".csv")
        }
        right_files = {
            name: checksum for name, checksum in right["files"].items() if name.endswith(".csv")
        }
        added = tuple(sorted(set(right_files) - set(left_files)))
        removed = tuple(sorted(set(left_files) - set(right_files)))
        changed = tuple(sorted(
            name for name in set(left_files) & set(right_files)
            if left_files[name] != right_files[name]
        ))
        return VersionComparison(
            batch_id=batch_id,
            from_version=version_a,
            to_version=version_b,
            rules_changed=left["rules_fingerprint"] != right["rules_fingerprint"],
            scope_changed=left.get("scope_fingerprint", "")
            != right.get("scope_fingerprint", ""),
            source_changed=left["source_fingerprint"] != right["source_fingerprint"],
            output_changed=left["output_fingerprint"] != right["output_fingerprint"],
            # 三个层次：配置指纹相同（修订号可以不同）、公开输出字节相同、同一次执行（幂等重跑）。
            rules_config_equal=left["rules_fingerprint"] == right["rules_fingerprint"],
            output_equal=left["output_fingerprint"] == right["output_fingerprint"],
            same_execution=(
                left.get("plan_fingerprint", f"legacy:v{int(left['rules_version'])}")
                == right.get("plan_fingerprint", f"legacy:v{int(right['rules_version'])}")
                and left["source_fingerprint"] == right["source_fingerprint"]
            ),
            rules_version_from=int(left["rules_version"]),
            rules_version_to=int(right["rules_version"]),
            rules_fingerprint_from=left["rules_fingerprint"],
            rules_fingerprint_to=right["rules_fingerprint"],
            scope_fingerprint_from=left.get("scope_fingerprint", ""),
            scope_fingerprint_to=right.get("scope_fingerprint", ""),
            source_fingerprint_from=left["source_fingerprint"],
            source_fingerprint_to=right["source_fingerprint"],
            output_fingerprint_from=left["output_fingerprint"],
            output_fingerprint_to=right["output_fingerprint"],
            added_files=added,
            removed_files=removed,
            changed_files=changed,
        )

    def rule_trail(self, batch_id: str) -> list[dict[str, Any]]:
        """沿规则修订顺序给出每次执行及其与前一次执行的关系。"""
        batch = self.batches.load(batch_id)
        revisions = {
            int(item["rules_version"]): item for item in batch.history
        }
        index = self._load_index(batch_id)
        trail: list[dict[str, Any]] = []
        prev: dict[str, Any] | None = None
        for entry in sorted(index["versions"], key=lambda item: int(item["version"])):
            revision = revisions.get(int(entry["rules_version"]))
            reused_from = entry.get("content_reused_from")
            if reused_from is not None:
                reused_from = int(reused_from)
            item = {
                "version": int(entry["version"]),
                "rules_version": int(entry["rules_version"]),
                "rules_note": revision.get("note", "") if revision else "",
                "rules_config_equal_previous": (
                    prev is not None and entry["rules_fingerprint"] == prev["rules_fingerprint"]
                ),
                "source_equal_previous": (
                    prev is not None and entry["source_fingerprint"] == prev["source_fingerprint"]
                ),
                "scope_equal_previous": (
                    prev is not None
                    and entry.get("scope_fingerprint", "") == prev.get("scope_fingerprint", "")
                ),
                "output_equal_previous": (
                    prev is not None and entry["output_fingerprint"] == prev["output_fingerprint"]
                ),
                "same_execution_as_previous": (
                    prev is not None
                    and entry.get("plan_fingerprint", "") == prev.get("plan_fingerprint", "")
                    and entry["source_fingerprint"] == prev["source_fingerprint"]
                ),
                "content_reused_from": reused_from,
                "note": entry["note"],
                "created_at": entry["created_at"],
            }
            trail.append(item)
            prev = entry
        return trail
