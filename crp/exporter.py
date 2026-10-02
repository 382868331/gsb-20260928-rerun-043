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
import io
import shutil
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
from crp.rules import FieldRule, parse_rules
from crp.scope import describe as describe_scope
from crp.scope import matches as scope_matches
from crp.scope import normalize_scope, scope_fingerprint
from crp.util import fingerprint, read_csv, read_json, sha256_file, write_csv, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class TableExport:
    table: str
    fieldnames: list[str]
    rows: list[dict[str, str]]
    decisions: list[dict[str, Any]]


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
class ScopePreview:
    included: tuple[dict[str, Any], ...]
    excluded: tuple[dict[str, Any], ...]


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

    def preview_scope(
        self,
        batch_id: str,
        scope: dict[str, Any] | None,
        rules_version: int | None = None,
    ) -> ScopePreview:
        batch = self.batches.load(batch_id)
        normalized = normalize_scope(scope)
        target_version = batch.rules_version if rules_version is None else rules_version
        included: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        for table in batch.tables:
            path = self.store.raw_dir(batch.batch_id) / f"{table}.csv"
            with path.open("r", encoding="utf-8-sig", newline="") as fh:
                columns = next(csv.reader(fh))
            for row_number, row in enumerate(read_csv(path), start=2):
                item = {
                    "table": table,
                    "row_number": row_number,
                    "subject_id": row.get(batch.subject_field, ""),
                    "candidate_rules_version": target_version,
                    "scope": normalized,
                    "scope_description": describe_scope(normalized),
                }
                target = included if scope_matches(
                    normalized, table, row, set(columns), row_number
                ) else excluded
                target.append(item)
        return ScopePreview(tuple(included), tuple(excluded))

    def _revision_rule_maps(self, batch: Batch):
        revisions = sorted(batch.revisions or [], key=lambda item: int(item["rules_version"]))
        maps = []
        last_map = self._rule_map(batch)
        for item in revisions:
            raw_rules = item.get("rules", {})
            last_map = (
                {table: {rule.field: rule for rule in rules}
                 for table, rules in parse_rules(raw_rules).items()}
                if raw_rules else last_map
            )
            maps.append((
                int(item["rules_version"]),
                last_map,
                normalize_scope(item.get("scope")),
            ))
        if not maps or maps[-1][0] != batch.rules_version:
            maps.append((batch.rules_version, self._rule_map(batch), normalize_scope(None)))
        return maps

    def transform(self, batch: Batch) -> list[TableExport]:
        mapping = SubjectMapping.load_or_create(self.store, batch.batch_id)
        raw_rows: dict[str, list[dict[str, str]]] = {}
        all_subjects: set[str] = set()
        for table in batch.tables:
            rows = list(read_csv(self.store.raw_dir(batch.batch_id) / f"{table}.csv"))
            raw_rows[table] = rows
            for row_number, row in enumerate(rows, start=2):
                sid = row.get(batch.subject_field, "").strip()
                if sid:
                    all_subjects.add(sid)
        for sid in sorted(all_subjects):
            mapping.register(sid)
        mapping.save(self.store)

        redactor = Redactor.from_batch(self.store.raw_dir(batch.batch_id))
        revision_maps = self._revision_rule_maps(batch)
        all_rule_maps = {version: rule_map for version, rule_map, _scope in revision_maps}
        exports: list[TableExport] = []
        for table in batch.tables:
            rows = raw_rows[table]
            with (self.store.raw_dir(batch.batch_id) / f"{table}.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as fh:
                columns = next(csv.reader(fh))
            for _version, rule_map_for_version in all_rule_maps.items():
                for name in rule_map_for_version.get(table, {}):
                    if name not in columns:
                        raise ValueError(f"表 {table} 的规则字段不存在: {name}")
            if batch.subject_field not in columns:
                raise ValueError(f"表 {table} 缺少受试者关联列 {batch.subject_field}")
            selected_for_rows = []
            for row_number, row in enumerate(rows, start=2):
                selected_for_rows.append(next(
                    revision for revision in reversed(revision_maps)
                    if scope_matches(revision[2], table, row, set(columns), row_number)
                ))
            used_versions = {revision[0] for revision in selected_for_rows}
            dropped_everywhere: set[str] | None = None
            for version, rule_map_for_version, _scope in revision_maps:
                if version not in used_versions:
                    continue
                table_rules = rule_map_for_version.get(table, {})
                subject_rule = table_rules.get(batch.subject_field)
                if subject_rule is not None and subject_rule.action == "drop":
                    raise ValueError(f"受试者关联列 {batch.subject_field} 不能删除，否则跨表关联会丢失")
                dropped_here = {name for name, rule in table_rules.items() if rule.action == "drop"}
                dropped_everywhere = dropped_here if dropped_everywhere is None else (dropped_everywhere | dropped_here)
            if not used_versions:
                dropped_everywhere = set()
            output_columns = [column for column in columns if column not in (dropped_everywhere or set())]
            out_rows: list[dict[str, str]] = []
            decisions: list[dict[str, Any]] = []
            for row_number, row in enumerate(rows, start=2):
                real_sid = row[batch.subject_field].strip()
                pseudo_sid, offset_days = mapping.register(real_sid)
                selected = selected_for_rows[len(out_rows)]
                selected_version, selected_map, selected_scope = selected
                table_rules = selected_map.get(table, {})
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
                decisions.append({
                    "table": table,
                    "source_row": int(row_number),
                    "output_row": len(out_rows) + 1,
                    "subject_id": pseudo_sid,
                    "record_id": self._record_id(table, row, columns),
                    "rules_version": selected_version,
                    "scope": describe_scope(selected_scope),
                    "basis": f"记录命中规则修订 v{selected_version} 的适用范围：{describe_scope(selected_scope)}",
                })
            exports.append(TableExport(table, output_columns, out_rows, decisions))
        return exports

    @staticmethod
    def _record_id(table: str, row: dict[str, str], columns: list[str]) -> str:
        key_fields = [
            column for column in columns
            if column != "subject_id"
            and (column.endswith("_id") or column in {"test_code", "row_id"})
        ]
        values = [f"{column}={row[column]}" for column in key_fields if row.get(column)]
        if values:
            return f"{table}:{';'.join(values)}"
        return f"{table}:source_row=auto"

    def _trace_csv(self, tables: list[TableExport]) -> str:
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([
            "table", "source_row", "output_row", "subject_id", "record_id",
            "rules_version", "scope", "basis",
        ])
        for exported in tables:
            for decision in exported.decisions:
                writer.writerow([
                    decision["table"], decision["source_row"], decision["output_row"],
                    decision["subject_id"], decision["record_id"], decision["rules_version"],
                    decision["scope"], decision["basis"],
                ])
        return buffer.getvalue()

    def calculate_fingerprints(self, batch: Batch, tables: list[TableExport]) -> tuple[str, str, str, str]:
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
        scopes = {
            int(item["rules_version"]): normalize_scope(item.get("scope"))
            for item in (batch.revisions or [])
        }
        from crp.util import sha256_text, stable_json
        scope_fp = sha256_text(stable_json(scopes))
        return rules_canonical, fingerprint(raw_parts), fingerprint(out_parts), scope_fp

    def export_batch(self, batch_id: str, note: str = "") -> ExportResult:
        batch = self.batches.load(batch_id)
        tables = self.transform(batch)
        rules_fp, source_fp, output_fp, scope_fp = self.calculate_fingerprints(batch, tables)
        index = self._load_index(batch_id)
        # 执行身份由「真正生效的规则修订号 + 输入指纹」唯一确定：
        # 规则退回旧配置时配置指纹虽然相同，但修订号已前进，必须产生新执行。
        for entry in index["versions"]:
            if (
                int(entry["rules_version"]) == batch.rules_version
                and entry["source_fingerprint"] == source_fp
                and entry.get("scope_fingerprint", scope_fingerprint(None)) == scope_fp
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
                batch, tables, version, version_dir, index,
                rules_fp, source_fp, output_fp, scope_fp, note,
            )
        except BaseException:
            # 中断/自检失败后清掉不完整目录，下次重试得到干净的新版本号，旧执行不受影响。
            shutil.rmtree(version_dir, ignore_errors=True)
            raise
        return ExportResult(batch_id, version, version_dir, False, batch.rules_version,
                            note or f"字段规则 v{batch.rules_version} 导出", content_reused_from)

    def _commit_version(
        self, batch: Batch, tables: list[TableExport], version: int, version_dir: Path,
        index: dict[str, Any], rules_fp: str, source_fp: str, output_fp: str,
        scope_fp: str, note: str,
    ) -> int | None:
        files: dict[str, str] = {}
        for exported in tables:
            target = version_dir / f"{exported.table}.csv"
            write_csv(target, exported.rows, exported.fieldnames)
            files[f"{exported.table}.csv"] = sha256_file(target)
        trace_path = version_dir / "rule_trace.csv"
        trace_path.write_text(self._trace_csv(tables), encoding="utf-8")
        files["rule_trace.csv"] = sha256_file(trace_path)
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
            "applicable_revisions": [
                {
                    "rules_version": int(item["rules_version"]),
                    "rules": item.get("rules", {}),
                    "scope": normalize_scope(item.get("scope")),
                    "scope_fingerprint": scope_fingerprint(item.get("scope")),
                }
                for item in (batch.revisions or [])
            ],
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
            "scope_fingerprint": manifest.get("scope_fingerprint", scope_fingerprint(None)),
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
            if name == "rule_trace.csv":
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
            name: checksum for name, checksum in left["files"].items()
            if name.endswith(".csv") and name != "rule_trace.csv"
        }
        right_files = {
            name: checksum for name, checksum in right["files"].items()
            if name.endswith(".csv") and name != "rule_trace.csv"
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
            scope_changed=left.get("scope_fingerprint", scope_fingerprint(None))
                != right.get("scope_fingerprint", scope_fingerprint(None)),
            source_changed=left["source_fingerprint"] != right["source_fingerprint"],
            output_changed=left["output_fingerprint"] != right["output_fingerprint"],
            # 三个层次：配置指纹相同（修订号可以不同）、公开输出字节相同、同一次执行（幂等重跑）。
            rules_config_equal=left["rules_fingerprint"] == right["rules_fingerprint"],
            output_equal=left["output_fingerprint"] == right["output_fingerprint"],
            same_execution=(
                int(left["rules_version"]) == int(right["rules_version"])
                and left["source_fingerprint"] == right["source_fingerprint"]
                and left.get("scope_fingerprint", scope_fingerprint(None))
                == right.get("scope_fingerprint", scope_fingerprint(None))
            ),
            rules_version_from=int(left["rules_version"]),
            rules_version_to=int(right["rules_version"]),
            rules_fingerprint_from=left["rules_fingerprint"],
            rules_fingerprint_to=right["rules_fingerprint"],
            scope_fingerprint_from=left.get("scope_fingerprint", scope_fingerprint(None)),
            scope_fingerprint_to=right.get("scope_fingerprint", scope_fingerprint(None)),
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
                "scope_equal_previous": (
                    prev is not None
                    and entry.get("scope_fingerprint", scope_fingerprint(None))
                    == prev.get("scope_fingerprint", scope_fingerprint(None))
                ),
                "source_equal_previous": (
                    prev is not None and entry["source_fingerprint"] == prev["source_fingerprint"]
                ),
                "output_equal_previous": (
                    prev is not None and entry["output_fingerprint"] == prev["output_fingerprint"]
                ),
                "same_execution_as_previous": (
                    prev is not None
                    and int(entry["rules_version"]) == int(prev["rules_version"])
                    and entry["source_fingerprint"] == prev["source_fingerprint"]
                    and entry.get("scope_fingerprint", scope_fingerprint(None))
                    == prev.get("scope_fingerprint", scope_fingerprint(None))
                ),
                "content_reused_from": reused_from,
                "note": entry["note"],
                "created_at": entry["created_at"],
            }
            trail.append(item)
            prev = entry
        return trail
