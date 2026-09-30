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
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from crp.audit import scan_leaks_dir
from crp.batch import Batch, BatchStore
from crp.dates import shift_date
from crp.paths import Store
from crp.pseudonym import SubjectMapping
from crp.redact import Redactor
from crp.rules import FieldRule
from crp.util import fingerprint, read_csv, read_json, sha256_file, write_csv, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")


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
class VersionComparison:
    """两次导出之间的影响比较，三类变化互不混淆。"""

    batch_id: str
    from_version: int
    to_version: int
    rules_changed: bool
    source_changed: bool
    output_changed: bool
    rules_version_from: int
    rules_version_to: int
    rules_fingerprint_from: str
    rules_fingerprint_to: str
    source_fingerprint_from: str
    source_fingerprint_to: str
    output_fingerprint_from: str
    output_fingerprint_to: str
    same_execution: bool
    content_reused_from_to: int | None
    added_files: tuple[str, ...]
    removed_files: tuple[str, ...]
    changed_files: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "rules_changed": self.rules_changed,
            "source_changed": self.source_changed,
            "output_changed": self.output_changed,
            "rules_version": {"from": self.rules_version_from, "to": self.rules_version_to},
            "rules_fingerprint": {
                "from": self.rules_fingerprint_from,
                "to": self.rules_fingerprint_to,
            },
            "source_fingerprint": {
                "from": self.source_fingerprint_from,
                "to": self.source_fingerprint_to,
            },
            "output_fingerprint": {
                "from": self.output_fingerprint_from,
                "to": self.output_fingerprint_to,
            },
            "same_execution": self.same_execution,
            "content_reused_from": {"from": None, "to": self.content_reused_from_to},
            "added_files": list(self.added_files),
            "removed_files": list(self.removed_files),
            "changed_files": list(self.changed_files),
        }


@dataclass(frozen=True)
class RuleRevisionView:
    """规则修订链路上的一个节点及其对应执行（若已导出）。

    - ``config_same_as``：本修订的规则配置与此前哪一版修订完全相同（规则改回旧配置）；
    - ``output_same_as``：本次执行的公开输出与此前哪一次执行字节相同（仅内容相同）；
    - ``execution_version``：本修订首次导出产生的独立执行版本；同一修订下重复导出
      幂等复用，属于同一次执行。
    """

    rules_version: int
    changed_at: str
    note: str
    rules_hash: str
    config_same_as: int | None
    execution_version: int | None
    source_fingerprint: str | None
    output_fingerprint: str | None
    output_same_as: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules_version": self.rules_version,
            "changed_at": self.changed_at,
            "note": self.note,
            "rules_hash": self.rules_hash,
            "config_same_as": self.config_same_as,
            "execution_version": self.execution_version,
            "source_fingerprint": self.source_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "output_same_as": self.output_same_as,
        }


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
        # 只有真正生效的【规则修订】与输入都相同（即同一次修订下的重复导出），
        # 才允许复用同一执行身份。规则改回旧配置时指纹可能相同，但修订号不同，
        # 必须产生新的执行记录，不得冒充历史执行。
        for entry in index["versions"]:
            if (
                int(entry["rules_version"]) == batch.rules_version
                and entry["source_fingerprint"] == source_fp
            ):
                version = int(entry["version"])
                version_dir = self.store.version_dir(batch_id, version)
                self._verify_checksums(version_dir, entry["files"])
                return ExportResult(batch_id, version, version_dir, True,
                                    int(entry["rules_version"]), entry["note"])

        self._cleanup_incomplete_dirs(batch_id, index)
        # 中断重试：上次执行已完整落盘但索引尚未更新时，恢复该执行的索引归属。
        recovered = self._recover_interrupted(
            batch_id, index, batch.rules_version, rules_fp, source_fp, output_fp
        )
        if recovered is not None:
            return recovered

        # 历史迁移后磁盘上可能有索引之外的完整版本目录：版本号在现有目录与索引
        # 共同之上顺延，迁移来的旧执行目录永不覆盖、继续可查。
        version = self._next_version_number(batch_id, index)
        version_dir = self.store.version_dir(batch_id, version)
        staging_dir = version_dir.with_name(f".staging-{version}-{_now_compact()}")
        staging_dir.mkdir(parents=True, exist_ok=False)
        files: dict[str, str] = {}
        for exported in tables:
            target = staging_dir / f"{exported.table}.csv"
            write_csv(target, exported.rows, exported.fieldnames)
            files[f"{exported.table}.csv"] = sha256_file(target)
        # 规则/输入已变，但最终字节可能恰好与旧版本一致：记录内容来源而非合并执行身份。
        content_reused_from = self._match_output_version(index, output_fp)
        if content_reused_from is not None:
            self._verify_reused_content(batch_id, index, content_reused_from, files)
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
            "content_reused_from": content_reused_from,
            "reused_content": content_reused_from is not None,
            "files": dict(sorted(files.items())),
        }
        write_json(staging_dir / "manifest.json", manifest)
        # 泄露自检针对暂存目录进行：失败时不留任何公开版本痕迹。
        findings = scan_leaks_dir(staging_dir, batch.to_json())
        if findings:
            shutil.rmtree(staging_dir)
            raise RuntimeError("导出结果泄露自检失败: " + "; ".join(findings))
        staging_dir.replace(version_dir)
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
            "content_reused_from": content_reused_from,
            "note": manifest["note"],
            "dir": version_dir.name,
            "files": final_files,
        }
        index["batch_id"] = batch_id
        index["latest"] = version
        index["versions"].append(entry)
        write_json(self.store.export_index(batch_id), index)
        return ExportResult(batch_id, version, version_dir, False, batch.rules_version,
                            manifest["note"], content_reused_from)

    def _next_version_number(self, batch_id: str, index: dict[str, Any]) -> int:
        highest = max((int(entry["version"]) for entry in index["versions"]), default=0)
        export_dir = self.store.export_dir(batch_id)
        if export_dir.exists():
            for path in export_dir.iterdir():
                if path.is_dir() and path.name.startswith("v"):
                    suffix = path.name[1:]
                    if suffix.isdigit():
                        highest = max(highest, int(suffix))
        return highest + 1

    def _unindexed_dirs(self, batch_id: str, index: dict[str, Any]) -> list[tuple[int, Path]]:
        export_dir = self.store.export_dir(batch_id)
        indexed = {int(entry["version"]) for entry in index["versions"]}
        if not export_dir.exists():
            return []
        found: list[tuple[int, Path]] = []
        for path in export_dir.iterdir():
            if not path.is_dir() or not path.name.startswith("v"):
                continue
            suffix = path.name[1:]
            if suffix.isdigit() and int(suffix) not in indexed:
                found.append((int(suffix), path))
        return sorted(found)

    def _cleanup_incomplete_dirs(self, batch_id: str, index: dict[str, Any]) -> None:
        """删除中断留下的暂存/残缺目录；迁移来的完整版本（含 manifest）原样保留。"""
        export_dir = self.store.export_dir(batch_id)
        if not export_dir.exists():
            return
        indexed = {int(entry["version"]) for entry in index["versions"]}
        for path in list(export_dir.iterdir()):
            if not path.is_dir():
                continue
            if path.name.startswith(".staging-"):
                shutil.rmtree(path)
                continue
            if path.name.startswith("v") and path.name[1:].isdigit():
                number = int(path.name[1:])
                if number not in indexed and not (path / "manifest.json").exists():
                    shutil.rmtree(path)

    def _recover_interrupted(
        self, batch_id: str, index: dict[str, Any], rules_version: int,
        rules_fp: str, source_fp: str, output_fp: str,
    ) -> ExportResult | None:
        """恢复已完整落盘但未登记索引的执行（崩溃发生在写索引之前或之中）。"""
        for number, path in self._unindexed_dirs(batch_id, index):
            manifest_path = path / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = read_json(manifest_path)
            if (
                int(manifest.get("rules_version", -1)) != rules_version
                or manifest.get("rules_fingerprint") != rules_fp
                or manifest.get("source_fingerprint") != source_fp
                or manifest.get("output_fingerprint") != output_fp
            ):
                continue
            final_files = {
                name: sha256_file(path / name)
                for name in sorted(
                    [p.name for p in path.iterdir() if p.is_file() and p.name != "manifest.json"]
                    + ["manifest.json"]
                )
            }
            entry = {
                "version": number,
                "created_at": manifest["created_at"],
                "rules_version": rules_version,
                "rules_fingerprint": rules_fp,
                "source_fingerprint": source_fp,
                "output_fingerprint": output_fp,
                "content_reused_from": manifest.get("content_reused_from"),
                "note": manifest["note"],
                "dir": path.name,
                "files": final_files,
            }
            index["batch_id"] = batch_id
            index["latest"] = max(int(index.get("latest", 0)), number)
            index["versions"].append(entry)
            index["versions"].sort(key=lambda item: int(item["version"]))
            write_json(self.store.export_index(batch_id), index)
            return ExportResult(
                batch_id, number, path, False, rules_version, manifest["note"],
                manifest.get("content_reused_from"),
            )
        return None

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

    def _match_output_version(self, index: dict[str, Any], output_fp: str) -> int | None:
        """在旧版本中找到输出字节完全一致的最近一版（只代表内容相同，不代表身份相同）。"""
        for entry in reversed(index["versions"]):
            if entry["output_fingerprint"] == output_fp:
                return int(entry["version"])
        return None

    def _verify_reused_content(
        self, batch_id: str, index: dict[str, Any], source_version: int,
        files: dict[str, str],
    ) -> None:
        """确认本次新写入的 CSV 与被引用版本逐文件字节一致。"""
        source_dir = self.store.version_dir(batch_id, source_version)
        source_entry = next(
            entry for entry in index["versions"] if int(entry["version"]) == source_version
        )
        for name, expected in files.items():
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
            source_changed=left["source_fingerprint"] != right["source_fingerprint"],
            output_changed=left["output_fingerprint"] != right["output_fingerprint"],
            rules_version_from=int(left["rules_version"]),
            rules_version_to=int(right["rules_version"]),
            rules_fingerprint_from=left["rules_fingerprint"],
            rules_fingerprint_to=right["rules_fingerprint"],
            source_fingerprint_from=left["source_fingerprint"],
            source_fingerprint_to=right["source_fingerprint"],
            output_fingerprint_from=left["output_fingerprint"],
            output_fingerprint_to=right["output_fingerprint"],
            same_execution=version_a == version_b,
            content_reused_from_to=right.get("content_reused_from"),
            added_files=added,
            removed_files=removed,
            changed_files=changed,
        )

    def rule_trail(self, batch_id: str) -> list[RuleRevisionView]:
        """沿规则修订顺序给出差异视图。

        对每个规则修订区分三件事：
        - 配置相同：rules_hash 与此前某修订相同（规则改回旧配置）；
        - 输出相同：执行的公开输出字节与此前某执行相同（content 复用）；
        - 同一次执行：同一修订下重复导出幂等复用，不产生新执行。
        """
        batch = self.batches.load(batch_id)
        index = self._load_index(batch_id)
        executions_by_revision: dict[int, dict[str, Any]] = {}
        for entry in sorted(index["versions"], key=lambda item: int(item["version"])):
            executions_by_revision.setdefault(int(entry["rules_version"]), entry)
        seen_hashes: dict[str, int] = {}
        seen_outputs: dict[str, int] = {}
        views: list[RuleRevisionView] = []
        for revision in batch.history:
            rules_version = int(revision["rules_version"])
            rules_hash = revision["rules_hash"]
            config_same_as = seen_hashes.get(rules_hash)
            execution = executions_by_revision.get(rules_version)
            output_fp = execution["output_fingerprint"] if execution else None
            output_same_as = seen_outputs.get(output_fp) if output_fp is not None else None
            views.append(
                RuleRevisionView(
                    rules_version=rules_version,
                    changed_at=revision["changed_at"],
                    note=revision["note"],
                    rules_hash=rules_hash,
                    config_same_as=config_same_as,
                    execution_version=int(execution["version"]) if execution else None,
                    source_fingerprint=execution["source_fingerprint"] if execution else None,
                    output_fingerprint=output_fp,
                    output_same_as=output_same_as,
                )
            )
            seen_hashes.setdefault(rules_hash, rules_version)
            if output_fp is not None:
                seen_outputs.setdefault(output_fp, rules_version)
        return views
