"""按接收者核对多次交付的联合披露预览。

去标识导出版本（``exports/``）是面向所有接收者的候选公开结果；本模块在其之上
增加「接收者维度」：

- 每个接收者有独立档案与**只增不改**的授权范围修订历史；授权缩小只影响之后的交付，
  历史交付记录原样保留；
- 每次交付形成一份不可变的**对外材料**（``disclosure/materials/``），由冻结的导出版本、
  资料选择、日期精度与来源别名确定性派生；同一份对外材料（字节一致）重复提交/重试
  不会被重复计入披露；
- 预览必须绑定明确的接收者、资料身份与既有交付范围，逐条指出本次记录能够对应到哪些
  既有交付、对应依据是什么，以及合在一起后新增的可关联组合信息；
- 关联依据区分「业务记录键可确认」「同一伪名（受试者级确定关联）」与「缺少依据」，
  来源改名且未提供别名时不得靠猜测补出记录对应关系；
- 规则/政策修订可以禁止**今后**的组合披露，但不改写已经交付的历史；
- 预览生成后若既有交付增加，确认时会被判为过期，必须重新核对；
- 审计说明只保存在内部交付登记中，受限原值（真实编号、敏感片段等）永远不会因为
  「留痕需要」进入对外材料，材料目录整体经过泄露扫描。
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import copy

from crp.audit import PATTERN_CHECKS
from crp.paths import Store
from crp.util import read_csv, read_json, sha256_file, sha256_text, stable_json, write_csv, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


DATE_PRECISION_ORDER = {"year": 0, "month": 1, "day": 2}


def precision_label(precision: str | None) -> str:
    """报告中的精度标注：非日期字段显式标为 ``none``，不留含糊的空值。"""
    return precision if precision is not None else "none"
DATE_RE = re.compile(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?")


def date_precision_of(value: str) -> str | None:
    value = (value or '').strip()
    match = DATE_RE.match(value)
    if not match:
        return None
    if match.group(3):
        return "day"
    if match.group(2):
        return "month"
    return "year"


def truncate_date(value: str, precision: str) -> str:
    value = (value or '').strip()
    if not value:
        return value
    match = DATE_RE.match(value)
    if not match:
        return value
    year, month, day = match.groups()
    if precision == "year":
        return year
    if precision == "month":
        return f"{year}-{month or '01'}"
    return f"{year}-{month or '01'}-{day or '01'}"


class RecipientExistsError(FileExistsError):
    pass


class RecipientNotFoundError(FileNotFoundError):
    pass


class StalePreviewError(RuntimeError):
    """预览生成后既有交付/政策/授权/导出版本发生变化，必须重新核对。"""


class PendingApplicationNotFoundError(FileNotFoundError):
    """待审申请不存在（可能已确认、取消或从未保存）。"""


class DisclosurePolicyError(ValueError):
    pass


def normalize_authorization(scope: dict[str, Any] | None) -> dict[str, Any]:
    """接收者授权范围：来源、伪名受试者、记录键三类约束，省略表示全部允许。"""
    if scope is None or scope == {} or scope.get("mode") == "all":
        return {"mode": "all"}
    normalized: dict[str, Any] = {"mode": "selected"}
    if "sources" in scope:
        if not isinstance(scope["sources"], list) or not scope["sources"]:
            raise ValueError("授权 sources 必须是非空数组")
        normalized["sources"] = [str(item) for item in scope["sources"]]
    if "subjects" in scope:
        if not isinstance(scope["subjects"], list) or not scope["subjects"]:
            raise ValueError("授权 subjects 必须是非空数组")
        normalized["subjects"] = [str(item) for item in scope["subjects"]]
    if "records" in scope:
        if not isinstance(scope["records"], list) or not scope["records"]:
            raise ValueError("授权 records 必须是非空数组")
        records = []
        for item in scope["records"]:
            if not isinstance(item, dict) or "table" not in item:
                raise ValueError("授权 records 每项必须包含 table")
            records.append({str(k): str(v) for k, v in sorted(item.items())})
        normalized["records"] = records
    if len(normalized) == 1:
        raise ValueError("选定授权范围时必须提供 sources、subjects 或 records")
    return normalized


def authorization_allows(authorization: dict[str, Any], table: str,
                         pseudonym: str, record_id: str) -> bool:
    if authorization.get("mode") == "all":
        return True
    if "sources" in authorization and table not in authorization["sources"]:
        return False
    if "subjects" in authorization and pseudonym not in authorization["subjects"]:
        return False
    if "records" in authorization:
        business_key = record_id.split(":", 1)[1] if ":" in record_id else record_id
        matched = any(
            record.get("table") == table
            and all(
                record.get(key) == value
                for key, value in record.items() if key not in {"table"}
            )
            and ("record_id" not in record or record["record_id"] == business_key)
            for record in authorization["records"]
        )
        if not matched:
            return False
    return True


@dataclass
class Recipient:
    batch_id: str
    recipient_id: str
    name: str
    created_at: str
    authorization_revision: int = 1
    authorization: list[dict[str, Any]] = field(default_factory=list)

    def current_authorization(self) -> dict[str, Any]:
        return self.authorization[-1]["scope"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "recipient_id": self.recipient_id,
            "name": self.name,
            "created_at": self.created_at,
            "authorization_revision": self.authorization_revision,
            "authorization": self.authorization,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Recipient":
        return cls(
            batch_id=raw["batch_id"],
            recipient_id=raw["recipient_id"],
            name=raw.get("name", raw["recipient_id"]),
            created_at=raw["created_at"],
            authorization_revision=int(raw.get("authorization_revision", 1)),
            authorization=list(raw.get("authorization", [])),
        )


class RecipientStore:
    def __init__(self, store: Store) -> None:
        self.store = store

    def register(self, batch_id: str, recipient_id: str, name: str = "",
                 authorization: dict[str, Any] | None = None,
                 note: str = "初始授权") -> Recipient:
        target = self.store.recipient_file(batch_id, recipient_id)
        if target.exists():
            raise RecipientExistsError(f"接收者已登记: {recipient_id}")
        now = _now()
        scope = normalize_authorization(authorization)
        recipient = Recipient(
            batch_id=batch_id,
            recipient_id=recipient_id,
            name=name or recipient_id,
            created_at=now,
            authorization_revision=1,
            authorization=[{
                "revision": 1,
                "changed_at": now,
                "note": note,
                "scope": scope,
            }],
        )
        write_json(target, recipient.to_dict())
        self._index(batch_id, add=recipient_id)
        return recipient

    def load(self, batch_id: str, recipient_id: str) -> Recipient:
        target = self.store.recipient_file(batch_id, recipient_id)
        if not target.exists():
            raise RecipientNotFoundError(f"接收者未登记: {recipient_id}")
        return Recipient.from_dict(read_json(target))

    def list(self, batch_id: str) -> list[str]:
        index_path = self.store.recipients_index(batch_id)
        if not index_path.exists():
            return []
        return list(read_json(index_path).get("recipients", []))

    def narrow_authorization(self, batch_id: str, recipient_id: str,
                             scope: dict[str, Any], note: str) -> Recipient:
        """追加一条授权修订（通常用于缩小范围）；历史修订不删除不改写。"""
        recipient = self.load(batch_id, recipient_id)
        normalized = normalize_authorization(scope)
        now = _now()
        recipient.authorization_revision += 1
        recipient.authorization.append({
            "revision": recipient.authorization_revision,
            "changed_at": now,
            "note": note,
            "scope": normalized,
        })
        write_json(self.store.recipient_file(batch_id, recipient_id), recipient.to_dict())
        return recipient

    def save(self, recipient: Recipient) -> None:
        write_json(
            self.store.recipient_file(recipient.batch_id, recipient.recipient_id),
            recipient.to_dict(),
        )

    def _index(self, batch_id: str, add: str) -> None:
        path = self.store.recipients_index(batch_id)
        payload = read_json(path) if path.exists() else {"batch_id": batch_id, "recipients": []}
        if add not in payload["recipients"]:
            payload["recipients"].append(add)
        write_json(path, payload)


class DisclosurePolicy:
    """只增不改的披露政策：禁止今后新增的字段或字段组合。"""

    def __init__(self, store: Store, batch_id: str) -> None:
        self.store = store
        self.batch_id = batch_id

    def load(self) -> dict[str, Any]:
        path = self.store.policy_file(self.batch_id)
        if not path.exists():
            return {"batch_id": self.batch_id, "revision": 0, "revisions": []}
        return read_json(path)

    def current(self) -> dict[str, Any]:
        payload = self.load()
        revisions = payload.get("revisions", [])
        return revisions[-1]["rules"] if revisions else {"forbid_fields": [], "forbid_combinations": []}

    def revise(self, rules: dict[str, Any], note: str) -> dict[str, Any]:
        normalized = self._normalize_rules(rules)
        payload = self.load()
        next_revision = int(payload.get("revision", 0)) + 1
        revision = {
            "revision": next_revision,
            "changed_at": _now(),
            "note": note,
            "rules": normalized,
        }
        payload["batch_id"] = self.batch_id
        payload["revision"] = next_revision
        payload.setdefault("revisions", []).append(revision)
        write_json(self.store.policy_file(self.batch_id), payload)
        return revision

    @staticmethod
    def _normalize_rules(rules: dict[str, Any]) -> dict[str, Any]:
        forbid_fields = rules.get("forbid_fields", [])
        if not isinstance(forbid_fields, list):
            raise DisclosurePolicyError("forbid_fields 必须是数组")
        combinations = rules.get("forbid_combinations", [])
        if not isinstance(combinations, list):
            raise DisclosurePolicyError("forbid_combinations 必须是数组")
        normalized_combinations = []
        for combo in combinations:
            if not isinstance(combo, dict) or not combo.get("fields"):
                raise DisclosurePolicyError("forbid_combinations 每项必须声明 fields")
            fields = [str(item) for item in combo["fields"]]
            if len(set(fields)) < 2:
                raise DisclosurePolicyError("禁止组合至少包含两个不同字段")
            entry = {"fields": sorted(fields)}
            if combo.get("sources"):
                entry["sources"] = sorted(str(item) for item in combo["sources"])
            normalized_combinations.append(entry)
        return {
            "forbid_fields": sorted({str(item) for item in forbid_fields}),
            "forbid_combinations": normalized_combinations,
        }


@dataclass(frozen=True)
class MaterialSpec:
    """一次拟交付对外材料的完整身份描述。

    - ``version``：冻结的去标识导出版本（资料身份的基础）；
    - ``records``：从该版本选取的记录，每项 {table, record_id}；
    - ``date_precision``：本次统一公开的日期精度（year/month/day）；
    - ``source_aliases``：本次来源名到既有交付来源名的**显式确认**别名映射，
      来源改名时只有在此声明才视为可确认关联；
    - ``include_fields``：每张表允许包含的列白名单（省略为全部列）。
    """

    version: int
    records: tuple[tuple[str, str], ...]
    date_precision: str = "day"
    source_aliases: dict[str, str] = field(default_factory=dict)
    source_names: dict[str, str] = field(default_factory=dict)
    include_fields: dict[str, list[str]] = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = {
            "version": self.version,
            "records": [list(item) for item in self.records],
            "date_precision": self.date_precision,
            "source_aliases": dict(sorted(self.source_aliases.items())),
            "source_names": dict(sorted(self.source_names.items())),
            "include_fields": {
                table: sorted(names) for table, names in sorted(self.include_fields.items())
            },
        }
        return sha256_text(stable_json(payload))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "MaterialSpec":
        records = tuple(
            (str(item["table"]), str(item["record_id"]))
            for item in raw.get("records", [])
        )
        precision = raw.get("date_precision", "day")
        if precision not in DATE_PRECISION_ORDER:
            raise ValueError(f"未知日期精度: {precision}")
        return cls(
            version=int(raw["version"]),
            records=records,
            date_precision=precision,
            source_aliases={str(k): str(v) for k, v in raw.get("source_aliases", {}).items()},
            source_names={str(k): str(v) for k, v in raw.get("source_names", {}).items()},
            include_fields={
                str(table): [str(name) for name in names]
                for table, names in raw.get("include_fields", {}).items()
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "records": [{"table": table, "record_id": record_id}
                        for table, record_id in self.records],
            "date_precision": self.date_precision,
            "source_aliases": dict(self.source_aliases),
            "include_fields": {table: list(names) for table, names in self.include_fields.items()},
        }


@dataclass(frozen=True)
class MaterialBuildResult:
    material_id: str
    material_dir: Path
    reused: bool


class MaterialBuilder:
    """依据冻结导出版本裁剪对外材料；材料中只出现伪名与去标识后的值。"""

    DATE_FIELDS_BY_HINT = ("date", "at", "_at")

    def __init__(self, store: Store) -> None:
        self.store = store

    def material_id(self, batch_id: str, spec: MaterialSpec) -> str:
        return "M" + spec.fingerprint()[:16].upper()

    def build(self, batch_id: str, spec: MaterialSpec) -> MaterialBuildResult:
        material_id = self.material_id(batch_id, spec)
        target_dir = self.store.material_dir(batch_id, material_id)
        if target_dir.exists():
            self._verify_existing(batch_id, material_id, target_dir)
            return MaterialBuildResult(material_id, target_dir, True)
        version_dir = self.store.version_dir(batch_id, spec.version)
        manifest = read_json(version_dir / "manifest.json")
        wanted: dict[str, set[str]] = {}
        for table, record_id in spec.records:
            wanted.setdefault(table, set()).add(record_id)
        files: dict[str, str] = {}
        for table in sorted(wanted):
            rows = read_csv(version_dir / f"{table}.csv")
            trace_rows = self._trace_index(version_dir, table)
            display_name = spec.source_names.get(table, table)
            allowed_columns = spec.include_fields.get(table)
            selected: list[dict[str, str]] = []
            # 通过 rule_trace 把输出行映射回业务记录键，保持记录身份可核对。
            for output_row_number, trace in enumerate(trace_rows, start=2):
                if trace["record_id"] not in wanted[table]:
                    continue
                row = rows[int(trace["output_row"]) - 2]
                if allowed_columns is not None:
                    row = {name: row.get(name, "") for name in allowed_columns}
                row = self._apply_precision(table, row, spec.date_precision, manifest)
                selected.append(row)
            columns = self._columns(table, rows, spec, manifest)
            path = target_dir / f"{display_name}.csv"
            write_csv(path, selected, columns)
            files[f"{display_name}.csv"] = sha256_file(path)
        trace_text = ""
        for table in sorted(wanted):
            trace_text += self._material_trace(table, [
                trace for trace in self._trace_index(version_dir, table)
                if trace["record_id"] in wanted[table]
            ], spec)
        trace_path = target_dir / "material_trace.csv"
        # 去重：多来源时只保留一次表头。
        lines = trace_text.splitlines(keepends=True)
        if lines:
            header = lines[0]
            trace_text = header + "".join(line for line in lines[1:] if line != header)
        trace_path.write_text(trace_text, encoding="utf-8")
        if trace_path.exists():
            files["material_trace.csv"] = sha256_file(trace_path)
        material_manifest = {
            "material_id": material_id,
            "batch_id": batch_id,
            "created_at": _now(),
            # 本次实际公开精度在材料层显式落盘，与 material_trace 中的逐记录标注一致。
            "date_precision": spec.date_precision,
            "spec": spec.to_dict(),
            "spec_fingerprint": spec.fingerprint(),
            "source_version": spec.version,
            "files": dict(sorted(files.items())),
        }
        write_json(target_dir / "manifest.json", material_manifest)
        findings = scan_material_leaks(self.store, batch_id, material_id)
        if findings:
            raise RuntimeError("对外材料泄露自检失败: " + "; ".join(findings))
        return MaterialBuildResult(material_id, target_dir, False)

    def _columns(self, table: str, rows: list[dict[str, str]], spec: MaterialSpec,
                 version_manifest: dict[str, Any]) -> list[str]:
        if not rows:
            raw_columns = self._version_columns(table, spec.version, version_manifest)
        else:
            raw_columns = list(rows[0].keys())
        allowed = spec.include_fields.get(table)
        return [name for name in raw_columns if allowed is None or name in allowed]

    def _version_columns(self, table: str, version: int, version_manifest: dict[str, Any]) -> list[str]:
        # 空表情况下从版本 CSV 表头读取列。
        path = self.store.version_dir(version_manifest["batch_id"], version) / f"{table}.csv"
        with path.open("r", encoding="utf-8-sig", newline="") as fh:
            return next(csv.reader(fh))

    @staticmethod
    def _trace_index(version_dir: Path, table: str) -> list[dict[str, str]]:
        trace_path = version_dir / "rule_trace.csv"
        return [row for row in read_csv(trace_path) if row["table"] == table]

    def _apply_precision(self, table: str, row: dict[str, str], precision: str,
                         version_manifest: dict[str, Any]) -> dict[str, str]:
        if precision == "day":
            return row
        for name, value in list(row.items()):
            if date_precision_of(value) is not None and \
                    DATE_PRECISION_ORDER[date_precision_of(value)] > DATE_PRECISION_ORDER[precision]:
                row[name] = truncate_date(value, precision)
        return row

    @staticmethod
    def _material_trace(table: str, trace_rows: list[dict[str, str]], spec: MaterialSpec) -> str:
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([
            "table", "source_name", "record_id", "subject_id", "source_version",
            "source_output_row", "date_precision", "source_alias",
        ])
        for trace in trace_rows:
            writer.writerow([
                table,
                spec.source_names.get(table, table),
                trace["record_id"],
                trace["subject_id"],
                spec.version,
                trace["output_row"],
                spec.date_precision,
                spec.source_aliases.get(table, ""),
            ])
        return buffer.getvalue()

    @staticmethod
    def _verify_existing(batch_id: str, material_id: str, material_dir: Path) -> None:
        manifest = read_json(material_dir / "manifest.json")
        for name, expected in manifest["files"].items():
            actual = sha256_file(material_dir / name)
            if actual != expected:
                raise RuntimeError(f"对外材料被改动，拒绝复用: {material_dir / name}")


def scan_material_leaks(store: Store, batch_id: str, material_id: str) -> list[str]:
    """对外材料目录整体扫描：真实编号、人工敏感片段、内置模式与禁止文件名。"""
    material_dir = store.material_dir(batch_id, material_id)
    mapping_path = store.private_dir(batch_id) / "mapping.json"
    raw_ids: set[str] = set()
    if mapping_path.exists():
        raw_ids.update(read_json(mapping_path).get("pseudonyms", {}).keys())
    manual_phrases: set[str] = set()
    manual_path = store.raw_dir(batch_id) / "manual_sensitive.json"
    if manual_path.exists():
        payload = read_json(manual_path)
        entries = payload.get("entries", payload) if isinstance(payload, dict) else payload
        for phrases in entries.values():
            manual_phrases.update(phrase for phrase in phrases if phrase)
    findings: list[str] = []
    for path in sorted(material_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"mapping.json", "secret"}:
            findings.append(f"对外材料包含禁止文件: {path.name}")
        if path.suffix != ".csv":
            continue
        for row_number, row in enumerate(read_csv(path), start=2):
            joined = " ".join(row.values())
            for raw_id in raw_ids:
                if raw_id and raw_id in joined:
                    findings.append(f"{path.name}:{row_number} 出现真实受试者号 {raw_id}")
            for phrase in manual_phrases:
                if phrase in joined:
                    findings.append(f"{path.name}:{row_number} 出现人工敏感片段 {phrase!r}")
            for pattern_name, pattern in PATTERN_CHECKS.items():
                match = pattern.search(joined)
                if match:
                    findings.append(f"{path.name}:{row_number} 命中未脱敏模式 {pattern_name}: {match.group(0)}")
    return findings


class DeliveryRegistry:
    """每个接收者一份只增不改的交付登记（内部文件，不随材料分发）。"""

    def __init__(self, store: Store) -> None:
        self.store = store

    def load(self, batch_id: str, recipient_id: str) -> dict[str, Any]:
        path = self.store.deliveries_index(batch_id, recipient_id)
        if not path.exists():
            return {"batch_id": batch_id, "recipient_id": recipient_id, "deliveries": []}
        return read_json(path)

    def deliveries(self, batch_id: str, recipient_id: str) -> list[dict[str, Any]]:
        return list(self.load(batch_id, recipient_id).get("deliveries", []))

    def find_by_material(self, batch_id: str, recipient_id: str,
                         material_id: str) -> dict[str, Any] | None:
        for delivery in self.deliveries(batch_id, recipient_id):
            if delivery["material_id"] == material_id:
                return delivery
        return None

    def record(self, batch_id: str, recipient_id: str, material_id: str,
               spec: MaterialSpec, note: str, audit_note: str,
               authorization_revision: int, policy_revision: int,
               new_disclosures: list[dict[str, Any]]) -> dict[str, Any]:
        payload = self.load(batch_id, recipient_id)
        existing = next(
            (item for item in payload["deliveries"] if item["material_id"] == material_id),
            None,
        )
        if existing is not None:
            # 同一份对外材料（字节级同一材料）重复提交/重试：不重复计入披露。
            existing.setdefault("attempts", 1)
            existing["attempts"] += 1
            existing.setdefault("retry_notes", []).append(note)
            write_json(self.store.deliveries_index(batch_id, recipient_id), payload)
            return existing
        deliveries = payload.get("deliveries", [])
        delivery_id = f"D{len(deliveries) + 1:03d}"
        entry = {
            "delivery_id": delivery_id,
            "created_at": _now(),
            "material_id": material_id,
            # 交付历史显式记录本次实际公开精度；后续更细精度的新交付不回写此条目。
            "date_precision": spec.date_precision,
            "note": note,
            # 审计说明仅保存在内部登记，绝不写入对外材料目录。
            "audit_note": audit_note,
            "authorization_revision": authorization_revision,
            "policy_revision": policy_revision,
            "spec": spec.to_dict(),
            "new_disclosures": new_disclosures,
            "attempts": 1,
        }
        deliveries.append(entry)
        payload["batch_id"] = batch_id
        payload["recipient_id"] = recipient_id
        payload["deliveries"] = deliveries
        write_json(self.store.deliveries_index(batch_id, recipient_id), payload)
        return entry


class PendingApplicationStore:
    """每个接收者一份只在「待审期间」存在的申请登记；确认/取消后移除。

    待审申请按接收者隔离存放（``disclosure/<batch>/pending/<recipient>/``）：

    - 预览生成时落盘，关闭流程、稍后重开仍可继续核对，不依赖内存状态；
    - 取消（cancel 方案）不形成任何对外材料，申请一并移除，不留登记；
    - 确认形成交付后移除；同一接收方此后再预览时它作为**既有交付**被计入；
    - 不同接收者的待审申请互不可见，历史与联合核对严格隔离。
    """

    def __init__(self, store: Store) -> None:
        self.store = store

    def save(self, batch_id: str, recipient_id: str, application_id: str,
             request: dict[str, Any], note: str = "") -> dict[str, Any]:
        entry = {
            "application_id": application_id,
            "batch_id": batch_id,
            "recipient_id": recipient_id,
            "created_at": _now(),
            "note": note,
            # 与联合预览记录同一结构：申请级日期精度显式落盘，
            # 未声明精度的申请明确视为 "day"，不依赖读取方补默认值。
            "date_precision": str(request.get("date_precision", "day")),
            "request": self._canonical_request(request),
        }
        write_json(
            self.store.pending_file(batch_id, recipient_id, application_id), entry,
        )
        return entry

    @staticmethod
    def entry_date_precision(entry: dict[str, Any]) -> str:
        """待审申请的实际日期精度；兼容早期未落盘该键的登记。"""
        precision = entry.get("date_precision")
        if precision is None:
            precision = entry.get("request", {}).get("date_precision", "day")
        return str(precision)

    def load(self, batch_id: str, recipient_id: str, application_id: str) -> dict[str, Any]:
        path = self.store.pending_file(batch_id, recipient_id, application_id)
        if not path.exists():
            raise PendingApplicationNotFoundError(f"待审申请不存在: {application_id}")
        return read_json(path)

    def list(self, batch_id: str, recipient_id: str,
             exclude: str | None = None) -> list[dict[str, Any]]:
        folder = self.store.pending_dir(batch_id, recipient_id)
        if not folder.exists():
            return []
        entries = []
        for path in sorted(folder.glob("*.json")):
            entry = read_json(path)
            if exclude is not None and entry["application_id"] == exclude:
                continue
            entries.append(entry)
        return entries

    def remove(self, batch_id: str, recipient_id: str, application_id: str) -> bool:
        path = self.store.pending_file(batch_id, recipient_id, application_id)
        if not path.exists():
            return False
        path.unlink()
        return True

    @staticmethod
    def _canonical_request(request: dict[str, Any]) -> dict[str, Any]:
        """剔除仅用于存储控制、不构成资料身份的键后规范化申请。"""
        skip = {"application_id"}
        return {str(key): value for key, value in sorted(request.items()) if key not in skip}

    def request_fingerprint(self, entry: dict[str, Any]) -> str:
        return sha256_text(stable_json(entry["request"]))


@dataclass(frozen=True)
class RecordLink:
    """一条本次记录与某份既有交付材料中记录的对应关系。

    basis:
    - ``record_key``：业务记录键（与伪名）可确认的同一记录对应，支持显式来源别名；
    - ``subject``：业务记录键无法对上，但同一稳定伪名可确认的受试者级关联；
    - ``unconfirmed``：来源改名且没有显式别名等依据，记录级对应只能列为「缺少依据」，
      不参与新增组合的计算。
    """

    delivery_id: str
    material_id: str
    source_name: str
    record_id: str
    basis: str


@dataclass(frozen=True)
class FieldDisclosure:
    """单个字段的披露标注。

    - ``source_precision``：来源资料（冻结导出版本）中该值的日期精度；
    - ``date_precision``：本次实际公开的日期精度（来源精度按申请上限压低后的结果）。
      两者都是 ``None`` 表示该字段不是日期字段，报告中显式标注为 ``none``。
    """

    field: str
    date_precision: str | None
    newly_linkable: bool
    precision_upgrade_from: str | None
    first_delivered_by: str | None
    source_precision: str | None = None


@dataclass
class RecordPreview:
    table: str
    source_name: str
    record_id: str
    pseudonym: str
    authorized: bool
    links: list[RecordLink] = field(default_factory=list)
    fields: list[FieldDisclosure] = field(default_factory=list)
    new_combinations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "source_name": self.source_name,
            "record_id": self.record_id,
            "pseudonym": self.pseudonym,
            "authorized": self.authorized,
            "links": [
                {
                    "delivery_id": link.delivery_id,
                    "material_id": link.material_id,
                    "source_name": link.source_name,
                    "record_id": link.record_id,
                    "basis": link.basis,
                }
                for link in self.links
            ],
            "fields": [
                {
                    "field": item.field,
                    "date_precision": precision_label(item.date_precision),
                    "source_precision": precision_label(item.source_precision),
                    "newly_linkable": item.newly_linkable,
                    "precision_upgrade_from": item.precision_upgrade_from,
                    "first_delivered_by": item.first_delivered_by,
                }
                for item in self.fields
            ],
            "new_combinations": self.new_combinations,
        }


@dataclass
class PlanPreview:
    plan: str
    description: str
    rule_revision: int
    included_records: list[RecordPreview]
    excluded_records: list[RecordPreview]
    new_disclosures: list[dict[str, Any]]
    blocked: list[dict[str, Any]]
    material_spec: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan,
            "description": self.description,
            "rule_revision": self.rule_revision,
            "included_records": [item.to_dict() for item in self.included_records],
            "excluded_records": [item.to_dict() for item in self.excluded_records],
            "new_disclosures": self.new_disclosures,
            "blocked": self.blocked,
            "material_spec": self.material_spec,
        }


class DisclosurePlanner:
    """生成按接收者核对既有交付的联合披露预览，并据此确认形成对外材料。"""

    PLAN_LABELS = {
        "as_requested": "按本次申请全部交付",
        "allow_only": "仅交付当前授权与政策允许的部分",
        "reduce_precision": "降低本次公开精度（日期降至月）",
        "cancel": "取消本次交付",
    }

    def __init__(self, store: Store) -> None:
        self.store = store
        self.recipients = RecipientStore(store)
        self.registry = DeliveryRegistry(store)
        self.pending = PendingApplicationStore(store)
        self.builder = MaterialBuilder(store)

    # ---- 既有交付快照 -------------------------------------------------

    def snapshot(self, batch_id: str, recipient_id: str,
                 exclude_application_id: str | None = None) -> str:
        recipient = self.recipients.load(batch_id, recipient_id)
        policy = DisclosurePolicy(self.store, batch_id).load()
        index_path = self.store.export_index(batch_id)
        index = read_json(index_path) if index_path.exists() else {}
        deliveries = self.registry.deliveries(batch_id, recipient_id)
        summary = {
            "authorization_revision": recipient.authorization_revision,
            "authorization": recipient.authorization,
            "policy_revision": policy.get("revision", 0),
            "exports": [
                {"version": entry["version"], "output_fingerprint": entry["output_fingerprint"]}
                for entry in index.get("versions", [])
            ],
            "deliveries": [
                {
                    "delivery_id": item["delivery_id"],
                    "material_id": item["material_id"],
                    "spec_fingerprint": item["spec_fingerprint"]
                    if "spec_fingerprint" in item else None,
                }
                for item in deliveries
            ],
            # 同一接收方同时待审的其他申请也是联合预览的一部分：任一份申请变化
            # （新建、修改、确认、取消）都会使旧预览快照过期。
            "pending_applications": [
                {
                    "application_id": item["application_id"],
                    "request_fingerprint": self.pending.request_fingerprint(item),
                }
                for item in self.pending.list(batch_id, recipient_id,
                                              exclude=exclude_application_id)
            ],
        }
        return sha256_text(stable_json(summary))

    def _prior_records(self, batch_id: str, recipient_id: str) -> list[dict[str, Any]]:
        prior: list[dict[str, Any]] = []
        for delivery in self.registry.deliveries(batch_id, recipient_id):
            material_dir = self.store.material_dir(batch_id, delivery["material_id"])
            trace_path = material_dir / "material_trace.csv"
            if not trace_path.exists():
                continue
            rows_by_source: dict[str, list[dict[str, str]]] = {}
            for trace in read_csv(trace_path):
                source_name = trace.get("source_name") or trace["table"]
                path = material_dir / f"{source_name}.csv"
                rows = rows_by_source.setdefault(source_name, read_csv(path) if path.exists() else [])
                index = int(trace["source_output_row"]) - 2
                row = rows[index] if 0 <= index < len(rows) else {}
                prior.append({
                    "delivery_id": delivery["delivery_id"],
                    "material_id": delivery["material_id"],
                    "table": trace["table"],
                    "source_name": source_name,
                    "record_id": trace["record_id"],
                    "pseudonym": trace["subject_id"],
                    "fields": set(row.keys()),
                    "values": dict(row),
                    "date_precision": trace.get("date_precision", "day"),
                    "status": "delivered",
                    "application_id": None,
                })
        return prior

    def _peer_pending_records(self, batch_id: str, recipient_id: str,
                              exclude_application_id: str | None,
                              precision_cap: str) -> list[dict[str, Any]]:
        """同一接收方其他**待审**申请中拟交付的记录，按各自申请精度归一。

        这些记录尚未实际交付，但联合预览必须把它们视为本次申请落地后
        「同一接收者已经能够关联到」的内容；标记为 ``status=pending``，
        与真正的既有交付（``status=delivered``）区分开。
        """
        peers: list[dict[str, Any]] = []
        for entry in self.pending.list(batch_id, recipient_id, exclude=exclude_application_id):
            request = entry["request"]
            requested_precision = self.pending.entry_date_precision(entry)
            effective_precision = requested_precision
            if DATE_PRECISION_ORDER[effective_precision] > DATE_PRECISION_ORDER[precision_cap]:
                effective_precision = precision_cap
            for record in self._requested_records(batch_id, request):
                values = {}
                fields = []
                for field_name in record["fields"]:
                    value = record["values"].get(field_name, "")
                    field_precision = date_precision_of(value)
                    if field_precision is not None \
                            and DATE_PRECISION_ORDER[field_precision] > DATE_PRECISION_ORDER[effective_precision]:
                        value = truncate_date(value, effective_precision)
                    fields.append(field_name)
                    values[field_name] = value
                peers.append({
                    "delivery_id": f"PENDING:{entry['application_id']}",
                    "material_id": None,
                    "table": record["table"],
                    "source_name": record["source_name"],
                    "record_id": record["record_id"],
                    "pseudonym": record["pseudonym"],
                    "fields": set(fields),
                    "values": values,
                    "date_precision": effective_precision,
                    "status": "pending",
                    "application_id": entry["application_id"],
                })
        return peers

    # ---- 本次申请记录 -------------------------------------------------

    def _requested_records(self, batch_id: str, request: dict[str, Any]) -> list[dict[str, Any]]:
        version = int(request["version"])
        version_dir = self.store.version_dir(batch_id, version)
        wanted = request.get("records")
        wanted_keys = None
        if wanted:
            wanted_keys = {}
            for item in wanted:
                record_id = item["record_id"]
                wanted_keys.setdefault(item["table"], set()).add(record_id)
        source_names = {str(k): str(v) for k, v in request.get("source_names", {}).items()}
        source_aliases = {str(k): str(v) for k, v in request.get("source_aliases", {}).items()}
        requested: list[dict[str, Any]] = []
        for trace_path_table in [p for p in [version_dir / "rule_trace.csv"]]:
            traces = read_csv(trace_path_table)
        tables = sorted({row["table"] for row in traces})
        for table in tables:
            rows = read_csv(version_dir / f"{table}.csv")
            for trace in traces:
                if trace["table"] != table:
                    continue
                if wanted_keys is not None and trace["record_id"] not in wanted_keys.get(table, set()):
                    continue
                row = rows[int(trace["output_row"]) - 2]
                requested.append({
                    "table": table,
                    "source_name": source_names.get(table, table),
                    "source_alias": source_aliases.get(table),
                    "record_id": trace["record_id"],
                    "pseudonym": trace["subject_id"],
                    "values": dict(row),
                    "fields": list(row.keys()),
                    "rules_version": int(trace["rules_version"]),
                })
        return requested

    # ---- 关联判定 -----------------------------------------------------

    def _links_for(self, record: dict[str, Any], prior: list[dict[str, Any]]) -> tuple[list[RecordLink], list[RecordLink]]:
        confirmed: list[RecordLink] = []
        unconfirmed: list[RecordLink] = []
        current_source = record["source_name"]
        alias = record.get("source_alias")
        for item in prior:
            prior_source = item["source_name"]
            same_source_identity = prior_source == current_source or prior_source == alias
            if item["pseudonym"] == record["pseudonym"] and item["record_id"] == record["record_id"]:
                if same_source_identity:
                    confirmed.append(RecordLink(
                        item["delivery_id"], item["material_id"], prior_source,
                        item["record_id"], "record_key"))
                else:
                    # 记录键相同但来源改名且未提供显式别名：记录级对应缺少依据。
                    unconfirmed.append(RecordLink(
                        item["delivery_id"], item["material_id"], prior_source,
                        item["record_id"], "unconfirmed"))
            elif item["pseudonym"] == record["pseudonym"]:
                confirmed.append(RecordLink(
                    item["delivery_id"], item["material_id"], prior_source,
                    item["record_id"], "subject"))
        # 去重（同一份材料可能被重试，但登记层已去重；这里按交付+记录键+依据再保一层）。
        def _dedupe(links: list[RecordLink]) -> list[RecordLink]:
            seen = set()
            result = []
            for link in links:
                key = (link.delivery_id, link.source_name, link.record_id, link.basis)
                if key not in seen:
                    seen.add(key)
                    result.append(link)
            return result
        return _dedupe(confirmed), _dedupe(unconfirmed)

    # ---- 预览 ---------------------------------------------------------

    def preview(self, batch_id: str, recipient_id: str,
                request: dict[str, Any], save: bool = False) -> dict[str, Any]:
        """生成联合披露预览。

        ``request`` 可包含 ``application_id``：带申请号的预览落盘为该接收者的
        **待审申请**，同一接收方其他待审申请（本申请除外）一并进入联合核对，
        关闭后重开仍在；不带申请号时为不落盘的临时预览，行为与旧版一致。
        """
        recipient = self.recipients.load(batch_id, recipient_id)
        policy_payload = DisclosurePolicy(self.store, batch_id).load()
        policy_revision = int(policy_payload.get("revision", 0))
        policy_rules = policy_payload["revisions"][-1]["rules"] if policy_payload.get("revisions") else {
            "forbid_fields": [], "forbid_combinations": [],
        }
        authorization = recipient.current_authorization()
        application_id = request.get("application_id")
        if save and not application_id:
            raise ValueError("保存待审申请时必须提供 application_id")
        # 本次申请声明的日期精度即实际公开精度的上限；未声明视为 "day"。
        request_cap = str(request.get("date_precision", "day"))
        if request_cap not in DATE_PRECISION_ORDER:
            raise ValueError(f"未知日期精度: {request_cap}")
        # 快照口径与确认时一致：待审清单不包含本申请自身（本申请身份由
        # 待审登记与预览绑定核对，其变化不通过快照判定）。
        snapshot = self.snapshot(
            batch_id, recipient_id,
            exclude_application_id=str(application_id) if application_id else None,
        )
        if application_id:
            self.pending.save(batch_id, recipient_id, str(application_id), request,
                              note=str(request.get("note", "")))
        requested = self._requested_records(batch_id, request)
        prior = self._prior_records(batch_id, recipient_id)
        peers_day = self._peer_pending_records(
            batch_id, recipient_id,
            exclude_application_id=str(application_id) if application_id else None,
            precision_cap="day",
        )
        joint_day = prior + peers_day

        previews: list[RecordPreview] = []
        for record in requested:
            links, unconfirmed = self._links_for(record, joint_day)
            allowed = authorization_allows(
                authorization, record["table"], record["pseudonym"], record["record_id"]
            )
            preview = RecordPreview(
                table=record["table"],
                source_name=record["source_name"],
                record_id=record["record_id"],
                pseudonym=record["pseudonym"],
                authorized=allowed,
                links=links + unconfirmed,
            )
            # 受试者维度的既往字段史：只统计可确认关联（record_key/subject）。
            subject_history = self._subject_field_history(joint_day, record["pseudonym"])
            record_history = self._record_field_history(links, prior)
            for field_name in record["fields"]:
                value = record["values"].get(field_name, "")
                prior_subject = subject_history.get(field_name)
                prior_record = record_history.get(field_name)
                first_by = (prior_record or prior_subject or {}).get("delivery_id") if (prior_record or prior_subject) else None
                upgrade_from = None
                # 来源精度按本申请实际上限压低后，才是本次真正公开的精度；
                # 是否新增/升级都与既往实际交付精度比较，不看来源原始精度。
                source_precision = date_precision_of(value)
                precision = source_precision
                if precision is not None and \
                        DATE_PRECISION_ORDER[precision] > DATE_PRECISION_ORDER[request_cap]:
                    precision = request_cap
                if precision is not None and prior_subject is not None:
                    prior_precision = prior_subject.get("precision") or "day"
                    if DATE_PRECISION_ORDER[precision] > DATE_PRECISION_ORDER[prior_precision]:
                        upgrade_from = prior_precision
                newly = prior_subject is None or upgrade_from is not None
                preview.fields.append(FieldDisclosure(
                    field=field_name,
                    date_precision=precision,
                    newly_linkable=newly,
                    precision_upgrade_from=upgrade_from,
                    first_delivered_by=first_by,
                    source_precision=source_precision,
                ))
            preview.new_combinations = self._new_combinations(record, links, joint_day, request_cap)
            previews.append(preview)

        plans = {}
        for plan_name in ("as_requested", "allow_only", "reduce_precision", "cancel"):
            plans[plan_name] = self._evaluate_plan(
                # 每个方案在独立副本上评估：降精度等调整不会污染其他方案的口径。
                plan_name, copy.deepcopy(previews), request, policy_rules, authorization,
                policy_revision, prior, peers_day, batch_id, recipient_id,
            ).to_dict()

        return {
            "batch_id": batch_id,
            "recipient_id": recipient_id,
            "recipient_name": recipient.name,
            "application_id": str(application_id) if application_id else None,
            "saved": bool(application_id),
            "authorization_revision": recipient.authorization_revision,
            "policy_revision": policy_revision,
            "request_version": int(request["version"]),
            "snapshot": snapshot,
            "peer_pending": [
                {
                    "application_id": item["application_id"],
                    "date_precision": self.pending.entry_date_precision(item),
                    "records": [
                        {"table": record["table"], "record_id": record["record_id"]}
                        for record in peers_day
                        if record["application_id"] == item["application_id"]
                    ],
                }
                for item in self.pending.list(
                    batch_id, recipient_id,
                    exclude=str(application_id) if application_id else None,
                )
            ],
            "prior_deliveries": [
                {
                    "delivery_id": item["delivery_id"],
                    "material_id": item["material_id"],
                    "created_at": item["created_at"],
                }
                for item in self.registry.deliveries(batch_id, recipient_id)
            ],
            "plans": plans,
        }

    @staticmethod
    def _subject_field_history(prior: list[dict[str, Any]], pseudonym: str) -> dict[str, dict[str, Any]]:
        history: dict[str, dict[str, Any]] = {}
        for item in prior:
            if item["pseudonym"] != pseudonym:
                continue
            for field_name in item["fields"]:
                value = item["values"].get(field_name, "")
                precision = date_precision_of(value)
                existing = history.get(field_name)
                if existing is None or (
                    precision is not None
                    and DATE_PRECISION_ORDER[precision] > DATE_PRECISION_ORDER[existing.get("precision") or "year"]
                ):
                    history[field_name] = {
                        "delivery_id": item["delivery_id"],
                        "record_id": item["record_id"],
                        "source_name": item["source_name"],
                        "precision": precision,
                    }
        return history

    @staticmethod
    def _record_field_history(links: list[RecordLink],
                              prior: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        keys = {
            (link.delivery_id, link.record_id)
            for link in links if link.basis == "record_key"
        }
        history: dict[str, dict[str, Any]] = {}
        for item in prior:
            if (item["delivery_id"], item["record_id"]) not in keys:
                continue
            for field_name in item["fields"]:
                history.setdefault(field_name, {
                    "delivery_id": item["delivery_id"],
                    "record_id": item["record_id"],
                    "source_name": item["source_name"],
                })
        return history

    def _new_combinations(self, record: dict[str, Any], links: list[RecordLink],
                          prior: list[dict[str, Any]], precision_cap: str) -> list[dict[str, Any]]:
        combos: list[dict[str, Any]] = []
        linked_prior = {
            (link.delivery_id, link.material_id, link.record_id, link.source_name): link.basis
            for link in links
        }
        for item in prior:
            key = (item["delivery_id"], item["material_id"], item["record_id"], item["source_name"])
            basis = linked_prior.get(key)
            if basis is None:
                continue
            combos.append({
                "kind": "record_link" if basis == "record_key" else "subject_link",
                "basis": basis,
                "status": item.get("status", "delivered"),
                "application_id": item.get("application_id"),
                "current_record": {"table": record["table"], "record_id": record["record_id"],
                                   "source_name": record["source_name"]},
                "prior_record": {"delivery_id": item["delivery_id"], "material_id": item["material_id"],
                                 "record_id": item["record_id"], "source_name": item["source_name"]},
                "current_fields": self._fields_at_precision(record["fields"], record["values"], precision_cap),
                "prior_fields": sorted(item["fields"]),
            })
        return combos

    @staticmethod
    def _fields_at_precision(fields: list[str], values: dict[str, str], cap: str) -> list[str]:
        result = []
        for name in fields:
            precision = date_precision_of(values.get(name, ""))
            if precision is not None and DATE_PRECISION_ORDER[precision] > DATE_PRECISION_ORDER[cap]:
                continue
            result.append(name)
        return sorted(result)

    # ---- 方案评估 -----------------------------------------------------

    def _evaluate_plan(self, plan_name: str, previews: list[RecordPreview],
                       request: dict[str, Any], policy_rules: dict[str, Any],
                       authorization: dict[str, Any], policy_revision: int,
                       prior: list[dict[str, Any]], peers_day: list[dict[str, Any]],
                       batch_id: str, recipient_id: str) -> PlanPreview:
        blocked: list[dict[str, Any]] = []
        included: list[RecordPreview] = []
        excluded: list[RecordPreview] = []
        if plan_name == "cancel":
            return PlanPreview(
                plan=plan_name,
                description=self.PLAN_LABELS[plan_name],
                rule_revision=policy_revision,
                included_records=[],
                excluded_records=previews,
                new_disclosures=[],
                blocked=[],
                material_spec=None,
            )

        # 本次申请声明的日期精度即实际交付精度的上限；reduce_precision 再压到月。
        precision_cap = str(request.get("date_precision", "day"))
        if plan_name == "reduce_precision" and (
                DATE_PRECISION_ORDER[precision_cap] > DATE_PRECISION_ORDER["month"]):
            precision_cap = "month"
        peers = self._peer_pending_records(
            batch_id, recipient_id,
            exclude_application_id=str(request.get("application_id"))
            if request.get("application_id") else None,
            precision_cap=precision_cap,
        )
        include_fields: dict[str, list[str]] = {}
        # 先做授权外剔除；通过的记录才进入「确认后将新增可关联内容」的联合计算。
        for preview in previews:
            if not preview.authorized:
                excluded.append(preview)
                blocked.append({
                    "kind": "outside_authorization",
                    "table": preview.table,
                    "record_id": preview.record_id,
                })
        for preview in previews:
            if not preview.authorized:
                continue
            allowed_field_names: list[str] = []
            record_fields: list[FieldDisclosure] = []
            for item in preview.fields:
                dropped_reason = None
                if self._field_forbidden(item.field, preview.table, policy_rules):
                    dropped_reason = "forbid_field"
                if dropped_reason and plan_name == "as_requested":
                    # 按申请全量方案：不删字段，但标注政策禁止，交由确认环节拦截。
                    blocked.append({
                        "kind": dropped_reason,
                        "table": preview.table,
                        "record_id": preview.record_id,
                        "field": item.field,
                    })
                if dropped_reason and plan_name in {"allow_only", "reduce_precision"}:
                    blocked.append({
                        "kind": dropped_reason,
                        "table": preview.table,
                        "record_id": preview.record_id,
                        "field": item.field,
                    })
                else:
                    allowed_field_names.append(item.field)
                adjusted = item
                if plan_name == "reduce_precision" and item.date_precision is not None \
                        and DATE_PRECISION_ORDER[item.date_precision] > DATE_PRECISION_ORDER["month"]:
                    adjusted = FieldDisclosure(
                        field=item.field,
                        date_precision="month",
                        newly_linkable=False,
                        precision_upgrade_from=None,
                        first_delivered_by=item.first_delivered_by,
                        source_precision=item.source_precision,
                    )
                record_fields.append(adjusted)
            preview.fields = record_fields
            include_fields.setdefault(preview.table, []).extend(
                name for name in allowed_field_names
                if name not in include_fields.get(preview.table, [])
            )
            included.append(preview)

        # 受试者级联合组合判定：既有交付 + 同接收方其他待审申请 + 本申请纳入记录。
        # 只有「历史单独尚不成组合、但三方合在一起后成组合」才算本次新增的政策禁止项；
        # 无论先确认哪一份申请，都逃不掉同一份判定，确认顺序不能绕过组合限制。
        combo_blocks = self._union_combo_blocks(
            included, prior, peers, policy_rules, precision_cap,
        )
        for entry in combo_blocks:
            blocked.append(entry)
            if plan_name in {"allow_only", "reduce_precision"}:
                table = entry["table"]
                field_name = entry["field"]
                include_fields[table] = [name for name in include_fields.get(table, [])
                                         if name != field_name]

        new_disclosures = self._summarize_new_disclosures(included, precision_cap)
        spec = None
        if included:
            spec = MaterialSpec(
                version=int(request["version"]),
                records=tuple((item.table, item.record_id) for item in included),
                date_precision=precision_cap,
                source_aliases=dict(request.get("source_aliases", {})),
                source_names=dict(request.get("source_names", {})),
                include_fields=include_fields,
            ).to_dict()
        return PlanPreview(
            plan=plan_name,
            description=self.PLAN_LABELS[plan_name],
            rule_revision=policy_revision,
            included_records=included,
            excluded_records=excluded,
            new_disclosures=new_disclosures,
            blocked=blocked,
            material_spec=spec,
        )

    @staticmethod
    def _field_forbidden(field_name: str, table: str, policy_rules: dict[str, Any]) -> bool:
        candidates = {field_name, f"{table}.{field_name}"}
        return any(item in candidates for item in policy_rules.get("forbid_fields", []))

    def _union_combo_blocks(self, included: list[RecordPreview],
                            prior: list[dict[str, Any]], peers: list[dict[str, Any]],
                            policy_rules: dict[str, Any],
                            precision_cap: str) -> list[dict[str, Any]]:
        """在「历史交付 ∪ 待审同伴 ∪ 本次申请」的受试者字段并集上判定禁止组合。

        对每位受试者分别汇总字段出处：组合在历史交付中已经成立的不拦（政策只管今后）；
        历史单独不成立、但合入待审申请与本次记录后才成立的组合为本次新增风险，
        逐字段标注本次记录与所依赖的待审申请。日期字段在当前方案精度下被压低的，
        该出处不计入，组合可能因此不成立。
        """
        combos = policy_rules.get("forbid_combinations", [])
        if not combos or not included:
            return []
        subjects = {preview.pseudonym for preview in included}
        subjects.update(item["pseudonym"] for item in peers)
        subjects.update(item["pseudonym"] for item in prior)

        def _source_ok(combo: dict[str, Any], table: str) -> bool:
            sources = combo.get("sources")
            return not sources or table in sources

        def _history_presence(subject: str, combo: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
            presence: dict[str, list[dict[str, str]]] = {}
            for item in prior:
                if item["pseudonym"] != subject or not _source_ok(combo, item["table"]):
                    continue
                for field_name in item["fields"]:
                    if field_name not in combo["fields"]:
                        continue
                    precision = date_precision_of(item["values"].get(field_name, ""))
                    if precision is not None \
                            and DATE_PRECISION_ORDER[precision] > DATE_PRECISION_ORDER[precision_cap]:
                        continue
                    presence.setdefault(field_name, []).append({
                        "table": item["table"], "record_id": item["record_id"],
                        "application_id": "",
                    })
            return presence

        def _peer_presence(subject: str, combo: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
            presence: dict[str, list[dict[str, str]]] = {}
            for item in peers:
                if item["pseudonym"] != subject or not _source_ok(combo, item["table"]):
                    continue
                for field_name in item["fields"]:
                    if field_name not in combo["fields"]:
                        continue
                    presence.setdefault(field_name, []).append({
                        "table": item["table"], "record_id": item["record_id"],
                        "application_id": item["application_id"],
                    })
            return presence

        blocks: list[dict[str, Any]] = []
        seen: set[tuple] = set()
        for subject in sorted(subjects):
            for combo in combos:
                required = set(combo["fields"])
                history_presence = _history_presence(subject, combo)
                if required <= set(history_presence):
                    # 历史交付中已经可以关联：政策只约束今后新增，旧材料不改写。
                    continue
                peer_presence = _peer_presence(subject, combo)
                current_presence: dict[str, list[dict[str, str]]] = {}
                for preview in included:
                    if preview.pseudonym != subject or not _source_ok(combo, preview.table):
                        continue
                    for field_item in preview.fields:
                        if field_item.field not in required:
                            continue
                        if field_item.date_precision is not None \
                                and DATE_PRECISION_ORDER[field_item.date_precision] > DATE_PRECISION_ORDER[precision_cap]:
                            continue
                        current_presence.setdefault(field_item.field, []).append({
                            "table": preview.table, "record_id": preview.record_id,
                            "application_id": "",
                        })
                union_presence: dict[str, list[dict[str, str]]] = {}
                for presence in (history_presence, peer_presence, current_presence):
                    for field_name, refs in presence.items():
                        union_presence.setdefault(field_name, []).extend(refs)
                if not required <= set(union_presence):
                    continue
                contributing = current_presence
                if not contributing:
                    # 组合完全由历史与其他待审申请构成：确认本申请既不补齐也不升级它。
                    continue
                peer_applications = sorted({
                    ref["application_id"]
                    for refs in peer_presence.values() for ref in refs if ref["application_id"]
                })
                for field_name in required:
                    for ref in contributing.get(field_name, ()):
                        key = (subject, tuple(sorted(required)), ref["table"],
                               ref["record_id"], field_name, tuple(peer_applications))
                        if key in seen:
                            continue
                        seen.add(key)
                        blocks.append({
                            "kind": "forbid_combination",
                            "table": ref["table"],
                            "record_id": ref["record_id"],
                            "field": field_name,
                            "fields": sorted(required),
                            "pseudonym": subject,
                            "peer_applications": peer_applications,
                        })
        return blocks

    def _summarize_new_disclosures(self, included: list[RecordPreview],
                                   precision_cap: str) -> list[dict[str, Any]]:
        summary: list[dict[str, Any]] = []
        seen_subjects: set[str] = set()
        for preview in included:
            new_fields = [item for item in preview.fields if item.newly_linkable]
            for item in new_fields:
                summary.append({
                    "kind": "new_field",
                    "table": preview.table,
                    "record_id": preview.record_id,
                    "pseudonym": preview.pseudonym,
                    "field": item.field,
                    # 字段级标注即本方案实际公开精度，与纳入记录中的口径一致。
                    "date_precision": precision_label(item.date_precision),
                    "source_precision": precision_label(item.source_precision),
                    "precision_upgrade_from": item.precision_upgrade_from,
                    "linkable_to": [
                        {"delivery_id": link.delivery_id, "record_id": link.record_id,
                         "source_name": link.source_name, "basis": link.basis}
                        for link in preview.links if link.basis in {"record_key", "subject"}
                    ],
                })
            for combo in preview.new_combinations:
                summary.append({
                    "kind": "new_combination",
                    "basis": combo["basis"],
                    "current": combo["current_record"],
                    "prior": combo["prior_record"],
                    "current_fields": combo["current_fields"],
                    "prior_fields": combo["prior_fields"],
                    "date_precision": precision_cap,
                })
            seen_subjects.add(preview.pseudonym)
        # 受试者级新增：同一伪名下本次出现的字段与既有来源组合。
        for pseudonym in sorted(seen_subjects):
            records = [item for item in included if item.pseudonym == pseudonym]
            summary.append({
                "kind": "subject_links",
                "pseudonym": pseudonym,
                "records": [
                    {"table": item.table, "record_id": item.record_id, "source_name": item.source_name}
                    for item in records
                ],
                "linkable_prior_deliveries": sorted({
                    link.delivery_id
                    for item in records for link in item.links
                    if link.basis in {"record_key", "subject"}
                }),
                "unconfirmed_prior": [
                    {"delivery_id": link.delivery_id, "source_name": link.source_name,
                     "record_id": link.record_id}
                    for item in records for link in item.links if link.basis == "unconfirmed"
                ],
            })
        return summary

    # ---- 确认交付 -----------------------------------------------------

    def confirm(self, batch_id: str, recipient_id: str, preview: dict[str, Any],
                plan_name: str, note: str = "", audit_note: str = "") -> dict[str, Any]:
        if preview["batch_id"] != batch_id or preview["recipient_id"] != recipient_id:
            raise ValueError("预览绑定的接收者或资料身份与确认请求不一致")
        plan = preview["plans"].get(plan_name)
        if plan is None:
            raise ValueError(f"未知方案: {plan_name}")
        application_id = preview.get("application_id")
        if application_id:
            # 申请必须仍处于待审状态：被确认或取消过的申请不能再次提交。
            self.pending.load(batch_id, recipient_id, str(application_id))
        if plan_name == "cancel":
            if application_id:
                # 取消不登记：不形成材料、不留交付，待审申请直接移除。
                self.pending.remove(batch_id, recipient_id, str(application_id))
            return {
                "cancelled": True,
                "recipient_id": recipient_id,
                "material_id": None,
                "new_disclosures": [],
            }
        if not plan["included_records"]:
            raise ValueError("该方案没有任何可交付记录；请改用 cancel 方案")
        if plan["blocked"] and plan_name == "as_requested":
            raise DisclosurePolicyError(
                "当前政策/授权不允许本次组合披露: "
                + "; ".join(f"{item['kind']}:{item.get('table', '')}/{item.get('field', item.get('record_id', ''))}"
                             for item in plan["blocked"])
            )
        spec = MaterialSpec.from_dict(plan["material_spec"])
        material_id = self.builder.material_id(batch_id, spec)
        existing_delivery = self.registry.find_by_material(batch_id, recipient_id, material_id)
        if existing_delivery is not None:
            # 同一份对外材料的保存/重试：不重新核对快照、不重复计入披露。
            entry = self.registry.record(
                batch_id, recipient_id, material_id, spec, note, audit_note,
                existing_delivery["authorization_revision"],
                existing_delivery["policy_revision"],
                existing_delivery.get("new_disclosures", []),
            )
            if application_id:
                self.pending.remove(batch_id, recipient_id, str(application_id))
            return {
                "cancelled": False,
                "recipient_id": recipient_id,
                "delivery_id": entry["delivery_id"],
                "material_id": material_id,
                "date_precision": spec.date_precision,
                "material_reused": True,
                "delivery_reused": True,
                "attempts": entry.get("attempts", 1),
                "new_disclosures": entry.get("new_disclosures", []),
                "blocked": plan["blocked"],
            }
        # 新材料的首次确认才做过期核对：预览生成后若既有交付增加（或授权/政策/导出变化），
        # 拒绝提交过期预览。本申请自身不计入快照（与预览生成时的口径一致，
        # 其身份已由待审登记与预览绑定核对）。
        current_snapshot = self.snapshot(
            batch_id, recipient_id,
            exclude_application_id=str(application_id) if application_id else None,
        )
        if current_snapshot != preview["snapshot"]:
            raise StalePreviewError(
                "预览已过期：既有交付范围、授权、政策、导出版本或同接收方待审申请已变化，请重新核对"
            )
        result = self.builder.build(batch_id, spec)
        recipient = self.recipients.load(batch_id, recipient_id)
        policy_revision = int(preview["policy_revision"])
        entry = self.registry.record(
            batch_id=batch_id,
            recipient_id=recipient_id,
            material_id=result.material_id,
            spec=spec,
            note=note,
            audit_note=audit_note,
            authorization_revision=recipient.authorization_revision,
            policy_revision=policy_revision,
            new_disclosures=plan["new_disclosures"],
        )
        entry.setdefault("spec_fingerprint", spec.fingerprint())
        if application_id:
            # 确认落地后申请离开待审：它此后作为既有交付出现在联合预览中。
            self.pending.remove(batch_id, recipient_id, str(application_id))
        return {
            "cancelled": False,
            "recipient_id": recipient_id,
            "delivery_id": entry["delivery_id"],
            "material_id": result.material_id,
            "date_precision": spec.date_precision,
            "material_reused": result.reused,
            "delivery_reused": entry.get("attempts", 1) > 1,
            "attempts": entry.get("attempts", 1),
            "new_disclosures": plan["new_disclosures"],
            "blocked": plan["blocked"],
        }
