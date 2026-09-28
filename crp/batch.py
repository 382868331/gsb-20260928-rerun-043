"""研究批次与字段规则的创建、更新和版本留痕。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from crp.paths import Store
from crp.rules import FieldRule, parse_rules
from crp.util import read_json, stable_json, write_json


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Batch:
    batch_id: str
    name: str
    tables: list[str]
    rules: dict[str, list[FieldRule]]
    subject_field: str = "subject_id"
    description: str = ""
    rules_version: int = 1
    created_at: str = ""
    updated_at: str = ""
    history: list[dict[str, Any]] = None  # type: ignore[assignment]

    def to_json(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "name": self.name,
            "description": self.description,
            "subject_field": self.subject_field,
            "tables": list(self.tables),
            "rules_version": self.rules_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "rules": {
                table: [rule.to_dict() for rule in rules]
                for table, rules in sorted(self.rules.items())
            },
            "history": self.history,
        }


class BatchExistsError(FileExistsError):
    pass


class BatchNotFoundError(FileNotFoundError):
    pass


class BatchStore:
    def __init__(self, store: Store) -> None:
        self.store = store

    def create(self, config: dict[str, Any], note: str = "初始字段规则") -> Batch:
        batch_id = str(config["batch_id"])
        target = self.store.batch_file(batch_id)
        if target.exists():
            raise BatchExistsError(f"批次已存在: {batch_id}")
        tables = list(config.get("tables", []))
        if not tables:
            raise ValueError("批次配置必须声明非空 tables 列表")
        missing = [name for name in tables if not (self.store.raw_dir(batch_id) / f"{name}.csv").exists()]
        if missing:
            raise FileNotFoundError(f"批次 {batch_id} 缺少原始表文件: {', '.join(missing)}")
        rules = parse_rules(config.get("rules", {}))
        unknown = sorted(set(rules) - set(tables))
        if unknown:
            raise ValueError(f"规则引用了未声明的表: {', '.join(unknown)}")
        now = _now()
        rules_hash = _rules_hash(rules)
        batch = Batch(
            batch_id=batch_id,
            name=str(config.get("name", batch_id)),
            description=str(config.get("description", "")),
            subject_field=str(config.get("subject_field", "subject_id")),
            tables=tables,
            rules=rules,
            created_at=now,
            updated_at=now,
            history=[{"rules_version": 1, "changed_at": now, "note": note, "rules_hash": rules_hash}],
        )
        write_json(target, batch.to_json())
        return batch

    def load(self, batch_id: str) -> Batch:
        target = self.store.batch_file(batch_id)
        if not target.exists():
            raise BatchNotFoundError(f"批次不存在: {batch_id}")
        raw = read_json(target)
        return Batch(
            batch_id=raw["batch_id"],
            name=raw["name"],
            description=raw.get("description", ""),
            subject_field=raw.get("subject_field", "subject_id"),
            tables=list(raw["tables"]),
            rules=parse_rules(raw.get("rules", {})),
            rules_version=int(raw.get("rules_version", 1)),
            created_at=raw.get("created_at", ""),
            updated_at=raw.get("updated_at", ""),
            history=list(raw.get("history", [])),
        )

    def update_rules(self, batch_id: str, new_rules: dict[str, Any], note: str) -> Batch:
        batch = self.load(batch_id)
        parsed = parse_rules(new_rules)
        unknown = sorted(set(parsed) - set(batch.tables))
        if unknown:
            raise ValueError(f"规则引用了未声明的表: {', '.join(unknown)}")
        next_version = batch.rules_version + 1
        now = _now()
        batch.rules = parsed
        batch.rules_version = next_version
        batch.updated_at = now
        batch.history.append(
            {
                "rules_version": next_version,
                "changed_at": now,
                "note": note,
                "rules_hash": _rules_hash(parsed),
            }
        )
        write_json(self.store.batch_file(batch_id), batch.to_json())
        return batch


def _rules_hash(rules: dict[str, list[FieldRule]]) -> str:
    canonical = {
        table: [rule.to_dict() for rule in table_rules]
        for table, table_rules in sorted(rules.items())
    }
    return stable_json(canonical)
