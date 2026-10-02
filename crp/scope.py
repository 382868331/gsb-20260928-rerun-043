"""规则修订的适用范围：来源表、时间区间、明确的资料集合。

一次规则修订可以只对指定资料范围生效，范围外的记录继续沿用更早的有效规则。
范围只描述"哪些原始记录在本次修订的适用对象内"，不包含规则内容本身：

- ``tables``：来源表白名单（缺省/为空表示全部表）；
- ``date_range``：按 ``{"表": {"field": 日期字段, "start": 起, "end": 止}}``
  声明时间区间，区间端点含当天；某表未声明即不对该表做时间限制；
- ``records``：明确的资料集合 ``{"表": ["键", ...]}``，与其它条件取并集，
  键为原始记录标识：优先使用 record_id/medication_id/visit_id/test_code
  等业务键，否则退化为受试者真实编号。

修订只在创建时按当时可见的资料校验明确集合；来源日后新增的记录必须在执行时
重新判断是否落入范围，绝不借用其它批次/执行的结论。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

UNIQUE_KEY_FIELDS = ("record_id", "medication_id")
QUALIFIED_KEY_FIELDS = ("test_code", "visit_id")
SUBJECT_FIELD = "subject_id"


@dataclass(frozen=True)
class DateRange:
    field_name: str
    start: str = ""
    end: str = ""

    @classmethod
    def from_dict(cls, table: str, raw: dict[str, Any]) -> "DateRange":
        field_name = str(raw.get("field", ""))
        if not field_name:
            raise ValueError(f"表 {table} 的时间区间必须声明 field")
        start = str(raw.get("start", "")).strip()
        end = str(raw.get("end", "")).strip()
        if start and end and start > end:
            raise ValueError(f"表 {table} 的时间区间起点 {start} 晚于终点 {end}")
        return cls(field_name=field_name, start=start, end=end)

    def to_dict(self) -> dict[str, str]:
        out = {"field": self.field_name}
        if self.start:
            out["start"] = self.start
        if self.end:
            out["end"] = self.end
        return out

    @property
    def spec(self) -> str:
        return f"{self.field_name}:{self.start or ''}..{self.end or ''}"

    def covers(self, value: str) -> bool:
        value = (value or "").strip()
        if not value:
            return False
        if self.start and value < self.start:
            return False
        if self.end and value > self.end:
            return False
        return True


@dataclass(frozen=True)
class Scope:
    tables: frozenset[str] = frozenset()
    date_ranges: dict[str, DateRange] = field(default_factory=dict)
    records: dict[str, frozenset[str]] = field(default_factory=dict)

    @classmethod
    def all_records(cls) -> "Scope":
        return cls()

    @property
    def is_all(self) -> bool:
        return not self.tables and not self.date_ranges and not self.records

    @classmethod
    def parse(cls, raw: Any) -> "Scope":
        if raw is None:
            return cls.all_records()
        if not isinstance(raw, dict):
            raise ValueError("适用范围必须是对象")
        tables = frozenset(str(name) for name in raw.get("tables", ()))
        ranges = {
            str(table): DateRange.from_dict(str(table), dict(spec))
            for table, spec in (raw.get("date_range") or {}).items()
        }
        records = {
            str(table): frozenset(str(key).strip() for key in keys if str(key).strip())
            for table, keys in (raw.get("records") or {}).items()
        }
        scope = cls(tables=tables, date_ranges=ranges, records=records)
        if not scope.is_all and scope.is_empty():
            raise ValueError("适用范围为空：不匹配任何表或记录")
        return scope

    def is_empty(self) -> bool:
        if self.is_all:
            return False
        scope_tables = self.tables | set(self.date_ranges) | set(self.records)
        return not scope_tables

    def to_dict(self) -> dict[str, Any]:
        if self.is_all:
            return {"all": True}
        out: dict[str, Any] = {}
        if self.tables:
            out["tables"] = sorted(self.tables)
        if self.date_ranges:
            out["date_range"] = {
                table: self.date_ranges[table].to_dict()
                for table in sorted(self.date_ranges)
            }
        if self.records:
            out["records"] = {
                table: sorted(self.records[table]) for table in sorted(self.records)
            }
        return out

    def validate_against(
        self, tables: list[str], rows_by_table: dict[str, list[dict[str, str]]]
    ) -> None:
        declared = self.tables | set(self.date_ranges) | set(self.records)
        unknown = sorted(declared - set(tables))
        if unknown:
            raise ValueError(f"适用范围引用了未声明的表: {', '.join(unknown)}")
        for table, date_range in self.date_ranges.items():
            header = set(rows_by_table.get(table, [{}])[0]) if rows_by_table.get(table) else set()
            if header and date_range.field_name not in header:
                raise ValueError(f"表 {table} 的时间区间字段不存在: {date_range.field_name}")
        for table, keys in self.records.items():
            known = {record_key(row) for row in rows_by_table.get(table, [])}
            missing = sorted(key for key in keys if key not in known)
            if missing:
                raise ValueError(
                    f"表 {table} 的明确资料集合中有 {len(missing)} 条记录在来源中不存在，"
                    f"例如: {', '.join(missing[:3])}"
                )

    def match(self, table: str, row: dict[str, str]) -> tuple[bool, str]:
        """返回（是否命中，命中原因）。"""
        if self.is_all:
            return True, "all"
        if self.tables and table in self.tables:
            return True, f"table:{table}"
        date_range = self.date_ranges.get(table)
        if date_range is not None and date_range.covers(row.get(date_range.field_name, "")):
            return True, f"date_range:{table}:{date_range.spec}"
        key = record_key(row)
        if key and key in self.records.get(table, frozenset()):
            return True, f"record:{table}:explicit_set"
        return False, ""


def record_key(row: dict[str, str]) -> str:
    for name in UNIQUE_KEY_FIELDS:
        value = (row.get(name) or "").strip()
        if value:
            return value
    subject = (row.get(SUBJECT_FIELD) or "").strip()
    visit = (row.get("visit_id") or "").strip()
    for name in QUALIFIED_KEY_FIELDS:
        value = (row.get(name) or "").strip()
        if value:
            if subject:
                parts = [subject]
                parts.append(value)
                if name == "test_code" and visit:
                    parts.insert(1, visit)
                return "|".join(parts)
            return value
    value = (row.get(SUBJECT_FIELD) or "").strip()
    if value:
        return value
    return ""
