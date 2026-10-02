"""规则修订适用范围判定。"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from crp.util import stable_json, sha256_text

ALL_SCOPE: dict[str, Any] = {"mode": "all"}


def normalize_scope(scope: dict[str, Any] | None) -> dict[str, Any]:
    if scope is None:
        return dict(ALL_SCOPE)
    if not isinstance(scope, dict):
        raise ValueError("规则适用范围必须是对象")
    if scope.get("mode") == "all" or not scope:
        return dict(ALL_SCOPE)
    normalized: dict[str, Any] = {"mode": "selected"}
    if "sources" in scope or "tables" in scope:
        values = scope.get("sources", scope.get("tables", []))
        if not isinstance(values, list) or not values:
            raise ValueError("适用范围 sources 必须是非空数组")
        normalized["sources"] = [str(item) for item in values]
    if "subjects" in scope:
        if not isinstance(scope["subjects"], list) or not scope["subjects"]:
            raise ValueError("适用范围 subjects 必须是非空数组")
        normalized["subjects"] = [str(item) for item in scope["subjects"]]
    if "time_range" in scope:
        time_range = scope["time_range"]
        if not isinstance(time_range, dict):
            raise ValueError("time_range 必须是对象")
        normalized_range = {"start": str(time_range.get("start", "")), "end": str(time_range.get("end", ""))}
        if not normalized_range["start"] and not normalized_range["end"]:
            raise ValueError("time_range 至少需要 start 或 end")
        fields = time_range.get("fields", {})
        if fields and not isinstance(fields, dict):
            raise ValueError("time_range.fields 必须按表声明日期字段")
        normalized_range["fields"] = {str(k): str(v) for k, v in (fields or {}).items()}
        normalized["time_range"] = normalized_range
    if "records" in scope:
        records = scope["records"]
        if not isinstance(records, list) or not records:
            raise ValueError("适用范围 records 必须是非空数组")
        normalized_records = []
        for item in records:
            if not isinstance(item, dict) or "table" not in item:
                raise ValueError("records 中每项必须包含 table")
            normalized_records.append({str(key): str(value) for key, value in sorted(item.items())})
        normalized["records"] = normalized_records
    if len(normalized) == 1:
        raise ValueError("选定适用范围时必须提供 sources、time_range、subjects 或 records")
    return normalized


def scope_fingerprint(scope: dict[str, Any] | None) -> str:
    return sha256_text(stable_json(normalize_scope(scope)))


def _parse_date(value: str) -> date | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        try:
            return datetime.fromisoformat(value).date()
        except ValueError:
            return None


def _date_field_for(table: str, columns: set[str], scope: dict[str, Any]) -> str | None:
    configured = scope.get("time_range", {}).get("fields", {}).get(table)
    if configured:
        return configured if configured in columns else None
    for candidate in ("visit_date", "collected_at", "start_date", "event_date", "date"):
        if candidate in columns:
            return candidate
    return None


def matches(
    scope: dict[str, Any] | None,
    table: str,
    row: dict[str, str],
    columns: set[str] | None = None,
    row_number: int | None = None,
) -> bool:
    normalized = normalize_scope(scope)
    if normalized["mode"] == "all":
        return True
    columns = set(row) if columns is None else columns
    if "sources" in normalized and table not in normalized["sources"]:
        return False
    if "subjects" in normalized and row.get("subject_id", "") not in normalized["subjects"]:
        return False
    if "time_range" in normalized:
        field_name = _date_field_for(table, columns, normalized)
        if field_name is None:
            return False
        day = _parse_date(row.get(field_name, ""))
        if day is None:
            return False
        start = _parse_date(normalized["time_range"]["start"])
        end = _parse_date(normalized["time_range"]["end"])
        if (start is not None and day < start) or (end is not None and day > end):
            return False
    if "records" in normalized:
        for record in normalized["records"]:
            if record.get("table") == table and all(
                (
                    str(row_number) == value
                    if key == "row_number"
                    else str(row.get(key, "")) == value
                )
                for key, value in record.items() if key != "table"
            ):
                return True
        return False
    return True


def describe(scope: dict[str, Any] | None) -> str:
    normalized = normalize_scope(scope)
    if normalized["mode"] == "all":
        return "全部资料"
    parts = []
    if "sources" in normalized:
        parts.append("来源=" + ",".join(normalized["sources"]))
    if "subjects" in normalized:
        parts.append(f"指定受试者 {len(normalized['subjects'])} 人")
    if "time_range" in normalized:
        time_range = normalized["time_range"]
        parts.append(f"时间={time_range['start'] or '..'}~{time_range['end'] or '..'}")
    if "records" in normalized:
        parts.append(f"明确记录 {len(normalized['records'])} 条")
    return "；".join(parts)
