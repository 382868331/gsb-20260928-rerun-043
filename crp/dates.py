"""日期平移工具。"""

from __future__ import annotations

from datetime import date, datetime, timedelta


def shift_date(value: str, offset_days: int) -> str:
    value = (value or "").strip()
    if not value:
        return value
    try:
        parsed = date.fromisoformat(value)
        return (parsed + timedelta(days=offset_days)).isoformat()
    except ValueError:
        pass
    parsed = datetime.fromisoformat(value)
    return (parsed + timedelta(days=offset_days)).date().isoformat()


def interval_days(left: str, right: str) -> int:
    return (date.fromisoformat(left) - date.fromisoformat(right)).days
