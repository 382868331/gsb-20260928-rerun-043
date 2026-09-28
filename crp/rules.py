"""字段级去标识规则。

支持的动作：
- ``drop``：移除直接身份字段（姓名、证件号、电话等整列删除）；
- ``date_shift``：日期按受试者固定偏移平移；
- ``redact_text``：文本字段中按内置模式与人工标注片段脱敏；
- ``keep``：显式保留（默认行为，便于文档化）。

受试者关联列（``subject_field``，默认 ``subject_id``）在每张表上统一做伪名化，
以保证同一受试者跨表关联一致，无需在规则里逐表声明。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ACTIONS = {"drop", "date_shift", "redact_text", "keep"}


@dataclass(frozen=True)
class FieldRule:
    field: str
    action: str
    patterns: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "FieldRule":
        action = raw.get("action")
        if action not in ACTIONS:
            raise ValueError(f"不支持的字段动作: {action!r}（字段 {raw.get('field')!r}）")
        patterns = tuple(raw.get("patterns", ()))
        if action != "redact_text" and patterns:
            raise ValueError(f"字段 {raw.get('field')!r} 只有 redact_text 可配置 patterns")
        return cls(field=str(raw["field"]), action=action, patterns=patterns)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"field": self.field, "action": self.action}
        if self.patterns:
            out["patterns"] = list(self.patterns)
        return out


def parse_rules(raw_rules: dict[str, list[dict[str, Any]]]) -> dict[str, list[FieldRule]]:
    parsed: dict[str, list[FieldRule]] = {}
    for table, rules in (raw_rules or {}).items():
        seen: set[str] = set()
        table_rules: list[FieldRule] = []
        for item in rules:
            rule = FieldRule.from_dict(item)
            if rule.field in seen:
                raise ValueError(f"表 {table} 中字段 {rule.field} 规则重复")
            seen.add(rule.field)
            table_rules.append(rule)
        parsed[table] = table_rules
    return parsed
