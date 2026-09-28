"""Field-level de-identification rules.

Each batch owns one current rule set. A rule set describes, for every table
and every column, exactly one action:

* ``keep``       - value passes through unchanged (only for non-sensitive data)
* ``drop``       - direct identifier column removed from export entirely
* ``subject_id`` - subject identifier replaced by a stable batch pseudonym
* ``date``       - date shifted by a fixed per-subject offset
* ``text``       - free text scanned for names/terms and identifier patterns

Every source column must be listed explicitly: unknown columns are rejected
at export time so a new identifier column can never leak by accident.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .storage import ProjectError

ACTIONS = {"keep", "drop", "subject_id", "date", "text"}


@dataclass
class TableRule:
    subject_field: str
    fields: dict[str, str]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "TableRule":
        if "subject_field" not in value:
            raise ProjectError("table rule missing 'subject_field'")
        fields = value.get("fields", {})
        if not isinstance(fields, dict) or not fields:
            raise ProjectError("table rule requires non-empty 'fields' mapping")
        for name, action in fields.items():
            if action not in ACTIONS:
                raise ProjectError(f"unknown action {action!r} for field {name!r}")
        sf = value["subject_field"]
        if sf not in fields or fields[sf] != "subject_id":
            raise ProjectError(f"subject_field {sf!r} must be declared with action 'subject_id'")
        return cls(subject_field=sf, fields=dict(fields))


@dataclass
class RuleSet:
    tables: dict[str, TableRule] = field(default_factory=dict)
    # Private sensitive phrases for text scrubbing (names, wards, addresses...).
    sensitive_terms: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuleSet":
        tables_raw = value.get("tables", {})
        if not isinstance(tables_raw, dict) or not tables_raw:
            raise ProjectError("rules require a non-empty 'tables' section")
        tables = {name: TableRule.from_dict(t) for name, t in tables_raw.items()}
        terms = [t for t in value.get("sensitive_terms", []) if isinstance(t, str) and t]
        # Longest first so multi-word phrases win over contained substrings.
        terms = sorted(set(terms), key=len, reverse=True)
        return cls(tables=tables, sensitive_terms=terms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables": {
                name: {"subject_field": tr.subject_field, "fields": tr.fields}
                for name, tr in sorted(self.tables.items())
            },
            "sensitive_terms": self.sensitive_terms,
        }

    def check_headers(self, table: str, headers: list[str]) -> None:
        if table not in self.tables:
            raise ProjectError(f"no rules for table {table!r}")
        declared = set(self.tables[table].fields)
        actual = set(headers)
        missing = declared - actual
        unknown = actual - declared
        problems = []
        if missing:
            problems.append(f"declared columns absent from data: {sorted(missing)}")
        if unknown:
            problems.append(f"columns without explicit rules (refusing to export): {sorted(unknown)}")
        if problems:
            raise ProjectError(f"rule/data mismatch in {table!r}: " + "; ".join(problems))

    def public_snapshot(self) -> dict[str, Any]:
        """Rule description safe to ship in a public manifest.

        The actual sensitive phrases stay private; only their count is shown.
        """
        return {
            "tables": {
                name: {"subject_field": tr.subject_field, "fields": tr.fields}
                for name, tr in sorted(self.tables.items())
            },
            "sensitive_term_count": len(self.sensitive_terms),
        }
