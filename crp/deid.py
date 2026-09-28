"""De-identification primitives and row/table transformation.

Implements the first-version rules:

* direct identifier columns are dropped;
* every date of one subject uses the same fixed (random-looking) shift;
* free-text fields are scrubbed for both listed sensitive phrases (names,
  ward names, addresses...) and unlisted identifier-shaped fragments such as
  mobile numbers, ID-card numbers and email addresses;
* subject identifiers become stable pseudonyms, consistently across tables.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Iterable

from .mapping import SubjectMapping
from .rules import RuleSet, TableRule
from .storage import ProjectError

REDACTION = "[REDACTED]"

# Identifier-shaped fragments that must be scrubbed even if no phrase lists
# them: mainland China mobile numbers, 18-digit ID numbers, emails.
BUILTIN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Digit lookarounds (not \b): Chinese characters are \w in unicode mode,
    # so \b would not separate an ID number from a preceding Chinese word.
    ("id_card", re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])")),
    ("mobile_cn", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("phone_generic", re.compile(r"(?<!\d)0\d{2,3}-?\d{7,8}(?!\d)")),
]

_DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d", "%Y%m%d")


def parse_date(text: str) -> date | None:
    value = text.strip()
    if not value:
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def render_date(value: date, style: str) -> str:
    if style == "%Y/%m/%d":
        return value.strftime("%Y/%m/%d")
    if style == "%Y%m%d":
        return value.strftime("%Y%m%d")
    return value.isoformat()


def _date_style(text: str) -> str:
    value = text.strip()
    if "/" in value:
        return "%Y/%m/%d"
    if len(value) == 8 and value.isdigit():
        return "%Y%m%d"
    return "%Y-%m-%d"


@dataclass
class TextScrubber:
    terms: list[str]
    term_hits: dict[str, int] = field(default_factory=dict)
    pattern_hits: dict[str, int] = field(default_factory=dict)
    _term_pattern: re.Pattern[str] | None = None

    def __post_init__(self) -> None:
        if self.terms:
            escaped = sorted((re.escape(t) for t in self.terms), key=len, reverse=True)
            self._term_pattern = re.compile("|".join(escaped))

    def scrub(self, text: str) -> str:
        if text is None:
            return text
        result = text
        if self._term_pattern is not None:
            def _hit(match: re.Match[str]) -> str:
                self.term_hits[match.group(0)] = self.term_hits.get(match.group(0), 0) + 1
                return REDACTION

            result = self._term_pattern.sub(_hit, result)
        for label, pattern in BUILTIN_PATTERNS:
            def _hit(match: re.Match[str], label: str = label) -> str:
                self.pattern_hits[label] = self.pattern_hits.get(label, 0) + 1
                return REDACTION

            result = pattern.sub(_hit, result)
        return result


@dataclass
class TableResult:
    headers: list[str]
    rows: list[list[str]]
    dropped_columns: list[str]
    bad_dates: int
    rows_out: int


def transform_table(
    table: str,
    rule: TableRule,
    reader_rows: Iterable[list[str]],
    headers: list[str],
    mapping: SubjectMapping,
    scrubber: TextScrubber,
) -> TableResult:
    sf_index = headers.index(rule.subject_field)

    out_indices: list[int] = []
    out_headers: list[str] = []
    dropped: list[str] = []
    for idx, name in enumerate(headers):
        action = rule.fields[name]
        if action == "drop":
            dropped.append(name)
        else:
            out_indices.append(idx)
            out_headers.append(name)

    out_rows: list[list[str]] = []
    bad_dates = 0
    for row in reader_rows:
        if len(row) < len(headers):
            row = row + [""] * (len(headers) - len(row))
        raw_subject = row[sf_index].strip()
        if not raw_subject:
            raise ProjectError(f"empty subject id in table {table!r}; cannot de-identify")
        pseudo = mapping.pseudonym(raw_subject)

        new_row: list[str] = []
        for idx in out_indices:
            name = headers[idx]
            action = rule.fields[name]
            value = row[idx]
            if action == "subject_id":
                new_row.append(pseudo)
            elif action == "date":
                if value.strip() == "":
                    new_row.append("")
                else:
                    parsed = parse_date(value)
                    if parsed is None:
                        bad_dates += 1
                        new_row.append("")
                    else:
                        new_row.append(render_date(mapping.shift_date(raw_subject, parsed), _date_style(value)))
            elif action == "text":
                new_row.append(scrubber.scrub(value))
            else:  # keep
                new_row.append(value)
        out_rows.append(new_row)

    return TableResult(
        headers=out_headers,
        rows=out_rows,
        dropped_columns=dropped,
        bad_dates=bad_dates,
        rows_out=len(out_rows),
    )


def read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        try:
            headers = next(reader)
        except StopIteration:
            raise ProjectError(f"empty csv file: {path}")
        headers = [h.strip() for h in headers]
        rows = [r for r in reader if any(cell.strip() for cell in r)]
    return headers, rows


def scrubbing_stats(scrubber: TextScrubber) -> dict:
    return {
        "listed_term_hits": dict(sorted(scrubber.term_hits.items())),
        "pattern_hits": dict(sorted(scrubber.pattern_hits.items())),
        "listed_term_total": sum(scrubber.term_hits.values()),
        "pattern_total": sum(scrubber.pattern_hits.values()),
        # Actual term strings are NOT written to the public manifest.
    }


__all__ = [
    "REDACTION",
    "BUILTIN_PATTERNS",
    "TextScrubber",
    "TableResult",
    "parse_date",
    "render_date",
    "transform_table",
    "read_csv",
    "scrubbing_stats",
]
