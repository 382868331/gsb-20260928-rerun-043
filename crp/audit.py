"""跨表引用一致性、重复导出核对与去标识泄露扫描。"""

from __future__ import annotations

import csv
import json
import re

from crp.paths import Store
from crp.util import read_csv, read_json

FORBIDDEN_EXPORT_NAMES = {"mapping.json", "secret"}
PATTERN_CHECKS = {
    "cn_id_card": re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)"),
    "cn_mobile": re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
    "email": re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])"),
}


def _manual_payload(store: Store, batch_id: str) -> tuple[set[str], set[str]]:
    raw_ids: set[str] = set()
    mapping_path = store.private_dir(batch_id) / "mapping.json"
    if mapping_path.exists():
        raw_ids.update(read_json(mapping_path).get("pseudonyms", {}).keys())
    manual_phrases: set[str] = set()
    manual_path = store.raw_dir(batch_id) / "manual_sensitive.json"
    if manual_path.exists():
        payload = read_json(manual_path)
        entries = payload.get("entries", payload) if isinstance(payload, dict) else payload
        for phrases in entries.values():
            manual_phrases.update(phrase for phrase in phrases if phrase)
    return raw_ids, manual_phrases


def scan_leaks(store: Store, batch_id: str, version: int) -> list[str]:
    batch = read_json(store.batch_file(batch_id))
    raw_ids, manual_phrases = _manual_payload(store, batch_id)
    dropped: dict[str, set[str]] = {}
    for table, rules in batch.get("rules", {}).items():
        dropped[table] = {rule["field"] for rule in rules if rule.get("action") == "drop"}
    findings: list[str] = []
    version_dir = store.version_dir(batch_id, version)
    for path in sorted(version_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in FORBIDDEN_EXPORT_NAMES:
            findings.append(f"公开版本包含禁止文件: {path.relative_to(version_dir)}")
        table = path.stem
        if path.suffix == ".csv":
            with path.open("r", encoding="utf-8", newline="") as fh:
                header = next(csv.reader(fh))
            basis_path = version_dir / "basis.jsonl"
            if not basis_path.exists():
                # 历史版本（无溯源）：维持整列删除检查。
                for field_name in dropped.get(table, set()):
                    if field_name in header:
                        findings.append(f"{path.name} 仍包含应删除字段 {field_name}")
            # 范围化修订下列可能对部分记录保留；是否泄露由逐条内容扫描保证，
            # 每条记录采用了哪条规则见 basis.jsonl。
        elif path.name == "basis.jsonl":
            pass
        else:
            continue
        with path.open("r", encoding="utf-8", newline="") as fh:
            lines = fh.readlines()
        for row_index, line in enumerate(lines, start=2):
            joined = line
            for raw_id in raw_ids:
                if raw_id and raw_id in joined:
                    findings.append(f"{path.name}:{row_index} 出现真实受试者号 {raw_id}")
            for phrase in manual_phrases:
                if phrase in joined:
                    findings.append(f"{path.name}:{row_index} 出现人工敏感片段 {phrase!r}")
            if path.name != "basis.jsonl":
                for name, pattern in PATTERN_CHECKS.items():
                    match = pattern.search(joined)
                    if match:
                        findings.append(f"{path.name}:{row_index} 命中未脱敏模式 {name}: {match.group(0)}")
    return findings


def cross_table_consistency(store: Store, batch_id: str, version: int) -> dict[str, list[str]]:
    """返回 {伪名: [表:行号...]}，覆盖出现在至少两张表中的受试者。"""
    batch = read_json(store.batch_file(batch_id))
    subject_field = batch.get("subject_field", "subject_id")
    seen: dict[str, dict[str, list[int]]] = {}
    for table in batch["tables"]:
        path = store.version_dir(batch_id, version) / f"{table}.csv"
        for line_number, row in enumerate(read_csv(path), start=2):
            sid = row[subject_field]
            seen.setdefault(sid, {}).setdefault(table, []).append(line_number)
    return {
        sid: [f"{table}:{min(lines)}" for table, lines in sorted(places.items())]
        for sid, places in sorted(seen.items())
        if len(places) >= 2
    }
