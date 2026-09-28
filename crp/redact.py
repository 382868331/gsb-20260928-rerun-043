"""文本字段敏感片段脱敏。

去标识不能只靠删除整列：自由文本（主诉、备注、用药说明）里常常由人工写入
姓名、证件号、电话、地址、住院号等片段。这里组合两类来源：

1. 内置正则模式（中文手机号、18 位身份证号、邮箱等），也接受规则里额外配置的模式；
2. 人工标注文件 ``raw/<batch>/manual_sensitive.json``，逐受试者列出敏感短语，
   例如文本里出现的家属姓名、具体住址——这些模式识别无法可靠覆盖，必须由人工补录。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from crp.util import read_json

REDACTION = "[REDACTED]"

# 顺序有意义：更长、更具体的模式先替换，避免被短模式截断。
# 中文也属于 \w，不能用 \b 判断中文与数字的边界；改用数字/单词字符环视。
BUILTIN_PATTERNS: dict[str, str] = {
    "cn_id_card": r"(?<!\d)\d{17}[0-9Xx](?!\d)",
    "cn_mobile": r"(?<!\d)1[3-9]\d{9}(?!\d)",
    "email": r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w.-])",
}


class Redactor:
    def __init__(self, manual_phrases_by_subject: dict[str, list[str]] | None = None,
                 extra_pattern_names: dict[str, str] | None = None) -> None:
        patterns: list[tuple[str, re.Pattern[str]]] = [
            ("cn_id_card", re.compile(BUILTIN_PATTERNS["cn_id_card"])),
            ("cn_mobile", re.compile(BUILTIN_PATTERNS["cn_mobile"])),
            ("email", re.compile(BUILTIN_PATTERNS["email"])),
        ]
        for name, pattern in (extra_pattern_names or {}).items():
            patterns.append((name, re.compile(pattern)))
        # 长模式优先，保证重叠片段整体替换。
        self._patterns = patterns
        self._manual_by_subject: dict[str, list[str]] = {
            subject: sorted({phrase for phrase in phrases if phrase},
                            key=len, reverse=True)
            for subject, phrases in (manual_phrases_by_subject or {}).items()
        }

    @classmethod
    def from_batch(cls, raw_dir: Path, extra_patterns: dict[str, str] | None = None) -> "Redactor":
        manual_path = raw_dir / "manual_sensitive.json"
        manual: dict[str, list[str]] = {}
        if manual_path.exists():
            payload = read_json(manual_path)
            entries = payload.get("entries", payload) if isinstance(payload, dict) else payload
            for subject_id, phrases in entries.items():
                manual[subject_id] = list(phrases)
        return cls(manual, extra_patterns)

    def redact(self, text: str, subject_id: str = "") -> str:
        if text is None:
            return text
        result = str(text)
        for phrase in self._manual_by_subject.get(subject_id, []):
            result = result.replace(phrase, REDACTION)
        for _name, pattern in self._patterns:
            result = pattern.sub(REDACTION, result)
        return result


def load_manual_phrases(path: Path) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    entries = payload.get("entries", payload) if isinstance(payload, dict) else payload
    return {str(subject): list(phrases) for subject, phrases in entries.items()}
