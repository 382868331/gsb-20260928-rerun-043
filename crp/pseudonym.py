"""受试者伪名与按人固定日期偏移。

同一批次内：
- 真实受试者号经过带批次密钥的 HMAC 派生为稳定伪名，
  因此同一受试者在 demographics / visit / lab / medication 等多张表中得到同一个伪名，
  跨表关联在导出后仍然一致；
- 每位受试者得到一个由其编号与批次密钥确定性派生的固定日期偏移（含正负），
  该受试者所有日期使用同一偏移，保留随访间隔与相对时序。

映射表只写入 ``private/``，绝不出现在 ``exports/`` 公开结果中；
它的存在用于内部审计与必要时回溯。重复导出复用同一映射，保证结果可复现。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from crp.paths import Store
from crp.util import read_json, write_json

MIN_OFFSET_DAYS = -90
MAX_OFFSET_DAYS = 90


def _derive_pseudonym(secret: str, batch_id: str, subject_id: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), f"{batch_id}|{subject_id}".encode("utf-8"), hashlib.sha256)
    return "S" + digest.hexdigest()[:16].upper()


def _derive_offset_days(secret: str, batch_id: str, subject_id: str) -> int:
    digest = hmac.new(
        secret.encode("utf-8"), f"shift|{batch_id}|{subject_id}".encode("utf-8"), hashlib.sha256
    ).digest()
    value = int.from_bytes(digest[:8], "big")
    span = MAX_OFFSET_DAYS - MIN_OFFSET_DAYS + 1
    return MIN_OFFSET_DAYS + value % span


@dataclass
class SubjectMapping:
    batch_id: str
    secret: str
    pseudonyms: dict[str, str]
    offset_days: dict[str, int]

    @classmethod
    def _path(cls, store: Store, batch_id: str):
        return store.private_dir(batch_id) / "mapping.json"

    @classmethod
    def load_or_create(cls, store: Store, batch_id: str) -> "SubjectMapping":
        path = cls._path(store, batch_id)
        if path.exists():
            raw = read_json(path)
            return cls(
                batch_id=raw["batch_id"],
                secret=raw["secret"],
                pseudonyms=dict(raw["pseudonyms"]),
                offset_days={k: int(v) for k, v in raw["offset_days"].items()},
            )
        mapping = cls(batch_id=batch_id, secret=secrets.token_hex(32), pseudonyms={}, offset_days={})
        mapping.save(store)
        return mapping

    def save(self, store: Store) -> None:
        write_json(
            self._path(store, self.batch_id),
            {
                "_warning": "机密文件：真实受试者号到伪名/日期偏移的映射，禁止随公开导出分发。",
                "batch_id": self.batch_id,
                "secret": self.secret,
                "pseudonyms": dict(sorted(self.pseudonyms.items())),
                "offset_days": dict(sorted(self.offset_days.items())),
            },
        )

    def register(self, subject_id: str) -> tuple[str, int]:
        subject_id = subject_id.strip()
        if not subject_id:
            raise ValueError("受试者编号不能为空")
        pseudonym = self.pseudonyms.get(subject_id)
        if pseudonym is None:
            pseudonym = _derive_pseudonym(self.secret, self.batch_id, subject_id)
            if pseudonym in self.pseudonyms.values():
                raise RuntimeError("伪名冲突（概率上不应发生），请更换批次密钥")
            self.pseudonyms[subject_id] = pseudonym
            self.offset_days[subject_id] = _derive_offset_days(self.secret, self.batch_id, subject_id)
        return pseudonym, self.offset_days[subject_id]

    def pseudonym_for(self, subject_id: str) -> str:
        return self.register(subject_id)[0]

    def offset_for(self, subject_id: str) -> int:
        return self.register(subject_id)[1]
