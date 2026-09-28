"""平台目录结构。

``raw/``     原始（虚构）研究记录，按批次存放 CSV；
``batches/`` 批次配置与字段规则（含规则变更历史）；
``private/`` 伪名/日期偏移映射与批次密钥，仅限内部，禁止进入公开导出；
``exports/`` 去标识后的公开结果，按不可变版本目录存放。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Store:
    root: Path

    @classmethod
    def create(cls, root: str | Path) -> "Store":
        return cls(root=Path(root))

    def raw_dir(self, batch_id: str) -> Path:
        return self.root / "raw" / batch_id

    def batch_dir(self, batch_id: str) -> Path:
        return self.root / "batches" / batch_id

    def batch_file(self, batch_id: str) -> Path:
        return self.batch_dir(batch_id) / "batch.json"

    def private_dir(self, batch_id: str) -> Path:
        return self.root / "private" / batch_id

    def export_dir(self, batch_id: str) -> Path:
        return self.root / "exports" / batch_id

    def version_dir(self, batch_id: str, version: int) -> Path:
        return self.export_dir(batch_id) / f"v{version:03d}"

    def export_index(self, batch_id: str) -> Path:
        return self.export_dir(batch_id) / "index.json"
