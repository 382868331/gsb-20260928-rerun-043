"""On-disk project layout.

Two areas are kept strictly separate:

* ``.crp-private/`` holds direct identifiers, subject pseudonym mappings,
  date offsets, full field rules and imported raw data. It is created with
  0700 and files with 0600 so mappings never leak into public results.
* ``exports/`` holds only de-identified, shareable data plus a manifest.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PRIVATE_DIR = ".crp-private"
EXPORT_DIR = "exports"


class ProjectError(Exception):
    pass


def _atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    os.chmod(path, mode)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    _atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode)


@dataclass
class Project:
    root: Path

    @classmethod
    def init(cls, root: str | Path = ".") -> "Project":
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        priv = root / PRIVATE_DIR
        priv.mkdir(exist_ok=True)
        os.chmod(priv, 0o700)
        for sub in ("batches", "mappings", "rules", "raw", "versions"):
            (priv / sub).mkdir(exist_ok=True)
            os.chmod(priv / sub, 0o700)
        salt_path = priv / "salt"
        if not salt_path.exists():
            _atomic_write(salt_path, secrets.token_hex(32) + "\n")
        (root / EXPORT_DIR).mkdir(exist_ok=True)
        return cls(root)

    @classmethod
    def open(cls, root: str | Path = ".") -> "Project":
        root = Path(root).resolve()
        priv = root / PRIVATE_DIR
        if not priv.is_dir():
            raise ProjectError(f"not a crp project (missing {PRIVATE_DIR}); run 'crp init' first")
        return cls(root)

    @property
    def private(self) -> Path:
        return self.root / PRIVATE_DIR

    @property
    def exports(self) -> Path:
        return self.root / EXPORT_DIR

    @property
    def salt(self) -> bytes:
        return (self.private / "salt").read_text(encoding="utf-8").strip().encode("utf-8")

    # ---- batches -------------------------------------------------------
    def batch_path(self, batch_id: str) -> Path:
        return self.private / "batches" / f"{batch_id}.json"

    def load_batch(self, batch_id: str) -> dict[str, Any]:
        path = self.batch_path(batch_id)
        if not path.exists():
            raise ProjectError(f"batch not found: {batch_id}")
        return read_json(path)

    def save_batch(self, batch: dict[str, Any]) -> None:
        write_json(self.batch_path(batch["id"]), batch)

    def list_batches(self) -> list[dict[str, Any]]:
        d = self.private / "batches"
        return [read_json(p) for p in sorted(d.glob("*.json"))]

    # ---- raw imported tables ------------------------------------------
    def raw_dir(self, batch_id: str) -> Path:
        return self.private / "raw" / batch_id

    # ---- mappings ------------------------------------------------------
    def mapping_path(self, batch_id: str) -> Path:
        return self.private / "mappings" / f"{batch_id}.json"

    # ---- private, full rule snapshots ---------------------------------
    def rule_snapshot_path(self, batch_id: str, version: int) -> Path:
        return self.private / "rules" / batch_id / f"rules-v{version:06d}.json"

    # ---- export version metadata (private) ----------------------------
    def version_meta_path(self, batch_id: str, version: int) -> Path:
        return self.private / "versions" / batch_id / f"v{version:06d}.json"

    def list_versions(self, batch_id: str) -> list[dict[str, Any]]:
        d = self.private / "versions" / batch_id
        if not d.is_dir():
            return []
        return [read_json(p) for p in sorted(d.glob("v*.json"))]

    def export_version_dir(self, batch_id: str, version: int) -> Path:
        return self.exports / batch_id / f"v{version:06d}"
