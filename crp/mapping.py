"""Private subject mapping: raw subject id -> stable pseudonym and a
fixed per-subject date offset.

This is the *only* place raw identifiers are kept. The mapping file lives in
``.crp-private/mappings/`` (0600) and is never copied into ``exports/``.

The mapping is persistent and shared across every table of a batch, so the
same subject receives the same pseudonym and the same date shift everywhere,
both across tables and across repeated exports.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import date

from .storage import Project, read_json, write_json


class SubjectMapping:
    def __init__(self, project: Project, batch_id: str):
        self._project = project
        self._batch_id = batch_id
        self._path = project.mapping_path(batch_id)
        if self._path.exists():
            data = read_json(self._path)
            self._pseudo: dict[str, str] = data["pseudonyms"]
            self._offset: dict[str, int] = data["date_offsets_days"]
        else:
            self._pseudo = {}
            self._offset = {}

    # -- persistence -----------------------------------------------------
    def save(self) -> None:
        write_json(
            self._path,
            {
                "batch_id": self._batch_id,
                "pseudonyms": self._pseudo,
                "date_offsets_days": self._offset,
            },
        )

    # -- pseudonyms ------------------------------------------------------
    def pseudonym(self, raw_subject_id: str) -> str:
        if raw_subject_id not in self._pseudo:
            # Order-independent, unguessable pseudonym derived with the
            # batch-specific private salt. Output is a fixed-width token.
            digest = hmac.new(
                self._project.salt, f"subject\x1f{raw_subject_id}".encode("utf-8"), hashlib.sha256
            ).hexdigest()
            self._pseudo[raw_subject_id] = f"P{digest[:16].upper()}"
        return self._pseudo[raw_subject_id]

    # -- dates -----------------------------------------------------------
    def date_offset_days(self, raw_subject_id: str) -> int:
        """Deterministic, fixed per-subject offset in [-180, 180) days.

        Derived from the private salt so it is stable across exports but not
        recoverable from the public data.
        """
        if raw_subject_id not in self._offset:
            digest = hmac.new(
                self._project.salt, f"dateshift\x1f{raw_subject_id}".encode("utf-8"), hashlib.sha256
            ).digest()
            number = int.from_bytes(digest[:8], "big")
            self._offset[raw_subject_id] = (number % 360) - 180
        return self._offset[raw_subject_id]

    def shift_date(self, raw_subject_id: str, value: date) -> date:
        from datetime import timedelta

        return value + timedelta(days=self.date_offset_days(raw_subject_id))

    # -- introspection (for verification only, private side) -------------
    def raw_ids(self) -> list[str]:
        return sorted(self._pseudo)

    def pseudonyms(self) -> dict[str, str]:
        return dict(self._pseudo)

    def offsets(self) -> dict[str, int]:
        return dict(self._offset)
