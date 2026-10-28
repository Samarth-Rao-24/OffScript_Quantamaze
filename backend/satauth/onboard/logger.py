"""Onboard audit logger (FR-11): one JSON line per frame."""

from __future__ import annotations

import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import append_jsonl, read_jsonl


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seq = len(read_jsonl(self.path))

    def write(self, record: dict) -> dict:
        with self._lock:
            self._seq += 1
            rec = {"seq": self._seq, "time_utc": datetime.now(timezone.utc).isoformat(), **record}
            append_jsonl(self.path, rec)
            return rec

    def tail(self, limit: int = 500) -> list[dict]:
        return read_jsonl(self.path, limit=limit)

    def archive(self) -> Path | None:
        """Move the current log aside (used by demo reset; nothing is deleted)."""
        with self._lock:
            if not self.path.exists():
                return None
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            dest = self.path.with_name(f"{self.path.stem}.{stamp}.jsonl")
            shutil.move(str(self.path), dest)
            self._seq = 0
            return dest
