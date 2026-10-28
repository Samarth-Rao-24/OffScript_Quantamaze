"""Simulated bandwidth-limited uplink (FR-12).

The ground transmitter can never exceed a pass's byte budget: a frame that does
not fit is refused *before* it is radiated and is not delivered. Attack traffic
injected by the attack lab models a hostile transmitter and is accounted for
separately (it does not consume the ground budget).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import append_jsonl


class LinkBudgetExceeded(RuntimeError):
    pass


class LinkSimulator:
    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.window_id = 0
        self.pass_no: int | None = None
        self.budget = 0
        self.used = 0
        self.frames_sent = 0
        self.refused = 0
        self.hostile_bytes = 0
        self.hostile_frames = 0
        self.history: list[dict] = []

    def open_window(self, window_id: int, pass_no: int | None, budget: int) -> None:
        if self.window_id:
            self.history.append(self.snapshot())
        self.window_id = window_id
        self.pass_no = pass_no
        self.budget = budget
        self.used = 0
        self.frames_sent = 0
        self.refused = 0
        self.hostile_bytes = 0
        self.hostile_frames = 0

    def can_send(self, n: int) -> bool:
        return self.used + n <= self.budget

    def transmit(self, data: bytes, *, label: str) -> dict:
        """Ground transmission. Raises LinkBudgetExceeded instead of overrunning."""
        n = len(data)
        if not self.window_id:
            raise RuntimeError("no contact window open")
        if not self.can_send(n):
            self.refused += 1
            self._log({"event": "REFUSED", "label": label, "bytes": n, "used": self.used, "budget": self.budget})
            raise LinkBudgetExceeded(
                f"frame of {n} B refused: {self.used} B already used of {self.budget} B in window {self.window_id}"
            )
        self.used += n
        self.frames_sent += 1
        rec = {"event": "TX", "label": label, "bytes": n, "used": self.used, "budget": self.budget}
        self._log(rec)
        return rec

    def inject_hostile(self, data: bytes, *, label: str, log: bool = True) -> None:
        self.hostile_bytes += len(data)
        self.hostile_frames += 1
        if log:
            self._log({"event": "HOSTILE", "label": label, "bytes": len(data)})

    def snapshot(self) -> dict:
        return {
            "window_id": self.window_id,
            "pass": self.pass_no,
            "budget_bytes": self.budget,
            "used_bytes": self.used,
            "remaining_bytes": self.budget - self.used,
            "frames_sent": self.frames_sent,
            "refused": self.refused,
            "hostile_frames": self.hostile_frames,
            "hostile_bytes": self.hostile_bytes,
        }

    def _log(self, rec: dict) -> None:
        append_jsonl(self.log_path, {"time_utc": datetime.now(timezone.utc).isoformat(), "window": self.window_id,
                                     "pass": self.pass_no, **rec})
