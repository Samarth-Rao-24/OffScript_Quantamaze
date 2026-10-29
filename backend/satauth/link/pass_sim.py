"""Simulated bandwidth-limited uplink (FR-12).

The ground transmitter can never exceed a pass's byte budget: a frame that does
not fit is refused *before* it is radiated and is not delivered. Attack traffic
injected by the attack lab models a hostile transmitter and is accounted for
separately (it does not consume the ground budget).

Packet loss (missing-packet drill): a frame can be marked as lost on the RF
path. It is radiated (it uses link bytes) but never reaches the spacecraft.
Loss is either deterministic (drop the first transmission of named frames) or
random with a fixed seed, so every drill is reproducible. Only the simulator
knows a frame was lost; the ground learns it the way a real station does, from
the missing acknowledgement and the satellite's counter-gap report.
"""

from __future__ import annotations

import random
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
        self.lost = 0
        self._drop_once: set[str] = set()
        self._loss_rate = 0.0
        self._rng = random.Random(0)

    def set_loss(self, *, drop: list[str] | None = None, rate: float = 0.0, seed: int | None = None) -> dict:
        """Configure simulated packet loss. ``drop`` lists frame labels whose *first*
        transmission is lost; ``rate`` is a seeded random loss probability."""
        if not 0.0 <= float(rate) <= 0.5:
            raise ValueError("loss rate must be between 0 and 0.5")
        self._drop_once = set(drop or [])
        self._loss_rate = float(rate)
        self._rng = random.Random(seed if seed is not None else 0)
        return self.loss_config()

    def clear_loss(self) -> None:
        self._drop_once, self._loss_rate = set(), 0.0

    def loss_config(self) -> dict:
        return {"drop_first_tx_of": sorted(self._drop_once), "random_rate": self._loss_rate}

    def _is_lost(self, label: str) -> bool:
        if label in self._drop_once:
            self._drop_once.discard(label)  # only the first transmission of that frame is lost
            return True
        return self._loss_rate > 0 and self._rng.random() < self._loss_rate

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
        self.lost = 0

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
        lost = self._is_lost(label)
        rec = {"event": "TX", "label": label, "bytes": n, "used": self.used, "budget": self.budget, "lost": lost}
        if lost:
            self.lost += 1
            rec["event"] = "TX_LOST"
            rec["note"] = "simulated RF loss: radiated, never delivered to the spacecraft"
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
            "lost": self.lost,
            "loss_model": self.loss_config(),
            "hostile_frames": self.hostile_frames,
            "hostile_bytes": self.hostile_bytes,
        }

    def _log(self, rec: dict) -> None:
        append_jsonl(self.log_path, {"time_utc": datetime.now(timezone.utc).isoformat(), "window": self.window_id,
                                     "pass": self.pass_no, **rec})
