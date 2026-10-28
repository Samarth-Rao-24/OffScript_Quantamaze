"""Flood guard (FR-13, NFR-06).

Counts signature failures within the current contact window. Once the count
reaches ``limit`` (N, default 8) every further frame in that window is rejected
at step 0 with no parsing-beyond-header and no signature work.

The window is reset by the onboard contact-window timer (``begin_window``),
which the satellite derives from its own pass schedule, not by a frame: if the
reset depended on a PASS_OPEN frame, a lockout could never be lifted.
"""

from __future__ import annotations


class FloodGuard:
    def __init__(self, limit: int = 8):
        if limit < 1:
            raise ValueError("flood limit must be >= 1")
        self.limit = limit
        self.window_id = 0
        self.failures = 0
        self.dropped = 0

    @property
    def locked(self) -> bool:
        return self.failures >= self.limit

    def begin_window(self, window_id: int) -> None:
        self.window_id = window_id
        self.failures = 0
        self.dropped = 0

    def record_sig_failure(self) -> None:
        self.failures += 1

    def record_drop(self) -> None:
        self.dropped += 1

    def snapshot(self) -> dict:
        return {
            "window_id": self.window_id,
            "failures": self.failures,
            "limit": self.limit,
            "locked": self.locked,
            "dropped_without_verify": self.dropped,
        }
