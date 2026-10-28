"""Ground signer (FR-03, FR-04).

Builds frames, assigns a strictly increasing counter that is persisted *before*
the frame is released for transmission, sets the expiry, and signs over
DOMAIN_TAG || header || command || pass nonce.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from ..common import crypto
from ..common.atomic import atomic_write_json, read_json
from ..common.frame import FRAME_VERSION, NONCE_LEN, Frame, max_body_for, pack_header, signed_message
from ..common.roles import ROLE_KEY_ID, Opcode
from .keygen import load_secret_key


class GroundCounter:
    """Monotonic counter persisted atomically before each frame is released."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        state = read_json(self.path, default={"last_issued": 0})
        self._last = int(state["last_issued"])

    @property
    def last_issued(self) -> int:
        return self._last

    def next(self) -> int:
        with self._lock:
            value = self._last + 1
            atomic_write_json(self.path, {"last_issued": value})  # persist first (FR-04)
            self._last = value
            return value

    def reset(self) -> None:
        with self._lock:
            self._last = 0
            atomic_write_json(self.path, {"last_issued": 0})


class Signer:
    def __init__(self, data_dir: Path, sat_id: int, default_expiry_s: int = 600):
        self.data_dir = Path(data_dir)
        self.sat_id = sat_id
        self.default_expiry_s = default_expiry_s
        self.counter = GroundCounter(self.data_dir / "ground" / "counter.json")
        self._sk_cache: dict[str, bytes] = {}

    def _sk(self, role: str) -> bytes:
        if role not in self._sk_cache:
            self._sk_cache[role] = load_secret_key(self.data_dir, role)
        return self._sk_cache[role]

    def build(
        self,
        *,
        role: str,
        command: bytes,
        pass_nonce: bytes,
        sat_id: int | None = None,
        expiry: int | None = None,
        counter: int | None = None,
        now: float | None = None,
        secret_key: bytes | None = None,
        key_id: int | None = None,
    ) -> Frame:
        """Sign a frame. Optional overrides exist only so the attack lab and
        tests can construct hostile frames with the *real* signing path."""
        if not command:
            raise ValueError("command body must contain at least the opcode")
        if len(command) > max_body_for(command[0]):
            raise ValueError(f"command body {len(command)} B exceeds limit")
        if len(pass_nonce) != NONCE_LEN:
            raise ValueError("pass nonce must be 32 bytes")
        now = time.time() if now is None else now
        kid = ROLE_KEY_ID[role] if key_id is None else key_id
        sid = self.sat_id if sat_id is None else sat_id
        exp = int(now) + self.default_expiry_s if expiry is None else int(expiry)
        ctr = self.counter.next() if counter is None else int(counter)
        header = pack_header(FRAME_VERSION, sid, kid, len(command), ctr, exp)
        sk = self._sk(role) if secret_key is None else secret_key
        sig = crypto.sign(sk, signed_message(header, command, pass_nonce))
        return Frame(FRAME_VERSION, sid, kid, ctr, exp, bytes(command), sig)

    def pass_open(self, *, new_nonce: bytes, current_nonce: bytes, now: float | None = None) -> Frame:
        """PASS_OPEN carries the new QRNG nonce and is signed (ADMIN key) over the
        nonce currently installed onboard, chaining passes together."""
        if len(new_nonce) != NONCE_LEN:
            raise ValueError("new nonce must be 32 bytes")
        body = bytes([Opcode.PASS_OPEN]) + new_nonce
        return self.build(role="ADMIN", command=body, pass_nonce=current_nonce, now=now)
