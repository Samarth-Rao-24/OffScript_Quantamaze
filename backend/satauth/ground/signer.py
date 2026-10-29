"""Ground signer (FR-03, FR-04).

Builds frames, assigns a strictly increasing counter that is persisted *before*
the frame is released for transmission, sets the expiry, and signs over
DOMAIN_TAG || header || command || pass nonce.
"""

from __future__ import annotations

from collections import OrderedDict

import threading
import time
from pathlib import Path

from ..common import crypto, suites  # noqa: F401
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


class KeyRingState:
    """The ground's view of its key ring: which key each role signs with, and which
    keys are retired. Persisted; changed only after the satellite acknowledges a
    KEY_ACTIVATE / KEY_REVOKE frame."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._s = read_json(self.path, default=None) or self._default()

    @staticmethod
    def _default() -> dict:
        from .keygen import ring_spec

        return {"signing": {r: k for r, k in ROLE_KEY_ID.items()},
                "states": {str(k): v["state"] for k, v in ring_spec().items()}}

    def signing_kid(self, role: str) -> int:
        return int(self._s["signing"][role])

    def state(self, kid: int) -> str:
        return self._s["states"].get(str(kid), "standby")

    def set(self, kid: int, state: str, *, signing_role: str | None = None) -> None:
        with self._lock:
            self._s["states"][str(kid)] = state
            if signing_role:
                self._s["signing"][signing_role] = kid
            atomic_write_json(self.path, self._s)

    def reset(self) -> None:
        with self._lock:
            self._s = self._default()
            atomic_write_json(self.path, self._s)

    def snapshot(self) -> dict:
        return {"signing": dict(self._s["signing"]), "states": dict(self._s["states"])}


class Signer:
    def __init__(self, data_dir: Path, sat_id: int, default_expiry_s: int = 600):
        self.data_dir = Path(data_dir)
        self.sat_id = sat_id
        self.default_expiry_s = default_expiry_s
        self.counter = GroundCounter(self.data_dir / "ground" / "counter.json")
        self.ring = KeyRingState(self.data_dir / "ground" / "key_ring_state.json")
        self._sk_cache: dict[int, bytes] = {}
        # counters this ground station assigned in this session (bounded), used to
        # reconcile the satellite's counter-gap reports
        self.issued: OrderedDict[int, dict] = OrderedDict()

    def _sk(self, kid: int) -> bytes:
        if kid not in self._sk_cache:
            self._sk_cache[kid] = load_secret_key(self.data_dir, kid)
        return self._sk_cache[kid]

    def suite_for(self, kid: int) -> str:
        from .keygen import ring_spec

        spec = ring_spec().get(int(kid))
        return spec["suite"] if spec else suites.DEFAULT_SUITE

    def sig_len_for_role(self, role: str) -> int:
        return suites.SUITES[self.suite_for(self.ring.signing_kid(role))]["sig_len"]

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
        suite: str | None = None,
        allow_retired: bool = False,
    ) -> Frame:
        """Sign a frame with the role's current signing key (its own suite). Optional
        overrides exist only so the attack lab and tests can construct hostile frames
        with the *real* signing path."""
        if not command:
            raise ValueError("command body must contain at least the opcode")
        if len(command) > max_body_for(command[0]):
            raise ValueError(f"command body {len(command)} B exceeds limit")
        if len(pass_nonce) != NONCE_LEN:
            raise ValueError("pass nonce must be 32 bytes")
        now = time.time() if now is None else now
        kid = self.ring.signing_kid(role) if key_id is None else key_id
        if secret_key is None:
            from .keygen import ring_spec

            own = kid if kid in ring_spec() else self.ring.signing_kid(role)  # a claimed foreign key_id: sign with our own key
            if self.ring.state(own) == "retired" and not allow_retired:
                raise ValueError(f"key_id {own} is retired; the ground no longer signs with it")
            sk, use_suite = self._sk(own), self.suite_for(own)
        else:
            sk, use_suite = secret_key, suite or suites.DEFAULT_SUITE
        sid = self.sat_id if sat_id is None else sat_id
        exp = int(now) + self.default_expiry_s if expiry is None else int(expiry)
        ctr = self.counter.next() if counter is None else int(counter)
        if counter is None:
            self.issued[ctr] = {"role": role, "opcode": command[0], "time": now, "key_id": kid}
            while len(self.issued) > 5000:
                self.issued.popitem(last=False)
        header = pack_header(FRAME_VERSION, sid, kid, len(command), ctr, exp)
        sig = suites.sign(use_suite, sk, signed_message(header, command, pass_nonce))
        return Frame(FRAME_VERSION, sid, kid, ctr, exp, bytes(command), sig)

    def pass_open(self, *, new_nonce: bytes, current_nonce: bytes, now: float | None = None) -> Frame:
        """PASS_OPEN carries the new QRNG nonce and is signed (ADMIN key) over the
        nonce currently installed onboard, chaining passes together."""
        if len(new_nonce) != NONCE_LEN:
            raise ValueError("new nonce must be 32 bytes")
        body = bytes([Opcode.PASS_OPEN]) + new_nonce
        return self.build(role="ADMIN", command=body, pass_nonce=current_nonce, now=now)
