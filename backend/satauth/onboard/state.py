"""Onboard state store: emulated non-volatile memory (JSON + atomic rename).

Persistent: sat_id, preloaded public keys, role table, last accepted counter,
current pass nonce, current pass index. The flood-failure count is deliberately
volatile (RAM) so that rejected frames cause zero NV writes (NFR-05).
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import atomic_write_json, read_json


class StateStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.nv_writes = 0  # number of NV write calls since this process started
        self._state: dict = read_json(self.path, default=None) or {}

    # ---- provisioning ----
    @property
    def provisioned(self) -> bool:
        return bool(self._state.get("public_keys"))

    def provision(self, *, sat_id: int, public_keys: dict[int, bytes], role_table: dict, genesis_nonce: bytes,
                  key_meta: dict[int, dict] | None = None) -> None:
        """Ground-side pre-launch provisioning (FR-02). Not a flight operation.

        ``key_meta`` = key_id -> {role, suite, state}; keys not listed default to the
        role in KEY_IDS, Falcon-512, active (the original two-key layout)."""
        from ..common.roles import KEY_IDS, KEY_RING_SPEC

        spec = {kid: {"role": r, "suite": su, "state": st} for kid, r, su, st in KEY_RING_SPEC}
        meta = {}
        for k in public_keys:
            m = (key_meta or {}).get(k) or spec.get(k) or {"role": KEY_IDS.get(k), "suite": "falcon512", "state": "active"}
            meta[str(k)] = {"role": m["role"], "suite": m["suite"], "state": m["state"]}
        with self._lock:
            self._state = {
                "sat_id": sat_id,
                "public_keys": {str(k): v.hex() for k, v in public_keys.items()},
                "key_meta": meta,
                "role_table": role_table,
                "last_counter": 0,
                "pass_nonce": genesis_nonce.hex(),
                "pass_index": 0,
                "accepted_total": 0,
                "provisioned_utc": datetime.now(timezone.utc).isoformat(),
            }
            atomic_write_json(self.path, self._state)
            self.nv_writes = 0

    # ---- reads (no NV writes) ----
    @property
    def sat_id(self) -> int:
        return int(self._state["sat_id"])

    @property
    def last_counter(self) -> int:
        return int(self._state["last_counter"])

    @property
    def pass_nonce(self) -> bytes:
        return bytes.fromhex(self._state["pass_nonce"])

    @property
    def pass_index(self) -> int:
        return int(self._state["pass_index"])

    def gap_summary(self) -> dict:
        return {"reports": int(self._state.get("gaps_reported_total", 0)),
                "missing_counters": int(self._state.get("missing_counters_total", 0)),
                "last_gap": self._state.get("last_gap")}

    def public_key(self, key_id: int) -> bytes | None:
        hx = self._state["public_keys"].get(str(key_id))
        return bytes.fromhex(hx) if hx else None

    def _key_meta(self, key_id: int) -> dict | None:
        if str(key_id) not in self._state["public_keys"]:
            return None
        from ..common.roles import KEY_IDS

        return (self._state.get("key_meta") or {}).get(str(key_id)) or {
            "role": KEY_IDS.get(key_id), "suite": "falcon512", "state": "active"}  # pre-ring state files

    def role_for_key(self, key_id: int) -> str | None:
        m = self._key_meta(key_id)
        return m["role"] if m else None

    def key_state(self, key_id: int) -> str | None:
        m = self._key_meta(key_id)
        return m["state"] if m else None

    def key_suite(self, key_id: int) -> str | None:
        m = self._key_meta(key_id)
        return m["suite"] if m else None

    def key_ring(self) -> dict[str, dict]:
        import hashlib

        return {k: {**(self._key_meta(int(k)) or {}), "public_key_sha256": hashlib.sha256(bytes.fromhex(v)).hexdigest()}
                for k, v in self._state.get("public_keys", {}).items()}

    def allowed(self, role: str, opcode: int) -> bool:
        return opcode in set(self._state["role_table"].get(role, []))

    def snapshot(self) -> dict:
        import hashlib

        s = dict(self._state)
        s["public_keys"] = {
            k: {"len": len(v) // 2, "sha256": hashlib.sha256(bytes.fromhex(v)).hexdigest()}
            for k, v in s.get("public_keys", {}).items()
        }
        return s

    # ---- the single NV write on acceptance (NFR-04) ----
    def commit_accept(self, *, counter: int, new_nonce: bytes | None = None, new_pass_index: int | None = None,
                      gap: dict | None = None, key_change: tuple[int, str] | None = None) -> None:
        with self._lock:
            new_state = dict(self._state)
            new_state["last_counter"] = counter
            if key_change is not None:  # KEY_ACTIVATE / KEY_REVOKE take effect in the same single write
                kid, new = key_change
                km = {k: dict(v) for k, v in (new_state.get("key_meta") or {}).items()}
                if str(kid) not in km:
                    km[str(kid)] = dict(self._key_meta(kid) or {})
                km[str(kid)]["state"] = new
                new_state["key_meta"] = km
            if gap:  # same single write: no extra NV cost for gap reporting
                new_state["gaps_reported_total"] = int(new_state.get("gaps_reported_total", 0)) + 1
                new_state["missing_counters_total"] = int(new_state.get("missing_counters_total", 0)) + int(gap["count"])
                new_state["last_gap"] = gap
            new_state["accepted_total"] = int(new_state.get("accepted_total", 0)) + 1
            if new_nonce is not None:
                new_state["pass_nonce"] = new_nonce.hex()
            if new_pass_index is not None:
                new_state["pass_index"] = new_pass_index
            atomic_write_json(self.path, new_state)  # write first, then adopt
            self._state = new_state
            self.nv_writes += 1

    def reload(self) -> None:
        """Simulate a reboot: re-read NV memory."""
        with self._lock:
            self._state = read_json(self.path, default={}) or {}
