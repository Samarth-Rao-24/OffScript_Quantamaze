"""Onboard verifier: the ordered check pipeline (PRD section 7).

    0  flood guard            E_FLOOD_LOCKOUT  (no signature work)
    -  parse frame            E_MALFORMED      (addition: unparseable bytes)
    1  sat_id matches         E_WRONG_SAT
    2  expiry >= onboard clock E_EXPIRED
    3  counter > last         E_REPLAY
    4  signature over frame + current pass nonce   E_BAD_SIG
    5  opcode allowed for key's role                E_UNAUTHORIZED
    -  all passed: commit counter (1 NV write), execute   OK

The first failure stops processing. The counter is committed only after steps
4 and 5 pass, so no rejected frame can advance it.
"""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from ..common import crypto
from ..common.frame import NONCE_LEN, MalformedFrame, parse_frame
from ..common.roles import Opcode, opcode_name
from .flood_guard import FloodGuard
from .logger import AuditLog
from .state import StateStore

OK = "OK"
E_FLOOD_LOCKOUT = "E_FLOOD_LOCKOUT"
E_MALFORMED = "E_MALFORMED"
E_WRONG_SAT = "E_WRONG_SAT"
E_EXPIRED = "E_EXPIRED"
E_REPLAY = "E_REPLAY"
E_BAD_SIG = "E_BAD_SIG"
E_UNAUTHORIZED = "E_UNAUTHORIZED"

STEP_NAMES = [
    (0, "flood_guard", "Flood guard below limit"),
    (None, "parse", "Frame well-formed"),
    (1, "sat_id", "Satellite ID matches"),
    (2, "expiry", "Not expired"),
    (3, "counter", "Counter > last accepted"),
    (4, "signature", "Falcon signature over frame + pass nonce"),
    (5, "role", "Opcode allowed for key role"),
]


@dataclass
class VerifierStats:
    frames: int = 0
    accepted: int = 0
    rejected: int = 0
    sig_verifications: int = 0
    sig_verify_ns_total: int = 0
    by_reason: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "frames": self.frames,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "sig_verifications": self.sig_verifications,
            "sig_verify_ms_total": round(self.sig_verify_ns_total / 1e6, 3),
            "by_reason": dict(self.by_reason),
        }


class OnboardVerifier:
    def __init__(self, state: StateStore, log: AuditLog | None, flood_limit: int = 8, clock=time.time):
        self.state = state
        self.log = log
        self.guard = FloodGuard(flood_limit)
        self.clock = clock
        self.stats = VerifierStats()
        self.executed: deque = deque(maxlen=20)  # bounded onboard memory

    # ---- onboard timer event: new contact window ----
    def begin_window(self, window_id: int) -> dict:
        self.guard.begin_window(window_id)
        return self.guard.snapshot()

    # ---- main entry ----
    def process(self, data: bytes, *, now: float | None = None, context: dict | None = None) -> dict:
        t_start = time.perf_counter_ns()
        now = self.clock() if now is None else now
        steps: list[dict] = []
        nv_before = self.state.nv_writes
        result = {
            "verdict": "REJECT",
            "reason": None,
            "frame_len": len(data),
            "frame_sha256": hashlib.sha256(data).hexdigest(),
            "window_id": self.guard.window_id,
            "pass_index": self.state.pass_index,
            "sig_checked": False,
            "counter": None,
            "opcode": None,
            "opcode_name": None,
            "key_id": None,
            "role": None,
            "sat_id": None,
            "executed": None,
        }

        def step(num, name, label, ok, detail="", t0=None):
            steps.append(
                {
                    "step": num,
                    "name": name,
                    "label": label,
                    "status": "pass" if ok else "fail",
                    "detail": detail,
                    "us": round((time.perf_counter_ns() - t0) / 1000, 2) if t0 else None,
                }
            )

        def finish(reason: str) -> dict:
            result["reason"] = reason
            result["verdict"] = "ACCEPT" if reason == OK else "REJECT"
            # mark the steps that were never reached
            done = {s["name"] for s in steps}
            for num, name, label in STEP_NAMES:
                if name not in done:
                    steps.append({"step": num, "name": name, "label": label, "status": "skipped", "detail": "", "us": None})
            order = {name: i for i, (_, name, _) in enumerate(STEP_NAMES)}
            result["steps"] = sorted(steps, key=lambda s: order[s["name"]])
            result["total_us"] = round((time.perf_counter_ns() - t_start) / 1000, 2)
            result["nv_writes"] = self.state.nv_writes - nv_before
            result["last_counter_after"] = self.state.last_counter
            result["flood"] = self.guard.snapshot()
            self.stats.frames += 1
            if reason == OK:
                self.stats.accepted += 1
            else:
                self.stats.rejected += 1
            self.stats.by_reason[reason] = self.stats.by_reason.get(reason, 0) + 1
            if self.log is not None:
                rec = {
                    "window": self.guard.window_id,
                    "pass_index": self.state.pass_index,
                    "counter": result["counter"],
                    "opcode": result["opcode"],
                    "opcode_name": result["opcode_name"],
                    "key_id": result["key_id"],
                    "sat_id": result["sat_id"],
                    "verdict": result["verdict"],
                    "reason": reason,
                    "sig_checked": result["sig_checked"],
                    "frame_len": result["frame_len"],
                    "frame_sha256": result["frame_sha256"],
                    "total_us": result["total_us"],
                    "nv_writes": result["nv_writes"],
                }
                if result.get("counter_gap"):
                    rec["counter_gap"] = result["counter_gap"]
                if context:
                    rec["context"] = context
                result["log"] = self.log.write(rec)
            return result

        # Step 0: flood guard (no signature work once locked)
        t0 = time.perf_counter_ns()
        if self.guard.locked:
            self.guard.record_drop()
            step(0, "flood_guard", "Flood guard below limit", False,
                 f"{self.guard.failures}/{self.guard.limit} signature failures this window: dropped unverified", t0)
            return finish(E_FLOOD_LOCKOUT)
        step(0, "flood_guard", "Flood guard below limit", True, f"{self.guard.failures}/{self.guard.limit}", t0)

        # Parse (cheap)
        t0 = time.perf_counter_ns()
        try:
            frame = parse_frame(data)
        except MalformedFrame as exc:
            step(None, "parse", "Frame well-formed", False, str(exc), t0)
            return finish(E_MALFORMED)
        step(None, "parse", "Frame well-formed", True, f"{len(data)} B, body {frame.cmd_len} B", t0)
        result.update(
            counter=frame.counter,
            opcode=frame.opcode,
            opcode_name=opcode_name(frame.opcode),
            key_id=frame.key_id,
            sat_id=frame.sat_id,
            role=self.state.role_for_key(frame.key_id),
        )

        # Step 1: satellite ID
        t0 = time.perf_counter_ns()
        if frame.sat_id != self.state.sat_id:
            step(1, "sat_id", "Satellite ID matches", False, f"frame sat_id={frame.sat_id}, this spacecraft={self.state.sat_id}", t0)
            return finish(E_WRONG_SAT)
        step(1, "sat_id", "Satellite ID matches", True, f"sat_id={frame.sat_id}", t0)

        # Step 2: expiry
        t0 = time.perf_counter_ns()
        if frame.expiry < int(now):
            step(2, "expiry", "Not expired", False, f"expiry {frame.expiry} < onboard clock {int(now)}", t0)
            return finish(E_EXPIRED)
        step(2, "expiry", "Not expired", True, f"{frame.expiry - int(now)} s remaining", t0)

        # Step 3: counter / replay (check only; commit happens at the end)
        t0 = time.perf_counter_ns()
        last = self.state.last_counter
        if frame.counter <= last:
            step(3, "counter", "Counter > last accepted", False, f"counter {frame.counter} <= last accepted {last}", t0)
            return finish(E_REPLAY)
        step(3, "counter", "Counter > last accepted", True, f"{frame.counter} > {last}", t0)

        # Step 4: signature over frame + current pass nonce
        t0 = time.perf_counter_ns()
        pk = self.state.public_key(frame.key_id)
        nonce = self.state.pass_nonce
        if pk is None:
            self.guard.record_sig_failure()
            step(4, "signature", "Falcon signature over frame + pass nonce", False, f"unknown key_id {frame.key_id}", t0)
            return finish(E_BAD_SIG)
        result["sig_checked"] = True
        v0 = time.perf_counter_ns()
        valid = crypto.verify(pk, frame.signed_message(nonce), frame.signature)
        dv = time.perf_counter_ns() - v0
        self.stats.sig_verifications += 1
        self.stats.sig_verify_ns_total += dv
        result["verify_us"] = round(dv / 1000, 2)
        if not valid:
            self.guard.record_sig_failure()
            step(4, "signature", "Falcon signature over frame + pass nonce", False,
                 f"invalid for key_id {frame.key_id} under pass nonce {nonce.hex()[:12]}... "
                 f"(failures {self.guard.failures}/{self.guard.limit})", t0)
            return finish(E_BAD_SIG)
        step(4, "signature", "Falcon signature over frame + pass nonce", True,
             f"valid ({crypto.ALGORITHM}, {round(dv / 1000)} us)", t0)

        # Step 5: role authorisation
        t0 = time.perf_counter_ns()
        role = result["role"]
        if role is None or not self.state.allowed(role, frame.opcode):
            step(5, "role", "Opcode allowed for key role", False, f"{role} may not issue {opcode_name(frame.opcode)}", t0)
            return finish(E_UNAUTHORIZED)
        step(5, "role", "Opcode allowed for key role", True, f"{role} -> {opcode_name(frame.opcode)}", t0)

        # Counter-gap report (missing-packet detection): counters skipped between the
        # last accepted frame and this one were never accepted onboard. Reported in the
        # acknowledgement so the ground can reconcile them; stored in the same NV write.
        gap = None
        if frame.counter > last + 1:
            gap = {"from": last + 1, "to": frame.counter - 1, "count": frame.counter - last - 1}
            result["counter_gap"] = gap

        # Commit: exactly one NV write, then execute
        if frame.opcode == Opcode.PASS_OPEN:
            new_nonce = frame.command[1 : 1 + NONCE_LEN]
            self.state.commit_accept(counter=frame.counter, new_nonce=new_nonce, new_pass_index=self.state.pass_index + 1,
                                     gap=gap)
            self.guard.begin_window(self.guard.window_id)  # PRD 4.1 step 3: reset flood count
            result["executed"] = f"pass nonce installed ({new_nonce.hex()[:16]}...), pass #{self.state.pass_index}"
            result["pass_index"] = self.state.pass_index
        else:
            self.state.commit_accept(counter=frame.counter, gap=gap)
            result["executed"] = f"{opcode_name(frame.opcode)} args={frame.command[1:].hex() or '-'}"
            self.executed.append({"counter": frame.counter, "opcode": opcode_name(frame.opcode), "args": frame.command[1:].hex()})
        return finish(OK)

    def snapshot(self) -> dict:
        return {
            "sat_id": self.state.sat_id,
            "last_counter": self.state.last_counter,
            "pass_index": self.state.pass_index,
            "pass_nonce": self.state.pass_nonce.hex(),
            "flood": self.guard.snapshot(),
            "nv_writes": self.state.nv_writes,
            "gaps": self.state.gap_summary(),
            "stats": self.stats.as_dict(),
            "executed_recent": list(self.executed),
            "state_file": str(self.state.path),
        }


def build_verifier(state_path: Path, log_path: Path | None, flood_limit: int = 8) -> OnboardVerifier:
    state = StateStore(state_path)
    log = AuditLog(log_path) if log_path else None
    return OnboardVerifier(state, log, flood_limit)
