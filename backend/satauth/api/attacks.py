"""Attack Lab: hostile frames built with real keys/library calls and delivered to
the real onboard process. Every attack reports the expected reason code, what
actually happened, and state before/after so the UI never shows a canned badge.
"""

from __future__ import annotations

import os
import time

from ..common import crypto
from ..common.frame import FRAME_VERSION, HEADER_LEN, SIG_LEN, pack_header
from ..common.roles import ROLE_KEY_ID, Opcode, Role
from ..ground.qrng import FuzzStream
from ..link.pass_sim import LinkBudgetExceeded
from .service import MissionControl, ServiceError

ATTACKS = {
    "valid": ("Valid command", "Correctly signed, fresh, authorised OPERATOR frame", "OK"),
    "tamper": ("Tamper", "Flip one QRNG-chosen bit in the command body after signing", "E_BAD_SIG"),
    "replay": ("Replay", "Resend the last accepted frame unchanged", "E_REPLAY"),
    "expired": ("Expired", "Validly signed frame whose expiry is 60 s in the past", "E_EXPIRED"),
    "unauthorized": ("Unauthorized", "OPERATOR key signs ADMIN-only ORBIT_BURN", "E_UNAUTHORIZED"),
    "forged": ("Forged", "Attacker key claiming key_id=1, plus QRNG random signature bytes", "E_BAD_SIG"),
    "crosspass": ("Cross-pass", "Frame signed under the previous pass nonce with a fresh counter", "E_BAD_SIG"),
    "wrongsat": ("Wrong satellite", "Valid frame addressed to another spacecraft", "E_WRONG_SAT"),
    "flood": ("Flood", "500 junk frames with high counters and random signatures", "E_BAD_SIG then E_FLOOD_LOCKOUT"),
    "overbudget": ("Over budget", "Ground tries to transmit more bytes than the pass allows", "LINK_REFUSED"),
}

FLOOD_FRAMES = 500


def _brief(state: dict) -> dict:
    o = state["onboard"]
    return {"last_counter": o["last_counter"], "pass_nonce": o["pass_nonce"], "nv_writes": o["nv_writes"],
            "flood": o["flood"], "sig_verifications": o["stats"]["sig_verifications"]}


def run_attack(mc: MissionControl, kind: str) -> dict:
    if kind not in ATTACKS:
        raise ServiceError(f"unknown attack {kind!r}", 404)
    if not mc.link.window_id:
        raise ServiceError("Open a contact window first (PASS_OPEN installs the QRNG pass nonce).", 409)
    title, desc, expected = ATTACKS[kind]
    with mc._lock:
        fuzz, fuzz_meta = mc.qrng.fuzz_stream()
        before = _brief(mc.state())
        t0 = time.perf_counter()
        frames = globals()[f"_atk_{kind}"](mc, fuzz)
        elapsed = time.perf_counter() - t0
        after = _brief(mc.state())
    reasons = [f["result"]["reason"] for f in frames if f.get("result")]
    target = [f for f in frames if f.get("is_attack", True)]
    if kind == "flood":
        n = mc.s.flood_limit
        bad = sum(1 for f in target if f["result"]["reason"] == "E_BAD_SIG")
        lock = sum(1 for f in target if f["result"]["reason"] == "E_FLOOD_LOCKOUT")
        passed = bad <= n and bad + lock == len(target) and after["sig_verifications"] - before["sig_verifications"] <= n
    elif kind == "overbudget":
        passed = any(f.get("link_refused") for f in frames)
    else:
        passed = all(f["result"]["reason"] == expected for f in target if f.get("result"))
    # per-frame state invariants: a rejected frame never moves the counter and makes no NV write
    prev = before["last_counter"]
    counter_ok = True
    for f in frames:
        r = f.get("result")
        if not r:
            continue
        if r["verdict"] == "REJECT":
            if r["last_counter_after"] != prev or r["nv_writes"] != 0:
                counter_ok = False
        else:
            if not (r["last_counter_after"] > prev and r["nv_writes"] == 1):
                counter_ok = False
            prev = r["last_counter_after"]
    if kind == "valid":
        counter_msg = "accepted: counter advanced with exactly 1 NV write"
    else:
        counter_msg = "every rejected frame left the counter unchanged with 0 NV writes"
    out = {
        "attack": kind, "title": title, "description": desc, "expected": expected,
        "observed": sorted(set(reasons)) + (["LINK_REFUSED"] if any(f.get("link_refused") for f in frames) else []),
        "passed": bool(passed and counter_ok),
        "counter_check": counter_msg if counter_ok else "STATE INVARIANT FAILED",
        "before": before, "after": after,
        "sig_verifications_spent": after["sig_verifications"] - before["sig_verifications"],
        "nv_writes_delta": after["nv_writes"] - before["nv_writes"],
        "elapsed_ms": round(elapsed * 1000, 2), "fuzz": fuzz_meta,
        "frames": frames if kind != "flood" else frames[: mc.s.flood_limit + 3],
        "frame_count": len(frames),
    }
    if kind == "flood":
        out["flood_summary"] = _flood_summary(frames, mc.s.flood_limit)
    mc.emit({"type": "attack", "attack": kind, "passed": out["passed"], "observed": out["observed"],
             "summary": out.get("flood_summary")})
    return out


def _send(mc: MissionControl, data: bytes, label: str, *, is_attack: bool = True, emit: bool = True) -> dict:
    mc.link.inject_hostile(data, label=label, log=emit)
    if emit:
        mc._frame_event("tx", label=label, bytes=len(data), window=mc.link.window_id, hostile=True)
    res = mc._deliver(data, context={"attack": label})
    if emit:
        mc._frame_event("verdict", label=label, bytes=len(data), window=mc.link.window_id, result=res, hostile=True)
    return {"label": label, "bytes": len(data), "is_attack": is_attack, "result": _slim(res)}


def _slim(res: dict) -> dict:
    keep = ("verdict", "reason", "counter", "opcode_name", "key_id", "sat_id", "sig_checked", "verify_us", "total_us",
            "nv_writes", "last_counter_after", "steps", "executed")
    out = {k: res.get(k) for k in keep}
    if "log" in res:
        out["log_seq"] = res["log"].get("seq")
    return out


def _valid_frame(mc: MissionControl, **kw):
    return mc.signer.build(role=Role.OPERATOR, command=bytes([Opcode.CAPTURE_IMAGE, 0x0B, 0x01]),
                           pass_nonce=mc.current_nonce(), **kw)


def _atk_valid(mc, fuzz):
    return [_send(mc, _valid_frame(mc).to_bytes(), "valid", is_attack=True)]


def _atk_tamper(mc, fuzz: FuzzStream):
    data = bytearray(_valid_frame(mc).to_bytes())
    body_len = data[3]
    bit = fuzz.below(body_len * 8)
    pos = HEADER_LEN + bit // 8
    data[pos] ^= 1 << (bit % 8)
    f = _send(mc, bytes(data), "tamper")
    f["mutation"] = {"byte_offset": pos, "bit": bit % 8, "body_bit_index": bit}
    return [f]


def _atk_replay(mc, fuzz):
    frames = []
    if mc.last_accepted_frame is None:
        frames.append(_send(mc, _valid_frame(mc).to_bytes(), "replay-setup (valid original)", is_attack=False))
    if mc.last_accepted_frame is None:
        raise ServiceError("Could not obtain an accepted frame to replay (is the window flood-locked?)", 409)
    frames.append(_send(mc, mc.last_accepted_frame, "replay"))
    return frames


def _atk_expired(mc, fuzz):
    return [_send(mc, _valid_frame(mc, expiry=int(time.time()) - 60).to_bytes(), "expired")]


def _atk_unauthorized(mc, fuzz):
    f = mc.signer.build(role=Role.OPERATOR, command=bytes([Opcode.ORBIT_BURN]) + bytes(8), pass_nonce=mc.current_nonce())
    return [_send(mc, f.to_bytes(), "unauthorized")]


def _atk_forged(mc, fuzz: FuzzStream):
    out = []
    # (a) attacker's own Falcon key, claiming to be the OPERATOR key
    pk, sk = crypto.generate_keypair()
    f = mc.signer.build(role=Role.OPERATOR, command=bytes([Opcode.SET_SAFE_MODE, 1]), pass_nonce=mc.current_nonce(),
                        secret_key=sk, key_id=ROLE_KEY_ID[Role.OPERATOR])
    out.append(_send(mc, f.to_bytes(), "forged (unknown key)"))
    # (b) QRNG-seeded random signature bytes on a plausible header
    body = bytes([Opcode.NOOP_PING])
    header = pack_header(FRAME_VERSION, mc.s.sat_id, ROLE_KEY_ID[Role.ADMIN], len(body),
                         mc.signer.counter.next(), int(time.time()) + 300)
    out.append(_send(mc, header + body + fuzz.bytes(SIG_LEN), "forged (random signature)"))
    return out


def _atk_crosspass(mc, fuzz):
    prev = mc.previous_nonce()
    if prev is None:
        raise ServiceError("Need at least two installed nonces; open another contact window first.", 409)
    f = mc.signer.build(role=Role.OPERATOR, command=bytes([Opcode.NOOP_PING]), pass_nonce=prev)
    r = _send(mc, f.to_bytes(), "crosspass")
    r["signed_under_nonce"] = prev.hex()
    return [r]


def _atk_wrongsat(mc, fuzz):
    other = (mc.s.sat_id + 1) % 256
    f = _valid_frame(mc, sat_id=other)
    return [_send(mc, f.to_bytes(), "wrongsat")]


def _atk_flood(mc, fuzz: FuzzStream):
    out = []
    base = mc.signer.counter.last_issued + 1_000_000
    body = bytes([Opcode.NOOP_PING])
    exp = int(time.time()) + 300
    show = mc.s.flood_limit + 3
    for i in range(FLOOD_FRAMES):
        header = pack_header(FRAME_VERSION, mc.s.sat_id, ROLE_KEY_ID[Role.OPERATOR], len(body), base + i, exp)
        data = header + body + fuzz.bytes(SIG_LEN)
        out.append(_send(mc, data, f"flood#{i + 1}", emit=i < show))
    mc._frame_event("flood_summary", window=mc.link.window_id, summary=_flood_summary(out, mc.s.flood_limit))
    return out


def _flood_summary(frames: list[dict], limit: int) -> dict:
    reasons: dict[str, int] = {}
    verify_us = 0.0
    total_us = 0.0
    for f in frames:
        r = f["result"]
        reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1
        verify_us += r.get("verify_us") or 0
        total_us += r.get("total_us") or 0
    return {"frames": len(frames), "by_reason": reasons, "signature_checks": sum(1 for f in frames if f["result"]["sig_checked"]),
            "flood_limit": limit, "onboard_verify_ms": round(verify_us / 1000, 3),
            "onboard_total_ms": round(total_us / 1000, 3)}


def _atk_overbudget(mc, fuzz):
    out = []
    nonce = mc.current_nonce()
    while True:
        f = mc.signer.build(role=Role.OPERATOR, command=bytes([Opcode.DOWNLINK_DATA]) + os.urandom(31), pass_nonce=nonce)
        data = f.to_bytes()
        try:
            mc.link.transmit(data, label="overbudget-filler")
        except LinkBudgetExceeded as exc:
            mc._frame_event("refused", label="overbudget", bytes=len(data), error=str(exc), link=mc.link.snapshot())
            out.append({"label": "overbudget (refused)", "bytes": len(data), "link_refused": True, "error": str(exc),
                        "link": mc.link.snapshot(), "result": None, "is_attack": True})
            return out
        res = mc._deliver(data, context={"attack": "overbudget-filler"})
        out.append({"label": "overbudget-filler (fits)", "bytes": len(data), "is_attack": False, "result": _slim(res),
                    "link": mc.link.snapshot()})
        if len(out) > 50:  # pragma: no cover - safety
            raise ServiceError("link budget never reached", 500)
