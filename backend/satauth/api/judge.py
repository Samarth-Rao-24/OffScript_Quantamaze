"""Judge console: frames and test cases supplied by the judges, not by us.

* compose: build and sign a frame from judge-chosen fields (key, opcode, args,
  sat_id, expiry, counter, nonce), optionally mutate it, send it.
* raw:     send arbitrary hex bytes.
* cases:   run a JSON/CSV case list where every case states the expected
  outcome; report pass/fail per case and totals, including false accepts.

Every frame goes through the real signer (where a key is used), the link's
hostile-transmitter path and the separate onboard process, and is logged.
"""

from __future__ import annotations

import csv
import io
import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from ..common import crypto
from ..common.atomic import atomic_write_bytes, atomic_write_json
from ..common.frame import FRAME_VERSION, HEADER_FMT, HEADER_LEN, NONCE_LEN, SIG_LEN, pack_header, signed_message
from ..common.roles import OPCODE_INFO, ROLE_KEY_ID, Opcode, Role, opcode_name
from .service import MissionControl, ServiceError

KEYS = ("OPERATOR", "ADMIN", "ATTACKER")
NONCE_CHOICES = ("current", "previous", "random")
REASONS = {"OK", "E_FLOOD_LOCKOUT", "E_MALFORMED", "E_WRONG_SAT", "E_EXPIRED", "E_REPLAY", "E_BAD_SIG", "E_UNAUTHORIZED"}
MAX_CASES = 500


# ------------------------------------------------------------------ helpers
def attacker_keypair(data_dir: Path) -> tuple[bytes, bytes]:
    """A Falcon key the satellite has never seen (persisted so runs are repeatable)."""
    d = Path(data_dir) / "attacker"
    pk_p, sk_p = d / "attacker.pk", d / "attacker.sk"
    if not (pk_p.exists() and sk_p.exists()):
        pk, sk = crypto.generate_keypair()
        atomic_write_bytes(sk_p, sk)
        atomic_write_bytes(pk_p, pk)
    return pk_p.read_bytes(), sk_p.read_bytes()


def parse_opcode(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if s.isdigit():
        return int(s)
    for op, info in OPCODE_INFO.items():
        if info["name"] == s.upper():
            return int(op)
    raise ValueError(f"unknown opcode {v!r}")


def clean_hex(h: str) -> bytes:
    s = "".join(str(h).split()).lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        raise ValueError("hex must have an even number of digits")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"not valid hex: {exc}") from None


def decode(data: bytes) -> dict:
    """Best-effort field view of any bytes (for display only; the verifier does its own parsing)."""
    out: dict = {"length": len(data)}
    if len(data) >= HEADER_LEN:
        v, sat, kid, clen, ctr, exp = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
        out.update(version=v, sat_id=sat, key_id=kid, cmd_len=clen, counter=ctr, expiry=exp,
                   expiry_in_s=exp - int(time.time()))
        body = data[HEADER_LEN:HEADER_LEN + clen]
        if body:
            out.update(opcode=body[0], opcode_name=opcode_name(body[0]), args_hex=body[1:].hex())
        sig = data[HEADER_LEN + clen:]
        out.update(signature_len=len(sig), signature_prefix=sig[:8].hex(),
                   length_consistent=len(data) == HEADER_LEN + clen + SIG_LEN)
    return out


def _slim(res: dict) -> dict:
    keep = ("verdict", "reason", "counter", "opcode_name", "key_id", "sat_id", "sig_checked", "verify_us",
            "total_us", "nv_writes", "last_counter_after", "steps", "executed", "flood")
    out = {k: res.get(k) for k in keep}
    if res.get("log"):
        out["log_seq"] = res["log"].get("seq")
    return out


def _mutate(data: bytes, m: dict | None) -> tuple[bytes, list[str]]:
    if not m:
        return data, []
    b = bytearray(data)
    notes = []
    if m.get("flip_bit") not in (None, ""):
        bit = int(m["flip_bit"])
        if not 0 <= bit < len(b) * 8:
            raise ValueError(f"flip_bit {bit} outside frame ({len(b) * 8} bits)")
        b[bit // 8] ^= 1 << (7 - bit % 8)
        notes.append(f"flipped bit {bit} (byte {bit // 8})")
    if m.get("set_byte") not in (None, ""):
        off, val = m["set_byte"]
        off, val = int(off), int(val) & 0xFF
        if not 0 <= off < len(b):
            raise ValueError(f"set_byte offset {off} outside frame")
        b[off] = val
        notes.append(f"byte {off} set to 0x{val:02x}")
    if m.get("truncate") not in (None, ""):
        b = b[: int(m["truncate"])]
        notes.append(f"truncated to {len(b)} bytes")
    return bytes(b), notes


def _resolve_nonce(mc: MissionControl, choice) -> tuple[bytes, str]:
    c = str(choice or "current").strip().lower()
    if c == "current":
        return mc.current_nonce(), "current pass nonce"
    if c == "previous":
        prev = mc.previous_nonce()
        if prev is None:
            raise ValueError("no previous nonce yet: open another contact window first")
        return prev, "previous pass nonce"
    if c == "random":
        return os.urandom(NONCE_LEN), "random 32 bytes (no pass uses this)"
    n = clean_hex(c)
    if len(n) != NONCE_LEN:
        raise ValueError("nonce must be 'current', 'previous', 'random' or 64 hex digits")
    return n, "nonce supplied as hex"


# ------------------------------------------------------------------ building
def build_frame(mc: MissionControl, spec: dict) -> tuple[bytes, dict]:
    """Sign a frame exactly as specified. Returns (bytes, description)."""
    assert mc.signer is not None
    key = str(spec.get("key") or "OPERATOR").upper()
    if key not in KEYS:
        raise ValueError(f"key must be one of {KEYS}")
    opcode = parse_opcode(spec.get("opcode", "NOOP_PING"))
    if not 0 <= opcode <= 255:
        raise ValueError("opcode must fit in one byte")
    body = bytes([opcode]) + clean_hex(spec.get("args_hex") or "")
    if len(body) > 255:
        raise ValueError("command body longer than 255 bytes cannot be encoded")
    sat_id = int(spec["sat_id"]) if spec.get("sat_id") not in (None, "") else mc.s.sat_id
    if spec.get("expiry") not in (None, ""):
        expiry = int(spec["expiry"])
    else:
        expiry = int(time.time()) + int(spec.get("expiry_offset_s") if spec.get("expiry_offset_s") not in (None, "") else 600)
    ctr_spec = spec.get("counter", "auto")
    if ctr_spec in (None, "", "auto"):
        counter, ctr_note = mc.signer.counter.next(), "next ground counter"
    else:
        counter, ctr_note = int(ctr_spec), "set by judge"
    if not (0 <= counter < 2 ** 64 and 0 <= expiry < 2 ** 32 and 0 <= sat_id <= 255):
        raise ValueError("counter, expiry or sat_id out of range for the header")
    nonce, nonce_note = _resolve_nonce(mc, spec.get("nonce"))
    if key == "ATTACKER":
        _, sk = attacker_keypair(mc.data)
        key_id = int(spec["key_id"]) if spec.get("key_id") not in (None, "") else ROLE_KEY_ID[Role.OPERATOR]
        key_note = "attacker's own Falcon key (unknown to the satellite)"
    else:
        sk = mc.signer._sk(key)
        key_id = int(spec["key_id"]) if spec.get("key_id") not in (None, "") else ROLE_KEY_ID[key]
        key_note = f"ground {key} key"
    if not 0 <= key_id <= 255:
        raise ValueError("key_id must be 0-255")
    header = pack_header(FRAME_VERSION, sat_id, key_id, len(body), counter, expiry)
    sig = crypto.sign(sk, signed_message(header, body, nonce))
    data = header + body + sig
    data, mut = _mutate(data, spec.get("mutate"))
    return data, {"key": key_note, "key_id": key_id, "opcode_name": opcode_name(opcode), "counter": counter,
                  "counter_source": ctr_note, "expiry": expiry, "sat_id": sat_id, "signed_under": nonce_note,
                  "nonce_prefix": nonce.hex()[:16], "mutations": mut,
                  "pass_open_new_nonce": body[1:].hex() if opcode == Opcode.PASS_OPEN and len(body) == 33 else None}


def _send(mc: MissionControl, data: bytes, label: str) -> dict:
    before = mc.sat.state() if mc.sat else {}
    mc.link.inject_hostile(data, label=label)
    mc._frame_event("tx", label=label, bytes=len(data), window=mc.link.window_id, hostile=True)
    res = mc._deliver(data, context={"judge": label})
    mc._frame_event("verdict", label=label, bytes=len(data), window=mc.link.window_id, result=res, hostile=True)
    # A judge-built PASS_OPEN that the satellite accepts installs a new nonce; keep the ground in step.
    if res["verdict"] == "ACCEPT" and res.get("opcode") == Opcode.PASS_OPEN:
        new = data[HEADER_LEN + 1: HEADER_LEN + 1 + NONCE_LEN]
        mc._install_ground_nonce(new, {"pass": None, "window": mc.link.window_id, "job_id": None, "device": None,
                                       "randomness_class": "judge-supplied PASS_OPEN"})
    return {"verdict": _slim(res), "counter_before": before.get("last_counter"),
            "counter_after": res.get("last_counter_after")}


def _need_window(mc: MissionControl) -> None:
    if not mc.link.window_id:
        raise ServiceError("Open a contact window first: frames are bound to the pass nonce that PASS_OPEN installs.", 409)


# ------------------------------------------------------------------ endpoints' logic
def compose_and_send(mc: MissionControl, spec: dict) -> dict:
    with mc._lock:
        _need_window(mc)
        try:
            data, desc = build_frame(mc, spec)
        except ValueError as exc:
            raise ServiceError(str(exc), 400) from exc
        out = _send(mc, data, "judge-compose")
        return {"frame_hex": data.hex(), "decoded": decode(data), "built": desc, **out}


def send_raw(mc: MissionControl, hex_text: str) -> dict:
    with mc._lock:
        _need_window(mc)
        try:
            data = clean_hex(hex_text)
        except ValueError as exc:
            raise ServiceError(str(exc), 400) from exc
        if not data:
            raise ServiceError("no bytes to send", 400)
        if len(data) > 4096:
            raise ServiceError("frame longer than 4096 bytes refused by the link", 400)
        out = _send(mc, data, "judge-raw")
        return {"frame_hex": data.hex(), "decoded": decode(data), **out}


def last_frame(mc: MissionControl) -> dict:
    d = mc.last_sent_frame
    return {"frame_hex": d.hex() if d else None, "decoded": decode(d) if d else None}


# ------------------------------------------------------------------ case runner
CSV_FIELDS = ["id", "description", "expect", "new_window", "key", "key_id", "opcode", "args_hex", "sat_id",
              "expiry_offset_s", "counter", "nonce", "raw_hex", "replay_of", "flip_bit"]


def parse_cases(payload: dict) -> list[dict]:
    if "csv" in payload and payload["csv"]:
        rows = list(csv.DictReader(io.StringIO(payload["csv"].lstrip("﻿"))))
        cases = []
        for i, r in enumerate(rows, start=1):
            r = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in r.items() if k}
            c = {k: v for k, v in r.items() if v not in (None, "")}
            if "flip_bit" in c:
                c["mutate"] = {"flip_bit": c.pop("flip_bit")}
            c.setdefault("id", f"row{i}")
            cases.append(c)
    else:
        cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ServiceError("Provide 'cases' (a JSON list) or 'csv' text with at least one case.", 400)
    if len(cases) > MAX_CASES:
        raise ServiceError(f"At most {MAX_CASES} cases per run.", 400)
    return cases


def _expectation(raw) -> str:
    e = str(raw or "").strip().upper()
    if e in ("ACCEPT", "OK"):
        return "ACCEPT"
    if e == "REJECT":
        return "REJECT"
    if e in REASONS:
        return e
    raise ValueError(f"expect must be ACCEPT, REJECT or one of {sorted(REASONS - {'OK'})}")


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "y")


def run_cases(mc: MissionControl, payload: dict) -> dict:
    cases = parse_cases(payload)
    results = []
    sent: dict[str, bytes] = {}
    totals = {"cases": len(cases), "passed": 0, "failed": 0, "errors": 0, "false_accepts": 0, "false_rejects": 0,
              "wrong_reason": 0}
    t0 = time.perf_counter()
    with mc._lock:
        for i, c in enumerate(cases, start=1):
            cid = str(c.get("id") or f"case{i}")
            row = {"id": cid, "description": c.get("description", ""), "expect": c.get("expect")}
            try:
                expect = _expectation(c.get("expect"))
                row["expect"] = expect
                if _truthy(c.get("new_window", False)):
                    mc.open_window()
                _need_window(mc)
                if c.get("raw_hex"):
                    data, kind = clean_hex(c["raw_hex"]), "raw"
                    data, notes = _mutate(data, c.get("mutate"))
                    built = {"mutations": notes}
                elif c.get("replay_of"):
                    ref = str(c["replay_of"])
                    if ref not in sent:
                        raise ValueError(f"replay_of {ref!r}: no earlier case with that id was sent")
                    data, notes = _mutate(sent[ref], c.get("mutate"))
                    kind, built = "replay", {"replay_of": ref, "mutations": notes}
                else:
                    data, built = build_frame(mc, c)
                    kind = "compose"
                if not data:
                    raise ValueError("empty frame")
                out = _send(mc, data, f"judge-case:{cid}")
                sent[cid] = data
                v = out["verdict"]
                got = v["verdict"]
                reason = v["reason"]
                if expect == "ACCEPT":
                    ok = got == "ACCEPT"
                    outcome = "correct accept" if ok else "FALSE REJECT"
                    if not ok:
                        totals["false_rejects"] += 1
                else:
                    if got == "ACCEPT":
                        ok, outcome = False, "FALSE ACCEPT"
                        totals["false_accepts"] += 1
                    elif expect == "REJECT" or reason == expect:
                        ok, outcome = True, "correct reject"
                    else:
                        ok, outcome = False, "rejected, different reason"
                        totals["wrong_reason"] += 1
                totals["passed" if ok else "failed"] += 1
                row.update(kind=kind, verdict=got, reason=reason, passed=ok, outcome=outcome,
                           frame_len=len(data), frame_hex=data.hex(), log_seq=v.get("log_seq"),
                           counter_before=out["counter_before"], counter_after=out["counter_after"],
                           nv_writes=v.get("nv_writes"), built=built, steps=v.get("steps"))
            except (ValueError, ServiceError) as exc:
                totals["errors"] += 1
                totals["failed"] += 1
                row.update(passed=False, outcome="CASE ERROR", error=str(exc))
            results.append(row)
    totals["pass_rate"] = round(totals["passed"] / totals["cases"], 4)
    run = {"kind": "judge_cases", "created_utc": datetime.now(timezone.utc).isoformat(),
           "elapsed_s": round(time.perf_counter() - t0, 3), "totals": totals, "results": results,
           "input": payload if "csv" in payload else {"cases": cases},
           "note": "Expected outcomes are supplied by the judges; the system is not grading itself."}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"judge_{stamp}.json"
    atomic_write_json(mc.ev / "judge_runs" / fname, run)
    run["evidence_file"] = f"judge_runs/{fname}"
    mc.emit({"type": "judge_run", "totals": totals})
    return run


SAMPLE_CASES = [
    {"id": "J1", "description": "Valid operator image capture", "key": "OPERATOR", "opcode": "CAPTURE_IMAGE",
     "args_hex": "0b01", "expect": "ACCEPT"},
    {"id": "J2", "description": "Replay J1 unchanged", "replay_of": "J1", "expect": "E_REPLAY"},
    {"id": "J3", "description": "Operator tries a thruster burn", "key": "OPERATOR", "opcode": "ORBIT_BURN",
     "args_hex": "0000000a", "expect": "E_UNAUTHORIZED"},
    {"id": "J4", "description": "Admin burn, but flip one bit of the body after signing", "key": "ADMIN",
     "opcode": "ORBIT_BURN", "args_hex": "0000000a", "mutate": {"flip_bit": 140}, "expect": "E_BAD_SIG"},
    {"id": "J5", "description": "Addressed to satellite 7", "key": "OPERATOR", "opcode": "NOOP_PING", "sat_id": 7,
     "expect": "E_WRONG_SAT"},
    {"id": "J6", "description": "Expired 30 s ago", "key": "OPERATOR", "opcode": "NOOP_PING",
     "expiry_offset_s": -30, "expect": "E_EXPIRED"},
    {"id": "J7", "description": "Attacker key pretending to be OPERATOR", "key": "ATTACKER", "opcode": "SET_SAFE_MODE",
     "args_hex": "01", "expect": "E_BAD_SIG"},
    {"id": "J8", "description": "Signed under a random nonce", "key": "ADMIN", "opcode": "NOOP_PING", "nonce": "random",
     "expect": "E_BAD_SIG"},
    {"id": "J9", "description": "Garbage bytes", "raw_hex": "deadbeef", "expect": "REJECT"},
    {"id": "J10", "description": "Valid admin heater command", "key": "ADMIN", "opcode": "SET_HEATER", "args_hex": "0112",
     "expect": "ACCEPT"},
]


def sample_csv() -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
    w.writeheader()
    for c in SAMPLE_CASES:
        row = {k: v for k, v in c.items() if k in CSV_FIELDS}
        if c.get("mutate", {}).get("flip_bit") is not None:
            row["flip_bit"] = c["mutate"]["flip_bit"]
        w.writerow(row)
    return buf.getvalue()
