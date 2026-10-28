"""Resource measurements (PRD section 10). All numbers are *emulated host*
measurements on the machine running this script, not flight hardware.

Runs against a scratch verifier with its own keys/state in a temp directory so
the live mission state is never touched.

    python -m satauth.bench.measure            # writes evidence/bench/measure_*.json
"""

from __future__ import annotations

import os
import statistics
import tempfile
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from ..common import crypto
from ..common.atomic import atomic_write_json
from ..common.frame import FRAME_VERSION, HEADER_LEN, SIG_LEN, pack_header
from ..common.roles import ROLE_KEY_ID, Opcode, Role, default_role_table
from ..ground.keygen import ensure_role_keys, load_public_keys
from ..ground.queue import PASS_OPEN_FRAME_BYTES, default_queue
from ..ground.signer import Signer
from ..onboard.verifier import build_verifier

SAT = 0x2A


def pct(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summary_us(ns: list[int]) -> dict:
    us = [v / 1000 for v in ns]
    return {"n": len(us), "mean_us": round(statistics.fmean(us), 2), "p50_us": round(pct(us, 0.5), 2),
            "p95_us": round(pct(us, 0.95), 2), "p99_us": round(pct(us, 0.99), 2), "max_us": round(max(us), 2)}


def _scratch(flood_limit: int):
    tmp = Path(tempfile.mkdtemp(prefix="quplink-bench-"))
    ensure_role_keys(tmp)
    v = build_verifier(tmp / "state.json", None, flood_limit)
    nonce = os.urandom(32)
    v.state.provision(sat_id=SAT, public_keys=load_public_keys(tmp), role_table=default_role_table(), genesis_nonce=nonce)
    v.begin_window(1)
    return tmp, v, Signer(tmp, SAT), nonce


def _junk(counter: int) -> bytes:
    body = bytes([Opcode.NOOP_PING])
    return pack_header(FRAME_VERSION, SAT, ROLE_KEY_ID[Role.OPERATOR], 1, counter, int(time.time()) + 600) + body + os.urandom(SIG_LEN)


def run(n_verify: int = 1000, flood_frames: int = 500, flood_limit: int = 8) -> dict:
    _, v, signer, nonce = _scratch(flood_limit)
    body = bytes([Opcode.CAPTURE_IMAGE]) + bytes(11)
    frames = [signer.build(role=Role.OPERATOR, command=body, pass_nonce=nonce).to_bytes() for _ in range(n_verify)]

    # 1) verification latency: crypto-only and full pipeline
    pk = v.state.public_key(ROLE_KEY_ID[Role.OPERATOR])
    from ..common.frame import parse_frame

    parsed = [parse_frame(f) for f in frames]
    crypto_ns = []
    for f in parsed:
        msg = f.signed_message(nonce)
        t0 = time.perf_counter_ns()
        ok = crypto.verify(pk, msg, f.signature)
        crypto_ns.append(time.perf_counter_ns() - t0)
        assert ok
    pipeline_ns = []
    nv0 = v.state.nv_writes
    for f in frames:
        t0 = time.perf_counter_ns()
        r = v.process(f)
        pipeline_ns.append(time.perf_counter_ns() - t0)
        assert r["reason"] == "OK", r["reason"]
    nv_accept = (v.state.nv_writes - nv0) / len(frames)

    # 2) peak RAM during verification (Python-heap view via tracemalloc)
    extra = [signer.build(role=Role.OPERATOR, command=body, pass_nonce=nonce).to_bytes() for _ in range(200)]
    tracemalloc.start()
    per_frame_peaks = []
    base_loop, _ = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    loop_peak = 0
    for f in extra:
        cur, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        v.process(f)
        _, pk_ = tracemalloc.get_traced_memory()
        per_frame_peaks.append(pk_ - cur)
        loop_peak = max(loop_peak, pk_ - base_loop)
    tracemalloc.stop()
    peak = max(per_frame_peaks)
    base_cur = 0

    # 3) NV writes per rejected frame (mixed rejection types)
    nv0 = v.state.nv_writes
    rej = 0
    last = v.state.last_counter
    for i in range(50):
        v.process(frames[i])  # replays
        rej += 1
    for i in range(50):
        v.process(signer.build(role=Role.OPERATOR, command=body, pass_nonce=nonce, expiry=int(time.time()) - 5).to_bytes())
        rej += 1
    v2 = v  # unauthorized
    for i in range(20):
        v2.process(signer.build(role=Role.OPERATOR, command=bytes([Opcode.ORBIT_BURN]), pass_nonce=nonce).to_bytes())
        rej += 1
    nv_reject = (v.state.nv_writes - nv0) / rej
    assert v.state.last_counter == last

    # 4) flood CPU with and without the guard
    atk_pk, atk_sk = crypto.generate_keypair()

    def flood(limit: int, kind: str = "random") -> dict:
        _, fv, fs, fnonce = _scratch(limit)
        if kind == "random":
            junk = [_junk(10_000_000 + i) for i in range(flood_frames)]
        else:  # well-formed signatures from an attacker key: forces full verification work
            junk = [fs.build(role=Role.OPERATOR, command=bytes([Opcode.NOOP_PING]), pass_nonce=fnonce,
                             counter=10_000_000 + i, secret_key=atk_sk).to_bytes() for i in range(flood_frames)]
        t0 = time.perf_counter_ns()
        reasons: dict[str, int] = {}
        for j in junk:
            r = fv.process(j)
            reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1
        total = time.perf_counter_ns() - t0
        return {"junk_kind": kind, "flood_limit": limit if limit < 10**8 else None, "frames": flood_frames,
                "signature_verifications": fv.stats.sig_verifications,
                "total_ms": round(total / 1e6, 3), "per_frame_us": round(total / 1000 / flood_frames, 2),
                "by_reason": reasons}

    with_guard = flood(flood_limit)
    without_guard = flood(10**9)
    with_guard_wf = flood(flood_limit, "attacker-key")
    without_guard_wf = flood(10**9, "attacker-key")

    q = default_queue()
    frame_sizes = [{"id": c.id, "body_bytes": len(c.body), "frame_bytes": c.frame_bytes,
                    "overhead_bytes": c.frame_bytes - len(c.body)} for c in q]
    from ..api.service import MissionControl

    host = MissionControl.host_info()
    return {
        "kind": "measure",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "label": "EMULATED HOST MEASUREMENT - not flight hardware",
        "host": host,
        "method": {
            "latency": f"time.perf_counter_ns around crypto.verify and around the full verifier pipeline, {n_verify} frames",
            "peak_ram": "tracemalloc: max over 200 full verifications of (peak during one verification - heap before it); "
                        "Python heap only, C-stack/static memory inside PQClean is not visible to tracemalloc. "
                        "peak_ram_loop_bytes is the peak across the whole 200-frame loop.",
            "nv_writes": "StateStore write-call counter per accepted / rejected frame",
            "flood": f"{flood_frames} junk frames with high counters; (a) random 666 B signatures (often fail early in "
                     f"signature decoding), (b) well-formed signatures from an attacker key (full verification cost). "
                     f"Guard N={flood_limit} vs no guard.",
        },
        "signature_scheme": crypto.ALGORITHM,
        "frame": {"header_bytes": HEADER_LEN, "signature_bytes": SIG_LEN, "auth_overhead_bytes": HEADER_LEN + SIG_LEN,
                  "nfr01_target_bytes": 682, "pass_open_frame_bytes": PASS_OPEN_FRAME_BYTES, "per_command": frame_sizes},
        "verify_crypto_only": summary_us(crypto_ns),
        "verify_pipeline": summary_us(pipeline_ns),
        "nfr02_target_us": 5000,
        "peak_ram_bytes": peak - base_cur,
        "peak_ram_per_frame_p50_bytes": int(pct(per_frame_peaks, 0.5)),
        "peak_ram_loop_bytes": loop_peak,
        "nfr03_target_bytes": 64 * 1024,
        "nv_writes_per_accepted": nv_accept,
        "nv_writes_per_rejected": nv_reject,
        "flood_with_guard": with_guard,
        "flood_without_guard": without_guard,
        "flood_wellformed_with_guard": with_guard_wf,
        "flood_wellformed_without_guard": without_guard_wf,
        "nfr06": {"max_verifications_with_guard": with_guard["signature_verifications"], "limit": flood_limit},
    }


def main() -> None:
    from ..config import load_settings

    s = load_settings()
    res = run(flood_limit=s.flood_limit)
    out = Path(s.evidence_dir) / "bench"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    atomic_write_json(out / f"measure_{stamp}.json", res)
    atomic_write_json(out / "latest_measure.json", res)
    print(f"verify p50={res['verify_crypto_only']['p50_us']} us p95={res['verify_crypto_only']['p95_us']} us; "
          f"pipeline p95={res['verify_pipeline']['p95_us']} us; peak RAM={res['peak_ram_bytes']} B; "
          f"flood verifications {res['flood_with_guard']['signature_verifications']} vs "
          f"{res['flood_without_guard']['signature_verifications']}")


if __name__ == "__main__":
    main()
