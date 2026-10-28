"""The ten required scenarios (PRD section 9) plus state-safety checks.

Each test asserts the verdict, the exact reason code, and the state effect
(counter, NV writes, flood counter, log line), not just a boolean.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from satauth.common import crypto
from satauth.common.frame import FRAME_VERSION, HEADER_LEN, SIG_LEN, pack_header
from satauth.common.roles import ROLE_KEY_ID, Opcode, Role
from satauth.ground.qrng import FuzzStream
from satauth.link.pass_sim import LinkBudgetExceeded, LinkSimulator
from satauth.onboard.state import StateStore
from satauth.onboard.verifier import OnboardVerifier

from .conftest import FLOOD_N, SAT

FUZZ_SEED = bytes.fromhex("51" * 32)  # recorded seed => reproducible bit flips / forged bytes


def _rejected_cleanly(rig, r, before_counter, before_writes, reason):
    assert r["verdict"] == "REJECT"
    assert r["reason"] == reason
    assert rig.state.last_counter == before_counter, "rejected frame must not advance the counter"
    assert rig.state.nv_writes == before_writes, "rejected frame must cause zero NV writes"
    assert r["nv_writes"] == 0
    assert r["log"]["verdict"] == "REJECT" and r["log"]["reason"] == reason


# 1 ---------------------------------------------------------------------------
def test_01_valid_command_accepted(rig):
    f = rig.frame()
    w0, c0 = rig.state.nv_writes, rig.state.last_counter
    r = rig.send(f.to_bytes())
    assert r["verdict"] == "ACCEPT" and r["reason"] == "OK"
    assert rig.state.last_counter == f.counter > c0
    assert rig.state.nv_writes == w0 + 1  # NFR-04: exactly one NV write
    assert [s["status"] for s in r["steps"]] == ["pass"] * 7
    on_disk = json.loads(rig.state.path.read_text())
    assert on_disk["last_counter"] == f.counter
    assert r["log"]["verdict"] == "ACCEPT" and r["log"]["opcode_name"] == "CAPTURE_IMAGE"


# 2 ---------------------------------------------------------------------------
def test_02_tampered_command_rejected(rig):
    fz = FuzzStream(FUZZ_SEED)
    for _ in range(12):  # 12 QRNG-seeded single-bit flips in the body
        data = bytearray(rig.frame(args=b"\x0a\x0b\x0c\x0d").to_bytes())
        bit = fz.below(data[3] * 8)
        data[HEADER_LEN + bit // 8] ^= 1 << (bit % 8)
        c0, w0 = rig.state.last_counter, rig.state.nv_writes
        r = rig.send(bytes(data))
        _rejected_cleanly(rig, r, c0, w0, "E_BAD_SIG")
        assert r["sig_checked"] is True
        rig.open_pass()  # keep the flood guard out of the way for this test


def test_02b_tampered_header_counter_rejected(rig):
    data = bytearray(rig.frame().to_bytes())
    data[4 + 7] ^= 0x01  # flip the lowest counter bit: still > last, but signature breaks
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    _rejected_cleanly(rig, rig.send(bytes(data)), c0, w0, "E_BAD_SIG")


# 3 ---------------------------------------------------------------------------
def test_03_replayed_command_rejected(rig):
    f = rig.frame()
    assert rig.send(f.to_bytes())["reason"] == "OK"
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(f.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_REPLAY")
    assert r["sig_checked"] is False  # cheap check ran before the signature


def test_03b_older_counter_rejected(rig):
    old = rig.frame()
    new = rig.frame()
    assert rig.send(new.to_bytes())["reason"] == "OK"
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    _rejected_cleanly(rig, rig.send(old.to_bytes()), c0, w0, "E_REPLAY")


# 4 ---------------------------------------------------------------------------
def test_04_expired_command_rejected(rig):
    f = rig.frame(expiry=int(time.time()) - 1)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(f.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_EXPIRED")
    assert r["sig_checked"] is False


def test_04b_expired_and_badly_signed_fails_cheaply(rig):
    data = bytearray(rig.frame(expiry=int(time.time()) - 1).to_bytes())
    data[-1] ^= 0xFF
    r = rig.send(bytes(data))
    assert r["reason"] == "E_EXPIRED" and r["sig_checked"] is False
    assert rig.v.guard.failures == 0  # no signature work, no flood count


# 5 ---------------------------------------------------------------------------
def test_05_unauthorized_command_rejected(rig):
    f = rig.frame(role=Role.OPERATOR, opcode=Opcode.ORBIT_BURN, args=b"\x00" * 8)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(f.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_UNAUTHORIZED")
    assert r["sig_checked"] is True  # signature was valid; the role check failed
    # the same opcode signed with the ADMIN key is accepted
    assert rig.send(rig.frame(role=Role.ADMIN, opcode=Opcode.ORBIT_BURN, args=b"\x00" * 8).to_bytes())["reason"] == "OK"


def test_05b_operator_cannot_open_pass(rig):
    body = bytes([Opcode.PASS_OPEN]) + os.urandom(32)
    f = rig.signer.build(role=Role.OPERATOR, command=body, pass_nonce=rig.nonce)
    nonce_before = rig.state.pass_nonce
    r = rig.send(f.to_bytes())
    assert r["reason"] == "E_UNAUTHORIZED"
    assert rig.state.pass_nonce == nonce_before


# 6 ---------------------------------------------------------------------------
def test_06_forged_random_signature_rejected(rig):
    fz = FuzzStream(FUZZ_SEED)
    body = bytes([Opcode.SET_SAFE_MODE, 1])
    hdr = pack_header(FRAME_VERSION, SAT, ROLE_KEY_ID[Role.ADMIN], len(body), 10**6, int(time.time()) + 60)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(hdr + body + fz.bytes(SIG_LEN))
    _rejected_cleanly(rig, r, c0, w0, "E_BAD_SIG")


def test_06b_forged_with_attacker_key_rejected(rig):
    _, attacker_sk = crypto.generate_keypair()
    f = rig.frame(role=Role.OPERATOR, secret_key=attacker_sk, key_id=ROLE_KEY_ID[Role.OPERATOR])
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    _rejected_cleanly(rig, rig.send(f.to_bytes()), c0, w0, "E_BAD_SIG")


def test_06c_unknown_key_id_rejected(rig):
    f = rig.frame(key_id=99)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(f.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_BAD_SIG")
    assert rig.v.guard.failures == 1


# 7 ---------------------------------------------------------------------------
def test_07_cross_pass_replay_rejected(rig):
    old_nonce = rig.nonce
    rig.open_pass()  # new QRNG nonce installed
    assert rig.state.pass_nonce != old_nonce
    captured = rig.frame(pass_nonce=old_nonce)  # bound to the previous pass, but with a fresh counter
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    assert captured.counter > c0  # fresh counter: only the nonce binding can stop it
    r = rig.send(captured.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_BAD_SIG")


def test_07b_nonce_binding_is_what_rejects(rig):
    """Control: the identical frame signed under the current nonce is accepted."""
    f = rig.frame(pass_nonce=rig.nonce)
    assert rig.send(f.to_bytes())["reason"] == "OK"


def test_07c_replayed_pass_open_rejected(rig):
    po = rig.signer.pass_open(new_nonce=os.urandom(32), current_nonce=rig.nonces[-2])  # chained to an old nonce
    r = rig.send(po.to_bytes())
    assert r["reason"] == "E_BAD_SIG"


# 8 ---------------------------------------------------------------------------
def test_08_wrong_satellite_rejected(rig):
    f = rig.frame(sat_id=SAT + 1)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    r = rig.send(f.to_bytes())
    _rejected_cleanly(rig, r, c0, w0, "E_WRONG_SAT")
    assert r["sig_checked"] is False


# 9 ---------------------------------------------------------------------------
def test_09_flood_attack_bounded(rig):
    fz = FuzzStream(FUZZ_SEED)
    c0, w0 = rig.state.last_counter, rig.state.nv_writes
    v0 = rig.v.stats.sig_verifications
    reasons = []
    body = bytes([Opcode.NOOP_PING])
    for i in range(500):
        hdr = pack_header(FRAME_VERSION, SAT, ROLE_KEY_ID[Role.OPERATOR], 1, 10**9 + i, int(time.time()) + 60)
        reasons.append(rig.send(hdr + body + fz.bytes(SIG_LEN))["reason"])
    assert reasons[:FLOOD_N] == ["E_BAD_SIG"] * FLOOD_N
    assert reasons[FLOOD_N:] == ["E_FLOOD_LOCKOUT"] * (500 - FLOOD_N)
    assert rig.v.stats.sig_verifications - v0 == FLOOD_N  # NFR-06: hard cap on signature work
    assert rig.state.last_counter == c0 and rig.state.nv_writes == w0
    # a genuine frame in the same window is also dropped (lockout), then the next window recovers
    assert rig.send(rig.frame().to_bytes())["reason"] == "E_FLOOD_LOCKOUT"
    rig.open_pass()
    assert rig.send(rig.frame().to_bytes())["reason"] == "OK"


def test_09b_flood_of_wellformed_signatures_also_capped(rig):
    _, sk = crypto.generate_keypair()
    v0 = rig.v.stats.sig_verifications
    out = [rig.send(rig.frame(secret_key=sk, counter=10**9 + i).to_bytes())["reason"] for i in range(60)]
    assert out.count("E_BAD_SIG") == FLOOD_N and out.count("E_FLOOD_LOCKOUT") == 60 - FLOOD_N
    assert rig.v.stats.sig_verifications - v0 == FLOOD_N


# 10 --------------------------------------------------------------------------
def test_10_link_never_exceeds_pass_budget(tmp_path, rig):
    link = LinkSimulator(tmp_path / "link.jsonl")
    link.open_window(1, 1, budget=2000)
    sent = 0
    with pytest.raises(LinkBudgetExceeded):
        while True:
            data = rig.frame(opcode=Opcode.DOWNLINK_DATA, args=os.urandom(31)).to_bytes()
            link.transmit(data, label="fill")
            sent += 1
    snap = link.snapshot()
    assert snap["used_bytes"] <= snap["budget_bytes"] == 2000
    assert sent == 2000 // 714 and snap["refused"] == 1
    # (the scheduler side of the over-budget scenario is in test_scheduler.py)


# --------------------------------------------------------------- state safety
def test_counter_survives_reboot(rig):
    f = rig.frame()
    assert rig.send(f.to_bytes())["reason"] == "OK"
    rebooted = OnboardVerifier(StateStore(rig.state.path), None, FLOOD_N)  # fresh process view of NV memory
    rebooted.begin_window(99)
    assert rebooted.state.last_counter == f.counter
    assert rebooted.process(f.to_bytes())["reason"] == "E_REPLAY"
    assert rebooted.state.pass_nonce == rig.nonce


def test_atomic_write_crash_leaves_previous_state(rig, monkeypatch):
    before = rig.state.path.read_bytes()
    f = rig.frame()

    def boom(*a, **k):
        raise OSError("simulated power loss during rename")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        rig.send(f.to_bytes())
    monkeypatch.undo()
    assert rig.state.path.read_bytes() == before  # old state intact and parseable
    json.loads(before)
    assert not list(rig.state.path.parent.glob(".*.tmp"))  # temp file cleaned up
    assert StateStore(rig.state.path).last_counter == json.loads(before)["last_counter"]


def test_rejections_write_nothing_to_state_file(rig):
    mtime_bytes = rig.state.path.read_bytes()
    rig.send(rig.frame(sat_id=7).to_bytes())
    rig.send(rig.frame(expiry=1).to_bytes())
    data = bytearray(rig.frame().to_bytes())
    data[-5] ^= 1
    rig.send(bytes(data))
    assert rig.state.path.read_bytes() == mtime_bytes


def test_malformed_frames_rejected(rig):
    good = rig.frame().to_bytes()
    for bad in (b"", good[:100], good + b"\x00", bytes([2]) + good[1:]):
        assert rig.send(bad)["reason"] == "E_MALFORMED"
    assert rig.v.guard.failures == 0


def test_check_order_matches_prd(rig):
    r = rig.send(rig.frame().to_bytes())
    assert [s["name"] for s in r["steps"]] == ["flood_guard", "parse", "sat_id", "expiry", "counter", "signature", "role"]


def test_frame_sizes_match_nfr01(rig):
    f = rig.frame(args=b"")
    assert len(f.signature) == SIG_LEN == 666
    assert len(f.to_bytes()) - len(f.command) == HEADER_LEN + SIG_LEN == 682


def test_separate_satellite_process_end_to_end(tmp_path):
    """The onboard verifier also runs as its own OS process (PRD section 10)."""
    from satauth.onboard.process import SatelliteProcess

    from .conftest import Rig

    rig = Rig(tmp_path)
    sat = SatelliteProcess(rig.state.path, tmp_path / "sat.jsonl", FLOOD_N)
    try:
        assert sat.pid != os.getpid()
        f = rig.frame()
        assert sat.send_frame(f.to_bytes())["reason"] == "OK"
        assert sat.send_frame(f.to_bytes())["reason"] == "E_REPLAY"
        assert sat.state()["last_counter"] == f.counter
    finally:
        sat.stop()
