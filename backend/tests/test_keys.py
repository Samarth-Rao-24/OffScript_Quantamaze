"""Key management and crypto agility: rotation, revocation, algorithm migration,
downgrade resistance and private keys encrypted at rest."""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from satauth.common import suites
from satauth.common.frame import HEADER_LEN
from satauth.common.roles import Opcode, Role
from satauth.ground import keygen


def _key_cmd(rig, opcode, kid, signer_kid=None):
    return rig.frame(role=Role.ADMIN, opcode=opcode, args=bytes([kid]), key_id=signer_kid)


def _clean_reject(rig, frame_bytes, reason):
    c0, w0, g0 = rig.state.last_counter, rig.state.nv_writes, rig.v.guard.failures
    r = rig.send(frame_bytes)
    assert r["verdict"] == "REJECT" and r["reason"] == reason, r["reason"]
    assert rig.state.last_counter == c0 and rig.state.nv_writes == w0
    return r, g0


# ---------------------------------------------------------------- suites
@pytest.mark.parametrize("suite", list(suites.SUITES))
def test_every_suite_signs_and_rejects_tampering(suite):
    pk, sk = suites.generate_keypair(suite)
    msg = b"Q-UPLINK test message"
    sig = suites.sign(suite, sk, msg)
    assert len(sig) == suites.SUITES[suite]["sig_len"] and len(pk) == suites.SUITES[suite]["pk_len"]
    assert suites.verify(suite, pk, msg, sig)
    assert not suites.verify(suite, pk, msg + b"!", sig)
    assert not suites.verify(suite, pk, msg, sig[:-1] + bytes([sig[-1] ^ 1]))


def test_hybrid_needs_both_signatures():
    pk, sk = suites.generate_keypair("hybrid")
    msg = b"hybrid"
    sig = suites.sign("hybrid", sk, msg)
    bad_classical = bytes([sig[0] ^ 1]) + sig[1:]
    bad_pq = sig[:64] + suites.sign("falcon512", suites.generate_keypair("falcon512")[1], msg)
    assert not suites.verify("hybrid", pk, msg, bad_classical)  # a broken Ed25519 half fails
    assert not suites.verify("hybrid", pk, msg, bad_pq)  # a broken Falcon half fails


# ---------------------------------------------------------------- onboard key states
def test_standby_key_is_refused_without_signature_work(rig):
    f = rig.frame(key_id=3)  # pre-loaded OPERATOR spare, not yet activated
    r, g0 = _clean_reject(rig, f.to_bytes(), "E_KEY_INACTIVE")
    assert r["sig_checked"] is False and rig.v.guard.failures == g0


def test_operator_cannot_manage_keys(rig):
    f = rig.frame(role=Role.OPERATOR, opcode=Opcode.KEY_ACTIVATE, args=bytes([3]))
    _clean_reject(rig, f.to_bytes(), "E_UNAUTHORIZED")


def test_rotation_activate_then_revoke_in_single_writes(rig):
    w0 = rig.state.nv_writes
    r = rig.send(_key_cmd(rig, Opcode.KEY_ACTIVATE, 3).to_bytes())
    assert r["verdict"] == "ACCEPT" and rig.state.key_state(3) == "active" and rig.state.nv_writes == w0 + 1
    assert rig.send(rig.frame(key_id=3).to_bytes())["verdict"] == "ACCEPT"  # new key works
    assert rig.send(rig.frame(key_id=1).to_bytes())["verdict"] == "ACCEPT"  # overlap: old key still valid
    r = rig.send(_key_cmd(rig, Opcode.KEY_REVOKE, 1).to_bytes())
    assert r["verdict"] == "ACCEPT" and rig.state.key_state(1) == "revoked"
    # a validly signed frame from the revoked (say, stolen) key is refused before signature work
    r, _ = _clean_reject(rig, rig.frame(key_id=1).to_bytes(), "E_KEY_REVOKED")
    assert r["sig_checked"] is False
    # revocation is final and cannot be repeated or undone
    _clean_reject(rig, _key_cmd(rig, Opcode.KEY_REVOKE, 1).to_bytes(), "E_KEY_POLICY")
    _clean_reject(rig, _key_cmd(rig, Opcode.KEY_ACTIVATE, 1).to_bytes(), "E_KEY_POLICY")


def test_last_admin_key_cannot_be_revoked(rig):
    _clean_reject(rig, _key_cmd(rig, Opcode.KEY_REVOKE, 2).to_bytes(), "E_KEY_POLICY")
    _clean_reject(rig, _key_cmd(rig, Opcode.KEY_ACTIVATE, 42).to_bytes(), "E_KEY_POLICY")  # not provisioned


def test_migration_to_ml_dsa_and_hybrid(rig):
    for kid in (5, 7):
        assert rig.send(_key_cmd(rig, Opcode.KEY_ACTIVATE, kid).to_bytes())["verdict"] == "ACCEPT"
    f5 = rig.frame(key_id=5)
    assert len(f5.signature) == 2420 and len(f5.to_bytes()) == HEADER_LEN + len(f5.command) + 2420
    r = rig.send(f5.to_bytes())
    assert r["verdict"] == "ACCEPT" and r["suite"] == "mldsa44"
    f7 = rig.frame(key_id=7)
    assert len(f7.signature) == 730
    assert rig.send(f7.to_bytes())["verdict"] == "ACCEPT"


def test_algorithm_is_bound_to_the_key_no_downgrade(rig):
    assert rig.send(_key_cmd(rig, Opcode.KEY_ACTIVATE, 5).to_bytes())["verdict"] == "ACCEPT"
    # attacker re-labels a valid Falcon (OPERATOR key 1) frame as coming from the ML-DSA key 5
    f = rig.frame(key_id=1)
    data = bytearray(f.to_bytes())
    data[2] = 5
    _clean_reject(rig, bytes(data), "E_BAD_SIG")


# ---------------------------------------------------------------- encryption at rest
def test_private_keys_encrypted_at_rest(tmp_path, monkeypatch):
    monkeypatch.delenv("QUPLINK_KEY_PASSPHRASE", raising=False)
    meta = keygen.ensure_role_keys(tmp_path)
    assert meta["encrypted_at_rest"] is False
    plain = keygen.load_secret_key(tmp_path, 1)
    monkeypatch.setenv("QUPLINK_KEY_PASSPHRASE", "correct horse battery staple")
    meta = keygen.ensure_role_keys(tmp_path)  # seals the existing plaintext keys
    kd = keygen.keys_dir(tmp_path)
    assert meta["encrypted_at_rest"] is True
    assert not list(kd.glob("*.sk")) and len(list(kd.glob("*.sk.enc"))) == 8
    assert plain.hex() not in (kd / "k1.sk.enc").read_text()
    assert keygen.load_secret_key(tmp_path, 1) == plain
    monkeypatch.setenv("QUPLINK_KEY_PASSPHRASE", "wrong")
    with pytest.raises(keygen.KeyUnavailable):
        keygen.load_secret_key(tmp_path, 1)
    monkeypatch.delenv("QUPLINK_KEY_PASSPHRASE")
    with pytest.raises(keygen.KeyUnavailable, match="QUPLINK_KEY_PASSPHRASE"):
        keygen.load_secret_key(tmp_path, 1)


# ---------------------------------------------------------------- end to end through the API
@pytest.fixture(scope="module")
def client(tmp_path_factory):
    root = tmp_path_factory.mktemp("keys")
    mp = pytest.MonkeyPatch()
    mp.setenv("QUPLINK_DATA_DIR", str(root / "data"))
    mp.setenv("QUPLINK_EVIDENCE_DIR", str(root / "evidence"))
    mp.setenv("QUPLINK_ALLOW_DEV_NONCE", "true")
    mp.setenv("QUPLINK_NO_DOTENV", "1")
    for k in ("QPIAI_OPT_API_KEY", "QPIAI_QCLOUD_API_KEY", "QCLOUD_API_KEY", "QUPLINK_KEY_PASSPHRASE"):
        mp.delenv(k, raising=False)
    import satauth.api.main as main
    import satauth.config

    importlib.reload(satauth.config)
    main = importlib.reload(main)
    with TestClient(main.app) as c:
        yield c
    mp.undo()


def test_rotate_and_migrate_through_the_api(client):
    k = client.get("/api/keys").json()
    assert k["signing"] == {"OPERATOR": 1, "ADMIN": 2} and len(k["keys"]) == 8
    assert client.post("/api/attack/revoked").status_code == 409  # no window / nothing retired yet
    client.post("/api/pass/open", json={})
    assert client.post("/api/keys/rotate", json={"role": "OPERATOR", "to_kid": 4}).status_code == 400  # ADMIN key
    r = client.post("/api/keys/rotate", json={"role": "OPERATOR", "to_kid": 3}).json()
    assert [f["verdict"] for f in r["frames"]] == ["ACCEPT", "ACCEPT"] and r["after"]["signing"]["OPERATOR"] == 3
    rows = {x["key_id"]: x for x in r["after"]["keys"]}
    assert rows[1]["onboard_state"] == "revoked" and rows[1]["ground_state"] == "retired"
    for kind in ("valid", "revoked", "forged", "unauthorized"):
        a = client.post(f"/api/attack/{kind}").json()
        assert a["passed"], (kind, a["observed"])
    # migrate ADMIN to ML-DSA-44 (FIPS 204): PASS_OPEN and ADMIN frames grow, plans are re-sized
    client.post("/api/pass/open", json={})
    resp = client.post("/api/keys/rotate", json={"role": "ADMIN", "to_kid": 6})
    assert resp.status_code == 200, resp.text
    r = resp.json()
    assert r["after"]["signature_bytes"]["ADMIN"] == 2420 and r["after"]["pass_open_bytes"] == 16 + 33 + 2420
    o = client.post("/api/pass/open", json={}).json()
    assert o["pass_open"]["verdict"] == "ACCEPT"  # PASS_OPEN now signed with ML-DSA-44
    q = client.get("/api/queue").json()
    assert q["passes"][0]["pass_open_bytes"] == 2469
    # reset restores the provisioned ring (primaries active, spares standby)
    client.post("/api/reset")
    assert client.get("/api/keys").json()["signing"] == {"OPERATOR": 1, "ADMIN": 2}
