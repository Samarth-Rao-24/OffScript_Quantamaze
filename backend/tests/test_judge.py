"""Judge console and QRNG inspector endpoints, against the real satellite process."""

from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    root = tmp_path_factory.mktemp("judge")
    mp = pytest.MonkeyPatch()
    mp.setenv("QUPLINK_DATA_DIR", str(root / "data"))
    mp.setenv("QUPLINK_EVIDENCE_DIR", str(root / "evidence"))
    mp.setenv("QUPLINK_ALLOW_DEV_NONCE", "true")
    mp.setenv("QUPLINK_NO_DOTENV", "1")
    for k in ("QPIAI_OPT_API_KEY", "QPIAI_QCLOUD_API_KEY", "QCLOUD_API_KEY"):
        mp.delenv(k, raising=False)
    import satauth.config
    import satauth.api.main as main

    importlib.reload(satauth.config)
    main = importlib.reload(main)
    with TestClient(main.app) as c:
        c.main = main
        yield c
    mp.undo()


def _window(client):
    r = client.post("/api/pass/open", json={})
    assert r.status_code == 200 and r.json()["pass_open"]["verdict"] == "ACCEPT", r.text


# ---------------------------------------------------------------- QRNG inspector
def test_qrng_job_detail_and_stats(client):
    rec = client.post("/api/qrng/fetch", json={"device": "QpiAI-QSV-Local"}).json()
    assert "h q[0];" in rec["qasm"] and "measure q[7] -> c[7];" in rec["qasm"]
    jobs = client.get("/api/qrng/jobs").json()["jobs"]
    assert jobs and jobs[-1]["device"] == "QpiAI-QSV-Local"
    d = client.get(f"/api/qrng/job/{jobs[-1]['file']}").json()
    st = d["stats"]
    assert st["shots"] == 1024 and st["outcomes_possible"] == 256
    assert sum(h["count"] for h in st["histogram"]) == 1024
    assert len(st["bit_one_frequency"]) == 8 and 0 <= st["chi_square_p_value"] <= 1
    assert client.get("/api/qrng/job/..%2F..%2Fsecret.json").status_code == 404


def test_nonce_verify_recomputes_and_matches(client):
    _window(client)  # consumes the job fetched in the previous test
    v = client.post("/api/nonce/verify", json={}).json()
    assert v["verified"] is True, v["steps"]
    assert v["recomputed"] == v["nonce"]
    labels = [s["label"] for s in v["steps"]]
    assert "Recomputed nonce matches" in labels


def test_nonce_verify_detects_tampered_counts(client):
    client.post("/api/qrng/fetch", json={"device": "QpiAI-QSV-Local"})
    _window(client)
    nonce = client.get("/api/state").json()["onboard"]["pass_nonce"]
    ev = client.main.settings.evidence_dir / "qcloud_jobs"
    row = [json.loads(l) for l in (ev / "nonce_derivations.jsonl").read_text().splitlines() if nonce in l][-1]
    p = ev / row["qrng_file"]
    rec = json.loads(p.read_text())
    original = p.read_text()
    k = next(iter(rec["counts"]))
    rec["counts"][k] += 1
    p.write_text(json.dumps(rec))
    try:
        v = client.post("/api/nonce/verify", json={"nonce": nonce}).json()
        assert v["verified"] is False
        assert any(s["label"] == "Counts unchanged since the job" and not s["ok"] for s in v["steps"])
    finally:
        p.write_text(original)


def test_refetch_needs_a_cloud_job(client):
    f = client.get("/api/qrng/jobs").json()["jobs"][0]["file"]
    r = client.post(f"/api/qrng/job/{f}/refetch")
    assert r.status_code == 502 and "no QCloud job ID" in r.json()["detail"]


def test_refetch_compares_remote_counts(client, monkeypatch):
    """QCloud is mocked at the SDK boundary; the comparison logic is real."""
    from satauth.common.atomic import atomic_write_json
    from satauth.ground.qrng import counts_digest

    ev = client.main.settings.evidence_dir / "qcloud_jobs"
    counts = {"00000000": 4, "11111111": 4}
    atomic_write_json(ev / "qrng_fake_job-123.json", {"kind": "qrng", "job_id": "job-123", "device": "QpiAI-Indus-1",
                                                      "n_qubits": 8, "shots": 8, "counts": counts,
                                                      "counts_sha256": counts_digest(counts).hex()})
    import qpiai_quantum
    from qpiai_quantum.jobmanager import jobmanager

    monkeypatch.setattr(qpiai_quantum.QpiAIQuantumAuth, "login", staticmethod(lambda api_key: "ok"))
    monkeypatch.setattr(jobmanager.JobManager, "get_job_status",
                        lambda self, j: {"id": j, "status": "completed", "credits_used": 32})
    monkeypatch.setattr(jobmanager.JobManager, "get_job_results",
                        lambda self, j, device_name=None: type("R", (), {"counts": dict(counts)})())
    monkeypatch.setattr(client.main.settings.__class__, "qcloud_api_key", property(lambda s: "test-key"))
    r = client.post("/api/qrng/job/qrng_fake_job-123.json/refetch").json()
    assert r["status"]["status"] == "completed" and r["status"]["credits_used"] == 32
    assert r["counts_match_recorded"] is True
    assert list(ev.glob("refetch_job-123_*.json"))


# ---------------------------------------------------------------- judge console
def test_compose_variants(client):
    _window(client)
    ok = client.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "CAPTURE_IMAGE", "args_hex": "0102"}).json()
    assert ok["verdict"]["verdict"] == "ACCEPT" and ok["counter_after"] > ok["counter_before"]
    assert ok["decoded"]["opcode_name"] == "CAPTURE_IMAGE"
    r = client.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "0x20"}).json()
    assert r["verdict"]["reason"] == "E_UNAUTHORIZED"
    r = client.post("/api/judge/compose", json={"key": "ADMIN", "opcode": "NOOP_PING", "nonce": "previous"}).json()
    assert r["verdict"]["reason"] == "E_BAD_SIG" and r["counter_after"] == r["counter_before"]
    r = client.post("/api/judge/compose", json={"key": "ATTACKER", "opcode": "NOOP_PING"}).json()
    assert r["verdict"]["reason"] == "E_BAD_SIG"
    r = client.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "NOOP_PING", "counter": 1}).json()
    assert r["verdict"]["reason"] == "E_REPLAY"
    r = client.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "NOOP_PING", "expiry_offset_s": -5}).json()
    assert r["verdict"]["reason"] == "E_EXPIRED"
    assert client.post("/api/judge/compose", json={"key": "ROOT", "opcode": 1}).status_code == 400


def test_raw_and_last_frame(client):
    _window(client)
    ok = client.post("/api/judge/compose", json={"key": "OPERATOR", "opcode": "NOOP_PING"}).json()
    last = client.get("/api/judge/last").json()
    assert last["frame_hex"] == ok["frame_hex"]
    assert client.post("/api/judge/raw", json={"hex": last["frame_hex"]}).json()["verdict"]["reason"] == "E_REPLAY"
    flipped = bytearray(bytes.fromhex(last["frame_hex"]))
    flipped[17] ^= 0x01
    flipped[11] = (flipped[11] + 50) % 256  # bump counter so it reaches the signature check
    r = client.post("/api/judge/raw", json={"hex": flipped.hex()}).json()
    assert r["verdict"]["reason"] in ("E_BAD_SIG", "E_REPLAY")
    assert client.post("/api/judge/raw", json={"hex": "de ad be ef"}).json()["verdict"]["reason"] == "E_MALFORMED"
    assert client.post("/api/judge/raw", json={"hex": "xyz"}).status_code == 400


def test_sample_cases_all_pass_json_and_csv(client):
    sample = client.get("/api/judge/sample").json()
    _window(client)
    run = client.post("/api/judge/cases", json={"cases": sample["cases"]}).json()
    t = run["totals"]
    assert t["cases"] == len(sample["cases"]) and t["passed"] == t["cases"], run["results"]
    assert t["false_accepts"] == 0
    _window(client)
    run = client.post("/api/judge/cases", json={"csv": sample["csv"]}).json()
    assert run["totals"]["passed"] == run["totals"]["cases"], run["results"]
    assert (client.main.settings.evidence_dir / run["evidence_file"]).exists()


def test_cases_report_wrong_expectations(client):
    cases = [
        {"id": "A", "new_window": True, "key": "OPERATOR", "opcode": "NOOP_PING", "expect": "ACCEPT"},
        {"id": "B", "replay_of": "A", "expect": "ACCEPT"},              # judge wrongly expects accept
        {"id": "C", "key": "ATTACKER", "opcode": "NOOP_PING", "expect": "E_REPLAY"},  # wrong reason
        {"id": "D", "key": "OPERATOR", "opcode": "NOOP_PING", "expect": "MAYBE"},     # malformed case
        {"id": "E", "replay_of": "ZZ", "expect": "REJECT"},              # bad reference
    ]
    run = client.post("/api/judge/cases", json={"cases": cases}).json()
    by = {r["id"]: r for r in run["results"]}
    assert by["A"]["passed"] and by["B"]["outcome"] == "FALSE REJECT"
    assert by["C"]["outcome"] == "rejected, different reason"
    assert by["D"]["outcome"] == "CASE ERROR" and by["E"]["outcome"] == "CASE ERROR"
    t = run["totals"]
    assert (t["passed"], t["false_rejects"], t["wrong_reason"], t["errors"], t["false_accepts"]) == (1, 1, 1, 2, 0)


def test_cases_validation(client):
    assert client.post("/api/judge/cases", json={}).status_code == 400
    assert client.post("/api/judge/cases", json={"cases": [{}] * 501}).status_code == 400
