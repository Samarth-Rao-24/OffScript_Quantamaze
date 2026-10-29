"""API-level tests through FastAPI's TestClient against the real satellite process."""

from __future__ import annotations

import importlib
import io
import zipfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    root = tmp_path_factory.mktemp("api")
    mp = pytest.MonkeyPatch()
    mp.setenv("QUPLINK_DATA_DIR", str(root / "data"))
    mp.setenv("QUPLINK_EVIDENCE_DIR", str(root / "evidence"))
    mp.setenv("QUPLINK_ALLOW_DEV_NONCE", "true")  # no QCloud in CI; nonces are labelled DEV
    mp.setenv("QUPLINK_NO_DOTENV", "1")  # these tests must never see real keys
    mp.delenv("QPIAI_OPT_API_KEY", raising=False)
    mp.delenv("QPIAI_QCLOUD_API_KEY", raising=False)
    mp.delenv("QCLOUD_API_KEY", raising=False)
    import satauth.config
    import satauth.api.main as main

    importlib.reload(satauth.config)
    main = importlib.reload(main)
    with TestClient(main.app) as c:
        c.root = root
        c.main = main
        yield c
    mp.undo()


def test_health_and_no_secrets(client):
    h = client.get("/api/health").json()
    assert h["ok"] is True
    text = client.get("/api/config").text + client.get("/api/state").text
    assert "secret" not in text.lower() or "secret_key_len" in text  # only lengths/flags, never values
    assert h["config"]["opt_key_configured"] is False


def test_plan_without_key_returns_503_and_no_plan(client):
    r = client.post("/api/plan", json={"mode": "local"})
    assert r.status_code == 503 and "never substituted" in r.json()["error"]
    assert client.get("/api/plan").json() == {}


def test_attacks_require_window_then_all_pass(client):
    assert client.post("/api/attack/tamper").status_code == 409
    o = client.post("/api/pass/open", json={}).json()
    assert o["pass_open"]["verdict"] == "ACCEPT"
    assert o["nonce"]["randomness_class"] == "development-only"
    for kind in ["valid", "tamper", "replay", "expired", "unauthorized", "forged", "wrongsat", "overbudget"]:
        r = client.post(f"/api/attack/{kind}").json()
        assert r["passed"], (kind, r)
    client.post("/api/pass/open", json={})
    r = client.post("/api/attack/crosspass").json()
    assert r["passed"] and r["observed"] == ["E_BAD_SIG"]
    r = client.post("/api/attack/flood").json()
    assert r["passed"] and r["sig_verifications_spent"] <= 8
    assert r["flood_summary"]["by_reason"]["E_FLOOD_LOCKOUT"] >= 492


def test_run_pass_uses_validated_plan(client):
    """Inject a plan file (as Opt would write it) and run pass 1 through the real pipeline."""
    from satauth.common.atomic import atomic_write_json
    from satauth.ground.baselines import brute_force
    from satauth.ground.queue import Instance

    client.post("/api/reset")
    q = client.get("/api/queue").json()
    inst = Instance.from_dict(q)
    plan = brute_force(inst)["plan"]
    fixture = {"instance": inst.to_dict(), "opt": {"plan": plan, "job_id": "TEST-FIXTURE-NOT-OPT",
                                                     "execution_mode": "test-fixture"}}
    atomic_write_json(client.main.settings.data_dir / "ground" / "current_plan.json", fixture)
    r = client.post("/api/pass/1/run", json={"pace_ms": 0}).json()
    sent = [f for f in r["frames"]]
    assert sent and all(f["verdict"] == "ACCEPT" for f in sent)
    assert r["link"]["used_bytes"] <= r["link"]["budget_bytes"]
    # a corrupted (infeasible) plan is refused before anything is signed
    bad = dict(fixture)
    bad["opt"] = {**fixture["opt"], "plan": {**plan, "C11": 4}}
    atomic_write_json(client.main.settings.data_dir / "ground" / "current_plan.json", bad)
    r = client.post("/api/pass/2/run", json={"pace_ms": 0})
    assert r.status_code == 409 and "feasibility" in r.json()["error"]


def test_evidence_zip_has_no_private_keys(client):
    r = client.get("/api/evidence.zip")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert "manifest.json" in names and any(n.endswith("/k1.pk") for n in names)
    assert sum(n.endswith(".pk") for n in names) == 8  # the whole public key ring
    assert not any(n.endswith((".sk", ".sk.enc")) for n in names)
    for n in names:
        # env var *names* (e.g. "QPIAI_OPT_API_KEY is not set") appear only in json/jsonl records and the txt logs
        assert b"QPIAI" not in z.read(n) or n.endswith((".json", ".jsonl", ".txt"))


def test_log_endpoint_filters(client):
    client.post("/api/pass/open", json={})
    client.post("/api/attack/wrongsat")
    rows = client.get("/api/log", params={"verdict": "REJECT"}).json()["rows"]
    assert any(r["reason"] == "E_WRONG_SAT" for r in rows)
    assert rows and all(r["verdict"] == "REJECT" for r in rows)


def test_websocket_streams_frame_events(client):
    with client.websocket_connect("/ws/frames") as ws:
        assert ws.receive_json()["type"] == "hello"
        client.post("/api/pass/open", json={})
        seen = set()
        for _ in range(10):
            e = ws.receive_json()
            if e.get("type") == "frame":
                seen.add(e["phase"])
            if "verdict" in seen:
                break
        assert {"signed", "tx", "verdict"} <= seen
