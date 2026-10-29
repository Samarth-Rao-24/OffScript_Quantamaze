"""Missing-packet detection and recovery.

Verifier level: the onboard counter-gap report. API level (real satellite
process): a frame lost on the link gets no acknowledgement, its dependents are
held, the satellite's gap report is reconciled against the ground ledger, the
lost command is re-signed (never resent as-is), and what cannot fit is carried
over to a re-plan. Plans here come from the brute-force baseline as a labelled
test fixture, because these tests run without a QpiAI key.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from satauth.ground.baselines import brute_force
from satauth.ground.feasibility import validate_plan
from satauth.ground.queue import Instance, default_passes, default_queue
from satauth.ground.replan import build_subinstance, delivered_from_runs, merge_plan
from satauth.link.pass_sim import LinkSimulator


# ---------------------------------------------------------------- unit level
def test_onboard_reports_counter_gap_in_the_same_single_write(rig):
    a = rig.frame()
    assert rig.send(a.to_bytes())["verdict"] == "ACCEPT"
    lost = rig.frame()  # signed and "transmitted", never delivered
    b = rig.frame()
    w0 = rig.state.nv_writes
    r = rig.send(b.to_bytes())
    assert r["verdict"] == "ACCEPT"
    assert r["counter_gap"] == {"from": lost.counter, "to": lost.counter, "count": 1}
    assert rig.state.nv_writes == w0 + 1  # gap report costs no extra NV write
    assert rig.state.gap_summary()["missing_counters"] == 1
    assert r["log"]["counter_gap"]["from"] == lost.counter
    # the late original is now a replay: this is why lost commands are re-signed
    late = rig.send(lost.to_bytes())
    assert late["verdict"] == "REJECT" and late["reason"] == "E_REPLAY"


def test_link_loss_is_deterministic_and_first_tx_only(tmp_path):
    link = LinkSimulator(tmp_path / "link.jsonl")
    link.open_window(1, 1, 10_000)
    link.set_loss(drop=["C07"])
    assert link.transmit(b"x" * 700, label="C07")["lost"] is True
    assert link.transmit(b"x" * 700, label="C07")["lost"] is False  # retransmission gets through
    assert link.snapshot()["lost"] == 1 and link.snapshot()["used_bytes"] == 1400  # lost frames still cost bytes
    link.set_loss(rate=0.3, seed=42)
    a = [link.transmit(b"y", label=f"F{i}")["lost"] for i in range(40)]
    link.set_loss(rate=0.3, seed=42)
    b = [link.transmit(b"y", label=f"F{i}")["lost"] for i in range(40)]
    assert a == b and any(a) and not all(a)  # seeded: reproducible drills
    with pytest.raises(ValueError):
        link.set_loss(rate=0.9)


def test_replan_subinstance_keeps_deadlines_and_dependencies():
    inst = Instance(default_queue(), default_passes([3600, 3600, 2900, 2200]))
    delivered = {"C01": 1, "C02": 1, "C05": 1, "C11": 1, "C03": 2, "C04": 2, "C06": 2, "C13": 2, "C07": 3, "C12": 3}
    cut = build_subinstance(inst, delivered, 4)
    sub = cut["sub"]
    assert [p.index for p in sub.passes] == [1] and sub.passes[0].budget_bytes == 2200
    by = sub.by_id()
    assert set(by) == {"C08", "C09", "C10", "C14"} and by["C08"].depends_on == []  # C07 already delivered
    assert by["C09"].depends_on == ["C08"] and by["C09"].deadline_pass == 1
    sub_plan = brute_force(sub)["plan"]
    merged = merge_plan(inst, delivered, sub_plan, cut["shift"])
    assert validate_plan(inst, merged)["feasible"]
    # a command past its deadline is missed, and its dependents are blocked
    cut2 = build_subinstance(inst, {"C01": 1}, 3)
    assert {"C02", "C03"} <= set(cut2["missed"])  # deadlines 2 and 2, re-planning from pass 3
    assert "C04" in cut2["blocked"]  # depends on C03, which can no longer run


# ---------------------------------------------------------------- API level, real satellite process
@pytest.fixture(scope="module")
def client(tmp_path_factory):
    root = tmp_path_factory.mktemp("loss")
    mp = pytest.MonkeyPatch()
    mp.setenv("QUPLINK_DATA_DIR", str(root / "data"))
    mp.setenv("QUPLINK_EVIDENCE_DIR", str(root / "evidence"))
    mp.setenv("QUPLINK_ALLOW_DEV_NONCE", "true")
    mp.setenv("QUPLINK_NO_DOTENV", "1")
    for k in ("QPIAI_OPT_API_KEY", "QPIAI_QCLOUD_API_KEY", "QCLOUD_API_KEY", "NASA_API_KEY"):
        mp.delenv(k, raising=False)
    import satauth.api.main as main
    import satauth.config

    importlib.reload(satauth.config)
    main = importlib.reload(main)
    with TestClient(main.app) as c:
        c.main = main
        yield c
    mp.undo()


def _fixture_plan(client):
    from satauth.common.atomic import atomic_write_json

    inst = Instance.from_dict(client.get("/api/queue").json())
    plan = brute_force(inst)["plan"]
    atomic_write_json(client.main.settings.data_dir / "ground" / "current_plan.json",
                      {"instance": inst.to_dict(), "opt": {"plan": plan, "job_id": "TEST-FIXTURE-NOT-OPT",
                                                           "execution_mode": "test-fixture"}})
    return plan


def test_lost_frame_hold_gap_report_retransmit_and_carry_over(client):
    client.post("/api/reset")
    plan = _fixture_plan(client)
    assert plan["C07"] == 3 and plan["C08"] == 3 and plan["C12"] == 3  # the drill below relies on this plan
    for t in (1, 2):
        r = client.post(f"/api/pass/{t}/run", json={"pace_ms": 0}).json()
        assert all(f["verdict"] == "ACCEPT" for f in r["frames"])
    before = client.get("/api/state").json()["onboard"]["last_counter"]
    r = client.post("/api/pass/3/run", json={"pace_ms": 0, "drop": ["C07"]}).json()
    v = [(f["cmd_id"], f["verdict"]) for f in r["frames"]]
    assert v[0] == ("C07", "NO_ACK")
    assert ("C08", "HELD") in v  # never signed ahead of its unacknowledged dependency
    retx = [f for f in r["frames"] if f["cmd_id"] == "C07" and f["verdict"] == "ACCEPT"]
    assert retx and retx[0]["attempt"] == 2 and retx[0]["counter"] > r["frames"][0]["counter"]  # re-signed
    assert [c["cmd_id"] for c in r["carried_over"]] == ["C08"]
    d = client.get("/api/delivery").json()
    kinds = [a["kind"] for a in d["alerts"]]
    for k in ("MISSING_PACKET", "DEPENDENCY_HOLD", "GAP_REPORTED", "RETRANSMIT_OK", "CARRIED_OVER"):
        assert k in kinds, k
    gap = next(a for a in d["alerts"] if a["kind"] == "GAP_REPORTED")
    assert gap["lost"] == ["C07"] and gap["unexplained"] == []
    onboard = client.get("/api/state").json()["onboard"]
    assert onboard["gaps"]["missing_counters"] == 1 and onboard["last_counter"] > before
    assert d["delivered"]["C07"] == 3 and "C08" not in d["delivered"]


def test_replan_moves_carried_command_and_next_pass_delivers_it(client, monkeypatch):
    import satauth.api.service as service

    def fixture_opt(sub, api_key, mode):  # stands in for QpiAI Opt (no key in tests), labelled as such
        b = brute_force(sub)
        return {"opt": {"plan": b["plan"], "execution_mode": "test-fixture", "job_id": None},
                "comparison": {}, "baselines": {}}

    monkeypatch.setattr(service, "plan_with_opt", fixture_opt)
    new = client.post("/api/replan", json={}).json()
    assert new["replan"]["from_pass"] == 4 and "C08" in new["replan"]["requeued"]
    assert new["opt"]["plan"]["C08"] == 4 and new["validation"]["feasible"]
    r = client.post("/api/pass/4/run", json={"pace_ms": 0}).json()
    assert ("C08", "ACCEPT") in [(f["cmd_id"], f["verdict"]) for f in r["frames"]]
    delivered = delivered_from_runs([{"pass": 4, "frames": r["frames"]}])
    assert "C08" in delivered


def test_rerunning_a_pass_never_resends_delivered_commands(client):
    r = client.post("/api/pass/1/run", json={"pace_ms": 0}).json()
    assert {f["verdict"] for f in r["frames"]} == {"SKIPPED"}


def test_nasa_routes_validate_and_never_expose_keys(client):
    r = client.get("/api/nasa").json()
    assert r["latest"] is None and r["config"]["nasa_key_configured"] is False
    assert r["config"]["norad_id"] == 25544
    assert client.post("/api/nasa/apply", json={}).status_code == 409  # nothing fetched yet
    assert client.post("/api/nasa/fetch", json={"uplink_bps": 1}).status_code == 400
    assert client.post("/api/nasa/fetch", json={"min_elevation_deg": 80}).status_code == 400
