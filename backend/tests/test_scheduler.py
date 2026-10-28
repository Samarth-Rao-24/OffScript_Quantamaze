"""Scheduler, feasibility validator, baselines and the QpiAI Opt model."""

from __future__ import annotations

import os

import pytest

from satauth.ground.baselines import brute_force, greedy
from satauth.ground.feasibility import explain, order_within_pass, validate_plan
from satauth.ground.queue import Command, Instance, PassWindow, default_passes, default_queue
from satauth.ground.scheduler_opt import OptUnavailable, build_model, decode, run_opt, var_name
from satauth.common.roles import Opcode, Role

BUDGETS = [3600, 3600, 2900, 3600]


@pytest.fixture
def inst():
    i = Instance(default_queue(), default_passes(BUDGETS))
    i.validate()
    return i


def test_baselines_feasible_and_brute_force_optimal(inst):
    g = greedy(inst)
    bf = brute_force(inst)
    assert bf["completed"]
    assert validate_plan(inst, g["plan"])["feasible"]
    assert validate_plan(inst, bf["plan"])["feasible"]
    assert bf["objective"] >= g["objective"]


@pytest.mark.parametrize("mutate,needle", [
    (lambda p: p.update({"C03": 1}), "before its dependency"),        # C02 is later than C03
    (lambda p: p.update({"C11": 2}), "after its deadline"),
    (lambda p: p.update({"C02": None}), "not scheduled"),             # C03 depends on C02
    (lambda p: p.update({"C05": 7}), "invalid pass"),
])
def test_validator_catches_violations(inst, mutate, needle):
    plan = brute_force(inst)["plan"]
    plan.update({"C01": 1, "C02": 2, "C03": 2})
    mutate(plan)
    rep = validate_plan(inst, plan)
    assert not rep["feasible"]
    assert any(needle in v for v in rep["violations"]), rep["violations"]


def test_validator_catches_budget_overrun(inst):
    plan = {c.id: 1 if c.deadline_pass >= 1 else None for c in inst.commands}
    rep = validate_plan(inst, plan)
    assert not rep["feasible"]
    assert any("exceeds budget" in v for v in rep["violations"])


def test_over_budget_queue_defers_low_priority():
    """Scenario 10 (scheduler side): more bytes queued than the passes allow."""
    cmds = [Command(f"K{i:02d}", f"cmd {i}", Opcode.CAPTURE_IMAGE, "00" * 10, Role.OPERATOR, 20 - i, 2)
            for i in range(10)]
    inst = Instance(cmds, [PassWindow(1, 715 + 2 * 700), PassWindow(2, 715 + 2 * 700)])
    total = sum(c.frame_bytes for c in cmds)
    assert total > sum(p.command_budget for p in inst.passes)
    bf = brute_force(inst)
    rep = validate_plan(inst, bf["plan"])
    assert rep["feasible"] and rep["scheduled"] == 4 and rep["deferred"] == 6
    sent = {c for c, t in bf["plan"].items() if t}
    assert sent == {"K00", "K01", "K02", "K03"}  # the four highest priorities
    for b in rep["budgets"]:
        assert b["used_bytes"] <= b["budget_bytes"]
    whys = {e["id"]: e["status"] for e in explain(inst, bf["plan"])}
    assert all(whys[f"K{i:02d}"] == "DEFERRED_BUDGET" for i in range(4, 10))


def test_order_within_pass_respects_dependencies(inst):
    plan = {c.id: None for c in inst.commands}
    plan.update({"C01": 1, "C02": 1, "C03": 1})
    assert order_within_pass(inst, plan, 1) == ["C01", "C02", "C03"]


def test_instance_rejects_cycles_and_unknown_deps():
    a = Command("A", "a", Opcode.NOOP_PING, "", Role.OPERATOR, 1, 1, ["B"])
    b = Command("B", "b", Opcode.NOOP_PING, "", Role.OPERATOR, 1, 1, ["A"])
    with pytest.raises(ValueError, match="cycle"):
        Instance([a, b], [PassWindow(1, 3000)]).validate()
    with pytest.raises(ValueError, match="unknown"):
        Instance([Command("A", "a", Opcode.NOOP_PING, "", Role.OPERATOR, 1, 1, ["Z"])], [PassWindow(1, 3000)]).validate()


def test_opt_model_structure_and_qpiai_feasibility_agree(inst):
    from qpiai_opt.opt_solvers import classify, feasibility

    model, x = build_model(inst)
    assert classify(model) == "MILP"
    assert len(x) == len(inst.commands) * inst.T
    bf = brute_force(inst)["plan"]
    good = {var_name(c, t): int(bf[c] == t) for c in bf for t in range(1, inst.T + 1)}
    assert feasibility(model, good)["feasible"] is True
    bad = dict(good)
    bad[var_name("C11", 3)] = 1  # deadline violation
    assert feasibility(model, bad)["feasible"] is False
    plan_bad = decode(inst, {**good, var_name("C11", 1): 0, var_name("C11", 3): 1})
    assert not validate_plan(inst, plan_bad)["feasible"]


def test_decode_rejects_double_assignment(inst):
    sol = {var_name("C01", 1): 1.0, var_name("C01", 2): 1.0}
    with pytest.raises(ValueError, match="several passes"):
        decode(inst, sol)


def test_opt_refuses_without_key_and_never_falls_back(inst):
    with pytest.raises(OptUnavailable, match="never substituted"):
        run_opt(inst, api_key=None, mode="platform")


def test_reduced_qaoa_instance_size(inst):
    from satauth.ground.qaoa_run import DEFAULT_REDUCED, compile_qubo, reduced_brute_force

    comp = compile_qubo(inst, DEFAULT_REDUCED)
    assert 8 <= comp["qubits"] <= 12
    bf = reduced_brute_force(inst, comp["red"])
    assert bf["objective"] > 0


@pytest.mark.skipif(not os.environ.get("QPIAI_OPT_API_KEY"), reason="needs QPIAI_OPT_API_KEY (real QpiAI Opt)")
def test_opt_local_solve_matches_brute_force(inst):
    """Integration: real QpiAI Opt (local mode, free) reaches the certified optimum."""
    res = run_opt(inst, api_key=os.environ["QPIAI_OPT_API_KEY"], mode="local")
    rep = validate_plan(inst, res["plan"])
    assert rep["feasible"]
    assert abs(rep["objective"] - brute_force(inst)["objective"]) < 1e-6
