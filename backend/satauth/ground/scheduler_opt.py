"""Multi-pass command scheduling with QpiAI Opt (FR-15, FR-16; PRD 11.1).

    maximise   sum_i sum_t p_i * w_t * x[i,t]
    subject to sum_t x[i,t] <= 1                       (sent at most once)
               sum_i b_i * x[i,t] <= B_t - PASS_OPEN   (pass byte budget)
               x[i,t] = 0 for t > d_i                  (deadline)
               x[B,t] <= sum_{t'<=t} x[A,t']           (B only after A)

Built with the qpiai_opt modeller and solved by the QpiAI Opt solver.
mode="platform" submits a cloud job (records job_id/problem_id, may consume
credits); mode="local" runs the authenticated QpiAI local solver (free, no job id).
The returned plan is decoded and re-validated independently before use; a
classical baseline is never substituted when Opt is unavailable.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .baselines import brute_force, greedy
from .feasibility import explain, validate_plan
from .queue import Instance


class OptUnavailable(RuntimeError):
    """QpiAI Opt could not be executed (missing key, auth failure, network...)."""


def var_name(cid: str, t: int) -> str:
    return f"x_{cid}_p{t}"


def build_model(inst: Instance):
    from qpiai_opt.opt_modeller import Binary, Model, quicksum

    inst.validate()
    x: dict[tuple[str, int], Any] = {}
    for c in inst.commands:
        for p in inst.passes:
            x[(c.id, p.index)] = Binary(var_name(c.id, p.index))

    model = Model("q_uplink_multipass_schedule")
    model.maximize(
        quicksum(c.priority * inst.weight(p.index) * x[(c.id, p.index)] for c in inst.commands for p in inst.passes)
    )
    for c in inst.commands:
        model.add_constraint(quicksum(x[(c.id, p.index)] for p in inst.passes) <= 1, label=f"once_{c.id}")
    for p in inst.passes:
        model.add_constraint(
            quicksum(c.frame_bytes * x[(c.id, p.index)] for c in inst.commands) <= p.command_budget,
            label=f"budget_p{p.index}",
        )
    for c in inst.commands:
        for p in inst.passes:
            if p.index > c.deadline_pass:
                model.add_constraint(x[(c.id, p.index)] <= 0, label=f"deadline_{c.id}_p{p.index}")
    for c in inst.commands:
        for dep in c.depends_on:
            for p in inst.passes:
                model.add_constraint(
                    x[(c.id, p.index)] - quicksum(x[(dep, q.index)] for q in inst.passes if q.index <= p.index) <= 0,
                    label=f"dep_{dep}_before_{c.id}_p{p.index}",
                )
    return model, x


def model_summary(inst: Instance, model) -> dict:
    from qpiai_opt.opt_solvers import classify

    n_cons = (
        len(inst.commands) + inst.T
        + sum(1 for c in inst.commands for p in inst.passes if p.index > c.deadline_pass)
        + sum(len(c.depends_on) * inst.T for c in inst.commands)
    )
    try:
        cls = classify(model)
    except Exception as exc:  # classification is informative only
        cls = f"unavailable: {exc}"
    return {
        "name": "q_uplink_multipass_schedule",
        "problem_class": cls,
        "binary_variables": len(inst.commands) * inst.T,
        "constraints": n_cons,
        "objective": "maximize sum_i sum_t priority_i * w_t * x[i,t], w_t = 1 - 0.1 (t-1)",
        "constraint_families": [
            "once_<cmd>: sum_t x[i,t] <= 1",
            "budget_p<t>: sum_i frame_bytes_i x[i,t] <= budget_t - 715 (PASS_OPEN)",
            "deadline_<cmd>_p<t>: x[i,t] <= 0 for t > deadline_i",
            "dep_<A>_before_<B>_p<t>: x[B,t] - sum_{t'<=t} x[A,t'] <= 0",
        ],
    }


def decode(inst: Instance, solution: Any) -> dict[str, int | None]:
    if not isinstance(solution, dict):
        raise ValueError(f"unexpected Opt solution type {type(solution).__name__}; expected name->value mapping")
    plan: dict[str, int | None] = {}
    for c in inst.commands:
        chosen = [p.index for p in inst.passes if float(solution.get(var_name(c.id, p.index), 0.0)) > 0.5]
        if len(chosen) > 1:
            raise ValueError(f"Opt assigned {c.id} to several passes {chosen}")
        plan[c.id] = chosen[0] if chosen else None
    return plan


def run_opt(inst: Instance, *, api_key: str | None, mode: str) -> dict:
    """Execute QpiAI Opt. Raises OptUnavailable instead of falling back."""
    if not api_key:
        raise OptUnavailable("QPIAI_OPT_API_KEY is not set in .env, so QpiAI Opt cannot run. "
                             "No plan was produced (classical baselines are never substituted).")
    if mode not in ("platform", "local"):
        raise ValueError("mode must be 'platform' or 'local'")
    from qpiai_opt.opt_solvers import Client, solve

    model, _ = build_model(inst)
    summary = model_summary(inst, model)
    client = Client(api_key=api_key)
    t0 = time.perf_counter()
    started = datetime.now(timezone.utc).isoformat()
    try:
        result = solve(model, mode=mode, client=client)
    except Exception as exc:
        raise OptUnavailable(f"QpiAI Opt {mode} solve failed: {type(exc).__name__}: {exc}") from exc
    wall = time.perf_counter() - t0
    raw = result.model_dump(mode="json")
    try:
        info = result.info()
        info_d = {"method": str(info.method), "termination": str(info.termination), "guarantee": str(info.guarantee)}
    except Exception as exc:
        info_d = {"error": str(exc)}
    plan = decode(inst, result.solution)
    return {
        "solver": "QpiAI Opt",
        "execution_mode": getattr(result, "execution_mode", mode),
        "requested_mode": mode,
        "job_id": raw.get("job_id"),
        "problem_id": raw.get("problem_id"),
        "problem_class": raw.get("problem_class"),
        "reported_objective": raw.get("objective"),
        "status": raw.get("status"),
        "model_status": raw.get("model_status"),
        "info": info_d,
        "started_utc": started,
        "wall_time_s": round(wall, 3),
        "model": summary,
        "raw_result": raw,
        "plan": plan,
    }


def plan_with_opt(inst: Instance, *, api_key: str | None, mode: str, brute_force_max_commands: int = 16) -> dict:
    """Run Opt, validate its plan, and compare with the classical baselines."""
    inst.validate()
    opt = run_opt(inst, api_key=api_key, mode=mode)
    validation = validate_plan(inst, opt["plan"])
    g = greedy(inst)
    g["validation"] = validate_plan(inst, g["plan"])
    if len(inst.commands) <= brute_force_max_commands:
        bf = brute_force(inst)
        if bf["plan"] is not None:
            bf["validation"] = validate_plan(inst, bf["plan"])
    else:
        bf = {"method": "brute_force", "completed": False, "plan": None, "objective": None,
              "note": f"skipped: {len(inst.commands)} commands > {brute_force_max_commands}"}
    comparison = {
        "opt_objective": validation["objective"],
        "greedy_objective": g["objective"],
        "brute_force_objective": bf.get("objective"),
        "opt_vs_greedy": round(validation["objective"] - g["objective"], 6),
        "opt_matches_brute_force": (bf.get("objective") is not None
                                    and abs(validation["objective"] - bf["objective"]) < 1e-6),
        "opt_scheduled": validation["scheduled"],
        "greedy_scheduled": g["validation"]["scheduled"],
        "brute_force_scheduled": (bf.get("validation") or {}).get("scheduled"),
    }
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "instance": inst.to_dict(),
        "opt": opt,
        "validation": validation,
        "approved_for_signing": validation["feasible"],
        "explanations": explain(inst, opt["plan"]),
        "baselines": {"greedy": g, "brute_force": bf},
        "comparison": comparison,
    }
