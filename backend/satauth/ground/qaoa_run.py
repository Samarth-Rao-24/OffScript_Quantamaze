"""QAOA experiment on a reduced scheduling instance (FR-18; PRD 11.2).

The full schedule (56 binaries, byte-level budgets) is far beyond what QAOA can
address today, so a reduced instance is cut from the live queue:

* a handful of commands and the first two passes;
* byte budgets expressed as *frame slots* (floor(command budget / 715 B), every
  frame is <= 715 B), which keeps slack qubits small. This restriction is
  conservative: any slot-feasible plan is byte-feasible, and the decoded plan is
  re-checked against exact byte budgets anyway.

The reduced model is compiled to a QUBO by the qpiai_opt modeller and solved
three ways on the *same* QUBO:
  1. QAOA via qpiai-opt[quantum] (mode="platform": QCloud circuit jobs on the
     configured simulator; mode="local": in-process QpiAI simulator, labelled);
  2. the classical QpiAI Opt solver;
  3. exhaustive brute force (exact optimum) for reference.
"""

from __future__ import annotations

import itertools
import time
from datetime import datetime, timezone

from ..common.frame import frame_size, MAX_BODY_LEN
from .queue import Instance, PassWindow

MAX_FRAME = frame_size(MAX_BODY_LEN)  # 714 B for a 32-byte body (PASS_OPEN excluded)
SLOT_BYTES = 715


def reduced_instance(inst: Instance, command_ids: list[str], n_passes: int = 2, slots_per_pass: int | None = 2) -> dict:
    """Cut a reduced instance. ``slots_per_pass`` tightens each pass to that many
    command frames (budget = (1 + slots) x 715 B incl. PASS_OPEN) so the budget
    constraint actually binds; None keeps the live budgets."""
    by = inst.by_id()
    cmds = [by[c] for c in command_ids]
    if slots_per_pass is None:
        passes = inst.passes[:n_passes]
    else:
        passes = [PassWindow(p.index, SLOT_BYTES * (1 + slots_per_pass), p.label) for p in inst.passes[:n_passes]]
    slots = {p.index: max(0, p.command_budget // SLOT_BYTES) for p in passes}
    chosen = set(command_ids)
    vars_ = [(c.id, p.index) for c in cmds for p in passes if p.index <= c.deadline_pass]
    deps = [(c.id, d) for c in cmds for d in c.depends_on if d in chosen]
    dropped_deps = [(c.id, d) for c in cmds for d in c.depends_on if d not in chosen]
    return {"commands": cmds, "passes": passes, "slots": slots, "vars": vars_, "deps": deps,
            "dropped_deps": dropped_deps}


def build_reduced_model(inst: Instance, red: dict):
    from qpiai_opt.opt_modeller import Binary, Model, quicksum

    x = {(cid, t): Binary(f"x_{cid}_p{t}") for cid, t in red["vars"]}
    by = inst.by_id()
    m = Model("q_uplink_reduced_schedule")
    m.maximize(quicksum(by[cid].priority * inst.weight(t) * v for (cid, t), v in x.items()))
    for c in red["commands"]:
        terms = [x[(c.id, p.index)] for p in red["passes"] if (c.id, p.index) in x]
        if len(terms) > 1:
            m.add_constraint(quicksum(terms) <= 1, label=f"once_{c.id}")
    for p in red["passes"]:
        terms = [v for (cid, t), v in x.items() if t == p.index]
        if len(terms) > red["slots"][p.index]:
            m.add_constraint(quicksum(terms) <= red["slots"][p.index], label=f"slots_p{p.index}")
    for cid, dep in red["deps"]:
        for p in red["passes"]:
            if (cid, p.index) not in x:
                continue
            prior = [x[(dep, q.index)] for q in red["passes"] if q.index <= p.index and (dep, q.index) in x]
            if prior:
                m.add_constraint(x[(cid, p.index)] - quicksum(prior) <= 0, label=f"dep_{dep}_before_{cid}_p{p.index}")
            else:
                m.add_constraint(x[(cid, p.index)] <= 0, label=f"dep_{dep}_unavailable_{cid}_p{p.index}")
    return m, x


def compile_qubo(inst: Instance, command_ids: list[str], n_passes: int = 2, slots_per_pass: int | None = 2) -> dict:
    from qpiai_opt.opt_solvers.qubo import QUBOProblem

    red = reduced_instance(inst, command_ids, n_passes, slots_per_pass)
    model, x = build_reduced_model(inst, red)
    qubo = QUBOProblem.from_model(model)
    names = list(model.qubo_variable_names)
    return {"red": red, "model": model, "x": x, "qubo": qubo, "qubits": len(names), "qubo_variables": names}


def reduced_brute_force(inst: Instance, red: dict) -> dict:
    by = inst.by_id()
    vars_ = red["vars"]
    best_val, best = -1.0, None
    for bits in itertools.product((0, 1), repeat=len(vars_)):
        a = dict(zip(vars_, bits))
        if _reduced_feasible(red, a):
            val = sum(by[c].priority * inst.weight(t) for (c, t), b in a.items() if b)
            if val > best_val + 1e-9:
                best_val, best = val, a
    return {"objective": round(best_val, 6), "assignment": {f"x_{c}_p{t}": b for (c, t), b in best.items()}}


def _reduced_feasible(red: dict, a: dict) -> bool:
    for c in red["commands"]:
        if sum(b for (cid, _), b in a.items() if cid == c.id) > 1:
            return False
    for p in red["passes"]:
        if sum(b for (_, t), b in a.items() if t == p.index) > red["slots"][p.index]:
            return False
    for cid, dep in red["deps"]:
        for (c2, t), b in a.items():
            if c2 == cid and b and not any(a.get((dep, q.index), 0) for q in red["passes"] if q.index <= t):
                return False
    return True


def _assignment_to_plan(red: dict, assignment: dict | None) -> dict:
    plan = {c.id: None for c in red["commands"]}
    if not assignment:
        return plan
    for (cid, t) in red["vars"]:
        if float(assignment.get(f"x_{cid}_p{t}", 0)) > 0.5:
            plan[cid] = t
    return plan


def _byte_check(inst: Instance, red: dict, plan: dict) -> dict:
    by = inst.by_id()
    used = {p.index: 715 for p in red["passes"]}
    for cid, t in plan.items():
        if t is not None:
            used[t] += by[cid].frame_bytes
    sub = Instance([by[c.id] for c in red["commands"]], [PassWindow(p.index, p.budget_bytes) for p in red["passes"]])
    from .feasibility import validate_plan

    # dependencies on commands outside the reduced set are ignored by design
    sub_cmds = []
    for c in sub.commands:
        cc = type(c).from_dict(c.to_dict())
        cc.depends_on = [d for d in c.depends_on if d in plan]
        sub_cmds.append(cc)
    return validate_plan(Instance(sub_cmds, sub.passes), plan)


DEFAULT_REDUCED = ["C01", "C02", "C05", "C11", "C06"]


def run_qaoa_experiment(
    inst: Instance,
    *,
    command_ids: list[str] | None = None,
    n_passes: int = 2,
    qcloud_api_key: str | None,
    opt_api_key: str | None,
    mode: str = "platform",
    device_name: str = "QpiAI-QSV-Simulator",
    reps: int = 1,
    max_iterations: int = 30,
    shots: int = 1024,
    seed: int = 7,
) -> dict:
    """Run QAOA (+ classical Opt and brute force) on the same reduced QUBO."""
    from qpiai_opt.opt_solvers import Client, solve
    from qpiai_opt.quantum import QAOA, QpiAIQuantumAuth, QuantumRun

    command_ids = command_ids or DEFAULT_REDUCED
    comp = compile_qubo(inst, command_ids, n_passes)
    red = comp["red"]
    record: dict = {
        "kind": "qaoa",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "reduced_instance": {
            "commands": [c.to_dict() for c in red["commands"]],
            "passes": [p.to_dict() for p in red["passes"]],
            "slots": red["slots"],
            "decision_variables": [f"x_{c}_p{t}" for c, t in red["vars"]],
            "dependencies_kept": red["deps"],
            "dependencies_dropped_outside_subset": red["dropped_deps"],
        },
        "qubits": comp["qubits"],
        "qubo_variables": comp["qubo_variables"],
        "qubo": comp["qubo"].model_dump(mode="json"),
        "mode": mode,
        "device_name": device_name if mode == "platform" else "QpiAI-QSV-Local (in-process, not a cloud run)",
        "parameters": {"reps": reps, "optimizer": "cobyla", "max_iterations": max_iterations, "shots": shots,
                       "seed": seed if mode == "local" else None},
    }
    bf = reduced_brute_force(inst, red)
    record["brute_force"] = bf

    # --- QAOA via qpiai-opt[quantum] ---
    if not qcloud_api_key:
        raise RuntimeError("QPIAI_QCLOUD_API_KEY is not set; QAOA was not run.")
    QpiAIQuantumAuth.login(api_key=qcloud_api_key)
    algorithm = QAOA(reps=reps, optimizer="cobyla", max_iterations=max_iterations)
    if mode == "platform":
        execution = QuantumRun(shots=shots, experiment_name="q-uplink-qaoa", device_name=device_name)
    else:
        execution = QuantumRun(shots=shots, seed=seed)
    t0 = time.perf_counter()
    qres = solve(comp["qubo"], mode=mode, algorithm=algorithm, execution=execution)
    qwall = time.perf_counter() - t0
    qraw = qres.model_dump(mode="json")
    qplan = _assignment_to_plan(red, qres.variable_assignment)
    record["qaoa"] = {
        "execution_mode": qraw.get("execution_mode"),
        "backend": (qraw.get("quantum") or {}).get("backend"),
        "job_ids": (qraw.get("quantum") or {}).get("job_ids", []),
        "objective": qraw.get("objective"),
        "variable_assignment": qraw.get("variable_assignment"),
        "plan": qplan,
        "byte_validation": _byte_check(inst, red, qplan),
        "wall_time_s": round(qwall, 3),
        "raw_result": qraw,
    }

    # --- classical QpiAI Opt on the same QUBO ---
    if opt_api_key:
        try:
            t0 = time.perf_counter()
            ores = solve(comp["qubo"], mode="local", client=Client(api_key=opt_api_key))
            oraw = ores.model_dump(mode="json")
            oplan = _assignment_to_plan(red, oraw.get("variable_assignment"))
            record["opt_classical"] = {
                "execution_mode": oraw.get("execution_mode"),
                "objective": oraw.get("objective"),
                "plan": oplan,
                "byte_validation": _byte_check(inst, red, oplan),
                "wall_time_s": round(time.perf_counter() - t0, 3),
                "raw_result": oraw,
            }
        except Exception as exc:
            record["opt_classical"] = {"error": f"{type(exc).__name__}: {exc}"}
    else:
        record["opt_classical"] = {"error": "QPIAI_OPT_API_KEY not set"}

    q_obj = record["qaoa"]["objective"]
    record["comparison"] = {
        "brute_force_optimum": bf["objective"],
        "qaoa_objective": q_obj,
        "opt_objective": record["opt_classical"].get("objective"),
        "qaoa_gap_to_optimum": None if q_obj is None else round(bf["objective"] - q_obj, 6),
        "qaoa_reached_optimum": q_obj is not None and abs(bf["objective"] - q_obj) < 1e-6,
        "note": "QAOA is not expected to beat classical solvers at this size; reported as an honest comparison.",
    }
    return record
