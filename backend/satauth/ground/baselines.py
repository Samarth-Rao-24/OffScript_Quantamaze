"""Classical comparison baselines (FR-19).

These exist only to evaluate the QpiAI Opt plan. They are never used to decide
what is signed or transmitted.
"""

from __future__ import annotations

import time

from .feasibility import Plan, objective
from .queue import Instance, pass_open_bytes

BRUTE_FORCE_NODE_CAP = 5_000_000


def greedy(inst: Instance) -> dict:
    """Highest priority first; earliest pass that fits budget, deadline and dependencies."""
    t0 = time.perf_counter()
    by = inst.by_id()
    used = {p.index: pass_open_bytes() for p in inst.passes}
    budget = {p.index: p.budget_bytes for p in inst.passes}
    plan: Plan = {c.id: None for c in inst.commands}
    # topological-aware: repeat until no change so dependants can follow their prerequisites
    order = sorted(inst.commands, key=lambda c: (-c.priority, c.deadline_pass, c.id))
    changed = True
    while changed:
        changed = False
        for c in order:
            if plan[c.id] is not None:
                continue
            if any(plan[d] is None for d in c.depends_on):
                continue
            earliest = max([plan[d] for d in c.depends_on], default=1)
            for t in range(earliest, min(c.deadline_pass, inst.T) + 1):
                if used[t] + by[c.id].frame_bytes <= budget[t]:
                    plan[c.id] = t
                    used[t] += by[c.id].frame_bytes
                    changed = True
                    break
    return {"method": "greedy", "plan": plan, "objective": objective(inst, plan),
            "runtime_s": round(time.perf_counter() - t0, 6)}


def brute_force(inst: Instance, node_cap: int = BRUTE_FORCE_NODE_CAP) -> dict:
    """Exhaustive enumeration of every assignment (each command: a pass or deferred),
    pruning only branches that are already infeasible. No objective bounding, so the
    result is the true optimum whenever the search completes."""
    t0 = time.perf_counter()
    cmds = sorted(inst.commands, key=lambda c: c.id)
    budget = {p.index: p.budget_bytes for p in inst.passes}
    used = {p.index: pass_open_bytes() for p in inst.passes}
    plan: Plan = {}
    best = {"obj": -1.0, "plan": None}
    nodes = 0
    aborted = False
    # dependency check needs prerequisites decided first: order topologically
    order: list = []
    seen: set[str] = set()
    by = inst.by_id()

    def topo(cid: str) -> None:
        if cid in seen:
            return
        for d in by[cid].depends_on:
            topo(d)
        seen.add(cid)
        order.append(by[cid])

    for c in cmds:
        topo(c.id)

    def rec(i: int, value: float) -> None:
        nonlocal nodes, aborted
        if aborted:
            return
        nodes += 1
        if nodes > node_cap:
            aborted = True
            return
        if i == len(order):
            if value > best["obj"] + 1e-9:
                best["obj"] = value
                best["plan"] = dict(plan)
            return
        c = order[i]
        # option: defer
        plan[c.id] = None
        rec(i + 1, value)
        dep_passes = [plan[d] for d in c.depends_on]
        if any(dp is None for dp in dep_passes):
            del plan[c.id]
            return
        earliest = max(dep_passes, default=1)
        for t in range(earliest, min(c.deadline_pass, inst.T) + 1):
            if used[t] + c.frame_bytes <= budget[t]:
                used[t] += c.frame_bytes
                plan[c.id] = t
                rec(i + 1, value + c.priority * inst.weight(t))
                used[t] -= c.frame_bytes
        del plan[c.id]

    rec(0, 0.0)
    n = len(cmds)
    return {
        "method": "brute_force",
        "plan": best["plan"] if not aborted else None,
        "objective": round(best["obj"], 6) if not aborted else None,
        "nodes_explored": nodes,
        "search_space": (inst.T + 1) ** n,
        "completed": not aborted,
        "note": None if not aborted else f"aborted after {node_cap:,} nodes; optimum not certified",
        "runtime_s": round(time.perf_counter() - t0, 6),
    }
