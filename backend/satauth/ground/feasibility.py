"""Independent plan validator (FR-16).

Every plan, whichever solver produced it, must pass this check before a single
frame is signed. It re-derives everything from the instance and never trusts a
solver's own feasibility flag.
"""

from __future__ import annotations

from .queue import Instance, pass_open_bytes

Plan = dict[str, int | None]  # command id -> pass index (1..T) or None (deferred)


def objective(inst: Instance, plan: Plan) -> float:
    by = inst.by_id()
    return round(sum(by[c].priority * inst.weight(t) for c, t in plan.items() if t is not None), 6)


def validate_plan(inst: Instance, plan: Plan) -> dict:
    by = inst.by_id()
    violations: list[str] = []
    T = inst.T

    unknown = set(plan) - set(by)
    if unknown:
        violations.append(f"plan references unknown commands {sorted(unknown)}")
    missing = set(by) - set(plan)
    if missing:
        violations.append(f"plan omits commands {sorted(missing)} (each must be assigned or explicitly deferred)")

    used = {p.index: pass_open_bytes() for p in inst.passes}
    for cid, t in plan.items():
        if cid not in by:
            continue
        if t is None:
            continue
        if not isinstance(t, int) or not (1 <= t <= T):
            violations.append(f"{cid}: invalid pass {t!r}")
            continue
        c = by[cid]
        used[t] += c.frame_bytes
        if t > c.deadline_pass:
            violations.append(f"{cid}: scheduled in pass {t} after its deadline pass {c.deadline_pass}")
        for dep in c.depends_on:
            td = plan.get(dep)
            if td is None:
                violations.append(f"{cid}: depends on {dep}, which is not scheduled")
            elif td > t:
                violations.append(f"{cid}: scheduled in pass {t} before its dependency {dep} (pass {td})")

    budget_report = []
    for p in inst.passes:
        ok = used[p.index] <= p.budget_bytes
        budget_report.append(
            {"pass": p.index, "used_bytes": used[p.index], "budget_bytes": p.budget_bytes,
             "remaining_bytes": p.budget_bytes - used[p.index], "ok": ok}
        )
        if not ok:
            violations.append(f"pass {p.index}: {used[p.index]} B exceeds budget {p.budget_bytes} B")

    return {
        "feasible": not violations,
        "violations": violations,
        "objective": objective(inst, {k: v for k, v in plan.items() if k in by}),
        "scheduled": sum(1 for t in plan.values() if t is not None),
        "deferred": sum(1 for t in plan.values() if t is None),
        "budgets": budget_report,
        "deadline_misses": sum(1 for cid, t in plan.items() if cid in by and t is None),
    }


def order_within_pass(inst: Instance, plan: Plan, t: int) -> list[str]:
    """Transmission order inside a pass: dependencies first, then priority."""
    by = inst.by_id()
    ids = [cid for cid, pt in plan.items() if pt == t]
    remaining = sorted(ids, key=lambda c: (-by[c].priority, c))
    ordered: list[str] = []
    placed: set[str] = set()
    while remaining:
        for cid in remaining:
            deps_here = [d for d in by[cid].depends_on if plan.get(d) == t]
            if all(d in placed for d in deps_here):
                ordered.append(cid)
                placed.add(cid)
                remaining.remove(cid)
                break
        else:  # pragma: no cover - cycles are rejected by Instance.validate
            raise ValueError("cannot order pass: dependency cycle")
    return ordered


def explain(inst: Instance, plan: Plan) -> list[dict]:
    """The "Why?" panel: one human-readable reason per command."""
    by = inst.by_id()
    used = {p.index: pass_open_bytes() for p in inst.passes}
    for cid, t in plan.items():
        if t is not None:
            used[t] += by[cid].frame_bytes
    out = []
    for c in inst.commands:
        t = plan.get(c.id)
        if t is not None:
            same_pass_deps = [d for d in c.depends_on if plan.get(d) == t]
            reason = f"Sent in pass {t} (weight {inst.weight(t)}), deadline pass {c.deadline_pass}."
            if c.depends_on:
                reason += " After " + ", ".join(f"{d} (pass {plan.get(d)})" for d in c.depends_on) + "."
            if same_pass_deps:
                reason += " Ordered after its dependency within the pass."
            out.append({"id": c.id, "status": "SENT", "pass": t, "reason": reason})
            continue
        unmet = [d for d in c.depends_on if plan.get(d) is None]
        reachable = [p for p in inst.passes if p.index <= min(c.deadline_pass, inst.T)]
        fits = [p.index for p in reachable if used[p.index] + c.frame_bytes <= p.budget_bytes]
        if c.deadline_pass < 1 or not reachable:
            status, reason = "BLOCKED_DEADLINE", f"Deadline pass {c.deadline_pass} is outside the planning horizon."
        elif unmet:
            status, reason = "WAITING_DEPENDENCY", f"Waiting on {', '.join(unmet)}, which is not scheduled in this horizon."
        elif not fits:
            status = "DEFERRED_BUDGET"
            reason = (f"No pass up to its deadline (pass {c.deadline_pass}) has {c.frame_bytes} B left; "
                      f"higher-value commands used the budget.")
        else:
            status = "DEFERRED_TRADEOFF"
            reason = (f"Would fit in pass {fits[0]}, but adding it is not optimal or would break a dependency "
                      f"ordering; kept for a later horizon.")
        out.append({"id": c.id, "status": status, "pass": None, "reason": reason})
    return out
