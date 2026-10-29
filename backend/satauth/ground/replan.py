"""Re-planning after missing packets.

When frames are lost and could not be recovered inside their pass, the commands
are carried over. Instead of squeezing them into later passes by hand, the
ground re-runs QpiAI Opt on what is left:

* every command not yet acknowledged by the spacecraft (including ones the
  original plan deferred) is re-queued;
* only the remaining passes are available, with their full budgets;
* deadlines are kept: a command whose deadline pass has already gone is
  reported as *missed*, and anything that depends on a missed command is
  *blocked* (it can never run safely);
* dependencies on commands that were already delivered are satisfied.

The sub-problem is solved on passes renumbered 1..k (the model requires that),
then mapped back onto the real pass numbers and merged with the delivery
history, and the merged plan is re-validated against the original instance
before anything is signed.
"""

from __future__ import annotations

from .feasibility import Plan
from .queue import Command, Instance, PassWindow


def delivered_from_runs(runs: list[dict]) -> dict[str, int]:
    """Command id -> pass in which the spacecraft acknowledged (accepted) it."""
    out: dict[str, int] = {}
    for run in runs:
        for f in run.get("frames", []):
            cid = f.get("cmd_id")
            if cid and f.get("verdict") == "ACCEPT" and cid not in out:
                out[cid] = int(run["pass"])
    return out


def build_subinstance(inst: Instance, delivered: dict[str, int], from_pass: int) -> dict:
    if not 1 <= from_pass <= inst.T:
        raise ValueError(f"from_pass must be 1..{inst.T}")
    remaining = [c for c in inst.commands if c.id not in delivered]
    missed = [c.id for c in remaining if c.deadline_pass < from_pass]
    # anything depending (transitively) on a missed command can never run safely
    blocked: set[str] = set()
    changed = True
    bad = set(missed)
    while changed:
        changed = False
        for c in remaining:
            if c.id in bad or c.id in blocked:
                continue
            if any(d in bad or d in blocked for d in c.depends_on):
                blocked.add(c.id)
                changed = True
    shift = from_pass - 1
    keep = [c for c in remaining if c.id not in bad and c.id not in blocked]
    keep_ids = {c.id for c in keep}
    sub_cmds = []
    for c in keep:
        cc = Command.from_dict(c.to_dict())
        cc.deadline_pass = c.deadline_pass - shift
        cc.depends_on = [d for d in c.depends_on if d in keep_ids]  # delivered deps are satisfied
        sub_cmds.append(cc)
    sub_passes = [PassWindow(p.index - shift, p.budget_bytes, p.label or f"Pass {p.index}")
                  for p in inst.passes if p.index >= from_pass]
    sub = Instance(sub_cmds, sub_passes)
    return {"sub": sub, "shift": shift, "missed": missed, "blocked": sorted(blocked),
            "remaining": [c.id for c in remaining]}


def merge_plan(inst: Instance, delivered: dict[str, int], sub_plan: Plan, shift: int) -> Plan:
    merged: Plan = {}
    for c in inst.commands:
        if c.id in delivered:
            merged[c.id] = delivered[c.id]
        elif c.id in sub_plan and sub_plan[c.id] is not None:
            merged[c.id] = int(sub_plan[c.id]) + shift
        else:
            merged[c.id] = None
    return merged
