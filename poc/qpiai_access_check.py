import json
import os
import platform
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE = Path(__file__).parent / "evidence"
EVIDENCE.mkdir(exist_ok=True)


def record(name, fn):
    entry = {"check": name, "started_utc": datetime.now(timezone.utc).isoformat()}
    t0 = time.perf_counter()
    try:
        entry["output"] = fn()
        entry["status"] = "PASS"
    except Exception as e:
        entry["status"] = "FAIL"
        entry["error_type"] = type(e).__name__
        entry["error"] = str(e)
        entry["traceback"] = traceback.format_exc()
    entry["elapsed_s"] = round(time.perf_counter() - t0, 3)
    print(f"[{entry['status']}] {name} ({entry['elapsed_s']}s)" + (f" -> {entry.get('error_type')}: {entry.get('error')}" if entry["status"] == "FAIL" else ""))
    return entry


def opt_local_solve():
    from qpiai_opt.opt_modeller import Binary, Model
    from qpiai_opt.opt_solvers import Client, solve
    key = os.environ.get("QPIAI_OPT_API_KEY")
    if not key:
        raise RuntimeError("QPIAI_OPT_API_KEY not set")
    x, y = Binary("x"), Binary("y")
    m = Model("access_check")
    m.maximize(6 * x + 4 * y)
    m.add_constraint(x + y <= 1, label="capacity")
    r = solve(m, client=Client(api_key=key))
    info = r.info()
    return {"problem_class": r.problem_class, "execution_mode": r.execution_mode, "solution": r.solution,
            "objective": r.objective, "method": str(info.method), "termination": str(info.termination),
            "guarantee": str(info.guarantee), "result": r.model_dump(mode="json")}


def qcloud_login():
    from qpiai_quantum import QpiAIQuantumAuth
    key = os.environ.get("QCLOUD_API_KEY")
    if not key:
        raise RuntimeError("QCLOUD_API_KEY not set")
    QpiAIQuantumAuth.login(api_key=key)
    return {"verified": QpiAIQuantumAuth.verify_api_key(),
            "compute_resources": QpiAIQuantumAuth.list_compute_resources(display=False)}


def bell(device):
    def run():
        from qpiai_quantum import Circuit
        c = Circuit(2, 2)
        c.h(0)
        c.cx(0, 1)
        c.measure([0, 1], [0, 1])
        r = c.run(shots=1000, experiment_name="offscript_access_check", device_name=device)
        return {"device": device, "shots": 1000, "counts": r.get_counts()}
    return run


def main():
    results = {"python": sys.version, "platform": platform.platform(), "checks": []}
    results["checks"].append(record("opt_local_solve", opt_local_solve))
    login = record("qcloud_login", qcloud_login)
    results["checks"].append(login)
    if login["status"] == "PASS":
        results["checks"].append(record("bell_local_sim", bell("QpiAI-QSV-Local")))
        results["checks"].append(record("bell_cloud_sim", bell("QpiAI-QSV-Simulator")))
    out = EVIDENCE / f"access_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"Evidence written to {out}")


if __name__ == "__main__":
    main()
