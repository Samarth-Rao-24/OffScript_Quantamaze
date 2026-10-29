"""Command-line QpiAI runs that record evidence (same code paths as the web app).

    python scripts/qpiai_runs.py check                      # free: verifies both keys, lists QCloud devices
    python scripts/qpiai_runs.py credits                    # free: Opt quota + QCloud cost estimates (nothing runs)
    python scripts/qpiai_runs.py plan --mode local          # free: QpiAI Opt local solve (no job ID)
    python scripts/qpiai_runs.py plan --mode platform       # Opt platform job (job ID, may use credits)
    python scripts/qpiai_runs.py qrng --device QpiAI-Indus-1 --shots 1024   # QCloud job: shows estimate, asks, then runs
    python scripts/qpiai_runs.py job <JOB_ID>                # free: re-fetch a job's status/credits from QCloud
    python scripts/qpiai_runs.py qaoa --mode platform --device QpiAI-QSV-Simulator   # ~30 QCloud jobs

Nothing here falls back silently: a failed call is reported and nothing is recorded.
Every credit-consuming command asks for confirmation unless --yes is given.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from satauth.common.atomic import atomic_write_json  # noqa: E402
from satauth.config import load_settings  # noqa: E402


def confirm(msg: str, yes: bool) -> None:
    if yes:
        return
    if input(f"{msg} Type 'yes' to continue: ").strip().lower() != "yes":
        print("Cancelled; nothing was submitted.")
        sys.exit(1)


def cmd_check(s) -> int:
    ok = True
    print("QPIAI_OPT_API_KEY:", "set" if s.opt_api_key else "MISSING")
    print("QPIAI_QCLOUD_API_KEY:", "set" if s.qcloud_api_key else "MISSING")
    if s.opt_api_key:
        try:
            from qpiai_opt.opt_modeller import Binary, Model
            from qpiai_opt.opt_solvers import Client, solve

            x, y = Binary("x"), Binary("y")
            m = Model("access_check")
            m.maximize(6 * x + 4 * y)
            m.add_constraint(x + y <= 1, label="capacity")
            r = solve(m, client=Client(api_key=s.opt_api_key))
            print(f"[PASS] QpiAI Opt local solve: {r.solution} objective {r.objective} ({r.execution_mode})")
        except Exception as exc:
            ok = False
            print(f"[FAIL] QpiAI Opt: {type(exc).__name__}: {exc}")
    if s.qcloud_api_key:
        try:
            from qpiai_quantum import QpiAIQuantumAuth

            QpiAIQuantumAuth.login(api_key=s.qcloud_api_key)
            res = QpiAIQuantumAuth.list_compute_resources(display=False)
            print("[PASS] QCloud login. Devices on this account:")
            for r in res or []:
                print(f"   {r.get('device_name')}  backend={r.get('backend_name')}  usage_rate={r.get('usage_rate')} credits")
            out = s.evidence_dir / "qcloud_jobs" / "compute_resources.json"
            atomic_write_json(out, {"checked_utc": datetime.now(timezone.utc).isoformat(), "resources": res})
        except Exception as exc:
            ok = False
            print(f"[FAIL] QCloud: {type(exc).__name__}: {exc}")
    return 0 if ok else 1


def _qrng_circuit(n: int):
    from qpiai_quantum import Circuit

    c = Circuit(n, n)
    for q in range(n):
        c.h(q)
    c.measure(list(range(n)), list(range(n)))
    return c


def _qaoa_circuit(s):
    """One QAOA circuit (initial angles) for the default reduced instance, as QCloud would receive it."""
    from satauth.api.service import MissionControl
    from satauth.ground.qaoa_run import DEFAULT_REDUCED, compile_qubo
    from satauth.ground.queue import Instance
    from qpiai_opt.quantum import QAOA, build_circuit

    inst = Instance.from_dict(MissionControl(s).get_queue())
    comp = compile_qubo(inst, DEFAULT_REDUCED)
    alg = QAOA(reps=s.qaoa_reps, initial_point=[0.3] * (2 * s.qaoa_reps))
    return build_circuit(comp["qubo"], algorithm=alg, measurements=True), comp["qubits"]


def _qcloud_resources(s) -> list:
    import requests
    from qpiai_quantum import QpiAIQuantumAuth
    from qpiai_quantum.config import get_api_url

    QpiAIQuantumAuth.login(api_key=s.qcloud_api_key)
    res = requests.get(get_api_url("/api/compute-resources"), headers={"X-Secret-Token": s.qcloud_api_key},
                       timeout=(10, 60))
    res.raise_for_status()
    return res.json()


def _estimate(s, resources: list, device: str, qasm: str, shots: int | None = None) -> dict:
    """QpiAI credit-estimator call (read-only; nothing is executed)."""
    import requests
    from qpiai_quantum.config import get_api_url

    match = [r for r in resources if r.get("status") == "active" and device in (r.get("device_name"), r.get("backend_name"))]
    if not match:
        return {"error": f"no active compute resource for {device}"}
    try:
        e = requests.post(get_api_url("/api/credit-estimator/estimate"), headers={"X-Secret-Token": s.qcloud_api_key},
                          json={"compute_resource_id": match[0]["ID"], "qasm": qasm,
                                **({"shots": int(shots)} if shots else {})}, timeout=(10, 60))
        body = e.json() if e.headers.get("content-type", "").startswith("application/json") else e.text[:300]
        return {"http_status": e.status_code, "response": body, "usage_rate": match[0].get("usage_rate")}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "usage_rate": match[0].get("usage_rate")}


def cmd_credits(s) -> int:
    """Read-only: remaining Opt credits and QCloud cost estimates. Executes no circuit or solve."""
    report: dict = {"checked_utc": datetime.now(timezone.utc).isoformat()}
    if s.opt_api_key:
        try:
            from qpiai_opt.opt_solvers import Client

            c = Client(api_key=s.opt_api_key)
            quotas = [q.model_dump(mode="json") if hasattr(q, "model_dump") else q for q in c.get_user_quotas()]
            usage = c.get_user_credit_usage()
            usage = usage.model_dump(mode="json") if hasattr(usage, "model_dump") else usage
            report["opt"] = {"quotas": quotas, "usage_monthly": usage}
            print("QpiAI Opt quotas:")
            print(json.dumps(quotas, indent=2, default=str))
        except Exception as exc:
            report["opt"] = {"error": f"{type(exc).__name__}: {exc}"}
            print(f"[INFO] Opt quota lookup failed: {type(exc).__name__}: {exc}")
    if s.qcloud_api_key:
        try:
            resources = _qcloud_resources(s)
        except Exception as exc:
            print(f"[FAIL] QCloud compute-resources lookup: {type(exc).__name__}: {exc}")
            resources = []
        report["qcloud_resources"] = resources
        print("\nQCloud compute resources (raw fields):")
        for r in resources:
            print("  " + json.dumps({k: v for k, v in r.items() if k not in ("address", "health_check", "run")}, default=str))
        qaoa_c, qubits = _qaoa_circuit(s)
        circuits = {f"qrng_{s.qrng_qubits}q": _qrng_circuit(s.qrng_qubits).to_qasm(), f"qaoa_{qubits}q_one_step": qaoa_c.to_qasm()}
        report["estimates"] = []
        print("\nQCloud credit estimates (no job is submitted):")
        for dev in (s.qrng_device, s.qaoa_device):
            for name, qasm in circuits.items():
                for shots in sorted({256, s.qrng_shots if name.startswith("qrng") else s.qaoa_shots}):
                    est = _estimate(s, resources, dev, qasm, shots)
                    report["estimates"].append({"device": dev, "circuit": name, "shots": shots, **est})
                    print(f"  {dev:<22} {name:<20} {shots:>5} shots  {json.dumps(est.get('response', est.get('error')), default=str)[:300]}")
    out = s.evidence_dir / "credit_check.json"
    atomic_write_json(out, report)
    print(f"\nSaved: {out}")
    return 0


def cmd_plan(s, mode: str, yes: bool) -> int:
    from satauth.api.service import MissionControl

    if mode == "platform":
        confirm("This submits a QpiAI Opt platform job and may consume Opt credits.", yes)
    mc = MissionControl(s)
    mc.data.mkdir(parents=True, exist_ok=True)
    res = mc.plan(mode)
    o, v = res["opt"], res["validation"]
    print(f"Opt {o['execution_mode']} solve: job_id={o.get('job_id')} problem_id={o.get('problem_id')} "
          f"objective={v['objective']} feasible={v['feasible']} sent={v['scheduled']}/{v['scheduled'] + v['deferred']}")
    print(f"Greedy {res['comparison']['greedy_objective']}, brute force {res['comparison']['brute_force_objective']}, "
          f"matches optimum: {res['comparison']['opt_matches_brute_force']}")
    print(f"Evidence: evidence/{res['evidence_file']}")
    return 0 if v["feasible"] else 2


def cmd_qrng(s, device: str, shots: int, yes: bool) -> int:
    from satauth.ground.qrng import QRNGPool

    if shots < 32:
        print("Refusing: use at least 32 shots (fewer gives too little entropy to be meaningful).")
        return 1
    if device != "QpiAI-QSV-Local":
        if not s.qcloud_api_key:
            print("QPIAI_QCLOUD_API_KEY is not set in .env")
            return 1
        print(f"Circuit: {s.qrng_qubits} qubits, H on each, measure all; {shots} shots on {device}.")
        try:
            resources = _qcloud_resources(s)
            est = _estimate(s, resources, device, _qrng_circuit(s.qrng_qubits).to_qasm(), shots)
            print(f"Device usage_rate: {est.get('usage_rate')} credits (unit not stated by the API)")
            print(f"QpiAI credit estimate: {json.dumps(est.get('response', est.get('error')), default=str)[:500]}")
        except Exception as exc:
            print(f"[INFO] Could not get an estimate ({type(exc).__name__}: {exc}); you can still cancel below.")
        confirm(f"Submit this job to {device}? It will consume QCloud credits.", yes)
    pool = QRNGPool(s.data_dir, s.evidence_dir, api_key=s.qcloud_api_key, n_qubits=s.qrng_qubits, shots=shots,
                    default_device=s.qrng_device, allow_dev_nonce=s.allow_dev_nonce)
    print("Submitted; waiting for QCloud (hardware jobs can queue for several minutes)...")
    rec = pool.fetch(device)
    print(f"[DONE] QRNG job_id={rec['job_id']} device={rec['device']} class={rec['randomness_class']}")
    print(f"       distinct outcomes={rec['distinct_outcomes']}/{2 ** rec['n_qubits']} status={rec['job_status']} "
          f"credits_used={rec['credits_used']} wall={rec['wall_time_s']} s")
    if rec["job_id"]:
        print(f"Verify any time (free): python scripts/qpiai_runs.py job {rec['job_id']}")
    if device == "QpiAI-QSV-Local":
        print("Local simulator run: recorded, but NOT used for pass nonces unless QUPLINK_ALLOW_DEV_NONCE=true.")
    else:
        print("The job is now in the app's QRNG pool and will supply the next pass nonce (one job per pass).")
    return 0


def cmd_job(s, job_id: str) -> int:
    """Re-fetch a job from QCloud by ID (status, credits used). Read-only."""
    from qpiai_quantum import Circuit, QpiAIQuantumAuth

    QpiAIQuantumAuth.login(api_key=s.qcloud_api_key)
    st = Circuit.get_job_status(job_id)
    if not st:
        print(f"QCloud has no job {job_id} for this account.")
        return 1
    keep = ("id", "status", "credits_used", "execution_time_ms", "compute_resource_id", "created_at", "updated_at", "error")
    print(json.dumps({k: st.get(k) for k in keep}, indent=2, default=str))
    out = s.evidence_dir / "qcloud_jobs" / f"jobstatus_{job_id}.json"
    atomic_write_json(out, {"fetched_utc": datetime.now(timezone.utc).isoformat(), "status": st})
    print(f"Saved: {out}")
    return 0


def cmd_qaoa(s, mode: str, device: str, iters: int, yes: bool) -> int:
    from satauth.ground.qaoa_run import run_qaoa_experiment
    from satauth.api.service import MissionControl
    from satauth.ground.queue import Instance

    if mode == "platform":
        confirm(f"This runs QAOA on {device}: about {iters + 2} QCloud circuit jobs, which may consume credits.", yes)
    mc = MissionControl(s)
    inst = Instance.from_dict(mc.get_queue())
    rec = run_qaoa_experiment(inst, qcloud_api_key=s.qcloud_api_key, opt_api_key=s.opt_api_key, mode=mode,
                              device_name=device, reps=s.qaoa_reps, max_iterations=iters, shots=s.qaoa_shots)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"qaoa_{stamp}_{mode}.json"
    rec["evidence_file"] = f"qcloud_jobs/{fname}"
    atomic_write_json(s.evidence_dir / "qcloud_jobs" / fname, rec)
    print(json.dumps({"qubits": rec["qubits"], "jobs": len(rec["qaoa"]["job_ids"]), "backend": rec["qaoa"]["backend"],
                      "comparison": rec["comparison"]}, indent=2))
    print(f"Evidence: evidence/{rec['evidence_file']}")
    return 0


def main() -> int:
    s = load_settings()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("credits")
    pp = sub.add_parser("plan")
    pp.add_argument("--mode", choices=["platform", "local"], default=s.opt_mode)
    pq = sub.add_parser("qrng")
    pq.add_argument("--device", default=s.qrng_device)
    pq.add_argument("--shots", type=int, default=s.qrng_shots)
    pj = sub.add_parser("job")
    pj.add_argument("job_id")
    pa = sub.add_parser("qaoa")
    pa.add_argument("--mode", choices=["platform", "local"], default=s.qaoa_mode)
    pa.add_argument("--device", default=s.qaoa_device)
    pa.add_argument("--iterations", type=int, default=s.qaoa_max_iterations)
    for sp in (pp, pq, pa):
        sp.add_argument("--yes", action="store_true", help="skip the credit confirmation prompt")
    a = p.parse_args()
    if a.cmd == "check":
        return cmd_check(s)
    if a.cmd == "credits":
        return cmd_credits(s)
    if a.cmd == "plan":
        return cmd_plan(s, a.mode, a.yes)
    if a.cmd == "qrng":
        return cmd_qrng(s, a.device, a.shots, a.yes)
    if a.cmd == "job":
        return cmd_job(s, a.job_id)
    return cmd_qaoa(s, a.mode, a.device, a.iterations, a.yes)


if __name__ == "__main__":
    raise SystemExit(main())
