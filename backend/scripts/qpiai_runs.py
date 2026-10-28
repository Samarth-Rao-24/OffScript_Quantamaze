"""Command-line QpiAI runs that record evidence (same code paths as the web app).

    python scripts/qpiai_runs.py check                      # free: verifies both keys, lists QCloud devices
    python scripts/qpiai_runs.py plan --mode local          # free: QpiAI Opt local solve (no job ID)
    python scripts/qpiai_runs.py plan --mode platform       # Opt platform job (job ID, may use credits)
    python scripts/qpiai_runs.py qrng --device QpiAI-Indus-1        # QCloud job (may use credits)
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


def cmd_qrng(s, device: str, yes: bool) -> int:
    from satauth.ground.qrng import QRNGPool

    if device != "QpiAI-QSV-Local":
        confirm(f"This runs a {s.qrng_qubits}-qubit, {s.qrng_shots}-shot circuit on {device} and may consume QCloud credits.", yes)
    pool = QRNGPool(s.data_dir, s.evidence_dir, api_key=s.qcloud_api_key, n_qubits=s.qrng_qubits, shots=s.qrng_shots,
                    default_device=s.qrng_device, allow_dev_nonce=s.allow_dev_nonce)
    rec = pool.fetch(device)
    print(f"QRNG job_id={rec['job_id']} device={rec['device']} class={rec['randomness_class']} "
          f"distinct outcomes={rec['distinct_outcomes']} credits_used={rec['credits_used']}")
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
    pp = sub.add_parser("plan")
    pp.add_argument("--mode", choices=["platform", "local"], default=s.opt_mode)
    pq = sub.add_parser("qrng")
    pq.add_argument("--device", default=s.qrng_device)
    pa = sub.add_parser("qaoa")
    pa.add_argument("--mode", choices=["platform", "local"], default=s.qaoa_mode)
    pa.add_argument("--device", default=s.qaoa_device)
    pa.add_argument("--iterations", type=int, default=s.qaoa_max_iterations)
    for sp in (pp, pq, pa):
        sp.add_argument("--yes", action="store_true", help="skip the credit confirmation prompt")
    a = p.parse_args()
    if a.cmd == "check":
        return cmd_check(s)
    if a.cmd == "plan":
        return cmd_plan(s, a.mode, a.yes)
    if a.cmd == "qrng":
        return cmd_qrng(s, a.device, a.yes)
    return cmd_qaoa(s, a.mode, a.device, a.iterations, a.yes)


if __name__ == "__main__":
    raise SystemExit(main())
