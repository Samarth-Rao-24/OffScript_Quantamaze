"""One command for the complete recorded submission run.

    F:\\OffScript\\.venv\\Scripts\\python.exe scripts\\final_run.py --fresh

Steps (QpiAI is used in every stage; nothing falls back to a non-QpiAI method).
Defaults follow the organisers' guidance: QpiAI local solver and simulator, no credits.
  1. key check (QpiAI Opt + QCloud login)
  2. QRNG pass-nonce circuits (default 4) on the QpiAI Quantum SDK simulator
     (--quantum cloud: QCloud jobs instead)
  3. QpiAI Opt schedule with the QpiAI Opt local solver (--opt-mode platform-qubo:
     cloud job first, local solver if it fails), validated and compared with baselines
  4. QAOA on the reduced schedule via qpiai-opt[quantum] (QpiAI simulator by default)
  5. resource benchmarks on this CPU
  2b. NASA: real ISS passes over Bengaluru (TLE API) + DONKI space weather -> pass budgets
  6. full mission run on the real satellite process: reset, passes 1..N with a
     missing-packet drill in pass N-1 (lost frame -> hold -> gap report -> re-sign ->
     QpiAI Opt re-plan of the remaining passes), nonce verification, QCloud re-fetch of
     each cloud QRNG job (if any), judge sample cases, all attacks
  7. evidence zip at F:\\OffScript\\q-uplink-evidence.zip and a summary

Every step's output and any error traceback go to evidence/final_run_log.txt.
A failed step is reported and the run continues with the steps that do not depend on it.
API keys are never printed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


class Tee:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(path, "a", encoding="utf-8")
        self.out = sys.stdout

    def write(self, s):
        self.out.write(s)
        self.f.write(s)
        self.f.flush()

    def flush(self):
        self.out.flush()
        self.f.flush()


RESULTS: list[dict] = []
# QpiAI account/organisation allocations the code cannot change (reported, not counted as failures)
ACCOUNT_LIMITS = ("does not have access to", "no active storage quota", "allocate quota",
                  "active subscription is required")


def step(name: str, fn, *args, **kwargs):
    print(f"\n=== {name} ===", flush=True)
    t0 = time.perf_counter()
    try:
        detail = fn(*args, **kwargs)
        RESULTS.append({"step": name, "status": "OK", "detail": detail, "s": round(time.perf_counter() - t0, 1)})
        print(f"[OK] {name}: {detail}", flush=True)
        return detail
    except Exception as exc:
        tb = traceback.format_exc()
        msg = f"{type(exc).__name__}: {exc}"
        account = any(p in str(exc) for p in ACCOUNT_LIMITS)
        status = "UNAVAILABLE" if account else "FAILED"
        RESULTS.append({"step": name, "status": status, "detail": msg, "s": round(time.perf_counter() - t0, 1)})
        if account:
            print(f"[UNAVAILABLE ON THIS ACCOUNT] {name}: {msg}", flush=True)
        else:
            print(f"[FAILED] {name}: {msg}\n{tb}", flush=True)
        return None


def main() -> int:
    from satauth.config import load_settings

    ap = argparse.ArgumentParser()
    ap.add_argument("--qrng-device", default="QpiAI-QSV-Simulator")
    ap.add_argument("--qrng-jobs", type=int, default=4)
    ap.add_argument("--qrng-shots", type=int, default=1024)
    ap.add_argument("--qaoa-device", default="QpiAI-QSV-Simulator")
    ap.add_argument("--qaoa-iterations", type=int, default=30)
    ap.add_argument("--opt-mode", default="local", choices=["local", "platform-qubo", "platform"],
                    help="local (default, organiser-recommended) = QpiAI Opt local solver authenticated with the Opt key")
    ap.add_argument("--skip-qaoa", action="store_true")
    ap.add_argument("--quantum", choices=["cloud", "local"], default="local",
                    help="local (default, organiser-recommended) = QpiAI Quantum SDK simulator authenticated with the "
                         "QCloud key, no credits, no cloud job IDs. cloud = QCloud jobs (needs a subscription).")
    ap.add_argument("--yes", action="store_true", help="skip the single cost confirmation")
    ap.add_argument("--no-nasa", action="store_true", help="keep the queue's current pass budgets (skip the NASA pull)")
    ap.add_argument("--no-drill", action="store_true", help="skip the missing-packet drill in the mission run")
    ap.add_argument("--fresh", action="store_true",
                    help="move the previous run's generated evidence into evidence/_previous_runs/<time>/ first "
                         "(nothing is deleted) so this run's evidence stands on its own")
    a = ap.parse_args()

    if a.quantum == "local":
        a.qrng_device = "QpiAI-QSV-Local"
    s = load_settings()
    if a.fresh:
        _archive_previous(s)
    log_path = Path(s.evidence_dir) / "final_run_log.txt"
    sys.stdout = Tee(log_path)
    started = datetime.now(timezone.utc).isoformat()
    print(f"\n\n######## final_run started {started} ########")
    print(f"settings: {json.dumps(s.public_status())}")

    qcloud_credits = a.qrng_jobs * (1 if "Simulator" in a.qrng_device or "Lite" in a.qrng_device else 0)
    qaoa_credits = 0 if (a.skip_qaoa or a.quantum == "local") else a.qaoa_iterations + 2
    if a.quantum == "local":
        print("\nQUANTUM MODE: LOCAL (organiser-recommended). QRNG and QAOA run in the QpiAI Quantum SDK simulator, "
              "authenticated with the QCloud key; no credits, no cloud job IDs. Records are labelled as "
              "'QpiAI local simulator (not a cloud run)'.")
    print(f"\nThis run submits: {a.qrng_jobs} QRNG job(s) on {a.qrng_device}"
          f"{f' (~{qcloud_credits} credits)' if qcloud_credits else (' (no credits)' if a.quantum == 'local' else ' (hardware: priced per shot)')}, "
          f"one QpiAI Opt {a.opt_mode} solve, "
          f"{'no QAOA' if a.skip_qaoa else ('QAOA on the local QpiAI simulator (no credits)' if a.quantum == 'local' else f'QAOA on {a.qaoa_device} (~{qaoa_credits} circuit jobs, ~{qaoa_credits} credits)')}.")
    free_run = a.quantum == "local" and a.opt_mode == "local"
    if free_run:
        print("Nothing in this run uses credits, so it starts without a confirmation.")
    if not (a.yes or free_run) and input("Type 'yes' to start: ").strip().lower() != "yes":
        print("Cancelled; nothing was submitted.")
        return 1

    # 1. keys -------------------------------------------------------------
    def keys():
        if not s.opt_api_key or not s.qcloud_api_key:
            raise RuntimeError("QPIAI_OPT_API_KEY and QPIAI_QCLOUD_API_KEY must both be set in F:\\OffScript\\.env")
        from qpiai_quantum import QpiAIQuantumAuth

        QpiAIQuantumAuth.login(api_key=s.qcloud_api_key)
        from qpiai_quantum.jobmanager.jobmanager import JobManager
        from satauth.ground.qrng import qcloud_experiment

        exp = qcloud_experiment()
        try:
            exp_id = JobManager().get_experiment_id_by_name(exp)
        except Exception as exc:
            if a.quantum == "local":  # the local simulator does not use QCloud experiments
                return f"both keys present; QCloud login accepted (experiment lookup skipped for local runs: {exc})"
            raise RuntimeError(
                f"QCloud experiment '{exp}' was not found on this account ({exc}). Create an experiment on "
                f"qcloud.qpiai.tech, then put its exact name in .env as QUPLINK_QCLOUD_EXPERIMENT=<name>.") from exc
        return f"both keys present; QCloud login accepted; experiment '{exp}' found (id {exp_id})"

    if step("1. Key check", keys) is None:
        print("Stopping: fix the keys first.")
        return finish(s, started)

    # 2. QRNG -------------------------------------------------------------
    from satauth.ground.qrng import QRNGPool

    pool = QRNGPool(s.data_dir, s.evidence_dir, api_key=s.qcloud_api_key, n_qubits=s.qrng_qubits,
                    shots=a.qrng_shots, default_device=a.qrng_device, allow_dev_nonce=False, allow_local_qrng=True)
    qrng_ok = 0
    for i in range(1, a.qrng_jobs + 1):
        rec = step(f"2.{i} QRNG job on {a.qrng_device}", lambda: _qrng(pool, a.qrng_device))
        if rec:
            qrng_ok += 1
        elif i == 1:
            print("First QRNG job failed; not retrying the remaining ones (see the error above).")
            break

    # 3. QpiAI Opt ----------------------------------------------------------
    from satauth.api.service import MissionControl

    mc = MissionControl(s)
    mc.qrng.allow_local_qrng = True
    mc.data.mkdir(parents=True, exist_ok=True)
    if not mc.queue_path.exists():
        from satauth.ground.queue import default_queue

        mc.save_queue({"commands": [c.to_dict() for c in default_queue()], "budgets": list(s.pass_budgets)})

    # 2b. NASA: real pass windows -> per-pass byte budgets ---------------------------
    if not a.no_nasa:
        def nasa():
            rec = mc.nasa_fetch()
            sw = rec["space_weather"]
            msg = (f"{rec['tle']['name']} TLE from {rec['tle']['source']} (epoch {rec['tle']['epoch_utc'][:16]}, "
                   f"{rec['tle_age_days']} d old); {rec['all_passes_found']} passes over "
                   f"{rec['ground_station']['name']} in 72 h; space weather x{sw['factor']} (max Kp {sw['kp_max_72h']}); "
                   f"budgets {rec['budgets']}")
            if rec.get("errors"):
                msg += f"; note: {rec['errors']}"
            if not rec["complete"]:
                raise RuntimeError(msg + " -- fewer than 4 usable passes, budgets NOT applied")
            mc.nasa_apply(rec["evidence_file"])
            return msg + " -> applied to the queue"

        if step("2b. NASA orbit + space weather -> pass budgets", nasa) is None:
            print("NASA data unavailable: the queue keeps its current budgets "
                  f"{(mc.get_queue() or {}).get('passes') and [p['budget_bytes'] for p in mc.get_queue()['passes']]}.")

    def opt(mode):
        res = mc.plan(mode)
        o, v, c = res["opt"], res["validation"], res["comparison"]
        if not v["feasible"]:
            raise RuntimeError(f"QpiAI Opt {mode} returned an infeasible plan ({len(v['violations'])} violations); "
                               f"recorded in evidence/{res['evidence_file']} but not used for signing")
        return (f"job_id={o.get('job_id')} mode={o['execution_mode']} objective={v['objective']} "
                f"optimum={c['brute_force_objective']} greedy={c['greedy_objective']} "
                f"sent={v['scheduled']}/{v['scheduled'] + v['deferred']}")

    label = "local solver, drives the uplink" if a.opt_mode == "local" else a.opt_mode
    plan_ok = step(f"3a. QpiAI Opt schedule ({label})", opt, a.opt_mode)
    plan_mode = a.opt_mode if plan_ok is not None else "local"
    if plan_ok is None and a.opt_mode != "local":
        print("Platform plan unavailable or infeasible: the QpiAI Opt LOCAL solver will produce the plan that drives "
              "the uplink. The platform attempt above stays in the log/evidence.")
        plan_ok = step("3b. QpiAI Opt schedule (local solver, drives the uplink)", opt, "local")

    # 4. QAOA ---------------------------------------------------------------
    if not a.skip_qaoa:
        def qaoa():
            from satauth.common.atomic import atomic_write_json
            from satauth.ground.qaoa_run import run_qaoa_experiment
            from satauth.ground.queue import Instance

            inst = Instance.from_dict(mc.get_queue())
            qmode = "local" if a.quantum == "local" else "platform"
            rec = run_qaoa_experiment(inst, qcloud_api_key=s.qcloud_api_key, opt_api_key=s.opt_api_key,
                                      mode=qmode, device_name=a.qaoa_device, reps=s.qaoa_reps,
                                      max_iterations=a.qaoa_iterations, shots=s.qaoa_shots)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            fname = f"qaoa_{stamp}_{qmode}.json"
            rec["evidence_file"] = f"qcloud_jobs/{fname}"
            atomic_write_json(Path(s.evidence_dir) / "qcloud_jobs" / fname, rec)
            c = rec["comparison"]
            where = (f"{len(rec['qaoa']['job_ids'])} QCloud jobs on {rec['qaoa']['backend']}" if qmode == "platform"
                     else f"QpiAI local simulator ({rec['qaoa']['backend']}, no cloud job IDs)")
            return (f"{rec['qubits']} qubits, {where}, "
                    f"QAOA={c['qaoa_objective']} classical Opt={c['opt_objective']} exact={c['brute_force_optimum']}")

        step("4. QAOA " + ("(local QpiAI simulator)" if a.quantum == "local" else "on QCloud"), qaoa)

    # 5. benchmarks ---------------------------------------------------------
    def bench():
        from satauth.bench import measure, scheme_compare
        from satauth.common.atomic import atomic_write_json

        m, sc = measure.run(flood_limit=s.flood_limit), scheme_compare.run()
        out = Path(s.evidence_dir) / "bench"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for name, res in (("measure", m), ("scheme_compare", sc)):
            atomic_write_json(out / f"{name}_{stamp}.json", res)
            atomic_write_json(out / f"latest_{name}.json", res)
        return (f"verify p50 {m['verify_crypto_only']['p50_us']} us, peak RAM {m['peak_ram_bytes']} B, "
                f"flood checks {m['flood_with_guard']['signature_verifications']}/500")

    step("5. Resource benchmarks", bench)

    # 6. mission run ----------------------------------------------------------
    def mission():
        from satauth.api.attacks import run_attack
        from satauth.api.judge import SAMPLE_CASES, run_cases
        from satauth.api.qrng_inspect import refetch, verify_nonce
        from satauth.common.atomic import read_json

        mc.start()
        try:
            mc.reset()  # clean audit log for the recorded run (old log archived, keys kept)
            out = {}
            plan = mc.current_plan()
            unused = pool.status()["unused_for_nonce"]
            if plan and plan.get("validation", {}).get("feasible") and unused:
                T = len(plan["instance"]["passes"])
                drill_t = T - 1 if (T >= 2 and not a.no_drill) else None
                for t in range(1, min(T, unused) + 1):
                    drop = None
                    if t == drill_t:
                        drop = _drill_target(mc.current_plan(), t)
                        if drop:
                            print(f"  missing-packet drill: the first transmission of {drop} in pass {t} is lost on the "
                                  "simulated link")
                    r = mc.run_pass(t, pace_ms=0, drop=[drop] if drop else None)
                    acc = sum(1 for f in r["frames"] if f["verdict"] == "ACCEPT")
                    src = r["nonce"].get("job_id") or r["nonce"].get("randomness_class")
                    tally = {}
                    for f in r["frames"]:
                        tally[f["verdict"]] = tally.get(f["verdict"], 0) + 1
                    out[f"pass {t}"] = (f"{acc} accepted ({', '.join(f'{k} {v}' for k, v in sorted(tally.items()))}), "
                                        f"nonce source: {src}")
                    print(f"  pass {t}: {out[f'pass {t}']}")
                    if drop:
                        alerts = [x for x in mc.alerts if x["kind"] in ("MISSING_PACKET", "DEPENDENCY_HOLD",
                                                                          "GAP_REPORTED", "RETRANSMIT_OK", "CARRIED_OVER")]
                        for x in alerts:
                            print(f"    alert {x['kind']}: {x['message']}")
                        gap = next((x for x in alerts if x["kind"] == "GAP_REPORTED"), None)
                        out["missing-packet drill"] = {
                            "dropped": drop, "pass": t,
                            "detected_no_ack": any(x["kind"] == "MISSING_PACKET" for x in alerts),
                            "satellite_gap_report_confirms": bool(gap and drop in gap.get("lost", [])),
                            "recovered_in_pass": any(x["kind"] == "RETRANSMIT_OK" and x.get("cmd_id") == drop for x in alerts),
                            "held": [x["cmd_id"] for x in alerts if x["kind"] == "DEPENDENCY_HOLD"],
                            "carried_over": [c["cmd_id"] for c in r["carried_over"]],
                        }
                        if r["carried_over"] and t < T:
                            new = mc.replan(t + 1, plan_mode)
                            moved = {c: new["opt"]["plan"][c] for c in new["replan"]["requeued"]}
                            out["missing-packet drill"]["replanned_with_qpiai_opt"] = {
                                "mode": new["opt"].get("execution_mode"), "moved": moved,
                                "missed": new["replan"]["missed_deadline"],
                                "blocked": new["replan"]["blocked_by_missed_dependency"]}
                            print(f"    QpiAI Opt re-plan from pass {t + 1}: {moved}")
                st = mc.state()
                chain = read_json(Path(s.data_dir) / "ground" / "nonce_chain.json", default={}) or {}
                v = verify_nonce(Path(s.evidence_dir) / "qcloud_jobs", st["onboard"]["pass_nonce"],
                                 onboard_nonce=st["onboard"]["pass_nonce"], chain=chain, log_rows=mc.log_tail(5000))
                out["nonce verified"] = v["verified"]
                print(f"  nonce verified: {v['verified']}")
            else:
                out["passes"] = "skipped: needs a feasible QpiAI Opt plan and unused QRNG records"
                print("  passes skipped: " + out["passes"])
            for e in pool.entries():
                if e.get("job_id"):
                    try:
                        rf = refetch(Path(s.evidence_dir) / "qcloud_jobs", e["file"], s.qcloud_api_key)
                        print(f"  QCloud re-fetch {e['job_id']}: status={rf['status'].get('status')} "
                              f"counts match={rf['counts_match_recorded']}")
                    except Exception as exc:
                        print(f"  QCloud re-fetch {e['job_id']} failed: {exc}")
            if mc.link.window_id:
                jr = run_cases(mc, {"cases": SAMPLE_CASES})
                out["judge sample"] = jr["totals"]
                print(f"  judge sample cases: {jr['totals']}")
                attacks = {}
                for k in ["valid", "tamper", "replay", "expired", "unauthorized", "forged", "crosspass", "wrongsat",
                          "overbudget", "flood"]:
                    try:
                        ar = run_attack(mc, k)
                        attacks[k] = ar["passed"]
                        print(f"  attack {k:<12} passed={ar['passed']} observed={ar['observed']}")
                    except Exception as exc:
                        attacks[k] = f"error: {exc}"
                        print(f"  attack {k:<12} error: {exc}")
                out["attacks passed"] = sum(1 for v in attacks.values() if v is True)
            else:
                out["attacks"] = "skipped: no contact window could be opened (no QRNG nonce available)"
            return out
        finally:
            mc.stop()

    step("6. Mission run on the satellite process", mission)

    # 7. evidence zip -----------------------------------------------------------
    def bundle():
        from satauth.api import main as api

        data = api.build_evidence_zip()
        dest = BACKEND.parent / "q-uplink-evidence.zip"
        dest.write_bytes(data)
        return f"{dest} ({len(data) // 1024} KB)"

    step("7. Evidence bundle", bundle)
    return finish(s, started)


def _drill_target(plan: dict, t: int) -> str | None:
    """Pick the command in pass t whose loss shows the most: one that another command in
    the same pass depends on, else the first command of the pass."""
    from satauth.ground.feasibility import order_within_pass
    from satauth.ground.queue import Instance

    inst = Instance.from_dict(plan["instance"])
    order = order_within_pass(inst, plan["opt"]["plan"], t)
    by = inst.by_id()
    for cid in order:
        if any(cid in by[o].depends_on for o in order):
            return cid
    return order[0] if order else None


def _archive_previous(s) -> None:
    import shutil

    ev, gd = Path(s.evidence_dir), Path(s.data_dir) / "ground"
    dest = ev / "_previous_runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    moves = [*(ev / "qcloud_jobs").glob("qrng_*.json"), *(ev / "qcloud_jobs").glob("qaoa_*.json"),
             *(ev / "qcloud_jobs").glob("refetch_*.json"), ev / "qcloud_jobs" / "nonce_derivations.jsonl",
             ev / "opt_jobs", ev / "judge_runs", ev / "bench", ev / "pass_runs.json", ev / "final_run_log.txt",
             ev / "final_run_summary.json", ev / "logs" / "alerts.jsonl", ev / "logs" / "ack_log.jsonl", gd / "qrng_pool.json", gd / "current_plan.json", gd / "pass_runs.json"]
    moved = 0
    for p in moves:
        if p.exists():
            target = dest / p.relative_to(ev if ev in p.parents else gd.parent)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(target))
            moved += 1
    print(f"--fresh: moved {moved} item(s) from the previous run to {dest} (nothing deleted)")


def _qrng(pool, device):
    rec = pool.fetch(device)
    return (f"job_id={rec['job_id']} status={rec['job_status']} credits_used={rec['credits_used']} "
            f"outcomes={rec['distinct_outcomes']}/{2 ** rec['n_qubits']} ({rec['randomness_class']})")


def finish(s, started) -> int:
    from satauth.common.atomic import atomic_write_json

    summary = {"started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(), "steps": RESULTS}
    atomic_write_json(Path(s.evidence_dir) / "final_run_summary.json", summary)
    print("\n######## SUMMARY ########")
    for r in RESULTS:
        print(f"{r['status']:<7} {r['step']}  ({r['s']} s)")
    failed = [r for r in RESULTS if r["status"] == "FAILED"]
    unavailable = [r for r in RESULTS if r["status"] == "UNAVAILABLE"]
    print(f"\n{sum(1 for r in RESULTS if r['status'] == 'OK')} OK, {len(failed)} failed, "
          f"{len(unavailable)} unavailable on this QpiAI account. Full log: evidence/final_run_log.txt")
    return 0 if not failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
