"""Inspect recorded QRNG jobs: circuit, histogram statistics, nonce re-derivation
and a read-only re-fetch from QCloud by job ID.

Nothing here executes a circuit. The re-fetch issues the SDK's job-status and
job-results GET requests for an existing job.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import atomic_write_json, read_json, read_jsonl
from ..ground.qrng import counts_digest, derive_nonce


def _qasm_for(rec: dict) -> str:
    if rec.get("qasm"):
        return rec["qasm"]
    # records written before the QASM was stored: rebuild the identical circuit text
    n = int(rec["n_qubits"])
    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', f"qreg q[{n}];", f"creg c[{n}];"]
    lines += [f"h q[{i}];" for i in range(n)]
    lines += [f"measure q[{i}] -> c[{i}];" for i in range(n)]
    return "\n".join(lines)


def job_stats(rec: dict) -> dict:
    """Descriptive statistics of the measured distribution (no claims of certified entropy)."""
    counts = {str(k): int(v) for k, v in rec["counts"].items()}
    n = int(rec["n_qubits"])
    shots = sum(counts.values())
    bins = 2 ** n
    expected = shots / bins
    chi2 = sum((counts.get(format(i, f"0{n}b"), 0) - expected) ** 2 / expected for i in range(bins))
    dof = bins - 1
    try:
        from scipy.stats import chi2 as _chi2

        p_value = float(_chi2.sf(chi2, dof))
    except Exception:  # pragma: no cover
        p_value = None
    probs = [c / shots for c in counts.values()]
    shannon = -sum(p * math.log2(p) for p in probs if p > 0)
    min_ent = -math.log2(max(probs)) if probs else 0.0
    ones = [0] * n
    for bits, c in counts.items():
        for i, ch in enumerate(bits):
            if ch == "1":
                ones[i] += c
    histogram = sorted(({"outcome": k, "value": int(k, 2), "count": v} for k, v in counts.items()),
                       key=lambda r: r["value"])
    return {
        "shots": shots,
        "outcomes_possible": bins,
        "outcomes_seen": len(counts),
        "expected_per_outcome": round(expected, 3),
        "chi_square": round(chi2, 2),
        "degrees_of_freedom": dof,
        "chi_square_p_value": None if p_value is None else round(p_value, 4),
        "empirical_shannon_bits": round(shannon, 3),
        "empirical_min_entropy_bits": round(min_ent, 3),
        "bit_one_frequency": [round(o / shots, 4) for o in ones],
        "bit_order_note": "bit positions are listed left to right as they appear in the returned bitstrings",
        "histogram": histogram,
        "interpretation": (
            "Chi-square tests the counts against a perfectly uniform distribution. A small p-value (< 0.01) "
            "means a detectable bias, which is expected on real hardware (gate and readout error). "
            "These are descriptive statistics, not certified min-entropy; every nonce is also mixed with "
            "32 bytes of OS randomness."
        ),
    }


def list_jobs(jobs_dir: Path, pool_entries: list[dict]) -> list[dict]:
    out = []
    used = {e["file"]: e for e in pool_entries}
    for p in sorted(Path(jobs_dir).glob("qrng_*.json")):
        rec = read_json(p) or {}
        e = used.get(p.name, {})
        out.append({"file": p.name, "job_id": rec.get("job_id"), "device": rec.get("device"),
                    "randomness_class": rec.get("randomness_class"), "shots": rec.get("shots"),
                    "n_qubits": rec.get("n_qubits"), "created_utc": rec.get("started_utc"),
                    "credits_used": rec.get("credits_used"), "nonce_used": e.get("nonce_used"),
                    "used_for_pass": e.get("used_for_pass")})
    return out


def job_detail(jobs_dir: Path, fname: str) -> dict:
    p = (Path(jobs_dir) / fname).resolve()
    if p.parent != Path(jobs_dir).resolve() or not p.name.startswith("qrng_") or not p.exists():
        raise FileNotFoundError(fname)
    rec = read_json(p)
    nonces = [n for n in read_jsonl(Path(jobs_dir) / "nonce_derivations.jsonl") if n.get("qrng_file") == fname]
    refetches = sorted(x.name for x in Path(jobs_dir).glob(f"refetch_{rec.get('job_id')}_*.json")) if rec.get("job_id") else []
    return {"file": fname, "record": rec, "qasm": _qasm_for(rec), "stats": job_stats(rec), "nonces": nonces,
            "refetches": refetches}


def verify_nonce(jobs_dir: Path, nonce_hex: str, *, onboard_nonce: str | None, chain: dict, log_rows: list[dict]) -> dict:
    """Recompute a pass nonce from its recorded inputs and check the satellite used it."""
    steps: list[dict] = []

    def step(label: str, ok: bool, detail: str) -> bool:
        steps.append({"label": label, "ok": bool(ok), "detail": detail})
        return ok

    rows = read_jsonl(Path(jobs_dir) / "nonce_derivations.jsonl")
    rec = next((r for r in reversed(rows) if r.get("nonce") == nonce_hex), None)
    if not step("Derivation record found", rec is not None,
                "nonce_derivations.jsonl entry for this nonce" if rec else "no recorded derivation for this nonce"):
        return {"verified": False, "steps": steps, "nonce": nonce_hex}
    os_e = bytes.fromhex(rec["os_entropy_hex"])
    pass_no = int(rec["pass"])
    if rec.get("job_id") is None and rec.get("randomness_class") == "development-only":
        recomputed = hashlib.sha256(b"Q-UPLINK/NONCE/DEV-OS-ONLY/v1" + os_e + pass_no.to_bytes(4, "big")).hexdigest()
        step("Source", True, "DEV nonce: OS randomness only, no QCloud job (development mode)")
        formula = "SHA-256('Q-UPLINK/NONCE/DEV-OS-ONLY/v1' || os_entropy || pass)"
    else:
        qfile = rec.get("qrng_file")
        qrec = read_json(Path(jobs_dir) / qfile) if qfile else None
        if not step("QRNG job record loaded", qrec is not None, f"{qfile} (" + (f"job {rec['job_id']}" if rec.get("job_id") else "local run, no job ID") + f", {rec.get('device')})"):
            return {"verified": False, "steps": steps, "nonce": nonce_hex}
        digest = counts_digest(qrec["counts"]).hex()
        step("Counts unchanged since the job", digest == rec.get("counts_sha256") == qrec.get("counts_sha256"),
             f"SHA-256(counts) = {digest[:16]}... matches the value logged when the nonce was made")
        recomputed = derive_nonce(os_e, qrec["counts"], rec.get("job_id") or "local", pass_no).hex()
        formula = "SHA-256('Q-UPLINK/NONCE/v1' || os_entropy(32 B) || SHA-256(counts) || job_id || pass)"
    step("Recomputed nonce matches", recomputed == nonce_hex, f"{recomputed[:16]}... vs recorded {nonce_hex[:16]}...")
    in_chain = any(h.get("nonce") == nonce_hex for h in chain.get("history", []))
    step("Installed by the ground after PASS_OPEN was accepted", in_chain,
         "present in the ground nonce chain" if in_chain else "PASS_OPEN carrying it was not accepted onboard")
    job = rec.get("job_id")
    accepted = [r for r in log_rows if r.get("verdict") == "ACCEPT" and r.get("opcode_name") == "PASS_OPEN"
                and (r.get("context") or {}).get("nonce_job_id") == job]
    if job:
        step("Satellite audit log shows PASS_OPEN accepted for this job", bool(accepted),
             f"log #{accepted[-1]['seq']}" if accepted else "no matching ACCEPT line in the current log")
    if onboard_nonce is not None:
        steps.append({"label": "Currently installed onboard", "ok": onboard_nonce == nonce_hex,
                      "detail": "this is the satellite's current pass nonce" if onboard_nonce == nonce_hex
                      else "an older pass nonce (a later PASS_OPEN replaced it)", "informational": True})
    verified = all(s["ok"] for s in steps if not s.get("informational"))
    return {"verified": verified, "steps": steps, "nonce": nonce_hex, "recomputed": recomputed, "formula": formula,
            "inputs": {"os_entropy_hex": rec["os_entropy_hex"], "job_id": job, "pass": pass_no,
                       "counts_sha256": rec.get("counts_sha256"), "qrng_file": rec.get("qrng_file")}}


def refetch(jobs_dir: Path, fname: str, api_key: str | None) -> dict:
    """Ask QCloud for an existing job by ID (status + stored results). Executes nothing."""
    rec = read_json(Path(jobs_dir) / fname)
    if not rec or not rec.get("job_id"):
        raise ValueError("this record has no QCloud job ID (local simulator run)")
    if not api_key:
        raise RuntimeError("QPIAI_QCLOUD_API_KEY is not set in .env")
    from qpiai_quantum import QpiAIQuantumAuth
    from qpiai_quantum.jobmanager.jobmanager import JobManager

    QpiAIQuantumAuth.login(api_key=api_key)
    jm = JobManager()
    status = jm.get_job_status(rec["job_id"])
    if not status:
        raise RuntimeError(f"QCloud has no job {rec['job_id']} for this account")
    remote_counts = None
    results_error = None
    try:
        res = jm.get_job_results(rec["job_id"], device_name=rec.get("device"))
        rc = getattr(res, "counts", None)
        if rc is None and isinstance(res, dict):
            rc = (res.get("results") or {}).get("counts")
        remote_counts = {str(k): int(v) for k, v in (rc or {}).items()} or None
    except Exception as exc:
        results_error = f"{type(exc).__name__}: {exc}"
    keep = ("id", "status", "credits_used", "execution_time_ms", "compute_resource_id", "created_at", "updated_at", "error")
    out = {
        "fetched_utc": datetime.now(timezone.utc).isoformat(),
        "job_id": rec["job_id"],
        "status": {k: status.get(k) for k in keep},
        "counts_match_recorded": None if remote_counts is None else remote_counts == rec["counts"],
        "remote_counts_sha256": None if remote_counts is None else counts_digest(remote_counts).hex(),
        "recorded_counts_sha256": rec.get("counts_sha256"),
        "results_error": results_error,
        "note": "Read-only GET requests for an existing job; no circuit was executed.",
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    atomic_write_json(Path(jobs_dir) / f"refetch_{rec['job_id']}_{stamp}.json", {**out, "raw_status": status})
    return out
