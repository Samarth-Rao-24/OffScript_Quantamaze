"""Plain-text (Notepad-friendly) logs rendered from the JSON evidence.

    evidence/txt/qpiai_usage_log.txt   every QpiAI tool call: QpiAI Opt schedules and re-plans,
                                       QRNG circuits, QAOA runs, pass nonces derived from QRNG
                                       output, and every failed QpiAI call with QpiAI's own error
    evidence/txt/test_data_log.txt     every test the website runs: Attack lab, Judge console
                                       (compose, raw bytes, case files), plus the latest pytest
                                       run and final-run summary

The JSON files stay the source of truth; these files are re-rendered from them after every
event (and by ``scripts/export_txt_logs.py``), so they always match. Events that have no JSON
record of their own (attacks, single judge frames, failed QpiAI calls) are first appended to
``evidence/logs/qpiai_calls.jsonl`` / ``evidence/logs/test_runs.jsonl``.

Secrets never appear: only selected fields are written, and the value of every configured
secret (API keys, key passphrase) is scrubbed from any text, including QpiAI error messages.
Logging is best effort and never breaks the call that triggered it.

Standard library only, so the export script can run without the app's dependencies.
"""

from __future__ import annotations

import glob
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

QPIAI_TXT = "qpiai_usage_log.txt"
TESTS_TXT = "test_data_log.txt"
QPIAI_EVENTS = "logs/qpiai_calls.jsonl"
TEST_EVENTS = "logs/test_runs.jsonl"
SECRET_ENV = ("QPIAI_OPT_API_KEY", "QPIAI_QCLOUD_API_KEY", "QCLOUD_API_KEY", "NASA_API_KEY", "QUPLINK_KEY_PASSPHRASE")
RULE = "=" * 92
SUB = "-" * 92
_lock = threading.Lock()


# ------------------------------------------------------------------ helpers
def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scrub(text) -> str:
    s = str(text)
    for name in SECRET_ENV:
        v = os.environ.get(name)
        if v and len(v) >= 6:
            s = s.replace(v, "[redacted]")
    return s


def _when(ts) -> str:
    if not ts:
        return "time unknown"
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return str(ts)


def _sort_key(e: dict) -> str:
    try:
        return datetime.fromisoformat(str(e.get("time")).replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except ValueError:
        return str(e.get("time") or "")


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _jsonl(path) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def _g(d, *path, default=None):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def _fmt_plan(plan: dict | None, passes: int) -> list[str]:
    if not isinstance(plan, dict):
        return []
    rows = []
    for t in range(1, passes + 1):
        ids = sorted(c for c, p in plan.items() if p == t)
        rows.append(f"pass {t}: {', '.join(ids) if ids else '(nothing)'}")
    held = sorted(c for c, p in plan.items() if p is None)
    if held:
        rows.append(f"not sent: {', '.join(held)}")
    return rows


def _block(time, title, status, fields: list[tuple[str, object]]) -> str:
    lines = [f"[{_when(time)}]  {title}  |  {status}"]
    for k, v in fields:
        if v is None or v == "":
            continue
        if isinstance(v, list):
            if not v:
                continue
            lines.append(f"  {k:<20}: {_scrub(v[0])}")
            lines += [f"  {'':<20}  {_scrub(x)}" for x in v[1:]]
        else:
            lines.append(f"  {k:<20}: {_scrub(v)}")
    return "\n".join(lines)


def _rel(ev: Path, p) -> str:
    try:
        return Path(p).resolve().relative_to(ev.resolve()).as_posix()
    except ValueError:
        return str(p)


# ------------------------------------------------------------------ live hooks
def record_event(ev_dir, stream: str, entry: dict) -> None:
    """Append an event that has no JSON record of its own, then re-render the text logs."""
    try:
        ev = Path(ev_dir)
        rel = QPIAI_EVENTS if stream == "qpiai" else TEST_EVENTS
        p = ev / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        entry = {"time": entry.get("time") or _utc(), **entry}
        if "error" in entry:
            entry["error"] = _scrub(entry["error"])[:2000]
        with _lock, open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception:  # pragma: no cover - logging must never break the caller
        return
    refresh(ev_dir)


def refresh(ev_dir) -> dict:
    """Re-render both text logs from the evidence folder. Never raises."""
    try:
        ev = Path(ev_dir)
        out = ev / "txt"
        out.mkdir(parents=True, exist_ok=True)
        q_text, q_n = render_qpiai(ev)
        t_text, t_n = render_tests(ev)
        with _lock:
            for name, text in ((QPIAI_TXT, q_text), (TESTS_TXT, t_text)):
                tmp = out / (name + ".tmp")
                with open(tmp, "w", encoding="utf-8") as f:  # text mode: CRLF on Windows, so Notepad is happy
                    f.write(text)
                os.replace(tmp, out / name)
        return {"qpiai_entries": q_n, "test_entries": t_n, "files": [f"txt/{QPIAI_TXT}", f"txt/{TESTS_TXT}"]}
    except Exception as exc:  # pragma: no cover
        return {"error": str(exc)}


# ------------------------------------------------------------------ QpiAI usage log
def _opt_entry(ev: Path, path) -> dict | None:
    r = _load(path)
    if not isinstance(r, dict) or not isinstance(r.get("opt"), dict):
        return None
    o, raw = r["opt"], r["opt"].get("raw_result") or {}
    si = raw.get("solve_info") or {}
    passes = len(_g(r, "instance", "passes", default=[]) or [])
    budgets = [p.get("budget_bytes") for p in _g(r, "instance", "passes", default=[]) or []]
    cmp_ = r.get("comparison") or {}
    plan = o.get("plan") or {}
    sent = sum(1 for v in plan.values() if v is not None)
    replan = r.get("replan")
    title = "QpiAI Opt  |  re-plan after a missing packet (MILP)" if replan else "QpiAI Opt  |  multi-pass uplink schedule (MILP)"
    model = o.get("model") or {}
    fields = [
        ("Product / SDK", "QpiAI Opt (qpiai-opt), called with the team API key"),
        ("Mode", f"requested {o.get('requested_mode', '?')}, executed {o.get('execution_mode', '?')}"),
        ("Solver", f"{si.get('solver', o.get('solver', '?'))} via {si.get('provider', '?')}; "
                   f"status {o.get('status', '?')}; optimality proven: {si.get('optimality_proven', '?')}; "
                   f"gap {raw.get('optimality_gap', '?')}"),
        ("Job ID", o.get("job_id") or "none (local solver: no cloud job is created)"),
        ("Problem", f"{o.get('problem_class', model.get('problem_class', 'MILP'))}, "
                    f"{model.get('binary_variables', '?')} binary variables, {model.get('constraints', '?')} constraints"),
        ("Input", f"{len(_g(r, 'instance', 'commands', default=[]) or [])} commands, {passes} passes, budgets {budgets} B"),
        ("Objective", f"{o.get('reported_objective', cmp_.get('opt_objective'))} delivered priority"),
        ("Commands sent", f"{sent}/{len(plan)}" if plan else None),
        ("Baselines", f"greedy {cmp_.get('greedy_objective')}, brute force {cmp_.get('brute_force_objective')}, "
                      f"Opt matches brute force: {cmp_.get('opt_matches_brute_force')}" if cmp_.get("greedy_objective") is not None else None),
        ("Plan re-check", "feasible, approved for signing" if _g(r, "validation", "feasible") else "NOT feasible, not signed"),
        ("Time", f"wall {o.get('wall_time_s', '?')} s, solver {raw.get('solver_time_s', raw.get('compute_time_s', '?'))} s"),
        ("Re-plan", f"from pass {replan.get('from_pass')}, re-queued {', '.join(replan.get('requeued') or []) or 'none'}" if isinstance(replan, dict) else None),
        ("Plan", _fmt_plan(plan, passes)),
        ("Evidence file", _rel(ev, path)),
    ]
    return {"time": o.get("started_utc") or r.get("created_utc"), "tool": "opt",
            "text": _block(o.get("started_utc") or r.get("created_utc"), title, "OK", fields)}


def _qrng_entry(ev: Path, path) -> dict | None:
    r = _load(path)
    if not isinstance(r, dict) or r.get("kind") != "qrng":
        return None
    sdk = r.get("sdk") or {}
    fields = [
        ("Product / SDK", f"QpiAI Quantum SDK (qpiai-quantum {sdk.get('qpiai-quantum', '?')})"),
        ("Device", r.get("device")),
        ("Randomness class", r.get("randomness_class")),
        ("Job ID", r.get("job_id") or "none (local simulator: no cloud job is created)"),
        ("Circuit", f"{r.get('circuit', '?')}, {r.get('shots', '?')} shots"),
        ("Output", f"{r.get('distinct_outcomes', '?')} distinct outcomes of {2 ** int(r.get('n_qubits') or 8)}; "
                   f"counts SHA-256 {str(r.get('counts_sha256', ''))[:32]}..."),
        ("Status", f"{r.get('job_status', '?')}, credits used {r.get('credits_used', '?')}, wall {r.get('wall_time_s', '?')} s"),
        ("Used for", "pass nonce + attack fuzz seed (mixed with OS entropy)"),
        ("Evidence file", _rel(ev, path)),
    ]
    return {"time": r.get("started_utc"), "tool": "qrng",
            "text": _block(r.get("started_utc"), "QpiAI Quantum SDK  |  QRNG circuit", "OK", fields)}


def _qaoa_entry(ev: Path, path) -> dict | None:
    r = _load(path)
    if not isinstance(r, dict) or r.get("kind") != "qaoa":
        return None
    q, c, par = r.get("qaoa") or {}, r.get("comparison") or {}, r.get("parameters") or {}
    oc = r.get("opt_classical") or {}
    jobs = q.get("job_ids") or []
    fields = [
        ("Product / SDK", "QpiAI Opt QUBO modeller + QpiAI Quantum SDK QAOA (qpiai-opt[quantum])"),
        ("Mode / device", f"{r.get('mode', '?')} / {r.get('device_name', q.get('backend', '?'))}"),
        ("Job IDs", ", ".join(map(str, jobs)) if jobs else "none (local simulator: no cloud job is created)"),
        ("Problem", f"reduced schedule as a QUBO, {r.get('qubits', '?')} qubits "
                    f"({len(_g(r, 'reduced_instance', 'commands', default=[]) or [])} commands, "
                    f"{len(_g(r, 'reduced_instance', 'passes', default=[]) or [])} passes)"),
        ("Parameters", f"reps {par.get('reps')}, optimizer {par.get('optimizer')}, max iterations "
                       f"{par.get('max_iterations')}, shots {par.get('shots')}, seed {par.get('seed')}"),
        ("Result", f"QAOA {c.get('qaoa_objective')}, classical Opt {c.get('opt_objective')}, exact optimum "
                   f"{c.get('brute_force_optimum')}; reached optimum: {c.get('qaoa_reached_optimum')}"),
        ("Time", f"QAOA {q.get('wall_time_s', '?')} s, classical Opt {oc.get('wall_time_s', '?')} s"),
        ("Evidence file", _rel(ev, path)),
    ]
    return {"time": r.get("created_utc"), "tool": "qaoa",
            "text": _block(r.get("created_utc"), "QpiAI  |  QAOA experiment", "OK", fields)}


def _nonce_entry(rec: dict) -> dict:
    fields = [
        ("From QRNG run", rec.get("qrng_file") or "none"),
        ("Device / job", f"{rec.get('device') or 'none'} / {rec.get('job_id') or 'no cloud job'}"),
        ("Derivation", rec.get("source")),
        ("Nonce", f"{str(rec.get('nonce', ''))[:16]}... (installed onboard via signed PASS_OPEN)"),
    ]
    return {"time": rec.get("time_utc"), "tool": "nonce",
            "text": _block(rec.get("time_utc"), "QRNG output used  |  " + (f"pass {rec['pass']} nonce" if rec.get("pass") is not None
                                                                         else "ad-hoc contact window nonce"), "OK", fields)}


def _failed_entry(rec: dict) -> dict:
    tool = rec.get("tool", "?")
    title = {"opt": "QpiAI Opt", "qrng": "QpiAI Quantum SDK  |  QRNG circuit", "qaoa": "QpiAI  |  QAOA experiment"}.get(tool, tool)
    fields = [("Requested", rec.get("requested")), ("QpiAI said", rec.get("error")),
              ("Effect", "nothing was signed or recorded as a result; the previous result stays in use")]
    return {"time": rec.get("time"), "tool": tool + "_failed", "text": _block(rec.get("time"), title, "FAILED", fields)}


def render_qpiai(ev: Path) -> tuple[str, int]:
    ev = Path(ev)
    entries = []
    for p in sorted(glob.glob(str(ev / "opt_jobs" / "opt_*.json"))):
        e = _opt_entry(ev, p)
        if e:
            entries.append(e)
    for p in sorted(glob.glob(str(ev / "qcloud_jobs" / "qrng_*.json"))):
        e = _qrng_entry(ev, p)
        if e:
            entries.append(e)
    for p in sorted(glob.glob(str(ev / "qcloud_jobs" / "qaoa_*.json"))):
        e = _qaoa_entry(ev, p)
        if e:
            entries.append(e)
    for rec in _jsonl(ev / "qcloud_jobs" / "nonce_derivations.jsonl"):
        if rec.get("qrng_file"):
            entries.append(_nonce_entry(rec))
    for rec in _jsonl(ev / QPIAI_EVENTS):
        if rec.get("status") == "failed":
            entries.append(_failed_entry(rec))
    entries.sort(key=_sort_key)
    count = {}
    for e in entries:
        count[e["tool"]] = count.get(e["tool"], 0) + 1
    res = _load(ev / "qcloud_jobs" / "compute_resources.json") or {}
    devices = ", ".join(sorted({str(x.get("device_name")) for x in res.get("resources", []) if x.get("device_name")}))
    head = [
        RULE,
        "QpiAI USAGE LOG  -  Q-Uplink Mission Control (team OffScript, Quant-A-Maze 3.0, PQC-03)",
        RULE,
        f"Generated     : {_when(_utc())}",
        "What this is  : a plain-text copy of every QpiAI tool call recorded in evidence/. The JSON file",
        "                named on each entry is the full record (inputs, raw solver output, counts).",
        "Execution path: QpiAI Opt local solver and QpiAI-QSV-Local simulator, authenticated with the team",
        "                API key, as the organisers advised (no credits, so no cloud job IDs). Simulator",
        "                randomness is classical PRNG sampling and is labelled as such.",
        f"Totals        : QpiAI Opt runs {count.get('opt', 0)}, QRNG circuits {count.get('qrng', 0)}, "
        f"QAOA runs {count.get('qaoa', 0)}, pass nonces from QRNG {count.get('nonce', 0)},",
        f"                failed QpiAI calls {sum(v for k, v in count.items() if k.endswith('_failed'))}",
        f"QCloud devices the platform lists: {devices or 'not checked'} (cloud runs need a QpiAI subscription)",
        "No API keys, passphrases or private keys appear in this file.",
        RULE,
        "",
    ]
    body = "\n\n".join(e["text"] for e in entries) or "(no QpiAI calls recorded yet)"
    return "\n".join(head) + "\n" + body + "\n", len(entries)


# ------------------------------------------------------------------ test data log
def _attack_entry(rec: dict) -> dict:
    fields = [
        ("What it sends", rec.get("description")),
        ("Expected", rec.get("expected")),
        ("Observed", ", ".join(rec.get("observed") or []) or "-"),
        ("Counter", f"{rec.get('counter_before')} -> {rec.get('counter_after')} ({rec.get('counter_check')})"),
        ("Cost onboard", f"{rec.get('sig_verifications_spent')} signature checks, {rec.get('nv_writes_delta')} NV writes, "
                         f"{rec.get('frame_count')} frame(s), {rec.get('elapsed_ms')} ms"),
        ("Window", rec.get("window")),
        ("Attack inputs from", rec.get("fuzz_source")),
    ]
    return {"time": rec.get("time"), "kind": "attack",
            "text": _block(rec.get("time"), f"Attack lab  |  {rec.get('title', rec.get('attack'))}",
                           "PASSED" if rec.get("passed") else "FAILED", fields)}


def _judge_single_entry(rec: dict) -> dict:
    b, d = rec.get("built") or {}, rec.get("decoded") or {}
    fields = [
        ("Built with", f"{b.get('key')}, {b.get('opcode_name')}, counter {b.get('counter')} ({b.get('counter_source')}), "
                       f"sat_id {b.get('sat_id')}, signed under {b.get('signed_under')}" if b else "raw bytes supplied by the judge"),
        ("Mutations", ", ".join(b.get("mutations") or []) or None),
        ("Frame", f"{rec.get('frame_len')} B, header key_id {d.get('key_id')}, counter {d.get('counter')}, "
                  f"opcode {d.get('opcode_name')}, args {d.get('args_hex') or '-'}"),
        ("Satellite said", f"{rec.get('verdict')} {rec.get('reason')}"),
        ("Counter", f"{rec.get('counter_before')} -> {rec.get('counter_after')}"),
        ("Frame hex (start)", (rec.get("frame_hex") or "")[:64] + "..."),
    ]
    return {"time": rec.get("time"), "kind": "judge",
            "text": _block(rec.get("time"), f"Judge console  |  {'Compose a frame' if rec.get('kind') == 'compose' else 'Raw bytes'}",
                           rec.get("verdict") or "?", fields)}


def _judge_run_entry(ev: Path, path) -> dict | None:
    r = _load(path)
    if not isinstance(r, dict) or r.get("kind") != "judge_cases":
        return None
    t = r.get("totals") or {}
    lines = [f"[{_when(r.get('created_utc'))}]  Judge console  |  case file, {t.get('cases')} case(s)  |  "
             f"{t.get('passed')}/{t.get('cases')} matched, {t.get('false_accepts')} false accepts",
             f"  {'Totals':<20}: passed {t.get('passed')}, failed {t.get('failed')}, false accepts {t.get('false_accepts')}, "
             f"false rejects {t.get('false_rejects')}, other reason {t.get('wrong_reason')}, case errors {t.get('errors')}",
             f"  {'Evidence file':<20}: {_rel(ev, path)}",
             f"  {'id':<6} {'expect':<16} {'got':<22} {'counter':<12} {'outcome':<26} description"]
    for c in r.get("results") or []:
        got = f"{c.get('verdict') or '-'} {c.get('reason') or ''}".strip()
        ctr = f"{c.get('counter_before')}->{c.get('counter_after')}" if c.get("counter_before") is not None else "-"
        out = c.get("outcome") or ""
        if c.get("error"):
            out += f" ({_scrub(c['error'])[:80]})"
        lines.append(f"  {str(c.get('id'))[:6]:<6} {str(c.get('expect'))[:16]:<16} {got[:22]:<22} {ctr:<12} {out[:60]:<26} "
                     f"{_scrub(c.get('description') or '')[:70]}")
    return {"time": r.get("created_utc"), "kind": "judge", "text": "\n".join(lines)}


def _pytest_block(ev: Path) -> str | None:
    s = _load(ev / "tests" / "summary.json")
    if not isinstance(s, dict):
        return None
    c = s.get("counts") or {}
    lines = [f"[{_when(s.get('finished_utc'))}]  Automated tests (pytest)  |  "
             + ", ".join(f"{v} {k}" for k, v in c.items()),
             f"  {'Platform':<20}: Python {s.get('python')} on {s.get('platform')}",
             "  Evidence file       : tests/summary.json"]
    for t in s.get("results") or []:
        lines.append(f"  {str(t.get('outcome', '?')).upper():<8} {t.get('test')}  ({t.get('duration_s')} s)")
    return "\n".join(lines)


def _final_run_block(ev: Path) -> str | None:
    s = _load(ev / "final_run_summary.json")
    if not isinstance(s, dict):
        return None
    lines = [f"[{_when(s.get('finished_utc'))}]  Final end-to-end run (scripts/final_run.py)",
             "  Evidence file       : final_run_summary.json, final_run_log.txt"]
    for st in s.get("steps") or []:
        d = st.get("detail")
        if isinstance(d, dict):
            d = "; ".join(f"{k}: {json.dumps(v, default=str)[:90]}" for k, v in d.items())
        lines.append(f"  {str(st.get('status')):<6} {st.get('step')}  ({st.get('s')} s)")
        lines.append(f"         {_scrub(d)[:400]}")
    return "\n".join(lines)


def render_tests(ev: Path) -> tuple[str, int]:
    ev = Path(ev)
    entries = []
    for rec in _jsonl(ev / TEST_EVENTS):
        if rec.get("kind") == "attack":
            entries.append(_attack_entry(rec))
        elif rec.get("kind") in ("compose", "raw"):
            entries.append(_judge_single_entry(rec))
    for p in sorted(glob.glob(str(ev / "judge_runs" / "judge_*.json"))):
        e = _judge_run_entry(ev, p)
        if e:
            entries.append(e)
    entries.sort(key=_sort_key)
    n_att = sum(1 for e in entries if e["kind"] == "attack")
    passed_att = sum(1 for e in entries if e["kind"] == "attack" and "|  PASSED" in e["text"].splitlines()[0])
    head = [
        RULE,
        "TEST DATA LOG  -  Q-Uplink Mission Control (team OffScript, Quant-A-Maze 3.0, PQC-03)",
        RULE,
        f"Generated     : {_when(_utc())}",
        "What this is  : every test the website ran against the real onboard verifier (Attack lab and",
        "                Judge console), the latest automated test run and the final end-to-end run.",
        "                Full records: evidence/logs/test_runs.jsonl, evidence/judge_runs/*.json.",
        f"Totals        : attack runs {n_att} ({passed_att} passed), judge entries "
        f"{sum(1 for e in entries if e['kind'] == 'judge')}",
        "No API keys, passphrases or private keys appear in this file.",
        RULE,
        "",
    ]
    parts = []
    for blk in (_pytest_block(ev), _final_run_block(ev)):
        if blk:
            parts.append(blk)
    if parts:
        parts = [SUB + "\nBASELINE RUNS\n" + SUB] + parts + [SUB + "\nWEBSITE TEST RUNS (oldest first)\n" + SUB]
    body = "\n\n".join(parts + [e["text"] for e in entries]) or "(no tests recorded yet)"
    if not entries:
        body += "\n\n(no Attack lab or Judge console runs recorded yet)"
    return "\n".join(head) + "\n" + body + "\n", len(entries)
