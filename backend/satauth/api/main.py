"""Q-Uplink Mission Control API (PRD 12.2).

Run:  uvicorn satauth.api.main:app --host 127.0.0.1 --port 8000   (from backend/)

Binds to localhost by default. The browser never receives private keys or API
secrets; only public metadata and "key configured: yes/no" flags.
"""

from __future__ import annotations

import asyncio
import io
import json
import zipfile
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..common import txtlog
from ..common.atomic import atomic_write_json, read_json, read_jsonl
from ..config import PROJECT_ROOT, load_settings
from .attacks import ATTACKS, run_attack
from .service import MissionControl, ServiceError


class Broadcaster:
    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()
        self.recent: deque = deque(maxlen=300)
        self.loop: asyncio.AbstractEventLoop | None = None

    def emit(self, event: dict) -> None:
        """Thread-safe: called from worker threads."""
        event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
        self.recent.append(event)
        if self.loop is None:
            return
        for q in list(self.clients):
            self.loop.call_soon_threadsafe(q.put_nowait, event)


bus = Broadcaster()
settings = load_settings()
mc = MissionControl(settings, emit=bus.emit)
_jobs: dict[str, bool] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    bus.loop = asyncio.get_running_loop()
    await asyncio.to_thread(mc.start)
    yield
    await asyncio.to_thread(mc.stop)


app = FastAPI(title="Q-Uplink Mission Control", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ServiceError)
async def _service_error(_, exc: ServiceError):
    return JSONResponse(status_code=exc.status, content={"error": str(exc)})


async def _exclusive(name: str, fn, *args, **kwargs):
    """Long-running external jobs (Opt, QCloud, benchmarks): one at a time per kind."""
    if _jobs.get(name):
        raise HTTPException(409, f"{name} already running")
    _jobs[name] = True
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    finally:
        _jobs[name] = False


# ---------------------------------------------------------------- health / config
@app.get("/api/health")
async def health():
    alive = mc.sat.alive() if mc.sat else False
    return {"ok": alive, "satellite_process": alive, "config": settings.public_status(), "running_jobs":
            [k for k, v in _jobs.items() if v]}


@app.get("/api/config")
async def config():
    return {"config": settings.public_status(), "host": MissionControl.host_info(),
            "attacks": {k: {"title": v[0], "description": v[1], "expected": v[2]} for k, v in ATTACKS.items()}}


# ---------------------------------------------------------------- queue / plan
@app.get("/api/queue")
async def get_queue():
    return mc.get_queue()


@app.put("/api/queue")
async def put_queue(payload: dict = Body(...)):
    try:
        return await asyncio.to_thread(mc.save_queue, payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/queue/reset")
async def reset_queue():
    from ..ground.queue import default_queue

    return mc.save_queue({"commands": [c.to_dict() for c in default_queue()], "budgets": list(settings.pass_budgets)})


@app.post("/api/plan")
async def plan(payload: dict = Body(default={})):
    mode = payload.get("mode") or settings.opt_mode
    if mode not in ("platform", "platform-qubo", "local"):
        raise HTTPException(400, "mode must be platform, platform-qubo or local")
    return await _exclusive("opt", mc.plan, mode)


@app.get("/api/plan")
async def get_plan():
    return mc.current_plan() or {}


@app.get("/api/baselines")
async def baselines():
    return await _exclusive("baselines", mc.baselines_only)


# ---------------------------------------------------------------- QCloud
@app.get("/api/qrng")
async def qrng_status():
    return mc.qrng.status()


@app.post("/api/qrng/fetch")
async def qrng_fetch(payload: dict = Body(default={})):
    device = payload.get("device") or settings.qrng_device
    try:
        rec = await _exclusive("qrng", mc.qrng.fetch, device)
    except HTTPException:
        raise
    except Exception as exc:
        bus.emit({"type": "qrng", "phase": "failed", "device": device, "error": str(exc)})
        await asyncio.to_thread(txtlog.record_event, settings.evidence_dir, "qpiai",
                                {"tool": "qrng", "status": "failed", "requested": f"QRNG circuit on {device}",
                                 "error": f"{type(exc).__name__}: {exc}"})
        raise HTTPException(502, f"QCloud QRNG job failed: {type(exc).__name__}: {exc}") from exc
    bus.emit({"type": "qrng", "phase": "done", "job_id": rec["job_id"], "device": rec["device"],
              "randomness_class": rec["randomness_class"]})
    await asyncio.to_thread(txtlog.refresh, settings.evidence_dir)
    return rec


@app.post("/api/qaoa/run")
async def qaoa_run(payload: dict = Body(default={})):
    from ..ground.qaoa_run import run_qaoa_experiment
    from ..ground.queue import Instance

    q = mc.get_queue()
    inst = Instance.from_dict(q)
    mode = payload.get("mode") or settings.qaoa_mode
    kwargs = dict(
        command_ids=payload.get("command_ids"), qcloud_api_key=settings.qcloud_api_key,
        opt_api_key=settings.opt_api_key, mode=mode, device_name=payload.get("device") or settings.qaoa_device,
        reps=int(payload.get("reps") or settings.qaoa_reps),
        max_iterations=int(payload.get("max_iterations") or settings.qaoa_max_iterations),
        shots=int(payload.get("shots") or settings.qaoa_shots),
    )
    bus.emit({"type": "qaoa", "phase": "started", "mode": mode, "device": kwargs["device_name"]})
    try:
        rec = await _exclusive("qaoa", run_qaoa_experiment, inst, **kwargs)
    except HTTPException:
        raise
    except Exception as exc:
        bus.emit({"type": "qaoa", "phase": "failed", "error": str(exc)})
        await asyncio.to_thread(txtlog.record_event, settings.evidence_dir, "qpiai",
                                {"tool": "qaoa", "status": "failed", "error": f"{type(exc).__name__}: {exc}",
                                 "requested": f"QAOA, mode {mode}, device {kwargs['device_name']}"})
        raise HTTPException(502, f"QAOA run failed: {type(exc).__name__}: {exc}") from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"qaoa_{stamp}_{mode}.json"
    rec["evidence_file"] = f"qcloud_jobs/{fname}"
    atomic_write_json(settings.evidence_dir / "qcloud_jobs" / fname, rec)
    await asyncio.to_thread(txtlog.refresh, settings.evidence_dir)
    bus.emit({"type": "qaoa", "phase": "done", "jobs": len(rec["qaoa"]["job_ids"]), "comparison": rec["comparison"]})
    return rec


@app.get("/api/qaoa")
async def qaoa_latest():
    files = sorted((settings.evidence_dir / "qcloud_jobs").glob("qaoa_*.json"))
    return read_json(files[-1]) if files else {}


@app.get("/api/qrng/jobs")
async def qrng_jobs():
    from .qrng_inspect import list_jobs

    return {"jobs": list_jobs(settings.evidence_dir / "qcloud_jobs", mc.qrng.entries())}


@app.get("/api/qrng/job/{fname}")
async def qrng_job(fname: str):
    from .qrng_inspect import job_detail

    try:
        return await asyncio.to_thread(job_detail, settings.evidence_dir / "qcloud_jobs", fname)
    except FileNotFoundError:
        raise HTTPException(404, "no such QRNG job record")


@app.post("/api/qrng/job/{fname}/refetch")
async def qrng_refetch(fname: str):
    """Read-only: ask QCloud for this job again by ID (status + stored results)."""
    from .qrng_inspect import refetch

    try:
        return await _exclusive("refetch", refetch, settings.evidence_dir / "qcloud_jobs", fname, settings.qcloud_api_key)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"QCloud re-fetch failed: {type(exc).__name__}: {exc}") from exc


@app.post("/api/nonce/verify")
async def nonce_verify(payload: dict = Body(default={})):
    from .qrng_inspect import verify_nonce

    st = await asyncio.to_thread(mc.state)
    nonce = (payload.get("nonce") or st["onboard"]["pass_nonce"]).lower()
    chain = read_json(settings.data_dir / "ground" / "nonce_chain.json", default={}) or {}
    return await asyncio.to_thread(verify_nonce, settings.evidence_dir / "qcloud_jobs", nonce,
                                   onboard_nonce=st["onboard"]["pass_nonce"], chain=chain, log_rows=mc.log_tail(5000))


# ---------------------------------------------------------------- judge console
@app.post("/api/judge/compose")
async def judge_compose(payload: dict = Body(...)):
    from .judge import compose_and_send

    return await asyncio.to_thread(compose_and_send, mc, payload)


@app.post("/api/judge/raw")
async def judge_raw(payload: dict = Body(...)):
    from .judge import send_raw

    return await asyncio.to_thread(send_raw, mc, payload.get("hex", ""))


@app.get("/api/judge/last")
async def judge_last():
    from .judge import last_frame

    return last_frame(mc)


@app.post("/api/judge/cases")
async def judge_cases(payload: dict = Body(...)):
    from .judge import run_cases

    return await _exclusive("judge", run_cases, mc, payload)


@app.get("/api/judge/sample")
async def judge_sample():
    from .judge import CSV_FIELDS, SAMPLE_CASES, sample_csv

    return {"cases": SAMPLE_CASES, "csv": sample_csv(), "csv_columns": CSV_FIELDS}


# ---------------------------------------------------------------- uplink
@app.post("/api/pass/open")
async def pass_open(payload: dict = Body(default={})):
    return await asyncio.to_thread(mc.open_window, payload.get("pass"), payload.get("budget"),
                                   int(payload.get("pace_ms", 0)))


@app.post("/api/pass/{t}/run")
async def pass_run(t: int, payload: dict = Body(default={})):
    drop = payload.get("drop") or []
    if isinstance(drop, str):
        drop = [d.strip() for d in drop.split(",") if d.strip()]
    try:
        rate = float(payload.get("loss_rate") or 0.0)
    except (TypeError, ValueError):
        raise HTTPException(400, "loss_rate must be a number")
    if not 0.0 <= rate <= 0.5:
        raise HTTPException(400, "loss_rate must be between 0 and 0.5")
    seed = payload.get("seed")
    return await _exclusive("pass", mc.run_pass, t, int(payload.get("pace_ms", 300)), drop=list(drop),
                            loss_rate=rate, seed=int(seed) if seed not in (None, "") else None)


@app.get("/api/nasa")
async def nasa_latest():
    s = settings.public_status()
    return {"latest": await asyncio.to_thread(mc.nasa_latest),
            "config": {k: s[k] for k in ("nasa_key_configured", "norad_id", "ground_station", "uplink_bps",
                                         "min_elevation_deg")}}


@app.post("/api/nasa/fetch")
async def nasa_fetch(payload: dict = Body(default={})):
    def num(k, cast):
        v = payload.get(k)
        if v in (None, ""):
            return None
        try:
            return cast(v)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{k} must be a number")
    norad, bps, el = num("norad", int), num("uplink_bps", float), num("min_elevation_deg", float)
    if bps is not None and not 8 <= bps <= 100000:
        raise HTTPException(400, "uplink_bps must be 8..100000")
    if el is not None and not 0 <= el <= 60:
        raise HTTPException(400, "min_elevation_deg must be 0..60")
    return await _exclusive("nasa", mc.nasa_fetch, norad=norad, uplink_bps=bps, min_el=el)


@app.post("/api/nasa/apply")
async def nasa_apply(payload: dict = Body(default={})):
    return await asyncio.to_thread(mc.nasa_apply, payload.get("evidence_file"))


@app.get("/api/keys")
async def keys():
    """Key ring: onboard and ground state per key, suites, sizes (public data only)."""
    return await asyncio.to_thread(mc.key_status)


@app.post("/api/keys/rotate")
async def keys_rotate(payload: dict = Body(...)):
    role = payload.get("role")
    if role not in ("OPERATOR", "ADMIN"):
        raise HTTPException(400, "role must be OPERATOR or ADMIN")
    try:
        kid = int(payload.get("to_kid"))
    except (TypeError, ValueError):
        raise HTTPException(400, "to_kid must be a key id")
    return await _exclusive("keys", mc.rotate_key, role, kid, int(payload.get("pace_ms", 0)))


@app.get("/api/delivery")
async def delivery():
    """Missing-packet view: acknowledged commands, carried-over commands, alerts, ACK ledger."""
    return await asyncio.to_thread(mc.delivery_status)


@app.post("/api/replan")
async def replan(payload: dict = Body(default={})):
    mode = payload.get("mode") or settings.opt_mode
    if mode not in ("platform", "platform-qubo", "local"):
        raise HTTPException(400, "mode must be platform, platform-qubo or local")
    fp = payload.get("from_pass")
    return await _exclusive("opt", mc.replan, int(fp) if fp else None, mode)


@app.post("/api/frame/send")
async def frame_send(payload: dict = Body(...)):
    return await asyncio.to_thread(mc.send_manual, role=payload["role"], opcode=int(payload["opcode"]),
                                   args_hex=payload.get("args_hex", ""), pace_ms=int(payload.get("pace_ms", 0)))


@app.post("/api/attack/{kind}")
async def attack(kind: str):
    return await _exclusive("attack", run_attack, mc, kind)


@app.get("/api/state")
async def state():
    return await asyncio.to_thread(mc.state)


@app.post("/api/satellite/reboot")
async def reboot():
    return await asyncio.to_thread(mc.reboot_satellite)


@app.post("/api/reset")
async def reset():
    return await asyncio.to_thread(mc.reset)


# ---------------------------------------------------------------- logs / metrics / evidence
@app.get("/api/log")
async def log(limit: int = Query(500, le=5000), verdict: str | None = None, reason: str | None = None):
    rows = mc.log_tail(limit)
    if verdict:
        rows = [r for r in rows if r.get("verdict") == verdict]
    if reason:
        rows = [r for r in rows if r.get("reason") == reason]
    return {"rows": rows, "file": "logs/onboard_log.jsonl"}


@app.get("/api/metrics")
async def metrics():
    b = settings.evidence_dir / "bench"
    st = await asyncio.to_thread(mc.state)
    runs = read_json(settings.data_dir / "ground" / "pass_runs.json", default={"runs": []}) or {"runs": []}
    return {
        "measure": read_json(b / "latest_measure.json", default=None),
        "schemes": read_json(b / "latest_scheme_compare.json", default=None),
        "live": {"onboard": st["onboard"]["stats"], "nv_writes": st["onboard"]["nv_writes"], "link": st["link"],
                 "link_history": mc.link.history[-10:]},
        "pass_runs": [{"pass": r["pass"], "window": r["window"], "bytes": r["link"]["used_bytes"],
                       "budget": r["link"]["budget_bytes"], "frames": r["link"]["frames_sent"]} for r in runs["runs"]],
        "label": "Emulated host measurements (not flight hardware)",
    }


@app.post("/api/bench/run")
async def bench_run():
    def _run():
        from ..bench import measure, scheme_compare

        m = measure.run(flood_limit=settings.flood_limit)
        s = scheme_compare.run()
        out = settings.evidence_dir / "bench"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for name, res in (("measure", m), ("scheme_compare", s)):
            atomic_write_json(out / f"{name}_{stamp}.json", res)
            atomic_write_json(out / f"latest_{name}.json", res)
        return {"measure": m, "schemes": s}

    return await _exclusive("bench", _run)


def _job_index() -> dict:
    ev = settings.evidence_dir
    opt = []
    for p in sorted((ev / "opt_jobs").glob("*.json")):
        d = read_json(p) or {}
        o = d.get("opt", {})
        opt.append({"file": f"opt_jobs/{p.name}", "job_id": o.get("job_id"), "problem_id": o.get("problem_id"),
                    "execution_mode": o.get("execution_mode"), "created_utc": d.get("created_utc"),
                    "objective": (d.get("validation") or {}).get("objective"),
                    "feasible": (d.get("validation") or {}).get("feasible"),
                    "wall_time_s": o.get("wall_time_s")})
    qc = []
    for p in sorted((ev / "qcloud_jobs").glob("qrng_*.json")):
        d = read_json(p) or {}
        qc.append({"file": f"qcloud_jobs/{p.name}", "kind": "qrng", "job_ids": [d.get("job_id")], "device": d.get("device"),
                   "randomness_class": d.get("randomness_class"), "created_utc": d.get("started_utc"),
                   "shots": d.get("shots"), "credits_used": d.get("credits_used")})
    for p in sorted((ev / "qcloud_jobs").glob("qaoa_*.json")):
        d = read_json(p) or {}
        q = d.get("qaoa", {})
        qc.append({"file": f"qcloud_jobs/{p.name}", "kind": "qaoa", "job_ids": q.get("job_ids", []),
                   "device": q.get("backend") or d.get("device_name"), "execution_mode": q.get("execution_mode"),
                   "created_utc": d.get("created_utc"), "qubits": d.get("qubits"), "comparison": d.get("comparison")})
    nasa = []
    for p in sorted((ev / "nasa").glob("nasa_*.json")):
        d = read_json(p) or {}
        nasa.append({"file": f"nasa/{p.name}", "created_utc": d.get("created_utc"), "spacecraft": (d.get("tle") or {}).get("name"),
                     "tle_source": (d.get("tle") or {}).get("source"), "tle_epoch_utc": (d.get("tle") or {}).get("epoch_utc"),
                     "budgets": d.get("budgets"), "space_weather_factor": (d.get("space_weather") or {}).get("factor"),
                     "kp_max_72h": (d.get("space_weather") or {}).get("kp_max_72h")})
    judge = []
    for p in sorted((ev / "judge_runs").glob("judge_*.json")):
        d = read_json(p) or {}
        judge.append({"file": f"judge_runs/{p.name}", "created_utc": d.get("created_utc"), "totals": d.get("totals")})
    return {"opt_jobs": opt, "qcloud_jobs": qc, "judge_runs": judge, "nasa_pulls": nasa,
            "alerts": read_jsonl(ev / "logs" / "alerts.jsonl", limit=300)[::-1],
            "nonce_derivations": read_jsonl(ev / "qcloud_jobs" / "nonce_derivations.jsonl", limit=100),
            "tests": read_json(ev / "tests" / "summary.json", default=None)}


@app.get("/api/evidence")
async def evidence():
    idx = await asyncio.to_thread(_job_index)
    return {**idx, "manifest": await asyncio.to_thread(mc.evidence_manifest),
            "reproduce": {
                "tests": "cd backend && python -m pytest -q",
                "benchmarks": "cd backend && python -m satauth.bench.measure && python -m satauth.bench.scheme_compare",
                "full": "scripts/run_all.ps1 (Windows) or scripts/run_all.sh",
            }}


@app.get("/api/evidence/file")
async def evidence_file(path: str):
    base = settings.evidence_dir.resolve()
    target = (base / path).resolve()
    if base not in target.parents or not target.is_file():
        raise HTTPException(404, "not found")
    if target.suffix == ".jsonl":
        return {"path": path, "rows": read_jsonl(target, limit=2000)}
    if target.suffix == ".json":
        return {"path": path, "content": read_json(target)}
    if target.suffix in (".xml", ".txt", ".md"):
        return {"path": path, "text": target.read_text(encoding="utf-8")[:500_000]}
    raise HTTPException(415, "unsupported file type")


def build_evidence_zip() -> bytes:
    buf = io.BytesIO()
    ev = settings.evidence_dir
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ev.rglob("*")):
            if p.is_file() and not p.name.endswith((".sk", ".env")):
                z.write(p, f"evidence/{p.relative_to(ev).as_posix()}")
        gd = settings.data_dir / "ground"
        for name in ("current_plan.json", "nonce_chain.json", "pass_runs.json", "queue.json"):
            if (gd / name).exists():
                z.write(gd / name, f"ground/{name}")
        kd = gd / "keys"
        for p in sorted(kd.glob("*.pk")) + [kd / "keys_meta.json"]:
            if p.exists():
                z.write(p, f"ground/public_keys/{p.name}")  # public keys only, never *.sk
        z.writestr("manifest.json", json.dumps(mc.evidence_manifest(), indent=2))
        z.writestr("job_index.json", json.dumps(_job_index(), indent=2, default=str))
        z.writestr("README.txt", "Q-Uplink Mission Control evidence bundle. Private keys and API secrets are never "
                                 "included. See manifest.json for SHA-256 of every file and host details.\n")
    return buf.getvalue()


@app.get("/api/evidence.zip")
async def evidence_zip():
    data = await asyncio.to_thread(build_evidence_zip)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(io.BytesIO(data), media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="q-uplink-evidence-{stamp}.zip"'})


# ---------------------------------------------------------------- websocket
@app.websocket("/ws/frames")
async def ws_frames(ws: WebSocket):
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue()
    bus.clients.add(q)
    try:
        await ws.send_json({"type": "hello", "recent": list(bus.recent)[-50:]})
        while True:
            event = await q.get()
            await ws.send_json(event)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.clients.discard(q)


# ---------------------------------------------------------------- built frontend (optional)
_dist = PROJECT_ROOT / "frontend" / "dist"
if _dist.exists():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        if full_path.startswith(("api/", "ws/")):
            raise HTTPException(404)
        f = _dist / full_path
        return FileResponse(f if full_path and f.is_file() else _dist / "index.html")
