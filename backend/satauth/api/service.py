"""Mission Control service: wires ground, link and the onboard process together.

The API layer is a thin shell over this class, which keeps it testable without
HTTP. All heavy calls are synchronous and are run in a worker thread by the API.
"""

from __future__ import annotations

import hashlib
import os
import platform
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..common.atomic import atomic_write_json, read_json, read_jsonl
from ..common.frame import NONCE_LEN
from ..common.roles import OPCODE_INFO, default_role_table, opcode_name
from ..config import Settings
from ..ground.feasibility import order_within_pass, validate_plan
from ..ground.keygen import ensure_role_keys, load_public_keys
from ..ground.qrng import QRNGPool
from ..ground.queue import Instance, PassWindow, default_passes, default_queue
from ..ground.scheduler_opt import plan_with_opt
from ..ground.signer import Signer
from ..link.pass_sim import LinkBudgetExceeded, LinkSimulator
from ..onboard.process import SatelliteProcess
from ..onboard.state import StateStore


class ServiceError(RuntimeError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class MissionControl:
    def __init__(self, settings: Settings, emit: Callable[[dict], None] | None = None):
        self.s = settings
        self.emit = emit or (lambda e: None)
        self.data = Path(settings.data_dir)
        self.ev = Path(settings.evidence_dir)
        self.state_path = self.data / "onboard" / "state.json"
        self.onboard_log = self.ev / "logs" / "onboard_log.jsonl"
        self.link = LinkSimulator(self.ev / "logs" / "link_log.jsonl")
        self.chain_path = self.data / "ground" / "nonce_chain.json"
        self.queue_path = self.data / "ground" / "queue.json"
        self.plan_path = self.data / "ground" / "current_plan.json"
        self.passes_path = self.data / "ground" / "pass_runs.json"
        self._lock = threading.RLock()
        self.sat: SatelliteProcess | None = None
        self.signer: Signer | None = None
        self.qrng = QRNGPool(self.data, self.ev, api_key=settings.qcloud_api_key, n_qubits=settings.qrng_qubits,
                             shots=settings.qrng_shots, default_device=settings.qrng_device,
                             allow_dev_nonce=settings.allow_dev_nonce)
        self.last_accepted_frame: bytes | None = None
        self.last_sent_frame: bytes | None = None
        self.window_counter = 0
        self.busy: str | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.data.mkdir(parents=True, exist_ok=True)
        (self.ev / "logs").mkdir(parents=True, exist_ok=True)
        self.keys_meta = ensure_role_keys(self.data)
        store = StateStore(self.state_path)
        if not store.provisioned:
            self._provision(store)
        self.signer = Signer(self.data, self.s.sat_id, self.s.default_expiry_s)
        self.sat = SatelliteProcess(self.state_path, self.onboard_log, self.s.flood_limit)
        chain = read_json(self.chain_path, default=None)
        self.window_counter = int((chain or {}).get("window_counter", 0))
        if not self.queue_path.exists():
            self.save_queue({"commands": [c.to_dict() for c in default_queue()],
                             "budgets": list(self.s.pass_budgets)})

    def stop(self) -> None:
        if self.sat:
            self.sat.stop()

    def _provision(self, store: StateStore) -> None:
        genesis = os.urandom(NONCE_LEN)
        store.provision(sat_id=self.s.sat_id, public_keys=load_public_keys(self.data),
                        role_table=default_role_table(), genesis_nonce=genesis)
        atomic_write_json(self.chain_path, {"current": genesis.hex(), "history": [
            {"nonce": genesis.hex(), "pass": 0, "source": "provisioning (OS CSPRNG, pre-launch)", "time_utc": _utc()}],
            "window_counter": 0})

    def reset(self) -> dict:
        """Demo reset: archive logs, re-provision onboard, restart satellite process. Keys are kept."""
        with self._lock:
            if self.sat:
                self.sat.stop()
            from ..onboard.logger import AuditLog

            archived = AuditLog(self.onboard_log).archive()
            store = StateStore(self.state_path)
            self._provision(store)
            assert self.signer is not None
            self.signer.counter.reset()
            self.sat = SatelliteProcess(self.state_path, self.onboard_log, self.s.flood_limit)
            self.link = LinkSimulator(self.ev / "logs" / "link_log.jsonl")
            self.window_counter = 0
            self.last_accepted_frame = None
            atomic_write_json(self.passes_path, {"runs": []})
            self.emit({"type": "reset", "time_utc": _utc()})
            return {"reset": True, "archived_log": str(archived) if archived else None, "state": self.state()}

    # ------------------------------------------------------------------ queue / plan
    def get_queue(self) -> dict:
        q = read_json(self.queue_path, default=None) or {}
        inst = self._instance(q)
        return {"commands": [c.to_dict() for c in inst.commands], "passes": [p.to_dict() for p in inst.passes],
                "weights": {p.index: inst.weight(p.index) for p in inst.passes},
                "opcodes": {int(k): v for k, v in OPCODE_INFO.items()}}

    def save_queue(self, q: dict) -> dict:
        inst = self._instance(q)
        inst.validate()
        atomic_write_json(self.queue_path, {"commands": [c.to_dict() for c in inst.commands],
                                            "budgets": [p.budget_bytes for p in inst.passes]})
        return self.get_queue()

    def _instance(self, q: dict) -> Instance:
        from ..ground.queue import Command

        cmds = [Command.from_dict(c) for c in q.get("commands", [])] or default_queue()
        budgets = q.get("budgets") or self.s.pass_budgets
        return Instance(cmds, default_passes([int(b) for b in budgets]))

    def plan(self, mode: str | None = None) -> dict:
        mode = mode or self.s.opt_mode
        inst = self._instance(read_json(self.queue_path, default={}) or {})
        self.emit({"type": "plan", "phase": "started", "mode": mode, "time_utc": _utc()})
        try:
            result = plan_with_opt(inst, api_key=self.s.opt_api_key, mode=mode)
        except Exception as exc:
            self.emit({"type": "plan", "phase": "failed", "error": str(exc)})
            raise ServiceError(str(exc), status=503) from exc
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        tag = result["opt"].get("job_id") or f"{result['opt']['execution_mode']}-nojobid"
        fname = f"opt_{stamp}_{tag}.json"
        result["evidence_file"] = f"opt_jobs/{fname}"
        atomic_write_json(self.ev / "opt_jobs" / fname, result)
        atomic_write_json(self.plan_path, result)
        self.emit({"type": "plan", "phase": "done", "job_id": result["opt"].get("job_id"),
                   "execution_mode": result["opt"]["execution_mode"], "feasible": result["validation"]["feasible"]})
        return result

    def current_plan(self) -> dict | None:
        return read_json(self.plan_path, default=None)

    def baselines_only(self) -> dict:
        """Greedy + brute force for the current queue (comparison only, never executed)."""
        from ..ground.baselines import brute_force, greedy

        inst = self._instance(read_json(self.queue_path, default={}) or {})
        g, bf = greedy(inst), brute_force(inst)
        return {"greedy": {**g, "validation": validate_plan(inst, g["plan"])},
                "brute_force": {**bf, "validation": validate_plan(inst, bf["plan"]) if bf["plan"] else None},
                "note": "Baselines are for comparison only and never drive the uplink."}

    # ------------------------------------------------------------------ nonce chain
    def _chain(self) -> dict:
        return read_json(self.chain_path, default={}) or {}

    def current_nonce(self) -> bytes:
        return bytes.fromhex(self._chain()["current"])

    def previous_nonce(self) -> bytes | None:
        hist = self._chain().get("history", [])
        return bytes.fromhex(hist[-2]["nonce"]) if len(hist) >= 2 else None

    def _install_ground_nonce(self, nonce: bytes, info: dict) -> None:
        chain = self._chain()
        chain["current"] = nonce.hex()
        chain.setdefault("history", []).append({"nonce": nonce.hex(), **info, "time_utc": _utc()})
        chain["window_counter"] = self.window_counter
        atomic_write_json(self.chain_path, chain)

    # ------------------------------------------------------------------ frames
    def _deliver(self, data: bytes, *, context: dict, now: float | None = None) -> dict:
        assert self.sat is not None
        res = self.sat.send_frame(data, now=now, context=context)
        self.last_sent_frame = data
        if res["verdict"] == "ACCEPT":
            self.last_accepted_frame = data
        return res

    def _frame_event(self, phase: str, **kw) -> None:
        self.emit({"type": "frame", "phase": phase, "time_utc": _utc(), **kw})

    def open_window(self, pass_no: int | None = None, budget: int | None = None, pace_ms: int = 0) -> dict:
        """Contact-window start: onboard timer resets flood guard; ground sends PASS_OPEN
        carrying a fresh QRNG-derived nonce, signed over the nonce currently installed."""
        with self._lock:
            assert self.signer is not None and self.sat is not None
            self.window_counter += 1
            wid = self.window_counter
            budget = budget if budget is not None else (self.s.pass_budgets[(pass_no or 1) - 1]
                                                       if pass_no and pass_no <= len(self.s.pass_budgets)
                                                       else max(self.s.pass_budgets))
            self.sat.begin_window(wid)
            self.link.open_window(wid, pass_no, budget)
            try:
                n = self.qrng.take_nonce(pass_no or wid)
            except Exception as exc:
                raise ServiceError(str(exc), status=409) from exc
            new_nonce = n.pop("nonce_bytes")
            current = self.current_nonce()
            frame = self.signer.pass_open(new_nonce=new_nonce, current_nonce=current)
            data = frame.to_bytes()
            ev = {"window": wid, "pass": pass_no, "label": "PASS_OPEN", "counter": frame.counter,
                  "bytes": len(data), "opcode_name": "PASS_OPEN", "nonce": n}
            self._frame_event("signed", **ev)
            self._pace(pace_ms)
            try:
                tx = self.link.transmit(data, label="PASS_OPEN")
            except LinkBudgetExceeded as exc:
                self._frame_event("refused", **ev, error=str(exc), link=self.link.snapshot())
                raise ServiceError(str(exc), status=409) from exc
            self._frame_event("tx", **ev, link=self.link.snapshot())
            self._pace(pace_ms)
            res = self._deliver(data, context={"window": wid, "pass": pass_no, "label": "PASS_OPEN",
                                               "nonce_job_id": n.get("job_id")})
            if res["verdict"] == "ACCEPT":
                self._install_ground_nonce(new_nonce, {"pass": pass_no, "window": wid, "job_id": n.get("job_id"),
                                                       "device": n.get("device"),
                                                       "randomness_class": n.get("randomness_class")})
            self._frame_event("verdict", **ev, result=res, link=self.link.snapshot())
            return {"window": wid, "pass": pass_no, "nonce": n, "pass_open": res, "tx": tx,
                    "link": self.link.snapshot(), "state": self.state()}

    def run_pass(self, t: int, pace_ms: int = 300) -> dict:
        """Execute pass t of the current, validated QpiAI Opt plan."""
        with self._lock:
            plan = self.current_plan()
            if not plan:
                raise ServiceError("No plan yet. Run Optimize (QpiAI Opt) first.", 409)
            inst = Instance.from_dict(plan["instance"])
            opt_plan = {k: v for k, v in plan["opt"]["plan"].items()}
            # FR-16: re-validate immediately before signing; never trust a stored flag
            check = validate_plan(inst, opt_plan)
            if not check["feasible"]:
                raise ServiceError(f"Plan failed feasibility check, nothing signed: {check['violations']}", 409)
            if not (1 <= t <= inst.T):
                raise ServiceError(f"pass must be 1..{inst.T}", 400)
            p: PassWindow = inst.passes[t - 1]
            opened = self.open_window(pass_no=t, budget=p.budget_bytes, pace_ms=pace_ms)
            if opened["pass_open"]["verdict"] != "ACCEPT":
                raise ServiceError(f"PASS_OPEN rejected: {opened['pass_open']['reason']}", 409)
            by = inst.by_id()
            nonce = self.current_nonce()
            results = []
            for cid in order_within_pass(inst, opt_plan, t):
                c = by[cid]
                assert self.signer is not None
                frame = self.signer.build(role=c.role, command=c.body, pass_nonce=nonce)
                data = frame.to_bytes()
                ev = {"window": opened["window"], "pass": t, "label": cid, "cmd_id": cid, "cmd_name": c.name,
                      "counter": frame.counter, "bytes": len(data), "opcode_name": opcode_name(c.opcode),
                      "role": c.role}
                self._frame_event("signed", **ev)
                self._pace(pace_ms)
                try:
                    self.link.transmit(data, label=cid)
                except LinkBudgetExceeded as exc:
                    self._frame_event("refused", **ev, error=str(exc), link=self.link.snapshot())
                    results.append({"cmd_id": cid, "verdict": "NOT_SENT", "reason": "LINK_BUDGET", "error": str(exc)})
                    continue
                self._frame_event("tx", **ev, link=self.link.snapshot())
                self._pace(pace_ms)
                res = self._deliver(data, context={"window": opened["window"], "pass": t, "cmd_id": cid,
                                                   "plan_job_id": plan["opt"].get("job_id")})
                self._frame_event("verdict", **ev, result=res, link=self.link.snapshot())
                self._pace(pace_ms)
                results.append({"cmd_id": cid, "name": c.name, "counter": frame.counter, "bytes": len(data),
                                "verdict": res["verdict"], "reason": res["reason"], "steps": res["steps"]})
            run = {"pass": t, "window": opened["window"], "time_utc": _utc(), "nonce": opened["nonce"],
                   "plan_job_id": plan["opt"].get("job_id"), "plan_execution_mode": plan["opt"]["execution_mode"],
                   "frames": results, "link": self.link.snapshot()}
            runs = read_json(self.passes_path, default={"runs": []}) or {"runs": []}
            runs["runs"].append(run)
            atomic_write_json(self.passes_path, runs)
            atomic_write_json(self.ev / "pass_runs.json", runs)
            self.emit({"type": "pass_done", "pass": t, "summary": {
                "accepted": sum(1 for r in results if r["verdict"] == "ACCEPT"),
                "rejected": sum(1 for r in results if r["verdict"] == "REJECT"),
                "not_sent": sum(1 for r in results if r["verdict"] == "NOT_SENT")}, "link": self.link.snapshot()})
            return {**run, "state": self.state()}

    def send_manual(self, *, role: str, opcode: int, args_hex: str = "", pace_ms: int = 0) -> dict:
        """Ground operator sends one ad-hoc command in the open window (uses the link budget)."""
        with self._lock:
            if not self.link.window_id:
                raise ServiceError("Open a contact window first.", 409)
            body = bytes([opcode]) + bytes.fromhex(args_hex)
            assert self.signer is not None
            frame = self.signer.build(role=role, command=body, pass_nonce=self.current_nonce())
            data = frame.to_bytes()
            ev = {"window": self.link.window_id, "pass": self.link.pass_no, "label": "manual",
                  "counter": frame.counter, "bytes": len(data), "opcode_name": opcode_name(opcode), "role": role}
            self._frame_event("signed", **ev)
            try:
                self.link.transmit(data, label="manual")
            except LinkBudgetExceeded as exc:
                self._frame_event("refused", **ev, error=str(exc), link=self.link.snapshot())
                raise ServiceError(str(exc), 409) from exc
            self._frame_event("tx", **ev, link=self.link.snapshot())
            self._pace(pace_ms)
            res = self._deliver(data, context={"label": "manual"})
            self._frame_event("verdict", **ev, result=res, link=self.link.snapshot())
            return {"frame": ev, "result": res, "state": self.state()}

    # ------------------------------------------------------------------ state / logs
    def state(self) -> dict:
        assert self.sat is not None
        sat = self.sat.state()
        chain = self._chain()
        return {"onboard": sat, "satellite_pid": self.sat.pid, "satellite_alive": self.sat.alive(),
                "ground": {"last_counter_issued": self.signer.counter.last_issued if self.signer else None,
                           "current_nonce": chain.get("current"), "nonce_history": chain.get("history", [])[-10:],
                           "window_counter": self.window_counter},
                "link": self.link.snapshot(), "qrng": self.qrng.status(), "config": self.s.public_status(),
                "keys": getattr(self, "keys_meta", {})}

    def log_tail(self, limit: int = 500) -> list[dict]:
        return read_jsonl(self.onboard_log, limit=limit)

    def reboot_satellite(self) -> dict:
        assert self.sat is not None
        return self.sat.reboot()

    @staticmethod
    def _pace(ms: int) -> None:
        if ms > 0:
            time.sleep(ms / 1000)

    # ------------------------------------------------------------------ evidence
    @staticmethod
    def host_info() -> dict:
        import sys

        cpu = platform.processor() or platform.machine()
        try:
            if platform.system() == "Linux":
                for line in Path("/proc/cpuinfo").read_text().splitlines():
                    if line.startswith("model name"):
                        cpu = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        from importlib.metadata import PackageNotFoundError, version

        pk = {}
        for p in ("qpiai-opt", "qpiai-quantum", "pqcrypto", "cryptography", "fastapi", "numpy"):
            try:
                pk[p] = version(p)
            except PackageNotFoundError:
                pk[p] = None
        return {"python": sys.version.split()[0], "platform": platform.platform(), "cpu": cpu,
                "machine": platform.machine(), "packages": pk,
                "measurement_label": "Emulated host measurement (desktop/laptop CPU), not flight hardware"}

    def evidence_manifest(self) -> dict:
        files = []
        for p in sorted(self.ev.rglob("*")):
            if p.is_file():
                files.append({"path": str(p.relative_to(self.ev)).replace("\\", "/"), "bytes": p.stat().st_size,
                              "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
        return {"generated_utc": _utc(), "host": self.host_info(), "files": files}
