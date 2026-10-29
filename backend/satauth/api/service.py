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
from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ..common import txtlog
from ..common.atomic import atomic_write_json, read_json, read_jsonl
from ..common.frame import NONCE_LEN
from ..common.roles import OPCODE_INFO, default_role_table, opcode_name
from ..config import Settings
from ..ground.feasibility import order_within_pass, validate_plan
from ..ground.keygen import ensure_role_keys, load_public_keys, ring_spec
from ..ground.queue import set_signature_sizes, signature_sizes
from ..ground.qrng import QRNGPool
from ..ground.queue import Command, Instance, PassWindow, default_passes, default_queue
from ..ground.replan import build_subinstance, delivered_from_runs, merge_plan
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
                             allow_dev_nonce=settings.allow_dev_nonce, allow_local_qrng=settings.allow_local_qrng)
        self.last_accepted_frame: bytes | None = None
        self.last_sent_frame: bytes | None = None
        self.window_counter = 0
        self.busy: str | None = None
        # missing-packet detection: what the ground transmitted on planned passes and
        # what it heard back (counter -> entry), plus operator alerts
        self.tx_ledger: OrderedDict[int, dict] = OrderedDict()
        self.alerts: deque = deque(maxlen=200)
        self.alert_log = self.ev / "logs" / "alerts.jsonl"
        self.ack_log = self.ev / "logs" / "ack_log.jsonl"

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self.data.mkdir(parents=True, exist_ok=True)
        (self.ev / "logs").mkdir(parents=True, exist_ok=True)
        self.keys_meta = ensure_role_keys(self.data)
        store = StateStore(self.state_path)
        if not store.provisioned:
            self._provision(store)
        self.signer = Signer(self.data, self.s.sat_id, self.s.default_expiry_s)
        self._sync_sig_sizes()
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
                        role_table=default_role_table(), genesis_nonce=genesis, key_meta=ring_spec())
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
            self.signer.ring.reset()
            self._sync_sig_sizes()
            self.sat = SatelliteProcess(self.state_path, self.onboard_log, self.s.flood_limit)
            self.link = LinkSimulator(self.ev / "logs" / "link_log.jsonl")
            self.window_counter = 0
            self.last_accepted_frame = None
            self.tx_ledger.clear()
            self.alerts.clear()
            self.signer.issued.clear()
            atomic_write_json(self.passes_path, {"runs": []})
            self.emit({"type": "reset", "time_utc": _utc()})
            return {"reset": True, "archived_log": str(archived) if archived else None, "state": self.state()}

    # ------------------------------------------------------------------ queue / plan
    def get_queue(self) -> dict:
        q = read_json(self.queue_path, default=None) or {}
        inst = self._instance(q)
        return {"commands": [c.to_dict() for c in inst.commands], "passes": [p.to_dict() for p in inst.passes],
                "weights": {p.index: inst.weight(p.index) for p in inst.passes},
                "opcodes": {int(k): v for k, v in OPCODE_INFO.items()},
                "budget_source": q.get("budget_source")}

    def save_queue(self, q: dict) -> dict:
        inst = self._instance(q)
        inst.validate()
        old = read_json(self.queue_path, default={}) or {}
        budgets = [p.budget_bytes for p in inst.passes]
        out = {"commands": [c.to_dict() for c in inst.commands], "budgets": budgets}
        src = q.get("budget_source", old.get("budget_source"))
        if src and list(src.get("budgets", [])) == budgets:  # keep NASA provenance only while budgets match it
            out["budget_source"] = src
            out["pass_labels"] = q.get("pass_labels", old.get("pass_labels"))
        atomic_write_json(self.queue_path, out)
        return self.get_queue()

    # ------------------------------------------------------------------ NASA pass windows
    def nasa_fetch(self, *, norad: int | None = None, uplink_bps: float | None = None,
                   min_el: float | None = None) -> dict:
        from ..ground.nasa import NasaUnavailable, nasa_pull

        try:
            rec = nasa_pull(evidence_dir=self.ev, api_key=self.s.nasa_api_key, norad=int(norad or self.s.norad_id),
                            gs=self.s.ground_station, uplink_bps=float(uplink_bps or self.s.uplink_bps),
                            min_el=float(min_el if min_el is not None else self.s.min_elevation_deg))
        except NasaUnavailable as exc:
            raise ServiceError(f"NASA data unavailable: {exc}", 503) from exc
        self.emit({"type": "nasa", "phase": "done", "evidence_file": rec["evidence_file"], "budgets": rec["budgets"]})
        return rec

    def nasa_latest(self) -> dict | None:
        files = sorted((self.ev / "nasa").glob("nasa_*.json"))
        return read_json(files[-1], default=None) if files else None

    def nasa_apply(self, evidence_file: str | None = None) -> dict:
        rec = read_json(self.ev / evidence_file, default=None) if evidence_file else self.nasa_latest()
        if not rec:
            raise ServiceError("No NASA pull recorded yet. Fetch pass windows first.", 409)
        if not rec.get("complete"):
            raise ServiceError(f"The NASA pull found only {len(rec.get('passes', []))} usable passes; need "
                               f"{rec['parameters']['n_passes']}. Lower the minimum elevation or raise the uplink rate.", 409)
        q = read_json(self.queue_path, default={}) or {}
        q["budgets"] = rec["budgets"]
        q["budget_source"] = {"kind": "nasa", "evidence_file": rec["evidence_file"], "created_utc": rec["created_utc"],
                              "budgets": rec["budgets"], "spacecraft": rec["tle"]["name"],
                              "tle_epoch_utc": rec["tle"]["epoch_utc"], "ground_station": rec["ground_station"]["name"],
                              "space_weather_factor": rec["space_weather"]["factor"],
                              "uplink_bps": rec["parameters"]["uplink_bps"]}
        q["pass_labels"] = [p["label"] for p in rec["passes"]]
        out = self.save_queue(q)
        self.emit({"type": "nasa", "phase": "applied", "budgets": rec["budgets"]})
        return out

    def _instance(self, q: dict) -> Instance:
        from ..ground.queue import Command

        cmds = [Command.from_dict(c) for c in q.get("commands", [])] or default_queue()
        budgets = [int(b) for b in (q.get("budgets") or self.s.pass_budgets)]
        passes = default_passes(budgets)
        labels = q.get("pass_labels") or []
        if q.get("budget_source") and len(labels) == len(passes):
            for p, lab in zip(passes, labels):
                p.label = lab
        return Instance(cmds, passes)

    def plan(self, mode: str | None = None) -> dict:
        mode = mode or self.s.opt_mode
        inst = self._instance(read_json(self.queue_path, default={}) or {})
        self.emit({"type": "plan", "phase": "started", "mode": mode, "time_utc": _utc()})
        try:
            result = plan_with_opt(inst, api_key=self.s.opt_api_key, mode=mode)
        except Exception as exc:
            self.emit({"type": "plan", "phase": "failed", "error": str(exc)})
            txtlog.record_event(self.ev, "qpiai", {"tool": "opt", "status": "failed",
                                                   "requested": f"multi-pass schedule, mode {mode}", "error": str(exc)})
            raise ServiceError(str(exc), status=503) from exc
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        tag = result["opt"].get("job_id") or f"{result['opt']['execution_mode']}-nojobid"
        fname = f"opt_{stamp}_{tag}.json"
        result["evidence_file"] = f"opt_jobs/{fname}"
        atomic_write_json(self.ev / "opt_jobs" / fname, result)
        atomic_write_json(self.plan_path, result)
        txtlog.refresh(self.ev)
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
        ctr = res.get("counter")
        entry = self.tx_ledger.get(ctr) if ctr is not None else None
        if entry is not None and entry.get("sha256") == res.get("frame_sha256"):
            entry["status"] = "ACCEPTED" if res["verdict"] == "ACCEPT" else f"REJECTED:{res['reason']}"
            self._ack_log(entry)
        if res["verdict"] == "ACCEPT" and res.get("counter_gap"):
            self._reconcile_gap(res["counter_gap"], reported_with=ctr)
        return res

    # ------------------------------------------------------------------ missing packets
    def _ack_log(self, entry: dict) -> None:
        from ..common.atomic import append_jsonl

        append_jsonl(self.ack_log, {"time_utc": _utc(), **entry})

    def _ledger(self, counter: int, **fields) -> dict:
        e = self.tx_ledger.setdefault(counter, {"counter": counter})
        e.update(fields)
        while len(self.tx_ledger) > 5000:
            self.tx_ledger.popitem(last=False)
        self._ack_log(e)
        return e

    def _alert(self, kind: str, severity: str, message: str, **data) -> dict:
        from ..common.atomic import append_jsonl

        a = {"id": f"{time.time_ns()}", "time_utc": _utc(), "kind": kind, "severity": severity, "message": message, **data}
        self.alerts.append(a)
        append_jsonl(self.alert_log, a)
        self.emit({"type": "alert", **a})
        return a

    def _reconcile_gap(self, gap: dict, *, reported_with: int | None) -> dict:
        """The satellite reported counters it never accepted. Explain each one from the
        ground's own records; anything the ground cannot explain is flagged."""
        items, lost, unexplained = [], [], []
        lo, hi = int(gap["from"]), int(gap["to"])
        for ctr in range(lo, min(hi, lo + 49) + 1):
            e = self.tx_ledger.get(ctr)
            if e is not None:
                st = e.get("status", "")
                if st == "NO_ACK":
                    why = f"{e.get('cmd_id')} sent in pass {e.get('pass')} with no acknowledgement: lost on the link"
                    lost.append(e.get("cmd_id"))
                elif st == "REFUSED":
                    why = f"{e.get('cmd_id')} refused at the ground link budget, never radiated"
                elif st.startswith("REJECTED"):
                    why = f"{e.get('cmd_id')} reached the spacecraft and was rejected ({st.split(':', 1)[1]})"
                else:
                    why = f"{e.get('cmd_id')}: {st or 'signed, not transmitted'}"
            elif self.signer is not None and ctr in self.signer.issued:
                why = "issued for a test or ad-hoc frame (attack lab / judge console) that was not accepted"
            else:
                why = "not issued by this ground station in this session"
                unexplained.append(ctr)
            items.append({"counter": ctr, "explanation": why})
        sev = "warn" if (lost or unexplained) else "info"
        msg = (f"Satellite reported {gap['count']} skipped counter(s) {lo}..{hi} when it accepted counter {reported_with}. "
               + (f"Confirmed missing packets: {', '.join(lost)}. " if lost else "")
               + (f"Unexplained: {unexplained}. " if unexplained else "")
               + ("All explained by ground records." if not (lost or unexplained) else ""))
        return self._alert("GAP_REPORTED", sev, msg.strip(), gap=gap, reconciliation=items, lost=lost,
                           unexplained=unexplained)

    def delivered_commands(self) -> dict[str, int]:
        runs = (read_json(self.passes_path, default={"runs": []}) or {"runs": []})["runs"]
        return delivered_from_runs(runs)

    def delivery_status(self) -> dict:
        plan = self.current_plan()
        runs = (read_json(self.passes_path, default={"runs": []}) or {"runs": []})["runs"]
        delivered = delivered_from_runs(runs)
        carried = runs[-1].get("carried_over", []) if runs else []
        last_pass = max((int(r["pass"]) for r in runs), default=0)
        T = len(plan["instance"]["passes"]) if plan else 0
        return {"delivered": delivered, "carried_over": carried, "last_pass_run": last_pass,
                "next_pass": last_pass + 1 if last_pass < T else None, "passes": T,
                "replanned": bool(plan and plan.get("replan")),
                "alerts": list(self.alerts)[-60:][::-1],
                "ledger": list(self.tx_ledger.values())[-40:][::-1]}

    def replan(self, from_pass: int | None = None, mode: str | None = None) -> dict:
        """Re-run QpiAI Opt on every unacknowledged command over the remaining passes."""
        with self._lock:
            plan = self.current_plan()
            if not plan:
                raise ServiceError("No plan yet. Run Optimize (QpiAI Opt) first.", 409)
            inst = Instance.from_dict(plan["instance"])
            delivered = self.delivered_commands()
            st = self.delivery_status()
            fp = int(from_pass or st["next_pass"] or 0)
            if not 1 <= fp <= inst.T:
                raise ServiceError("No passes left to re-plan.", 409)
            cut = build_subinstance(inst, delivered, fp)
            sub: Instance = cut["sub"]
            mode = mode or self.s.opt_mode
            self.emit({"type": "plan", "phase": "started", "mode": mode, "replan_from": fp, "time_utc": _utc()})
            if sub.commands:
                try:
                    res = plan_with_opt(sub, api_key=self.s.opt_api_key, mode=mode)
                except Exception as exc:
                    self.emit({"type": "plan", "phase": "failed", "error": str(exc)})
                    txtlog.record_event(self.ev, "qpiai", {"tool": "opt", "status": "failed", "error": str(exc),
                                                           "requested": f"re-plan from pass {fp}, mode {mode}"})
                    raise ServiceError(str(exc), status=503) from exc
                sub_plan = res["opt"]["plan"]
            else:
                res, sub_plan = None, {}
            merged = merge_plan(inst, delivered, sub_plan, cut["shift"])
            from ..ground.feasibility import explain

            validation = validate_plan(inst, merged)
            new = dict(plan)
            new["created_utc"] = _utc()
            new["opt"] = {**(res["opt"] if res else {"solver": "none (nothing left to schedule)",
                                                      "execution_mode": "n/a", "job_id": None}),
                          "plan": merged}
            new["validation"] = validation
            new["approved_for_signing"] = validation["feasible"]
            new["explanations"] = explain(inst, merged)
            if res:
                new["comparison"] = {**res["comparison"], "scope": f"re-plan: passes {fp}..{inst.T}, "
                                                                    f"{len(sub.commands)} unacknowledged command(s)"}
                new["baselines"] = res["baselines"]
            new["replan"] = {"from_pass": fp, "delivered": delivered, "missed_deadline": cut["missed"],
                             "blocked_by_missed_dependency": cut["blocked"], "requeued": [c.id for c in sub.commands],
                             "sub_instance": sub.to_dict(), "sub_plan": sub_plan,
                             "previous_plan": plan["opt"]["plan"], "history": plan.get("replan_history", [])}
            new["replan_history"] = plan.get("replan_history", []) + [{"time_utc": _utc(), "from_pass": fp,
                                                                       "previous_plan": plan["opt"]["plan"]}]
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            tag = new["opt"].get("job_id") or f"{new['opt'].get('execution_mode')}-nojobid"
            fname = f"opt_{stamp}_replan_p{fp}_{tag}.json"
            new["evidence_file"] = f"opt_jobs/{fname}"
            atomic_write_json(self.ev / "opt_jobs" / fname, new)
            if validation["feasible"]:
                atomic_write_json(self.plan_path, new)
            txtlog.refresh(self.ev)
            moved = {c: merged[c] for c in cut["remaining"] if merged.get(c) is not None}
            self._alert("REPLANNED", "info" if validation["feasible"] else "error",
                        f"QpiAI Opt re-planned passes {fp}..{inst.T}: "
                        + (", ".join(f"{c}->pass {t}" for c, t in moved.items()) or "nothing fits")
                        + (f". Missed deadline: {', '.join(cut['missed'])}" if cut["missed"] else "")
                        + (f". Blocked: {', '.join(cut['blocked'])}" if cut["blocked"] else ""),
                        from_pass=fp, moved=moved, missed=cut["missed"], blocked=cut["blocked"],
                        feasible=validation["feasible"])
            self.emit({"type": "plan", "phase": "done", "job_id": new["opt"].get("job_id"),
                       "execution_mode": new["opt"].get("execution_mode"), "feasible": validation["feasible"]})
            if not validation["feasible"]:
                raise ServiceError(f"Re-plan failed validation, not adopted: {validation['violations']}", 409)
            return new

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

    # ------------------------------------------------------------------ key management
    def _sync_sig_sizes(self) -> None:
        assert self.signer is not None
        set_signature_sizes({r: self.signer.sig_len_for_role(r) for r in ("OPERATOR", "ADMIN")})

    def key_status(self) -> dict:
        from ..common import suites
        from ..common.frame import HEADER_LEN, MAX_BODY_LEN, PASS_OPEN_BODY_LEN

        assert self.signer is not None and self.sat is not None
        onboard = self.sat.state().get("key_ring", {})
        ground = self.signer.ring.snapshot()
        meta = (getattr(self, "keys_meta", {}) or {})
        rows = []
        for kid, spec in sorted(ring_spec().items()):
            su = suites.info(spec["suite"])
            rows.append({"key_id": kid, "role": spec["role"], "suite": spec["suite"], "algorithm": su["name"],
                         "standard": su["standard"], "signature_bytes": su["sig_len"], "public_key_bytes": su["pk_len"],
                         "onboard_state": (onboard.get(str(kid)) or {}).get("state", "not provisioned"),
                         "ground_state": ground["states"].get(str(kid), "standby"),
                         "signing": ground["signing"].get(spec["role"]) == kid,
                         "public_key_sha256": ((meta.get("keys") or {}).get(str(kid)) or {}).get("public_key_sha256")})
        sizes = signature_sizes()
        typical = HEADER_LEN + 12  # header + a 12-byte command body
        return {"keys": rows, "signing": ground["signing"], "signature_bytes": sizes,
                "frame_bytes_typical": {r: typical + n for r, n in sizes.items()},
                "pass_open_bytes": HEADER_LEN + PASS_OPEN_BODY_LEN + sizes["ADMIN"],
                "operator_commands_per_3600B_pass": (3600 - (HEADER_LEN + PASS_OPEN_BODY_LEN + sizes["ADMIN"]))
                // (HEADER_LEN + MAX_BODY_LEN // 2 + sizes["OPERATOR"]),
                "encrypted_at_rest": bool(meta.get("encrypted_at_rest")), "at_rest": meta.get("at_rest"),
                "needs_reset": any(r["onboard_state"] == "not provisioned" for r in rows)}

    def _send_admin(self, opcode: int, kid: int, label: str, pace_ms: int, sign_kid: int | None = None) -> dict:
        assert self.signer is not None
        frame = self.signer.build(role="ADMIN", command=bytes([opcode, kid]), pass_nonce=self.current_nonce(),
                                  key_id=sign_kid)
        data = frame.to_bytes()
        ev = {"window": self.link.window_id, "pass": self.link.pass_no, "label": label, "counter": frame.counter,
              "bytes": len(data), "opcode_name": opcode_name(opcode), "role": "ADMIN"}
        self._frame_event("signed", **ev)
        try:
            self.link.transmit(data, label=label)
        except LinkBudgetExceeded as exc:
            self._frame_event("refused", **ev, error=str(exc), link=self.link.snapshot())
            raise ServiceError(f"{label}: {exc}. Start a new contact window and try again.", 409) from exc
        self._frame_event("tx", **ev, link=self.link.snapshot())
        self._pace(pace_ms)
        res = self._deliver(data, context={"key_management": label})
        self._frame_event("verdict", **ev, result=res, link=self.link.snapshot())
        return {"label": label, "counter": frame.counter, "bytes": len(data), "verdict": res["verdict"],
                "reason": res["reason"], "steps": res["steps"]}

    def rotate_key(self, role: str, to_kid: int, pace_ms: int = 0) -> dict:
        """Rotate (or migrate) a role to a pre-loaded standby key: ADMIN-signed
        KEY_ACTIVATE(new), then KEY_REVOKE(old). The ground switches keys only after
        the spacecraft acknowledges each step."""
        from ..common.roles import Opcode

        with self._lock:
            assert self.signer is not None
            if not self.link.window_id:
                raise ServiceError("Open a contact window first: key commands travel over the link like any other.", 409)
            spec = ring_spec().get(int(to_kid))
            if not spec or spec["role"] != role:
                raise ServiceError(f"key_id {to_kid} is not a {role} key", 400)
            if self.signer.ring.state(to_kid) != "standby":
                raise ServiceError(f"key_id {to_kid} is {self.signer.ring.state(to_kid)}; choose a standby key", 409)
            if self.key_status()["needs_reset"]:
                raise ServiceError("This satellite was provisioned before the key ring existed. Use Reset demo state "
                                   "once to pre-load the full key ring.", 409)
            old = self.signer.ring.signing_kid(role)
            before = self.key_status()
            steps = [self._send_admin(Opcode.KEY_ACTIVATE, to_kid, f"KEY_ACTIVATE {to_kid}", pace_ms)]
            if steps[0]["verdict"] != "ACCEPT":
                raise ServiceError(f"KEY_ACTIVATE rejected: {steps[0]['reason']}", 409)
            self.signer.ring.set(to_kid, "active", signing_role=role)
            self._sync_sig_sizes()
            # an ADMIN key signs its own revocation (the new ADMIN key is already active,
            # so the spacecraft is never left without one, and the frame stays small)
            steps.append(self._send_admin(Opcode.KEY_REVOKE, old, f"KEY_REVOKE {old}", pace_ms,
                                          sign_kid=old if role == "ADMIN" else None))
            if steps[1]["verdict"] != "ACCEPT":
                raise ServiceError(f"KEY_REVOKE rejected: {steps[1]['reason']} (key {to_kid} is active, {old} still valid)", 409)
            self.signer.ring.set(old, "retired")
            self.signer._sk_cache.pop(old, None)
            after = self.key_status()
            self._alert("KEY_ROTATED", "info",
                        f"{role} rotated from key_id {old} ({self.signer.suite_for(old)}) to key_id {to_kid} "
                        f"({spec['suite']}). Key {old} is revoked onboard; frames signed with it are now refused. "
                        f"{role} frames are now {after['frame_bytes_typical'][role]} B (were "
                        f"{before['frame_bytes_typical'][role]} B): re-optimise the plan.",
                        role=role, from_kid=old, to_kid=to_kid, suite=spec["suite"])
            from ..common.atomic import append_jsonl

            append_jsonl(self.ev / "logs" / "key_events.jsonl",
                         {"time_utc": _utc(), "event": "rotate", "role": role, "from_kid": old, "to_kid": to_kid,
                          "suite": spec["suite"], "frames": steps, "sizes_before": before["frame_bytes_typical"],
                          "sizes_after": after["frame_bytes_typical"]})
            self.emit({"type": "keys", "phase": "rotated", "role": role, "to_kid": to_kid})
            return {"role": role, "from_kid": old, "to_kid": to_kid, "frames": steps, "before": before, "after": after}

    MAX_ATTEMPTS = 3

    def _uplink_command(self, c: Command, *, t: int, window: int, plan: dict, nonce: bytes, pace_ms: int,
                        attempt: int) -> dict:
        """Sign one queued command, transmit it and wait for the onboard acknowledgement."""
        assert self.signer is not None
        frame = self.signer.build(role=c.role, command=c.body, pass_nonce=nonce)
        data = frame.to_bytes()
        label = c.id if attempt == 1 else f"{c.id} retx{attempt - 1}"
        ev = {"window": window, "pass": t, "label": label, "cmd_id": c.id, "cmd_name": c.name,
              "counter": frame.counter, "bytes": len(data), "opcode_name": opcode_name(c.opcode),
              "role": c.role, "attempt": attempt}
        sha = hashlib.sha256(data).hexdigest()
        self._ledger(frame.counter, **{"cmd_id": c.id, "label": label, "pass": t, "window": window, "bytes": len(data),
                                       "sha256": sha, "attempt": attempt, "status": "SIGNED"})
        self._frame_event("signed", **ev)
        self._pace(pace_ms)
        base = {"cmd_id": c.id, "name": c.name, "counter": frame.counter, "bytes": len(data), "attempt": attempt}
        try:
            tx = self.link.transmit(data, label=c.id)
        except LinkBudgetExceeded as exc:
            self._ledger(frame.counter, status="REFUSED")
            self._frame_event("refused", **ev, error=str(exc), link=self.link.snapshot())
            return {**base, "verdict": "NOT_SENT", "reason": "LINK_BUDGET", "error": str(exc)}
        self._frame_event("tx", **ev, lost=tx["lost"], link=self.link.snapshot())
        self._pace(pace_ms)
        if tx["lost"]:
            self._pace(pace_ms)  # acknowledgement timeout
            self._ledger(frame.counter, status="NO_ACK")
            self._frame_event("no_ack", **ev, link=self.link.snapshot())
            self._alert("MISSING_PACKET", "warn",
                        f"No acknowledgement for {c.id} ({c.name}, counter {frame.counter}) in pass {t}. "
                        "Presumed lost on the link. It will be re-signed with a fresh counter, never resent "
                        "as-is: once a later frame is accepted, the old counter would be rejected as a replay.",
                        cmd_id=c.id, counter=frame.counter, pass_no=t, attempt=attempt)
            return {**base, "verdict": "NO_ACK", "reason": "ACK_TIMEOUT"}
        res = self._deliver(data, context={"window": window, "pass": t, "cmd_id": c.id, "attempt": attempt,
                                           "plan_job_id": plan["opt"].get("job_id")})
        self._frame_event("verdict", **ev, result=res, link=self.link.snapshot())
        self._pace(pace_ms)
        if attempt > 1 and res["verdict"] == "ACCEPT":
            self._alert("RETRANSMIT_OK", "info", f"{c.id} recovered: re-signed as counter {frame.counter} "
                        f"(attempt {attempt}) and acknowledged in pass {t}.", cmd_id=c.id, counter=frame.counter,
                        pass_no=t)
        return {**base, "verdict": res["verdict"], "reason": res["reason"], "steps": res["steps"],
                "counter_gap": res.get("counter_gap")}

    def run_pass(self, t: int, pace_ms: int = 300, *, drop: list[str] | None = None, loss_rate: float = 0.0,
                 seed: int | None = None) -> dict:
        """Execute pass t of the current, validated QpiAI Opt plan.

        Missing-packet handling: a command whose acknowledgement never arrives is
        re-signed and retransmitted later in the same pass if the byte budget allows;
        commands that depend on an unacknowledged command are held, never sent ahead
        of it; anything left is carried over for a QpiAI Opt re-plan."""
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
            delivered = self.delivered_commands()
            loss = None
            if drop or loss_rate:
                loss = self.link.set_loss(drop=drop, rate=loss_rate, seed=seed)
            results: list[dict] = []
            pending: list[str] = []
            attempts: dict[str, int] = {}
            kw = {"t": t, "window": opened["window"], "plan": plan, "nonce": nonce, "pace_ms": pace_ms}
            try:
                for cid in order_within_pass(inst, opt_plan, t):
                    c = by[cid]
                    if cid in delivered:
                        results.append({"cmd_id": cid, "name": c.name, "verdict": "SKIPPED", "reason": "ALREADY_DELIVERED",
                                        "note": f"acknowledged in pass {delivered[cid]}"})
                        continue
                    waiting = [d for d in c.depends_on if d not in delivered]
                    if waiting:
                        results.append({"cmd_id": cid, "name": c.name, "verdict": "HELD", "reason": "WAITING_FOR_DEPENDENCY",
                                        "waiting_for": waiting})
                        self._alert("DEPENDENCY_HOLD", "warn", f"{cid} ({c.name}) held: it depends on "
                                    f"{', '.join(waiting)}, which the spacecraft has not acknowledged. Not signed, "
                                    "no counter used.", cmd_id=cid, waiting_for=waiting, pass_no=t)
                        pending.append(cid)
                        continue
                    attempts[cid] = 1
                    r = self._uplink_command(c, attempt=1, **kw)
                    results.append(r)
                    if r["verdict"] == "ACCEPT":
                        delivered[cid] = t
                    elif r["verdict"] == "NO_ACK":
                        pending.append(cid)
                # recovery: re-sign lost frames, then release held dependents, while budget lasts
                progress = True
                while pending and progress:
                    progress = False
                    for cid in list(pending):
                        c = by[cid]
                        if any(d not in delivered for d in c.depends_on):
                            continue
                        if attempts.get(cid, 0) >= self.MAX_ATTEMPTS or not self.link.can_send(c.frame_bytes):
                            continue
                        attempts[cid] = attempts.get(cid, 0) + 1
                        r = self._uplink_command(c, attempt=attempts[cid], **kw)
                        results.append(r)
                        progress = True
                        if r["verdict"] != "NO_ACK":
                            pending.remove(cid)
                            if r["verdict"] == "ACCEPT":
                                delivered[cid] = t
            finally:
                self.link.clear_loss()
            carried = []
            for cid in pending:
                c = by[cid]
                waiting = [d for d in c.depends_on if d not in delivered]
                why = (f"waiting for {', '.join(waiting)}" if waiting else
                       f"{self.MAX_ATTEMPTS} attempts without acknowledgement" if attempts.get(cid, 0) >= self.MAX_ATTEMPTS
                       else f"no budget left in pass {t} ({self.link.snapshot()['remaining_bytes']} B < {c.frame_bytes} B)")
                carried.append({"cmd_id": cid, "name": c.name, "deadline_pass": c.deadline_pass, "reason": why})
            if carried:
                self._alert("CARRIED_OVER", "warn", f"{len(carried)} command(s) not delivered in pass {t}: "
                            + "; ".join(f"{x['cmd_id']} ({x['reason']})" for x in carried)
                            + ". Re-plan the remaining passes with QpiAI Opt.", carried=carried, pass_no=t)
            run = {"pass": t, "window": opened["window"], "time_utc": _utc(), "nonce": opened["nonce"],
                   "plan_job_id": plan["opt"].get("job_id"), "plan_execution_mode": plan["opt"]["execution_mode"],
                   "frames": results, "carried_over": carried, "loss_model": loss, "link": self.link.snapshot()}
            runs = read_json(self.passes_path, default={"runs": []}) or {"runs": []}
            runs["runs"].append(run)
            atomic_write_json(self.passes_path, runs)
            atomic_write_json(self.ev / "pass_runs.json", runs)
            self.emit({"type": "pass_done", "pass": t, "summary": {
                "accepted": sum(1 for r in results if r["verdict"] == "ACCEPT"),
                "rejected": sum(1 for r in results if r["verdict"] == "REJECT"),
                "not_sent": sum(1 for r in results if r["verdict"] == "NOT_SENT"),
                "no_ack": sum(1 for r in results if r["verdict"] == "NO_ACK"),
                "held": sum(1 for r in results if r["verdict"] == "HELD"),
                "carried_over": len(carried)}, "link": self.link.snapshot()})
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
                "alerts": {"total": len(self.alerts), "warnings": sum(1 for a in self.alerts if a["severity"] != "info"),
                           "latest": self.alerts[-1] if self.alerts else None},
                "keys": {"encrypted_at_rest": bool((getattr(self, "keys_meta", {}) or {}).get("encrypted_at_rest")),
                         "signing": self.signer.ring.snapshot()["signing"] if self.signer else None}}

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
