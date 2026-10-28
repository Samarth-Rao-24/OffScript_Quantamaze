"""Run the onboard verifier as a separate OS process (PRD section 10).

The ground/API process only ever exchanges *bytes* with the satellite process
over a pipe, mimicking an RF link: it cannot reach into onboard memory. The
satellite process owns its own state file and audit log.
"""

from __future__ import annotations

import multiprocessing as mp
import threading
from pathlib import Path


def _satellite_main(conn, state_path: str, log_path: str, flood_limit: int) -> None:
    from .verifier import build_verifier

    verifier = build_verifier(Path(state_path), Path(log_path), flood_limit)
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            break
        op = msg.get("op")
        try:
            if op == "frame":
                out = verifier.process(bytes.fromhex(msg["hex"]), now=msg.get("now"), context=msg.get("context"))
            elif op == "begin_window":
                out = verifier.begin_window(int(msg["window_id"]))
            elif op == "state":
                out = verifier.snapshot()
            elif op == "reload":  # simulate reboot: re-read NV state, volatile counters reset
                verifier.state.reload()
                verifier.guard.begin_window(verifier.guard.window_id)
                out = verifier.snapshot()
            elif op == "stop":
                conn.send({"ok": True, "result": None})
                break
            else:
                raise ValueError(f"unknown op {op!r}")
            conn.send({"ok": True, "result": out})
        except Exception as exc:  # report, never crash the satellite loop
            conn.send({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    conn.close()


class SatelliteProcess:
    """Client handle for the onboard process. Thread-safe."""

    def __init__(self, state_path: Path, log_path: Path, flood_limit: int):
        ctx = mp.get_context("spawn")  # same behaviour on Windows and Linux
        self._parent, child = ctx.Pipe()
        self._proc = ctx.Process(
            target=_satellite_main,
            args=(child, str(state_path), str(log_path), flood_limit),
            daemon=True,
            name="q-uplink-satellite",
        )
        self._proc.start()
        child.close()
        self._lock = threading.Lock()

    def _call(self, msg: dict):
        with self._lock:
            self._parent.send(msg)
            reply = self._parent.recv()
        if not reply["ok"]:
            raise RuntimeError(reply["error"])
        return reply["result"]

    def send_frame(self, data: bytes, *, now: float | None = None, context: dict | None = None) -> dict:
        return self._call({"op": "frame", "hex": data.hex(), "now": now, "context": context})

    def begin_window(self, window_id: int) -> dict:
        return self._call({"op": "begin_window", "window_id": window_id})

    def state(self) -> dict:
        return self._call({"op": "state"})

    def reboot(self) -> dict:
        return self._call({"op": "reload"})

    @property
    def pid(self) -> int | None:
        return self._proc.pid

    def alive(self) -> bool:
        return self._proc.is_alive()

    def stop(self) -> None:
        if self._proc.is_alive():
            try:
                self._call({"op": "stop"})
            except Exception:
                pass
            self._proc.join(timeout=5)
            if self._proc.is_alive():
                self._proc.terminate()
