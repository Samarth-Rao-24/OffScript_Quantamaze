"""Shared fixtures. Every test gets its own keys, state file and log in tmp_path."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import satauth.config  # noqa: E402,F401  (loads the project .env so key-gated integration tests can run)
from satauth.common.roles import Opcode, Role, default_role_table  # noqa: E402
from satauth.ground.keygen import ensure_role_keys, load_public_keys  # noqa: E402
from satauth.ground.signer import Signer  # noqa: E402
from satauth.onboard.logger import AuditLog  # noqa: E402
from satauth.onboard.state import StateStore  # noqa: E402
from satauth.onboard.verifier import OnboardVerifier  # noqa: E402

SAT = 0x2A
FLOOD_N = 8


class Rig:
    """Ground signer + onboard verifier with one open pass."""

    def __init__(self, root: Path):
        self.root = root
        ensure_role_keys(root)
        self.state = StateStore(root / "onboard" / "state.json")
        self.genesis = os.urandom(32)
        self.state.provision(sat_id=SAT, public_keys=load_public_keys(root), role_table=default_role_table(),
                             genesis_nonce=self.genesis)
        self.log = AuditLog(root / "logs" / "onboard.jsonl")
        self.v = OnboardVerifier(self.state, self.log, FLOOD_N)
        self.signer = Signer(root, SAT)
        self.nonces = [self.genesis]
        self.window = 0
        self.open_pass()

    @property
    def nonce(self) -> bytes:
        return self.nonces[-1]

    def open_pass(self) -> dict:
        self.window += 1
        self.v.begin_window(self.window)
        new = os.urandom(32)
        po = self.signer.pass_open(new_nonce=new, current_nonce=self.nonce)
        r = self.v.process(po.to_bytes())
        assert r["reason"] == "OK", r
        self.nonces.append(new)
        return r

    def frame(self, role=Role.OPERATOR, opcode=Opcode.CAPTURE_IMAGE, args=b"\x01\x02", **kw):
        kw.setdefault("pass_nonce", self.nonce)
        return self.signer.build(role=role, command=bytes([opcode]) + args, **kw)

    def send(self, data: bytes) -> dict:
        return self.v.process(data)


@pytest.fixture
def rig(tmp_path) -> Rig:
    return Rig(tmp_path)


_results: list[dict] = []


def pytest_runtest_logreport(report):
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        _results.append({"test": report.nodeid, "outcome": report.outcome, "duration_s": round(report.duration, 4)})


def pytest_sessionfinish(session, exitstatus):
    """Write a machine-readable summary into evidence/tests/ for the Evidence screen."""
    out_dir = Path(os.environ.get("QUPLINK_EVIDENCE_DIR", BACKEND.parent / "evidence")) / "tests"
    if os.environ.get("QUPLINK_NO_TEST_SUMMARY"):
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for r in _results:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    (out_dir / "summary.json").write_text(json.dumps({
        "finished_utc": datetime.now(timezone.utc).isoformat(), "exit_status": int(exitstatus),
        "counts": counts, "total": len(_results), "results": _results,
        "python": sys.version.split()[0], "platform": sys.platform,
    }, indent=2))
