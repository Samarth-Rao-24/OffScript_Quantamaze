"""QCloud quantum randomness for pass nonces and attack fuzzing (FR-14; PRD 11.2).

Mechanism (the PRD's documented fallback, because ``qpiai_quantum.QRNG`` in the
SDK version pinned by qpiai-opt[quantum] (0.3.0) cannot target a cloud device):
an n-qubit circuit applies H to every qubit and measures, and the circuit is
executed on QCloud with ``Circuit.run(device_name=...)``. Each run returns a
genuine QCloud ``job_id`` and the measurement **counts** (QCloud reports
aggregated counts, not per-shot order).

Honesty labels: only ``QpiAI-Indus-1`` (QPU) yields physical quantum randomness.
QCloud simulators and the in-process local simulator sample with a classical
PRNG; their output is recorded as such.

Pass nonce derivation (reproducible from recorded inputs; the nonce is public,
it travels in PASS_OPEN):

    nonce = SHA-256("Q-UPLINK/NONCE/v1" || os_entropy(32) || SHA-256(counts) || job_id || pass_no)

The OS CSPRNG always contributes, so QRNG is an additional source, never the
only one. One QCloud job is consumed per pass nonce.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import append_jsonl, atomic_write_json, read_json

HARDWARE_DEVICES = {"QpiAI-Indus-1"}
CLOUD_SIMULATORS = {"QpiAI-QSV-Simulator", "QpiAI-QDM-Simulator", "QpiAI-QTN-Simulator", "QpiAI-QSV-Lite", "QpiAI-QDM-Lite"}
LOCAL_DEVICE = "QpiAI-QSV-Local"


class NonceUnavailable(RuntimeError):
    pass


def randomness_class(device: str) -> str:
    if device in HARDWARE_DEVICES:
        return "quantum-hardware"
    if device in CLOUD_SIMULATORS:
        return "qcloud-simulator (classical PRNG sampling)"
    if device == LOCAL_DEVICE:
        return "local-simulator (classical PRNG sampling, not a cloud run)"
    return "unknown"


def counts_digest(counts: dict[str, int]) -> bytes:
    canonical = json.dumps({k: int(v) for k, v in sorted(counts.items())}, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode()).digest()


def derive_nonce(os_entropy: bytes, counts: dict[str, int], job_id: str, pass_no: int) -> bytes:
    h = hashlib.sha256()
    h.update(b"Q-UPLINK/NONCE/v1")
    h.update(os_entropy)
    h.update(counts_digest(counts))
    h.update(job_id.encode())
    h.update(pass_no.to_bytes(4, "big"))
    return h.digest()


def fuzz_seed_from(counts: dict[str, int], job_id: str) -> bytes:
    return hashlib.sha256(b"Q-UPLINK/FUZZ/v1" + counts_digest(counts) + job_id.encode()).digest()


class FuzzStream:
    """Deterministic byte stream (SHAKE-256) from a recorded seed, so every
    attack-input choice can be replayed exactly."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self._pos = 0

    def bytes(self, n: int) -> bytes:
        out = hashlib.shake_256(self.seed).digest(self._pos + n)[self._pos :]
        self._pos += n
        return out

    def below(self, n: int) -> int:
        """Uniform integer in [0, n) by rejection sampling."""
        if n <= 0:
            raise ValueError("n must be positive")
        k = (n - 1).bit_length() or 1
        nbytes = (k + 7) // 8
        mask = (1 << k) - 1
        while True:
            v = int.from_bytes(self.bytes(nbytes), "big") & mask
            if v < n:
                return v


class QRNGPool:
    def __init__(self, data_dir: Path, evidence_dir: Path, *, api_key: str | None, n_qubits: int = 8,
                 shots: int = 1024, default_device: str = "QpiAI-Indus-1", allow_dev_nonce: bool = False):
        self.index_path = Path(data_dir) / "ground" / "qrng_pool.json"
        self.jobs_dir = Path(evidence_dir) / "qcloud_jobs"
        self.nonce_log = self.jobs_dir / "nonce_derivations.jsonl"
        self.api_key = api_key
        self.n_qubits = n_qubits
        self.shots = shots
        self.default_device = default_device
        self.allow_dev_nonce = allow_dev_nonce
        self._lock = threading.Lock()

    # ---- pool index ----
    def _index(self) -> dict:
        return read_json(self.index_path, default={"entries": []}) or {"entries": []}

    def entries(self) -> list[dict]:
        return self._index()["entries"]

    def status(self) -> dict:
        ents = self.entries()
        usable = [e for e in ents if not e.get("nonce_used") and self._usable_for_nonce(e)]
        return {
            "entries": ents,
            "unused_for_nonce": len(usable),
            "default_device": self.default_device,
            "n_qubits": self.n_qubits,
            "shots": self.shots,
            "allow_dev_nonce": self.allow_dev_nonce,
        }

    def _usable_for_nonce(self, e: dict) -> bool:
        if e["device"] == LOCAL_DEVICE:
            return self.allow_dev_nonce
        return bool(e.get("job_id"))

    def load_record(self, entry: dict) -> dict:
        return read_json(self.jobs_dir / entry["file"])

    # ---- QCloud execution ----
    def fetch(self, device: str | None = None) -> dict:
        """Run one Hadamard-measure circuit and record it. May consume QCloud credits."""
        device = device or self.default_device
        from qpiai_quantum import Circuit, QpiAIQuantumAuth

        if device != LOCAL_DEVICE:
            if not self.api_key:
                raise RuntimeError("QPIAI_QCLOUD_API_KEY is not set in .env; cannot run a QCloud job.")
            QpiAIQuantumAuth.login(api_key=self.api_key)
        n = self.n_qubits
        circ = Circuit(n, n)
        for q in range(n):
            circ.h(q)
        circ.measure(list(range(n)), list(range(n)))
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        res = circ.run(shots=self.shots, experiment_name="q-uplink-qrng", device_name=device)
        wall = time.perf_counter() - t0
        counts = {str(k): int(v) for k, v in (res.counts or {}).items()}
        job_id = getattr(res, "job_id", None)
        if device != LOCAL_DEVICE and not job_id:
            raise RuntimeError("QCloud returned no job_id; result not recorded (no IDs are fabricated).")
        if sum(counts.values()) != self.shots:
            raise RuntimeError(f"QCloud returned {sum(counts.values())} shots, expected {self.shots}")
        record = {
            "kind": "qrng",
            "job_id": job_id,
            "device": device,
            "randomness_class": randomness_class(device),
            "circuit": f"{n} qubits: H on each, measure all",
            "n_qubits": n,
            "shots": self.shots,
            "counts": counts,
            "distinct_outcomes": len(counts),
            "counts_sha256": counts_digest(counts).hex(),
            "job_status": getattr(res, "job_status", None),
            "credits_used": getattr(res, "credits_used", None),
            "execution_time": getattr(res, "execution_time", None),
            "started_utc": started.isoformat(),
            "wall_time_s": round(wall, 3),
            "sdk": _sdk_versions(),
        }
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        fname = f"qrng_{stamp}_{(job_id or 'local')[:36]}.json".replace("/", "_")
        atomic_write_json(self.jobs_dir / fname, record)
        with self._lock:
            idx = self._index()
            idx["entries"].append({
                "file": fname, "job_id": job_id, "device": device, "randomness_class": record["randomness_class"],
                "created_utc": record["started_utc"], "nonce_used": False, "used_for_pass": None,
            })
            atomic_write_json(self.index_path, idx)
        return record

    # ---- consumers ----
    def take_nonce(self, pass_no: int) -> dict:
        with self._lock:
            idx = self._index()
            entry = next((e for e in idx["entries"] if not e.get("nonce_used") and self._usable_for_nonce(e)), None)
            os_entropy = os.urandom(32)
            if entry is None:
                if not self.allow_dev_nonce:
                    raise NonceUnavailable(
                        "No unused QCloud QRNG job in the pool. Run 'Fetch QRNG' (QCloud) first. "
                        "Set QUPLINK_ALLOW_DEV_NONCE=true only for offline development (nonces are then labelled DEV)."
                    )
                nonce = hashlib.sha256(b"Q-UPLINK/NONCE/DEV-OS-ONLY/v1" + os_entropy + pass_no.to_bytes(4, "big")).digest()
                rec = {"pass": pass_no, "nonce": nonce.hex(), "source": "DEV: OS CSPRNG only (no QCloud job)",
                       "job_id": None, "device": None, "randomness_class": "development-only",
                       "os_entropy_hex": os_entropy.hex(), "time_utc": datetime.now(timezone.utc).isoformat()}
                append_jsonl(self.nonce_log, rec)
                return {**rec, "nonce_bytes": nonce}
            record = read_json(self.jobs_dir / entry["file"])
            nonce = derive_nonce(os_entropy, record["counts"], entry["job_id"] or "local", pass_no)
            entry["nonce_used"] = True
            entry["used_for_pass"] = pass_no
            atomic_write_json(self.index_path, idx)
            rec = {"pass": pass_no, "nonce": nonce.hex(),
                   "source": f"SHA-256(OS 32 B || QCloud counts digest || job_id || pass)",
                   "job_id": entry["job_id"], "device": entry["device"], "randomness_class": entry["randomness_class"],
                   "qrng_file": entry["file"], "counts_sha256": record["counts_sha256"],
                   "os_entropy_hex": os_entropy.hex(), "time_utc": datetime.now(timezone.utc).isoformat()}
            append_jsonl(self.nonce_log, rec)
            return {**rec, "nonce_bytes": nonce}

    def fuzz_stream(self) -> tuple[FuzzStream, dict]:
        """Attack-input stream seeded from the newest recorded QRNG job."""
        ents = [e for e in self.entries() if e.get("job_id") or self.allow_dev_nonce]
        if not ents:
            seed = hashlib.sha256(b"Q-UPLINK/FUZZ/FIXED-TEST-SEED/v1").digest()
            return FuzzStream(seed), {"fuzz_seed": seed.hex(), "source": "fixed test seed (no QRNG job recorded yet)",
                                      "job_id": None}
        e = ents[-1]
        rec = read_json(self.jobs_dir / e["file"])
        seed = fuzz_seed_from(rec["counts"], e.get("job_id") or "local")
        return FuzzStream(seed), {"fuzz_seed": seed.hex(), "source": (f"QCloud QRNG job {e['job_id']} ({e['device']})" if e.get("job_id")
                                             else f"local simulator QRNG run, no job ID ({e['device']}, dev only)"),
                                  "job_id": e.get("job_id"), "randomness_class": e["randomness_class"]}


def _sdk_versions() -> dict:
    from importlib.metadata import PackageNotFoundError, version

    out = {}
    for pkg in ("qpiai-quantum", "qpiai-opt"):
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = None
    return out
