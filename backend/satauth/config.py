"""Central configuration.

All secrets come from environment variables, loaded from the project-root
``.env`` file. Secrets are never logged, returned by the API, or sent to the
browser; only "is it configured?" booleans leave this module.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# backend/satauth/config.py -> project root is two levels above backend/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if os.environ.get("QUPLINK_NO_DOTENV") != "1":  # tests that must run key-free set this
    load_dotenv(PROJECT_ROOT / ".env", override=False)


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw is not None else default


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    evidence_dir: Path
    sat_id: int
    flood_limit: int
    default_expiry_s: int
    opt_mode: str  # "platform" (records job_id, may use credits) | "local" (free, no job_id)
    qrng_device: str
    qrng_qubits: int
    qrng_shots: int
    qaoa_device: str
    qaoa_mode: str  # "platform" | "local"
    qaoa_max_iterations: int
    qaoa_reps: int
    qaoa_shots: int
    allow_dev_nonce: bool
    allow_local_qrng: bool
    pass_budgets: list[int] = field(default_factory=list)

    # --- secrets: never serialise these ---
    @property
    def opt_api_key(self) -> str | None:
        return _env("QPIAI_OPT_API_KEY")

    @property
    def qcloud_api_key(self) -> str | None:
        # Project convention is QPIAI_QCLOUD_API_KEY; the earlier poc used
        # QCLOUD_API_KEY and the SDK itself reads API_KEY from qcloud.env.
        return _env("QPIAI_QCLOUD_API_KEY") or _env("QCLOUD_API_KEY")

    def public_status(self) -> dict:
        """Safe-to-display configuration (no secret values)."""
        return {
            "opt_key_configured": self.opt_api_key is not None,
            "qcloud_key_configured": self.qcloud_api_key is not None,
            "opt_mode": self.opt_mode,
            "qrng_device": self.qrng_device,
            "qrng_qubits": self.qrng_qubits,
            "qrng_shots": self.qrng_shots,
            "qaoa_device": self.qaoa_device,
            "qaoa_mode": self.qaoa_mode,
            "qaoa_max_iterations": self.qaoa_max_iterations,
            "allow_dev_nonce": self.allow_dev_nonce,
            "allow_local_qrng": self.allow_local_qrng,
            "sat_id": self.sat_id,
            "flood_limit": self.flood_limit,
            "pass_budgets": self.pass_budgets,
        }


def load_settings() -> Settings:
    data_dir = Path(_env("QUPLINK_DATA_DIR", str(PROJECT_ROOT / "data")))
    evidence_dir = Path(_env("QUPLINK_EVIDENCE_DIR", str(PROJECT_ROOT / "evidence")))
    budgets_raw = _env("QUPLINK_PASS_BUDGETS", "3600,3600,2900,2200")
    budgets = [int(b) for b in budgets_raw.split(",") if b.strip()]
    opt_mode = _env("QUPLINK_OPT_MODE", "local")
    qaoa_mode = _env("QUPLINK_QAOA_MODE", "local")
    if opt_mode not in ("platform", "platform-qubo", "local"):
        raise ValueError("QUPLINK_OPT_MODE must be 'platform', 'platform-qubo' or 'local'")
    if qaoa_mode not in ("platform", "local"):
        raise ValueError("QUPLINK_QAOA_MODE must be 'platform' or 'local'")
    return Settings(
        data_dir=data_dir,
        evidence_dir=evidence_dir,
        sat_id=_env_int("QUPLINK_SAT_ID", 0x2A),
        flood_limit=_env_int("QUPLINK_FLOOD_LIMIT", 8),
        default_expiry_s=_env_int("QUPLINK_DEFAULT_EXPIRY_S", 600),
        opt_mode=opt_mode,
        qrng_device=_env("QUPLINK_QRNG_DEVICE", "QpiAI-QSV-Local"),
        qrng_qubits=_env_int("QUPLINK_QRNG_QUBITS", 8),
        qrng_shots=_env_int("QUPLINK_QRNG_SHOTS", 1024),
        qaoa_device=_env("QUPLINK_QAOA_DEVICE", "QpiAI-QSV-Simulator"),
        qaoa_mode=qaoa_mode,
        qaoa_max_iterations=_env_int("QUPLINK_QAOA_MAX_ITERATIONS", 30),
        qaoa_reps=_env_int("QUPLINK_QAOA_REPS", 1),
        qaoa_shots=_env_int("QUPLINK_QAOA_SHOTS", 1024),
        allow_dev_nonce=(_env("QUPLINK_ALLOW_DEV_NONCE", "false") or "false").lower() == "true",
        allow_local_qrng=(_env("QUPLINK_ALLOW_LOCAL_QRNG", "true") or "true").lower() == "true",
        pass_budgets=budgets,
    )
