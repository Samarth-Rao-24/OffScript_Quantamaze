"""Ground key generation (FR-01).

One Falcon-512 key pair per role. Secret keys stay under data/ground/keys/ (git
ignored, never served by the API). Public keys are exported for onboard
provisioning (FR-02).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..common import crypto
from ..common.atomic import atomic_write_bytes, atomic_write_json, read_json
from ..common.roles import ROLE_KEY_ID, ROLES


def keys_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "ground" / "keys"


def ensure_role_keys(data_dir: Path) -> dict:
    """Create missing role key pairs; return public metadata for every role."""
    kdir = keys_dir(data_dir)
    kdir.mkdir(parents=True, exist_ok=True)
    meta_path = kdir / "keys_meta.json"
    meta = read_json(meta_path, default={}) or {}
    changed = False
    for role in ROLES:
        sk_path, pk_path = kdir / f"{role.lower()}.sk", kdir / f"{role.lower()}.pk"
        if not (sk_path.exists() and pk_path.exists()):
            pk, sk = crypto.generate_keypair()
            atomic_write_bytes(sk_path, sk)
            atomic_write_bytes(pk_path, pk)
            meta[role] = {
                "role": role,
                "key_id": ROLE_KEY_ID[role],
                "algorithm": crypto.ALGORITHM,
                "library": crypto.LIBRARY,
                "public_key_sha256": hashlib.sha256(pk).hexdigest(),
                "public_key_len": len(pk),
                "secret_key_len": len(sk),
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "entropy_source": "OS CSPRNG via library (QRNG seeding not supported by library; see README deviations)",
            }
            changed = True
    if changed:
        atomic_write_json(meta_path, meta)
    return meta


def load_secret_key(data_dir: Path, role: str) -> bytes:
    return (keys_dir(data_dir) / f"{role.lower()}.sk").read_bytes()


def load_public_keys(data_dir: Path) -> dict[int, bytes]:
    """key_id -> public key bytes (what gets preloaded onboard)."""
    out: dict[int, bytes] = {}
    for role in ROLES:
        out[ROLE_KEY_ID[role]] = (keys_dir(data_dir) / f"{role.lower()}.pk").read_bytes()
    return out
