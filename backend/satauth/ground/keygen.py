"""Ground key ring (FR-01) with rotation spares, migration suites and keys encrypted at rest.

The ring (``KEY_RING_SPEC`` in roles.py) is generated once and pre-loaded onboard
at provisioning: a primary Falcon-512 key per role, a Falcon-512 spare per role
for routine rotation, and ML-DSA-44 and hybrid Ed25519 + Falcon-512 keys per
role for algorithm migration. Only the primaries start active; the others are
standby until an ADMIN-signed KEY_ACTIVATE frame turns them on.

Private keys live under data/ground/keys/ (git-ignored, never served by the
API). When ``QUPLINK_KEY_PASSPHRASE`` is set, each private key is stored
encrypted: scrypt (n=2^15, r=8, p=1) derives a 256-bit key from the passphrase
and a random salt, and AES-256-GCM seals the key bytes with the key id as
associated data. Plaintext key files from earlier runs are encrypted and then
removed at start-up. Without a passphrase keys stay in plaintext and the app
says so. In production the ground keys belong in an HSM.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..common import suites
from ..common.atomic import atomic_write_bytes, atomic_write_json, read_json
from ..common.roles import KEY_RING_SPEC, ROLE_KEY_ID, ROLES


class KeyUnavailable(RuntimeError):
    pass


def keys_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "ground" / "keys"


def _passphrase() -> bytes | None:
    p = os.environ.get("QUPLINK_KEY_PASSPHRASE")
    return p.encode() if p else None


def _kdf(passphrase: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase)


def _seal(kid: int, sk: bytes, passphrase: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_kdf(passphrase, salt)).encrypt(nonce, sk, f"q-uplink-key:{kid}".encode())
    return json.dumps({"format": "q-uplink-sealed-key/1", "kdf": "scrypt", "n": 2 ** 15, "r": 8, "p": 1,
                       "aead": "AES-256-GCM", "key_id": kid, "salt": salt.hex(), "nonce": nonce.hex(),
                       "ciphertext": ct.hex()}).encode()


def _open(kid: int, blob: bytes, passphrase: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    d = json.loads(blob)
    try:
        return AESGCM(_kdf(passphrase, bytes.fromhex(d["salt"]))).decrypt(
            bytes.fromhex(d["nonce"]), bytes.fromhex(d["ciphertext"]), f"q-uplink-key:{kid}".encode())
    except Exception as exc:
        raise KeyUnavailable(f"cannot decrypt key {kid}: wrong QUPLINK_KEY_PASSPHRASE?") from exc


def _paths(data_dir: Path, kid: int) -> tuple[Path, Path, Path]:
    k = keys_dir(data_dir)
    return k / f"k{kid}.pk", k / f"k{kid}.sk", k / f"k{kid}.sk.enc"


def _store_secret(data_dir: Path, kid: int, sk: bytes) -> None:
    _, plain, sealed = _paths(data_dir, kid)
    pw = _passphrase()
    if pw:
        atomic_write_bytes(sealed, _seal(kid, sk, pw))
        if _open(kid, sealed.read_bytes(), pw) != sk:  # pragma: no cover - paranoia before removing plaintext
            raise KeyUnavailable(f"sealed key {kid} did not round-trip")
        if plain.exists():
            plain.unlink()
    else:
        atomic_write_bytes(plain, sk)


def _migrate_legacy(data_dir: Path) -> None:
    """Earlier builds stored operator.sk/pk and admin.sk/pk: adopt them as keys 1 and 2."""
    k = keys_dir(data_dir)
    for role in ROLES:
        kid = ROLE_KEY_ID[role]
        old_pk, old_sk = k / f"{role.lower()}.pk", k / f"{role.lower()}.sk"
        pk_path, plain, sealed = _paths(data_dir, kid)
        if old_pk.exists() and old_sk.exists() and not pk_path.exists():
            atomic_write_bytes(pk_path, old_pk.read_bytes())
            _store_secret(data_dir, kid, old_sk.read_bytes())
            old_sk.unlink()  # the key now lives under its key id (sealed if a passphrase is set)
            old_pk.unlink()


def ensure_role_keys(data_dir: Path) -> dict:
    """Create any missing key in the ring, seal plaintext keys if a passphrase is set,
    and return public metadata: {"keys": {kid: {...}}, "encrypted_at_rest": bool}."""
    kdir = keys_dir(data_dir)
    kdir.mkdir(parents=True, exist_ok=True)
    _migrate_legacy(data_dir)
    meta_path = kdir / "keys_meta.json"
    meta = read_json(meta_path, default={}) or {}
    ring = meta.get("keys") or {}
    changed = False
    pw = _passphrase()
    for kid, role, suite, _state in KEY_RING_SPEC:
        pk_path, plain, sealed = _paths(data_dir, kid)
        if not (pk_path.exists() and (plain.exists() or sealed.exists())):
            pk, sk = suites.generate_keypair(suite)
            atomic_write_bytes(pk_path, pk)
            _store_secret(data_dir, kid, sk)
            ring[str(kid)] = {
                "key_id": kid, "role": role, "suite": suite, "algorithm": suites.SUITES[suite]["name"],
                "public_key_sha256": hashlib.sha256(pk).hexdigest(), "public_key_len": len(pk),
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "entropy_source": "OS CSPRNG via library (QRNG seeding not supported by library; see README deviations)",
            }
            changed = True
        elif str(kid) not in ring:
            pk = pk_path.read_bytes()
            ring[str(kid)] = {"key_id": kid, "role": role, "suite": suite, "algorithm": suites.SUITES[suite]["name"],
                              "public_key_sha256": hashlib.sha256(pk).hexdigest(), "public_key_len": len(pk),
                              "created_utc": None, "entropy_source": "OS CSPRNG via library"}
            changed = True
        if pw and plain.exists():  # a passphrase was added since the key was made: seal it now
            _store_secret(data_dir, kid, plain.read_bytes())
    enc = all(_paths(data_dir, kid)[2].exists() and not _paths(data_dir, kid)[1].exists()
              for kid, *_ in KEY_RING_SPEC)
    new_meta = {"keys": ring, "encrypted_at_rest": enc,
                "at_rest": ("scrypt + AES-256-GCM, passphrase from QUPLINK_KEY_PASSPHRASE" if enc
                            else "PLAINTEXT: set QUPLINK_KEY_PASSPHRASE in .env to encrypt private keys")}
    if changed or meta != new_meta:
        atomic_write_json(meta_path, new_meta)
    return new_meta


def load_secret_key(data_dir: Path, key_id: int) -> bytes:
    _, plain, sealed = _paths(data_dir, int(key_id))
    if sealed.exists():
        pw = _passphrase()
        if not pw:
            raise KeyUnavailable(f"key {key_id} is encrypted at rest; set QUPLINK_KEY_PASSPHRASE")
        return _open(int(key_id), sealed.read_bytes(), pw)
    if plain.exists():
        return plain.read_bytes()
    raise KeyUnavailable(f"no private key for key_id {key_id}")


def load_public_keys(data_dir: Path) -> dict[int, bytes]:
    """key_id -> public key bytes for the whole ring (what gets pre-loaded onboard)."""
    return {kid: _paths(data_dir, kid)[0].read_bytes() for kid, *_ in KEY_RING_SPEC}


def ring_spec() -> dict[int, dict]:
    """key_id -> {role, suite, initial state} as provisioned onboard."""
    return {kid: {"role": role, "suite": suite, "state": state} for kid, role, suite, state in KEY_RING_SPEC}
