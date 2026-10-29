"""Signature suites: crypto agility for migration.

Every onboard key carries exactly one suite, fixed when the key is provisioned.
The satellite takes the algorithm from the key named by ``key_id``, never from
anything an attacker can set in the frame, so a frame cannot downgrade itself
to a weaker algorithm.

Moving a fleet from one algorithm to another is therefore a key rotation:
activate a pre-loaded key of the new suite, then revoke the old key.

| suite      | signature | standard status                                   |
| falcon512  | 666 B     | NIST-selected (FN-DSA, FIPS 206 in draft)         |
| mldsa44    | 2420 B    | FIPS 204 (final)                                  |
| hybrid     | 730 B     | Ed25519 + Falcon-512; both must verify            |

Every primitive comes from a vetted library (PQClean via pqcrypto 0.4.0, and
OpenSSL via ``cryptography``). Nothing here implements cryptography itself.
"""

from __future__ import annotations

from pqcrypto.sign import falcon_padded_512 as _falcon
from pqcrypto.sign import ml_dsa_44 as _mldsa

ED25519_PK, ED25519_SK, ED25519_SIG = 32, 32, 64

SUITES: dict[str, dict] = {
    "falcon512": {"name": "Falcon-padded-512", "sig_len": _falcon.SIGNATURE_SIZE, "pk_len": _falcon.PUBLIC_KEY_SIZE,
                  "quantum_safe": True, "standard": "NIST-selected; FN-DSA (FIPS 206) in draft",
                  "library": "pqcrypto 0.4.0 (PQClean)"},
    "mldsa44": {"name": "ML-DSA-44", "sig_len": _mldsa.SIGNATURE_SIZE, "pk_len": _mldsa.PUBLIC_KEY_SIZE,
                "quantum_safe": True, "standard": "FIPS 204 (final)", "library": "pqcrypto 0.4.0 (PQClean)"},
    "hybrid": {"name": "Hybrid Ed25519 + Falcon-512", "sig_len": ED25519_SIG + _falcon.SIGNATURE_SIZE,
               "pk_len": ED25519_PK + _falcon.PUBLIC_KEY_SIZE, "quantum_safe": True,
               "standard": "Ed25519 (RFC 8032) AND Falcon-512: secure while either holds",
               "library": "cryptography (OpenSSL) + pqcrypto 0.4.0 (PQClean)"},
}
DEFAULT_SUITE = "falcon512"

from .frame import SIG_LENGTHS  # noqa: E402

assert sorted(s["sig_len"] for s in SUITES.values()) == sorted(SIG_LENGTHS), "frame.SIG_LENGTHS out of sync"
MIN_SIG_LEN = min(s["sig_len"] for s in SUITES.values())
MAX_SIG_LEN = max(s["sig_len"] for s in SUITES.values())


def info(suite: str) -> dict:
    if suite not in SUITES:
        raise ValueError(f"unknown signature suite {suite!r}")
    return {"suite": suite, **SUITES[suite]}


def _ed_keypair() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    raw = serialization.Encoding.Raw
    pk = sk.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    skb = sk.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return pk, skb


def generate_keypair(suite: str) -> tuple[bytes, bytes]:
    info(suite)
    if suite == "falcon512":
        pk, sk = _falcon.generate_keypair()
        return bytes(pk), bytes(sk)
    if suite == "mldsa44":
        pk, sk = _mldsa.generate_keypair()
        return bytes(pk), bytes(sk)
    epk, esk = _ed_keypair()
    fpk, fsk = _falcon.generate_keypair()
    return epk + bytes(fpk), esk + bytes(fsk)


def sign(suite: str, secret_key: bytes, message: bytes) -> bytes:
    info(suite)
    if suite == "falcon512":
        sig = bytes(_falcon.sign(secret_key, message))
    elif suite == "mldsa44":
        sig = bytes(_mldsa.sign(secret_key, message))
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        ed = Ed25519PrivateKey.from_private_bytes(secret_key[:ED25519_SK]).sign(message)
        sig = ed + bytes(_falcon.sign(secret_key[ED25519_SK:], message))
    if len(sig) != SUITES[suite]["sig_len"]:  # pragma: no cover - library guard
        raise RuntimeError(f"unexpected {suite} signature length {len(sig)}")
    return sig


def verify(suite: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True only for a valid signature of exactly the suite's length. Never raises."""
    try:
        if suite not in SUITES or len(signature) != SUITES[suite]["sig_len"]:
            return False
        if suite == "falcon512":
            return bool(_falcon.verify(public_key, message, signature))
        if suite == "mldsa44":
            return bool(_mldsa.verify(public_key, message, signature))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key[:ED25519_PK]).verify(signature[:ED25519_SIG], message)
        return bool(_falcon.verify(public_key[ED25519_PK:], message, signature[ED25519_SIG:]))
    except Exception:
        return False
