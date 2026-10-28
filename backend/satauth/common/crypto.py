"""Thin wrapper around the vetted signature implementation.

Library: ``pqcrypto==0.4.0`` (Python bindings to PQClean). ``falcon_padded_512``
produces fixed 666-byte Falcon-512 signatures. No primitive is implemented here;
this module only adapts the library API and checks its sizes at import time.

Note (FR-17 deviation): the library draws key-generation randomness from the
operating system CSPRNG internally and exposes no seed parameter, so QRNG output
cannot be mixed into Falcon key generation without patching the library. See
README "Deviations".
"""

from __future__ import annotations

from pqcrypto.sign import falcon_padded_512 as _falcon

from .frame import SIG_LEN

ALGORITHM = "Falcon-padded-512"
LIBRARY = "pqcrypto 0.4.0 (PQClean)"
PUBLIC_KEY_LEN = _falcon.PUBLIC_KEY_SIZE
SECRET_KEY_LEN = _falcon.SECRET_KEY_SIZE

if _falcon.SIGNATURE_SIZE != SIG_LEN:  # pragma: no cover - environment guard
    raise RuntimeError(f"Expected {SIG_LEN}-byte padded Falcon signatures, library reports {_falcon.SIGNATURE_SIZE}")


def generate_keypair() -> tuple[bytes, bytes]:
    pk, sk = _falcon.generate_keypair()
    return bytes(pk), bytes(sk)


def sign(secret_key: bytes, message: bytes) -> bytes:
    sig = bytes(_falcon.sign(secret_key, message))
    if len(sig) != SIG_LEN:  # pragma: no cover
        raise RuntimeError("unexpected signature length")
    return sig


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return True only for a valid signature. Never raises on bad input."""
    if len(signature) != SIG_LEN:
        return False
    try:
        return bool(_falcon.verify(public_key, message, signature))
    except Exception:
        return False
