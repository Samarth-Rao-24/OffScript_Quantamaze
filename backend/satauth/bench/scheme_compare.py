"""Signature-scheme comparison on one harness (FR-20).

Falcon-padded-512 (selected), Falcon-512 (variable length), ML-DSA-44 (FIPS 204)
from pqcrypto 0.4.0, and classical ECDSA P-256 / Ed25519 from the
``cryptography`` package as non-quantum-safe baselines. Emulated host timings.

    python -m satauth.bench.scheme_compare
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path

from ..common.atomic import atomic_write_json
from ..common.frame import HEADER_LEN
from .measure import summary_us

BODY_LEN = 12  # typical command body used for frame-size comparison
PASS_BUDGET = 3600


def _pqc(modname: str):
    import importlib

    m = importlib.import_module(f"pqcrypto.sign.{modname}")
    return (lambda: m.generate_keypair(), lambda sk, msg: m.sign(sk, msg), lambda pk, msg, s: m.verify(pk, msg, s))


def _ecdsa():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

    def kg():
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        return pk, sk

    def sign(sk, msg):  # fixed 64-byte r||s encoding
        r, s = decode_dss_signature(sk.sign(msg, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify(pk, msg, sig):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        try:
            pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    return kg, sign, verify, "ECDSA P-256 secret key (32 B scalar)"


def _ed25519():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def kg():
        sk = Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), sk

    def verify(pk, msg, sig):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except Exception:
            return False

    return kg, (lambda sk, msg: sk.sign(msg)), verify


SCHEMES = [
    ("Falcon-padded-512", "pqcrypto 0.4.0 / PQClean", True, "falcon_padded_512", True),
    ("Falcon-512 (compressed)", "pqcrypto 0.4.0 / PQClean", True, "falcon_512", False),
    ("ML-DSA-44 (FIPS 204)", "pqcrypto 0.4.0 / PQClean", True, "ml_dsa_44", False),
    ("ECDSA P-256", "cryptography (OpenSSL)", False, "ecdsa", False),
    ("Ed25519", "cryptography (OpenSSL)", False, "ed25519", False),
]


def bench_scheme(name, lib, pq, key, selected, n_sign=200, n_verify=1000) -> dict:
    if key == "ecdsa":
        kg, sign, verify, _ = _ecdsa()
    elif key == "ed25519":
        kg, sign, verify = _ed25519()
    else:
        kg, sign, verify = _pqc(key)
    kg_ns = []
    for _ in range(10):
        t0 = time.perf_counter_ns()
        pk, sk = kg()
        kg_ns.append(time.perf_counter_ns() - t0)
    msgs = [os.urandom(64) for _ in range(n_sign)]
    sign_ns, sigs = [], []
    for m in msgs:
        t0 = time.perf_counter_ns()
        s = sign(sk, m)
        sign_ns.append(time.perf_counter_ns() - t0)
        sigs.append(bytes(s))
    verify_ns = []
    for i in range(n_verify):
        m, s = msgs[i % n_sign], sigs[i % n_sign]
        t0 = time.perf_counter_ns()
        ok = verify(pk, m, s)
        verify_ns.append(time.perf_counter_ns() - t0)
        assert ok, name
    lens = [len(s) for s in sigs]
    max_sig = max(lens)
    frame = HEADER_LEN + BODY_LEN + max_sig
    sk_len = len(sk) if isinstance(sk, (bytes, bytearray)) else (32 if key in ("ecdsa", "ed25519") else None)
    return {
        "scheme": name, "library": lib, "quantum_safe": pq, "selected": selected,
        "public_key_bytes": len(pk), "secret_key_bytes": sk_len,
        "signature_bytes": {"min": min(lens), "max": max_sig, "mean": round(sum(lens) / len(lens), 1)},
        "frame_bytes_12B_body_worst_case": frame,
        "frames_per_3600B_pass": (PASS_BUDGET - 715) // frame,
        "keygen": summary_us(kg_ns), "sign": summary_us(sign_ns), "verify": summary_us(verify_ns),
    }


def run() -> dict:
    from ..api.service import MissionControl

    rows = [bench_scheme(*s) for s in SCHEMES]
    falcon = next(r for r in rows if r["selected"])
    mldsa = next(r for r in rows if r["scheme"].startswith("ML-DSA"))
    return {
        "kind": "scheme_compare",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "label": "EMULATED HOST MEASUREMENT - not flight hardware",
        "host": MissionControl.host_info(),
        "method": "time.perf_counter_ns; 10 keygens, 200 signs, 1000 verifies per scheme on random 64 B messages. "
                  "Frame size = 16 B header + 12 B body + worst observed signature. Classical schemes are baselines only.",
        "schemes": rows,
        "falcon_vs_mldsa_signature_saving_pct": round(100 * (1 - falcon["signature_bytes"]["max"] / mldsa["signature_bytes"]["max"]), 1),
    }


def main() -> None:
    from ..config import load_settings

    s = load_settings()
    res = run()
    out = Path(s.evidence_dir) / "bench"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    atomic_write_json(out / f"scheme_compare_{stamp}.json", res)
    atomic_write_json(out / "latest_scheme_compare.json", res)
    for r in res["schemes"]:
        print(f"{r['scheme']:<26} sig {r['signature_bytes']['max']:>5} B  verify p50 {r['verify']['p50_us']:>8} us")


if __name__ == "__main__":
    main()
