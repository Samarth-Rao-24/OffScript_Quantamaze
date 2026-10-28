"""QRNG pool, nonce derivation and fuzz stream."""

from __future__ import annotations

import os

import pytest

from satauth.common.atomic import atomic_write_json
from satauth.ground.qrng import FuzzStream, NonceUnavailable, QRNGPool, derive_nonce, randomness_class


def test_nonce_derivation_reproducible_and_input_sensitive():
    os_e, counts = bytes(32), {"0101": 3, "1100": 1}
    n = derive_nonce(os_e, counts, "job-1", 1)
    assert n == derive_nonce(os_e, counts, "job-1", 1) and len(n) == 32
    assert n != derive_nonce(b"\x01" * 32, counts, "job-1", 1)
    assert n != derive_nonce(os_e, {"0101": 2, "1100": 2}, "job-1", 1)
    assert n != derive_nonce(os_e, counts, "job-2", 1)
    assert n != derive_nonce(os_e, counts, "job-1", 2)


def test_fuzz_stream_deterministic_and_bounded():
    a, b = FuzzStream(b"s" * 32), FuzzStream(b"s" * 32)
    assert a.bytes(100) == b.bytes(100)
    vals = [a.below(37) for _ in range(2000)]
    assert min(vals) == 0 and max(vals) == 36


def test_labels():
    assert randomness_class("QpiAI-Indus-1") == "quantum-hardware"
    assert "PRNG" in randomness_class("QpiAI-QSV-Simulator")
    assert "not a cloud run" in randomness_class("QpiAI-QSV-Local")


def _fake_entry(pool: QRNGPool, name: str, device: str, job_id):
    rec = {"counts": {"0000": 500, "1111": 524}, "counts_sha256": "x", "job_id": job_id, "device": device}
    atomic_write_json(pool.jobs_dir / name, rec)
    idx = pool._index()
    idx["entries"].append({"file": name, "job_id": job_id, "device": device,
                           "randomness_class": randomness_class(device), "nonce_used": False})
    atomic_write_json(pool.index_path, idx)


def test_nonce_requires_qcloud_job_unless_dev(tmp_path):
    pool = QRNGPool(tmp_path, tmp_path / "ev", api_key=None, allow_dev_nonce=False)
    with pytest.raises(NonceUnavailable):
        pool.take_nonce(1)
    _fake_entry(pool, "local.json", "QpiAI-QSV-Local", None)
    with pytest.raises(NonceUnavailable):  # local simulator output is not accepted for nonces
        pool.take_nonce(1)
    dev = QRNGPool(tmp_path, tmp_path / "ev", api_key=None, allow_dev_nonce=True)
    n = dev.take_nonce(1)
    assert n["randomness_class"] == "local-simulator (classical PRNG sampling, not a cloud run)"


def test_cloud_entry_consumed_once(tmp_path):
    pool = QRNGPool(tmp_path, tmp_path / "ev", api_key=None)
    _fake_entry(pool, "hw.json", "QpiAI-Indus-1", "job-abc")
    n = pool.take_nonce(1)
    assert n["job_id"] == "job-abc" and n["randomness_class"] == "quantum-hardware"
    recomputed = derive_nonce(bytes.fromhex(n["os_entropy_hex"]), {"0000": 500, "1111": 524}, "job-abc", 1)
    assert recomputed.hex() == n["nonce"]  # reproducible from the recorded inputs (NFR-07)
    with pytest.raises(NonceUnavailable):
        pool.take_nonce(2)


@pytest.mark.skipif(not (os.environ.get("QPIAI_QCLOUD_API_KEY") and os.environ.get("QUPLINK_RUN_QCLOUD_TESTS")),
                    reason="real QCloud job: set QPIAI_QCLOUD_API_KEY and QUPLINK_RUN_QCLOUD_TESTS=1 (may use credits)")
def test_qcloud_simulator_job_recorded(tmp_path):
    pool = QRNGPool(tmp_path, tmp_path / "ev", api_key=os.environ["QPIAI_QCLOUD_API_KEY"], shots=64)
    rec = pool.fetch("QpiAI-QSV-Simulator")
    assert rec["job_id"] and sum(rec["counts"].values()) == 64
