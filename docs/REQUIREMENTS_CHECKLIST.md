# Requirements checklist

Status key: **Done** = implemented and tested in the build workspace. **Needs your run** = code complete; the real QpiAI execution happens on your machine with your keys. **Deviation** = changed with reason (README §7).

## Official PQC-03 deliverables (rubric §5)

| Requirement | Where | Status |
|---|---|---|
| Ground-side signing | `ground/signer.py`, `common/crypto.py` | Done |
| Onboard-side receiving verification | `onboard/verifier.py`, `onboard/process.py` (separate process) | Done |
| Accepted/rejected log | `evidence/logs/onboard_log.jsonl`, Evidence screen | Done |
| Measured resource budget | `bench/measure.py`, `bench/scheme_compare.py`, Resource screen | Done (numbers on your CPU: Needs your run) |
| Test tampered, replayed, expired, unauthorized, forged | `tests/test_attacks.py` | Done |

## QpiAI technology rubric (§8, 20 points)

| Criterion | How it is met | Status |
|---|---|---|
| A1 product choice and domain integration | The Opt plan decides what is signed and sent; the QCloud nonce sits inside every signature (cross-pass test proves it) | Done |
| A2 QCloud formulation | Hadamard-measure circuits on QCloud for pass nonces and fuzz seeds; QAOA on the scheduling QUBO via qpiai-opt[quantum] | Needs your run |
| A2 Opt formulation | MILP: at-most-once, byte budget (minus PASS_OPEN), deadlines, dependency precedence; feasibility re-checked before signing | Done; platform job ID needs your run |
| A3 recorded execution evidence | Job IDs, raw inputs and outputs, nonce derivations, SHA-256 manifest, evidence zip | Needs your run |

## PRD functional requirements

| ID | Requirement | Status |
|---|---|---|
| FR-01 | Falcon-512 key pairs per role | Done (padded variant, 666 B) |
| FR-02 | Preload public keys and role table onboard | Done |
| FR-03 | Sign header + body + pass nonce | Done (plus domain tag) |
| FR-04 | Counter persisted before transmit | Done (`GroundCounter.next`) |
| FR-05 | sat_id check | Done |
| FR-06 | Expiry check | Done |
| FR-07 | Counter / replay check | Done |
| FR-08 | Falcon verify with the key from key_id | Done |
| FR-09 | Role authorisation | Done |
| FR-10 | Counter commit only after all checks | Done (tested, including a crash mid-write) |
| FR-11 | One log line per frame | Done |
| FR-12 | Link byte budget per pass | Done |
| FR-13 | Flood guard | Done (N=8, per contact window) |
| FR-14 | PASS_OPEN with QCloud nonce | Done; real QCloud jobs need your run |
| FR-15 | Opt multi-pass scheduling | Done; real solve needs your key |
| FR-16 | Feasibility check before signing | Done (again at pass run time) |
| FR-17 | Key seed mixes OS + QRNG | **Deviation**: not supported by any vetted Falcon library (approved) |
| FR-18 | QAOA on QCloud via qpiai-opt[quantum] | Done (12 qubits); needs your run |
| FR-19 | Greedy + brute-force baselines, comparison only | Done |
| FR-20 | Falcon / ML-DSA / ECDSA benchmark | Done (+ Ed25519) |
| FR-21 | Two-tier ML-KEM mode (Could) | Not implemented |
| FR-22 | Five-screen web app | Done |
| FR-23 | WebSocket live events | Done |

## Non-functional requirements (build workspace measurements, emulated host)

| ID | Target | Measured in build workspace |
|---|---|---|
| NFR-01 | ≤ 682 B overhead | 682 B |
| NFR-02 | < 5 ms verify | Falcon verify p50 ≈ 57–108 µs; full pipeline incl. NV commit p95 ≈ 1.2–2.3 ms |
| NFR-03 | < 64 KB RAM | ≈ 19 KB per verification (Python heap) |
| NFR-04 | 1 NV write per accept | 1.0 |
| NFR-05 | 0 NV writes per reject | 0.0 |
| NFR-06 | ≤ N + accepted verifications under flood | 8 of 500 |
| NFR-07 | Reproducible from seeds and job IDs | Fuzz seeds and nonce inputs recorded; the run_all scripts |
| NFR-08 | Vetted libraries only | pqcrypto (PQClean), cryptography (OpenSSL), QpiAI SDKs |
