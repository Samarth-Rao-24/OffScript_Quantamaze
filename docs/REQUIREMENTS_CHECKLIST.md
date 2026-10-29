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
| A2 QCloud formulation | Hadamard-measure circuits for pass nonces and fuzz seeds; QAOA on the scheduling QUBO via qpiai-opt[quantum]. Run on the QpiAI Quantum SDK simulator, authenticated with the QCloud key (organiser-recommended path) | Done (QpiAI local simulator; labelled, no cloud job IDs) |
| A2 Opt formulation | MILP: at-most-once, byte budget (minus PASS_OPEN), deadlines, dependency precedence; feasibility re-checked before signing | Done (QpiAI Opt local solver, proven optimal 65.8 vs greedy 55.3) |
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
| FR-14 | PASS_OPEN with QRNG nonce | Done (QpiAI local simulator runs; nonces recompute from evidence) |
| FR-15 | Opt multi-pass scheduling | Done (QpiAI Opt local solver, authenticated) |
| FR-16 | Feasibility check before signing | Done (again at pass run time) |
| FR-17 | Key seed mixes OS + QRNG | **Deviation**: not supported by any vetted Falcon library (approved) |
| FR-18 | QAOA via qpiai-opt[quantum] | Done (12 qubits, QpiAI local simulator, reached the exact optimum) |
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

**Note on QpiAI execution path.** The organisers confirmed: "You do not need workspaces or platform utilities after getting the API key and use that to run local solvers and simulators. They do not need any credits as well." The submission therefore uses the QpiAI Opt local solver and the QpiAI Quantum SDK simulator, both authenticated with our API keys. Cloud job paths remain in the code (`--quantum cloud`, `--opt-mode platform-qubo`) but were refused on our account for subscription reasons.

**Additions after mentor review (2026-10-29).**

| Item | What | Status |
|---|---|---|
| Missing-packet detection | No-ACK detection, onboard counter-gap report (same single NV write), ground ledger reconciliation, dependency hold, re-sign (never resend), in-pass retransmission, carry-over, QpiAI Opt re-plan of the remaining passes with deadlines and dependencies kept | Done; `tests/test_packet_loss.py` (6 tests), drill in `final_run.py` |
| NASA data | Real ISS TLE (TLE API in the api.nasa.gov catalogue) -> SGP4 passes over Bengaluru -> per-pass byte budgets; NASA DONKI storms/flares -> space-weather margin; raw responses recorded with SHA-256 | Done; `tests/test_nasa.py` (6 offline tests on a synthetic TLE), live fetch in `final_run.py` |
