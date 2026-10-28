# Q-Uplink Mission Control

**Quant-A-Maze 3.0 (Q-BITS × QpiAI), Post-Quantum Cryptography track, PQC-03: Quantum-Resistant Satellite Command Authentication.**

Ground-side Falcon-512 command signing, a separate simulated onboard verifier, an accept/reject audit log and a measured resource budget. Every command frame is bound to a per-pass nonce derived from a QpiAI QCloud quantum-circuit job. Which commands are signed in which pass is decided by a QpiAI Opt model with byte budgets, deadlines and dependencies. A reduced instance of the same schedule is also solved with QAOA on QCloud.

```
queue ──► QpiAI Opt (MILP) ──► independent feasibility check ──► Falcon-512 signer ──► link (byte budget) ──► onboard verifier process ──► audit log
              │                                                     ▲                                          │
              └─ greedy / brute force (comparison only)              └── pass nonce = SHA-256(OS entropy ∥ QCloud QRNG job) ─┘
```

---

## 1. What is in this folder

| Path | Contents |
|---|---|
| `backend/satauth/common/` | Frame format (`frame.py`), roles/opcodes (`roles.py`), Falcon wrapper (`crypto.py`), atomic file I/O |
| `backend/satauth/ground/` | Key generation, signer + persisted counter, queue, **QpiAI Opt scheduler**, feasibility validator, greedy/brute-force baselines, **QCloud QRNG**, **QAOA experiment** |
| `backend/satauth/link/` | Byte-budgeted uplink simulator |
| `backend/satauth/onboard/` | Verifier pipeline, flood guard, NV state store, audit logger, separate satellite **process** |
| `backend/satauth/api/` | FastAPI app, WebSocket stream, attack lab, service layer |
| `backend/satauth/bench/` | `measure.py` (latency, RAM, NV writes, flood CPU), `scheme_compare.py` (Falcon vs ML-DSA vs ECDSA vs Ed25519) |
| `backend/tests/` | pytest suite: the 10 required scenarios plus state-safety, scheduler, QRNG and API tests |
| `backend/scripts/qpiai_runs.py` | Command-line QpiAI runs: key check, Opt plan, QRNG job, QAOA |
| `frontend/` | React + Vite + TypeScript + Tailwind + Recharts, five screens |
| `scripts/` | `start.ps1`, `run_all.ps1` (Windows), `run_all.sh` (Linux/macOS) |
| `evidence/` | Generated on **your** machine: logs, Opt/QCloud job records, benchmarks, test summary |
| `data/` | Generated runtime state: **private keys**, counters, nonce chain (git-ignored, never served) |
| `docs/` | `DEMO_SCRIPT.md` (3 minutes), `REQUIREMENTS_CHECKLIST.md` |
| `poc/`, `PRD_*.docx`, rubric PDF | Your original files, left untouched |

---

## 2. Setup on Windows (PowerShell)

**Prerequisites:** Python **3.11** (64-bit) from python.org (`py -3.11 --version` should work) and Node.js **20 LTS or newer** (`node --version`). Git is optional.

```powershell
cd F:\OffScript

# 1) Python environment (installs the pinned packages from PyPI)
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# 2) Frontend (installs pinned npm packages, then builds the UI)
cd frontend
npm install
npm run build
cd ..

# 3) Secrets
Copy-Item .env.example .env
notepad .env        # paste your two keys, save, close
```

If PowerShell blocks scripts, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### Linux / macOS

```bash
python3.11 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
(cd frontend && npm install && npm run build)
cp .env.example .env && $EDITOR .env
```

---

## 3. API keys: where to get them and where they go

| Key | Dashboard | `.env` variable | Used by |
|---|---|---|---|
| QpiAI Opt | https://opt.qpiai.tech (register, copy your API key) | `QPIAI_OPT_API_KEY` | `qpiai_opt.opt_solvers.Client(api_key=...)` for every Opt solve |
| QpiAI QCloud | https://qcloud.qpiai.tech (register, copy your API key) | `QPIAI_QCLOUD_API_KEY` | `QpiAIQuantumAuth.login(api_key=...)` for QRNG circuits and QAOA |

- `.env` is git-ignored. The backend reads it on start-up. Keys are never logged, never returned by the API and never sent to the browser; the UI shows only "Opt key ✓/✗".
- `QCLOUD_API_KEY` (the name your `poc/` used) is accepted as a fallback.
- **Free:** Opt *local* solves, the key check, all tests and benchmarks.
- **May consume credits** (the app and CLI ask before each one): Opt *platform* jobs, QRNG circuits on QCloud (Indus-1 hardware or simulators), QAOA on QCloud (about 30 circuit jobs per run).

Verify both keys without spending credits:

```powershell
cd backend
..\.venv\Scripts\python.exe scripts\qpiai_runs.py check
```

---

## 4. Run the app

```powershell
.\scripts\start.ps1          # open http://127.0.0.1:8000
.\scripts\start.ps1 -Dev     # API on :8000 + hot-reload UI on http://127.0.0.1:5173
```

Manual equivalent: `cd backend; ..\.venv\Scripts\python.exe -m uvicorn satauth.api.main:app --host 127.0.0.1 --port 8000`

The server binds to `127.0.0.1` only. On first start it generates OPERATOR and ADMIN Falcon key pairs, provisions the onboard state, and starts the satellite verifier as a separate OS process.

**First real run (recorded evidence):**
1. *Live uplink*: **Fetch QRNG from QCloud** (Indus-1). Fetch one per pass you plan to run, since each pass nonce consumes one job.
2. *Pass planner*: **Optimize with QpiAI Opt** (platform mode records a job ID).
3. *Live uplink*: **Run pass 1 … 4**.
4. *Attack lab*: fire each attack. Use **Start next window** after Flood.
5. *Pass planner*: **Run QAOA** (QCloud simulator).
6. *Resource budget*: **Run benchmarks**.
7. *Evidence*: **Download evidence bundle**.

Or from the command line: `.\scripts\run_all.ps1 -WithQpiAI`.

---

## 5. Tests and benchmarks

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q                         # 51 tests, no keys needed
..\.venv\Scripts\python.exe -m satauth.bench.measure             # latency, RAM, NV writes, flood
..\.venv\Scripts\python.exe -m satauth.bench.scheme_compare      # Falcon / ML-DSA / ECDSA / Ed25519
.\scripts\run_all.ps1                                            # all of the above + UI build (from repo root)
```

Two integration tests run only when keys are present:
- `test_opt_local_solve_matches_brute_force` runs when `QPIAI_OPT_API_KEY` is set (free).
- `test_qcloud_simulator_job_recorded` also needs `QUPLINK_RUN_QCLOUD_TESTS=1` (may use credits).

| Required scenario | Test(s) | Expected |
|---|---|---|
| Valid | `test_01_valid_command_accepted` | ACCEPT, counter advances, exactly 1 NV write |
| Tampered | `test_02_*` (12 QRNG-seeded bit flips, header flip) | `E_BAD_SIG`, counter unchanged, 0 NV writes |
| Replayed | `test_03_*` | `E_REPLAY` before any signature work |
| Expired | `test_04_*` | `E_EXPIRED` before any signature work |
| Unauthorized | `test_05_*` | `E_UNAUTHORIZED`; OPERATOR also cannot send PASS_OPEN |
| Forged | `test_06_*` (random bytes, attacker key, unknown key_id) | `E_BAD_SIG` |
| Cross-pass | `test_07_*` | `E_BAD_SIG` with a fresh counter; control frame under the current nonce is accepted |
| Wrong satellite | `test_08_*` | `E_WRONG_SAT` |
| Flood | `test_09_*` (500 random, 60 well-formed) | first N=8 `E_BAD_SIG`, rest `E_FLOOD_LOCKOUT`, exactly 8 signature checks |
| Over budget | `test_10_*`, `test_over_budget_queue_defers_low_priority` | link refuses the frame that would exceed the budget; scheduler defers the lowest priorities |

Every test asserts the reason code **and** the state effect (counter, NV writes, flood count, log line). Extra tests cover counter persistence across reboot, a simulated crash during the atomic write, check ordering, malformed frames, the separate satellite process, the Opt model structure (cross-checked with QpiAI's `feasibility()`), and the API (including that the evidence zip contains no private keys).

---

## 6. How the security pipeline works

Frame: `version(1) sat_id(1) key_id(1) cmd_len(1) counter(8) expiry(4) | command(≤32 B) | Falcon-padded-512 signature (666 B)`. Authentication overhead is exactly **682 B**. The signature covers `"Q-UPLINK/FRAME/v1" ∥ header ∥ command ∥ current pass nonce`; the nonce itself is never resent.

Onboard checks run in this order. The first failure stops processing.

| Step | Check | Code |
|---|---|---|
| 0 | flood guard below N (per contact window) | `E_FLOOD_LOCKOUT` |
| – | frame parses | `E_MALFORMED` |
| 1 | `sat_id` matches | `E_WRONG_SAT` |
| 2 | expiry ≥ onboard clock | `E_EXPIRED` |
| 3 | counter > last accepted (check only) | `E_REPLAY` |
| 4 | Falcon signature with the key named by `key_id`, over frame + pass nonce | `E_BAD_SIG` |
| 5 | opcode allowed for that key's role | `E_UNAUTHORIZED` |
| – | commit counter (one atomic NV write), execute | `OK` |

A pass opens with `PASS_OPEN`, signed with the ADMIN key over the *previous* nonce and carrying the new one. The pass nonce is SHA-256 of 32 B of OS entropy, the digest of the QCloud job's measurement counts, the job ID and the pass number. Every input is recorded in `evidence/qcloud_jobs/nonce_derivations.jsonl`, so each nonce can be recomputed.

---

## 7. Deviations from the PRD (and why)

| PRD item | What changed | Reason |
|---|---|---|
| §13 liboqs-python | **pqcrypto 0.4.0** (PQClean), `falcon_padded_512` | Prebuilt Windows wheel; liboqs-python compiles liboqs with CMake + MSVC on first import. pqcrypto 1.0.0 removed Falcon, so the version is pinned. Approved by the team. |
| FR-17 key seed = SHA-256(OS ∥ QRNG) | **Not implemented**; Falcon keys use the library's OS CSPRNG | Neither pqcrypto nor liboqs-python accepts a seed for Falcon key generation; injecting one would mean patching the library's RNG (custom crypto, against NFR-08). QRNG stays on the security path through the pass nonce. Approved by the team. |
| §11.2 "QRNG" call | Hadamard-on-every-qubit circuit run with `Circuit.run(device_name=…)` | The `QRNG` class in qpiai-quantum 0.3.0 (pinned by `qpiai-opt[quantum]`) cannot target a cloud device. This is the PRD's own fallback (§16). |
| "quantum random bytes" | Labelled by device | The SDK documents that only `QpiAI-Indus-1` output is physical quantum randomness; simulators sample with a classical PRNG. The UI and evidence label every nonce accordingly. QCloud returns aggregated counts, not per-shot order, so the entropy used is that of the count histogram (about 780 bits for an ideal 8-qubit, 1024-shot job); OS entropy is always mixed in. |
| §5 command ≤ 32 B | PASS_OPEN body is 33 B | 1-byte opcode + 32-byte nonce cannot fit in 32 B. |
| "few hundred bytes per pass" | Default budgets 3600/3600/2900/2200 B | One authenticated frame is at least 683 B, so a few-hundred-byte pass could not carry any frame. Budgets are editable in the planner. |
| §7 codes | Added `E_MALFORMED` | Unparseable bytes need a code; they are rejected before any signature work. |
| Flood guard reset | Reset at the start of each contact window by the onboard pass timer (and on PASS_OPEN) | If only PASS_OPEN reset it, a lockout could never be lifted. Trade-off: a flood early in a window denies the rest of that window (DoS) while keeping onboard CPU bounded. |
| QAOA instance | 5 commands × 2 passes, budgets as 2 frame slots, 12 qubits | Exact byte budgets need ~11 slack qubits per pass. The slot form is conservative (every frame ≤ 715 B) and decoded plans are re-checked against exact bytes. |

---

## 8. What was verified, and what still needs you

Verified in the build workspace (Linux, Python 3.11.18, Node 22):
- 51 tests pass; the 2 integration tests are skipped there for lack of keys.
- The frontend type-checks and builds. All five screens were rendered and visually reviewed against the real API, including a mobile width.
- The API, satellite process, attacks and benchmarks were exercised end to end.
- The Opt model compiles (MILP, 56 binaries, 53 constraints), and QpiAI's `feasibility()` agrees with the independent validator.

**Not yet verified, needs your machine and keys:**
- Installation on Windows (expected to work: every package has a win_amd64/py3 wheel).
- A real QpiAI Opt solve, local and platform. The code path stops at authentication without a key.
- Real QCloud QRNG jobs on Indus-1 and QAOA on the QCloud simulator. Device availability and credit cost depend on your account; `qpiai_runs.py check` lists your devices.
- Benchmark numbers on your CPU. The evidence folder is intentionally empty until you run them.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `py -3.11` not found | Install Python 3.11 x64 from python.org and tick "Add to PATH". |
| `pip install` fails on `pqcrypto` | Check the Python version: 3.9–3.11 has Windows wheels for pqcrypto 0.4.0. Do not upgrade to pqcrypto 1.x (no Falcon). |
| Planner says "QPIAI_OPT_API_KEY is not set" | Create `.env` in the project root (not in `backend/`), then restart the server. |
| `AuthenticationError ... unreachable` | Opt and QCloud verify keys online even for local solves. Check internet, proxy and firewall. |
| "No unused QCloud QRNG job in the pool" | Fetch QRNG first, one per pass. For offline UI work only, set `QUPLINK_ALLOW_DEV_NONCE=true` (nonces are labelled DEV). |
| Every attack returns `E_FLOOD_LOCKOUT` | The window is locked by the flood guard. Press **Start next window**. |
| QRNG on Indus-1 is slow or fails | The hardware may be queued or not on your plan. Run `qpiai_runs.py check` to list devices. Using a simulator instead is your choice, and its output is labelled as simulator randomness. |
| Port 8000 busy | `netstat -ano | findstr :8000`, stop that process, or change the port in `scripts\start.ps1` and `frontend\vite.config.ts`. |
| Want a clean demo | Sidebar **Reset demo state**. It archives the log, re-provisions onboard state and keeps the keys. |
| Lost or corrupted keys | Stop the server, delete `data\` (this regenerates keys and state), restart. |

---

## 10. Security notes and known limitations

- Software-only. All timings are **emulated host** measurements, labelled with the CPU model; they are not flight-hardware numbers.
- `tracemalloc` sees only the Python heap. C stack and static memory inside PQClean are not counted.
- The ground counter, keys and nonce chain are local JSON files; there is no HSM. Key revocation and rotation are out of scope (PRD §2.3).
- The flood guard trades availability for bounded CPU within a window (see §7).
- Commands are authenticated, not encrypted (PRD §2.3).
- The stretch two-tier mode (ML-KEM + HMAC, FR-21, "Could") is not implemented.
- The QCloud entropy contribution is not certified min-entropy; it is an additional source mixed with OS randomness, as the PRD requires.
