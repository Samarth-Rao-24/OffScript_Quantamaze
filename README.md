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
| NASA Open APIs (optional) | https://api.nasa.gov (fill in the form; the key is shown and emailed at once) | `NASA_API_KEY` | DONKI space-weather requests. Without it `DEMO_KEY` is used (rate-limited). The TLE API needs no key. |

- `.env` is git-ignored. The backend reads it on start-up. Keys are never logged, never returned by the API and never sent to the browser; the UI shows only "Opt key ✓/✗".
- `QCLOUD_API_KEY` (the name your `poc/` used) is accepted as a fallback.
- **Default path (organiser guidance):** the Quant-A-Maze organisers confirmed that, once you have the API keys, you run the QpiAI **local solvers and simulators**; workspaces, platform utilities and credits are not needed. So by default:
  - scheduling uses the **QpiAI Opt local solver** (`solve(model, mode="local", client=Client(api_key=...))`), authenticated with `QPIAI_OPT_API_KEY`;
  - QRNG circuits and QAOA run on the **QpiAI Quantum SDK simulator** (`QpiAI-QSV-Local`), after `QpiAIQuantumAuth.login` with `QPIAI_QCLOUD_API_KEY`.
  These runs cost nothing and produce no cloud job IDs. Every record is labelled "QpiAI local simulator (not a cloud run)", and the simulator samples with a classical PRNG, so we never call that randomness physical quantum randomness. OS entropy is always mixed into each nonce.
- **Optional cloud path** (needs platform resources and credits on the account; the app and CLI ask before each run): Opt *platform* jobs, QRNG circuits on QCloud (Indus-1 hardware or simulators), QAOA on QCloud (about 30 circuit jobs per run). On our account QCloud replied "an active subscription is required to run jobs" and Opt platform replied "no access to 'QUBO Solver'", which is why the organisers pointed us to the local path.

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
0. *Pass planner*: **Fetch from NASA**, then **Use these budgets** (real pass windows; see section 4a).
1. *Live uplink*: **Run QRNG circuit** (QpiAI local simulator by default). Run one per pass you plan to run, since each pass nonce consumes one run.
2. *Pass planner*: **Optimize with QpiAI Opt** (QpiAI Opt local solver by default).
3. *Live uplink*: **Run pass 1 … 4**.
4. *Attack lab*: fire each attack. Use **Start next window** after Flood.
5. *Pass planner*: **Run QAOA** (QpiAI local simulator by default).
6. *Resource budget*: **Run benchmarks**.
7. *Evidence*: **Download evidence bundle**.

Or from the command line: `.\scripts\run_all.ps1 -WithQpiAI`.

**Recommended single command for the recorded submission run** (no credits; logs everything to `evidence\final_run_log.txt`, writes `q-uplink-evidence.zip`):
```powershell
cd F:\OffScript\backend
F:\OffScript\.venv\Scripts\python.exe scripts\final_run.py --fresh
```
It runs: key check (both keys authenticate with QpiAI), 6 QRNG circuits on the QpiAI Quantum SDK simulator (4 passes + 2 contact windows), the NASA pull (real ISS passes over Bengaluru + DONKI space weather, applied as the pass budgets; skipped with a note if NASA is unreachable, or with `--no-nasa`), the QpiAI Opt local solver plan (validated, compared with greedy and brute force), QAOA on the QpiAI simulator, benchmarks, then passes with a **missing-packet drill** in pass 3 (one frame lost on the link, detected, reconciled, recovered or re-planned with QpiAI Opt; `--no-drill` to skip), nonce verification, judge sample cases, all attacks, and a **key-management drill** (rotate OPERATOR to its spare, prove the old key is refused, migrate to hybrid Ed25519 + Falcon) on the real satellite process. `--fresh` archives the previous evidence to `evidence\_previous_runs\`. Options: `--quantum cloud` and `--opt-mode platform-qubo` for cloud jobs (need platform access and credits), `--qrng-jobs`, `--skip-qaoa`.

### 4a. Real pass windows from NASA data (Pass planner, top)

Our satellite is simulated, but its contact windows don't have to be invented:
1. **Orbit:** the latest TLE for NORAD 25544 (the ISS, as a stand-in) from the TLE API in the api.nasa.gov catalogue (`tle.ivanstanojevic.me`, no key; CelesTrak is a fallback). Checksums are verified.
2. **Passes:** SGP4 propagation with `skyfield` finds the next passes over Bengaluru above 10° elevation within 72 h. Passes too short for PASS_OPEN plus one command are skipped.
3. **Budget per pass** = contact seconds × command-uplink allocation (default 80 bit/s, adjustable) ÷ 8. The allocation is our stated assumption: the share of a low-rate TT&C link given to authenticated commands.
4. **Space weather:** NASA DONKI geomagnetic storms (Kp) and solar flares from the last 7 days (via api.nasa.gov; if that gateway fails, NASA CCMC's own DONKI web service). Transient errors are retried twice. Our margin policy keeps 15% back after Kp ≥ 5 (30% at Kp ≥ 7) in the last 72 h, and a further 10% after an X-class flare in the last 24 h.

**Fetch from NASA** shows the passes (in your local time), budgets, TLE age and the space-weather reasoning. **Use these budgets** writes them into the queue (the planner then asks you to Optimize again). Every pull is saved in `evidence/nasa/` with the raw responses, their SHA-256, the URLs (API key removed) and the derived passes. It is labelled everywhere as a real orbit used for a simulated satellite.

### 4b. Missing packets (Live uplink, "Packet-loss drill" + "Missing-packet monitor")

Choose a drill next to the pass buttons: lose the first transmission of a chosen command, or random 10% / 25% loss with a fixed seed (reproducible). Then run a pass. What happens:
1. The lost frame uses link bytes but never reaches the satellite. The ground gets **no acknowledgement** and raises a *Missing packet* alert.
2. Commands that depend on it are **held**: they are not signed (no counter is used) and are never sent ahead of their dependency.
3. When the satellite accepts the next frame, it reports the **counter gap** (counters it never accepted) in its acknowledgement. The gap is stored in the same single NV write, so it costs nothing extra. The ground reconciles every skipped counter against its own transmit ledger: lost on the link, refused at budget, rejected onboard, used by a test frame, or **unexplained** (flagged).
4. The lost command is **re-signed with a fresh counter**, never resent as-is: once a later frame is accepted, the old counter would be rejected as a replay (the tests prove this). It is retransmitted in the same pass if the byte budget allows, then held dependents are released.
5. Anything left is **carried over**. **Re-plan passes N–4 with QpiAI Opt** re-runs the optimiser on every unacknowledged command over the remaining passes, with deadlines kept: past-deadline commands are reported *missed*, and their dependents *blocked*. The merged plan is re-validated before anything is signed. Re-running a pass never resends a command that was already acknowledged.

Alerts are logged to `evidence/logs/alerts.jsonl`, and the acknowledgement ledger to `evidence/logs/ack_log.jsonl`. Both appear on the Evidence screen.

### 4c. Key management and algorithm migration (Attack lab, "Key management" panel)

Eight public keys are pre-loaded onboard before launch:
- a primary and a spare Falcon-512 key per role;
- an ML-DSA-44 key per role (FIPS 204, the final standard);
- a hybrid Ed25519 + Falcon-512 key per role.

Only the primaries start active. **Rotate key** sends two ADMIN-signed frames: `KEY_ACTIVATE` for the new key, then `KEY_REVOKE` for the old one. After that, the **Revoked key** attack card shows a validly signed frame from the old key refused as `E_KEY_REVOKED` before any signature work.

The algorithm is bound to the key, not chosen by the frame, so migration (Falcon → hybrid → ML-DSA fallback) is just a rotation. Plans are re-sized for the new frame lengths.

Set `QUPLINK_KEY_PASSPHRASE` in `.env` to keep every private key encrypted at rest (scrypt + AES-256-GCM).

Full design, migration phases, CCSDS mapping and deployment notes: `docs/MIGRATION_AND_DEPLOYMENT.md`.

### Checking cost before a paid QCloud run

```powershell
cd backend
..\.venv\Scripts\python.exe scripts\qpiai_runs.py credits                                       # free: device list + QpiAI price estimates
..\.venv\Scripts\python.exe scripts\qpiai_runs.py qrng --device QpiAI-Indus-1 --shots 256       # shows the estimate, asks 'yes', then runs
..\.venv\Scripts\python.exe scripts\qpiai_runs.py job <JOB_ID>                                  # free: re-fetch status and credits_used from QCloud
```

The QCloud estimator prices simulators per circuit (1 credit on QSV-Simulator) and hardware per shot. QpiAI API keys cannot read account balances, so check your balance on the dashboards.

### QRNG job inspector (Live uplink, bottom)

For any recorded QRNG job the inspector shows:
- the circuit that was submitted, drawn from its stored OpenQASM;
- a histogram of all 2^n outcomes against the uniform expectation, with chi-square, p-value, empirical entropy and per-bit bias. Hardware bias shows up here honestly;
- **Verify current nonce**: recomputes the satellite's pass nonce from the recorded OS entropy, the job's counts and the job ID, and checks that the counts are unchanged, the ground installed the nonce, and the audit log shows the PASS_OPEN accepted;
- **Ask QCloud for this job**: read-only GET requests for the job by ID (status, credits used, stored counts), compared with our record. No circuit is executed. Each re-fetch is saved in `evidence/qcloud_jobs/refetch_*.json`.

### Judge console (Attack lab, bottom)

Lets judges test the satellite with their own inputs instead of our attack buttons. Open a contact window first.
- **Compose a frame:** signing key (ground OPERATOR, ground ADMIN, or an attacker key the satellite has never seen), opcode, argument bytes, satellite ID, expiry, counter (next or a fixed value), the nonce to sign under (current, previous, random or custom), a key_id override, and an optional bit to flip after signing. The frame is really signed and sent, and the check-by-check result is shown.
- **Raw bytes:** paste or edit any hex. **Load last frame sent** fills the box so a judge can flip any bit and resend.
- **Case file:** paste or upload JSON or CSV. Each case states its expected outcome (`ACCEPT`, `REJECT`, or a reason code such as `E_REPLAY`); the runner reports per-case match/mismatch and totals including **false accepts** (must be 0), false rejects and different-reason rejections. Results are saved to `evidence/judge_runs/`. Samples: `docs/judge_cases_sample.json` and `docs/judge_cases_sample.csv`. Bits are numbered from 0 = most significant bit of byte 0.

Judges can also **add or remove commands** in the Pass planner (then **Save queue** and **Optimize**), so the scheduling problem can be theirs too.

---

## 5. Tests and benchmarks

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q                         # 90 tests without keys (92 with Opt + QCloud integration enabled)
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
- 61 tests pass; the 2 integration tests are skipped there for lack of keys. On your PC (keys in .env) the real Opt test also runs and passed.
- The frontend type-checks and builds. All five screens were rendered and visually reviewed against the real API, including a mobile width.
- The API, satellite process, attacks and benchmarks were exercised end to end.
- The Opt model compiles (MILP, 56 binaries, 53 constraints), and QpiAI's `feasibility()` agrees with the independent validator.

**Not yet verified, needs your machine and keys:**
- Installation on Windows (expected to work: every package has a win_amd64/py3 wheel).
- A real QpiAI Opt solve, local and platform. The code path stops at authentication without a key.
- QCloud cloud jobs (Indus-1, QCloud simulators) and Opt platform jobs: refused on our account (subscription / QUBO Solver access). Per organiser guidance the submission uses the QpiAI local solver and simulator instead, which ran successfully on the PC.
- Benchmark numbers on your CPU. The evidence folder is intentionally empty until you run them.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `py -3.11` not found | Install Python 3.11 x64 from python.org and tick "Add to PATH". |
| `pip install` fails on `pqcrypto` | Check the Python version: 3.9–3.11 has Windows wheels for pqcrypto 0.4.0. Do not upgrade to pqcrypto 1.x (no Falcon). |
| Planner says "QPIAI_OPT_API_KEY is not set" | Create `.env` in the project root (not in `backend/`), then restart the server. |
| `AuthenticationError ... unreachable` | Opt and QCloud verify keys online even for local solves. Check internet, proxy and firewall. |
| "No unused QRNG run in the pool" | Press **Run QRNG circuit** first, one per pass. For offline UI work only, set `QUPLINK_ALLOW_DEV_NONCE=true` (nonces are labelled DEV). |
| Every attack returns `E_FLOOD_LOCKOUT` | The window is locked by the flood guard. Press **Start next window**. |
| QCloud says "an active subscription is required" | Expected without a subscription. Keep the default `QUPLINK_QRNG_DEVICE=QpiAI-QSV-Local` and `QUPLINK_QAOA_MODE=local` (organiser-recommended, no credits). |
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
