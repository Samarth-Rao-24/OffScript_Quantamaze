# Three-minute judging demo

**Before judges arrive (5 minutes):**
1. `.\scripts\start.ps1`, then open http://127.0.0.1:8000.
2. Sidebar → **Reset demo state**.
3. *Live uplink* → **Fetch QRNG from QCloud** (Indus-1) at least twice, so passes 1 and 2 have fresh quantum jobs. If hardware is queued, fetch these earlier.
4. *Pass planner* → **Optimize with QpiAI Opt** once in platform mode, so a real job ID is on screen.
5. *Resource budget* → **Run benchmarks** once.
6. Have a recorded QAOA run already in evidence (it takes minutes on QCloud); show its result rather than launching one live.
7. Set animation pace to "presenter".

| Time | Screen | Action and line to say |
|---|---|---|
| 0:00–0:20 | (any) | "Satellites take high-consequence commands over links of a few kilobytes per pass. We authenticate every command with Falcon-512, which is post-quantum, and keep the satellite's work bounded." |
| 0:20–0:50 | **1 Pass planner** | Point at the queue (priorities, deadlines, dependencies), then the pass timeline. "QpiAI Opt solved this 56-variable model. Here is its job ID. Each bar is a pass's byte budget, and the orange block is the PASS_OPEN frame that carries the quantum nonce. Opt matches the exhaustive optimum, beats greedy by about 10 priority points, and the Why panel explains C10 being deferred for budget." |
| 0:50–1:30 | **2 Live uplink** | Show the nonce and its QCloud job ID and device. Click **Run pass 1**. "Each frame is signed on the ground, crosses the byte-limited link, and the satellite process runs the checks in order: cheap ones first, signature fifth. The counter commits only after everything passes, with exactly one non-volatile write." |
| 1:30–2:15 | **3 Attack lab** | Fire Tamper, Replay, Expired, Unauthorized, Forged, Cross-pass and Wrong satellite (about 4 s each). "Each one is rejected with its own reason code, and the counter doesn't move. Cross-pass has a fresh counter, so the only thing stopping it is the quantum nonce binding." Then **Flood**: "500 junk frames, 8 signature checks, then lockout." |
| 2:15–2:40 | **4 Resource budget** | "682 bytes of authentication per frame, against 2,436 for ML-DSA. That's 72% less, four commands per pass instead of one. Verification takes tens of microseconds on this laptop, labelled as emulated. Flood CPU stays flat with the guard." |
| 2:40–3:00 | **5 Evidence** | Show the log filters and the Opt and QCloud job IDs, open one raw solver record, then click **Download evidence bundle**. "Everything is reproducible: one script reruns the tests, benchmarks and QpiAI jobs." |

**Prepared answers** (PRD §21), with the honest additions:
- *Is the randomness really quantum?* On Indus-1, yes. Simulator runs are labelled as classical PRNG sampling. Either way it is mixed with OS entropy, never used alone.
- *Did QRNG seed the keys?* No. No vetted Falcon library accepts a seed, and patching its RNG would be custom crypto. The quantum input is in every signature through the pass nonce instead.
- *Does QAOA beat classical?* Not at 12 qubits, and we say so. We show its gap to the exact optimum and to the classical Opt solver on the same QUBO.
