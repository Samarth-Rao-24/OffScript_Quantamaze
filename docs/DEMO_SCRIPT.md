# Three-minute judging demo

**Before judges arrive (5 minutes):**
1. `.\scripts\start.ps1`, then open http://127.0.0.1:8000.
2. Sidebar → **Reset demo state**.
3. *Live uplink* → **Run QRNG circuit** (QpiAI local simulator) at least twice, so passes 1 and 2 have fresh QRNG runs.
4. *Pass planner* → **Optimize with QpiAI Opt** once (QpiAI Opt local solver).
5. *Resource budget* → **Run benchmarks** once.
6. Have a recorded QAOA run already in evidence (`final_run.py` makes one); show its result rather than launching one live.
7. Set animation pace to "presenter".

| Time | Screen | Action and line to say |
|---|---|---|
| 0:00–0:20 | (any) | "Satellites take high-consequence commands over links of a few kilobytes per pass. We authenticate every command with Falcon-512, which is post-quantum, and keep the satellite's work bounded." |
| 0:20–0:50 | **1 Pass planner** | Point at the queue (priorities, deadlines, dependencies), then the pass timeline. "The QpiAI Opt solver solved this 56-variable model, authenticated with our Opt key. Each bar is a pass's byte budget, and the orange block is the PASS_OPEN frame that carries the quantum nonce. Opt matches the exhaustive optimum, beats greedy by about 10 priority points, and the Why panel explains C10 being deferred for budget." |
| 0:50–1:30 | **2 Live uplink** | Show the nonce and the QRNG run behind it (QpiAI simulator, labelled). Click **Run pass 1**. "Each frame is signed on the ground, crosses the byte-limited link, and the satellite process runs the checks in order: cheap ones first, signature fifth. The counter commits only after everything passes, with exactly one non-volatile write." |
| 1:30–2:15 | **3 Attack lab** | Fire Tamper, Replay, Expired, Unauthorized, Forged, Cross-pass and Wrong satellite (about 4 s each). "Each one is rejected with its own reason code, and the counter doesn't move. Cross-pass has a fresh counter, so the only thing stopping it is the quantum nonce binding." Then **Flood**: "500 junk frames, 8 signature checks, then lockout." |
| (if asked) | **3 Attack lab → Judge console** | "Give us your own case." Let the judge pick fields in Compose, or paste a case file. "You supply the expected answer; the false-accept count must stay at 0." |
| (if asked) | **2 Live uplink → QRNG job inspector** | Show the circuit and histogram, press **Verify current nonce**, to recompute it from the recorded circuit output and OS entropy. |
| 2:15–2:40 | **4 Resource budget** | "682 bytes of authentication per frame, against 2,436 for ML-DSA. That's 72% less, four commands per pass instead of one. Verification takes tens of microseconds on this laptop, labelled as emulated. Flood CPU stays flat with the guard." |
| 2:40–3:00 | **5 Evidence** | Show the log filters, the QpiAI Opt and QRNG/QAOA run records, open one raw solver record, then click **Download evidence bundle**. "Everything is reproducible: one script reruns the tests, benchmarks and QpiAI jobs." |

**Prepared answers** (PRD §21), with the honest additions:
- *Is the randomness really quantum?* Not in this run, and we say so. Following the organisers' guidance we ran the QRNG circuit on the QpiAI simulator, which samples with a classical PRNG; it is labelled that way and always mixed with OS entropy. The same code targets QpiAI-Indus-1 for physical quantum randomness with one setting change.
- *Did QRNG seed the keys?* No. No vetted Falcon library accepts a seed, and patching its RNG would be custom crypto. The quantum input is in every signature through the pass nonce instead.
- *Does QAOA beat classical?* Not at 12 qubits, and we say so. We show its gap to the exact optimum and to the classical Opt solver on the same QUBO.
- *Where are the QCloud and Opt platform job IDs?* The organisers told us: after getting the API keys, run the QpiAI local solvers and simulators; no workspaces, platform utilities or credits are needed. So both keys authenticate with QpiAI, the schedule comes from the QpiAI Opt local solver (proven optimal), and QRNG and QAOA run on the QpiAI Quantum SDK simulator. Local runs have no cloud job IDs, so we record the solver inputs, outputs and run metadata instead. The cloud path is still in the code (`--quantum cloud`) and records job IDs on an account with a subscription.
