# Evidence

Generated on your machine by the app, `backend/scripts/qpiai_runs.py`, the benchmarks and pytest:

- `logs/onboard_log.jsonl`: one line per frame received onboard (ACCEPT/REJECT + reason)
- `logs/link_log.jsonl`: ground transmissions, refusals at budget, hostile traffic
- `opt_jobs/opt_*.json`: QpiAI Opt inputs, raw result (job_id, problem_id), validation, baselines
- `qcloud_jobs/qrng_*.json`: QCloud QRNG circuit jobs (job_id, device, counts)
- `qcloud_jobs/qaoa_*.json`: QAOA experiment (QUBO, circuit job IDs, comparison)
- `qcloud_jobs/nonce_derivations.jsonl`: inputs for every pass nonce (recomputable)
- `bench/`: resource and scheme benchmarks (emulated host)
- `tests/`: pytest summary and JUnit XML
- `pass_runs.json`: each executed pass

Nothing in this folder is fabricated. It is empty until you run things.
