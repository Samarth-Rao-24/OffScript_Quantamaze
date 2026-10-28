#!/usr/bin/env bash
# Q-Uplink: reproduce every local result (Linux/macOS).
#   ./scripts/run_all.sh            tests + benchmarks + frontend build (no credits)
#   ./scripts/run_all.sh --qpiai    also key check, Opt platform plan, QRNG on Indus-1, QAOA on QCloud simulator
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "Virtual environment not found; see README.md"; exit 1; }
cd "$ROOT/backend"
echo "== 1/4 Test suite =="; "$PY" -m pytest -q --junitxml=../evidence/tests/junit.xml
echo "== 2/4 Resource measurements =="; "$PY" -m satauth.bench.measure; "$PY" -m satauth.bench.scheme_compare
if [ "${1:-}" = "--qpiai" ]; then
  echo "== 3/4 QpiAI runs =="
  "$PY" scripts/qpiai_runs.py check
  "$PY" scripts/qpiai_runs.py plan --mode platform
  "$PY" scripts/qpiai_runs.py qrng --device QpiAI-Indus-1
  "$PY" scripts/qpiai_runs.py qaoa --mode platform --device QpiAI-QSV-Simulator
else
  echo "== 3/4 QpiAI runs skipped (use --qpiai) =="
fi
echo "== 4/4 Frontend build =="; cd "$ROOT/frontend" && npm run build
echo "Done. Start: cd backend && ../.venv/bin/python -m uvicorn satauth.api.main:app --port 8000"
