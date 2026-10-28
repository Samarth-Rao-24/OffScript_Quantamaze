# Q-Uplink: reproduce every local result in one command (Windows PowerShell).
#   .\scripts\run_all.ps1              tests + benchmarks + frontend build (no credits)
#   .\scripts\run_all.ps1 -WithQpiAI   also: key check, Opt platform plan, QRNG on Indus-1, QAOA on QCloud simulator
#                                      (each paid step asks for confirmation)
param([switch]$WithQpiAI)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "Virtual environment not found. Run the setup steps in README.md first."; exit 1 }

Push-Location (Join-Path $root "backend")
try {
    Write-Host "== 1/4 Test suite (pytest) ==" -ForegroundColor Cyan
    & $py -m pytest -q --junitxml=..\evidence\tests\junit.xml
    if ($LASTEXITCODE -ne 0) { Write-Error "Tests failed."; exit 1 }

    Write-Host "== 2/4 Resource measurements ==" -ForegroundColor Cyan
    & $py -m satauth.bench.measure
    & $py -m satauth.bench.scheme_compare

    if ($WithQpiAI) {
        Write-Host "== 3/4 QpiAI runs ==" -ForegroundColor Cyan
        & $py scripts\qpiai_runs.py check
        if ($LASTEXITCODE -ne 0) { Write-Error "Key check failed; fix .env before paid runs."; exit 1 }
        & $py scripts\qpiai_runs.py plan --mode platform
        & $py scripts\qpiai_runs.py qrng --device QpiAI-Indus-1
        & $py scripts\qpiai_runs.py qaoa --mode platform --device QpiAI-QSV-Simulator
    } else {
        Write-Host "== 3/4 QpiAI runs skipped (use -WithQpiAI) ==" -ForegroundColor DarkGray
    }
} finally { Pop-Location }

Write-Host "== 4/4 Frontend build ==" -ForegroundColor Cyan
Push-Location (Join-Path $root "frontend")
try { npm run build } finally { Pop-Location }
Write-Host "Done. Evidence is in .\evidence. Start the app with .\scripts\start.ps1" -ForegroundColor Green
