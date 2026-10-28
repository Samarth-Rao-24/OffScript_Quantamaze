# Start Q-Uplink Mission Control (Windows PowerShell).
#   .\scripts\start.ps1          serves the built UI and API on http://127.0.0.1:8000
#   .\scripts\start.ps1 -Dev     API on :8000 plus Vite dev server on http://127.0.0.1:5173 (hot reload)
param([switch]$Dev)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "Virtual environment not found. Run the setup steps in README.md first."; exit 1 }
if (-not (Test-Path (Join-Path $root ".env"))) { Write-Warning ".env not found: QpiAI Opt and QCloud features will report missing keys." }

if ($Dev) {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm", "run", "dev" -WorkingDirectory (Join-Path $root "frontend")
    Write-Host "UI (dev): http://127.0.0.1:5173" -ForegroundColor Green
} elseif (-not (Test-Path (Join-Path $root "frontend\dist\index.html"))) {
    Write-Warning "frontend\dist not built yet. Run: cd frontend; npm run build"
} else {
    Write-Host "Open http://127.0.0.1:8000" -ForegroundColor Green
}
Push-Location (Join-Path $root "backend")
try { & $py -m uvicorn satauth.api.main:app --host 127.0.0.1 --port 8000 } finally { Pop-Location }
