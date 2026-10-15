$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectRoot "backend\.venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    throw "Backend virtual environment not found at $python"
}

Write-Host "Running backend tests..." -ForegroundColor Cyan
Push-Location (Join-Path $projectRoot "backend")
try {
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        throw "Backend tests failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "Running frontend production build..." -ForegroundColor Cyan
Push-Location (Join-Path $projectRoot "frontend")
try {
    npm run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "Validation passed." -ForegroundColor Green
