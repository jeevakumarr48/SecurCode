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
$previousApiBaseUrl = $env:VITE_API_BASE_URL
if ([string]::IsNullOrWhiteSpace($previousApiBaseUrl)) {
    $env:VITE_API_BASE_URL = "https://api.example.invalid"
}
Push-Location (Join-Path $projectRoot "frontend")
try {
    Write-Host "Running frontend tests..." -ForegroundColor Cyan
    npm test
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend tests failed with exit code $LASTEXITCODE"
    }

    Write-Host "Building frontend production bundle..." -ForegroundColor Cyan
    npm run build
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
    if ($null -eq $previousApiBaseUrl) {
        Remove-Item Env:VITE_API_BASE_URL -ErrorAction SilentlyContinue
    }
    else {
        $env:VITE_API_BASE_URL = $previousApiBaseUrl
    }
}

Write-Host "Validation passed." -ForegroundColor Green
