param(
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$backendDirectory = Join-Path $repositoryRoot "backend"
$python = Join-Path $backendDirectory ".venv\Scripts\python.exe"
$environmentNames = @(
    "SECURCODE_ENV",
    "SECURCODE_DEMO_MODE",
    "SECURCODE_DATABASE_PATH",
    "SECURCODE_BOOTSTRAP_TOKEN",
    "SECURCODE_BOOTSTRAP_BACKEND",
    "SECURCODE_BOOTSTRAP_WORKING_DIRECTORY"
)
$originalEnvironment = @{}
foreach ($name in $environmentNames) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

$server = $null
$securePassword = $null
$confirmation = $null
$bootstrapSessionToken = $null
$loginSessionToken = $null
$bootstrapToken = $null
$password = $null
$confirmationText = $null
$bootstrapBody = $null
$loginBody = $null
$created = $null
$session = $null

function ConvertFrom-PrivateInput([Security.SecureString]$Value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-AccountCounts([string]$PythonPath) {
    $scriptText = @'
import json
import os
import sqlite3
from pathlib import Path

database = Path(os.environ["SECURCODE_DATABASE_PATH"])
connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
try:
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if "auth_users" not in tables:
        raise RuntimeError("The configured database has no auth_users table.")
    total = connection.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0]
    administrators = connection.execute(
        "SELECT COUNT(*) FROM auth_users WHERE role = 'administrator'"
    ).fetchone()[0]
    print(json.dumps({"total": total, "administrators": administrators}))
finally:
    connection.close()
'@
    $result = $scriptText | & $PythonPath -
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only account inspection failed."
    }
    return ($result | ConvertFrom-Json)
}

function Get-ConfiguredDatabasePath([string]$PythonPath) {
    $scriptText = @'
import os
from pathlib import Path

backend = Path(os.environ["SECURCODE_BOOTSTRAP_BACKEND"]).resolve()
configured = os.environ.get("SECURCODE_DATABASE_PATH")
path = Path(configured if configured and configured.strip() else backend / "sentinelops.db").expanduser()
if not path.is_absolute():
    path = (Path(os.environ["SECURCODE_BOOTSTRAP_WORKING_DIRECTORY"]) / path).resolve()
print(path)
'@
    $result = $scriptText | & $PythonPath -
    if ($LASTEXITCODE -ne 0 -or -not $result) {
        throw "Effective database path could not be resolved from the backend configuration."
    }
    return ($result | Select-Object -Last 1).Trim()
}

function Assert-SessionRevoked([string]$BaseUri, [string]$Token) {
    $revoked = $false
    try {
        $null = Invoke-RestMethod -Uri "$BaseUri/auth/me" `
            -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 10
    } catch {
        $statusCode = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if ($statusCode -eq 401) {
            $revoked = $true
        } else {
            throw "Session revocation could not be verified; response details suppressed."
        }
    }
    if (-not $revoked) {
        throw "Session revocation verification failed."
    }
}

try {
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw "Backend virtual environment was not found."
    }
    $env:SECURCODE_BOOTSTRAP_BACKEND = $backendDirectory
    $env:SECURCODE_BOOTSTRAP_WORKING_DIRECTORY = $repositoryRoot
    $databasePath = Get-ConfiguredDatabasePath $python
    $env:SECURCODE_DATABASE_PATH = $databasePath
    if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) {
        throw "The existing configured database file was not found; no database was created."
    }
    Write-Host "Configured database: $databasePath"
    $counts = Get-AccountCounts $python
    if ($counts.total -ne 0) {
        throw "Bootstrap stopped: the selected database already contains $($counts.total) account(s)."
    }
    Write-Host "Read-only check passed: selected database contains zero accounts."
    if ($WhatIf) {
        Write-Host "Read-only mode: administrator creation was not attempted."
        return
    }

    $username = (Read-Host "Choose administrator username").Trim()
    if ($username.Length -lt 3 -or $username.Length -gt 120) {
        throw "Username must be 3-120 characters."
    }

    $securePassword = Read-Host "Choose administrator password (12-256 characters)" -AsSecureString
    if ($securePassword.Length -lt 12 -or $securePassword.Length -gt 256) {
        throw "Password must be 12-256 characters."
    }
    $confirmation = Read-Host "Re-enter administrator password" -AsSecureString
    $password = ConvertFrom-PrivateInput $securePassword
    $confirmationText = ConvertFrom-PrivateInput $confirmation
    if ($password -cne $confirmationText) {
        throw "The passwords did not match; no account was created."
    }

    $randomBytes = New-Object byte[] 48
    $randomGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $randomGenerator.GetBytes($randomBytes)
        $bootstrapToken = [Convert]::ToBase64String($randomBytes)
    } finally {
        [Array]::Clear($randomBytes, 0, $randomBytes.Length)
        $randomGenerator.Dispose()
    }

    $env:SECURCODE_ENV = "development"
    $env:SECURCODE_DEMO_MODE = "false"
    $env:SECURCODE_BOOTSTRAP_TOKEN = $bootstrapToken

    $portProbe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $portProbe.Start()
    $port = $portProbe.LocalEndpoint.Port
    $portProbe.Stop()
    $baseUri = "http://127.0.0.1:$port"

    $server = Start-Process -FilePath $python `
        -ArgumentList @(
            "-m", "uvicorn", "app.main:app", "--app-dir", "backend",
            "--host", "127.0.0.1", "--port", "$port", "--no-access-log"
        ) `
        -WorkingDirectory $repositoryRoot -PassThru -WindowStyle Hidden

    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $server.Refresh()
        if ($server.HasExited) {
            throw "Temporary loopback API failed to start; response details suppressed."
        }
        try {
            $health = Invoke-RestMethod -Uri "$baseUri/status" -TimeoutSec 2
            if ($health.status -eq "healthy" -and -not $health.demo_mode) {
                $ready = $true
                break
            }
        } catch {
            # The loopback API may still be starting.
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        throw "Temporary loopback API did not become ready; no credentials were submitted."
    }

    $bootstrapBody = @{
        username = $username
        password = $password
        bootstrap_token = $bootstrapToken
    } | ConvertTo-Json -Compress
    try {
        $created = Invoke-RestMethod -Uri "$baseUri/auth/bootstrap" -Method Post `
            -ContentType "application/json" -Body $bootstrapBody -TimeoutSec 30
    } catch {
        $statusCode = 0
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
        }
        if ($statusCode) {
            throw "Bootstrap failed with HTTP $statusCode; response details suppressed."
        }
        throw "Bootstrap failed; response details suppressed."
    }

    if ($created.user.username -ne $username -or $created.user.role -ne "administrator") {
        throw "Bootstrap response did not confirm the requested administrator."
    }
    $bootstrapSessionToken = $created.access_token
    $identity = Invoke-RestMethod -Uri "$baseUri/auth/me" `
        -Headers @{ Authorization = "Bearer $($created.access_token)" } -TimeoutSec 10
    if ($identity.username -ne $username -or $identity.role -ne "administrator") {
        throw "Bootstrap session identity verification failed."
    }
    $null = Invoke-RestMethod -Uri "$baseUri/auth/logout" -Method Post `
        -Headers @{ Authorization = "Bearer $($created.access_token)" } -TimeoutSec 10

    Assert-SessionRevoked $baseUri $bootstrapSessionToken
    $loginBody = @{ username = $username; password = $password } | ConvertTo-Json -Compress
    try {
        $session = Invoke-RestMethod -Uri "$baseUri/auth/login" -Method Post `
            -ContentType "application/json" -Body $loginBody -TimeoutSec 30
    } catch {
        throw "Login verification failed; response details suppressed."
    }
    if ($session.user.username -ne $username -or $session.user.role -ne "administrator") {
        throw "Login identity verification failed."
    }
    $loginSessionToken = $session.access_token
    $null = Invoke-RestMethod -Uri "$baseUri/auth/logout" -Method Post `
        -Headers @{ Authorization = "Bearer $($session.access_token)" } -TimeoutSec 10

    Assert-SessionRevoked $baseUri $loginSessionToken
    Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
    Wait-Process -Id $server.Id -Timeout 10 -ErrorAction SilentlyContinue
    $server.Refresh()
    if (-not $server.HasExited) {
        throw "Temporary API could not be stopped; its bootstrap secret may still be in process memory."
    }
    $server = $null

    $verifiedCounts = Get-AccountCounts $python
    if ($verifiedCounts.total -ne 1 -or $verifiedCounts.administrators -ne 1) {
        throw "Post-bootstrap database verification did not find exactly one administrator."
    }
    Write-Host "Administrator created, login verified, both temporary sessions revoked, and database account counts confirmed."
} finally {
    if ($server) {
        Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
        Wait-Process -Id $server.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
    foreach ($name in $environmentNames) {
        $value = $originalEnvironment[$name]
        if ($null -eq $value) {
            Remove-Item -LiteralPath "Env:\$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path "Env:\$name" -Value $value
        }
    }
    if ($securePassword) { $securePassword.Dispose() }
    if ($confirmation) { $confirmation.Dispose() }
    $password = $null
    $confirmationText = $null
    $bootstrapToken = $null
    $bootstrapSessionToken = $null
    $loginSessionToken = $null
    $bootstrapBody = $null
    $loginBody = $null
    $created = $null
    $session = $null
}
