[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Username,

    [Parameter(Position = 1)]
    [string]$CertPath,

    [switch]$Interactive
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ServerDir = $ScriptDir
if (Test-Path (Join-Path $ScriptDir "Win64\Debug\ManageUsers.exe")) {
    $ServerDir = Join-Path $ScriptDir "Win64\Debug"
} elseif (Test-Path (Join-Path (Get-Location) "ManageUsers.exe")) {
    $ServerDir = (Get-Location).Path
}

$ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
$TrustedClientsDir = Join-Path $ServerDir "trusted_clients"

if (-not (Test-Path $ManageUsersExe)) {
    Write-Error "ManageUsers.exe not found. Please compile the project first."
    exit 1
}

if (-not (Test-Path $TrustedClientsDir)) {
    New-Item -ItemType Directory -Path $TrustedClientsDir -Force | Out-Null
}

if (-not $Username -or $Interactive) {
    Write-Host "=== Bind Client Certificate to Existing User ===" -ForegroundColor Cyan
    & $ManageUsersExe list
    Write-Host ""
    $Username = Read-Host "Enter username to bind certificate to"
}

if (-not $Username) {
    Write-Error "Username is required."
    exit 1
}

if (-not $CertPath -or $Interactive) {
    $CertPath = Read-Host "Enter path or filename of client certificate (.crt / .cer)"
}

if (-not $CertPath) {
    Write-Error "Certificate path or filename is required."
    exit 1
}

$ResolvedCertPath = ""
if (Test-Path $CertPath) {
    $ResolvedCertPath = (Resolve-Path $CertPath).Path
} elseif (Test-Path (Join-Path $TrustedClientsDir $CertPath)) {
    $ResolvedCertPath = (Join-Path $TrustedClientsDir $CertPath)
} elseif (Test-Path (Join-Path $ServerDir $CertPath)) {
    $ResolvedCertPath = (Join-Path $ServerDir $CertPath)
} elseif (Test-Path (Join-Path (Get-Location) $CertPath)) {
    $ResolvedCertPath = (Join-Path (Get-Location) $CertPath)
} else {
    Write-Error "Certificate file not found: $CertPath"
    exit 1
}

$CertFileName = Split-Path -Leaf $ResolvedCertPath
$TargetInTrusted = Join-Path $TrustedClientsDir $CertFileName

if (-not (Test-Path $TargetInTrusted) -or ((Resolve-Path $ResolvedCertPath).Path -ne (Resolve-Path $TargetInTrusted).Path)) {
    Write-Host "Copying certificate to trusted_clients directory..." -ForegroundColor Cyan
    Copy-Item -Path $ResolvedCertPath -Destination $TargetInTrusted -Force
    Write-Host "Certificate copied: $TargetInTrusted" -ForegroundColor DarkGray
}

Write-Host "Binding certificate '$CertFileName' to user '$Username'..." -ForegroundColor Cyan
Push-Location $ServerDir
try {
    & $ManageUsersExe bind-cert $Username $CertFileName
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) {
        Write-Host ""
        Write-Host "[SUCCESS] Client certificate '$CertFileName' successfully bound to user '$Username'!" -ForegroundColor Green
        Write-Host "Restart GTermBoxServer to reload the updated whitelist." -ForegroundColor Yellow
        Write-Host ""
        & $ManageUsersExe show $Username
    }
} finally {
    Pop-Location
}

if ($exitCode -ne 0) {
    exit $exitCode
}
