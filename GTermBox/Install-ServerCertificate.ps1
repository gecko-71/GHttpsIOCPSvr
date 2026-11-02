[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CertPath = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $CertPath) {
    $Candidates = @(
        (Join-Path $ScriptDir "localhost.cer"),
        (Join-Path $ScriptDir "Win64\Debug\localhost.cer"),
        (Join-Path $ScriptDir "..\localhost.cer"),
        (Join-Path (Get-Location) "localhost.cer"),
        (Join-Path (Get-Location) "GTermBox\Win64\Debug\localhost.cer")
    )
    foreach ($cand in $Candidates) {
        if (Test-Path $cand) {
            $CertPath = (Resolve-Path $cand).Path
            break
        }
    }
}

if (-not $CertPath -or -not (Test-Path $CertPath)) {
    Write-Error "Server certificate file (localhost.cer) not found."
    exit 1
}

Write-Host "Installing server certificate to CurrentUser Trusted Root store..." -ForegroundColor Cyan
Write-Host "Certificate Path: $CertPath" -ForegroundColor DarkGray
Write-Host "NOTE: If a Windows Security Warning popup appears, click 'Yes' to trust the certificate." -ForegroundColor Yellow

$Process = Start-Process -FilePath "certutil.exe" -ArgumentList "-user -addstore Root `"$CertPath`"" -NoNewWindow -Wait -PassThru

if ($Process.ExitCode -eq 0) {
    Write-Host "Server certificate successfully trusted in Windows Root store." -ForegroundColor Green
    Write-Host "WebTransport (HTTP/3) and HTTPS in Chrome/Edge will now be fully trusted without security warnings." -ForegroundColor Green
} else {
    Write-Error "certutil failed with exit code $($Process.ExitCode)"
    exit $Process.ExitCode
}
