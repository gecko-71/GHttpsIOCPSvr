# check_docker_tests_telnet.ps1
# Automatyczny skrypt do sprawdzania stanu procesow, testow i serwerow wewnatrz kontenera Windows Docker przez Telnet na adresie WAN (198.51.100.10:23)

param(
    [string]$HostAddress = "198.51.100.10",
    [int]$Port = 23,
    [switch]$Interactive
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SPRAWDZANIE STANU TESTOW I SERWEROW WINDOWS DOCKER (TELNET)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Docelowy adres serwera Windows (VirtualBox/Docker): ${HostAddress}:${Port}" -ForegroundColor Yellow

if ($Interactive) {
    Write-Host "Uruchamianie interaktywnej sesji telnet na ${HostAddress}:${Port}..." -ForegroundColor Yellow
    telnet.exe $HostAddress $Port
    exit $LASTEXITCODE
}

Write-Host "Logowanie przez Telnet do ${HostAddress}:${Port} w celu sprawdzenia stanu..." -ForegroundColor Yellow

$pyScript = Join-Path $PSScriptRoot "tools\telnet_probe.py"
if (Test-Path $pyScript) {
    python.exe $pyScript $HostAddress $Port
} else {
    Write-Host "Logowanie bezposrednio przez Docker:" -ForegroundColor Green
    docker exec -it gtermbox_windows_wan telnet $HostAddress $Port
}
