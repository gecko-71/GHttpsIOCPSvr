param(
    [switch]$Parallel = $false
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " COMPREHENSIVE DOCKER + WINDOWS TEST RUNNER (34+ SUITES)    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "[1/2] Verifying Docker container gtermbox_windows_wan..." -ForegroundColor Yellow
$containerId = (docker ps -q --filter "name=gtermbox_windows_wan" | Select-Object -First 1)
if (-not $containerId) {
    Write-Host "Container gtermbox_windows_wan is not running. Starting..." -ForegroundColor Yellow
    docker compose up -d
    Start-Sleep -Seconds 5
} else {
    Write-Host "Container gtermbox_windows_wan is active ($containerId)." -ForegroundColor Green
}

Write-Host "`n[2/2] Running Python test runner..." -ForegroundColor Yellow
$pyArgs = @("run_all_tests_docker.py")
if ($Parallel) {
    $pyArgs += "--parallel"
}

python.exe @pyArgs
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " ALL DOCKER + WINDOWS TESTS PASSED SUCCESSFULLY (100%)       " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Host "`n============================================================" -ForegroundColor Red
    Write-Host " ERRORS OCCURRED DURING TEST SUITE EXECUTION                " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
}

exit $exitCode
