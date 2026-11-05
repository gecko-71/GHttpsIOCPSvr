# test_dockur_windows_wan.ps1
# Automatyczny skrypt testowy weryfikujacy dzialanie GTermBoxServer w kontenerze dockurr/windows przez adres WAN

param(
    [string]$TargetHost = "localhost",
    [int]$TargetPort = 8543,
    [string]$WanHost = "198.51.100.10"
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TESTY SIECIOWE WAN DLA GTERMBOXSERVER W DOCKURR/WINDOWS    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Docelowy endpoint testu: https://${TargetHost}:${TargetPort}/ (Host/WAN: ${WanHost}:${TargetPort})" -ForegroundColor Yellow

$passed = 0
$failed = 0

function Assert-Result($name, $condition, $details) {
    if ($condition) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "  [FAIL] $name - $details" -ForegroundColor Red
        $script:failed++
    }
}

# 1. Test sprawdzajacy gotowosc serwera (healthcheck)
Write-Host "`n[Test 1] Sprawdzanie polaczenia i pobranie skrotu certyfikatu..." -ForegroundColor Yellow
$out1 = curl.exe -k -s -i --max-time 10 --retry 3 --retry-connrefused -H "Host: ${WanHost}:${TargetPort}" -H "Origin: https://${WanHost}:${TargetPort}" "https://${TargetHost}:${TargetPort}/api/certificate-hash" 2>&1
$status1 = ($out1 | Select-String -Pattern "HTTP/.* ([0-9]{3})" | ForEach-Object { $_.Matches.Groups[1].Value }) | Select-Object -First 1
Assert-Result "Status 200 OK dla żądania Same-Origin z adresem WAN ($WanHost)" ($status1 -eq "200") "Otrzymano status: $status1"
Start-Sleep -Milliseconds 250

# 2. Test blokady Cross-Origin (CSRF / CSWSH)
Write-Host "`n[Test 2] Test ochrony przed atakiem Cross-Origin (Origin: evil-attacker.com)..." -ForegroundColor Yellow
$loginBadOrigin = '{"username":"usr1","password":"1234"}'
$tempFileBad = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllText($tempFileBad, $loginBadOrigin)
$out2 = curl.exe -k -s -i --max-time 10 --retry 3 --retry-connrefused -X POST -H "Content-Type: application/json" -H "Host: ${WanHost}:${TargetPort}" -H "Origin: https://evil-attacker.com" --data-binary "@$tempFileBad" "https://${TargetHost}:${TargetPort}/api/login" 2>&1
Remove-Item $tempFileBad -ErrorAction SilentlyContinue
$status2 = ($out2 | Select-String -Pattern "HTTP/.* ([0-9]{3})" | ForEach-Object { $_.Matches.Groups[1].Value }) | Select-Object -First 1
Assert-Result "Status 403 Forbidden dla obcego Origin atakującego" ($status2 -eq "403") "Otrzymano status: $status2"
Start-Sleep -Milliseconds 250

# 3. Test logowania uzytkownika usr1
Write-Host "`n[Test 3] Test logowania użytkownika usr1 przez adres WAN ($WanHost)..." -ForegroundColor Yellow
$loginPayload = '{"username":"usr1","password":"1234"}'
$tempFileLogin = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllText($tempFileLogin, $loginPayload)
$out3 = curl.exe -k -s -i --max-time 10 --retry 3 --retry-connrefused -X POST -H "Content-Type: application/json" -H "Host: ${WanHost}:${TargetPort}" -H "Origin: https://${WanHost}:${TargetPort}" --data-binary "@$tempFileLogin" "https://${TargetHost}:${TargetPort}/api/login" 2>&1
Remove-Item $tempFileLogin -ErrorAction SilentlyContinue
$status3 = ($out3 | Select-String -Pattern "HTTP/.* ([0-9]{3})" | ForEach-Object { $_.Matches.Groups[1].Value }) | Select-Object -First 1
$tokenMatch = ($out3 | Select-String -Pattern '"token":\s*"([^"]+)"')
$token = if ($tokenMatch) { $tokenMatch.Matches.Groups[1].Value } else { "" }

Assert-Result "Status 200 OK i wygenerowanie tokenu JWT dla usr1" ($status3 -eq "200" -and $token.Length -gt 20) "Status: $status3, token dlugosc: $($token.Length)"
Start-Sleep -Milliseconds 250

# 4. Test autoryzowanego zapytania o liste aplikacji RBAC
Write-Host "`n[Test 4] Pobranie listy aplikacji RBAC z tokenem JWT..." -ForegroundColor Yellow
if ($token) {
    $out4 = curl.exe -k -s -i --max-time 10 --retry 3 --retry-connrefused -H "Authorization: Bearer $token" -H "Host: ${WanHost}:${TargetPort}" "https://${TargetHost}:${TargetPort}/api/apps" 2>&1
    $status4 = ($out4 | Select-String -Pattern "HTTP/.* ([0-9]{3})" | ForEach-Object { $_.Matches.Groups[1].Value }) | Select-Object -First 1
    $hasApps = ($out4 | Select-String -Pattern "powershell|cmd")
    Assert-Result "Status 200 OK i poprawny zwrot listy aplikacji RBAC" ($status4 -eq "200" -and $hasApps) "Status: $status4"
} else {
    Assert-Result "Pobranie aplikacji RBAC z tokenem JWT" $false "Brak tokenu z kroku 3"
}
Start-Sleep -Milliseconds 250

# 5. Test Directory Traversal
Write-Host "`n[Test 5] Weryfikacja blokady Directory Traversal (zakres piaskownicy)..." -ForegroundColor Yellow
if ($token) {
    $out5 = curl.exe -k -s -i --max-time 10 --retry 3 --retry-connrefused -H "Authorization: Bearer $token" -H "Host: ${WanHost}:${TargetPort}" "https://${TargetHost}:${TargetPort}/api/files?action=list&path=../../windows/system32" 2>&1
    $status5 = ($out5 | Select-String -Pattern "HTTP/.* ([0-9]{3})" | ForEach-Object { $_.Matches.Groups[1].Value }) | Select-Object -First 1
    Assert-Result "Blokada ucieczki z piaskownicy (kod 400 Bad Request / 403 Forbidden)" ($status5 -eq "403" -or $status5 -eq "400") "Otrzymano status: $status5"
} else {
    Assert-Result "Blokada Directory Traversal" $false "Brak tokenu"
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " WYNIK TESTOW WAN: ZDANE: $passed, NIEZDANE: $failed        " -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "============================================================" -ForegroundColor Cyan

if ($failed -gt 0) {
    exit 1
} else {
    exit 0
}
