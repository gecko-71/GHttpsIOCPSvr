# run_dockur_windows_wan.ps1
# Skrypt uruchamiajacy kontener Windows w srodowisku Docker (dockurr/windows) z adresem WAN

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " START SRODOWISKA DOCKURR/WINDOWS WAN DLA GTERMBOXSERVER " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Sprawdzenie stanu Dockera i jego uruchomienie
Write-Host "[1/5] Weryfikacja dostepnosci silnika Docker..." -ForegroundColor Yellow
$dockerCliPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"

$dockerVersion = $null
try {
    $v = & docker version --format '{{.Server.Version}}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $v) { $dockerVersion = $v }
} catch { }

if (-not $dockerVersion) {
    if (Test-Path $dockerCliPath) {
        Write-Host "  -> Docker Desktop jest wylaczony. Uruchamianie procesu..." -ForegroundColor Yellow
        Start-Process $dockerCliPath
        Write-Host "  -> Oczekiwanie na inicjalizacje silnika Docker (moze potrwac do 30 sekund)..." -ForegroundColor Yellow
        
        $retries = 20
        while ($retries -gt 0) {
            Start-Sleep -Seconds 3
            try {
                $v = & docker version --format '{{.Server.Version}}' 2>$null
                if ($LASTEXITCODE -eq 0 -and $v) {
                    $dockerVersion = $v
                    break
                }
            } catch { }
            $retries--
            Write-Host -NoNewline "."
        }
        Write-Host ""
    } else {
        Write-Error "Nie znaleziono Docker Desktop pod sciezka: $dockerCliPath. Zainstaluj Docker Desktop."
        exit 1
    }
}

if ($dockerVersion) {
    Write-Host "  -> Docker Server aktywny (wersja: $dockerVersion)" -ForegroundColor Green
} else {
    Write-Error "Nie udalo sie polaczyc z silnikiem Docker. Uruchom Docker Desktop recznie i sprobuj ponownie."
    exit 1
}

# 2. Utworzenie sieci z podsiecia publiczna WAN RFC 5737 TEST-NET-2 (198.51.100.0/24)
Write-Host "[2/5] Weryfikacja sieci Docker 'wan_net' (198.51.100.0/24)..." -ForegroundColor Yellow
$netSubnet = docker network inspect wan_net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>$null
if ($netSubnet -and $netSubnet -ne "198.51.100.0/24") {
    Write-Host "  -> Usuwanie starej konfiguracji sieci wan_net ($netSubnet)..." -ForegroundColor Yellow
    docker network rm wan_net 2>$null | Out-Null
    $netSubnet = $null
}

if (-not $netSubnet) {
    Write-Host "  -> Tworzenie sieci 'wan_net' (subnet: 198.51.100.0/24, gateway: 198.51.100.1)..." -ForegroundColor Yellow
    docker network create --subnet 198.51.100.0/24 --gateway 198.51.100.1 wan_net | Out-Null
    Write-Host "  -> Siec 'wan_net' utworzona pomyslnie (198.51.100.0/24)." -ForegroundColor Green
} else {
    Write-Host "  -> Siec 'wan_net' (198.51.100.0/24) juz istnieje." -ForegroundColor Green
}

# 3. Przygotowanie zasobow OEM dla instalatora Windows
Write-Host "[3/5] Kopiowanie aktualnych plikow serwera do katalogu OEM..." -ForegroundColor Yellow
$oemDir = Join-Path $PSScriptRoot "oem"
if (-not (Test-Path $oemDir)) {
    New-Item -ItemType Directory -Path $oemDir -Force | Out-Null
}

$storageDir = Join-Path $PSScriptRoot "storage_win"
if (-not (Test-Path $storageDir)) {
    New-Item -ItemType Directory -Path $storageDir -Force | Out-Null
}

# Kopiowanie najnowszych binariow serwera do OEM
Copy-Item "GTermBox\Win64\Debug\GTermBoxServer.exe" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\msquic.dll" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\ls-qpack.dll" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\users.json" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\apps.json" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\localhost.cer" "$oemDir\" -Force
Copy-Item "GTermBox\Win64\Debug\trusted_clients" "$oemDir\trusted_clients" -Recurse -Force
Copy-Item "GTermBox\web" "$oemDir\web" -Recurse -Force

Write-Host "  -> Pliki serwera i skrypt install.bat zsynchronizowane w katalogu OEM." -ForegroundColor Green

# 4. Uruchomienie kontenera dockurr/windows
Write-Host "[4/5] Uruchamianie kontenera dockurr/windows (docker compose up -d)..." -ForegroundColor Yellow
docker compose up -d

Write-Host "  -> Kontener 'gtermbox_windows_wan' uruchomiony w tle." -ForegroundColor Green
Write-Host "  -> Adres WAN w kontenerze: 198.51.100.10" -ForegroundColor Cyan
Write-Host "  -> Port serwera HTTPS/WT:  8443 (TCP/UDP)" -ForegroundColor Cyan
Write-Host "  -> Podglad instalacji GUI: http://localhost:8006" -ForegroundColor Cyan

# 5. Oczekiwanie na gotowosc uslug
Write-Host "[5/5] Status srodowiska..." -ForegroundColor Yellow
Write-Host "Podczas pierwszego uruchomienia instalator Windows pobiera i instaluje system automatycznie (ok. 5-10 min)."
Write-Host "Postep instalacji mozesz obserwowac w przegladarce: http://localhost:8006"
Write-Host "Gdy system Windows sie uruchomi, install.bat uruchomi GTermBoxServer automatycznie."
Write-Host "Aby wykonac testy, wpisz w terminalu: .\test_dockur_windows_wan.ps1 -WanHost 198.51.100.10" -ForegroundColor Yellow
