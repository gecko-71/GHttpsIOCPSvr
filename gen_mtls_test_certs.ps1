param (
    [string]$OutputDir = "$PSScriptRoot\test_certs"
)

Write-Host "[mTLS PKI] Inicjalizacja generowania certyfikatow w katalogu: $OutputDir" -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$OpenSslExe = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $OpenSslExe) {
    $StandardPaths = @(
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe"
    )
    foreach ($p in $StandardPaths) {
        if (Test-Path $p) {
            $OpenSslExe = $p
            break
        }
    }
}

if (-not $OpenSslExe) {
    Write-Error "Blad: openssl.exe nie zostal znaleziony w sciezce PATH ani w standardowych katalogach."
    exit 1
}

Write-Host "[mTLS PKI] Wykryto OpenSSL: $OpenSslExe" -ForegroundColor Green

$CaKey = "$OutputDir\test_root_ca.key"
$CaCrt = "$OutputDir\test_root_ca.crt"
if (-not (Test-Path $CaCrt)) {
    Write-Host "[mTLS PKI] Generowanie Test Root CA..." -ForegroundColor Yellow
    & $OpenSslExe req -x509 -newkey rsa:2048 -nodes -keyout $CaKey -out $CaCrt -days 365 -subj "/CN=GHttpsIOCP-TestRootCA/O=TestOrg/C=PL"
}

$SvrKey = "$OutputDir\server.key"
$SvrCsr = "$OutputDir\server.csr"
$SvrCrt = "$OutputDir\server.crt"
$SvrExt = "$OutputDir\server.ext"
$SvrPfx = "$OutputDir\server.pfx"

if (-not (Test-Path $SvrCrt)) {
    Write-Host "[mTLS PKI] Generowanie Certyfikatu Serwera (SAN: localhost)..." -ForegroundColor Yellow
    & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $SvrKey -out $SvrCsr -subj "/CN=localhost/O=TestOrg/C=PL"
    @"
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"@ | Set-Content $SvrExt -Encoding ASCII

    & $OpenSslExe x509 -req -in $SvrCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $SvrCrt -days 365 -extfile $SvrExt
    & $OpenSslExe pkcs12 -export -out $SvrPfx -inkey $SvrKey -in $SvrCrt -passout pass:testpassword
}

$CliKey = "$OutputDir\client_valid.key"
$CliCsr = "$OutputDir\client_valid.csr"
$CliCrt = "$OutputDir\client_valid.crt"
$CliExt = "$OutputDir\client_valid.ext"
$CliPfx = "$OutputDir\client_valid.pfx"

if (-not (Test-Path $CliCrt)) {
    Write-Host "[mTLS PKI] Generowanie Autoryzowanego Certyfikatu Klienta (CN=AuthorizedClient1)..." -ForegroundColor Yellow
    & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $CliKey -out $CliCsr -subj "/CN=AuthorizedClient1/O=ClientOrg/C=PL"
    @"
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"@ | Set-Content $CliExt -Encoding ASCII

    & $OpenSslExe x509 -req -in $CliCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $CliCrt -days 365 -extfile $CliExt
    & $OpenSslExe pkcs12 -export -out $CliPfx -inkey $CliKey -in $CliCrt -passout pass:testpassword
}

$ExpKey = "$OutputDir\client_expired.key"
$ExpCsr = "$OutputDir\client_expired.csr"
$ExpCrt = "$OutputDir\client_expired.crt"

if (-not (Test-Path $ExpCrt)) {
    Write-Host "[mTLS PKI] Generowanie Wygaslego Certyfikatu Klienta..." -ForegroundColor Yellow
    & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $ExpKey -out $ExpCsr -subj "/CN=ExpiredClient/O=ClientOrg/C=PL"
    & $OpenSslExe x509 -req -in $ExpCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $ExpCrt -days -1 -extfile $CliExt
}

$RogueCaKey = "$OutputDir\rogue_ca.key"
$RogueCaCrt = "$OutputDir\rogue_ca.crt"
$UntrustedKey = "$OutputDir\client_untrusted.key"
$UntrustedCsr = "$OutputDir\client_untrusted.csr"
$UntrustedCrt = "$OutputDir\client_untrusted.crt"

if (-not (Test-Path $UntrustedCrt)) {
    Write-Host "[mTLS PKI] Generowanie Niezaufanego Certyfikatu Klienta (Rogue CA)..." -ForegroundColor Yellow
    & $OpenSslExe req -x509 -newkey rsa:2048 -nodes -keyout $RogueCaKey -out $RogueCaCrt -days 30 -subj "/CN=RogueUntrustedCA/C=XX"
    & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $UntrustedKey -out $UntrustedCsr -subj "/CN=RogueClient/C=XX"
    & $OpenSslExe x509 -req -in $UntrustedCsr -CA $RogueCaCrt -CAkey $RogueCaKey -CAcreateserial -out $UntrustedCrt -days 30 -extfile $CliExt
}

Write-Host "[mTLS PKI] Wszystkie certyfikaty testowe wygenerowane pomyslnie w: $OutputDir" -ForegroundColor Green
