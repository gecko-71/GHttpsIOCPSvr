param(
    [string]$Password = "Simple123!"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DEMO 11: Setup Certificates (Server & Client)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$scriptDir = $PSScriptRoot
$serverDir = Join-Path $scriptDir "server_certificates"
$clientDir = Join-Path $scriptDir "client_certificates"

New-Item -ItemType Directory -Path $serverDir -Force | Out-Null
New-Item -ItemType Directory -Path $clientDir -Force | Out-Null

$secPass = ConvertTo-SecureString $Password -AsPlainText -Force

function Export-PemCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$filePath) {
    $base64 = [System.Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN CERTIFICATE-----`r`n" + $base64 + "`r`n-----END CERTIFICATE-----`r`n"
    [System.IO.File]::WriteAllText($filePath, $pem, [System.Text.Encoding]::ASCII)
}

Write-Host "[1/3] Generating Server Certificate (CN=localhost)..." -ForegroundColor White
$serverCert = New-SelfSignedCertificate `
    -DnsName "localhost", "127.0.0.1" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotBefore (Get-Date).AddDays(-30) `
    -NotAfter (Get-Date).AddYears(5)

$serverStore = Get-Item "Cert:\CurrentUser\GHttpsIOCPSvr" -ErrorAction SilentlyContinue
if (-not $serverStore) {
    New-Item -Path "Cert:\CurrentUser\GHttpsIOCPSvr" -Force | Out-Null
}
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "CurrentUser")
$store.Open("ReadWrite")
$store.Add($serverCert)
$store.Close()

Export-PemCert $serverCert (Join-Path $serverDir "server.crt")
Export-PemCert $serverCert (Join-Path $clientDir "server.crt")
Write-Host "  -> server.crt saved to server_certificates and client_certificates" -ForegroundColor Green

Write-Host "[2/3] Generating Client Certificate (CN=SimpleMtlsClient)..." -ForegroundColor White
$clientCert = New-SelfSignedCertificate `
    -Subject "CN=SimpleMtlsClient" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotBefore (Get-Date).AddDays(-30) `
    -NotAfter (Get-Date).AddYears(5)

$clientPfxPath = Join-Path $clientDir "client.pfx"
Export-PfxCertificate -Cert $clientCert -FilePath $clientPfxPath -Password $secPass | Out-Null
Write-Host "  -> client.pfx saved to client_certificates" -ForegroundColor Green

Export-PemCert $clientCert (Join-Path $clientDir "client.crt")
Export-PemCert $clientCert (Join-Path $serverDir "client.crt")

$clientShaPath = Join-Path $serverDir "client.sha256"
$sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($clientCert.RawData)).Replace("-", "")
[System.IO.File]::WriteAllText($clientShaPath, $sha256)
Write-Host "  -> client.crt & client.sha256 saved to server_certificates ($sha256)" -ForegroundColor Green

$debugDir = Join-Path $scriptDir "Win64\Debug"
if (Test-Path $debugDir) {
    Copy-Item -Path $serverDir -Destination $debugDir -Recurse -Force
    Copy-Item -Path $clientDir -Destination $debugDir -Recurse -Force
    Write-Host "  -> Synced certificate folders to Win64\Debug" -ForegroundColor Yellow
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SETUP COMPLETE!" -ForegroundColor Green
Write-Host " - server_certificates: server.crt, client.crt, client.sha256" -ForegroundColor White
Write-Host " - client_certificates: client.pfx, client.crt, server.crt" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
