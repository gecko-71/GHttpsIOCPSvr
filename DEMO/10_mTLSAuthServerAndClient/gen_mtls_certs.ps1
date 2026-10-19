param(
    [string]$ServerDir = "",
    [string]$ClientDir = "",
    [string]$Password = "1234",
    [switch]$InstallLocalhostCert
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "     GHttpsIOCPSvr - mTLS Demonstration Certificate Generator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$baseDir = Join-Path $PSScriptRoot "Win64\Debug"

if ([string]::IsNullOrWhiteSpace($ServerDir)) {
    $ServerDir = Join-Path $baseDir "cercts_server"
}
if ([string]::IsNullOrWhiteSpace($ClientDir)) {
    $ClientDir = Join-Path $baseDir "cercts_client"
}

if (-not (Test-Path -Path $ServerDir)) {
    New-Item -ItemType Directory -Path $ServerDir -Force | Out-Null
}
if (-not (Test-Path -Path $ClientDir)) {
    New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null
}

$ServerDir = (Resolve-Path $ServerDir).Path
$ClientDir = (Resolve-Path $ClientDir).Path
Write-Host "Server Certificate Directory: $ServerDir" -ForegroundColor Yellow
Write-Host "Client Certificate Directory: $ClientDir" -ForegroundColor Yellow

$secPass = ConvertTo-SecureString $Password -AsPlainText -Force

function Export-PemCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$filePath) {
    $base64 = [System.Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN CERTIFICATE-----`r`n" + $base64 + "`r`n-----END CERTIFICATE-----`r`n"
    [System.IO.File]::WriteAllText($filePath, $pem, [System.Text.Encoding]::ASCII)
}

$createdCerts = @()

try {
    Write-Host "[1/5] Generating mTLS Root CA Certificate..." -ForegroundColor White
    $rootCa = New-SelfSignedCertificate `
        -Subject "CN=GHttpsIOCP-DemoRootCA" `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -KeyUsageProperty All `
        -TextExtension @("2.5.29.19={critical}{text}ca=1") `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddDays(-30) `
        -NotAfter (Get-Date).AddYears(5)
    $createdCerts += $rootCa

    $serverRootCaPath = Join-Path $ServerDir "test_root_ca.crt"
    Export-PemCert $rootCa $serverRootCaPath

    $clientRootCaPath = Join-Path $ClientDir "test_root_ca.crt"
    Export-PemCert $rootCa $clientRootCaPath
    Write-Host "  -> Created: test_root_ca.crt in server and client dirs [Thumbprint: $($rootCa.Thumbprint)]" -ForegroundColor Green

    Write-Host "[2/5] Generating Valid Client Certificate (signed by Root CA)..." -ForegroundColor White
    $validCert = New-SelfSignedCertificate `
        -Subject "CN=DemoAuthorizedClient" `
        -Signer $rootCa `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @(
            "2.5.29.17={text}dns=demo-client.local&dns=localhost",
            "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
        ) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddDays(-1) `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyExportPolicy Exportable
    $createdCerts += $validCert

    $validPfxPath = Join-Path $ClientDir "client_valid.pfx"
    Export-PfxCertificate -Cert $validCert -FilePath $validPfxPath -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
    Write-Host "  -> Created: $validPfxPath [CN: DemoAuthorizedClient]" -ForegroundColor Green

    Write-Host "[3/5] Generating Untrusted Client Certificate (Rogue / Self-signed)..." -ForegroundColor White
    $untrustedCert = New-SelfSignedCertificate `
        -Subject "CN=DemoUntrustedClient" `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @(
            "2.5.29.17={text}dns=untrusted.local",
            "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
        ) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddDays(-1) `
        -NotAfter (Get-Date).AddYears(1) `
        -KeyExportPolicy Exportable
    $createdCerts += $untrustedCert

    $untrustedPfxPath = Join-Path $ClientDir "client_untrusted.pfx"
    Export-PfxCertificate -Cert $untrustedCert -FilePath $untrustedPfxPath -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
    Write-Host "  -> Created: $untrustedPfxPath [CN: DemoUntrustedClient]" -ForegroundColor Green

    Write-Host "[4/5] Generating Expired Client Certificate (signed by Root CA)..." -ForegroundColor White
    $expiredCert = New-SelfSignedCertificate `
        -Subject "CN=DemoExpiredClient" `
        -Signer $rootCa `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @(
            "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
        ) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddYears(-2) `
        -NotAfter (Get-Date).AddDays(-1) `
        -KeyExportPolicy Exportable
    $createdCerts += $expiredCert

    $expiredPfxPath = Join-Path $ClientDir "client_expired.pfx"
    Export-PfxCertificate -Cert $expiredCert -FilePath $expiredPfxPath -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
    Write-Host "  -> Created: $expiredPfxPath [CN: DemoExpiredClient]" -ForegroundColor Green

    Write-Host "[5/5] Generating Dedicated Pinned Client Certificate (Direct Trust / Certificate Pinning)..." -ForegroundColor White
    $pinnedCert = New-SelfSignedCertificate `
        -Subject "CN=DemoPinnedDirectTrustClient" `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @(
            "2.5.29.17={text}dns=pinned-client.local",
            "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
        ) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddDays(-1) `
        -NotAfter (Get-Date).AddYears(2) `
        -KeyExportPolicy Exportable
    $createdCerts += $pinnedCert

    $pinnedPfxPath = Join-Path $ClientDir "client_pinned.pfx"
    Export-PfxCertificate -Cert $pinnedCert -FilePath $pinnedPfxPath -Password $secPass -ChainOption EndEntityCertOnly | Out-Null

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hasher.ComputeHash($pinnedCert.RawData)
    $pinnedSha256 = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""

    $serverPinnedCrtPath = Join-Path $ServerDir "client_pinned.crt"
    Export-PemCert $pinnedCert $serverPinnedCrtPath
    [System.IO.File]::WriteAllText((Join-Path $ServerDir "client_pinned.sha256"), $pinnedSha256, [System.Text.Encoding]::ASCII)

    $clientPinnedCrtPath = Join-Path $ClientDir "client_pinned.crt"
    Export-PemCert $pinnedCert $clientPinnedCrtPath
    [System.IO.File]::WriteAllText((Join-Path $ClientDir "client_pinned.sha256"), $pinnedSha256, [System.Text.Encoding]::ASCII)

    Write-Host "  -> Created: client_pinned.pfx in client dir, client_pinned.crt & .sha256 in server dir [SHA-256: $pinnedSha256]" -ForegroundColor Green

    if ($InstallLocalhostCert) {
        Write-Host "[+] Installing standard RSA localhost server certificate..." -ForegroundColor White
        $serverCert = New-SelfSignedCertificate `
            -DnsName "localhost", "127.0.0.1", $env:COMPUTERNAME `
            -FriendlyName "GHttpsIOCPSvr" `
            -KeyUsage DigitalSignature, KeyEncipherment `
            -KeyUsageProperty All `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -HashAlgorithm SHA256 `
            -KeyExportPolicy Exportable
        Write-Host "  -> Installed localhost cert in Cert:\LocalMachine\My [Thumbprint: $($serverCert.Thumbprint)]" -ForegroundColor Green
    }

    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Certificate generation completed successfully!" -ForegroundColor Green
    Write-Host "Server certificates in ${ServerDir}:" -ForegroundColor White
    Write-Host "  - test_root_ca.crt     (Root CA public certificate for verifying client certs)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.crt    (Public certificate for SHA-256 thumbprint pinning)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.sha256 (Pinned client SHA-256 thumbprint)" -ForegroundColor Yellow
    Write-Host "Client certificates in ${ClientDir}:" -ForegroundColor White
    Write-Host "  - client_valid.pfx     (Valid client certificate signed by CA, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_untrusted.pfx (Untrusted client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_expired.pfx   (Expired client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.pfx    (Pinned client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
}
finally {
    foreach ($cert in $createdCerts) {
        if ($null -ne $cert -and -not [string]::IsNullOrEmpty($cert.Thumbprint)) {
            Get-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
