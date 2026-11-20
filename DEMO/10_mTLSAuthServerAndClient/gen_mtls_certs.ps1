param(
    [string]$ServerDir = "",
    [string]$ClientDir = "",
    [string]$Password = "1234",
    [switch]$InstallLocalhostCert,
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    $relaunchArgs = @("-ExecutionPolicy", "Bypass", "-NoProfile", "-File", $MyInvocation.MyCommand.Path, "-ServerDir", $ServerDir, "-ClientDir", $ClientDir, "-Password", $Password)
    if ($InstallLocalhostCert) { $relaunchArgs += "-InstallLocalhostCert" }
    if (-not [string]::IsNullOrWhiteSpace($TlsProvider)) { $relaunchArgs += @("-TlsProvider", $TlsProvider) }
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @relaunchArgs
    exit $LASTEXITCODE
}

$ErrorActionPreference = "Stop"

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "     GHttpsIOCPSvr - mTLS Demonstration Certificate Generator" -ForegroundColor Cyan
Write-Host "     Active TLS Profile: $EffectiveTlsProvider" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$baseDir = Join-Path $PSScriptRoot "Win64\Debug"

if ([string]::IsNullOrWhiteSpace($ServerDir)) {
    $ServerDir = Join-Path $baseDir "cercts_server"
} elseif (-not [System.IO.Path]::IsPathRooted($ServerDir)) {
    $ServerDir = Join-Path $PSScriptRoot $ServerDir
}
if ([string]::IsNullOrWhiteSpace($ClientDir)) {
    $ClientDir = Join-Path $baseDir "cercts_client"
} elseif (-not [System.IO.Path]::IsPathRooted($ClientDir)) {
    $ClientDir = Join-Path $PSScriptRoot $ClientDir
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

function Export-PemPrivateKey([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$filePath) {
    try {
        $pkcs8 = $null
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($rsa) {
            if ($rsa.PSObject.Methods['ExportPkcs8PrivateKey']) {
                $pkcs8 = $rsa.ExportPkcs8PrivateKey()
            } elseif ($rsa -is [System.Security.Cryptography.RSACng]) {
                $pkcs8 = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            }
        } else {
            $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
            if ($ecdsa) {
                if ($ecdsa.PSObject.Methods['ExportPkcs8PrivateKey']) {
                    $pkcs8 = $ecdsa.ExportPkcs8PrivateKey()
                } elseif ($ecdsa -is [System.Security.Cryptography.ECDsaCng]) {
                    $pkcs8 = $ecdsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
                }
            }
        }
        if ($pkcs8) {
            $k64 = [System.Convert]::ToBase64String($pkcs8, [System.Base64FormattingOptions]::InsertLineBreaks)
            $keyPem = "-----BEGIN PRIVATE KEY-----`r`n" + $k64 + "`r`n-----END PRIVATE KEY-----`r`n"
            [System.IO.File]::WriteAllText($filePath, $keyPem, [System.Text.Encoding]::ASCII)
            return $true
        }
    } catch {
    }
    return $false
}

$relDllSources = @(
    (Join-Path $PSScriptRoot "..\..\Win64\Debug"),
    (Join-Path $PSScriptRoot "..\..\Win64\Release")
)
if (Test-Path $baseDir) {
    foreach ($dll in @("libcrypto-3-x64.dll", "libssl-3-x64.dll")) {
        $dst = Join-Path $baseDir $dll
        if (-not (Test-Path $dst)) {
            foreach ($srcDir in $relDllSources) {
                $cand = Join-Path $srcDir $dll
                if (Test-Path $cand) {
                    Copy-Item -Path $cand -Destination $dst -Force
                    break
                }
            }
        }
    }
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
    Export-PemCert $validCert (Join-Path $ClientDir "client_valid.crt")
    $null = Export-PemPrivateKey $validCert (Join-Path $ClientDir "client_valid.key")
    Write-Host "  -> Created: $validPfxPath (+ .crt/.key) [CN: DemoAuthorizedClient]" -ForegroundColor Green

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
    Export-PemCert $untrustedCert (Join-Path $ClientDir "client_untrusted.crt")
    $null = Export-PemPrivateKey $untrustedCert (Join-Path $ClientDir "client_untrusted.key")
    Write-Host "  -> Created: $untrustedPfxPath (+ .crt/.key) [CN: DemoUntrustedClient]" -ForegroundColor Green

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
    Export-PemCert $expiredCert (Join-Path $ClientDir "client_expired.crt")
    $null = Export-PemPrivateKey $expiredCert (Join-Path $ClientDir "client_expired.key")
    Write-Host "  -> Created: $expiredPfxPath (+ .crt/.key) [CN: DemoExpiredClient]" -ForegroundColor Green

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
    $null = Export-PemPrivateKey $pinnedCert (Join-Path $ClientDir "client_pinned.key")
    [System.IO.File]::WriteAllText((Join-Path $ClientDir "client_pinned.sha256"), $pinnedSha256, [System.Text.Encoding]::ASCII)

    Write-Host "  -> Created: client_pinned.pfx, client_pinned.crt & .key in client dir, client_pinned.crt & .sha256 in server dir [SHA-256: $pinnedSha256]" -ForegroundColor Green

    $detectedServerIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -ExpandProperty IPAddress)
    $serverDnsNames = @("localhost", "127.0.0.1")
    if ($detectedServerIps) { $serverDnsNames += $detectedServerIps }
    $serverDnsNames = @($serverDnsNames | Select-Object -Unique)
    $demoServerCert = New-SelfSignedCertificate `
        -DnsName $serverDnsNames `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm ECDSA_nistP256 `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature `
        -KeyExportPolicy Exportable `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
        -NotBefore (Get-Date).AddDays(-1) `
        -NotAfter (Get-Date).AddDays(13) `
        -FriendlyName "GHttpsIOCPSvr-Demo10"
    $createdCerts += $demoServerCert
    Export-PemCert $demoServerCert (Join-Path $ServerDir "server.crt")
    $null = Export-PemPrivateKey $demoServerCert (Join-Path $ServerDir "server.key")
    if (Test-Path $baseDir) {
        $baseCertsDir = Join-Path $baseDir "certs"
        if (-not (Test-Path $baseCertsDir)) {
            New-Item -ItemType Directory -Path $baseCertsDir -Force | Out-Null
        }
        Export-PemCert $demoServerCert (Join-Path $baseCertsDir "server.crt")
        $null = Export-PemPrivateKey $demoServerCert (Join-Path $baseCertsDir "server.key")
    }

    if ($InstallLocalhostCert) {
        try {
            $cuGhStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "CurrentUser")
            $cuGhStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $toRemove = @($cuGhStore.Certificates | Where-Object { $_.Subject -like "*CN=localhost*" })
            foreach ($oldC in $toRemove) {
                $cuGhStore.Remove($oldC)
            }
            $cuGhStore.Close()
        } catch {}

        $existingLmCert = Get-ChildItem -Path "Cert:\LocalMachine\GHttpsIOCPSvr" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Subject -like "*CN=localhost*" -and
                $_.NotAfter -gt (Get-Date).AddDays(1) -and
                (($_.NotAfter - $_.NotBefore).TotalDays -le 14.1) -and
                $_.PublicKey.Oid.Value -eq "1.2.840.10045.2.1"
            } | Select-Object -First 1

        if ($null -ne $existingLmCert) {
            Write-Host "  -> Reusing valid W3C ECDSA P-256 server certificate in Cert:\LocalMachine\GHttpsIOCPSvr [Thumbprint: $($existingLmCert.Thumbprint)]" -ForegroundColor Green
        } else {
            $rootW3cScript = Join-Path $PSScriptRoot "..\..\gen_w3c_wt_cert.ps1"
            if (Test-Path $rootW3cScript) {
                Write-Host "[+] Installing W3C WebTransport ECDSA P-256 server certificate via gen_w3c_wt_cert.ps1..." -ForegroundColor White
                & $rootW3cScript -TlsProvider $EffectiveTlsProvider
            }
        }
    }

    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "Certificate generation completed successfully! (TLS Profile: $EffectiveTlsProvider)" -ForegroundColor Green
    Write-Host "Server certificates in ${ServerDir}:" -ForegroundColor White
    Write-Host "  - test_root_ca.crt     (Root CA public certificate for verifying client certs)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.crt    (Public certificate for SHA-256 thumbprint pinning)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.sha256 (Pinned client SHA-256 thumbprint)" -ForegroundColor Yellow
    Write-Host "Client certificates in ${ClientDir}:" -ForegroundColor White
    Write-Host "  - client_valid.pfx / .crt / .key     (Valid client certificate signed by CA, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_untrusted.pfx / .crt / .key (Untrusted client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_expired.pfx / .crt / .key   (Expired client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "  - client_pinned.pfx / .crt / .key    (Pinned client certificate, password: $Password)" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
}
finally {
    foreach ($cert in $createdCerts) {
        if ($null -ne $cert -and -not [string]::IsNullOrEmpty($cert.Thumbprint)) {
            Get-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
