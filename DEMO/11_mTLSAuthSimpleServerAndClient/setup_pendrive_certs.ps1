param(
    [string]$Password = "Simple123!",
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    $relaunchArgs = @("-ExecutionPolicy", "Bypass", "-NoProfile", "-File", $MyInvocation.MyCommand.Path, "-Password", $Password)
    if (-not [string]::IsNullOrWhiteSpace($TlsProvider)) {
        $relaunchArgs += @("-TlsProvider", $TlsProvider)
    }
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @relaunchArgs
    exit $LASTEXITCODE
}

$ErrorActionPreference = "Stop"

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " DEMO 11: Setup Certificates (Server & Client)" -ForegroundColor Cyan
Write-Host " Active TLS Profile: $EffectiveTlsProvider" -ForegroundColor Cyan
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

function Copy-OpenSslRuntimeDlls([string]$targetBinDir, [string]$rootSearchBase) {
    if (-not (Test-Path $targetBinDir)) { return }
    $relDirs = @(
        (Join-Path $rootSearchBase "..\..\Win64\Debug"),
        (Join-Path $rootSearchBase "..\..\Win64\Release"),
        (Join-Path $rootSearchBase "..\Win64\Debug"),
        (Join-Path $rootSearchBase "..\Win64\Release"),
        $rootSearchBase
    )
    foreach ($dll in @("libcrypto-3-x64.dll", "libssl-3-x64.dll")) {
        $dest = Join-Path $targetBinDir $dll
        if (-not (Test-Path $dest)) {
            foreach ($candDir in $relDirs) {
                if (Test-Path $candDir) {
                    $candFile = Join-Path $candDir $dll
                    if (Test-Path $candFile) {
                        Copy-Item -Path $candFile -Destination $dest -Force
                        Write-Host "  -> Copied $dll to $targetBinDir" -ForegroundColor DarkGray
                        break
                    }
                }
            }
        }
    }
}

$createdTempCerts = @()

try {
    Write-Host "[1/3] Ensuring W3C-Compliant Server Certificate in GHttpsIOCPSvr..." -ForegroundColor White

    try {
        $cuStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "CurrentUser")
        $cuStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        foreach ($old in @($cuStore.Certificates | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" })) {
            try { $cuStore.Remove($old) } catch {}
        }
        $cuStore.Close()
    } catch {}

    $serverCert = Get-ChildItem "Cert:\LocalMachine\GHttpsIOCPSvr" -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr") -and
            $_.HasPrivateKey -and
            $_.NotAfter -gt (Get-Date).AddDays(1) -and
            $_.PublicKey.Oid.FriendlyName -match "ECC|ECDSA"
        } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $serverCert) {
        $rootW3cScript = Join-Path $scriptDir "..\..\gen_w3c_wt_cert.ps1"
        if (Test-Path $rootW3cScript) {
            & $rootW3cScript -TlsProvider $EffectiveTlsProvider
        } else {
            $detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                Select-Object -ExpandProperty IPAddress)
            $dnsNames = @("localhost", "127.0.0.1")
            if ($detectedIps) { $dnsNames += $detectedIps }
            $dnsNames = @($dnsNames | Select-Object -Unique)

            $serverCert = New-SelfSignedCertificate `
                -DnsName $dnsNames `
                -CertStoreLocation "Cert:\LocalMachine\My" `
                -KeyAlgorithm ECDSA_nistP256 `
                -HashAlgorithm SHA256 `
                -KeyUsage DigitalSignature `
                -KeyExportPolicy Exportable `
                -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
                -NotBefore (Get-Date).AddDays(-1) `
                -NotAfter (Get-Date).AddDays(13) `
                -FriendlyName "GHttpsIOCPSvr"

            $storeLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "LocalMachine")
            $storeLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $storeLM.Add($serverCert)
            $storeLM.Close()

            try {
                $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($serverCert)
                if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
                    $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\" + $ecdsaKey.Key.UniqueName
                    if (Test-Path $keyPath) {
                        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                        & icacls.exe $keyPath /remove "*S-1-1-0" /Q | Out-Null
                        & icacls.exe $keyPath /grant "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" "*$($currentUser.Value):(R)" /Q | Out-Null
                    }
                }
            } catch {}
        }

        $serverCert = Get-ChildItem "Cert:\LocalMachine\GHttpsIOCPSvr" -ErrorAction SilentlyContinue |
            Where-Object { ($_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr") -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
    }

    $serverKeyExported = $false
    if ($serverCert) {
        Export-PemCert $serverCert (Join-Path $serverDir "server.crt")
        Export-PemCert $serverCert (Join-Path $clientDir "server.crt")
        $serverKeyExported = Export-PemPrivateKey $serverCert (Join-Path $serverDir "server.key")
        Write-Host "  -> server.crt (and exportable server.key if available) saved to server_certificates and client_certificates" -ForegroundColor Green
    }

    if (-not $serverKeyExported) {
        $detectedIpsFallback = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
            Select-Object -ExpandProperty IPAddress)
        $dnsNamesFallback = @("localhost", "127.0.0.1")
        if ($detectedIpsFallback) { $dnsNamesFallback += $detectedIpsFallback }
        $dnsNamesFallback = @($dnsNamesFallback | Select-Object -Unique)
        $ephemServerCert = New-SelfSignedCertificate `
            -DnsName $dnsNamesFallback `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyAlgorithm ECDSA_nistP256 `
            -HashAlgorithm SHA256 `
            -KeyUsage DigitalSignature `
            -KeyExportPolicy Exportable `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
            -NotBefore (Get-Date).AddDays(-1) `
            -NotAfter (Get-Date).AddDays(13) `
            -FriendlyName "GHttpsIOCPSvr-Demo11"
        $createdTempCerts += $ephemServerCert
        Export-PemCert $ephemServerCert (Join-Path $serverDir "server.crt")
        Export-PemCert $ephemServerCert (Join-Path $clientDir "server.crt")
        $serverKeyExported = Export-PemPrivateKey $ephemServerCert (Join-Path $serverDir "server.key")
    }

    Write-Host "[2/3] Generating Client Certificate (CN=SimpleMtlsClient)..." -ForegroundColor White
    $clientCert = New-SelfSignedCertificate `
        -Subject "CN=SimpleMtlsClient" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -TextExtension @(
            "2.5.29.17={text}dns=simple-mtls-client.local&dns=localhost",
            "2.5.29.37={text}1.3.6.1.5.5.7.3.2"
        ) `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -NotBefore (Get-Date).AddDays(-1) `
        -NotAfter (Get-Date).AddYears(2)
    $createdTempCerts += $clientCert

    $clientPfxPath = Join-Path $clientDir "client.pfx"
    Export-PfxCertificate -Cert $clientCert -FilePath $clientPfxPath -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
    Write-Host "  -> client.pfx saved to client_certificates" -ForegroundColor Green

    Export-PemCert $clientCert (Join-Path $clientDir "client.crt")
    Export-PemCert $clientCert (Join-Path $serverDir "client.crt")
    $null = Export-PemPrivateKey $clientCert (Join-Path $clientDir "client.key")

    $clientShaPath = Join-Path $serverDir "client.sha256"
    $sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($clientCert.RawData)).Replace("-", "")
    [System.IO.File]::WriteAllText($clientShaPath, $sha256, [System.Text.Encoding]::ASCII)
    Write-Host "  -> client.crt, client.key & client.sha256 saved ($sha256)" -ForegroundColor Green

    $debugDir = Join-Path $scriptDir "Win64\Debug"
    if (Test-Path $debugDir) {
        Copy-Item -Path $serverDir -Destination $debugDir -Recurse -Force
        Copy-Item -Path $clientDir -Destination $debugDir -Recurse -Force
        $debugCertsDir = Join-Path $debugDir "certs"
        if (-not (Test-Path $debugCertsDir)) {
            New-Item -ItemType Directory -Path $debugCertsDir -Force | Out-Null
        }
        if (Test-Path (Join-Path $serverDir "server.crt")) { Copy-Item -Path (Join-Path $serverDir "server.crt") -Destination (Join-Path $debugCertsDir "server.crt") -Force }
        if (Test-Path (Join-Path $serverDir "server.key")) { Copy-Item -Path (Join-Path $serverDir "server.key") -Destination (Join-Path $debugCertsDir "server.key") -Force }
        Copy-OpenSslRuntimeDlls $debugDir $scriptDir
        Write-Host "  -> Synced certificate folders and OpenSSL DLLs to Win64\Debug" -ForegroundColor Yellow
    }
    $releaseDir = Join-Path $scriptDir "Win64\Release"
    if (Test-Path $releaseDir) {
        Copy-Item -Path $serverDir -Destination $releaseDir -Recurse -Force
        Copy-Item -Path $clientDir -Destination $releaseDir -Recurse -Force
        $releaseCertsDir = Join-Path $releaseDir "certs"
        if (-not (Test-Path $releaseCertsDir)) {
            New-Item -ItemType Directory -Path $releaseCertsDir -Force | Out-Null
        }
        if (Test-Path (Join-Path $serverDir "server.crt")) { Copy-Item -Path (Join-Path $serverDir "server.crt") -Destination (Join-Path $releaseCertsDir "server.crt") -Force }
        if (Test-Path (Join-Path $serverDir "server.key")) { Copy-Item -Path (Join-Path $serverDir "server.key") -Destination (Join-Path $releaseCertsDir "server.key") -Force }
        Copy-OpenSslRuntimeDlls $releaseDir $scriptDir
    }

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " SETUP COMPLETE!" -ForegroundColor Green
    Write-Host " - TLS Profile:         $EffectiveTlsProvider" -ForegroundColor Cyan
    Write-Host " - server_certificates: server.crt, client.crt, client.sha256" -ForegroundColor White
    Write-Host " - client_certificates: client.pfx, client.crt, client.key, server.crt" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor Cyan
}
finally {
    foreach ($c in $createdTempCerts) {
        if ($null -ne $c -and -not [string]::IsNullOrEmpty($c.Thumbprint)) {
            Get-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
