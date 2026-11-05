param(
    [string]$Password = "Simple123!"
)

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -File $MyInvocation.MyCommand.Path -Password $Password
    exit $LASTEXITCODE
}

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
        $rootW3cScript = Join-Path (Resolve-Path (Join-Path $scriptDir "..\..")).Path "gen_w3c_wt_cert.ps1"
        if (Test-Path $rootW3cScript) {
            & $rootW3cScript
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

    Export-PemCert $serverCert (Join-Path $serverDir "server.crt")
    Export-PemCert $serverCert (Join-Path $clientDir "server.crt")
    Write-Host "  -> server.crt saved to server_certificates and client_certificates" -ForegroundColor Green

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

    $clientShaPath = Join-Path $serverDir "client.sha256"
    $sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($clientCert.RawData)).Replace("-", "")
    [System.IO.File]::WriteAllText($clientShaPath, $sha256, [System.Text.Encoding]::ASCII)
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
}
finally {
    foreach ($c in $createdTempCerts) {
        if ($null -ne $c -and -not [string]::IsNullOrEmpty($c.Thumbprint)) {
            Get-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
}
