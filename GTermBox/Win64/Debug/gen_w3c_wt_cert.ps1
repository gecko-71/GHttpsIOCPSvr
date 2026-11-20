param(
    [string]$ServerIp = $env:TEST_SERVER_BIND_IP,
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER,
    [string]$ExportDir = ""
)

Write-Host "--- Generating W3C WebTransport Certificate (ECDSA P-256, 14 days) ---" -ForegroundColor Cyan

$detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -ExpandProperty IPAddress)

$dnsNames = @('localhost', '127.0.0.1')
if ($detectedIps) { $dnsNames += $detectedIps }
if ($ServerIp) { $dnsNames += $ServerIp }
$dnsNames = @($dnsNames | Select-Object -Unique)
$primaryIp = if ($ServerIp) { $ServerIp } elseif ($detectedIps.Count -gt 0) { $detectedIps[0] } else { '127.0.0.1' }

Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*CN=$primaryIp*" -or $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } |
    Remove-Item -Force -ErrorAction SilentlyContinue

$notBefore = (Get-Date).AddDays(-1)
$notAfter  = (Get-Date).AddDays(13)

$cert = New-SelfSignedCertificate `
    -DnsName $dnsNames `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm ECDSA_nistP256 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -FriendlyName "GHttpsIOCPSvr"

if (-not $cert) {
    Write-Error "Failed to generate certificate. Ensure PowerShell is running as Administrator."
    Exit 1
}

$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store('GHttpsIOCPSvr', 'LocalMachine')
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }

function Export-GtbW3cCertPairToDir([string]$TargetOutDir, $CertObj) {
    if (-not (Test-Path $TargetOutDir)) {
        New-Item -ItemType Directory -Path $TargetOutDir -Force | Out-Null
    }
    $cerOut = Join-Path $TargetOutDir "localhost.cer"
    [System.IO.File]::WriteAllBytes($cerOut, $CertObj.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $b64 = [System.Convert]::ToBase64String($CertObj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $crtPem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "server.crt"), $crtPem, [System.Text.Encoding]::ASCII)

    try {
        $ecExport = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($CertObj)
        if ($ecExport) {
            $pkcs8Bytes = $null
            if ($ecExport.PSObject.Methods['ExportPkcs8PrivateKey']) {
                $pkcs8Bytes = $ecExport.ExportPkcs8PrivateKey()
            } elseif ($ecExport -is [System.Security.Cryptography.ECDsaCng]) {
                $pkcs8Bytes = $ecExport.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            }
            if ($pkcs8Bytes) {
                $k64 = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                $keyPem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
                [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "server.key"), $keyPem, [System.Text.Encoding]::ASCII)
            }
        }
    } catch {
        Write-Warning "OpenSSL PEM key export note: $($_.Exception.Message)"
    }
}

$ExportTargets = New-Object System.Collections.Generic.List[string]
if (-not [string]::IsNullOrWhiteSpace($ExportDir)) {
    $ResolvedExportDir = if ([System.IO.Path]::IsPathRooted($ExportDir)) { $ExportDir } else { Join-Path $PSScriptRoot $ExportDir }
    $ExportTargets.Add($ResolvedExportDir)
    if (Test-Path (Join-Path $ResolvedExportDir "GTermBoxServer.exe")) {
        $ExportTargets.Add((Join-Path $ResolvedExportDir "certs"))
    }
} else {
    $ExportTargets.Add((Join-Path $PSScriptRoot "certs"))
    if ($EffectiveTlsProvider -match '(?i)openssl') {
        $ExportTargets.Add((Join-Path $PSScriptRoot "test_certs"))
    }
    foreach ($relBin in @("Win64\Debug", "Win64\Release")) {
        $absBin = Join-Path $PSScriptRoot $relBin
        if (Test-Path $absBin) {
            $ExportTargets.Add((Join-Path $absBin "certs"))
        }
    }
}

foreach ($outTarget in ($ExportTargets | Select-Object -Unique)) {
    Export-GtbW3cCertPairToDir $outTarget $cert
    Write-Host "PEM certificate and key exported to: $outTarget" -ForegroundColor Cyan
}

try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\" + $ecdsaKey.Key.UniqueName
        if (Test-Path $keyPath) {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            & icacls.exe $keyPath /remove "*S-1-1-0" /Q | Out-Null
            & icacls.exe $keyPath /grant "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" "*$($currentUser.Value):(R)" /Q | Out-Null
            $acl = Get-Acl -Path $keyPath
            $rulesToRemove = @($acl.Access | Where-Object { $_.IdentityReference.Value -match 'S-1-1-0|Everyone|Wszyscy' })
            foreach ($r in $rulesToRemove) {
                [void]$acl.RemoveAccessRule($r)
            }
            $sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, 'Read', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmins, 'Read', 'Allow')))
            if ($currentUser) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'Read', 'Allow')))
            }
            Set-Acl -Path $keyPath -AclObject $acl
            Write-Host "CNG private key permissions successfully configured (SYSTEM, Administrators and installing user $env:USERNAME)." -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Key ACL configuration note: $_"
}

$sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
$hashArrayStr = '[' + (($sha256 | ForEach-Object { $_.ToString() }) -join ', ') + ']'
$hashHexStr = [System.BitConverter]::ToString($sha256).Replace('-', '')

Write-Host "`nSuccess! Certificate generated in compliance with W3C WebTransport:" -ForegroundColor Green
Write-Host "Thumbprint (SHA-1): " $cert.Thumbprint -ForegroundColor Yellow
Write-Host "TLS Profile:        " $EffectiveTlsProvider -ForegroundColor Cyan
Write-Host "Valid from:         " $cert.NotBefore
Write-Host "Valid to:           " $cert.NotAfter
Write-Host "Algorithm:          ECDSA P-256 (secp256r1) [W3C Compliant]" -ForegroundColor Cyan
Write-Host "SHA-256 Hex:        " $hashHexStr -ForegroundColor Cyan
Write-Host "SHA-256 Array:      " $hashArrayStr -ForegroundColor Cyan
Write-Host "`nCertificate is installed in Cert:\LocalMachine\GHttpsIOCPSvr." -ForegroundColor Green
