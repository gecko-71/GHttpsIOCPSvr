param(
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER,
    [string]$ExportDir = ""
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Get-ChildItem Cert:\CurrentUser\GMcpSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GMcpSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue
if ($isAdmin) {
    Get-ChildItem Cert:\LocalMachine\GMcpSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GMcpSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue
}

$baseStore = if ($isAdmin) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }

$cert = New-SelfSignedCertificate `
    -DnsName 'localhost', '127.0.0.1' `
    -CertStoreLocation $baseStore `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -KeyExportPolicy Exportable `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2') `
    -NotAfter (Get-Date).AddYears(5) `
    -FriendlyName "GMcpSvr"

if (-not $cert) {
    Write-Error "Failed to generate certificate."
    Exit 1
}

$destStoreCU = New-Object System.Security.Cryptography.X509Certificates.X509Store("GMcpSvr", "CurrentUser")
$destStoreCU.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreCU.Add($cert)
$destStoreCU.Close()

if ($isAdmin) {
    try {
        $destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GMcpSvr", "LocalMachine")
        $destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $destStoreLM.Add($cert)
        $destStoreLM.Close()
    } catch {}
}

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }

function Export-McpCertPairToDir([string]$TargetOutDir, $CertObj) {
    if (-not (Test-Path $TargetOutDir)) {
        New-Item -ItemType Directory -Path $TargetOutDir -Force | Out-Null
    }
    $b64 = [System.Convert]::ToBase64String($CertObj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $crtPem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "mcp_server.crt"), $crtPem, [System.Text.Encoding]::ASCII)

    try {
        $expRsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertObj)
        if ($expRsaKey) {
            $pkcs8Bytes = $null
            if ($expRsaKey.PSObject.Methods['ExportPkcs8PrivateKey']) {
                $pkcs8Bytes = $expRsaKey.ExportPkcs8PrivateKey()
            } elseif ($expRsaKey -is [System.Security.Cryptography.RSACng]) {
                $pkcs8Bytes = $expRsaKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            }
            if ($pkcs8Bytes) {
                $k64 = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                $keyPem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
                [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "mcp_server.key"), $keyPem, [System.Text.Encoding]::ASCII)
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
} else {
    $ExportTargets.Add((Join-Path $PSScriptRoot "certs"))
    if ($EffectiveTlsProvider -match '(?i)openssl') {
        $ExportTargets.Add((Join-Path $PSScriptRoot "test_certs"))
    }
    foreach ($relBin in @("Win64\Debug", "Win64\Release", "GMcpSvr\Win64\Debug", "GMcpSvr\Win64\Release")) {
        $absBin = Join-Path $PSScriptRoot $relBin
        if (Test-Path $absBin) {
            $ExportTargets.Add((Join-Path $absBin "certs"))
        }
    }
}

foreach ($outTarget in ($ExportTargets | Select-Object -Unique)) {
    Export-McpCertPairToDir $outTarget $cert
}

try {
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsaKey -and $rsaKey.Key) {
        $keyName = $rsaKey.Key.UniqueName
        $keyPaths = @(
            "$env:ProgramData\Microsoft\Crypto\Keys\$keyName",
            "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyName",
            "$env:APPDATA\Microsoft\Crypto\Keys\$keyName",
            "$env:APPDATA\Microsoft\Crypto\RSA\$keyName"
        )
        foreach ($kp in $keyPaths) {
            if (Test-Path $kp) {
                $acl = Get-Acl $kp
                $sidUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
                $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, "Read", "Allow")
                $acl.AddAccessRule($ruleUsers)
                $sidEveryone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
                $ruleEveryone = New-Object System.Security.AccessControl.FileSystemAccessRule($sidEveryone, "Read", "Allow")
                $acl.AddAccessRule($ruleEveryone)
                Set-Acl $kp $acl
                & icacls.exe $kp /grant "*S-1-1-0:(R)" | Out-Null
            }
        }
    }
} catch {
    Write-Warning "Key ACL configuration note: $_"
}

Write-Host "New CNG MCP certificate generated successfully." -ForegroundColor Green
Write-Host "Store Name:  GMcpSvr" -ForegroundColor Cyan
Write-Host "TLS Profile: $EffectiveTlsProvider" -ForegroundColor Cyan
Write-Host "Subject:     $($cert.Subject)" -ForegroundColor Cyan
Write-Host "Thumbprint:  $($cert.Thumbprint)" -ForegroundColor Yellow
Write-Host "Valid Until: $($cert.NotAfter)" -ForegroundColor Green
