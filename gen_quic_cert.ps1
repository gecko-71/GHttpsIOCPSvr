param(
    [string]$ServerIp = $env:TEST_SERVER_BIND_IP,
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER,
    [string]$ExportDir = ""
)

$detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -ExpandProperty IPAddress)

$dnsNames = @('localhost', '127.0.0.1')
if ($detectedIps) { $dnsNames += $detectedIps }
if ($ServerIp) { $dnsNames += $ServerIp }
$dnsNames = @($dnsNames | Select-Object -Unique)

Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr, Cert:\CurrentUser\GHttpsIOCPSvr -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } |
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

$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "LocalMachine")
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }

function Export-QuicCertPairToDir([string]$TargetOutDir, $CertObj) {
    if (-not (Test-Path $TargetOutDir)) {
        New-Item -ItemType Directory -Path $TargetOutDir -Force | Out-Null
    }
    $cerOut = Join-Path $TargetOutDir "localhost.cer"
    [System.IO.File]::WriteAllBytes($cerOut, $CertObj.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $b64 = [System.Convert]::ToBase64String($CertObj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $crtPem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "server.crt"), $crtPem, [System.Text.Encoding]::ASCII)

    try {
        $ecKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($CertObj)
        if ($ecKey) {
            $pkcs8Bytes = $null
            if ($ecKey.PSObject.Methods['ExportPkcs8PrivateKey']) {
                $pkcs8Bytes = $ecKey.ExportPkcs8PrivateKey()
            } elseif ($ecKey -is [System.Security.Cryptography.ECDsaCng]) {
                $pkcs8Bytes = $ecKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            }
            if ($pkcs8Bytes) {
                $k64 = [System.Convert]::ToBase64String($pkcs8Bytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                $keyPem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
                [System.IO.File]::WriteAllText((Join-Path $TargetOutDir "server.key"), $keyPem, [System.Text.Encoding]::ASCII)
            }
        }
    } catch {
        Write-Warning "OpenSSL PEM key export info: $($_.Exception.Message)"
    }
}

$ExportTargets = New-Object System.Collections.Generic.List[string]
if (-not [string]::IsNullOrWhiteSpace($ExportDir)) {
    $ResolvedExportDir = if ([System.IO.Path]::IsPathRooted($ExportDir)) { $ExportDir } else { Join-Path $PSScriptRoot $ExportDir }
    $ExportTargets.Add($ResolvedExportDir)
    if ((Test-Path (Join-Path $ResolvedExportDir "GTermBoxServer.exe")) -or (Test-Path (Join-Path $ResolvedExportDir "GHttpsIOCPSvr.exe"))) {
        $ExportTargets.Add((Join-Path $ResolvedExportDir "certs"))
    }
} else {
    $ExportTargets.Add((Join-Path $PSScriptRoot "certs"))
    if ($EffectiveTlsProvider -match '(?i)openssl') {
        $ExportTargets.Add((Join-Path $PSScriptRoot "test_certs"))
    }
    $RelBinDirs = @(
        "Win64\Debug",
        "Win64\Release",
        "GTermBox\Win64\Debug",
        "GTermBox\Win64\Release",
        "test_jeden\Win64\Debug",
        "testy\Win64\Debug",
        "GMcpSvr\Win64\Debug",
        "benchmark_suite\servers\ghttps_bench\Win64\Debug",
        "benchmark_suite\servers\ghttps_bench\Win64\Release",
        "benchmark_suite\servers\indy_bench\Win64\Debug",
        "benchmark_suite\servers\horse_bench\Win64\Debug",
        "DEMO\01_StaticAndSpaServer\Win64\Debug",
        "DEMO\02_JwtSecurityWafServer\Win64\Debug",
        "DEMO\03_HighSpeedFileStreamServer\Win64\Debug",
        "DEMO\04_WebSocketChatAndTelemetryServer\Win64\Debug",
        "DEMO\05_Http3QuicSpeedServer\Win64\Debug",
        "DEMO\06_TriProtocolHybridServer\Win64\Debug",
        "DEMO\08_MorseAudioServer\Win64\Debug",
        "DEMO\09_MoveServer\Win64\Debug",
        "DEMO\10_mTLSAuthServerAndClient\Win64\Debug",
        "DEMO\11_mTLSAuthSimpleServerAndClient\Win64\Debug"
    )
    foreach ($relBin in $RelBinDirs) {
        $absBin = Join-Path $PSScriptRoot $relBin
        if (Test-Path $absBin) {
            $ExportTargets.Add((Join-Path $absBin "certs"))
        }
    }
}

foreach ($outTarget in ($ExportTargets | Select-Object -Unique)) {
    Export-QuicCertPairToDir $outTarget $cert
}

try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyName = $ecdsaKey.Key.UniqueName
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\$keyName"
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
            Write-Host "Granted restricted Read permission for private key file: $keyPath"
        }
    }
} catch {
    Write-Host "Key ACL info: $($_.Exception.Message)"
}

Write-Host "New CNG W3C WebTransport certificate generated and ready in GHttpsIOCPSvr store (TLS Profile: $EffectiveTlsProvider)"
Write-Host "Thumbprint: $($cert.Thumbprint)"
