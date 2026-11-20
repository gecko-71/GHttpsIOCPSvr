param (
    [string]$OutputDir = "test_certs",
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $PSScriptRoot $OutputDir
}

Write-Host "[mTLS PKI] Inicjalizacja generowania certyfikatow w katalogu: $OutputDir" -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { "tpSchannel" } else { $TlsProvider }
Write-Host "[mTLS PKI] Aktywny profil TLS: $EffectiveTlsProvider" -ForegroundColor Cyan

$RelativeOpenSslCandidates = @(
    (Join-Path $PSScriptRoot "http3_src\sources\msquic_full\submodules\openssl\build_mingw64\apps\openssl.exe"),
    (Join-Path $PSScriptRoot "Win64\Debug\openssl.exe"),
    (Join-Path $PSScriptRoot "Win64\Release\openssl.exe")
)

$OpenSslExe = $null
foreach ($relCand in $RelativeOpenSslCandidates) {
    if (Test-Path $relCand) {
        $OpenSslExe = (Resolve-Path $relCand).Path
        break
    }
}

if (-not $OpenSslExe) {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) {
        $OpenSslExe = $cmd.Source
    }
}

if (-not $OpenSslExe) {
    $EnvPaths = @()
    foreach ($pfRoot in @($env:ProgramFiles, $env:ProgramW6432)) {
        if (-not [string]::IsNullOrWhiteSpace($pfRoot)) {
            $EnvPaths += (Join-Path $pfRoot "OpenSSL-Win64\bin\openssl.exe")
            $EnvPaths += (Join-Path $pfRoot "Git\usr\bin\openssl.exe")
        }
    }
    foreach ($p in $EnvPaths) {
        if (Test-Path $p) {
            $OpenSslExe = $p
            break
        }
    }
}

function Export-X509ToPemFiles(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObj,
    [string]$CrtOut,
    [string]$KeyOut
) {
    $b64 = [Convert]::ToBase64String($CertObj.RawData, [Base64FormattingOptions]::InsertLineBreaks)
    $crtPem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    [System.IO.File]::WriteAllText($CrtOut, $crtPem, [System.Text.Encoding]::ASCII)

    if (-not [string]::IsNullOrWhiteSpace($KeyOut)) {
        $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertObj)
        $pkcs8 = $null
        if ($rsaKey) {
            if ($rsaKey.PSObject.Methods['ExportPkcs8PrivateKey']) {
                $pkcs8 = $rsaKey.ExportPkcs8PrivateKey()
            } elseif ($rsaKey -is [System.Security.Cryptography.RSACng]) {
                $pkcs8 = $rsaKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            }
        }
        if ($pkcs8) {
            $k64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
            $keyPem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
            [System.IO.File]::WriteAllText($KeyOut, $keyPem, [System.Text.Encoding]::ASCII)
        }
    }
}

$CaKey = Join-Path $OutputDir "test_root_ca.key"
$CaCrt = Join-Path $OutputDir "test_root_ca.crt"
$SvrKey = Join-Path $OutputDir "server.key"
$SvrCsr = Join-Path $OutputDir "server.csr"
$SvrCrt = Join-Path $OutputDir "server.crt"
$SvrExt = Join-Path $OutputDir "server.ext"
$SvrPfx = Join-Path $OutputDir "server.pfx"
$CliKey = Join-Path $OutputDir "client_valid.key"
$CliCsr = Join-Path $OutputDir "client_valid.csr"
$CliCrt = Join-Path $OutputDir "client_valid.crt"
$CliExt = Join-Path $OutputDir "client_valid.ext"
$CliPfx = Join-Path $OutputDir "client_valid.pfx"
$ExpKey = Join-Path $OutputDir "client_expired.key"
$ExpCsr = Join-Path $OutputDir "client_expired.csr"
$ExpCrt = Join-Path $OutputDir "client_expired.crt"
$RogueCaKey = Join-Path $OutputDir "rogue_ca.key"
$RogueCaCrt = Join-Path $OutputDir "rogue_ca.crt"
$UntrustedKey = Join-Path $OutputDir "client_untrusted.key"
$UntrustedCsr = Join-Path $OutputDir "client_untrusted.csr"
$UntrustedCrt = Join-Path $OutputDir "client_untrusted.crt"
$NwKey = Join-Path $OutputDir "client_non_whitelisted.key"
$NwCsr = Join-Path $OutputDir "client_non_whitelisted.csr"
$NwCrt = Join-Path $OutputDir "client_non_whitelisted.crt"

if ($OpenSslExe) {
    Write-Host "[mTLS PKI] Wykryto OpenSSL: $OpenSslExe" -ForegroundColor Green

    if (-not (Test-Path $CaCrt) -or -not (Test-Path $CaKey)) {
        Write-Host "[mTLS PKI] Generowanie Test Root CA..." -ForegroundColor Yellow
        & $OpenSslExe req -x509 -newkey rsa:2048 -nodes -keyout $CaKey -out $CaCrt -days 365 -subj "/CN=GHttpsIOCP-TestRootCA/O=TestOrg/C=PL"
    }

    if (-not (Test-Path $SvrCrt) -or -not (Test-Path $SvrKey)) {
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

    if (-not (Test-Path $CliExt)) {
        @"
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
"@ | Set-Content $CliExt -Encoding ASCII
    }

    if (-not (Test-Path $CliCrt) -or -not (Test-Path $CliKey)) {
        Write-Host "[mTLS PKI] Generowanie Autoryzowanego Certyfikatu Klienta (CN=AuthorizedClient1)..." -ForegroundColor Yellow
        & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $CliKey -out $CliCsr -subj "/CN=AuthorizedClient1/O=ClientOrg/C=PL"
        & $OpenSslExe x509 -req -in $CliCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $CliCrt -days 365 -extfile $CliExt
        & $OpenSslExe pkcs12 -export -out $CliPfx -inkey $CliKey -in $CliCrt -passout pass:testpassword
    }

    if (-not (Test-Path $ExpCrt) -or -not (Test-Path $ExpKey)) {
        Write-Host "[mTLS PKI] Generowanie Wygaslego Certyfikatu Klienta..." -ForegroundColor Yellow
        & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $ExpKey -out $ExpCsr -subj "/CN=ExpiredClient/O=ClientOrg/C=PL"
        & $OpenSslExe x509 -req -in $ExpCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $ExpCrt -days -1 -extfile $CliExt
    }

    if (-not (Test-Path $UntrustedCrt) -or -not (Test-Path $UntrustedKey)) {
        Write-Host "[mTLS PKI] Generowanie Niezaufanego Certyfikatu Klienta (Rogue CA)..." -ForegroundColor Yellow
        & $OpenSslExe req -x509 -newkey rsa:2048 -nodes -keyout $RogueCaKey -out $RogueCaCrt -days 30 -subj "/CN=RogueUntrustedCA/C=XX"
        & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $UntrustedKey -out $UntrustedCsr -subj "/CN=RogueClient/C=XX"
        & $OpenSslExe x509 -req -in $UntrustedCsr -CA $RogueCaCrt -CAkey $RogueCaKey -CAcreateserial -out $UntrustedCrt -days 30 -extfile $CliExt
    }

    if (-not (Test-Path $NwCrt) -or -not (Test-Path $NwKey)) {
        Write-Host "[mTLS PKI] Generowanie Certyfikatu Spoza Bialej Listy (CN=RevokedOrNonWhitelistedClient)..." -ForegroundColor Yellow
        & $OpenSslExe req -newkey rsa:2048 -nodes -keyout $NwKey -out $NwCsr -subj "/CN=RevokedOrNonWhitelistedClient/O=ClientOrg/C=PL"
        & $OpenSslExe x509 -req -in $NwCsr -CA $CaCrt -CAkey $CaKey -CAcreateserial -out $NwCrt -days 365 -extfile $CliExt
    }
} else {
    Write-Host "[mTLS PKI] Brak zewnetrznego openssl.exe - uzywam wbudowanego generatora CNG/.NET PKI." -ForegroundColor Yellow
    $secPass = ConvertTo-SecureString "testpassword" -AsPlainText -Force
    $tempCreated = @()
    try {
        if (-not (Test-Path $CaCrt)) {
            $caCert = New-SelfSignedCertificate -Subject "CN=GHttpsIOCP-TestRootCA,O=TestOrg,C=PL" -KeyUsage CertSign,CRLSign,DigitalSignature -TextExtension @("2.5.29.19={critical}{text}ca=1") -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddYears(1)
            $tempCreated += $caCert
            Export-X509ToPemFiles $caCert $CaCrt $CaKey
        } else {
            $caCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CaCrt)
        }
        $caInStore = $null
        if ($caCert.HasPrivateKey) {
            $caInStore = $caCert
        }
        if (-not (Test-Path $SvrCrt) -or -not (Test-Path $SvrKey)) {
            $svrParams = @{
                Subject = "CN=localhost,O=TestOrg,C=PL"
                CertStoreLocation = "Cert:\CurrentUser\My"
                KeyExportPolicy = "Exportable"
                KeyLength = 2048
                KeyAlgorithm = "RSA"
                HashAlgorithm = "SHA256"
                KeyUsage = @("DigitalSignature", "KeyEncipherment")
                TextExtension = @("2.5.29.17={text}dns=localhost&ipaddress=127.0.0.1", "2.5.29.37={text}1.3.6.1.5.5.7.3.1")
                NotBefore = (Get-Date).AddDays(-1)
                NotAfter = (Get-Date).AddYears(1)
            }
            if ($caInStore) { $svrParams["Signer"] = $caInStore }
            $svrObj = New-SelfSignedCertificate @svrParams
            $tempCreated += $svrObj
            Export-X509ToPemFiles $svrObj $SvrCrt $SvrKey
            Export-PfxCertificate -Cert $svrObj -FilePath $SvrPfx -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
        }
        if (-not (Test-Path $CliCrt) -or -not (Test-Path $CliKey)) {
            $cliParams = @{
                Subject = "CN=AuthorizedClient1,O=ClientOrg,C=PL"
                CertStoreLocation = "Cert:\CurrentUser\My"
                KeyExportPolicy = "Exportable"
                KeyLength = 2048
                KeyAlgorithm = "RSA"
                HashAlgorithm = "SHA256"
                KeyUsage = @("DigitalSignature", "KeyEncipherment")
                TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
                NotBefore = (Get-Date).AddDays(-1)
                NotAfter = (Get-Date).AddYears(1)
            }
            if ($caInStore) { $cliParams["Signer"] = $caInStore }
            $cliObj = New-SelfSignedCertificate @cliParams
            $tempCreated += $cliObj
            Export-X509ToPemFiles $cliObj $CliCrt $CliKey
            Export-PfxCertificate -Cert $cliObj -FilePath $CliPfx -Password $secPass -ChainOption EndEntityCertOnly | Out-Null
        }
        if (-not (Test-Path $ExpCrt) -or -not (Test-Path $ExpKey)) {
            $expParams = @{
                Subject = "CN=ExpiredClient,O=ClientOrg,C=PL"
                CertStoreLocation = "Cert:\CurrentUser\My"
                KeyExportPolicy = "Exportable"
                KeyLength = 2048
                KeyAlgorithm = "RSA"
                HashAlgorithm = "SHA256"
                KeyUsage = @("DigitalSignature", "KeyEncipherment")
                TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
                NotBefore = (Get-Date).AddDays(-30)
                NotAfter = (Get-Date).AddDays(-1)
            }
            if ($caInStore) { $expParams["Signer"] = $caInStore }
            $expObj = New-SelfSignedCertificate @expParams
            $tempCreated += $expObj
            Export-X509ToPemFiles $expObj $ExpCrt $ExpKey
        }
        if (-not (Test-Path $UntrustedCrt) -or -not (Test-Path $UntrustedKey)) {
            $rogueCaObj = New-SelfSignedCertificate -Subject "CN=RogueUntrustedCA,C=XX" -KeyUsage CertSign,CRLSign,DigitalSignature -TextExtension @("2.5.29.19={critical}{text}ca=1") -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddDays(30)
            $tempCreated += $rogueCaObj
            Export-X509ToPemFiles $rogueCaObj $RogueCaCrt $RogueCaKey
            $untrustedObj = New-SelfSignedCertificate -Subject "CN=RogueClient,C=XX" -Signer $rogueCaObj -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -KeyUsage DigitalSignature,KeyEncipherment -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddDays(30)
            $tempCreated += $untrustedObj
            Export-X509ToPemFiles $untrustedObj $UntrustedCrt $UntrustedKey
        }
        if (-not (Test-Path $NwCrt) -or -not (Test-Path $NwKey)) {
            $nwParams = @{
                Subject = "CN=RevokedOrNonWhitelistedClient,O=ClientOrg,C=PL"
                CertStoreLocation = "Cert:\CurrentUser\My"
                KeyExportPolicy = "Exportable"
                KeyLength = 2048
                KeyAlgorithm = "RSA"
                HashAlgorithm = "SHA256"
                KeyUsage = @("DigitalSignature", "KeyEncipherment")
                TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
                NotBefore = (Get-Date).AddDays(-1)
                NotAfter = (Get-Date).AddYears(1)
            }
            if ($caInStore) { $nwParams["Signer"] = $caInStore }
            $nwObj = New-SelfSignedCertificate @nwParams
            $tempCreated += $nwObj
            Export-X509ToPemFiles $nwObj $NwCrt $NwKey
        }
    } finally {
        foreach ($tc in $tempCreated) {
            if ($null -ne $tc -and -not [string]::IsNullOrWhiteSpace($tc.Thumbprint)) {
                Get-Item "Cert:\CurrentUser\My\$($tc.Thumbprint)" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Host "[mTLS PKI] Wszystkie certyfikaty testowe wygenerowane pomyslnie w: $OutputDir" -ForegroundColor Green
