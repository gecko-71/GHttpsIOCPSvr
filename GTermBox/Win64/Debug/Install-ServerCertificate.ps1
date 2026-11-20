[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$CertPath = '',

  [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

$ErrorActionPreference = 'Stop'

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { 'tpSchannel' } else { $TlsProvider }
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($CertPath -and -not [System.IO.Path]::IsPathRooted($CertPath)) {
  if (Test-Path (Join-Path $ScriptDir $CertPath)) {
    $CertPath = (Resolve-Path (Join-Path $ScriptDir $CertPath)).Path
  } elseif (Test-Path (Join-Path (Get-Location).Path $CertPath)) {
    $CertPath = (Resolve-Path (Join-Path (Get-Location).Path $CertPath)).Path
  }
}

if (-not $CertPath) {
  $localCer = Join-Path $ScriptDir 'localhost.cer'
  if (Test-Path $localCer) {
    $CertPath = $localCer
  }
}

$StoreCert = $null
if (-not $CertPath -or -not (Test-Path $CertPath)) {
  $StoreCert = Get-ChildItem 'Cert:\LocalMachine\GHttpsIOCPSvr' -ErrorAction SilentlyContinue |
    Where-Object { ($_.Subject -like '*CN=localhost*' -or $_.FriendlyName -eq 'GHttpsIOCPSvr') -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object @{Expression = { if ($_.PublicKey.Oid.FriendlyName -match 'ECC|ECDSA') { 1 } else { 0 } }}, NotAfter -Descending |
    Select-Object -First 1
  if ($StoreCert) {
    $CertPath = Join-Path $ScriptDir 'localhost.cer'
    [System.IO.File]::WriteAllBytes($CertPath, $StoreCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host "Exported server certificate $($StoreCert.Thumbprint) from LocalMachine\GHttpsIOCPSvr to $CertPath" -ForegroundColor DarkGray
  }
}

if (-not $CertPath -or -not (Test-Path $CertPath)) {
  Write-Error 'Server certificate file (localhost.cer) not found in directory and no valid certificate found in LocalMachine\GHttpsIOCPSvr.'
  exit 1
}

$targetCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
$pemOutPath = Join-Path $ScriptDir 'localhost.crt'
if (-not (Test-Path $pemOutPath)) {
  $b64 = [System.Convert]::ToBase64String($targetCert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
  $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
  [System.IO.File]::WriteAllText($pemOutPath, $pem, [System.Text.Encoding]::ASCII)
}
if ($StoreCert -and ($EffectiveTlsProvider -match '(?i)openssl')) {
  $keyOutPath = Join-Path $ScriptDir 'localhost.key'
  if (-not (Test-Path $keyOutPath)) {
    try {
      $pkcs8 = $null
      $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($StoreCert)
      if ($rsaKey) {
        if ($rsaKey.PSObject.Methods['ExportPkcs8PrivateKey']) { $pkcs8 = $rsaKey.ExportPkcs8PrivateKey() }
        elseif ($rsaKey -is [System.Security.Cryptography.RSACng]) { $pkcs8 = $rsaKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
      } else {
        $ecKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($StoreCert)
        if ($ecKey) {
          if ($ecKey.PSObject.Methods['ExportPkcs8PrivateKey']) { $pkcs8 = $ecKey.ExportPkcs8PrivateKey() }
          elseif ($ecKey -is [System.Security.Cryptography.ECDsaCng]) { $pkcs8 = $ecKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
        }
      }
      if ($pkcs8) {
        $k64 = [System.Convert]::ToBase64String($pkcs8, [System.Base64FormattingOptions]::InsertLineBreaks)
        [System.IO.File]::WriteAllText($keyOutPath, "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n", [System.Text.Encoding]::ASCII)
      }
    } catch {}
  }
}
Write-Host "TLS Profile: $EffectiveTlsProvider" -ForegroundColor DarkGray
$alreadyTrusted = $false
foreach ($loc in @('LocalMachine', 'CurrentUser')) {
  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', [System.Security.Cryptography.X509Certificates.StoreLocation]::$loc)
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    if ($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $targetCert.Thumbprint, $false).Count -gt 0) {
      $alreadyTrusted = $true
      break
    }
  } catch {
  } finally {
    $store.Close()
  }
}

if ($alreadyTrusted) {
  Write-Host 'Server certificate is already trusted in Root store.' -ForegroundColor Green
  exit 0
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
  $certutilArgs = "-addstore -f Root `"$CertPath`""
  Write-Host 'Installing server certificate to LocalMachine Trusted Root store...' -ForegroundColor Cyan
} else {
  $certutilArgs = "-user -addstore Root `"$CertPath`""
  Write-Host 'Installing server certificate to CurrentUser Trusted Root store...' -ForegroundColor Cyan
  Write-Host "NOTE: If a Windows Security Warning popup appears, click 'Yes' to trust the certificate." -ForegroundColor Yellow
}
Write-Host "Certificate Path: $CertPath" -ForegroundColor DarkGray

$Process = Start-Process -FilePath 'certutil.exe' -ArgumentList $certutilArgs -NoNewWindow -Wait -PassThru

if ($Process.ExitCode -eq 0) {
  Write-Host 'Server certificate successfully trusted in Windows Root store.' -ForegroundColor Green
  Write-Host 'WebTransport (HTTP/3) and HTTPS in Chrome/Edge will now be fully trusted without security warnings.' -ForegroundColor Green
} else {
  Write-Error "certutil failed with exit code $($Process.ExitCode)"
  exit $Process.ExitCode
}
