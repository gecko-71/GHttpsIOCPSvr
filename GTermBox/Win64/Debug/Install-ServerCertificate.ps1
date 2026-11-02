[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$CertPath = ''
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $CertPath) {
  $localCer = Join-Path $ScriptDir 'localhost.cer'
  if (Test-Path $localCer) {
    $CertPath = $localCer
  }
}

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
