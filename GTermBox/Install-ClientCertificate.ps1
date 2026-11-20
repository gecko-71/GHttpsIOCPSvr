[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$Username = 'usr1',

  [Parameter(Position = 1)]
  [string]$Password = '',

  [Parameter(Position = 2)]
  [string]$PfxPath = '',

  [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

$ErrorActionPreference = 'Stop'

$EffectiveTlsProvider = if ([string]::IsNullOrWhiteSpace($TlsProvider)) { 'tpSchannel' } else { $TlsProvider }
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($PfxPath -and -not [System.IO.Path]::IsPathRooted($PfxPath)) {
  if (Test-Path (Join-Path $ScriptDir $PfxPath)) {
    $PfxPath = (Resolve-Path (Join-Path $ScriptDir $PfxPath)).Path
  } elseif (Test-Path (Join-Path (Get-Location).Path $PfxPath)) {
    $PfxPath = (Resolve-Path (Join-Path (Get-Location).Path $PfxPath)).Path
  }
}

if (-not $PfxPath) {
  $Candidates = @(
    (Join-Path $ScriptDir "$Username.pfx"),
    (Join-Path $ScriptDir "client_keys\$Username.pfx"),
    (Join-Path $ScriptDir "Win64\Debug\client_keys\$Username.pfx")
  )
  foreach ($Cand in $Candidates) {
    if (Test-Path $Cand) {
      $PfxPath = (Resolve-Path $Cand).Path
      break
    }
  }
}

if (-not $Password) {
  $rngBytes = New-Object byte[] 18
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($rngBytes)
  $Password = [System.Convert]::ToBase64String($rngBytes).Replace('+', 'A').Replace('/', 'B').TrimEnd('=') + '!9a'
  Write-Host "Generated random PFX password for '$Username': $Password" -ForegroundColor Yellow
}

function Export-ClientPemPair([System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObj, [string]$CrtPath, [string]$KeyPath) {
  $b64 = [Convert]::ToBase64String($CertObj.RawData, [Base64FormattingOptions]::InsertLineBreaks)
  $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
  [System.IO.File]::WriteAllText($CrtPath, $pem, [System.Text.Encoding]::ASCII)

  if (-not [string]::IsNullOrWhiteSpace($KeyPath)) {
    try {
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
        $kpem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
        [System.IO.File]::WriteAllText($KeyPath, $kpem, [System.Text.Encoding]::ASCII)
      }
    } catch {}
  }
}

if (-not $PfxPath -or -not (Test-Path $PfxPath)) {
  $clientKeysDir = Join-Path $ScriptDir 'client_keys'
  if (-not (Test-Path $clientKeysDir)) {
    New-Item -ItemType Directory -Path $clientKeysDir -Force | Out-Null
  }
  $PfxPath = Join-Path $clientKeysDir "$Username.pfx"
  $cc = New-SelfSignedCertificate -Subject "CN=$Username" -FriendlyName "GTermBox client $Username" -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') -NotAfter (Get-Date).AddYears(5)
  $sec = ConvertTo-SecureString -String $Password -AsPlainText -Force
  Export-PfxCertificate -Cert $cc -FilePath $PfxPath -Password $sec | Out-Null
  $trustedClientsDir = Join-Path $ScriptDir 'trusted_clients'
  if (-not (Test-Path $trustedClientsDir)) {
    New-Item -ItemType Directory -Path $trustedClientsDir -Force | Out-Null
  }
  Export-ClientPemPair $cc (Join-Path $trustedClientsDir "$Username.crt") ""
  Export-ClientPemPair $cc (Join-Path $clientKeysDir "$Username.crt") (Join-Path $clientKeysDir "$Username.key")
  Write-Host "Generated client certificate, PFX and OpenSSL PEM (.crt/.key) for $Username" -ForegroundColor Green
}

Write-Host "Installing client certificate for user '$Username' (TLS Profile: $EffectiveTlsProvider)..." -ForegroundColor Cyan
Write-Host "PFX Path: $PfxPath" -ForegroundColor DarkGray

$Process = Start-Process -FilePath 'certutil.exe' -ArgumentList "-user -p `"$Password`" -importpfx `"$PfxPath`" NoRoot" -NoNewWindow -Wait -PassThru

if ($Process.ExitCode -eq 0) {
  Write-Host "Certificate '$Username.pfx' imported successfully into Windows CurrentUser Personal store." -ForegroundColor Green
  Write-Host 'Chrome, Edge, and Windows applications will now offer this certificate for mTLS authentication.' -ForegroundColor Green
} else {
  Write-Error "certutil failed with exit code $($Process.ExitCode)"
  exit $Process.ExitCode
}
