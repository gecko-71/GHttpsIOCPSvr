[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$Username = 'usr1',

  [Parameter(Position = 1)]
  [string]$Password = '',

  [Parameter(Position = 2)]
  [string]$PfxPath = ''
)

$ErrorActionPreference = 'Stop'

if (-not $Password) {
  switch ($Username) {
    'usr1' { $Password = 'PasswordUsr1!' }
    'usr2' { $Password = 'PasswordUsr2!' }
    'usr3' { $Password = 'PasswordUsr3!' }
    'admin' { $Password = 'PasswordAdmin!' }
    'mallory' { $Password = 'PasswordMallory!' }
    default { $Password = "Password$Username!" }
  }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $PfxPath) {
  $Candidates = @(
    (Join-Path $ScriptDir "$Username.pfx"),
    (Join-Path $ScriptDir "client_keys\$Username.pfx")
  )
  foreach ($Cand in $Candidates) {
    if (Test-Path $Cand) {
      $PfxPath = (Resolve-Path $Cand).Path
      break
    }
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
  $b64 = [Convert]::ToBase64String($cc.RawData, [Base64FormattingOptions]::InsertLineBreaks)
  $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
  [System.IO.File]::WriteAllText((Join-Path $trustedClientsDir "$Username.crt"), $pem, [System.Text.Encoding]::ASCII)
  Write-Host "Generated client certificate and PFX for $Username" -ForegroundColor Green
}

Write-Host "Installing client certificate for user '$Username'..." -ForegroundColor Cyan
Write-Host "PFX Path: $PfxPath" -ForegroundColor DarkGray

$Process = Start-Process -FilePath 'certutil.exe' -ArgumentList "-user -p `"$Password`" -importpfx `"$PfxPath`" NoRoot" -NoNewWindow -Wait -PassThru

if ($Process.ExitCode -eq 0) {
  Write-Host "Certificate '$Username.pfx' imported successfully into Windows CurrentUser Personal store." -ForegroundColor Green
  Write-Host 'Chrome, Edge, and Windows applications will now offer this certificate for mTLS authentication.' -ForegroundColor Green
} else {
  Write-Error "certutil failed with exit code $($Process.ExitCode)"
  exit $Process.ExitCode
}
