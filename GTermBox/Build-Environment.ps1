[CmdletBinding()]
param(
  [string]$TargetDir = '',
  [string]$PythonPath = '',
  [string]$FarPath = '',
  [string]$EditPath = '',
  [switch]$SkipPython,
  [switch]$SkipFar,
  [switch]$SkipEdit,
  [hashtable[]]$CustomApps = @(),
  [switch]$Interactive,
  [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

if ([string]::IsNullOrWhiteSpace($TargetDir)) {
  if (Test-Path (Join-Path $ScriptDir "GTermBoxServer.exe")) {
    $TargetDir = $ScriptDir
  } elseif (Test-Path (Join-Path $ScriptDir "Win64\Debug\GTermBoxServer.exe")) {
    $TargetDir = Join-Path $ScriptDir "Win64\Debug"
  } elseif (Test-Path (Join-Path (Get-Location) "GTermBox\Win64\Debug\GTermBoxServer.exe")) {
    $TargetDir = Join-Path (Get-Location).Path "GTermBox\Win64\Debug"
  } elseif (Test-Path (Join-Path (Get-Location) "Win64\Debug\GTermBoxServer.exe")) {
    $TargetDir = Join-Path (Get-Location).Path "Win64\Debug"
  } elseif (Test-Path (Join-Path (Get-Location) "GTermBoxServer.exe")) {
    $TargetDir = (Get-Location).Path
  } else {
    $TargetDir = Join-Path $ScriptDir "Win64\Debug"
  }
}

$TargetDir = (Resolve-Path $TargetDir).Path

$IsInteractive = $false
if ($Interactive) {
  $IsInteractive = $true
} elseif (-not $NonInteractive) {
  if ([string]::IsNullOrWhiteSpace($PythonPath) -and [string]::IsNullOrWhiteSpace($FarPath) -and [string]::IsNullOrWhiteSpace($EditPath) -and -not $SkipPython -and -not $SkipFar -and -not $SkipEdit -and $CustomApps.Count -eq 0) {
    if ([Environment]::UserInteractive) {
      $IsInteractive = $true
    }
  }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       GTermBoxServer Environment Setup Wizard               " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Target Directory: $TargetDir"
Write-Host "Interactive Mode: $IsInteractive"
Write-Host ""

$CoreDirs = @(
  'web',
  'Log',
  'trusted_clients',
  'client_keys',
  'sandbox_admin',
  'sandbox_admin\AppData',
  'sandbox_admin\Documents',
  'sandbox_admin\tmp',
  'sandbox_admin\profile',
  'sandbox_admin\profile\local',
  'sandbox_admin\profile\PluginsData',
  'sandbox_admin\profile\local\PluginsData',
  'sandbox_admin\profile\Menus',
  'sandbox_admin\profile\Macros\scripts',
  'sandbox_admin\apps',
  'sandbox_usr1',
  'sandbox_usr1\AppData',
  'sandbox_usr1\Documents',
  'sandbox_usr1\tmp',
  'sandbox_usr1\profile',
  'sandbox_usr1\profile\local',
  'sandbox_usr1\profile\PluginsData',
  'sandbox_usr1\profile\local\PluginsData',
  'sandbox_usr1\profile\Menus',
  'sandbox_usr1\profile\Macros\scripts',
  'sandbox_usr1\apps'
)

foreach ($Sub in $CoreDirs) {
  $DirPath = Join-Path $TargetDir $Sub
  if (-not (Test-Path $DirPath)) {
    New-Item -ItemType Directory -Path $DirPath -Force | Out-Null
  }
}

$ManageUsersExe = Join-Path $TargetDir "ManageUsers.exe"
if (Test-Path $ManageUsersExe) {
  Write-Host "[1/4] Initializing base environment and configurations..." -ForegroundColor Yellow
  Push-Location $TargetDir
  try {
    & $ManageUsersExe init-env $TargetDir
    & $ManageUsersExe passwd admin 1234 | Out-Null
    & $ManageUsersExe passwd usr1 1234 | Out-Null
  } finally {
    Pop-Location
  }
}

Write-Host "[2/5] Configuring Mutual TLS (mTLS) client certificates..." -ForegroundColor Yellow
$TrustedClientsDir = Join-Path $TargetDir "trusted_clients"
$ClientKeysDir = Join-Path $TargetDir "client_keys"
$RepoCandidateCerts = @(
  (Join-Path $ScriptDir "trusted_clients"),
  (Join-Path $ScriptDir "client_keys"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\trusted_clients"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\client_keys")
)

foreach ($rc in $RepoCandidateCerts) {
  if (Test-Path $rc) {
    Get-ChildItem -Path $rc -Filter "*.crt" | ForEach-Object {
      $dest = Join-Path $TrustedClientsDir $_.Name
      if (-not (Test-Path $dest)) { Copy-Item $_.FullName $dest -Force }
    }
    Get-ChildItem -Path $rc -Include "*.pfx","*.key","*.crt" | ForEach-Object {
      $dest = Join-Path $ClientKeysDir $_.Name
      if (-not (Test-Path $dest)) { Copy-Item $_.FullName $dest -Force }
    }
  }
}

$DefaultMtlsUsers = @(
  @{ Name = 'admin'; Pwd = 'PasswordAdmin!' },
  @{ Name = 'usr1';  Pwd = 'PasswordUsr1!' },
  @{ Name = 'usr2';  Pwd = 'PasswordUsr2!' },
  @{ Name = 'usr3';  Pwd = 'PasswordUsr3!' }
)

foreach ($mu in $DefaultMtlsUsers) {
  $cName = $mu.Name
  $cPwd = $mu.Pwd
  $cPath = Join-Path $TrustedClientsDir "$cName.crt"
  $kPfx = Join-Path $ClientKeysDir "$cName.pfx"
  $kKey = Join-Path $ClientKeysDir "$cName.key"

  if (-not (Test-Path $cPath) -or -not (Test-Path $kPfx)) {
    $secPwd = ConvertTo-SecureString -String $cPwd -AsPlainText -Force
    $newCert = New-SelfSignedCertificate -Subject "CN=$cName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -Type Custom -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") -NotAfter (Get-Date).AddYears(5)
    Export-PfxCertificate -Cert $newCert -FilePath $kPfx -Password $secPwd | Out-Null

    $certBytes = $newCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $b64 = [Convert]::ToBase64String($certBytes, [Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
    [System.IO.File]::WriteAllText($cPath, $pem, [System.Text.Encoding]::ASCII)
    [System.IO.File]::WriteAllText((Join-Path $ClientKeysDir "$cName.crt"), $pem, [System.Text.Encoding]::ASCII)

    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($newCert)
    if ($rsaKey) {
      $pkcs8 = $null
      if ($rsaKey.PSObject.Methods['ExportPkcs8PrivateKey']) {
        $pkcs8 = $rsaKey.ExportPkcs8PrivateKey()
      } elseif ($rsaKey -is [System.Security.Cryptography.RSACng]) {
        $pkcs8 = $rsaKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
      }
      if ($pkcs8) {
        $k64 = [Convert]::ToBase64String($pkcs8, [Base64FormattingOptions]::InsertLineBreaks)
        $kpem = "-----BEGIN PRIVATE KEY-----`n$k64`n-----END PRIVATE KEY-----`n"
        [System.IO.File]::WriteAllText($kKey, $kpem, [System.Text.Encoding]::ASCII)
      }
    }
  }

  if (Test-Path $ManageUsersExe) {
    Push-Location $TargetDir
    try {
      & $ManageUsersExe bind-cert $cName "$cName.crt" | Out-Null
    } finally {
      Pop-Location
    }
  }
}

Write-Host "[2/5] Configuring server TLS certificate (localhost.cer)..." -ForegroundColor Yellow
$ServerStoreName = 'GHttpsIOCPSvr'
$ServerCerPath = Join-Path $TargetDir "localhost.cer"
$ServerHostName = [System.Net.Dns]::GetHostName()
$ServerIps = @()
try {
  $ServerIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -Unique)
} catch {
  $ServerIps = @([System.Net.Dns]::GetHostAddresses($ServerHostName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique)
}
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$CertNow = Get-Date

$UserStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($ServerStoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
$UserStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
  $ServerCert = $null
  $ReuseCandidates = @($UserStore.Certificates | Where-Object { $_.Subject -eq 'CN=localhost' -and $_.HasPrivateKey -and $_.NotAfter -gt $CertNow.AddDays(30) } | Sort-Object NotAfter -Descending)
  foreach ($rc in $ReuseCandidates) {
    $sanExtObj = $rc.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    $sanText = ''
    if ($sanExtObj) { $sanText = $sanExtObj.Format($false) }
    $covers = $true
    foreach ($ip in $ServerIps) {
      if ($sanText -notmatch ('(^|[^0-9.])' + [regex]::Escape($ip) + '($|[^0-9.])')) { $covers = $false; break }
    }
    if ($covers) { $ServerCert = $rc; break }
  }

  if ($ServerCert) {
    Write-Host ("  [=] Reusing valid server certificate {0} (expires {1})" -f $ServerCert.Thumbprint, $ServerCert.NotAfter) -ForegroundColor DarkGray
  } else {
    $sanParts = New-Object System.Collections.Generic.List[string]
    $sanParts.Add('DNS=localhost')
    if ($ServerHostName -and $ServerHostName -ne 'localhost') { $sanParts.Add("DNS=$ServerHostName") }
    foreach ($ip in $ServerIps) { $sanParts.Add("IPAddress=$ip") }
    $sanExt = '2.5.29.17={text}' + ($sanParts -join '&')
    $newServerCert = New-SelfSignedCertificate -Subject 'CN=localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeySpec KeyExchange -KeyUsage DigitalSignature,KeyEncipherment -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -Type Custom -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1', $sanExt) -NotAfter $CertNow.AddYears(5)

    foreach ($old in @($UserStore.Certificates | Where-Object { $_.Subject -eq 'CN=localhost' })) {
      try {
        $UserStore.Remove($old)
        Write-Host ("  [-] Removed outdated server certificate {0} (expires {1})" -f $old.Thumbprint, $old.NotAfter) -ForegroundColor DarkYellow
      } catch {
        Write-Host ("  [!] Certificate {0} belongs to LocalMachine\{1} and cannot be removed without Administrator rights" -f $old.Thumbprint, $ServerStoreName) -ForegroundColor Yellow
      }
    }
    $UserStore.Add($newServerCert)
    Remove-Item -Path ("Cert:\CurrentUser\My\" + $newServerCert.Thumbprint) -Force
    $ServerCert = $newServerCert
    Write-Host ("  [+] Generated new server certificate {0} (SAN: {1})" -f $ServerCert.Thumbprint, ($sanParts -join ', ')) -ForegroundColor Green
  }

  if ($IsAdmin) {
    try {
      $MachineStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($ServerStoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
      $MachineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
      try {
        foreach ($old in @($MachineStore.Certificates | Where-Object { $_.Subject -eq 'CN=localhost' -and $_.NotAfter -le $CertNow })) {
          $MachineStore.Remove($old)
          Write-Host ("  [-] Removed expired LocalMachine certificate {0} (expired {1})" -f $old.Thumbprint, $old.NotAfter) -ForegroundColor DarkYellow
        }
      } finally {
        $MachineStore.Close()
      }
    } catch {
      Write-Host ("  [!] Could not clean LocalMachine\{0}: {1}" -f $ServerStoreName, $_.Exception.Message) -ForegroundColor Yellow
    }
  } else {
    $ExpiredMachine = @(Get-ChildItem ("Cert:\LocalMachine\" + $ServerStoreName) -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq 'CN=localhost' -and $_.NotAfter -le $CertNow })
    if ($ExpiredMachine.Count -gt 0) {
      Write-Host ("  [!] LocalMachine\{0} contains {1} expired localhost certificate(s). Rerun as Administrator to remove them." -f $ServerStoreName, $ExpiredMachine.Count) -ForegroundColor Yellow
    }
  }

  [System.IO.File]::WriteAllBytes($ServerCerPath, $ServerCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
  Write-Host ("  [+] Server certificate exported: {0}" -f $ServerCerPath) -ForegroundColor Green
  Write-Host ("      Thumbprint: {0}  Expires: {1}" -f $ServerCert.Thumbprint, $ServerCert.NotAfter) -ForegroundColor DarkGray
} finally {
  $UserStore.Close()
}

$InstallScriptCandidates = @(
  (Join-Path $ScriptDir "Install-ClientCertificate.ps1"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Install-ClientCertificate.ps1")
)
foreach ($isc in $InstallScriptCandidates) {
  if (Test-Path $isc) {
    $dstTarget = Join-Path $TargetDir "Install-ClientCertificate.ps1"
    $dstKeys = Join-Path $ClientKeysDir "Install-ClientCertificate.ps1"
    if ([System.IO.Path]::GetFullPath($isc) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $isc $dstTarget -Force
    }
    if ([System.IO.Path]::GetFullPath($isc) -ne [System.IO.Path]::GetFullPath($dstKeys)) {
      Copy-Item $isc $dstKeys -Force
    }
    break
  }
}

$InstallCmdCandidates = @(
  (Join-Path $ScriptDir "Install-ClientCertificate.cmd"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Install-ClientCertificate.cmd")
)
foreach ($icc in $InstallCmdCandidates) {
  if (Test-Path $icc) {
    $dstTarget = Join-Path $TargetDir "Install-ClientCertificate.cmd"
    $dstKeys = Join-Path $ClientKeysDir "Install-ClientCertificate.cmd"
    if ([System.IO.Path]::GetFullPath($icc) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $icc $dstTarget -Force
    }
    if ([System.IO.Path]::GetFullPath($icc) -ne [System.IO.Path]::GetFullPath($dstKeys)) {
      Copy-Item $icc $dstKeys -Force
    }
    break
  }
}

$ServerInstallCandidates = @(
  (Join-Path $ScriptDir "Install-ServerCertificate.ps1"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Install-ServerCertificate.ps1")
)
foreach ($sic in $ServerInstallCandidates) {
  if (Test-Path $sic) {
    $dstTarget = Join-Path $TargetDir "Install-ServerCertificate.ps1"
    $dstKeys = Join-Path $ClientKeysDir "Install-ServerCertificate.ps1"
    if ([System.IO.Path]::GetFullPath($sic) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $sic $dstTarget -Force
    }
    if ([System.IO.Path]::GetFullPath($sic) -ne [System.IO.Path]::GetFullPath($dstKeys)) {
      Copy-Item $sic $dstKeys -Force
    }
    break
  }
}

$ServerCmdCandidates = @(
  (Join-Path $ScriptDir "Install-ServerCertificate.cmd"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Install-ServerCertificate.cmd")
)
foreach ($scc in $ServerCmdCandidates) {
  if (Test-Path $scc) {
    $dstTarget = Join-Path $TargetDir "Install-ServerCertificate.cmd"
    $dstKeys = Join-Path $ClientKeysDir "Install-ServerCertificate.cmd"
    if ([System.IO.Path]::GetFullPath($scc) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $scc $dstTarget -Force
    }
    if ([System.IO.Path]::GetFullPath($scc) -ne [System.IO.Path]::GetFullPath($dstKeys)) {
      Copy-Item $scc $dstKeys -Force
    }
    break
  }
}

$BindScriptCandidates = @(
  (Join-Path $ScriptDir "Bind-ClientCertificate.ps1"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Bind-ClientCertificate.ps1")
)
foreach ($bsc in $BindScriptCandidates) {
  if (Test-Path $bsc) {
    $dstTarget = Join-Path $TargetDir "Bind-ClientCertificate.ps1"
    if ([System.IO.Path]::GetFullPath($bsc) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $bsc $dstTarget -Force
    }
    break
  }
}

$BindCmdCandidates = @(
  (Join-Path $ScriptDir "Bind-ClientCertificate.cmd"),
  (Join-Path (Get-Location) "GTermBox\Win64\Debug\Bind-ClientCertificate.cmd")
)
foreach ($bcc in $BindCmdCandidates) {
  if (Test-Path $bcc) {
    $dstTarget = Join-Path $TargetDir "Bind-ClientCertificate.cmd"
    if ([System.IO.Path]::GetFullPath($bcc) -ne [System.IO.Path]::GetFullPath($dstTarget)) {
      Copy-Item $bcc $dstTarget -Force
    }
    break
  }
}

$SuggestedPy = ''
if (Test-Path (Join-Path $TargetDir "Python\python.exe")) {
  $SuggestedPy = (Join-Path $TargetDir "Python\python.exe")
} else {
  $SysPy = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($SysPy -and (Test-Path $SysPy.Source)) {
    $SuggestedPy = $SysPy.Source
  } else {
    $RegPy = (Get-ItemProperty -Path "HKLM:\Software\Python\PythonCore\*\InstallPath", "HKCU:\Software\Python\PythonCore\*\InstallPath" -ErrorAction SilentlyContinue).'(default)'
    foreach ($rp in $RegPy) {
      if ($rp -and (Test-Path (Join-Path $rp "python.exe"))) {
        $SuggestedPy = Join-Path $rp "python.exe"
        break
      }
    }
  }
}

$SuggestedFar = ''
if (Test-Path (Join-Path $TargetDir "Far\Far.exe")) {
  $SuggestedFar = (Join-Path $TargetDir "Far\Far.exe")
} else {
  $SysFar = Get-Command far.exe -ErrorAction SilentlyContinue
  if ($SysFar -and (Test-Path $SysFar.Source)) {
    $SuggestedFar = $SysFar.Source
  } else {
    $FarCandidates = @(
      (Join-Path $TargetDir "..\Far\Far.exe"),
      (Join-Path $TargetDir "..\..\Far\Far.exe"),
      (Join-Path $ScriptDir "Far\Far.exe"),
      (Join-Path $ScriptDir "..\Far\Far.exe"),
      (Join-Path (Get-Location) "tmp\Far\Far.exe")
    )
    foreach ($fc in $FarCandidates) {
      if (Test-Path $fc) {
        $SuggestedFar = (Resolve-Path $fc).Path
        break
      }
    }
  }
}

$SuggestedEdit = ''
if (Test-Path (Join-Path $TargetDir "Edit\edit.exe")) {
  $SuggestedEdit = (Join-Path $TargetDir "Edit\edit.exe")
} else {
  $SysEdit = Get-Command edit.exe -ErrorAction SilentlyContinue
  if (-not $SysEdit) {
    $SysEdit = Get-Command micro.exe -ErrorAction SilentlyContinue
  }
  if ($SysEdit -and (Test-Path $SysEdit.Source)) {
    $SuggestedEdit = $SysEdit.Source
  } else {
    $EditCandidates = @(
      (Join-Path $TargetDir "..\Edit\edit.exe"),
      (Join-Path $TargetDir "..\..\Edit\edit.exe"),
      (Join-Path $ScriptDir "Edit\edit.exe"),
      (Join-Path $ScriptDir "..\Edit\edit.exe"),
      (Join-Path (Get-Location) "tmp\Edit\edit.exe")
    )
    foreach ($ec in $EditCandidates) {
      if (Test-Path $ec) {
        $SuggestedEdit = (Resolve-Path $ec).Path
        break
      }
    }
  }
}

if ($IsInteractive) {
  Write-Host "--- Application Configuration & Source Selection ---" -ForegroundColor Cyan
  Write-Host "Enter application paths or enter 'none' / 'skip' to decline." -ForegroundColor DarkCyan
  Write-Host ""

  $PromptPyMsg = "Path for Python (python.exe)"
  if ($SuggestedPy) { $PromptPyMsg += " [Hint: $SuggestedPy]" } else { $PromptPyMsg += " [No hint detected]" }
  $UserPy = Read-Host $PromptPyMsg
  $UserPy = $UserPy.Trim().Trim('"')
  if ($UserPy -match '^(none|skip|n|no|0)$') {
    $SkipPython = $true
    $PythonPath = ''
  } elseif (-not [string]::IsNullOrWhiteSpace($UserPy)) {
    $PythonPath = $UserPy
    $SkipPython = $false
  } elseif ($SuggestedPy) {
    $PythonPath = $SuggestedPy
    $SkipPython = $false
  } else {
    $SkipPython = $true
  }

  $PromptFarMsg = "Path for Far Manager (Far.exe or folder)"
  if ($SuggestedFar) { $PromptFarMsg += " [Hint: $SuggestedFar]" } else { $PromptFarMsg += " [No hint detected]" }
  $UserFar = Read-Host $PromptFarMsg
  $UserFar = $UserFar.Trim().Trim('"')
  if ($UserFar -match '^(none|skip|n|no|0)$') {
    $SkipFar = $true
    $FarPath = ''
  } elseif (-not [string]::IsNullOrWhiteSpace($UserFar)) {
    $FarPath = $UserFar
    $SkipFar = $false
  } elseif ($SuggestedFar) {
    $FarPath = $SuggestedFar
    $SkipFar = $false
  } else {
    $SkipFar = $true
  }

  $PromptEditMsg = "Path for Text Editor (edit.exe / micro.exe)"
  if ($SuggestedEdit) { $PromptEditMsg += " [Hint: $SuggestedEdit]" } else { $PromptEditMsg += " [No hint detected]" }
  $UserEdit = Read-Host $PromptEditMsg
  $UserEdit = $UserEdit.Trim().Trim('"')
  if ($UserEdit -match '^(none|skip|n|no|0)$') {
    $SkipEdit = $true
    $EditPath = ''
  } elseif (-not [string]::IsNullOrWhiteSpace($UserEdit)) {
    $EditPath = $UserEdit
    $SkipEdit = $false
  } elseif ($SuggestedEdit) {
    $EditPath = $SuggestedEdit
    $SkipEdit = $false
  } else {
    $SkipEdit = $true
  }

  Write-Host ""
  $AddCustom = Read-Host "Would you like to install/register additional custom applications? [y/N]"
  if ($AddCustom -match '^[Yy]') {
    while ($true) {
      $cId = Read-Host "Enter Application ID (e.g. htop, git, node, ping)"
      $cId = $cId.Trim().ToLower()
      if ([string]::IsNullOrWhiteSpace($cId)) { break }
      $cName = Read-Host "Enter Display Name (default: $cId)"
      if ([string]::IsNullOrWhiteSpace($cName)) { $cName = $cId }
      $cCmd = Read-Host "Enter Command/Executable path"
      $cCmd = $cCmd.Trim().Trim('"')
      if ([string]::IsNullOrWhiteSpace($cCmd)) {
        Write-Host "Command is required. App aborted." -ForegroundColor Red
      } else {
        $cSb = Read-Host "Enter Sandbox mode [standard / job-only / none] (default: standard)"
        $cSb = $cSb.Trim().ToLower()
        if ([string]::IsNullOrWhiteSpace($cSb)) { $cSb = 'standard' }
        $cNet = Read-Host "Enable Network access? [Y/N] (default: N)"
        $bNet = ($cNet -match '^[Yy]')
        $CustomApps += @{
          Id = $cId; Name = $cName; Command = $cCmd; Sandbox = $cSb; Network = $bNet
        }
        Write-Host "Registered custom app definition: $cId" -ForegroundColor Green
      }
      $More = Read-Host "Add another custom application? [y/N]"
      if ($More -notmatch '^[Yy]') { break }
    }
  }
}

Write-Host "[2/4] Deploying selected applications..." -ForegroundColor Yellow

$TargetPyDir = Join-Path $TargetDir "Python"
$TargetPyTuiDir = Join-Path $TargetDir "PyTui"
if ($SkipPython) {
  Write-Host "  [-] Python & PyTui: SKIPPED by user choice" -ForegroundColor DarkYellow
  if (Test-Path $TargetPyDir) {
    Remove-Item -Path $TargetPyDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $TargetPyTuiDir) {
    Remove-Item -Path $TargetPyTuiDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $ManageUsersExe) {
    & $ManageUsersExe delete-app python | Out-Null
    & $ManageUsersExe delete-app pytui | Out-Null
  }
} elseif (-not [string]::IsNullOrWhiteSpace($PythonPath)) {
  $PyResolvedExe = $PythonPath
  if (Test-Path (Join-Path $PythonPath "python.exe")) {
    $PyResolvedExe = Join-Path $PythonPath "python.exe"
  }
  if (Test-Path $PyResolvedExe) {
    if (-not (Test-Path $TargetPyDir)) {
      New-Item -ItemType Directory -Path $TargetPyDir -Force | Out-Null
    }
    $PySourceDir = Split-Path -Parent $PyResolvedExe
    if ((Resolve-Path $PySourceDir).Path -ne (Resolve-Path $TargetPyDir).Path) {
      Write-Host "      Deploying Python from user-specified location: $PySourceDir" -ForegroundColor Yellow
      Copy-Item -Path (Join-Path $PySourceDir "python.exe") -Destination (Join-Path $TargetPyDir "python.exe") -Force
      if (Test-Path (Join-Path $PySourceDir "pythonw.exe")) {
        Copy-Item -Path (Join-Path $PySourceDir "pythonw.exe") -Destination (Join-Path $TargetPyDir "pythonw.exe") -Force
      }
      Get-ChildItem -Path $PySourceDir -Filter "python3*.dll" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $TargetPyDir -Force
      }
      Get-ChildItem -Path $PySourceDir -Filter "vcruntime*.dll" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $TargetPyDir -Force
      }
      if (Test-Path (Join-Path $PySourceDir "DLLs")) {
        Copy-Item -Path (Join-Path $PySourceDir "DLLs") -Destination (Join-Path $TargetPyDir "DLLs") -Recurse -Force
      }
      if (Test-Path (Join-Path $PySourceDir "Lib")) {
        $DstLib = Join-Path $TargetPyDir "Lib"
        New-Item -ItemType Directory -Path $DstLib -Force | Out-Null
        Get-ChildItem -Path (Join-Path $PySourceDir "Lib") | Where-Object {
          $_.Name -notin @('site-packages', 'test', 'tests', 'idlelib', 'tkinter', '__pycache__')
        } | ForEach-Object {
          Copy-Item -Path $_.FullName -Destination (Join-Path $DstLib $_.Name) -Recurse -Force
        }
      }
    }

    if (-not (Test-Path $TargetPyTuiDir)) {
      New-Item -ItemType Directory -Path $TargetPyTuiDir -Force | Out-Null
    }
    $PyTuiAppPy = Join-Path $TargetPyTuiDir "app.py"
    if (-not (Test-Path $PyTuiAppPy)) {
      $TuiSources = @(
        (Join-Path $ScriptDir "PyTui\app.py"),
        (Join-Path $ScriptDir "..\PyTui\app.py"),
        (Join-Path $ScriptDir "..\..\PyTui\app.py")
      )
      $FoundTui = $false
      foreach ($Cand in $TuiSources) {
        if (Test-Path $Cand) {
          Copy-Item -Path $Cand -Destination $PyTuiAppPy -Force
          $FoundTui = $true
          break
        }
      }
      if (-not $FoundTui) {
        Set-Content -Path $PyTuiAppPy -Value "import sys`r`nprint('Python TUI VirtualEnv Demonstration')`r`n" -Encoding UTF8
      }
    }

    $PyTuiRunCmd = Join-Path $TargetPyTuiDir "run.cmd"
    if (-not (Test-Path $PyTuiRunCmd)) {
      Set-Content -Path $PyTuiRunCmd -Value "@echo off`r`npython app.py`r`n" -Encoding ASCII
    }

    if (Test-Path $ManageUsersExe) {
      Push-Location $TargetDir
      try {
        & $ManageUsersExe add-app python "Python Console" "python.exe" --sandbox=job-only --no-network --args="-i,-q" --env="TERM=xterm-256color,COLORTERM=truecolor,PYTHONIOENCODING=utf-8,PYTHONUTF8=1" | Out-Null
        & $ManageUsersExe add-app pytui "Python Demo TUI" "PyTui\run.cmd" --sandbox=job-only --no-network --env="TERM=xterm-256color,COLORTERM=truecolor,PYTHONIOENCODING=utf-8,PYTHONUTF8=1" | Out-Null
      } finally {
        Pop-Location
      }
    }
  }
}

$TargetFarDir = Join-Path $TargetDir "Far"
if ($SkipFar) {
  Write-Host "  [-] Far Manager: SKIPPED by user choice" -ForegroundColor DarkYellow
  if (Test-Path $TargetFarDir) {
    Remove-Item -Path $TargetFarDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $ManageUsersExe) {
    & $ManageUsersExe delete-app far | Out-Null
  }
} elseif (-not [string]::IsNullOrWhiteSpace($FarPath)) {
  $FarResolvedExe = $FarPath
  if (Test-Path (Join-Path $FarPath "Far.exe")) {
    $FarResolvedExe = Join-Path $FarPath "Far.exe"
  }
  if (Test-Path $FarResolvedExe) {
    if (-not (Test-Path $TargetFarDir)) {
      New-Item -ItemType Directory -Path $TargetFarDir -Force | Out-Null
    }
    $FarSourceDir = Split-Path -Parent $FarResolvedExe
    if ((Resolve-Path $FarSourceDir).Path -ne (Resolve-Path $TargetFarDir).Path) {
      Write-Host "      Deploying Far Manager from user-specified location: $FarSourceDir" -ForegroundColor Yellow
      Copy-Item -Path "$FarSourceDir\*" -Destination $TargetFarDir -Recurse -Force
    }
    if (Test-Path $ManageUsersExe) {
      Push-Location $TargetDir
      try {
        & $ManageUsersExe add-app far "Far Manager" "Far\Far.exe" --sandbox=standard --no-network --cols=160 --rows=38 --args="-title:Far,-s,%SANDBOX%\profile,%SANDBOX%\profile\local,%SANDBOX%,%SANDBOX%" | Out-Null
      } finally {
        Pop-Location
      }
    }
  }
}

$TargetEditDir = Join-Path $TargetDir "Edit"
if ($SkipEdit) {
  Write-Host "  [-] Text Editor: SKIPPED by user choice" -ForegroundColor DarkYellow
  if (Test-Path $TargetEditDir) {
    Remove-Item -Path $TargetEditDir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $ManageUsersExe) {
    & $ManageUsersExe delete-app edit | Out-Null
  }
} elseif (-not [string]::IsNullOrWhiteSpace($EditPath)) {
  $EditResolvedExe = $EditPath
  if (Test-Path (Join-Path $EditPath "edit.exe")) {
    $EditResolvedExe = Join-Path $EditPath "edit.exe"
  } elseif (Test-Path (Join-Path $EditPath "micro.exe")) {
    $EditResolvedExe = Join-Path $EditPath "micro.exe"
  }
  if (Test-Path $EditResolvedExe) {
    if (-not (Test-Path $TargetEditDir)) {
      New-Item -ItemType Directory -Path $TargetEditDir -Force | Out-Null
    }
    $TargetEditFile = Join-Path $TargetEditDir "edit.exe"
    if (-not (Test-Path $TargetEditFile) -or (Resolve-Path $EditResolvedExe).Path -ne (Resolve-Path $TargetEditFile).Path) {
      Write-Host "      Deploying Edit from user-specified location: $EditResolvedExe" -ForegroundColor Yellow
      Copy-Item -Path $EditResolvedExe -Destination $TargetEditFile -Force
    }
    if (Test-Path $ManageUsersExe) {
      Push-Location $TargetDir
      try {
        & $ManageUsersExe add-app edit "Microsoft Edit" "Edit\edit.exe" --sandbox=standard --no-network --cols=120 --rows=40 | Out-Null
      } finally {
        Pop-Location
      }
    }
  }
}

if ($CustomApps.Count -gt 0 -and (Test-Path $ManageUsersExe)) {
  Write-Host "[3/4] Registering user-specified custom applications..." -ForegroundColor Yellow
  foreach ($app in $CustomApps) {
    $aId = $app.Id
    $aName = $app.Name
    $aCmd = $app.Command
    $aSb = if ($app.Sandbox) { $app.Sandbox } else { 'standard' }
    $bNet = if ($app.Network) { $true } else { $false }

    $argsList = @("add-app", $aId, $aName, $aCmd, "--sandbox=$aSb")
    if ($bNet) { $argsList += "--network" } else { $argsList += "--no-network" }

    Push-Location $TargetDir
    try {
      & $ManageUsersExe @argsList
      Write-Host "  [+] Configured custom app: $aId ($aName) -> $aCmd" -ForegroundColor Green
    } finally {
      Pop-Location
    }
  }
}

$AppsJsonPath = Join-Path $TargetDir "apps.json"
if ((Test-Path $AppsJsonPath) -and (Test-Path $ManageUsersExe)) {
  try {
    $appsData = Get-Content $AppsJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $activeAppIds = @($appsData.apps | Where-Object { $_.id -ne 'admin-powershell' } | ForEach-Object { $_.id })
    if ($activeAppIds.Count -gt 0) {
      Push-Location $TargetDir
      try {
        & $ManageUsersExe edit usr1 "--apps=$($activeAppIds -join ',')" | Out-Null
      } finally {
        Pop-Location
      }
    }
  } catch {}
}

Write-Host "[3/4] Configuring AppContainer security ACLs on active directories..." -ForegroundColor Yellow

$AclFolders = @(
  @{ Path = (Join-Path $TargetDir "sandbox_usr1"); Perm = "(OI)(CI)F" },
  @{ Path = (Join-Path $TargetDir "sandbox_admin"); Perm = "(OI)(CI)F" },
  @{ Path = (Join-Path $TargetDir "web"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "trusted_clients"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "client_keys"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "Python"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "PyTui"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "Far"); Perm = "(OI)(CI)RX" },
  @{ Path = (Join-Path $TargetDir "Edit"); Perm = "(OI)(CI)RX" }
)

foreach ($Acl in $AclFolders) {
  if (Test-Path $Acl.Path) {
    & icacls $Acl.Path /grant "*S-1-15-2-1:$($Acl.Perm)" /T /C /Q | Out-Null
  }
}

Write-Host "[4/4] Verifying environment readiness..." -ForegroundColor Yellow

$Checklist = @(
  @{ Name = "GTermBoxServer.exe"; Path = (Join-Path $TargetDir "GTermBoxServer.exe"); Required = $true; Skipped = $false },
  @{ Name = "ManageUsers.exe";    Path = (Join-Path $TargetDir "ManageUsers.exe");    Required = $true; Skipped = $false },
  @{ Name = "web\index.html";     Path = (Join-Path $TargetDir "web\index.html");     Required = $true; Skipped = $false },
  @{ Name = "msquic.dll";         Path = (Join-Path $TargetDir "msquic.dll");         Required = $true; Skipped = $false },
  @{ Name = "ls-qpack.dll";       Path = (Join-Path $TargetDir "ls-qpack.dll");       Required = $true; Skipped = $false },
  @{ Name = "users.json";         Path = (Join-Path $TargetDir "users.json");         Required = $true; Skipped = $false },
  @{ Name = "apps.json";          Path = (Join-Path $TargetDir "apps.json");          Required = $true; Skipped = $false },
  @{ Name = "trusted_clients\admin.crt"; Path = (Join-Path $TargetDir "trusted_clients\admin.crt"); Required = $true; Skipped = $false },
  @{ Name = "trusted_clients\usr1.crt";  Path = (Join-Path $TargetDir "trusted_clients\usr1.crt");  Required = $true; Skipped = $false },
  @{ Name = "client_keys\admin.pfx";     Path = (Join-Path $TargetDir "client_keys\admin.pfx");     Required = $true; Skipped = $false },
  @{ Name = "client_keys\usr1.pfx";      Path = (Join-Path $TargetDir "client_keys\usr1.pfx");      Required = $true; Skipped = $false },
  @{ Name = "localhost.cer";      Path = (Join-Path $TargetDir "localhost.cer");      Required = $true; Skipped = $false },
  @{ Name = "Python\python.exe";  Path = (Join-Path $TargetDir "Python\python.exe");  Required = (-not $SkipPython); Skipped = $SkipPython },
  @{ Name = "PyTui\app.py";       Path = (Join-Path $TargetDir "PyTui\app.py");       Required = (-not $SkipPython); Skipped = $SkipPython },
  @{ Name = "PyTui\run.cmd";      Path = (Join-Path $TargetDir "PyTui\run.cmd");      Required = (-not $SkipPython); Skipped = $SkipPython },
  @{ Name = "Far\Far.exe";        Path = (Join-Path $TargetDir "Far\Far.exe");        Required = (-not $SkipFar); Skipped = $SkipFar },
  @{ Name = "Edit\edit.exe";      Path = (Join-Path $TargetDir "Edit\edit.exe");      Required = (-not $SkipEdit); Skipped = $SkipEdit },
  @{ Name = "sandbox_admin";      Path = (Join-Path $TargetDir "sandbox_admin");      Required = $true; Skipped = $false },
  @{ Name = "sandbox_usr1";       Path = (Join-Path $TargetDir "sandbox_usr1");       Required = $true; Skipped = $false }
)

$AllPassed = $true
foreach ($Item in $Checklist) {
  if ($Item.Skipped) {
    Write-Host ("  [-] {0,-20} : SKIPPED (User choice)" -f $Item.Name) -ForegroundColor DarkYellow
    continue
  }
  $Exists = Test-Path $Item.Path
  if ($Exists) {
    Write-Host ("  [+] {0,-20} : READY" -f $Item.Name) -ForegroundColor Green
  } else {
    if ($Item.Required) {
      Write-Host ("  [-] {0,-20} : MISSING (Required)" -f $Item.Name) -ForegroundColor Red
      $AllPassed = $false
    } else {
      Write-Host ("  [?] {0,-20} : NOT FOUND (Optional)" -f $Item.Name) -ForegroundColor Yellow
    }
  }
}

if ($CustomApps.Count -gt 0) {
  foreach ($app in $CustomApps) {
    Write-Host ("  [+] Custom: {0,-12} : READY ({1})" -f $app.Id, $app.Name) -ForegroundColor Green
  }
}

Write-Host ""
if ($AllPassed) {
  Write-Host "============================================================" -ForegroundColor Green
  Write-Host " GTermBoxServer environment is ready for operation!         " -ForegroundColor Green
  Write-Host "============================================================" -ForegroundColor Green
} else {
  Write-Host "============================================================" -ForegroundColor Red
  Write-Host " Environment incomplete! Please inspect missing files above." -ForegroundColor Red
  Write-Host "============================================================" -ForegroundColor Red
  exit 1
}
