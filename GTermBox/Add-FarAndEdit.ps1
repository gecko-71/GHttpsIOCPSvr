[CmdletBinding()]
param(
  [string]$InstallDir = '',
  [switch]$ForceDownload
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  if (Test-Path (Join-Path $PSScriptRoot 'ManageUsers.exe')) {
    $InstallDir = $PSScriptRoot
  } elseif (Test-Path (Join-Path (Get-Location).Path 'ManageUsers.exe')) {
    $InstallDir = (Get-Location).Path
  } else {
    $InstallDir = $PSScriptRoot
  }
}
$InstallDir = (Resolve-Path $InstallDir).Path

$ManageExe = Join-Path $InstallDir 'ManageUsers.exe'
if (-not (Test-Path $ManageExe)) {
  Write-Host "ManageUsers.exe not found in $InstallDir" -ForegroundColor Red
  exit 1
}

function Write-Step([string]$Text) { Write-Host ''; Write-Host $Text -ForegroundColor Yellow }
function Write-Ok([string]$Text) { Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "  [=] $Text" -ForegroundColor DarkGray }
function Write-Warn([string]$Text) { Write-Host "  [!] $Text" -ForegroundColor DarkYellow }
function Stop-Script([string]$Text) { Write-Host "  [X] $Text" -ForegroundColor Red; exit 1 }

function Invoke-Manage {
  param([string[]]$Arguments)
  Push-Location $InstallDir
  try {
    $output = & $ManageExe @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Stop-Script ("ManageUsers {0} failed: {1}" -f ($Arguments -join ' '), $output.Trim()) }
    return $output
  } finally {
    Pop-Location
  }
}

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '   GTermBox - Download and Register Far Manager & Edit      ' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "Target directory: $InstallDir"

Write-Step '[1/4] Checking/Downloading Far Manager from Internet...'
$FarDir = Join-Path $InstallDir 'Far'
$FarExe = Join-Path $FarDir 'Far.exe'
$farInstalled = $false

if ((Test-Path $FarExe) -and (-not $ForceDownload)) {
  Write-Info "Far.exe already present in $FarDir"
  $farInstalled = $true
} else {
  Write-Info 'Attempting to download Far Manager from GitHub releases...'
  try {
    $downloadUrl = ''
    try {
      $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/FarGroup/FarManager/releases/latest' -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 15
      $asset = $rel.assets | Where-Object { $_.name -like '*x64*.7z' -and $_.name -notlike '*pdb*' } | Select-Object -First 1
      if ($asset) { $downloadUrl = $asset.browser_download_url }
    } catch {
    }

    if (-not $downloadUrl) {
      $downloadUrl = 'https://github.com/FarGroup/FarManager/releases/download/ci/v3.0.6750.5033/Far_3.0.6750.5033_x64_20261102_b16f95d.7z'
    }

    $tempArchive = Join-Path $env:TEMP ("far_download_" + [System.Guid]::NewGuid().ToString('N') + '.7z')
    try {
      Invoke-WebRequest -Uri $downloadUrl -OutFile $tempArchive -TimeoutSec 45
      if (-not (Test-Path $FarDir)) { New-Item -ItemType Directory -Path $FarDir -Force | Out-Null }
      & tar.exe -xf $tempArchive -C $FarDir
      if (Test-Path $FarExe) {
        $farInstalled = $true
        Write-Ok "Far Manager downloaded and deployed to $FarDir"
      } else {
        Write-Warn "Extraction finished but Far.exe not found in $FarDir"
      }
    } finally {
      if (Test-Path $tempArchive) { Remove-Item $tempArchive -Force -ErrorAction SilentlyContinue }
    }
  } catch {
    Write-Warn "Internet access unavailable or download failed for Far Manager ($($_.Exception.Message)). Skipping."
  }
}

Write-Step '[2/4] Checking/Downloading Microsoft Edit from Internet...'
$EditDir = Join-Path $InstallDir 'Edit'
$EditExe = Join-Path $EditDir 'edit.exe'
$editInstalled = $false

if ((Test-Path $EditExe) -and (-not $ForceDownload)) {
  Write-Info "edit.exe already present in $EditDir"
  $editInstalled = $true
} else {
  Write-Info 'Attempting to download Microsoft Edit from GitHub releases...'
  try {
    $downloadUrl = ''
    try {
      $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/edit/releases/latest' -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 15
      $asset = $rel.assets | Where-Object { $_.name -like '*x86_64-windows.zip' } | Select-Object -First 1
      if ($asset) { $downloadUrl = $asset.browser_download_url }
    } catch {
    }

    if (-not $downloadUrl) {
      $downloadUrl = 'https://github.com/microsoft/edit/releases/download/v2.0.0/edit-2.0.0-x86_64-windows.zip'
    }

    $tempArchive = Join-Path $env:TEMP ("edit_download_" + [System.Guid]::NewGuid().ToString('N') + '.zip')
    $tempExtract = Join-Path $env:TEMP ("edit_extract_" + [System.Guid]::NewGuid().ToString('N'))
    try {
      Invoke-WebRequest -Uri $downloadUrl -OutFile $tempArchive -TimeoutSec 45
      Expand-Archive -Path $tempArchive -DestinationPath $tempExtract -Force
      if (-not (Test-Path $EditDir)) { New-Item -ItemType Directory -Path $EditDir -Force | Out-Null }
      $extractedExe = Get-ChildItem -Path $tempExtract -Filter 'edit.exe' -Recurse | Select-Object -First 1
      if ($extractedExe) {
        Move-Item $extractedExe.FullName $EditExe -Force
        $editInstalled = $true
        Write-Ok "Microsoft Edit downloaded and deployed to $EditDir"
      } else {
        Write-Warn "Extraction finished but edit.exe not found"
      }
    } finally {
      if (Test-Path $tempArchive) { Remove-Item $tempArchive -Force -ErrorAction SilentlyContinue }
      if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue }
    }
  } catch {
    Write-Warn "Internet access unavailable or download failed for Microsoft Edit ($($_.Exception.Message)). Skipping."
  }
}

Write-Step '[3/4] Applying AppContainer ACLs...'
if ($farInstalled -and (Test-Path $FarDir)) {
  & icacls $FarDir /grant "*S-1-15-2-1:(OI)(CI)RX" /T /C /Q | Out-Null
  Write-Ok 'AppContainer ACLs granted for Far'
}
if ($editInstalled -and (Test-Path $EditDir)) {
  & icacls $EditDir /grant "*S-1-15-2-1:(OI)(CI)RX" /T /C /Q | Out-Null
  Write-Ok 'AppContainer ACLs granted for Edit'
}

Write-Step '[4/4] Registering installed applications in apps.json and users.json...'
$AppsFile = Join-Path $InstallDir 'apps.json'
$UsersFile = Join-Path $InstallDir 'users.json'

if ($farInstalled) {
  if (Test-Path $AppsFile) {
    $AppsJson = Get-Content $AppsFile -Raw | ConvertFrom-Json
    foreach ($app in @($AppsJson.apps)) {
      if ($app.id -eq 'far') {
        Invoke-Manage @('delete-app', 'far') | Out-Null
      }
    }
  }
  Invoke-Manage @(
    'add-app',
    'far',
    'Far Manager',
    'Far\Far.exe',
    '--args=-title:Far,-s,%SANDBOX%\profile,%SANDBOX%\profile\local,%SANDBOX%,%SANDBOX%',
    '--cols=160',
    '--rows=38',
    '--sandbox=standard',
    '--roles=user,admin',
    '--no-network'
  ) | Out-Null
  Write-Ok 'Registered app: far (Far Manager)'

  if (Test-Path $UsersFile) {
    $UsersJson = Get-Content $UsersFile -Raw | ConvertFrom-Json
    $modified = $false
    foreach ($u in $UsersJson.users) {
      if ($u.apps -is [System.Array]) {
        if ($u.apps -notcontains '*' -and $u.apps -notcontains 'far') {
          $u.apps = @($u.apps) + 'far'
          $modified = $true
        }
      }
    }
    if ($modified) {
      ($UsersJson | ConvertTo-Json -Depth 10) | Set-Content -Path $UsersFile -Encoding UTF8
      Write-Ok 'Granted far to users in users.json'
    }
  }
} else {
  Write-Info 'Far Manager not installed; skipping registration.'
}

if ($editInstalled) {
  if (Test-Path $AppsFile) {
    $AppsJson = Get-Content $AppsFile -Raw | ConvertFrom-Json
    foreach ($app in @($AppsJson.apps)) {
      if ($app.id -eq 'edit') {
        Invoke-Manage @('delete-app', 'edit') | Out-Null
      }
    }
  }
  Invoke-Manage @(
    'add-app',
    'edit',
    'Microsoft Edit',
    'Edit\edit.exe',
    '--cols=120',
    '--rows=40',
    '--sandbox=standard',
    '--roles=user,admin',
    '--no-network'
  ) | Out-Null
  Write-Ok 'Registered app: edit (Microsoft Edit)'

  if (Test-Path $UsersFile) {
    $UsersJson = Get-Content $UsersFile -Raw | ConvertFrom-Json
    $modified = $false
    foreach ($u in $UsersJson.users) {
      if ($u.apps -is [System.Array]) {
        if ($u.apps -notcontains '*' -and $u.apps -notcontains 'edit') {
          $u.apps = @($u.apps) + 'edit'
          $modified = $true
        }
      }
    }
    if ($modified) {
      ($UsersJson | ConvertTo-Json -Depth 10) | Set-Content -Path $UsersFile -Encoding UTF8
      Write-Ok 'Granted edit to users in users.json'
    }
  }
} else {
  Write-Info 'Microsoft Edit not installed; skipping registration.'
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host ' Add-FarAndEdit.ps1 process completed.' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
