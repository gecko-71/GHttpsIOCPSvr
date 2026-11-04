[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$Username,

  [Parameter(Position = 1)]
  [string]$Password,

  [switch]$Admin,

  [switch]$Restricted,

  [switch]$NoUpload,

  [switch]$NoDownload,

  [switch]$PowerShellOutsideSandbox,

  [switch]$NoPowerShellOutsideSandbox,

  [string]$Upload = '',

  [string]$Download = '',

  [ValidateSet('user', 'admin', '')]
  [string]$Role = '',

  [string]$Sandbox = '',

  [string]$Apps = '',

  [string]$Network = '',

  [string]$AllowJobOnly = '',

  [string]$FullDisk = '',

  [string]$DirsRead = '',

  [string]$DirsWrite = '',

  [string]$Cert = '',

  [switch]$Interactive
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path (Join-Path $ScriptDir "Win64\Debug\ManageUsers.exe")) {
  $ServerDir = Join-Path $ScriptDir "Win64\Debug"
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path (Get-Location) "ManageUsers.exe")) {
  $ServerDir = (Get-Location).Path
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path $ScriptDir "ManageUsers.exe")) {
  $ServerDir = $ScriptDir
  $ManageUsersExe = Join-Path $ScriptDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path (Get-Location) "GTermBox\Win64\Debug\ManageUsers.exe")) {
  $ServerDir = Join-Path (Get-Location).Path "GTermBox\Win64\Debug"
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} else {
  Write-Error "ManageUsers.exe not found. Please compile the project first."
  exit 1
}

if ($Admin) {
  $Role = 'admin'
} elseif ($Restricted) {
  $Role = 'user'
}

if ($Interactive -or [string]::IsNullOrWhiteSpace($Username)) {
  Write-Host "==========================================" -ForegroundColor Cyan
  Write-Host "        GTermBox User Setup Wizard        " -ForegroundColor Cyan
  Write-Host "==========================================" -ForegroundColor Cyan

  if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host "Enter Username (no spaces or slashes)"
    $Username = $Username.Trim()
  }

  if ([string]::IsNullOrWhiteSpace($Password)) {
    $Password = Read-Host "Enter Password (minimum 4 characters)"
  }

  if ([string]::IsNullOrWhiteSpace($Role)) {
    $roleInput = Read-Host "Select User Role [1: regular user, 2: administrator] (default: 1)"
    if ($roleInput -eq '2' -or $roleInput -match '(?i)admin') {
      $Role = 'admin'
    } else {
      $Role = 'user'
    }
  }

  if ($Role -eq 'user') {
    $restrInput = Read-Host "Configure as fully restricted user? [Y/N] (default: Y)"
    if ($restrInput -notmatch '^[Nn]') {
      $Restricted = $true
    }
  }

  if ([string]::IsNullOrWhiteSpace($Sandbox)) {
    $sbPrompt = Read-Host "Enter Sandbox folder name (default: sandbox_$Username)"
    if (-not [string]::IsNullOrWhiteSpace($sbPrompt)) {
      $Sandbox = $sbPrompt.Trim()
    }
  }
}

if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Password)) {
  Write-Error "Username and Password are required."
  exit 1
}

if ([string]::IsNullOrWhiteSpace($Role)) {
  $Role = 'user'
}

if ([string]::IsNullOrWhiteSpace($Sandbox)) {
  $Sandbox = "sandbox_$Username"
}

function Parse-Bool([string]$val, [bool]$defaultVal) {
  if ([string]::IsNullOrWhiteSpace($val)) { return $defaultVal }
  if ($val -match '^(false|0|no|n|\$false)$') { return $false }
  return $true
}

if ($Role -eq 'admin') {
  if ([string]::IsNullOrWhiteSpace($Apps)) { $Apps = '*' }
  $bNetwork = Parse-Bool $Network $true
  $bAllowJobOnly = Parse-Bool $AllowJobOnly $true
  $bFullDisk = Parse-Bool $FullDisk $true
  if ([string]::IsNullOrWhiteSpace($DirsRead)) { $DirsRead = '*' }
  if ([string]::IsNullOrWhiteSpace($DirsWrite)) { $DirsWrite = '*' }
} else {
  if ([string]::IsNullOrWhiteSpace($Apps)) {
    $AppsJsonFile = Join-Path $ServerDir "apps.json"
    if (Test-Path $AppsJsonFile) {
      try {
        $aData = Get-Content $AppsJsonFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $Apps = ($aData.apps | Where-Object {
          -not $_.roles -or $_.roles.Count -eq 0 -or $_.roles -contains $Role -or $_.roles -contains '*'
        } | ForEach-Object { $_.id }) -join ','
        if ([string]::IsNullOrWhiteSpace($Apps)) {
          $Apps = 'powershell'
        }
      } catch {
        $Apps = 'powershell'
      }
    } else {
      $Apps = 'powershell'
    }
  }
  if ($Restricted) {
    $bNetwork = Parse-Bool $Network $false
    $bAllowJobOnly = Parse-Bool $AllowJobOnly $false
    $bFullDisk = Parse-Bool $FullDisk $false
    if ([string]::IsNullOrWhiteSpace($DirsRead)) { $DirsRead = 'AppData,Documents,tmp,profile,apps' }
    if ([string]::IsNullOrWhiteSpace($DirsWrite)) { $DirsWrite = 'AppData,Documents,tmp,profile,apps' }
  } else {
    $bNetwork = Parse-Bool $Network $true
    $bAllowJobOnly = Parse-Bool $AllowJobOnly $false
    $bFullDisk = Parse-Bool $FullDisk $false
  }
}

$targetDirs = @()
$targetDirs += (Join-Path $ServerDir $Sandbox)
if ($ScriptDir -ne $ServerDir) {
  $targetDirs += (Join-Path $ScriptDir $Sandbox)
}

foreach ($FullSandbox in $targetDirs) {
  Write-Host "Initializing sandbox directory on disk: $FullSandbox" -ForegroundColor Cyan
  $subdirs = @('AppData', 'AppData\Local', 'AppData\Roaming', 'Documents', 'tmp', 'profile', 'profile\local', 'profile\Macros\scripts', 'apps')
  foreach ($sub in $subdirs) {
    $p = Join-Path $FullSandbox $sub
    if (-not (Test-Path $p)) {
      New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
  }

  $psProfileContent = "`$env:TMP = Join-Path `$PSScriptRoot '..\..\tmp'`r`n`$env:TEMP = `$env:TMP`r`n"
  $psDocDirs = @(
    (Join-Path $FullSandbox "Documents\PowerShell"),
    (Join-Path $FullSandbox "Documents\WindowsPowerShell")
  )
  foreach ($pdir in $psDocDirs) {
    if (-not (Test-Path $pdir)) {
      New-Item -ItemType Directory -Path $pdir -Force | Out-Null
    }
    $profFile = Join-Path $pdir "Microsoft.PowerShell_profile.ps1"
    if (-not (Test-Path $profFile)) {
      [System.IO.File]::WriteAllText($profFile, $psProfileContent, [System.Text.Encoding]::UTF8)
    }
  }
  & icacls $FullSandbox /grant "*S-1-5-11:(OI)(CI)F" /T /C /Q | Out-Null
}

$cliArgs = @(
  "add",
  $Username,
  $Password,
  "--role=$Role",
  "--sandbox=$Sandbox",
  "--apps=$Apps"
)

if ($bNetwork) { $cliArgs += "--network" } else { $cliArgs += "--no-network" }
if ($bAllowJobOnly) { $cliArgs += "--allow-job-only" } else { $cliArgs += "--no-job-only" }
if ($bFullDisk) { $cliArgs += "--full-disk" } else { $cliArgs += "--no-full-disk" }

if ($NoUpload -or (Parse-Bool $Upload $true) -eq $false) {
  $cliArgs += "--no-upload"
} else {
  $cliArgs += "--upload"
}

if ($NoDownload -or (Parse-Bool $Download $true) -eq $false) {
  $cliArgs += "--no-download"
} else {
  $cliArgs += "--download"
}

if ($PowerShellOutsideSandbox -or ($Role -eq 'admin' -and -not $NoPowerShellOutsideSandbox)) {
  $cliArgs += "--powershell-outside-sandbox"
} else {
  $cliArgs += "--no-powershell-outside-sandbox"
}

if (-not [string]::IsNullOrWhiteSpace($DirsRead)) {
  $cliArgs += "--dirs-read=$DirsRead"
}
if (-not [string]::IsNullOrWhiteSpace($DirsWrite)) {
  $cliArgs += "--dirs-write=$DirsWrite"
}
if (-not [string]::IsNullOrWhiteSpace($Cert)) {
  $cliArgs += "--cert=$Cert"
}

Write-Host "Registering user '$Username' (Role: $Role) in $ServerDir..." -ForegroundColor Yellow
Push-Location $ServerDir
try {
  & $ManageUsersExe @cliArgs
  $exitCode = $LASTEXITCODE
  if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "[SUCCESS] User '$Username' has been successfully created and sandbox prepared!" -ForegroundColor Green
    & $ManageUsersExe "show" $Username
  }
} finally {
  Pop-Location
}

if ($exitCode -eq 0) {
  exit 0
} else {
  Write-Error "Failed to create user '$Username' (Exit code: $exitCode)."
  exit $exitCode
}
