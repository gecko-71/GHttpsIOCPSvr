[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$AppId,

  [Parameter(Position = 1)]
  [string]$AppName,

  [Parameter(Position = 2)]
  [string]$Command,

  [string]$Args = '',

  [string]$WorkingDir = '%SANDBOX%',

  [ValidateSet('standard', 'job-only', 'jobonly', 'none', '')]
  [string]$Sandbox = 'standard',

  [string]$Network = '',

  [string]$Roles = 'user,admin',

  [int]$Cols = 120,

  [int]$Rows = 30,

  [string]$Env = 'TERM=xterm-256color,COLORTERM=truecolor',

  [string]$DirsRead = '',

  [string]$DirsWrite = '',

  [switch]$UpdateUsers,

  [switch]$Interactive
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (Test-Path (Join-Path $ScriptDir "ManageUsers.exe")) {
  $ServerDir = $ScriptDir
  $ManageUsersExe = Join-Path $ScriptDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path $ScriptDir "Win64\Debug\ManageUsers.exe")) {
  $ServerDir = Join-Path $ScriptDir "Win64\Debug"
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path (Get-Location) "Win64\Debug\ManageUsers.exe")) {
  $ServerDir = Join-Path (Get-Location).Path "Win64\Debug"
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path (Get-Location) "ManageUsers.exe")) {
  $ServerDir = (Get-Location).Path
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} elseif (Test-Path (Join-Path (Get-Location) "GTermBox\Win64\Debug\ManageUsers.exe")) {
  $ServerDir = Join-Path (Get-Location).Path "GTermBox\Win64\Debug"
  $ManageUsersExe = Join-Path $ServerDir "ManageUsers.exe"
} else {
  Write-Error "ManageUsers.exe not found. Please compile the project first."
  exit 1
}

if ($Interactive -or [string]::IsNullOrWhiteSpace($AppId)) {
  Write-Host "==========================================" -ForegroundColor Cyan
  Write-Host "    GTermBox Application Setup Wizard     " -ForegroundColor Cyan
  Write-Host "==========================================" -ForegroundColor Cyan

  if ([string]::IsNullOrWhiteSpace($AppId)) {
    $AppId = Read-Host "Enter Application ID (e.g. far, python, my-tool)"
    $AppId = $AppId.Trim().ToLower()
  }

  if ([string]::IsNullOrWhiteSpace($AppName)) {
    $AppName = Read-Host "Enter Application Display Name (default: $AppId)"
    if ([string]::IsNullOrWhiteSpace($AppName)) { $AppName = $AppId }
  }

  if ([string]::IsNullOrWhiteSpace($Command)) {
    $Command = Read-Host "Enter Command/Executable (e.g. powershell.exe, C:\tools\app.exe)"
  }

  $inputSandbox = Read-Host "Enter Sandbox mode [standard / jobonly / none] (default: standard)"
  if (-not [string]::IsNullOrWhiteSpace($inputSandbox)) {
    $Sandbox = $inputSandbox.Trim().ToLower()
  }

  $inputNet = Read-Host "Enable network access? [Y/N] (default: Y)"
  if ($inputNet -match '^[Nn]') {
    $Network = $false
  } else {
    $Network = $true
  }

  $inputRoles = Read-Host "Enter allowed roles comma-separated (default: user,admin)"
  if (-not [string]::IsNullOrWhiteSpace($inputRoles)) {
    $Roles = $inputRoles.Trim()
  }

  if (-not $UpdateUsers) {
    $syncChoice = Read-Host "Grant this application to existing users with matching roles in users.json? [Y/N] (default: Y)"
    if ($syncChoice -notmatch '^[Nn]') {
      $UpdateUsers = $true
    }
  }
}

if ([string]::IsNullOrWhiteSpace($AppId) -or [string]::IsNullOrWhiteSpace($Command)) {
  Write-Error "Application ID and Command are required."
  exit 1
}

$cmdTrimmed = $Command.Trim().Trim('"')
$cmdResolved = $false
if (Test-Path $cmdTrimmed) {
  $cmdResolved = $true
} elseif (Test-Path (Join-Path $ServerDir $cmdTrimmed)) {
  $cmdResolved = $true
} elseif (Get-Command $cmdTrimmed -ErrorAction SilentlyContinue) {
  $cmdResolved = $true
}
if (-not $cmdResolved) {
  Write-Host "[WARNING] Application command '$cmdTrimmed' was not found on PATH or in server directory." -ForegroundColor Yellow
}

if ([string]::IsNullOrWhiteSpace($AppName)) {
  $AppName = $AppId
}

$isNetEnabled = $true
if (-not [string]::IsNullOrWhiteSpace($Network)) {
  if ($Network -match '^(false|0|no|n|\$false)$') {
    $isNetEnabled = $false
  } else {
    $isNetEnabled = $true
  }
}

if ($Sandbox -eq 'jobonly') {
  $Sandbox = 'job-only'
}

$cliArgs = @(
  "add-app",
  $AppId,
  $AppName,
  $Command,
  "--sandbox=$Sandbox",
  "--roles=$Roles",
  "--working-dir=$WorkingDir",
  "--cols=$Cols",
  "--rows=$Rows"
)

if (-not [string]::IsNullOrWhiteSpace($Args)) {
  $cliArgs += "--args=$Args"
}

if (-not [string]::IsNullOrWhiteSpace($Env)) {
  $cliArgs += "--env=$Env"
}

if (-not [string]::IsNullOrWhiteSpace($DirsRead)) {
  $cliArgs += "--dirs-read=$DirsRead"
}

if (-not [string]::IsNullOrWhiteSpace($DirsWrite)) {
  $cliArgs += "--dirs-write=$DirsWrite"
}

if ($isNetEnabled) {
  $cliArgs += "--network"
} else {
  $cliArgs += "--no-network"
}

Write-Host "Registering application '$AppId' in $ServerDir..." -ForegroundColor Yellow
Push-Location $ServerDir
try {
  & $ManageUsersExe @cliArgs
  $exitCode = $LASTEXITCODE
  if ($exitCode -eq 0) {
    $targetAclDirs = @()
    $localAppDir = Join-Path $ServerDir $AppId
    if (Test-Path $localAppDir) {
      $targetAclDirs += $localAppDir
    }
    if (Test-Path $cmdTrimmed) {
      $parentOfCmd = Split-Path -Parent (Resolve-Path $cmdTrimmed).Path
      if ($parentOfCmd -and (Test-Path $parentOfCmd) -and -not ($parentOfCmd -like "C:\Windows*")) {
        $targetAclDirs += $parentOfCmd
      }
    } elseif (Test-Path (Join-Path $ServerDir $cmdTrimmed)) {
      $parentOfCmd = Split-Path -Parent (Join-Path $ServerDir $cmdTrimmed)
      if ($parentOfCmd -and (Test-Path $parentOfCmd)) {
        $targetAclDirs += $parentOfCmd
      }
    }
    foreach ($aclDir in ($targetAclDirs | Select-Object -Unique)) {
      & icacls $aclDir /grant "*S-1-15-2-1:(OI)(CI)RX" /T /C /Q | Out-Null
    }

    if ($UpdateUsers) {
      $UsersJsonPath = Join-Path $ServerDir "users.json"
      if (Test-Path $UsersJsonPath) {
        try {
          $uData = Get-Content $UsersJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
          $appRoles = $Roles -split ',' | ForEach-Object { $_.Trim().ToLower() }
          $updatedCount = 0
          foreach ($u in $uData.users) {
            $userRole = if ($u.role) { $u.role.ToLower() } else { 'user' }
            $matchesRole = ($appRoles -contains '*' -or $appRoles -contains $userRole)
            if ($matchesRole) {
              if ($u.apps -is [System.Collections.IEnumerable] -and -not ($u.apps -contains '*')) {
                if (-not ($u.apps -contains $AppId)) {
                  $u.apps = @($u.apps) + $AppId
                  $updatedCount++
                }
              }
            }
          }
          if ($updatedCount -gt 0) {
            $uData | ConvertTo-Json -Depth 10 | Set-Content $UsersJsonPath -Encoding UTF8
            Write-Host "[+] Granted '$AppId' to $updatedCount matching existing user(s) in users.json" -ForegroundColor Green
          }
        } catch {
          Write-Host "[WARNING] Could not update users.json: $_" -ForegroundColor Yellow
        }
      }
    }

    Write-Host ""
    Write-Host "[SUCCESS] Application '$AppId' has been successfully configured!" -ForegroundColor Green
    & $ManageUsersExe "show-app" $AppId
  }
} finally {
  Pop-Location
}

if ($exitCode -eq 0) {
  exit 0
} else {
  Write-Error "Failed to register application '$AppId' (Exit code: $exitCode)."
  exit $exitCode
}
