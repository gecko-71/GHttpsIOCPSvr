[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Username = "usr1",

    [Parameter(Position = 1)]
    [string]$Password = "",

    [Parameter(Position = 2)]
    [string]$PfxPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $Password) {
    switch ($Username) {
        "usr1" { $Password = "PasswordUsr1!" }
        "usr2" { $Password = "PasswordUsr2!" }
        "usr3" { $Password = "PasswordUsr3!" }
        "admin" { $Password = "PasswordAdmin!" }
        "mallory" { $Password = "PasswordMallory!" }
        default { $Password = "Password$Username!" }
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $PfxPath) {
    $Candidates = @(
        (Join-Path $ScriptDir "$Username.pfx"),
        (Join-Path $ScriptDir "client_keys\$Username.pfx"),
        (Join-Path $ScriptDir "Win64\Debug\$Username.pfx"),
        (Join-Path $ScriptDir "Win64\Debug\client_keys\$Username.pfx"),
        (Join-Path (Get-Location) "$Username.pfx"),
        (Join-Path (Get-Location) "client_keys\$Username.pfx"),
        (Join-Path (Get-Location) "GTermBox\Win64\Debug\$Username.pfx"),
        (Join-Path (Get-Location) "GTermBox\Win64\Debug\client_keys\$Username.pfx")
    )
    foreach ($Cand in $Candidates) {
        if (Test-Path $Cand) {
            $PfxPath = (Resolve-Path $Cand).Path
            break
        }
    }
}

if (-not $PfxPath -or -not (Test-Path $PfxPath)) {
    Write-Error "Certificate PFX file not found for user: $Username"
    exit 1
}

Write-Host "Installing client certificate for user '$Username'..." -ForegroundColor Cyan
Write-Host "PFX Path: $PfxPath" -ForegroundColor DarkGray

$Process = Start-Process -FilePath "certutil.exe" -ArgumentList "-user -p `"$Password`" -importpfx `"$PfxPath`" NoRoot" -NoNewWindow -Wait -PassThru

if ($Process.ExitCode -eq 0) {
    Write-Host "Certificate '$Username.pfx' imported successfully into Windows CurrentUser Personal store." -ForegroundColor Green
    Write-Host "Chrome, Edge, and Windows applications will now offer this certificate for mTLS authentication." -ForegroundColor Green
} else {
    Write-Error "certutil failed with exit code $($Process.ExitCode)"
    exit $Process.ExitCode
}
