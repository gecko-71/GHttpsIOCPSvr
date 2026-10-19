param(
    [string]$ServerDir = "",
    [string]$ClientDir = "",
    [string]$Password = "1234",
    [switch]$InstallLocalhostCert
)

$scriptPath = Join-Path $PSScriptRoot "gen_mtls_certs.ps1"
if (Test-Path $scriptPath) {
    & $scriptPath -ServerDir $ServerDir -ClientDir $ClientDir -Password $Password -InstallLocalhostCert:$InstallLocalhostCert
} else {
    Write-Error "gen_mtls_certs.ps1 not found in $PSScriptRoot"
}
