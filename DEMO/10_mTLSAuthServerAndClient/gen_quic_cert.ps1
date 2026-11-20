param(
    [string]$ServerDir = "",
    [string]$ClientDir = "",
    [string]$Password = "1234",
    [switch]$InstallLocalhostCert,
    [string]$TlsProvider = $env:GHTTPS_TLS_PROVIDER
)

$scriptPath = Join-Path $PSScriptRoot "gen_mtls_certs.ps1"
if (Test-Path $scriptPath) {
    $callArgs = @{
        ServerDir = $ServerDir
        ClientDir = $ClientDir
        Password = $Password
        InstallLocalhostCert = $InstallLocalhostCert
    }
    if (-not [string]::IsNullOrWhiteSpace($TlsProvider)) {
        $callArgs["TlsProvider"] = $TlsProvider
    }
    & $scriptPath @callArgs
} else {
    Write-Error "gen_mtls_certs.ps1 not found in $PSScriptRoot"
}
