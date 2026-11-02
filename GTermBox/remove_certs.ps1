[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$SkipUserRoot
)

$ErrorActionPreference = 'Continue'

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$SubjectPattern = '^CN=(localhost|admin|usr\d+|mallory|GHttpsIOCP-DemoRootCA|Demo[A-Za-z]*Client|GTermBox[^,]*|\d{1,3}(\.\d{1,3}){3})(,|$)'
$ExcludedFriendlyNames = @('IIS Express Development Certificate', 'ASP.NET Core HTTPS development certificate')
$StoreNames = @('GHttpsIOCPSvr', 'My', 'Root', 'CA', 'TrustedPeople', 'ExpiredStore', 'TestExpiredStore', 'PyTestExpiredStore')

function Remove-CertificateKey([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    if (-not $Cert.HasPrivateKey) { return }
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        if ($rsa -is [System.Security.Cryptography.RSACng]) {
            $rsa.Key.Delete()
        } elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $rsa.PersistKeyInCsp = $false
            $rsa.Clear()
        }
    } catch {
    }
}

$Mode = 'REMOVING'
if ($VerifyOnly) { $Mode = 'VERIFYING' }

Write-Host '=========================================================================' -ForegroundColor Yellow
Write-Host "      $Mode GHttpsIOCPSvr / GTermBox CERTIFICATES" -ForegroundColor Yellow
Write-Host '=========================================================================' -ForegroundColor Yellow

$Removed = 0
$Failed = 0
$Remaining = 0

foreach ($Location in @('LocalMachine', 'CurrentUser')) {
    if ($Location -eq 'LocalMachine' -and -not $IsAdmin -and -not $VerifyOnly) {
        Write-Host 'Skipping LocalMachine stores (Administrator rights required).' -ForegroundColor DarkYellow
    }
    foreach ($StoreName in $StoreNames) {
        if ($Location -eq 'CurrentUser' -and $StoreName -eq 'Root' -and $SkipUserRoot) { continue }
        $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $Location)
        $Flags = [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
        if ($VerifyOnly -or ($Location -eq 'LocalMachine' -and -not $IsAdmin)) {
            $Flags = $Flags -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly
        } else {
            $Flags = $Flags -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
        }
        try { $Store.Open($Flags) } catch { continue }
        try {
            $Targets = @($Store.Certificates | Where-Object { $_.Subject -match $SubjectPattern -and $ExcludedFriendlyNames -notcontains $_.FriendlyName })
            foreach ($Cert in $Targets) {
                $Label = "{0}\{1} {2} [{3}] expires {4:yyyy-MM-dd}" -f $Location, $StoreName, $Cert.Subject, $Cert.Thumbprint, $Cert.NotAfter
                if ($VerifyOnly -or ($Location -eq 'LocalMachine' -and -not $IsAdmin)) {
                    Write-Host "  FOUND   $Label" -ForegroundColor Red
                    $Remaining++
                    continue
                }
                try {
                    $Store.Remove($Cert)
                    Remove-CertificateKey $Cert
                    Write-Host "  REMOVED $Label" -ForegroundColor Cyan
                    $Removed++
                } catch {
                    Write-Host "  FAILED  $Label : $($_.Exception.Message)" -ForegroundColor DarkYellow
                    $Failed++
                }
            }
        } finally {
            $Store.Close()
        }
    }
}

Write-Host '-------------------------------------------------------------------------' -ForegroundColor Yellow
if ($VerifyOnly) {
    if ($Remaining -eq 0) {
        Write-Host 'CLEAN: no project certificates found in any certificate store.' -ForegroundColor Green
        exit 0
    }
    Write-Host "NOT CLEAN: $Remaining project certificate(s) still present." -ForegroundColor Red
    exit 1
}
Write-Host "Removed: $Removed  Failed: $Failed" -ForegroundColor Green
Write-Host '=========================================================================' -ForegroundColor Yellow
if ($Failed -gt 0) { exit 1 }
exit 0
