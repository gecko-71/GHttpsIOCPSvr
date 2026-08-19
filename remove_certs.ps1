# Script removing all certificates associated with GHttpsIOCPSvr / localhost

Write-Host '=========================================================================' -ForegroundColor Yellow
Write-Host '      REMOVING GHttpsIOCPSvr CERTIFICATES                                ' -ForegroundColor Yellow
Write-Host '=========================================================================' -ForegroundColor Yellow

$stores = @(
    "Cert:\LocalMachine\GHttpsIOCPSvr",
    "Cert:\CurrentUser\GHttpsIOCPSvr",
    "Cert:\LocalMachine\My"
)

$count = 0
foreach ($storePath in $stores) {
    if (Test-Path $storePath) {
        $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue | Where-Object { 
            $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" 
        }
        foreach ($c in $certs) {
            Write-Host "Removing certificate: $($c.Subject) [Thumbprint: $($c.Thumbprint)] from $storePath" -ForegroundColor Cyan
            Remove-Item -Path $c.PSPath -Force -ErrorAction SilentlyContinue
            $count++
        }
    }
}

Write-Host '-------------------------------------------------------------------------' -ForegroundColor Yellow
Write-Host "Operation completed successfully. Total certificates removed: $count" -ForegroundColor Green
Write-Host '=========================================================================' -ForegroundColor Yellow
