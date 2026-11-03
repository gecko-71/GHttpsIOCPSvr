param(
    [string]$ServerIp = $env:TEST_SERVER_BIND_IP
)

Write-Host "--- Generating W3C WebTransport Certificate (ECDSA P-256, 14 days) ---" -ForegroundColor Cyan

$detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -ExpandProperty IPAddress)

$dnsNames = @('localhost', '127.0.0.1')
if ($detectedIps) { $dnsNames += $detectedIps }
if ($ServerIp) { $dnsNames += $ServerIp }
$dnsNames = @($dnsNames | Select-Object -Unique)
$primaryIp = if ($ServerIp) { $ServerIp } elseif ($detectedIps.Count -gt 0) { $detectedIps[0] } else { '127.0.0.1' }

Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*CN=$primaryIp*" -or $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } |
    Remove-Item -Force -ErrorAction SilentlyContinue

$notBefore = (Get-Date).AddDays(-1)
$notAfter  = (Get-Date).AddDays(13)

$cert = New-SelfSignedCertificate `
    -DnsName $dnsNames `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm ECDSA_nistP256 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -FriendlyName "GHttpsIOCPSvr"

if (-not $cert) {
    Write-Error "Failed to generate certificate. Ensure PowerShell is running as Administrator."
    Exit 1
}

$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store('GHttpsIOCPSvr', 'LocalMachine')
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\" + $ecdsaKey.Key.UniqueName
        if (Test-Path $keyPath) {
            & icacls.exe $keyPath /remove "*S-1-1-0" | Out-Null
            & icacls.exe $keyPath /grant "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null
            $acl = Get-Acl -Path $keyPath
            $rulesToRemove = @($acl.Access | Where-Object { $_.IdentityReference.Value -match 'S-1-1-0|Everyone|Wszyscy' })
            foreach ($r in $rulesToRemove) {
                [void]$acl.RemoveAccessRule($r)
            }
            $sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, 'Read', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmins, 'Read', 'Allow')))
            Set-Acl -Path $keyPath -AclObject $acl
            Write-Host "CNG private key permissions successfully configured (SYSTEM and Administrators only)." -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Key ACL configuration note: $_"
}

$sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
$hashArrayStr = '[' + (($sha256 | ForEach-Object { $_.ToString() }) -join ', ') + ']'
$hashHexStr = [System.BitConverter]::ToString($sha256).Replace('-', '')

Write-Host "`nSuccess! Certificate generated in compliance with W3C WebTransport:" -ForegroundColor Green
Write-Host "Thumbprint (SHA-1): " $cert.Thumbprint -ForegroundColor Yellow
Write-Host "Valid from:         " $cert.NotBefore
Write-Host "Valid to:           " $cert.NotAfter
Write-Host "Algorithm:          ECDSA P-256 (secp256r1) [W3C Compliant]" -ForegroundColor Cyan
Write-Host "SHA-256 Hex:        " $hashHexStr -ForegroundColor Cyan
Write-Host "SHA-256 Array:      " $hashArrayStr -ForegroundColor Cyan
Write-Host "`nCertificate is installed in Cert:\LocalMachine\GHttpsIOCPSvr." -ForegroundColor Green
