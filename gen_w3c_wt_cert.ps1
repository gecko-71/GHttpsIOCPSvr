# ==============================================================================
# Script generating ECDSA P-256 certificate 100% compliant with W3C WebTransport
# specification (Section 3.3 serverCertificateHashes).
#
# W3C Specification Requirements:
# 1. Key Algorithm: ECDSA P-256 (secp256r1) - RSA is explicitly forbidden by W3C!
# 2. Validity Period: MUST NOT EXCEED 14 DAYS (2 weeks)!
# 3. Hash Algorithm: SHA-256
#
# NOTE: Must be executed in PowerShell as Administrator!
# This script ONLY generates the certificate and configures key store permissions.
# It does NOT modify any project source files.
# ==============================================================================

Write-Host "--- Generating W3C WebTransport Certificate (ECDSA P-256, 14 days) ---" -ForegroundColor Cyan

# 1. Clean up old GHttpsIOCPSvr certificates
Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# 2. Create new ECDSA P-256 certificate valid for exactly 14 days
$notBefore = (Get-Date).AddDays(-1)
$notAfter  = (Get-Date).AddDays(13)

$cert = New-SelfSignedCertificate `
    -DnsName 'localhost', '127.0.0.1' `
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

# 3. Copy certificate to LocalMachine\GHttpsIOCPSvr store
$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store('GHttpsIOCPSvr', 'LocalMachine')
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

# 4. Grant read permissions on CNG private key file to Everyone using universal SID (S-1-1-0)
try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\" + $ecdsaKey.Key.UniqueName
        if (Test-Path $keyPath) {
            # Use language-neutral Well-Known SID S-1-1-0 (Everyone / Wszyscy)
            $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'Read', 'Allow')
            $acl = Get-Acl -Path $keyPath
            $acl.AddAccessRule($rule)
            Set-Acl -Path $keyPath -AclObject $acl
            & icacls.exe $keyPath /grant "*S-1-1-0:(R)" | Out-Null
            Write-Host "CNG private key permissions successfully configured (Everyone / S-1-1-0)." -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Key ACL configuration note: $_"
}

# 5. Compute SHA-256 hash of the DER raw certificate
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
