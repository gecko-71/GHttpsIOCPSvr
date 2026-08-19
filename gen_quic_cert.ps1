# Generate CNG certificate in Cert:\LocalMachine\GHttpsIOCPSvr and Cert:\CurrentUser\GHttpsIOCPSvr (without using CurrentUser\My)
# Requires running PowerShell as Administrator

Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr, Cert:\CurrentUser\GHttpsIOCPSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue

$cert = New-SelfSignedCertificate `
    -DnsName 'localhost','127.0.0.1' `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature,KeyEncipherment `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
    -NotAfter (Get-Date).AddYears(5) `
    -FriendlyName "GHttpsIOCPSvr"

# Copy to GHttpsIOCPSvr stores in LocalMachine and CurrentUser
$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "LocalMachine")
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

try {
    $destStoreCU = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "CurrentUser")
    $destStoreCU.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $destStoreCU.Add($cert)
    $destStoreCU.Close()
} catch {}

# Grant Read permissions for the CNG private key file for the BuiltinUsersSid group
try {
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsaKey -and $rsaKey.Key) {
        $keyName = $rsaKey.Key.UniqueName
        $keyPaths = @(
            "$env:ProgramData\Microsoft\Crypto\Keys\$keyName",
            "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyName"
        )
        foreach ($kp in $keyPaths) {
            if (Test-Path $kp) {
                $acl = Get-Acl $kp
                $sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, "Read", "Allow")
                $acl.AddAccessRule($rule)
                Set-Acl $kp $acl
                Write-Host "Granted Read permission for private key file: $kp"
            }
        }
    }
} catch {
    Write-Host "Key ACL info: $($_.Exception.Message)"
}

Write-Host "New CNG certificate generated and ready in GHttpsIOCPSvr store"
Write-Host "Thumbprint: $($cert.Thumbprint)"
