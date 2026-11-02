Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr, Cert:\CurrentUser\GHttpsIOCPSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue

$notBefore = (Get-Date).AddDays(-1)
$notAfter  = (Get-Date).AddDays(13)

$cert = New-SelfSignedCertificate `
    -DnsName 'localhost','127.0.0.1' `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm ECDSA_nistP256 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -FriendlyName "GHttpsIOCPSvr"

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

try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyName = $ecdsaKey.Key.UniqueName
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\$keyName"
        if (Test-Path $keyPath) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'Read', 'Allow')
            $acl = Get-Acl $keyPath
            $acl.AddAccessRule($rule)
            Set-Acl $keyPath $acl
            & icacls.exe $keyPath /grant "*S-1-1-0:(R)" /Q | Out-Null
            Write-Host "Granted Read permission for private key file: $keyPath"
        }
    }
} catch {
    Write-Host "Key ACL info: $($_.Exception.Message)"
}

Write-Host "New CNG W3C WebTransport certificate generated and ready in GHttpsIOCPSvr store"
Write-Host "Thumbprint: $($cert.Thumbprint)"
