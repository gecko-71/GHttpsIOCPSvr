$detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -ExpandProperty IPAddress)

$dnsNames = @('localhost', '127.0.0.1') 
if ($detectedIps) { $dnsNames += $detectedIps }
$dnsNames = @($dnsNames | Select-Object -Unique)

Get-ChildItem Cert:\LocalMachine\GHttpsIOCPSvr, Cert:\CurrentUser\GHttpsIOCPSvr -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GHttpsIOCPSvr" } |
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

$destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GHttpsIOCPSvr", "LocalMachine")
$destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreLM.Add($cert)
$destStoreLM.Close()

try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
        $keyName = $ecdsaKey.Key.UniqueName
        $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\$keyName"
        if (Test-Path $keyPath) {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            & icacls.exe $keyPath /remove "*S-1-1-0" /Q | Out-Null
            & icacls.exe $keyPath /grant "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" "*$($currentUser.Value):(R)" /Q | Out-Null
            $acl = Get-Acl -Path $keyPath
            $rulesToRemove = @($acl.Access | Where-Object { $_.IdentityReference.Value -match 'S-1-1-0|Everyone|Wszyscy' })
            foreach ($r in $rulesToRemove) {
                [void]$acl.RemoveAccessRule($r)
            }
            $sidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $sidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSystem, 'Read', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdmins, 'Read', 'Allow')))
            if ($currentUser) {
                $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'Read', 'Allow')))
            }
            Set-Acl -Path $keyPath -AclObject $acl
            Write-Host "Granted restricted Read permission for private key file: $keyPath"
        }
    }
} catch {
    Write-Host "Key ACL info: $($_.Exception.Message)"
}

Write-Host "New CNG W3C WebTransport certificate generated and ready in GHttpsIOCPSvr store"
Write-Host "Thumbprint: $($cert.Thumbprint)"
