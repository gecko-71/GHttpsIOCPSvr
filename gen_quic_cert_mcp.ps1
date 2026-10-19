$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Get-ChildItem Cert:\CurrentUser\GMcpSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GMcpSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue
if ($isAdmin) {
    Get-ChildItem Cert:\LocalMachine\GMcpSvr -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like "*CN=localhost*" -or $_.FriendlyName -eq "GMcpSvr" } | Remove-Item -Force -ErrorAction SilentlyContinue
}

$baseStore = if ($isAdmin) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }

$cert = New-SelfSignedCertificate `
    -DnsName 'localhost', '127.0.0.1' `
    -CertStoreLocation $baseStore `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2') `
    -NotAfter (Get-Date).AddYears(5) `
    -FriendlyName "GMcpSvr"

if (-not $cert) {
    Write-Error "Failed to generate certificate."
    Exit 1
}

$destStoreCU = New-Object System.Security.Cryptography.X509Certificates.X509Store("GMcpSvr", "CurrentUser")
$destStoreCU.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$destStoreCU.Add($cert)
$destStoreCU.Close()

if ($isAdmin) {
    try {
        $destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store("GMcpSvr", "LocalMachine")
        $destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $destStoreLM.Add($cert)
        $destStoreLM.Close()
    } catch {}
}

try {
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsaKey -and $rsaKey.Key) {
        $keyName = $rsaKey.Key.UniqueName
        $keyPaths = @(
            "$env:ProgramData\Microsoft\Crypto\Keys\$keyName",
            "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyName",
            "$env:APPDATA\Microsoft\Crypto\Keys\$keyName",
            "$env:APPDATA\Microsoft\Crypto\RSA\$keyName"
        )
        foreach ($kp in $keyPaths) {
            if (Test-Path $kp) {
                $acl = Get-Acl $kp
                $sidUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)
                $ruleUsers = New-Object System.Security.AccessControl.FileSystemAccessRule($sidUsers, "Read", "Allow")
                $acl.AddAccessRule($ruleUsers)
                $sidEveryone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
                $ruleEveryone = New-Object System.Security.AccessControl.FileSystemAccessRule($sidEveryone, "Read", "Allow")
                $acl.AddAccessRule($ruleEveryone)
                Set-Acl $kp $acl
                & icacls.exe $kp /grant "*S-1-1-0:(R)" | Out-Null
            }
        }
    }
} catch {
    Write-Warning "Key ACL configuration note: $_"
}

Write-Host "New CNG MCP certificate generated successfully." -ForegroundColor Green
Write-Host "Store Name:  GMcpSvr" -ForegroundColor Cyan
Write-Host "Subject:     $($cert.Subject)" -ForegroundColor Cyan
Write-Host "Thumbprint:  $($cert.Thumbprint)" -ForegroundColor Yellow
Write-Host "Valid Until: $($cert.NotAfter)" -ForegroundColor Green
