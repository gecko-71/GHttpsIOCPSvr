[CmdletBinding()]
param(
  [string]$BindIp = '',
  [int]$Port = 8443,
  [string]$Password = '',
  [string]$AssetsDir = '',
  [string]$InstallDir = '',
  [switch]$SkipFirewall,
  [switch]$SkipSelfTest,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
  $InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}
$InstallDir = (Resolve-Path $InstallDir).Path

if ([string]::IsNullOrWhiteSpace($Password)) {
  $rngBytes = New-Object byte[] 16
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $rng.GetBytes($rngBytes)
  $Password = [System.Convert]::ToBase64String($rngBytes).Replace('+', 'A').Replace('/', 'B').TrimEnd('=') + '!9a'
  Write-Host "==========================================================" -ForegroundColor Yellow
  Write-Host " GENERATED SECURE ADMIN PASSWORD: $Password" -ForegroundColor Green
  Write-Host " Store this password securely! You must change it on first login." -ForegroundColor Yellow
  Write-Host "==========================================================" -ForegroundColor Yellow
}

function Write-Step([string]$Text) { Write-Host ''; Write-Host $Text -ForegroundColor Yellow }
function Write-Ok([string]$Text) { Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "  [=] $Text" -ForegroundColor DarkGray }
function Write-Warn([string]$Text) { Write-Host "  [!] $Text" -ForegroundColor DarkYellow }
function Stop-Install([string]$Text) { Write-Host "  [X] $Text" -ForegroundColor Red; exit 1 }

function Invoke-Manage {
  param([string[]]$Arguments)
  Push-Location $InstallDir
  try {
    $output = & $script:ManageExe @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Stop-Install ("ManageUsers {0} failed: {1}" -f ($Arguments -join ' '), $output.Trim()) }
    return $output
  } finally {
    Pop-Location
  }
}

function Invoke-HttpJson {
  param(
    [string]$Url,
    [string]$Method = 'GET',
    [string]$Body = $null,
    [string]$BearerToken = $null
  )
  $uri = New-Object System.Uri($Url)
  $tcp = New-Object System.Net.Sockets.TcpClient
  $tcp.Connect($uri.Host, $uri.Port)
  $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
  $ssl.AuthenticateAsClient($uri.Host)
  
  $pathAndQuery = $uri.PathAndQuery
  $reqText = "$Method $pathAndQuery HTTP/1.1`r`nHost: $($uri.Host)`r`nConnection: close`r`n"
  if ($BearerToken) {
    $reqText += "Authorization: Bearer $BearerToken`r`n"
  }
  if ($Body) {
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $reqText += "Content-Type: application/json`r`nContent-Length: $($bodyBytes.Length)`r`n`r`n"
  } else {
    $reqText += "`r`n"
  }
  
  $writer = New-Object System.IO.StreamWriter($ssl, [System.Text.Encoding]::ASCII)
  $writer.Write($reqText)
  $writer.Flush()
  if ($Body) {
    $ssl.Write($bodyBytes, 0, $bodyBytes.Length)
    $ssl.Flush()
  }
  
  $reader = New-Object System.IO.StreamReader($ssl, [System.Text.Encoding]::UTF8)
  $statusLine = $reader.ReadLine()
  $statusCode = 0
  if ($statusLine -match 'HTTP/\d\.\d\s+(\d+)') {
    $statusCode = [int]$matches[1]
  }
  
  $contentLength = -1
  $isChunked = $false
  while ($true) {
    $line = $reader.ReadLine()
    if ([string]::IsNullOrEmpty($line)) { break }
    if ($line -match '(?i)Content-Length:\s*(\d+)') {
      $contentLength = [int]$matches[1]
    }
    if ($line -match '(?i)Transfer-Encoding:\s*chunked') {
      $isChunked = $true
    }
  }
  
  $respBody = ''
  if ($contentLength -gt 0) {
    $buf = New-Object char[] $contentLength
    $readTotal = 0
    while ($readTotal -lt $contentLength) {
      $count = $reader.Read($buf, $readTotal, $contentLength - $readTotal)
      if ($count -le 0) { break }
      $readTotal += $count
    }
    $respBody = New-Object string ($buf, 0, $readTotal)
  } else {
    $respBody = $reader.ReadToEnd()
  }
  
  $tcp.Close()
  return [PSCustomObject]@{ StatusCode = $statusCode; Content = $respBody }
}

function Remove-CertWithKey {
  param($Store, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
  $Store.Remove($Cert)
  if ($Cert.HasPrivateKey) {
    try {
      $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
      if ($rsa -is [System.Security.Cryptography.RSACng]) { $rsa.Key.Delete() }
      elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false; $rsa.Clear() }
    } catch {
    }
  }
}

function Open-CertStore([string]$Name, [string]$Location) {
  $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($Name, [System.Security.Cryptography.X509Certificates.StoreLocation]::$Location)
  $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  return $s
}

function Test-TcpPort([string]$Address, [int]$TcpPort) {
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $client.BeginConnect($Address, $TcpPort, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(500)) { return $false }
    $client.EndConnect($ar)
    return $true
  } catch {
    return $false
  } finally {
    $client.Close()
  }
}

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '            GTermBoxServer Installer                         ' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "Install directory: $InstallDir"
Write-Host ''
Write-Host ' [WARNING] This installer configures system-wide security settings:' -ForegroundColor DarkYellow
Write-Host '   - Generates and imports TLS server and client certificates into system stores' -ForegroundColor DarkYellow
Write-Host '   - Cleans old development/test certificates from system stores' -ForegroundColor DarkYellow
Write-Host '   - Configures local AppContainer permissions and Windows Firewall rules' -ForegroundColor DarkYellow
Write-Host "   - Initializes server accounts and configuration in: $InstallDir" -ForegroundColor DarkYellow
Write-Host ''

if (-not $Force) {
  $confirm = Read-Host "Do you want to proceed with installation in '$InstallDir'? (y/N)"
  if ($confirm -notmatch '^(y|yes)$') {
    Write-Host 'Installation cancelled by user.' -ForegroundColor Yellow
    exit 0
  }
}

Write-Step '[1/9] Checking prerequisites and clearing old certificates...'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Stop-Install 'Run this script from an elevated PowerShell (Run as Administrator).' }
$ServerExe = Join-Path $InstallDir 'GTermBoxServer.exe'
$script:ManageExe = Join-Path $InstallDir 'ManageUsers.exe'
foreach ($exe in @($ServerExe, $script:ManageExe)) {
  if (-not (Test-Path $exe)) { Stop-Install "Required file not found: $exe" }
}
if (Get-Process -Name GTermBoxServer -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $ServerExe }) {
  Stop-Install 'GTermBoxServer.exe from this directory is running. Stop it before installation.'
}

$LocalIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress -Unique)
if (-not $BindIp) { $BindIp = $env:GTERM_BIND_IP }
if (-not $BindIp) {
  $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
  if ($route) {
    $BindIp = (Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
  }
}
if (-not $BindIp) { Stop-Install 'Unable to determine the bind IP address. Use -BindIp <address>.' }
if ($LocalIps -notcontains $BindIp) { Stop-Install "Bind IP $BindIp is not assigned to any local network adapter." }
if (Test-TcpPort $BindIp $Port) { Stop-Install "Port $Port on $BindIp is already in use by another process." }

$SubjectPattern = '^CN=(localhost|admin|usr\d+|mallory|GHttpsIOCP-DemoRootCA|Demo[A-Za-z]*Client|GTermBox[^,]*|\d{1,3}(\.\d{1,3}){3})(,|$)'
$ExcludedFriendlyNames = @('IIS Express Development Certificate', 'ASP.NET Core HTTPS development certificate')
$StoreNames = @('GHttpsIOCPSvr', 'My', 'Root', 'CA', 'TrustedPeople')
$PurgedCount = 0

foreach ($Location in @('LocalMachine', 'CurrentUser')) {
  foreach ($StoreName in $StoreNames) {
    if ($Location -eq 'CurrentUser' -and $StoreName -eq 'Root') { continue }
    $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $Location)
    try {
      $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
      $Targets = @($Store.Certificates | Where-Object { $_.Subject -match $SubjectPattern -and $ExcludedFriendlyNames -notcontains $_.FriendlyName })
      foreach ($Cert in $Targets) {
        Remove-CertWithKey $Store $Cert
        $PurgedCount++
      }
    } catch {
    } finally {
      $Store.Close()
    }
  }
}
if ($PurgedCount -gt 0) {
  Write-Ok "Cleaned $PurgedCount old certificate(s) from system stores"
} else {
  Write-Ok 'System certificate stores clean'
}

Write-Ok ("PowerShell {0}, Administrator, executables present" -f $PSVersionTable.PSVersion)
Write-Ok "Server endpoint: https://${BindIp}:$Port"

Write-Step '[2/9] Checking management scripts and runtime dependencies...'
$RequiredScripts = @(
  'Add-App.ps1',
  'Add-User.ps1',
  'Bind-ClientCertificate.ps1',
  'Install-ClientCertificate.ps1',
  'Install-ServerCertificate.ps1',
  'remove_certs.ps1',
  'gen_w3c_wt_cert.ps1'
)
foreach ($scriptName in $RequiredScripts) {
  $destScript = Join-Path $InstallDir $scriptName
  if (-not (Test-Path $destScript)) {
    Stop-Install "Missing required script in target directory: $scriptName"
  }
}
Write-Ok 'All required helper ps1 scripts present in directory'

$MsQuicDest = Join-Path $InstallDir 'msquic.dll'
if (-not (Test-Path $MsQuicDest)) {
  Write-Host ''
  Write-Host "  [!] Missing library: msquic.dll" -ForegroundColor Yellow
  Write-Host "      Official secure source: https://github.com/microsoft/msquic/releases (Official Microsoft QUIC repository)" -ForegroundColor Cyan
  Write-Host "      Target directory: $InstallDir" -ForegroundColor DarkGray
  $dlConfirm = Read-Host "  Do you want to download msquic.dll from its official release repository? (y/N)"
  if ($dlConfirm -match '^(y|yes)$') {
    $msquicUrl = 'https://github.com/microsoft/msquic/releases/download/v2.2.2/msquic_windows_x64_Release_openssl.zip'
    $tmpZip = Join-Path $env:TEMP 'msquic_download.zip'
    $tmpExtract = Join-Path $env:TEMP "msquic_extract_$([System.Guid]::NewGuid().ToString('N'))"
    try {
      Write-Info "Downloading msquic from $msquicUrl..."
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
      Invoke-WebRequest -Uri $msquicUrl -OutFile $tmpZip -UseBasicParsing -Headers @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
      Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
      $extractedDll = Get-ChildItem -Path $tmpExtract -Filter 'msquic.dll' -Recurse | Select-Object -First 1
      if ($extractedDll) {
        Copy-Item $extractedDll.FullName $MsQuicDest -Force
        Write-Ok "msquic.dll successfully downloaded and placed in $MsQuicDest"
      } else {
        Stop-Install "Failed to locate msquic.dll inside the downloaded archive."
      }
    } catch {
      Stop-Install "Download of msquic.dll failed: $($_.Exception.Message)"
    } finally {
      if (Test-Path $tmpZip) { Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue }
      if (Test-Path $tmpExtract) { Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue }
    }
  } else {
    Stop-Install "Missing required library in server directory: msquic.dll"
  }
}
if (-not (Test-Path $MsQuicDest)) {
  Stop-Install "Missing required library in server directory: msquic.dll"
}
Write-Ok "msquic.dll present in directory"

$LsQpackDest = Join-Path $InstallDir 'ls-qpack.dll'
if (-not (Test-Path $LsQpackDest)) {
  Stop-Install "Missing required library in server directory: ls-qpack.dll"
}
Write-Ok "ls-qpack.dll present in directory"

$WebDir = Join-Path $InstallDir 'web'
if (-not (Test-Path (Join-Path $WebDir 'index.html'))) {
  Stop-Install 'Missing web assets in server directory: web\index.html not found'
}
Write-Ok 'web\index.html present in directory'

Write-Step '[3/9] Initializing directory structure and configuration...'
Invoke-Manage @('init-env', $InstallDir) | Out-Null
foreach ($sub in @('Log', 'trusted_clients', 'client_keys')) {
  New-Item -ItemType Directory -Path (Join-Path $InstallDir $sub) -Force | Out-Null
}
Write-Ok 'Directories, apps.json and users.json initialized'

Write-Step '[4/9] Configuring applications (powershell, pytui, python)...'
$AppsJson = Get-Content (Join-Path $InstallDir 'apps.json') -Raw | ConvertFrom-Json
foreach ($app in @($AppsJson.apps)) {
  if (@('powershell', 'pytui', 'python') -notcontains $app.id) {
    Invoke-Manage @('delete-app', $app.id) | Out-Null
    Write-Info "Removed app: $($app.id)"
  }
}
$CurrentAppIds = @((Get-Content (Join-Path $InstallDir 'apps.json') -Raw | ConvertFrom-Json).apps | ForEach-Object { $_.id })
if ($CurrentAppIds -notcontains 'powershell') {
  Invoke-Manage @('add-app', 'powershell', 'PowerShell', 'powershell.exe', '--sandbox=standard', '--args=-NoExit,-NoLogo,-ExecutionPolicy,RemoteSigned', '--roles=user,admin', '--no-network') | Out-Null
} else {
  Invoke-Manage @('edit-app', 'powershell', '--args=-NoExit,-NoLogo,-ExecutionPolicy,RemoteSigned') | Out-Null
}
if ($CurrentAppIds -notcontains 'pytui') {
  Invoke-Manage @('add-app', 'pytui', 'Python TUI', 'PyTui\run.cmd', '--cols=120', '--rows=30', '--sandbox=job-only', '--roles=admin', '--env=TERM=xterm-256color,COLORTERM=truecolor,PYTHONIOENCODING=utf-8,PYTHONUTF8=1', '--no-network') | Out-Null
}
if ($CurrentAppIds -notcontains 'python') {
  Invoke-Manage @('add-app', 'python', 'Python', 'python.exe', '--args=-i,-q', '--cols=120', '--rows=30', '--sandbox=job-only', '--roles=admin', '--env=TERM=xterm-256color,COLORTERM=truecolor,PYTHONIOENCODING=utf-8,PYTHONUTF8=1', '--no-network') | Out-Null
}
$AppIds = @((Get-Content (Join-Path $InstallDir 'apps.json') -Raw | ConvertFrom-Json).apps | ForEach-Object { $_.id })
Write-Ok ("apps.json: {0}" -f ($AppIds -join ', '))

Write-Step '[5/9] Configuring users (admin, usr1)...'
$UsersJson = Get-Content (Join-Path $InstallDir 'users.json') -Raw | ConvertFrom-Json
$Existing = @($UsersJson.users | ForEach-Object { $_.username })
foreach ($u in $Existing) {
  if (@('admin', 'usr1') -notcontains $u) {
    Invoke-Manage @('delete', $u) | Out-Null
    Write-Info "Removed user: $u"
  }
}
if ($Existing -notcontains 'admin') { Invoke-Manage @('add', 'admin', $Password, '--role=admin', '--apps=*') | Out-Null }
if ($Existing -notcontains 'usr1') { Invoke-Manage @('add', 'usr1', $Password, '--role=user', '--apps=powershell') | Out-Null }
Invoke-Manage @('passwd', 'admin', $Password) | Out-Null
Invoke-Manage @('passwd', 'usr1', $Password) | Out-Null
Get-ChildItem -Path $InstallDir -Filter 'sandbox_*' -Directory | ForEach-Object {
  & icacls $_.FullName /grant "*S-1-5-11:(OI)(CI)F" /T /C /Q | Out-Null
}
Write-Ok 'users.json: admin (admin), usr1 (user)'

Write-Step '[6/9] Generating W3C WebTransport TLS certificate (ECDSA P-256)...'
$StoreName = 'GHttpsIOCPSvr'
$genScript = Join-Path $InstallDir 'gen_w3c_wt_cert.ps1'
if (Test-Path $genScript) {
  & $genScript -ServerIp $BindIp
} else {
  $detectedIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
    Select-Object -ExpandProperty IPAddress)

  $dnsNames = @('localhost', '127.0.0.1')
  if ($detectedIps) { $dnsNames += $detectedIps }
  if ($BindIp) { $dnsNames += $BindIp }
  $dnsNames = @($dnsNames | Select-Object -Unique)
  $primaryIp = if ($BindIp) { $BindIp } elseif ($detectedIps.Count -gt 0) { $detectedIps[0] } else { '127.0.0.1' }

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

  $destStoreLM = New-Object System.Security.Cryptography.X509Certificates.X509Store('GHttpsIOCPSvr', 'LocalMachine')
  $destStoreLM.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $destStoreLM.Add($cert)
  $destStoreLM.Close()

  try {
    $ecdsaKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
    if ($ecdsaKey -and $ecdsaKey.Key -and $ecdsaKey.Key.UniqueName) {
      $keyPath = "$env:ProgramData\Microsoft\Crypto\Keys\" + $ecdsaKey.Key.UniqueName
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
      }
    }
  } catch {}
}

$LocalStore = Open-CertStore $StoreName 'LocalMachine'
try {
  $foundCerts = @($LocalStore.Certificates | Where-Object { ($_.Subject -like "*CN=$BindIp*" -or $_.Subject -like '*CN=localhost*' -or $_.FriendlyName -eq 'GHttpsIOCPSvr') -and $_.HasPrivateKey -and $_.PublicKey.Oid.FriendlyName -match 'ECC|ECDSA' } | Sort-Object NotAfter -Descending)
  $ServerCert = if ($foundCerts.Count -gt 0) { $foundCerts[0] } else { $null }
} finally {
  $LocalStore.Close()
}

if (-not $ServerCert) {
  Stop-Install "Failed to locate generated W3C certificate in LocalMachine\$StoreName"
}

try {
  $UserStore = Open-CertStore $StoreName 'CurrentUser'
  try {
    foreach ($old in @($UserStore.Certificates | Where-Object { $_.Subject -like '*CN=localhost*' -or $_.FriendlyName -eq 'GHttpsIOCPSvr' -or $_.FriendlyName -eq 'GTermBoxServer' })) {
      try { Remove-CertWithKey $UserStore $old } catch {}
    }
  } finally {
    $UserStore.Close()
  }
} catch {}

$cerBytes = $ServerCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes((Join-Path $InstallDir 'localhost.cer'), $cerBytes)

$sha256Hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cerBytes)
$hashHex = [System.BitConverter]::ToString($sha256Hash).Replace('-', '')
Write-Ok "Certificate exported: localhost.cer"
Write-Ok "W3C SHA-256 Hash: $hashHex"
Write-Ok "Valid: $($ServerCert.NotBefore) to $($ServerCert.NotAfter)"

Write-Step '[7/9] Generating mTLS client certificates (admin, usr1)...'
$Now = Get-Date
function New-RandomClientPassword {
  $bytes = New-Object byte[] 18
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B').Replace('=', 'C') + '!9'
}
$ClientPasswords = @{
  'admin' = (New-RandomClientPassword);
  'usr1'  = (New-RandomClientPassword)
}
$MyStore = Open-CertStore 'My' 'CurrentUser'
try {
  foreach ($u in @('admin', 'usr1')) {
    $crtPath = Join-Path $InstallDir "trusted_clients\$u.crt"
    $pfxPath = Join-Path $InstallDir "client_keys\$u.pfx"
    $current = $null
    if ((Test-Path $crtPath) -and (Test-Path $pfxPath)) {
      try {
        $fileCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($crtPath)
        $current = $MyStore.Certificates | Where-Object { $_.Thumbprint -eq $fileCert.Thumbprint -and $_.HasPrivateKey -and $_.NotAfter -gt $Now.AddDays(30) } | Select-Object -First 1
      } catch {
        $current = $null
      }
    }
    if ($current) {
      Write-Info "Reusing client certificate for $u ($($current.Thumbprint))"
    } else {
      foreach ($old in @($MyStore.Certificates | Where-Object { $_.Subject -eq "CN=$u" })) {
        try { Remove-CertWithKey $MyStore $old } catch { Write-Warn "Cannot remove $($old.Thumbprint): $($_.Exception.Message)" }
      }
      $cc = New-SelfSignedCertificate -Subject "CN=$u" -FriendlyName "GTermBox client $u" -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') -NotAfter $Now.AddYears(5)
      $sec = ConvertTo-SecureString -String $ClientPasswords[$u] -AsPlainText -Force
      Export-PfxCertificate -Cert $cc -FilePath $pfxPath -Password $sec | Out-Null
      $b64 = [Convert]::ToBase64String($cc.RawData, [Base64FormattingOptions]::InsertLineBreaks)
      $pem = "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n"
      [System.IO.File]::WriteAllText($crtPath, $pem, [System.Text.Encoding]::ASCII)
      [System.IO.File]::WriteAllText((Join-Path $InstallDir "client_keys\$u.crt"), $pem, [System.Text.Encoding]::ASCII)
      $current = $cc
      Write-Ok "Generated client certificate for $u ($($cc.Thumbprint)), installed in CurrentUser\My"
    }
    Invoke-Manage @('bind-cert', $u, "$u.crt") | Out-Null
  }
} finally {
  $MyStore.Close()
}

Write-Step '[8/9] Configuring ACLs, firewall and start script...'
foreach ($acl in @(@{ P = 'web'; R = '(OI)(CI)RX' }, @{ P = 'PyTui'; R = '(OI)(CI)RX' }, @{ P = 'trusted_clients'; R = '(OI)(CI)RX' })) {
  $p = Join-Path $InstallDir $acl.P
  if (Test-Path $p) { & icacls $p /grant "*S-1-15-2-1:$($acl.R)" /T /C /Q | Out-Null }
}
Get-ChildItem -Path $InstallDir -Filter 'sandbox_*' -Directory | ForEach-Object {
  & icacls $_.FullName /grant "*S-1-5-11:(OI)(CI)F" /T /C /Q | Out-Null
}
Write-Ok 'AppContainer ACLs applied'
if (-not $SkipFirewall) {
  foreach ($proto in @('TCP', 'UDP')) {
    $ruleName = "GTermBoxServer $proto $Port"
    Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol $proto -LocalPort $Port -LocalAddress $BindIp -Program $ServerExe -Profile Any | Out-Null
  }
  Write-Ok "Firewall rules for TCP/UDP $Port on $BindIp"
}
$StartCmd = "@echo off`r`ncd /d `"%~dp0`"`r`nGTermBoxServer.exe --bind $BindIp --port $Port %*`r`n"
[System.IO.File]::WriteAllText((Join-Path $InstallDir 'Start-GTermBox.cmd'), $StartCmd, [System.Text.Encoding]::ASCII)
$Info = [ordered]@{
  bindIp = $BindIp
  port = $Port
  serverCertificate = $ServerCert.Thumbprint
  installedAt = (Get-Date).ToString('s')
}
($Info | ConvertTo-Json) | Set-Content -Path (Join-Path $InstallDir 'install_info.json') -Encoding UTF8
Write-Ok 'Start-GTermBox.cmd and install_info.json created'

if ($SkipSelfTest) {
  Write-Step '[9/9] Self-test skipped'
} else {
  Write-Step '[9/9] Running self-test...'
  $logOut = Join-Path $InstallDir 'Log\install_selftest_stdout.log'
  $logErr = Join-Path $InstallDir 'Log\install_selftest_stderr.log'
  $proc = Start-Process -FilePath $ServerExe -ArgumentList @('--bind', $BindIp, '--port', "$Port") -WorkingDirectory $InstallDir -WindowStyle Hidden -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
  $failures = New-Object System.Collections.Generic.List[string]
  try {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and -not (Test-TcpPort $BindIp $Port)) {
      if ($proc.HasExited) { break }
      Start-Sleep -Milliseconds 300
    }
    if (-not (Test-TcpPort $BindIp $Port)) {
      $tail = ''
      if (Test-Path $logOut) { $tail = (Get-Content $logOut -Tail 15) -join "`n" }
      $failures.Add("Server did not start listening on ${BindIp}:$Port. Log:`n$tail")
    } else {
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]3072 -bor [Net.SecurityProtocolType]12288
      $base = "https://${BindIp}:$Port"
      try {
        $r = Invoke-HttpJson -Url "$base/" -Method 'GET'
        if ($r.StatusCode -eq 200 -and $r.Content -match '<html') { Write-Ok "GET / -> 200 (certificate trusted without warnings)" } else { $failures.Add("GET / returned $($r.StatusCode)") }
      } catch { $failures.Add("GET / failed: $($_.Exception.Message)") }
      foreach ($u in @('admin', 'usr1')) {
        try {
          $body = @{ username = $u; password = $Password } | ConvertTo-Json
          $lr = Invoke-HttpJson -Url "$base/api/login" -Method 'POST' -Body $body
          if ($lr.StatusCode -ne 200) { $failures.Add("Login $u failed with status $($lr.StatusCode): $($lr.Content)"); continue }
          $loginObj = $lr.Content | ConvertFrom-Json
          if (-not $loginObj.token) { $failures.Add("Login $u returned no token"); continue }
          Write-Ok "POST /api/login ($u) -> token received"
          $ar = Invoke-HttpJson -Url "$base/api/apps" -Method 'GET' -BearerToken $loginObj.token
          $appsObj = $ar.Content | ConvertFrom-Json
          $ids = @($appsObj.apps | ForEach-Object { $_.id })
          if (-not $ids) { $ids = @($appsObj | ForEach-Object { $_.id }) }
          $customApps = @($ids | Where-Object { $_ -ne 'files' })
          if ($u -eq 'admin') {
            if ($customApps -contains 'powershell' -and $customApps -contains 'pytui' -and $customApps -contains 'python') {
              Write-Ok "GET /api/apps ($u) -> $($customApps -join ', ')"
            } else {
              $failures.Add("Apps for ${u}: $($ids -join ',')")
            }
          } else {
            if (($customApps -join ',') -eq 'powershell') {
              Write-Ok "GET /api/apps ($u) -> powershell"
            } else {
              $failures.Add("Apps for ${u}: $($ids -join ',')")
            }
          }
        } catch { $failures.Add("API test for $u failed: $($_.Exception.Message)") }
      }
      try {
        $bad = @{ username = 'usr1'; password = 'wrong-password' } | ConvertTo-Json
        $br = Invoke-HttpJson -Url "$base/api/login" -Method 'POST' -Body $bad
        if ($br.StatusCode -eq 401 -or $br.StatusCode -eq 403) {
          Write-Ok "POST /api/login (wrong password) -> rejected ($($br.StatusCode))"
        } else {
          $failures.Add("Login with wrong password returned unexpected status $($br.StatusCode)")
        }
      } catch {
        Write-Ok "POST /api/login (wrong password) -> rejected ($($_.Exception.Message))"
      }
    }
  } finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  }
  if ($failures.Count -gt 0) {
    foreach ($f in $failures) { Write-Host "  [X] $f" -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Installation finished with self-test errors.' -ForegroundColor Red
    exit 1
  }
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host ' GTermBoxServer installed successfully.' -ForegroundColor Green
Write-Host " Start:  $InstallDir\Start-GTermBox.cmd" -ForegroundColor Green
Write-Host " Open:   https://${BindIp}:$Port/" -ForegroundColor Green
Write-Host " Users:  admin / usr1" -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
exit 0

