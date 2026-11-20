# GHttpsServerIOCP - A Multi-Protocol HTTP, HTTPS, WebSocket, HTTP/3 & WebTransport Server in Delphi

This server is built in Delphi using asynchronous and multithreaded architecture. The server utilizes Windows I/O Completion Ports (IOCP), the native Windows TLS/SSL stack (SChannel) alongside an optional OpenSSL 3.x (`tpOpenSSL`) engine, Microsoft MsQuic, and RFC 6455 WebSockets, ensuring high throughput, minimal latency, and robust enterprise security.

It serves as a high-performance foundation for REST APIs, real-time WebSocket communication, next-generation HTTP/3 services, and ultra-low-latency WebTransport applications.

---

## Key Features

*   **Hybrid Multi-Protocol Architecture:**
    *   **HTTP/1.1 (TCP):** Ultra-fast plaintext HTTP engine with zero-cost SChannel bypass.
    *   **HTTPS (TLS 1.3 / 1.2):** Native Windows SChannel SSPI integration by default (`tpSchannel`, zero external TLS dependencies, Windows CNG certificate store integration) with an optional OpenSSL 3.x (`tpOpenSSL`) engine loaded dynamically on demand from file-based PEM certificates (`certs\server.crt` / `server.key`) and ALPN negotiation.
    *   **WebSocket (`ws://` and `wss://`):** Fully asynchronous RFC 6455 implementation with framing, ping/pong heartbeats, fragmentation support, and custom route handlers.
    *   **HTTP/3 over QUIC (UDP):** Next-gen HTTP/3 engine powered by Microsoft `msquic.dll` and QPACK header compression. Seamless `Alt-Svc` header advertisement for automatic browser upgrades.
    *   **WebTransport over HTTP/3 (RFC 9220):** Bidirectional transport over QUIC, supporting unidirectional and bidirectional streams, datagrams (RFC 9297), and dedicated CONNECT session multiplexing.
*   **Flexible Protocol Operating Modes:**
    *   **Dual-Stack Mode (`-mode:dual`):** Simultaneous listening on plaintext HTTP (default: `8080`) and encrypted HTTPS (default: `8443`) within a unified IOCP completion engine. Supports optional automatic `301 Moved Permanently` redirects (`-redirect`).
    *   **HTTP-Only Mode (`-mode:http`):** Operates without any SSL/TLS certificates or TLS engine overhead. Ideal for internal microservices, proxies, or reverse-proxy backends.
    *   **HTTPS-Only Mode (`-mode:https`):** Purely encrypted TLS 1.3/1.2 (`SChannel` or `OpenSSL 3.x` when `tpOpenSSL` is active) on port `8443` + HTTP/3 (UDP `8443`). Plaintext HTTP requests are rejected with `400 Bad Request`.
*   **Persistent Connections (Keep-Alive):**
    *   Full HTTP/1.1 Keep-Alive pipelining with zero-allocation buffer reuse.
    *   Configurable idle-timeout sweeper in a dedicated monitor thread.
*   **Enterprise Security & Web Application Firewall (WAF):**
    *   **Mutual TLS (mTLS) & Zero-Trust Client Authentication:**
        *   Full two-way cryptographic verification across both HTTPS (TCP: SChannel and OpenSSL 3.x) and HTTP/3 (QUIC / MsQuic).
        *   Flexible enforcement policies: Required client certificate, optional client certificate, and disabled.
        *   Deep X.509 v3 client identity extraction: Common Name (CN), Subject, Issuer, Serial Number, validity dates, SHA-256 thumbprint, and Subject Alternative Names (SAN).
        *   Reverse-proxy identity propagation compatible with standard conventions (`X-Forwarded-Tls-Client-Cert-Info`).
        *   **RFC Standards Compliance:**
            *   **RFC 8446:** TLS 1.3 Mutual Authentication (§4.3.2 CertificateRequest, §4.4.2 Certificate, §4.4.3 CertificateVerify).
            *   **RFC 5246:** TLS 1.2 Client Certificate mutual exchange and validation (§7.4.4, §7.4.6).
            *   **RFC 9001:** QUIC TLS encapsulation and client authentication (§4.4 Client Authentication).
            *   **RFC 5280:** X.509 v3 certificate structure, Subject Alternative Names (SAN), and Client Authentication EKU (OID 1.3.6.1.5.5.7.3.2).
    *   Built-in **JWT (JSON Web Token)** Manager with HMAC-SHA256 verification for Bearer-token protected routes.
    *   Zero-day request sanitization: Protection against path traversal, HTTP Request Smuggling, header injection, and malformed chunk framing.
*   **Advanced Content & Streaming:**
    *   High-speed file streaming via IOCP chunking (`otWriteChunk`) for multi-gigabyte downloads.
    *   Asynchronous multipart form data uploads (`multipart/form-data`) with disk streaming.
    *   **In-RAM HLS Live Broadcast Engine:** Native Delphi MPEG-TS parser and dynamic M3U8 generator (RFC 8216) with real-time PCR/PTS/DTS timeline rewriting and multi-client master synchronization.

---

## Requirements & Dependencies

*   **Architecture:** 64-bit only (Win64).
*   **Delphi:** Version 10.4 Sydney, 11 Alexandria, 12 Athens (or newer) - 64-bit Windows compiler.
*   **Operating System:** 64-bit Windows 10 / 11, Windows Server 2019 / 2022.
*   **Native 64-bit Binaries (Included / Self-Compiled):**
    *   `msquic.dll` (Microsoft MsQuic x64 with SChannel TLS support — used for HTTP/3 & WebTransport in default `tpSchannel` mode).
    *   `msquicSSL.dll` (Microsoft MsQuic x64 built with OpenSSL 3.5 — used for HTTP/3 & WebTransport when `tpOpenSSL` is active, without SChannel).
    *   `ls-qpack.dll` (LiteSpeed QPACK x64 header compression — for HTTP/3 & WebTransport).
    *   `libcrypto-3-x64.dll` & `libssl-3-x64.dll` (OpenSSL 3.5 x64 — optional, dynamically loaded when `TlsProvider = tpOpenSSL`, `-tls:tpOpenSSL`, or `GHTTPS_TLS_PROVIDER=tpOpenSSL` is selected).

---

### Required Library Directories in Project Root

The Delphi projects (`.dproj`) and compilation search paths (`<DCC_UnitSearchPath>`) require the following library directories to be present directly in the project root:

*   **`[QuickLib]`** ([github.com/exilon/QuickLib](https://github.com/exilon/QuickLib)) — Core utilities, threading helpers, collections, and base types.
*   **`[QuickLogger]`** ([github.com/exilon/QuickLogger](https://github.com/exilon/QuickLogger)) — High-performance asynchronous structured logging framework.
*   **`[FastMM5]`** ([github.com/pleriche/FastMM5](https://github.com/pleriche/FastMM5)) — High-performance memory manager.

---

### Unified Logging (`GLogger`) — Switching & Adding Loggers

All projects use `src\GLogger.pas` (`GLog` / `Logger`) configured via `src\GLogger.inc`.

**1. Switching Logger in `src\GLogger.inc`:**

Built-in async UTF-8 logger (default):
```pascal
{$IFNDEF GLOGGER_OVERRIDE}
  {$DEFINE GLOGGER_BACKEND_FAST}
{$ENDIF}
```
`Quick.Logger` (or copy `src\GLoggerQUICKLOGGER.inc` to `src\GLogger.inc`):
```pascal
{$IFNDEF GLOGGER_OVERRIDE}
  {$DEFINE GLOGGER_BACKEND_QUICKLOGGER}
{$ENDIF}
```
Custom logger (`IGLogSink`):
```pascal
{$IFNDEF GLOGGER_OVERRIDE}
  {$DEFINE GLOGGER_BACKEND_CUSTOM}
{$ENDIF}
```
Disabled logger:
```pascal
{$IFNDEF GLOGGER_OVERRIDE}
  {$DEFINE GLOGGER_DISABLED}
{$ENDIF}
```

**2. Adding a Third-Party Logger (Method A — `IGLogSink`):**
1.  Set `{$DEFINE GLOGGER_BACKEND_CUSTOM}` in `src\GLogger.inc`.
2.  Implement `IGLogSink`:
    ```pascal
    type
      TMyCustomSink = class(TInterfacedObject, IGLogSink)
      public
        procedure WriteLog(ALevel: TGLogLevel; const AMsg: string);
        procedure Flush;
      end;
    ```
3.  Register at startup:
    ```pascal
    GLog.SetCustomSink(TMyCustomSink.Create);
    GLog.Configure(Cfg);
    ```

---

## Native Dependencies: msquic.dll, msquicSSL.dll, ls-qpack.dll & OpenSSL 3.x

HTTP/3 and WebTransport require `ls-qpack.dll` plus the MsQuic library matching your active TLS provider:
- **`tpSchannel` (default):** uses `msquic.dll` (SChannel TLS) and certificates from the Windows Certificate Store (`LocalMachine\GHttpsIOCPSvr`).
- **`tpOpenSSL` (optional):** uses `msquicSSL.dll`, `libcrypto-3-x64.dll`, and `libssl-3-x64.dll` placed alongside your compiled `.exe`, together with file-based PEM certificates (`certs\server.crt` and `certs\server.key`). Selection between `msquic.dll` and `msquicSSL.dll` is automatic in `Http3DelphiV3\Quic.Server.pas` (`TQuicServer.Start`).

### 1. `msquic.dll` (Microsoft MsQuic — SChannel Mode `tpSchannel`)
High-performance IETF QUIC transport protocol implementation by Microsoft compiled with Windows SChannel (`-DQUIC_TLS_LIB=schannel`).

*   **Download Pre-built Binaries:**
    Official GitHub releases: [github.com/microsoft/msquic/releases](https://github.com/microsoft/msquic/releases)  
    Download the Windows x64 release package with **SChannel** TLS support (e.g. `msquic_windows_x64_Release_schannel.zip`) and extract `msquic.dll`.
*   **Building from Local Repository Sources (Recommended, MsQuic v2.7.0):**  
    *Requirements:* Visual Studio 2022 (Desktop development with C++), CMake (>= 3.20).
    ```powershell
    cd http3_src\sources\msquic_full
    cmake -B build_perf -G "Visual Studio 17 2022" -A x64 -DQUIC_TLS_LIB=schannel -DQUIC_BUILD_SHARED=ON -DQUIC_ENABLE_LOGGING=OFF
    cmake --build build_perf --config Release --target msquic
    ```
    *Output binary:* `http3_src\sources\msquic_full\build_perf\bin\Release\msquic.dll`
*   **Building from Upstream Source:**  
    *Requirements:* Visual Studio 2022 (Desktop development with C++), CMake (>= 3.20), Git.
    ```bash
    git clone --recursive https://github.com/microsoft/msquic.git
    cd msquic
    cmake -B build_perf -G "Visual Studio 17 2022" -A x64 -DQUIC_TLS_LIB=schannel -DQUIC_BUILD_SHARED=ON -DQUIC_ENABLE_LOGGING=OFF
    cmake --build build_perf --config Release --target msquic
    ```
    *Output binary:* `build_perf\bin\Release\msquic.dll`  
    *(Note: In `tpSchannel` mode, `Http3DelphiV3\MsQuic.Certificate.pas` loads credentials via `QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT` from the Windows Certificate Store).*

### 1b. `msquicSSL.dll` (Microsoft MsQuic — OpenSSL 3.5 Mode `tpOpenSSL`)
Dedicated OpenSSL-backed MsQuic binary (`-DQUIC_TLS_LIB=openssl`) used automatically when `tpOpenSSL` is active (`-tls:tpOpenSSL`, `GHTTPS_TLS_PROVIDER=tpOpenSSL`, or `Server.TlsProvider := tpOpenSSL`). It links dynamically against `libssl-3-x64.dll` and `libcrypto-3-x64.dll` and loads `certs\server.crt` / `certs\server.key` directly via `QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE` with zero SChannel or Windows Certificate Store usage.

*   **Building `msquicSSL.dll` from Local Repository Sources (against OpenSSL 3.5 DLLs):**
    1. Build OpenSSL 3.5 (`libcrypto-3-x64.dll` & `libssl-3-x64.dll`) as shown in Section 3 below, and generate MSVC import libraries (`libcrypto.lib` and `libssl.lib`) from the DLL exports (`dumpbin /EXPORTS` + `lib /MACHINE:X64 /DEF:...`).
    2. Configure and build `msquic` with external OpenSSL 3.5:
       ```powershell
       cd http3_src\sources\msquic_full
       cmake -B build_openssl -G "Visual Studio 17 2022" -A x64 `
         -DQUIC_TLS_LIB=openssl `
         -DQUIC_USE_EXTERNAL_OPENSSL=ON `
         -DQUIC_OPENSSL_INCLUDE_DIR=<merged_openssl_include_dir> `
         -DQUIC_OPENSSL_LIB_DIR=<openssl_import_libs_dir> `
         -DQUIC_BUILD_SHARED=ON -DQUIC_ENABLE_LOGGING=OFF `
         -DQUIC_BUILD_TEST=OFF -DQUIC_BUILD_TOOLS=OFF -DQUIC_BUILD_PERF=OFF
       # Important: replace /DEPENDENTLOADFLAG:0x800 with /DEPENDENTLOADFLAG:0xA00 in build_openssl\src\bin\msquic.vcxproj
       # so msquicSSL.dll can load libssl-3-x64.dll and libcrypto-3-x64.dll from the executable directory.
       cmake --build build_openssl --config Release --target msquic
       ```
    3. Copy the resulting `http3_src\sources\msquic_full\build_openssl\bin\Release\msquic.dll` as **`msquicSSL.dll`** alongside `libssl-3-x64.dll`, `libcrypto-3-x64.dll`, `msquic.dll`, and `ls-qpack.dll` in your target `.exe` output directory.

### 2. `ls-qpack.dll` (LiteSpeed QPACK v2.7.0)
High-efficiency QPACK header compression (RFC 9204) for HTTP/3 streams.

*   **Download Source:**
    Official GitHub repository: [github.com/litespeedtech/ls-qpack](https://github.com/litespeedtech/ls-qpack) (Release tag `v2.7.0`).
*   **Building from Source:**  
    *Requirements:* Visual Studio 2022 (Desktop development with C++), CMake (>= 3.16), Git.
    ```bash
    git clone --recursive -b v2.7.0 https://github.com/litespeedtech/ls-qpack.git
    cd ls-qpack
    mkdir build && cd build
    cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON ..
    cmake --build . --config Release
    ```
    *Output binary:* `build\Release\ls-qpack.dll`  
    *(Note: The `-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON` flag is required on Windows so that CMake exports all C functions into the DLL without modifying source headers).*

### 3. `libcrypto-3-x64.dll` & `libssl-3-x64.dll` (OpenSSL 3.5 — Optional `tpOpenSSL` TLS Engine)
Self-compiled 64-bit OpenSSL 3.5 shared libraries used when `tpOpenSSL` is selected instead of the default Windows SChannel engine (`tpSchannel`). No external MSYS2/GCC runtime DLLs are required at runtime when built with `-static-libgcc` (`mingw64`) or MSVC `/MT`.

*   **Method A — Building from Local Repository Sources via MSYS2 MinGW-w64 + NASM (Recommended):**  
    *Requirements:* MSYS2 (`mingw-w64-x86_64-gcc`, `make`, `perl`), NASM (`>= 2.15`).
    ```powershell
    & "C:\msys64\usr\bin\bash.exe" -lc '
      set -e
      export PATH="/mingw64/bin:/usr/bin:/c/Program Files/nasm-2.16.01:$PATH"
      cd http3_src/sources/msquic_full/submodules/openssl
      mkdir -p build_mingw64 && cd build_mingw64
      perl ../Configure mingw64 shared no-tests no-docs
      make -j$(nproc) build_libs
    '
    ```
    *Output binaries:*
    *   `http3_src\sources\msquic_full\submodules\openssl\build_mingw64\libcrypto-3-x64.dll`
    *   `http3_src\sources\msquic_full\submodules\openssl\build_mingw64\libssl-3-x64.dll`

*   **Method B — Building from Local or Upstream Sources via Visual Studio 2022 (`VC-WIN64A`):**  
    *Requirements:* Visual Studio 2022 (x64 Native Tools Command Prompt / `vcvars64.bat`), Strawberry Perl, NASM.
    ```bat
    git clone --depth 1 -b openssl-3.5 https://github.com/openssl/openssl.git
    cd openssl
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    perl Configure VC-WIN64A shared no-tests no-docs no-makedepend
    nmake build_libs
    ```
    *Output binaries:* `libcrypto-3-x64.dll` and `libssl-3-x64.dll` in the OpenSSL build root directory.

*   **Activating OpenSSL at Runtime (`tpOpenSSL`):**
    *   Programmatically before `Server.Start`: `Server.TlsProvider := tpOpenSSL;` (with explicit `Server.TlsCertFile` / `Server.TlsKeyFile` / `Server.TlsKeyPassword`, or automatic file-only discovery of `<ExeDir>\certs\server.crt` and `<ExeDir>\certs\server.key`). In `tpOpenSSL` mode, **Windows Certificate Stores and SChannel are never used** (HTTP/3 uses `msquicSSL.dll` with `QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE`).
    *   Via CLI switch (supported across all servers, demos, and tools in the repository): `-tls:tpOpenSSL` (or `--tls tpOpenSSL` / `--tpOpenSSL`), optionally paired with `--cert <path>` and `--key <path>`.
    *   Via environment variable: `set GHTTPS_TLS_PROVIDER=tpOpenSSL` (PowerShell: `$env:GHTTPS_TLS_PROVIDER="tpOpenSSL"`), and optionally `GHTTPS_TLS_CERT_FILE` / `GHTTPS_TLS_KEY_FILE`.

### Deployment Requirement
`msquic.dll` (for `tpSchannel`) and `ls-qpack.dll` must be present in the same directory as the compiled server binary (e.g. `Win64\Debug\` or `Win64\Release\`). When using `tpOpenSSL`, also place the self-compiled `msquicSSL.dll`, `libcrypto-3-x64.dll`, and `libssl-3-x64.dll` in the executable directory and provide `certs\server.crt` + `certs\server.key` (or pass explicit `--cert` / `--key` paths).

---

## Getting Started: Running the Server

### 1. SSL/TLS Certificates Management (Required for HTTPS, HTTP/3 & WebTransport)

Depending on your target protocol and client environment, choose the appropriate certificate script:

#### Option A: WebTransport & Browser Streaming (Recommended for DEMO 09 & Chrome/Edge)
Browser WebTransport implementations (Google Chrome, Microsoft Edge) strictly enforce **W3C WebTransport Specification Section 3.3** (`serverCertificateHashes`):
*   **Key Algorithm**: **ECDSA P-256 (`secp256r1`)** (RSA keys are explicitly forbidden by W3C for hash verification).
*   **Validity Period**: **Maximum 14 days** (2 weeks).
*   **Hash**: SHA-256 fingerprint verified by the client via `/api/certificate-hash`.

To generate a W3C-compliant certificate (and export `certs\server.crt` / `server.key` for `tpOpenSSL` across all build directories):
```powershell
# For Windows SChannel (Run PowerShell as Administrator)
.\gen_w3c_wt_cert.ps1

# For OpenSSL file-only mode (exports server.crt / server.key to certs\ directories)
.\gen_w3c_wt_cert.ps1 -ServerIp 127.0.0.1 -TlsProvider tpOpenSSL
```
*(Enables WebTransport connections in standard Chrome/Edge without any developer flags).*

#### Option B: General HTTPS & HTTP/3 QUIC (API & Benchmark Tools)
For standard HTTPS (TLS 1.3/1.2 via Windows SChannel or `tpOpenSSL`) and HTTP/3 QUIC CLI benchmark tools (`aioquic`, `h3bench`, `curl -k`):
*   **Key Algorithm**: ECDSA P-256 (`secp256r1`) / SHA-256.
*   **Validity Period**: 14 days (W3C WebTransport compliant).

To generate and export the QUIC/HTTPS certificate:
```powershell
# Run PowerShell as Administrator (add -TlsProvider tpOpenSSL to populate test_certs\ and certs\)
.\gen_quic_cert.ps1
```
*(For GMcpSvr MCP server instance, use `.\gen_quic_cert_mcp.ps1`).*

*   **Certificate Storage & Key Security:**
    *   **Windows Certificate Store (`tpSchannel`):** The certificate is installed into `Cert:\LocalMachine\GHttpsIOCPSvr`.
    *   **PEM Files (`tpOpenSSL`):** `server.crt` and `server.key` are exported to `certs\` directories alongside the compiled `.exe` files; `tpOpenSSL` reads only these PEM files.
    *   **Private Key Permissions (CNG):** Both scripts remove `Everyone` (`S-1-1-0`) and configure restricted `Read` ACLs on the CNG private key file in `%ProgramData%\Microsoft\Crypto\Keys\` exclusively for `SYSTEM` (`S-1-5-18`), `Administrators` (`S-1-5-32-544`), and the installing user.

#### Option C: Mutual TLS (mTLS) Test Certificates
To generate test CA, server, and client certificates for mTLS verification in `test_certs\`:
```powershell
.\gen_mtls_test_certs.ps1
```

#### Remove / Clean Certificates:
To remove generated test certificates from Windows Certificate Stores (and optionally clean `certs\` PEM files for `tpOpenSSL`):
```powershell
# Windows Certificate Stores (Run PowerShell as Administrator)
.\remove_certs.ps1

# Also remove exported PEM/CER files in certs\ directories
.\remove_certs.ps1 -TlsProvider tpOpenSSL -CleanPemFiles
```
*(Note: In `-mode:http`, no certificates are needed).*

---

### 2. Build & Launch

Open the server project in RAD Studio / Delphi:
*   `GHttpsIOCPSvrWebTransport.dpr` — Complete multi-protocol server (HTTP/1.1, HTTPS, WebSocket, HTTP/3, WebTransport).
*   `GHttpsIOCPSvrWebSocket.dpr` — HTTP/1.1, HTTPS, WebSocket, HTTP/3.
*   `GHttpsIOCPSvr.dpr` — Core HTTP/1.1, HTTPS, HTTP/3.

---

### 3. Command-Line Options (CLI)

```bash
# Run in Dual-Stack mode (HTTP: 8080 + HTTPS: 8443 + HTTP/3: 8443)
GHttpsIOCPSvrWebTransport.exe -mode:dual -httpport:8080 -httpsport:8443

# Run in HTTP-Only mode (No certificate required, plaintext & ws://)
GHttpsIOCPSvrWebTransport.exe -mode:http -httpport:8080

# Run in HTTPS-Only mode with Keep-Alive disabled
GHttpsIOCPSvrWebTransport.exe -mode:https -httpsport:8443 -nokeepalive

# Dual-Stack with automatic 301 Redirect from HTTP to HTTPS
GHttpsIOCPSvrWebTransport.exe -mode:dual -redirect

# Maximum performance benchmark mode (Disable logging)
GHttpsIOCPSvrWebTransport.exe -mode:dual -nolog

# Use self-compiled OpenSSL 3.x engine (tpOpenSSL) instead of default SChannel (tpSchannel)
GHttpsIOCPSvrWebTransport.exe -mode:dual -tls:tpOpenSSL

# View CLI Help
GHttpsIOCPSvrWebTransport.exe -help
```

---

## Code Examples: Building Applications

### 1. Initializing the Multi-Protocol Server
```pascal
program MyServerApp;

{$APPTYPE CONSOLE}

uses
  FASTMM5,
  Quick.Logger,
  System.SysUtils,
  GHttpsServerIOCP in 'src\GHttpsServerIOCP.pas',
  GRequest in 'src\GRequest.pas',
  GResponse in 'src\GResponse.pas';

var
  Server: TGHttpsServerIOCP;
begin
  Server := TGHttpsServerIOCP.Create(
    8443, 'localhost', 'GHttpsIOCPSvr',
    'MySecretJwtKey1234567890!',
    2000, 1000000,
    DEFAULT_MAX_REQUEST_HEDER_SIZE,
    DEFAULT_MAX_REQUEST_SIZE,
    DEFAULT_MAX_RESPONSE_SIZE,
    DEFAULT_CHUNK_SIZE,
    50, 85, True, True,
    8080, haServeNormally
  );
  try
    Server.EnableHttp3 := True;
    Server.EnableKeepAlive := True;

    Server.Start;
    Writeln('Server running. Press Enter to stop...');
    Readln;
    Server.Stop;
  finally
    Server.Free;
  end;
end.
```

---

### 2. Registering REST Endpoints
```pascal
Server.RegisterEndpointProc('/api/status', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  var
    Json: TJSONObject;
  begin
    Json := TJSONObject.Create;
    try
      Json.AddPair('status', 'online');
      Json.AddPair('time', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
      AResponse.AddJSONContent(Json.ToJSON);
    finally
      Json.Free;
    end;
  end
);
```

---

### 3. Registering WebSockets (`ws://` & `wss://`)
```pascal
Server.RegisterWebSocketRoute('/chat',
  procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const MessageText: string; Opcode: TWebSocketOpcode)
  begin
    if Opcode = wsOpText then
    begin
      Session.SendText('Echo: ' + MessageText);
      AServer.TriggerWebSocketWrite(Session);
    end;
  end
);
```

---

### 4. Registering WebTransport Routes (HTTP/3 QUIC)
```pascal
var
  OnSessionReady: TWebTransportSessionProc;
  OnStreamData: TWebTransportStreamProc;
  OnDatagram: TWebTransportDatagramProc;
  OnSessionClosed: TWebTransportClosedProc;
begin
  OnSessionReady :=
    procedure(Session: PWTSessionContext)
    begin
      Writeln('WebTransport session opened: ' + UIntToStr(Session.SessionId));
    end;

  OnStreamData :=
    procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
    begin
      Session.SendOnStream(Stream, Data);
    end;

  OnDatagram :=
    procedure(Session: PWTSessionContext; const Data: TBytes)
    begin
      Session.SendDatagram(Data);
    end;

  OnSessionClosed :=
    procedure(SessionId: TWTSessionId)
    begin
      Writeln('WebTransport session closed: ' + UIntToStr(SessionId));
    end;

  Server.RegisterWebTransportRoute(
    '/live-transport',
    OnSessionReady,
    OnStreamData,
    OnDatagram,
    OnSessionClosed
  );
end;
```

---

## Performance Benchmarks (`k6` / `xk6-http3`)

Measured on Windows 11 

### HTTP (Plaintext)

| # | Server | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Errors | RAM (MB) |
| :---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | kestrel | 32818.30 | 2.52 | 5.23 | 8.47 | 0.0% | 67.72 |
| **2** | **ghttps** | 29619.90 | 2.86 | 6.02 | 9.82 | 0.0% | 32.97 |
| **3** | nginx | 27271.95 | 3.25 | 8.65 | 12.50 | 0.0% | 137.49 |
| **4** | caddy | 25694.47 | 3.34 | 8.21 | 13.08 | 0.0% | 49.14 |
| **5** | indy | 6515.88 | 3.42 | 54.64 | 75.07 | 0.0% | 15.73 |
| **6** | horse | 5891.47 | 5.66 | 57.10 | 76.89 | 17.14% | 18.00 |

### HTTPS — Keep-Alive

| # | Server | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Errors | RAM (MB) |
| :---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | kestrel | 27825.06 | 3.44 | 6.02 | 8.63 | 0.0% | 107.27 |
| **2** | **ghttps** | 26300.56 | 3.51 | 6.29 | 10.57 | 0.0% | 35.44 |
| **3** | caddy | 24601.95 | 3.52 | 8.34 | 13.70 | 0.0% | 54.62 |
| **4** | nginx | 16493.68 | 5.37 | 12.31 | 18.92 | 0.0% | 139.74 |
| **5** | indy | 6964.48 | 2.28 | 56.17 | 76.66 | 0.0% | 19.42 |
| **6** | horse | 6364.80 | 3.56 | 56.70 | 76.07 | 9.34% | 22.07 |

### HTTPS — Handshake (`Connection: close`)

| # | Server | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Errors | RAM (MB) |
| :---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | horse | 2835.81 | 0.00 | 14.56 | 27.27 | 56.98% | 34.42 |
| **2** | indy | 2818.44 | 0.00 | 13.77 | 25.72 | 53.85% | 31.68 |
| **3** | **ghttps** | 2012.66 | 11.62 | 23.51 | 33.30 | 0.0% | 35.66 |
| **4** | kestrel | 1523.03 | 12.04 | 24.78 | 31.80 | 0.0% | 106.07 |
| **5** | caddy | 1491.87 | 3.00 | 11.56 | 16.92 | 0.0% | 50.30 |
| **6** | nginx | 75.12 | 13.29 | 27.32 | 163.69 | 0.0% | 138.40 |

### HTTP/3 (QUIC)

| # | Server | Status | RPS (Avg) | p50 (ms) | p95 (ms) | p99 (ms) | Errors | Peak RAM (MB) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **#1** | <nobr>`quicgo`</nobr> | ok | 13945.91 | 1.0 | 3.0 | 6.0 | 0.0% | 19.38 |
| **#2** | <nobr>`caddy`</nobr> | ok | 11532.02 | 1.0 | 4.0 | 6.0 | 0.0% | 45.12 |
| **#3** | <nobr>`ghttps`</nobr> | ok | 10211.2 | 1.0 | 7.0 | 24.0 | 0.0% | 38.65 |
| **#4** | <nobr>`traefik`</nobr> | ok | 8117.4 | 2.0 | 5.0 | 8.0 | 0.0% | 137.7 |
| **#5** | <nobr>`kestrel`</nobr> | ok | 7523.92 | 2.0 | 6.0 | 9.0 | 0.0% | 93.84 |
| **#6** | <nobr>`aioquic_wt`</nobr> | ok | 1239.57 | 16.0 | 20.0 | 24.0 | 0.0% | 44.99 |

---

## License

This project is licensed under the **MIT License**. See source headers for details.

Copyright (c) 2026 GECKO-71.
