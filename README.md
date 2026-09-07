# GHttpsServerIOCP - A Multi-Protocol HTTP, HTTPS, WebSocket, HTTP/3 & WebTransport Server in Delphi

This server is built in Delphi using asynchronous and multithreaded architecture. The server utilizes Windows I/O Completion Ports (IOCP), the native Windows TLS/SSL stack (SChannel), Microsoft MsQuic, and RFC 6455 WebSockets, ensuring high throughput, minimal latency, and robust enterprise security.

It serves as a high-performance foundation for REST APIs, real-time WebSocket communication, next-generation HTTP/3 services, and ultra-low-latency WebTransport applications.

---

## Key Features

*   **Hybrid Multi-Protocol Architecture:**
    *   **HTTP/1.1 (TCP):** Ultra-fast plaintext HTTP engine with zero-cost SChannel bypass.
    *   **HTTPS (TLS 1.3 / 1.2):** Secure SChannel SSPI integration with ALPN negotiation, zero OpenSSL dependencies, and native Windows CNG certificate store integration.
    *   **WebSocket (`ws://` and `wss://`):** Fully asynchronous RFC 6455 implementation with framing, ping/pong heartbeats, fragmentation support, and custom route handlers.
    *   **HTTP/3 over QUIC (UDP):** Next-gen HTTP/3 engine powered by Microsoft `msquic.dll` and QPACK header compression. Seamless `Alt-Svc` header advertisement for automatic browser upgrades.
    *   **WebTransport over HTTP/3 (RFC 9220):** Bidirectional transport over QUIC, supporting unidirectional and bidirectional streams, datagrams (RFC 9297), and dedicated CONNECT session multiplexing.
*   **Flexible Protocol Operating Modes:**
    *   **Dual-Stack Mode (`-mode:dual`):** Simultaneous listening on plaintext HTTP (default: `8080`) and encrypted HTTPS (default: `8443`) within a unified IOCP completion engine. Supports optional automatic `301 Moved Permanently` redirects (`-redirect`).
    *   **HTTP-Only Mode (`-mode:http`):** Operates without any SSL/TLS certificates or SChannel overhead. Ideal for internal microservices, proxies, or reverse-proxy backends.
    *   **HTTPS-Only Mode (`-mode:https`):** Purely encrypted TLS 1.3/1.2 SChannel on port `8443` + HTTP/3 (UDP `8443`). Plaintext HTTP requests are rejected with `400 Bad Request`.
*   **Persistent Connections (Keep-Alive):**
    *   Full HTTP/1.1 Keep-Alive pipelining with zero-allocation buffer reuse.
    *   Configurable idle-timeout sweeper in a dedicated monitor thread.
*   **Enterprise Security & Web Application Firewall (WAF):**
    *   Built-in **JWT (JSON Web Token)** Manager with HMAC-SHA256 verification for Bearer-token protected routes (`atJWTBearer`).
    *   Zero-day request sanitization: Protection against path traversal (`..`), HTTP Request Smuggling, header injection, and malformed chunk framing.
*   **Advanced Content & Streaming:**
    *   High-speed file streaming via IOCP chunking (`otWriteChunk`) for multi-gigabyte downloads.
    *   Asynchronous multipart form data uploads (`multipart/form-data`) with disk streaming.
    *   **In-RAM HLS Live Broadcast Engine:** Native Delphi MPEG-TS parser and dynamic M3U8 generator (RFC 8216) with real-time PCR/PTS/DTS timeline rewriting and multi-client master synchronization.

---

## Requirements & Dependencies

*   **Architecture:** 64-bit only (Win64).
*   **Delphi:** Version 10.4 Sydney, 11 Alexandria, 12 Athens (or newer) - 64-bit Windows compiler.
*   **Operating System:** 64-bit Windows 10 / 11, Windows Server 2019 / 2022.
*   **Native 64-bit Binaries (Included in repository):**
    *   `msquic.dll` (Microsoft MsQuic x64 with SChannel TLS support).
    *   `ls-qpack.dll` (LiteSpeed QPACK x64 header compression).

---

### Required Library Directories in Project Root

The Delphi projects (`.dproj`) and compilation search paths (`<DCC_UnitSearchPath>`) require the following library directories to be present directly in the project root:

*   **`[QuickLib]`** ([github.com/exilon/QuickLib](https://github.com/exilon/QuickLib)) — Core utilities, threading helpers, collections, and base types.
*   **`[QuickLogger]`** ([github.com/exilon/QuickLogger](https://github.com/exilon/QuickLogger)) — High-performance asynchronous structured logging framework.
*   **`[FastMM5]`** ([github.com/pleriche/FastMM5](https://github.com/pleriche/FastMM5)) — High-performance memory manager.

---

## Native Dependencies: msquic.dll & ls-qpack.dll

HTTP/3 and WebTransport require two 64-bit native dynamic link libraries placed alongside your compiled `.exe`:

### 1. `msquic.dll` (Microsoft MsQuic)
High-performance IETF QUIC transport protocol implementation by Microsoft.

*   **Download Pre-built Binaries:**
    Official GitHub releases: [github.com/microsoft/msquic/releases](https://github.com/microsoft/msquic/releases)  
    Download the Windows x64 release package with **SChannel** TLS support (e.g. `msquic_windows_x64_Release_schannel.zip`) and extract `msquic.dll`.
*   **Building from Source:**  
    *Requirements:* Visual Studio 2022 (Desktop development with C++), CMake (>= 3.20), Git.
    ```bash
    git clone --recursive https://github.com/microsoft/msquic.git
    cd msquic
    mkdir build && cd build
    cmake -G "Visual Studio 17 2022" -A x64 -DQUIC_TLS=schannel -DQUIC_BUILD_SHARED=ON -DCMAKE_BUILD_TYPE=Release -DQUIC_ENABLE_LOGGING=OFF ..
    cmake --build . --config Release
    ```
    *Output binary:* `build\bin\Release\msquic.dll`  
    *(Note: `GHttpsIOCPSvr` uses Windows SChannel TLS via `-DQUIC_TLS=schannel`, avoiding external OpenSSL dependencies).*

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

### Deployment Requirement
Both `msquic.dll` and `ls-qpack.dll` must be present in the same directory as the compiled server binary (e.g. `Win64\Debug\` or `Win64\Release\`).

---

## Getting Started: Running the Server

### 1. SSL/TLS Certificates Management (Required for HTTPS, HTTP/3 & WebTransport)

Depending on your target protocol and client environment, choose the appropriate certificate script:

#### Option A: WebTransport & Browser Streaming (Recommended for DEMO 09 & Chrome/Edge)
Browser WebTransport implementations (Google Chrome, Microsoft Edge) strictly enforce **W3C WebTransport Specification Section 3.3** (`serverCertificateHashes`):
*   **Key Algorithm**: **ECDSA P-256 (`secp256r1`)** (RSA keys are explicitly forbidden by W3C for hash verification).
*   **Validity Period**: **Maximum 14 days** (2 weeks).
*   **Hash**: SHA-256 fingerprint verified by the client via `/api/certificate-hash`.

To generate a W3C-compliant certificate:
```powershell
# Run PowerShell as Administrator
.\gen_w3c_wt_cert.ps1
```
*(Enables WebTransport connections in standard Chrome/Edge without any developer flags).*

#### Option B: General HTTPS & HTTP/3 QUIC (API & Benchmark Tools)
For standard HTTPS (TLS 1.3/1.2 via Windows SChannel) and HTTP/3 QUIC CLI benchmark tools (`aioquic`, `h3bench`, `curl -k`):
*   **Key Algorithm**: RSA 2048 / SHA-256.
*   **Validity Period**: 5 years.

To generate the standard RSA certificate:
```powershell
# Run PowerShell as Administrator
.\gen_quic_cert.ps1
```

*   **Certificate Storage & Key Security:**
    *   **Certificate Store:** The certificate is installed into the dedicated Windows machine store: `Cert:\LocalMachine\GHttpsIOCPSvr`.
    *   **Private Key Permissions (CNG):** Both scripts configure Access Control Lists (ACLs) on the CNG private key file in `%ProgramData%\Microsoft\Crypto\Keys\` granting Read access to service accounts and the `Users` group (SID `S-1-1-0`).

#### Remove / Clean Certificates:
To remove all generated test certificates from Windows Certificate Stores:
```powershell
# Run PowerShell as Administrator
.\remove_certs.ps1
```
*(Note: In `-mode:http`, no certificates are needed).*

---

### 2. Build & Launch

Open the project group `GHttpsIOCPSvrGroup.groupproj` in RAD Studio / Delphi:
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
    Server.EnableWebTransport := True;
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
Server.RegisterWebSocketRoute('/chat', True);

Server.OnWebSocketFrame := procedure(AServer: TObject; ASession: TWebSocketSession; const AFrame: TWebSocketFrame)
begin
  if AFrame.OpCode = wsOpText then
  begin
    var Msg := TEncoding.UTF8.GetString(AFrame.Payload);
    ASession.QueueSendTextFrame('Echo: ' + Msg);
    Server.TriggerWebSocketWrite(ASession);
  end;
end;
```

---

### 4. Registering WebTransport Routes (HTTP/3 QUIC)
```pascal
Server.RegisterWebTransportRoute('/live-transport',
  procedure(ASession: TWebTransportSession)
  begin
    Writeln('WebTransport session opened: ' + IntToStr(ASession.SessionId));
  end,
  procedure(ASession: TWebTransportSession; AStream: TWebTransportStream; const AData: TBytes)
  begin
    AStream.Send(AData);
  end,
  procedure(ASession: TWebTransportSession; const ADatagram: TBytes)
  begin
    ASession.SendDatagram(ADatagram);
  end
);
```

---

## License

This project is licensed under the **MIT License**. See source headers for details.

Copyright (c) 2026 GECKO-71.
