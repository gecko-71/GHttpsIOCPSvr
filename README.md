# GHttpsServerIOCP - A Multi-Protocol HTTP, HTTPS, WebSocket & HTTP/3 Server in Delphi

This server is built in Delphi using asynchronous and multithreaded methods. The server utilizes I/O Completion Ports (IOCP), the native Windows TLS/SSL stack (SChannel), Microsoft MsQuic, and RFC 6455 WebSockets, ensuring high performance, scalability, and security.

It can be used to build efficient REST APIs, web services, real-time WebSocket applications, and modern systems that handle many simultaneous HTTP, HTTPS, and HTTP/3 connections.

---

## Key Features

*   **Hybrid Multi-Protocol Architecture:**
    *   **HTTP/1.1 (TCP):** Ultra-fast plaintext HTTP engine with zero-cost SChannel bypass.
    *   **HTTPS (TLS 1.3 / 1.2):** Secure SChannel SSPI integration with ALPN negotiation, zero OpenSSL dependencies, and native Windows CNG certificate store integration.
    *   **WebSocket (`ws://` and `wss://`):** Fully asynchronous RFC 6455 implementation with framing, ping/pong heartbeats, fragmentation support, and custom route handlers.
    *   **HTTP/3 over QUIC (UDP):** Next-gen HTTP/3 engine powered by Microsoft `msquic.dll` and QPACK header compression. Seamless `Alt-Svc` header advertisement for automatic browser upgrades.
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

---

## Requirements & Dependencies

*   **Architecture:** 64-bit only.
*   **Delphi:** Version 10.4 Sydney, 11 Alexandria, 12 Athens (or newer) - 64-bit Windows compiler.
*   **Operating System:** 64-bit Windows 10 / 11, Windows Server 2019 / 2022.
*   **Delphi Libraries (Included in repository / Add to Library Path):**
    *   [FastMM5](https://github.com/pleriche/FastMM5) - High-performance memory manager.
    *   [QuickLib](https://github.com/exilon/QuickLib) (`./QuickLib`) - Core utilities, threading helpers, collections, and base types.
    *   [QuickLogger](https://github.com/exilon/QuickLogger) (`./QuickLogger`) - High-performance asynchronous structured logging framework.
*   **Runtime Binary:**
    *   [MsQuic Official Repository](https://github.com/microsoft/msquic) & [MsQuic x64 Releases](https://github.com/microsoft/msquic/releases) (`msquic.dll` 64-bit - precompiled binary included in project directory for HTTP/3 QUIC support).

---

## Getting Started: Running the Server

### 1. SSL Certificates Management (Required for HTTPS / HTTP/3)

#### Generate SSL Certificate:
To enable TLS and HTTP/3 on localhost, generate a self-signed CNG certificate:
```powershell
# Run PowerShell as Administrator
.\gen_quic_cert.ps1
```

*   **Certificate Storage & Key Security:**
    *   **Certificate Store:** The certificate is installed into a dedicated Windows machine store: `Cert:\LocalMachine\GHttpsIOCPSvr`. This ensures server certificates remain isolated from the default `Personal/My` store.
    *   **Private Key (CNG):** The RSA 2048 / SHA-256 private key is stored securely in the Windows Cryptography Next Generation (CNG) machine key directory (`%ProgramData%\Microsoft\Crypto\Keys\`). The generation script automatically configures Access Control Lists (ACLs) to grant Read permissions to service accounts and the `Users` group.

#### Remove / Clean Certificates:
To remove and clean up all generated test certificates from Windows Certificate Stores (`LocalMachine\GHttpsIOCPSvr`, `CurrentUser\GHttpsIOCPSvr`, `LocalMachine\My`):
```powershell
# Run PowerShell as Administrator
.\remove_certs.ps1
```
*(Note: If you run the server in `-mode:http`, no certificates are needed!)*

### 2. Build & Launch
Open and build `GHttpsIOCPSvrWebSocket.dpr` or `GHttpsIOCPSvr.dpr`.

### 3. Command-Line Options (CLI)
You can customize the server execution directly from the command line:

```bash
# Run in Dual-Stack mode (HTTP: 8080 + HTTPS: 8443 + HTTP/3: 8443)
GHttpsIOCPSvrWebSocket.exe -mode:dual -httpport:8080 -httpsport:8443

# Run in HTTP-Only mode (No certificate required, pure plaintext & ws://)
GHttpsIOCPSvrWebSocket.exe -mode:http -httpport:8080

# Run in HTTPS-Only mode with Keep-Alive disabled
GHttpsIOCPSvrWebSocket.exe -mode:https -httpsport:8443 -nokeepalive

# Dual-Stack with automatic 301 Redirect from HTTP to HTTPS
GHttpsIOCPSvrWebSocket.exe -mode:dual -redirect

# Maximum performance benchmark mode (Disable console/file logging)
GHttpsIOCPSvrWebSocket.exe -mode:dual -nolog

# View CLI Help
GHttpsIOCPSvrWebSocket.exe -help
```

---

## Code Examples: Building Applications

### 1. Initializing the Server (Dual-Stack with Keep-Alive)
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
  // Create server: HTTPS: 8443, HTTP: 8080, Dual-Stack mode
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

    // Register endpoints here...
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

#### Simple JSON API:
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

#### JWT Protected Route:
```pascal
Server.RegisterEndpointProc('/api/admin/data', hmGET,
  procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
  begin
    AResponse.AddTextContent('text/plain', 'Welcome, authorized administrator!');
  end,
  atJWTBearer // Enforces Authorization: Bearer <Token>
);
```

---

### 3. Registering WebSockets (`ws://` & `wss://`)

```pascal
// 1. Register WebSocket route
Server.RegisterWebSocketRoute('/chat', True);

// 2. Handle incoming WebSocket frames
Server.OnWebSocketFrame := procedure(AServer: TObject; ASession: TWebSocketSession; const AFrame: TWebSocketFrame)
begin
  if AFrame.OpCode = wsOpText then
  begin
    var Msg := TEncoding.UTF8.GetString(AFrame.Payload);
    Writeln('Received WS message: ' + Msg);

    // Echo back or broadcast to other clients
    ASession.QueueSendTextFrame('Echo: ' + Msg);
    Server.TriggerWebSocketWrite(ASession);
  end;
end;
```

---

### 4. Testing Endpoints with cURL

```bash
# 1. Test Plaintext HTTP (Port 8080)
curl -i http://localhost:8080/status

# 2. Test Secure HTTPS TLS 1.3 (Port 8443)
curl -k -i https://localhost:8443/status

# 3. Test HTTP/3 (QUIC / UDP) using h3bench
.\h3bench.exe -u https://localhost:8443/api/protocol -c 10 -n 100 -k

# 4. Authenticate & Obtain JWT Bearer Token
curl -k -X POST https://localhost:8443/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"password123\"}"
```

---

## License

This project is licensed under the **MIT License**. See source headers for details.

Copyright (c) 2026 GECKO-71.
