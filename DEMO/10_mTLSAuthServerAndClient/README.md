# DEMO 10: Mutual TLS (mTLS) Authentication Server & Delphi Client

This demonstration presents end-to-end mutual TLS (mTLS) authentication using the high-performance **GHttpsIOCPSvr** engine on Windows, alongside a dedicated **Delphi native client application** implemented via Windows WinHTTP and CryptoAPI.

It supports two distinct authentication architectures **simultaneously** on the same running server instance:
1. **Hierarchical Trust via Root CA (Standard mTLS)**: Traditional PKI where clients present certificates signed by a trusted Root CA.
2. **Direct Trust / Certificate Pinning (Out-of-band 1:1 Trust)**: Modern zero-CA architecture where client identity is verified strictly against a pinned SHA-256 certificate fingerprint (e.g., IoT devices, internal secure microservices).

---

## 1. Architecture Overview

### Server (`D10_mTLSServer.exe`)
- Built on `TGHttpsServerIOCP` using Windows SSPI (SChannel).
- **Simultaneous Dual-Trust**:
  - Automatically loads Root CA (`test_root_ca.crt`) AND pinned client SHA-256 fingerprint (`client_pinned.sha256` / `client_pinned.crt`) simultaneously at startup.
  - No interactive question prompts or command-line parameters required.
  - Any client certificate signed by the Root CA OR matching the pinned SHA-256 fingerprint is authorized concurrently.
- Reads server certificates strictly from `cercts_server\` in `Win64\Debug\`:
  - `test_root_ca.crt`: Trusted Root CA used for client verification.
  - `client_pinned.crt` / `client_pinned.sha256`: Pinned client fingerprint used for Direct Trust.
- Automatically extracts X.509 client identity parameters into `TGClientCertInfo`:
  - `CommonName` (CN), `Subject`, `Issuer`
  - `SAN` (Subject Alternative Names via `CERT_NAME_DNS_TYPE`)
  - `SerialNumber`
  - `ThumbprintSHA256`
  - `RawCertBase64` (Base64 sanitized per Traefik specification)
  - `BuildXForwardedClientCertInfo` (`x_forwarded_tls_client_cert_info`)
- Endpoints:
  - `GET /api/client-identity`: Returns full X.509 client certificate details as JSON.
  - `POST /api/secure-m2m`: Dedicated Machine-to-Machine endpoint requiring verified client certificates.
  - `GET /api/public`: Publicly accessible status endpoint.
- Starts immediately on ports 8090 (HTTP) and 8453 (HTTPS). Press `[ENTER]` to gracefully stop.

### Client (`D10_mTLSClient.exe`)
- Pure Delphi console application using native Windows `winhttp.dll` (`Winapi.WinHTTP`) and `crypt32.dll`.
- Reads client certificates strictly from `cercts_client\` in `Win64\Debug\`:
  - `client_valid.pfx`: Valid certificate signed by Demo Root CA (password: `1234`).
  - `client_untrusted.pfx`: Rogue self-signed certificate (password: `1234`).
  - `client_expired.pfx`: Expired certificate (password: `1234`).
  - `client_pinned.pfx`: Standalone self-signed certificate for Direct Trust (password: `1234`).
- Binds client certificates to outgoing HTTPS requests using `WINHTTP_OPTION_CLIENT_CERT_CONTEXT`.
- Executes 5 verification scenarios via interactive menu:
  1. **Valid Client Certificate** (`client_valid.pfx`) -> `HTTP 200 OK` (authorized via Root CA).
  2. **Anonymous / Missing Certificate** -> Server terminates handshake / connection blocked (`12044`/`12152`).
  3. **Untrusted / Rogue CA Certificate** (`client_untrusted.pfx`) -> Server rejects untrusted client.
  4. **Expired Certificate** (`client_expired.pfx`) -> Server rejects expired credentials.
  5. **Pinned Certificate / Direct Trust** (`client_pinned.pfx`) -> `HTTP 200 OK` (authorized via Direct Trust SHA-256).

---

## 2. Implemented Standards & RFC Specifications

The mutual TLS implementation in **GHttpsIOCPSvr** complies with the following Internet Engineering Task Force (IETF) RFC specifications defining client certificate authentication:

*   **[RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) (TLS 1.3):** Core TLS 1.3 mutual handshake negotiation, `CertificateRequest` (§4.3.2), client `Certificate` (§4.4.2), and `CertificateVerify` (§4.4.3) signature verification.
*   **[RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246) (TLS 1.2):** TLS 1.2 client certificate request (§7.4.4) and mutual certificate exchange (§7.4.6).
*   **[RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001) (Using TLS to Secure QUIC):** QUIC TLS handshake encapsulation and client certificate authentication (§4.4 Client Authentication).
*   **[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) (X.509 PKI):** X.509 v3 certificate structure, Subject Alternative Names (SAN, OID `2.5.29.17`), and Extended Key Usage for Client Authentication (`id-kp-clientAuth`, OID `1.3.6.1.5.5.7.3.2`).

---

## 3. How to Run

### Step 1: Generate Demonstration Certificates (PowerShell)
```powershell
# Run PowerShell in DEMO\10_mTLSAuthServerAndClient
.\gen_mtls_certs.ps1
# or
.\gen_quic_cert.ps1
```
This script creates all test certificates directly into:
- `Win64\Debug\cercts_server\`: `test_root_ca.crt`, `client_pinned.crt`, `client_pinned.sha256`
- `Win64\Debug\cercts_client\`: `client_valid.pfx`, `client_untrusted.pfx`, `client_expired.pfx`, `client_pinned.pfx`

### Step 2: Start Server
```powershell
cd DEMO\10_mTLSAuthServerAndClient\Win64\Debug
.\D10_mTLSServer.exe
```
The server immediately starts with both Root CA validation and Direct Trust certificate pinning active simultaneously. Press `[ENTER]` to stop.

### Step 3: Run Client Suite
In a second PowerShell / Command Prompt window:
```powershell
cd DEMO\10_mTLSAuthServerAndClient\Win64\Debug
.\D10_mTLSClient.exe
```
Select:
- `[1]` to test valid CA-signed certificate
- `[2]` to test anonymous access (blocked)
- `[3]` to test untrusted certificate (blocked)
- `[4]` to test expired certificate (blocked)
- `[5]` to test pinned certificate / Direct Trust (authorized)
- `[A]` to run all 5 scenarios sequentially
- `[Q]` to quit
