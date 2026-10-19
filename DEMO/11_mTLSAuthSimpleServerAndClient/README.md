# DEMO 11: Simple mTLS Direct Trust Server & Client

This demonstration presents end-to-end mutual TLS (mTLS) authentication using the high-performance **GHttpsIOCPSvr** engine on Windows, alongside a dedicated **Delphi native client application** built with standard Delphi components (`TNetHTTPClient`).

Unlike traditional PKI setups requiring complex Certificate Authorities (Root CAs), DEMO 11 demonstrates the **Direct Trust / Certificate Pinning (Out-of-band 1:1 Trust)** model:
- Zero Certificate Authority (CA) infrastructure is required.
- The server strictly verifies incoming client identity against the SHA-256 fingerprint pinned in `server_certificates\client.sha256` or `client.crt`.
- Anonymous connections and unpinned certificates are rejected immediately during the TLS handshake.

---

## 1. Architecture Overview

### Server (`mTLSAuthSimpleServer.exe`)
- Built on `TGHttpsServerIOCP` using Windows SSPI (SChannel).
- **Direct Trust Verification**:
  - Automatically loads the pinned client SHA-256 fingerprint at startup using native RTL (`THashSHA2`, `TBytesStream`):
    ```pascal
    PinnedClientThumbprint := LoadClientThumbprint;
    ```
  - Reads server assets strictly from `server_certificates\`:
    - `server.crt`: Server public certificate (`CN=localhost`).
    - `client.crt`: Trusted client public certificate delivered out-of-band.
    - `client.sha256`: SHA-256 hex fingerprint of the trusted client.
- **Strict mTLS Enforcement**:
  - Enables required mutual TLS: `Server.mTLSMode := mtlsRequired`.
  - Configures graceful SSL shutdown: `Server.SetSSLShutdownOptions(True, 200)`.
  - In `Server.OnValidateClientCertificate`:
    ```pascal
    Result := (PinnedClientThumbprint <> '') and SameText(CertInfo.ThumbprintSHA256, PinnedClientThumbprint);
    ```
- **Endpoints**:
  - `GET /api/secret-data`: Protected resource returning client identity and confirmation JSON.
- Starts immediately on HTTPS port **8454**. Press `[ENTER]` to gracefully stop.

### Client (`mTLSAuthSimpleClient.exe`)
- Pure Delphi console application using standard Delphi networking components:
  - `TNetHTTPClient` (`System.Net.HttpClientComponent`) and `System.Net.URLClient`.
- Reads client credentials strictly from `client_certificates\`:
  - `client.pfx`: Client private key and certificate bundle (password: `Simple123!`).
  - `client.crt`: Client public certificate.
  - `server.crt`: Server public certificate.
- Handles mutual TLS via native Delphi event callbacks:
  - `OnNeedClientCertificate`: Automatically supplies the matching client certificate from the imported PFX store.
  - `OnValidateServerCertificate`: Accepts the pinned server certificate.
- Performs secure GET request to `https://localhost:8454/api/secret-data` and displays server response.

---

## 2. Implemented Standards & RFC Specifications

The mutual TLS implementation in **GHttpsIOCPSvr** complies with the following Internet Engineering Task Force (IETF) RFC specifications defining client certificate authentication:

*   **[RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) (TLS 1.3):** Core TLS 1.3 mutual handshake negotiation, `CertificateRequest` (§4.3.2), client `Certificate` (§4.4.2), and `CertificateVerify` (§4.4.3) signature verification.
*   **[RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246) (TLS 1.2):** TLS 1.2 client certificate request (§7.4.4) and mutual certificate exchange (§7.4.6).
*   **[RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) (X.509 PKI):** X.509 v3 certificate structure, SHA-256 fingerprint generation, and Extended Key Usage for Client Authentication (`id-kp-clientAuth`, OID `1.3.6.1.5.5.7.3.2`).

---

## 3. How to Run

### Step 1: Generate Demonstration Certificates (PowerShell)
```powershell
# Run PowerShell in DEMO\11_mTLSAuthSimpleServerAndClient
./setup_pendrive_certs.ps1
```
This script creates:
- RSA 2048-bit server certificate and installs it into `Cert:\CurrentUser\GHttpsIOCPSvr`.
- RSA 2048-bit client certificate and exports `client.pfx` (password: `Simple123!`).
- Computes true SHA-256 fingerprint into `server_certificates\client.sha256`.
- Automatically copies certificate folders into `Win64\Debug\`.


