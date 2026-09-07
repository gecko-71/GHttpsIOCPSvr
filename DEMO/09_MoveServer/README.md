# DEMO 09: Dynamic HLS Live Cinema & WebTransport Server

A high-performance, multi-threaded continuous live TV broadcast server implementing HTTP Live Streaming (HLS, RFC 8216) and WebTransport over HTTP/3 (RFC 9220), built entirely on top of **GHttpsServerIOCP** in Delphi.

## Key Features

### 1. Native Delphi In-RAM MPEG-TS Engine

* **On-the-Fly TS Demuxing**: Parses 188-byte MPEG-TS packets, Program Association Tables (PAT), Program Map Tables (PMT), and H.264 SPS/IDR boundaries natively in pure Delphi without external binaries.
* **Continuous Timeline Rewriting**: Re-calculates and rewrites Program Clock Reference (PCR), Presentation Time Stamps (PTS), and Decode Time Stamps (DTS) in memory, ensuring infinite smooth looping without playback freezes or PTS discontinuities.
* **Dynamic Sliding Window**: Generates real-time HLS manifests (`/live/stream.m3u8`) with a sliding window of 5 active segments out of 15 total rotating segments.

### 2. Dual Protocol Streaming (HTTP/2 vs WebTransport)

* **HTTP/2 (TCP / TLS 1.3 / SChannel)**: Standard HLS video delivery via native Windows SChannel.
* **WebTransport over HTTP/3 (QUIC / UDP)**: Next-generation ultra-low-latency transport using Microsoft `msquic.dll`.
* **RFC 9220 WebTransport Session Management**: Full compliance with RFC 9220 draft framing over dedicated QUIC CONNECT streams (Stream 0). Separates the protocol-level wire Stream ID from unique sequential server session tracking IDs.

### 3. Real-Time Telemetry & Viewer Tracking

* **WebSocket Channel (`/status-ws`)**: Broadcasts server uptime, active viewers, and transport statistics every second.
* **WebTransport Bidirectional Streams (`/live-transport`)**: Low-overhead telemetry exchange over QUIC datagrams and bidirectional streams.

---

## Endpoints & Routes

| Endpoint | Protocol | Purpose |
| :--- | :--- | :--- |
| `/` | HTTP/1.1, HTTP/2, HTTP/3 | Web application interface with live video player and telemetry dashboard |
| `/live/stream.m3u8` | HTTP/1.1, HTTP/2, HTTP/3 | Dynamic HLS M3U8 live playlist (RFC 8216) |
| `/live/segment_X.ts` | HTTP/1.1, HTTP/2, HTTP/3 | Dynamic In-Memory MPEG-TS live video chunk |
| `/api/time` | HTTP/1.1, HTTP/2, HTTP/3 | Current server master broadcast timestamp |
| `/status-ws` | WebSocket (`wss://`) | Real-time broadcast telemetry and viewer count |
| `/live-transport` | WebTransport (QUIC) | WebTransport over HTTP/3 bidirectional channel |

---

## Building and Running

### Prerequisites

* 64-bit Windows 10, 11, or Windows Server.
* Delphi 10.4 Sydney, 11 Alexandria, or 12 Athens (Win64 target).
* `msquic.dll` (64-bit) placed in the executable directory.
* Valid W3C WebTransport certificate generated via `.\gen_w3c_wt_cert.ps1`.

### Certificate Setup (`gen_w3c_wt_cert.ps1`)

DEMO 09 utilizes **WebTransport over HTTP/3 (QUIC / UDP)** for real-time video control and telemetry. Chromium-based browsers (Google Chrome, Microsoft Edge) strictly validate certificates used in WebTransport connections:

* **W3C WebTransport Specification (Section 3.3)**: When connecting via `new WebTransport(url, { serverCertificateHashes: [...] })`, the specification strictly mandates:
  1. **Key Algorithm**: **ECDSA P-256 (`secp256r1`)** (RSA keys are explicitly forbidden by W3C for hash-pinned certificates).
  2. **Validity Period**: **Maximum 14 days** (2 weeks).
  3. **Certificate Hash**: SHA-256 fingerprint verified dynamically via `/api/certificate-hash`.
* **Zero Browser Flags**: This setup allows standard Chrome and Edge browsers to establish WebTransport connections on `localhost` out-of-the-box without requiring `--enable-webtransport-developer-mode`.

#### Generate Certificate

Open PowerShell as Administrator from the project root directory:

```powershell
.\gen_w3c_wt_cert.ps1
```

> **Note on `gen_quic_cert.ps1` vs `gen_w3c_wt_cert.ps1`**:
> The repository also includes `gen_quic_cert.ps1`, which creates an RSA 2048 certificate valid for 5 years. While suitable for standard HTTPS and CLI benchmarking tools, it will be rejected by the browser's WebTransport engine. Always use `gen_w3c_wt_cert.ps1` for DEMO 09.

### Running the Server

The server listens on:

* **HTTPS / HTTP/2**: `https://localhost:8089/`
* **HTTP/3 (QUIC / UDP)**: `https://localhost:8089/`
* **Port**: `8089` (default)


### External Media Player Playback (VLC / MPV)

Open Network Stream in VLC or MPV:

```text
https://localhost:8089/live/stream.m3u8
```
