# DEMO 05: HTTP/3 QUIC Speed Server

A server demonstrating dual-stack transport over both TCP (HTTP/1.1) and UDP (HTTP/3 QUIC) on the same port.

---

## Key Features
- **Dual-Stack Transport**: Simultaneous TCP socket (HTTP/1.1) and UDP socket (HTTP/3 QUIC) listeners.
- **Alt-Svc Negotiation**: The `Alt-Svc: h3=":8443"; ma=86400` response header advertises QUIC support to browsers.
- **Benchmarking**: `/api/http3/ping` and `/api/http3/benchmark` endpoints for protocol performance comparison.

## Getting Started
1. Open `Http3QuicSpeedServer.dproj` in RAD Studio and build (Shift+F9).
2. Run `Http3QuicSpeedServer.exe`.
3. Open `https://localhost:8443/` in your browser.
