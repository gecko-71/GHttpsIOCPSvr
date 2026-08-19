# DEMO 11: Tri-Protocol Hybrid Server (HTTP/1.1 + HTTP/3 + WebSocket)

A hybrid network server combining three leading transport protocols on a single port 8444.

---

## Key Features
- **Tri-Protocol Listener**: Simultaneous TCP (HTTP/1.1 and WebSocket) and UDP (HTTP/3 QUIC) listeners.
- **Alt-Svc Negotiation**: `Alt-Svc: h3=":8444"; ma=86400` response header for automatic browser QUIC upgrade.
- **Multi-Protocol Event Hub**: `POST /api/broadcast` pushes a message to all connected WebSocket clients in real time.

## Getting Started
1. Open `TriProtocolHybridServer.dproj` in RAD Studio and build (Shift+F9).
2. Run `TriProtocolHybridServer.exe`.
3. Open `https://localhost:8444/` in your browser.
