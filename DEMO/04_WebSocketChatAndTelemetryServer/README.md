# DEMO 04: WebSocket Multi-Room Chat & IoT Telemetry Server

A real-time bidirectional communication server built on IOCP with full WebSocket protocol support.

---

## Key Features
- **Multi-Room Chat Broadcast**: A client sends a JSON frame and it is broadcast to all other connected users in the same room.
- **IoT Telemetry Broadcast**: A background thread generates sensor readings every 1000ms and pushes them to subscribed clients.
- **Heartbeat & Graceful Close**: Full support for Ping/Pong frames and safe connection teardown.

## Getting Started
1. Run `WebSocketChatAndTelemetryServer.exe`.
2. Open `https://localhost:8443/` in your browser.
