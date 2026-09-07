# DEMO 03: High-Speed File Stream & Media Server

A server designed for streaming large media files without exhausting system RAM.

---

## Key Features
- **HTTP 206 Partial Content**: `/api/media/stream` supports the `Range: bytes=start-end` header for smooth video/audio seeking and playback.
- **File Download**: `/api/download` serves binary streams with `Content-Disposition: attachment`.
- **Streaming Upload**: `/api/upload` saves incoming binary packets.

## Getting Started
1. Run `HighSpeedFileStreamServer.exe`.
2. Open `https://localhost:8083/` in your browser.
