# DEMO 08: Morse Audio Radio Server

A multi-threaded Morse code radio broadcast server built on **GHttpsServerIOCP** (Delphi IOCP HTTP/HTTPS/WebSocket) with a PCM WAVE audio synthesizer and an HTML5 browser receiver featuring a 60 FPS telegraph tape visualization and Web Audio API playback.

---

## Key Features

- **Continuous Morse Broadcast (WebSocket `/morse-stream`)**:
  - A dedicated background thread (`TMorseBroadcastThread`) encodes and broadcasts a sequence of 200 English words as Morse impulses (`dit`, `dah`, `element_pause`, `letter_pause`, `word_pause`).
  - High-speed QRQ transmission (~24 WPM): `DIT_MS = 50ms`, `DAH_MS = 150ms`.
  - Real-time JSON sync frames with live active listener count (`active_listeners`).
- **PCM WAVE Audio Synthesizer (REST `/api/morse/audio`)**:
  - Generates a pure 800 Hz sine wave PCM WAV (16-bit Mono, 44.1 kHz) directly in server memory.
- **HTML5 Browser Receiver (Web Audio API / CSS3 / Canvas)**:
  - **Smooth telegraph tape**: 60 FPS canvas animation with sub-pixel smoothness (`performance.now()`).
  - **Real-time text decoding**: Scrolling text tape accumulating received letters 1:1 with a pulsing cursor.
  - **Live listener counter**: Dynamic display of connected receiver count.

---

## API Endpoints

| Endpoint | Method | Description |
|:---|:---|:---|
| `/` | `GET` | Serve the radio receiver UI (HTML/CSS/JS) from the `www` directory. |
| `/api/status` | `GET` | Server status and live listener count telemetry. |
| `/api/morse/broadcast` | `GET` | Current position and state of the ongoing Morse transmission. |
| `/api/morse/encode?text=...` | `GET` | Returns Morse element array and timing delays for given text. |
| `/api/morse/audio?text=...` | `GET` | Generated `audio/wav` file with Morse tone (800 Hz). |
| `/morse-stream` | `WebSocket` | Real-time bidirectional channel for Morse impulse transmission. |

---

## Getting Started

1. **Run**: Launch `MorseAudioServer.exe` and open `https://localhost:8088/` in your browser.
2. Click **▶ Start Radio** to begin receiving the telegraph broadcast and audio synthesis.

---

 
