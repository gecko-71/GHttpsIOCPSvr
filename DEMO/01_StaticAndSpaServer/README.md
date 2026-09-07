# DEMO 01: Static File Server & SPA Fallback Router

A demo server for secure and efficient hosting of static files (HTML5, CSS3, JavaScript, images) with automatic route fallback for Single Page Applications (SPA).

---

## Key Features
- **Static File Hosting**: Automatic MIME type detection based on file extensions.
- **ETag Caching**: Returns `304 Not Modified` when the `If-None-Match` header matches the current ETag.
- **SPA Fallback Router**: All requests to dynamic paths (e.g. `/dashboard`, `/settings`) return `index.html`.

## Getting Started
1. Run `StaticAndSpaServer.exe`.
2. Open `https://localhost:8081/` in your browser.
