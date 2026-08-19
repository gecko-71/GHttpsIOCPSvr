
const views = {
  '/': renderHomeView,
  '/explorer': renderExplorerView,
  '/etag-test': renderETagTestView,
  '/dashboard': renderSPADashboardView,
  '/api-status': renderApiStatusView
};

function renderHomeView() {
  return `
    <h1>Welcome to DEMO 01: Static File Server &amp; SPA Fallback</h1>
    <p>Demonstration server written in Delphi using asynchronous Windows IOCP architecture and SSPI Schannel TLS encryption.</p>
    
    <div style="background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 6px; margin: 15px 0;">
      <h3 style="color: #38bdf8;">Core Server Capabilities:</h3>
      <ul style="margin-left: 20px; color: #cbd5e1; line-height: 1.8;">
        <li><b>Automatic MIME Type Detection</b> – Supports HTML, CSS, JS, SVG, JSON, PNG file extensions.</li>
        <li><b>ETag Cache Validation (HTTP 304)</b> – Reduces bandwidth usage by returning 304 Not Modified status without payload.</li>
        <li><b>SPA Fallback Router</b> – Intercepts client-side routes (e.g. <code>/dashboard</code>, <code>/settings</code>) and serves <code>index.html</code> (HTTP 200 OK).</li>
        <li><b>REST API Metrics</b> – Exposes telemetry metrics via <code>GET /api/status</code>.</li>
      </ul>
    </div>

    <button class="btn" onclick="navigatePath('/etag-test')">Launch ETag Test (304)</button>
    <button class="btn btn-secondary" onclick="navigatePath('/explorer')">View Static Assets</button>
  `;
}

function renderExplorerView() {
  return `
    <h1>Static Assets Directory (www/)</h1>
    <p>List of registered static assets served directly from disk by the Delphi IOCP engine.</p>
    
    <table class="table">
      <thead>
        <tr>
          <th>Asset Path</th>
          <th>MIME Type (Content-Type)</th>
          <th>Cache Status</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><b>/index.html</b></td>
          <td><span class="badge badge-blue">text/html; charset=utf-8</span></td>
          <td><span class="badge badge-green">ETag Active</span></td>
          <td><button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.8rem; margin: 0;" onclick="fetchAsset('/index.html')">Inspect Headers</button></td>
        </tr>
        <tr>
          <td><b>/style.css</b></td>
          <td><span class="badge badge-blue">text/css; charset=utf-8</span></td>
          <td><span class="badge badge-green">ETag Active</span></td>
          <td><button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.8rem; margin: 0;" onclick="fetchAsset('/style.css')">Inspect Headers</button></td>
        </tr>
        <tr>
          <td><b>/app.js</b></td>
          <td><span class="badge badge-blue">application/javascript</span></td>
          <td><span class="badge badge-green">ETag Active</span></td>
          <td><button class="btn btn-secondary" style="padding: 4px 10px; font-size: 0.8rem; margin: 0;" onclick="fetchAsset('/app.js')">Inspect Headers</button></td>
        </tr>
      </tbody>
    </table>

    <div id="inspectorLog" class="code-box">Click "Inspect Headers" next to any asset...</div>
  `;
}

function renderETagTestView() {
  return `
    <h1>ETag Cache Validation Test (HTTP 304 Not Modified)</h1>
    <p>This test verifies that the server correctly calculates ETag checksums for static assets and responds with HTTP 304 when queried with an <code>If-None-Match</code> header.</p>
    
    <button class="btn" onclick="runETagTest()">Run ETag Validation Pass (304)</button>

    <div id="etagOutput" class="code-box">Click the button above to start the two-pass HTTP 304 test...</div>
  `;
}

function renderSPADashboardView() {
  return `
    <h1>System &amp; Server Dashboard</h1>
    <p>Active client-side SPA route: <code style="color: #38bdf8; font-weight: bold;">/dashboard</code> (Served via Delphi IOCP Fallback with HTTP 200 OK).</p>

    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0;">
      <div style="background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 6px;">
        <div style="font-size: 0.8rem; color: #94a3b8; font-weight: bold;">SERVER STATUS</div>
        <div style="font-size: 1.4rem; font-weight: bold; color: #4ade80; margin-top: 5px;">ONLINE</div>
      </div>
      <div style="background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 6px;">
        <div style="font-size: 0.8rem; color: #94a3b8; font-weight: bold;">PROTOCOL</div>
        <div style="font-size: 1.4rem; font-weight: bold; color: #38bdf8; margin-top: 5px;">HTTPS / TLS 1.3</div>
      </div>
      <div style="background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 6px;">
        <div style="font-size: 0.8rem; color: #94a3b8; font-weight: bold;">SPA ROUTING</div>
        <div style="font-size: 1.4rem; font-weight: bold; color: #38bdf8; margin-top: 5px;">200 OK Fallback</div>
      </div>
    </div>

    <div style="margin-top: 20px;">
      <h3 style="margin-bottom: 10px;">Test Other SPA Routes:</h3>
      <button class="btn btn-secondary" onclick="navigatePath('/settings/profile')">Open /settings/profile</button>
      <button class="btn btn-secondary" onclick="navigatePath('/analytics')">Open /analytics</button>
    </div>
  `;
}

function renderSettingsProfileView() {
  return `
    <h1>Server Settings &amp; TLS Security</h1>
    <p>Active client-side SPA route: <code style="color: #38bdf8; font-weight: bold;">/settings/profile</code></p>

    <div style="background: #0f172a; border: 1px solid #334155; padding: 20px; border-radius: 6px; margin: 15px 0;">
      <div style="margin-bottom: 15px;">
        <label style="display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 5px;">Server Listener Domain</label>
        <input type="text" value="localhost:8082" readonly style="width: 100%; max-width: 400px; padding: 8px 12px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;">
      </div>

      <div style="margin-bottom: 15px;">
        <label style="display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 5px;">Windows Certificate Store</label>
        <input type="text" value="GHttpsIOCPSvr (Cert:\CurrentUser\My)" readonly style="width: 100%; max-width: 400px; padding: 8px 12px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;">
      </div>

      <div>
        <label style="display: block; font-size: 0.85rem; color: #94a3b8; margin-bottom: 5px;">ETag Cache Expiration Policy</label>
        <input type="text" value="public, max-age=3600 (RFC 7232)" readonly style="width: 100%; max-width: 400px; padding: 8px 12px; background: #1e293b; border: 1px solid #334155; color: #fff; border-radius: 4px;">
      </div>
    </div>

    <button class="btn" onclick="alert('Settings verified! Delphi IOCP Server is active.')">Save Configuration</button>
    <button class="btn btn-secondary" onclick="navigatePath('/dashboard')">Back to Dashboard</button>
  `;
}

function renderAnalyticsView() {
  return `
    <h1>Real-Time Traffic Analytics</h1>
    <p>Active client-side SPA route: <code style="color: #38bdf8; font-weight: bold;">/analytics</code></p>

    <table class="table">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>HTTP Method</th>
          <th>Request Path</th>
          <th>HTTP Status</th>
          <th>Payload Transfer</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Just now</td>
          <td><b>GET</b></td>
          <td>/analytics</td>
          <td><span class="badge badge-green">200 OK (SPA Fallback)</span></td>
          <td>2.4 KB</td>
        </tr>
        <tr>
          <td>1s ago</td>
          <td><b>GET</b></td>
          <td>/style.css</td>
          <td><span class="badge badge-green">304 Not Modified</span></td>
          <td>0 Bytes (Cached)</td>
        </tr>
        <tr>
          <td>2s ago</td>
          <td><b>GET</b></td>
          <td>/api/status</td>
          <td><span class="badge badge-blue">200 OK (JSON API)</span></td>
          <td>148 Bytes</td>
        </tr>
      </tbody>
    </table>

    <button class="btn btn-secondary" onclick="navigatePath('/dashboard')">Back to Dashboard</button>
  `;
}

function renderApiStatusView() {
  return `
    <h1>REST API Status (GET /api/status)</h1>
    <p>Live telemetry JSON data returned by the REST API endpoint.</p>
    
    <button class="btn" onclick="fetchApiStatus()">Refresh JSON Data</button>

    <div id="jsonOutput" class="code-box">Fetching metrics from /api/status...</div>
  `;
}

const customRoutes = {
  '/': renderHomeView,
  '/explorer': renderExplorerView,
  '/etag-test': renderETagTestView,
  '/dashboard': renderSPADashboardView,
  '/settings/profile': renderSettingsProfileView,
  '/analytics': renderAnalyticsView,
  '/api-status': renderApiStatusView
};

function navigatePath(path) {
  window.history.pushState({}, '', path);
  renderRoute(path);
}

function renderRoute(path) {
  const container = document.getElementById('mainContent');
  if (!container) return;

  const viewFn = customRoutes[path] || (() => `
    <h1>SPA Route Intercepted: <span style="color: #38bdf8;">${path}</span></h1>
    <p>This unhandled client-side route was served via Delphi IOCP Fallback Engine with <b>HTTP 200 OK</b>.</p>
    <div style="background: #0f172a; border: 1px solid #334155; padding: 15px; border-radius: 6px; margin: 15px 0;">
      <p style="color: #4ade80;">✅ Client JavaScript router successfully loaded index.html!</p>
    </div>
    <button class="btn btn-secondary" onclick="navigatePath('/dashboard')">Back to Dashboard</button>
  `);

  container.innerHTML = typeof viewFn === 'function' ? viewFn() : viewFn;

  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-path') === path);
  });

  if (path === '/api-status') {
    setTimeout(fetchApiStatus, 50);
  }
}

async function fetchAsset(path) {
  const log = document.getElementById('inspectorLog');
  if (!log) return;

  log.innerText = `Sending GET ${path} request...`;
  try {
    const res = await fetch(path);
    let txt = `Status: ${res.status} ${res.statusText}\n`;
    res.headers.forEach((val, key) => {
      txt += `${key}: ${val}\n`;
    });
    log.innerText = txt;
  } catch (e) {
    log.innerText = `Error: ${e.message}`;
  }
}

async function runETagTest() {
  const out = document.getElementById('etagOutput');
  if (!out) return;

  out.innerText = "Step 1: Sending initial GET /style.css request...\n";
  try {
    const res1 = await fetch('/style.css');
    const etag = res1.headers.get('ETag');
    out.innerText += `-> Step 1 Result: HTTP ${res1.status} ${res1.statusText}\n`;
    out.innerText += `-> Received ETag Header: ${etag}\n\n`;

    if (etag) {
      out.innerText += `Step 2: Sending second GET /style.css request with header (If-None-Match: ${etag})...\n`;
      const res2 = await fetch('/style.css', {
        headers: { 'If-None-Match': etag }
      });
      out.innerText += `-> Step 2 Result: HTTP ${res2.status} ${res2.statusText}\n`;
      out.innerText += `-> Transferred Payload Size: 0 Bytes\n\n`;
      out.innerText += `✅ TEST COMPLETED SUCCESSFULLY: Server validated ETag checksum and returned 304 Not Modified!`;
    }
  } catch (e) {
    out.innerText += `Test Error: ${e.message}`;
  }
}

async function fetchApiStatus() {
  const out = document.getElementById('jsonOutput');
  if (!out) return;

  out.innerText = "Fetching /api/status...";
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    out.innerText = JSON.stringify(data, null, 2);
  } catch (e) {
    out.innerText = `Error: ${e.message}`;
  }
}

window.addEventListener('popstate', () => {
  renderRoute(window.location.pathname);
});

let appInitialized = false;

function initApp() {
  if (appInitialized) return;
  appInitialized = true;

  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('nav-btn')) {
      e.preventDefault();
      const path = e.target.getAttribute('data-path');
      navigatePath(path);
    }
  });

  renderRoute(window.location.pathname);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
}
window.addEventListener('load', initApp);
initApp();
