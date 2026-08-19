document.addEventListener('DOMContentLoaded', () => {
  const btnProtocol = document.getElementById('btnProtocol');
  const btnBroadcast = document.getElementById('btnBroadcast');
  const outputLog = document.getElementById('outputLog');
  const wsBadge = document.getElementById('wsBadge');

  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/ws`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    wsBadge.innerText = 'WS CONNECTED';
    wsBadge.style.background = '#22c55e';
    outputLog.innerText += '\n[WS] Connected to Tri-Protocol WebSocket Hub.';
    ws.send('ping');
  };

  ws.onmessage = (event) => {
    outputLog.innerText += `\n[WS RECV] ${event.data}`;
  };

  ws.onclose = () => {
    wsBadge.innerText = 'WS DISCONNECTED';
    wsBadge.style.background = '#ef4444';
  };

  btnProtocol.addEventListener('click', () => {
    fetch('/api/protocol')
      .then(res => {
        const altSvc = res.headers.get('Alt-Svc');
        return res.json().then(data => ({ status: res.status, altSvc, data }));
      })
      .then(res => {
        outputLog.innerText += `\n[REST GET] HTTP ${res.status} Protocol Inspection:\nAlt-Svc: ${res.altSvc}\nData: ${JSON.stringify(res.data, null, 2)}`;
      });
  });

  btnBroadcast.addEventListener('click', () => {
    fetch('/api/broadcast', { method: 'POST' })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(res => {
        outputLog.innerText += `\n[REST POST] Broadcast Trigger Result:\nData: ${JSON.stringify(res.data, null, 2)}`;
      });
  });
});
