let streamState = 'offline';
let telemetryState = 'disconnected';

let player = null;
let ws = null;

let sessionTimer = null;
let sessionStartTimestamp = null;
let playerReconnectTimer = null;
let playerRetryCount = 0;
let wsReconnectTimer = null;
let wsRetryCount = 0;

let videoTransportMode = 'http';
let wtHlsSession = null;
let wtSegmentsLoaded = 0;

const offlineOverlay = document.getElementById('offlineOverlay');
const streamStateVal = document.getElementById('streamStateVal');
const uptimeVal = document.getElementById('uptimeVal');
const sessionTimeDisplay = document.getElementById('sessionTimeDisplay');
const btnStart = document.getElementById('btnStart');
const btnPause = document.getElementById('btnPause');
const btnFullscreen = document.getElementById('btnFullscreen');
const btnTransportHttp = document.getElementById('btnTransportHttp');
const btnTransportWT = document.getElementById('btnTransportWT');
const wtSegmentsLoadedVal = document.getElementById('wtSegmentsLoadedVal');
const activeVideoTransportVal = document.getElementById('activeVideoTransportVal');

function formatTime(seconds) {
  if (isNaN(seconds) || seconds < 0) seconds = 0;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function startSessionTimer() {
  if (sessionTimer) return;
  if (!sessionStartTimestamp) {
    sessionStartTimestamp = Date.now();
  }
  sessionTimer = setInterval(() => {
    if (!sessionStartTimestamp || streamState !== 'live') return;
    if (sessionTimeDisplay && sessionTimeDisplay.dataset.synced) return;
    const elapsedSec = Math.floor((Date.now() - sessionStartTimestamp) / 1000);
    const formatted = formatTime(elapsedSec);
    if (sessionTimeDisplay) sessionTimeDisplay.innerText = formatted;
  }, 1000);
}

function stopSessionTimer() {
  if (sessionTimer) {
    clearInterval(sessionTimer);
    sessionTimer = null;
  }
}

function resetSessionTimer() {
  stopSessionTimer();
  sessionStartTimestamp = null;
  if (sessionTimeDisplay) {
    delete sessionTimeDisplay.dataset.synced;
    sessionTimeDisplay.innerText = '00:00:00';
  }
}

function updateControls(isPlaying) {
  if (isPlaying) {
    if (btnStart) {
      btnStart.disabled = true;
      btnStart.classList.remove('active');
    }
    if (btnPause) {
      btnPause.disabled = false;
      btnPause.classList.add('active');
    }
  } else {
    if (btnStart) {
      btnStart.disabled = false;
      btnStart.classList.add('active');
    }
    if (btnPause) {
      btnPause.disabled = true;
      btnPause.classList.remove('active');
    }
  }
}

function resetControls() {
  if (btnStart) {
    btnStart.disabled = true;
    btnStart.classList.remove('active');
  }
  if (btnPause) {
    btnPause.disabled = true;
    btnPause.classList.remove('active');
  }
}

function setStreamState(newState) {
  if (streamState === newState) return;
  console.log(`[Player State] Video stream transition: ${streamState} -> ${newState}`);
  streamState = newState;

  switch (streamState) {
    case 'live':
      if (offlineOverlay) offlineOverlay.classList.add('hidden');
      if (streamStateVal) {
        streamStateVal.innerText = 'LIVE HLS BROADCAST (VHS)';
        streamStateVal.className = 'm-val highlight-green';
      }
      updateControls(true);
      startSessionTimer();
      playerRetryCount = 0;
      break;

    case 'loading':
      if (offlineOverlay) offlineOverlay.classList.add('hidden');
      if (streamStateVal) {
        streamStateVal.innerText = 'BUFFERING LIVE EDGE...';
        streamStateVal.className = 'm-val highlight-yellow';
      }
      break;

    case 'error':
    case 'offline':
    default:
      if (offlineOverlay) offlineOverlay.classList.remove('hidden');
      if (streamStateVal) {
        streamStateVal.innerText = 'OFFLINE (NO SIGNAL)';
        streamStateVal.className = 'm-val highlight';
      }
      updateControls(false);
      stopSessionTimer();
      break;
  }
}

function schedulePlayerReconnect() {
  if (playerReconnectTimer) return;
  playerRetryCount++;
  const delay = Math.min(1000 * Math.pow(1.5, playerRetryCount - 1), 5000);
  console.log(`[Player] Scheduling reconnect in ${delay}ms (attempt #${playerRetryCount})...`);
  playerReconnectTimer = setTimeout(() => {
    playerReconnectTimer = null;
    startPlayer();
  }, delay);
}

function stopPlayer() {
  if (playerReconnectTimer) {
    clearTimeout(playerReconnectTimer);
    playerReconnectTimer = null;
  }
  if (player) {
    try {
      player.pause();
    } catch (e) {}
  }
  setStreamState('offline');
}

async function getOrInitWebTransportHls() {
  if (wtHlsSession && wtHlsSession.ready) {
    return wtHlsSession;
  }
  if (wt && wt.ready) {
    wtHlsSession = wt;
    return wtHlsSession;
  }

  try {
    const hashResp = await fetch('/api/certificate-hash');
    if (!hashResp.ok) throw new Error('Failed to fetch certificate hash');
    const hashData = await hashResp.json();
    const hex = hashData.sha256;
    const certHash = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const wtUrl = `https://${window.location.hostname}:${window.location.port || 8089}/status-wt`;
    const newWt = new WebTransport(wtUrl, {
      serverCertificateHashes: [{ algorithm: 'sha-256', value: certHash }]
    });
    await newWt.ready;
    wtHlsSession = newWt;
    return wtHlsSession;
  } catch (err) {
    console.warn('[WebTransport HLS] Session init error:', err);
    return null;
  }
}

async function fetchViaWebTransportStream(targetUrl) {
  const session = await getOrInitWebTransportHls();
  if (!session) throw new Error('WebTransport not available');

  const bidi = await session.createBidirectionalStream();
  const writer = bidi.writable.getWriter();
  const reader = bidi.readable.getReader();

  const reqCmd = `GET ${targetUrl}\n`;
  await writer.write(new TextEncoder().encode(reqCmd));
  await writer.close();

  const chunks = [];
  let totalLength = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      totalLength += value.byteLength;
    }
  }

  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

function initPlayer() {
  if (player) return;

  player = videojs('moviePlayer', {
    autoplay: true,
    muted: true,
    controls: false,
    preload: 'auto',
    fluid: false,
    liveui: true,
    liveTracker: {
      trackingThreshold: 0,
      liveTolerance: 1.0
    },
    html5: {
      vhs: {
        overrideNative: true
      }
    }
  });

  player.on('playing', () => {
    isUserPaused = false;
    setStreamState('live');
    updateControls(true);
    tryInitialSync();
  });

  player.on('pause', () => {
    if (isUserPaused) {
      updateControls(false);
    }
  });

  player.on('loadedmetadata', () => {
    if (!isUserPaused && player.paused()) {
      player.play().catch(() => {});
    }
    tryInitialSync();
  });

  player.on('canplay', () => {
    if (!isUserPaused && player.paused()) {
      player.play().catch(() => {});
    }
    tryInitialSync();
  });

  player.on('waiting', () => {
    if (streamState === 'live') {
      setStreamState('loading');
    }
  });

  player.on('error', () => {
    console.warn('[VideoJS] Error event encountered.');
    setStreamState('offline');
    updateControls(false);
    schedulePlayerReconnect();
  });
}

function startPlayer() {
  hasInitialSynced = false;
  initPlayer();
  setStreamState('loading');

  const streamUrl = '/live/stream.m3u8';
  player.src({
    src: streamUrl,
    type: 'application/x-mpegURL'
  });

  player.ready(() => {
    player.muted(true);
    const playPromise = player.play();
    if (playPromise !== undefined) {
      playPromise.then(() => {
        updateControls(true);
      }).catch(err => {
        console.warn('[VideoJS] Autoplay note:', err);
      });
    }
  });
}

function setVideoTransport(mode) {
  if (videoTransportMode === mode) return;
  videoTransportMode = mode;
  console.log(`[Transport Switch] Switched to: ${videoTransportMode}`);

  if (btnTransportHttp && btnTransportWT) {
    if (videoTransportMode === 'webtransport') {
      btnTransportHttp.className = 'transport-btn';
      btnTransportWT.className = 'transport-btn active-wt';
      if (activeVideoTransportVal) {
        activeVideoTransportVal.innerText = 'WebTransport (QUIC/UDP)';
        activeVideoTransportVal.className = 'm-val highlight-green';
      }
    } else {
      btnTransportHttp.className = 'transport-btn active-tcp';
      btnTransportWT.className = 'transport-btn';
      if (activeVideoTransportVal) {
        activeVideoTransportVal.innerText = 'HTTP/2 (TCP)';
        activeVideoTransportVal.className = 'm-val highlight-cyan';
      }
    }
  }

  startPlayer();
}

if (btnStart) {
  btnStart.addEventListener('click', () => {
    isUserPaused = false;
    if (player) {
      player.play().then(() => {
        updateControls(true);
        performLiveSync();
      }).catch(err => {
        console.warn('[VideoJS] Play error:', err);
      });
    } else {
      startPlayer();
    }
  });
}

if (btnPause) {
  btnPause.addEventListener('click', () => {
    console.log('[Controls] PAUSE clicked: pausing live playback...');
    isUserPaused = true;
    if (player) {
      player.pause();
    }
    updateControls(false);
  });
}

if (btnFullscreen) {
  btnFullscreen.addEventListener('click', () => {
    const container = document.querySelector('.video-container');
    if (!container) return;
    if (!document.fullscreenElement) {
      container.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  });
}

if (btnTransportHttp) {
  btnTransportHttp.addEventListener('click', () => setVideoTransport('http'));
}

if (btnTransportWT) {
  btnTransportWT.addEventListener('click', () => setVideoTransport('webtransport'));
}

function setTelemetryState(newState) {
  telemetryState = newState;
  console.log(`[WebSocket Telemetry] Connection state: ${telemetryState}`);
}

let wsPacketCount = 0;
let wt = null;
let wtDatagramCount = 0;
let wtRetryCount = 0;
let wtReconnectTimer = null;
let syncRole = 'slave';
let isUserPaused = false;
let syncTickInterval = null;
let sync30sInterval = null;
let hasInitialSynced = false;
let lastCorrectionTime = 0;
let lastServerSync = null;

function tryInitialSync() {
  if (hasInitialSynced) return;
  if (!player || player.paused()) return;
  const seekable = player.seekable();
  if (!seekable || seekable.length === 0) return;
  const maxTime = seekable.end(seekable.length - 1);
  const minTime = seekable.start(0);
  if (maxTime - minTime < 2.0) return;

  performLiveSync();
  const curBehind = maxTime - (player.currentTime() || 0);
  if (Math.abs(curBehind - 2.0) <= 0.4) {
    hasInitialSynced = true;
  }
}

function performLiveSync() {
  if (!player || isUserPaused) return;
  const seekable = player.seekable();
  if (!seekable || seekable.length === 0) return;
  const liveEdge = seekable.end(seekable.length - 1);
  const minTime = seekable.start(0);
  const targetTime = Math.max(minTime, liveEdge - 2.0);
  player.currentTime(targetTime);
  player.playbackRate(1.0);
}

function correctToServerLivePosition(serverSync, applyCorrection = false) {
  if (!player) return;
  if (typeof player.currentTime !== 'function') return;

  const seekable = player.seekable();
  if (!seekable || seekable.length === 0) return;

  const liveEdge = seekable.end(seekable.length - 1);
  const minTime = seekable.start(0);
  const curTime = player.currentTime() || 0;
  const behindLive = liveEdge - curTime;
  const drift = 2.0 - behindLive;

  const syncDriftVal = document.getElementById('syncDriftVal');
  if (syncDriftVal) {
    syncDriftVal.innerText = `${drift >= 0 ? '+' : ''}${drift.toFixed(2)}s`;
  }

  if (player.paused() || isUserPaused) return;

  if (applyCorrection) {
    performLiveSync();
    return;
  }

  if (behindLive > 4.0) {
    performLiveSync();
  } else if (behindLive > 2.3) {
    player.playbackRate(1.06);
  } else if (behindLive < 1.7) {
    player.playbackRate(0.94);
  } else {
    player.playbackRate(1.0);
  }
}

function connectTelemetryWebSocket() {
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  if (ws) {
    try {
      ws.close();
    } catch (e) {}
    ws = null;
  }

  const wsStatusBadge = document.getElementById('wsStatusBadge');
  const wsPacketCountEl = document.getElementById('wsPacketCount');
  const wsViewersCountEl = document.getElementById('wsViewersCount');
  const wtViewersCountEl = document.getElementById('wtViewersCount');
  const loopBadge = document.getElementById('loopBadge');

  setTelemetryState('connecting');
  if (wsStatusBadge) {
    wsStatusBadge.innerText = 'Connecting...';
    wsStatusBadge.className = 'p-status connecting';
  }

  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/status-ws`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setTelemetryState('connected');
      if (wsStatusBadge) {
        wsStatusBadge.innerText = 'Active (TCP)';
        wsStatusBadge.className = 'p-status active';
      }
      wsRetryCount = 0;

      if (syncTickInterval) clearInterval(syncTickInterval);
      syncTickInterval = setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN && player && streamState === 'live') {
          ws.send(JSON.stringify({
            type: 'tick',
            time: lastServerSync && isFinite(lastServerSync.liveElapsedSec) ? lastServerSync.liveElapsedSec : (typeof player.currentTime === 'function' ? player.currentTime() : 0),
            paused: isUserPaused
          }));
        }
      }, 500);
    };

    ws.onmessage = (event) => {
      try {
        wsPacketCount++;
        if (wsPacketCountEl) wsPacketCountEl.innerText = wsPacketCount;

        const data = JSON.parse(event.data);

        if (data.type === 'role') {
          syncRole = 'slave';
          const syncRoleBadge = document.getElementById('syncRoleBadge');
          if (syncRoleBadge) {
            syncRoleBadge.innerText = 'SERVER MASTER';
            syncRoleBadge.className = 'p-status active';
          }
          return;
        }

        if (data.type === 'sync') {
          return;
        }

        if (data.uptime_sec !== undefined || data.live_position_sec !== undefined) {
          lastServerSync = {
            liveElapsedSec: Number(data.uptime_sec),
            livePositionSec: Number(data.live_position_sec),
            totalDurationSec: Number(data.total_duration_sec) || 0,
            receivedAt: Date.now()
          };
          if (streamState === 'live') {
            if (!hasInitialSynced) {
              tryInitialSync();
            } else {
              correctToServerLivePosition(lastServerSync, false);
            }
          }
        }
        if (data.uptime_sec !== undefined) {
          const formattedUptime = formatTime(data.uptime_sec);
          if (uptimeVal) uptimeVal.innerText = formattedUptime;
          if (sessionTimeDisplay) {
            sessionTimeDisplay.innerText = formattedUptime;
            sessionTimeDisplay.dataset.synced = 'true';
          }
        }
        if (data.ws_viewers !== undefined && wsViewersCountEl) {
          wsViewersCountEl.innerText = data.ws_viewers;
        }
        if (data.wt_viewers !== undefined && wtViewersCountEl) {
          wtViewersCountEl.innerText = data.wt_viewers;
        }
        if (data.loop_number !== undefined && loopBadge) {
          loopBadge.innerText = `Loop #${data.loop_number + 1}`;
        }
      } catch (e) {
        console.error('[WebSocket] JSON parse error:', e);
      }
    };

    ws.onclose = () => {
      if (syncTickInterval) {
        clearInterval(syncTickInterval);
        syncTickInterval = null;
      }
      setTelemetryState('disconnected');
      if (wsStatusBadge) {
        wsStatusBadge.innerText = 'Disconnected';
        wsStatusBadge.className = 'p-status disconnected';
      }
      const delay = Math.min(15000, 1000 * Math.pow(2, wsRetryCount));
      wsRetryCount++;
      wsReconnectTimer = setTimeout(connectTelemetryWebSocket, delay);
    };

    ws.onerror = (err) => {
      console.warn('[WebSocket] Telemetry connection error:', err);
    };

  } catch (e) {
    setTelemetryState('disconnected');
    if (wsStatusBadge) {
      wsStatusBadge.innerText = 'Error';
      wsStatusBadge.className = 'p-status disconnected';
    }
    wsReconnectTimer = setTimeout(connectTelemetryWebSocket, 3000);
  }
}

async function connectTelemetryWebTransport() {
  if (wtReconnectTimer) {
    clearTimeout(wtReconnectTimer);
    wtReconnectTimer = null;
  }
  if (wt) {
    try { wt.close(); } catch (e) {}
    wt = null;
  }

  const wtStatusBadge = document.getElementById('wtStatusBadge');
  const wtDatagramCountEl = document.getElementById('wtDatagramCount');
  const wtViewersCountEl = document.getElementById('wtViewersCount');
  const loopBadge = document.getElementById('loopBadge');

  if (!window.WebTransport) {
    if (wtStatusBadge) {
      wtStatusBadge.innerText = 'Unsupported';
      wtStatusBadge.className = 'p-status unsupported';
    }
    console.warn('[WebTransport] Browser does not support WebTransport API');
    return;
  }

  if (wtStatusBadge) {
    wtStatusBadge.innerText = 'Connecting...';
    wtStatusBadge.className = 'p-status connecting';
  }

  const wtUrl = `https://${window.location.host}/status-wt`;
  try {
    let wtOptions = undefined;
    try {
      const res = await fetch('/api/certificate-hash');
      if (res.ok) {
        const data = await res.json();
        if (data && data.hash && Array.isArray(data.hash) && data.hash.length === 32) {
          const certHash = new Uint8Array(data.hash);
          wtOptions = {
            serverCertificateHashes: [{ algorithm: 'sha-256', value: certHash }]
          };
        }
      }
    } catch (fetchErr) {
      console.warn('[WebTransport] Certificate hash fetch error:', fetchErr);
    }

    wt = wtOptions ? new WebTransport(wtUrl, wtOptions) : new WebTransport(wtUrl);
    await wt.ready;
    console.log('[WebTransport] Connected to HTTP/3 WebTransport session!');
    if (wtStatusBadge) {
      wtStatusBadge.innerText = 'Active (QUIC)';
      wtStatusBadge.className = 'p-status active-wt';
    }
    wtRetryCount = 0;

    (async () => {
      const reader = wt.datagrams.readable.getReader();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          wtDatagramCount++;
          if (wtDatagramCountEl) wtDatagramCountEl.innerText = wtDatagramCount;

          try {
            const text = new TextDecoder().decode(value);
            const data = JSON.parse(text);
            if (data.uptime_sec !== undefined || data.live_position_sec !== undefined) {
              lastServerSync = {
                liveElapsedSec: Number(data.uptime_sec),
                livePositionSec: Number(data.live_position_sec),
                totalDurationSec: Number(data.total_duration_sec) || 0,
                receivedAt: Date.now()
              };
              if (streamState === 'live') {
                if (!hasInitialSynced) {
                  tryInitialSync();
                } else {
                  correctToServerLivePosition(lastServerSync, false);
                }
              }
            }
            if (data.uptime_sec !== undefined) {
              const formattedUptime = formatTime(data.uptime_sec);
              if (uptimeVal) uptimeVal.innerText = formattedUptime;
              if (sessionTimeDisplay) {
                sessionTimeDisplay.innerText = formattedUptime;
                sessionTimeDisplay.dataset.synced = 'true';
              }
            }
            if (data.wt_viewers !== undefined && wtViewersCountEl) {
              wtViewersCountEl.innerText = data.wt_viewers;
            }
            if (data.loop_number !== undefined && loopBadge) {
              loopBadge.innerText = `Loop #${data.loop_number + 1}`;
            }
          } catch (err) {
            console.error('[WebTransport] Datagram JSON parse error:', err);
          }
        }
      } catch (err) {
        console.warn('[WebTransport] Datagram reader closed:', err);
      } finally {
        reader.releaseLock();
      }
    })();

    wt.closed.then(() => {
      scheduleWtReconnect();
    }).catch(() => {
      scheduleWtReconnect();
    });

  } catch (err) {
    console.warn('[WebTransport] Connection error:', err);
    scheduleWtReconnect();
  }
}

function scheduleWtReconnect() {
  const wtStatusBadge = document.getElementById('wtStatusBadge');
  if (wtStatusBadge) {
    if (wtRetryCount >= 2) {
      wtStatusBadge.innerText = 'Standby';
      wtStatusBadge.className = 'p-status disconnected';
      wtStatusBadge.title = 'WebTransport connection standby';
    } else {
      wtStatusBadge.innerText = 'Connecting...';
      wtStatusBadge.className = 'p-status connecting';
    }
  }
  const delay = Math.min(30000, 3000 * Math.pow(1.5, Math.min(wtRetryCount, 5)));
  wtRetryCount++;
  wtReconnectTimer = setTimeout(connectTelemetryWebTransport, delay);
}

window.addEventListener('beforeunload', () => {
  if (syncTickInterval) clearInterval(syncTickInterval);
  if (sync30sInterval) clearInterval(sync30sInterval);
  stopSessionTimer();
  if (playerReconnectTimer) clearTimeout(playerReconnectTimer);
  if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
  if (wtReconnectTimer) clearTimeout(wtReconnectTimer);
  if (ws && ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify({ type: 'leave' })); } catch (e) {}
  }
  if (player) {
    try { player.dispose(); } catch (e) {}
  }
  if (ws) ws.close();
  if (wt) {
    try { wt.close(); } catch (e) {}
  }
});

window.addEventListener('DOMContentLoaded', () => {
  resetSessionTimer();
  resetControls();
  startPlayer();
  connectTelemetryWebSocket();
  connectTelemetryWebTransport();
  if (sync30sInterval) clearInterval(sync30sInterval);
  sync30sInterval = setInterval(() => {
    if (player && streamState === 'live' && !isUserPaused) {
      performLiveSync();
    }
  }, 30000);
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && player && !player.paused() && !isUserPaused) {
    performLiveSync();
  }
});
