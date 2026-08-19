let audioCtx = null;
let masterGain = null;
let masterOsc = null;
let soundEnabled = false;

let ws = null;
let liveConnected = false;
let isTonePlaying = false;

let tapeCanvas = null;
let tapeCtx = null;

const tapeCharBuffer = [];

function initWebAudio() {
  if (!audioCtx) {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    audioCtx = new AudioContext();

    masterGain = audioCtx.createGain();
    masterGain.gain.setValueAtTime(0.0, audioCtx.currentTime);

    masterOsc = audioCtx.createOscillator();
    masterOsc.type = 'sine';
    masterOsc.frequency.setValueAtTime(800, audioCtx.currentTime);
    masterOsc.connect(masterGain);
    masterGain.connect(audioCtx.destination);
    masterOsc.start();
  }

  if (audioCtx.state === 'suspended') {
    audioCtx.resume();
  }
  soundEnabled = true;
}

function setToneState(playing) {
  isTonePlaying = playing;

  if (audioCtx && masterGain && soundEnabled) {
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    const now = audioCtx.currentTime;
    if (playing) {
      masterGain.gain.cancelScheduledValues(now);
      masterGain.gain.setValueAtTime(masterGain.gain.value, now);
      masterGain.gain.linearRampToValueAtTime(0.25, now + 0.005);
    } else {
      masterGain.gain.cancelScheduledValues(now);
      masterGain.gain.setValueAtTime(masterGain.gain.value, now);
      masterGain.gain.linearRampToValueAtTime(0.0, now + 0.005);
    }
  }
}

function resizeTapeCanvas() {
  if (tapeCanvas && tapeCanvas.parentElement) {
    const rect = tapeCanvas.getBoundingClientRect();
    if (rect.width > 0 && tapeCanvas.width !== Math.floor(rect.width)) {
      tapeCanvas.width = Math.floor(rect.width);
      tapeCanvas.height = 60;
    }
  }
}

function pushCharToTape(char, symbol) {
  const now = performance.now();
  tapeCharBuffer.push({
    char: char || '',
    symbol: symbol || '',
    time: now
  });

  while (tapeCharBuffer.length > 0 && (now - tapeCharBuffer[0].time) * 0.12 > 1400) {
    tapeCharBuffer.shift();
  }
}

function drawTelegraphTape() {
  if (!tapeCtx || !tapeCanvas) return;

  resizeTapeCanvas();

  const w = tapeCanvas.width;
  const h = tapeCanvas.height;
  const now = performance.now();
  const scrollSpeed = 0.24;

  tapeCtx.fillStyle = '#0f172a';
  tapeCtx.fillRect(0, 0, w, h);

  const stripY = 6;
  const stripH = 48;

  tapeCtx.fillStyle = '#ffffff';
  tapeCtx.fillRect(0, stripY, w, stripH);

  tapeCtx.strokeStyle = '#cbd5e1';
  tapeCtx.lineWidth = 1;
  tapeCtx.strokeRect(0, stripY, w, stripH);

  tapeCtx.beginPath();
  tapeCtx.strokeStyle = 'rgba(239, 68, 68, 0.3)';
  tapeCtx.moveTo(0, stripY + (stripH / 2));
  tapeCtx.lineTo(w, stripY + (stripH / 2));
  tapeCtx.stroke();

  const midY = stripY + (stripH / 2);
  const entryX = w - 30;

  for (let i = 0; i < tapeCharBuffer.length; i++) {
    const item = tapeCharBuffer[i];
    const elapsed = now - item.time;
    const charX = entryX - (elapsed * scrollSpeed);

    if (charX < -100 || charX > w + 100) continue;

    const symbols = item.symbol || '';
    const symbolWidth = 24;
    const startSymbolX = charX - ((symbols.length - 1) * symbolWidth / 2);

    for (let s = 0; s < symbols.length; s++) {
      const sym = symbols[s];
      const symX = startSymbolX + (s * symbolWidth);

      if (sym === '.') {
        tapeCtx.fillStyle = '#0f172a';
        tapeCtx.beginPath();
        tapeCtx.arc(symX, midY, 4, 0, Math.PI * 2);
        tapeCtx.fill();
      } else if (sym === '-') {
        tapeCtx.fillStyle = '#0f172a';
        tapeCtx.fillRect(symX - 13, midY - 3, 26, 6);
      }
    }
  }

  requestAnimationFrame(drawTelegraphTape);
}

function startBroadcast() {
  resetDecodedTextFeed();
  initWebAudio();
  if (!ws || ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
    connectLiveBroadcast();
  }
  updateButtonStates(true);
}

function stopBroadcast() {
  setToneState(false);
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    ws.close();
  }
  updateButtonStates(false);
}

function updateButtonStates(active) {
  const btnStart = document.getElementById('btnStart');
  const btnStop = document.getElementById('btnStop');

  if (btnStart && btnStop) {
    if (active) {
      btnStart.classList.add('active');
      btnStop.classList.remove('active');
    } else {
      btnStart.classList.remove('active');
      btnStop.classList.add('active');
    }
  }
}

function connectLiveBroadcast() {
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/morse-stream`;

  const liveBadge = document.getElementById('liveBadge');

  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      liveConnected = true;
      if (liveBadge) {
        liveBadge.innerHTML = 'LIVE BROADCAST';
        liveBadge.className = 'status-badge status-live';
      }
      updateButtonStates(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.event === 'sync') {
          updateLiveUI(data);
        }
      } catch (e) {
        console.error('WS Parse Error:', e);
      }
    };

    ws.onclose = () => {
      liveConnected = false;
      setToneState(false);
      if (liveBadge) {
        liveBadge.innerHTML = 'STREAM DISCONNECTED';
        liveBadge.className = 'status-badge status-offline';
      }
      updateButtonStates(false);
    };

    ws.onerror = (err) => {
      console.error('WS Error:', err);
    };
  } catch (e) {
    if (liveBadge) {
      liveBadge.innerHTML = 'CONNECTION FAILED';
      liveBadge.className = 'status-badge status-offline';
    }
  }
}

let lastElementIndex = -1;
let decodedTextHistory = '';
let characterFinished = true;
let lastPushedChar = '';

function resetDecodedTextFeed() {
  decodedTextHistory = '';
  characterFinished = true;
  lastPushedChar = '';
  const textElem = document.getElementById('broadcastText');
  if (textElem) {
    textElem.innerHTML = '';
  }
}

function appendDecodedChar(char, symbol) {
  decodedTextHistory += char;

  if (decodedTextHistory.length > 200) {
    decodedTextHistory = decodedTextHistory.slice(-200);
  }

  const textElem = document.getElementById('broadcastText');
  if (textElem) {
    const historyStr = decodedTextHistory.slice(0, -1);
    const activeChar = decodedTextHistory.slice(-1);
    textElem.innerHTML = `${historyStr}<span class="active-char-box">${activeChar}</span><span class="cursor-line">|</span>`;
    textElem.scrollLeft = textElem.scrollWidth;
  }

  if (char !== ' ') {
    pushCharToTape(char, symbol);
  }
}

function updateLiveUI(data) {
  const charElem = document.getElementById('currentChar');
  const symbolElem = document.getElementById('currentSymbol');
  const typeElem = document.getElementById('currentElement');

  const elemType = data.element_type || '';
  const currentChar = data.current_char || '';

  if (elemType === 'word_pause') {
    if (lastPushedChar !== ' ') {
      appendDecodedChar(' ', '/');
      lastPushedChar = ' ';
    }
    characterFinished = true;
  } else if (elemType === 'letter_pause') {
    characterFinished = true;
  } else if (elemType === 'dit' || elemType === 'dah') {
    if (characterFinished && currentChar && currentChar !== ' ') {
      appendDecodedChar(currentChar, data.symbol);
      lastPushedChar = currentChar;
      characterFinished = false;
    }
  }

  if (charElem) charElem.innerText = data.current_char || '-';
  if (symbolElem) symbolElem.innerText = data.symbol || '(pause)';
  if (typeElem) typeElem.innerText = data.element_type || '-';

  const activeElem = document.getElementById('activeListeners');
  if (activeElem && data.active_listeners !== undefined) {
    activeElem.innerText = data.active_listeners;
  }

  if (elemType === 'dit' || elemType === 'dah') {
    setToneState(true);
  } else {
    setToneState(false);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  tapeCanvas = document.getElementById('morseTapeCanvas');
  if (tapeCanvas) {
    tapeCtx = tapeCanvas.getContext('2d');
    resizeTapeCanvas();
    drawTelegraphTape();
  }

  const btnStart = document.getElementById('btnStart');
  if (btnStart) {
    btnStart.addEventListener('click', startBroadcast);
  }

  const btnStop = document.getElementById('btnStop');
  if (btnStop) {
    btnStop.addEventListener('click', stopBroadcast);
  }

  document.addEventListener('click', () => {
    initWebAudio();
  });

  window.addEventListener('resize', resizeTapeCanvas);

  fetch('/api/status')
    .then(r => r.json())
    .then(data => {
      const activeElem = document.getElementById('activeListeners');
      if (activeElem && data.active_listeners !== undefined) {
        activeElem.innerText = data.active_listeners;
      }
    })
    .catch(() => {});

  updateButtonStates(false);
});
