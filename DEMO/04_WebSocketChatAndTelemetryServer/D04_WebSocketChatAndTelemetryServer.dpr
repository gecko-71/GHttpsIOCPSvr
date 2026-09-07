program D04_WebSocketChatAndTelemetryServer;

{
  MIT License

  Copyright (c) (c) 2026 GECKO-71

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.IOUtils,
  System.JSON,
  System.Math,
  System.DateUtils,
  GWebSocket in '..\..\src\GWebSocket.pas',
  GHttpsServerIOCP in '..\..\src\GHttpsServerIOCP.pas',
  GJWTManager in '..\..\src\GJWTManager.pas',
  GRequest in '..\..\src\GRequest.pas',
  GRequestBody in '..\..\src\GRequestBody.pas',
  GResponse in '..\..\src\GResponse.pas',
  OverlappedExPool in '..\..\src\OverlappedExPool.pas',
  WinApiAdditions in '..\..\src\WinApiAdditions.pas';

const
  SERVER_HOST = 'localhost';
  SERVER_PORT = 8443;
  CertStoreName = 'GHttpsIOCPSvr';

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

type
  TTelemetryThread = class(TThread)
  private
    FServer: TGHttpsServerIOCP;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TGHttpsServerIOCP);
  end;

constructor TTelemetryThread.Create(AServer: TGHttpsServerIOCP);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FServer := AServer;
end;

procedure TTelemetryThread.Execute;
var
  Temp, Humidity, Pressure, Battery: Double;
  TelemetryObj: TJSONObject;
  JsonStr: string;
begin
  Temp := 22.5;
  Humidity := 50.0;
  Pressure := 1013.2;
  Battery := 99.0;
  
  while not Terminated do
  begin
    Temp := Temp + (Random(10) - 5) * 0.1;
    Humidity := Max(20.0, Min(90.0, Humidity + (Random(10) - 5) * 0.2));
    Pressure := Pressure + (Random(10) - 5) * 0.05;
    Battery := Max(1.0, Battery - 0.01);

    TelemetryObj := TJSONObject.Create;
    try
      TelemetryObj.AddPair('type', 'telemetry');
      TelemetryObj.AddPair('device_id', 'IOT-NODE-007');
      TelemetryObj.AddPair('temperature_c', TJSONNumber.Create(RoundTo(Temp, -2)));
      TelemetryObj.AddPair('humidity_percent', TJSONNumber.Create(RoundTo(Humidity, -2)));
      TelemetryObj.AddPair('pressure_hpa', TJSONNumber.Create(RoundTo(Pressure, -2)));
      TelemetryObj.AddPair('battery_pct', TJSONNumber.Create(RoundTo(Battery, -2)));
      TelemetryObj.AddPair('timestamp_ms', TJSONNumber.Create(DateTimeToUnix(Now, False) * 1000));
      JsonStr := TelemetryObj.ToJSON;
    finally
      TelemetryObj.Free;
    end;

    if Assigned(FServer) then
      FServer.BroadcastWebSocket(JsonStr);

    Sleep(1000);
  end;
end;

function GetWebUIHTML: string;
begin
  Result := 
    '<!DOCTYPE html>' + sLineBreak +
    '<html lang="en">' + sLineBreak +
    '<head>' + sLineBreak +
      '  <meta charset="UTF-8">' + sLineBreak +
      '  <meta name="viewport" content="width=device-width, initial-scale=1.0">' + sLineBreak +
      '  <title>DEMO 04: WebSocket Chat &amp; IoT Telemetry</title>' + sLineBreak +
      '  <style>' + sLineBreak +
        '    :root { --bg: #0f172a; --panel: #1e293b; --accent: #38bdf8; --accent-hover: #0284c7; --text: #f8fafc; --muted: #94a3b8; --border: #334155; --success: #22c55e; }' + sLineBreak +
        '    * { box-sizing: border-box; margin: 0; padding: 0; font-family: "Segoe UI", system-ui, sans-serif; }' + sLineBreak +
        '    body { background-color: var(--bg); color: var(--text); display: flex; flex-direction: column; min-height: 100vh; padding: 1.5rem; }' + sLineBreak +
        '    header { text-align: center; margin-bottom: 2rem; }' + sLineBreak +
        '    header h1 { font-size: 2.2rem; color: var(--accent); margin-bottom: 0.5rem; }' + sLineBreak +
        '    header p { color: var(--muted); font-size: 1rem; }' + sLineBreak +
        '    .status-bar { display: flex; justify-content: space-between; align-items: center; background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }' + sLineBreak +
        '    .status-badge { display: inline-flex; align-items: center; gap: 0.5rem; font-weight: 600; padding: 0.4rem 0.8rem; border-radius: 20px; font-size: 0.9rem; }' + sLineBreak +
        '    .status-online { background: rgba(34, 197, 94, 0.15); color: var(--success); }' + sLineBreak +
        '    .status-offline { background: rgba(239, 68, 68, 0.15); color: #ef4444; }' + sLineBreak +
        '    .dot { width: 10px; height: 10px; border-radius: 50%; background: currentColor; }' + sLineBreak +
        '    .grid-container { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 1.5rem; align-items: start; max-width: 1200px; margin: 0 auto; width: 100%; }' + sLineBreak +
        '    @media (max-width: 900px) { .grid-container { grid-template-columns: 1fr; } }' + sLineBreak +
        '    .card { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem; display: flex; flex-direction: column; min-width: 0; min-height: 530px; height: 530px; max-height: 530px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); overflow: hidden; }' + sLineBreak +
        '    .card h2 { font-size: 1.4rem; margin-bottom: 1rem; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; flex-shrink: 0; }' + sLineBreak +
        '    .telemetry-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-bottom: 1rem; flex-shrink: 0; }' + sLineBreak +
        '    .gauge-box { background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); border-radius: 12px; padding: 1rem; text-align: center; height: 95px; min-height: 95px; max-height: 95px; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow: hidden; }' + sLineBreak +
        '    .gauge-title { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }' + sLineBreak +
        '    .gauge-value { font-size: 1.8rem; font-weight: 700; margin: 0.2rem 0; color: #fff; font-variant-numeric: tabular-nums; font-family: "Consolas", "Segoe UI Monospace", monospace; min-width: 110px; text-align: center; display: inline-block; }' + sLineBreak +
        '    .gauge-unit { font-size: 0.85rem; color: var(--accent); }' + sLineBreak +
        '    .log-box { background: #090d16; border: 1px solid var(--border); border-radius: 10px; padding: 0.8rem; flex: 1; min-height: 140px; max-height: 160px; overflow-y: auto; overflow-x: hidden; font-family: monospace; font-size: 0.8rem; color: #a7f3d0; word-break: break-all; overflow-wrap: anywhere; white-space: pre-wrap; }' + sLineBreak +
        '    .chat-controls { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-shrink: 0; }' + sLineBreak +
        '    input, select, button { background: #0f172a; border: 1px solid var(--border); color: #fff; padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.95rem; outline: none; }' + sLineBreak +
        '    input:focus, select:focus { border-color: var(--accent); }' + sLineBreak +
        '    button { background: var(--accent); color: #0f172a; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; }' + sLineBreak +
        '    button:hover { background: var(--accent-hover); color: #fff; }' + sLineBreak +
        '    .chat-messages { background: #090d16; border: 1px solid var(--border); border-radius: 10px; padding: 1rem; flex: 1; min-height: 250px; max-height: 330px; overflow-y: auto; overflow-x: hidden; display: flex; flex-direction: column; gap: 0.6rem; margin-bottom: 1rem; word-break: break-word; }' + sLineBreak +
        '    .chat-msg { background: rgba(30, 41, 59, 0.8); border-left: 3px solid var(--accent); padding: 0.6rem 0.8rem; border-radius: 0 8px 8px 0; font-size: 0.9rem; word-break: break-word; overflow-wrap: anywhere; }' + sLineBreak +
        '    .chat-msg .meta { font-size: 0.75rem; color: var(--muted); margin-bottom: 0.2rem; display: flex; justify-content: space-between; }' + sLineBreak +
        '    .chat-msg .user { font-weight: bold; color: var(--accent); }' + sLineBreak +
        '    .chat-input-box { display: flex; gap: 0.5rem; flex-shrink: 0; }' + sLineBreak +
        '    .chat-input-box input { flex: 1; }' + sLineBreak +
        '  </style>' + sLineBreak +
    '</head>' + sLineBreak +
    '<body>' + sLineBreak +
      '  <header>' + sLineBreak +
        '    <h1>DEMO 04: WebSocket Chat &amp; IoT Telemetry</h1>' + sLineBreak +
        '    <p>Multi-threaded Windows IOCP server with real-time bi-directional communication</p>' + sLineBreak +
      '  </header>' + sLineBreak +
 
      '  <div class="status-bar">' + sLineBreak +
        '    <div>' + sLineBreak +
          '      <span>IOCP Server Connection: </span>' + sLineBreak +
          '      <span id="wsStatus" class="status-badge status-offline"><span class="dot"></span> Disconnected</span>' + sLineBreak +
        '    </div>' + sLineBreak +
        '    <div>' + sLineBreak +
          '      <span>Socket Address: </span><strong style="color: var(--accent);">wss://localhost:8443/ws</strong>' + sLineBreak +
        '    </div>' + sLineBreak +
      '  </div>' + sLineBreak +
 
      '  <div class="grid-container">' + sLineBreak +
        '    <!-- IoT Telemetry Card -->' + sLineBreak +
        '    <div class="card">' + sLineBreak +
          '      <h2>IoT Telemetry (Live Streaming)</h2>' + sLineBreak +
          '      <div class="telemetry-grid">' + sLineBreak +
            '        <div class="gauge-box">' + sLineBreak +
              '          <div class="gauge-title">Temperature</div>' + sLineBreak +
              '          <div class="gauge-value" id="valTemp">--</div>' + sLineBreak +
              '          <div class="gauge-unit">°C</div>' + sLineBreak +
            '        </div>' + sLineBreak +
            '        <div class="gauge-box">' + sLineBreak +
              '          <div class="gauge-title">Humidity</div>' + sLineBreak +
              '          <div class="gauge-value" id="valHum">--</div>' + sLineBreak +
              '          <div class="gauge-unit">% RH</div>' + sLineBreak +
            '        </div>' + sLineBreak +
            '        <div class="gauge-box">' + sLineBreak +
              '          <div class="gauge-title">Pressure</div>' + sLineBreak +
              '          <div class="gauge-value" id="valPress">--</div>' + sLineBreak +
              '          <div class="gauge-unit">hPa</div>' + sLineBreak +
            '        </div>' + sLineBreak +
            '        <div class="gauge-box">' + sLineBreak +
              '          <div class="gauge-title">Device Battery</div>' + sLineBreak +
              '          <div class="gauge-value" id="valBatt">--</div>' + sLineBreak +
              '          <div class="gauge-unit">%</div>' + sLineBreak +
            '        </div>' + sLineBreak +
          '      </div>' + sLineBreak +
          '      <h3 style="font-size: 1rem; color: var(--muted); margin-bottom: 0.5rem;">Raw WebSocket Frame Log:</h3>' + sLineBreak +
          '      <div class="log-box" id="telemetryLog">Waiting for first telemetry packets...</div>' + sLineBreak +
        '    </div>' + sLineBreak +
 
        '    <!-- Live Multi-Room Chat Card -->' + sLineBreak +
        '    <div class="card">' + sLineBreak +
          '      <h2>💬 Live Multi-Room Chat</h2>' + sLineBreak +
          '      <div class="chat-controls">' + sLineBreak +
            '        <input type="text" id="username" value="Operator" style="width: 140px;">' + sLineBreak +
            '        <select id="roomSelect" onchange="switchRoom(this.value)">' + sLineBreak +
              '          <option value="General">Room: General</option>' + sLineBreak +
              '          <option value="DevTeam">Room: DevTeam</option>' + sLineBreak +
              '          <option value="IoT-Alerts">Room: IoT-Alerts</option>' + sLineBreak +
            '        </select>' + sLineBreak +
            '        <button id="btnConnect" onclick="toggleConnection()">Connect</button>' + sLineBreak +
          '      </div>' + sLineBreak +
          '      <div class="chat-messages" id="chatMessages">' + sLineBreak +
            '        <div class="chat-msg"><div class="meta"><span class="user">System</span><span>Now</span></div>Click "Connect" to open a WebSocket socket over HTTPS IOCP.</div>' + sLineBreak +
          '      </div>' + sLineBreak +
          '      <div class="chat-input-box">' + sLineBreak +
            '        <input type="text" id="chatInput" placeholder="Type a message..." onkeypress="handleKeyPress(event)">' + sLineBreak +
            '        <button onclick="sendMessage()">Send</button>' + sLineBreak +
          '      </div>' + sLineBreak +
        '    </div>' + sLineBreak +
      '  </div>' + sLineBreak +
 
      '  <script>' + sLineBreak +
        '    let ws = null;' + sLineBreak +
        '    const wsStatus = document.getElementById("wsStatus");' + sLineBreak +
        '    const chatMessages = document.getElementById("chatMessages");' + sLineBreak +
        '    const telemetryLog = document.getElementById("telemetryLog");' + sLineBreak +
        '    const roomSelect = document.getElementById("roomSelect");' + sLineBreak +
        '    const roomMessages = {' + sLineBreak +
        '      "General": [],' + sLineBreak +
        '      "DevTeam": [],' + sLineBreak +
        '      "IoT-Alerts": []' + sLineBreak +
        '    };' + sLineBreak +
        '    let currentRoom = "General";' + sLineBreak +
        '    function switchRoom(newRoom) {' + sLineBreak +
        '      if (!newRoom) return;' + sLineBreak +
        '      currentRoom = newRoom;' + sLineBreak +
        '      for (let opt of roomSelect.options) {' + sLineBreak +
        '        if (opt.value === currentRoom) opt.text = "Room: " + currentRoom;' + sLineBreak +
        '      }' + sLineBreak +
        '      chatMessages.innerHTML = "";' + sLineBreak +
        '      appendChatMessageElement("System", "Switched to room: [" + currentRoom + "]", new Date().toLocaleTimeString(), true);' + sLineBreak +
        '      const history = roomMessages[currentRoom] || [];' + sLineBreak +
        '      history.forEach(item => {' + sLineBreak +
        '        appendChatMessageElement(item.user, item.message, item.time, false);' + sLineBreak +
        '      });' + sLineBreak +
        '    }' + sLineBreak +
        '    function handleKeyPress(e) {' + sLineBreak +
        '      if (e.key === "Enter") sendMessage();' + sLineBreak +
        '    }' + sLineBreak +
        '    function toggleConnection() {' + sLineBreak +
        '      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {' + sLineBreak +
        '        ws.close();' + sLineBreak +
        '      } else {' + sLineBreak +
        '        connectWebSocket();' + sLineBreak +
        '      }' + sLineBreak +
        '    }' + sLineBreak +
        '    function connectWebSocket() {' + sLineBreak +
        '      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";' + sLineBreak +
        '      const wsUrl = protocol + "//" + window.location.host + "/ws";' + sLineBreak +
        '      try {' + sLineBreak +
        '        ws = new WebSocket(wsUrl);' + sLineBreak +
        '        document.getElementById("btnConnect").innerText = "Connecting...";' + sLineBreak +
        '        ws.onopen = function() {' + sLineBreak +
        '          wsStatus.className = "status-badge status-online";' + sLineBreak +
        '          wsStatus.innerHTML = "<span class=\"dot\"></span> Connected (WSS)";' + sLineBreak +
        '          document.getElementById("btnConnect").innerText = "Disconnect";' + sLineBreak +
        '          switchRoom(roomSelect.value || "General");' + sLineBreak +
        '        };' + sLineBreak +
        '        ws.onmessage = function(event) {' + sLineBreak +
        '          try {' + sLineBreak +
        '            const data = JSON.parse(event.data);' + sLineBreak +
        '            if (data.type === "telemetry") {' + sLineBreak +
        '              updateTelemetry(data);' + sLineBreak +
        '            } else if (data.type === "chat") {' + sLineBreak +
        '              const room = data.room || "General";' + sLineBreak +
        '              if (!roomMessages[room]) roomMessages[room] = [];' + sLineBreak +
        '              roomMessages[room].push({ user: data.user, message: data.message, time: data.time });' + sLineBreak +
        '              if (room === currentRoom) {' + sLineBreak +
        '                appendChatMessageElement(data.user + " [" + room + "]", data.message, data.time, false);' + sLineBreak +
        '              } else {' + sLineBreak +
        '                for (let opt of roomSelect.options) {' + sLineBreak +
        '                  if (opt.value === room && !opt.text.includes("●")) opt.text = "Room: " + room + " ●";' + sLineBreak +
        '                }' + sLineBreak +
        '              }' + sLineBreak +
        '            }' + sLineBreak +
        '          } catch(e) {' + sLineBreak +
        '            appendChatMessageElement("Raw Payload", event.data, new Date().toLocaleTimeString(), true);' + sLineBreak +
        '          }' + sLineBreak +
        '        };' + sLineBreak +
        '        ws.onclose = function() {' + sLineBreak +
        '          wsStatus.className = "status-badge status-offline";' + sLineBreak +
        '          wsStatus.innerHTML = "<span class=\"dot\"></span> Disconnected";' + sLineBreak +
        '          document.getElementById("btnConnect").innerText = "Connect";' + sLineBreak +
        '          appendChatMessageElement("System", "WebSocket connection closed.", new Date().toLocaleTimeString(), true);' + sLineBreak +
        '        };' + sLineBreak +
        '        ws.onerror = function(err) {' + sLineBreak +
        '          console.error("WS Error:", err);' + sLineBreak +
        '        };' + sLineBreak +
        '      } catch(e) {' + sLineBreak +
        '        alert("WebSocket connection error: " + e.message);' + sLineBreak +
        '      }' + sLineBreak +
        '    }' + sLineBreak +
        '    function updateTelemetry(data) {' + sLineBreak +
        '      if (data.temperature_c !== undefined) document.getElementById("valTemp").innerText = data.temperature_c.toFixed(1);' + sLineBreak +
        '      if (data.humidity_percent !== undefined) document.getElementById("valHum").innerText = data.humidity_percent.toFixed(1);' + sLineBreak +
        '      if (data.pressure_hpa !== undefined) document.getElementById("valPress").innerText = data.pressure_hpa.toFixed(1);' + sLineBreak +
        '      if (data.battery_pct !== undefined) document.getElementById("valBatt").innerText = data.battery_pct.toFixed(1);' + sLineBreak +
        '      telemetryLog.innerText = "[" + new Date().toLocaleTimeString() + "] FRAME: " + JSON.stringify(data);' + sLineBreak +
        '    }' + sLineBreak +
        '    function sendMessage() {' + sLineBreak +
        '      const input = document.getElementById("chatInput");' + sLineBreak +
        '      const text = input.value.trim();' + sLineBreak +
        '      if (!text) return;' + sLineBreak +
        '      if (!ws || ws.readyState !== WebSocket.OPEN) {' + sLineBreak +
        '        alert("Please connect to the WebSocket server first!");' + sLineBreak +
        '        return;' + sLineBreak +
        '      }' + sLineBreak +
        '      const user = document.getElementById("username").value || "Operator";' + sLineBreak +
        '      const room = roomSelect.value || "General";' + sLineBreak +
        '      const payload = {' + sLineBreak +
        '        type: "chat",' + sLineBreak +
        '        user: user,' + sLineBreak +
        '        room: room,' + sLineBreak +
        '        message: text,' + sLineBreak +
        '        time: new Date().toLocaleTimeString()' + sLineBreak +
        '      };' + sLineBreak +
        '      ws.send(JSON.stringify(payload));' + sLineBreak +
        '      input.value = "";' + sLineBreak +
        '    }' + sLineBreak +
        '    function appendChatMessageElement(user, msg, time, isSystem) {' + sLineBreak +
        '      const timeStr = time || new Date().toLocaleTimeString();' + sLineBreak +
        '      const div = document.createElement("div");' + sLineBreak +
        '      div.className = "chat-msg";' + sLineBreak +
        '      if (isSystem) {' + sLineBreak +
        '        div.style.borderLeftColor = "#94a3b8";' + sLineBreak +
        '        div.style.background = "rgba(51, 65, 85, 0.4)";' + sLineBreak +
        '      }' + sLineBreak +
        '      div.innerHTML = "<div class=\"meta\"><span class=\"user\" style=\"" + (isSystem ? "color: #94a3b8;" : "") + "\">" + user + "</span><span>" + timeStr + "</span></div><div>" + msg + "</div>";' + sLineBreak +
        '      chatMessages.appendChild(div);' + sLineBreak +
        '      chatMessages.scrollTop = chatMessages.scrollHeight;' + sLineBreak +
        '    }' + sLineBreak +
        '    window.onload = function() { connectWebSocket(); };' + sLineBreak +
      '  </script>' + sLineBreak +
    '</body>' + sLineBreak +
    '</html>';
end;

begin
  ConfigureFastMM;
  try
    Logger.Providers.Add(GlobalLogFileProvider);
    Logger.Providers.Add(GlobalLogConsoleProvider);
    
    var LogDir := '.\Log';
    if not TDirectory.Exists(LogDir) then
      TDirectory.CreateDirectory(LogDir);

    with GlobalLogFileProvider do
    begin
      FileName := LogDir + '\WebSocketChatAndTelemetryServer.log';
      DailyRotate := True;
      MaxFileSizeInMB := 50;
      LogLevel := LOG_ALL;
      Enabled := True;
    end;

    with GlobalLogConsoleProvider do
    begin
      LogLevel := LOG_DEBUG;
      ShowEventColors := True;
      Enabled := True;
    end;

    Logger.Info('=====================================================');
    Logger.Info('  DEMO 04: WebSocket Chat & Telemetry Server (IOCP)');
    Logger.Info('=====================================================');
    
    var Server := TGHttpsServerIOCP.Create(SERVER_PORT, SERVER_HOST, CertStoreName, 'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!', 2000, 1000000);
    try
      Server.SetSSLShutdownOptions(True, 200);

      Server.RegisterWebSocketRoute('/ws',
        procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const MessageText: string; Opcode: TWebSocketOpcode)
        var
          JsonVal: TJSONValue;
          JsonObj: TJSONObject;
          MsgType: string;
        begin
          JsonVal := TJSONObject.ParseJSONValue(MessageText);
          if Assigned(JsonVal) then
          begin
            try
              if JsonVal is TJSONObject then
              begin
                JsonObj := TJSONObject(JsonVal);
                MsgType := JsonObj.GetValue<string>('type', '');
                if MsgType = 'chat' then
                begin
                  AServer.BroadcastWebSocket(MessageText);
                end;
              end;
            finally
              JsonVal.Free;
            end;
          end
          else
          begin
            AServer.BroadcastWebSocket(MessageText);
          end;
        end);

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.AddHTMLContent(GetWebUIHTML);
        end);

      if Server.Start then
      begin
        Writeln;
        Writeln;
        Logger.Info(Format('SERVER STARTED: https://%s:%d/ (Host: %s, Port: %d)', [SERVER_HOST, SERVER_PORT, SERVER_HOST, SERVER_PORT]));
        
        var TelemetryThread := TTelemetryThread.Create(Server);
        try
          Logger.Info('Press [ENTER] to stop the demo server...');
          Readln;
        finally
          TelemetryThread.Terminate;
          TelemetryThread.WaitFor;
          TelemetryThread.Free;
        end;

        Server.Stop;
      end
      else
      begin
        Writeln;
        Writeln(Format('CRITICAL ERROR: Failed to start server on https://%s:%d/', [SERVER_HOST, SERVER_PORT]));
        Writeln;
        Logger.Error(Format('Failed to start HTTPS IOCP server on host %s port %d.', [SERVER_HOST, SERVER_PORT]));
      end;
    finally
      Server.Free;
    end;

    Logger.Info('Server stopped successfully.');
  except
    on E: Exception do
      Logger.Error('Critical server error: ' + E.ClassName + ': ' + E.Message);
  end;
end.








