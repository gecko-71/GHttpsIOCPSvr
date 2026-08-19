program D05_Http3QuicSpeedServer;

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
  System.Diagnostics,
  System.DateUtils,
  GHttpsServerIOCP in '..\..\src\GHttpsServerIOCP.pas',
  GWebSocket in '..\..\src\GWebSocket.pas',
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

function TryServeStaticFile(const FilePath: string; const ARequest: TRequest; const AResponse: TResponse): Boolean;
var
  Ext: string;
  ContentType: string;
  FileBytes: TBytes;
  ETagVal: string;
begin
  Result := False;
  if not FileExists(FilePath) then Exit;

  Ext := LowerCase(TPath.GetExtension(FilePath));
  if Ext = '.html' then
     ContentType := 'text/html; charset=utf-8'
  else if Ext = '.css' then
     ContentType := 'text/css'
  else if Ext = '.js' then
     ContentType := 'application/javascript'
  else if Ext = '.png' then
     ContentType := 'image/png'
  else
     ContentType := 'application/octet-stream';

  FileBytes := TFile.ReadAllBytes(FilePath);
  ETagVal := Format('"%d-%d"', [Length(FileBytes), DateTimeToUnix(TFile.GetLastWriteTime(FilePath))]);

  if (ARequest.Headers.GetHeader('If-None-Match') = ETagVal) then
  begin
    AResponse.SetStatus(304);
    AResponse.AddHeader('ETag', ETagVal);
    Exit(True);
  end;

  AResponse.SetStatus(200);
  AResponse.AddHeader('ETag', ETagVal);
  AResponse.AddHeader('Alt-Svc', Format('h3=":%d"; ma=86400', [SERVER_PORT]));
  AResponse.AddBinaryContent(ContentType, FileBytes);
  Result := True;
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
      FileName := LogDir + '\Logger.log';
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
    Logger.Info('  DEMO 05: Low-Latency HTTP/3 QUIC Speed Server');
    Logger.Info('=====================================================');

    var Server := TGHttpsServerIOCP.Create(SERVER_PORT, SERVER_HOST, CertStoreName, 'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!', 2000, 1000000);
    try
      Server.SetSSLShutdownOptions(True, 200);
      Server.EnableHttp3 := True;

      Server.RegisterEndpointProc('/api/http3/ping', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JSONResp: TJSONObject;
        begin
          JSONResp := TJSONObject.Create;
          try
            JSONResp.AddPair('status', 'pong');
            JSONResp.AddPair('protocol', 'HTTP/3 QUIC Dual-Stack');
            JSONResp.AddPair('alt_svc', Format('h3=":%d"; ma=86400', [SERVER_PORT]));
            JSONResp.AddPair('timestamp', DateTimeToStr(Now));

            AResponse.SetStatus(200);
            AResponse.AddHeader('Alt-Svc', Format('h3=":%d"; ma=86400', [SERVER_PORT]));
            AResponse.AddJSONContent(JSONResp.ToJSON);
          finally
            JSONResp.Free;
          end;
        end);

      Server.RegisterEndpointProc('/api/http3/benchmark', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JSONResp: TJSONObject;
          Sw: TStopwatch;
        begin
          Sw := TStopwatch.StartNew;
          Sleep(1);
          Sw.Stop;

          JSONResp := TJSONObject.Create;
          try
            JSONResp.AddPair('status', 'success');
            JSONResp.AddPair('elapsed_ms', TJSONNumber.Create(Sw.ElapsedMilliseconds));
            JSONResp.AddPair('transport', 'UDP QUIC / TCP TLS 1.3');

            AResponse.SetStatus(200);
            AResponse.AddHeader('Alt-Svc', Format('h3=":%d"; ma=86400', [SERVER_PORT]));
            AResponse.AddJSONContent(JSONResp.ToJSON);
          finally
            JSONResp.Free;
          end;
        end);

      Server.RegisterEndpointProc('/api/status', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JSONResp: TJSONObject;
        begin
          JSONResp := TJSONObject.Create;
          try
            JSONResp.AddPair('status', 'online');
            JSONResp.AddPair('server', 'GHttpsIOCPSvr-Http3SpeedDemo');
            JSONResp.AddPair('http3_enabled', 'true');

            AResponse.SetStatus(200);
            AResponse.AddJSONContent(JSONResp.ToJSON);
          finally
            JSONResp.Free;
          end;
        end);

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          WebRootDir, RequestedPath, FullPath: string;
        begin
          WebRootDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'www');
          RequestedPath := ARequest.RequestInfo.Path;
          if (RequestedPath = '/') or (RequestedPath = '') then
            RequestedPath := '/index.html';

          FullPath := TPath.Combine(WebRootDir, StringReplace(RequestedPath.TrimStart(['/', '\']), '/', '\', [rfReplaceAll]));
          if TryServeStaticFile(FullPath, ARequest, AResponse) then
             Exit;

          FullPath := TPath.Combine(WebRootDir, 'index.html');
          if not TryServeStaticFile(FullPath, ARequest, AResponse) then
          begin
            AResponse.SetNotFound('404 Not Found - DEMO 05 HTTP/3 Speed Server');
          end;
        end);

      if Server.Start then
      begin
        Writeln;
        Writeln;
        Logger.Info(Format('SERVER STARTED: https://%s:%d/ (Host: %s, Port: %d)', [SERVER_HOST, SERVER_PORT, SERVER_HOST, SERVER_PORT]));
        Logger.Info('Press [ENTER] to stop the server...');
        Readln;
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
    begin
      Logger.Error('Critical server error: ' + E.ClassName + ': ' + E.Message);
    end;
  end;
end.








