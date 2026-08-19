program D01_StaticAndSpaServer;

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
  System.SyncObjs,
  System.Generics.Collections,
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
  SERVER_PORT = 8081;
  CertStoreName = 'GHttpsIOCPSvr';

var
  GStartTime: TDateTime;
  GRequestsProcessed: Int64 = 0;

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
  if not FileExists(FilePath) then
     Exit;

  Ext := LowerCase(TPath.GetExtension(FilePath));
  if Ext = '.html' then
     ContentType := 'text/html; charset=utf-8'
  else if Ext = '.css' then
     ContentType := 'text/css'
  else if Ext = '.js' then
     ContentType := 'application/javascript'
  else if Ext = '.png' then
     ContentType := 'image/png'
  else if Ext = '.jpg' then
     ContentType := 'image/jpeg'
  else if Ext = '.svg' then
     ContentType := 'image/svg+xml'
  else if Ext = '.json' then
     ContentType := 'application/json'
  else
     ContentType := 'application/octet-stream';

  FileBytes := TFile.ReadAllBytes(FilePath);
  ETagVal := Format('"%d-%d"', [Length(FileBytes), DateTimeToUnix(TFile.GetLastWriteTime(FilePath))]);

  if (ARequest.Headers.GetHeader('If-None-Match') = ETagVal) then
  begin
    AResponse.SetStatus(304);
    AResponse.AddHeader('ETag', ETagVal);
    AResponse.AddHeader('Cache-Control', 'public, max-age=3600');
    Exit(True);
  end;

  AResponse.SetStatus(200);
  AResponse.AddHeader('ETag', ETagVal);
  AResponse.AddHeader('Cache-Control', 'public, max-age=3600');
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

    GStartTime := Now;

    Logger.Info('=====================================================');
    Logger.Info('  DEMO 01: Static File Server & SPA Fallback Router');
    Logger.Info('=====================================================');

    var Server := TGHttpsServerIOCP.Create(SERVER_PORT, SERVER_HOST,
                                           CertStoreName,
                                           'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!',
                                           2000,
                                           1000000);
    try
      Server.SetSSLShutdownOptions(True, 200);

      Server.RegisterEndpointProc('/api/status', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JsonObj: TJSONObject;
          UptimeSec: Int64;
          ActiveWsCount: Integer;
          SessionList: TList<TWebSocketSession>;
          Session: TWebSocketSession;
        begin
          TInterlocked.Increment(GRequestsProcessed);
          UptimeSec := SecondsBetween(Now, GStartTime);
          ActiveWsCount := 0;

          if Assigned(AServer.WebSocketManager) then
          begin
            SessionList := AServer.WebSocketManager.AcquireSessionList;
            try
              ActiveWsCount := SessionList.Count;
            finally
              for Session in SessionList do
                  Session.Release;
              SessionList.Free;
            end;
          end;

          JsonObj := TJSONObject.Create;
          try
            JsonObj.AddPair('status', 'online');
            JsonObj.AddPair('server', 'GHttpsIOCPSvr-StaticAndSpa');
            JsonObj.AddPair('uptime_seconds', TJSONNumber.Create(UptimeSec));
            JsonObj.AddPair('requests_processed', TJSONNumber.Create(GRequestsProcessed));
            JsonObj.AddPair('active_connections', TJSONNumber.Create(ActiveWsCount));

            AResponse.SetStatus(200);
            AResponse.AddHeader('Cache-Control', 'no-cache');
            AResponse.AddJSONContent(JsonObj.ToJSON);
          finally
            JsonObj.Free;
          end;
        end);

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          ReqPath, LocalPath, WebRootDir, ExeDir: string;
        begin
          TInterlocked.Increment(GRequestsProcessed);
          ExeDir := ExtractFilePath(ParamStr(0));
          WebRootDir := TPath.Combine(ExeDir, 'www');
          if not TDirectory.Exists(WebRootDir) then
            WebRootDir := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\www'));
          if not TDirectory.Exists(WebRootDir) then
            WebRootDir := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\DEMO\01_StaticAndSpaServer\www'));
          if not TDirectory.Exists(WebRootDir) then
            WebRootDir := TPath.GetFullPath('DEMO\01_StaticAndSpaServer\www');
          if not TDirectory.Exists(WebRootDir) then
            WebRootDir := TPath.GetFullPath('www');

          ReqPath := ARequest.RequestInfo.Path;
          var RelPath := ReqPath;
          while (RelPath <> '') and ((RelPath[1] = '/') or (RelPath[1] = '\')) do
            Delete(RelPath, 1, 1);
          RelPath := StringReplace(RelPath, '/', '\', [rfReplaceAll]);

          if RelPath = '' then
            LocalPath := TPath.Combine(WebRootDir, 'index.html')
          else
            LocalPath := TPath.Combine(WebRootDir, RelPath);

          if not TryServeStaticFile(LocalPath, ARequest, AResponse) then
          begin
            LocalPath := TPath.Combine(WebRootDir, 'index.html');
            if not TryServeStaticFile(LocalPath, ARequest, AResponse) then
            begin
              AResponse.SetNotFound('Static assets directory not found.');
            end;
          end;
        end);

      if Server.Start then
      begin
        Writeln;
        Writeln;
        Logger.Info(Format('SERVER STARTED: https://%s:%d/ (Host: %s, Port: %d)', [SERVER_HOST, SERVER_PORT, SERVER_HOST, SERVER_PORT]));
        Logger.Info('Press [ENTER] to stop the demo server...');
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








