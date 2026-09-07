program D03_HighSpeedFileStreamServer;

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
  SERVER_PORT = 8083;
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
  else if Ext = '.mp4' then
     ContentType := 'video/mp4'
  else if Ext = '.mp3' then
     ContentType := 'audio/mpeg'
  else
     ContentType := 'application/octet-stream';

  var FileSize := TFile.GetSize(FilePath);
  ETagVal := Format('"%d-%d"', [FileSize, DateTimeToUnix(TFile.GetLastWriteTime(FilePath))]);

  if (ARequest.Headers.GetHeader('If-None-Match') = ETagVal) then
  begin
    AResponse.SetStatus(304);
    AResponse.AddHeader('ETag', ETagVal);
    Exit(True);
  end;

  AResponse.SetStatus(200);
  AResponse.AddHeader('ETag', ETagVal);
  if FileSize > 1024 * 1024 then
    AResponse.AddFileStreamContent(ContentType, FilePath)
  else
  begin
    FileBytes := TFile.ReadAllBytes(FilePath);
    AResponse.AddBinaryContent(ContentType, FileBytes);
  end;
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
    Logger.Info('  DEMO 03: High-Speed File Stream & Media Server');
    Logger.Info('=====================================================');

    var Server := TGHttpsServerIOCP.Create(SERVER_PORT,
                                           SERVER_HOST,
                                           CertStoreName,
                                           'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!',
                                           2000,
                                           1000000,
                                           DEFAULT_MAX_REQUEST_HEDER_SIZE,
                                           1073741824,
                                           1073741824,
                                           65536);
    try
      Server.SetSSLShutdownOptions(True, 200);

      Server.RegisterEndpointProc('/api/download', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          DummyData: TBytes;
        begin
          SetLength(DummyData, 1024 * 64);
          FillChar(DummyData[0], Length(DummyData), $41);

          AResponse.SetStatus(200);
          AResponse.AddHeader('Content-Disposition', 'attachment; filename="demo_data.bin"');
          AResponse.AddBinaryContent('application/octet-stream', DummyData);
        end);

      Server.RegisterEndpointProc('/api/upload', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JSONResp: TJSONObject;
        begin
          JSONResp := TJSONObject.Create;
          try
            JSONResp.AddPair('status', 'success');
            JSONResp.AddPair('bytes_received', TJSONNumber.Create(ARequest.BodyBytesReceived));
            JSONResp.AddPair('message', 'File uploaded successfully');

            AResponse.SetStatus(200);
            AResponse.AddJSONContent(JSONResp.ToJSON);
          finally
            JSONResp.Free;
          end;
        end);

      Server.RegisterEndpointProc('/api/media/stream', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          DummyMedia: TBytes;
          RangeHeader, RangeVal, StartStr, EndStr: string;
          TotalSize, StartByte, EndByte, ChunkSize, DashPos: Integer;
          PartialData: TBytes;
        begin
          TotalSize := 1024 * 512;
          SetLength(DummyMedia, TotalSize);
          FillChar(DummyMedia[0], TotalSize, $55);

          RangeHeader := ARequest.Headers.GetHeader('Range');
          if RangeHeader.StartsWith('bytes=') then
          begin
            RangeVal := RangeHeader.Substring(6).Trim;
            DashPos := Pos('-', RangeVal);
            if DashPos > 0 then
            begin
              StartStr := Copy(RangeVal, 1, DashPos - 1);
              EndStr := Copy(RangeVal, DashPos + 1, Length(RangeVal));
              StartByte := StrToIntDef(StartStr, 0);
              EndByte := StrToIntDef(EndStr, TotalSize - 1);
            end
            else
            begin
              StartByte := 0;
              EndByte := 1023;
            end;

            if StartByte < 0 then
               StartByte := 0;
            if EndByte >= TotalSize then
               EndByte := TotalSize - 1;
            if StartByte > EndByte then
               StartByte := EndByte;

            ChunkSize := (EndByte - StartByte) + 1;
            SetLength(PartialData, ChunkSize);
            Move(DummyMedia[StartByte], PartialData[0], ChunkSize);

            AResponse.SetStatus(206);
            AResponse.AddHeader('Content-Range', Format('bytes %d-%d/%d', [StartByte, EndByte, TotalSize]));
            AResponse.AddHeader('Accept-Ranges', 'bytes');
            AResponse.AddBinaryContent('video/mp4', PartialData);
          end
          else
          begin
            AResponse.SetStatus(200);
            AResponse.AddHeader('Accept-Ranges', 'bytes');
            AResponse.AddBinaryContent('video/mp4', DummyMedia);
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
            JSONResp.AddPair('server', 'GHttpsIOCPSvr-HighSpeedFileStreamDemo');
            JSONResp.AddPair('range_requests', 'HTTP 206 Supported');

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
          if TryServeStaticFile(FullPath, ARequest, AResponse) then Exit;

          FullPath := TPath.Combine(WebRootDir, 'index.html');
          if not TryServeStaticFile(FullPath, ARequest, AResponse) then
            AResponse.SetNotFound('404 Not Found - DEMO 03 High-Speed File Stream Server');
        end);

      if Server.Start then
      begin
        try
          Writeln;
          Writeln;
        except
          on EInOutError do ;
        end;
        Logger.Info(Format('SERVER STARTED: https://%s:%d/ (Host: %s, Port: %d)', [SERVER_HOST, SERVER_PORT, SERVER_HOST, SERVER_PORT]));
        if FindCmdLineSwitch('daemon', True) then
        begin
          Logger.Info('Running in daemon mode. Press Ctrl+C or kill process to stop.');
          while Server.Running do
            Sleep(1000);
        end
        else
        begin
          try
            Readln;
          except
            on E: EInOutError do
            begin
              while Server.Running do
                Sleep(1000);
            end;
          end;
        end;
        Server.Stop;
      end
      else
      begin
        try
          Writeln;
          Writeln(Format('CRITICAL ERROR: Failed to start server on https://%s:%d/', [SERVER_HOST, SERVER_PORT]));
          Writeln;
        except
          on EInOutError do ;
        end;
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








