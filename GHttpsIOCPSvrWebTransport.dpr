{
  MIT License

  Copyright (c) 2026 GECKO-71

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

program GHttpsIOCPSvrWebTransport;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  Winapi.Windows,
  System.NetEncoding,
  System.StrUtils,
  System.IOUtils,
  System.JSON,
  GWebSocket in 'src\GWebSocket.pas',
  GHttpsServerIOCP in 'src\GHttpsServerIOCP.pas',
  GJWTManager in 'src\GJWTManager.pas',
  GRequest in 'src\GRequest.pas',
  GRequestBody in 'src\GRequestBody.pas',
  GResponse in 'src\GResponse.pas',
  OverlappedExPool in 'src\OverlappedExPool.pas',
  WinApiAdditions in 'src\WinApiAdditions.pas',
  LsQpack.Loader in 'Http3DelphiV3\ls-qpack\LsQpack.Loader.pas',
  LsQpack.Types in 'Http3DelphiV3\ls-qpack\LsQpack.Types.pas',
  Http3.Connection in 'Http3DelphiV3\Http3.Connection.pas',
  Http3.Frames in 'Http3DelphiV3\Http3.Frames.pas',
  Http3.Request in 'Http3DelphiV3\Http3.Request.pas',
  Http3.Response in 'Http3DelphiV3\Http3.Response.pas',
  Http3.Server in 'Http3DelphiV3\Http3.Server.pas',
  Http3.Types in 'Http3DelphiV3\Http3.Types.pas',
  MsQuic.ApiTable in 'Http3DelphiV3\MsQuic.ApiTable.pas',
  MsQuic.Certificate in 'Http3DelphiV3\MsQuic.Certificate.pas',
  MsQuic.Configuration in 'Http3DelphiV3\MsQuic.Configuration.pas',
  MsQuic.Errors in 'Http3DelphiV3\MsQuic.Errors.pas',
  MsQuic.Listener in 'Http3DelphiV3\MsQuic.Listener.pas',
  MsQuic.Loader in 'Http3DelphiV3\MsQuic.Loader.pas',
  MsQuic.Registration in 'Http3DelphiV3\MsQuic.Registration.pas',
  MsQuic.Types in 'Http3DelphiV3\MsQuic.Types.pas',
  Quic.Server in 'Http3DelphiV3\Quic.Server.pas',
  WebTransport.Server in 'Http3DelphiV3\WebTransport.Server.pas',
  WebTransport.Session in 'Http3DelphiV3\WebTransport.Session.pas',
  WebTransport.Types in 'Http3DelphiV3\WebTransport.Types.pas';

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

procedure PrepareTestFile(const ASubDir, AFileName: string; AFileSizeInBytes: Int64);
var
  BaseDir, FullFilePath: string;
  FileStream: TFileStream;
  Buffer: TBytes;
  BufferSize, NumWrites, RemainingBytes, i: Int64;
begin
  BaseDir := TPath.Combine(ExtractFilePath(ParamStr(0)), ASubDir);
  FullFilePath := TPath.Combine(BaseDir, AFileName);

  if TFile.Exists(FullFilePath) then
    Exit;

  try
    if not TDirectory.Exists(BaseDir) then
      TDirectory.CreateDirectory(BaseDir);
    FileStream := TFileStream.Create(FullFilePath, fmCreate);
    try
      BufferSize := 65536;
      SetLength(Buffer, BufferSize);
      FillChar(Buffer[0], BufferSize, $AA);
      NumWrites := AFileSizeInBytes div BufferSize;
      RemainingBytes := AFileSizeInBytes mod BufferSize;

      for i := 1 to NumWrites do
        FileStream.WriteBuffer(Buffer[0], BufferSize);

      if RemainingBytes > 0 then
        FileStream.WriteBuffer(Buffer[0], RemainingBytes);
    finally
      FileStream.Free;
    end;
  except
    on E: Exception do
    begin
      Logger.Error(Format('Failed to generate test file "%s". Error: %s', [FullFilePath, E.Message]));
      if TFile.Exists(FullFilePath) then
        TFile.Delete(FullFilePath);
      raise;
    end;
  end;
end;

function GetWebTransportDemoHTML: string;
begin
  Result := Format(
    '<!DOCTYPE html>' + sLineBreak +
    '<html lang="en">' + sLineBreak +
    '<head>' + sLineBreak +
    '  <meta charset="UTF-8">' + sLineBreak +
    '  <title>GHttpsIOCPSvr WebTransport Demo</title>' + sLineBreak +
    '  <style>' + sLineBreak +
    '    body { font-family: Segoe UI, Tahoma, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }' + sLineBreak +
    '    .card { background: #1e293b; padding: 24px; border-radius: 12px; max-width: 700px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }' + sLineBreak +
    '    h1 { color: #38bdf8; margin-top: 0; }' + sLineBreak +
    '    .badge { display: inline-block; background: #0284c7; color: white; padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 12px; margin-right: 6px; }' + sLineBreak +
    '    code { background: #334155; padding: 2px 6px; border-radius: 4px; font-family: Consolas, monospace; }' + sLineBreak +
    '    ul { line-height: 1.8; }' + sLineBreak +
    '  </style>' + sLineBreak +
    '</head>' + sLineBreak +
    '<body>' + sLineBreak +
    '  <div class="card">' + sLineBreak +
    '    <h1>GHttpsIOCPSvr WebTransport Demo</h1>' + sLineBreak +
    '    <p>High Performance Multi-Protocol IOCP Server with WebTransport over HTTP/3 (MSQuic + ls-qpack).</p>' + sLineBreak +
    '    <p><span class="badge">HTTP/3</span><span class="badge">WebTransport</span><span class="badge">RFC 9220</span><span class="badge">QUIC Datagrams</span></p>' + sLineBreak +
    '    <h3>Active Endpoints:</h3>' + sLineBreak +
    '    <ul>' + sLineBreak +
    '      <li><code>/webtransport</code> - Primary WebTransport Endpoint (Bidi & Uni Streams + QUIC Datagrams)</li>' + sLineBreak +
    '      <li><code>/wt</code> - Short WebTransport Alias</li>' + sLineBreak +
    '      <li><code>/status</code> - JSON Server Health Status</li>' + sLineBreak +
    '      <li><code>/api/protocol</code> - Active Protocol Capabilities</li>' + sLineBreak +
    '      <li><code>/chat</code> - WebSocket Echo Endpoint (RFC 6455)</li>' + sLineBreak +
    '    </ul>' + sLineBreak +
    '  </div>' + sLineBreak +
    '  <script>' + sLineBreak +
    '    async function connectWT(url) {' + sLineBreak +
    '      const wt = new WebTransport(url);' + sLineBreak +
    '      await wt.ready;' + sLineBreak +
    '      const r = wt.datagrams.readable.getReader();' + sLineBreak +
    '      const w = wt.datagrams.writable.getWriter();' + sLineBreak +
    '      const uni = await wt.createUnidirectionalStream();' + sLineBreak +
    '      const bidi = await wt.createBidirectionalStream();' + sLineBreak +
    '    }' + sLineBreak +
    '  </script>' + sLineBreak +
    '</body>' + sLineBreak +
    '</html>', []);
end;

procedure PrintUsage;
begin
  Writeln('================================================================');
  Writeln('  GHttpsIOCPSvrWebTransport - High Performance WebTransport Server');
  Writeln('  Supported Protocols: HTTP/1.1, HTTPS TLS, WebSocket, HTTP/3, WebTransport (RFC 9220)');
  Writeln('================================================================');
  Writeln('COMMAND LINE SWITCHES (CLI):');
  Writeln('  -mode:http | dual | https     Select operating mode (default: dual)');
  Writeln('                                 http:  Plain HTTP/1.1 + ws:// only (no SSL cert required)');
  Writeln('                                 dual:  Simultaneous HTTP + HTTPS on two separate ports');
  Writeln('                                 https: HTTPS (TLS 1.3/1.2) + wss:// + HTTP/3 + WebTransport');
  Writeln('  -httpport:<port>              Port for plaintext HTTP (default: 8080)');
  Writeln('  -httpsport:<port>             Port for encrypted HTTPS / QUIC (default: 8443)');
  Writeln('  -redirect                     Automatically redirect plain HTTP to HTTPS (301)');
  Writeln('  -keepalive / -nokeepalive     Enable or disable persistent Keep-Alive connections');
  Writeln('  -nolog                        Disable all logging (maximum performance)');
  Writeln('  -daemon                       Run as continuous background daemon without console input');
  Writeln('  -certstore:<name>             Windows Certificate Store name (default: GHttpsIOCPSvr)');
  Writeln('  -subject:<name>               TLS Certificate Subject name (default: localhost)');
  Writeln('  -help / -h / -?               Display this help message');
  Writeln('----------------------------------------------------------------');
  Writeln('WEBTRANSPORT ENDPOINTS:');
  Writeln('  /webtransport                 Primary WebTransport endpoint (CONNECT handshake + Echo)');
  Writeln('  /wt                           Short alias endpoint for WebTransport');
  Writeln('================================================================');
  Writeln('SERVER CONTROL:');
  Writeln('  [ENTER]                       Graceful server shutdown');
  Writeln('================================================================');
end;

const
   DOWNLOAD_DIR = 'download';
   DOWNLAD_FILE = 'largefile_10mb.bin';

begin
  if FindCmdLineSwitch('help', True) or FindCmdLineSwitch('h', True) or
     FindCmdLineSwitch('?', True) or FindCmdLineSwitch('-help', True) then
  begin
    PrintUsage;
    Exit;
  end;

  PrepareTestFile(DOWNLOAD_DIR, DOWNLAD_FILE, 10 * 1024 * 1024);
  ConfigureFastMM;
  try
    var LoggingDisabled := FindCmdLineSwitch('nolog', True) or
                           FindCmdLineSwitch('disable-log', True) or
                           FindCmdLineSwitch('no-log', True);

    Logger.WaitForFlushBeforeExit := 60;
    Logger.Providers.Add(GlobalLogFileProvider);
    Logger.Providers.Add(GlobalLogConsoleProvider);

    var AFileName := '.\Log';
    if (not LoggingDisabled) and (not TDirectory.Exists(AFileName)) then
       TDirectory.CreateDirectory(AFileName);

    with GlobalLogFileProvider do
    begin
      FileName := AFileName + '\GHttpsIOCPSvrWebTransport.log';
      DailyRotate := True;
      MaxFileSizeInMB := 50;
      LogLevel := LOG_ALL;
      Enabled := not LoggingDisabled;
    end;
    with GlobalLogConsoleProvider do
    begin
      LogLevel := LOG_DEBUG;
      ShowEventColors := True;
      Enabled := not LoggingDisabled;
    end;

    var CertStoreName: string := 'GHttpsIOCPSvr';
    var SubjectNameParam: string := 'localhost';
    var CustomCertStore: string;
    if FindCmdLineSwitch('certstore', CustomCertStore, True) and (CustomCertStore <> '') then
    begin
      CertStoreName := CustomCertStore;
      Logger.Info(Format('Using custom Certificate Store: "%s"', [CertStoreName]));
    end
    else
      Logger.Info(Format('Using default Certificate Store: "%s"', [CertStoreName]));

    var CustomSubject: string;
    if FindCmdLineSwitch('subject', CustomSubject, True) and (CustomSubject <> '') then
    begin
      SubjectNameParam := CustomSubject;
      Logger.Info(Format('Using custom Certificate Subject: "%s"', [SubjectNameParam]));
    end
    else
      Logger.Info(Format('Using default Certificate Subject: "%s"', [SubjectNameParam]));

    var HttpPortParam: Word := 8080;
    var HttpsPortParam: Word := 8443;
    var ModeParam: TServerProtocolMode := pmDualHttpAndHttps;
    var HttpActionParam: THttpActionOnDualMode := haServeNormally;
    var KeepAliveParam: Boolean := True;

    if FindCmdLineSwitch('nokeepalive', True) or FindCmdLineSwitch('disable-keepalive', True) then
    begin
      KeepAliveParam := False;
      Logger.Info('Keep-Alive disabled via command line');
    end
    else if FindCmdLineSwitch('keepalive', True) then
    begin
      KeepAliveParam := True;
      Logger.Info('Keep-Alive explicitly enabled via command line');
    end;

    var HttpPortStr: string;
    if FindCmdLineSwitch('httpport', HttpPortStr, True) then
    begin
      var P := StrToIntDef(HttpPortStr, 0);
      if (P > 0) and (P <= 65535) then
        HttpPortParam := P;
    end;

    var HttpsPortStr: string;
    if FindCmdLineSwitch('httpsport', HttpsPortStr, True) then
    begin
      var P := StrToIntDef(HttpsPortStr, 0);
      if (P > 0) and (P <= 65535) then
        HttpsPortParam := P;
    end;

    var ModeStr: string;
    if FindCmdLineSwitch('mode', ModeStr, True) then
    begin
      ModeStr := LowerCase(ModeStr);
      if ModeStr = 'http' then
        ModeParam := pmHttpOnly
      else if ModeStr = 'https' then
        ModeParam := pmHttpsOnly
      else if ModeStr = 'dual' then
        ModeParam := pmDualHttpAndHttps;
    end;

    if FindCmdLineSwitch('redirect', True) then
      HttpActionParam := haRedirectToHttps;

    Logger.Info('================================================================');
    Logger.Info('  GHttpsIOCPSvrWebTransport - High Performance WebTransport Server');
    Logger.Info('  Protocols: HTTP/1.1, HTTPS TLS, WebSocket, HTTP/3 QUIC, WebTransport (RFC 9220)');
    Logger.Info('================================================================');
    case ModeParam of
      pmHttpOnly:
        Logger.Info(Format('Operating Mode: HTTP-Only on port %d', [HttpPortParam]));
      pmHttpsOnly:
        Logger.Info(Format('Operating Mode: HTTPS-Only on port %d (TLS + HTTP/3 + WebTransport)', [HttpsPortParam]));
      pmDualHttpAndHttps:
      begin
        var ActionStr := 'Serve independently';
        if HttpActionParam = haRedirectToHttps then
          ActionStr := Format('Redirect HTTP to HTTPS (port %d)', [HttpsPortParam]);
        Logger.Info(Format('Operating Mode: Dual-Stack (HTTP:%d + HTTPS:%d) - %s',
          [HttpPortParam, HttpsPortParam, ActionStr]));
      end;
    end;
    Logger.Info('================================================================');
    Logger.Info('Starting server...');

    var Server := TGHttpsServerIOCP.Create(HttpsPortParam, SubjectNameParam,
                               CertStoreName,
                               'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!',
                               2000,
                               1000000,
                               DEFAULT_MAX_REQUEST_HEDER_SIZE,
                               DEFAULT_MAX_REQUEST_SIZE,
                               DEFAULT_MAX_RESPONSE_SIZE,
                               DEFAULT_CHUNK_SIZE,
                               50,
                               85,
                               True,
                               KeepAliveParam,
                               HttpPortParam,
                               HttpActionParam);
    try
      Server.SetSSLShutdownOptions(True, 200);
      Server.EnableKeepAlive := KeepAliveParam;
      Server.EnableHttp3 := True;
      Server.RegisterWebTransportRoute(
        '/webtransport',
        nil,
        procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
        begin
          Session.SendOnStream(Stream, Data);
        end,
        procedure(Session: PWTSessionContext; const Data: TBytes)
        begin
          Session.SendDatagram(Data);
        end,
        nil
      );

      Server.RegisterWebTransportRoute(
        '/wt',
        nil,
        procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
        begin
          Session.SendOnStream(Stream, Data);
        end,
        procedure(Session: PWTSessionContext; const Data: TBytes)
        begin
          Session.SendDatagram(Data);
        end,
        nil
      );

      Server.RegisterWebSocketRoute('/chat',
        procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const MessageText: string; Opcode: TWebSocketOpcode)
        begin
          if Opcode = wsOpText then
            Session.SendText(MessageText);
          AServer.TriggerWebSocketWrite(Session);
        end
      );

      Server.RegisterWebSocketRoute('/ws');

      Server.RegisterEndpointProc('/status', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          Json: TJSONObject;
        begin
          Json := TJSONObject.Create;
          try
            Json.AddPair('status', 'ok');
            Json.AddPair('time', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
            Json.AddPair('server', 'GHttpsIOCPSvrWebTransport');
            Json.AddPair('webtransport_enabled', TJSONBool.Create(True));
            Json.AddPair('keepalive', TJSONBool.Create(AServer.EnableKeepAlive));
            AResponse.AddJSONContent(Json.ToJSON);
          finally
            Json.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/protocol', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          ProtoJson: TJSONObject;
        begin
          ProtoJson := TJSONObject.Create;
          try
            ProtoJson.AddPair('server', 'GHttpsIOCPSvrWebTransport');
            ProtoJson.AddPair('protocols_active', 'HTTP/1.1 + HTTPS TLS + WebSocket + HTTP/3 QUIC + WebTransport (RFC 9220)');
            ProtoJson.AddPair('webtransport_routes', TJSONArray.Create.Add('/webtransport').Add('/wt'));
            ProtoJson.AddPair('alt_svc', Format('h3=":%d"; ma=86400', [HttpsPortParam]));
            AResponse.AddJSONContent(ProtoJson.ToJSON);
          finally
            ProtoJson.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/login', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          RequestBody: string;
          JsonRequest, CustomClaims, JsonResponse: TJSONObject;
          Username, Password, Token: string;
        begin
          if not StartsText('application/json', ARequest.Headers.ContentType) then
          begin
            AResponse.SetBadRequest('Invalid Content-Type. Expected application/json.');
            Exit;
          end;
          RequestBody := ARequest.BodyAsString;
          if RequestBody = '' then
          begin
            AResponse.SetBadRequest('Request body cannot be empty.');
            Exit;
          end;
          JsonRequest := nil;
          try
            try
              JsonRequest := TJSONObject.ParseJSONValue(RequestBody) as TJSONObject;
              if not Assigned(JsonRequest) then
              begin
                AResponse.SetBadRequest('Invalid JSON format.');
                Exit;
              end;
              Username := JsonRequest.GetValue<string>('username', '');
              Password := JsonRequest.GetValue<string>('password', '');
              if (Username = 'admin') and (Password = 'password123') then
              begin
                CustomClaims := TJSONObject.Create;
                try
                  CustomClaims.AddPair('role', TJSONString.Create('administrator'));
                  CustomClaims.AddPair('department', TJSONString.Create('IT'));
                  Token := AServer.JWTManager.CreateToken(Username, CustomClaims);
                  if Token <> '' then
                  begin
                    JsonResponse := TJSONObject.Create;
                    try
                      JsonResponse.AddPair('token_type', TJSONString.Create('Bearer'));
                      JsonResponse.AddPair('access_token', TJSONString.Create(Token));
                      JsonResponse.AddPair('expires_in', TJSONNumber.Create(AServer.JWTManager.TokenExpiration * 60));
                      AResponse.AddJSONContent(JsonResponse.ToJSON);
                    finally
                      JsonResponse.Free;
                    end;
                  end
                  else
                  begin
                    AResponse.SetInternalServerError('Failed to generate JWT token.');
                  end;
                finally
                  CustomClaims.Free;
                end;
              end
              else
              begin
                AResponse.SetUnauthorized('Invalid username or password.');
              end;
            except
              on E: Exception do
              begin
                AResponse.SetBadRequest('Error processing request: ' + E.Message);
              end;
            end;
          finally
            if Assigned(JsonRequest) then
              JsonRequest.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/echo', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          Msg: string;
        begin
          if ARequest.RequestInfo.QueryParameters.TryGetValue('msg', Msg) then
          begin
            AResponse.SetStatus(200);
            AResponse.AddTextContent('text/plain; charset=utf-8', Msg);
          end
          else
          begin
            var ResponseStr: String := '<html><body><h1>Echo Parameters</h1><ul>';
            ResponseStr := ResponseStr + '<li>Method: GET</li>';

            for var Pair in ARequest.RequestInfo.QueryParameters do
            begin
               ResponseStr := ResponseStr + Format('<p><li>%s = %s</li></p>',
                             [Pair.Key, Pair.Value]);
            end;
            ResponseStr := ResponseStr + '</ul></body></html>';
            AResponse.SetStatus(200);
            AResponse.AddTextContent('text/html; charset=utf-8', ResponseStr);
          end;
        end, atNone);

      Server.RegisterEndpointProc('/echojson', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          JsonValue: TJSONValue;
        begin
          if not StartsText('application/json', ARequest.Headers.ContentType) then
          begin
            AResponse.SetBadRequest('Invalid Content-Type header. Expected ''application/json''.');
            Exit;
          end;
          if ARequest.BodyAsString = '' then
          begin
            AResponse.SetBadRequest('Request body cannot be empty.');
            Exit;
          end;
          JsonValue := nil;
          try
            JsonValue := TJSONObject.ParseJSONValue(ARequest.BodyAsString);
            try
              if not Assigned(JsonValue) then
              begin
                AResponse.SetBadRequest('The provided body is not valid JSON.');
                Exit;
              end;
              AResponse.AddJSONContent(ARequest.BodyAsString);
            except
              on E: EJSONParseException do
              begin
                AResponse.SetBadRequest('Error parsing JSON: ' + E.Message);
              end;
              on E: Exception do
              begin
                AResponse.SetInternalServerError('An unexpected error occurred: ' + E.Message);
              end;
            end;
          finally
            if Assigned(JsonValue) then
              JsonValue.Free;
          end;
        end, atJWTBearer);

      Server.RegisterEndpointProc('/upload', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          UploadDir: string;
          SavedFilesCount: Integer;
          i: Integer;
          Part: TBodyPart;
          FilePart: TBinaryBodyPart;
          OriginalFileName, Ext, UniqueFileName, DestFilePath, GuidStr: string;
          NewGuid: TGUID;
          JsonRoot, JsonFileResult: TJSONObject;
          JsonFilesArray, JsonFieldsArray: TJSONArray;
          HasErrors: Boolean;
        begin
          UploadDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'uploads');
          SavedFilesCount := 0;
          HasErrors := False;
          JsonRoot := TJSONObject.Create;
          JsonFilesArray := TJSONArray.Create;
          JsonFieldsArray := TJSONArray.Create;
          try
            if not TDirectory.Exists(UploadDir) then
               TDirectory.CreateDirectory(UploadDir);
            if ARequest.BodyPartCount > 0 then
            begin
              for i := 0 to ARequest.BodyPartCount - 1 do
              begin
                Part := ARequest.GetBodyPart(i);
                if Assigned(Part) then
                begin
                  if (Part is TBinaryBodyPart) and (TBinaryBodyPart(Part).FileName <> '') then
                  begin
                    FilePart := TBinaryBodyPart(Part);
                    OriginalFileName := TPath.GetFileName(FilePart.FileName);
                    Ext := TPath.GetExtension(OriginalFileName);
                    if CreateGUID(NewGuid) = S_OK then
                      GuidStr := StringReplace(GUIDToString(NewGuid), '-', '', [rfReplaceAll])
                    else
                      GuidStr := IntToStr(Random(MaxInt));
                    UniqueFileName := FormatDateTime('yyyymmddhhnnsszzz', Now) + '_' + GuidStr + Ext;
                    DestFilePath := TPath.Combine(UploadDir, UniqueFileName);
                    JsonFileResult := TJSONObject.Create;
                    JsonFileResult.AddPair('original_name', OriginalFileName);
                    try
                      if FilePart.MoveTo(DestFilePath) then
                      begin
                        JsonFileResult.AddPair('status', 'saved');
                        JsonFileResult.AddPair('saved_as', UniqueFileName);
                        JsonFileResult.AddPair('size_bytes', TJSONNumber.Create(FilePart.Size));
                        Inc(SavedFilesCount);
                      end
                      else
                      begin
                        JsonFileResult.AddPair('status', 'error');
                        JsonFileResult.AddPair('error_message', FilePart.ErrorMessage);
                        HasErrors := True;
                      end;
                    except
                      on E: Exception do
                      begin
                        JsonFileResult.AddPair('status', 'exception');
                        JsonFileResult.AddPair('error_message', E.Message);
                        HasErrors := True;
                      end;
                    end;
                    JsonFilesArray.Add(JsonFileResult);
                  end
                  else
                  begin
                    var JsonField := TJSONObject.Create;
                    JsonField.AddPair(Part.Name, Part.AsString);
                    JsonFieldsArray.Add(JsonField);
                  end;
                end;
              end;
            end;
            if HasErrors then
            begin
              JsonRoot.AddPair('status', 'error');
              JsonRoot.AddPair('message', Format('%d file(s) saved, but some errors occurred.', [SavedFilesCount]));
              AResponse.SetInternalServerError();
            end
            else
            begin
              JsonRoot.AddPair('status', 'success');
              JsonRoot.AddPair('message', Format('Successfully saved %d file(s).', [SavedFilesCount]));
            end;
            JsonRoot.AddPair('files_processed', JsonFilesArray);
            JsonRoot.AddPair('form_fields', JsonFieldsArray);
            AResponse.AddJSONContent(JsonRoot.ToJSON);
          finally
            JsonRoot.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/', hmGET,
      procedure(Sender: TObject; const ARequest: TRequest;
                                 const AResponse: TResponse;
                                 AServer:TGHttpsServerIOCP)
      begin
        AResponse.AddHTMLContent(GetWebTransportDemoHTML);
      end);

      Server.RegisterEndpointProc('/jwt/token', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer:TGHttpsServerIOCP)
        var
          RequestBody: string;
          JsonRequest, CustomClaims, JsonResponse: TJSONObject;
          Username, Password, Token: string;
        begin
          if not StartsText('application/json', ARequest.Headers.ContentType) then
          begin
            AResponse.SetBadRequest('Invalid Content-Type. Expected application/json.');
            Exit;
          end;
          RequestBody := ARequest.BodyAsString;
          if RequestBody = '' then
          begin
            AResponse.SetBadRequest('Request body cannot be empty.');
            Exit;
          end;
          JsonRequest := nil;
          try
            try
              JsonRequest := TJSONObject.ParseJSONValue(RequestBody) as TJSONObject;
              if not Assigned(JsonRequest) then
              begin
                AResponse.SetBadRequest('Invalid JSON format.');
                Exit;
              end;
              Username := JsonRequest.GetValue<string>('username', '');
              Password := JsonRequest.GetValue<string>('password', '');
              if (Username = 'admin') and (Password = 'password123') then
              begin
                CustomClaims := TJSONObject.Create;
                try
                  CustomClaims.AddPair('role', TJSONString.Create('administrator'));
                  CustomClaims.AddPair('department', TJSONString.Create('IT'));
                  Token := AServer.JWTManager.CreateToken(Username, CustomClaims);
                  if Token <> '' then
                  begin
                    JsonResponse := TJSONObject.Create;
                    try
                      JsonResponse.AddPair('token_type', TJSONString.Create('Bearer'));
                      JsonResponse.AddPair('access_token', TJSONString.Create(Token));
                      JsonResponse.AddPair('expires_in', TJSONNumber.Create(AServer.JWTManager.TokenExpiration * 60));
                      AResponse.AddJSONContent(JsonResponse.ToJSON);
                    finally
                      JsonResponse.Free;
                    end;
                  end
                  else
                  begin
                    AResponse.SetInternalServerError('Failed to generate JWT token.');
                  end;
                finally
                  CustomClaims.Free;
                end;
              end
              else
              begin
                AResponse.SetUnauthorized('Invalid username or password.');
              end;
            except
              on E: Exception do
              begin
                AResponse.SetBadRequest('Error processing request: ' + E.Message);
              end;
            end;
          finally
            if Assigned(JsonRequest) then
              JsonRequest.Free;
          end;
        end);

      Server.RegisterEndpointProc('/jwt/protected', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer:TGHttpsServerIOCP)
        var
          Json: TJSONObject;
        begin
          Json := TJSONObject.Create;
          try
            Json.AddPair('message', 'Access granted to protected resource');
            Json.AddPair('timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss', Now));
            AResponse.AddJSONContent(Json.ToJSON);
          finally
            Json.Free;
          end;
        end, atJWTBearer);

      Server.RegisterEndpointProc('/status', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        begin
          AResponse.AddJSONContent('{"status":"ok","server":"GHttpsIOCPSvr","webtransport_enabled":true}');
        end);

      Server.RegisterEndpointProc('/echo', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          Msg: string;
        begin
          if ARequest.RequestInfo.QueryParameters.TryGetValue('msg', Msg) then
            AResponse.AddTextContent('text/plain; charset=utf-8', Msg)
          else if Length(ARequest.BodyAsString) > 0 then
            AResponse.AddTextContent('text/plain', ARequest.BodyAsString)
          else
            AResponse.AddTextContent('text/plain', 'h3_echo_ok');
        end);

      Server.RegisterEndpointProc('/400_check', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetBadRequest('400 Bad Request');
        end);

      Server.RegisterEndpointProc('/405_check', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetMethodNotAllowed('405 Method Not Allowed');
        end);

      Server.RegisterEndpointProc('/download', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          DownloadSize: Integer;
          SizeStr: string;
          Data: TBytes;
        begin
          DownloadSize := 65536;
          if ARequest.RequestInfo.QueryParameters.TryGetValue('size', SizeStr) then
            DownloadSize := StrToIntDef(SizeStr, 65536);
          if DownloadSize > 10 * 1024 * 1024 then
            DownloadSize := 10 * 1024 * 1024;
          SetLength(Data, DownloadSize);
          FillChar(Data[0], DownloadSize, Ord('X'));
          AResponse.AddBinaryContent('application/octet-stream', Data);
        end);

      Server.RegisterEndpointProc('/large', hmGET,
      procedure(Sender: TObject; const ARequest: TRequest;
                                 const AResponse: TResponse;
                                 AServer:TGHttpsServerIOCP)
      var
        FilePath: string;
        Data: TBytes;
      begin
        FilePath := TPath.Combine(ExtractFilePath(ParamStr(0)), DOWNLOAD_DIR, DOWNLAD_FILE);
        if TFile.Exists(FilePath) then
          AResponse.AddFileStreamContent('application/octet-stream', FilePath)
        else
        begin
          SetLength(Data, 10485760);
          FillChar(Data[0], 10485760, $AA);
          AResponse.AddBinaryContent('application/octet-stream', Data);
        end;
      end);

      Server.RegisterEndpointProc('/api/metrics', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          MetricsJson: TJSONObject;
        begin
          MetricsJson := TJSONObject.Create;
          try
            MetricsJson.AddPair('pool_count', TJSONNumber.Create(AServer.OverlappedPool.Count));
            MetricsJson.AddPair('total_created', TJSONNumber.Create(AServer.OverlappedPool.TotalCreated));
            MetricsJson.AddPair('active_connections', TJSONNumber.Create(AServer.ActiveConnections));
            AResponse.AddJSONContent(MetricsJson.ToJSON);
          finally
            MetricsJson.Free;
          end;
        end
      );

      Server.Start;
      if not Server.Running then
      begin
        Logger.Error('CRITICAL: Server startup failed (e.g. missing certificate). Exiting application.');
        ExitCode := 1;
        Exit;
      end;

      Logger.Info('================================================================');
      Logger.Info('  GHttpsIOCPSvrWebTransport STARTED SUCCESSFULLY AND READY');
      Logger.Info('================================================================');
      if HttpsPortParam > 0 then
      begin
        Logger.Info(Format('  [HTTPS TLS]    https://localhost:%d/status', [HttpsPortParam]));
        Logger.Info(Format('  [WebSocket]    wss://localhost:%d/chat', [HttpsPortParam]));
        Logger.Info(Format('  [HTTP/3 QUIC]  UDP Port %d (Alt-Svc h3 enabled)', [HttpsPortParam]));
        Logger.Info(Format('  [WebTransport] https://localhost:%d/webtransport', [HttpsPortParam]));
        Logger.Info(Format('  [WebTransport] https://localhost:%d/wt', [HttpsPortParam]));
      end;
      if HttpPortParam > 0 then
      begin
        Logger.Info(Format('  [HTTP Plain]   http://localhost:%d/status', [HttpPortParam]));
        Logger.Info(Format('  [WebSocket]    ws://localhost:%d/chat', [HttpPortParam]));
      end;
      Logger.Info('----------------------------------------------------------------');
      Logger.Info('  CONTROL: Press [ENTER] in console window to gracefully stop the server.');
      Logger.Info('================================================================');

      if FindCmdLineSwitch('daemon') then
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
    finally
      Server.Free;
    end;
    Logger.Info('Program completed cleanly.');
  except
    on E: Exception do
    begin
      Writeln('Error: ' + E.ClassName +  ': ' + E.Message);
      Logger.Error('Error: ' + E.ClassName +  ': ' + E.Message);
    end;
  end;
end.
