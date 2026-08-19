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

program GHttpsIOCPSvr;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
  System.NetEncoding,
  System.StrUtils,
  System.IOUtils,
  System.JSON,
  GHttpsServerIOCP in 'src\GHttpsServerIOCP.pas',
  GJWTManager in 'src\GJWTManager.pas',
  GRequest in 'src\GRequest.pas',
  GRequestBody in 'src\GRequestBody.pas',
  GResponse in 'src\GResponse.pas',
  OverlappedExPool in 'src\OverlappedExPool.pas',
  WinApiAdditions in 'src\WinApiAdditions.pas',
  WinApi.MsQuic in 'Http3Delphi\WinApi.MsQuic.pas',
  Net.MsQuic in 'Http3Delphi\Net.MsQuic.pas',
  Net.Http3Frames in 'Http3Delphi\Net.Http3Frames.pas',
  Net.QPACK.Huffman in 'Http3Delphi\Net.QPACK.Huffman.pas',
  Net.QPACK in 'Http3Delphi\Net.QPACK.pas',
  Net.Http3Request in 'Http3Delphi\Net.Http3Request.pas',
  Net.Http3Response in 'Http3Delphi\Net.Http3Response.pas',
  Net.Http3Server in 'Http3Delphi\Net.Http3Server.pas';

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

procedure PrintUsage;
begin
  Writeln('================================================================');
  Writeln('  GHttpsIOCPSvr - High Performance Hybrid IOCP Server');
  Writeln('  Supported Protocols: HTTP/1.1, HTTPS (TLS 1.3/1.2), HTTP/3 QUIC');
  Writeln('================================================================');
  Writeln('COMMAND LINE SWITCHES (CLI):');
  Writeln('  -mode:http | dual | https     Select operating mode (default: dual)');
  Writeln('                                 http:  Plain HTTP/1.1 only (no SSL certificate required)');
  Writeln('                                 dual:  Simultaneous HTTP + HTTPS on two separate ports');
  Writeln('                                 https: HTTPS (TLS 1.3/1.2) + HTTP/3 only');
  Writeln('  -httpport:<port>              Port for plaintext HTTP (default: 8080)');
  Writeln('  -httpsport:<port>             Port for encrypted HTTPS TLS (default: 8443)');
  Writeln('  -redirect                     Automatically redirect plain HTTP to HTTPS (301)');
  Writeln('  -keepalive / -nokeepalive     Enable or disable persistent Keep-Alive connections');
  Writeln('  -nolog                        Disable all logging (maximum performance)');
  Writeln('  -certstore:<name>             Windows Certificate Store name (default: GHttpsIOCPSvr)');
  Writeln('  -subject:<name>               TLS Certificate Subject name (default: localhost)');
  Writeln('  -help / -h / -?               Display this help message');
  Writeln('----------------------------------------------------------------');
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
      FileName := AFileName + '\Logger.log';
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
    var KeepAliveParam := not (FindCmdLineSwitch('nokeepalive', True) or
                               FindCmdLineSwitch('no-keepalive', True) or
                               FindCmdLineSwitch('disable-keepalive', True));

    if FindCmdLineSwitch('keepalive', True) or
       FindCmdLineSwitch('keep-alive', True) or
       FindCmdLineSwitch('enable-keepalive', True) then
      KeepAliveParam := True;

    var HttpsPortParam: Word := 8443;
    var HttpPortParam: Word := 8080;
    var HttpActionParam: THttpActionOnDualMode := haServeNormally;

    var ParamIdx: Integer;
    for ParamIdx := 1 to ParamCount do
    begin
      var Param := ParamStr(ParamIdx);
      if (Length(Param) > 1) and ((Param[1] = '-') or (Param[1] = '/')) then
      begin
        var CleanParam := Copy(Param, 2, MaxInt);
        var Key := CleanParam;
        var Val := '';
        var SepPos := Pos(':', CleanParam);
        if SepPos = 0 then SepPos := Pos('=', CleanParam);
        if SepPos > 0 then
        begin
          Key := Copy(CleanParam, 1, SepPos - 1);
          Val := Copy(CleanParam, SepPos + 1, MaxInt);
        end
        else if (ParamIdx < ParamCount) and (Length(ParamStr(ParamIdx + 1)) > 0) and (not ((ParamStr(ParamIdx + 1)[1] = '-') or (ParamStr(ParamIdx + 1)[1] = '/'))) then
        begin
          Val := ParamStr(ParamIdx + 1);
        end;

        if SameText(Key, 'mode') then
        begin
          if SameText(Val, 'http') or SameText(Val, 'httponly') then
          begin
            HttpsPortParam := 0;
            if HttpPortParam = 0 then HttpPortParam := 8080;
          end
          else if SameText(Val, 'https') or SameText(Val, 'httpsonly') then
          begin
            HttpsPortParam := 8443;
            HttpPortParam := 0;
          end
          else if SameText(Val, 'dual') or SameText(Val, 'dualstack') then
          begin
            if HttpsPortParam = 0 then HttpsPortParam := 8443;
            if HttpPortParam = 0 then HttpPortParam := 8080;
          end;
        end
        else if SameText(Key, 'httponly') or SameText(Key, 'http-only') then
        begin
          HttpsPortParam := 0;
          if HttpPortParam = 0 then HttpPortParam := 8080;
        end
        else if SameText(Key, 'httpsonly') or SameText(Key, 'https-only') then
        begin
          HttpPortParam := 0;
          if HttpsPortParam = 0 then HttpsPortParam := 8443;
        end
        else if SameText(Key, 'port') or SameText(Key, 'httpsport') or SameText(Key, 'https-port') then
        begin
          if Length(Val) > 0 then HttpsPortParam := StrToIntDef(Val, HttpsPortParam);
        end
        else if SameText(Key, 'httpport') or SameText(Key, 'http-port') then
        begin
          if Length(Val) > 0 then HttpPortParam := StrToIntDef(Val, HttpPortParam);
        end
        else if SameText(Key, 'certstore') or SameText(Key, 'cert-store') or SameText(Key, 'store') then
        begin
          if Length(Val) > 0 then CertStoreName := Val;
        end
        else if SameText(Key, 'subject') or SameText(Key, 'cert') then
        begin
          if Length(Val) > 0 then SubjectNameParam := Val;
        end
        else if SameText(Key, 'redirect') or SameText(Key, 'redirect-to-https') then
        begin
          HttpActionParam := haRedirectToHttps;
        end;
      end;
    end;

    Logger.Info('================================================================');
    Logger.Info('  GHttpsIOCPSvr - High Performance Hybrid IOCP Server');
    Logger.Info('  Protocols: HTTP/1.1, HTTPS (TLS 1.3/1.2), HTTP/3 QUIC');
    Logger.Info('================================================================');
    Logger.Info('SERVER CONTROL:');
    Logger.Info('  Press [ENTER] in this console window to gracefully shut down.');
    Logger.Info('----------------------------------------------------------------');
    Logger.Info('ACTIVE CONFIGURATION:');
    if (HttpsPortParam > 0) and (HttpPortParam > 0) then
      Logger.Info('  Mode:            DUAL-STACK (Simultaneous HTTP + HTTPS)')
    else if HttpsPortParam > 0 then
      Logger.Info('  Mode:            HTTPS-ONLY (TLS 1.3/1.2 SChannel + HTTP/3)')
    else
      Logger.Info('  Mode:            HTTP-ONLY (Plaintext, No SSL certificate required)');
    Logger.Info(Format('  HTTPS Port:      %d', [HttpsPortParam]));
    Logger.Info(Format('  HTTP Port:       %d', [HttpPortParam]));
    Logger.Info(Format('  HTTP->HTTPS 301: %s', [BoolToStr(HttpActionParam = haRedirectToHttps, True)]));
    Logger.Info(Format('  Keep-Alive:      %s', [BoolToStr(KeepAliveParam, True)]));
    Logger.Info(Format('  Cert Store:      %s (Subject: %s)', [CertStoreName, SubjectNameParam]));
    Logger.Info('----------------------------------------------------------------');
    Logger.Info('CLI SWITCHES GUIDE:');
    Logger.Info('  -mode:http|dual|https  -httpport:<port>  -httpsport:<port>');
    Logger.Info('  -redirect              -keepalive|-nokeepalive  -nolog');
    Logger.Info('  -certstore:<name>      -subject:<name>          -help');
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
            Json.AddPair('server', 'GHttpsIOCPSvr-Hybrid');
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
          Json: TJSONObject;
        begin
          Json := TJSONObject.Create;
          try
            Json.AddPair('protocol', 'HTTP/1.1');
            Json.AddPair('server', 'GHttpsIOCPSvr');
            AResponse.AddJSONContent(Json.ToJSON);
          finally
            Json.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/', hmGET,
      procedure(Sender: TObject; const ARequest: TRequest;
                                 const AResponse: TResponse;
                                 AServer:TGHttpsServerIOCP)
      var
        Html: string;
      begin
        Html := Format(
          '<!DOCTYPE html>' +
          '<html lang="en">' +
          '<head>' +
            '<meta charset="UTF-8">' +
            '<title>HTTPS IOCP Server</title>' +
            '<style>body { font-family: sans-serif; text-align: center; padding-top: 5em; color: #444; }</style>' +
          '</head>' +
          '<body>' +
            '<h1>GHttpsIOCPSvr Hybrid Server is Running</h1>' +
            '<p>Connection successful. The server is operational.</p>' +
            '<p>Server time is: %s UTC</p>' +
          '</body>' +
          '</html>',
           [FormatDateTime('yyyy-mm-dd hh:nn:ss', Now)]
        );
        AResponse.AddHTMLContent(Html);
      end);

      Server.RegisterEndpointProc('/login', hmPOST,
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
        end
      );

      Server.RegisterEndpointProc('/echo', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer:TGHttpsServerIOCP)
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
        end, atNone);

      Server.RegisterEndpointProc('/echojson', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer:TGHttpsServerIOCP)
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

      Server.RegisterEndpointProc('/large', hmGET,
      procedure(Sender: TObject; const ARequest: TRequest;
                                 const AResponse: TResponse;
                                       AServer:TGHttpsServerIOCP)
      var
        FilePath: string;
      begin
        FilePath := TPath.Combine(ExtractFilePath(ParamStr(0)), DOWNLOAD_DIR, DOWNLAD_FILE);
        if not TFile.Exists(FilePath) then
        begin
          AResponse.SetNotFound('The requested file could not be found on the server.');
          Exit;
        end;
        try
          AResponse.AddFileStreamContent('application/octet-stream', FilePath);
        except
          on E: Exception do
          begin
            AResponse.SetInternalServerError('An error occurred while trying to serve the file: ' + E.Message);
          end;
        end;
      end);

      Server.RegisterEndpointProc('/upload', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                 const AResponse: TResponse;
                                       AServer:TGHttpsServerIOCP)
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
      Logger.Info('  SERVER STARTED SUCCESSFULLY AND READY FOR TRAFFIC');
      Logger.Info('================================================================');
      if HttpsPortParam > 0 then
      begin
        Logger.Info(Format('  [HTTPS TLS]   https://localhost:%d/status', [HttpsPortParam]));
        Logger.Info(Format('  [HTTP/3 QUIC] UDP Port %d (Alt-Svc h3 enabled)', [HttpsPortParam]));
      end;
      if HttpPortParam > 0 then
      begin
        Logger.Info(Format('  [HTTP Plain]  http://localhost:%d/status', [HttpPortParam]));
      end;
      Logger.Info('----------------------------------------------------------------');
      Logger.Info('  CONTROL: Press [ENTER] in console window to gracefully stop the server.');
      Logger.Info('================================================================');

      try
        Readln;
      except
        on E: EInOutError do ;
      end;
      Server.Stop;
    finally
      Server.Free;
    end;
    Logger.Info('Program completed');
  except
    on E: Exception do
    begin
      Writeln('Error: ' + E.ClassName +  ': ' + E.Message);
      Logger.Error('Error: ' + E.ClassName +  ': ' + E.Message);
    end;
  end;
end.
