{
  MIT License

  Copyright (c) (c) 2025 GECKO-71

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
  WinApiAdditions in 'src\WinApiAdditions.pas';

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
  begin
    Exit;
  end;
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
      begin
        FileStream.WriteBuffer(Buffer[0], BufferSize);
      end;
      if RemainingBytes > 0 then
      begin
        FileStream.WriteBuffer(Buffer[0], RemainingBytes);
      end;
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

const
   DOWNLOAD_DIR = 'download';
   DOWNLAD_FILE = 'largefile_10mb.bin';

begin
  PrepareTestFile(DOWNLOAD_DIR, DOWNLAD_FILE, 10 * 1024 * 1024);
  ConfigureFastMM;
  try
    Logger.Providers.Add(GlobalLogFileProvider);
    Logger.Providers.Add(GlobalLogConsoleProvider);
    var AFileName := '.\Log';
    if not TDirectory.Exists(AFileName) then
       TDirectory.CreateDirectory(AFileName);

    with GlobalLogFileProvider do
   	begin
      FileName := AFileName + '\Logger.log';
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
    Writeln('If you don''t have an existing certificate,');
    Writeln('this command generates a self-signed X.509 certificate for localhost to enable secure');
    Writeln('HTTPS communication for testing purposes on a local server.');
    Writeln('MakeCert.exe -r -pe -n "CN=localhost" -ss GHttpsIOCPSvr -a sha256 -sky exchange -sp "Microsoft Enhanced RSA and AES Cryptographic Provider" -sy 24');
    Logger.Info('====================================');
    Logger.Info('');
    var Server := TGHttpsServerIOCP.Create(8443, 'localhost', 'GHttpsIOCPSvr');
    try
      Server.SetSSLShutdownOptions(True, 200);
      ///////////////////////////////////////////////////
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
            '<h1>HTTPS IOCP Server is Running</h1>' +
            '<p>Connection successful. The server is operational.</p>' +
            '<p>Server time is: %s UTC</p>' +
          '</body>' +
          '</html>',
           [FormatDateTime('yyyy-mm-dd hh:nn:ss', Now)]
        );
        AResponse.AddHTMLContent(Html);
      end);
      ///////////////////////////////////////////////////
      Server.RegisterEndpointProc('/login', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse                                   ;
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
                      JsonResponse.AddPair('expires_in', TJSONNumber.Create(AServer.JWTManager.TokenExpiration * 60)); // w sekundach
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
      ///////////////////////////////////////////////////
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
      ///////////////////////////////////////////////////
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
            end
          finally
            if Assigned(JsonValue) then
              JsonValue.Free;
          end;
        end, atJWTBearer);
      //////////////////////////////////////////////////////
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
      //////////////////////////////////////////////////////
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
      ///////////////////////////////////////////////////////////////////////////
      Server.Start;
      Logger.Info('Server running. Press Enter to stop...');
      Readln;
      Server.Stop;
    finally
      Server.Free;
    end;
    Logger.Info('Program completed');
  except
    on E: Exception do
    begin
      Logger.Error('Error: ' + E.ClassName +  ': ' + E.Message);
      Logger.Info('Press Enter to finish...');
      Readln;
    end;
  end;
end.
