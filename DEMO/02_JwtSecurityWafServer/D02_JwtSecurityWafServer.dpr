program D02_JwtSecurityWafServer;

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
  Winapi.WinSock2,
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
  SERVER_PORT = 8082;
  CertStoreName = 'GHttpsIOCPSvr';
  SECRET_KEY = 'SuperSecretWafKeyForDemo02JwtSecurityAndWafProtection123!';

type
  TRateLimiter = class
  private
    FLock: TCriticalSection;
    FRequests: TDictionary<string, TDateTime>;
  public
    constructor Create;
    destructor Destroy; override;
    function IsAllowed(const IP: string): Boolean;
  end;

var
  GRateLimiter: TRateLimiter;

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

constructor TRateLimiter.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FRequests := TDictionary<string, TDateTime>.Create;
end;

destructor TRateLimiter.Destroy;
begin
  FRequests.Free;
  FLock.Free;
  inherited;
end;

function TRateLimiter.IsAllowed(const IP: string): Boolean;
var
  LastTime: TDateTime;
  NowTime: TDateTime;
begin
  Result := True;
  NowTime := Now;
  FLock.Acquire;
  try
    if FRequests.TryGetValue(IP, LastTime) then
    begin
      if MilliSecondsBetween(NowTime, LastTime) < 100 then
        Result := False
      else
        FRequests[IP] := NowTime;
    end
    else
    begin
      FRequests.Add(IP, NowTime);
    end;
  finally
    FLock.Leave;
  end;
end;

function IsWafThreatDetected(const InputText: string): Boolean;
var
  Lower: string;
begin
  Lower := LowerCase(InputText);
  Result := (Pos('select ', Lower) > 0) or
            (Pos('union ', Lower) > 0) or
            (Pos('drop ', Lower) > 0) or
            (Pos('<script>', Lower) > 0) or
            (Pos('javascript:', Lower) > 0) or
            (Pos('1=1', Lower) > 0);
end;

function TryServeStaticFile(const FilePath: string; const ARequest: TRequest; const AResponse: TResponse): Boolean;
var
  Ext: string;
  ContentType: string;
  CacheControl: string;
  FileBytes: TBytes;
  ETagVal: string;
begin
  Result := False;
  if not FileExists(FilePath) then Exit;

  Ext := LowerCase(TPath.GetExtension(FilePath));
  if Ext = '.html' then
  begin
    ContentType := 'text/html; charset=utf-8';
    CacheControl := 'no-cache';
  end
  else if Ext = '.css' then
  begin
    ContentType := 'text/css';
    CacheControl := 'public, max-age=3600';
  end
  else if Ext = '.js' then
  begin
    ContentType := 'application/javascript';
    CacheControl := 'public, max-age=3600';
  end
  else if Ext = '.png' then
  begin
    ContentType := 'image/png';
    CacheControl := 'public, max-age=3600';
  end
  else if Ext = '.jpg' then
  begin
    ContentType := 'image/jpeg';
    CacheControl := 'public, max-age=3600';
  end
  else if Ext = '.json' then
  begin
    ContentType := 'application/json';
    CacheControl := 'no-cache';
  end
  else
  begin
    ContentType := 'application/octet-stream';
    CacheControl := 'public, max-age=3600';
  end;

  FileBytes := TFile.ReadAllBytes(FilePath);
  ETagVal := Format('"%d-%d"', [Length(FileBytes), DateTimeToUnix(TFile.GetLastWriteTime(FilePath))]);

  if (ARequest.Headers.GetHeader('If-None-Match') = ETagVal) then
  begin
    AResponse.SetStatus(304);
    AResponse.AddHeader('ETag', ETagVal);
    AResponse.AddHeader('Cache-Control', CacheControl);
    Exit(True);
  end;

  AResponse.SetStatus(200);
  AResponse.AddHeader('ETag', ETagVal);
  AResponse.AddHeader('Cache-Control', CacheControl);
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
      FileName := LogDir + '\JwtSecurityWafServer.log';
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
    Logger.Info('  DEMO 02: JWT Security & WAF Protection Server');
    Logger.Info('=====================================================');

    GRateLimiter := TRateLimiter.Create;
    try
      var Server := TGHttpsServerIOCP.Create(SERVER_PORT, SERVER_HOST, CertStoreName, SECRET_KEY, 2000, 1000000);
      try
        Server.SetSSLShutdownOptions(True, 200);

        Server.RegisterEndpointProc('/api/login', hmPOST,
          procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
          var
            JSONReq, JSONResp, CustomClaims: TJSONObject;
            UserStr, PassStr, RoleStr, Token, ClientIP: string;
          begin
            ClientIP := string(inet_ntoa(ARequest.RemoteAddr.sin_addr));
            if not GRateLimiter.IsAllowed(ClientIP) then
            begin
              AResponse.SetStatus(429);
              AResponse.AddJSONContent('{"error": "429 Too Many Requests - WAF Rate Limit Exceeded"}');
              Exit;
            end;

            if IsWafThreatDetected(ARequest.RequestInfo.Path) or IsWafThreatDetected(ARequest.GetBodyString) then
            begin
              Logger.Warn('WAF Threat Detected from IP: %s on /api/login', [ClientIP]);
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error": "403 Forbidden - WAF Threat Blocked"}');
              Exit;
            end;

            JSONReq := nil;
            try
              JSONReq := TJSONObject.ParseJSONValue(ARequest.GetBodyString) as TJSONObject;
            except
              JSONReq := nil;
            end;

            if not Assigned(JSONReq) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error": "Invalid JSON body"}');
              Exit;
            end;

            try
              UserStr := JSONReq.GetValue<string>('username', '');
              PassStr := JSONReq.GetValue<string>('password', '');

              if (UserStr = 'admin') and (PassStr = 'admin123') then
                RoleStr := 'admin'
              else if (UserStr = 'user') and (PassStr = 'user123') then
                RoleStr := 'user'
              else
              begin
                AResponse.SetStatus(401);
                AResponse.AddJSONContent('{"error": "Invalid credentials. Use admin/admin123 or user/user123."}');
                Exit;
              end;

              CustomClaims := TJSONObject.Create;
              try
                CustomClaims.AddPair('role', RoleStr);
                Token := AServer.JWTManager.CreateToken(UserStr, CustomClaims);
              finally
                CustomClaims.Free;
              end;

              JSONResp := TJSONObject.Create;
              try
                JSONResp.AddPair('status', 'success');
                JSONResp.AddPair('token', Token);
                JSONResp.AddPair('user', UserStr);
                JSONResp.AddPair('role', RoleStr);

                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JSONResp.ToJSON);
              finally
                JSONResp.Free;
              end;
            finally
              JSONReq.Free;
            end;
          end);

        Server.RegisterEndpointProc('/api/protected/profile', hmGET,
          procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
          var
            AuthHeader, Token, UserStr, RoleStr: string;
            JwtObj: TJWTToken;
            JSONResp: TJSONObject;
          begin
            AuthHeader := ARequest.Headers.GetHeader('Authorization');
            if not AuthHeader.StartsWith('Bearer ') then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error": "Missing or invalid Authorization Bearer header"}');
              Exit;
            end;

            Token := AuthHeader.Substring(7).Trim;
            if not AServer.JWTManager.ValidateToken(Token, JwtObj) then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error": "Invalid or expired JWT token"}');
              Exit;
            end;

            try
              UserStr := JwtObj.Subject;
              RoleStr := JwtObj.GetClaim('role');

              JSONResp := TJSONObject.Create;
              try
                JSONResp.AddPair('message', 'Access granted to Protected Profile');
                JSONResp.AddPair('user', UserStr);
                JSONResp.AddPair('role', RoleStr);
                JSONResp.AddPair('timestamp', DateTimeToStr(Now));

                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JSONResp.ToJSON);
              finally
                JSONResp.Free;
              end;
            finally
              JwtObj.Free;
            end;
          end);

        Server.RegisterEndpointProc('/api/protected/admin', hmGET,
          procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
          var
            AuthHeader, Token, UserStr, RoleStr: string;
            JwtObj: TJWTToken;
            JSONResp: TJSONObject;
          begin
            AuthHeader := ARequest.Headers.GetHeader('Authorization');
            if not AuthHeader.StartsWith('Bearer ') then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error": "Missing Authorization header"}');
              Exit;
            end;

            Token := AuthHeader.Substring(7).Trim;
            if not AServer.JWTManager.ValidateToken(Token, JwtObj) then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error": "Invalid JWT token"}');
              Exit;
            end;

            try
              UserStr := JwtObj.Subject;
              RoleStr := JwtObj.GetClaim('role');

              if RoleStr <> 'admin' then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error": "Forbidden - Admin role required"}');
                Exit;
              end;

              JSONResp := TJSONObject.Create;
              try
                JSONResp.AddPair('message', 'Welcome to Admin Dashboard');
                JSONResp.AddPair('admin_user', UserStr);
                JSONResp.AddPair('system_status', 'All Security Systems Operational');

                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JSONResp.ToJSON);
              finally
                JSONResp.Free;
              end;
            finally
              JwtObj.Free;
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
              JSONResp.AddPair('server', 'GHttpsIOCPSvr-JwtWafDemo');
              JSONResp.AddPair('waf_protection', 'enabled');
              JSONResp.AddPair('rate_limiting', '10 req/sec');

              AResponse.SetStatus(200);
              AResponse.AddJSONContent(JSONResp.ToJSON);
            finally
              JSONResp.Free;
            end;
          end);

        Server.RegisterEndpointProc('/', hmGET,
          procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
          var
            ClientIP, WebRootDir, RequestedPath, FullPath: string;
          begin
            ClientIP := string(inet_ntoa(ARequest.RemoteAddr.sin_addr));
            if not GRateLimiter.IsAllowed(ClientIP) then
            begin
              AResponse.SetStatus(429);
              AResponse.AddJSONContent('{"error": "429 Too Many Requests - WAF Rate Limit Exceeded"}');
              Exit;
            end;

            if IsWafThreatDetected(ARequest.RequestInfo.Path) or IsWafThreatDetected(ARequest.GetBodyString) then
            begin
              Logger.Warn('WAF Threat Detected from IP: %s (Path: %s)', [ClientIP, ARequest.RequestInfo.Path]);
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error": "403 Forbidden - WAF Threat Blocked"}');
              Exit;
            end;

            WebRootDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'www');
            RequestedPath := ARequest.RequestInfo.Path;
            if (RequestedPath = '/') or (RequestedPath = '') then
              RequestedPath := '/index.html';

            FullPath := TPath.Combine(WebRootDir, StringReplace(RequestedPath.TrimStart(['/', '\']), '/', '\', [rfReplaceAll]));
            if TryServeStaticFile(FullPath, ARequest, AResponse) then
               Exit;

            FullPath := TPath.Combine(WebRootDir, 'index.html');
            if not TryServeStaticFile(FullPath, ARequest, AResponse) then
               AResponse.SetNotFound('404 Not Found - DEMO 02 JWT Security & WAF Server');
          end);


        if Server.Start then
        begin
          Writeln;
          Writeln;
          Logger.Info(Format('Server started: https://%s:%d/', [SERVER_HOST, SERVER_PORT]));
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
    finally
      GRateLimiter.Free;
    end;

    Logger.Info('Server stopped successfully.');
  except
    on E: Exception do
    begin
      Logger.Error('Critical server error: ' + E.ClassName + ': ' + E.Message);
    end;
  end;
end.







