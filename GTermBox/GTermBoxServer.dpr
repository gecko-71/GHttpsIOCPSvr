program GTermBoxServer;

{$APPTYPE CONSOLE}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.SyncObjs,
  System.Generics.Collections,
  Winapi.Windows,
  Winapi.Winsock2,
  GTerm.Types in 'src\GTerm.Types.pas',
  GTerm.AppConfig in 'src\GTerm.AppConfig.pas',
  GTerm.UserConfig in 'src\GTerm.UserConfig.pas',
  GTerm.ConPty.Loader in 'src\GTerm.ConPty.Loader.pas',
  GTerm.ConPty in 'src\GTerm.ConPty.pas',
  GTerm.Session in 'src\GTerm.Session.pas',
  GHttpsServerIOCP in 'GHttpsIOCPSvr\src\GHttpsServerIOCP.pas',
  GJWTManager in 'GHttpsIOCPSvr\src\GJWTManager.pas',
  GRequest in 'GHttpsIOCPSvr\src\GRequest.pas',
  GRequestBody in 'GHttpsIOCPSvr\src\GRequestBody.pas',
  GResponse in 'GHttpsIOCPSvr\src\GResponse.pas',
  OverlappedExPool in 'GHttpsIOCPSvr\src\OverlappedExPool.pas',
  WinApiAdditions in 'GHttpsIOCPSvr\src\WinApiAdditions.pas',
  MsQuic.Types in 'GHttpsIOCPSvr\Http3DelphiV3\MsQuic.Types.pas',
  WebTransport.Types in 'GHttpsIOCPSvr\Http3DelphiV3\WebTransport.Types.pas',
  WebTransport.Session in 'GHttpsIOCPSvr\Http3DelphiV3\WebTransport.Session.pas';

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [
    mmetUnexpectedMemoryLeakDetail,
    mmetUnexpectedMemoryLeakSummary,
    mmetDebugBlockDoubleFree,
    mmetDebugBlockReallocOfFreedBlock
  ];
end;

const
  ENABLE_QUICK_EDIT_MODE = $0040;
  ENABLE_EXTENDED_FLAGS  = $0080;

type
  TPendingSession = record
    Username: string;
    ClientIP: string;
    SandboxDir: string;
    AppKey: string;
    Cols: Integer;
    Rows: Integer;
    CreatedTick: UInt64;
  end;

  TLoginRateLimit = record
    FailedCount: Integer;
    BlockedUntilTick: UInt64;
  end;

var
  Server: TGHttpsServerIOCP;
  SessionManager: TGTermSessionManager;
  PendingSessionsLock: TCriticalSection;
  PendingSessions: TDictionary<string, TPendingSession>;
  LoginRateLock: TCriticalSection;
  LoginRateMap: TDictionary<string, TLoginRateLimit>;
  BaseWebDir: string;
  CertStoreName: string;
  SubjectNameParam: string;
  HttpsPortParam: Word;
  HStdIn: THandle;
  ConsoleMode: DWORD;
  InputRec: TInputRecord;
  NumRead: DWORD;
  GServerRunning: Boolean = True;

function ConsoleCtrlHandler(dwCtrlType: DWORD): BOOL; stdcall;
begin
  case dwCtrlType of
    CTRL_C_EVENT,
    CTRL_BREAK_EVENT,
    CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT:
    begin
      GServerRunning := False;
      Result := True;
    end;
  else
    Result := False;
  end;
end;

function ResolveJwtSecret: string;
const
  SecretChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
var
  EnvSecret: string;
  I, R: Integer;
begin
  EnvSecret := GetEnvironmentVariable('GTERM_JWT_SECRET');
  if Length(Trim(EnvSecret)) >= 32 then
    Exit(Trim(EnvSecret));
  SetLength(Result, 64);
  for I := 1 to 64 do
  begin
    R := Random(Length(SecretChars)) + 1;
    Result[I] := SecretChars[R];
  end;
end;

procedure EnsureUserAppShims(const AUsername: string; const ASandboxDir: string);
var
  BaseDir, FullSandbox, ShimPath, CmdContent: string;
  UserEntry: TUserEntry;
  AppId: string;
  AppEntry: TAppEntry;
  FullCmd, ArgsStr, Arg: string;
  I: Integer;
begin
  BaseDir := ExtractFilePath(ParamStr(0));
  FullSandbox := TPath.Combine(BaseDir, ASandboxDir);
  if not TDirectory.Exists(FullSandbox) then
    TDirectory.CreateDirectory(FullSandbox);

  if not TGTermUserConfig.Instance.FindUser(AUsername, UserEntry) then Exit;

  for AppId in UserEntry.Apps do
  begin
    if TGTermAppConfig.Instance.FindById(AppId, AppEntry) then
    begin
      if not (SameText(AppId, 'cmd') or SameText(AppId, 'powershell')) then
      begin
        FullCmd := AppEntry.Command;
        if not TPath.IsPathRooted(FullCmd) then
          FullCmd := TPath.Combine(BaseDir, FullCmd);
        if FileExists(FullCmd) then
        begin
          ArgsStr := '';
          for I := 0 to High(AppEntry.Args) do
          begin
            Arg := AppEntry.Args[I];
            Arg := StringReplace(Arg, '%SANDBOX%', '%~dp0.', [rfReplaceAll, rfIgnoreCase]);
            if Arg.StartsWith('-') or Arg.StartsWith('/') then
              ArgsStr := ArgsStr + ' ' + Arg
            else
              ArgsStr := ArgsStr + ' "' + Arg + '"';
          end;
          ShimPath := TPath.Combine(FullSandbox, AppId + '.cmd');
          CmdContent := '@"' + FullCmd + '"' + ArgsStr + ' %*' + #13#10;
          TFile.WriteAllText(ShimPath, CmdContent, TEncoding.ASCII);
        end;
      end;
    end;
  end;
end;

function ResolveAppProfile(const APathOrQuery: string; const ASandboxDir: string = ''; const AUsername: string = ''): TGTermAppProfile;
var
  LowerPath: string;
  AppKey: string;
  Entry: TAppEntry;
  UserEntry: TUserEntry;
  AllowedApp: string;
  P: Integer;
  FullSandbox: string;
  BaseDir: string;
  DirsRead: TList<string>;
  DirsWrite: TList<string>;
  D: string;
begin
  BaseDir := ExtractFilePath(ParamStr(0));
  if ASandboxDir <> '' then
  begin
    FullSandbox := TPath.Combine(BaseDir, ASandboxDir);
    if not TDirectory.Exists(FullSandbox) then
      TDirectory.CreateDirectory(FullSandbox);
  end;

  if (AUsername <> '') and (ASandboxDir <> '') then
    EnsureUserAppShims(AUsername, ASandboxDir);

  LowerPath := LowerCase(APathOrQuery);
  AppKey := '';
  P := Pos('app=', LowerPath);
  if P > 0 then
  begin
    AppKey := Copy(APathOrQuery, P + 4, MaxInt);
    P := Pos('&', AppKey);
    if P > 0 then SetLength(AppKey, P - 1);
    P := Pos('#', AppKey);
    if P > 0 then SetLength(AppKey, P - 1);
    AppKey := LowerCase(Trim(AppKey));
  end
  else
    AppKey := LowerCase(Trim(APathOrQuery));

  if (AppKey <> '') and TGTermAppConfig.Instance.FindById(AppKey, Entry) then
    Result := Entry.ToProfile(ASandboxDir)
  else
    Result := TGTermAppConfig.Instance.GetDefaultProfile(ASandboxDir);

  DirsRead := TList<string>.Create;
  DirsWrite := TList<string>.Create;
  try
    for D in Result.AllowedDirsRead do
      if not DirsRead.Contains(D) then DirsRead.Add(D);
    for D in Result.AllowedDirsWrite do
      if not DirsWrite.Contains(D) then DirsWrite.Add(D);

    if (AUsername <> '') and TGTermUserConfig.Instance.FindUser(AUsername, UserEntry) then
    begin
      Result.NetworkAccess := Result.NetworkAccess and UserEntry.Grants.Network;

      if (Result.Sandbox = smJobOnly) and not (UserEntry.IsAdmin or UserEntry.Grants.AllowJobOnly) then
        Result.Sandbox := smStandard;

      for AllowedApp in UserEntry.Apps do
      begin
        var AppItem: TAppEntry;
        if TGTermAppConfig.Instance.FindById(AllowedApp, AppItem) then
        begin
          var TargetCmd := AppItem.Command;
          if not TPath.IsPathRooted(TargetCmd) then
            TargetCmd := TPath.Combine(BaseDir, TargetCmd);
          var TargetDir := ExtractFilePath(TargetCmd);
          if (TargetDir <> '') and TDirectory.Exists(TargetDir) and not DirsRead.Contains(TargetDir) then
            DirsRead.Add(TargetDir);
        end;
      end;

      for D in UserEntry.Grants.AllowedDirsRead do
        if not DirsRead.Contains(D) then DirsRead.Add(D);

      for D in UserEntry.Grants.AllowedDirsWrite do
        if not DirsWrite.Contains(D) then DirsWrite.Add(D);
    end;

    Result.AllowedDirsRead := DirsRead.ToArray;
    Result.AllowedDirsWrite := DirsWrite.ToArray;
  finally
    DirsRead.Free;
    DirsWrite.Free;
  end;
end;

function ValidateRequestToken(const ARequest: TRequest; AServer: TGHttpsServerIOCP; const ATokenStr: string; out AJWT: TJWTToken): Boolean;
var
  ReqIP, TokenIP: string;
begin
  Result := False;
  AJWT := nil;
  if (ATokenStr = '') or not AServer.JWTManager.ValidateToken(ATokenStr, AJWT) then
    Exit;

  TokenIP := AJWT.GetClaim('ip');
  if TokenIP <> '' then
  begin
    ReqIP := string(inet_ntoa(ARequest.RemoteAddr.sin_addr));
    if (ReqIP = '') or (ReqIP = '0.0.0.0') then
      ReqIP := '127.0.0.1';
    if not SameText(TokenIP, ReqIP) then
    begin
      Logger.Warn(Format('[Security] Token IP mismatch: token_ip=%s req_ip=%s (user=%s)', [TokenIP, ReqIP, AJWT.Subject]));
      FreeAndNil(AJWT);
      Exit(False);
    end;
  end;
  Result := True;
end;

begin
  ConfigureFastMM;
  try
    Logger.WaitForFlushBeforeExit := 60;
    Logger.Providers.Add(GlobalLogFileProvider);
    Logger.Providers.Add(GlobalLogConsoleProvider);

    var LogDir := '.\Log';
    if not TDirectory.Exists(LogDir) then
      TDirectory.CreateDirectory(LogDir);

    with GlobalLogFileProvider do
    begin
      FileName := LogDir + '\GTermBoxServer.log';
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

    Logger.Info('================================================================');
    Logger.Info('  GTermBox Web Terminal Host Server (FastMM5 + QuickLogger)');
    Logger.Info('  HTTPS TLS 1.3/1.2 + HTTP/3 WebTransport');
    Logger.Info('================================================================');

    Randomize;
    SetConsoleCtrlHandler(@ConsoleCtrlHandler, True);

    TGTermConPtyLoader.Initialize;
    if not TGTermConPtyLoader.IsAvailable then
    begin
      Logger.Error('ConPTY subsystem is not available on this Windows platform.');
      Halt(1);
    end;

    TGTermAppConfig.Instance.LoadFromFile(
      ExtractFilePath(ParamStr(0)) + 'apps.json');
    TGTermUserConfig.Instance.LoadFromFile(
      ExtractFilePath(ParamStr(0)) + 'users.json');

    CertStoreName := 'GHttpsIOCPSvr';
    SubjectNameParam := 'localhost';
    HttpsPortParam := 8443;

    BaseWebDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'web');

    Server := nil;
    SessionManager := nil;
    PendingSessionsLock := nil;
    PendingSessions := nil;
    LoginRateLock := nil;
    LoginRateMap := nil;

    try
      SessionManager := TGTermSessionManager.Create;
      PendingSessionsLock := TCriticalSection.Create;
      PendingSessions := TDictionary<string, TPendingSession>.Create;
      LoginRateLock := TCriticalSection.Create;
      LoginRateMap := TDictionary<string, TLoginRateLimit>.Create;

      Logger.Info(Format('Initializing HTTPS IOCP Server on port %d (Store: %s, Subject: %s)...', [HttpsPortParam, CertStoreName, SubjectNameParam]));
      Logger.Info(Format('Serving Web Assets from: %s', [BaseWebDir]));

      Server := TGHttpsServerIOCP.Create(
        HttpsPortParam,
        SubjectNameParam,
        CertStoreName,
        ResolveJwtSecret,
        2000,
        1000000,
        DEFAULT_MAX_REQUEST_HEDER_SIZE,
        DEFAULT_MAX_REQUEST_SIZE,
        DEFAULT_MAX_RESPONSE_SIZE,
        DEFAULT_CHUNK_SIZE,
        50,
        85,
        False,
        True,
        0,
        haServeNormally
      );

      Server.SetSSLShutdownOptions(True, 200);
      Server.EnableKeepAlive := True;
      Server.EnableHttp3 := True;

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          HtmlFile: string;
        begin
          HtmlFile := TPath.Combine(BaseWebDir, 'index.html');
          if TFile.Exists(HtmlFile) then
            AResponse.AddHTMLContent(TFile.ReadAllText(HtmlFile, TEncoding.UTF8))
          else
            AResponse.SetNotFound('index.html not found');
        end
      );

      Server.RegisterEndpointProc('/lib/xterm.js', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          FilePath: string;
        begin
          FilePath := TPath.Combine(BaseWebDir, 'lib' + PathDelim + 'xterm.js');
          if TFile.Exists(FilePath) then
            AResponse.AddTextContent('application/javascript; charset=utf-8', TFile.ReadAllText(FilePath, TEncoding.UTF8))
          else
            AResponse.SetNotFound('xterm.js not found');
        end
      );

      Server.RegisterEndpointProc('/lib/xterm.css', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          FilePath: string;
        begin
          FilePath := TPath.Combine(BaseWebDir, 'lib' + PathDelim + 'xterm.css');
          if TFile.Exists(FilePath) then
            AResponse.AddTextContent('text/css; charset=utf-8', TFile.ReadAllText(FilePath, TEncoding.UTF8))
          else
            AResponse.SetNotFound('xterm.css not found');
        end
      );

      Server.RegisterEndpointProc('/lib/addon-fit.js', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          FilePath: string;
        begin
          FilePath := TPath.Combine(BaseWebDir, 'lib' + PathDelim + 'addon-fit.js');
          if TFile.Exists(FilePath) then
            AResponse.AddTextContent('application/javascript; charset=utf-8', TFile.ReadAllText(FilePath, TEncoding.UTF8))
          else
            AResponse.SetNotFound('addon-fit.js not found');
        end
      );

      Server.RegisterEndpointProc('/api/certificate-hash', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          HashBytes: TBytes;
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          I: Integer;
        begin
          AResponse.SetStatus(200);
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          HashBytes := AServer.GetCertificateSha256Hash;
          JsonRes := TJSONObject.Create;
          try
            JsonRes.AddPair('algorithm', 'sha-256');
            JsonArr := TJSONArray.Create;
            for I := 0 to High(HashBytes) do
              JsonArr.Add(HashBytes[I]);
            JsonRes.AddPair('hash', JsonArr);
            AResponse.AddJSONContent(JsonRes.ToJSON);
          finally
            JsonRes.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/login', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/login', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          BodyStr: string;
          JsonVal: TJSONValue;
          JsonReq, JsonRes: TJSONObject;
          Username, Password, TokenStr: string;
          UserEntry: TUserEntry;
          Claims: TJSONObject;
          AppsArr: TJSONArray;
          ClientIP: string;
          NowTick: UInt64;
          RateInfo: TLoginRateLimit;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          ClientIP := string(inet_ntoa(ARequest.RemoteAddr.sin_addr));
          if (ClientIP = '') or (ClientIP = '0.0.0.0') then
            ClientIP := '127.0.0.1';

          NowTick := GetTickCount64;
          LoginRateLock.Enter;
          try
            if LoginRateMap.TryGetValue(ClientIP, RateInfo) then
            begin
              if (RateInfo.BlockedUntilTick > 0) and (NowTick < RateInfo.BlockedUntilTick) then
              begin
                AResponse.SetStatus(429);
                AResponse.AddJSONContent('{"error":"Too many failed attempts. Please wait 60 seconds."}');
                Exit;
              end;
            end;
          finally
            LoginRateLock.Leave;
          end;

          BodyStr := ARequest.GetBodyAsString;
          JsonVal := TJSONObject.ParseJSONValue(BodyStr);
          if not (JsonVal is TJSONObject) then
          begin
            if Assigned(JsonVal) then JsonVal.Free;
            AResponse.SetStatus(400);
            AResponse.AddJSONContent('{"error":"Invalid JSON"}');
            Exit;
          end;

          JsonReq := JsonVal as TJSONObject;
          try
            Username := JsonReq.GetValue<string>('username', '');
            Password := JsonReq.GetValue<string>('password', '');

            if (Username = '') or not TGTermUserConfig.Instance.ValidateUser(Username, Password, UserEntry) then
            begin
              LoginRateLock.Enter;
              try
                if not LoginRateMap.TryGetValue(ClientIP, RateInfo) then
                begin
                  RateInfo.FailedCount := 0;
                  RateInfo.BlockedUntilTick := 0;
                end;
                Inc(RateInfo.FailedCount);
                if RateInfo.FailedCount >= 5 then
                begin
                  RateInfo.BlockedUntilTick := NowTick + 60000;
                  RateInfo.FailedCount := 0;
                  Logger.Warn(Format('[Security] Rate limit exceeded for IP %s. Blocked for 60 seconds.', [ClientIP]));
                end;
                LoginRateMap.AddOrSetValue(ClientIP, RateInfo);
              finally
                LoginRateLock.Leave;
              end;

              Sleep(200);
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error":"Invalid username or password"}');
              Exit;
            end;

            LoginRateLock.Enter;
            try
              LoginRateMap.Remove(ClientIP);
            finally
              LoginRateLock.Leave;
            end;

            Claims := TJSONObject.Create;
            try
              Claims.AddPair('role', UserEntry.Role);
              Claims.AddPair('sandbox', UserEntry.Sandbox);
              Claims.AddPair('ip', ClientIP);
              AppsArr := TJSONArray.Create;
              for var AppId in UserEntry.Apps do
                AppsArr.Add(AppId);
              Claims.AddPair('apps', AppsArr);
              TokenStr := AServer.JWTManager.CreateToken(UserEntry.Username, Claims);
            finally
              Claims.Free;
            end;

            JsonRes := TJSONObject.Create;
            try
              JsonRes.AddPair('token', TokenStr);
              JsonRes.AddPair('username', UserEntry.Username);
              JsonRes.AddPair('role', UserEntry.Role);
              JsonRes.AddPair('sandbox', UserEntry.Sandbox);
              AppsArr := TJSONArray.Create;
              for var AppId in UserEntry.Apps do
                AppsArr.Add(AppId);
              JsonRes.AddPair('apps', AppsArr);

              AResponse.SetStatus(200);
              AResponse.AddJSONContent(JsonRes.ToJSON);
            finally
              JsonRes.Free;
            end;
          finally
            JsonReq.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/apps', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/apps', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          AppObj: TJSONObject;
          Entry: TAppEntry;
          I: Integer;
          SandboxStr: string;
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal: string;
          UserRole: string;
          FoundUser: TUserEntry;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if (TokenStr = '') and ARequest.RequestInfo.QueryParameters.TryGetValue('token', QueryVal) then
            TokenStr := QueryVal;

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            UserRole := JWT.GetClaim('role');
            if UserRole = '' then
            begin
              if TGTermUserConfig.Instance.FindUser(JWT.Subject, FoundUser) then
                UserRole := FoundUser.Role
              else
                UserRole := 'user';
            end;

            AResponse.SetStatus(200);
            JsonRes := TJSONObject.Create;
            try
              JsonArr := TJSONArray.Create;
              for I := 0 to TGTermAppConfig.Instance.AppCount - 1 do
              begin
                if TGTermAppConfig.Instance.FindByIndex(I, Entry) then
                begin
                  if TGTermAppConfig.Instance.CanRoleAccessApp(UserRole, Entry.Id) and
                     TGTermUserConfig.Instance.CanAccessApp(JWT.Subject, Entry.Id) then
                  begin
                    case Entry.Sandbox of
                      smStandard: SandboxStr := 'standard';
                      smJobOnly:  SandboxStr := 'job-only';
                    else
                      SandboxStr := 'none';
                    end;
                    AppObj := TJSONObject.Create;
                    AppObj.AddPair('id',      Entry.Id);
                    AppObj.AddPair('name',    Entry.Name);
                    AppObj.AddPair('sandbox', SandboxStr);
                    AppObj.AddPair('network', TJSONBool.Create(Entry.Network));
                    JsonArr.AddElement(AppObj);
                  end;
                end;
              end;
              JsonRes.AddPair('apps', JsonArr);
              AResponse.AddJSONContent(JsonRes.ToJSON);
            finally
              JsonRes.Free;
            end;
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/terminal/session', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/terminal/session', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          BodyStr: string;
          JsonVal: TJSONValue;
          JsonReq, JsonRes: TJSONObject;
          TokenStr: string;
          JWT: TJWTToken;
          AppKey: string;
          Cols, Rows: Integer;
          SessionGuid: string;
          Pending: TPendingSession;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          BodyStr := ARequest.GetBodyAsString;
          JsonVal := TJSONObject.ParseJSONValue(BodyStr);
          if not (JsonVal is TJSONObject) then
          begin
            if Assigned(JsonVal) then JsonVal.Free;
            AResponse.SetStatus(400);
            AResponse.AddJSONContent('{"error":"Invalid JSON"}');
            Exit;
          end;

          JsonReq := JsonVal as TJSONObject;
          try
            if TokenStr = '' then
              TokenStr := JsonReq.GetValue<string>('token', '');

            if (TokenStr = '') or not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error":"Unauthorized"}');
              Exit;
            end;

            try
              AppKey := LowerCase(Trim(JsonReq.GetValue<string>('app', '')));
              if AppKey = '' then
                AppKey := TGTermAppConfig.Instance.GetDefaultAppId;
              Cols := JsonReq.GetValue<Integer>('cols', 120);
              Rows := JsonReq.GetValue<Integer>('rows', 40);

              var UserRole := JWT.GetClaim('role');
              if UserRole = '' then
              begin
                var CheckUser: TUserEntry;
                if TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser) then
                  UserRole := CheckUser.Role
                else
                  UserRole := 'user';
              end;

              if not TGTermAppConfig.Instance.CanRoleAccessApp(UserRole, AppKey) or
                 not TGTermUserConfig.Instance.CanAccessApp(JWT.Subject, AppKey) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden app access"}');
                Exit;
              end;

              var ReqClientIP := string(inet_ntoa(ARequest.RemoteAddr.sin_addr));
              if (ReqClientIP = '') or (ReqClientIP = '0.0.0.0') then
                ReqClientIP := '127.0.0.1';

              SessionGuid := TGUID.NewGuid.ToString.Trim(['{', '}']);

              Pending.Username := JWT.Subject;
              Pending.ClientIP := ReqClientIP;
              Pending.SandboxDir := JWT.GetClaim('sandbox');
              Pending.AppKey := AppKey;
              Pending.Cols := Cols;
              Pending.Rows := Rows;
              Pending.CreatedTick := GetTickCount64;

              PendingSessionsLock.Enter;
              try
                PendingSessions.AddOrSetValue(SessionGuid, Pending);
              finally
                PendingSessionsLock.Leave;
              end;

              JsonRes := TJSONObject.Create;
              try
                JsonRes.AddPair('status', 'ok');
                JsonRes.AddPair('sessionId', SessionGuid);
                JsonRes.AddPair('app', AppKey);
                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JsonRes.ToJSON);
              finally
                JsonRes.Free;
              end;
            finally
              JWT.Free;
            end;
          finally
            JsonReq.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/sandbox/file', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/sandbox/file', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal, FileName, UserSandbox, TargetDir, TargetPath: string;
          FileBytes: TBytes;
          JsonRes: TJSONObject;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if (TokenStr = '') and 
		     ARequest.RequestInfo.QueryParameters.TryGetValue('token', QueryVal) then
            TokenStr := QueryVal;

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            FileName := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('name', QueryVal) then
              FileName := QueryVal;
            FileName := TPath.GetFileName(FileName);
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;

            UserSandbox := JWT.GetClaim('sandbox');
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            TargetDir := TPath.Combine(ExtractFilePath(ParamStr(0)), UserSandbox);
            if not TDirectory.Exists(TargetDir) then
              TDirectory.CreateDirectory(TargetDir);

            TargetPath := TPath.Combine(TargetDir, FileName);
            FileBytes := ARequest.BodyAsBytes;
            TFile.WriteAllBytes(TargetPath, FileBytes);

            JsonRes := TJSONObject.Create;
            try
              JsonRes.AddPair('status', 'ok');
              JsonRes.AddPair('filename', FileName);
              JsonRes.AddPair('size', TJSONNumber.Create(Length(FileBytes)));
              AResponse.SetStatus(200);
              AResponse.AddJSONContent(JsonRes.ToJSON);
            finally
              JsonRes.Free;
            end;
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/sandbox/file', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal, FileName, UserSandbox, TargetDir, TargetPath: string;
        begin
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if (TokenStr = '') and ARequest.RequestInfo.QueryParameters.TryGetValue('token', QueryVal) then
            TokenStr := QueryVal;

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            FileName := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('name', QueryVal) then
              FileName := QueryVal;
            FileName := TPath.GetFileName(FileName);
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;

            UserSandbox := JWT.GetClaim('sandbox');
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            TargetDir := TPath.Combine(ExtractFilePath(ParamStr(0)), UserSandbox);
            TargetPath := TPath.Combine(TargetDir, FileName);

            if not FileExists(TargetPath) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"File not found"}');
              Exit;
            end;

            AResponse.SetStatus(200);
            AResponse.AddHeader('Content-Disposition', 'attachment; filename="' + FileName + '"');
            AResponse.AddFileContent('application/octet-stream', TargetPath);
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/admin/sessions', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/admin/sessions', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal: string;
          Snapshots: TArray<TGTermSessionInfo>;
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          SessObj: TJSONObject;
          I: Integer;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if (TokenStr = '') and ARequest.RequestInfo.QueryParameters.TryGetValue('token', QueryVal) then
            TokenStr := QueryVal;

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            var AdminRole := JWT.GetClaim('role');
            if not SameText(AdminRole, 'admin') then
            begin
              var AdminUser: TUserEntry;
              if not (TGTermUserConfig.Instance.FindUser(JWT.Subject, AdminUser) and 
			      AdminUser.IsAdmin) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Admin role required"}');
                Exit;
              end;
            end;

            Snapshots := SessionManager.GetSessionSnapshots;
            JsonRes := TJSONObject.Create;
            try
              JsonArr := TJSONArray.Create;
              for I := 0 to High(Snapshots) do
              begin
                SessObj := TJSONObject.Create;
                SessObj.AddPair('sessionId', UIntToStr(Snapshots[I].SessionId));
                SessObj.AddPair('app', Snapshots[I].AppKey);
                SessObj.AddPair('profile', Snapshots[I].ProfileName);
                SessObj.AddPair('pid', TJSONNumber.Create(Snapshots[I].ProcessId));
                SessObj.AddPair('cols', TJSONNumber.Create(Snapshots[I].Cols));
                SessObj.AddPair('rows', TJSONNumber.Create(Snapshots[I].Rows));
                SessObj.AddPair('connectedSeconds', TJSONNumber.Create(Snapshots[I].ConnectedSeconds));
                SessObj.AddPair('idleSeconds', TJSONNumber.Create(Snapshots[I].IdleSeconds));
                SessObj.AddPair('closed', TJSONBool.Create(Snapshots[I].Closed));
                JsonArr.AddElement(SessObj);
              end;
              JsonRes.AddPair('sessions', JsonArr);
              AResponse.SetStatus(200);
              AResponse.AddJSONContent(JsonRes.ToJSON);
            finally
              JsonRes.Free;
            end;
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/admin/sessions/kill', hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          AResponse.AddHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc('/api/admin/sessions/kill', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr, BodyStr, SessIdStr: string;
          JWT: TJWTToken;
          JsonVal: TJSONValue;
          JsonReq: TJSONObject;
          SessionId: UInt64;
          Success: Boolean;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          AResponse.AddHeader('Access-Control-Allow-Origin', '*');
          AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          BodyStr := ARequest.GetBodyAsString;
          JsonVal := TJSONObject.ParseJSONValue(BodyStr);
          if not (JsonVal is TJSONObject) then
          begin
            if Assigned(JsonVal) then JsonVal.Free;
            AResponse.SetStatus(400);
            AResponse.AddJSONContent('{"error":"Invalid JSON"}');
            Exit;
          end;

          JsonReq := JsonVal as TJSONObject;
          try
            if TokenStr = '' then
              TokenStr := JsonReq.GetValue<string>('token', '');

            if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
            begin
              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error":"Unauthorized: Invalid token"}');
              Exit;
            end;

            try
              var AdminRole := JWT.GetClaim('role');
              if not SameText(AdminRole, 'admin') then
              begin
                var AdminUser: TUserEntry;
                if not (TGTermUserConfig.Instance.FindUser(JWT.Subject, AdminUser) and AdminUser.IsAdmin) then
                begin
                  AResponse.SetStatus(403);
                  AResponse.AddJSONContent('{"error":"Forbidden: Admin role required"}');
                  Exit;
                end;
              end;

              SessIdStr := JsonReq.GetValue<string>('sessionId', '');
              SessionId := StrToUInt64Def(SessIdStr, 0);
              if SessionId = 0 then
              begin
                AResponse.SetStatus(400);
                AResponse.AddJSONContent('{"error":"Invalid sessionId"}');
                Exit;
              end;

              Success := SessionManager.TerminateSessionById(SessionId);
              if Success then
              begin
                AResponse.SetStatus(200);
                AResponse.AddJSONContent('{"status":"ok"}');
              end
              else
              begin
                AResponse.SetStatus(404);
                AResponse.AddJSONContent('{"error":"Session not found"}');
              end;
            finally
              JWT.Free;
            end;
          finally
            JsonReq.Free;
          end;
        end
      );

      Server.RegisterWebTransportRoute('/wt/terminal',
        procedure(Session: PWTSessionContext)
        var
          Profile: TGTermAppProfile;
          TermSession: TGTermSession;
          TokenStr: string;
          JWT: TJWTToken;
          AppKey: string;
          UserSandbox: string;
          LowerPath: string;
          P: Integer;
          SessionGuid: string;
          HasPending: Boolean;
          Pending: TPendingSession;
        begin
          Logger.Info(Format('[WT] Client connected (SessionId: %d, Path: %s)', [Session^.SessionId, Session^.Path]));
          LowerPath := LowerCase(Session^.Path);

          TokenStr := '';
          P := Pos('token=', LowerPath);
          if P > 0 then
          begin
            TokenStr := Copy(Session^.Path, P + 6, MaxInt);
            P := Pos('&', TokenStr);
            if P > 0 then SetLength(TokenStr, P - 1);
            P := Pos('#', TokenStr);
            if P > 0 then SetLength(TokenStr, P - 1);
            TokenStr := Trim(TokenStr);
          end;

          SessionGuid := '';
          P := Pos('session=', LowerPath);
          if P > 0 then
          begin
            SessionGuid := Copy(Session^.Path, P + 8, MaxInt);
            P := Pos('&', SessionGuid);
            if P > 0 then SetLength(SessionGuid, P - 1);
            P := Pos('#', SessionGuid);
            if P > 0 then SetLength(SessionGuid, P - 1);
            SessionGuid := Trim(SessionGuid);
          end;

          HasPending := False;
          if SessionGuid <> '' then
          begin
            PendingSessionsLock.Enter;
            try
              HasPending := PendingSessions.TryGetValue(SessionGuid, Pending);
              if HasPending then
                PendingSessions.Remove(SessionGuid);
            finally
              PendingSessionsLock.Leave;
            end;
          end;

          if HasPending then
          begin
            if (TokenStr = '') or not Server.JWTManager.ValidateToken(TokenStr, JWT) then
            begin
              Logger.Warn(Format('[WT] Rejecting connection: invalid or missing token (SessionId: %d)', [Session^.SessionId]));
              Exit;
            end;

            try
              if not SameText(JWT.Subject, Pending.Username) then
              begin
                Logger.Warn(Format('[WT] Rejecting connection: token user "%s" does not match session owner "%s" (SessionId: %d)',
                  [JWT.Subject, Pending.Username, Session^.SessionId]));
                Exit;
              end;

              UserSandbox := Pending.SandboxDir;
              Profile := ResolveAppProfile(Pending.AppKey, UserSandbox, Pending.Username);
              if Pending.Cols > 0 then Profile.DefaultCols := Pending.Cols;
              if Pending.Rows > 0 then Profile.DefaultRows := Pending.Rows;
              TermSession := TGTermSession.Create(Session, Profile);
              SessionManager.RegisterSession(Pointer(Session^.SessionId), TermSession);
            finally
              JWT.Free;
            end;
          end
          else
          begin
            AppKey := '';
            P := Pos('app=', LowerPath);
            if P > 0 then
            begin
              AppKey := Copy(Session^.Path, P + 4, MaxInt);
              P := Pos('&', AppKey);
              if P > 0 then SetLength(AppKey, P - 1);
              P := Pos('#', AppKey);
              if P > 0 then SetLength(AppKey, P - 1);
              AppKey := LowerCase(Trim(AppKey));
            end;
            if AppKey = '' then
              AppKey := TGTermAppConfig.Instance.GetDefaultAppId;

            if (TokenStr = '') or not Server.JWTManager.ValidateToken(TokenStr, JWT) then
            begin
              Logger.Warn(Format('[WT] Rejecting connection: invalid or missing token (SessionId: %d)', [Session^.SessionId]));
              Exit;
            end;

            try
              var UserRole := JWT.GetClaim('role');
              if UserRole = '' then
              begin
                var CheckU: TUserEntry;
                if TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckU) then
                  UserRole := CheckU.Role
                else
                  UserRole := 'user';
              end;

              if not TGTermAppConfig.Instance.CanRoleAccessApp(UserRole, AppKey) or
                 not TGTermUserConfig.Instance.CanAccessApp(JWT.Subject, AppKey) then
              begin
                Logger.Warn(Format('[WT] Forbidden app access for user "%s" to app "%s"', [JWT.Subject, AppKey]));
                Exit;
              end;

              UserSandbox := JWT.GetClaim('sandbox');
              Profile := ResolveAppProfile(Session^.Path, UserSandbox, JWT.Subject);
              TermSession := TGTermSession.Create(Session, Profile);
              SessionManager.RegisterSession(Pointer(Session^.SessionId), TermSession);
            finally
              JWT.Free;
            end;
          end;
        end,
        procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
        var
          TermSession: TGTermSession;
        begin
          TermSession := SessionManager.FindSession(Pointer(Session^.SessionId));
          if Assigned(TermSession) then
          begin
            TermSession.SetWTStream(Session, Stream);
            TermSession.ProcessClientMessage(TEncoding.UTF8.GetString(Data));
          end;
        end,
        procedure(Session: PWTSessionContext; const Data: TBytes)
        var
          TermSession: TGTermSession;
        begin
          TermSession := SessionManager.FindSession(Pointer(Session^.SessionId));
          if Assigned(TermSession) then
            TermSession.ProcessClientMessage(TEncoding.UTF8.GetString(Data));
        end,
        procedure(SessionId: TWTSessionId)
        begin
          Logger.Info(Format('[WT] Client disconnected (SessionId: %d)', [SessionId]));
          if Assigned(SessionManager) then
            SessionManager.UnregisterAndFreeSession(Pointer(SessionId));
        end
      );

      if not Server.Start then
      begin
        Logger.Error(Format('Failed to start HTTPS IOCP server on port %d.', [HttpsPortParam]));
        Halt(1);
      end;

      Logger.Info('================================================================');
      Logger.Info(Format('  Server listening on HTTPS:        https://localhost:%d', [HttpsPortParam]));
      Logger.Info(Format('  Server listening on WebTransport: https://localhost:%d/wt/terminal', [HttpsPortParam]));
      Logger.Info('  Press Enter to stop the server.');
      Logger.Info('================================================================');

      HStdIn := GetStdHandle(STD_INPUT_HANDLE);
      if (HStdIn <> 0) and (HStdIn <> INVALID_HANDLE_VALUE) and GetConsoleMode(HStdIn, ConsoleMode) then
      begin
        ConsoleMode := (ConsoleMode and not ENABLE_QUICK_EDIT_MODE) or ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(HStdIn, ConsoleMode);
        FlushConsoleInputBuffer(HStdIn);
      end;

      while GServerRunning do
      begin
        if (HStdIn <> 0) and (HStdIn <> INVALID_HANDLE_VALUE) and (WaitForSingleObject(HStdIn, 100) = WAIT_OBJECT_0) then
        begin
          if ReadConsoleInput(HStdIn, InputRec, 1, NumRead) and (NumRead > 0) then
          begin
            if (InputRec.EventType = KEY_EVENT) and InputRec.Event.KeyEvent.bKeyDown then
            begin
              if InputRec.Event.KeyEvent.wVirtualKeyCode = VK_RETURN then
                Break;
            end;
          end;
        end
        else
          Sleep(50);
      end;

    finally
      Logger.Info('Stopping server...');
      if Assigned(Server) then
      begin
        Server.Stop;
        FreeAndNil(Server);
      end;
      Logger.Info('Stopping session manager...');
      if Assigned(SessionManager) then
      begin
        SessionManager.Clear;
        FreeAndNil(SessionManager);
      end;
      FreeAndNil(PendingSessions);
      FreeAndNil(PendingSessionsLock);
      FreeAndNil(LoginRateMap);
      FreeAndNil(LoginRateLock);
      Logger.Info('Server stopped cleanly.');
    end;
  except
    on E: Exception do
      Logger.Critical(Format('Fatal Error [%s]: %s', [E.ClassName, E.Message]));
  end;
end.
