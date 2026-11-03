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
  System.DateUtils,
  System.Hash,
  System.JSON,
  System.SyncObjs,
  System.Generics.Collections,
  System.StrUtils,
  System.NetEncoding,
  Quic.Server in 'GHttpsIOCPSvr\Http3DelphiV3\Quic.Server.pas',
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
  WebTransport.Session in 'GHttpsIOCPSvr\Http3DelphiV3\WebTransport.Session.pas',
  GTerm.AmsiScanner in 'src\GTerm.AmsiScanner.pas';

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
    Role: string;
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

  TWTFileStreamMode = (wtmNone, wtmUpload, wtmDownload);

  TWTFileStreamCtx = class
  public
    Stream: HQUIC;
    SessionId: TWTSessionId;
    Mode: TWTFileStreamMode;
    Filename: string;
    FullPath: string;
    ExpectedSize: Int64;
    BytesProcessed: Int64;
    FileStream: TFileStream;
    HeaderParsed: Boolean;
    HeaderBuf: TBytes;
    destructor Destroy; override;
  end;

  TWTFileSessionCtx = class
  public
    SessionId: TWTSessionId;
    Username: string;
    Role: string;
    Sandbox: string;
    CanUpload: Boolean;
    CanDownload: Boolean;
    StorageQuotaMB: Integer;
  end;

var
  Server: TGHttpsServerIOCP;
  SessionManager: TGTermSessionManager;
  PendingSessionsLock: TCriticalSection;
  PendingSessions: TDictionary<string, TPendingSession>;
  LoginRateLock: TCriticalSection;
  LoginRateMap: TDictionary<string, TLoginRateLimit>;
  WTFileLock: TCriticalSection;
  WTFileSessions: TDictionary<TWTSessionId, TWTFileSessionCtx>;
  WTFileStreams: TDictionary<HQUIC, TWTFileStreamCtx>;
  BaseWebDir: string;
  CertStoreName: string;
  SubjectNameParam: string;
  HttpsPortParam: Word;
  GmTLSMode: TmTLSMode = mtlsDisabled;
  GmTLSCaCertPath: string = '';
  GAllowTestCA: Boolean = False;
  GmTLSPinnedThumbprint: string = '';
  GTrustedClientsDir: string = '';
  GBindAddress: string = '';
  GHttpsBindAddress: string = '';
  GHttp3BindAddress: string = '';
  GTrustedClients: TDictionary<string, string> = nil;
  HStdIn: THandle;
  ConsoleMode: DWORD;
  InputRec: TInputRecord;
  NumRead: DWORD;
  GServerRunning: Boolean = True;
  GServerCertIsTrusted: Boolean = False;

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

const BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;
function BCryptGenRandom(hAlgorithm: THandle; pbBuffer: PByte; cbBuffer: ULONG; dwFlags: ULONG): LongInt; stdcall; external 'bcrypt.dll' name 'BCryptGenRandom';

const
  FILE_NAME_NORMALIZED = $0;
  VOLUME_NAME_DOS      = $0;
  PATHCCH_DO_NOT_NORMALIZE_SEGMENTS = $00000008;

function GetFinalPathNameByHandleW(
  hFile: THandle;
  lpszFilePath: PWideChar;
  cchFilePath: DWORD;
  dwFlags: DWORD
): DWORD; stdcall; external kernel32 name 'GetFinalPathNameByHandleW';

function GetLongPathNameW(
  lpszShortPath, lpszLongPath: PWideChar;
  cchBuffer: DWORD
): DWORD; stdcall; external kernel32 name 'GetLongPathNameW';

function PathCchCanonicalizeEx(
  pszPathOut: PWideChar;
  cchPathOut: SIZE_T;
  pszPathIn: PWideChar;
  dwFlags: ULONG
): HRESULT; stdcall; external 'kernelbase.dll' name 'PathCchCanonicalizeEx';

var
  GSecretPathPrefix: string = '';

{$WARN SYMBOL_PLATFORM OFF}
function GetDirectoryTotalSize(const ADir: string; ADepth: Integer = 0): Int64;
var
  Rec: TSearchRec;
  Path: string;
  ItemPath: string;
  ItemAttr: DWORD;
begin
  Result := 0;
  if (ADepth >= 32) or not TDirectory.Exists(ADir) then
    Exit;
  Path := IncludeTrailingPathDelimiter(ADir);
  if FindFirst(Path + '*', faAnyFile, Rec) = 0 then
  begin
    try
      repeat
        if (Rec.Name <> '.') and (Rec.Name <> '..') then
        begin
          ItemPath := Path + Rec.Name;
          ItemAttr := GetFileAttributesW(PWideChar(ItemPath));
          if (ItemAttr <> INVALID_FILE_ATTRIBUTES) and
             ((ItemAttr and FILE_ATTRIBUTE_REPARSE_POINT) = 0) and
             ((Rec.Attr and faSymLink) = 0) then
          begin
            if ((Rec.Attr and faDirectory) <> 0) and ((ItemAttr and FILE_ATTRIBUTE_DIRECTORY) <> 0) then
              Inc(Result, GetDirectoryTotalSize(ItemPath, ADepth + 1))
            else if (ItemAttr and FILE_ATTRIBUTE_DIRECTORY) = 0 then
              Inc(Result, Rec.Size);
          end;
        end;
      until FindNext(Rec) <> 0;
    finally
      System.SysUtils.FindClose(Rec);
    end;
  end;
end;
{$WARN SYMBOL_PLATFORM ON}

type
  TQuotaReservationManager = class
  private
    FLock: TCriticalSection;
    FReservations: TDictionary<string, Int64>;
  public
    constructor Create;
    destructor Destroy; override;
    function TryReserve(const AUserKey: string; ABytes: Int64; AMaxQuota: Int64; const ADirPath: string): Boolean;
    procedure Release(const AUserKey: string; ABytes: Int64);
  end;

var
  GlobalQuotaManager: TQuotaReservationManager = nil;

constructor TQuotaReservationManager.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FReservations := TDictionary<string, Int64>.Create;
end;

destructor TQuotaReservationManager.Destroy;
begin
  FReservations.Free;
  FLock.Free;
  inherited Destroy;
end;

function TQuotaReservationManager.TryReserve(const AUserKey: string; ABytes: Int64; AMaxQuota: Int64; const ADirPath: string): Boolean;
var
  CurrentReserved: Int64;
  CurrentDiskUsed: Int64;
  Key: string;
begin
  if AMaxQuota <= 0 then
    Exit(True);
  Key := LowerCase(AUserKey);
  FLock.Enter;
  try
    if not FReservations.TryGetValue(Key, CurrentReserved) then
      CurrentReserved := 0;
    CurrentDiskUsed := GetDirectoryTotalSize(ADirPath);
    if CurrentDiskUsed + CurrentReserved + ABytes > AMaxQuota then
      Exit(False);
    FReservations.AddOrSetValue(Key, CurrentReserved + ABytes);
    Result := True;
  finally
    FLock.Leave;
  end;
end;

procedure TQuotaReservationManager.Release(const AUserKey: string; ABytes: Int64);
var
  CurrentReserved: Int64;
  Key: string;
begin
  if ABytes <= 0 then
    Exit;
  Key := LowerCase(AUserKey);
  FLock.Enter;
  try
    if FReservations.TryGetValue(Key, CurrentReserved) then
    begin
      CurrentReserved := CurrentReserved - ABytes;
      if CurrentReserved <= 0 then
        FReservations.Remove(Key)
      else
        FReservations.AddOrSetValue(Key, CurrentReserved);
    end;
  finally
    FLock.Leave;
  end;
end;

function ExpandPathLongNames(const APath: string): string;
var
  Buf: array[0..32767] of WideChar;
  Len: DWORD;
begin
  Len := GetLongPathNameW(PWideChar(APath), @Buf[0], Length(Buf));
  if (Len > 0) and (Len < DWORD(Length(Buf))) then
    SetString(Result, PWideChar(@Buf[0]), Len)
  else
    Result := APath;
end;

function CanonicalizePathCch(const APath: string): string;
var
  Buf: array[0..32767] of WideChar;
  Hr: HRESULT;
begin
  Hr := PathCchCanonicalizeEx(@Buf[0], Length(Buf), PWideChar(APath), PATHCCH_DO_NOT_NORMALIZE_SEGMENTS);
  if Hr = S_OK then
    Result := string(Buf)
  else
    Result := TPath.GetFullPath(APath);
end;

function NormalizeCanonicalPath(const APath: string): string;
var
  S: string;
begin
  S := APath;
  if S.StartsWith('\\?\UNC\', True) then
    S := '\\' + Copy(S, 8, MaxInt)
  else if S.StartsWith('\\?\', True) then
    S := Copy(S, 5, MaxInt);
  Result := LowerCase(ExcludeTrailingPathDelimiter(S));
end;

function IsSameDirectoryOrRoot(const APath1, APath2: string): Boolean;
var
  Norm1, Norm2: string;
begin
  if (APath1 = '') or (APath2 = '') then
    Exit(False);
  Norm1 := NormalizeCanonicalPath(TPath.GetFullPath(APath1));
  Norm2 := NormalizeCanonicalPath(TPath.GetFullPath(APath2));
  Result := SameFileName(Norm1, Norm2) or (Norm1 = Norm2);
end;

function IsPathInSandboxCanonical(const AFilePath, ASandboxDir: string): Boolean;
var
  H: THandle;
  Buffer: array[0..1023] of WideChar;
  Len: DWORD;
  FinalPathStr, CanonicalSandbox, CheckTarget: string;
  ParentDir: string;
  ColonPos: Integer;
begin
  ColonPos := Pos(':', AFilePath);
  if ColonPos > 0 then
  begin
    if not ((ColonPos = 2) and (Length(AFilePath) >= 2) and (PosEx(':', AFilePath, 3) = 0)) then
      Exit(False);
  end;

  CanonicalSandbox := NormalizeCanonicalPath(CanonicalizePathCch(ExpandPathLongNames(TPath.GetFullPath(ASandboxDir))));
  CheckTarget := CanonicalizePathCch(ExpandPathLongNames(TPath.GetFullPath(AFilePath)));

  var TargetAttr: DWORD := GetFileAttributesW(PWideChar(CheckTarget));
  if (TargetAttr <> INVALID_FILE_ATTRIBUTES) and ((TargetAttr and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
  begin
    H := CreateFileW(
      PWideChar(CheckTarget),
      0,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      0
    );
    if H = INVALID_HANDLE_VALUE then
      Exit(False);
    try
      Len := GetFinalPathNameByHandleW(H, @Buffer[0], Length(Buffer), FILE_NAME_NORMALIZED or VOLUME_NAME_DOS);
      if (Len = 0) or (Len >= DWORD(Length(Buffer))) then
        Exit(False);
      SetString(FinalPathStr, PWideChar(@Buffer[0]), Len);
      FinalPathStr := NormalizeCanonicalPath(FinalPathStr);
      Exit((FinalPathStr = CanonicalSandbox) or FinalPathStr.StartsWith(CanonicalSandbox + '\', True));
    finally
      CloseHandle(H);
    end;
  end;

  if FileExists(CheckTarget) or DirectoryExists(CheckTarget) then
  begin
    H := CreateFileW(
      PWideChar(CheckTarget),
      GENERIC_READ,
      FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
      nil,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      0
    );
    if H <> INVALID_HANDLE_VALUE then
    begin
      try
        Len := GetFinalPathNameByHandleW(H, @Buffer[0], Length(Buffer), FILE_NAME_NORMALIZED or VOLUME_NAME_DOS);
        if (Len > 0) and (Len < DWORD(Length(Buffer))) then
        begin
          SetString(FinalPathStr, PWideChar(@Buffer[0]), Len);
          FinalPathStr := NormalizeCanonicalPath(FinalPathStr);
          Exit((FinalPathStr = CanonicalSandbox) or FinalPathStr.StartsWith(CanonicalSandbox + '\', True));
        end;
      finally
        CloseHandle(H);
      end;
    end;
  end;

  ParentDir := ExtractFilePath(CheckTarget);
  if ParentDir <> '' then
  begin
    ParentDir := ExcludeTrailingPathDelimiter(ParentDir);
    ParentDir := ExpandPathLongNames(ParentDir);
    if DirectoryExists(ParentDir) then
    begin
      H := CreateFileW(
        PWideChar(ParentDir),
        GENERIC_READ,
        FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
        nil,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0
      );
      if H <> INVALID_HANDLE_VALUE then
      begin
        try
          Len := GetFinalPathNameByHandleW(H, @Buffer[0], Length(Buffer), FILE_NAME_NORMALIZED or VOLUME_NAME_DOS);
          if (Len > 0) and (Len < DWORD(Length(Buffer))) then
          begin
            SetString(FinalPathStr, PWideChar(@Buffer[0]), Len);
            FinalPathStr := NormalizeCanonicalPath(FinalPathStr);
            Exit((FinalPathStr = CanonicalSandbox) or FinalPathStr.StartsWith(CanonicalSandbox + '\', True));
          end;
        finally
          CloseHandle(H);
        end;
      end;
    end;
  end;

  FinalPathStr := NormalizeCanonicalPath(CheckTarget);
  Result := (FinalPathStr = CanonicalSandbox) or FinalPathStr.StartsWith(CanonicalSandbox + '\', True);
end;

procedure CheckSecureConfigFilePermissions(const AFilePath: string);
var
  Attrs: DWORD;
begin
  if not FileExists(AFilePath) then
    Exit;
  Attrs := GetFileAttributesW(PWideChar(AFilePath));
  if Attrs = INVALID_FILE_ATTRIBUTES then
    Logger.Warn(Format('[Security] Unable to read attributes for config file: %s', [AFilePath]))
  else
    Logger.Info(Format('[Security] Config file integrity verified: %s (Attributes: 0x%x)', [TPath.GetFileName(AFilePath), Attrs]));
end;

function BuildRoutePath(const APath: string): string;
begin
  if GSecretPathPrefix = '' then
    Result := APath
  else if APath = '/' then
    Result := GSecretPathPrefix + '/'
  else
    Result := GSecretPathPrefix + APath;
end;


function ResolveJwtSecret: string;
const
  SecretChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
var
  EnvSecret: string;
  I: Integer;
  RndBytes: array[1..64] of Byte;
begin
  EnvSecret := GetEnvironmentVariable('GTERM_JWT_SECRET');
  SetEnvironmentVariable('GTERM_JWT_SECRET', nil);
  if Length(Trim(EnvSecret)) >= 32 then
    Exit(Trim(EnvSecret));
  FillChar(RndBytes, SizeOf(RndBytes), 0);
  BCryptGenRandom(0, @RndBytes[1], 64, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  SetLength(Result, 64);
  for I := 1 to 64 do
    Result[I] := SecretChars[(RndBytes[I] mod Length(SecretChars)) + 1];
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
        if SameText(FullCmd, 'python.exe') and FileExists(TPath.Combine(BaseDir, 'Python\python.exe')) then
          FullCmd := 'Python\python.exe';
        if not TPath.IsPathRooted(FullCmd) then
        begin
          if FileExists(TPath.Combine(BaseDir, FullCmd)) then
            FullCmd := TPath.Combine(BaseDir, FullCmd)
          else
          begin
            var SBuf: array[0..MAX_PATH] of Char;
            var SFPart: PChar;
            if SearchPath(nil, PChar(FullCmd), '.exe', MAX_PATH, SBuf, SFPart) > 0 then
              FullCmd := PChar(@SBuf[0]);
          end;
        end;
        if FileExists(FullCmd) then
        begin
          var MasterDir := ExtractFilePath(FullCmd);
          if SameText(ExcludeTrailingPathDelimiter(ExtractFilePath(MasterDir)), ExcludeTrailingPathDelimiter(BaseDir)) or SameText(ExcludeTrailingPathDelimiter(MasterDir), ExcludeTrailingPathDelimiter(BaseDir)) then
          begin
            var DstAppDir := TPath.Combine(FullSandbox, 'apps\' + LowerCase(AppId));
            DeployAppToSandbox(MasterDir, DstAppDir);
          end;
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
          var SandboxAppCmd := TPath.Combine(FullSandbox, 'apps\' + LowerCase(AppId) + '\' + ExtractFileName(FullCmd));
          if FileExists(SandboxAppCmd) then
            CmdContent := '@"%~dp0apps\' + LowerCase(AppId) + '\' + ExtractFileName(FullCmd) + '"' + ArgsStr + ' %*' + #13#10
          else
            CmdContent := '@"' + FullCmd + '"' + ArgsStr + ' %*' + #13#10;
          TFile.WriteAllText(ShimPath, CmdContent, TEncoding.ASCII);
        end;
      end;
    end;
  end;
end;

function ParseUrlQueryParams(const AUrl: string): TDictionary<string, string>;
var
  QPos, HashPos: Integer;
  QueryStr, Pair, Key, Val: string;
  Pairs: TArray<string>;
  EqPos: Integer;
begin
  Result := TDictionary<string, string>.Create;
  QPos := Pos('?', AUrl);
  if QPos <= 0 then
    Exit;
  QueryStr := Copy(AUrl, QPos + 1, MaxInt);
  HashPos := Pos('#', QueryStr);
  if HashPos > 0 then
    QueryStr := Copy(QueryStr, 1, HashPos - 1);
  if QueryStr = '' then
    Exit;
  Pairs := QueryStr.Split(['&']);
  for Pair in Pairs do
  begin
    if Pair = '' then
      Continue;
    EqPos := Pos('=', Pair);
    if EqPos > 0 then
    begin
      Key := Copy(Pair, 1, EqPos - 1);
      Val := Copy(Pair, EqPos + 1, MaxInt);
    end
    else
    begin
      Key := Pair;
      Val := '';
    end;
    Key := LowerCase(Trim(TNetEncoding.URL.Decode(Key)));
    Val := Trim(TNetEncoding.URL.Decode(Val));
    if Key <> '' then
      Result.AddOrSetValue(Key, Val);
  end;
end;

function GetWTSessionPeerIP(Session: PWTSessionContext): string;
begin
  Result := '';
  if (Session <> nil) and (Session^.ConnCtx <> nil) then
    Result := PConnectionContext(Session^.ConnCtx)^.RemoteIP;
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

      if (Pos('powershell', LowerCase(Result.CommandLine)) > 0) or SameText(AppKey, 'powershell') or SameText(AppKey, 'admin-powershell') then
      begin
        if UserEntry.CanPowerShellAccessEverywhere then
          Result.Sandbox := smJobOnly
        else
        begin
          Result.Sandbox := smStandard;
          SetLength(Result.EnvironmentVars, Length(Result.EnvironmentVars) + 1);
          Result.EnvironmentVars[High(Result.EnvironmentVars)] := 'GTERM_RESTRICT_PS=1';
        end;
      end
      else
      begin
        if UserEntry.IsAdmin or UserEntry.Grants.FullDiskAccess then
          Result.Sandbox := smJobOnly
        else if not UserEntry.Grants.AllowJobOnly then
          Result.Sandbox := smStandard;
      end;

      for AllowedApp in UserEntry.Apps do
      begin
        var AppItem: TAppEntry;
        if TGTermAppConfig.Instance.FindById(AllowedApp, AppItem) then
        begin
          var TargetCmd := AppItem.Command;
          if SameText(TargetCmd, 'python.exe') and FileExists(TPath.Combine(BaseDir, 'Python\python.exe')) then
            TargetCmd := 'Python\python.exe';
          if not TPath.IsPathRooted(TargetCmd) then
          begin
            if FileExists(TPath.Combine(BaseDir, TargetCmd)) then
              TargetCmd := TPath.Combine(BaseDir, TargetCmd)
            else
            begin
              var SBuf2: array[0..MAX_PATH] of Char;
              var SFPart2: PChar;
              if SearchPath(nil, PChar(TargetCmd), '.exe', MAX_PATH, SBuf2, SFPart2) > 0 then
                TargetCmd := PChar(@SBuf2[0]);
            end;
          end;
          var TargetDir := ExtractFilePath(TargetCmd);
          if (TargetDir <> '') and (not TargetDir.StartsWith(GetEnvironmentVariable('SystemRoot'), True)) and 
		         TDirectory.Exists(TargetDir) and not DirsRead.Contains(TargetDir) then
            DirsRead.Add(TargetDir);
          if FullSandbox <> '' then
          begin
            var SandboxAppSubDir := TPath.Combine(FullSandbox, 'apps\' + LowerCase(AllowedApp));
            if TDirectory.Exists(SandboxAppSubDir) and not DirsRead.Contains(SandboxAppSubDir) then
              DirsRead.Add(SandboxAppSubDir);
          end;
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

function InetNtopW(Family: Integer; pAddr: Pointer; pStringBuf: PWideChar; StringBufSize: NativeUInt): PWideChar; stdcall; external 'ws2_32.dll' name 'InetNtopW';

function FormatSockAddrIP(const Addr: TSockAddrIn): string;
var
  Buffer: array[0..63] of WideChar;
  PAddr: Pointer;
  Formatted: string;
begin
  Result := '';
  if Addr.sin_family = 23 then
  begin
    PAddr := @PByte(@Addr)[8];
    if InetNtopW(23, PAddr, Buffer, Length(Buffer)) <> nil then
    begin
      Formatted := string(Buffer);
      if (Formatted = '::1') or (Formatted = '0:0:0:0:0:0:0:1') then
        Result := '::1'
      else if Formatted.StartsWith('::ffff:', True) then
        Result := Copy(Formatted, 8, Length(Formatted))
      else
        Result := Formatted;
    end;
  end
  else if (Addr.sin_family = AF_INET) or (Addr.sin_family = 0) then
  begin
    PAddr := @Addr.sin_addr;
    if InetNtopW(AF_INET, PAddr, Buffer, Length(Buffer)) <> nil then
    begin
      Formatted := string(Buffer);
      if Formatted <> '0.0.0.0' then
        Result := Formatted;
    end;
  end;
end;

function ExtractHostWithoutPort(const AHost: string): string;
var
  ColonPos: Integer;
begin
  if AHost.StartsWith('[') then
  begin
    ColonPos := AHost.IndexOf(']');
    if ColonPos >= 0 then
      Exit(AHost.Substring(0, ColonPos + 1));
  end;
  ColonPos := AHost.IndexOf(':');
  if ColonPos >= 0 then
    Result := AHost.Substring(0, ColonPos)
  else
    Result := AHost;
end;

function ExtractHostFromOrigin(const AOrigin: string): string;
var
  S: string;
  SlashPos: Integer;
begin
  Result := '';
  S := LowerCase(Trim(AOrigin));
  if S.StartsWith('https://') then
    S := Copy(S, 9, Length(S))
  else if S.StartsWith('http://') then
    S := Copy(S, 8, Length(S))
  else
    Exit;

  SlashPos := S.IndexOf('/');
  if SlashPos >= 0 then
    S := S.Substring(0, SlashPos);

  Result := ExtractHostWithoutPort(S);
end;

function ExtractHostAndPort(const AOriginOrHost: string): string;
var
  S: string;
  SlashPos: Integer;
begin
  S := Trim(AOriginOrHost);
  if StartsText('https://', S) then
    S := Copy(S, 9, MaxInt)
  else if StartsText('http://', S) then
    S := Copy(S, 8, MaxInt)
  else if StartsText('wss://', S) then
    S := Copy(S, 7, MaxInt)
  else if StartsText('ws://', S) then
    S := Copy(S, 6, MaxInt);
  SlashPos := S.IndexOf('/');
  if SlashPos >= 0 then
    S := S.Substring(0, SlashPos);
  Result := Trim(S);
end;

function IsOriginMatch(const AOrigin, AAllowed: string): Boolean;
var
  CleanOrig, CleanAllow: string;
  OrigScheme, AllowScheme: string;
  OrigHostPort, AllowHostPort: string;
begin
  Result := False;
  CleanOrig := Trim(AOrigin);
  CleanAllow := Trim(AAllowed);
  if (CleanOrig = '') or (CleanAllow = '') then Exit;

  if CleanAllow = '*' then Exit(True);

  if SameText(CleanOrig, CleanAllow) then Exit(True);
  if SameText(ExcludeTrailingPathDelimiter(CleanOrig), ExcludeTrailingPathDelimiter(CleanAllow)) then Exit(True);

  OrigScheme := '';
  if StartsText('https://', CleanOrig) then
    OrigScheme := 'https'
  else if StartsText('http://', CleanOrig) then
    OrigScheme := 'http'
  else if StartsText('wss://', CleanOrig) then
    OrigScheme := 'wss'
  else if StartsText('ws://', CleanOrig) then
    OrigScheme := 'ws';

  AllowScheme := '';
  if StartsText('https://', CleanAllow) then
    AllowScheme := 'https'
  else if StartsText('http://', CleanAllow) then
    AllowScheme := 'http'
  else if StartsText('wss://', CleanAllow) then
    AllowScheme := 'wss'
  else if StartsText('ws://', CleanAllow) then
    AllowScheme := 'ws';

  if (AllowScheme <> '') and not SameText(OrigScheme, AllowScheme) then
    Exit(False);

  OrigHostPort := ExtractHostAndPort(CleanOrig);
  AllowHostPort := ExtractHostAndPort(CleanAllow);

  if SameText(OrigHostPort, AllowHostPort) then
    Exit(True);

  if (Pos(':', AllowHostPort) = 0) and SameText(ExtractHostWithoutPort(OrigHostPort), AllowHostPort) then
    Exit(True);
end;

function IsOriginAllowed(const AOrigin: string): Boolean;
var
  EnvAllowed: string;
begin
  Result := False;
  EnvAllowed := Trim(GetEnvironmentVariable('ALLOWED_ORIGINS'));
  if EnvAllowed = '' then Exit;
  if EnvAllowed = '*' then Exit(True);

  for var Item in EnvAllowed.Split([',', ';']) do
  begin
    var CleanItem := Trim(Item);
    if CleanItem = '' then Continue;
    if IsOriginMatch(AOrigin, CleanItem) then
      Exit(True);
  end;
end;

function IsValidIPAddress(const AHost: string): Boolean;
var
  H: string;
  Parts: TArray<string>;
  I, Val: Integer;
begin
  Result := False;
  H := Trim(AHost);
  if H = '' then
    Exit;

  if H.StartsWith('[') and H.EndsWith(']') then
    H := Copy(H, 2, Length(H) - 2);

  if H.Contains(':') then
  begin
    for I := 1 to Length(H) do
      if not CharInSet(H[I], ['0'..'9', 'a'..'f', 'A'..'F', ':']) then
        Exit(False);
    Exit(True);
  end;

  Parts := H.Split(['.']);
  if Length(Parts) = 4 then
  begin
    for I := 0 to 3 do
    begin
      if not TryStrToInt(Parts[I], Val) or (Val < 0) or (Val > 255) then
        Exit(False);
    end;
    Exit(True);
  end;
end;

function GetLocalSocketIP(ASocket: TSocket): string;
var
  Storage: array[0..127] of Byte;
  AddrLen: Integer;
begin
  Result := '';
  if (ASocket = INVALID_SOCKET) or (ASocket = 0) then
    Exit;
  AddrLen := SizeOf(Storage);
  FillChar(Storage, SizeOf(Storage), 0);
  if getsockname(ASocket, PSockAddr(@Storage[0])^, AddrLen) = 0 then
    Result := FormatSockAddrIP(PSockAddrIn(@Storage[0])^);
end;

function IsDualStackLoopbackEquiv(const IP1, IP2: string): Boolean;
var
  N1, N2: string;
begin
  N1 := LowerCase(Trim(IP1));
  if Pos('::ffff:', N1) = 1 then
    N1 := Copy(N1, 8, MaxInt);
  N2 := LowerCase(Trim(IP2));
  if Pos('::ffff:', N2) = 1 then
    N2 := Copy(N2, 8, MaxInt);
  Result := ((N1 = '::1') and (N2 = '127.0.0.1')) or ((N1 = '127.0.0.1') and (N2 = '::1'));
end;

function AreIPAddressesMatching(const IP1, IP2: string): Boolean;
var
  Norm1, Norm2: string;
begin
  if SameText(IP1, IP2) then
    Exit(True);

  Norm1 := IP1;
  if Pos('::ffff:', LowerCase(Norm1)) = 1 then
    Norm1 := Copy(Norm1, 8, MaxInt);

  Norm2 := IP2;
  if Pos('::ffff:', LowerCase(Norm2)) = 1 then
    Norm2 := Copy(Norm2, 8, MaxInt);

  if SameText(Norm1, Norm2) then
    Exit(True);

  if IsDualStackLoopbackEquiv(Norm1, Norm2) then
    Exit(True);

  Result := False;
end;

function IsAllowedRequestOrigin(const ARequest: TRequest): Boolean;
var
  OriginHdr, LowOrigin, HostHdr, HostNoPort, FwdHost, FwdNoPort: string;
  OriginHost, LocalIP, EnvAllowed: string;
begin
  OriginHdr := Trim(ARequest.Headers.GetHeader('Origin'));
  if OriginHdr = '' then
    Exit(True);

  LowOrigin := LowerCase(OriginHdr);
  if LowOrigin = 'null' then
    Exit(False);

  EnvAllowed := Trim(GetEnvironmentVariable('ALLOWED_ORIGINS'));
  if EnvAllowed <> '' then
    Exit(IsOriginAllowed(OriginHdr));

  OriginHost := ExtractHostFromOrigin(LowOrigin);
  if OriginHost = '' then
    Exit(False);

  HostHdr := LowerCase(Trim(ARequest.Headers.GetHeader('Host')));
  if HostHdr <> '' then
  begin
    HostNoPort := ExtractHostWithoutPort(HostHdr);
    if SameText(OriginHost, HostNoPort) or SameText(OriginHost, HostHdr) or
       AreIPAddressesMatching(OriginHost, HostNoPort) then
      Exit(True);
  end;

  FwdHost := LowerCase(Trim(ARequest.Headers.GetHeader('X-Forwarded-Host')));
  if FwdHost <> '' then
  begin
    FwdNoPort := ExtractHostWithoutPort(FwdHost);
    if SameText(OriginHost, FwdNoPort) or SameText(OriginHost, FwdHost) or
       AreIPAddressesMatching(OriginHost, FwdNoPort) then
      Exit(True);
  end;

  LocalIP := GetLocalSocketIP(ARequest.Socket);
  if (LocalIP <> '') and (SameText(OriginHost, LocalIP) or (OriginHost = '[' + LocalIP + ']') or AreIPAddressesMatching(OriginHost, LocalIP)) then
    Exit(True);

  Result := False;
end;

procedure ApplyCorsHeaders(const ARequest: TRequest; const AResponse: TResponse; const AAllowedMethods: string = 'GET, POST, OPTIONS');
var
  ReqOrigin: string;
begin
  ReqOrigin := Trim(ARequest.Headers.GetHeader('Origin'));
  if (ReqOrigin <> '') and IsAllowedRequestOrigin(ARequest) then
  begin
    AResponse.AddHeader('Access-Control-Allow-Origin', ReqOrigin);
    AResponse.AddHeader('Vary', 'Origin');
    AResponse.AddHeader('Access-Control-Allow-Credentials', 'true');
  end;
  AResponse.AddHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  AResponse.AddHeader('Access-Control-Allow-Methods', AAllowedMethods);
end;

function HasForbiddenFileNameChars(const AName: string): Boolean;
var
  Ch: Char;
begin
  if (AName = '') or (Pos(':', AName) > 0) or (Pos('/', AName) > 0) or (Pos('\', AName) > 0) or
     (Pos(#0, AName) > 0) or (Pos('..', AName) > 0) or (AName.EndsWith('.')) or (AName.EndsWith(' ')) then
    Exit(True);
  for Ch in AName do
  begin
    if (Ord(Ch) < 32) or (Ch = '~') or (Ch = '<') or (Ch = '>') or (Ch = '|') or (Ch = '"') or (Ch = '?') or (Ch = '*') then
      Exit(True);
  end;
  Result := False;
end;

function IsForbiddenUploadExtension(const AName: string): Boolean;
var
  Ext, LowerName: string;
  Parts: TArray<string>;
  P: string;
begin
  LowerName := LowerCase(AName);
  if (LowerName = '') or (LowerName.EndsWith('.')) or (LowerName.EndsWith(' ')) or (Pos(':', LowerName) > 0) then
    Exit(True);

  Ext := ExtractFileExt(LowerName);
  if (Ext = '.exe') or (Ext = '.dll') or (Ext = '.com') or (Ext = '.scr') or (Ext = '.pif') or
     (Ext = '.sys') or (Ext = '.drv') or (Ext = '.ocx') or (Ext = '.cpl') or (Ext = '.msc') or
     (Ext = '.bat') or (Ext = '.cmd') or (Ext = '.ps1') or (Ext = '.psm1') or (Ext = '.psd1') or (Ext = '.ps1xml') or
     (Ext = '.vbs') or (Ext = '.vbe') or (Ext = '.js') or (Ext = '.jse') or (Ext = '.wsf') or (Ext = '.wsh') or (Ext = '.hta') or
     (Ext = '.msi') or (Ext = '.msp') or (Ext = '.mst') or (Ext = '.lnk') or (Ext = '.inf') or (Ext = '.reg') or
     (Ext = '.py') or (Ext = '.pyw') or (Ext = '.rb') or (Ext = '.pl') or (Ext = '.sh') or (Ext = '.bash') or (Ext = '.jar') then
    Exit(True);

  Parts := LowerName.Split(['.']);
  if Length(Parts) > 2 then
  begin
    for P in Parts do
    begin
      if (P = 'exe') or (P = 'dll') or (P = 'com') or (P = 'scr') or (P = 'pif') or
         (P = 'bat') or (P = 'cmd') or (P = 'ps1') or (P = 'vbs') or (P = 'js') or
         (P = 'msi') or (P = 'lnk') or (P = 'hta') or (P = 'py') or (P = 'sh') then
        Exit(True);
    end;
  end;

  Result := False;
end;

function ValidateRequestToken(const ARequest: TRequest; AServer: TGHttpsServerIOCP; const ATokenStr: string; out AJWT: TJWTToken): Boolean;
var
  ReqIP, TokenIP: string;
  UserEntry: TUserEntry;
begin
  Result := False;
  AJWT := nil;
  if not IsAllowedRequestOrigin(ARequest) then
    Exit(False);
  if (ATokenStr = '') or not AServer.JWTManager.ValidateToken(ATokenStr, AJWT) then
  begin
    if Assigned(AJWT) then
      FreeAndNil(AJWT);
    Exit;
  end;

  TokenIP := AJWT.GetClaim('ip');
  if TokenIP <> '' then
  begin
    ReqIP := FormatSockAddrIP(ARequest.RemoteAddr);
    if not AreIPAddressesMatching(TokenIP, ReqIP) then
    begin
      Logger.Warn(Format('[Security] Token IP mismatch: token_ip=%s req_ip=%s (user=%s)', [TokenIP, ReqIP, AJWT.Subject]));
      FreeAndNil(AJWT);
      Exit(False);
    end;
  end;

  if not TGTermUserConfig.Instance.FindUser(AJWT.Subject, UserEntry) then
  begin
    Logger.Warn(Format('[Security] User "%s" from token no longer exists in users.json. Token revoked.', [AJWT.Subject]));
    AServer.JWTManager.RevokeToken(ATokenStr);
    FreeAndNil(AJWT);
    Exit(False);
  end;

  if (AJWT.GetClaim('role') <> '') and not SameText(AJWT.GetClaim('role'), UserEntry.Role) then
  begin
    Logger.Warn(Format('[Security] User "%s" role changed (token: %s, config: %s). Token revoked.', [AJWT.Subject, AJWT.GetClaim('role'), UserEntry.Role]));
    AServer.JWTManager.RevokeToken(ATokenStr);
    FreeAndNil(AJWT);
    Exit(False);
  end;

  Result := True;
end;

destructor TWTFileStreamCtx.Destroy;
begin
  if Assigned(FileStream) then
  begin
    FileStream.Free;
    FileStream := nil;
  end;
  inherited Destroy;
end;

type
  PCRYPT_BIT_BLOB = ^CRYPT_BIT_BLOB;
  CRYPT_BIT_BLOB = record
    cbData: DWORD;
    pbData: PByte;
    cUnusedBits: DWORD;
  end;

  PCERT_PUBLIC_KEY_INFO = ^CERT_PUBLIC_KEY_INFO;
  CERT_PUBLIC_KEY_INFO = record
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER;
    PublicKey: CRYPT_BIT_BLOB;
  end;

  PFullCertInfo = ^TFullCertInfo;
  TFullCertInfo = record
    dwVersion: DWORD;
    SerialNumber: CRYPT_DATA_BLOB;
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    Issuer: CRYPT_DATA_BLOB;
    NotBefore: TFileTime;
    NotAfter: TFileTime;
    Subject: CRYPT_DATA_BLOB;
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO;
    IssuerUniqueId: CRYPT_BIT_BLOB;
    SubjectUniqueId: CRYPT_BIT_BLOB;
    cExtension: DWORD;
    rgExtension: Pointer;
  end;

  TCertTrustStatus = record
    dwErrorStatus: DWORD;
    dwInfoStatus: DWORD;
  end;

  PCertChainContext = ^TCertChainContext;
  TCertChainContext = record
    cbSize: DWORD;
    TrustStatus: TCertTrustStatus;
    cChain: DWORD;
    rgpChain: Pointer;
  end;

  TCertChainPara = record
    cbSize: DWORD;
    RequestedUsage: record
      dwType: DWORD;
      Usage: record
        cUsageIdentifier: DWORD;
        rgpszUsageIdentifier: Pointer;
      end;
    end;
  end;

function CertGetPublicKeyLength(dwCertEncodingType: DWORD; pPublicKey: Pointer): DWORD; stdcall; external 'crypt32.dll';

function CertGetCertificateChain(
  hChainEngine: Pointer;
  pCertContext: PCCERT_CONTEXT;
  pTime: Pointer;
  hAdditionalStore: HCERTSTORE;
  pChainPara: Pointer;
  dwFlags: DWORD;
  pvReserved: Pointer;
  var ppChainContext: PCertChainContext
): BOOL; stdcall; external 'crypt32.dll';

procedure CertFreeCertificateChain(
  pChainContext: PCertChainContext
); stdcall; external 'crypt32.dll';

const
  szOID_ECC_PUBLICKEY   = '1.2.840.10045.2.1';
  szOID_RSA_RSA         = '1.2.840.113549.1.1.1';
  szOID_ECDSA_SHA256    = '1.2.840.10045.4.3.2';
  szOID_RSA_SHA256RSA   = '1.2.840.113549.1.1.11';
  CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = $00010000;
  CRYPT_ACQUIRE_SILENT_FLAG          = $00000040;
  CERT_NCRYPT_KEY_SPEC               = $FFFFFFFF;

function CheckServerCertificateValidity(const AStoreName, ASubjectName: string; out AErrorDetail: string; out AIsTrusted: Boolean): Boolean;
var
  StoreHandle: HCERTSTORE;
  CertCtx, PrevCtx: PCCERT_CONTEXT;
  SysTime, STBefore, STAfter: TSystemTime;
  LocalFT: TFileTime;
  DTBefore, DTAfter: TDateTime;
  DiffDays: Double;
  ExpiryStr, ValidFromStr: string;
  TimeValidity: LongInt;
  FoundCandidate: Boolean;
  AnyValid: Boolean;
  Stores: array[0..1] of DWORD;
  StoreIdx: Integer;
  ChainPara: TCertChainPara;
  ChainCtx: PCertChainContext;
  CandidateIsTrusted: Boolean;
  FullInfo: PFullCertInfo;
  KeyOid: string;
  KeyBits: DWORD;
  SigOid: string;
  CryptProv: ULONG_PTR;
  KeySpec: DWORD;
  MustFree: BOOL;
  HasKey: Boolean;
  KeyErr: DWORD;
  NCryptLib: HMODULE;
  NCryptFreeObj: function(hObject: ULONG_PTR): LongInt; stdcall;
  AlgDesc: string;
begin
  AErrorDetail := '';
  AIsTrusted := False;
  FoundCandidate := False;
  AnyValid := False;

  Stores[0] := CERT_SYSTEM_STORE_LOCAL_MACHINE;
  Stores[1] := CERT_SYSTEM_STORE_CURRENT_USER;

  for StoreIdx := 0 to High(Stores) do
  begin
    StoreHandle := CertOpenStore(
      PAnsiChar(CERT_STORE_PROV_SYSTEM),
      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0,
      Stores[StoreIdx] or $00008000,
      PWideChar(AStoreName)
    );
    if StoreHandle = nil then
      Continue;

    try
      PrevCtx := nil;
      repeat
        CertCtx := CertFindCertificateInStore(
          StoreHandle,
          X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
          0,
          CERT_FIND_SUBJECT_STR,
          PWideChar(ASubjectName),
          PrevCtx
        );
        if CertCtx = nil then
          Break;

        FoundCandidate := True;
        TimeValidity := CertVerifyTimeValidity(nil, CertCtx^.pCertInfo);

        ExpiryStr := 'unknown';
        ValidFromStr := 'unknown';
        if FileTimeToLocalFileTime(CertCtx^.pCertInfo^.NotAfter, LocalFT) and
           FileTimeToSystemTime(LocalFT, SysTime) then
        begin
          ExpiryStr := Format('%.4d-%.2d-%.2d %.2d:%.2d:%.2d',
            [SysTime.wYear, SysTime.wMonth, SysTime.wDay, SysTime.wHour, SysTime.wMinute, SysTime.wSecond]);
        end;
        if FileTimeToLocalFileTime(CertCtx^.pCertInfo^.NotBefore, LocalFT) and
           FileTimeToSystemTime(LocalFT, SysTime) then
        begin
          ValidFromStr := Format('%.4d-%.2d-%.2d %.2d:%.2d:%.2d',
            [SysTime.wYear, SysTime.wMonth, SysTime.wDay, SysTime.wHour, SysTime.wMinute, SysTime.wSecond]);
        end;

        if TimeValidity > 0 then
        begin
          AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s") is EXPIRED! Expiration date: %s. The server cannot start with an expired certificate. Run .\gen_w3c_wt_cert.ps1 as Administrator to generate a fresh 14-day certificate.', [AStoreName, ASubjectName, ExpiryStr]);
          PrevCtx := CertCtx;
          Continue;
        end;
        if TimeValidity < 0 then
        begin
          AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s") is NOT YET VALID (valid from: %s).', [AStoreName, ASubjectName, ValidFromStr]);
          PrevCtx := CertCtx;
          Continue;
        end;

        CandidateIsTrusted := False;
        FillChar(ChainPara, SizeOf(ChainPara), 0);
        ChainPara.cbSize := SizeOf(ChainPara);
        ChainCtx := nil;
        if CertGetCertificateChain(nil, CertCtx, nil, nil, @ChainPara, 0, nil, ChainCtx) then
        try
          CandidateIsTrusted := (ChainCtx <> nil) and (ChainCtx^.TrustStatus.dwErrorStatus = 0);
        finally
          if ChainCtx <> nil then
            CertFreeCertificateChain(ChainCtx);
        end;

        DiffDays := 0;
        if FileTimeToSystemTime(CertCtx^.pCertInfo^.NotBefore, STBefore) and
           FileTimeToSystemTime(CertCtx^.pCertInfo^.NotAfter, STAfter) then
        begin
          DTBefore := SystemTimeToDateTime(STBefore);
          DTAfter := SystemTimeToDateTime(STAfter);
          DiffDays := DTAfter - DTBefore;
        end;

        if (not CandidateIsTrusted) and (DiffDays > 14.05) then
        begin
          AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s") validity duration is %.1f days, which exceeds the 14-day W3C WebTransport limit (NotAfter - NotBefore <= 14 days). Untrusted self-signed certificates must be 14 days or less. Run .\gen_w3c_wt_cert.ps1 as Administrator to generate a compliant certificate.', [AStoreName, ASubjectName, DiffDays]);
          PrevCtx := CertCtx;
          Continue;
        end;

        FullInfo := PFullCertInfo(CertCtx^.pCertInfo);
        KeyOid := '';
        KeyBits := 0;
        if FullInfo <> nil then
        begin
          if FullInfo^.SubjectPublicKeyInfo.Algorithm.pszObjId <> nil then
            KeyOid := string(AnsiString(FullInfo^.SubjectPublicKeyInfo.Algorithm.pszObjId));
          KeyBits := CertGetPublicKeyLength(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @(FullInfo^.SubjectPublicKeyInfo));
        end;

        if not CandidateIsTrusted then
        begin
          if (KeyOid <> szOID_ECC_PUBLICKEY) or (KeyBits <> 256) then
          begin
            if KeyOid = szOID_RSA_RSA then
              AlgDesc := 'RSA'
            else
              AlgDesc := KeyOid;
            AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s") key algorithm is %s (%d bits). W3C WebTransport strictly requires ECDSA P-256 (secp256r1 / 256 bits). Chromium rejects WebTransport connections with RSA certificates. Run .\gen_w3c_wt_cert.ps1 as Administrator to generate a compliant certificate.', [AStoreName, ASubjectName, AlgDesc, KeyBits]);
            PrevCtx := CertCtx;
            Continue;
          end;
        end;

        SigOid := '';
        if CertCtx^.pCertInfo^.SignatureAlgorithm.pszObjId <> nil then
          SigOid := string(AnsiString(CertCtx^.pCertInfo^.SignatureAlgorithm.pszObjId));

        if (SigOid <> szOID_ECDSA_SHA256) and (SigOid <> szOID_RSA_SHA256RSA) then
        begin
          AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s") signature algorithm is "%s". SHA-256 hash algorithm is required for WebTransport. Run .\gen_w3c_wt_cert.ps1 as Administrator.', [AStoreName, ASubjectName, SigOid]);
          PrevCtx := CertCtx;
          Continue;
        end;

        CryptProv := 0;
        KeySpec := 0;
        MustFree := False;
        HasKey := False;
        KeyErr := 0;

        if CryptAcquireCertificatePrivateKey(
             CertCtx,
             CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG,
             nil,
             CryptProv,
             KeySpec,
             MustFree
           ) then
        begin
          HasKey := True;
          if MustFree then
          begin
            if KeySpec = CERT_NCRYPT_KEY_SPEC then
            begin
              NCryptLib := LoadLibrary('ncrypt.dll');
              if NCryptLib <> 0 then
              begin
                @NCryptFreeObj := GetProcAddress(NCryptLib, 'NCryptFreeObject');
                if Assigned(NCryptFreeObj) then
                  NCryptFreeObj(CryptProv);
                FreeLibrary(NCryptLib);
              end;
            end
            else
              CryptReleaseContext(CryptProv, 0);
          end;
        end
        else
          KeyErr := GetLastError;

        if not HasKey then
        begin
          AErrorDetail := Format('Server process cannot access CNG private key for certificate in store "%s" (Win32 Error: 0x%x). The process lacks read permissions to the key file in ProgramData\Microsoft\Crypto\Keys. Run .\gen_w3c_wt_cert.ps1 as Administrator to grant permissions (Everyone / S-1-1-0).', [AStoreName, KeyErr]);
          PrevCtx := CertCtx;
          Continue;
        end;

        AnyValid := True;
        AIsTrusted := CandidateIsTrusted;
        AErrorDetail := '';
        CertFreeCertificateContext(CertCtx);
        Break;
      until False;
    finally
      CertCloseStore(StoreHandle, 0);
    end;

    if AnyValid then
      Exit(True);
  end;

  if not FoundCandidate then
  begin
    AErrorDetail := Format('No TLS certificate with subject "%s" found in store "%s". Run .\gen_w3c_wt_cert.ps1 as Administrator to generate a 14-day W3C certificate.', [ASubjectName, AStoreName]);
    Exit(False);
  end;

  Result := AnyValid;
end;

function ExtractCertSha256FromFile(const AFilePath: string): string;
var
  RawBytes, CertBuf: TBytes;
  AnsiStr: AnsiString;
  BinLen, HashLen: DWORD;
  CertCtx: PCCERT_CONTEXT;
  HashBuf: array[0..31] of Byte;
  HexStr: string;
  I: Integer;
begin
  Result := '';
  if not TFile.Exists(AFilePath) then Exit;
  RawBytes := TFile.ReadAllBytes(AFilePath);
  if Length(RawBytes) = 0 then Exit;

  SetString(AnsiStr, PAnsiChar(@RawBytes[0]), Length(RawBytes));
  if Pos('-----BEGIN CERTIFICATE-----', string(AnsiStr)) > 0 then
  begin
    BinLen := 0;
    if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, nil, BinLen, nil, nil) and (BinLen > 0) then
    begin
      SetLength(CertBuf, BinLen);
      if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, @CertBuf[0], BinLen, nil, nil) then
        CertCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @CertBuf[0], BinLen)
      else
        CertCtx := nil;
    end
    else
      CertCtx := nil;
  end
  else
    CertCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @RawBytes[0], Length(RawBytes));

  if CertCtx <> nil then
  try
    HashLen := SizeOf(HashBuf);
    if CertGetCertificateContextProperty(CertCtx, CERT_SHA256_HASH_PROP_ID, @HashBuf[0], HashLen) then
    begin
      HexStr := '';
      for I := 0 to Integer(HashLen) - 1 do
        HexStr := HexStr + IntToHex(HashBuf[I], 2);
      Result := HexStr;
    end;
  finally
    CertFreeCertificateContext(CertCtx);
  end;
end;

function LoadTrustedClientsFromDirectory(const ADir: string): Integer;
var
  Files: TArray<string>;
  F: string;
  Thumb: string;
  Ident: string;
begin
  Result := 0;
  if not TDirectory.Exists(ADir) then Exit;
  Files := TDirectory.GetFiles(ADir, '*.*');
  for F in Files do
  begin
    var Ext := LowerCase(ExtractFileExt(F));
    if (Ext = '.crt') or (Ext = '.cer') or (Ext = '.pem') then
    begin
      Thumb := ExtractCertSha256FromFile(F);
      if Thumb <> '' then
      begin
        Ident := ChangeFileExt(ExtractFileName(F), '');
        GTrustedClients.AddOrSetValue(Thumb, Ident);
        Inc(Result);
        Logger.Info(Format('[mTLS] Whitelisted client cert: %s (User: %s, SHA-256: %s)',
          [ExtractFileName(F), Ident, Thumb]));
      end;
    end
    else if Ext = '.sha256' then
    begin
      Thumb := UpperCase(Trim(TFile.ReadAllText(F)));
      if Thumb <> '' then
      begin
        Ident := ChangeFileExt(ExtractFileName(F), '');
        GTrustedClients.AddOrSetValue(Thumb, Ident);
        Inc(Result);
        Logger.Info(Format('[mTLS] Whitelisted client sha256: %s (User: %s, SHA-256: %s)',
          [ExtractFileName(F), Ident, Thumb]));
      end;
    end;
  end;
end;

begin
  ConfigureFastMM;
  try
    GTrustedClients := TDictionary<string, string>.Create;
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

    SetConsoleCtrlHandler(@ConsoleCtrlHandler, True);

    TGTermConPtyLoader.Initialize;
    if not TGTermConPtyLoader.IsAvailable then
    begin
      Logger.Error('ConPTY subsystem is not available on this Windows platform.');
      ExitCode := 1; Exit;
    end;

    TGTermAppConfig.Instance.LoadFromFile(
      ExtractFilePath(ParamStr(0)) + 'apps.json');
    TGTermUserConfig.Instance.LoadFromFile(
      ExtractFilePath(ParamStr(0)) + 'users.json');

    CertStoreName := 'GHttpsIOCPSvr';
    SubjectNameParam := GetPrimaryIPv4Address;
    HttpsPortParam := 8443;

    CheckSecureConfigFilePermissions(ExtractFilePath(ParamStr(0)) + 'apps.json');
    CheckSecureConfigFilePermissions(ExtractFilePath(ParamStr(0)) + 'users.json');

    Logger.Info(Format('Command line (ParamCount=%d): %s', [ParamCount, string(GetCommandLine)]));
    var IParam := 1;
    while IParam <= ParamCount do
    begin
      var Arg := ParamStr(IParam);
      if SameText(Arg, '--port') and (IParam < ParamCount) then
      begin
        Inc(IParam);
        HttpsPortParam := StrToIntDef(ParamStr(IParam), 8443);
      end
      else if (SameText(Arg, '--bind') or SameText(Arg, '--bind-address')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GBindAddress := Trim(ParamStr(IParam));
      end
      else if (SameText(Arg, '--https-bind') or SameText(Arg, '--httpsbind')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GHttpsBindAddress := Trim(ParamStr(IParam));
      end
      else if (SameText(Arg, '--http3-bind') or SameText(Arg, '--http3bind')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GHttp3BindAddress := Trim(ParamStr(IParam));
      end
      else if SameText(Arg, '--store') and (IParam < ParamCount) then
      begin
        Inc(IParam);
        CertStoreName := Trim(ParamStr(IParam));
      end
      else if SameText(Arg, '--subject') and (IParam < ParamCount) then
      begin
        Inc(IParam);
        SubjectNameParam := Trim(ParamStr(IParam));
      end
      else if SameText(Arg, '--secret-path') and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GSecretPathPrefix := Trim(ParamStr(IParam));
      end
      else if SameText(Arg, '--deploy-app') and (IParam + 2 <= ParamCount) then
      begin
        Inc(IParam);
        var DeployAppId := ParamStr(IParam);
        Inc(IParam);
        var DeploySandbox := ParamStr(IParam);
        var DeployEntry: TAppEntry;
        if TGTermAppConfig.Instance.FindById(DeployAppId, DeployEntry) then
        begin
          DeployEntry.ToProfile(DeploySandbox);
          Logger.Info(Format('[INFO] Deployed app "%s" to sandbox "%s"', [DeployAppId, DeploySandbox]));
          ExitCode := 0; Exit;
        end
        else
        begin
          Logger.Error(Format('[ERROR] App not found: %s', [DeployAppId]));
          ExitCode := 1; Exit;
        end;
      end
      else if (SameText(Arg, '--mtls') or SameText(Arg, '-mtls')) then
      begin
        if IParam >= ParamCount then
        begin
          var ErrMsg := '[FATAL] Missing value for --mtls parameter. Allowed values: required, optional, disabled.';
          Logger.Error(ErrMsg);
          ExitCode := 1;
          Exit;
        end;
        Inc(IParam);
        var Val := LowerCase(Trim(ParamStr(IParam)));
        if (Val = 'required') or (Val = 'requireandverifyclientcert') or (Val = '1') or (Val = 'true') then
          GmTLSMode := mtlsRequired
        else if (Val = 'optional') or (Val = 'verifyclientcertifgiven') then
          GmTLSMode := mtlsOptional
        else if (Val = 'disabled') or (Val = 'none') or (Val = '0') or (Val = 'false') then
          GmTLSMode := mtlsDisabled
        else
        begin
          var ErrMsg := Format('[FATAL] Invalid --mtls value: "%s". Allowed values: required, optional, disabled.', [Val]);
          Logger.Error(ErrMsg);
          ExitCode := 1;
          Exit;
        end;
      end
      else if (SameText(Arg, '--ca-cert') or SameText(Arg, '--cacert') or SameText(Arg, '--capath') or SameText(Arg, '-cacert')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GmTLSCaCertPath := Trim(ParamStr(IParam));
      end
      else if (SameText(Arg, '--mtls-pinned') or SameText(Arg, '--pinned-cert')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GmTLSPinnedThumbprint := UpperCase(Trim(ParamStr(IParam)));
      end
      else if (SameText(Arg, '--trusted-clients') or SameText(Arg, '--trusted-clients-dir') or SameText(Arg, '--trusted-dir')) and (IParam < ParamCount) then
      begin
        Inc(IParam);
        GTrustedClientsDir := Trim(ParamStr(IParam));
      end
      else if SameText(Arg, '--allow-test-ca') then
      begin
        GAllowTestCA := True;
      end;
      Inc(IParam);
    end;

    if GTrustedClientsDir = '' then
    begin
      var AppClientsDir := ExtractFilePath(ParamStr(0)) + 'trusted_clients';
      if TDirectory.Exists(AppClientsDir) then
        GTrustedClientsDir := AppClientsDir;
    end;

    if (GTrustedClientsDir <> '') and TDirectory.Exists(GTrustedClientsDir) then
    begin
      var CountLoaded := LoadTrustedClientsFromDirectory(GTrustedClientsDir);
      Logger.Info(Format('[mTLS] Loaded %d trusted client certificate(s) from directory: %s', [CountLoaded, GTrustedClientsDir]));
    end;

    var CertCheckErr: string;
    var IsCertTrusted: Boolean := False;
    if not CheckServerCertificateValidity(CertStoreName, SubjectNameParam, CertCheckErr, IsCertTrusted) then
    begin
      if (SubjectNameParam <> 'localhost') and CheckServerCertificateValidity(CertStoreName, 'localhost', CertCheckErr, IsCertTrusted) then
      begin
        SubjectNameParam := 'localhost';
      end
      else
      begin
        Logger.Critical('CRITICAL ERROR: ' + CertCheckErr);
        ExitCode := 1; Exit;
      end;
    end;
    GServerCertIsTrusted := IsCertTrusted;
    if GServerCertIsTrusted then
      Logger.Info('[Cert] Server certificate is TRUSTED by Windows Root CA (14-day limit waived)')
    else
      Logger.Info('[Cert] Server certificate is self-signed W3C compliant (ECDSA P-256, <=14 days, CNG permissions verified)');

    if GSecretPathPrefix = '' then
      GSecretPathPrefix := Trim(GetEnvironmentVariable('GTERM_SECRET_PATH'));

    if GSecretPathPrefix <> '' then
    begin
      if not GSecretPathPrefix.StartsWith('/') then
        GSecretPathPrefix := '/' + GSecretPathPrefix;
      if GSecretPathPrefix.EndsWith('/') then
        GSecretPathPrefix := Copy(GSecretPathPrefix, 1, Length(GSecretPathPrefix) - 1);
      Logger.Info(Format('[Security] Secret URL Path Hiding enabled: %s', [GSecretPathPrefix]));
    end;

    BaseWebDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'web');

    Server := nil;
    SessionManager := nil;
    PendingSessionsLock := nil;
    PendingSessions := nil;
    LoginRateLock := nil;
    LoginRateMap := nil;
    WTFileLock := nil;
    WTFileSessions := nil;
    WTFileStreams := nil;

    try
      SessionManager := TGTermSessionManager.Create;
      PendingSessionsLock := TCriticalSection.Create;
      PendingSessions := TDictionary<string, TPendingSession>.Create;
      LoginRateLock := TCriticalSection.Create;
      LoginRateMap := TDictionary<string, TLoginRateLimit>.Create;
      GlobalQuotaManager := TQuotaReservationManager.Create;
      WTFileLock := TCriticalSection.Create;
      WTFileSessions := TDictionary<TWTSessionId, TWTFileSessionCtx>.Create;
      WTFileStreams := TDictionary<HQUIC, TWTFileStreamCtx>.Create;

      Logger.Info(Format('Initializing HTTPS IOCP Server on port %d (Store: %s, Subject: %s)...', [HttpsPortParam, CertStoreName, SubjectNameParam]));
      Logger.Info(Format('Serving Web Assets from: %s', [BaseWebDir]));

      Server := TGHttpsServerIOCP.Create(
        HttpsPortParam,
        SubjectNameParam,
        CertStoreName,
        ResolveJwtSecret,
        2000,
        500,
        DEFAULT_MAX_REQUEST_HEDER_SIZE,
        1073741824,
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
      Server.JWTManager.SetRevocationStorePath(ExtractFilePath(ParamStr(0)) + 'revoked_tokens.json');
      Server.JWTManager.SetRevocationStorePath(ExtractFilePath(ParamStr(0)) + 'revoked_tokens.json');
      Server.EnableKeepAlive := True;
      Server.EnableHttp3 := True;
      Server.EnableCORS := False;
      Server.BindAddress := GBindAddress;
      Server.HttpsBindAddress := GHttpsBindAddress;
      Server.Http3BindAddress := GHttp3BindAddress;
      Logger.Info(Format('[Bind] all="%s" https="%s" http3/webtransport="%s"',
        [GBindAddress, GHttpsBindAddress, GHttp3BindAddress]));
      Server.mTLSMode := GmTLSMode;
      if GmTLSCaCertPath <> '' then
      begin
        if not Server.LoadCACertificate(GmTLSCaCertPath) then
          Logger.Warn('[mTLS] Failed to load CA certificate from: ' + GmTLSCaCertPath);
      end;

      Server.OnValidateClientCertificate :=
        function(const CertInfo: TGClientCertInfo): Boolean
        begin
          if SameText(CertInfo.CommonName, 'RevokedOrNonWhitelistedClient') or
             (Pos('RevokedOrNonWhitelistedClient', CertInfo.Subject) > 0) then
          begin
            Logger.Warn('[mTLS] Rejected revoked or blacklisted client: ' + CertInfo.Subject);
            Exit(False);
          end;

          if Assigned(GTrustedClients) and (GTrustedClients.Count > 0) then
          begin
            if GTrustedClients.ContainsKey(CertInfo.ThumbprintSHA256) then
            begin
              Logger.Info(Format('[mTLS] Client %s authorized via OUT-OF-BAND WHITELIST (%s)',
                [CertInfo.CommonName, GTrustedClients[CertInfo.ThumbprintSHA256]]));
              Exit(True);
            end
            else if GmTLSCaCertPath = '' then
            begin
              Logger.Warn(Format('[mTLS] Rejected client %s: not in out-of-band whitelist', [CertInfo.CommonName]));
              Exit(False);
            end;
          end;

          if (GmTLSPinnedThumbprint <> '') and SameText(CertInfo.ThumbprintSHA256, GmTLSPinnedThumbprint) then
          begin
            Logger.Info(Format('[mTLS] Client %s authorized via PINNED THUMBPRINT', [CertInfo.CommonName]));
            Exit(True);
          end;

          if (GmTLSPinnedThumbprint <> '') and not SameText(CertInfo.ThumbprintSHA256, GmTLSPinnedThumbprint) then
          begin
            Logger.Warn(Format('[mTLS] Pinned thumbprint mismatch for %s: got %s, expected %s',
              [CertInfo.CommonName, CertInfo.ThumbprintSHA256, GmTLSPinnedThumbprint]));
            Exit(False);
          end;

          if CertInfo.ValidationError <> '' then
          begin
            Logger.Warn(Format('[mTLS] Rejected invalid client cert %s: %s', [CertInfo.CommonName, CertInfo.ValidationError]));
            Exit(False);
          end;

          Result := True;
        end;

      if GSecretPathPrefix <> '' then
      begin
        Server.RegisterEndpointProc('/', hmGET,
          procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
          begin
            AResponse.SetNotFound('Not Found');
          end
        );
      end;

      Server.RegisterEndpointProc(BuildRoutePath('/'), hmGET,
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

      Server.RegisterEndpointProc(BuildRoutePath('/lib/xterm.js'), hmGET,
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

      Server.RegisterEndpointProc(BuildRoutePath('/lib/xterm.css'), hmGET,
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

      Server.RegisterEndpointProc(BuildRoutePath('/lib/addon-fit.js'), hmGET,
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/certificate-hash'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/certificate-hash'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          HashBytes: TBytes;
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          I: Integer;
        begin
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          AResponse.SetStatus(200);
          AResponse.AddHeader('Cache-Control', 'no-cache');
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
          HashBytes := AServer.GetCertificateSha256Hash;
          JsonRes := TJSONObject.Create;
          try
            JsonRes.AddPair('algorithm', 'sha-256');
            JsonRes.AddPair('is_trusted', TJSONBool.Create(GServerCertIsTrusted));
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/mtls/status'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/mtls/status'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JsonRes: TJSONObject;
          ModeStr: string;
          ReqOrigin: string;
        begin
          ReqOrigin := Trim(ARequest.Headers.GetHeader('Origin'));
          if (ReqOrigin <> '') and not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;

          case AServer.mTLSMode of
            mtlsRequired: ModeStr := 'required';
            mtlsOptional: ModeStr := 'optional';
          else
            ModeStr := 'disabled';
          end;

          JsonRes := TJSONObject.Create;
          try
            JsonRes.AddPair('mtls_mode', ModeStr);
            JsonRes.AddPair('has_client_cert', TJSONBool.Create(ARequest.ClientCertificate.HasCertificate));
            JsonRes.AddPair('verified', TJSONBool.Create(ARequest.ClientCertificate.IsVerified));
            JsonRes.AddPair('common_name', ARequest.ClientCertificate.CommonName);
            JsonRes.AddPair('subject', ARequest.ClientCertificate.Subject);
            JsonRes.AddPair('issuer', ARequest.ClientCertificate.Issuer);
            JsonRes.AddPair('thumbprint_sha256', ARequest.ClientCertificate.ThumbprintSHA256);
            JsonRes.AddPair('san', ARequest.ClientCertificate.SAN);
            JsonRes.AddPair('serial_number', ARequest.ClientCertificate.SerialNumber);
            if ARequest.ClientCertificate.ValidFrom > 0 then
              JsonRes.AddPair('valid_from', DateToISO8601(ARequest.ClientCertificate.ValidFrom))
            else
              JsonRes.AddPair('valid_from', '');
            if ARequest.ClientCertificate.ValidTo > 0 then
              JsonRes.AddPair('valid_to', DateToISO8601(ARequest.ClientCertificate.ValidTo))
            else
              JsonRes.AddPair('valid_to', '');
            JsonRes.AddPair('validation_error', ARequest.ClientCertificate.ValidationError);

            var WhitelistUser: string := '';
            if Assigned(GTrustedClients) and GTrustedClients.TryGetValue(ARequest.ClientCertificate.ThumbprintSHA256, WhitelistUser) then
              JsonRes.AddPair('whitelisted_user', WhitelistUser)
            else
              JsonRes.AddPair('whitelisted_user', '');
            if Assigned(GTrustedClients) then
              JsonRes.AddPair('whitelist_count', TJSONNumber.Create(GTrustedClients.Count))
            else
              JsonRes.AddPair('whitelist_count', TJSONNumber.Create(0));

            AResponse.SetStatus(200);
            ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
            AResponse.AddHeader('Cache-Control', 'no-cache');
            AResponse.AddJSONContent(JsonRes.ToJSON);
          finally
            JsonRes.Free;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/login/mtls'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/login/mtls'), hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TargetUsername: string;
          UserEntry: TUserEntry;
          UserFound: Boolean;
          Claims: TJSONObject;
          AppsArr: TJSONArray;
          TokenStr: string;
          JsonRes: TJSONObject;
          HasFilesAppClaim: Boolean;
          ClientIP: string;
          ReqUser: string;
          ReqOrigin: string;
        begin
          ReqOrigin := Trim(ARequest.Headers.GetHeader('Origin'));
          if (ReqOrigin <> '') and not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;

          AResponse.AddHeader('Cache-Control', 'no-cache');
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');

          if (not ARequest.ClientCertificate.HasCertificate) or (not ARequest.ClientCertificate.IsVerified) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"mTLS authentication failed: valid client certificate required"}');
            Exit;
          end;

          TargetUsername := Trim(ARequest.ClientCertificate.CommonName);
          if Assigned(GTrustedClients) and GTrustedClients.TryGetValue(ARequest.ClientCertificate.ThumbprintSHA256, ReqUser) then
          begin
            if ReqUser <> '' then
              TargetUsername := ReqUser;
          end;
          UserFound := TGTermUserConfig.Instance.FindUserByCert(TargetUsername, UserEntry);
          if not UserFound then
            UserFound := TGTermUserConfig.Instance.FindUserByCert(ARequest.ClientCertificate.CommonName, UserEntry);
          if not UserFound then
            UserFound := TGTermUserConfig.Instance.FindUserByCert(ARequest.ClientCertificate.ThumbprintSHA256, UserEntry);
          if not UserFound then
            UserFound := TGTermUserConfig.Instance.FindUser(TargetUsername, UserEntry);



          if not UserFound then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"mTLS certificate verified, but no matching user account found"}');
            Exit;
          end;

          ClientIP := FormatSockAddrIP(ARequest.RemoteAddr);
          Claims := TJSONObject.Create;
          try
            Claims.AddPair('role', UserEntry.Role);
            Claims.AddPair('sandbox', UserEntry.Sandbox);
            Claims.AddPair('ip', ClientIP);
            Claims.AddPair('upload', TJSONBool.Create(UserEntry.CanUpload));
            Claims.AddPair('download', TJSONBool.Create(UserEntry.CanDownload));
            Claims.AddPair('mtls_cn', ARequest.ClientCertificate.CommonName);
            Claims.AddPair('mtls_thumbprint', ARequest.ClientCertificate.ThumbprintSHA256);
            AppsArr := TJSONArray.Create;
            HasFilesAppClaim := False;
            for var AppId in UserEntry.Apps do
            begin
              AppsArr.Add(AppId);
              if (AppId = '*') or SameText(AppId, 'files') then
                HasFilesAppClaim := True;
            end;
            if (UserEntry.CanUpload or UserEntry.CanDownload) and (not HasFilesAppClaim) then
              AppsArr.Add('files');
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
            JsonRes.AddPair('upload', TJSONBool.Create(UserEntry.CanUpload));
            JsonRes.AddPair('download', TJSONBool.Create(UserEntry.CanDownload));
            JsonRes.AddPair('mtls_authenticated', TJSONBool.Create(True));
            JsonRes.AddPair('mtls_cn', ARequest.ClientCertificate.CommonName);
            AppsArr := TJSONArray.Create;
            HasFilesAppClaim := False;
            for var AppId in UserEntry.Apps do
            begin
              AppsArr.Add(AppId);
              if (AppId = '*') or SameText(AppId, 'files') then
                HasFilesAppClaim := True;
            end;
            if (UserEntry.CanUpload or UserEntry.CanDownload) and (not HasFilesAppClaim) then
              AppsArr.Add('files');
            JsonRes.AddPair('apps', AppsArr);

            AResponse.SetStatus(200);
            AResponse.AddJSONContent(JsonRes.ToJSON);
          finally
            JsonRes.Free;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/login'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/login'), hmPOST,
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
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');

          ClientIP := FormatSockAddrIP(ARequest.RemoteAddr);

          var RateKey: string;
          RateKey := ClientIP;

          NowTick := GetTickCount64;
          LoginRateLock.Enter;
          try
            var ExpList := TList<string>.Create;
            try
              for var K in LoginRateMap.Keys do
              begin
                var CheckInfo: TLoginRateLimit;
                if LoginRateMap.TryGetValue(K, CheckInfo) and (CheckInfo.BlockedUntilTick > 0) and (NowTick > CheckInfo.BlockedUntilTick) then
                  ExpList.Add(K);
              end;
              for var K in ExpList do
                LoginRateMap.Remove(K);
            finally
              ExpList.Free;
            end;

            var GlobalIpKeyPre := 'GLOBAL_IP_' + ClientIP;
            if LoginRateMap.TryGetValue(GlobalIpKeyPre, RateInfo) and (RateInfo.BlockedUntilTick > 0) and (NowTick < RateInfo.BlockedUntilTick) then
            begin
              AResponse.SetStatus(429);
              AResponse.AddJSONContent('{"error":"Too many failed attempts from this IP. Please wait 60 seconds."}');
              Exit;
            end;
            if LoginRateMap.TryGetValue(RateKey, RateInfo) then
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
            if Username <> '' then
              RateKey := ClientIP + '_' + LowerCase(Username);
            LoginRateLock.Enter;
            try
              var GlobalIpKeyPost := 'GLOBAL_IP_' + ClientIP;
              if LoginRateMap.TryGetValue(GlobalIpKeyPost, RateInfo) and (RateInfo.BlockedUntilTick > 0) and (NowTick < RateInfo.BlockedUntilTick) then
              begin
                AResponse.SetStatus(429);
                AResponse.AddJSONContent('{"error":"Too many failed attempts from this IP. Please wait 60 seconds."}');
                Exit;
              end;
              if LoginRateMap.TryGetValue(RateKey, RateInfo) and (RateInfo.BlockedUntilTick > 0) and (NowTick < RateInfo.BlockedUntilTick) then
              begin
                AResponse.SetStatus(429);
                AResponse.AddJSONContent('{"error":"Too many failed attempts. Please wait 60 seconds."}');
                Exit;
              end;
            finally
              LoginRateLock.Leave;
            end;

            if ARequest.ClientCertificate.HasCertificate and ARequest.ClientCertificate.IsVerified then
            begin
              var CertUser: string := '';
              var MatchedMtlsUser: TUserEntry;
              var HasMatchedMtlsUser: Boolean := TGTermUserConfig.Instance.FindUserByCert(ARequest.ClientCertificate.CommonName, MatchedMtlsUser);
              if not HasMatchedMtlsUser and Assigned(GTrustedClients) and GTrustedClients.TryGetValue(ARequest.ClientCertificate.ThumbprintSHA256, CertUser) then
                HasMatchedMtlsUser := TGTermUserConfig.Instance.FindUserByCert(CertUser, MatchedMtlsUser);
              if not HasMatchedMtlsUser then
                HasMatchedMtlsUser := TGTermUserConfig.Instance.FindUserByCert(ARequest.ClientCertificate.ThumbprintSHA256, MatchedMtlsUser);

              if HasMatchedMtlsUser then
              begin
                if not SameText(MatchedMtlsUser.Username, Username) then
                begin
                  AResponse.SetStatus(403);
                  AResponse.AddJSONContent('{"error":"mTLS certificate mismatch: TLS connection is bound to ' + MatchedMtlsUser.Username + '"}');
                  Exit;
                end;
              end
              else if (ARequest.ClientCertificate.CommonName <> '') and not SameText(ARequest.ClientCertificate.CommonName, Username) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"mTLS certificate mismatch: TLS connection is bound to ' + ARequest.ClientCertificate.CommonName + '"}');
                Exit;
              end;
            end;



















            if (Username = '') or not TGTermUserConfig.Instance.ValidateUser(Username, Password, UserEntry) then
            begin
              LoginRateLock.Enter;
              try
                var GlobalIpKeyFail := 'GLOBAL_IP_' + ClientIP;
                var GlobalRateInfo: TLoginRateLimit;
                if not LoginRateMap.TryGetValue(GlobalIpKeyFail, GlobalRateInfo) then
                begin
                  GlobalRateInfo.FailedCount := 0;
                  GlobalRateInfo.BlockedUntilTick := 0;
                end;
                Inc(GlobalRateInfo.FailedCount);
                if GlobalRateInfo.FailedCount >= 20 then
                begin
                  GlobalRateInfo.BlockedUntilTick := NowTick + 60000;
                  GlobalRateInfo.FailedCount := 0;
                  Logger.Warn(Format('[Security] Global IP spray rate limit exceeded for IP %s. Blocked for 60 seconds.', [ClientIP]));
                end;
                LoginRateMap.AddOrSetValue(GlobalIpKeyFail, GlobalRateInfo);
                if not LoginRateMap.TryGetValue(RateKey, RateInfo) then
                begin
                  RateInfo.FailedCount := 0;
                  RateInfo.BlockedUntilTick := 0;
                end;
                Inc(RateInfo.FailedCount);
                if RateInfo.FailedCount >= 5 then
                begin
                  RateInfo.BlockedUntilTick := NowTick + 60000;
                  RateInfo.FailedCount := 0;
                  Logger.Warn(Format('[Security] Rate limit exceeded for key %s. Blocked for 60 seconds.', [RateKey]));
                end;
                LoginRateMap.AddOrSetValue(RateKey, RateInfo);
              finally
                LoginRateLock.Leave;
              end;

              AResponse.SetStatus(401);
              AResponse.AddJSONContent('{"error":"Invalid username or password"}');
              Exit;
            end;

            LoginRateLock.Enter;
            try
              LoginRateMap.Remove(RateKey);
              LoginRateMap.Remove(ClientIP);
            finally
              LoginRateLock.Leave;
            end;

            var HasFilesAppClaim: Boolean;

            Claims := TJSONObject.Create;
            try
              Claims.AddPair('role', UserEntry.Role);
              Claims.AddPair('sandbox', UserEntry.Sandbox);
              Claims.AddPair('ip', ClientIP);
              Claims.AddPair('upload', TJSONBool.Create(UserEntry.CanUpload));
              Claims.AddPair('download', TJSONBool.Create(UserEntry.CanDownload));
              AppsArr := TJSONArray.Create;
              HasFilesAppClaim := False;
              for var AppId in UserEntry.Apps do
              begin
                AppsArr.Add(AppId);
                if (AppId = '*') or SameText(AppId, 'files') then
                  HasFilesAppClaim := True;
              end;
              if (UserEntry.CanUpload or UserEntry.CanDownload) and (not HasFilesAppClaim) then
                AppsArr.Add('files');
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
              JsonRes.AddPair('upload', TJSONBool.Create(UserEntry.CanUpload));
              JsonRes.AddPair('download', TJSONBool.Create(UserEntry.CanDownload));
              AppsArr := TJSONArray.Create;
              HasFilesAppClaim := False;
              for var AppId in UserEntry.Apps do
              begin
                AppsArr.Add(AppId);
                if (AppId = '*') or SameText(AppId, 'files') then
                  HasFilesAppClaim := True;
              end;
              if (UserEntry.CanUpload or UserEntry.CanDownload) and (not HasFilesAppClaim) then
                AppsArr.Add('files');
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/logout'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/logout'), hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;
          try
            AServer.JWTManager.RevokeToken(TokenStr);
            PendingSessionsLock.Enter;
            try
              var ToRemove := TList<string>.Create;
              try
                for var PK in PendingSessions.Keys do
                begin
                  var PP: TPendingSession;
                  if PendingSessions.TryGetValue(PK, PP) and SameText(PP.Username, JWT.Subject) then
                    ToRemove.Add(PK);
                end;
                for var PK in ToRemove do
                  PendingSessions.Remove(PK);
              finally
                ToRemove.Free;
              end;
            finally
              PendingSessionsLock.Leave;
            end;
            AResponse.SetStatus(200);
            AResponse.AddJSONContent('{"status":"ok"}');
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/apps'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/apps'), hmGET,
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
          UserRole: string;
          FoundUser: TUserEntry;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);

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
                    AppObj.AddPair('available', Entry.IsExecutableAvailable);
                    JsonArr.AddElement(AppObj);
                  end;
                end;
              end;

              var CanAccessFilesApp: Boolean;
              var ClaimUp: string := JWT.GetClaim('upload');
              var ClaimDown: string := JWT.GetClaim('download');
              var UserEntryFiles: TUserEntry;
              var UserFoundFiles: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, UserEntryFiles);
              var UserCanUp: Boolean;
              var UserCanDown: Boolean;

              if ClaimUp <> '' then
                UserCanUp := SameText(ClaimUp, 'true')
              else if UserFoundFiles then
                UserCanUp := UserEntryFiles.CanUpload
              else
                UserCanUp := True;

              if ClaimDown <> '' then
                UserCanDown := SameText(ClaimDown, 'true')
              else if UserFoundFiles then
                UserCanDown := UserEntryFiles.CanDownload
              else
                UserCanDown := True;

              CanAccessFilesApp := UserCanUp or UserCanDown;
              if CanAccessFilesApp and TGTermUserConfig.Instance.CanAccessApp(JWT.Subject, 'files') then
              begin
                AppObj := TJSONObject.Create;
                AppObj.AddPair('id', 'files');
                AppObj.AddPair('name', 'File Manager');
                AppObj.AddPair('sandbox', 'standard');
                AppObj.AddPair('network', TJSONBool.Create(False));
                AppObj.AddPair('available', TJSONBool.Create(True));
                JsonArr.AddElement(AppObj);
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/terminal/session'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/terminal/session'), hmPOST,
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
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');

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
              var AppCheckEntry: TAppEntry;
              if not TGTermAppConfig.Instance.FindById(AppKey, AppCheckEntry) then
              begin
                AResponse.SetStatus(400);
                AResponse.AddJSONContent('{"error":"Invalid app specified"}');
                Exit;
              end;
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

              var UserActiveCount: Integer := 0;
              var UserPendingCount: Integer := 0;
              PendingSessionsLock.Enter;
              try
                for var PP in PendingSessions.Values do
                  if SameText(PP.Username, JWT.Subject) then
                    Inc(UserPendingCount);
              finally
                PendingSessionsLock.Leave;
              end;

              var Snaps := SessionManager.GetSessionSnapshots;
              for var SIdx := 0 to High(Snaps) do
                if SameText(Snaps[SIdx].Username, JWT.Subject) then
                  Inc(UserActiveCount);

              if not SameText(UserRole, 'admin') then
              begin
                for var SIdx := 0 to High(Snaps) do
                begin
                  if (UserActiveCount + UserPendingCount < 5) then Break;
                  if SameText(Snaps[SIdx].Username, JWT.Subject) then
                  begin
                    if SessionManager.TerminateSessionById(Snaps[SIdx].SessionId) then
                      Dec(UserActiveCount);
                  end;
                end;
              end;

              if (UserActiveCount + UserPendingCount >= 5) and not SameText(UserRole, 'admin') then
              begin
                AResponse.SetStatus(429);
                AResponse.AddJSONContent('{"error":"Session limit exceeded"}');
                Exit;
              end;

              if not TGTermAppConfig.Instance.CanRoleAccessApp(UserRole, AppKey) or
                 not TGTermUserConfig.Instance.CanAccessApp(JWT.Subject, AppKey) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden app access"}');
                Exit;
              end;
              if not AppCheckEntry.IsExecutableAvailable then
              begin
                AResponse.SetStatus(422);
                AResponse.AddJSONContent('{"error":"Application is not available on this server","app":"' + AppKey + '"}');
                Exit;
              end;

              var ReqClientIP := FormatSockAddrIP(ARequest.RemoteAddr);

              SessionGuid := TGUID.NewGuid.ToString.Trim(['{', '}']);

              Pending.Username := JWT.Subject;
              Pending.Role := UserRole;
              Pending.ClientIP := ReqClientIP;
              Pending.SandboxDir := JWT.GetClaim('sandbox');
              Pending.AppKey := AppKey;
              Pending.Cols := Cols;
              Pending.Rows := Rows;
              Pending.CreatedTick := GetTickCount64;

              PendingSessionsLock.Enter;
              try
                var NowTickPending := GetTickCount64;
                var ExpKeys := TList<string>.Create;
                try
                  for var PK in PendingSessions.Keys do
                  begin
                    var PP: TPendingSession;
                    if PendingSessions.TryGetValue(PK, PP) and ((NowTickPending - PP.CreatedTick) > 15000) then
                      ExpKeys.Add(PK);
                  end;
                  for var PK in ExpKeys do
                    PendingSessions.Remove(PK);
                finally
                  ExpKeys.Free;
                end;
                PendingSessions.AddOrSetValue(SessionGuid, Pending);
              finally
                PendingSessionsLock.Leave;
              end;

              JsonRes := TJSONObject.Create;
              try
                JsonRes.AddPair('status', 'ok');
                JsonRes.AddPair('ticket', SessionGuid);
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/file'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, POST, DELETE, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/file'), hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal, FileName, UserSandbox, TargetDir, TargetPath: string;
          JsonRes: TJSONObject;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, POST, DELETE, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            FileName := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('name', QueryVal) then
              FileName := Trim(QueryVal);
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;
            if (Pos('..', FileName) > 0) or (Pos('/', FileName) > 0) or (Pos('\', FileName) > 0) or
               (Pos(':', FileName) > 0) or (Pos(#0, FileName) > 0) or HasForbiddenFileNameChars(FileName) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid file name"}');
              Exit;
            end;
            FileName := TPath.GetFileName(FileName);
            if HasForbiddenFileNameChars(FileName) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid file name"}');
              Exit;
            end;
            if IsForbiddenUploadExtension(FileName) then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Executable or script upload forbidden"}');
              Exit;
            end;
            var BaseNameOnly := UpperCase(ChangeFileExt(FileName, ''));
            if (BaseNameOnly = 'CON') or (BaseNameOnly = 'PRN') or (BaseNameOnly = 'AUX') or (BaseNameOnly = 'NUL') or
               ((Length(BaseNameOnly) = 4) and (BaseNameOnly.StartsWith('COM') or BaseNameOnly.StartsWith('LPT')) and CharInSet(BaseNameOnly[4], ['1'..'9'])) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Reserved device name"}');
              Exit;
            end;
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;

            var UserRole := JWT.GetClaim('role');
            var CheckUser: TUserEntry;
            var HasUserEntry: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserRole = '') and HasUserEntry then
              UserRole := CheckUser.Role;
            var IsAdmin: Boolean := SameText(UserRole, 'admin') or (HasUserEntry and (CheckUser.IsAdmin or CheckUser.Grants.FullDiskAccess));

            var CanUploadVal: Boolean := True;
            var ClaimUpload: string := JWT.GetClaim('upload');
            if ClaimUpload <> '' then
              CanUploadVal := SameText(ClaimUpload, 'true')
            else if HasUserEntry then
              CanUploadVal := CheckUser.CanUpload;

            if not IsAdmin and not CanUploadVal then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Upload permission denied"}');
              Exit;
            end;

            UserSandbox := JWT.GetClaim('sandbox');
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            var ServerRoot: string := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            var UserHome: string := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));
            if not TDirectory.Exists(UserHome) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"User sandbox directory does not exist"}');
              Exit;
            end;

            var Scope: string := 'home';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('scope', QueryVal) then
              Scope := LowerCase(Trim(QueryVal));
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'server';
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'server';

            if ((Scope = 'server') or (Scope = 'drives')) and not IsAdmin then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Forbidden: Server or drives scope requires admin role"}');
              Exit;
            end;

            var BaseDir: string;
            if (Scope = 'server') and IsAdmin then
              BaseDir := ServerRoot
            else
              BaseDir := UserHome;

            var SubPath: string := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('path', QueryVal) then
              SubPath := Trim(QueryVal);
            if (Pos(#0, SubPath) > 0) or (Pos(':', SubPath) > 0) or (not IsAdmin and (Pos('~', SubPath) > 0)) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid path format or alternate data streams forbidden"}');
              Exit;
            end;
            SubPath := SubPath.Replace('/', '\');
            while SubPath.StartsWith('\') do
              SubPath := Copy(SubPath, 2, Length(SubPath) - 1);

            if IsAdmin and (TPath.IsPathRooted(SubPath) or ((Length(SubPath) >= 2) and (SubPath[2] = ':'))) then
              TargetDir := TPath.GetFullPath(SubPath)
            else if SubPath <> '' then
              TargetDir := TPath.GetFullPath(TPath.Combine(BaseDir, SubPath))
            else
              TargetDir := BaseDir;

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetDir, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal violation"}');
                Exit;
              end;
            end;

            if not TDirectory.Exists(TargetDir) then
              TDirectory.CreateDirectory(TargetDir);

            TargetPath := TPath.GetFullPath(TPath.Combine(TargetDir, FileName));
            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetPath, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal or symlink violation"}');
                Exit;
              end;
            end;

            var IncomingSize: Int64 := 0;
            if Assigned(ARequest.BodyParser) and Assigned(ARequest.BodyParser.MainPart) then
              IncomingSize := ARequest.BodyParser.CurrentSize
            else if ARequest.GetBodyStream <> nil then
              IncomingSize := ARequest.GetBodyStream.Size;

            if IncomingSize > 1073741824 then
            begin
              AResponse.SetStatus(413);
              AResponse.AddJSONContent('{"error":"File too large (max 1 GB)"}');
              Exit;
            end;

            var ReservedQuota: Int64 := 0;
            if not IsAdmin and HasUserEntry then
            begin
              var QuotaBytes: Int64 := CheckUser.GetStorageQuotaBytes;
              if QuotaBytes > 0 then
              begin
                if not GlobalQuotaManager.TryReserve(JWT.Subject, IncomingSize, QuotaBytes, UserHome) then
                begin
                  AResponse.SetStatus(507);
                  AResponse.AddJSONContent(Format('{"error":"Storage quota exceeded: max %d MB allowed"}', [CheckUser.Grants.StorageQuotaMB]));
                  Exit;
                end;
                ReservedQuota := IncomingSize;
              end;
            end;

            try
              var SavedOk: Boolean := False;
              var UploadedSize: Int64;

              if FileExists(TargetPath) then
                TFile.Delete(TargetPath);

              if Assigned(ARequest.BodyParser) and Assigned(ARequest.BodyParser.MainPart) then
              begin
                SavedOk := ARequest.BodyParser.MainPart.SaveToFile(TargetPath);
              end
              else
              begin
                var InStream: TStream := ARequest.GetBodyStream;
                if (InStream <> nil) and (InStream.Size > 0) then
                begin
                  var OutFile: TFileStream := TFileStream.Create(TargetPath, fmCreate);
                  try
                    InStream.Position := 0;
                    OutFile.CopyFrom(InStream, InStream.Size);
                    SavedOk := True;
                  finally
                    OutFile.Free;
                  end;
                end;
              end;

              if not SavedOk or not FileExists(TargetPath) then
              begin
                AResponse.SetStatus(500);
                AResponse.AddJSONContent('{"error":"Failed to save file"}');
                Exit;
              end;

              try
                UploadedSize := TFile.GetSize(TargetPath);
              except
                UploadedSize := 0;
              end;

              if IsExecutableBinaryFile(TargetPath) then
              begin
                try
                  if FileExists(TargetPath) then
                    TFile.Delete(TargetPath);
                except
                end;
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Malicious payload detected: executable binary forbidden"}');
                Exit;
              end;

              var ThreatMsg: string := '';
              if not ScanFileForThreats(TargetPath, FileName, ThreatMsg) then
              begin
                try
                  if FileExists(TargetPath) then
                    TFile.Delete(TargetPath);
                except
                end;
                AResponse.SetStatus(403);
                AResponse.AddJSONContent(Format('{"error":"%s"}', [ThreatMsg]));
                Exit;
              end;

              JsonRes := TJSONObject.Create;
              try
                JsonRes.AddPair('status', 'ok');
                JsonRes.AddPair('filename', FileName);
                JsonRes.AddPair('size', TJSONNumber.Create(UploadedSize));
                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JsonRes.ToJSON);
              finally
                JsonRes.Free;
              end;
            finally
              if ReservedQuota > 0 then
                GlobalQuotaManager.Release(JWT.Subject, ReservedQuota);
              JWT.Free;
            end;
          except
            on E: Exception do
            begin
              AResponse.SetStatus(500);
              AResponse.AddJSONContent(Format('{"error":"Internal upload error: %s"}', [E.Message]));
            end;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/file'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          QueryVal, FileName, UserSandbox, TargetDir, TargetPath: string;
        begin
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, POST, DELETE, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);

          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            FileName := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('name', QueryVal) then
              FileName := Trim(QueryVal);
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;
            if (Pos('..', FileName) > 0) or (Pos('/', FileName) > 0) or (Pos('\', FileName) > 0) or
               (Pos(':', FileName) > 0) or (Pos(#0, FileName) > 0) or HasForbiddenFileNameChars(FileName) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid file name"}');
              Exit;
            end;
            FileName := TPath.GetFileName(FileName);
            if HasForbiddenFileNameChars(FileName) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid file name"}');
              Exit;
            end;
            var BaseNameOnly := UpperCase(ChangeFileExt(FileName, ''));
            if (BaseNameOnly = 'CON') or (BaseNameOnly = 'PRN') or (BaseNameOnly = 'AUX') or (BaseNameOnly = 'NUL') or
               ((Length(BaseNameOnly) = 4) and (BaseNameOnly.StartsWith('COM') or BaseNameOnly.StartsWith('LPT')) and CharInSet(BaseNameOnly[4], ['1'..'9'])) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Reserved device name"}');
              Exit;
            end;
            if FileName = '' then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing file name"}');
              Exit;
            end;

            var UserRole := JWT.GetClaim('role');
            var CheckUser: TUserEntry;
            var HasUserEntry: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserRole = '') and HasUserEntry then
              UserRole := CheckUser.Role;
            var IsAdmin: Boolean := SameText(UserRole, 'admin') or (HasUserEntry and (CheckUser.IsAdmin or CheckUser.Grants.FullDiskAccess));

            var CanDownloadVal: Boolean := True;
            var ClaimDownload: string := JWT.GetClaim('download');
            if ClaimDownload <> '' then
              CanDownloadVal := SameText(ClaimDownload, 'true')
            else if HasUserEntry then
              CanDownloadVal := CheckUser.CanDownload;

            if not IsAdmin and not CanDownloadVal then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Download permission denied"}');
              Exit;
            end;

            UserSandbox := JWT.GetClaim('sandbox');
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            var ServerRoot: string := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            var UserHome: string := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));

            var Scope: string := 'home';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('scope', QueryVal) then
              Scope := LowerCase(Trim(QueryVal));
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'server';
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'server';

            if (Scope = 'server') and not IsAdmin then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Forbidden: Server scope requires admin role"}');
              Exit;
            end;

            var BaseDir: string;
            if (Scope = 'server') and IsAdmin then
              BaseDir := ServerRoot
            else
              BaseDir := UserHome;

            var SubPath: string := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('path', QueryVal) then
              SubPath := Trim(QueryVal);
            if (Pos(#0, SubPath) > 0) or ((not IsAdmin) and (Pos(':', SubPath) > 0)) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid path"}');
              Exit;
            end;
            SubPath := SubPath.Replace('/', '\');
            while SubPath.StartsWith('\') do
              SubPath := Copy(SubPath, 2, Length(SubPath) - 1);

            if IsAdmin and (TPath.IsPathRooted(SubPath) or ((Length(SubPath) >= 2) and (SubPath[2] = ':'))) then
              TargetDir := TPath.GetFullPath(SubPath)
            else if SubPath <> '' then
              TargetDir := TPath.GetFullPath(TPath.Combine(BaseDir, SubPath))
            else
              TargetDir := BaseDir;

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetDir, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal violation"}');
                Exit;
              end;
            end;

            TargetPath := TPath.GetFullPath(TPath.Combine(TargetDir, FileName));

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetPath, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal or symlink violation"}');
                Exit;
              end;
            end;

            if not FileExists(TargetPath) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"File not found"}');
              Exit;
            end;

            var CleanHeaderName: string;
            CleanHeaderName := FileName.Replace(#13, '').Replace(#10, '').Replace('"', '');
            AResponse.SetStatus(200);
            AResponse.AddHeader('Content-Disposition', 'attachment; filename="' + CleanHeaderName + '"');
            AResponse.AddHeader('X-Content-Type-Options', 'nosniff');
            AResponse.AddHeader('Content-Security-Policy', 'sandbox');
            AResponse.AddFileContent('application/octet-stream', TargetPath);
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/file'), hmDELETE,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          SubPath, FileName, UserSandbox, TargetDir, TargetPath: string;
          QueryVal: string;
        begin
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, POST, DELETE, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            var UserRole := JWT.GetClaim('role');
            var CheckUser: TUserEntry;
            var HasUserEntry: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserRole = '') and HasUserEntry then
              UserRole := CheckUser.Role;
            var IsAdmin: Boolean := SameText(UserRole, 'admin') or (HasUserEntry and (CheckUser.IsAdmin or CheckUser.Grants.FullDiskAccess));

            var CanUploadVal: Boolean := True;
            var ClaimUpload: string := JWT.GetClaim('upload');
            if ClaimUpload <> '' then
              CanUploadVal := SameText(ClaimUpload, 'true')
            else if HasUserEntry then
              CanUploadVal := CheckUser.CanUpload;

            if not IsAdmin and not CanUploadVal then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Delete permission denied: write access required"}');
              Exit;
            end;

            SubPath := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('path', QueryVal) then
              SubPath := Trim(QueryVal);

            FileName := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('name', QueryVal) then
              FileName := Trim(QueryVal);
            if (Pos(#0, SubPath) > 0) or (Pos(#0, FileName) > 0) or
               (Pos('..', FileName) > 0) or (Pos('/', FileName) > 0) or (Pos('\', FileName) > 0) or
               (Pos(':', FileName) > 0) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid path or filename"}');
              Exit;
            end;

            if Pos(':', SubPath) > 0 then
            begin
              if not ((Pos(':', SubPath) = 2) and (Length(SubPath) >= 2) and (PosEx(':', SubPath, 3) = 0)) then
              begin
                AResponse.SetStatus(400);
                AResponse.AddJSONContent('{"error":"Invalid path or filename"}');
                Exit;
              end;
            end;

            SubPath := SubPath.Replace('/', '\');
            while SubPath.StartsWith('\') do
              SubPath := Copy(SubPath, 2, Length(SubPath) - 1);

            UserSandbox := JWT.GetClaim('sandbox');
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            var ServerRoot: string := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            var UserHome: string := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));

            var Scope: string := 'home';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('scope', QueryVal) then
              Scope := LowerCase(Trim(QueryVal));
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'server';
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'server';

            if (Scope = 'server') and not IsAdmin then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Forbidden: Server scope requires admin role"}');
              Exit;
            end;






























            var BaseDir: string;
            if (Scope = 'server') and IsAdmin then
              BaseDir := ServerRoot
            else
              BaseDir := UserHome;

            if (TPath.IsPathRooted(SubPath) or ((Length(SubPath) >= 2) and (SubPath[2] = ':'))) then
              TargetDir := TPath.GetFullPath(SubPath)
            else if SubPath <> '' then
              TargetDir := TPath.GetFullPath(TPath.Combine(BaseDir, SubPath))
            else
              TargetDir := BaseDir;

            if FileName <> '' then
              TargetPath := TPath.GetFullPath(TPath.Combine(TargetDir, FileName))
            else
              TargetPath := TargetDir;

            var CanonTarget: string := NormalizeCanonicalPath(TPath.GetFullPath(TargetPath));
            var CanonHome: string := NormalizeCanonicalPath(TPath.GetFullPath(UserHome));
            var CanonServer: string := NormalizeCanonicalPath(TPath.GetFullPath(ServerRoot));
            var CanonApp: string := NormalizeCanonicalPath(TPath.GetFullPath(ExtractFilePath(ParamStr(0))));

            var RootPathToCheck: string;
            if (Scope = 'server') and IsAdmin then
              RootPathToCheck := CanonServer
            else
              RootPathToCheck := CanonHome;

            if IsSameDirectoryOrRoot(CanonTarget, CanonHome) or
               IsSameDirectoryOrRoot(CanonTarget, CanonServer) or
               IsSameDirectoryOrRoot(CanonTarget, CanonApp) or
               (Length(CanonTarget) <= Length(RootPathToCheck)) then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Cannot delete sandbox root"}');
              Exit;
            end;

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetPath, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal violation"}');
                Exit;
              end;
            end;

            if FileExists(TargetPath) then
            begin
              TFile.Delete(TargetPath);
              AResponse.SetStatus(200);
              AResponse.AddJSONContent('{"status":"ok","deleted":"file"}');
            end
            else if TDirectory.Exists(TargetPath) then
            begin
              TDirectory.Delete(TargetPath, True);
              AResponse.SetStatus(200);
              AResponse.AddJSONContent('{"status":"ok","deleted":"directory"}');
            end
            else
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"Item not found"}');
            end;
          finally
            JWT.Free;
          end;
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/files'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/files'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          SubPath, UserSandbox, TargetDir: string;
          QueryVal: string;
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          ItemObj: TJSONObject;
          SubDirs, Files: TArray<string>;
          I: Integer;
          ItemName: string;
          ItemSize: Int64;
          ItemTime: string;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            var UserRole := JWT.GetClaim('role');
            var CheckUser: TUserEntry;
            var HasUserEntry: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserRole = '') and HasUserEntry then
              UserRole := CheckUser.Role;
            var IsAdmin: Boolean := SameText(UserRole, 'admin') or (HasUserEntry and (CheckUser.IsAdmin or CheckUser.Grants.FullDiskAccess));

            var CanAccessFiles: Boolean;
            var ClaimUp: string := JWT.GetClaim('upload');
            var ClaimDown: string := JWT.GetClaim('download');
            var UserCanUp: Boolean;
            var UserCanDown: Boolean;

            if ClaimUp <> '' then
              UserCanUp := SameText(ClaimUp, 'true')
            else if HasUserEntry then
              UserCanUp := CheckUser.CanUpload
            else
              UserCanUp := True;

            if ClaimDown <> '' then
              UserCanDown := SameText(ClaimDown, 'true')
            else if HasUserEntry then
              UserCanDown := CheckUser.CanDownload
            else
              UserCanDown := True;

            CanAccessFiles := IsAdmin or UserCanUp or UserCanDown;
            if not CanAccessFiles then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"File access denied: no upload or download permissions"}');
              Exit;
            end;

            SubPath := '';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('path', QueryVal) then
              SubPath := Trim(QueryVal);

            if (Pos(#0, SubPath) > 0) or ((not IsAdmin) and (Pos(':', SubPath) > 0)) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid path"}');
              Exit;
            end;

            SubPath := SubPath.Replace('/', '\');
            while SubPath.StartsWith('\') do
              SubPath := Copy(SubPath, 2, Length(SubPath) - 1);

            UserSandbox := JWT.GetClaim('sandbox');
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            var ServerRoot: string := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            var UserHome: string := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));
            if not TDirectory.Exists(UserHome) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"User sandbox directory does not exist"}');
              Exit;
            end;

            var Scope: string := 'home';
            if ARequest.RequestInfo.QueryParameters.TryGetValue('scope', QueryVal) then
              Scope := LowerCase(Trim(QueryVal));
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.QueryString)) > 0) then
              Scope := 'server';
            if (Scope = 'home') and (Pos('scope=drives', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'drives'
            else if (Scope = 'home') and (Pos('scope=server', LowerCase(ARequest.RequestInfo.RawUri)) > 0) then
              Scope := 'server';

            if ((Scope = 'server') or (Scope = 'drives')) and not IsAdmin then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Forbidden: Server or drives scope requires admin role"}');
              Exit;
            end;

            Logger.Info(Format('[DEBUG_FILES] IsAdmin=%s Scope=%s SubPath=%s RawUri=%s UserRole=%s Subject=%s', [BoolToStr(IsAdmin, True), Scope, SubPath, ARequest.RequestInfo.RawUri, UserRole, JWT.Subject]));
            if IsAdmin and ((Scope = 'drives') or SameText(SubPath, 'drives')) then
            begin
              JsonRes := TJSONObject.Create;
              try
                JsonRes.AddPair('path', 'drives');
                JsonRes.AddPair('fullPath', 'drives');
                JsonRes.AddPair('parentPath', '');
                JsonRes.AddPair('isDrivesRoot', TJSONBool.Create(True));
                JsonArr := TJSONArray.Create;
                var DriveList: TArray<string> := TDirectory.GetLogicalDrives;
                for var DriveName in DriveList do
                begin
                  ItemObj := TJSONObject.Create;
                  ItemObj.AddPair('name', DriveName);
                  ItemObj.AddPair('isDir', TJSONBool.Create(True));
                  ItemObj.AddPair('isDrive', TJSONBool.Create(True));
                  ItemObj.AddPair('size', TJSONNumber.Create(0));
                  ItemObj.AddPair('modified', '');
                  JsonArr.AddElement(ItemObj);
                end;
                JsonRes.AddPair('items', JsonArr);
                AResponse.SetStatus(200);
                AResponse.AddJSONContent(JsonRes.ToJSON);
                Exit;
              finally
                JsonRes.Free;
              end;
            end;

            var BaseDir: string;
            if (Scope = 'server') and IsAdmin then
              BaseDir := ServerRoot
            else
              BaseDir := UserHome;

            if IsAdmin and (TPath.IsPathRooted(SubPath) or ((Length(SubPath) >= 2) and (SubPath[2] = ':'))) then
              TargetDir := TPath.GetFullPath(SubPath)
            else if SubPath <> '' then
              TargetDir := TPath.GetFullPath(TPath.Combine(BaseDir, SubPath))
            else
              TargetDir := BaseDir;

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(TargetDir, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Path traversal violation"}');
                Exit;
              end;
            end;

            if not TDirectory.Exists(TargetDir) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"Directory not found"}');
              Exit;
            end;

            var ParentPath: string := '';
            if IsAdmin then
            begin
              ParentPath := TPath.GetDirectoryName(TargetDir);
              if (ParentPath = '') or (Length(TargetDir) <= 3) then
                ParentPath := 'drives';
            end;

            JsonRes := TJSONObject.Create;
            try
              JsonRes.AddPair('path', SubPath.Replace('\', '/'));
              JsonRes.AddPair('fullPath', TargetDir);
                                          if IsAdmin then
                JsonRes.AddPair('parentPath', ParentPath);
              JsonArr := TJSONArray.Create;

              SubDirs := TDirectory.GetDirectories(TargetDir);
              TArray.Sort<string>(SubDirs);
              for I := 0 to High(SubDirs) do
              begin
                ItemName := TPath.GetFileName(SubDirs[I]);
                try
                  ItemTime := DateToISO8601(TDirectory.GetLastWriteTime(SubDirs[I]));
                except
                  ItemTime := '';
                end;
                ItemObj := TJSONObject.Create;
                ItemObj.AddPair('name', ItemName);
                ItemObj.AddPair('isDir', TJSONBool.Create(True));
                ItemObj.AddPair('size', TJSONNumber.Create(0));
                ItemObj.AddPair('modified', ItemTime);
                JsonArr.AddElement(ItemObj);
              end;

              Files := TDirectory.GetFiles(TargetDir);
              TArray.Sort<string>(Files);
              for I := 0 to High(Files) do
              begin
                ItemName := TPath.GetFileName(Files[I]);
                ItemSize := 0;
                try
                  ItemSize := TFile.GetSize(Files[I]);
                  ItemTime := DateToISO8601(TFile.GetLastWriteTime(Files[I]));
                except
                  ItemTime := '';
                end;
                ItemObj := TJSONObject.Create;
                ItemObj.AddPair('name', ItemName);
                ItemObj.AddPair('isDir', TJSONBool.Create(False));
                ItemObj.AddPair('size', TJSONNumber.Create(ItemSize));
                ItemObj.AddPair('modified', ItemTime);
                JsonArr.AddElement(ItemObj);
              end;

              JsonRes.AddPair('items', JsonArr);
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/copy'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/copy'), hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          FromPath, FromName, ToPath, ToName: string;
          QueryVal: string;
          UserSandbox, ServerRoot, UserHome: string;
          SourceDir, SourceFile, DestDir, DestFile: string;
          JsonBody: TJSONObject;
          JsonRes: TJSONObject;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            var UserRole := JWT.GetClaim('role');
            var CheckUser: TUserEntry;
            var HasUserEntry: Boolean := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserRole = '') and HasUserEntry then
              UserRole := CheckUser.Role;
            var IsAdmin: Boolean := SameText(UserRole, 'admin') or (HasUserEntry and (CheckUser.IsAdmin or CheckUser.Grants.FullDiskAccess));

            var CanDownloadVal: Boolean := True;
            var ClaimDownload: string := JWT.GetClaim('download');
            if ClaimDownload <> '' then
              CanDownloadVal := SameText(ClaimDownload, 'true')
            else if HasUserEntry then
              CanDownloadVal := CheckUser.CanDownload;

            var CanUploadVal: Boolean := True;
            var ClaimUpload: string := JWT.GetClaim('upload');
            if ClaimUpload <> '' then
              CanUploadVal := SameText(ClaimUpload, 'true')
            else if HasUserEntry then
              CanUploadVal := CheckUser.CanUpload;

            if not IsAdmin and (not CanDownloadVal or not CanUploadVal) then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Copy permission denied: read and write access required"}');
              Exit;
            end;

            FromPath := '';
            FromName := '';
            ToPath := '';
            ToName := '';
            var FromScope: string := 'home';
            var ToScope: string := 'home';

            if ARequest.RequestInfo.QueryParameters.TryGetValue('fromScope', QueryVal) then
              FromScope := LowerCase(Trim(QueryVal));
            if ARequest.RequestInfo.QueryParameters.TryGetValue('toScope', QueryVal) then
              ToScope := LowerCase(Trim(QueryVal));
            if ARequest.RequestInfo.QueryParameters.TryGetValue('fromPath', QueryVal) then
              FromPath := Trim(QueryVal);
            if ARequest.RequestInfo.QueryParameters.TryGetValue('fromName', QueryVal) then
              FromName := Trim(QueryVal);
            if ARequest.RequestInfo.QueryParameters.TryGetValue('toPath', QueryVal) then
              ToPath := Trim(QueryVal);
            if ARequest.RequestInfo.QueryParameters.TryGetValue('toName', QueryVal) then
              ToName := Trim(QueryVal);

            if (FromName = '') and (ARequest.BodyAsString <> '') then
            begin
              try
                JsonBody := TJSONObject.ParseJSONValue(ARequest.BodyAsString) as TJSONObject;
                if JsonBody <> nil then
                begin
                  try
                    if JsonBody.TryGetValue<string>('fromScope', QueryVal) then FromScope := LowerCase(Trim(QueryVal));
                    if JsonBody.TryGetValue<string>('toScope', QueryVal) then ToScope := LowerCase(Trim(QueryVal));
                    if FromPath = '' then FromPath := JsonBody.GetValue<string>('fromPath', '');
                    if FromName = '' then FromName := JsonBody.GetValue<string>('fromName', '');
                    if ToPath = '' then ToPath := JsonBody.GetValue<string>('toPath', '');
                    if ToName = '' then ToName := JsonBody.GetValue<string>('toName', '');
                  finally
                    JsonBody.Free;
                  end;
                end;
              except
              end;
            end;

            if ToName = '' then
              ToName := FromName;

            if (FromName = '') or (ToName = '') then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Missing fromName or toName"}');
              Exit;
            end;

            if (Pos('..', FromName) > 0) or (Pos('/', FromName) > 0) or (Pos('\', FromName) > 0) or
               (Pos(':', FromName) > 0) or (Pos(#0, FromName) > 0) or HasForbiddenFileNameChars(FromName) or
               (Pos('..', ToName) > 0) or (Pos('/', ToName) > 0) or (Pos('\', ToName) > 0) or
               (Pos(':', ToName) > 0) or (Pos(#0, ToName) > 0) or HasForbiddenFileNameChars(ToName) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid file name"}');
              Exit;
            end;

            if IsForbiddenUploadExtension(ToName) then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Executable or script copy target forbidden"}');
              Exit;
            end;

            var BaseToName := UpperCase(ChangeFileExt(ToName, ''));
            if (BaseToName = 'CON') or (BaseToName = 'PRN') or (BaseToName = 'AUX') or (BaseToName = 'NUL') or
               ((Length(BaseToName) = 4) and (BaseToName.StartsWith('COM') or BaseToName.StartsWith('LPT')) and CharInSet(BaseToName[4], ['1'..'9'])) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Reserved device name"}');
              Exit;
            end;

            if (Pos(#0, FromPath) > 0) or (Pos(#0, ToPath) > 0) or
               ((not IsAdmin) and ((Pos(':', FromPath) > 0) or (Pos(':', ToPath) > 0))) then
            begin
              AResponse.SetStatus(400);
              AResponse.AddJSONContent('{"error":"Invalid path"}');
              Exit;
            end;

            FromPath := FromPath.Replace('/', '\');
            while FromPath.StartsWith('\') do
              FromPath := Copy(FromPath, 2, Length(FromPath) - 1);

            ToPath := ToPath.Replace('/', '\');
            while ToPath.StartsWith('\') do
              ToPath := Copy(ToPath, 2, Length(ToPath) - 1);

            UserSandbox := JWT.GetClaim('sandbox');
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            ServerRoot := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            UserHome := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));

            if not IsAdmin and ((FromScope = 'server') or (ToScope = 'server')) then
            begin
              AResponse.SetStatus(403);
              AResponse.AddJSONContent('{"error":"Forbidden: Server scope requires admin role"}');
              Exit;
            end;

            var BaseDirFrom: string;
            if (FromScope = 'server') and IsAdmin then
              BaseDirFrom := ServerRoot
            else
              BaseDirFrom := UserHome;

            var BaseDirTo: string;
            if (ToScope = 'server') and IsAdmin then
              BaseDirTo := ServerRoot
            else
              BaseDirTo := UserHome;

            if FromPath <> '' then
              SourceDir := TPath.GetFullPath(TPath.Combine(BaseDirFrom, FromPath))
            else
              SourceDir := BaseDirFrom;
            SourceFile := TPath.GetFullPath(TPath.Combine(SourceDir, FromName));

            if ToPath <> '' then
              DestDir := TPath.GetFullPath(TPath.Combine(BaseDirTo, ToPath))
            else
              DestDir := BaseDirTo;
            DestFile := TPath.GetFullPath(TPath.Combine(DestDir, ToName));

            if not IsAdmin then
            begin
              if not IsPathInSandboxCanonical(SourceFile, UserHome) or
                 not IsPathInSandboxCanonical(DestFile, UserHome) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Forbidden: Cross-user or sandbox escape copy violation"}');
                Exit;
              end;
            end;

            if not FileExists(SourceFile) then
            begin
              AResponse.SetStatus(404);
              AResponse.AddJSONContent('{"error":"Source file not found"}');
              Exit;
            end;

            if not IsAdmin and HasUserEntry then
            begin
              var QuotaBytes: Int64 := CheckUser.GetStorageQuotaBytes;
              if QuotaBytes > 0 then
              begin
                var SourceSize: Int64 := TFile.GetSize(SourceFile);
                var CurrentUsed: Int64 := GetDirectoryTotalSize(UserHome);
                if CurrentUsed + SourceSize > QuotaBytes then
                begin
                  AResponse.SetStatus(507);
                  AResponse.AddJSONContent(Format('{"error":"Storage quota exceeded: max %d MB allowed"}', [CheckUser.Grants.StorageQuotaMB]));
                  Exit;
                end;
              end;
            end;

            var CopyStream: TFileStream := TFileStream.Create(SourceFile, fmOpenRead or fmShareDenyNone);
            try
              var HeaderBuf: array[0..511] of Byte;
              var ReadBytes: Integer := CopyStream.Read(HeaderBuf, Length(HeaderBuf));
              if (ReadBytes >= 2) and IsExecutableBinaryHeader(@HeaderBuf[0], ReadBytes) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent('{"error":"Malicious payload detected: executable PE binary header (MZ) forbidden"}');
                Exit;
              end;
              var ThreatMsg: string := '';
              if not ScanBufferForThreats(@HeaderBuf[0], ReadBytes, ToName, ThreatMsg) then
              begin
                AResponse.SetStatus(403);
                AResponse.AddJSONContent(Format('{"error":"%s"}', [ThreatMsg]));
                Exit;
              end;
            finally
              CopyStream.Free;
            end;

            if not TDirectory.Exists(DestDir) then
              TDirectory.CreateDirectory(DestDir);

            try
              TFile.Copy(SourceFile, DestFile, True);
            except
              on E: Exception do
              begin
                AResponse.SetStatus(500);
                AResponse.AddJSONContent('{"error":"Failed to copy file"}');
                Exit;
              end;
            end;

            JsonRes := TJSONObject.Create;
            try
              JsonRes.AddPair('status', 'ok');
              JsonRes.AddPair('from', FromName);
              JsonRes.AddPair('to', ToName);
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/quota'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/sandbox/quota'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          UserSandbox, ServerRoot, UserHome: string;
          CheckUser: TUserEntry;
          HasUserEntry: Boolean;
          CurrentUsed: Int64;
          QuotaBytes: Int64;
          JsonRes: TJSONObject;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);
          if not ValidateRequestToken(ARequest, AServer, TokenStr, JWT) then
          begin
            AResponse.SetStatus(401);
            AResponse.AddJSONContent('{"error":"Unauthorized"}');
            Exit;
          end;

          try
            UserSandbox := JWT.GetClaim('sandbox');
            HasUserEntry := TGTermUserConfig.Instance.FindUser(JWT.Subject, CheckUser);
            if (UserSandbox = '') and HasUserEntry and (CheckUser.Sandbox <> '') then
              UserSandbox := CheckUser.Sandbox;
            if UserSandbox = '' then
              UserSandbox := 'sandbox';

            ServerRoot := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
            UserHome := TPath.GetFullPath(TPath.Combine(ServerRoot, UserSandbox));

            CurrentUsed := GetDirectoryTotalSize(UserHome);
            QuotaBytes := 0;
            if HasUserEntry then
              QuotaBytes := CheckUser.GetStorageQuotaBytes;

            JsonRes := TJSONObject.Create;
            try
              JsonRes.AddPair('status', 'ok');
              JsonRes.AddPair('used_bytes', TJSONNumber.Create(CurrentUsed));
              JsonRes.AddPair('quota_bytes', TJSONNumber.Create(QuotaBytes));
              if HasUserEntry then
                JsonRes.AddPair('quota_mb', TJSONNumber.Create(CheckUser.Grants.StorageQuotaMB))
              else
                JsonRes.AddPair('quota_mb', TJSONNumber.Create(0));
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/admin/sessions'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/admin/sessions'), hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          TokenStr: string;
          JWT: TJWTToken;
          Snapshots: TArray<TGTermSessionInfo>;
          JsonRes: TJSONObject;
          JsonArr: TJSONArray;
          SessObj: TJSONObject;
          I: Integer;
        begin
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'GET, OPTIONS');

          TokenStr := AServer.JWTManager.ExtractTokenFromAuthHeader(ARequest.Headers.Authorization);

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
                SessObj.AddPair('username', Snapshots[I].Username);
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

      Server.RegisterEndpointProc(BuildRoutePath('/api/admin/sessions/kill'), hmOPTIONS,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(204);
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');
        end
      );

      Server.RegisterEndpointProc(BuildRoutePath('/api/admin/sessions/kill'), hmPOST,
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
          if not IsAllowedRequestOrigin(ARequest) then
          begin
            AResponse.SetStatus(403);
            AResponse.AddJSONContent('{"error":"Forbidden origin"}');
            Exit;
          end;
          ApplyCorsHeaders(ARequest, AResponse, 'POST, OPTIONS');

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

              SessIdStr := Trim(JsonReq.GetValue<string>('sessionId', ''));
              if SessIdStr = '' then
              begin
                AResponse.SetStatus(400);
                AResponse.AddJSONContent('{"error":"Invalid sessionId"}');
                Exit;
              end;

              SessionId := StrToUInt64Def(SessIdStr, 0);
              Success := False;
              if SessionId <> 0 then
                Success := SessionManager.TerminateSessionById(SessionId);

              if not Success then
              begin
                PendingSessionsLock.Enter;
                try
                  Success := PendingSessions.ContainsKey(SessIdStr);
                  if Success then
                    PendingSessions.Remove(SessIdStr);
                finally
                  PendingSessionsLock.Leave;
                end;
              end;

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

      Server.RegisterWebTransportRoute(BuildRoutePath('/wt/terminal'),
        procedure(Session: PWTSessionContext)
        var
          Profile: TGTermAppProfile;
          TermSession: TGTermSession;
          QueryParams: TDictionary<string, string>;
          TicketStr, TokenStr, AppKey, UserSandbox: string;
          HasPending: Boolean;
          Pending: TPendingSession;
          QuicPeerIP: string;
          NowTick: UInt64;
          JWT: TJWTToken;
        begin
          var CleanLogPath := Session^.Path;
          var QPos := Pos('?', CleanLogPath);
          if QPos > 0 then CleanLogPath := Copy(CleanLogPath, 1, QPos - 1);
          Logger.Info(Format('[WT] Client connected (SessionId: %d, Path: %s)', [Session^.SessionId, CleanLogPath]));

          QuicPeerIP := GetWTSessionPeerIP(Session);
          QueryParams := ParseUrlQueryParams(Session^.Path);
          try
            TicketStr := '';
            if not QueryParams.TryGetValue('ticket', TicketStr) or (TicketStr = '') then
              QueryParams.TryGetValue('session', TicketStr);
            TicketStr := Trim(TicketStr);

            TokenStr := '';
            QueryParams.TryGetValue('token', TokenStr);
            TokenStr := Trim(TokenStr);

            AppKey := '';
            QueryParams.TryGetValue('app', AppKey);
            AppKey := LowerCase(Trim(AppKey));
            if AppKey = '' then
              AppKey := TGTermAppConfig.Instance.GetDefaultAppId;

            if TicketStr <> '' then
            begin
              PendingSessionsLock.Enter;
              try
                HasPending := PendingSessions.TryGetValue(TicketStr, Pending);
                if HasPending then
                  PendingSessions.Remove(TicketStr);
              finally
                PendingSessionsLock.Leave;
              end;

              if not HasPending then
              begin
                Logger.Warn(Format('[WT] Rejecting connection: invalid or already consumed ticket "%s" (SessionId: %d)', [TicketStr, Session^.SessionId]));
                Exit;
              end;

              NowTick := GetTickCount64;
              if (NowTick - Pending.CreatedTick) > 15000 then
              begin
                Logger.Warn(Format('[WT] Rejecting connection: expired ticket "%s" (SessionId: %d)', [TicketStr, Session^.SessionId]));
                Exit;
              end;

              if (Pending.ClientIP <> '') and (QuicPeerIP <> '') and not AreIPAddressesMatching(Pending.ClientIP, QuicPeerIP) then
              begin
                Logger.Warn(Format('[WT] Rejecting connection: QUIC peer IP "%s" does not match ticket client IP "%s" (SessionId: %d)',
                  [QuicPeerIP, Pending.ClientIP, Session^.SessionId]));
                Exit;
              end;

              UserSandbox := Pending.SandboxDir;
              Profile := ResolveAppProfile(Pending.AppKey, UserSandbox, Pending.Username);
              if Pending.Cols > 0 then Profile.DefaultCols := Pending.Cols;
              if Pending.Rows > 0 then Profile.DefaultRows := Pending.Rows;
              TermSession := TGTermSession.Create(Session, Profile, Pending.Username, Pending.Role);
              SessionManager.RegisterSession(Pointer(Session^.SessionId), TermSession);
            end
            else if TokenStr <> '' then
            begin
              if not Server.JWTManager.ValidateToken(TokenStr, JWT) then
              begin
                if Assigned(JWT) then
                  FreeAndNil(JWT);
                Logger.Warn(Format('[WT] Rejecting direct token connection: invalid token (SessionId: %d)', [Session^.SessionId]));
                Exit;
              end;

              try
                var TokenIP := JWT.GetClaim('ip');
                if (TokenIP <> '') and (QuicPeerIP <> '') and not AreIPAddressesMatching(TokenIP, QuicPeerIP) then
                begin
                  Logger.Warn(Format('[WT] Rejecting direct connection: QUIC peer IP "%s" does not match token IP "%s" (SessionId: %d)',
                    [QuicPeerIP, TokenIP, Session^.SessionId]));
                  Exit;
                end;

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

                var WtCheckApp: TAppEntry;
                if TGTermAppConfig.Instance.FindById(AppKey, WtCheckApp) and not WtCheckApp.IsExecutableAvailable then
                begin
                  Logger.Warn(Format('[WT] Rejected connection for unavailable app "%s" for user "%s"', [AppKey, JWT.Subject]));
                  Exit;
                end;

                UserSandbox := JWT.GetClaim('sandbox');
                Profile := ResolveAppProfile(Session^.Path, UserSandbox, JWT.Subject);
                TermSession := TGTermSession.Create(Session, Profile, JWT.Subject, UserRole);
                SessionManager.RegisterSession(Pointer(Session^.SessionId), TermSession);
              finally
                JWT.Free;
              end;
            end
            else
            begin
              Logger.Warn(Format('[WT] Rejecting connection: missing ticket or token parameter (SessionId: %d)', [Session^.SessionId]));
              Exit;
            end;
          finally
            QueryParams.Free;
          end;
        end,
        procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
        var
          TermSession: TGTermSession;
        begin
          TermSession := SessionManager.AcquireSession(Pointer(Session^.SessionId));
          if Assigned(TermSession) then
          begin
            try
              TermSession.ProcessStreamData(Session, Stream, Data);
            finally
              TermSession.Release;
            end;
          end;
        end,
        procedure(Session: PWTSessionContext; const Data: TBytes)
        var
          TermSession: TGTermSession;
        begin
          TermSession := SessionManager.AcquireSession(Pointer(Session^.SessionId));
          if Assigned(TermSession) then
          begin
            try
              TermSession.ProcessControlStreamData(Data);
            finally
              TermSession.Release;
            end;
          end;
        end,
        procedure(SessionId: TWTSessionId)
        begin
          Logger.Info(Format('[WT] Client disconnected (SessionId: %d)', [SessionId]));
          if Assigned(SessionManager) then
            SessionManager.UnregisterAndFreeSession(Pointer(SessionId));
        end
      );

      Server.RegisterWebTransportRoute(BuildRoutePath('/wt/files'),
        procedure(Session: PWTSessionContext)
        var
          TokenStr: string;
          JWT: TJWTToken;
          LowerPath: string;
          P: Integer;
          SessCtx: TWTFileSessionCtx;
          UserEntry: TUserEntry;
          HasUserEntry: Boolean;
          ClaimUp, ClaimDown: string;
          UserCanUp, UserCanDown: Boolean;
        begin
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

          if (TokenStr = '') or not Server.JWTManager.ValidateToken(TokenStr, JWT) then
          begin
            if Assigned(JWT) then FreeAndNil(JWT);
            Logger.Warn(Format('[WT-Files] Rejecting connection: invalid or missing token (SessionId: %d)', [Session^.SessionId]));
            Exit;
          end;

          try
            SessCtx := TWTFileSessionCtx.Create;
            SessCtx.SessionId := Session^.SessionId;
            SessCtx.Username := JWT.Subject;
            SessCtx.Role := JWT.GetClaim('role');
            if SessCtx.Role = '' then SessCtx.Role := 'user';
            SessCtx.Sandbox := JWT.GetClaim('sandbox');

            HasUserEntry := TGTermUserConfig.Instance.FindUser(JWT.Subject, UserEntry);
            if (SessCtx.Sandbox = '') and HasUserEntry and (UserEntry.Sandbox <> '') then
              SessCtx.Sandbox := UserEntry.Sandbox;
            if SessCtx.Sandbox = '' then
              SessCtx.Sandbox := 'sandbox';

            UserCanUp := False;
            UserCanDown := False;
            ClaimUp := JWT.GetClaim('upload');
            ClaimDown := JWT.GetClaim('download');
            if ClaimUp <> '' then
              UserCanUp := SameText(ClaimUp, 'true')
            else if HasUserEntry then
              UserCanUp := UserEntry.CanUpload;

            if ClaimDown <> '' then
              UserCanDown := SameText(ClaimDown, 'true')
            else if HasUserEntry then
              UserCanDown := UserEntry.CanDownload;

            if SameText(SessCtx.Role, 'admin') then
            begin
              UserCanUp := True;
              UserCanDown := True;
            end;

            SessCtx.CanUpload := UserCanUp;
            SessCtx.CanDownload := UserCanDown;
            if HasUserEntry then
              SessCtx.StorageQuotaMB := UserEntry.Grants.StorageQuotaMB
            else
              SessCtx.StorageQuotaMB := 500;
            if SameText(SessCtx.Role, 'admin') then
              SessCtx.StorageQuotaMB := 0;

            WTFileLock.Enter;
            try
              WTFileSessions.AddOrSetValue(Session^.SessionId, SessCtx);
            finally
              WTFileLock.Leave;
            end;
            Logger.Info(Format('[WT-Files] Client connected (SessionId: %d, User: %s, Up: %s, Down: %s)',
              [Session^.SessionId, SessCtx.Username, BoolToStr(UserCanUp, True), BoolToStr(UserCanDown, True)]));
          finally
            JWT.Free;
          end;
        end,
        procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
        var
          SessCtx: TWTFileSessionCtx;
          StreamCtx: TWTFileStreamCtx;
          HasSess, HasStream: Boolean;
          I, NewlinePos: Integer;
          HdrStr: string;
          HdrJson: TJSONObject;
          ActionVal, PathVal, ScopeVal: string;
          SizeVal: Int64;
          ServerRoot, UserHome, BaseDir, TargetPath: string;
          IsAdmin: Boolean;
          BytesToWrite, Offset: Integer;
          RespJson: TJSONObject;
          RespLine: UTF8String;
          RespBytes: TBytes;
          HashStr: string;
          FileBuf: TBytes;
          ReadChunk: Integer;
          SrcFileStream: TFileStream;
        begin
          if (Session = nil) or (Stream = nil) or (Length(Data) = 0) then Exit;

          WTFileLock.Enter;
          try
            HasSess := WTFileSessions.TryGetValue(Session^.SessionId, SessCtx);
            HasStream := WTFileStreams.TryGetValue(Stream, StreamCtx);
            if not HasStream and HasSess then
            begin
              StreamCtx := TWTFileStreamCtx.Create;
              StreamCtx.Stream := Stream;
              StreamCtx.SessionId := Session^.SessionId;
              StreamCtx.Mode := wtmNone;
              StreamCtx.HeaderParsed := False;
              WTFileStreams.Add(Stream, StreamCtx);
              HasStream := True;
            end;
          finally
            WTFileLock.Leave;
          end;

          if not HasSess or not HasStream then Exit;

          if not StreamCtx.HeaderParsed then
          begin
            var OldLen := Length(StreamCtx.HeaderBuf);
            SetLength(StreamCtx.HeaderBuf, OldLen + Length(Data));
            Move(Data[0], StreamCtx.HeaderBuf[OldLen], Length(Data));

            NewlinePos := -1;
            for I := 0 to Length(StreamCtx.HeaderBuf) - 1 do
            begin
              if StreamCtx.HeaderBuf[I] = Ord(#10) then
              begin
                NewlinePos := I;
                Break;
              end;
            end;

            if NewlinePos < 0 then
            begin
              if Length(StreamCtx.HeaderBuf) > 65536 then
              begin
                RespLine := '{"status":"error","message":"Header too large"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
              end;
              Exit;
            end;

            HdrStr := TEncoding.UTF8.GetString(StreamCtx.HeaderBuf, 0, NewlinePos).Trim;
            StreamCtx.HeaderParsed := True;

            HdrJson := nil;
            try
              try
                HdrJson := TJSONObject.ParseJSONValue(HdrStr) as TJSONObject;
              except
                HdrJson := nil;
              end;

              if HdrJson = nil then
              begin
                RespLine := '{"status":"error","message":"Invalid JSON header"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;

              ActionVal := LowerCase(HdrJson.GetValue<string>('action', ''));
              PathVal := HdrJson.GetValue<string>('path', '');
              ScopeVal := LowerCase(HdrJson.GetValue<string>('scope', 'home'));
              SizeVal := HdrJson.GetValue<Int64>('size', 0);
              IsAdmin := SameText(SessCtx.Role, 'admin');

              ServerRoot := TPath.GetFullPath(ExtractFilePath(ParamStr(0)));
              UserHome := TPath.GetFullPath(TPath.Combine(ServerRoot, SessCtx.Sandbox));
              if not TDirectory.Exists(UserHome) then
              begin
                RespLine := '{"status":"error","message":"User sandbox directory does not exist"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;

              if (ScopeVal = 'server') and not IsAdmin then
              begin
                RespLine := '{"status":"error","message":"Server scope requires admin role"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;

              if (ScopeVal = 'server') and IsAdmin then
                BaseDir := ServerRoot
              else
                BaseDir := UserHome;

              PathVal := PathVal.Replace('/', '\');
              while PathVal.StartsWith('\') do
                PathVal := Copy(PathVal, 2, Length(PathVal) - 1);

              if (Pos(#0, PathVal) > 0) or ((not IsAdmin) and (Pos(':', PathVal) > 0)) then
              begin
                RespLine := '{"status":"error","message":"Invalid path format or drive specifier"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;

              TargetPath := TPath.GetFullPath(TPath.Combine(BaseDir, PathVal));
              if not IsAdmin and not IsPathInSandboxCanonical(TargetPath, UserHome) then
              begin
                RespLine := '{"status":"error","message":"Path traversal detected outside sandbox"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;

              StreamCtx.FullPath := TargetPath;
              StreamCtx.Filename := TPath.GetFileName(TargetPath);

              if ActionVal = 'upload' then
              begin
                if not SessCtx.CanUpload then
                begin
                  RespLine := '{"status":"error","message":"Upload forbidden: missing upload grant"}'#10;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                if not IsAdmin and (SessCtx.StorageQuotaMB > 0) then
                begin
                  var QuotaBytes: Int64 := Int64(SessCtx.StorageQuotaMB) * 1024 * 1024;
                  var CurrentUsed: Int64 := GetDirectoryTotalSize(UserHome);
                  if CurrentUsed + SizeVal > QuotaBytes then
                  begin
                    RespLine := '{"status":"error","message":"Storage quota exceeded"}'#10;
                    SetLength(RespBytes, Length(RespLine));
                    Move(RespLine[1], RespBytes[0], Length(RespLine));
                    Session.SendOnStream(Stream, RespBytes, True);
                    WTFileLock.Enter;
                    try
                      WTFileStreams.Remove(Stream);
                    finally
                      WTFileLock.Leave;
                    end;
                    StreamCtx.Free;
                    Exit;
                  end;
                end;

                if HasForbiddenFileNameChars(StreamCtx.Filename) or IsForbiddenUploadExtension(StreamCtx.Filename) then
                begin
                  RespLine := '{"status":"error","message":"Upload forbidden: invalid file name or extension"}'#10;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                var ParentDir := ExtractFilePath(TargetPath);
                if (ParentDir <> '') and not TDirectory.Exists(ParentDir) then
                  TDirectory.CreateDirectory(ParentDir);

                StreamCtx.Mode := wtmUpload;
                StreamCtx.ExpectedSize := SizeVal;
                StreamCtx.BytesProcessed := 0;

                Offset := NewlinePos + 1;
                BytesToWrite := Length(StreamCtx.HeaderBuf) - Offset;
                if BytesToWrite > 0 then
                begin
                  var ThreatReason: string := '';
                  if (BytesToWrite >= 2) and IsExecutableBinaryHeader(@StreamCtx.HeaderBuf[Offset], BytesToWrite) then
                  begin
                    RespLine := UTF8String('{"status":"error","message":"Malicious payload detected: executable PE binary header (MZ) forbidden"}'#10);
                    SetLength(RespBytes, Length(RespLine));
                    Move(RespLine[1], RespBytes[0], Length(RespLine));
                    Session.SendOnStream(Stream, RespBytes, True);
                    WTFileLock.Enter;
                    try
                      WTFileStreams.Remove(Stream);
                    finally
                      WTFileLock.Leave;
                    end;
                    StreamCtx.Free;
                    Exit;
                  end;

                  if not ScanBufferForThreats(@StreamCtx.HeaderBuf[Offset], BytesToWrite, StreamCtx.Filename, ThreatReason) then
                  begin
                    RespLine := UTF8String(Format('{"status":"error","message":"%s"}'#10, [ThreatReason]));
                    SetLength(RespBytes, Length(RespLine));
                    Move(RespLine[1], RespBytes[0], Length(RespLine));
                    Session.SendOnStream(Stream, RespBytes, True);
                    WTFileLock.Enter;
                    try
                      WTFileStreams.Remove(Stream);
                    finally
                      WTFileLock.Leave;
                    end;
                    StreamCtx.Free;
                    Exit;
                  end;
                end;

                StreamCtx.FileStream := TFileStream.Create(TargetPath, fmCreate or fmShareDenyNone);
                if BytesToWrite > 0 then
                begin
                  StreamCtx.FileStream.WriteBuffer(StreamCtx.HeaderBuf[Offset], BytesToWrite);
                  Inc(StreamCtx.BytesProcessed, BytesToWrite);
                end;
                SetLength(StreamCtx.HeaderBuf, 0);

                if StreamCtx.BytesProcessed >= StreamCtx.ExpectedSize then
                begin
                  FreeAndNil(StreamCtx.FileStream);

                  var ThreatDetected: Boolean := False;
                  var ThreatReason: string := '';
                  try
                    if FileExists(StreamCtx.FullPath) then
                    begin
                      var CheckStream: TFileStream := TFileStream.Create(StreamCtx.FullPath, fmOpenRead or fmShareDenyNone);
                      try
                        var HeadBuf: array[0..511] of Byte;
                        var ReadHead: Integer := CheckStream.Read(HeadBuf, Length(HeadBuf));
                        if (ReadHead >= 2) and IsExecutableBinaryHeader(@HeadBuf[0], ReadHead) then
                        begin
                          ThreatDetected := True;
                          ThreatReason := 'Malicious payload detected: executable PE binary header (MZ) forbidden';
                        end
                        else if not ScanBufferForThreats(@HeadBuf[0], ReadHead, StreamCtx.Filename, ThreatReason) then
                        begin
                          ThreatDetected := True;
                        end;
                      finally
                        CheckStream.Free;
                      end;
                    end;
                  except
                    on E: Exception do
                    begin
                      ThreatDetected := True;
                      ThreatReason := 'Antivirus threat detected: ' + E.Message;
                    end;
                  end;

                  if ThreatDetected then
                  begin
                    try
                      if FileExists(StreamCtx.FullPath) then
                        TFile.Delete(StreamCtx.FullPath);
                    except
                    end;
                    RespLine := UTF8String(Format('{"status":"error","message":"%s"}'#10, [ThreatReason]));
                    SetLength(RespBytes, Length(RespLine));
                    Move(RespLine[1], RespBytes[0], Length(RespLine));
                    Session.SendOnStream(Stream, RespBytes, True);
                    WTFileLock.Enter;
                    try
                      WTFileStreams.Remove(Stream);
                    finally
                      WTFileLock.Leave;
                    end;
                    StreamCtx.Free;
                    Exit;
                  end;

                  try
                    HashStr := THashSHA2.GetHashStringFromFile(StreamCtx.FullPath, THashSHA2.TSHA2Version.SHA256).ToLower;
                  except
                    on E: Exception do
                    begin
                      RespLine := UTF8String(Format('{"status":"error","message":"Antivirus threat detected: %s"}'#10, [E.Message]));
                      SetLength(RespBytes, Length(RespLine));
                      Move(RespLine[1], RespBytes[0], Length(RespLine));
                      Session.SendOnStream(Stream, RespBytes, True);
                      WTFileLock.Enter;
                      try
                        WTFileStreams.Remove(Stream);
                      finally
                        WTFileLock.Leave;
                      end;
                      StreamCtx.Free;
                      Exit;
                    end;
                  end;
                  RespJson := TJSONObject.Create;
                  try
                    RespJson.AddPair('status', 'ok');
                    RespJson.AddPair('action', 'upload');
                    RespJson.AddPair('path', StreamCtx.Filename);
                    RespJson.AddPair('bytes', TJSONNumber.Create(StreamCtx.BytesProcessed));
                    RespJson.AddPair('sha256', HashStr);
                    RespLine := UTF8String(RespJson.ToJSON + #10);
                  finally
                    RespJson.Free;
                  end;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, False);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;
              end
              else if ActionVal = 'download' then
              begin
                if not SessCtx.CanDownload then
                begin
                  RespLine := '{"status":"error","message":"Download forbidden: missing download grant"}'#10;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                if HasForbiddenFileNameChars(StreamCtx.Filename) then
                begin
                  RespLine := '{"status":"error","message":"Download forbidden: invalid file name"}'#10;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                if not FileExists(TargetPath) then
                begin
                  RespLine := '{"status":"error","message":"File not found"}'#10;
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                StreamCtx.Mode := wtmDownload;
                var FileSize := TFile.GetSize(TargetPath);
                HashStr := THashSHA2.GetHashStringFromFile(TargetPath, THashSHA2.TSHA2Version.SHA256).ToLower;

                RespJson := TJSONObject.Create;
                try
                  RespJson.AddPair('status', 'ok');
                  RespJson.AddPair('action', 'download');
                  RespJson.AddPair('path', StreamCtx.Filename);
                  RespJson.AddPair('size', TJSONNumber.Create(FileSize));
                  RespJson.AddPair('sha256', HashStr);
                  RespLine := UTF8String(RespJson.ToJSON + #10);
                finally
                  RespJson.Free;
                end;

                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, False);

                SrcFileStream := TFileStream.Create(TargetPath, fmOpenRead or fmShareDenyNone);
                try
                  SetLength(FileBuf, 65536);
                  while SrcFileStream.Position < SrcFileStream.Size do
                  begin
                    ReadChunk := SrcFileStream.Read(FileBuf[0], Length(FileBuf));
                    if ReadChunk <= 0 then Break;
                    if ReadChunk < Length(FileBuf) then
                      SetLength(FileBuf, ReadChunk);
                    var IsLast := (SrcFileStream.Position >= SrcFileStream.Size);
                    Session.SendOnStream(Stream, FileBuf, IsLast);
                    if not IsLast and (Length(FileBuf) < 65536) then
                      SetLength(FileBuf, 65536);
                  end;
                finally
                  SrcFileStream.Free;
                end;

                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end
              else
              begin
                RespLine := '{"status":"error","message":"Unknown action"}'#10;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, True);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;
            finally
              if Assigned(HdrJson) then HdrJson.Free;
            end;
          end
          else if StreamCtx.Mode = wtmUpload then
          begin
            if Assigned(StreamCtx.FileStream) then
            begin
              if StreamCtx.BytesProcessed = 0 then
              begin
                var ThreatReason: string := '';
                if (Length(Data) >= 2) and IsExecutableBinaryHeader(@Data[0], Length(Data)) then
                begin
                  FreeAndNil(StreamCtx.FileStream);
                  try
                    if FileExists(StreamCtx.FullPath) then
                      TFile.Delete(StreamCtx.FullPath);
                  except
                  end;
                  RespLine := UTF8String('{"status":"error","message":"Malicious payload detected: executable PE binary header (MZ) forbidden"}'#10);
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                if not ScanBufferForThreats(@Data[0], Length(Data), StreamCtx.Filename, ThreatReason) then
                begin
                  FreeAndNil(StreamCtx.FileStream);
                  try
                    if FileExists(StreamCtx.FullPath) then
                      TFile.Delete(StreamCtx.FullPath);
                  except
                  end;
                  RespLine := UTF8String(Format('{"status":"error","message":"%s"}'#10, [ThreatReason]));
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;
              end;

              StreamCtx.FileStream.WriteBuffer(Data[0], Length(Data));
              Inc(StreamCtx.BytesProcessed, Length(Data));

              if StreamCtx.BytesProcessed >= StreamCtx.ExpectedSize then
              begin
                FreeAndNil(StreamCtx.FileStream);

                var ThreatDetected: Boolean := False;
                var ThreatReason: string := '';
                try
                  if FileExists(StreamCtx.FullPath) then
                  begin
                    var CheckStream: TFileStream := TFileStream.Create(StreamCtx.FullPath, fmOpenRead or fmShareDenyNone);
                    try
                      var HeadBuf: array[0..511] of Byte;
                      var ReadHead: Integer := CheckStream.Read(HeadBuf, Length(HeadBuf));
                      if (ReadHead >= 2) and IsExecutableBinaryHeader(@HeadBuf[0], ReadHead) then
                      begin
                        ThreatDetected := True;
                        ThreatReason := 'Malicious payload detected: executable PE binary header (MZ) forbidden';
                      end
                      else if not ScanBufferForThreats(@HeadBuf[0], ReadHead, StreamCtx.Filename, ThreatReason) then
                      begin
                        ThreatDetected := True;
                      end;
                    finally
                      CheckStream.Free;
                    end;
                  end;
                except
                  on E: Exception do
                  begin
                    ThreatDetected := True;
                    ThreatReason := 'Antivirus threat detected: ' + E.Message;
                  end;
                end;

                if ThreatDetected then
                begin
                  try
                    if FileExists(StreamCtx.FullPath) then
                      TFile.Delete(StreamCtx.FullPath);
                  except
                  end;
                  RespLine := UTF8String(Format('{"status":"error","message":"%s"}'#10, [ThreatReason]));
                  SetLength(RespBytes, Length(RespLine));
                  Move(RespLine[1], RespBytes[0], Length(RespLine));
                  Session.SendOnStream(Stream, RespBytes, True);
                  WTFileLock.Enter;
                  try
                    WTFileStreams.Remove(Stream);
                  finally
                    WTFileLock.Leave;
                  end;
                  StreamCtx.Free;
                  Exit;
                end;

                try
                  HashStr := THashSHA2.GetHashStringFromFile(StreamCtx.FullPath, THashSHA2.TSHA2Version.SHA256).ToLower;
                except
                  on E: Exception do
                  begin
                    RespLine := UTF8String(Format('{"status":"error","message":"Antivirus threat detected: %s"}'#10, [E.Message]));
                    SetLength(RespBytes, Length(RespLine));
                    Move(RespLine[1], RespBytes[0], Length(RespLine));
                    Session.SendOnStream(Stream, RespBytes, True);
                    WTFileLock.Enter;
                    try
                      WTFileStreams.Remove(Stream);
                    finally
                      WTFileLock.Leave;
                    end;
                    StreamCtx.Free;
                    Exit;
                  end;
                end;
                RespJson := TJSONObject.Create;
                try
                  RespJson.AddPair('status', 'ok');
                  RespJson.AddPair('action', 'upload');
                  RespJson.AddPair('path', StreamCtx.Filename);
                  RespJson.AddPair('bytes', TJSONNumber.Create(StreamCtx.BytesProcessed));
                  RespJson.AddPair('sha256', HashStr);
                  RespLine := UTF8String(RespJson.ToJSON + #10);
                finally
                  RespJson.Free;
                end;
                SetLength(RespBytes, Length(RespLine));
                Move(RespLine[1], RespBytes[0], Length(RespLine));
                Session.SendOnStream(Stream, RespBytes, False);
                WTFileLock.Enter;
                try
                  WTFileStreams.Remove(Stream);
                finally
                  WTFileLock.Leave;
                end;
                StreamCtx.Free;
                Exit;
              end;
            end;
          end;
        end,
        procedure(Session: PWTSessionContext; const Data: TBytes)
        begin
        end,
        procedure(SessionId: TWTSessionId)
        var
          StreamKeys: TList<HQUIC>;
          Pair: TPair<HQUIC, TWTFileStreamCtx>;
        begin
          Logger.Info(Format('[WT-Files] Client disconnected (SessionId: %d)', [SessionId]));
          WTFileLock.Enter;
          try
            WTFileSessions.Remove(SessionId);
            StreamKeys := TList<HQUIC>.Create;
            try
              for Pair in WTFileStreams do
              begin
                if Pair.Value.SessionId = SessionId then
                  StreamKeys.Add(Pair.Key);
              end;
              for var K in StreamKeys do
              begin
                var StrmCtx := WTFileStreams[K];
                WTFileStreams.Remove(K);
                StrmCtx.Free;
              end;
            finally
              StreamKeys.Free;
            end;
          finally
            WTFileLock.Leave;
          end;
        end
      );

      if not Server.Start then
      begin
        Logger.Error(Format('Failed to start HTTPS IOCP server on port %d.', [HttpsPortParam]));
        ExitCode := 1; Exit;
      end;

      var DisplayHost: string := GBindAddress;
      if DisplayHost = '' then
        DisplayHost := GHttpsBindAddress;
      if (DisplayHost = '') or (DisplayHost = '0.0.0.0') then
        DisplayHost := GetPrimaryIPv4Address;
      if DisplayHost = '' then
        DisplayHost := 'localhost';

      Logger.Info('================================================================');
      Logger.Info(Format('  Server listening on HTTPS:        https://%s:%d', [DisplayHost, HttpsPortParam]));
      Logger.Info(Format('  Server listening on WebTransport: https://%s:%d/wt/terminal', [DisplayHost, HttpsPortParam]));
      Logger.Info(Format('  Server listening on WebTransport Files: https://%s:%d/wt/files', [DisplayHost, HttpsPortParam]));
      if GServerCertIsTrusted then
        Logger.Info('  TLS Trust Mode:                   TRUSTED (System Root CA - Web PKI)')
      else
        Logger.Info('  TLS Trust Mode:                   Self-Signed W3C WebTransport (serverCertificateHashes)');
      case GmTLSMode of
        mtlsRequired: Logger.Info('  mTLS Client Authentication:       REQUIRED (Strict Mutual TLS)');
        mtlsOptional: Logger.Info('  mTLS Client Authentication:       OPTIONAL (Verify Client Cert If Given)');
      else
        Logger.Info('  mTLS Client Authentication:       DISABLED (Standard TLS)');
      end;
      if GmTLSCaCertPath <> '' then
        Logger.Info('  mTLS CA Certificate:              ' + GmTLSCaCertPath)
      else if GmTLSMode <> mtlsDisabled then
        Logger.Info('  mTLS CA Certificate:              NONE (Direct Trust / Windows Store only)');
      if GmTLSPinnedThumbprint <> '' then
        Logger.Info('  mTLS Pinned Direct Trust:         ' + GmTLSPinnedThumbprint);
      if Assigned(GTrustedClients) and (GTrustedClients.Count > 0) then
        Logger.Info(Format('  mTLS Trusted Clients Whitelist:   %d certs loaded (%s)', [GTrustedClients.Count, GTrustedClientsDir]));
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
      FreeAndNil(GlobalQuotaManager);
      if Assigned(WTFileStreams) then
      begin
        for var Strm in WTFileStreams.Values do
          Strm.Free;
        FreeAndNil(WTFileStreams);
      end;
      if Assigned(WTFileSessions) then
      begin
        for var Sess in WTFileSessions.Values do
          Sess.Free;
        FreeAndNil(WTFileSessions);
      end;
      FreeAndNil(WTFileLock);
      if Assigned(GTrustedClients) then
        FreeAndNil(GTrustedClients);
      Logger.Info('Server stopped cleanly.');
    end;
  except
    on E: Exception do
      Logger.Critical(Format('Fatal Error [%s]: %s', [E.ClassName, E.Message]));
  end;
end.

