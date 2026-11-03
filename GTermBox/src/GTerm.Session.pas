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
unit GTerm.Session;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.JSON,
  System.StrUtils,
  System.Generics.Collections,
  Winapi.Windows,
  Quick.Logger,
  GTerm.Types,
  GTerm.AppConfig,
  GTerm.UserConfig,
  GTerm.ConPty,
  MsQuic.Types,
  WebTransport.Types,
  WebTransport.Session;

type
  TGTermSession = class
  private
    FRefCount: Integer;
    FWTSessionContext: TWTSessionContext;
    FWTSession: PWTSessionContext;
    FWTHasSession: Boolean;
    FWTStream: HQUIC;
    FWTControlStream: HQUIC;
    FControlBuffer: string;
    FConPty: TGTermConPty;
    FCols: Integer;
    FRows: Integer;
    FProfile: TGTermAppProfile;
    FUsername: string;
    FRole: string;
    FClosed: Boolean;
    FStopping: Integer;
    FSessionLock: TCriticalSection;
    FConnectedTick: UInt64;
    FLastActivityTick: UInt64;
    FInitialBuffer: TBytes;
    procedure HandlePtyDataReceived(const AData: TBytes; ACount: Integer);
    procedure HandleProcessTerminated(AExitCode: DWORD);
    procedure SendClientText(const AText: string);
    procedure ProcessSingleClientMessage(const AMessageText: string);
  public
    constructor Create(AWTSession: PWTSessionContext; const AProfile: TGTermAppProfile; const AUsername: string = ''; const ARole: string = '');
    destructor Destroy; override;
    procedure Retain;
    procedure Release;
    procedure SetWTStream(ASession: PWTSessionContext; AStream: HQUIC);
    procedure SetWTControlStream(ASession: PWTSessionContext; AStream: HQUIC);
    procedure ProcessStreamData(ASession: PWTSessionContext; AStream: HQUIC; const Data: TBytes);
    procedure ProcessControlStreamData(const Data: TBytes);
    procedure WriteInputChunked(const AInputStr: string);
    procedure Start;
    procedure Stop;
    procedure SwitchProfile(const AAppKey: string);
    procedure ProcessClientMessage(const AMessageText: string);
    procedure SendInitialScreen;
    property Closed: Boolean read FClosed;
    property ConnectedTick: UInt64 read FConnectedTick;
    property LastActivityTick: UInt64 read FLastActivityTick;
    property WTStream: HQUIC read FWTStream;
    property WTControlStream: HQUIC read FWTControlStream;
    property ConPty: TGTermConPty read FConPty;
    property Profile: TGTermAppProfile read FProfile;
    property Username: string read FUsername;
    property Cols: Integer read FCols;
    property Rows: Integer read FRows;
  end;

  TGTermSessionInfo = record
    SessionId: UInt64;
    AppKey: string;
    ProfileName: string;
    Username: string;
    ProcessId: DWORD;
    Cols: Integer;
    Rows: Integer;
    ConnectedSeconds: UInt64;
    IdleSeconds: UInt64;
    Closed: Boolean;
  end;

  TGTermSessionManager = class;

  TSessionWatchdogThread = class(TThread)
  private
    FManager: TGTermSessionManager;
  protected
    procedure Execute; override;
  public
    constructor Create(AManager: TGTermSessionManager);
  end;

  TGTermSessionManager = class
  private
    FLock: TObject;
    FSessions: TDictionary<Pointer, TGTermSession>;
    FWatchdog: TSessionWatchdogThread;
    FIdleTimeoutMs: Cardinal;
  public
    constructor Create(AIdleTimeoutMs: Cardinal = 300000);
    destructor Destroy; override;
    procedure RegisterSession(SessionKey: Pointer; ASession: TGTermSession);
    function FindSession(SessionKey: Pointer): TGTermSession;
    function AcquireSession(SessionKey: Pointer): TGTermSession;
    procedure UnregisterAndFreeSession(SessionKey: Pointer);
    function GetSessionSnapshots: TArray<TGTermSessionInfo>;
    function TerminateSessionById(ASessionId: UInt64): Boolean;
    procedure CheckSessions;
    procedure Clear;
    property IdleTimeoutMs: Cardinal read FIdleTimeoutMs write FIdleTimeoutMs;
  end;

implementation

constructor TGTermSession.Create(AWTSession: PWTSessionContext; const AProfile: TGTermAppProfile; const AUsername: string = ''; const ARole: string = '');
begin
  inherited Create;
  FRefCount := 1;
  if AWTSession <> nil then
  begin
    FWTSessionContext := AWTSession^;
    FWTSession := @FWTSessionContext;
    FWTHasSession := True;
  end
  else
  begin
    FWTSession := nil;
    FWTHasSession := False;
  end;
  FWTStream := nil;
  FWTControlStream := nil;
  FControlBuffer := '';
  FProfile := AProfile;
  FUsername := AUsername;
  FRole := ARole;
  FClosed := False;
  FStopping := 0;
  FConnectedTick := GetTickCount64;
  FLastActivityTick := FConnectedTick;

  FCols := FProfile.DefaultCols;
  FRows := FProfile.DefaultRows;
  FConPty := TGTermConPty.Create(FProfile.DefaultCols, FProfile.DefaultRows);
  FConPty.SandboxMode := FProfile.Sandbox;
  FSessionLock := TCriticalSection.Create;

  FConPty.OnDataReceived := HandlePtyDataReceived;
  FConPty.OnProcessTerminated := HandleProcessTerminated;
end;

destructor TGTermSession.Destroy;
begin
  if Assigned(FSessionLock) then
  begin
    FSessionLock.Enter;
    try
      Stop;
      if Assigned(FConPty) then
      begin
        FConPty.OnDataReceived := nil;
        FConPty.OnProcessTerminated := nil;
      end;
      FreeAndNil(FConPty);
    finally
      FSessionLock.Leave;
    end;
  end;
  FreeAndNil(FSessionLock);
  inherited Destroy;
end;

procedure TGTermSession.Retain;
begin
  TInterlocked.Increment(FRefCount);
end;

procedure TGTermSession.Release;
begin
  if TInterlocked.Decrement(FRefCount) <= 0 then
    Free;
end;

procedure TGTermSession.SetWTStream(ASession: PWTSessionContext; AStream: HQUIC);
var
  IsNewStream: Boolean;
  PendingBytes: TBytes;
begin
  if FSessionLock <> nil then
    FSessionLock.Enter;
  try
    IsNewStream := (FWTStream = nil) or (FWTStream <> AStream);
    if ASession <> nil then
    begin
      FWTSessionContext := ASession^;
      FWTSession := @FWTSessionContext;
      FWTHasSession := True;
    end;
    FWTStream := AStream;
    PendingBytes := FInitialBuffer;
    SetLength(FInitialBuffer, 0);
  finally
    if FSessionLock <> nil then
      FSessionLock.Leave;
  end;
  Logger.Info(Format('[Session] SetWTStream called: Stream=%p, PendingBytes=%d', [Pointer(AStream), Length(PendingBytes)]));
  if (FWTStream <> nil) and (Length(PendingBytes) > 0) and FWTHasSession and (FWTSession <> nil) then
  begin
    try
      FWTSession^.SendOnStream(FWTStream, PendingBytes, False);
    except
    end;
  end;
  FLastActivityTick := GetTickCount64;
  if not FConPty.Running then
    Start;
  if IsNewStream then
    SendInitialScreen;
end;

procedure TGTermSession.Start;
var
  Started: Boolean;
begin
  if FProfile.Sandbox = smInvalid then Exit;
  if FClosed or (FStopping <> 0) then Exit;
  if not FConPty.Running then
  begin
    FConPty.SandboxMode := FProfile.Sandbox;
    FConPty.OnDataReceived := HandlePtyDataReceived;
    FConPty.OnProcessTerminated := HandleProcessTerminated;
    Logger.Info(Format('[Session] Starting session for profile "%s" (Command: %s) sandbox=%d net=%s',
      [FProfile.ProfileName, FProfile.CommandLine, Ord(FProfile.Sandbox), IfThen(FProfile.NetworkAccess, 'true', 'false')]));
    Started := FConPty.StartProcess(FProfile.CommandLine, FProfile.WorkingDirectory, FProfile.AllowedDirsRead, FProfile.AllowedDirsWrite, FProfile.EnvironmentVars, FProfile.NetworkAccess);
    if not Started then
    begin
      Logger.Error(Format('[Session] Process failed to start for app: %s', [FProfile.ProfileName]));
      var ErrMsg := #13#10#27'[1;31m[GTermBox Error] Application unavailable: "' + FProfile.ProfileName + '"'#27'[0m'#13#10 +
                    #27'[33mThe specified application is not installed on this server.'#27'[0m'#13#10#13#10;
      var ErrBytes := TEncoding.UTF8.GetBytes(ErrMsg);
      if (FWTStream <> nil) and FWTHasSession and (FWTSession <> nil) then
      begin
        try
          FWTSession^.SendOnStream(FWTStream, ErrBytes, False);
        except
        end;
      end;
      SendClientText('{"type":"app_error","app":"' + FProfile.ProfileName + '","reason":"process_failed"}');
      Stop;
      Exit;
    end;
  end;
end;

procedure TGTermSession.SwitchProfile(const AAppKey: string);
var
  Entry: TAppEntry;
  WantedProfile: TGTermAppProfile;
  CurrentSandbox: string;
begin
  if FUsername <> '' then
  begin
    var EffectiveRole := FRole;
    if EffectiveRole = '' then EffectiveRole := 'user';
    if not TGTermAppConfig.Instance.CanRoleAccessApp(EffectiveRole, AAppKey) or
       not TGTermUserConfig.Instance.CanAccessApp(FUsername, AAppKey) then
    begin
      Logger.Warn(Format('[Session] SwitchProfile forbidden for user "%s" (role: %s) to app "%s"',
        [FUsername, EffectiveRole, AAppKey]));
      Stop;
      Exit;
    end;
  end;

  CurrentSandbox := ExtractFileName(FProfile.WorkingDirectory);
  if TGTermAppConfig.Instance.FindById(AAppKey, Entry) then
    WantedProfile := Entry.ToProfile(CurrentSandbox)
  else
    WantedProfile := TGTermAppConfig.Instance.GetDefaultProfile(CurrentSandbox);



  var UserEntry: TUserEntry;
  if (FUsername <> '') and TGTermUserConfig.Instance.FindUser(FUsername, UserEntry) then
  begin
    WantedProfile.NetworkAccess := WantedProfile.NetworkAccess and UserEntry.Grants.Network;
    if (Pos('powershell', LowerCase(WantedProfile.CommandLine)) > 0) or SameText(AAppKey, 'powershell') or SameText(AAppKey, 'admin-powershell') then
    begin
      if UserEntry.CanPowerShellAccessEverywhere then
        WantedProfile.Sandbox := smJobOnly
      else
      begin
        WantedProfile.Sandbox := smStandard;
        SetLength(WantedProfile.EnvironmentVars, Length(WantedProfile.EnvironmentVars) + 1);
        WantedProfile.EnvironmentVars[High(WantedProfile.EnvironmentVars)] := 'GTERM_RESTRICT_PS=1';
      end;
    end
    else
    begin
      if UserEntry.IsAdmin or UserEntry.Grants.FullDiskAccess then
        WantedProfile.Sandbox := smJobOnly
      else if not UserEntry.Grants.AllowJobOnly then
        WantedProfile.Sandbox := smStandard;
    end;
  end
  else if SameText(FRole, 'admin') then
    WantedProfile.Sandbox := smJobOnly;
  if (WantedProfile.Sandbox = smJobOnly) and not SameText(FRole, 'admin') and not (TGTermUserConfig.Instance.FindUser(FUsername, UserEntry) and (UserEntry.Grants.AllowJobOnly or UserEntry.Grants.FullDiskAccess)) then
    WantedProfile.Sandbox := smStandard;

  if FProfile.ProfileName <> WantedProfile.ProfileName then
  begin
    if FConPty.Running then
      FConPty.StopProcess;
    if Length(WantedProfile.AllowedDirsRead) = 0 then
      WantedProfile.AllowedDirsRead := FProfile.AllowedDirsRead;
    if Length(WantedProfile.AllowedDirsWrite) = 0 then
      WantedProfile.AllowedDirsWrite := FProfile.AllowedDirsWrite;
    FCols := WantedProfile.DefaultCols;
    FRows := WantedProfile.DefaultRows;
    FProfile := WantedProfile;
    FConPty.SandboxMode := WantedProfile.Sandbox;
  end;

  if not FConPty.Running then
    Start;
end;

procedure TGTermSession.Stop;
var
  DataBytes: TBytes;
  StreamToClose: HQUIC;
  ControlStreamToClose: HQUIC;
  PtyToStop: TGTermConPty;
  SessionToClose: PWTSessionContext;
  HasSessionToClose: Boolean;
begin
  PtyToStop := nil;
  if Assigned(FSessionLock) then
    FSessionLock.Enter;
  try
    if TInterlocked.CompareExchange(FStopping, 1, 0) <> 0 then Exit;
    FClosed := True;
    StreamToClose := FWTStream;
    ControlStreamToClose := FWTControlStream;
    SessionToClose := FWTSession;
    HasSessionToClose := FWTHasSession and (SessionToClose <> nil);
    FWTHasSession := False;
    FWTSession := nil;
    FWTStream := nil;
    FWTControlStream := nil;
    if Assigned(FConPty) then
    begin
      FConPty.OnDataReceived := nil;
      FConPty.OnProcessTerminated := nil;
      PtyToStop := FConPty;
    end;
  finally
    if Assigned(FSessionLock) then
      FSessionLock.Leave;
  end;

  if (ControlStreamToClose <> nil) and HasSessionToClose then
  begin
    SetLength(DataBytes, 0);
    try
      SessionToClose^.SendOnStream(ControlStreamToClose, DataBytes, True);
    except
    end;
  end;

  if (StreamToClose <> nil) and HasSessionToClose then
  begin
    SetLength(DataBytes, 0);
    try
      SessionToClose^.SendOnStream(StreamToClose, DataBytes, True);
      SessionToClose^.Close;
    except
    end;
  end;

  if Assigned(PtyToStop) then
    PtyToStop.StopProcess;
end;

procedure TGTermSession.SendClientText(const AText: string);
var
  DataBytes: TBytes;
  ActiveStream: HQUIC;
  ActiveSession: PWTSessionContext;
  HasActiveSession: Boolean;
begin
  if FClosed or (AText = '') then Exit;
  FLastActivityTick := GetTickCount64;

  if FSessionLock <> nil then
    FSessionLock.Enter;
  try
    ActiveStream := FWTStream;
    ActiveSession := FWTSession;
    HasActiveSession := FWTHasSession and (ActiveSession <> nil);
  finally
    if FSessionLock <> nil then
      FSessionLock.Leave;
  end;

  if (ActiveStream <> nil) and HasActiveSession then
  begin
    DataBytes := TEncoding.UTF8.GetBytes(AText + #10);
    try
      ActiveSession^.SendOnStream(ActiveStream, DataBytes, False);
    except
    end;
  end;
end;

procedure TGTermSession.SendInitialScreen;
begin
  if FClosed or (FWTStream = nil) then Exit;
  if Assigned(FConPty) and FConPty.Running then
    begin
      FConPty.Resize(FCols, FRows + 1);
      FConPty.Resize(FCols, FRows);
    end;
end;

procedure TGTermSession.HandlePtyDataReceived(const AData: TBytes; ACount: Integer);
var
  ActiveStream: HQUIC;
  ActiveSession: PWTSessionContext;
  HasActiveSession: Boolean;
begin
  Retain;
  try
    if FClosed or (FStopping <> 0) or (Length(AData) = 0) then Exit;
    FLastActivityTick := GetTickCount64;

    if FSessionLock <> nil then
      FSessionLock.Enter;
    try
      ActiveStream := FWTStream;
      ActiveSession := FWTSession;
      HasActiveSession := FWTHasSession and (ActiveSession <> nil);
      if ActiveStream = nil then
      begin
        var OldLen := Length(FInitialBuffer);
        if OldLen + Length(AData) < 524288 then
        begin
          SetLength(FInitialBuffer, OldLen + Length(AData));
          Move(AData[0], FInitialBuffer[OldLen], Length(AData));
        end;
      end;
    finally
      if FSessionLock <> nil then
        FSessionLock.Leave;
    end;

    if (ActiveStream <> nil) and HasActiveSession then
    begin
      Logger.Debug(Format('[Session] HandlePtyDataReceived sending %d bytes to stream %p', [Length(AData), Pointer(ActiveStream)]));
      try
        ActiveSession^.SendOnStream(ActiveStream, AData, False);
      except
        on E: Exception do
          Logger.Error('[Session] SendOnStream exception: ' + E.Message);
      end;
    end
    else
      Logger.Warn(Format('[Session] HandlePtyDataReceived dropped %d bytes (ActiveStream=%p, HasSession=%s)', [Length(AData), Pointer(ActiveStream), IfThen(HasActiveSession, 'true', 'false')]));
  finally
    Release;
  end;
end;

procedure TGTermSession.HandleProcessTerminated(AExitCode: DWORD);
begin
  Retain;
  try
    Logger.Warn(Format('[Session] Process terminated with exit code %d', [AExitCode]));
    SendClientText('{"type":"logout","reason":"terminated"}');
    Stop;
  finally
    Release;
  end;
end;

procedure TGTermSession.SetWTControlStream(ASession: PWTSessionContext; AStream: HQUIC);
begin
  if FSessionLock <> nil then
    FSessionLock.Enter;
  try
    if ASession <> nil then
    begin
      FWTSessionContext := ASession^;
      FWTSession := @FWTSessionContext;
      FWTHasSession := True;
    end;
    FWTControlStream := AStream;
  finally
    if FSessionLock <> nil then
      FSessionLock.Leave;
  end;
  Logger.Info(Format('[Session] SetWTControlStream called: Stream=%p', [Pointer(AStream)]));
end;

procedure TGTermSession.WriteInputChunked(const AInputStr: string);
const
  CHUNK_SIZE = 4096;
var
  Offset, ChunkLen: Integer;
begin
  if FClosed or (FStopping <> 0) or (AInputStr = '') then Exit;
  FLastActivityTick := GetTickCount64;
  if Assigned(FConPty) and FConPty.Running then
  begin
    Offset := 1;
    while Offset <= Length(AInputStr) do
    begin
      ChunkLen := Length(AInputStr) - Offset + 1;
      if ChunkLen > CHUNK_SIZE then
        ChunkLen := CHUNK_SIZE;
      FConPty.WriteInput(Copy(AInputStr, Offset, ChunkLen));
      Inc(Offset, ChunkLen);
    end;
  end;
end;

procedure TGTermSession.ProcessStreamData(ASession: PWTSessionContext; AStream: HQUIC; const Data: TBytes);
begin
  if FClosed or (FStopping <> 0) or (Length(Data) = 0) then Exit;
  FLastActivityTick := GetTickCount64;

  if FSessionLock <> nil then
    FSessionLock.Enter;
  try
    if FWTStream = nil then
      SetWTStream(ASession, AStream);

    if AStream = FWTStream then
    begin
      var LRawData := TEncoding.UTF8.GetString(Data);
      var LTrimData := Trim(LRawData);
      if (LTrimData <> '') and (LTrimData[1] = '{') and (LTrimData[Length(LTrimData)] = '}') and
         (Pos('"type"', LTrimData) > 0) then
        ProcessClientMessage(LTrimData)
      else
        WriteInputChunked(TEncoding.UTF8.GetString(Data));
      Exit;
    end;

    if FWTControlStream = nil then
      FWTControlStream := AStream;
  finally
    if FSessionLock <> nil then
      FSessionLock.Leave;
  end;

  if AStream = FWTControlStream then
    ProcessControlStreamData(Data);
end;

procedure TGTermSession.ProcessControlStreamData(const Data: TBytes);
var
  Chunk: string;
  NewlinePos: Integer;
  Line: string;
begin
  Chunk := TEncoding.UTF8.GetString(Data);
  FControlBuffer := FControlBuffer + Chunk;

  while True do
  begin
    NewlinePos := Pos(#10, FControlBuffer);
    if NewlinePos > 0 then
    begin
      Line := Trim(Copy(FControlBuffer, 1, NewlinePos - 1));
      FControlBuffer := Copy(FControlBuffer, NewlinePos + 1, MaxInt);
      if Line <> '' then
        ProcessSingleClientMessage(Line);
    end
    else
    begin
      Line := Trim(FControlBuffer);
      if (Line <> '') and (Line[1] = '{') and (Line[Length(Line)] = '}') then
      begin
        FControlBuffer := '';
        ProcessSingleClientMessage(Line);
      end;
      Break;
    end;
  end;
end;
procedure TGTermSession.ProcessClientMessage(const AMessageText: string);
var
  CleanText: string;
begin
  if FClosed or (FStopping <> 0) or (AMessageText = '') then Exit;
  FLastActivityTick := GetTickCount64;

  CleanText := Trim(AMessageText);
  if (CleanText <> '') and (CleanText[1] = '{') and (CleanText[Length(CleanText)] = '}') then
    ProcessSingleClientMessage(CleanText)
  else
    WriteInputChunked(AMessageText);
end;

procedure TGTermSession.ProcessSingleClientMessage(const AMessageText: string);
var
  JsonObj: TJSONObject;
  MsgType: string;
  NewCols, NewRows: Integer;
begin
  JsonObj := nil;
  try
    JsonObj := TJSONObject.ParseJSONValue(AMessageText) as TJSONObject;
    if not Assigned(JsonObj) then
    begin
      FConPty.WriteInput(AMessageText);
      Exit;
    end;

    MsgType := JsonObj.GetValue<string>('type', '');

    if MsgType = 'input' then
    begin
      var InputStr := JsonObj.GetValue<string>('data', '');
      if (InputStr <> '') and Assigned(FConPty) and FConPty.Running then
        FConPty.WriteInput(InputStr);
    end
    else if MsgType = 'resize' then
    begin
      NewCols := JsonObj.GetValue<Integer>('cols', FCols);
      NewRows := JsonObj.GetValue<Integer>('rows', FRows);
      if (NewCols > 0) and (NewRows > 0) and Assigned(FConPty) and FConPty.Running then
      begin
        FCols := NewCols;
        FRows := NewRows;
        FConPty.Resize(NewCols, NewRows);
      end;
    end
    else if MsgType = 'init' then
    begin
      var AppReq := LowerCase(JsonObj.GetValue<string>('app', ''));
      var TargetApp := LowerCase(JsonObj.GetValue<string>('target', ''));
      NewCols := JsonObj.GetValue<Integer>('cols', FCols);
      NewRows := JsonObj.GetValue<Integer>('rows', FRows);
      if (NewCols > 0) and (NewRows > 0) and ((NewCols <> FCols) or (NewRows <> FRows)) then
      begin
        FCols := NewCols;
        FRows := NewRows;
        FConPty.Resize(NewCols, NewRows);
      end;
      if TargetApp = '' then
        TargetApp := AppReq;
      if TargetApp <> '' then
      begin
        if not SameText(FProfile.ProfileName, TargetApp) or not FConPty.Running then
          SwitchProfile(TargetApp);
      end
      else if not FConPty.Running then
        Start;
    end
    else if MsgType = 'close' then
    begin
      Stop;
    end;
  finally
    JsonObj.Free;
  end;
end;

constructor TSessionWatchdogThread.Create(AManager: TGTermSessionManager);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FManager := AManager;
end;

procedure TSessionWatchdogThread.Execute;
begin
  while not Terminated do
  begin
    Sleep(1000);
    if (not Terminated) and Assigned(FManager) then
      FManager.CheckSessions;
  end;
end;

constructor TGTermSessionManager.Create(AIdleTimeoutMs: Cardinal);
begin
  inherited Create;
  FIdleTimeoutMs := AIdleTimeoutMs;
  FLock := TObject.Create;
  FSessions := TDictionary<Pointer, TGTermSession>.Create;
  FWatchdog := TSessionWatchdogThread.Create(Self);
end;

destructor TGTermSessionManager.Destroy;
begin
  if Assigned(FWatchdog) then
  begin
    FWatchdog.Terminate;
    FWatchdog.WaitFor;
    FreeAndNil(FWatchdog);
  end;
  Clear;
  FreeAndNil(FSessions);
  FreeAndNil(FLock);
  inherited Destroy;
end;

procedure TGTermSessionManager.RegisterSession(SessionKey: Pointer; ASession: TGTermSession);
begin
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  TMonitor.Enter(FLock);
  try
    FSessions.AddOrSetValue(SessionKey, ASession);
    Logger.Info(Format('[SessionManager] Registered session for socket key %p (Total sessions: %d)', [SessionKey, FSessions.Count]));
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TGTermSessionManager.FindSession(SessionKey: Pointer): TGTermSession;
begin
  Result := nil;
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  TMonitor.Enter(FLock);
  try
    FSessions.TryGetValue(SessionKey, Result);
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TGTermSessionManager.AcquireSession(SessionKey: Pointer): TGTermSession;
begin
  Result := nil;
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  TMonitor.Enter(FLock);
  try
    if FSessions.TryGetValue(SessionKey, Result) and Assigned(Result) then
      Result.Retain;
  finally
    TMonitor.Exit(FLock);
  end;
end;

procedure TGTermSessionManager.UnregisterAndFreeSession(SessionKey: Pointer);
var
  Session: TGTermSession;
begin
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  Session := nil;
  TMonitor.Enter(FLock);
  try
    if FSessions.TryGetValue(SessionKey, Session) then
    begin
      FSessions.Remove(SessionKey);
      Logger.Info(Format('[SessionManager] Unregistered session for socket key %p (Remaining: %d)', [SessionKey, FSessions.Count]));
    end;
  finally
    TMonitor.Exit(FLock);
  end;

  if Assigned(Session) then
  begin
    Session.Stop;
    Session.Release;
  end;
end;

procedure TGTermSessionManager.CheckSessions;
var
  NowTick: UInt64;
  Pair: TPair<Pointer, TGTermSession>;
  KeysToPurge: TList<Pointer>;
  Key: Pointer;
  Session: TGTermSession;
  ShouldPurge: Boolean;
begin
  NowTick := GetTickCount64;
  KeysToPurge := TList<Pointer>.Create;
  try
    TMonitor.Enter(FLock);
    try
      for Pair in FSessions do
      begin
        Session := Pair.Value;
        if not Assigned(Session) then
        begin
          KeysToPurge.Add(Pair.Key);
          Continue;
        end;

        ShouldPurge := False;
        if Session.Closed then
          ShouldPurge := True
        else if (Session.WTStream = nil) and ((NowTick - Session.ConnectedTick) > 15000) then
          ShouldPurge := True
        else if (FIdleTimeoutMs > 0) and ((NowTick - Session.LastActivityTick) > FIdleTimeoutMs) then
        begin
          Logger.Warn(Format('[SessionManager] Session %p idle timeout exceeded (%d ms without traffic). Terminating session process.', [Pair.Key, NowTick - Session.LastActivityTick]));
          Session.SendClientText('{"type":"logout","reason":"idle_timeout"}');
          ShouldPurge := True;
        end;

        if ShouldPurge then
          KeysToPurge.Add(Pair.Key);
      end;
    finally
      TMonitor.Exit(FLock);
    end;

    for Key in KeysToPurge do
      UnregisterAndFreeSession(Key);
  finally
    KeysToPurge.Free;
  end;
end;

procedure TGTermSessionManager.Clear;
var
  SessionList: TList<TGTermSession>;
  Session: TGTermSession;
begin
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  SessionList := TList<TGTermSession>.Create;
  try
    TMonitor.Enter(FLock);
    try
      for Session in FSessions.Values do
        if Assigned(Session) then
          SessionList.Add(Session);
      FSessions.Clear;
    finally
      TMonitor.Exit(FLock);
    end;

    for Session in SessionList do
    begin
      Session.Stop;
      Session.Release;
    end;
  finally
    SessionList.Free;
  end;
end;

function TGTermSessionManager.GetSessionSnapshots: TArray<TGTermSessionInfo>;
var
  Pair: TPair<Pointer, TGTermSession>;
  List: TList<TGTermSessionInfo>;
  Info: TGTermSessionInfo;
  NowTick: UInt64;
begin
  NowTick := GetTickCount64;
  List := TList<TGTermSessionInfo>.Create;
  try
    TMonitor.Enter(FLock);
    try
      for Pair in FSessions do
      begin
        if Assigned(Pair.Value) then
        begin
          Info.SessionId := UInt64(Pair.Key);
          Info.AppKey := Pair.Value.Profile.ProfileName;
          Info.ProfileName := Pair.Value.Profile.ProfileName;
          Info.Username := Pair.Value.Username;
          if Assigned(Pair.Value.ConPty) then
            Info.ProcessId := Pair.Value.ConPty.ProcessId
          else
            Info.ProcessId := 0;
          Info.Cols := Pair.Value.Cols;
          Info.Rows := Pair.Value.Rows;
          Info.ConnectedSeconds := (NowTick - Pair.Value.ConnectedTick) div 1000;
          Info.IdleSeconds := (NowTick - Pair.Value.LastActivityTick) div 1000;
          Info.Closed := Pair.Value.Closed;
          List.Add(Info);
        end;
      end;
    finally
      TMonitor.Exit(FLock);
    end;
    Result := List.ToArray;
  finally
    List.Free;
  end;
end;

function TGTermSessionManager.TerminateSessionById(ASessionId: UInt64): Boolean;
begin
  Result := False;
  TMonitor.Enter(FLock);
  try
    if FSessions.ContainsKey(Pointer(ASessionId)) then
      Result := True;
  finally
    TMonitor.Exit(FLock);
  end;
  if Result then
    UnregisterAndFreeSession(Pointer(ASessionId));
end;

end.
