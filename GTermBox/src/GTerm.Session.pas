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
  GTerm.ConPty,
  MsQuic.Types,
  WebTransport.Types,
  WebTransport.Session;

type
  TGTermSession = class
  private
    FWTSession: TWTSessionContext;
    FWTStream: HQUIC;
    FConPty: TGTermConPty;
    FCols: Integer;
    FRows: Integer;
    FProfile: TGTermAppProfile;
    FClosed: Boolean;
    FStopping: Integer;
    FSessionLock: TCriticalSection;
    FConnectedTick: UInt64;
    FLastActivityTick: UInt64;
    procedure HandlePtyDataReceived(const AData: TBytes; ACount: Integer);
    procedure HandleProcessTerminated(AExitCode: DWORD);
    procedure SendClientText(const AText: string);
    procedure ProcessSingleClientMessage(const AMessageText: string);
  public
    constructor Create(AWTSession: PWTSessionContext; const AProfile: TGTermAppProfile);
    destructor Destroy; override;
    procedure SetWTStream(ASession: PWTSessionContext; AStream: HQUIC);
    procedure Start;
    procedure Stop;
    procedure SwitchProfile(const AAppKey: string);
    procedure ProcessClientMessage(const AMessageText: string);
    procedure SendInitialScreen;
    property Closed: Boolean read FClosed;
    property ConnectedTick: UInt64 read FConnectedTick;
    property LastActivityTick: UInt64 read FLastActivityTick;
    property WTStream: HQUIC read FWTStream;
    property ConPty: TGTermConPty read FConPty;
    property Profile: TGTermAppProfile read FProfile;
    property Cols: Integer read FCols;
    property Rows: Integer read FRows;
  end;

  TGTermSessionInfo = record
    SessionId: UInt64;
    AppKey: string;
    ProfileName: string;
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
    procedure UnregisterAndFreeSession(SessionKey: Pointer);
    function GetSessionSnapshots: TArray<TGTermSessionInfo>;
    function TerminateSessionById(ASessionId: UInt64): Boolean;
    procedure CheckSessions;
    procedure Clear;
    property IdleTimeoutMs: Cardinal read FIdleTimeoutMs write FIdleTimeoutMs;
  end;

implementation

constructor TGTermSession.Create(AWTSession: PWTSessionContext; const AProfile: TGTermAppProfile);
begin
  inherited Create;
  if AWTSession <> nil then
    FWTSession := AWTSession^
  else
    FWTSession := Default(TWTSessionContext);
  FWTStream := nil;
  FProfile := AProfile;
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

procedure TGTermSession.SetWTStream(ASession: PWTSessionContext; AStream: HQUIC);
var
  IsNewStream: Boolean;
begin
  IsNewStream := (FWTStream = nil) or (FWTStream <> AStream);
  if ASession <> nil then
    FWTSession := ASession^;
  FWTStream := AStream;
  FLastActivityTick := GetTickCount64;
  if not FConPty.Running then
    Start;
  if IsNewStream then
    SendInitialScreen;
end;

procedure TGTermSession.Start;
begin
  if not FConPty.Running then
  begin
    FConPty.SandboxMode := FProfile.Sandbox;
    FConPty.OnDataReceived := HandlePtyDataReceived;
    FConPty.OnProcessTerminated := HandleProcessTerminated;
    Logger.Info(Format('[Session] Starting session for profile "%s" (Command: %s) sandbox=%d net=%s',
      [FProfile.ProfileName, FProfile.CommandLine, Ord(FProfile.Sandbox), IfThen(FProfile.NetworkAccess, 'true', 'false')]));
    FConPty.StartProcess(FProfile.CommandLine, FProfile.WorkingDirectory, FProfile.AllowedDirsRead, FProfile.AllowedDirsWrite, FProfile.EnvironmentVars, FProfile.NetworkAccess);
  end;
end;

procedure TGTermSession.SwitchProfile(const AAppKey: string);
var
  Entry: TAppEntry;
  WantedProfile: TGTermAppProfile;
  CurrentSandbox: string;
begin
  CurrentSandbox := ExtractFileName(FProfile.WorkingDirectory);
  if TGTermAppConfig.Instance.FindById(AAppKey, Entry) then
    WantedProfile := Entry.ToProfile(CurrentSandbox)
  else
    WantedProfile := TGTermAppConfig.Instance.GetDefaultProfile(CurrentSandbox);

  if FProfile.ProfileName <> WantedProfile.ProfileName then
  begin
    if FConPty.Running then
      FConPty.StopProcess;
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
begin
  if Assigned(FSessionLock) then
    FSessionLock.Enter;
  try
    if TInterlocked.CompareExchange(FStopping, 1, 0) <> 0 then Exit;
    FClosed := True;
    StreamToClose := FWTStream;
    FWTStream := nil;
    if StreamToClose <> nil then
    begin
      SetLength(DataBytes, 0);
      try
        FWTSession.SendOnStream(StreamToClose, DataBytes, True);
        FWTSession.Close;
      except
      end;
    end;
    if Assigned(FConPty) then
    begin
      FConPty.OnDataReceived := nil;
      FConPty.OnProcessTerminated := nil;
      FConPty.StopProcess;
    end;
  finally
    if Assigned(FSessionLock) then
      FSessionLock.Leave;
  end;
end;

procedure TGTermSession.SendClientText(const AText: string);
var
  DataBytes: TBytes;
begin
  if FClosed or (AText = '') or (FWTStream = nil) then Exit;

  FLastActivityTick := GetTickCount64;
  DataBytes := TEncoding.UTF8.GetBytes(AText + #10);
  FWTSession.SendOnStream(FWTStream, DataBytes, False);
end;

procedure TGTermSession.SendInitialScreen;
begin
  if FClosed or (FWTStream = nil) then Exit;
  if Assigned(FConPty) and FConPty.Running then
    FConPty.Resize(FCols, FRows);
end;

procedure TGTermSession.HandlePtyDataReceived(const AData: TBytes; ACount: Integer);
begin
  if FClosed or (FStopping <> 0) or (Length(AData) = 0) then Exit;

  if FWTStream <> nil then
    FWTSession.SendOnStream(FWTStream, AData, False);
end;

procedure TGTermSession.HandleProcessTerminated(AExitCode: DWORD);
begin
  Logger.Warn(Format('[Session] Process terminated with exit code %d', [AExitCode]));
  SendClientText('{"type":"logout","reason":"terminated"}');
  Stop;
end;

procedure TGTermSession.ProcessClientMessage(const AMessageText: string);
var
  CleanText: string;
begin
  if FClosed or (AMessageText = '') then Exit;
  FLastActivityTick := GetTickCount64;

  CleanText := Trim(AMessageText);
  if (CleanText <> '') and (CleanText[1] = '{') and (CleanText[Length(CleanText)] = '}') then
    ProcessSingleClientMessage(CleanText)
  else
    FConPty.WriteInput(AMessageText);
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
      if InputStr <> '' then
        FConPty.WriteInput(InputStr);
    end
    else if MsgType = 'resize' then
    begin
      NewCols := JsonObj.GetValue<Integer>('cols', FCols);
      NewRows := JsonObj.GetValue<Integer>('rows', FRows);
      if (NewCols > 0) and (NewRows > 0) then
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
    Session.Free;
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
  Session: TGTermSession;
begin
  if (Self = nil) or (FLock = nil) or (FSessions = nil) then Exit;
  TMonitor.Enter(FLock);
  try
    for Session in FSessions.Values do
    begin
      if Assigned(Session) then
      begin
        Session.Stop;
        Session.Free;
      end;
    end;
    FSessions.Clear;
  finally
    TMonitor.Exit(FLock);
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
