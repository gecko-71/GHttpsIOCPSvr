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
unit GTerm.AppConfig;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.JSON, System.IOUtils,
  System.Generics.Collections, System.SyncObjs,
  Quick.Logger, GTerm.Types;

type
  TAppEntry = record
    Id: string;
    Name: string;
    Command: string;
    Args: TArray<string>;
    WorkingDir: string;
    Env: TArray<string>;
    Cols: Integer;
    Rows: Integer;
    Sandbox: TSandboxMode;
    Network: Boolean;
    AllowedDirsRead: TArray<string>;
    AllowedDirsWrite: TArray<string>;
    Roles: TArray<string>;
    function ToProfile(const ASandboxDir: string = ''): TGTermAppProfile;
    function IsExecutableAvailable: Boolean;
  end;

  TGTermAppConfig = class
  private
    FLock: TCriticalSection;
    FLastCheckTick: UInt64;
    FApps: TArray<TAppEntry>;
    FConfigPath: string;
    FLastWriteTime: TDateTime;
    class var FInstance: TGTermAppConfig;
    class function GetInstance: TGTermAppConfig; static;
    function ParseSandbox(const S: string): TSandboxMode;
    procedure CheckReload;
  public
    constructor Create;
    destructor Destroy; override;
    procedure LoadFromFile(const APath: string);
    function FindById(const AId: string; out AEntry: TAppEntry): Boolean;
    function FindByIndex(AIndex: Integer; out AEntry: TAppEntry): Boolean;
    function AppCount: Integer;
    function GetDefaultProfile(const ASandboxDir: string = ''): TGTermAppProfile;
    function GetDefaultAppId: string;
    function CanRoleAccessApp(const ARole: string; const AAppId: string): Boolean;
    class property Instance: TGTermAppConfig read GetInstance;
  end;

procedure DeployAppToSandbox(const ASrcDir, ADstDir: string);

implementation

constructor TGTermAppConfig.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FLastCheckTick := 0;
  SetLength(FApps, 0);
end;

destructor TGTermAppConfig.Destroy;
begin
  FLock.Free;
  SetLength(FApps, 0);
  inherited Destroy;
end;

class function TGTermAppConfig.GetInstance: TGTermAppConfig;
begin
  if FInstance = nil then
    FInstance := TGTermAppConfig.Create;
  Result := FInstance;
end;

function TGTermAppConfig.ParseSandbox(const S: string): TSandboxMode;
var
  Lower: string;
begin
  Lower := LowerCase(Trim(S));
  if Lower = 'job-only' then
    Result := smJobOnly
  else if Lower = 'none' then
    Result := smNone
  else
    Result := smStandard;
end;

procedure TGTermAppConfig.CheckReload;
var
  CurrTime: TDateTime;
  NowTick: UInt64;
  ShouldReload: Boolean;
begin
  if FConfigPath = '' then Exit;
  NowTick := GetTickCount64;
  if (FLastCheckTick <> 0) and (NowTick - FLastCheckTick < 500) then
    Exit;

  ShouldReload := False;
  FLock.Enter;
  try
    NowTick := GetTickCount64;
    if (FLastCheckTick <> 0) and (NowTick - FLastCheckTick < 500) then
      Exit;
    FLastCheckTick := NowTick;

    if FileExists(FConfigPath) then
    begin
      if FileAge(FConfigPath, CurrTime) and (CurrTime <> FLastWriteTime) then
        ShouldReload := True;
    end;
  finally
    FLock.Leave;
  end;

  if ShouldReload then
    LoadFromFile(FConfigPath);
end;

procedure TGTermAppConfig.LoadFromFile(const APath: string);
var
  JsonText: string;
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  EnvArr: TJSONArray;
  ArgsArr: TJSONArray;
  JsonVal: TJSONValue;
  Entry: TAppEntry;
  I, J: Integer;
  NewApps: TArray<TAppEntry>;
  NewWriteTime: TDateTime;
begin
  if not FileExists(APath) then
  begin
    Logger.Warn(Format('[Config] apps.json not found at: %s — using hardcoded defaults', [APath]));
    Exit;
  end;

  FileAge(APath, NewWriteTime);

  try
    with TStringList.Create do
    try
      LoadFromFile(APath, TEncoding.UTF8);
      JsonText := Text;
    finally
      Free;
    end;

    Root := TJSONObject.ParseJSONValue(JsonText) as TJSONObject;
    if Root = nil then
    begin
      Logger.Error('[Config] Failed to parse apps.json — invalid JSON');
      Exit;
    end;

    try
      AppsArr := Root.GetValue<TJSONArray>('apps');
      if AppsArr = nil then
      begin
        Logger.Warn('[Config] apps.json has no "apps" array');
        Exit;
      end;

      SetLength(NewApps, AppsArr.Count);
      for I := 0 to AppsArr.Count - 1 do
      begin
        AppObj := AppsArr.Items[I] as TJSONObject;
        Entry.Id          := AppObj.GetValue<string>('id', '');
        Entry.Name        := AppObj.GetValue<string>('name', Entry.Id);
        Entry.Command     := AppObj.GetValue<string>('command', '');
        Entry.WorkingDir  := AppObj.GetValue<string>('workingDir', '');
        Entry.Cols        := AppObj.GetValue<Integer>('cols', 80);
        Entry.Rows        := AppObj.GetValue<Integer>('rows', 25);
        Entry.Sandbox     := ParseSandbox(AppObj.GetValue<string>('sandbox', 'standard'));
        Entry.Network     := AppObj.GetValue<Boolean>('network', False);

        JsonVal := AppObj.FindValue('allowedDirs');
        if (JsonVal <> nil) and (JsonVal is TJSONArray) then
        begin
          var DirArr := TJSONArray(JsonVal);
          SetLength(Entry.AllowedDirsRead, DirArr.Count);
          for J := 0 to DirArr.Count - 1 do
            Entry.AllowedDirsRead[J] := DirArr.Items[J].Value;
        end
        else
          SetLength(Entry.AllowedDirsRead, 0);

        JsonVal := AppObj.FindValue('allowedDirsWrite');
        if (JsonVal <> nil) and (JsonVal is TJSONArray) then
        begin
          var DirWArr := TJSONArray(JsonVal);
          SetLength(Entry.AllowedDirsWrite, DirWArr.Count);
          for J := 0 to DirWArr.Count - 1 do
            Entry.AllowedDirsWrite[J] := DirWArr.Items[J].Value;
        end
        else
          SetLength(Entry.AllowedDirsWrite, 0);

        JsonVal := AppObj.FindValue('roles');
        if (JsonVal <> nil) and (JsonVal is TJSONArray) then
        begin
          var RolesArr := TJSONArray(JsonVal);
          SetLength(Entry.Roles, RolesArr.Count);
          for J := 0 to RolesArr.Count - 1 do
            Entry.Roles[J] := RolesArr.Items[J].Value;
        end
        else
          Entry.Roles := ['admin', 'user'];

        JsonVal := AppObj.FindValue('env');
        if (JsonVal <> nil) and (JsonVal is TJSONArray) then
        begin
          EnvArr := TJSONArray(JsonVal);
          SetLength(Entry.Env, EnvArr.Count);
          for J := 0 to EnvArr.Count - 1 do
            Entry.Env[J] := EnvArr.Items[J].Value;
        end
        else
          SetLength(Entry.Env, 0);

        JsonVal := AppObj.FindValue('args');
        if (JsonVal <> nil) and (JsonVal is TJSONArray) then
        begin
          ArgsArr := TJSONArray(JsonVal);
          SetLength(Entry.Args, ArgsArr.Count);
          for J := 0 to ArgsArr.Count - 1 do
            Entry.Args[J] := ArgsArr.Items[J].Value;
        end
        else
          SetLength(Entry.Args, 0);

        NewApps[I] := Entry;
      end;

      FLock.Enter;
      try
        FConfigPath := APath;
        FLastWriteTime := NewWriteTime;
        FApps := NewApps;
      finally
        FLock.Leave;
      end;

      Logger.Info(Format('[Config] Loaded %d apps from %s', [Length(NewApps), APath]));

    finally
      Root.Free;
    end;

  except
    on E: Exception do
      Logger.Error(Format('[Config] Error loading apps.json: %s', [E.Message]));
  end;
end;

function TGTermAppConfig.FindByIndex(AIndex: Integer; out AEntry: TAppEntry): Boolean;
begin
  CheckReload;
  FLock.Enter;
  try
    if (AIndex >= 0) and (AIndex < Length(FApps)) then
    begin
      AEntry := FApps[AIndex];
      Exit(True);
    end;
    Result := False;
  finally
    FLock.Leave;
  end;
end;

function TGTermAppConfig.FindById(const AId: string; out AEntry: TAppEntry): Boolean;
var
  I: Integer;
  Lower: string;
begin
  CheckReload;
  Lower := LowerCase(AId);
  FLock.Enter;
  try
    for I := 0 to High(FApps) do
    begin
      if LowerCase(FApps[I].Id) = Lower then
      begin
        AEntry := FApps[I];
        Exit(True);
      end;
    end;
    Result := False;
  finally
    FLock.Leave;
  end;
end;

function TGTermAppConfig.AppCount: Integer;
begin
  CheckReload;
  FLock.Enter;
  try
    Result := Length(FApps);
  finally
    FLock.Leave;
  end;
end;

function TGTermAppConfig.GetDefaultProfile(const ASandboxDir: string = ''): TGTermAppProfile;
var
  HaveApp: Boolean;
  FirstApp: TAppEntry;
begin
  CheckReload;
  FLock.Enter;
  try
    HaveApp := Length(FApps) > 0;
    if HaveApp then
      FirstApp := FApps[0];
  finally
    FLock.Leave;
  end;

  if HaveApp then
    Result := FirstApp.ToProfile(ASandboxDir)
  else
  begin
    Result.ProfileName := 'Command Prompt';
    Result.CommandLine := 'cmd.exe';
    Result.WorkingDirectory := ExtractFilePath(ParamStr(0));
    Result.EnvironmentVars := ['TERM=xterm-256color', 'COLORTERM=truecolor'];
    Result.DefaultCols := 120;
    Result.DefaultRows := 30;
    Result.Sandbox := smStandard;
    Result.NetworkAccess := False;
    SetLength(Result.AllowedDirsRead, 0);
    SetLength(Result.AllowedDirsWrite, 0);
    Result.Roles := ['admin', 'user'];
  end;
end;

function TGTermAppConfig.GetDefaultAppId: string;
begin
  CheckReload;
  FLock.Enter;
  try
    if Length(FApps) > 0 then
      Result := FApps[0].Id
    else
      Result := 'cmd';
  finally
    FLock.Leave;
  end;
end;

function TGTermAppConfig.CanRoleAccessApp(const ARole: string; const AAppId: string): Boolean;
var
  App: TAppEntry;
  I: Integer;
  RoleLower: string;
begin
  Result := False;
  if not FindById(AAppId, App) then Exit;
  if Length(App.Roles) = 0 then Exit(True);
  RoleLower := LowerCase(Trim(ARole));
  for I := 0 to High(App.Roles) do
  begin
    if (App.Roles[I] = '*') or (LowerCase(Trim(App.Roles[I])) = RoleLower) then
      Exit(True);
  end;
end;

procedure DeployAppToSandbox(const ASrcDir, ADstDir: string);
var
  SearchRec: TSearchRec;
  SrcItem, DstItem: string;
begin
  if not TDirectory.Exists(ADstDir) then
    TDirectory.CreateDirectory(ADstDir);

  if FindFirst(TPath.Combine(ASrcDir, '*'), faAnyFile, SearchRec) = 0 then
  begin
    try
      repeat
        if (SearchRec.Name <> '.') and (SearchRec.Name <> '..') then
        begin
          SrcItem := TPath.Combine(ASrcDir, SearchRec.Name);
          DstItem := TPath.Combine(ADstDir, SearchRec.Name);
          if (SearchRec.Attr and faDirectory) <> 0 then
            DeployAppToSandbox(SrcItem, DstItem)
          else
          begin
            if not FileExists(DstItem) then
            begin
              CopyFileW(PChar(SrcItem), PChar(DstItem), False);
            end;
          end;
        end;
      until FindNext(SearchRec) <> 0;
    finally
      FindClose(SearchRec);
    end;
  end;
end;

function TAppEntry.ToProfile(const ASandboxDir: string = ''): TGTermAppProfile;
var
  ExeDir: string;
  FullCmd: string;
  FullWorkDir: string;
  I: Integer;
  Arg: string;
  ArgsStr: string;
  ActualSandbox: string;
  MasterAppDir: string;
  SandboxAppDir: string;
begin
  ExeDir := ExtractFilePath(ParamStr(0));

  if ASandboxDir <> '' then
    ActualSandbox := ASandboxDir
  else
    ActualSandbox := WorkingDir;

  if ActualSandbox <> '' then
  begin
    if not TPath.IsPathRooted(ActualSandbox) then
      FullWorkDir := TPath.Combine(ExeDir, ActualSandbox)
    else
      FullWorkDir := ActualSandbox;
    ForceDirectories(FullWorkDir);
  end
  else
    FullWorkDir := ExeDir;

  ArgsStr := '';
  FullCmd := Command;
  if SameText(FullCmd, 'python.exe') and FileExists(TPath.Combine(ExeDir, 'Python\python.exe')) then
    FullCmd := 'Python\python.exe';

  if not TPath.IsPathRooted(FullCmd) then
  begin
    if FileExists(TPath.Combine(ExeDir, FullCmd)) or DirectoryExists(TPath.Combine(ExeDir, FullCmd)) then
    begin
      MasterAppDir := ExtractFilePath(TPath.Combine(ExeDir, FullCmd));
      if (ActualSandbox <> '') and DirectoryExists(MasterAppDir) then
      begin
        SandboxAppDir := TPath.Combine(FullWorkDir, 'apps\' + LowerCase(Id));
        DeployAppToSandbox(MasterAppDir, SandboxAppDir);
        FullCmd := TPath.Combine(SandboxAppDir, ExtractFileName(FullCmd));
      end
      else
        FullCmd := TPath.Combine(ExeDir, FullCmd);
    end
    else
    begin
      var SBuf: array[0..MAX_PATH] of Char;
      var SFPart: PChar;
      if SearchPath(nil, PChar(FullCmd), nil, MAX_PATH, SBuf, SFPart) > 0 then
        FullCmd := PChar(@SBuf[0]);
    end;
  end;

  if SameText(Id, 'pytui') then
  begin
    var LocalPyDir := TPath.Combine(ExeDir, 'Python');
    if (ActualSandbox <> '') and DirectoryExists(LocalPyDir) then
    begin
      var SandboxPyDir := TPath.Combine(FullWorkDir, 'apps\python');
      DeployAppToSandbox(LocalPyDir, SandboxPyDir);
      var SandboxPyExe := TPath.Combine(SandboxPyDir, 'python.exe');
      var SandboxAppPy := TPath.Combine(ExtractFilePath(FullCmd), 'app.py');
      if FileExists(SandboxPyExe) and FileExists(SandboxAppPy) then
      begin
        FullCmd := SandboxPyExe;
        ArgsStr := ' "' + SandboxAppPy + '"';
      end;
    end
    else if DirectoryExists(LocalPyDir) then
    begin
      var HostPyExe := TPath.Combine(LocalPyDir, 'python.exe');
      var HostAppPy := TPath.Combine(ExtractFilePath(FullCmd), 'app.py');
      if FileExists(HostPyExe) and FileExists(HostAppPy) then
      begin
        FullCmd := HostPyExe;
        ArgsStr := ' "' + HostAppPy + '"';
      end;
    end;
  end;

  if (Pos('far.exe', LowerCase(FullCmd)) > 0) or SameText(Id, 'far') then
  begin
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile'));
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile\local'));
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile\PluginsData'));
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile\local\PluginsData'));
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile\Menus'));
    ForceDirectories(TPath.Combine(FullWorkDir, 'profile\Macros\scripts'));
  end;

  for I := 0 to High(Args) do
  begin
    Arg := Args[I];
    if WorkingDir <> '' then
      Arg := StringReplace(Arg, WorkingDir, FullWorkDir, [rfReplaceAll, rfIgnoreCase]);
    Arg := StringReplace(Arg, '%SANDBOX%', FullWorkDir, [rfReplaceAll, rfIgnoreCase]);

    if (Arg = '.') or (Arg = '.\') then
      Arg := FullWorkDir
    else if (Arg <> '') and not Arg.StartsWith('-') and not Arg.StartsWith('/') and
       not TPath.IsPathRooted(Arg) and not Arg.StartsWith('.') and
       (DirectoryExists(ExeDir + Arg) or FileExists(ExeDir + Arg)) then
      Arg := ExeDir + Arg;

    var EscArg: string;
    EscArg := StringReplace(Arg, '"', '\"', [rfReplaceAll]);
    if (EscArg = '') or (Pos(' ', EscArg) > 0) or (Pos('"', Arg) > 0) or not (Arg.StartsWith('-') or Arg.StartsWith('/')) then
      ArgsStr := ArgsStr + ' "' + EscArg + '"'
    else
      ArgsStr := ArgsStr + ' ' + EscArg;
  end;

  Result.ProfileName      := Name;
  Result.CommandLine      := '"' + FullCmd + '"' + ArgsStr;
  Result.WorkingDirectory := FullWorkDir;
  SetLength(Result.EnvironmentVars, Length(Env));
  for I := 0 to High(Env) do
  begin
    Arg := Env[I];
    if ASandboxDir <> '' then
      Arg := StringReplace(Arg, '%SANDBOX%', FullWorkDir, [rfReplaceAll, rfIgnoreCase]);
    Result.EnvironmentVars[I] := Arg;
  end;
  Result.DefaultCols      := Cols;
  Result.DefaultRows      := Rows;
  Result.Sandbox          := Sandbox;
  Result.NetworkAccess    := Network;
  Result.AllowedDirsRead  := AllowedDirsRead;
  Result.AllowedDirsWrite := AllowedDirsWrite;
  Result.Roles            := Roles;
end;

function TAppEntry.IsExecutableAvailable: Boolean;
var
  ExeDir: string;
  Cmd: string;
  WinDir: string;
  SysDir: string;
begin
  ExeDir := ExtractFilePath(ParamStr(0));
  Cmd := Command;
  if TPath.IsPathRooted(Cmd) then
    Exit(FileExists(Cmd));

  if FileExists(ExeDir + Cmd) then
    Exit(True);

  if (Pos('\', Cmd) = 0) and (Pos('/', Cmd) = 0) then
  begin
    WinDir := GetEnvironmentVariable('WINDIR');
    SysDir := WinDir + '\System32\';
    if FileExists(SysDir + Cmd) or
       FileExists(SysDir + 'WindowsPowerShell\v1.0\' + Cmd) or
       (FileSearch(Cmd, GetEnvironmentVariable('PATH')) <> '') then
      Exit(True);
  end;

  Result := False;
end;

initialization

finalization
  if TGTermAppConfig.FInstance <> nil then
  begin
    TGTermAppConfig.FInstance.Free;
    TGTermAppConfig.FInstance := nil;
  end;

end.
