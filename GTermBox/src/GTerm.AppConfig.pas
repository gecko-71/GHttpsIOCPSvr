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
  System.SysUtils, System.Classes, System.JSON, System.IOUtils,
  System.Generics.Collections,
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
  end;

  TGTermAppConfig = class
  private
    FApps: TArray<TAppEntry>;
    class var FInstance: TGTermAppConfig;
    class function GetInstance: TGTermAppConfig; static;
    function ParseSandbox(const S: string): TSandboxMode;
  public
    procedure LoadFromFile(const APath: string);
    function FindById(const AId: string; out AEntry: TAppEntry): Boolean;
    function FindByIndex(AIndex: Integer; out AEntry: TAppEntry): Boolean;
    function AppCount: Integer;
    function GetDefaultProfile(const ASandboxDir: string = ''): TGTermAppProfile;
    function GetDefaultAppId: string;
    function CanRoleAccessApp(const ARole: string; const AAppId: string): Boolean;
    class property Instance: TGTermAppConfig read GetInstance;
    class destructor Destroy;
  end;

implementation

class destructor TGTermAppConfig.Destroy;
begin
  FreeAndNil(FInstance);
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
  else if Lower = 'standard' then
    Result := smStandard
  else
    Result := smNone;
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
begin
  SetLength(FApps, 0);

  if not FileExists(APath) then
  begin
    Logger.Warn(Format('[Config] apps.json not found at: %s — using hardcoded defaults', [APath]));
    Exit;
  end;

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

      SetLength(FApps, AppsArr.Count);
      for I := 0 to AppsArr.Count - 1 do
      begin
        AppObj := AppsArr.Items[I] as TJSONObject;
        Entry.Id          := AppObj.GetValue<string>('id', '');
        Entry.Name        := AppObj.GetValue<string>('name', Entry.Id);
        Entry.Command     := AppObj.GetValue<string>('command', '');
        Entry.WorkingDir  := AppObj.GetValue<string>('workingDir', '');
        Entry.Cols        := AppObj.GetValue<Integer>('cols', 80);
        Entry.Rows        := AppObj.GetValue<Integer>('rows', 25);
        Entry.Sandbox     := ParseSandbox(AppObj.GetValue<string>('sandbox', 'none'));
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

        FApps[I] := Entry;
      end;

      Logger.Info(Format('[Config] Loaded %d apps from %s', [Length(FApps), APath]));
      for I := 0 to High(FApps) do
        Logger.Info(Format('[Config]   [%s] %s (%s) sandbox=%d',
          [FApps[I].Id, FApps[I].Name, FApps[I].Command, Ord(FApps[I].Sandbox)]));

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
  if (AIndex >= 0) and (AIndex < Length(FApps)) then
  begin
    AEntry := FApps[AIndex];
    Exit(True);
  end;
  Result := False;
end;

function TGTermAppConfig.FindById(const AId: string; out AEntry: TAppEntry): Boolean;
var
  I: Integer;
  Lower: string;
begin
  Lower := LowerCase(AId);
  for I := 0 to High(FApps) do
  begin
    if LowerCase(FApps[I].Id) = Lower then
    begin
      AEntry := FApps[I];
      Exit(True);
    end;
  end;
  Result := False;
end;

function TGTermAppConfig.AppCount: Integer;
begin
  Result := Length(FApps);
end;

function TGTermAppConfig.GetDefaultProfile(const ASandboxDir: string = ''): TGTermAppProfile;
begin
  if Length(FApps) > 0 then
    Result := FApps[0].ToProfile(ASandboxDir)
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
  if Length(FApps) > 0 then
    Result := FApps[0].Id
  else
    Result := 'cmd';
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

function TAppEntry.ToProfile(const ASandboxDir: string = ''): TGTermAppProfile;
var
  ExeDir: string;
  FullCmd: string;
  FullWorkDir: string;
  I: Integer;
  Arg: string;
  ArgsStr: string;
  ActualSandbox: string;
begin
  ExeDir := ExtractFilePath(ParamStr(0));

  FullCmd := Command;
  if not TPath.IsPathRooted(FullCmd) then
  begin
    if FileExists(ExeDir + FullCmd) or DirectoryExists(ExeDir + FullCmd) then
      FullCmd := ExeDir + FullCmd;
  end;

  if ASandboxDir <> '' then
    ActualSandbox := ASandboxDir
  else
    ActualSandbox := WorkingDir;

  if ActualSandbox <> '' then
  begin
    if not TPath.IsPathRooted(ActualSandbox) then
      FullWorkDir := ExeDir + ActualSandbox
    else
      FullWorkDir := ActualSandbox;
    ForceDirectories(FullWorkDir);
  end
  else
    FullWorkDir := ExeDir;

  ArgsStr := '';
  for I := 0 to High(Args) do
  begin
    Arg := Args[I];
    if ASandboxDir <> '' then
    begin
      if WorkingDir <> '' then
        Arg := StringReplace(Arg, WorkingDir, FullWorkDir, [rfReplaceAll, rfIgnoreCase]);
      Arg := StringReplace(Arg, '%SANDBOX%', FullWorkDir, [rfReplaceAll, rfIgnoreCase]);
    end;

    if (Arg = '.') or (Arg = '.\') then
      Arg := FullWorkDir
    else if (Arg <> '') and not Arg.StartsWith('-') and not Arg.StartsWith('/') and
       not TPath.IsPathRooted(Arg) and not Arg.StartsWith('.') and
       (DirectoryExists(ExeDir + Arg) or FileExists(ExeDir + Arg)) then
      Arg := ExeDir + Arg;

    if Arg.StartsWith('-') or Arg.StartsWith('/') then
      ArgsStr := ArgsStr + ' ' + Arg
    else
      ArgsStr := ArgsStr + ' "' + Arg + '"';
  end;

  Result.ProfileName      := Name;
  Result.CommandLine      := '"' + FullCmd + '"' + ArgsStr;
  Result.WorkingDirectory := FullWorkDir;
  Result.EnvironmentVars  := Env;
  Result.DefaultCols      := Cols;
  Result.DefaultRows      := Rows;
  Result.Sandbox          := Sandbox;
  Result.NetworkAccess    := Network;
  Result.AllowedDirsRead  := AllowedDirsRead;
  Result.AllowedDirsWrite := AllowedDirsWrite;
  Result.Roles            := Roles;
end;

end.
