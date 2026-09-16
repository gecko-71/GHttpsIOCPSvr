program ManageUsers;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.Hash,
  System.StrUtils,
  System.Generics.Collections;

function GetExeDir: string;
begin
  Result := ExtractFilePath(ParamStr(0));
  if Result = '' then
    Result := GetCurrentDir;
end;

function GetUsersPath: string;
begin
  Result := TPath.Combine(GetExeDir, 'users.json');
end;

function GetAppsPath: string;
begin
  Result := TPath.Combine(GetExeDir, 'apps.json');
end;

function ComputeHash(const ASalt, APassword: string): string;
begin
  Result := LowerCase(THashSHA2.GetHashString(ASalt + ':' + APassword, THashSHA2.TSHA2Version.SHA256));
end;

function GenerateSalt(const AUsername: string): string;
var
  G: string;
begin
  G := TGUID.NewGuid.ToString.Trim(['{', '}']).Replace('-', '').ToLower;
  Result := Format('salt_%s_%s', [LowerCase(AUsername), Copy(G, 1, 10)]);
end;

procedure BackupFile(const AFilePath: string);
var
  Dir, BaseName, Ext, Prefix, Candidate: string;
  Idx: Integer;
begin
  if not FileExists(AFilePath) then
    Exit;
  Dir := ExtractFilePath(AFilePath);
  BaseName := ExtractFileName(AFilePath);
  Ext := ExtractFileExt(AFilePath);
  Prefix := ChangeFileExt(BaseName, '');
  Idx := 1;
  while True do
  begin
    Candidate := TPath.Combine(Dir, Format('%s_v%d%s', [Prefix, Idx, Ext]));
    if not FileExists(Candidate) then
      Break;
    Inc(Idx);
  end;
  TFile.Copy(AFilePath, Candidate);
end;

function SplitComma(const AText: string): TArray<string>;
var
  Parts: TArray<string>;
  I, Count: Integer;
  S: string;
begin
  Parts := AText.Split([',']);
  Count := 0;
  SetLength(Result, Length(Parts));
  for I := 0 to High(Parts) do
  begin
    S := Trim(Parts[I]);
    if S <> '' then
    begin
      Result[Count] := S;
      Inc(Count);
    end;
  end;
  SetLength(Result, Count);
end;

function ArrayToJsonArray(const AArr: TArray<string>): TJSONArray;
var
  I: Integer;
begin
  Result := TJSONArray.Create;
  for I := 0 to High(AArr) do
    Result.Add(AArr[I]);
end;

function JsonArrayToArray(AJsonArr: TJSONArray): TArray<string>;
var
  I: Integer;
begin
  if AJsonArr = nil then
    Exit(nil);
  SetLength(Result, AJsonArr.Count);
  for I := 0 to AJsonArr.Count - 1 do
    Result[I] := AJsonArr.Items[I].Value;
end;

function LoadRootObject(const AFilePath: string): TJSONObject;
var
  RawBytes: TBytes;
  Content: string;
  Val: TJSONValue;
begin
  Result := nil;
  if not FileExists(AFilePath) then
    Exit;
  RawBytes := TFile.ReadAllBytes(AFilePath);
  Content := TEncoding.UTF8.GetString(RawBytes);
  if (Length(Content) > 0) and (Content[1] = #$FEFF) then
    Content := Copy(Content, 2, MaxInt);
  Val := TJSONObject.ParseJSONValue(Content);
  if Val is TJSONObject then
    Result := Val as TJSONObject
  else if Assigned(Val) then
    Val.Free;
end;

procedure SaveRootObject(const AFilePath: string; ARoot: TJSONObject);
var
  RawBytes: TBytes;
begin
  BackupFile(AFilePath);
  RawBytes := TEncoding.UTF8.GetBytes(ARoot.Format(2) + sLineBreak);
  TFile.WriteAllBytes(AFilePath, RawBytes);
end;

function FindObj(AObj: TJSONObject; const AName: string): TJSONObject;
var
  Val: TJSONValue;
begin
  Result := nil;
  if AObj = nil then Exit;
  Val := AObj.FindValue(AName);
  if Val is TJSONObject then
    Result := TJSONObject(Val);
end;

function FindArr(AObj: TJSONObject; const AName: string): TJSONArray;
var
  Val: TJSONValue;
begin
  Result := nil;
  if AObj = nil then Exit;
  Val := AObj.FindValue(AName);
  if Val is TJSONArray then
    Result := TJSONArray(Val);
end;

function GetStr(AObj: TJSONObject; const AName: string; const ADefault: string = ''): string;
var
  Val: TJSONValue;
begin
  Result := ADefault;
  if AObj = nil then Exit;
  Val := AObj.FindValue(AName);
  if Val <> nil then
    Result := Val.Value;
end;

function GetBool(AObj: TJSONObject; const AName: string; ADefault: Boolean = False): Boolean;
var
  Val: TJSONValue;
begin
  Result := ADefault;
  if AObj = nil then Exit;
  Val := AObj.FindValue(AName);
  if Val is TJSONTrue then
    Result := True
  else if Val is TJSONFalse then
    Result := False
  else if Val <> nil then
    Result := SameText(Val.Value, 'true');
end;

function GetInt(AObj: TJSONObject; const AName: string; ADefault: Integer = 0): Integer;
var
  Val: TJSONValue;
begin
  Result := ADefault;
  if AObj = nil then Exit;
  Val := AObj.FindValue(AName);
  if Val is TJSONNumber then
    Result := TJSONNumber(Val).AsInt
  else if Val <> nil then
    Result := StrToIntDef(Val.Value, ADefault);
end;

function LoadUsersArray(const AFilePath: string; out ARoot: TJSONObject): TJSONArray;
begin
  ARoot := LoadRootObject(AFilePath);
  if ARoot = nil then
    ARoot := TJSONObject.Create;
  Result := FindArr(ARoot, 'users');
  if Result = nil then
  begin
    Result := TJSONArray.Create;
    ARoot.AddPair('users', Result);
  end;
end;

function LoadAppsArray(const AFilePath: string; out ARoot: TJSONObject): TJSONArray;
begin
  ARoot := LoadRootObject(AFilePath);
  if ARoot = nil then
    ARoot := TJSONObject.Create;
  Result := FindArr(ARoot, 'apps');
  if Result = nil then
  begin
    Result := TJSONArray.Create;
    ARoot.AddPair('apps', Result);
  end;
end;

procedure ListUsers;
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj, GrantsObj: TJSONObject;
  I: Integer;
  UName, URole, USandbox, AppsStr, NetStr, JobStr: string;
  AppsArr: TJSONArray;
begin
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    if (UsersArr = nil) or (UsersArr.Count = 0) then
    begin
      Writeln('No users found in: ', GetUsersPath);
      Exit;
    end;

    Writeln(Format('%-12s %-8s %-5s %-8s %-16s %-24s', ['Username', 'Role', 'Net', 'JobOnly', 'Sandbox', 'Apps']));
    Writeln(StringOfChar('-', 75));
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      UName := GetStr(UserObj, 'username');
      URole := GetStr(UserObj, 'role', 'user');
      USandbox := GetStr(UserObj, 'sandbox');
      NetStr := 'YES';
      JobStr := 'NO';
      GrantsObj := FindObj(UserObj, 'grants');
      if GrantsObj <> nil then
      begin
        if not GetBool(GrantsObj, 'network', True) then
          NetStr := 'NO';
        if GetBool(GrantsObj, 'allowJobOnly', False) then
          JobStr := 'YES';
      end;
      AppsArr := FindArr(UserObj, 'apps');
      if AppsArr <> nil then
        AppsStr := string.Join(', ', JsonArrayToArray(AppsArr))
      else
        AppsStr := '*';
      Writeln(Format('%-12s %-8s %-5s %-8s %-16s %-24s', [UName, URole, NetStr, JobStr, USandbox, AppsStr]));
    end;
    Writeln;
    Writeln(Format('Total users: %d', [UsersArr.Count]));
    Writeln;
  finally
    Root.Free;
  end;
end;

procedure AddUser(const AUsername, APassword: string; const AApps: TArray<string>;
  const ASandbox, ARole: string; ANetwork, AAllowJobOnly, AFullDisk: Boolean;
  const ADirsRead, ADirsWrite: TArray<string>);
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj, GrantsObj: TJSONObject;
  ExistingIdx, I: Integer;
  Salt, PwdHash, FullSandbox: string;
  EffectiveRole, EffectiveSandbox: string;
  EffectiveApps, EffectiveDirsRead, EffectiveDirsWrite: TArray<string>;
  EffectiveJobOnly, EffectiveFullDisk: Boolean;
begin
  EffectiveRole := ARole;
  if EffectiveRole = '' then
    EffectiveRole := 'user';

  EffectiveSandbox := ASandbox;
  if EffectiveSandbox = '' then
    EffectiveSandbox := 'sandbox_' + AUsername;

  if Length(AApps) > 0 then
    EffectiveApps := AApps
  else
  begin
    if SameText(EffectiveRole, 'admin') then
      EffectiveApps := ['*']
    else
      EffectiveApps := ['far', 'edit', 'powershell'];
  end;

  if SameText(EffectiveRole, 'admin') then
  begin
    EffectiveJobOnly := True;
    EffectiveFullDisk := True;
    EffectiveDirsRead := ['*'];
    EffectiveDirsWrite := ['*'];
  end
  else
  begin
    EffectiveJobOnly := AAllowJobOnly;
    EffectiveFullDisk := AFullDisk;
    EffectiveDirsRead := ADirsRead;
    EffectiveDirsWrite := ADirsWrite;
  end;

  FullSandbox := TPath.Combine(GetExeDir, EffectiveSandbox);
  if not TDirectory.Exists(FullSandbox) then
  begin
    TDirectory.CreateDirectory(FullSandbox);
    Writeln('[OK] Created sandbox directory: ', FullSandbox);
  end;

  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Salt := GenerateSalt(AUsername);
    PwdHash := ComputeHash(Salt, APassword);

    UserObj := TJSONObject.Create;
    UserObj.AddPair('username', AUsername);
    UserObj.AddPair('role', EffectiveRole);
    UserObj.AddPair('salt', Salt);
    UserObj.AddPair('passwordHash', PwdHash);
    UserObj.AddPair('sandbox', EffectiveSandbox);
    UserObj.AddPair('apps', ArrayToJsonArray(EffectiveApps));

    GrantsObj := TJSONObject.Create;
    GrantsObj.AddPair('network', TJSONBool.Create(ANetwork));
    GrantsObj.AddPair('allowJobOnly', TJSONBool.Create(EffectiveJobOnly));
    GrantsObj.AddPair('fullDiskAccess', TJSONBool.Create(EffectiveFullDisk));
    GrantsObj.AddPair('allowedDirsRead', ArrayToJsonArray(EffectiveDirsRead));
    GrantsObj.AddPair('allowedDirsWrite', ArrayToJsonArray(EffectiveDirsWrite));
    UserObj.AddPair('grants', GrantsObj);

    ExistingIdx := -1;
    for I := 0 to UsersArr.Count - 1 do
    begin
      if SameText(GetStr(UsersArr.Items[I] as TJSONObject, 'username'), AUsername) then
      begin
        ExistingIdx := I;
        Break;
      end;
    end;

    if ExistingIdx >= 0 then
    begin
      UsersArr.Remove(ExistingIdx).Free;
      UsersArr.AddElement(UserObj);
      Writeln(Format('[OK] Updated existing user ''%s'' in %s', [AUsername, GetUsersPath]));
    end
    else
    begin
      UsersArr.AddElement(UserObj);
      Writeln(Format('[OK] Added new user ''%s'' to %s', [AUsername, GetUsersPath]));
    end;

    SaveRootObject(GetUsersPath, Root);

    Writeln;
    Writeln(Format('User ''%s'' successfully configured!', [AUsername]));
    Writeln('  Role:    ', EffectiveRole);
    Writeln('  Sandbox: ', EffectiveSandbox);
    Writeln('  Apps:    ', string.Join(', ', EffectiveApps));
    Writeln('  Salt:    ', Salt);
    Writeln('  Hash:    ', PwdHash);
    Writeln;
  finally
    Root.Free;
  end;
end;

procedure ChangePassword(const AUsername, ANewPassword: string);
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj: TJSONObject;
  I: Integer;
  Found: Boolean;
  Salt, PwdHash: string;
begin
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Found := False;
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      if SameText(GetStr(UserObj, 'username'), AUsername) then
      begin
        Salt := GenerateSalt(AUsername);
        PwdHash := ComputeHash(Salt, ANewPassword);
        UserObj.RemovePair('salt').Free;
        UserObj.AddPair('salt', Salt);
        UserObj.RemovePair('passwordHash').Free;
        UserObj.AddPair('passwordHash', PwdHash);
        Found := True;
        Break;
      end;
    end;

    if Found then
    begin
      SaveRootObject(GetUsersPath, Root);
      Writeln;
      Writeln(Format('Password for ''%s'' successfully updated!', [AUsername]));
      Writeln;
    end
    else
    begin
      Writeln;
      Writeln(Format('[ERROR] User ''%s'' not found.', [AUsername]));
      Writeln;
    end;
  finally
    Root.Free;
  end;
end;

procedure DeleteUser(const AUsername: string);
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj: TJSONObject;
  I: Integer;
  Found: Boolean;
begin
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Found := False;
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      if SameText(GetStr(UserObj, 'username'), AUsername) then
      begin
        UsersArr.Remove(I).Free;
        Found := True;
        Break;
      end;
    end;

    if Found then
    begin
      SaveRootObject(GetUsersPath, Root);
      Writeln;
      Writeln(Format('User ''%s'' deleted from configuration.', [AUsername]));
      Writeln;
    end
    else
    begin
      Writeln;
      Writeln(Format('[ERROR] User ''%s'' not found.', [AUsername]));
      Writeln;
    end;
  finally
    Root.Free;
  end;
end;

procedure ListApps;
var
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  I: Integer;
  AppId, AppName, Sandbox, NetStr, Cmd, RolesStr: string;
  RolesArr: TJSONArray;
begin
  AppsArr := LoadAppsArray(GetAppsPath, Root);
  try
    if (AppsArr = nil) or (AppsArr.Count = 0) then
    begin
      Writeln('No apps found in: ', GetAppsPath);
      Exit;
    end;

    Writeln(Format('%-14s %-24s %-10s %-5s %-26s %-16s', ['ID', 'Name', 'Sandbox', 'Net', 'Command', 'Roles']));
    Writeln(StringOfChar('-', 98));
    for I := 0 to AppsArr.Count - 1 do
    begin
      AppObj := AppsArr.Items[I] as TJSONObject;
      AppId := GetStr(AppObj, 'id');
      AppName := GetStr(AppObj, 'name');
      Sandbox := GetStr(AppObj, 'sandbox', 'standard');
      NetStr := 'NO';
      if GetBool(AppObj, 'network', False) then
        NetStr := 'YES';
      Cmd := GetStr(AppObj, 'command');
      RolesArr := FindArr(AppObj, 'roles');
      if RolesArr <> nil then
        RolesStr := string.Join(', ', JsonArrayToArray(RolesArr))
      else
        RolesStr := 'admin, user';
      Writeln(Format('%-14s %-24s %-10s %-5s %-26s %-16s', [AppId, AppName, Sandbox, NetStr, Cmd, RolesStr]));
    end;
    Writeln;
    Writeln(Format('Total apps: %d', [AppsArr.Count]));
    Writeln;
  finally
    Root.Free;
  end;
end;

procedure AddApp(const AId, AName, ACommand: string; const AArgs: TArray<string>;
  const AWorkingDir: string; const AEnv: TArray<string>; ACols, ARows: Integer;
  const ASandbox: string; ANetwork: Boolean; const ADirsRead, ADirsWrite, ARoles: TArray<string>);
var
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  ExistingIdx, I: Integer;
begin
  AppsArr := LoadAppsArray(GetAppsPath, Root);
  try
    AppObj := TJSONObject.Create;
    AppObj.AddPair('id', AId);
    AppObj.AddPair('name', AName);
    AppObj.AddPair('command', ACommand);
    AppObj.AddPair('args', ArrayToJsonArray(AArgs));
    if AWorkingDir <> '' then
      AppObj.AddPair('workingDir', AWorkingDir);
    AppObj.AddPair('env', ArrayToJsonArray(AEnv));
    AppObj.AddPair('cols', TJSONNumber.Create(ACols));
    AppObj.AddPair('rows', TJSONNumber.Create(ARows));
    AppObj.AddPair('sandbox', ASandbox);
    AppObj.AddPair('network', TJSONBool.Create(ANetwork));
    AppObj.AddPair('allowedDirs', ArrayToJsonArray(ADirsRead));
    AppObj.AddPair('allowedDirsWrite', ArrayToJsonArray(ADirsWrite));
    AppObj.AddPair('roles', ArrayToJsonArray(ARoles));

    ExistingIdx := -1;
    for I := 0 to AppsArr.Count - 1 do
    begin
      if SameText(GetStr(AppsArr.Items[I] as TJSONObject, 'id'), AId) then
      begin
        ExistingIdx := I;
        Break;
      end;
    end;

    if ExistingIdx >= 0 then
    begin
      AppsArr.Remove(ExistingIdx).Free;
      AppsArr.AddElement(AppObj);
      Writeln(Format('[OK] Updated existing app ''%s'' in %s', [AId, GetAppsPath]));
    end
    else
    begin
      AppsArr.AddElement(AppObj);
      Writeln(Format('[OK] Added new app ''%s'' to %s', [AId, GetAppsPath]));
    end;

    SaveRootObject(GetAppsPath, Root);

    Writeln;
    Writeln(Format('App ''%s'' (%s) successfully configured!', [AId, AName]));
    Writeln('  Command: ', ACommand);
    Writeln('  Sandbox: ', ASandbox);
    Writeln('  Network: ', BoolToStr(ANetwork, True));
    Writeln('  Roles:   ', string.Join(', ', ARoles));
    Writeln;
  finally
    Root.Free;
  end;
end;

procedure DeleteApp(const AId: string);
var
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  I: Integer;
  Found: Boolean;
begin
  AppsArr := LoadAppsArray(GetAppsPath, Root);
  try
    Found := False;
    for I := 0 to AppsArr.Count - 1 do
    begin
      AppObj := AppsArr.Items[I] as TJSONObject;
      if SameText(GetStr(AppObj, 'id'), AId) then
      begin
        AppsArr.Remove(I).Free;
        Found := True;
        Break;
      end;
    end;

    if Found then
    begin
      SaveRootObject(GetAppsPath, Root);
      Writeln;
      Writeln(Format('App ''%s'' deleted from configuration.', [AId]));
      Writeln;
    end
    else
    begin
      Writeln;
      Writeln(Format('[ERROR] App ''%s'' not found.', [AId]));
      Writeln;
    end;
  finally
    Root.Free;
  end;
end;

function GetOptionValue(const AName: string; const ADefault: string = ''): string;
var
  I: Integer;
  Arg: string;
begin
  Result := ADefault;
  for I := 1 to ParamCount - 1 do
  begin
    Arg := ParamStr(I);
    if SameText(Arg, '--' + AName) then
    begin
      Result := ParamStr(I + 1);
      Exit;
    end;
    if StartsText('--' + AName + '=', Arg) then
    begin
      Result := Copy(Arg, Length(AName) + 4, MaxInt);
      Exit;
    end;
  end;
end;

function HasFlag(const AName: string): Boolean;
var
  I: Integer;
begin
  for I := 1 to ParamCount do
    if SameText(ParamStr(I), '--' + AName) then
      Exit(True);
  Result := False;
end;

function GetPositionalArg(AIndex: Integer): string;
var
  I, PosIdx: Integer;
  Arg: string;
begin
  Result := '';
  PosIdx := 0;
  I := 2;
  while I <= ParamCount do
  begin
    Arg := ParamStr(I);
    if Arg.StartsWith('--') then
    begin
      if not (SameText(Arg, '--network') or SameText(Arg, '--no-network') or
              SameText(Arg, '--allow-job-only') or SameText(Arg, '--no-job-only')) then
      begin
        if not Arg.Contains('=') then
          Inc(I);
      end;
    end
    else
    begin
      Inc(PosIdx);
      if PosIdx = AIndex then
        Exit(Arg);
    end;
    Inc(I);
  end;
end;

procedure EditUserCLI;
var
  Username, RoleVal, SandboxVal, AppsVal, ReadVal, WriteVal: string;
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj, GrantsObj: TJSONObject;
  I: Integer;
  Found: Boolean;
begin
  Username := GetPositionalArg(1);
  if Username = '' then
  begin
    Writeln('[ERROR] Username required for edit.');
    Exit;
  end;

  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Found := False;
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      if SameText(GetStr(UserObj, 'username'), Username) then
      begin
        Found := True;
        RoleVal := GetOptionValue('role');
        if RoleVal <> '' then
        begin
          UserObj.RemovePair('role').Free;
          UserObj.AddPair('role', RoleVal);
        end;

        SandboxVal := GetOptionValue('sandbox');
        if SandboxVal <> '' then
        begin
          UserObj.RemovePair('sandbox').Free;
          UserObj.AddPair('sandbox', SandboxVal);
          TDirectory.CreateDirectory(TPath.Combine(GetExeDir, SandboxVal));
        end;

        AppsVal := GetOptionValue('apps');
        if AppsVal <> '' then
        begin
          UserObj.RemovePair('apps').Free;
          UserObj.AddPair('apps', ArrayToJsonArray(SplitComma(AppsVal)));
        end;

        GrantsObj := FindObj(UserObj, 'grants');
        if GrantsObj = nil then
        begin
          GrantsObj := TJSONObject.Create;
          UserObj.AddPair('grants', GrantsObj);
        end;

        if HasFlag('network') then
        begin
          GrantsObj.RemovePair('network').Free;
          GrantsObj.AddPair('network', TJSONBool.Create(True));
        end
        else if HasFlag('no-network') then
        begin
          GrantsObj.RemovePair('network').Free;
          GrantsObj.AddPair('network', TJSONBool.Create(False));
        end;

        if HasFlag('allow-job-only') then
        begin
          GrantsObj.RemovePair('allowJobOnly').Free;
          GrantsObj.AddPair('allowJobOnly', TJSONBool.Create(True));
        end
        else if HasFlag('no-job-only') then
        begin
          GrantsObj.RemovePair('allowJobOnly').Free;
          GrantsObj.AddPair('allowJobOnly', TJSONBool.Create(False));
        end;

        ReadVal := GetOptionValue('dirs-read');
        if ReadVal <> '' then
        begin
          GrantsObj.RemovePair('allowedDirsRead').Free;
          GrantsObj.AddPair('allowedDirsRead', ArrayToJsonArray(SplitComma(ReadVal)));
        end;

        WriteVal := GetOptionValue('dirs-write');
        if WriteVal <> '' then
        begin
          GrantsObj.RemovePair('allowedDirsWrite').Free;
          GrantsObj.AddPair('allowedDirsWrite', ArrayToJsonArray(SplitComma(WriteVal)));
        end;
        Break;
      end;
    end;

    if Found then
    begin
      SaveRootObject(GetUsersPath, Root);
      Writeln;
      Writeln(Format('User ''%s'' parameters successfully updated!', [Username]));
      Writeln;
    end
    else
    begin
      Writeln;
      Writeln(Format('[ERROR] User ''%s'' not found.', [Username]));
      Writeln;
    end;
  finally
    Root.Free;
  end;
end;

procedure EditAppCLI;
var
  AppId, NameVal, CmdVal, SandboxVal, ArgsVal, EnvVal, ReadVal, WriteVal, RolesVal: string;
  ColsVal, RowsVal: string;
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  I: Integer;
  Found: Boolean;
begin
  AppId := GetPositionalArg(1);
  if AppId = '' then
  begin
    Writeln('[ERROR] App ID required for edit-app.');
    Exit;
  end;

  AppsArr := LoadAppsArray(GetAppsPath, Root);
  try
    Found := False;
    for I := 0 to AppsArr.Count - 1 do
    begin
      AppObj := AppsArr.Items[I] as TJSONObject;
      if SameText(GetStr(AppObj, 'id'), AppId) then
      begin
        Found := True;
        NameVal := GetOptionValue('name');
        if NameVal <> '' then
        begin
          AppObj.RemovePair('name').Free;
          AppObj.AddPair('name', NameVal);
        end;

        CmdVal := GetOptionValue('command');
        if CmdVal <> '' then
        begin
          AppObj.RemovePair('command').Free;
          AppObj.AddPair('command', CmdVal);
        end;

        SandboxVal := GetOptionValue('sandbox');
        if SandboxVal <> '' then
        begin
          AppObj.RemovePair('sandbox').Free;
          AppObj.AddPair('sandbox', SandboxVal);
        end;

        ColsVal := GetOptionValue('cols');
        if ColsVal <> '' then
        begin
          AppObj.RemovePair('cols').Free;
          AppObj.AddPair('cols', TJSONNumber.Create(StrToIntDef(ColsVal, 120)));
        end;

        RowsVal := GetOptionValue('rows');
        if RowsVal <> '' then
        begin
          AppObj.RemovePair('rows').Free;
          AppObj.AddPair('rows', TJSONNumber.Create(StrToIntDef(RowsVal, 30)));
        end;

        if HasFlag('network') then
        begin
          AppObj.RemovePair('network').Free;
          AppObj.AddPair('network', TJSONBool.Create(True));
        end
        else if HasFlag('no-network') then
        begin
          AppObj.RemovePair('network').Free;
          AppObj.AddPair('network', TJSONBool.Create(False));
        end;

        ArgsVal := GetOptionValue('args');
        if ArgsVal <> '' then
        begin
          AppObj.RemovePair('args').Free;
          AppObj.AddPair('args', ArrayToJsonArray(SplitComma(ArgsVal)));
        end;

        EnvVal := GetOptionValue('env');
        if EnvVal <> '' then
        begin
          AppObj.RemovePair('env').Free;
          AppObj.AddPair('env', ArrayToJsonArray(SplitComma(EnvVal)));
        end;

        ReadVal := GetOptionValue('dirs-read');
        if ReadVal <> '' then
        begin
          AppObj.RemovePair('allowedDirs').Free;
          AppObj.AddPair('allowedDirs', ArrayToJsonArray(SplitComma(ReadVal)));
        end;

        WriteVal := GetOptionValue('dirs-write');
        if WriteVal <> '' then
        begin
          AppObj.RemovePair('allowedDirsWrite').Free;
          AppObj.AddPair('allowedDirsWrite', ArrayToJsonArray(SplitComma(WriteVal)));
        end;

        RolesVal := GetOptionValue('roles');
        if RolesVal <> '' then
        begin
          AppObj.RemovePair('roles').Free;
          AppObj.AddPair('roles', ArrayToJsonArray(SplitComma(RolesVal)));
        end;
        Break;
      end;
    end;

    if Found then
    begin
      SaveRootObject(GetAppsPath, Root);
      Writeln;
      Writeln(Format('App ''%s'' parameters successfully updated!', [AppId]));
      Writeln;
    end
    else
    begin
      Writeln;
      Writeln(Format('[ERROR] App ''%s'' not found.', [AppId]));
      Writeln;
    end;
  finally
    Root.Free;
  end;
end;

procedure InteractiveMode;
var
  Choice: string;
  UName, Pwd, RoleChoice, AppsInput, SandboxInput, NetChoice, JobChoice: string;
  DirsR, DirsW, Confirm: string;
  AppId, AppName, Cmd, SandboxMode, RolesInput: string;
  ColsStr, RowsStr: string;
begin
  while True do
  begin
    Writeln('=== GTermBox Management Tool ===');
    Writeln('--- User Management (users.json) ---');
    Writeln('1. List users');
    Writeln('2. Add new user');
    Writeln('3. Edit user parameters (role, apps, sandbox, grants)');
    Writeln('4. Change user password');
    Writeln('5. Delete user');
    Writeln('--- Application Management (apps.json) ---');
    Writeln('6. List applications');
    Writeln('7. Add new application');
    Writeln('8. Edit application parameters');
    Writeln('9. Delete application');
    Writeln('0. Exit');
    Writeln;
    Write('Select option [1-9, 0]: ');
    Readln(Choice);
    Choice := Trim(Choice);

    if Choice = '0' then
      Break
    else if Choice = '1' then
      ListUsers
    else if Choice = '2' then
    begin
      Write('Enter username: ');
      Readln(UName);
      UName := Trim(UName);
      if UName = '' then
      begin
        Writeln('[ERROR] Username cannot be empty.');
        Continue;
      end;
      Write('Enter password: ');
      Readln(Pwd);
      Pwd := Trim(Pwd);
      if Pwd = '' then
      begin
        Writeln('[ERROR] Password cannot be empty.');
        Continue;
      end;
      Write('Enter role [user/admin, default: user]: ');
      Readln(RoleChoice);
      RoleChoice := Trim(LowerCase(RoleChoice));
      if RoleChoice <> 'admin' then
        RoleChoice := 'user';
      Write('Enter allowed apps comma-separated (default: * for admin, far,edit,powershell for user): ');
      Readln(AppsInput);
      Write('Enter sandbox dir (default: sandbox_' + UName + '): ');
      Readln(SandboxInput);
      Write('Enable network access? [Y/n, default: y]: ');
      Readln(NetChoice);
      AddUser(UName, Pwd, SplitComma(AppsInput), Trim(SandboxInput), RoleChoice,
        not SameText(Trim(NetChoice), 'n'), False, False, nil, nil);
    end
    else if Choice = '3' then
    begin
      Write('Enter username to edit: ');
      Readln(UName);
      UName := Trim(UName);
      if UName = '' then
        Continue;
      Write('New role [admin/user] (leave blank to keep): ');
      Readln(RoleChoice);
      Write('New sandbox dir (leave blank to keep): ');
      Readln(SandboxInput);
      Write('New allowed apps comma-separated (leave blank to keep): ');
      Readln(AppsInput);
      Write('Enable network access? (y/n/leave blank to keep): ');
      Readln(NetChoice);
      Write('Allow Job-Only full disk access? (y/n/leave blank to keep): ');
      Readln(JobChoice);
      Write('Allowed read dirs comma-separated (leave blank to keep): ');
      Readln(DirsR);
      Write('Allowed write dirs comma-separated (leave blank to keep): ');
      Readln(DirsW);

      var R, UUsersArr: TJSONArray;
      var RObj: TJSONObject;
      UUsersArr := LoadUsersArray(GetUsersPath, RObj);
      try
        var UserFound: Boolean := False;
        for var J := 0 to UUsersArr.Count - 1 do
        begin
          var ExistingUser := UUsersArr.Items[J] as TJSONObject;
          if SameText(GetStr(ExistingUser, 'username'), UName) then
          begin
            UserFound := True;
            if Trim(RoleChoice) <> '' then
            begin
              ExistingUser.RemovePair('role').Free;
              ExistingUser.AddPair('role', Trim(RoleChoice));
            end;
            if Trim(SandboxInput) <> '' then
            begin
              ExistingUser.RemovePair('sandbox').Free;
              ExistingUser.AddPair('sandbox', Trim(SandboxInput));
              TDirectory.CreateDirectory(TPath.Combine(GetExeDir, Trim(SandboxInput)));
            end;
            if Trim(AppsInput) <> '' then
            begin
              ExistingUser.RemovePair('apps').Free;
              ExistingUser.AddPair('apps', ArrayToJsonArray(SplitComma(AppsInput)));
            end;
            var GObj := FindObj(ExistingUser, 'grants');
            if GObj = nil then
            begin
              GObj := TJSONObject.Create;
              ExistingUser.AddPair('grants', GObj);
            end;
            if SameText(Trim(NetChoice), 'y') then
            begin
              GObj.RemovePair('network').Free;
              GObj.AddPair('network', TJSONBool.Create(True));
            end
            else if SameText(Trim(NetChoice), 'n') then
            begin
              GObj.RemovePair('network').Free;
              GObj.AddPair('network', TJSONBool.Create(False));
            end;
            if SameText(Trim(JobChoice), 'y') then
            begin
              GObj.RemovePair('allowJobOnly').Free;
              GObj.AddPair('allowJobOnly', TJSONBool.Create(True));
            end
            else if SameText(Trim(JobChoice), 'n') then
            begin
              GObj.RemovePair('allowJobOnly').Free;
              GObj.AddPair('allowJobOnly', TJSONBool.Create(False));
            end;
            if Trim(DirsR) <> '' then
            begin
              GObj.RemovePair('allowedDirsRead').Free;
              GObj.AddPair('allowedDirsRead', ArrayToJsonArray(SplitComma(DirsR)));
            end;
            if Trim(DirsW) <> '' then
            begin
              GObj.RemovePair('allowedDirsWrite').Free;
              GObj.AddPair('allowedDirsWrite', ArrayToJsonArray(SplitComma(DirsW)));
            end;
            Break;
          end;
        end;
        if UserFound then
        begin
          SaveRootObject(GetUsersPath, RObj);
          Writeln('[OK] User parameters updated successfully.');
        end
        else
          Writeln('[ERROR] User not found.');
      finally
        RObj.Free;
      end;
    end
    else if Choice = '4' then
    begin
      Write('Enter username: ');
      Readln(UName);
      Write('Enter new password: ');
      Readln(Pwd);
      if (Trim(UName) <> '') and (Trim(Pwd) <> '') then
        ChangePassword(Trim(UName), Trim(Pwd));
    end
    else if Choice = '5' then
    begin
      Write('Enter username to delete: ');
      Readln(UName);
      Write('Are you sure you want to delete user ''' + Trim(UName) + '''? (y/N): ');
      Readln(Confirm);
      if SameText(Trim(Confirm), 'y') then
        DeleteUser(Trim(UName));
    end
    else if Choice = '6' then
      ListApps
    else if Choice = '7' then
    begin
      Write('Enter app ID (e.g. git-bash): ');
      Readln(AppId);
      if Trim(AppId) = '' then Continue;
      Write('Enter display name: ');
      Readln(AppName);
      Write('Enter command / executable path: ');
      Readln(Cmd);
      if Trim(Cmd) = '' then Continue;
      Write('Sandbox mode [standard/job-only/none, default: standard]: ');
      Readln(SandboxMode);
      if Trim(SandboxMode) = '' then SandboxMode := 'standard';
      Write('Allow network access? [y/N, default: n]: ');
      Readln(NetChoice);
      Write('Allowed roles comma-separated [default: admin,user]: ');
      Readln(RolesInput);
      if Trim(RolesInput) = '' then RolesInput := 'admin,user';
      AddApp(Trim(AppId), Trim(AppName), Trim(Cmd), nil, '', ['TERM=xterm-256color', 'COLORTERM=truecolor'],
        120, 30, Trim(SandboxMode), SameText(Trim(NetChoice), 'y'), nil, nil, SplitComma(RolesInput));
    end
    else if Choice = '8' then
    begin
      Write('Enter app ID to edit: ');
      Readln(AppId);
      if Trim(AppId) = '' then Continue;
      Write('New display name (leave blank to keep): ');
      Readln(AppName);
      Write('New command (leave blank to keep): ');
      Readln(Cmd);
      Write('New sandbox mode (leave blank to keep): ');
      Readln(SandboxMode);
      Write('Allow network access? (y/n/leave blank to keep): ');
      Readln(NetChoice);
      Write('New allowed roles comma-separated (leave blank to keep): ');
      Readln(RolesInput);

      var RRoot: TJSONObject;
      var RAppsArr := LoadAppsArray(GetAppsPath, RRoot);
      try
        var AppFound: Boolean := False;
        for var J := 0 to RAppsArr.Count - 1 do
        begin
          var ExistingApp := RAppsArr.Items[J] as TJSONObject;
          if SameText(GetStr(ExistingApp, 'id'), Trim(AppId)) then
          begin
            AppFound := True;
            if Trim(AppName) <> '' then
            begin
              ExistingApp.RemovePair('name').Free;
              ExistingApp.AddPair('name', Trim(AppName));
            end;
            if Trim(Cmd) <> '' then
            begin
              ExistingApp.RemovePair('command').Free;
              ExistingApp.AddPair('command', Trim(Cmd));
            end;
            if Trim(SandboxMode) <> '' then
            begin
              ExistingApp.RemovePair('sandbox').Free;
              ExistingApp.AddPair('sandbox', Trim(SandboxMode));
            end;
            if SameText(Trim(NetChoice), 'y') then
            begin
              ExistingApp.RemovePair('network').Free;
              ExistingApp.AddPair('network', TJSONBool.Create(True));
            end
            else if SameText(Trim(NetChoice), 'n') then
            begin
              ExistingApp.RemovePair('network').Free;
              ExistingApp.AddPair('network', TJSONBool.Create(False));
            end;
            if Trim(RolesInput) <> '' then
            begin
              ExistingApp.RemovePair('roles').Free;
              ExistingApp.AddPair('roles', ArrayToJsonArray(SplitComma(RolesInput)));
            end;
            Break;
          end;
        end;
        if AppFound then
        begin
          SaveRootObject(GetAppsPath, RRoot);
          Writeln('[OK] App parameters updated successfully.');
        end
        else
          Writeln('[ERROR] App not found.');
      finally
        RRoot.Free;
      end;
    end
    else if Choice = '9' then
    begin
      Write('Enter app ID to delete: ');
      Readln(AppId);
      Write('Are you sure you want to delete app ''' + Trim(AppId) + '''? (y/N): ');
      Readln(Confirm);
      if SameText(Trim(Confirm), 'y') then
        DeleteApp(Trim(AppId));
    end;
    Writeln;
  end;
end;

var
  Cmd: string;
  UName, Pwd, AppId, AppName, ExecCmd: string;
  RolesStr, SandboxStr, AppsStr, ReadStr, WriteStr: string;
  ArgsStr, EnvStr, WDirStr, ColsStr, RowsStr: string;
  NetFlag: Boolean;
begin
  try
    if ParamCount = 0 then
    begin
      InteractiveMode;
      Exit;
    end;

    Cmd := LowerCase(ParamStr(1));

    if Cmd = 'list' then
      ListUsers
    else if Cmd = 'add' then
    begin
      UName := GetPositionalArg(1);
      Pwd := GetPositionalArg(2);
      if (UName = '') or (Pwd = '') then
      begin
        Writeln('[ERROR] Usage: ManageUsers add <username> <password> [options]');
        Exit;
      end;
      RolesStr := GetOptionValue('role', 'user');
      SandboxStr := GetOptionValue('sandbox', '');
      AppsStr := GetOptionValue('apps', '');
      ReadStr := GetOptionValue('dirs-read', '');
      WriteStr := GetOptionValue('dirs-write', '');
      NetFlag := not HasFlag('no-network');
      AddUser(UName, Pwd, SplitComma(AppsStr), SandboxStr, RolesStr, NetFlag,
        HasFlag('allow-job-only'), False, SplitComma(ReadStr), SplitComma(WriteStr));
    end
    else if Cmd = 'edit' then
      EditUserCLI
    else if Cmd = 'passwd' then
    begin
      UName := GetPositionalArg(1);
      Pwd := GetPositionalArg(2);
      if (UName = '') or (Pwd = '') then
      begin
        Writeln('[ERROR] Usage: ManageUsers passwd <username> <new_password>');
        Exit;
      end;
      ChangePassword(UName, Pwd);
    end
    else if Cmd = 'delete' then
    begin
      UName := GetPositionalArg(1);
      if UName = '' then
      begin
        Writeln('[ERROR] Usage: ManageUsers delete <username>');
        Exit;
      end;
      DeleteUser(UName);
    end
    else if Cmd = 'list-apps' then
      ListApps
    else if Cmd = 'add-app' then
    begin
      AppId := GetPositionalArg(1);
      AppName := GetPositionalArg(2);
      ExecCmd := GetPositionalArg(3);
      if (AppId = '') or (AppName = '') or (ExecCmd = '') then
      begin
        Writeln('[ERROR] Usage: ManageUsers add-app <id> <name> <command> [options]');
        Exit;
      end;
      ArgsStr := GetOptionValue('args', '');
      WDirStr := GetOptionValue('working-dir', '');
      EnvStr := GetOptionValue('env', 'TERM=xterm-256color,COLORTERM=truecolor');
      ColsStr := GetOptionValue('cols', '120');
      RowsStr := GetOptionValue('rows', '30');
      SandboxStr := GetOptionValue('sandbox', 'standard');
      ReadStr := GetOptionValue('dirs-read', '');
      WriteStr := GetOptionValue('dirs-write', '');
      RolesStr := GetOptionValue('roles', 'admin,user');
      NetFlag := HasFlag('network');
      AddApp(AppId, AppName, ExecCmd, SplitComma(ArgsStr), WDirStr, SplitComma(EnvStr),
        StrToIntDef(ColsStr, 120), StrToIntDef(RowsStr, 30), SandboxStr, NetFlag,
        SplitComma(ReadStr), SplitComma(WriteStr), SplitComma(RolesStr));
    end
    else if Cmd = 'edit-app' then
      EditAppCLI
    else if Cmd = 'delete-app' then
    begin
      AppId := GetPositionalArg(1);
      if AppId = '' then
      begin
        Writeln('[ERROR] Usage: ManageUsers delete-app <id>');
        Exit;
      end;
      DeleteApp(AppId);
    end
    else
    begin
      Writeln('Unknown command: ', ParamStr(1));
      Writeln('Available commands: list, add, edit, passwd, delete, list-apps, add-app, edit-app, delete-app');
    end;
  except
    on E: Exception do
      Writeln('[ERROR] Exception: ', E.Message);
  end;
end.
