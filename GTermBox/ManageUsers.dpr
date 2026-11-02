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
program ManageUsers;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
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

function HasFlag(const AName: string): Boolean; forward;

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
  Dir, BaseName, Ext, Prefix, OldF, NewF: string;
  I: Integer;
begin
  if not FileExists(AFilePath) then
    Exit;
  Dir := ExtractFilePath(AFilePath);
  BaseName := ExtractFileName(AFilePath);
  Ext := ExtractFileExt(AFilePath);
  Prefix := ChangeFileExt(BaseName, '');

  OldF := TPath.Combine(Dir, Format('%s_v5%s', [Prefix, Ext]));
  if FileExists(OldF) then
    TFile.Delete(OldF);

  for I := 4 downto 1 do
  begin
    OldF := TPath.Combine(Dir, Format('%s_v%d%s', [Prefix, I, Ext]));
    NewF := TPath.Combine(Dir, Format('%s_v%d%s', [Prefix, I + 1, Ext]));
    if FileExists(OldF) then
    begin
      if FileExists(NewF) then
        TFile.Delete(NewF);
      TFile.Move(OldF, NewF);
    end;
  end;

  NewF := TPath.Combine(Dir, Format('%s_v1%s', [Prefix, Ext]));
  TFile.Copy(AFilePath, NewF);
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
  TempFile, AltPath, BaseDir, FileName: string;
begin
  BackupFile(AFilePath);
  RawBytes := TEncoding.UTF8.GetBytes(ARoot.Format(2) + sLineBreak);
  TempFile := AFilePath + '.tmp';
  TFile.WriteAllBytes(TempFile, RawBytes);
  if not MoveFileExW(PWideChar(TempFile), PWideChar(AFilePath), MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) then
  begin
    DeleteFile(PWideChar(TempFile));
    TFile.WriteAllBytes(AFilePath, RawBytes);
  end;

  BaseDir := ExtractFilePath(AFilePath);
  FileName := ExtractFileName(AFilePath);
  AltPath := TPath.GetFullPath(TPath.Combine(BaseDir, '..\..\' + FileName));
  if FileExists(AltPath) and not SameText(AltPath, AFilePath) then
  begin
    BackupFile(AltPath);
    TFile.WriteAllBytes(AltPath, RawBytes);
  end
  else
  begin
    AltPath := TPath.GetFullPath(TPath.Combine(BaseDir, 'Win64\Debug\' + FileName));
    if FileExists(AltPath) and not SameText(AltPath, AFilePath) then
    begin
      BackupFile(AltPath);
      TFile.WriteAllBytes(AltPath, RawBytes);
    end;
  end;
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
  UName, URole, USandbox, AppsStr, NetStr, JobStr, FullDiskStr, CertStr: string;
  AppsArr: TJSONArray;
begin
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    if (UsersArr = nil) or (UsersArr.Count = 0) then
    begin
      Writeln('No users found in: ', GetUsersPath);
      Exit;
    end;

    Writeln(Format('%-12s %-8s %-16s %-5s %-8s %-9s %-16s %-20s', ['Username', 'Role', 'Cert', 'Net', 'JobOnly', 'FullDisk', 'Sandbox', 'Apps']));
    Writeln(StringOfChar('-', 100));
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      UName := GetStr(UserObj, 'username');
      URole := GetStr(UserObj, 'role', 'user');
      USandbox := GetStr(UserObj, 'sandbox');
      CertStr := GetStr(UserObj, 'clientCertificate', '-');
      NetStr := 'YES';
      JobStr := 'NO';
      FullDiskStr := 'NO';
      GrantsObj := FindObj(UserObj, 'grants');
      if GrantsObj <> nil then
      begin
        if not GetBool(GrantsObj, 'network', True) then
          NetStr := 'NO';
        if GetBool(GrantsObj, 'allowJobOnly', False) then
          JobStr := 'YES';
        if GetBool(GrantsObj, 'fullDiskAccess', False) then
          FullDiskStr := 'YES';
      end;
      AppsArr := FindArr(UserObj, 'apps');
      if AppsArr <> nil then
        AppsStr := string.Join(', ', JsonArrayToArray(AppsArr))
      else
        AppsStr := '*';
      Writeln(Format('%-12s %-8s %-16s %-5s %-8s %-9s %-16s %-20s', [UName, URole, CertStr, NetStr, JobStr, FullDiskStr, USandbox, AppsStr]));
    end;
    Writeln;
    Writeln(Format('Total users: %d', [UsersArr.Count]));
    Writeln;
  finally
    Root.Free;
  end;
end;

procedure ShowUser(const AUsername: string);
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj, GrantsObj: TJSONObject;
  I: Integer;
  Found: Boolean;
  UName, URole, USandbox, AppsStr, SaltStr, HashStr: string;
  NetStr, JobStr, FullDiskStr, UploadStr, DownloadStr, ReadStr, WriteStr: string;
  AppsArr, ReadArr, WriteArr: TJSONArray;
begin
  if AUsername = '' then
  begin
    Writeln('[ERROR] Username required. Usage: ManageUsers show <username>');
    Exit;
  end;
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Found := False;
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      UName := GetStr(UserObj, 'username');
      if SameText(UName, AUsername) then
      begin
        Found := True;
        URole := GetStr(UserObj, 'role', 'user');
        USandbox := GetStr(UserObj, 'sandbox');
        SaltStr := GetStr(UserObj, 'salt');
        HashStr := GetStr(UserObj, 'passwordHash');
        NetStr := 'YES';
        JobStr := 'NO';
        FullDiskStr := 'NO';
        UploadStr := 'YES';
        DownloadStr := 'YES';
        ReadStr := '';
        WriteStr := '';
        GrantsObj := FindObj(UserObj, 'grants');
        if GrantsObj <> nil then
        begin
          if not GetBool(GrantsObj, 'network', True) then
            NetStr := 'NO';
          if GetBool(GrantsObj, 'allowJobOnly', False) then
            JobStr := 'YES';
          if GetBool(GrantsObj, 'fullDiskAccess', False) then
            FullDiskStr := 'YES';
          if not GetBool(GrantsObj, 'upload', True) then
            UploadStr := 'NO';
          if not GetBool(GrantsObj, 'download', True) then
            DownloadStr := 'NO';
          ReadArr := FindArr(GrantsObj, 'allowedDirsRead');
          if ReadArr <> nil then
            ReadStr := string.Join(', ', JsonArrayToArray(ReadArr));
          WriteArr := FindArr(GrantsObj, 'allowedDirsWrite');
          if WriteArr <> nil then
            WriteStr := string.Join(', ', JsonArrayToArray(WriteArr));
        end;
        AppsArr := FindArr(UserObj, 'apps');
        if AppsArr <> nil then
          AppsStr := string.Join(', ', JsonArrayToArray(AppsArr))
        else
          AppsStr := '*';

        Writeln('============================================================');
        Writeln(Format(' User Details: %s', [UName]));
        Writeln('============================================================');
        Writeln(Format('  Role:             %s', [URole]));
        Writeln(Format('  Client Certificate: %s', [GetStr(UserObj, 'clientCertificate', 'None (Password auth only)')]));
        Writeln(Format('  Sandbox:          %s', [USandbox]));
        Writeln(Format('  Network Access:   %s', [NetStr]));
        Writeln(Format('  Job-Only Access:  %s', [JobStr]));
        Writeln(Format('  Full Disk Access: %s', [FullDiskStr]));
        Writeln(Format('  PowerShell Outside Sandbox: %s', [IfThen(GetBool(GrantsObj, 'powershellAccessEverywhere', GetBool(GrantsObj, 'powershellOutsideSandbox', False)), 'YES', 'NO')]));
        Writeln(Format('  Upload Access:    %s', [UploadStr]));
        Writeln(Format('  Download Access:  %s', [DownloadStr]));
        Writeln(Format('  Allowed Apps:     %s', [AppsStr]));
        Writeln(Format('  Allowed Read:     %s', [ReadStr]));
        Writeln(Format('  Allowed Write:    %s', [WriteStr]));
        Writeln(Format('  Salt:             %s', [SaltStr]));
        Writeln(Format('  Password Hash:    %s', [HashStr]));
        Writeln('============================================================');
        Writeln;
        Break;
      end;
    end;
    if not Found then
      Writeln(Format('[ERROR] User ''%s'' not found.', [AUsername]));
  finally
    Root.Free;
  end;
end;

procedure AddUser(const AUsername, APassword: string; const AApps: TArray<string>;
  const ASandbox, ARole: string; ANetwork, AAllowJobOnly, AFullDisk: Boolean;
  const ADirsRead, ADirsWrite: TArray<string>; AUpload: Boolean = True; ADownload: Boolean = True;
  APowerShellOutsideSandbox: Boolean = False; const AClientCert: string = '');
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj, GrantsObj: TJSONObject;
  ExistingIdx, I: Integer;
  Salt, PwdHash, FullSandbox: string;
  EffectiveRole, EffectiveSandbox: string;
  EffectiveApps, EffectiveDirsRead, EffectiveDirsWrite: TArray<string>;
  EffectiveJobOnly, EffectiveFullDisk, EffectivePowerShellEverywhere: Boolean;
begin
  if (AUsername = '') or (Pos(' ', AUsername) > 0) or (Pos(':', AUsername) > 0) or
     (Pos('/', AUsername) > 0) or (Pos('\', AUsername) > 0) or (Pos('"', AUsername) > 0) then
  begin
    Writeln(Format('[ERROR] Invalid username ''%s''. Usernames cannot contain spaces, colons, or slashes.', [AUsername]));
    Exit;
  end;

  if Length(APassword) < 4 then
  begin
    Writeln('[ERROR] Password is too short. Minimum 4 characters required.');
    Exit;
  end;

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
      EffectiveApps := ['far', 'edit', 'powershell', 'pytui', 'python'];
  end;

  if SameText(EffectiveRole, 'admin') then
  begin
    EffectiveJobOnly := True;
    EffectiveFullDisk := True;
    EffectivePowerShellEverywhere := True;
    EffectiveDirsRead := ['*'];
    EffectiveDirsWrite := ['*'];
  end
  else
  begin
    EffectiveJobOnly := AAllowJobOnly;
    EffectiveFullDisk := AFullDisk;
    EffectivePowerShellEverywhere := APowerShellOutsideSandbox;
    EffectiveDirsRead := ADirsRead;
    EffectiveDirsWrite := ADirsWrite;
  end;

  FullSandbox := TPath.Combine(GetExeDir, EffectiveSandbox);
  if not TDirectory.Exists(FullSandbox) then
  begin
    TDirectory.CreateDirectory(FullSandbox);
    Writeln('[OK] Created sandbox directory: ', FullSandbox);
  end;
  TDirectory.CreateDirectory(TPath.Combine(FullSandbox, 'AppData'));
  TDirectory.CreateDirectory(TPath.Combine(FullSandbox, 'Documents'));
  TDirectory.CreateDirectory(TPath.Combine(FullSandbox, 'tmp'));
  TDirectory.CreateDirectory(TPath.Combine(FullSandbox, 'profile'));
  TDirectory.CreateDirectory(TPath.Combine(FullSandbox, 'apps'));

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
    if AClientCert <> '' then
      UserObj.AddPair('clientCertificate', AClientCert);
    UserObj.AddPair('apps', ArrayToJsonArray(EffectiveApps));

    GrantsObj := TJSONObject.Create;
    GrantsObj.AddPair('network', TJSONBool.Create(ANetwork));
    GrantsObj.AddPair('allowJobOnly', TJSONBool.Create(EffectiveJobOnly));
    GrantsObj.AddPair('fullDiskAccess', TJSONBool.Create(EffectiveFullDisk));
    GrantsObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(EffectivePowerShellEverywhere));
    GrantsObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(EffectivePowerShellEverywhere));
    GrantsObj.AddPair('upload', TJSONBool.Create(AUpload));
    GrantsObj.AddPair('download', TJSONBool.Create(ADownload));
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

    if (ExistingIdx >= 0) and not HasFlag('force') then
    begin
      Writeln(Format('[ERROR] User ''%s'' already exists! Use edit command or --force.', [AUsername]));
      UserObj.Free;
      Exit;
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
  SandboxDir, FullSandbox, CanonicalSandbox, CanonicalExeDir, ParentSandbox: string;
begin
  SandboxDir := '';
  UsersArr := LoadUsersArray(GetUsersPath, Root);
  try
    Found := False;
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      if SameText(GetStr(UserObj, 'username'), AUsername) then
      begin
        SandboxDir := GetStr(UserObj, 'sandbox');
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
      if SandboxDir <> '' then
      begin
        FullSandbox := TPath.Combine(GetExeDir, SandboxDir);
        if TDirectory.Exists(FullSandbox) then
        begin
          CanonicalSandbox := TPath.GetFullPath(FullSandbox);
          CanonicalExeDir := TPath.GetFullPath(GetExeDir);
          if (CanonicalSandbox <> CanonicalExeDir) and (Length(CanonicalSandbox) > Length(CanonicalExeDir)) then
          begin
            try
              TDirectory.Delete(FullSandbox, True);
              Writeln(Format('[OK] Deleted sandbox directory from disk: %s', [FullSandbox]));
            except
              on E: Exception do
                Writeln(Format('[WARN] Could not delete sandbox directory: %s (%s)', [FullSandbox, E.Message]));
            end;
          end;
        end;
        ParentSandbox := TPath.Combine(ExtractFilePath(ExcludeTrailingPathDelimiter(GetExeDir)), SandboxDir);
        if TDirectory.Exists(ParentSandbox) then
        begin
          CanonicalSandbox := TPath.GetFullPath(ParentSandbox);
          CanonicalExeDir := TPath.GetFullPath(ExtractFilePath(ExcludeTrailingPathDelimiter(GetExeDir)));
          if (CanonicalSandbox <> CanonicalExeDir) and (Length(CanonicalSandbox) > Length(CanonicalExeDir)) then
          begin
            try
              TDirectory.Delete(ParentSandbox, True);
              Writeln(Format('[OK] Deleted parent sandbox directory from disk: %s', [ParentSandbox]));
            except
            end;
          end;
        end;
      end;
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

procedure ShowApp(const AAppId: string);
var
  Root: TJSONObject;
  AppsArr: TJSONArray;
  AppObj: TJSONObject;
  I: Integer;
  Found: Boolean;
  AppId, AppName, Sandbox, NetStr, Cmd, RolesStr, WDir, ArgsStr, EnvStr: string;
  ColsVal, RowsVal: Integer;
  RolesArr, ArgsArr, EnvArr: TJSONArray;
begin
  if AAppId = '' then
  begin
    Writeln('[ERROR] App ID required. Usage: ManageUsers show-app <id>');
    Exit;
  end;
  AppsArr := LoadAppsArray(GetAppsPath, Root);
  try
    Found := False;
    for I := 0 to AppsArr.Count - 1 do
    begin
      AppObj := AppsArr.Items[I] as TJSONObject;
      AppId := GetStr(AppObj, 'id');
      if SameText(AppId, AAppId) then
      begin
        Found := True;
        AppName := GetStr(AppObj, 'name');
        Cmd := GetStr(AppObj, 'command');
        Sandbox := GetStr(AppObj, 'sandbox', 'standard');
        WDir := GetStr(AppObj, 'workingDir');
        ColsVal := GetInt(AppObj, 'cols', 120);
        RowsVal := GetInt(AppObj, 'rows', 30);
        NetStr := 'NO';
        if GetBool(AppObj, 'network', False) then
          NetStr := 'YES';
        ArgsArr := FindArr(AppObj, 'args');
        if ArgsArr <> nil then
          ArgsStr := string.Join(', ', JsonArrayToArray(ArgsArr))
        else
          ArgsStr := '';
        EnvArr := FindArr(AppObj, 'env');
        if EnvArr <> nil then
          EnvStr := string.Join(', ', JsonArrayToArray(EnvArr))
        else
          EnvStr := '';
        RolesArr := FindArr(AppObj, 'roles');
        if RolesArr <> nil then
          RolesStr := string.Join(', ', JsonArrayToArray(RolesArr))
        else
          RolesStr := 'admin, user';

        Writeln('============================================================');
        Writeln(Format(' App Details: %s (%s)', [AppName, AppId]));
        Writeln('============================================================');
        Writeln(Format('  Command:          %s', [Cmd]));
        Writeln(Format('  Arguments:        %s', [ArgsStr]));
        Writeln(Format('  Sandbox Mode:     %s', [Sandbox]));
        Writeln(Format('  Working Dir:      %s', [WDir]));
        Writeln(Format('  Network Access:   %s', [NetStr]));
        Writeln(Format('  Allowed Roles:    %s', [RolesStr]));
        Writeln(Format('  Terminal Window:  %d cols x %d rows', [ColsVal, RowsVal]));
        Writeln(Format('  Environment:      %s', [EnvStr]));
        Writeln('============================================================');
        Writeln;
        Break;
      end;
    end;
    if not Found then
      Writeln(Format('[ERROR] App ''%s'' not found.', [AAppId]));
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
  if (AId = '') or (Pos(' ', AId) > 0) or (Pos('/', AId) > 0) or (Pos('\', AId) > 0) then
  begin
    Writeln(Format('[ERROR] Invalid app ID ''%s''. App IDs cannot contain spaces or slashes.', [AId]));
    Exit;
  end;

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
  I, J, K: Integer;
  Found: Boolean;
  Sandboxes: TArray<string>;
  SDir, Shim, SAppDir, MasterAppDir, LowerId: string;
  UsersRoot: TJSONObject;
  UsersArr, UserAppsArr: TJSONArray;
  UserObj: TJSONObject;
  UsersModified: Boolean;
begin
  LowerId := LowerCase(AId);
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

      if FileExists(GetUsersPath) then
      begin
        UsersArr := LoadUsersArray(GetUsersPath, UsersRoot);
        try
          UsersModified := False;
          for J := 0 to UsersArr.Count - 1 do
          begin
            UserObj := UsersArr.Items[J] as TJSONObject;
            UserAppsArr := UserObj.GetValue('apps') as TJSONArray;
            if UserAppsArr <> nil then
            begin
              for K := UserAppsArr.Count - 1 downto 0 do
              begin
                if SameText(UserAppsArr.Items[K].Value, AId) then
                begin
                  UserAppsArr.Remove(K).Free;
                  UsersModified := True;
                end;
              end;
            end;
          end;
          if UsersModified then
          begin
            SaveRootObject(GetUsersPath, UsersRoot);
            Writeln(Format('[OK] Removed app ''%s'' from user(s) in %s', [AId, GetUsersPath]));
          end;
        finally
          UsersRoot.Free;
        end;
      end;

      if TDirectory.Exists(GetExeDir) then
      begin
        Sandboxes := TDirectory.GetDirectories(GetExeDir, 'sandbox_*');
        for SDir in Sandboxes do
        begin
          Shim := TPath.Combine(SDir, AId + '.cmd');
          if TFile.Exists(Shim) then
          begin
            try
              TFile.Delete(Shim);
              Writeln(Format('[OK] Deleted app shim: %s', [Shim]));
            except
            end;
          end;
          SAppDir := TPath.Combine(SDir, 'apps\' + LowerId);
          if TDirectory.Exists(SAppDir) then
          begin
            try
              TDirectory.Delete(SAppDir, True);
              Writeln(Format('[OK] Deleted app sandbox directory: %s', [SAppDir]));
            except
            end;
          end;
        end;
        MasterAppDir := TPath.Combine(GetExeDir, 'apps\' + LowerId);
        if TDirectory.Exists(MasterAppDir) then
        begin
          try
            TDirectory.Delete(MasterAppDir, True);
            Writeln(Format('[OK] Deleted app directory: %s', [MasterAppDir]));
          except
          end;
        end;
      end;
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
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    if SameText(Arg, '--' + AName) and (I < ParamCount) and (not ParamStr(I + 1).StartsWith('--')) then
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
              SameText(Arg, '--allow-job-only') or SameText(Arg, '--no-job-only') or
              SameText(Arg, '--full-disk') or SameText(Arg, '--no-full-disk') or
              SameText(Arg, '--powershell-outside-sandbox') or SameText(Arg, '--no-powershell-outside-sandbox') or
              SameText(Arg, '--powershell-access-everywhere') or SameText(Arg, '--no-powershell-access-everywhere') or
              SameText(Arg, '--upload') or SameText(Arg, '--no-upload') or
              SameText(Arg, '--download') or SameText(Arg, '--no-download') or
              SameText(Arg, '--force')) then
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
  Username, RoleVal, SandboxVal, AppsVal, ReadVal, WriteVal, CertVal: string;
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

        CertVal := GetOptionValue('cert');
        if CertVal = '' then
          CertVal := GetOptionValue('client-cert');
        if CertVal <> '' then
        begin
          if UserObj.Values['clientCertificate'] <> nil then
            UserObj.RemovePair('clientCertificate').Free;
          if not SameText(CertVal, 'none') and not SameText(CertVal, 'clear') then
            UserObj.AddPair('clientCertificate', CertVal);
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

        if HasFlag('full-disk') then
        begin
          GrantsObj.RemovePair('fullDiskAccess').Free;
          GrantsObj.AddPair('fullDiskAccess', TJSONBool.Create(True));
        end
        else if HasFlag('no-full-disk') then
        begin
          GrantsObj.RemovePair('fullDiskAccess').Free;
          GrantsObj.AddPair('fullDiskAccess', TJSONBool.Create(False));
        end;

        if HasFlag('powershell-outside-sandbox') or HasFlag('powershell-access-everywhere') then
        begin
          GrantsObj.RemovePair('powershellAccessEverywhere').Free;
          GrantsObj.RemovePair('powershellOutsideSandbox').Free;
          GrantsObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(True));
          GrantsObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(True));
        end
        else if HasFlag('no-powershell-outside-sandbox') or HasFlag('no-powershell-access-everywhere') then
        begin
          GrantsObj.RemovePair('powershellAccessEverywhere').Free;
          GrantsObj.RemovePair('powershellOutsideSandbox').Free;
          GrantsObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(False));
          GrantsObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(False));
        end;

        if HasFlag('upload') then
        begin
          GrantsObj.RemovePair('upload').Free;
          GrantsObj.AddPair('upload', TJSONBool.Create(True));
        end
        else if HasFlag('no-upload') then
        begin
          GrantsObj.RemovePair('upload').Free;
          GrantsObj.AddPair('upload', TJSONBool.Create(False));
        end
        else
        begin
          var UpVal := GetOptionValue('upload');
          if UpVal <> '' then
          begin
            GrantsObj.RemovePair('upload').Free;
            GrantsObj.AddPair('upload', TJSONBool.Create(SameText(UpVal, 'true') or SameText(UpVal, '1') or SameText(UpVal, 'yes')));
          end;
        end;

        if HasFlag('download') then
        begin
          GrantsObj.RemovePair('download').Free;
          GrantsObj.AddPair('download', TJSONBool.Create(True));
        end
        else if HasFlag('no-download') then
        begin
          GrantsObj.RemovePair('download').Free;
          GrantsObj.AddPair('download', TJSONBool.Create(False));
        end
        else
        begin
          var DownVal := GetOptionValue('download');
          if DownVal <> '' then
          begin
            GrantsObj.RemovePair('download').Free;
            GrantsObj.AddPair('download', TJSONBool.Create(SameText(DownVal, 'true') or SameText(DownVal, '1') or SameText(DownVal, 'yes')));
          end;
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

procedure BindClientCert(const AUsername, ACertFileOrThumb: string);
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
        Found := True;
        if UserObj.Values['clientCertificate'] <> nil then
          UserObj.RemovePair('clientCertificate').Free;
        if (ACertFileOrThumb <> '') and not SameText(ACertFileOrThumb, 'none') and not SameText(ACertFileOrThumb, 'clear') then
          UserObj.AddPair('clientCertificate', ACertFileOrThumb);
        SaveRootObject(GetUsersPath, Root);
        Writeln(Format('[OK] Successfully bound client certificate ''%s'' to user ''%s''.', [ACertFileOrThumb, AUsername]));
        Break;
      end;
    end;
    if not Found then
      Writeln(Format('[ERROR] User ''%s'' not found.', [AUsername]));
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

procedure CopyDirTree(const ASrcDir, ADstDir: string; const AExcludeSubstrings: TArray<string> = nil);
var
  Files, Dirs: TArray<string>;
  F, D, DstFile, DstSubDir: string;
  Skip: Boolean;
  I: Integer;
begin
  if not TDirectory.Exists(ASrcDir) then Exit;
  if not TDirectory.Exists(ADstDir) then
    TDirectory.CreateDirectory(ADstDir);

  Files := TDirectory.GetFiles(ASrcDir);
  for F in Files do
  begin
    Skip := False;
    if Assigned(AExcludeSubstrings) then
    begin
      for I := 0 to High(AExcludeSubstrings) do
      begin
        if Pos(LowerCase(AExcludeSubstrings[I]), LowerCase(F)) > 0 then
        begin
          Skip := True;
          Break;
        end;
      end;
    end;
    if not Skip then
    begin
      DstFile := TPath.Combine(ADstDir, ExtractFileName(F));
      try
        TFile.Copy(F, DstFile, True);
      except
      end;
    end;
  end;

  Dirs := TDirectory.GetDirectories(ASrcDir);
  for D in Dirs do
  begin
    Skip := False;
    if Assigned(AExcludeSubstrings) then
    begin
      for I := 0 to High(AExcludeSubstrings) do
      begin
        if Pos(LowerCase(AExcludeSubstrings[I]), LowerCase(D)) > 0 then
        begin
          Skip := True;
          Break;
        end;
      end;
    end;
    if not Skip then
    begin
      DstSubDir := TPath.Combine(ADstDir, ExtractFileName(D));
      CopyDirTree(D, DstSubDir, AExcludeSubstrings);
    end;
  end;
end;

procedure RunIcaclsGrant(const APath, ASidGrant: string);
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  CmdLine: string;
begin
  if not TDirectory.Exists(APath) and not TFile.Exists(APath) then Exit;
  FillChar(SI, SizeOf(SI), 0);
  SI.cb := SizeOf(SI);
  SI.dwFlags := STARTF_USESHOWWINDOW;
  SI.wShowWindow := SW_HIDE;
  CmdLine := Format('icacls "%s" /grant %s /T /C /Q', [APath, ASidGrant]);
  UniqueString(CmdLine);
  if CreateProcess(nil, PChar(CmdLine), nil, nil, False, CREATE_NO_WINDOW, nil, nil, SI, PI) then
  begin
    WaitForSingleObject(PI.hProcess, 15000);
    CloseHandle(PI.hProcess);
    CloseHandle(PI.hThread);
  end;
end;

procedure EnsureDefaultAppsJson(const AFilePath: string);
var
  Root: TJSONObject;
  AppsArr: TJSONArray;
  App: TJSONObject;
  ArgsArr, EnvArr, RolesArr: TJSONArray;
begin
  if TFile.Exists(AFilePath) then Exit;

  Root := TJSONObject.Create;
  try
    AppsArr := TJSONArray.Create;

    App := TJSONObject.Create;
    App.AddPair('id', 'powershell');
    App.AddPair('name', 'PowerShell');
    App.AddPair('command', 'powershell.exe');
    ArgsArr := TJSONArray.Create;
    ArgsArr.Add('-NoExit');
    ArgsArr.Add('-NoLogo');
    ArgsArr.Add('-ExecutionPolicy');
    ArgsArr.Add('Bypass');
    App.AddPair('args', ArgsArr);
    EnvArr := TJSONArray.Create;
    EnvArr.Add('TERM=xterm-256color');
    EnvArr.Add('COLORTERM=truecolor');
    App.AddPair('env', EnvArr);
    App.AddPair('cols', TJSONNumber.Create(120));
    App.AddPair('rows', TJSONNumber.Create(30));
    App.AddPair('sandbox', 'job-only');
    App.AddPair('network', TJSONBool.Create(False));
    App.AddPair('allowedDirs', TJSONArray.Create);
    App.AddPair('allowedDirsWrite', TJSONArray.Create);
    RolesArr := TJSONArray.Create;
    RolesArr.Add('user');
    RolesArr.Add('admin');
    App.AddPair('roles', RolesArr);
    AppsArr.AddElement(App);

    App := TJSONObject.Create;
    App.AddPair('id', 'admin-powershell');
    App.AddPair('name', 'PowerShell Administrator');
    App.AddPair('command', 'powershell.exe');
    ArgsArr := TJSONArray.Create;
    ArgsArr.Add('-NoExit');
    ArgsArr.Add('-NoLogo');
    ArgsArr.Add('-ExecutionPolicy');
    ArgsArr.Add('Bypass');
    App.AddPair('args', ArgsArr);
    EnvArr := TJSONArray.Create;
    EnvArr.Add('TERM=xterm-256color');
    EnvArr.Add('COLORTERM=truecolor');
    App.AddPair('env', EnvArr);
    App.AddPair('cols', TJSONNumber.Create(120));
    App.AddPair('rows', TJSONNumber.Create(30));
    App.AddPair('sandbox', 'standard');
    App.AddPair('network', TJSONBool.Create(True));
    App.AddPair('allowedDirs', TJSONArray.Create);
    App.AddPair('allowedDirsWrite', TJSONArray.Create);
    RolesArr := TJSONArray.Create;
    RolesArr.Add('admin');
    App.AddPair('roles', RolesArr);
    AppsArr.AddElement(App);

    Root.AddPair('apps', AppsArr);
    TFile.WriteAllText(AFilePath, Root.Format(2) + sLineBreak, TEncoding.UTF8);
  finally
    Root.Free;
  end;
end;

procedure EnsureDefaultUsersJson(const AFilePath: string);
var
  Root, AdminObj, Usr1Obj, AdminGrants, Usr1Grants: TJSONObject;
  UsersArr, AdminApps, Usr1Apps, RArr, WArr: TJSONArray;
  AdminSalt, Usr1Salt: string;
begin
  if TFile.Exists(AFilePath) then Exit;

  Root := TJSONObject.Create;
  try
    UsersArr := TJSONArray.Create;

    AdminSalt := GenerateSalt('admin');
    AdminObj := TJSONObject.Create;
    AdminObj.AddPair('username', 'admin');
    AdminObj.AddPair('role', 'admin');
    AdminObj.AddPair('salt', AdminSalt);
    AdminObj.AddPair('passwordHash', ComputeHash(AdminSalt, '1234'));
    AdminObj.AddPair('sandbox', 'sandbox_admin');
    AdminObj.AddPair('clientCertificate', 'admin.crt');
    AdminApps := TJSONArray.Create;
    AdminApps.Add('*');
    AdminObj.AddPair('apps', AdminApps);
    AdminGrants := TJSONObject.Create;
    AdminGrants.AddPair('network', TJSONBool.Create(True));
    AdminGrants.AddPair('allowJobOnly', TJSONBool.Create(True));
    AdminGrants.AddPair('fullDiskAccess', TJSONBool.Create(True));
    AdminGrants.AddPair('powershellAccessEverywhere', TJSONBool.Create(True));
    AdminGrants.AddPair('powershellOutsideSandbox', TJSONBool.Create(True));
    AdminGrants.AddPair('upload', TJSONBool.Create(True));
    AdminGrants.AddPair('download', TJSONBool.Create(True));
    RArr := TJSONArray.Create;
    RArr.Add('*');
    AdminGrants.AddPair('allowedDirsRead', RArr);
    WArr := TJSONArray.Create;
    WArr.Add('*');
    AdminGrants.AddPair('allowedDirsWrite', WArr);
    AdminObj.AddPair('grants', AdminGrants);
    UsersArr.AddElement(AdminObj);

    Usr1Salt := GenerateSalt('usr1');
    Usr1Obj := TJSONObject.Create;
    Usr1Obj.AddPair('username', 'usr1');
    Usr1Obj.AddPair('role', 'user');
    Usr1Obj.AddPair('salt', Usr1Salt);
    Usr1Obj.AddPair('passwordHash', ComputeHash(Usr1Salt, '1234'));
    Usr1Obj.AddPair('sandbox', 'sandbox_usr1');
    Usr1Obj.AddPair('clientCertificate', 'usr1.crt');
    Usr1Apps := TJSONArray.Create;
    Usr1Apps.Add('powershell');
    Usr1Obj.AddPair('apps', Usr1Apps);
    Usr1Grants := TJSONObject.Create;
    Usr1Grants.AddPair('network', TJSONBool.Create(False));
    Usr1Grants.AddPair('allowJobOnly', TJSONBool.Create(False));
    Usr1Grants.AddPair('fullDiskAccess', TJSONBool.Create(False));
    Usr1Grants.AddPair('powershellAccessEverywhere', TJSONBool.Create(False));
    Usr1Grants.AddPair('powershellOutsideSandbox', TJSONBool.Create(False));
    Usr1Grants.AddPair('upload', TJSONBool.Create(True));
    Usr1Grants.AddPair('download', TJSONBool.Create(True));
    RArr := TJSONArray.Create;
    RArr.Add('AppData');
    RArr.Add('Documents');
    RArr.Add('tmp');
    RArr.Add('profile');
    RArr.Add('apps');
    Usr1Grants.AddPair('allowedDirsRead', RArr);
    WArr := TJSONArray.Create;
    WArr.Add('AppData');
    WArr.Add('Documents');
    WArr.Add('tmp');
    WArr.Add('profile');
    WArr.Add('apps');
    Usr1Grants.AddPair('allowedDirsWrite', WArr);
    Usr1Obj.AddPair('grants', Usr1Grants);
    UsersArr.AddElement(Usr1Obj);

    Root.AddPair('users', UsersArr);
    TFile.WriteAllText(AFilePath, Root.Format(2) + sLineBreak, TEncoding.UTF8);
  finally
    Root.Free;
  end;
end;

function ResolveSystemPathExecutable(const AExeName: string): string;
var
  SBuf: array[0..MAX_PATH] of Char;
  SFPart: PChar;
begin
  Result := '';
  if SearchPath(nil, PChar(AExeName), nil, MAX_PATH, SBuf, SFPart) > 0 then
    Result := PChar(@SBuf[0]);
end;

procedure InitializeEnvironment(const ATargetDir: string = '');
var
  BaseDir, SDir, Candidate: string;
  Candidates: TArray<string>;
begin
  if ATargetDir <> '' then
    BaseDir := TPath.GetFullPath(ATargetDir)
  else
    BaseDir := GetExeDir;

  Writeln('=== Initializing GTermBox Environment in: ', BaseDir, ' ===');
  TDirectory.CreateDirectory(BaseDir);

  TDirectory.CreateDirectory(TPath.Combine(BaseDir, 'web'));
  TDirectory.CreateDirectory(TPath.Combine(BaseDir, 'Log'));
  TDirectory.CreateDirectory(TPath.Combine(BaseDir, 'trusted_clients'));
  TDirectory.CreateDirectory(TPath.Combine(BaseDir, 'client_keys'));

  SDir := TPath.Combine(BaseDir, 'sandbox_admin');
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'AppData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'Documents'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'tmp'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\local'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\PluginsData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\local\PluginsData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\Menus'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\Macros\scripts'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'apps'));

  SDir := TPath.Combine(BaseDir, 'sandbox_usr1');
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'AppData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'Documents'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'tmp'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\local'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\PluginsData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\local\PluginsData'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\Menus'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'profile\Macros\scripts'));
  TDirectory.CreateDirectory(TPath.Combine(SDir, 'apps'));

  if not TFile.Exists(TPath.Combine(BaseDir, 'web\index.html')) then
  begin
    Candidates := [
      TPath.Combine(BaseDir, '..\web'),
      TPath.Combine(BaseDir, '..\..\web'),
      TPath.Combine(BaseDir, '..\..\GTermBox\web'),
      TPath.Combine(GetCurrentDir, 'GTermBox\web'),
      TPath.Combine(GetCurrentDir, 'web')
    ];
    for Candidate in Candidates do
    begin
      if TFile.Exists(TPath.Combine(Candidate, 'index.html')) then
      begin
        CopyDirTree(Candidate, TPath.Combine(BaseDir, 'web'));
        Writeln('[OK] Deployed web assets from: ', Candidate);
        Break;
      end;
    end;
  end;










  if not TFile.Exists(TPath.Combine(BaseDir, 'msquic.dll')) then
  begin
    Candidates := [
      TPath.Combine(BaseDir, '..\msquic.dll'),
      TPath.Combine(BaseDir, '..\..\msquic.dll'),
      TPath.Combine(GetCurrentDir, 'msquic.dll'),
      TPath.Combine(GetCurrentDir, 'GTermBox\Win64\Debug\msquic.dll')
    ];
    for Candidate in Candidates do
    begin
      if TFile.Exists(Candidate) then
      begin
        TFile.Copy(Candidate, TPath.Combine(BaseDir, 'msquic.dll'), True);
        Writeln('[OK] Copied msquic.dll');
        Break;
      end;
    end;
  end;

  if not TFile.Exists(TPath.Combine(BaseDir, 'ls-qpack.dll')) then
  begin
    Candidates := [
      TPath.Combine(BaseDir, '..\ls-qpack.dll'),
      TPath.Combine(BaseDir, '..\..\ls-qpack.dll'),
      TPath.Combine(GetCurrentDir, 'ls-qpack.dll'),
      TPath.Combine(GetCurrentDir, 'GTermBox\Win64\Debug\ls-qpack.dll')
    ];
    for Candidate in Candidates do
    begin
      if TFile.Exists(Candidate) then
      begin
        TFile.Copy(Candidate, TPath.Combine(BaseDir, 'ls-qpack.dll'), True);
        Writeln('[OK] Copied ls-qpack.dll');
        Break;
      end;
    end;
  end;

  EnsureDefaultAppsJson(TPath.Combine(BaseDir, 'apps.json'));
  EnsureDefaultUsersJson(TPath.Combine(BaseDir, 'users.json'));

  RunIcaclsGrant(TPath.Combine(BaseDir, 'sandbox_usr1'), '*S-1-15-2-1:(OI)(CI)F');
  RunIcaclsGrant(TPath.Combine(BaseDir, 'sandbox_admin'), '*S-1-15-2-1:(OI)(CI)F');
  RunIcaclsGrant(TPath.Combine(BaseDir, 'web'), '*S-1-15-2-1:(OI)(CI)RX');
  if TDirectory.Exists(TPath.Combine(BaseDir, 'Python')) then
    RunIcaclsGrant(TPath.Combine(BaseDir, 'Python'), '*S-1-15-2-1:(OI)(CI)RX');
  if TDirectory.Exists(TPath.Combine(BaseDir, 'PyTui')) then
    RunIcaclsGrant(TPath.Combine(BaseDir, 'PyTui'), '*S-1-15-2-1:(OI)(CI)RX');
  if TDirectory.Exists(TPath.Combine(BaseDir, 'Far')) then
    RunIcaclsGrant(TPath.Combine(BaseDir, 'Far'), '*S-1-15-2-1:(OI)(CI)RX');
  if TDirectory.Exists(TPath.Combine(BaseDir, 'Edit')) then
    RunIcaclsGrant(TPath.Combine(BaseDir, 'Edit'), '*S-1-15-2-1:(OI)(CI)RX');

  Writeln('=== GTermBox environment initialization complete! ===');
  Writeln;
end;

procedure PrintHelp;
begin
  Writeln('========================================================================');
  Writeln('                GTermBox User & App Management Utility                  ');
  Writeln('========================================================================');
  Writeln;
  Writeln('USAGE:');
  Writeln('  ManageUsers <command> [arguments] [options]');
  Writeln;
  Writeln('USER COMMANDS (users.json):');
  Writeln('  list                             List all configured users in tabular format');
  Writeln('  show <username>                  Display detailed configuration card for a user');
  Writeln('  add <username> <password>        Create a new user with standard/custom grants');
  Writeln('  edit <username> [options]        Update role, sandbox, apps, cert or privilege grants');
  Writeln('  bind-cert <user> <cert_file>     Bind client certificate (.crt or thumbprint) for mTLS');
  Writeln('  passwd <username> <new_password> Change password and recalculate SHA-256 hash');
  Writeln('  delete <username>                Remove user from configuration');
  Writeln;
  Writeln('APPLICATION COMMANDS (apps.json):');
  Writeln('  list-apps                        List all registered terminal applications');
  Writeln('  show-app <id>                    Display detailed configuration card for an app');
  Writeln('  add-app <id> <name> <command>    Register a new application');
  Writeln('  edit-app <id> [options]          Update application attributes and security mode');
  Writeln('  delete-app <id>                  Remove application from configuration');
  Writeln('  help                             Show this help manual');
  Writeln;
  Writeln('ENVIRONMENT COMMANDS:');
  Writeln('  init-env [path]                  Initialize complete GTermBox directory structure,');
  Writeln('                                   including web, Python, PyTui, Far, Edit, sandboxes,');
  Writeln('                                   trusted_clients, client_keys, configs, and ACLs');
  Writeln;
  Writeln('USER OPTIONS:');
  Writeln('  --role=user|admin                User role (default: user)');
  Writeln('  --cert=<filename_or_thumb>       Bind client certificate for mTLS Zero-Trust auth');
  Writeln('  --sandbox=<directory>            Custom sandbox folder (default: sandbox_<user>)');
  Writeln('  --apps=<app1,app2,...>           Comma-separated allowed apps (default: all tools)');
  Writeln('  --network / --no-network         Enable or disable outbound network access');
  Writeln('  --upload / --no-upload           Enable or disable file upload to sandbox');
  Writeln('  --download / --no-download       Enable or disable file download from sandbox');
  Writeln('  --allow-job-only / --no-job-only Allow unrestricted access under Job Object limit');
  Writeln('  --full-disk / --no-full-disk     Allow full disk host traversal');
  Writeln('  --dirs-read=<dir1,dir2,...>      Allowed read directories');
  Writeln('  --dirs-write=<dir1,dir2,...>     Allowed write directories');
  Writeln('  --force                          Overwrite existing user without error');
  Writeln;
  Writeln('APP OPTIONS:');
  Writeln('  --sandbox=standard|job-only|none Execution sandbox isolation level');
  Writeln('  --args=<arg1,arg2,...>           Default arguments passed to command');
  Writeln('  --working-dir=<path>             Initial working directory');
  Writeln('  --network / --no-network         App network capability');
  Writeln('  --roles=<role1,role2,...>        Allowed roles (e.g. admin,user)');
  Writeln('  --cols=<number> / --rows=<num>   Default ConPTY terminal geometry (120x30)');
  Writeln('  --env=<VAR1=VAL,VAR2=VAL>        Environment variables for session');
  Writeln;
  Writeln('EXAMPLES:');
  Writeln('  ManageUsers add alice Secret123! --role=user --full-disk');
  Writeln('  ManageUsers edit alice --no-network --no-full-disk');
  Writeln('  ManageUsers show alice');
  Writeln('  ManageUsers add-app htop "Htop Monitor" "htop.exe" --sandbox=job-only');
  Writeln('  ManageUsers show-app far');
  Writeln('========================================================================');
  Writeln;
end;

procedure InteractiveMode;
var
  Choice: string;
  UName, Pwd, RoleChoice, AppsInput, SandboxInput, NetChoice, JobChoice, FullDiskChoice, UploadChoice, DownloadChoice, PsChoice: string;
  DirsR, DirsW, Confirm: string;
  AppId, AppName, Cmd, SandboxMode, RolesInput: string;
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
    Writeln('6. Show user details');
    Writeln('--- Application Management (apps.json) ---');
    Writeln('7. List applications');
    Writeln('8. Add new application');
    Writeln('9. Edit application parameters');
    Writeln('10. Delete application');
    Writeln('11. Show application details');
    Writeln('12. Display help documentation');
    Writeln('13. Initialize complete GTermBox environment');
    Writeln('0. Exit');
    Writeln;
    Write('Select option [0-13]: ');
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
      Write('Enter allowed apps comma-separated (default: * for admin, far,edit,powershell,pytui,python for user): ');
      Readln(AppsInput);
      Write('Enter sandbox dir (default: sandbox_' + UName + '): ');
      Readln(SandboxInput);
      Write('Enable network access? [Y/n, default: y]: ');
      Readln(NetChoice);
      Write('Enable full disk access? [y/N, default: n]: ');
      Readln(FullDiskChoice);
      Write('Enable file upload to sandbox? [Y/n, default: y]: ');
      Readln(UploadChoice);
      Write('Enable file download from sandbox? [Y/n, default: y]: ');
      Readln(DownloadChoice);
      Write('Allow PowerShell access outside sandbox? [y/N, default: ' + IfThen(RoleChoice = 'admin', 'y', 'n') + ']: ');
      Readln(PsChoice);
      AddUser(UName, Pwd, SplitComma(AppsInput), Trim(SandboxInput), RoleChoice,
        not SameText(Trim(NetChoice), 'n'), False, SameText(Trim(FullDiskChoice), 'y'), nil, nil,
        not SameText(Trim(UploadChoice), 'n'), not SameText(Trim(DownloadChoice), 'n'),
        SameText(Trim(PsChoice), 'y') or ((Trim(PsChoice) = '') and (RoleChoice = 'admin')));
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
      Write('Enable full disk access? (y/n/leave blank to keep): ');
      Readln(FullDiskChoice);
      Write('Enable file upload? (y/n/leave blank to keep): ');
      Readln(UploadChoice);
      Write('Enable file download? (y/n/leave blank to keep): ');
      Readln(DownloadChoice);
      Write('Allow PowerShell access outside sandbox? (y/n/leave blank to keep): ');
      Readln(PsChoice);
      Write('Allowed read dirs comma-separated (leave blank to keep): ');
      Readln(DirsR);
      Write('Allowed write dirs comma-separated (leave blank to keep): ');
      Readln(DirsW);

      var UUsersArr: TJSONArray;
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
            if SameText(Trim(FullDiskChoice), 'y') then
            begin
              GObj.RemovePair('fullDiskAccess').Free;
              GObj.AddPair('fullDiskAccess', TJSONBool.Create(True));
            end
            else if SameText(Trim(FullDiskChoice), 'n') then
            begin
              GObj.RemovePair('fullDiskAccess').Free;
              GObj.AddPair('fullDiskAccess', TJSONBool.Create(False));
            end;
            if SameText(Trim(UploadChoice), 'y') then
            begin
              GObj.RemovePair('upload').Free;
              GObj.AddPair('upload', TJSONBool.Create(True));
            end
            else if SameText(Trim(UploadChoice), 'n') then
            begin
              GObj.RemovePair('upload').Free;
              GObj.AddPair('upload', TJSONBool.Create(False));
            end;
            if SameText(Trim(DownloadChoice), 'y') then
            begin
              GObj.RemovePair('download').Free;
              GObj.AddPair('download', TJSONBool.Create(True));
            end
            else if SameText(Trim(DownloadChoice), 'n') then
            begin
              GObj.RemovePair('download').Free;
              GObj.AddPair('download', TJSONBool.Create(False));
            end;
            if SameText(Trim(PsChoice), 'y') then
            begin
              GObj.RemovePair('powershellAccessEverywhere').Free;
              GObj.RemovePair('powershellOutsideSandbox').Free;
              GObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(True));
              GObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(True));
            end
            else if SameText(Trim(PsChoice), 'n') then
            begin
              GObj.RemovePair('powershellAccessEverywhere').Free;
              GObj.RemovePair('powershellOutsideSandbox').Free;
              GObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(False));
              GObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(False));
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
    begin
      Write('Enter username to show: ');
      Readln(UName);
      if Trim(UName) <> '' then
        ShowUser(Trim(UName));
    end
    else if Choice = '7' then
      ListApps
    else if Choice = '8' then
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
    else if Choice = '9' then
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
    else if Choice = '10' then
    begin
      Write('Enter app ID to delete: ');
      Readln(AppId);
      Write('Are you sure you want to delete app ''' + Trim(AppId) + '''? (y/N): ');
      Readln(Confirm);
      if SameText(Trim(Confirm), 'y') then
        DeleteApp(Trim(AppId));
    end
    else if Choice = '11' then
    begin
      Write('Enter app ID to show: ');
      Readln(AppId);
      if Trim(AppId) <> '' then
        ShowApp(Trim(AppId));
    end
    else if Choice = '12' then
      PrintHelp
    else if Choice = '13' then
      InitializeEnvironment('');
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

    if (Cmd = 'help') or (Cmd = '--help') or (Cmd = '-h') or (Cmd = '/?') then
      PrintHelp
    else if Cmd = 'list' then
      ListUsers
    else if Cmd = 'show' then
      ShowUser(GetPositionalArg(1))
    else if Cmd = 'show-app' then
      ShowApp(GetPositionalArg(1))
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
      var UploadFlag: Boolean := True;
      if HasFlag('no-upload') then
        UploadFlag := False
      else if HasFlag('upload') then
        UploadFlag := True
      else
      begin
        var UpOpt := GetOptionValue('upload');
        if UpOpt <> '' then
          UploadFlag := SameText(UpOpt, 'true') or SameText(UpOpt, '1') or SameText(UpOpt, 'yes');
      end;

      var DownloadFlag: Boolean := True;
      if HasFlag('no-download') then
        DownloadFlag := False
      else if HasFlag('download') then
        DownloadFlag := True
      else
      begin
        var DownOpt := GetOptionValue('download');
        if DownOpt <> '' then
          DownloadFlag := SameText(DownOpt, 'true') or SameText(DownOpt, '1') or SameText(DownOpt, 'yes');
      end;

      var PsEverywhereFlag: Boolean := SameText(RolesStr, 'admin') or HasFlag('admin') or HasFlag('powershell-outside-sandbox') or HasFlag('powershell-access-everywhere');
      if HasFlag('no-powershell-outside-sandbox') or HasFlag('no-powershell-access-everywhere') then
        PsEverywhereFlag := False;

      var ClientCertStr := GetOptionValue('cert', '');
      if ClientCertStr = '' then
        ClientCertStr := GetOptionValue('client-cert', '');

      AddUser(UName, Pwd, SplitComma(AppsStr), SandboxStr, RolesStr, NetFlag,
        HasFlag('allow-job-only'), HasFlag('full-disk'), SplitComma(ReadStr), SplitComma(WriteStr),
        UploadFlag, DownloadFlag, PsEverywhereFlag, ClientCertStr);
    end
    else if (Cmd = 'bind-cert') or (Cmd = 'set-cert') or (Cmd = 'cert-bind') then
    begin
      UName := GetPositionalArg(1);
      var CertArg := GetPositionalArg(2);
      if (UName = '') or (CertArg = '') then
      begin
        Writeln('[ERROR] Usage: ManageUsers bind-cert <username> <cert_file_or_thumbprint>');
        Exit;
      end;
      BindClientCert(UName, CertArg);
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
    else if (Cmd = 'init-env') or (Cmd = 'setup-env') or (Cmd = 'init') then
    begin
      InitializeEnvironment(GetPositionalArg(1));
    end
    else
    begin
      Writeln(Format('[ERROR] Unknown command ''%s''.', [ParamStr(1)]));
      Writeln('Type ''ManageUsers help'' to see available commands and options.');
    end;
  except
    on E: Exception do
      Writeln('[ERROR] Exception: ', E.Message);
  end;
end.
