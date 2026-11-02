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
unit GTerm.UserConfig;

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.Hash, System.StrUtils,
  System.Generics.Collections,
  Quick.Logger;

type
  TUserGrants = record
    Network: Boolean;
    AllowJobOnly: Boolean;
    FullDiskAccess: Boolean;
    PowerShellAccessEverywhere: Boolean;
    PowerShellOutsideSandbox: Boolean;
    Upload: Boolean;
    Download: Boolean;
    StorageQuotaMB: Integer;
    AllowedDirsRead: TArray<string>;
    AllowedDirsWrite: TArray<string>;
  end;

  TUserEntry = record
    Username: string;
    Role: string;
    PasswordHash: string;
    Salt: string;
    Sandbox: string;
    Apps: TArray<string>;
    Grants: TUserGrants;
    ClientCertificate: string;
    function HasApp(const AAppId: string): Boolean;
    function IsAdmin: Boolean;
    function CanUpload: Boolean;
    function CanDownload: Boolean;
    function CanPowerShellAccessEverywhere: Boolean;
    function GetStorageQuotaBytes: Int64;
  end;

  TGTermUserConfig = class
  private
    FUsers: TArray<TUserEntry>;
    FConfigPath: string;
    FLastWriteTime: TDateTime;
    class var FInstance: TGTermUserConfig;
    class function HashPassword(const APassword: string): string;
    class function HashPasswordWithSalt(const APassword, ASalt: string): string;
    procedure CheckReload;
  public
    constructor Create;
    destructor Destroy; override;
    class function Instance: TGTermUserConfig;
    function LoadFromFile(const APath: string): Boolean;
    function LoadFromString(const AJsonText: string): Boolean;
    function ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
    function CanAccessApp(const AUsername, AAppId: string): Boolean;
    function FindUser(const AUsername: string; out AUser: TUserEntry): Boolean;
    function FindUserByCert(const ACertIdentifier: string; out AUser: TUserEntry): Boolean;
  end;

implementation

function TUserEntry.HasApp(const AAppId: string): Boolean;
var
  I: Integer;
  Wanted: string;
begin
  Wanted := LowerCase(Trim(AAppId));
  if Wanted = 'files' then
    Exit(CanUpload or CanDownload);
  for I := 0 to High(Apps) do
  begin
    if (Apps[I] = '*') or (LowerCase(Trim(Apps[I])) = Wanted) then
      Exit(True);
  end;
  Result := False;
end;

function TUserEntry.IsAdmin: Boolean;
begin
  Result := SameText(Trim(Role), 'admin');
end;

function TUserEntry.CanUpload: Boolean;
begin
  if IsAdmin then
    Exit(True);
  Result := Grants.Upload;
end;

function TUserEntry.CanDownload: Boolean;
begin
  if IsAdmin then
    Exit(True);
  Result := Grants.Download;
end;

function TUserEntry.CanPowerShellAccessEverywhere: Boolean;
begin
  if Grants.PowerShellAccessEverywhere or Grants.PowerShellOutsideSandbox then
    Exit(True);
  if IsAdmin and Grants.FullDiskAccess then
    Exit(True);
  Result := False;
end;

function TUserEntry.GetStorageQuotaBytes: Int64;
begin
  if IsAdmin then
    Exit(0);
  if Grants.StorageQuotaMB <= 0 then
    Exit(0);
  Result := Int64(Grants.StorageQuotaMB) * 1024 * 1024;
end;

constructor TGTermUserConfig.Create;
begin
  inherited Create;
  SetLength(FUsers, 0);
end;

destructor TGTermUserConfig.Destroy;
begin
  SetLength(FUsers, 0);
  inherited Destroy;
end;

class function TGTermUserConfig.Instance: TGTermUserConfig;
begin
  if FInstance = nil then
    FInstance := TGTermUserConfig.Create;
  Result := FInstance;
end;

class function TGTermUserConfig.HashPassword(const APassword: string): string;
begin
  Result := LowerCase(THashSHA2.GetHashString(APassword, THashSHA2.TSHA2Version.SHA256));
end;

class function TGTermUserConfig.HashPasswordWithSalt(const APassword, ASalt: string): string;
begin
  Result := LowerCase(THashSHA2.GetHashString(ASalt + ':' + APassword, THashSHA2.TSHA2Version.SHA256));
end;

function TGTermUserConfig.LoadFromString(const AJsonText: string): Boolean;
var
  Root: TJSONObject;
  UsersArr: TJSONArray;
  UserObj: TJSONObject;
  AppsArr: TJSONArray;
  Entry: TUserEntry;
  I, J: Integer;
  JsonVal, ArrVal: TJSONValue;
  GrantsObj: TJSONObject;
  ReadArr, WriteArr: TJSONArray;
begin
  Result := False;
  SetLength(FUsers, 0);

  Root := TJSONObject.ParseJSONValue(AJsonText) as TJSONObject;
  if Root = nil then
  begin
    Logger.Error('[UserConfig] Failed to parse JSON text');
    Exit;
  end;

  try
    UsersArr := Root.GetValue<TJSONArray>('users');
    if UsersArr = nil then
    begin
      Logger.Warn('[UserConfig] JSON has no "users" array');
      Exit;
    end;

    SetLength(FUsers, UsersArr.Count);
    for I := 0 to UsersArr.Count - 1 do
    begin
      UserObj := UsersArr.Items[I] as TJSONObject;
      Entry.Username     := UserObj.GetValue<string>('username', '');
      Entry.Role         := UserObj.GetValue<string>('role', 'user');
      Entry.Salt         := UserObj.GetValue<string>('salt', '');
      Entry.PasswordHash := UserObj.GetValue<string>('passwordHash', '');
      if Entry.PasswordHash = '' then
        Entry.PasswordHash := UserObj.GetValue<string>('password_hash', '');
      if Entry.PasswordHash = '' then
      begin
        if Entry.Salt <> '' then
          Entry.PasswordHash := HashPasswordWithSalt(UserObj.GetValue<string>('password', ''), Entry.Salt)
        else
          Entry.PasswordHash := HashPassword(UserObj.GetValue<string>('password', ''));
      end;

      Entry.Sandbox := UserObj.GetValue<string>('sandbox', '');
      if Entry.Sandbox = '' then
        Entry.Sandbox := UserObj.GetValue<string>('sandbox_dir', 'sandbox_' + Entry.Username);

      Entry.ClientCertificate := UserObj.GetValue<string>('clientCertificate', '');
      if Entry.ClientCertificate = '' then
        Entry.ClientCertificate := UserObj.GetValue<string>('client_certificate', '');
      if Entry.ClientCertificate = '' then
        Entry.ClientCertificate := UserObj.GetValue<string>('cert', '');

      JsonVal := UserObj.FindValue('apps');
      if (JsonVal <> nil) and (JsonVal is TJSONArray) then
      begin
        AppsArr := TJSONArray(JsonVal);
        SetLength(Entry.Apps, AppsArr.Count);
        for J := 0 to AppsArr.Count - 1 do
          Entry.Apps[J] := AppsArr.Items[J].Value;
      end
      else
        SetLength(Entry.Apps, 0);

      Entry.Grants.Network := False;
      Entry.Grants.AllowJobOnly := False;
      Entry.Grants.FullDiskAccess := False;
      Entry.Grants.PowerShellAccessEverywhere := False;
      Entry.Grants.PowerShellOutsideSandbox := False;
      Entry.Grants.Upload := True;
      Entry.Grants.Download := True;
      Entry.Grants.StorageQuotaMB := 500;
      SetLength(Entry.Grants.AllowedDirsRead, 0);
      SetLength(Entry.Grants.AllowedDirsWrite, 0);

      if Entry.IsAdmin then
      begin
        Entry.Grants.Network := True;
        Entry.Grants.AllowJobOnly := True;
        Entry.Grants.FullDiskAccess := True;
        Entry.Grants.PowerShellAccessEverywhere := True;
        Entry.Grants.PowerShellOutsideSandbox := True;
        Entry.Grants.Upload := True;
        Entry.Grants.Download := True;
        Entry.Grants.StorageQuotaMB := 0;
        Entry.Grants.AllowedDirsRead := ['*'];
        Entry.Grants.AllowedDirsWrite := ['*'];
      end;

      if UserObj.FindValue('storageQuotaMB') <> nil then
        Entry.Grants.StorageQuotaMB := UserObj.GetValue<Integer>('storageQuotaMB', Entry.Grants.StorageQuotaMB)
      else if UserObj.FindValue('quotaMB') <> nil then
        Entry.Grants.StorageQuotaMB := UserObj.GetValue<Integer>('quotaMB', Entry.Grants.StorageQuotaMB);

      JsonVal := UserObj.FindValue('grants');
      if (JsonVal <> nil) and (JsonVal is TJSONObject) then
      begin
        GrantsObj := TJSONObject(JsonVal);
        Entry.Grants.Network := GrantsObj.GetValue<Boolean>('network', Entry.Grants.Network);
        Entry.Grants.AllowJobOnly := GrantsObj.GetValue<Boolean>('allowJobOnly', Entry.Grants.AllowJobOnly);
        Entry.Grants.FullDiskAccess := GrantsObj.GetValue<Boolean>('fullDiskAccess', Entry.Grants.FullDiskAccess);
        Entry.Grants.PowerShellAccessEverywhere := GrantsObj.GetValue<Boolean>('powershellAccessEverywhere', Entry.Grants.PowerShellAccessEverywhere);
        Entry.Grants.PowerShellOutsideSandbox := GrantsObj.GetValue<Boolean>('powershellOutsideSandbox', Entry.Grants.PowerShellOutsideSandbox);
        if (GrantsObj.FindValue('powershellAccessEverywhere') <> nil) and (GrantsObj.FindValue('powershellOutsideSandbox') = nil) then
          Entry.Grants.PowerShellOutsideSandbox := Entry.Grants.PowerShellAccessEverywhere
        else if (GrantsObj.FindValue('powershellOutsideSandbox') <> nil) and (GrantsObj.FindValue('powershellAccessEverywhere') = nil) then
          Entry.Grants.PowerShellAccessEverywhere := Entry.Grants.PowerShellOutsideSandbox;
        Entry.Grants.Upload := GrantsObj.GetValue<Boolean>('upload', Entry.Grants.Upload);
        Entry.Grants.Download := GrantsObj.GetValue<Boolean>('download', Entry.Grants.Download);
        Entry.Grants.StorageQuotaMB := GrantsObj.GetValue<Integer>('storageQuotaMB', Entry.Grants.StorageQuotaMB);
        if GrantsObj.FindValue('quotaMB') <> nil then
          Entry.Grants.StorageQuotaMB := GrantsObj.GetValue<Integer>('quotaMB', Entry.Grants.StorageQuotaMB);

        ArrVal := GrantsObj.FindValue('allowedDirsRead');
        if (ArrVal <> nil) and (ArrVal is TJSONArray) then
        begin
          ReadArr := TJSONArray(ArrVal);
          SetLength(Entry.Grants.AllowedDirsRead, ReadArr.Count);
          for J := 0 to ReadArr.Count - 1 do
            Entry.Grants.AllowedDirsRead[J] := ReadArr.Items[J].Value;
        end;

        ArrVal := GrantsObj.FindValue('allowedDirsWrite');
        if (ArrVal <> nil) and (ArrVal is TJSONArray) then
        begin
          WriteArr := TJSONArray(ArrVal);
          SetLength(Entry.Grants.AllowedDirsWrite, WriteArr.Count);
          for J := 0 to WriteArr.Count - 1 do
            Entry.Grants.AllowedDirsWrite[J] := WriteArr.Items[J].Value;
        end;
      end;

      FUsers[I] := Entry;
    end;

    Result := True;
  finally
    Root.Free;
  end;
end;

function TGTermUserConfig.LoadFromFile(const APath: string): Boolean;
var
  JsonText: string;
  I: Integer;
begin
  Result := False;
  if not FileExists(APath) then
  begin
    Logger.Warn(Format('[UserConfig] users.json not found at: %s', [APath]));
    Exit;
  end;

  FConfigPath := APath;
  FileAge(APath, FLastWriteTime);

  try
    with TStringList.Create do
    try
      LoadFromFile(APath, TEncoding.UTF8);
      JsonText := Text;
    finally
      Free;
    end;

    Result := LoadFromString(JsonText);
    if Result then
    begin
      Logger.Info(Format('[UserConfig] Loaded %d users from %s', [Length(FUsers), APath]));
      for I := 0 to High(FUsers) do
        Logger.Info(Format('[UserConfig]   User [%s] sandbox=%s apps=[%s]',
          [FUsers[I].Username, FUsers[I].Sandbox, string.Join(',', FUsers[I].Apps)]));
    end;
  except
    on E: Exception do
      Logger.Error(Format('[UserConfig] Error loading users.json: %s', [E.Message]));
  end;
end;

procedure TGTermUserConfig.CheckReload;
var
  CurrTime: TDateTime;
begin
  if (FConfigPath <> '') and FileExists(FConfigPath) then
  begin
    if FileAge(FConfigPath, CurrTime) and (CurrTime <> FLastWriteTime) then
      LoadFromFile(FConfigPath);
  end;
end;

function TGTermUserConfig.ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
  CalculatedHash: string;
begin
  CheckReload;
  for I := 0 to High(FUsers) do
  begin
    if SameText(FUsers[I].Username, AUsername) then
    begin
      if FUsers[I].Salt <> '' then
        CalculatedHash := HashPasswordWithSalt(APassword, FUsers[I].Salt)
      else
        CalculatedHash := HashPassword(APassword);

      if SameText(FUsers[I].PasswordHash, CalculatedHash) then
      begin
        AUser := FUsers[I];
        Exit(True);
      end;
    end;
  end;
  Result := False;
end;

function TGTermUserConfig.CanAccessApp(const AUsername, AAppId: string): Boolean;
var
  User: TUserEntry;
begin
  CheckReload;
  Result := FindUser(AUsername, User) and User.HasApp(AAppId);
end;

function TGTermUserConfig.FindUser(const AUsername: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
begin
  CheckReload;
  for I := 0 to High(FUsers) do
  begin
    if SameText(FUsers[I].Username, AUsername) then
    begin
      AUser := FUsers[I];
      Exit(True);
    end;
  end;
  Result := False;
end;

function TGTermUserConfig.FindUserByCert(const ACertIdentifier: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
  CleanId, CertFile, CertBase: string;
begin
  CheckReload;
  CleanId := Trim(ACertIdentifier);
  if CleanId = '' then
    Exit(False);

  for I := 0 to High(FUsers) do
  begin
    CertFile := Trim(FUsers[I].ClientCertificate);
    if CertFile <> '' then
    begin
      if SameText(CertFile, CleanId) then
      begin
        AUser := FUsers[I];
        Exit(True);
      end;
      if SameText(ExtractFileName(CertFile), ExtractFileName(CleanId)) then
      begin
        AUser := FUsers[I];
        Exit(True);
      end;
      CertBase := ChangeFileExt(ExtractFileName(CertFile), '');
      if SameText(CertBase, CleanId) or SameText(CertBase, ChangeFileExt(ExtractFileName(CleanId), '')) then
      begin
        AUser := FUsers[I];
        Exit(True);
      end;
    end;
  end;

  for I := 0 to High(FUsers) do
  begin
    if SameText(FUsers[I].Username, CleanId) or SameText(FUsers[I].Username, ChangeFileExt(ExtractFileName(CleanId), '')) then
    begin
      AUser := FUsers[I];
      Exit(True);
    end;
  end;

  Result := False;
end;

initialization

finalization
  if TGTermUserConfig.FInstance <> nil then
  begin
    TGTermUserConfig.FInstance.Free;
    TGTermUserConfig.FInstance := nil;
  end;

end.
