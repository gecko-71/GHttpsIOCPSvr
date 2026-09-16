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
    function HasApp(const AAppId: string): Boolean;
    function IsAdmin: Boolean;
  end;

  TGTermUserConfig = class
  private
    FUsers: TArray<TUserEntry>;
    class var FInstance: TGTermUserConfig;
    class function HashPassword(const APassword: string): string;
    class function HashPasswordWithSalt(const APassword, ASalt: string): string;
  public
    constructor Create;
    destructor Destroy; override;
    class function Instance: TGTermUserConfig;
    function LoadFromFile(const APath: string): Boolean;
    function LoadFromString(const AJsonText: string): Boolean;
    function ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
    function CanAccessApp(const AUsername, AAppId: string): Boolean;
    function FindUser(const AUsername: string; out AUser: TUserEntry): Boolean;
  end;

implementation

function TUserEntry.HasApp(const AAppId: string): Boolean;
var
  I: Integer;
  Wanted: string;
begin
  Wanted := LowerCase(Trim(AAppId));
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
      SetLength(Entry.Grants.AllowedDirsRead, 0);
      SetLength(Entry.Grants.AllowedDirsWrite, 0);

      if Entry.IsAdmin then
      begin
        Entry.Grants.Network := True;
        Entry.Grants.AllowJobOnly := True;
        Entry.Grants.FullDiskAccess := True;
        Entry.Grants.AllowedDirsRead := ['*'];
        Entry.Grants.AllowedDirsWrite := ['*'];
      end;

      JsonVal := UserObj.FindValue('grants');
      if (JsonVal <> nil) and (JsonVal is TJSONObject) then
      begin
        GrantsObj := TJSONObject(JsonVal);
        Entry.Grants.Network := GrantsObj.GetValue<Boolean>('network', Entry.Grants.Network);
        Entry.Grants.AllowJobOnly := GrantsObj.GetValue<Boolean>('allowJobOnly', Entry.Grants.AllowJobOnly);
        Entry.Grants.FullDiskAccess := GrantsObj.GetValue<Boolean>('fullDiskAccess', Entry.Grants.FullDiskAccess);

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

function TGTermUserConfig.ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
  CalculatedHash: string;
begin
  for I := 0 to High(FUsers) do
  begin
    if SameText(FUsers[I].Username, AUsername) then
    begin
      if FUsers[I].Salt <> '' then
        CalculatedHash := HashPasswordWithSalt(APassword, FUsers[I].Salt)
      else
        CalculatedHash := HashPassword(APassword);

      if SameText(FUsers[I].PasswordHash, CalculatedHash) or (FUsers[I].PasswordHash = APassword) then
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
  Result := FindUser(AUsername, User) and User.HasApp(AAppId);
end;

function TGTermUserConfig.FindUser(const AUsername: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
begin
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

initialization

finalization
  if TGTermUserConfig.FInstance <> nil then
  begin
    TGTermUserConfig.FInstance.Free;
    TGTermUserConfig.FInstance := nil;
  end;

end.
