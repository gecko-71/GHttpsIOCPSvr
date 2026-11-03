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
  Winapi.Windows, System.SysUtils, System.Classes, System.JSON, System.Hash, System.StrUtils,
  System.Generics.Collections, System.SyncObjs,
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
    FLock: TCriticalSection;
    FLastCheckTick: UInt64;
    FUsers: TArray<TUserEntry>;
    FConfigPath: string;
    FLastWriteTime: TDateTime;
    class var FInstance: TGTermUserConfig;
    class function HashPasswordWithSalt(const APassword, ASalt: string): string;
    procedure CheckReload;
  public
    constructor Create;
    destructor Destroy; override;
    class function Instance: TGTermUserConfig;
    class function GenerateSalt: string;
    class function DerivePBKDF2(const APassword, ASalt: string; const AIterations: UInt64 = 100000): string;
    class function ConstantTimeCompare(const A, B: string): Boolean;
    function LoadFromFile(const APath: string): Boolean;
    function LoadFromString(const AJsonText: string): Boolean;
    function SaveToFile(const APath: string): Boolean;
    function ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
    function CanAccessApp(const AUsername, AAppId: string): Boolean;
    function FindUser(const AUsername: string; out AUser: TUserEntry): Boolean;
    function FindUserByCert(const ACertIdentifier: string; out AUser: TUserEntry): Boolean;
  end;

implementation

const
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;
  BCRYPT_ALG_HANDLE_HMAC_FLAG = $00000008;
  BCRYPT_SHA256_ALGORITHM = 'SHA256';

function BCryptOpenAlgorithmProvider(
  out phAlgorithm: THandle;
  pszAlgId: LPCWSTR;
  pszImplementation: LPCWSTR;
  dwFlags: ULONG): LongInt; stdcall; external 'bcrypt.dll';

function BCryptCloseAlgorithmProvider(
  hAlgorithm: THandle;
  dwFlags: ULONG): LongInt; stdcall; external 'bcrypt.dll';

function BCryptGenRandom(
  hAlgorithm: THandle;
  pbBuffer: PByte;
  cbBuffer: ULONG;
  dwFlags: ULONG): LongInt; stdcall; external 'bcrypt.dll';

function BCryptDeriveKeyPBKDF2(
  hPrf: THandle;
  pbPassword: PByte;
  cbPassword: ULONG;
  pbSalt: PByte;
  cbSalt: ULONG;
  cIterations: UInt64;
  pbDerivedKey: PByte;
  cbDerivedKey: ULONG;
  dwFlags: ULONG): LongInt; stdcall; external 'bcrypt.dll';

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
  FLock := TCriticalSection.Create;
  FLastCheckTick := 0;
  SetLength(FUsers, 0);
end;

destructor TGTermUserConfig.Destroy;
begin
  FLock.Free;
  SetLength(FUsers, 0);
  inherited Destroy;
end;

class function TGTermUserConfig.Instance: TGTermUserConfig;
begin
  if FInstance = nil then
    FInstance := TGTermUserConfig.Create;
  Result := FInstance;
end;

class function TGTermUserConfig.ConstantTimeCompare(const A, B: string): Boolean;
var
  I, MaxLen, Diff: Integer;
  aChar, bChar: Word;
begin
  MaxLen := Length(A);
  if Length(B) > MaxLen then
    MaxLen := Length(B);
  Diff := Length(A) xor Length(B);
  for I := 1 to MaxLen do
  begin
    aChar := 0;
    bChar := 0;
    if I <= Length(A) then
      aChar := Ord(A[I]);
    if I <= Length(B) then
      bChar := Ord(B[I]);
    Diff := Diff or (aChar xor bChar);
  end;
  Result := (Diff = 0);
end;

class function TGTermUserConfig.GenerateSalt: string;
var
  SaltBytes: array[0..15] of Byte;
  I: Integer;
begin
  if BCryptGenRandom(0, @SaltBytes[0], Length(SaltBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) <> 0 then
  begin
    for I := 0 to High(SaltBytes) do
      SaltBytes[I] := Random(256);
  end;
  Result := '';
  for I := 0 to High(SaltBytes) do
    Result := Result + IntToHex(SaltBytes[I], 2).ToLower;
end;

class function TGTermUserConfig.DerivePBKDF2(const APassword, ASalt: string; const AIterations: UInt64): string;
var
  hAlg: THandle;
  PassBytes, SaltBytes: TBytes;
  DerivedBytes: array[0..31] of Byte;
  I: Integer;
  pPass, pSalt: PByte;
begin
  Result := '';
  PassBytes := TEncoding.UTF8.GetBytes(APassword);
  SaltBytes := TEncoding.UTF8.GetBytes(ASalt);
  FillChar(DerivedBytes[0], Length(DerivedBytes), 0);
  if BCryptOpenAlgorithmProvider(hAlg, BCRYPT_SHA256_ALGORITHM, nil, BCRYPT_ALG_HANDLE_HMAC_FLAG) = 0 then
  begin
    try
      pPass := nil;
      if Length(PassBytes) > 0 then
        pPass := @PassBytes[0];
      pSalt := nil;
      if Length(SaltBytes) > 0 then
        pSalt := @SaltBytes[0];
      if BCryptDeriveKeyPBKDF2(hAlg, pPass, Length(PassBytes), pSalt, Length(SaltBytes), AIterations, @DerivedBytes[0], Length(DerivedBytes), 0) = 0 then
      begin
        for I := 0 to High(DerivedBytes) do
          Result := Result + IntToHex(DerivedBytes[I], 2).ToLower;
      end;
    finally
      BCryptCloseAlgorithmProvider(hAlg, 0);
    end;
  end;
  if Result <> '' then
    Result := Format('PBKDF2$%d$%s', [AIterations, Result]);
end;

class function TGTermUserConfig.HashPasswordWithSalt(const APassword, ASalt: string): string;
begin
  Result := DerivePBKDF2(APassword, ASalt, 100000);
end;

function TGTermUserConfig.SaveToFile(const APath: string): Boolean;
var
  Root, UserObj, GrantsObj: TJSONObject;
  UsersArr, AppsArr, ReadArr, WriteArr: TJSONArray;
  I, J: Integer;
  LocalUsers: TArray<TUserEntry>;
  NewWriteTime: TDateTime;
begin
  FLock.Enter;
  try
    LocalUsers := Copy(FUsers);
  finally
    FLock.Leave;
  end;

  Root := TJSONObject.Create;
  try
    UsersArr := TJSONArray.Create;
    for I := 0 to High(LocalUsers) do
    begin
      UserObj := TJSONObject.Create;
      UserObj.AddPair('username', LocalUsers[I].Username);
      UserObj.AddPair('role', LocalUsers[I].Role);
      UserObj.AddPair('sandbox', LocalUsers[I].Sandbox);

      AppsArr := TJSONArray.Create;
      for J := 0 to High(LocalUsers[I].Apps) do
        AppsArr.Add(LocalUsers[I].Apps[J]);
      UserObj.AddPair('apps', AppsArr);

      GrantsObj := TJSONObject.Create;
      GrantsObj.AddPair('network', TJSONBool.Create(LocalUsers[I].Grants.Network));
      GrantsObj.AddPair('allowJobOnly', TJSONBool.Create(LocalUsers[I].Grants.AllowJobOnly));
      GrantsObj.AddPair('fullDiskAccess', TJSONBool.Create(LocalUsers[I].Grants.FullDiskAccess));
      GrantsObj.AddPair('powershellAccessEverywhere', TJSONBool.Create(LocalUsers[I].Grants.PowerShellAccessEverywhere));
      GrantsObj.AddPair('powershellOutsideSandbox', TJSONBool.Create(LocalUsers[I].Grants.PowerShellOutsideSandbox));
      GrantsObj.AddPair('upload', TJSONBool.Create(LocalUsers[I].Grants.Upload));
      GrantsObj.AddPair('download', TJSONBool.Create(LocalUsers[I].Grants.Download));
      GrantsObj.AddPair('storageQuotaMB', TJSONNumber.Create(LocalUsers[I].Grants.StorageQuotaMB));

      ReadArr := TJSONArray.Create;
      for J := 0 to High(LocalUsers[I].Grants.AllowedDirsRead) do
        ReadArr.Add(LocalUsers[I].Grants.AllowedDirsRead[J]);
      GrantsObj.AddPair('allowedDirsRead', ReadArr);

      WriteArr := TJSONArray.Create;
      for J := 0 to High(LocalUsers[I].Grants.AllowedDirsWrite) do
        WriteArr.Add(LocalUsers[I].Grants.AllowedDirsWrite[J]);
      GrantsObj.AddPair('allowedDirsWrite', WriteArr);

      UserObj.AddPair('grants', GrantsObj);
      UserObj.AddPair('salt', LocalUsers[I].Salt);
      UserObj.AddPair('passwordHash', LocalUsers[I].PasswordHash);
      if LocalUsers[I].ClientCertificate <> '' then
        UserObj.AddPair('clientCertificate', LocalUsers[I].ClientCertificate);

      UsersArr.AddElement(UserObj);
    end;
    Root.AddPair('users', UsersArr);

    with TStringList.Create do
    try
      Text := Root.Format(2);
      var EncNoBom := TUTF8Encoding.Create(False);
      try
        var Saved := False;
        for var Retry := 1 to 5 do
        begin
          try
            SaveToFile(APath, EncNoBom);
            Saved := True;
            Break;
          except
            Sleep(30);
          end;
        end;
        Result := Saved;
        if Saved then
        begin
          NewWriteTime := 0;
          FileAge(APath, NewWriteTime);
          FLock.Enter;
          try
            FLastWriteTime := NewWriteTime;
          finally
            FLock.Leave;
          end;
        end;
      finally
        EncNoBom.Free;
      end;
    finally
      Free;
    end;
  finally
    Root.Free;
  end;
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
  NewUsers: TArray<TUserEntry>;
begin
  Result := False;

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

    SetLength(NewUsers, UsersArr.Count);
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
        var PlainPass: string := UserObj.GetValue<string>('password', '');
        if PlainPass <> '' then
        begin
          if Entry.Salt = '' then
            Entry.Salt := GenerateSalt;
          Entry.PasswordHash := HashPasswordWithSalt(PlainPass, Entry.Salt);
        end
        else
          Entry.PasswordHash := 'DISABLED_NO_PASSWORD_' + GenerateSalt;
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

      NewUsers[I] := Entry;
    end;

    FLock.Enter;
    try
      FUsers := NewUsers;
    finally
      FLock.Leave;
    end;

    Result := True;
  finally
    Root.Free;
  end;
end;

function TGTermUserConfig.LoadFromFile(const APath: string): Boolean;
var
  JsonText: string;
  NewWriteTime: TDateTime;
begin
  Result := False;
  if not FileExists(APath) then
  begin
    Logger.Warn(Format('[UserConfig] users.json not found at: %s', [APath]));
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

    Result := LoadFromString(JsonText);
    if Result then
    begin
      FLock.Enter;
      try
        FConfigPath := APath;
        FLastWriteTime := NewWriteTime;
      finally
        FLock.Leave;
      end;

      Logger.Info(Format('[UserConfig] Loaded %d users from %s', [Length(FUsers), APath]));
    end;
  except
    on E: Exception do
      Logger.Error(Format('[UserConfig] Error loading users.json: %s', [E.Message]));
  end;
end;

procedure TGTermUserConfig.CheckReload;
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

function TGTermUserConfig.ValidateUser(const AUsername, APassword: string; out AUser: TUserEntry): Boolean;
var
  I: Integer;
  CalculatedHash: string;
  Matched: Boolean;
  FoundIndex: Integer;
  MigratePassword: Boolean;
begin
  CheckReload;
  if (AUsername = '') or (APassword = '') then
    Exit(False);

  FoundIndex := -1;
  MigratePassword := False;

  FLock.Enter;
  try
    for I := 0 to High(FUsers) do
    begin
      if SameText(FUsers[I].Username, AUsername) then
      begin
        if (FUsers[I].PasswordHash = '') or StartsText('DISABLED_NO_PASSWORD_', FUsers[I].PasswordHash) then
          Exit(False);

        if StartsText('PBKDF2$', FUsers[I].PasswordHash) then
        begin
          CalculatedHash := HashPasswordWithSalt(APassword, FUsers[I].Salt);
          Matched := ConstantTimeCompare(FUsers[I].PasswordHash, CalculatedHash);
        end
        else
        begin
          if FUsers[I].Salt <> '' then
            CalculatedHash := LowerCase(THashSHA2.GetHashString(FUsers[I].Salt + ':' + APassword, THashSHA2.TSHA2Version.SHA256))
          else
            CalculatedHash := LowerCase(THashSHA2.GetHashString(APassword, THashSHA2.TSHA2Version.SHA256));

          Matched := ConstantTimeCompare(FUsers[I].PasswordHash, CalculatedHash);
          if Matched then
          begin
            FUsers[I].Salt := GenerateSalt;
            FUsers[I].PasswordHash := HashPasswordWithSalt(APassword, FUsers[I].Salt);
            MigratePassword := True;
          end;
        end;

        if Matched then
        begin
          AUser := FUsers[I];
          FoundIndex := I;
          Break;
        end;
      end;
    end;
  finally
    FLock.Leave;
  end;

  if (FoundIndex >= 0) and MigratePassword and (FConfigPath <> '') then
  try
    SaveToFile(FConfigPath);
  except
  end;

  Result := (FoundIndex >= 0);
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
  CheckReload;
  FLock.Enter;
  try
    for I := 0 to High(FUsers) do
    begin
      if SameText(FUsers[I].Username, AUsername) then
      begin
        AUser := FUsers[I];
        Exit(True);
      end;
    end;
    Result := False;
  finally
    FLock.Leave;
  end;
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

  FLock.Enter;
  try
    for I := 0 to High(FUsers) do
    begin
      CertFile := Trim(FUsers[I].ClientCertificate);
      if CertFile <> '' then
      begin
        for var SingleCert in CertFile.Split([';', ',']) do
        begin
          var CleanSingle := Trim(SingleCert);
          if CleanSingle = '' then Continue;
          if SameText(CleanSingle, CleanId) or SameText(ExtractFileName(CleanSingle), ExtractFileName(CleanId)) then
          begin
            AUser := FUsers[I];
            Exit(True);
          end;
          CertBase := ChangeFileExt(ExtractFileName(CleanSingle), '');
          if SameText(CertBase, CleanId) or SameText(CertBase, ChangeFileExt(ExtractFileName(CleanId), '')) then
          begin
            AUser := FUsers[I];
            Exit(True);
          end;
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
  finally
    FLock.Leave;
  end;
end;

initialization

finalization
  if TGTermUserConfig.FInstance <> nil then
  begin
    TGTermUserConfig.FInstance.Free;
    TGTermUserConfig.FInstance := nil;
  end;

end.
