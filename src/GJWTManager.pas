{
  MIT License

  Copyright (c) (c) 2025 GECKO-71

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

unit GJWTManager;

interface

uses
  SysUtils, Classes, SyncObjs, System.Threading, System.StrUtils,
  System.JSON, System.NetEncoding, System.Generics.Collections,
  System.DateUtils, System.Hash, System.Math;

type
  TJWTError = (
    jeNone, jeInvalidFormat, jeInvalidSignature, jeExpiredToken,
    jeInvalidIssuer, jeInvalidAudience, jeNotYetValid, jeParsingError,
    jeEncodingError, jeInvalidHeader, jeInvalidPayload, jeTokenTooLarge,
    jeRateLimited, jeInvalidAlgorithm, jeInvalidTokenType, jeWeakKey,
    jeTokenFromFuture
  );

  TJWTToken = class
  private
    FHeader: string;
    FPayload: string;
    FSignature: string;
    FRaw: string;
    FDecoded: TJSONObject;
    FHeaderDecoded: TJSONObject;
    FExpirationTime: TDateTime;
    FIssuedAt: TDateTime;
    FNotBefore: TDateTime;
    FIsValid: Boolean;
    FSubject: string;
    FIssuer: string;
    FAudience: string;
    FJwtId: string;
    FLastError: TJWTError;
    FErrorMessage: string;
  public
    constructor Create;
    destructor Destroy; override;
    function GetClaim(const Name: string): string;
    procedure Clear;
    procedure SecureClear;

    property Header: string read FHeader write FHeader;
    property Payload: string read FPayload write FPayload;
    property Signature: string read FSignature write FSignature;
    property Raw: string read FRaw write FRaw;
    property Decoded: TJSONObject read FDecoded write FDecoded;
    property HeaderDecoded: TJSONObject read FHeaderDecoded write FHeaderDecoded;
    property ExpirationTime: TDateTime read FExpirationTime write FExpirationTime;
    property IssuedAt: TDateTime read FIssuedAt write FIssuedAt;
    property NotBefore: TDateTime read FNotBefore write FNotBefore;
    property IsValid: Boolean read FIsValid write FIsValid;
    property Subject: string read FSubject write FSubject;
    property Issuer: string read FIssuer write FIssuer;
    property Audience: string read FAudience write FAudience;
    property JwtId: string read FJwtId write FJwtId;
    property LastError: TJWTError read FLastError write FLastError;
    property ErrorMessage: string read FErrorMessage write FErrorMessage;
  end;

  TValidationAttempt = record
    LastAttempt: TDateTime;
    Count: Integer;
  end;

  TJWTManager = class
  private
    FSecretKey: string;
    FIssuer: string;
    FAudience: string;
    FTokenExpiration: Integer;
    FClockSkewTolerance: Integer;
    FMaxTokenSize: Integer;
    FAllowedAlgorithms: TArray<string>;
    FValidationAttempts: TDictionary<string, TValidationAttempt>;
    FValidationLock: TCriticalSection;
    FMaxValidationAttempts: Integer;
    FValidationWindowMinutes: Integer;
    FEnableSecurityLogging: Boolean;

    function ValidateAlgorithm(const Algorithm: string): Boolean;
    function CreateSignature(const HeaderPayload: string): string;
    function VerifySignature(const HeaderPayload, Signature: string): Boolean;
    function SecureCompare(const A, B: string): Boolean;
    function DecodeBase64Url(const Input: string): string;
    function EncodeBase64Url(const Input: TBytes): string;
    function ParseJsonSafely(const JsonStr: string): TJSONObject;
    function ValidateStandardClaims(const PayloadObj: TJSONObject; out Error: TJWTError; out ErrorMsg: string): Boolean;
    function IsValidSecretKey(const Key: string): Boolean;
    function IsRateLimited(const ClientId: string): Boolean;
    procedure UpdateValidationAttempt(const ClientId: string);
    procedure LogSecurityEvent(const Event: string; const Details: string = '');
    function GenerateSecureJti: string;
    procedure SecureZeroMemory(var Str: string);
    function ValidateTokenSize(const Token: string): Boolean;
    function ValidateHeaderSafely(const HeaderObj: TJSONObject): Boolean;
  public
    constructor Create(const ASecretKey, AIssuer: string; ATokenExpiration: Integer = 60; const AAudience: string = '');
    destructor Destroy; override;
    function ValidateToken(const Token: string; out JWT: TJWTToken): Boolean; overload;
    function ValidateToken(const Token: string; out JWT: TJWTToken; const ClientId: string): Boolean; overload;
    function CreateToken(const Subject: string; const CustomClaims: TJSONObject = nil; const JwtId: string = ''): string;
    function ExtractTokenFromAuthHeader(const AuthHeader: string): string;
    function RefreshToken(const Token: string; out NewToken: string): Boolean; overload;
    function RefreshToken(const Token: string; out NewToken: string; const ClientId: string): Boolean; overload;
    procedure ClearValidationHistory;

    property SecretKey: string read FSecretKey write FSecretKey;
    property Issuer: string read FIssuer write FIssuer;
    property Audience: string read FAudience write FAudience;
    property TokenExpiration: Integer read FTokenExpiration write FTokenExpiration;
    property ClockSkewTolerance: Integer read FClockSkewTolerance write FClockSkewTolerance;
    property MaxTokenSize: Integer read FMaxTokenSize write FMaxTokenSize;
    property AllowedAlgorithms: TArray<string> read FAllowedAlgorithms write FAllowedAlgorithms;
    property MaxValidationAttempts: Integer read FMaxValidationAttempts write FMaxValidationAttempts;
    property ValidationWindowMinutes: Integer read FValidationWindowMinutes write FValidationWindowMinutes;
    property EnableSecurityLogging: Boolean read FEnableSecurityLogging write FEnableSecurityLogging;
  end;

implementation

{ TJWTToken }

constructor TJWTToken.Create;
begin
  inherited Create;
  FDecoded := nil;
  FHeaderDecoded := nil;
  Clear;
end;

destructor TJWTToken.Destroy;
begin
  SecureClear;
  inherited Destroy;
end;

function TJWTToken.GetClaim(const Name: string): string;
var
  Value: TJSONValue;
begin
  Result := '';
  try
    if Assigned(FDecoded) then
    begin
      Value := FDecoded.FindValue(Name);
      if Assigned(Value) then
        Result := Value.Value;
    end;
  except
    on E: Exception do
      Result := '';
  end;
end;

procedure TJWTToken.Clear;
begin
  try
    if Assigned(FDecoded) then
      FreeAndNil(FDecoded);
    if Assigned(FHeaderDecoded) then
      FreeAndNil(FHeaderDecoded);
  except
  end;

  FHeader := '';
  FPayload := '';
  FSignature := '';
  FRaw := '';
  FExpirationTime := 0;
  FIssuedAt := 0;
  FNotBefore := 0;
  FIsValid := False;
  FSubject := '';
  FIssuer := '';
  FAudience := '';
  FJwtId := '';
  FLastError := jeNone;
  FErrorMessage := '';
end;

procedure TJWTToken.SecureClear;
begin
  if FRaw <> '' then
  begin
    FillChar(FRaw[1], Length(FRaw) * SizeOf(Char), 0);
    FRaw := '';
  end;

  if FSignature <> '' then
  begin
    FillChar(FSignature[1], Length(FSignature) * SizeOf(Char), 0);
    FSignature := '';
  end;

  Clear;
end;

{ TJWTManager }

constructor TJWTManager.Create(const ASecretKey,
                                     AIssuer: string;
                                     ATokenExpiration: Integer;
                               const AAudience: string);
begin
  inherited Create;
  try
    if not IsValidSecretKey(ASecretKey) then
      raise Exception.Create('Invalid secret key: must be at least 32 characters long and have enough entropy.');

    FSecretKey := ASecretKey;
    FIssuer := AIssuer;
    FAudience := AAudience;
    FTokenExpiration := ATokenExpiration;
    FClockSkewTolerance := 30;
    FMaxTokenSize := 8192;
    FMaxValidationAttempts := 10;
    FValidationWindowMinutes := 15;
    FEnableSecurityLogging := True;
    FAllowedAlgorithms := ['HS256'];
    FValidationAttempts := TDictionary<string, TValidationAttempt>.Create;
    FValidationLock := TCriticalSection.Create;
    LogSecurityEvent('JWT Manager initialized', Format('Issuer: %s', [AIssuer]));
  except
    on E: Exception do
      raise Exception.Create('Failed to initialize JWT Manager: ' + E.Message);
  end;
end;

destructor TJWTManager.Destroy;
begin
  try
    LogSecurityEvent('JWT Manager destroyed');
    SecureZeroMemory(FSecretKey);
    SetLength(FAllowedAlgorithms, 0);
    if Assigned(FValidationAttempts) then
      FValidationAttempts.Free;
    if Assigned(FValidationLock) then
      FValidationLock.Free;
  finally
    inherited Destroy;
  end;
end;

function TJWTManager.IsValidSecretKey(const Key: string): Boolean;
var
  UniqueChars: Integer;
  CharSet: set of AnsiChar;
begin
  Result := False;
  if Length(Key) < 32 then Exit;
  if Trim(Key) = '' then Exit;

  UniqueChars := 0;
  CharSet := [];
  for var C in Key do
  begin
    var AC: AnsiChar := AnsiChar(C);
    if not (AC in CharSet) then
    begin
      Include(CharSet, AC);
      Inc(UniqueChars);
    end;
  end;
  Result := UniqueChars >= 16;
end;

function TJWTManager.ValidateAlgorithm(const Algorithm: string): Boolean;
begin
  Result := False;
  try
    if SameText(Algorithm, 'none') then
    begin
      LogSecurityEvent('Security Alert: Blocked "none" algorithm attack attempt.', Algorithm);
      Exit;
    end;

    for var AllowedAlg in FAllowedAlgorithms do
    begin
      if SameText(Algorithm, AllowedAlg) then
      begin
        Result := True;
        Exit;
      end;
    end;
  except
    on E: Exception do
    begin
      LogSecurityEvent('Algorithm validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.SecureCompare(const A, B: string): Boolean;
var
  i, MaxLen, Diff: Integer;
begin
  MaxLen := Max(Length(A), Length(B));
  Diff := Length(A) xor Length(B);

  for i := 1 to MaxLen do
  begin
    var aChar: Word := 0;
    var bChar: Word := 0;
    if i <= Length(A) then aChar := Ord(A[i]);
    if i <= Length(B) then bChar := Ord(B[i]);
    Diff := Diff or (aChar xor bChar);
  end;
  Result := Diff = 0;
end;

function TJWTManager.DecodeBase64Url(const Input: string): string;
var
  DecodedBytes: TBytes;
begin
  Result := '';
  try
    DecodedBytes := TNetEncoding.Base64Url.DecodeStringToBytes(Input);
    Result := TEncoding.UTF8.GetString(DecodedBytes);
  except
    on E: Exception do
    begin
      LogSecurityEvent('Base64Url decode error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.EncodeBase64Url(const Input: TBytes): string;
begin
  Result := '';
  try
    Result := TNetEncoding.Base64Url.EncodeBytesToString(Input);
  except
    on E: Exception do
    begin
      LogSecurityEvent('Base64Url encode error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.ParseJsonSafely(const JsonStr: string): TJSONObject;
begin
  Result := nil;
  try
    if Length(JsonStr) > 4096 then
    begin
      LogSecurityEvent('JSON parsing rejected', Format('Size (%d bytes) exceeds limit (4096)', [Length(JsonStr)]));
      Exit;
    end;
    Result := TJSONObject.ParseJSONValue(JsonStr) as TJSONObject;
  except
    on E: Exception do
    begin
      LogSecurityEvent('JSON parsing error', E.Message);
      if Assigned(Result) then
        FreeAndNil(Result);
    end;
  end;
end;

function TJWTManager.CreateSignature(const HeaderPayload: string): string;
const
  BlockSize = 64;
var
  DataBytes, KeyBytes, PaddedKey, o_key_pad, i_key_pad, InnerHash, OuterHash, HashedKey: TBytes;
  i: Integer;
  KeyAnsi, InnerDataAnsi, OuterDataAnsi: AnsiString;
begin
  Result := '';
  DataBytes := TEncoding.UTF8.GetBytes(HeaderPayload);
  KeyBytes := TEncoding.UTF8.GetBytes(FSecretKey);
  SetLength(PaddedKey, BlockSize);
  if Length(KeyBytes) > BlockSize then
  begin
    SetString(KeyAnsi, PAnsiChar(KeyBytes), Length(KeyBytes));
    HashedKey := THashSHA2.GetHashBytes(string(KeyAnsi), THashSHA2.TSHA2Version.SHA256);
    Move(HashedKey[0], PaddedKey[0], Length(HashedKey));
  end
  else
  begin
    Move(KeyBytes[0], PaddedKey[0], Length(KeyBytes));
  end;
  SetLength(o_key_pad, BlockSize);
  SetLength(i_key_pad, BlockSize);
  for i := 0 to BlockSize - 1 do
  begin
    i_key_pad[i] := PaddedKey[i] xor $36;
    o_key_pad[i] := PaddedKey[i] xor $5C;
  end;
  var InnerDataBytes := i_key_pad + DataBytes;
  SetString(InnerDataAnsi, PAnsiChar(InnerDataBytes), Length(InnerDataBytes));
  InnerHash := THashSHA2.GetHashBytes(string(InnerDataAnsi), THashSHA2.TSHA2Version.SHA256);
  var OuterDataBytes := o_key_pad + InnerHash;
  SetString(OuterDataAnsi, PAnsiChar(OuterDataBytes), Length(OuterDataBytes));
  OuterHash := THashSHA2.GetHashBytes(string(OuterDataAnsi), THashSHA2.TSHA2Version.SHA256);
  Result := EncodeBase64Url(OuterHash);
end;

function TJWTManager.VerifySignature(const HeaderPayload, Signature: string): Boolean;
var
  ExpectedSignature: string;
begin
  Result := False;
  try
    ExpectedSignature := CreateSignature(HeaderPayload);
    Result := (ExpectedSignature <> '') and SecureCompare(ExpectedSignature, Signature);
    if not Result then
      LogSecurityEvent('Invalid signature detected.');
  except
    on E: Exception do
    begin
      LogSecurityEvent('Signature verification error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.ValidateStandardClaims(const PayloadObj: TJSONObject; out Error: TJWTError; out ErrorMsg: string): Boolean;
var
  ExpTime, IatTime, NbfTime: Int64;
  CurrentTime: TDateTime;
  ClaimValue: string;
begin
  Result := False;
  Error := jeNone;
  ErrorMsg := '';
  CurrentTime := Now;
  try
    if PayloadObj.TryGetValue<Int64>('exp', ExpTime) then
    begin
      if CurrentTime > IncSecond(UnixToDateTime(ExpTime), FClockSkewTolerance) then
      begin
        Error := jeExpiredToken; ErrorMsg := 'Token has expired';
        LogSecurityEvent('Expired token', Format('Exp: %s, Now: %s', [DateTimeToStr(UnixToDateTime(ExpTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;

    if PayloadObj.TryGetValue<Int64>('iat', IatTime) then
    begin
      if UnixToDateTime(IatTime) > IncSecond(CurrentTime, FClockSkewTolerance) then
      begin
        Error := jeTokenFromFuture; ErrorMsg := 'Token issued in the future (iat claim)';
        LogSecurityEvent('Token from future', Format('Iat: %s, Now: %s', [DateTimeToStr(UnixToDateTime(IatTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;

    if PayloadObj.TryGetValue<Int64>('nbf', NbfTime) then
    begin
      if CurrentTime < IncSecond(UnixToDateTime(NbfTime), -FClockSkewTolerance) then
      begin
        Error := jeNotYetValid; ErrorMsg := 'Token is not yet valid (nbf claim)';
        LogSecurityEvent('Token not yet valid', Format('Nbf: %s, Now: %s', [DateTimeToStr(UnixToDateTime(NbfTime)), DateTimeToStr(CurrentTime)]));
        Exit;
      end;
    end;
    if (FIssuer <> '') and PayloadObj.TryGetValue<string>('iss', ClaimValue) then
    begin
      if ClaimValue <> FIssuer then
      begin
        Error := jeInvalidIssuer; ErrorMsg := 'Invalid issuer';
        LogSecurityEvent('Invalid issuer', Format('Expected: %s, Got: %s', [FIssuer, ClaimValue]));
        Exit;
      end;
    end;
    if (FAudience <> '') and PayloadObj.TryGetValue<string>('aud', ClaimValue) then
    begin
      if ClaimValue <> FAudience then
      begin
        Error := jeInvalidAudience; ErrorMsg := 'Invalid audience';
        LogSecurityEvent('Invalid audience', Format('Expected: %s, Got: %s', [FAudience, ClaimValue]));
        Exit;
      end;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      Error := jeParsingError; ErrorMsg := 'Error validating claims: ' + E.Message;
      LogSecurityEvent('Claims validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.ValidateTokenSize(const Token: string): Boolean;
begin
  Result := Length(Token) <= FMaxTokenSize;
  if not Result then
    LogSecurityEvent('Token size validation failed', Format('Size: %d, Max: %d', [Length(Token), FMaxTokenSize]));
end;

function TJWTManager.ValidateHeaderSafely(const HeaderObj: TJSONObject): Boolean;
var
  Algorithm, TokenType: string;
begin
  Result := False;
  try
    if not HeaderObj.TryGetValue<string>('alg', Algorithm) then
    begin
      LogSecurityEvent('Header validation failed', 'Missing "alg" claim');
      Exit;
    end;

    if not ValidateAlgorithm(Algorithm) then
    begin
      LogSecurityEvent('Header validation failed', 'Algorithm not allowed: ' + Algorithm);
      Exit;
    end;

    if HeaderObj.TryGetValue<string>('typ', TokenType) then
    begin
      if not SameText(TokenType, 'JWT') then
      begin
        LogSecurityEvent('Header validation failed', 'Invalid "typ" claim: ' + TokenType);
        Exit;
      end;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      LogSecurityEvent('Header validation error', E.Message);
      Result := False;
    end;
  end;
end;

function TJWTManager.IsRateLimited(const ClientId: string): Boolean;
var
  Attempt: TValidationAttempt;
  CurrentTime: TDateTime;
begin
  Result := False;
  if (ClientId = '') or (FMaxValidationAttempts <= 0) then Exit;

  FValidationLock.Enter;
  try
    CurrentTime := Now;
    if FValidationAttempts.TryGetValue(ClientId, Attempt) then
    begin
      if MinutesBetween(CurrentTime, Attempt.LastAttempt) >= FValidationWindowMinutes then
      begin
        Attempt.Count := 0;
        Attempt.LastAttempt := CurrentTime;
        FValidationAttempts.AddOrSetValue(ClientId, Attempt);
      end
      else if Attempt.Count >= FMaxValidationAttempts then
      begin
        Result := True;
        LogSecurityEvent('Rate limit exceeded', Format('Client: %s, Attempts: %d', [ClientId, Attempt.Count]));
      end;
    end;
  finally
    FValidationLock.Leave;
  end;
end;

procedure TJWTManager.UpdateValidationAttempt(const ClientId: string);
var
  Attempt: TValidationAttempt;
  CurrentTime: TDateTime;
begin
  if (ClientId = '') or (FMaxValidationAttempts <= 0) then Exit;

  FValidationLock.Enter;
  try
    CurrentTime := Now;
    if FValidationAttempts.TryGetValue(ClientId, Attempt) then
    begin
      if MinutesBetween(CurrentTime, Attempt.LastAttempt) >= FValidationWindowMinutes then
        Attempt.Count := 1
      else
        Inc(Attempt.Count);
    end
    else
      Attempt.Count := 1;

    Attempt.LastAttempt := CurrentTime;
    FValidationAttempts.AddOrSetValue(ClientId, Attempt);
  finally
    FValidationLock.Leave;
  end;
end;

procedure TJWTManager.LogSecurityEvent(const Event: string; const Details: string);
begin
end;

function TJWTManager.GenerateSecureJti: string;
begin
  Result := THashSHA2.GetHashString(
    GUIDToString(TGuid.NewGuid) +
    IntToStr(DateTimeToUnix(Now)) +
    IntToStr(Random(MaxInt)), THashSHA2.TSHA2Version.SHA256);
end;

procedure TJWTManager.SecureZeroMemory(var Str: string);
begin
  if Str <> '' then
  begin
    FillChar(Str[1], Length(Str) * SizeOf(Char), 0);
    Str := '';
  end;
end;

function TJWTManager.ExtractTokenFromAuthHeader(const AuthHeader: string): string;
begin
  Result := '';
  try
    if StartsText('Bearer ', AuthHeader) then
      Result := Trim(Copy(AuthHeader, 8, MaxInt));
  except
    on E: Exception do
    begin
      LogSecurityEvent('Auth header extraction error', E.Message);
      Result := '';
    end;
  end;
end;

function TJWTManager.ValidateToken(const Token: string; out JWT: TJWTToken): Boolean;
begin
  Result := ValidateToken(Token, JWT, '');
end;

function TJWTManager.ValidateToken(const Token: string; out JWT: TJWTToken; const ClientId: string): Boolean;
var
  TokenParts: TArray<string>;
  HeaderObj, PayloadObj: TJSONObject;
  Error: TJWTError;
  ErrorMsg: string;
  ExpTime, IatTime, NbfTime: Int64;
  SubValue, IssValue, AudValue, JtiValue: string;
begin
  Result := False;
  JWT := TJWTToken.Create;
  JWT.Raw := Token;
  HeaderObj := nil;
  PayloadObj := nil;
  try
    if IsRateLimited(ClientId) then
    begin
      JWT.LastError := jeRateLimited;
      JWT.ErrorMessage := 'Too many validation attempts.';
      Exit;
    end;
    UpdateValidationAttempt(ClientId);

    if not ValidateTokenSize(Token) then
    begin
      JWT.LastError := jeTokenTooLarge;
      JWT.ErrorMessage := Format('Token size (%d) exceeds maximum (%d bytes).', [Length(Token), FMaxTokenSize]);
      Exit;
    end;

    TokenParts := Token.Split(['.']);
    if Length(TokenParts) <> 3 then
    begin
      JWT.LastError := jeInvalidFormat;
      JWT.ErrorMessage := 'Token must have exactly 3 parts separated by dots.';
      LogSecurityEvent('Invalid token format', Format('Parts found: %d', [Length(TokenParts)]));
      Exit;
    end;
    JWT.Header := TokenParts[0];
    JWT.Payload := TokenParts[1];
    JWT.Signature := TokenParts[2];

    HeaderObj := ParseJsonSafely(DecodeBase64Url(JWT.Header));
    if not Assigned(HeaderObj) then
    begin
      JWT.LastError := jeInvalidHeader;
      JWT.ErrorMessage := 'Cannot decode or parse token header JSON.';
      Exit;
    end;

    if not ValidateHeaderSafely(HeaderObj) then
    begin
      JWT.LastError := jeInvalidHeader;
      JWT.ErrorMessage := 'Invalid header content (e.g., algorithm not allowed).';
      raise Exception.Create(JWT.ErrorMessage);
    end;

    if not VerifySignature(JWT.Header + '.' + JWT.Payload, JWT.Signature) then
    begin
      JWT.LastError := jeInvalidSignature;
      JWT.ErrorMessage := 'Invalid token signature.';
      raise Exception.Create(JWT.ErrorMessage);
    end;

    PayloadObj := ParseJsonSafely(DecodeBase64Url(JWT.Payload));
    if not Assigned(PayloadObj) then
    begin
      JWT.LastError := jeInvalidPayload;
      JWT.ErrorMessage := 'Cannot decode or parse token payload JSON.';
      raise Exception.Create(JWT.ErrorMessage);
    end;
    if not ValidateStandardClaims(PayloadObj, Error, ErrorMsg) then
    begin
      JWT.LastError := Error;
      JWT.ErrorMessage := ErrorMsg;
      raise Exception.Create(JWT.ErrorMessage);
    end;

    if PayloadObj.TryGetValue<Int64>('exp', ExpTime) then
       JWT.ExpirationTime := UnixToDateTime(ExpTime);
    if PayloadObj.TryGetValue<Int64>('iat', IatTime) then
       JWT.IssuedAt := UnixToDateTime(IatTime);
    if PayloadObj.TryGetValue<Int64>('nbf', NbfTime) then
       JWT.NotBefore := UnixToDateTime(NbfTime);
    if PayloadObj.TryGetValue<string>('sub', SubValue) then
       JWT.Subject := SubValue;
    if PayloadObj.TryGetValue<string>('iss', IssValue) then
       JWT.Issuer := IssValue;
    if PayloadObj.TryGetValue<string>('aud', AudValue) then
       JWT.Audience := AudValue;
    if PayloadObj.TryGetValue<string>('jti', JtiValue) then
       JWT.JwtId := JtiValue;
    //PayloadObj.Free;
    //HeaderObj.Free;


    JWT.HeaderDecoded := HeaderObj;
    JWT.Decoded := PayloadObj;
    JWT.IsValid := True;
    Result := True;
  except
    on E: Exception do
    begin
      if JWT.LastError = jeNone then
      begin
        JWT.LastError := jeParsingError;
        JWT.ErrorMessage := 'Unexpected error during token validation: ' + E.Message;
      end;
      LogSecurityEvent('Token validation failed', JWT.ErrorMessage);
      Result := False;
      if Assigned(HeaderObj) then HeaderObj.Free;
      if Assigned(PayloadObj) then PayloadObj.Free;
    end;
  end;
end;

function TJWTManager.CreateToken(const Subject: string; const CustomClaims: TJSONObject; const JwtId: string): string;
var
  Header, Payload: TJSONObject;
  HeaderBase64, PayloadBase64, Signature: string;
  CurrentTime: TDateTime;
  GeneratedJti: string;
  HeaderBytes, PayloadBytes: TBytes;
begin
  Result := '';
  Header := nil;
  Payload := nil;
  try
    CurrentTime := Now;
    Header := TJSONObject.Create;
    Header.AddPair('alg', 'HS256');
    Header.AddPair('typ', 'JWT');

    Payload := TJSONObject.Create;
    Payload.AddPair('sub', Subject);
    if FIssuer <> '' then Payload.AddPair('iss', FIssuer);
    if FAudience <> '' then Payload.AddPair('aud', FAudience);
    Payload.AddPair('iat', TJSONNumber.Create(DateTimeToUnix(CurrentTime)));
    Payload.AddPair('exp', TJSONNumber.Create(DateTimeToUnix(IncMinute(CurrentTime, FTokenExpiration))));

    GeneratedJti := IfThen(JwtId <> '', JwtId, GenerateSecureJti);
    Payload.AddPair('jti', GeneratedJti);
    if Assigned(CustomClaims) then
    begin
      for var Pair in CustomClaims do
      begin
        if not (SameText(Pair.JsonString.Value, 'sub') or SameText(Pair.JsonString.Value, 'iss') or
                SameText(Pair.JsonString.Value, 'aud') or SameText(Pair.JsonString.Value, 'iat') or
                SameText(Pair.JsonString.Value, 'exp') or SameText(Pair.JsonString.Value, 'nbf') or
                SameText(Pair.JsonString.Value, 'jti')) then
          Payload.AddPair(Pair.JsonString.Value, Pair.JsonValue.Clone as TJSONValue);
      end;
    end;

    HeaderBytes := TEncoding.UTF8.GetBytes(Header.ToString);
    PayloadBytes := TEncoding.UTF8.GetBytes(Payload.ToString);
    HeaderBase64 := EncodeBase64Url(HeaderBytes);
    PayloadBase64 := EncodeBase64Url(PayloadBytes);
    if (HeaderBase64 = '') or (PayloadBase64 = '') then
    begin
      LogSecurityEvent('Token creation failed', 'Base64Url encoding of header or payload failed.');
      Exit;
    end;
    Signature := CreateSignature(HeaderBase64 + '.' + PayloadBase64);
    if Signature = '' then
    begin
      LogSecurityEvent('Token creation failed', 'Signature creation failed.');
      Exit;
    end;
    Result := HeaderBase64 + '.' + PayloadBase64 + '.' + Signature;
    LogSecurityEvent('Token created successfully', Format('Subject: %s, JTI: %s', [Subject, GeneratedJti]));
  finally
    if Assigned(Header) then Header.Free;
    if Assigned(Payload) then Payload.Free;
  end;
end;

function TJWTManager.RefreshToken(const Token: string; out NewToken: string): Boolean;
begin
  Result := RefreshToken(Token, NewToken, '');
end;

function TJWTManager.RefreshToken(const Token: string; out NewToken: string; const ClientId: string): Boolean;
var
  JWT: TJWTToken;
  CustomClaims: TJSONObject;
begin
  Result := False;
  NewToken := '';
  JWT := nil;
  CustomClaims := nil;
  try
    if not ValidateToken(Token, JWT, ClientId) then
    begin
      LogSecurityEvent('Token refresh failed', 'The provided token is invalid. Reason: ' + JWT.ErrorMessage);
      Exit;
    end;
    CustomClaims := TJSONObject.Create;
    if Assigned(JWT.Decoded) then
      for var Pair in JWT.Decoded do
        if not (SameText(Pair.JsonString.Value, 'sub') or SameText(Pair.JsonString.Value, 'iss') or
                SameText(Pair.JsonString.Value, 'aud') or SameText(Pair.JsonString.Value, 'iat') or
                SameText(Pair.JsonString.Value, 'exp') or SameText(Pair.JsonString.Value, 'nbf') or
                SameText(Pair.JsonString.Value, 'jti')) then
          CustomClaims.AddPair(Pair.JsonString.Value, Pair.JsonValue.Clone as TJSONValue);

    Sleep(1);
    NewToken := CreateToken(JWT.Subject, CustomClaims);
    Result := NewToken <> '';
    if Result then
      LogSecurityEvent('Token refreshed successfully', Format('Subject: %s', [JWT.Subject]))
    else
      LogSecurityEvent('Token refresh failed', 'Could not create new token.');
  finally
    if Assigned(JWT) then JWT.Free;
    if Assigned(CustomClaims) then CustomClaims.Free;
  end;
end;

procedure TJWTManager.ClearValidationHistory;
begin
  FValidationLock.Enter;
  try
    FValidationAttempts.Clear;
    LogSecurityEvent('Validation history cleared.');
  finally
    FValidationLock.Leave;
  end;
end;

end.
