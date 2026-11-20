unit GRequestHeaders;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  GLogger,
  GRequestBody,
  GRequestTypes,
  GRequestHeaderValidator,
  GRequestEncodingAndRecovery;

type
  THttpHeaders = class
  private
    FHeaders: TObjectDictionary<string, TStringList>;
    FPooledLists: TList<TStringList>;
    FSlotNames: array[0..15] of string;
    FSlotValues: array[0..15] of string;
    FSlotCount: Integer;
    FUseDict: Boolean;
    FValidationLevel: TValidationLevel;
    FContentEncodingHandler: TContentEncodingHandler;
    function NormalizeHeaderName(const HeaderName: string): string;
    procedure EnsureDictMode;
  protected
    function ParseFoldedHeader(const Lines: TStringList; StartIndex: Integer; out EndIndex: Integer): string;
    procedure ValidateAndAdd(const Name, Value: string);
    function GetContentLength: string;
    function GetContentType: string;
    function GetContentEncoding: string;
    function GetUserAgent: string;
    function GetHost: string;
    function GetAuthorization: string;
    function GetCookie: string;
    function GetReferer: string;
    function GetTransferEncoding: string;
    function GetConnection: string;
  public
    constructor Create(ValidationLevel: TValidationLevel = vlModerate);
    destructor Destroy; override;
    procedure AddHeader(const Name, Value: string);
    procedure AddNormalizedHeader(const NormalizedName, CleanValue: string);
    procedure AddMultipleValues(const Name: string; const Values: TArray<string>);
    function GetHeader(const Name: string): string;
    function GetHeaderValues(const Name: string): TArray<string>;
    function HasHeader(const Name: string): Boolean;
    function GetFirstValue(const Name: string): string;
    function GetLastValue(const Name: string): string;
    procedure Clear;
    function GetHeaderNames: TArray<string>;
    function Count: Integer;
    function DetectSecurityThreats: TArray<TSecurityThreat>;
    function SanitizeHeaders: Integer;
    function GetContentEncodings: TArray<TContentEncoding>;
    function IsCompressionUsed: Boolean;
    function ProcessInternationalHeader(const Value: string): string;
    function GetSlotName(Index: Integer): string; inline;
    function GetSlotValue(Index: Integer): string; inline;
    property UseDict: Boolean read FUseDict;
    property SlotCount: Integer read FSlotCount;
    property ValidationLevel: TValidationLevel read FValidationLevel write FValidationLevel;
    property ContentLength: string read GetContentLength;
    property ContentType: string read GetContentType;
    property ContentEncoding: string read GetContentEncoding;
    property UserAgent: string read GetUserAgent;
    property Host: string read GetHost;
    property Authorization: string read GetAuthorization;
    property Cookie: string read GetCookie;
    property Referer: string read GetReferer;
    property TransferEncoding: string read GetTransferEncoding;
    property Connection: string read GetConnection;
    property Headers: TObjectDictionary<string, TStringList> read FHeaders;
  end;

implementation

type
  THeaderValidatorAccess = class(THeaderValidator);

function THttpHeaders.GetSlotName(Index: Integer): string;
begin
  Result := FSlotNames[Index];
end;

function THttpHeaders.GetSlotValue(Index: Integer): string;
begin
  Result := FSlotValues[Index];
end;

constructor THttpHeaders.Create(ValidationLevel: TValidationLevel);
begin
  inherited Create;

  FHeaders := nil;
  FPooledLists := nil;
  FSlotCount := 0;
  FUseDict := False;
  FValidationLevel := ValidationLevel;
  FContentEncodingHandler := TContentEncodingHandler.Create;
end;

destructor THttpHeaders.Destroy;
var
  Pair: TPair<string, TStringList>;
  I: Integer;
begin
  try
    if Assigned(FHeaders) then
    begin
      for Pair in FHeaders do
        Pair.Value.Free;
      FreeAndNil(FHeaders);
    end;
    if Assigned(FPooledLists) then
    begin
      for I := 0 to FPooledLists.Count - 1 do
        FPooledLists[I].Free;
      FreeAndNil(FPooledLists);
    end;
    FreeAndNil(FContentEncodingHandler);
  finally
    inherited Destroy;
  end;
end;

function THttpHeaders.NormalizeHeaderName(const HeaderName: string): string;
var
  Len: Integer;
begin
  Len := Length(HeaderName);
  case Len of
    4:
      if (HeaderName = 'Host') or (HeaderName = 'host') then
        Exit('host');
    6:
      if (HeaderName = 'Accept') or (HeaderName = 'accept') then
        Exit('accept')
      else if (HeaderName = 'Origin') or (HeaderName = 'origin') then
        Exit('origin')
      else if (HeaderName = 'Cookie') or (HeaderName = 'cookie') then
        Exit('cookie');
    7:
      if (HeaderName = 'Referer') or (HeaderName = 'referer') then
        Exit('referer');
    10:
      if (HeaderName = 'Connection') or (HeaderName = 'connection') then
        Exit('connection')
      else if (HeaderName = 'User-Agent') or (HeaderName = 'user-agent') then
        Exit('user-agent');
    12:
      if (HeaderName = 'Content-Type') or (HeaderName = 'content-type') then
        Exit('content-type');
    13:
      if (HeaderName = 'Cache-Control') or (HeaderName = 'cache-control') then
        Exit('cache-control')
      else if (HeaderName = 'Authorization') or (HeaderName = 'authorization') then
        Exit('authorization');
    14:
      if (HeaderName = 'Content-Length') or (HeaderName = 'content-length') then
        Exit('content-length');
    15:
      if (HeaderName = 'Accept-Encoding') or (HeaderName = 'accept-encoding') then
        Exit('accept-encoding');
    17:
      if (HeaderName = 'Transfer-Encoding') or (HeaderName = 'transfer-encoding') then
        Exit('transfer-encoding');
  end;
  Result := LowerCase(Trim(HeaderName));
end;

function THttpHeaders.ParseFoldedHeader(const Lines: TStringList; StartIndex: Integer;
                                        out EndIndex: Integer): string;
var
  I: Integer;
  Line: string;
  FirstLine: Boolean;
begin
  Result := '';
  EndIndex := StartIndex;
  FirstLine := True;
  try
    for I := StartIndex to Lines.Count - 1 do
    begin
      Line := Lines[I];
      if (Length(Line) > 0) and CharInSet(Line[1], [' ', #9]) then
      begin
        if not FirstLine then
          Result := Result + ' ';
        Result := Result + Trim(Line);
        EndIndex := I;
      end
      else
      begin
        if FirstLine then
        begin
          Result := Line;
          EndIndex := I;
          FirstLine := False;
        end
        else
          Break;
      end;
    end;
  except
    on E: Exception do
    begin
      Result := Lines[StartIndex];
      EndIndex := StartIndex;
    end;
  end;
end;

function THttpHeaders.ProcessInternationalHeader(const Value: string): string;
var
  I: Integer;
  C: Char;
  ByteValue: Byte;
begin
  Result := '';
  try
    for I := 1 to Length(Value) do
    begin
      C := Value[I];
      ByteValue := Ord(C);

      if ByteValue <= 127 then
        Result := Result + C
      else
      begin
        case FValidationLevel of
          vlStrict:
            Continue;
          vlModerate:
            Result := Result + '?';
          vlPermissive:
            Result := Result + C;
        end;
      end;
    end;
    if Pos('=?', Result) > 0 then
    begin
      Result := StringReplace(Result, '=?UTF-8?B?', '', [rfReplaceAll, rfIgnoreCase]);
      Result := StringReplace(Result, '=?UTF-8?Q?', '', [rfReplaceAll, rfIgnoreCase]);
      Result := StringReplace(Result, '?=', '', [rfReplaceAll]);
    end;
  except
    Result := Value;
  end;
end;

procedure THttpHeaders.ValidateAndAdd(const Name, Value: string);
var
  ErrorMsg: string;
  SanitizedValue: string;
  IsContentTypeHeader: Boolean;
  IsKnownSafeHeader: Boolean;
  IsAcceptHeader: Boolean;
begin
  try
    IsContentTypeHeader := (LowerCase(Name) = 'content-type');
    IsAcceptHeader := (LowerCase(Name) = 'accept');
    IsKnownSafeHeader := IsContentTypeHeader or
                        IsAcceptHeader or
                        (LowerCase(Name) = 'user-agent') or
                        (LowerCase(Name) = 'host') or
                        (LowerCase(Name) = 'authorization') or
                        (LowerCase(Name) = 'cache-control') or
                        (LowerCase(Name) = 'connection') or
                        (LowerCase(Name) = 'content-length') or
                        (LowerCase(Name) = 'accept-language') or
                        (LowerCase(Name) = 'accept-encoding') or
                        (LowerCase(Name) = 'referer') or
                        (LowerCase(Name) = 'origin');
    if not THeaderValidator.ValidateHeaderName(Name, ErrorMsg) then
    begin
      case FValidationLevel of
        vlStrict:
          raise Exception.Create('Invalid header name: ' + ErrorMsg);
        vlModerate:
            raise Exception.Create('Invalid header name rejected: ' + ErrorMsg);
        vlPermissive:
          Logger.Info('  -> Permissive: Accepting invalid header name: ' + Name + ' (' + ErrorMsg + ')');
      end;
    end;
    if IsKnownSafeHeader then
    begin
      if IsContentTypeHeader then
      begin
        if (Pos('multipart/', LowerCase(Value)) > 0) or
           (Pos('application/', LowerCase(Value)) > 0) or
           (Pos('text/', LowerCase(Value)) > 0) then
        begin
          AddHeader(Name, Value);
          Exit;
        end;
      end
      else if IsAcceptHeader then
      begin
        if (Pos('text/', LowerCase(Value)) > 0) or
           (Pos('application/', LowerCase(Value)) > 0) or
           (Pos('*/*', LowerCase(Value)) > 0) or
           (Pos('q=0.', LowerCase(Value)) > 0) then
        begin
          AddHeader(Name, Value);
          Exit;
        end;
      end
      else if SameText(Name, 'Authorization') then
      begin
        AddHeader(Name, Value);
        Exit;
      end
      else
      begin
        if not THeaderValidatorAccess.HasSuspiciousPatterns(Value) then
        begin
          AddHeader(Name, Value);
          Exit;
        end;
      end;
    end;

    if not SameText(Name, 'Authorization') and THeaderValidatorAccess.HasSuspiciousPatterns(Value) then
    begin
      case FValidationLevel of
        vlStrict:
          raise Exception.Create('Suspicious patterns detected in header value: ' + Name);
        vlModerate:
          begin
            Logger.Error('  -> Moderate: SECURITY THREAT - I reject suspicious headline');
            raise Exception.Create('Security threat detected in header value: ' + Name);
          end;
        vlPermissive:
          Logger.Info('  -> Permissive: I accept the suspicious header');
      end;
    end;
    if THeaderValidatorAccess.HasSuspiciousPatterns(Name) then
    begin
      case FValidationLevel of
        vlStrict:
          raise Exception.Create('Suspicious patterns detected in header name: ' + Name);
        vlModerate:
          begin
            Logger.Error('  -> Moderate: SECURITY RISK - I reject suspicious header name');
            raise Exception.Create('Security threat detected in header name: ' + Name);
          end;
        vlPermissive:
          Logger.Info('  -> Permissive: I accept the suspicious header name');
      end;
    end;
    SanitizedValue := ProcessInternationalHeader(Value);
    if not THeaderValidator.ValidateHeaderValue(Name, SanitizedValue, ErrorMsg) then
    begin
      case FValidationLevel of
        vlStrict:
          raise Exception.Create('Invalid header value: ' + ErrorMsg);
        vlModerate:
          begin
            SanitizedValue := THeaderValidator.SanitizeHeaderValue(SanitizedValue);
          end;
        vlPermissive:
          Logger.Info('  -> Permissive: Accepting invalid header value for: ' + Name + ' (' + ErrorMsg + ')');
      end;
    end;
    AddHeader(Name, SanitizedValue);
  except
    on E: Exception do
    begin
      if (Pos('Security threat', E.Message) > 0) or
         (Pos('Suspicious patterns', E.Message) > 0) or
         (Pos('Invalid header name', E.Message) > 0) then
           raise;
      if FValidationLevel = vlStrict then
         raise;
    end;
  end;
end;

procedure THttpHeaders.EnsureDictMode;
var
  I: Integer;
  HeaderValues: TStringList;
begin
  if FUseDict then
    Exit;
  FUseDict := True;
  if not Assigned(FHeaders) then
    FHeaders := TObjectDictionary<string, TStringList>.Create([]);
  if not Assigned(FPooledLists) then
    FPooledLists := TList<TStringList>.Create;
  for I := 0 to FSlotCount - 1 do
  begin
    if not FHeaders.TryGetValue(FSlotNames[I], HeaderValues) then
    begin
      if Assigned(FPooledLists) and (FPooledLists.Count > 0) then
      begin
        HeaderValues := FPooledLists[FPooledLists.Count - 1];
        FPooledLists.Delete(FPooledLists.Count - 1);
      end
      else
        HeaderValues := TStringList.Create;
      FHeaders.Add(FSlotNames[I], HeaderValues);
    end;
    HeaderValues.Add(FSlotValues[I]);
    FSlotNames[I] := '';
    FSlotValues[I] := '';
  end;
  FSlotCount := 0;
end;

procedure THttpHeaders.AddHeader(const Name, Value: string);
var
  NormalizedName: string;
  CleanValue: string;
begin
  NormalizedName := NormalizeHeaderName(Name);
  if NormalizedName = '' then
    Exit;
  if (Length(Value) = 0) or ((Value[1] > ' ') and (Value[Length(Value)] > ' ')) then
    CleanValue := Value
  else
    CleanValue := Trim(Value);
  AddNormalizedHeader(NormalizedName, CleanValue);
end;

procedure THttpHeaders.AddNormalizedHeader(const NormalizedName, CleanValue: string);
var
  HeaderValues: TStringList;
  I: Integer;
begin
  if NormalizedName = '' then
    Exit;
  if not FUseDict then
  begin
    if FSlotCount = 0 then
    begin
      FSlotNames[0] := NormalizedName;
      FSlotValues[0] := CleanValue;
      FSlotCount := 1;
      Exit;
    end;
    for I := 0 to FSlotCount - 1 do
    begin
      if FSlotNames[I] = NormalizedName then
      begin
        EnsureDictMode;
        Break;
      end;
    end;
    if not FUseDict then
    begin
      if FSlotCount < 16 then
      begin
        FSlotNames[FSlotCount] := NormalizedName;
        FSlotValues[FSlotCount] := CleanValue;
        Inc(FSlotCount);
        Exit;
      end;
      EnsureDictMode;
    end;
  end;
  try
    if not FHeaders.TryGetValue(NormalizedName, HeaderValues) then
    begin
      if Assigned(FPooledLists) and (FPooledLists.Count > 0) then
      begin
        HeaderValues := FPooledLists[FPooledLists.Count - 1];
        FPooledLists.Delete(FPooledLists.Count - 1);
      end
      else
        HeaderValues := TStringList.Create;
      FHeaders.Add(NormalizedName, HeaderValues);
    end;
    HeaderValues.Add(CleanValue);
  except
    on E: Exception do
    begin
      Logger.Error('Error adding header "%s": %s', [NormalizedName, E.Message]);
      raise Exception.CreateFmt('Error adding header "%s": %s', [NormalizedName, E.Message]);
    end;
  end;
end;

procedure THttpHeaders.AddMultipleValues(const Name: string; const Values: TArray<string>);
var
  I: Integer;
begin
  try
    for I := 0 to Length(Values) - 1 do
      AddHeader(Name, Values[I]);
  except
    on E: Exception do
    begin
      Logger.Error('Error adding multiple values for header "%s": %s', [Name, E.Message]);
      raise Exception.CreateFmt('Error adding multiple values for header "%s": %s', [Name, E.Message]);
    end;
  end;
end;

function THttpHeaders.GetHeader(const Name: string): string;
var
  NormalizedName: string;
  HeaderValues: TStringList;
  I: Integer;
begin
  Result := '';
  try
    NormalizedName := NormalizeHeaderName(Name);
    if not FUseDict then
    begin
      for I := 0 to FSlotCount - 1 do
      begin
        if FSlotNames[I] = NormalizedName then
          Exit(FSlotValues[I]);
      end;
      Exit('');
    end;
    if FHeaders.TryGetValue(NormalizedName, HeaderValues) and (HeaderValues.Count > 0) then
      Result := HeaderValues[0];
  except
    Result := '';
  end;
end;

function THttpHeaders.GetHeaderValues(const Name: string): TArray<string>;
var
  NormalizedName: string;
  HeaderValues: TStringList;
  I: Integer;
begin
  SetLength(Result, 0);
  try
    NormalizedName := NormalizeHeaderName(Name);
    if not FUseDict then
    begin
      for I := 0 to FSlotCount - 1 do
      begin
        if FSlotNames[I] = NormalizedName then
        begin
          SetLength(Result, 1);
          Result[0] := FSlotValues[I];
          Exit;
        end;
      end;
      Exit;
    end;
    if FHeaders.TryGetValue(NormalizedName, HeaderValues) then
    begin
      SetLength(Result, HeaderValues.Count);
      for I := 0 to HeaderValues.Count - 1 do
        Result[I] := HeaderValues[I];
    end;
  except
    SetLength(Result, 0);
  end;
end;

function THttpHeaders.HasHeader(const Name: string): Boolean;
var
  NormalizedName: string;
  I: Integer;
begin
  try
    NormalizedName := NormalizeHeaderName(Name);
    if not FUseDict then
    begin
      for I := 0 to FSlotCount - 1 do
      begin
        if FSlotNames[I] = NormalizedName then
          Exit(True);
      end;
      Exit(False);
    end;
    Result := FHeaders.ContainsKey(NormalizedName);
  except
    Result := False;
  end;
end;

function THttpHeaders.GetFirstValue(const Name: string): string;
var
  Values: TArray<string>;
begin
  try
    Values := GetHeaderValues(Name);
    if Length(Values) > 0 then
      Result := Values[0]
    else
      Result := '';
  except
    Result := '';
  end;
end;

function THttpHeaders.GetLastValue(const Name: string): string;
var
  Values: TArray<string>;
begin
  try
    Values := GetHeaderValues(Name);
    if Length(Values) > 0 then
      Result := Values[Length(Values) - 1]
    else
      Result := '';
  except
    Result := '';
  end;
end;

procedure THttpHeaders.Clear;
var
  Pair: TPair<string, TStringList>;
  I: Integer;
begin
  try
    if not FUseDict then
    begin
      for I := 0 to FSlotCount - 1 do
      begin
        FSlotNames[I] := '';
        FSlotValues[I] := '';
      end;
      FSlotCount := 0;
      Exit;
    end;
    if Assigned(FHeaders) then
    begin
      for Pair in FHeaders do
      begin
        if Assigned(FPooledLists) and (FPooledLists.Count < 16) then
        begin
          Pair.Value.Clear;
          FPooledLists.Add(Pair.Value);
        end
        else
          Pair.Value.Free;
      end;
      FHeaders.Clear;
    end;
    FUseDict := False;
  except
  end;
end;

function THttpHeaders.GetHeaderNames: TArray<string>;
var
  I: Integer;
begin
  try
    if not FUseDict then
    begin
      SetLength(Result, FSlotCount);
      for I := 0 to FSlotCount - 1 do
        Result[I] := FSlotNames[I];
      Exit;
    end;
    Result := FHeaders.Keys.ToArray;
  except
    SetLength(Result, 0);
  end;
end;

function THttpHeaders.Count: Integer;
begin
  try
    if not FUseDict then
      Exit(FSlotCount);
    Result := FHeaders.Count;
  except
    Result := 0;
  end;
end;

function THttpHeaders.GetContentLength: string;
begin
  Result := GetHeader('Content-Length');
end;

function THttpHeaders.GetContentType: string;
begin
  Result := GetHeader('Content-Type');
end;

function THttpHeaders.GetContentEncoding: string;
begin
  Result := GetHeader('Content-Encoding');
end;

function THttpHeaders.GetUserAgent: string;
begin
  Result := GetHeader('User-Agent');
end;

function THttpHeaders.GetHost: string;
begin
  Result := GetHeader('Host');
end;

function THttpHeaders.GetAuthorization: string;
begin
  Result := GetHeader('Authorization');
end;

function THttpHeaders.GetCookie: string;
begin
  Result := GetHeader('Cookie');
end;

function THttpHeaders.GetReferer: string;
begin
  Result := GetHeader('Referer');
end;

function THttpHeaders.GetTransferEncoding: string;
begin
  Result := GetHeader('Transfer-Encoding');
end;

function THttpHeaders.GetConnection: string;
begin
  Result := GetHeader('Connection');
end;

function THttpHeaders.DetectSecurityThreats: TArray<TSecurityThreat>;
var
  Threats: TList<TSecurityThreat>;
  HeaderName: string;
  HeaderValues: TStringList;
  I: Integer;
  AllHeaders: TStringList;
begin
  if not FUseDict then
    EnsureDictMode;
  Threats := TList<TSecurityThreat>.Create;
  AllHeaders := TStringList.Create;
  try
    for HeaderName in FHeaders.Keys do
    begin
      if FHeaders.TryGetValue(HeaderName, HeaderValues) then
      begin
        for I := 0 to HeaderValues.Count - 1 do
          AllHeaders.Add(HeaderName + ': ' + HeaderValues[I]);
      end;
    end;
    if THeaderValidator.DetectRequestSmuggling(AllHeaders) <> stNone then
      Threats.Add(stRequestSmuggling);
    for HeaderName in FHeaders.Keys do
    begin
      if FHeaders.TryGetValue(HeaderName, HeaderValues) then
      begin
        for I := 0 to HeaderValues.Count - 1 do
        begin
          if THeaderValidatorAccess.HasSuspiciousPatterns(HeaderValues[I]) then
            Threats.Add(stHeaderInjection);
        end;
        if HeaderValues.Count > 10 then
          Threats.Add(stOversizeAttack);
      end;
      if not THeaderValidator.IsSafeHeaderName(HeaderName) then
        Threats.Add(stSuspiciousHeaders);
    end;
    Result := Threats.ToArray;
  finally
    Threats.Free;
    AllHeaders.Free;
  end;
end;

function THttpHeaders.SanitizeHeaders: Integer;
var
  HeaderName: string;
  HeaderValues: TStringList;
  I: Integer;
  OriginalValue, SanitizedValue: string;
begin
  Result := 0;
  if not FUseDict then
    EnsureDictMode;
  try
    for HeaderName in FHeaders.Keys do
    begin
      if FHeaders.TryGetValue(HeaderName, HeaderValues) then
      begin
        for I := 0 to HeaderValues.Count - 1 do
        begin
          OriginalValue := HeaderValues[I];
          SanitizedValue := THeaderValidator.SanitizeHeaderValue(OriginalValue);
          if SanitizedValue <> OriginalValue then
          begin
            HeaderValues[I] := SanitizedValue;
            Inc(Result);
          end;
        end;
      end;
    end;
  except
    on E: Exception do
      Logger.Error('[HttpHeaders.SanitizeHeaders] Exception during header sanitization: %s (%s)', [E.Message, E.ClassName]);
  end;
end;

function THttpHeaders.GetContentEncodings: TArray<TContentEncoding>;
var
  ContentEncodingHeader: string;
begin
  try
    ContentEncodingHeader := GetHeader('Content-Encoding');
    if ContentEncodingHeader = '' then
    begin
      SetLength(Result, 0);
      Exit;
    end;
    Result := FContentEncodingHandler.ParseContentEncoding(ContentEncodingHeader);
  except
    SetLength(Result, 0);
  end;
end;

function THttpHeaders.IsCompressionUsed: Boolean;
var
  Encodings: TArray<TContentEncoding>;
  Encoding: TContentEncoding;
begin
  Result := False;
  try
    Encodings := GetContentEncodings;
    for Encoding in Encodings do
    begin
      if Encoding in [ceGzip, ceDeflate, ceCompress, ceBrotli] then
      begin
        Result := True;
        Exit;
      end;
    end;
  except
    Result := False;
  end;
end;

end.
