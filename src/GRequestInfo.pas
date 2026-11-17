unit GRequestInfo;

interface

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.NetEncoding,
  System.Generics.Collections,
  Quick.Logger,
  GRequestBody,
  GRequestTypes,
  GRequestHeaderValidator,
  GRequestUriValidator,
  GRequestHeaders;

type
  THttpRequestInfo = class
  private
    FMethod: THttpMethod;
    FVersion: THttpVersion;
    FUri: string;
    FRawUri: string;
    FNormalizedUri: string;
    FQueryString: string;
    FPath: string;
    FFragment: string;
    FScheme: string;
    FAuthority: string;
    FTransferEncoding: TTransferEncoding;
    FConnectionType: TConnectionType;
    FContentLength: Int64;
    FContentEncodings: TArray<TContentEncoding>;
    FIsSecure: Boolean;
    FUriValidationErrors: TStringList;
    FQueryParameters: TDictionary<string, string>;
    function GetUriValidationErrors: TStringList;
    function GetQueryParameters: TDictionary<string, string>;
    procedure ClearValidationErrors;
    function HasValidationErrors: Boolean; inline;
    function ParseTransferEncoding(const EncodingStr: string): TTransferEncoding;
    function ParseConnectionType(const ConnectionStr: string): TConnectionType;
  public
    constructor Create;
    destructor Destroy; override;
    function StringToHttpMethod(const MethodStr: string): THttpMethod;
    function StringToHttpVersion(const VersionStr: string): THttpVersion;
    procedure ApplyFastHeaderInfo(ATransferEncoding: TTransferEncoding; AConnectionType: TConnectionType;
      AContentLength: Int64; const AContentEncodings: TArray<TContentEncoding>; AIsSecure: Boolean);
    procedure ValidateUriComponents;
    procedure ParseQueryString(const AQueryString: string; ADictionary: TDictionary<string, string>);
    procedure ParseUri(const RawUri: string);
    procedure ParseRequestLine(const RequestLine: string);
    function ParseRequestLinePtr(LinePtr: PByte; LineLen: Integer; var CachedUri: string): Boolean;
    procedure ParseFromHeaders(Headers: THttpHeaders);
    procedure Clear;
    property Method: THttpMethod read FMethod;
    property Version: THttpVersion read FVersion;
    property Uri: string read FUri;
    property RawUri: string read FRawUri;
    property NormalizedUri: string read FNormalizedUri;
    property QueryString: string read FQueryString;
    property Path: string read FPath;
    property Fragment: string read FFragment;
    property Scheme: string read FScheme;
    property Authority: string read FAuthority;
    property TransferEncoding: TTransferEncoding read FTransferEncoding;
    property ConnectionType: TConnectionType read FConnectionType;
    property ContentLength: Int64 read FContentLength;
    property ContentEncodings: TArray<TContentEncoding> read FContentEncodings;
    property IsSecure: Boolean read FIsSecure write FIsSecure;
    property UriValidationErrors: TStringList read GetUriValidationErrors;
    property QueryParameters: TDictionary<string, string> read GetQueryParameters;
    function MethodToString: string;
    function VersionToString: string;
    function HasBody: Boolean;
    function IsMethodSafe: Boolean;
    function IsMethodIdempotent: Boolean;
    function IsUriValid: Boolean;
    function GetUriValidationSummary: string;
  end;

function AsciiEqualsStrPtr(P: PByte; Len: Integer; const S: string): Boolean; inline;

implementation

type
  THeaderValidatorAccess = class(THeaderValidator);
  TUriValidatorAccess = class(TUriValidator);

function AsciiEqualsStrPtr(P: PByte; Len: Integer; const S: string): Boolean; inline;
var
  I: Integer;
begin
  if Length(S) <> Len then
    Exit(False);
  for I := 0 to Len - 1 do
  begin
    if Ord(S[I + 1]) <> P[I] then
      Exit(False);
  end;
  Result := True;
end;

constructor THttpRequestInfo.Create;
begin
  inherited Create;
  FQueryParameters := nil;
  FUriValidationErrors := nil;
  Clear;
end;

function THttpRequestInfo.GetUriValidationErrors: TStringList;
begin
  if FUriValidationErrors = nil then
    FUriValidationErrors := TStringList.Create;
  Result := FUriValidationErrors;
end;

function THttpRequestInfo.GetQueryParameters: TDictionary<string, string>;
begin
  if FQueryParameters = nil then
    FQueryParameters := TDictionary<string, string>.Create;
  Result := FQueryParameters;
end;

procedure THttpRequestInfo.ClearValidationErrors;
begin
  if (FUriValidationErrors <> nil) and (FUriValidationErrors.Count > 0) then
    ClearValidationErrors;
end;

function THttpRequestInfo.HasValidationErrors: Boolean;
begin
  Result := (FUriValidationErrors <> nil) and (FUriValidationErrors.Count > 0);
end;

destructor THttpRequestInfo.Destroy;
begin
  try
    FUriValidationErrors.Free;
    FQueryParameters.Free;
  finally
    inherited Destroy;
  end;
end;

procedure THttpRequestInfo.Clear;
begin
  FMethod := hmUnknown;
  FVersion := hvUnknown;
  FUri := '';
  FRawUri := '';
  FNormalizedUri := '';
  FQueryString := '';
  FPath := '';
  FFragment := '';
  FScheme := '';
  FAuthority := '';
  FTransferEncoding := teNone;
  FConnectionType := ctKeepAlive;
  FContentLength := -1;
  if Length(FContentEncodings) > 0 then
    SetLength(FContentEncodings, 0);
  FIsSecure := False;
  ClearValidationErrors;
end;

function THttpRequestInfo.StringToHttpMethod(const MethodStr: string): THttpMethod;
var
  UpperMethod: string;
begin
  try
    UpperMethod := UpperCase(Trim(MethodStr));
    if UpperMethod = 'GET' then
      Result := hmGET
    else if UpperMethod = 'POST' then
      Result := hmPOST
    else if UpperMethod = 'PUT' then
      Result := hmPUT
    else if UpperMethod = 'DELETE' then
      Result := hmDELETE
    else if UpperMethod = 'HEAD' then
      Result := hmHEAD
    else if UpperMethod = 'OPTIONS' then
      Result := hmOPTIONS
    else if UpperMethod = 'PATCH' then
      Result := hmPATCH
    else if UpperMethod = 'TRACE' then
      Result := hmTRACE
    else if UpperMethod = 'CONNECT' then
      Result := hmCONNECT
    else
      Result := hmUnknown;
  except
    Result := hmUnknown;
  end;
end;

function THttpRequestInfo.StringToHttpVersion(const VersionStr: string): THttpVersion;
var
  UpperVersion: string;
begin
  try
    UpperVersion := UpperCase(Trim(VersionStr));
    if UpperVersion = 'HTTP/1.0' then
      Result := hvHTTP10
    else if UpperVersion = 'HTTP/1.1' then
      Result := hvHTTP11
    else if UpperVersion = 'HTTP/2.0' then
      Result := hvHTTP20
    else if UpperVersion = 'HTTP/2' then
      Result := hvHTTP20
    else
      Result := hvUnknown;
  except
    Result := hvUnknown;
  end;
end;

function THttpRequestInfo.ParseTransferEncoding(const EncodingStr: string): TTransferEncoding;
var
  LowerEncoding: string;
begin
  try
    LowerEncoding := LowerCase(Trim(EncodingStr));
    if LowerEncoding = 'chunked' then
      Result := teChunked
    else if LowerEncoding = 'compress' then
      Result := teCompress
    else if LowerEncoding = 'deflate' then
      Result := teDeflate
    else if LowerEncoding = 'gzip' then
      Result := teGzip
    else if LowerEncoding = 'identity' then
      Result := teIdentity
    else
      Result := teNone;
  except
    Result := teNone;
  end;
end;

function THttpRequestInfo.ParseConnectionType(const ConnectionStr: string): TConnectionType;
var
  LowerConnection: string;
begin
  try
    LowerConnection := LowerCase(Trim(ConnectionStr));
    if LowerConnection = 'close' then
      Result := ctClose
    else if LowerConnection = 'upgrade' then
      Result := ctUpgrade
    else
      Result := ctKeepAlive;
  except
    Result := ctKeepAlive;
  end;
end;

procedure THttpRequestInfo.ParseQueryString(const AQueryString: string; ADictionary: TDictionary<string, string>);
var
  StartIndex: Integer;
  PairEndIndex: Integer;
  SeparatorPos: Integer;
  Key, Value: string;
begin
  if not Assigned(ADictionary) then
    raise EArgumentNilException.Create('ADictionary cannot be nil');
  ADictionary.Clear;
  if AQueryString.Trim = '' then
    Exit;

  StartIndex := 1;
  while StartIndex <= Length(AQueryString) do
  begin
    PairEndIndex := Pos('&', AQueryString, StartIndex);
    if PairEndIndex = 0 then
      PairEndIndex := Length(AQueryString) + 1;
    SeparatorPos := PosEx('=', AQueryString, StartIndex);
    if (SeparatorPos > 0) and (SeparatorPos < PairEndIndex) then
    begin
      Key := TNetEncoding.URL.Decode(Copy(AQueryString, StartIndex, SeparatorPos - StartIndex));
      Value := TNetEncoding.URL.Decode(Copy(AQueryString, SeparatorPos + 1, PairEndIndex - SeparatorPos - 1));
    end
    else
    begin
      Key := TNetEncoding.URL.Decode(Copy(AQueryString, StartIndex, PairEndIndex - StartIndex));
      Value := '';
    end;
    if Key <> '' then
      ADictionary.AddOrSetValue(Key, Value);

    StartIndex := PairEndIndex + 1;
  end;
end;

procedure THttpRequestInfo.ParseUri(const RawUri: string);
var
  QuestionPos, HashPos, SchemeEnd, AuthorityStart, PathStart: Integer;
  WorkingUri: string;
  ErrorMsg: string;
  I, RawLen: Integer;
  Ch, PrevCh: Char;
  IsSimpleCleanPath: Boolean;
begin
  try
    if RawUri = '/' then
    begin
      FRawUri := '/';
      FUri := '/';
      FPath := '/';
      FNormalizedUri := '/';
      FQueryString := '';
      FFragment := '';
      FScheme := '';
      FAuthority := '';
      ClearValidationErrors;
      Exit;
    end;
    RawLen := Length(RawUri);
    if (RawLen > 1) and (RawLen <= 512) and (RawUri[1] = '/') then
    begin
      IsSimpleCleanPath := True;
      PrevCh := '/';
      for I := 2 to RawLen do
      begin
        Ch := RawUri[I];
        if not (((Ch >= 'a') and (Ch <= 'z')) or ((Ch >= 'A') and (Ch <= 'Z')) or
                ((Ch >= '0') and (Ch <= '9')) or (Ch = '/') or (Ch = '-') or
                (Ch = '_') or (Ch = '.')) then
        begin
          IsSimpleCleanPath := False;
          Break;
        end;
        if ((Ch = '.') and ((PrevCh = '.') or (PrevCh = '/'))) or
           ((Ch = '/') and (PrevCh = '/')) then
        begin
          IsSimpleCleanPath := False;
          Break;
        end;
        PrevCh := Ch;
      end;
      if IsSimpleCleanPath then
      begin
        FRawUri := RawUri;
        FUri := RawUri;
        FPath := RawUri;
        FNormalizedUri := RawUri;
        FQueryString := '';
        FFragment := '';
        FScheme := '';
        FAuthority := '';
        ClearValidationErrors;
        if (RawLen >= 6) and THeaderValidatorAccess.HasSuspiciousPatterns(FPath) then
          GetUriValidationErrors.Add('Suspicious patterns detected in path');
        Exit;
      end;
    end;
    FRawUri := Trim(RawUri);
    FUri := FRawUri;
    ClearValidationErrors;
    if (Pos('%00', FRawUri) > 0) or (Pos(#0, FRawUri) > 0) then
      GetUriValidationErrors.Add('Null byte injection attempt detected in URI');
    if Length(FRawUri) = 0 then
    begin
      GetUriValidationErrors.Add('URI cannot be empty');
      FPath := '/';
      Exit;
    end;
    WorkingUri := FRawUri;
    HashPos := Pos('#', WorkingUri);
    if HashPos > 0 then
    begin
      FFragment := Copy(WorkingUri, HashPos + 1, Length(WorkingUri));
      WorkingUri := Copy(WorkingUri, 1, HashPos - 1);
      if not TUriValidatorAccess.IsValidFragment(FFragment) then
        GetUriValidationErrors.Add('Invalid fragment: ' + FFragment);
    end
    else
      FFragment := '';
    QuestionPos := Pos('?', WorkingUri);
    if QuestionPos > 0 then
    begin
      FQueryString := Copy(WorkingUri, QuestionPos + 1, Length(WorkingUri));
      WorkingUri := Copy(WorkingUri, 1, QuestionPos - 1);
      if not TUriValidator.IsValidQuery(FQueryString) then
        GetUriValidationErrors.Add('Invalid query string: ' + FQueryString);
      if FQueryString <> '' then
        ParseQueryString(FQueryString, GetQueryParameters);
    end
    else
      FQueryString := '';
    SchemeEnd := Pos('://', WorkingUri);
    if SchemeEnd > 0 then
    begin
      FScheme := Copy(WorkingUri, 1, SchemeEnd - 1);
      AuthorityStart := SchemeEnd + 3;
      PathStart := Pos('/', WorkingUri, AuthorityStart);
      if PathStart > 0 then
      begin
        FAuthority := Copy(WorkingUri, AuthorityStart, PathStart - AuthorityStart);
        FPath := Copy(WorkingUri, PathStart, Length(WorkingUri));
      end
      else
      begin
        FAuthority := Copy(WorkingUri, AuthorityStart, Length(WorkingUri));
        FPath := '/';
      end;
    end
    else
    begin
      FScheme := '';
      FAuthority := '';
      FPath := WorkingUri;
    end;
    if not ((FMethod = hmOPTIONS) and (FPath = '*')) and not TUriValidator.ValidateAbsolutePath(FPath, ErrorMsg) then
      GetUriValidationErrors.Add('Path validation: ' + ErrorMsg);
    FNormalizedUri := TUriValidator.NormalizeURI(FRawUri);
    if FPath = '' then
      FPath := '/';
    ValidateUriComponents;
  except
    on E: Exception do
    begin
      GetUriValidationErrors.Add('Parse error: ' + E.Message);
      FPath := '/';
      FQueryString := '';
      FFragment := '';
      FScheme := '';
      FAuthority := '';
    end;
  end;
end;

procedure THttpRequestInfo.ValidateUriComponents;
var
  DecodedQuery, DecodedPath, LowerPath, LowerRaw: string;
  HasPercentPath, HasPercentRaw: Boolean;
  Params: TArray<string>;
  Param: string;
begin
  try
    if Length(FPath) > 2048 then
      GetUriValidationErrors.Add('Path too long (>2048 characters)');
    if Length(FQueryString) > 4096 then
      GetUriValidationErrors.Add('Query string too long (>4096 characters)');
    if Length(FFragment) > 1024 then
      GetUriValidationErrors.Add('Fragment too long (>1024 characters)');

    HasPercentPath := Pos('%', FPath) > 0;
    HasPercentRaw := HasPercentPath or (Pos('%', FRawUri) > 0);

    if Pos('..', FPath) > 0 then
      GetUriValidationErrors.Add('Path traversal attempt detected')
    else if HasPercentPath then
    begin
      LowerPath := LowerCase(FPath);
      if (Pos('%2e%2e', LowerPath) > 0) or (Pos('%252e', LowerPath) > 0) or (Pos('%c0%af', LowerPath) > 0) then
        GetUriValidationErrors.Add('Path traversal attempt detected');
    end;

    if (Pos(#0, FRawUri) > 0) or (HasPercentRaw and (Pos('%00', FRawUri) > 0)) then
      GetUriValidationErrors.Add('Null byte injection attempt detected');

    if (Pos(#10, FRawUri) > 0) or (Pos(#13, FRawUri) > 0) then
      GetUriValidationErrors.Add('CRLF injection attempt detected')
    else if HasPercentRaw then
    begin
      LowerRaw := LowerCase(FRawUri);
      if (Pos('%0a', LowerRaw) > 0) or (Pos('%0d', LowerRaw) > 0) then
        GetUriValidationErrors.Add('CRLF injection attempt detected');
    end;

    if FQueryString <> '' then
    begin
      if THeaderValidatorAccess.HasSuspiciousPatterns(FQueryString) then
        GetUriValidationErrors.Add('Potential attack detected in query string')
      else if (Pos('%', FQueryString) > 0) or (Pos('+', FQueryString) > 0) then
      begin
        DecodedQuery := TNetEncoding.URL.Decode(FQueryString);
        if THeaderValidatorAccess.HasSuspiciousPatterns(DecodedQuery) then
          GetUriValidationErrors.Add('Potential attack detected in query string');
      end;
      if Length(FQueryString) > 1024 then
      begin
        Params := FQueryString.Split(['&']);
        for Param in Params do
        begin
          if Length(Param) > 1024 then
          begin
            GetUriValidationErrors.Add('Query parameter too long: ' + Copy(Param, 1, 50) + '...');
            Break;
          end;
        end;
      end;
    end;

    if FPath <> '' then
    begin
      if THeaderValidatorAccess.HasSuspiciousPatterns(FPath) then
        GetUriValidationErrors.Add('Potential attack detected in path')
      else if HasPercentPath then
      begin
        DecodedPath := TNetEncoding.URL.Decode(FPath);
        if THeaderValidatorAccess.HasSuspiciousPatterns(DecodedPath) then
          GetUriValidationErrors.Add('Potential attack detected in path');
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Info(Format('DEBUG: Exception in ValidateUriComponents: %s', [E.Message]));
      GetUriValidationErrors.Add('Validation error: ' + E.Message);
    end;
  end;
end;

function THttpRequestInfo.ParseRequestLinePtr(LinePtr: PByte; LineLen: Integer; var CachedUri: string): Boolean;
var
  MethodVal: THttpMethod;
  MethodLen: Integer;
  UriStart, UriEnd, UriLen, I: Integer;
  B, PrevB: Byte;
  UriStr: string;
begin
  Result := False;
  if (LinePtr = nil) or (LineLen < 14) then
    Exit;

  if (LinePtr[LineLen - 9] <> Ord(' ')) or (LinePtr[LineLen - 8] <> Ord('H')) or
     (LinePtr[LineLen - 7] <> Ord('T')) or (LinePtr[LineLen - 6] <> Ord('T')) or
     (LinePtr[LineLen - 5] <> Ord('P')) or (LinePtr[LineLen - 4] <> Ord('/')) or
     (LinePtr[LineLen - 3] <> Ord('1')) or (LinePtr[LineLen - 2] <> Ord('.')) then
    Exit;

  if LinePtr[LineLen - 1] = Ord('1') then
    FVersion := hvHTTP11
  else if LinePtr[LineLen - 1] = Ord('0') then
    FVersion := hvHTTP10
  else
    Exit;

  if (LinePtr[0] = Ord('G')) and (LinePtr[1] = Ord('E')) and (LinePtr[2] = Ord('T')) and (LinePtr[3] = Ord(' ')) then
  begin
    MethodVal := hmGET;
    MethodLen := 4;
  end
  else if (LinePtr[0] = Ord('P')) and (LinePtr[1] = Ord('O')) and (LinePtr[2] = Ord('S')) and (LinePtr[3] = Ord('T')) and (LinePtr[4] = Ord(' ')) then
  begin
    MethodVal := hmPOST;
    MethodLen := 5;
  end
  else if (LinePtr[0] = Ord('H')) and (LinePtr[1] = Ord('E')) and (LinePtr[2] = Ord('A')) and (LinePtr[3] = Ord('D')) and (LinePtr[4] = Ord(' ')) then
  begin
    MethodVal := hmHEAD;
    MethodLen := 5;
  end
  else if (LinePtr[0] = Ord('P')) and (LinePtr[1] = Ord('U')) and (LinePtr[2] = Ord('T')) and (LinePtr[3] = Ord(' ')) then
  begin
    MethodVal := hmPUT;
    MethodLen := 4;
  end
  else
    Exit;

  UriStart := MethodLen;
  UriEnd := LineLen - 10;
  UriLen := UriEnd - UriStart + 1;
  if (UriLen <= 0) or (UriLen > 512) or (LinePtr[UriStart] <> Ord('/')) then
    Exit;

  if UriLen = 1 then
  begin
    FMethod := MethodVal;
    FRawUri := '/';
    FUri := '/';
    FPath := '/';
    FNormalizedUri := '/';
    FQueryString := '';
    FFragment := '';
    FScheme := '';
    FAuthority := '';
    ClearValidationErrors;
    Result := True;
    Exit;
  end;

  if AsciiEqualsStrPtr(LinePtr + UriStart, UriLen, CachedUri) then
  begin
    FMethod := MethodVal;
    FRawUri := CachedUri;
    FUri := CachedUri;
    FPath := CachedUri;
    FNormalizedUri := CachedUri;
    FQueryString := '';
    FFragment := '';
    FScheme := '';
    FAuthority := '';
    ClearValidationErrors;
    Result := True;
    Exit;
  end;

  PrevB := Ord('/');
  for I := UriStart + 1 to UriEnd do
  begin
    B := LinePtr[I];
    if not (((B >= Ord('a')) and (B <= Ord('z'))) or ((B >= Ord('A')) and (B <= Ord('Z'))) or
            ((B >= Ord('0')) and (B <= Ord('9'))) or (B = Ord('/')) or (B = Ord('-')) or
            (B = Ord('_')) or (B = Ord('.'))) then
      Exit;
    if ((B = Ord('.')) and ((PrevB = Ord('.')) or (PrevB = Ord('/')))) or
       ((B = Ord('/')) and (PrevB = Ord('/'))) then
      Exit;
    PrevB := B;
  end;

  if (UriLen >= 6) and THeaderValidator.HasSuspiciousPatternsPtr(LinePtr + UriStart, UriLen) then
    Exit;

  SetLength(UriStr, UriLen);
  for I := 0 to UriLen - 1 do
    UriStr[I + 1] := Char(LinePtr[UriStart + I]);
  CachedUri := UriStr;

  FMethod := MethodVal;
  FRawUri := UriStr;
  FUri := UriStr;
  FPath := UriStr;
  FNormalizedUri := UriStr;
  FQueryString := '';
  FFragment := '';
  FScheme := '';
  FAuthority := '';
  ClearValidationErrors;
  Result := True;
end;

procedure THttpRequestInfo.ParseRequestLine(const RequestLine: string);
var
  MethodStr, UriStr, VerStr: string;
  ErrorMsg: string;
  SpacePos1, SpacePos2, Len: Integer;
begin
  try
    Len := Length(RequestLine);
    if (Len >= 14) and (RequestLine[1] = 'G') and (RequestLine[2] = 'E') and (RequestLine[3] = 'T') and (RequestLine[4] = ' ') and
       (RequestLine[Len - 8] = ' ') and (RequestLine[Len - 7] = 'H') and (RequestLine[Len - 6] = 'T') and (RequestLine[Len - 5] = 'T') and
       (RequestLine[Len - 4] = 'P') and (RequestLine[Len - 3] = '/') and (RequestLine[Len - 2] = '1') and (RequestLine[Len - 1] = '.') and
       ((RequestLine[Len] = '1') or (RequestLine[Len] = '0')) then
    begin
      FMethod := hmGET;
      if RequestLine[Len] = '1' then
        FVersion := hvHTTP11
      else
        FVersion := hvHTTP10;
      if (Len = 14) and (RequestLine[5] = '/') then
        ParseUri('/')
      else
      begin
        UriStr := Copy(RequestLine, 5, Len - 13);
        ParseUri(UriStr);
      end;
      if (FPath <> '/') and HasValidationErrors and not ((FMethod = hmOPTIONS) and (FPath = '*')) and not TUriValidator.ValidateAbsolutePath(FPath, ErrorMsg) then
        raise Exception.Create('Invalid URI path: ' + ErrorMsg);
      Exit;
    end;
    SpacePos1 := Pos(' ', RequestLine);
    if SpacePos1 = 0 then
      raise Exception.Create('Invalid HTTP request line - missing first space');
    SpacePos2 := Pos(' ', RequestLine, SpacePos1 + 1);
    if SpacePos2 = 0 then
      raise Exception.Create('Invalid HTTP request line - missing second space');
    MethodStr := Copy(RequestLine, 1, SpacePos1 - 1);
    UriStr := Copy(RequestLine, SpacePos1 + 1, SpacePos2 - SpacePos1 - 1);
    VerStr := Copy(RequestLine, SpacePos2 + 1, Len - SpacePos2);
    if MethodStr = 'GET' then
      FMethod := hmGET
    else if MethodStr = 'POST' then
      FMethod := hmPOST
    else
      FMethod := StringToHttpMethod(MethodStr);
    if FMethod = hmUnknown then
      raise Exception.CreateFmt('Unknown HTTP method: %s', [MethodStr]);
    ParseUri(UriStr);
    if VerStr = 'HTTP/1.1' then
      FVersion := hvHTTP11
    else if VerStr = 'HTTP/1.0' then
      FVersion := hvHTTP10
    else
      FVersion := StringToHttpVersion(VerStr);
    if FVersion = hvUnknown then
      raise Exception.CreateFmt('Unsupported HTTP version: %s', [VerStr]);
    if (FPath <> '/') and not ((FMethod = hmOPTIONS) and (FPath = '*')) and not TUriValidator.ValidateAbsolutePath(FPath, ErrorMsg) then
      raise Exception.Create('Invalid URI path: ' + ErrorMsg);
  except
    on E: Exception do
      raise Exception.CreateFmt('Error parsing request line: %s', [E.Message]);
  end;
end;

procedure THttpRequestInfo.ParseFromHeaders(Headers: THttpHeaders);
var
  ContentLengthStr: string;
  TransferEncodingStr: string;
  ConnectionStr: string;
  ContentEncodingStr: string;
  HostHeader: string;
  SlotName: string;
  I: Integer;
begin
  try
    if not Headers.UseDict then
    begin
      TransferEncodingStr := '';
      ConnectionStr := '';
      ContentLengthStr := '';
      ContentEncodingStr := '';
      HostHeader := '';
      for I := 0 to Headers.SlotCount - 1 do
      begin
        SlotName := Headers.GetSlotName(I);
        if SlotName = 'host' then
          HostHeader := Headers.GetSlotValue(I)
        else if SlotName = 'connection' then
          ConnectionStr := Headers.GetSlotValue(I)
        else if SlotName = 'content-length' then
          ContentLengthStr := Headers.GetSlotValue(I)
        else if SlotName = 'transfer-encoding' then
          TransferEncodingStr := Headers.GetSlotValue(I)
        else if SlotName = 'content-encoding' then
          ContentEncodingStr := Headers.GetSlotValue(I);
      end;
      if TransferEncodingStr = '' then
        FTransferEncoding := teNone
      else
        FTransferEncoding := ParseTransferEncoding(TransferEncodingStr);
      if ConnectionStr = 'keep-alive' then
        FConnectionType := ctKeepAlive
      else if ConnectionStr = 'close' then
        FConnectionType := ctClose
      else
        FConnectionType := ParseConnectionType(ConnectionStr);
      if ContentEncodingStr = '' then
        SetLength(FContentEncodings, 0)
      else
        FContentEncodings := Headers.GetContentEncodings;
    end
    else
    begin
      TransferEncodingStr := Headers.TransferEncoding;
      FTransferEncoding := ParseTransferEncoding(TransferEncodingStr);
      ConnectionStr := Headers.Connection;
      FConnectionType := ParseConnectionType(ConnectionStr);
      ContentLengthStr := Headers.ContentLength;
      FContentEncodings := Headers.GetContentEncodings;
      HostHeader := Headers.Host;
    end;
    if FVersion = hvHTTP10 then
      FConnectionType := ctClose;
    if ContentLengthStr <> '' then
    begin
      FContentLength := StrToInt64Def(ContentLengthStr, -1);
      if FContentLength < 0 then
        raise Exception.Create('Invalid Content-Length value: ' + ContentLengthStr);
    end
    else
      FContentLength := -1;

    if (FVersion = hvHTTP11) and (HostHeader = '') then
      raise Exception.Create('HTTP/1.1 requires Host header');

    FIsSecure := (FScheme <> '') and SameText(FScheme, 'https');
  except
    on E: Exception do
      raise Exception.CreateFmt('Header parsing error: %s', [E.Message]);
  end;
end;

function THttpRequestInfo.MethodToString: string;
begin
  case FMethod of
    hmGET: Result := 'GET';
    hmPOST: Result := 'POST';
    hmPUT: Result := 'PUT';
    hmDELETE: Result := 'DELETE';
    hmHEAD: Result := 'HEAD';
    hmOPTIONS: Result := 'OPTIONS';
    hmPATCH: Result := 'PATCH';
    hmTRACE: Result := 'TRACE';
    hmCONNECT: Result := 'CONNECT';
  else
    Result := 'UNKNOWN';
  end;
end;

function THttpRequestInfo.VersionToString: string;
begin
  case FVersion of
    hvHTTP10: Result := 'HTTP/1.0';
    hvHTTP11: Result := 'HTTP/1.1';
    hvHTTP20: Result := 'HTTP/2.0';
  else
    Result := 'UNKNOWN';
  end;
end;

function THttpRequestInfo.HasBody: Boolean;
begin
  Result := (FMethod in [hmPOST, hmPUT, hmPATCH]) or
           (FContentLength > 0) or
           (FTransferEncoding <> teNone);
end;

function THttpRequestInfo.IsMethodSafe: Boolean;
begin
  Result := FMethod in [hmGET, hmHEAD, hmOPTIONS, hmTRACE];
end;

function THttpRequestInfo.IsMethodIdempotent: Boolean;
begin
  Result := FMethod in [hmGET, hmHEAD, hmPUT, hmDELETE, hmOPTIONS, hmTRACE];
end;

function THttpRequestInfo.IsUriValid: Boolean;
begin
  Result := not HasValidationErrors;
end;

function THttpRequestInfo.GetUriValidationSummary: string;
begin
  if not HasValidationErrors then
    Result := 'URI validation passed'
  else
    Result := Format('URI validation failed (%d errors): %s',
                    [GetUriValidationErrors.Count, GetUriValidationErrors.Text]);
end;

procedure THttpRequestInfo.ApplyFastHeaderInfo(ATransferEncoding: TTransferEncoding; AConnectionType: TConnectionType;
  AContentLength: Int64; const AContentEncodings: TArray<TContentEncoding>; AIsSecure: Boolean);
begin
  FTransferEncoding := ATransferEncoding;
  FConnectionType := AConnectionType;
  FContentLength := AContentLength;
  FContentEncodings := AContentEncodings;
  FIsSecure := AIsSecure;
end;

end.
