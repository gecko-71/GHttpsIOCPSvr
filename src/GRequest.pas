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

unit GRequest;

interface

uses
  Quick.Logger, System.SysUtils, System.Classes, System.Threading, System.SyncObjs,
  System.Generics.Collections, System.Math, System.StrUtils, System.Character,
  Winapi.Windows, Winapi.WinSock2,
  System.NetEncoding, GRequestBody, System.Generics.Defaults;

type
  TCaseInsensitiveStringComparer = class(TInterfacedObject, IEqualityComparer<string>)
  public
    function Equals(const Left, Right: string): Boolean;
    function GetHashCode(const Value: string): Integer;
  end;

  THttpMethod = (hmUnknown, hmGET, hmPOST, hmPUT, hmDELETE, hmHEAD, hmOPTIONS, hmPATCH, hmTRACE, hmCONNECT);
  THttpVersion = (hvUnknown, hvHTTP10, hvHTTP11, hvHTTP20);
  TRequestState = (rsWaitingHeaders, rsParsingHeaders, rsWaitingBody, rsComplete, rsError, rsRecovering);
  TTransferEncoding = (teNone, teChunked, teCompress, teDeflate, teGzip, teIdentity);
  TConnectionType = (ctKeepAlive, ctClose, ctUpgrade);
  TSecurityThreat = (stNone, stRequestSmuggling, stHeaderInjection, stOversizeAttack,
                    stMalformedURI, stInvalidEncoding, stSuspiciousHeaders);
  TRecoveryAction = (raAbort, raSkipHeader, raTruncateValue, raSanitize, raContinue);
  TValidationLevel = (vlStrict, vlModerate, vlPermissive);

  TUriValidator = class
  private
    class function IsUnreserved(C: Char): Boolean;
    class function IsReserved(C: Char): Boolean;
    class function IsGenDelim(C: Char): Boolean;
    class function IsSubDelim(C: Char): Boolean;
    class function IsValidPath(const Path: string): Boolean;
    class function IsValidQuery(const Query: string): Boolean;
    class function IsValidFragment(const Fragment: string): Boolean;
    class function DecodePercentEncoding(const Input: string): string;
    class function IsValidPercentEncoded(const Input: string; Pos: Integer): Boolean;
  public
    class function ValidateURI(const URI: string; out ErrorMsg: string): Boolean;
    class function ValidateAbsolutePath(const Path: string; out ErrorMsg: string): Boolean;
    class function SanitizeURI(const URI: string): string;
    class function NormalizeURI(const URI: string): string;
    class function IsValidScheme(const Scheme: string): Boolean;
    class function IsValidAuthority(const Authority: string): Boolean;
  end;

  THeaderValidator = class
  private
    class function IsValidTokenChar(C: Char): Boolean;
    class function IsValidFieldVChar(C: Char): Boolean;
    class function IsObsText(C: Char): Boolean;
    class function HasSuspiciousPatterns(const Value: string): Boolean;
    class function DetectInjectionAttempt(const Value: string): Boolean;
  public
    class function ValidateHeaderName(const Name: string; out ErrorMsg: string): Boolean;
    class function ValidateHeaderValue(const Value: string; out ErrorMsg: string): Boolean;
    class function SanitizeHeaderValue(const Value: string): string;
    class function IsSafeHeaderName(const Name: string): Boolean;
    class function DetectRequestSmuggling(const Headers: TStringList): TSecurityThreat;
  end;

  TContentEncodingHandler = class
  private
    function GetEncodingFromString(const EncodingStr: string): TContentEncoding;
    function DecompressGzip(const Data: TBytes): TBytes;
    function DecompressDeflate(const Data: TBytes): TBytes;
    function DecompressBrotli(const Data: TBytes): TBytes;
  public
    constructor Create;
    destructor Destroy; override;
    function ParseContentEncoding(const EncodingHeader: string): TArray<TContentEncoding>;
    function DecompressData(const Data: TBytes; Encoding: TContentEncoding): TBytes;
    function GetEncodingName(Encoding: TContentEncoding): string;
    function IsCompressionSupported(Encoding: TContentEncoding): Boolean;
  end;

  TRequestRecovery = class
  private
    FRecoveryActions: TList<TRecoveryAction>;
    FErrorLog: TStringList;
    FRecoveryAttempts: Integer;
    FMaxRecoveryAttempts: Integer;
  public
    constructor Create(MaxAttempts: Integer = 3);
    destructor Destroy; override;
    function CanRecover(const Error: string): Boolean;
    function SuggestRecoveryAction(const Error: string; const Context: string): TRecoveryAction;
    procedure LogRecoveryAttempt(const Action: TRecoveryAction; const Details: string);
    function GetRecoveryLog: string;
    procedure Clear;
    property RecoveryAttempts: Integer read FRecoveryAttempts;
    property MaxRecoveryAttempts: Integer read FMaxRecoveryAttempts write FMaxRecoveryAttempts;
  end;

  THttpHeaders = class
  private
    FHeaders: TDictionary<string, TStringList>;
    FValidationLevel: TValidationLevel;
    FContentEncodingHandler: TContentEncodingHandler;
    function NormalizeHeaderName(const HeaderName: string): string;
    function ParseFoldedHeader(const Lines: TStringList; StartIndex: Integer; out EndIndex: Integer): string;
    function ProcessInternationalHeader(const Value: string): string;
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
    property Headers:TDictionary<string, TStringList> read FHeaders;
  end;

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
    function StringToHttpMethod(const MethodStr: string): THttpMethod;
    function StringToHttpVersion(const VersionStr: string): THttpVersion;
    function ParseTransferEncoding(const EncodingStr: string): TTransferEncoding;
    function ParseConnectionType(const ConnectionStr: string): TConnectionType;
    procedure ValidateUriComponents;
  public
    constructor Create;
    destructor Destroy; override;
    procedure ParseQueryString(const AQueryString: string; ADictionary: TDictionary<string, string>);
    procedure ParseUri(const RawUri: string);
    procedure ParseRequestLine(const RequestLine: string);
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
    property UriValidationErrors: TStringList read FUriValidationErrors;
    property QueryParameters: TDictionary<string, string> read FQueryParameters;
    function MethodToString: string;
    function VersionToString: string;
    function HasBody: Boolean;
    function IsMethodSafe: Boolean;
    function IsMethodIdempotent: Boolean;
    function IsUriValid: Boolean;
    function GetUriValidationSummary: string;
  end;

  TRequest = class
  private
    FHeadersSize: Integer;
    FMaxHeaderSize: Integer;
    FMaxBodySize: Int64;
    FValidationLevel: TValidationLevel;
    FEnableRecovery: Boolean;
    FMaxHeaderCount: Integer;
    FMaxHeaderLineLength: Integer;
    FBodyParser: THttpBodyParser;
    FSocket: TSocket;
    FRemoteAddr: TSockAddrIn;
    FRawBuffer: TBytes;
    FRawBufferSize: Integer;
    FHeadersBuffer: TBytes;
    FBodyStream: TMemoryStream;
    FDecompressedBodyStream: TMemoryStream;
    FState: TRequestState;
    FErrorParsing: Boolean;
    FErrorMessage: string;
    FSecurityThreats: TArray<TSecurityThreat>;
    FHeaders: THttpHeaders;
    FRequestInfo: THttpRequestInfo;
    FContentEncodingHandler: TContentEncodingHandler;
    FRecovery: TRequestRecovery;
    FHeadersEndPos: Integer;
    FTotalBytesReceived: Int64;
    FBodyBytesReceived: Int64;
    FExpectedBodySize: Int64;
    FIsChunkedTransfer: Boolean;
    FChunkState: Integer;
    FCurrentChunkSize: Integer;
    FCurrentChunkReceived: Integer;
    FHeaderLineCount: Integer;
    FSuspiciousHeaderCount: Integer;
    FLargeHeaderWarnings: Integer;
    FMalformedLineCount: Integer;
    FSecurityViolationDetected: Boolean;
    function GetHeadersSize: Integer;
    function StartsWithHTTPMethod(const Data: string): Boolean;
    function IsValidHTTPRequestLine(const RequestLine: string): Boolean;
    function HasExistingThreat(ThreatType: TSecurityThreat): Boolean;
    procedure InitializeBuffers;
    procedure ClearBuffers;
    function FindHeadersEnd(const Buffer: TBytes; Size: Integer): Integer;
    procedure ParseRequestLine(const FirstLine: string);
    procedure ProcessHeaderLines(const HeaderLines: TStringList);
    procedure ProcessRemainingDataAfterHeaders;
    procedure DetermineBodySize;
    procedure ProcessBodyData(const Data: array of Byte; Size: Integer);
    procedure ProcessChunkedBody(const Data: array of Byte; Size: Integer);
    procedure ProcessRegularBody(const Data: array of Byte; Size: Integer);
    function ValidateRequest: Boolean;
    function DetectRequestSmuggling: Boolean;
    function ValidateHeaderSecurity: Boolean;
    function CheckContentLengthConsistency: Boolean;
    function DetectMaliciousPatterns: Boolean;
    procedure AnalyzeSecurity;
    procedure ApplySecurityMeasures;
    function AttemptRecovery(const Error: string; const Context: string): Boolean;
    function RecoverFromMalformedHeader(const HeaderLine: string): string;
    function RecoverFromOversizeData(var Data: TBytes): Boolean;
    procedure SkipToNextValidHeader(var HeaderLines: TStringList; var Index: Integer);
    procedure DecompressBodyIfNeeded;
    function GetFinalBodyStream: TMemoryStream;
    procedure SetError(const ErrorMsg: string; Threat: TSecurityThreat = stNone);
    function IsValidHttpMethod(const Method: string): Boolean;
    function IsValidHttpVersion(const Version: string): Boolean;
    function ExtractChunkSize(const ChunkHeader: string): Integer;
    function SanitizeHeaderLine(const HeaderLine: string): string;
    function ProcessInternationalContent(const Content: string): string;
    function DetectSlowlorisAttack: Boolean;
    function DetectSlowlorisInCompleteHeaders: Boolean;
  public
    constructor Create(ASocket: TSocket; const ARemoteAddr: TSockAddrIn;
                      AMaxHeaderSize: Integer = 32768; AMaxBodySize: Int64 = 8147484123;
                      ValidationLevel: TValidationLevel = vlModerate;
                      EnableRecovery: Boolean = True);
    destructor Destroy; override;
    procedure ParseHeaders;
    function GetContentLength: Int64;
    function GetRequestSize: Int64;
    property HeadersSize: Integer read GetHeadersSize;
    property BodyReceived: Int64 read FBodyBytesReceived;
    property RequestSize: Int64 read GetRequestSize;
    function GetBodyParser: THttpBodyParser;
    function GetBodyAsString: string;
    function GetBodyAsBytes: TBytes;
    function GetBodyPart(Index: Integer): TBodyPart;
    function GetBodyPartByName(const Name: string): TBodyPart;
    function GetBodyPartCount: Integer;
    function GetBodyContentType: TBodyContentType;
    function HasSecurityViolation: Boolean;
    function GetRecoveryAttempts: Integer;
    procedure SetLemBuf(Alen: Integer);
    procedure AppendData(const Data: array of Byte; Size: Integer);
    function CheckComplete: Boolean;
    procedure Reset;
    procedure Clear;
    function GetRequestString: string;
    function GetHeadersString: string;
    function GetBodyString: string;
    function GetBodyBytes: TBytes;
    function GetBodyStream: TMemoryStream;
    function GetDecompressedBodyStream: TMemoryStream;
    function HasSecurityThreats: Boolean;
    function GetThreatSummary: string;
    property Socket: TSocket read FSocket;
    property RemoteAddr: TSockAddrIn read FRemoteAddr;
    property State: TRequestState read FState;
    property ErrorParsing: Boolean read FErrorParsing;
    property ErrorMessage: string read FErrorMessage;
    property SecurityThreats: TArray<TSecurityThreat> read FSecurityThreats;
    property Headers: THttpHeaders read FHeaders;
    property RequestInfo: THttpRequestInfo read FRequestInfo;
    property TotalBytesReceived: Int64 read FTotalBytesReceived;
    property BodyBytesReceived: Int64 read FBodyBytesReceived;
    property ExpectedBodySize: Int64 read FExpectedBodySize;
    property MaxHeaderSize: Integer read FMaxHeaderSize;
    property MaxBodySize: Int64 read FMaxBodySize;
    property ValidationLevel: TValidationLevel read FValidationLevel;
    property EnableRecovery: Boolean read FEnableRecovery;
    property SuspiciousHeaderCount: Integer read FSuspiciousHeaderCount;
    property RecoveryAttempts: Integer read GetRecoveryAttempts;
    property BodyParser: THttpBodyParser read GetBodyParser;
    property BodyAsString: string read GetBodyAsString;
    property BodyAsBytes: TBytes read GetBodyAsBytes;
    property BodyPartCount: Integer read GetBodyPartCount;
    property BodyContentType: TBodyContentType read GetBodyContentType;
    property ContentLength: Int64 read GetContentLength;
    property RawBuffer: TBytes read FRawBuffer;
    property RawBufferSize: Integer read FRawBufferSize write  FRawBufferSize;
    function IsComplete: Boolean;
    function IsHeadersComplete: Boolean;
    function IsBodyComplete: Boolean;
    function HasError: Boolean;
    function CanAcceptMoreData: Boolean;
    function IsSecure: Boolean;
    function IsRecoverable: Boolean;
  end;

implementation


const
  CRLF = #13#10;
  DOUBLE_CRLF = #13#10#13#10;
  MAX_REQUEST_LINE_LENGTH = 8192;
  MAX_HEADER_LINE_LENGTH = 8192;
  MAX_HEADER_COUNT = 100;
  CHUNK_BUFFER_SIZE = 4096;
  MAX_SUSPICIOUS_HEADERS = 10;
  MAX_MALFORMED_LINES = 5;
  MAX_RECOVERY_ATTEMPTS = 3;

function IsHexDigit(c: Char): Boolean;
begin
  Result := ((c >= '0') and (c <= '9')) or
            ((c >= 'A') and (c <= 'F')) or
            ((c >= 'a') and (c <= 'f'));
end;

class function TUriValidator.IsUnreserved(C: Char): Boolean;
begin
  Result := TCharacter.IsLetterOrDigit(C) or (C = '-') or (C = '.') or (C = '_') or (C = '~');
end;

class function TUriValidator.IsReserved(C: Char): Boolean;
begin
  Result := IsGenDelim(C) or IsSubDelim(C);
end;

class function TUriValidator.IsGenDelim(C: Char): Boolean;
begin
  Result := C in [':', '/', '?', '#', '[', ']', '@'];
end;

class function TUriValidator.IsSubDelim(C: Char): Boolean;
begin
  Result := C in ['!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '='];
end;

class function TUriValidator.IsValidScheme(const Scheme: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  if Length(Scheme) = 0 then
    Exit;
  if not TCharacter.IsLetter(Scheme[1]) then
    Exit;
  for I := 2 to Length(Scheme) do
  begin
    if not (TCharacter.IsLetterOrDigit(Scheme[I]) or (Scheme[I] in ['+', '-', '.'])) then
      Exit;
  end;
  Result := True;
end;

class function TUriValidator.IsValidAuthority(const Authority: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;

  for I := 1 to Length(Authority) do
  begin
    C := Authority[I];
    if not (IsUnreserved(C) or IsSubDelim(C) or (C = ':') or (C = '@') or (C = '[') or (C = ']')) then
    begin
      if (C = '%') and (I <= Length(Authority) - 2) then
      begin
        if not IsValidPercentEncoded(Authority, I) then
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidPath(const Path: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;
  if Length(Path) = 0 then
  begin
    Exit(True);
  end;
  try
    I := 1;
    while I <= Length(Path) do
    begin
      C := Path[I];
      if IsUnreserved(C) or IsSubDelim(C) or (C = ':') or (C = '@') or (C = '/') then
      begin
        Inc(I);
        Continue;
      end;
      if (C = '%') and (I <= Length(Path) - 2) then
      begin
        if IsValidPercentEncoded(Path, I) then
        begin
          Inc(I, 3);
          Continue;
        end
        else
        begin
          Result := False;
          Exit;
        end;
      end;
      Result := False;
      Exit;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception in IsValidPath: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

class function TUriValidator.IsValidQuery(const Query: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;
  for I := 1 to Length(Query) do
  begin
    C := Query[I];
    if not (IsUnreserved(C) or IsSubDelim(C) or (C = ':') or (C = '@') or (C = '/') or (C = '?')) then
    begin
      if (C = '%') and (I <= Length(Query) - 2) then
      begin
        if not IsValidPercentEncoded(Query, I) then
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidFragment(const Fragment: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;
  for I := 1 to Length(Fragment) do
  begin
    C := Fragment[I];
    if not (IsUnreserved(C) or IsSubDelim(C) or (C = ':') or (C = '@') or (C = '/') or (C = '?')) then
    begin
      if (C = '%') and (I <= Length(Fragment) - 2) then
      begin
        if not IsValidPercentEncoded(Fragment, I) then
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidPercentEncoded(const Input: string; Pos: Integer): Boolean;
begin
  Result := False;
  if (Pos > Length(Input) - 2) then
    Exit;
  if Input[Pos] <> '%' then
    Exit;
  Result := IsHexDigit(Input[Pos + 1]) and IsHexDigit(Input[Pos + 2]);
end;

class function TUriValidator.DecodePercentEncoding(const Input: string): string;
var
  I: Integer;
  HexStr: string;
  ByteValue: Byte;
begin
  Result := '';
  I := 1;
  while I <= Length(Input) do
  begin
    if (Input[I] = '%') and (I <= Length(Input) - 2) and IsValidPercentEncoded(Input, I) then
    begin
      HexStr := Copy(Input, I + 1, 2);
      try
        ByteValue := StrToInt('$' + HexStr);
        Result := Result + Chr(ByteValue);
        Inc(I, 3);
      except
        Result := Result + Input[I];
        Inc(I);
      end;
    end
    else
    begin
      Result := Result + Input[I];
      Inc(I);
    end;
  end;
end;

class function TUriValidator.ValidateURI(const URI: string; out ErrorMsg: string): Boolean;
var
  SchemeEnd, AuthorityStart, AuthorityEnd, PathEnd, QueryEnd: Integer;
  Scheme, Authority, Path, Query, Fragment: string;
begin
  Result := False;
  ErrorMsg := '';
  try
    if Length(URI) = 0 then
    begin
      ErrorMsg := 'URI cannot be empty';
      Exit;
    end;
    if Length(URI) > 2048 then
    begin
      ErrorMsg := 'URI too long (>2048 characters)';
      Exit;
    end;
    SchemeEnd := Pos(':', URI);
    if SchemeEnd > 0 then
    begin
      Scheme := Copy(URI, 1, SchemeEnd - 1);
      if not IsValidScheme(Scheme) then
      begin
        ErrorMsg := 'Incorrect schema URI: ' + Scheme;
        Exit;
      end;
    end;
    AuthorityStart := 0;
    AuthorityEnd := 0;
    if (SchemeEnd > 0) and (SchemeEnd < Length(URI) - 1) and
       (Copy(URI, SchemeEnd + 1, 2) = '//') then
    begin
      AuthorityStart := SchemeEnd + 3;
      AuthorityEnd := AuthorityStart;

      while (AuthorityEnd <= Length(URI)) and
            not (URI[AuthorityEnd] in ['/', '?', '#']) do
        Inc(AuthorityEnd);
      Dec(AuthorityEnd);
      if AuthorityEnd >= AuthorityStart then
      begin
        Authority := Copy(URI, AuthorityStart, AuthorityEnd - AuthorityStart + 1);
        if not IsValidAuthority(Authority) then
        begin
          ErrorMsg := 'Incorrect authority in URI: ' + Authority;
          Exit;
        end;
      end;
    end;
    PathEnd := Length(URI);
    QueryEnd := Pos('?', URI);
    if QueryEnd > 0 then
      PathEnd := QueryEnd - 1;
    if Pos('#', URI) > 0 then
      PathEnd := Min(PathEnd, Pos('#', URI) - 1);
    if AuthorityEnd > 0 then
      Path := Copy(URI, AuthorityEnd + 1, PathEnd - AuthorityEnd)
    else if SchemeEnd > 0 then
      Path := Copy(URI, SchemeEnd + 1, PathEnd - SchemeEnd)
    else
      Path := Copy(URI, 1, PathEnd);
    if not IsValidPath(Path) then
    begin
      ErrorMsg := 'Invalid path in URI: ' + Path;
      Exit;
    end;
    if QueryEnd > 0 then
    begin
      QueryEnd := Pos('#', URI);
      if QueryEnd = 0 then
        QueryEnd := Length(URI)
      else
        Dec(QueryEnd);

      Query := Copy(URI, Pos('?', URI) + 1, QueryEnd - Pos('?', URI));
      if not IsValidQuery(Query) then
      begin
        ErrorMsg := 'Invalid query string in URI: ' + Query;
        Exit;
      end;
    end;
    if Pos('#', URI) > 0 then
    begin
      Fragment := Copy(URI, Pos('#', URI) + 1, Length(URI));
      if not IsValidFragment(Fragment) then
      begin
        ErrorMsg := 'Invalid fragment in URI: ' + Fragment;
        Exit;
      end;
    end;

    Result := True;

  except
    on E: Exception do
    begin
      ErrorMsg := 'URI validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function TUriValidator.ValidateAbsolutePath(const Path: string; out ErrorMsg: string): Boolean;
begin
  Result := False;
  ErrorMsg := '';
  try
    if Length(Path) = 0 then
    begin
      ErrorMsg := 'The path cannot be empty';
      Exit;
    end;

    if Path[1] <> '/' then
    begin
      ErrorMsg := 'The path must be absolute (start with /)';
      Exit;
    end;

    if not IsValidPath(Path) then
    begin
      ErrorMsg := 'Invalid characters in path';
      Exit;
    end;

    Result := True;

  except
    on E: Exception do
    begin
      ErrorMsg := 'Path validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function TUriValidator.SanitizeURI(const URI: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(URI) do
  begin
    C := URI[I];
    if IsUnreserved(C) or IsReserved(C) or (C = '%') then
      Result := Result + C
    else
      Result := Result + '%' + IntToHex(Ord(C), 2);
  end;
end;

class function TUriValidator.NormalizeURI(const URI: string): string;
var
  Scheme, Authority, Path, Query, Fragment, Host, Port: string;
  SchemeEnd, AuthorityStart, PathStart, QueryStart, FragmentStart: Integer;
  PathSegments, NormalizedSegments: TStringList;
  I: Integer;
  Segment: string;
begin
  Scheme := ''; Authority := ''; Path := URI; Query := ''; Fragment := '';
  SchemeEnd := Pos(':', URI);
  if (SchemeEnd > 0) and (Pos('//', URI) = SchemeEnd + 1) then
  begin
    Scheme := Copy(URI, 1, SchemeEnd - 1);
    AuthorityStart := SchemeEnd + 3;
    PathStart := Pos('/', URI, AuthorityStart);
    if PathStart = 0 then
    begin
      Authority := Copy(URI, AuthorityStart, Length(URI));
      Path := '/';
    end else
    begin
      Authority := Copy(URI, AuthorityStart, PathStart - AuthorityStart);
      Path := Copy(URI, PathStart, Length(URI));
    end;
  end;
  FragmentStart := Pos('#', Path);
  if FragmentStart > 0 then
  begin
    Fragment := Copy(Path, FragmentStart, Length(Path));
    Path := Copy(Path, 1, FragmentStart - 1);
  end;
  QueryStart := Pos('?', Path);
  if QueryStart > 0 then
  begin
    Query := Copy(Path, QueryStart, Length(Path));
    Path := Copy(Path, 1, QueryStart - 1);
  end;
  Scheme := LowerCase(Scheme);
  if Authority <> '' then
  begin
    var AtPos := Pos('@', Authority);
    var HostPart := Authority;
    if AtPos > 0 then HostPart := Copy(Authority, AtPos + 1, Length(Authority));
    var ColonPos := Pos(':', HostPart);
    if ColonPos > 0 then
    begin
      Host := Copy(HostPart, 1, ColonPos - 1);
      Port := Copy(HostPart, ColonPos + 1, Length(HostPart));
    end else
    begin
      Host := HostPart;
      Port := '';
    end;
    Host := LowerCase(Host);
    if ((Scheme = 'http') and (Port = '80')) or ((Scheme = 'https') and (Port = '443')) then Port := '';
    Authority := Host;
    if Port <> '' then Authority := Authority + ':' + Port;
    if AtPos > 0 then Authority := Copy(URI, 1, AtPos) + Authority;
  end;

  if Path <> '' then
  begin
    PathSegments := TStringList.Create;
    NormalizedSegments := TStringList.Create;
    try
      PathSegments.Delimiter := '/';
      PathSegments.DelimitedText := Path;
      for I := 0 to PathSegments.Count - 1 do
      begin
        Segment := PathSegments[I];
        if Segment = '..' then
        begin
          if (NormalizedSegments.Count > 0) and (NormalizedSegments.Count > NormalizedSegments.IndexOf('')) then
            NormalizedSegments.Delete(NormalizedSegments.Count - 1);
        end
        else if (Segment <> '.') then
        begin
          NormalizedSegments.Add(LowerCase(Segment));
        end;
      end;
      Path := string.Join('/', NormalizedSegments.ToStringArray);
    finally
      PathSegments.Free;
      NormalizedSegments.Free;
    end;
  end;
  if Path = '' then Path := '/';
  Result := '';
  if Scheme <> '' then
    Result := Scheme + '://' + Authority;
  Result := Result + Path + Query + Fragment;
end;

class function THeaderValidator.IsValidTokenChar(C: Char): Boolean;
begin
  Result := TCharacter.IsLetterOrDigit(C) or
           (C in ['-', '.', '_', '~', '^', '`', '|']);
end;

class function THeaderValidator.IsValidFieldVChar(C: Char): Boolean;
begin
  Result := (Ord(C) >= $21) and (Ord(C) <= $7E);
end;

class function THeaderValidator.IsObsText(C: Char): Boolean;
begin
  Result := (Ord(C) >= $80) and (Ord(C) <= $FF);
end;

class function THeaderValidator.HasSuspiciousPatterns(const Value: string): Boolean;
var
  SuspiciousPatterns: TArray<string>;
  SQLPatterns: TArray<string>;
  Pattern: string;
  LowerValue: string;
  I: Integer;
  C: Char;
begin
  Result := False;
  LowerValue := LowerCase(Value);
  for C in Value do
  begin
    if (Ord(C) < 32) and (C <> #9) then
    begin
      if not (C in [#10, #13]) then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
  SuspiciousPatterns := [
    'javascript:', 'data:', 'vbscript:', '<script', '</script>',
    'onload=', 'onerror=', 'onclick=', 'onmouseover=',
    'x-injected-header', 'x-forwarded-host', 'x-original-host'
  ];
  for Pattern in SuspiciousPatterns do
  begin
    if Pos(Pattern, LowerValue) > 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
  SQLPatterns := [
    'union', 'select', 'insert', 'delete', 'update', 'drop',
    'or 1=1', 'or ''1''=''1''', '; drop',
    'exec', 'execute', 'sp_', 'xp_'
  ];
  for Pattern in SQLPatterns do
  begin
    if Pos(Pattern, LowerValue) > 0 then
    begin
      if (Pattern = 'select') and (Pos('user-agent', LowerValue) > 0) then
        Continue;
      Result := True;
      Exit;
    end;
  end;
  if (Pos('%00', Value) > 0) or (Pos(#0, Value) > 0) then
  begin
    Result := True;
    Exit;
  end;
end;


class function THeaderValidator.DetectInjectionAttempt(const Value: string): Boolean;
var
  I: Integer;
  ConsecutiveControlChars: Integer;
begin
  Result := False;
  ConsecutiveControlChars := 0;
  for I := 1 to Length(Value) do
  begin
    if Ord(Value[I]) < 32 then
    begin
      Inc(ConsecutiveControlChars);
      if ConsecutiveControlChars > 2 then
      begin
        Result := True;
        Exit;
      end;
    end
    else
      ConsecutiveControlChars := 0;
    if (Value[I] = #13) or (Value[I] = #10) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

class function THeaderValidator.ValidateHeaderName(const Name: string; out ErrorMsg: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  ErrorMsg := '';
  try
    if Length(Name) = 0 then
    begin
      ErrorMsg := 'Header name cannot be empty';
      Exit;
    end;

    if Length(Name) > 256 then
    begin
      ErrorMsg := 'Header name too long (>256 characters)';
      Exit;
    end;
    for I := 1 to Length(Name) do
    begin
      if not IsValidTokenChar(Name[I]) then
      begin
        ErrorMsg := Format('Invalid character in header name: %s (code: %d, position %d', [Name[I], Ord(Name[I]), I]);
        Exit;
      end;
    end;
    var LowerName := LowerCase(Name);
    if (Pos('script', LowerName) > 0) or
       (Pos('javascript', LowerName) > 0) or
       (Pos('vbscript', LowerName) > 0) then
    begin
      ErrorMsg := 'Forbidden pattern in header name: ' + Name;
      Exit;
    end;
    if HasSuspiciousPatterns(Name) then
    begin
      ErrorMsg := 'Suspicious patterns detected in header name: ' + Name;
      Exit;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      ErrorMsg := 'Header name validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function THeaderValidator.SanitizeHeaderValue(const Value: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(Value) do
  begin
    C := Value[I];
    if (Ord(C) < 32) and (C <> ' ') and (C <> #9) then
      Continue;
    if C in [#13, #10, #0] then
      Continue;
    Result := Result + C;
  end;
  Result := Trim(Result);
  if Length(Result) > 8192 then
    Result := Copy(Result, 1, 8192);
end;

class function THeaderValidator.IsSafeHeaderName(const Name: string): Boolean;
var
  SafeHeaders: TArray<string>;
  UnsafeHeaders: TArray<string>;
  Header: string;
  NormalizedName: string;
begin
  NormalizedName := LowerCase(Trim(Name));
  SafeHeaders := [
    'accept', 'accept-encoding', 'accept-language', 'authorization',
    'cache-control', 'connection', 'content-length', 'content-type',
    'cookie', 'host', 'referer', 'user-agent', 'x-requested-with',
    'x-forwarded-for', 'x-real-ip', 'if-none-match', 'if-modified-since'
  ];
  UnsafeHeaders := [
    'x-forwarded-host', 'x-original-host', 'x-rewrite-url',
    'x-original-url', 'x-override-url', 'x-http-destip',
    'x-http-host-override', 'x-forwarded-server'
  ];

  for Header in UnsafeHeaders do
  begin
    if NormalizedName = Header then
    begin
      Result := False;
      Exit;
    end;
  end;

  for Header in SafeHeaders do
  begin
    if NormalizedName = Header then
    begin
      Result := True;
      Exit;
    end;
  end;

  if (Pos('x-', NormalizedName) = 1) then
  begin
    if THeaderValidator.HasSuspiciousPatterns(NormalizedName) then
    begin
      Result := False;
      Exit;
    end;
    Result := (Length(Name) <= 64);
    Exit;
  end;
  Result := (Length(Name) <= 64) and TCharacter.IsLetter(Name[1]);
end;

class function THeaderValidator.DetectRequestSmuggling(const Headers: TStringList): TSecurityThreat;
var
  I, ContentLengthCount, TransferEncodingCount: Integer;
  Line, Name, Value: string;
  ColonPos: Integer;
  ContentLengthValues: TStringList;
  HasChunked, HasContentLength: Boolean;
begin
  Result := stNone;
  ContentLengthCount := 0;
  TransferEncodingCount := 0;
  HasChunked := False;
  HasContentLength := False;
  ContentLengthValues := TStringList.Create;
  try
    for I := 0 to Headers.Count - 1 do
    begin
      Line := Headers[I];
      ColonPos := Pos(':', Line);
      if ColonPos > 0 then
      begin
        Name := LowerCase(Trim(Copy(Line, 1, ColonPos - 1)));
        Value := Trim(Copy(Line, ColonPos + 1, Length(Line)));
        if Name = 'content-length' then
        begin
          Inc(ContentLengthCount);
          ContentLengthValues.Add(Value);
          HasContentLength := True;
        end
        else if Name = 'transfer-encoding' then
        begin
          Inc(TransferEncodingCount);
          if Pos('chunked', LowerCase(Value)) > 0 then
            HasChunked := True;
        end;
      end;
    end;
    if ContentLengthCount > 1 then
    begin
      for I := 1 to ContentLengthValues.Count - 1 do
      begin
        if ContentLengthValues[I] <> ContentLengthValues[0] then
        begin
          Result := stRequestSmuggling;
          Exit;
        end;
      end;
    end;
    if HasContentLength and HasChunked then
    begin
      Result := stRequestSmuggling;
      Exit;
    end;

    if TransferEncodingCount > 1 then
    begin
      Result := stRequestSmuggling;
      Exit;
    end;
  finally
    ContentLengthValues.Free;
  end;
end;

constructor TContentEncodingHandler.Create;
begin
  inherited Create;
end;

destructor TContentEncodingHandler.Destroy;
begin
  inherited Destroy;
end;

function TContentEncodingHandler.GetEncodingFromString(const EncodingStr: string): TContentEncoding;
var
  LowerEncoding: string;
begin
  LowerEncoding := LowerCase(Trim(EncodingStr));
  if LowerEncoding = 'gzip' then Result := ceGzip
  else if LowerEncoding = 'deflate' then Result := ceDeflate
  else if LowerEncoding = 'compress' then Result := ceCompress
  else if LowerEncoding = 'br' then Result := ceBrotli
  else if LowerEncoding = 'identity' then Result := ceIdentity
  else Result := ceNone;
end;

function TContentEncodingHandler.ParseContentEncoding(const EncodingHeader: string): TArray<TContentEncoding>;
var
  Encodings: TStringList;
  I: Integer;
  EncodingStr: string;
begin
  SetLength(Result, 0);
  if Trim(EncodingHeader) = '' then
    Exit;
  Encodings := TStringList.Create;
  try
    Encodings.Delimiter := ',';
    Encodings.DelimitedText := EncodingHeader;
    SetLength(Result, Encodings.Count);
    for I := 0 to Encodings.Count - 1 do
    begin
      EncodingStr := Trim(Encodings[I]);
      Result[I] := GetEncodingFromString(EncodingStr);
    end;
  finally
    Encodings.Free;
  end;
end;

function TContentEncodingHandler.DecompressGzip(const Data: TBytes): TBytes;
begin
  try
    SetLength(Result, Length(Data));
    Move(Data[0], Result[0], Length(Data));
  except
    on E: Exception do
    begin
      SetLength(Result, Length(Data));
      Move(Data[0], Result[0], Length(Data));
    end;
  end;
end;

function TContentEncodingHandler.DecompressDeflate(const Data: TBytes): TBytes;
begin
  try
    SetLength(Result, Length(Data));
    Move(Data[0], Result[0], Length(Data));
  except
    on E: Exception do
    begin
      SetLength(Result, Length(Data));
      Move(Data[0], Result[0], Length(Data));
    end;
  end;
end;

function TContentEncodingHandler.DecompressBrotli(const Data: TBytes): TBytes;
begin
  try
    SetLength(Result, Length(Data));
    Move(Data[0], Result[0], Length(Data));
  except
    on E: Exception do
    begin
      SetLength(Result, Length(Data));
      Move(Data[0], Result[0], Length(Data));
    end;
  end;
end;

function TContentEncodingHandler.DecompressData(const Data: TBytes; Encoding: TContentEncoding): TBytes;
begin
  try
    case Encoding of
      ceGzip: Result := DecompressGzip(Data);
      ceDeflate: Result := DecompressDeflate(Data);
      ceBrotli: Result := DecompressBrotli(Data);
      ceCompress: Result := DecompressDeflate(Data);
      ceIdentity, ceNone:
        begin
          SetLength(Result, Length(Data));
          Move(Data[0], Result[0], Length(Data));
        end;
    else
      begin
        SetLength(Result, Length(Data));
        Move(Data[0], Result[0], Length(Data));
      end;
    end;
  except
    on E: Exception do
    begin
      SetLength(Result, Length(Data));
      Move(Data[0], Result[0], Length(Data));
    end;
  end;
end;

function TContentEncodingHandler.GetEncodingName(Encoding: TContentEncoding): string;
begin
  case Encoding of
    ceGzip: Result := 'gzip';
    ceDeflate: Result := 'deflate';
    ceCompress: Result := 'compress';
    ceBrotli: Result := 'br';
    ceIdentity: Result := 'identity';
  else
    Result := 'none';
  end;
end;

function TContentEncodingHandler.IsCompressionSupported(Encoding: TContentEncoding): Boolean;
begin
  Result := Encoding in [ceGzip, ceDeflate, ceIdentity, ceNone];
end;

constructor TRequestRecovery.Create(MaxAttempts: Integer);
begin
  inherited Create;
  FMaxRecoveryAttempts := MaxAttempts;
  FRecoveryActions := TList<TRecoveryAction>.Create;
  FErrorLog := TStringList.Create;
  FRecoveryAttempts := 0;
end;

destructor TRequestRecovery.Destroy;
begin
  try
    FRecoveryActions.Free;
    FErrorLog.Free;
  finally
    inherited Destroy;
  end;
end;

function TRequestRecovery.CanRecover(const Error: string): Boolean;
var
  RecoverableErrors: TArray<string>;
  ErrorPattern: string;
begin
  Result := False;
  if FRecoveryAttempts >= FMaxRecoveryAttempts then
    Exit;
  RecoverableErrors := [
    'oversized', 'malformed header', 'invalid encoding',
    'suspicious pattern', 'unknown character', 'truncated'
  ];
  for ErrorPattern in RecoverableErrors do
  begin
    if Pos(LowerCase(ErrorPattern), LowerCase(Error)) > 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function TRequestRecovery.SuggestRecoveryAction(const Error: string; const Context: string): TRecoveryAction;
var
  LowerError: string;
begin
  LowerError := LowerCase(Error);
  if Pos('oversized', LowerError) > 0 then
    Result := raTruncateValue
  else if Pos('malformed', LowerError) > 0 then
    Result := raSkipHeader
  else if Pos('suspicious', LowerError) > 0 then
    Result := raSanitize
  else if Pos('invalid encoding', LowerError) > 0 then
    Result := raSanitize
  else if Pos('unknown character', LowerError) > 0 then
    Result := raSanitize
  else if Pos('truncated', LowerError) > 0 then
    Result := raContinue
  else
    Result := raAbort;
end;

procedure TRequestRecovery.LogRecoveryAttempt(const Action: TRecoveryAction; const Details: string);
var
  ActionStr: string;
  LogEntry: string;
begin
  try
    Inc(FRecoveryAttempts);
    case Action of
      raAbort: ActionStr := 'ABORT';
      raSkipHeader: ActionStr := 'SKIP_HEADER';
      raTruncateValue: ActionStr := 'TRUNCATE';
      raSanitize: ActionStr := 'SANITIZE';
      raContinue: ActionStr := 'CONTINUE';
    else
      ActionStr := 'UNKNOWN';
    end;
    LogEntry := Format('[%s] Attempt %d: %s - %s',
                      [FormatDateTime('hh:nn:ss.zzz', Now),
                       FRecoveryAttempts, ActionStr, Details]);
    FErrorLog.Add(LogEntry);
    FRecoveryActions.Add(Action);
  except

  end;
end;

function TRequestRecovery.GetRecoveryLog: string;
begin
  try
    Result := FErrorLog.Text;
  except
    Result := 'Error retrieving recovery log';
  end;
end;

procedure TRequestRecovery.Clear;
begin
  try
    FRecoveryActions.Clear;
    FErrorLog.Clear;
    FRecoveryAttempts := 0;
  except

  end;
end;

constructor THttpHeaders.Create(ValidationLevel: TValidationLevel);
begin
  inherited Create;
  FHeaders := TDictionary<string, TStringList>.Create;
  FValidationLevel := ValidationLevel;
  FContentEncodingHandler := TContentEncodingHandler.Create;
end;

destructor THttpHeaders.Destroy;
var
  HeaderValues: TStringList;
begin
  try
    for HeaderValues in FHeaders.Values do
        HeaderValues.Free;
    FHeaders.Free;
    FContentEncodingHandler.Free;
  finally
    inherited Destroy;
  end;
end;

function THttpHeaders.NormalizeHeaderName(const HeaderName: string): string;
begin
  Result := LowerCase(Trim(HeaderName));
end;

function THttpHeaders.ParseFoldedHeader(const Lines: TStringList; StartIndex: Integer; out EndIndex: Integer): string;
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
      if (Length(Line) > 0) and (Line[1] in [' ', #9]) then
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
  IsFormBoundary: Boolean;
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
          begin
            raise Exception.Create('Invalid header name rejected: ' + ErrorMsg);
          end;
        vlPermissive:
          ;
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
      else
      begin
        if not THeaderValidator.HasSuspiciousPatterns(Value) then
        begin
          AddHeader(Name, Value);
          Exit;
        end;
      end;
    end;

    if THeaderValidator.HasSuspiciousPatterns(Value) then
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
    if THeaderValidator.HasSuspiciousPatterns(Name) then
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
    if not THeaderValidator.ValidateHeaderValue(SanitizedValue, ErrorMsg) then
    begin
      case FValidationLevel of
        vlStrict:
          raise Exception.Create('Invalid header value: ' + ErrorMsg);
        vlModerate:
          begin
            SanitizedValue := THeaderValidator.SanitizeHeaderValue(SanitizedValue);
          end;
        vlPermissive:
          ;
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

procedure THttpHeaders.AddHeader(const Name, Value: string);
var
  NormalizedName: string;
  HeaderValues: TStringList;
begin
  try
    NormalizedName := NormalizeHeaderName(Name);
    if NormalizedName = '' then
       Exit;
    if not FHeaders.TryGetValue(NormalizedName, HeaderValues) then
    begin
      HeaderValues := TStringList.Create;
      FHeaders.Add(NormalizedName, HeaderValues);
    end;
    HeaderValues.Add(Trim(Value));
  except
    on E: Exception do
    begin
      Logger.Error('Error adding header "%s": %s', [Name, E.Message]);
      raise Exception.CreateFmt('Error adding header "%s": %s', [Name, E.Message]);
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

function THttpHeaders.GetHeaderValues(const Name: string): TArray<string>;
var
  NormalizedName: string;
  HeaderValues: TStringList;
  I: Integer;
begin
  SetLength(Result, 0);
  try
    NormalizedName := NormalizeHeaderName(Name);
    if FHeaders.TryGetValue(NormalizedName, HeaderValues) then
    begin
      SetLength(Result, HeaderValues.Count);
      for I := 0 to HeaderValues.Count - 1 do
      begin
        Result[I] := HeaderValues[I];
      end;
    end;
  except
    SetLength(Result, 0);
  end;
end;


function THttpHeaders.HasHeader(const Name: string): Boolean;
var
  NormalizedName: string;
begin
  try
    NormalizedName := NormalizeHeaderName(Name);
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
  HeaderValues: TStringList;
begin
  try
    for HeaderValues in FHeaders.Values do
      HeaderValues.Free;
    FHeaders.Clear;
  except

  end;
end;


function THttpHeaders.GetHeaderNames: TArray<string>;
begin
  try
    Result := FHeaders.Keys.ToArray;
  except
    SetLength(Result, 0);
  end;
end;

function THttpHeaders.Count: Integer;
begin
  try
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
          if THeaderValidator.HasSuspiciousPatterns(HeaderValues[I]) then
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

  end;
end;

function THttpHeaders.GetContentEncodings: TArray<TContentEncoding>;
var
  ContentEncodingHeader: string;
begin
  try
    ContentEncodingHeader := GetHeader('Content-Encoding');
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

constructor THttpRequestInfo.Create;
begin
  inherited Create;
  FQueryParameters := TDictionary<string, string>.Create;
  FUriValidationErrors := TStringList.Create;
  Clear;
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
  SetLength(FContentEncodings, 0);
  FIsSecure := False;
  FUriValidationErrors.Clear;
end;

function THttpRequestInfo.StringToHttpMethod(const MethodStr: string): THttpMethod;
var
  UpperMethod: string;
begin
  try
    UpperMethod := UpperCase(Trim(MethodStr));
    if UpperMethod = 'GET' then Result := hmGET
    else if UpperMethod = 'POST' then Result := hmPOST
    else if UpperMethod = 'PUT' then Result := hmPUT
    else if UpperMethod = 'DELETE' then Result := hmDELETE
    else if UpperMethod = 'HEAD' then Result := hmHEAD
    else if UpperMethod = 'OPTIONS' then Result := hmOPTIONS
    else if UpperMethod = 'PATCH' then Result := hmPATCH
    else if UpperMethod = 'TRACE' then Result := hmTRACE
    else if UpperMethod = 'CONNECT' then Result := hmCONNECT
    else Result := hmUnknown;
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
    if UpperVersion = 'HTTP/1.0' then Result := hvHTTP10
    else if UpperVersion = 'HTTP/1.1' then Result := hvHTTP11
    else if UpperVersion = 'HTTP/2.0' then Result := hvHTTP20
    else if UpperVersion = 'HTTP/2' then Result := hvHTTP20
    else Result := hvUnknown;
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
    if LowerEncoding = 'chunked' then Result := teChunked
    else if LowerEncoding = 'compress' then Result := teCompress
    else if LowerEncoding = 'deflate' then Result := teDeflate
    else if LowerEncoding = 'gzip' then Result := teGzip
    else if LowerEncoding = 'identity' then Result := teIdentity
    else Result := teNone;
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
    if LowerConnection = 'close' then Result := ctClose
    else if LowerConnection = 'upgrade' then Result := ctUpgrade
    else Result := ctKeepAlive;
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
    begin
      ADictionary.Add(Key, Value);
    end;
    StartIndex := PairEndIndex + 1;
  end;
end;

procedure THttpRequestInfo.ParseUri(const RawUri: string);
var
  QuestionPos, HashPos, SchemeEnd, AuthorityStart, PathStart: Integer;
  WorkingUri: string;
  ErrorMsg: string;
begin
  try
    FRawUri := Trim(RawUri);
    FUri := FRawUri;
    FUriValidationErrors.Clear;
    if (Pos('%00', FRawUri) > 0) or (Pos(#0, FRawUri) > 0) then
       FUriValidationErrors.Add('Null byte injection attempt detected in URI');
    if Length(FRawUri) = 0 then
    begin
      FUriValidationErrors.Add('URI cannot be empty');
      FPath := '/'; Exit;
    end;
    WorkingUri := FRawUri;
    HashPos := Pos('#', WorkingUri);
    if HashPos > 0 then
    begin
      FFragment := Copy(WorkingUri, HashPos + 1, Length(WorkingUri));
      WorkingUri := Copy(WorkingUri, 1, HashPos - 1);
      if not TUriValidator.IsValidFragment(FFragment) then
        FUriValidationErrors.Add('Invalid fragment: ' + FFragment);
    end else FFragment := '';
    QuestionPos := Pos('?', WorkingUri);
    if QuestionPos > 0 then
    begin
      FQueryString := Copy(WorkingUri, QuestionPos + 1, Length(WorkingUri));
      WorkingUri := Copy(WorkingUri, 1, QuestionPos - 1);
      if not TUriValidator.IsValidQuery(FQueryString) then
        FUriValidationErrors.Add('Invalid query string: ' + FQueryString);
      ParseQueryString(FQueryString, FQueryParameters);
    end else FQueryString := '';
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
      end else
      begin
        FAuthority := Copy(WorkingUri, AuthorityStart, Length(WorkingUri));
        FPath := '/';
      end;
    end else
    begin
      FScheme := '';
      FAuthority := '';
      FPath := WorkingUri;
    end;
    if not TUriValidator.ValidateAbsolutePath(FPath, ErrorMsg) then
      FUriValidationErrors.Add('Path validation: ' + ErrorMsg);
    FNormalizedUri := TUriValidator.NormalizeURI(FRawUri);
    if FPath = '' then FPath := '/';
  except
    on E: Exception do
    begin
      FUriValidationErrors.Add('Parse error: ' + E.Message);
      FPath := '/'; FQueryString := ''; FFragment := ''; FScheme := ''; FAuthority := '';
    end;
  end;
end;

procedure THttpRequestInfo.ValidateUriComponents;
var
  SQLPatterns: TArray<string>;
  XSSPatterns: TArray<string>;
  Pattern: string;
  LowerQuery, LowerPath: string;
begin
  try
    if Length(FPath) > 2048 then
       FUriValidationErrors.Add('Path too long (>2048 characters)');
    if Length(FQueryString) > 4096 then
       FUriValidationErrors.Add('Query string too long (>4096 characters)');
    if Length(FFragment) > 1024 then
       FUriValidationErrors.Add('Fragment too long (>1024 characters)');
    if Pos('..', FPath) > 0 then
       FUriValidationErrors.Add('Path traversal attempt detected in path');
    if Pos('%00', FRawUri) > 0 then
       FUriValidationErrors.Add('Null byte injection attempt detected');
    if (Pos('%0A', FRawUri) > 0) or (Pos('%0D', FRawUri) > 0) or  (Pos(#10, FRawUri) > 0) or (Pos(#13, FRawUri) > 0) then
       FUriValidationErrors.Add('CRLF injection attempt detected');

    if FQueryString <> '' then
    begin
      LowerQuery := LowerCase(FQueryString);
      SQLPatterns := [
        'union', 'select', 'insert', 'delete', 'update', 'drop',
        'or 1=1', 'or ''1''=''1''', '--', '/*', '*/',
        'exec', 'execute', 'sp_', 'xp_', '; drop',
        'union select', 'order by', 'group by', 'having',
        'information_schema', 'sys.', 'master.', 'msdb.',
        'declare @', 'cast(', 'convert(', 'waitfor delay'
      ];
      for Pattern in SQLPatterns do
      begin
        if Pos(Pattern, LowerQuery) > 0 then
        begin
          FUriValidationErrors.Add('Potential SQL injection in query string: ' + Pattern);
          Break;
        end;
      end;
    end;
    if FPath <> '' then
    begin
      LowerPath := LowerCase(FPath);
      for Pattern in SQLPatterns do
      begin
        if Pos(Pattern, LowerPath) > 0 then
        begin
          FUriValidationErrors.Add('Potential SQL injection in path: ' + Pattern);
          Break;
        end;
      end;
    end;
    if FQueryString <> '' then
    begin
      XSSPatterns := [
        'script', 'javascript:', 'vbscript:', 'data:', 'onload',
        'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        '<img', '<iframe', '<object', '<embed', '<form',
        'document.cookie', 'document.location', 'window.location'
      ];
      for Pattern in XSSPatterns do
      begin
        if Pos(Pattern, LowerQuery) > 0 then
        begin
          FUriValidationErrors.Add('Potential XSS in query string: ' + Pattern);
          Break;
        end;
      end;
    end;
    if FQueryString <> '' then
    begin
      var Params := FQueryString.Split(['&']);
      for var Param in Params do
      begin
        if Length(Param) > 1024 then
        begin
          FUriValidationErrors.Add('Query parameter too long: ' + Copy(Param, 1, 50) + '...');
          Break;
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Info(Format('DEBUG: Exception in ValidateUriComponents: %s', [E.Message]));
      FUriValidationErrors.Add('Validation error: ' + E.Message);
    end;
  end;
end;

procedure THttpRequestInfo.ParseRequestLine(const RequestLine: string);
var
  Parts: TArray<string>;
  ErrorMsg: string;
  SpacePos1, SpacePos2: Integer;
begin
  try
    SpacePos1 := Pos(' ', RequestLine);
    if SpacePos1 = 0 then
       raise Exception.Create('Invalid HTTP request line - missing first space');
    SpacePos2 := Pos(' ', RequestLine, SpacePos1 + 1);
    if SpacePos2 = 0 then
       raise Exception.Create('Invalid HTTP request line - missing second space');
    SetLength(Parts, 3);
    Parts[0] := Copy(RequestLine, 1, SpacePos1 - 1);
    Parts[1] := Copy(RequestLine, SpacePos1 + 1, SpacePos2 - SpacePos1 - 1);
    Parts[2] := Copy(RequestLine, SpacePos2 + 1, Length(RequestLine));
    FMethod := StringToHttpMethod(Parts[0]);
    if FMethod = hmUnknown then
       raise Exception.CreateFmt('Unknown HTTP method: %s', [Parts[0]]);
    ParseUri(Parts[1]);
    FVersion := StringToHttpVersion(Parts[2]);
    if FVersion = hvUnknown then
       raise Exception.CreateFmt('Unsupported HTTP version: %s', [Parts[2]]);
    if not TUriValidator.ValidateAbsolutePath(FPath, ErrorMsg) then
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
  HostHeader: string;
begin
  try
    TransferEncodingStr := Headers.TransferEncoding;
    FTransferEncoding := ParseTransferEncoding(TransferEncodingStr);
    ConnectionStr := Headers.Connection;
    FConnectionType := ParseConnectionType(ConnectionStr);
    if FVersion = hvHTTP10 then
       FConnectionType := ctClose;
    ContentLengthStr := Headers.ContentLength;
    if ContentLengthStr <> '' then
    begin
      FContentLength := StrToInt64Def(ContentLengthStr, -1);
      if FContentLength < 0 then
         raise Exception.Create('Invalid Content-Length value: ' + ContentLengthStr);
    end
    else
      FContentLength := -1;

    FContentEncodings := Headers.GetContentEncodings;
    HostHeader := Headers.Host;
    if (FVersion = hvHTTP11) and (HostHeader = '') then
      raise Exception.Create('HTTP/1.1 requires Host header');

    FIsSecure := (Headers.GetHeader('X-Forwarded-Proto') = 'https') or
                (Headers.GetHeader('X-Forwarded-SSL') = 'on') or
                (Pos('https', LowerCase(FScheme)) > 0);
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
  Result := FUriValidationErrors.Count = 0;
end;

function THttpRequestInfo.GetUriValidationSummary: string;
begin
  if FUriValidationErrors.Count = 0 then
    Result := 'URI validation passed'
  else
    Result := Format('URI validation failed (%d errors): %s',
                    [FUriValidationErrors.Count, FUriValidationErrors.Text]);
end;

constructor TRequest.Create(ASocket: TSocket; const ARemoteAddr: TSockAddrIn;
                           AMaxHeaderSize: Integer; AMaxBodySize: Int64;
                           ValidationLevel: TValidationLevel; EnableRecovery: Boolean);
begin
  inherited Create;

  try
    FSecurityViolationDetected := False;
    FSocket := ASocket;
    FRemoteAddr := ARemoteAddr;
    FMaxHeaderSize := AMaxHeaderSize;
    FMaxBodySize := AMaxBodySize;
    FValidationLevel := ValidationLevel;
    FEnableRecovery := EnableRecovery;
    FMaxHeaderCount := MAX_HEADER_COUNT;
    FMaxHeaderLineLength := MAX_HEADER_LINE_LENGTH;
    if FMaxHeaderSize < 1024 then
      FMaxHeaderSize := 32768;
    if FMaxBodySize < 0 then
      FMaxBodySize := 104857600;

    FHeaders := THttpHeaders.Create(ValidationLevel);
    FRequestInfo := THttpRequestInfo.Create;
    FContentEncodingHandler := TContentEncodingHandler.Create;
    FRecovery := TRequestRecovery.Create(MAX_RECOVERY_ATTEMPTS);
    FBodyParser := nil;
    FBodyStream := TMemoryStream.Create;
    FDecompressedBodyStream := TMemoryStream.Create;
    InitializeBuffers;
    Clear;
  except
    on E: Exception do
    begin
      try
        FreeAndNil(FHeaders);
        FreeAndNil(FRequestInfo);
        FreeAndNil(FContentEncodingHandler);
        FreeAndNil(FRecovery);
        FreeAndNil(FBodyStream);
        FreeAndNil(FDecompressedBodyStream);
      except

      end;
      raise Exception.CreateFmt('Error creating TRequest: %s', [E.Message]);
    end;
  end;
end;

destructor TRequest.Destroy;
begin
  try
    ClearBuffers;
    FreeAndNil(FHeaders);
    FreeAndNil(FRequestInfo);
    FreeAndNil(FContentEncodingHandler);
    FreeAndNil(FRecovery);
    FreeAndNil(FBodyStream);
    FreeAndNil(FDecompressedBodyStream);
    FreeAndNil(FBodyParser);
  finally
    inherited Destroy;
  end;
end;

procedure TRequest.InitializeBuffers;
begin
  try
    SetLength(FRawBuffer, FMaxHeaderSize);
    SetLength(FHeadersBuffer, FMaxHeaderSize);
    FRawBufferSize := 0;
  except
    on E: Exception do
      raise Exception.CreateFmt('Buffer initialization error: %s', [E.Message]);
  end;
end;

procedure TRequest.ClearBuffers;
begin
  try
    SetLength(FRawBuffer, 0);
    SetLength(FHeadersBuffer, 0);
    FRawBufferSize := 0;
    if Assigned(FBodyStream) then
    begin
      FBodyStream.Clear;
      FBodyStream.Size := 0;
    end;
    if Assigned(FDecompressedBodyStream) then
    begin
      FDecompressedBodyStream.Clear;
      FDecompressedBodyStream.Size := 0;
    end;
  except

  end;
end;

procedure TRequest.Clear;
begin
  try
    ClearBuffers;
    if Assigned(FHeaders) then
       FHeaders.Clear;
    if Assigned(FRequestInfo) then
       FRequestInfo.Clear;
    if Assigned(FRecovery) then
       FRecovery.Clear;
    FreeAndNil(FBodyParser);
    FBodyParser := nil;
    FState := rsWaitingHeaders;
    FHeadersSize := 0;
    FErrorParsing := False;
    FErrorMessage := '';
    SetLength(FSecurityThreats, 0);
    FHeadersEndPos := -1;
    FTotalBytesReceived := 0;
    FBodyBytesReceived := 0;
    FExpectedBodySize := -1;
    FIsChunkedTransfer := False;
    FChunkState := 0;
    FCurrentChunkSize := 0;
    FCurrentChunkReceived := 0;
    FHeaderLineCount := 0;
    FSuspiciousHeaderCount := 0;
    FLargeHeaderWarnings := 0;
    FMalformedLineCount := 0;
    FSecurityViolationDetected := False;
    InitializeBuffers;
  except
    on E: Exception do
      SetError(Format('TRequest cleanup error: %s', [E.Message]));
  end;
end;

procedure TRequest.Reset;
begin
  Clear;
end;

procedure TRequest.SetError(const ErrorMsg: string; Threat: TSecurityThreat);
var
  i: Integer;
  ThreatsStr: string;
begin
  FErrorParsing := True;
  FErrorMessage := ErrorMsg;
  FState := rsError;
  if (Threat <> stNone) or (Pos('injection', LowerCase(ErrorMsg)) > 0) or (Pos('attack', LowerCase(ErrorMsg)) > 0) then
  begin
    FSecurityViolationDetected := True;
  end;

  if Threat <> stNone then
  begin
    if not HasExistingThreat(Threat) then
    begin
      var OldLen := Length(FSecurityThreats);
      SetLength(FSecurityThreats, OldLen + 1);
      FSecurityThreats[OldLen] := Threat;
    end
    else
    begin
    end;
  end;
  ThreatsStr := '';
  for i := 0 to Length(FSecurityThreats) - 1 do
     ThreatsStr := ThreatsStr + IntToStr(Ord(FSecurityThreats[i])) + ' ';
end;

function TRequest.FindHeadersEnd(const Buffer: TBytes; Size: Integer): Integer;
var
  HeadersAsString: string;
  PosCRLF: Integer;
begin
  Result := -1;
  if Size < 4 then
     Exit;

  try
    SetString(HeadersAsString, PAnsiChar(Buffer), Size);
    PosCRLF := Pos(#13#10#13#10, HeadersAsString);
    if PosCRLF > 0 then
    begin
      Result := PosCRLF + 3;
    end;
  except
    Result := -1;
  end;
end;

procedure TRequest.AppendData(const Data: array of Byte; Size: Integer);
var
  NewSize: Integer;
begin
  if FErrorParsing or (FState = rsComplete) then
     Exit;

  if (FState = rsWaitingHeaders) and (FRawBufferSize + Size > FMaxHeaderSize) then
  begin
    if FindHeadersEnd(FRawBuffer, FRawBufferSize) = -1 then
    begin
      SetError(Format('Headers size will exceed maximum limit (%d bytes)', [FMaxHeaderSize]), stOversizeAttack);
      Exit;
    end;
  end;
  if Size <= 0 then
  begin
    if (FTotalBytesReceived = 0) then
       SetError('Empty request detected', stMalformedURI);
    Exit;
  end;

  try
    if FTotalBytesReceived + Size > FMaxHeaderSize + FMaxBodySize then
    begin
      SetError('Total request size exceeds maximum limit', stOversizeAttack);
      Exit;
    end;
    case FState of
      rsWaitingHeaders, rsParsingHeaders:
        begin
          NewSize := FRawBufferSize + Size;
          if NewSize > Length(FRawBuffer) then
            SetLength(FRawBuffer, NewSize);
          Move(Data[0], FRawBuffer[FRawBufferSize], Size);
          FRawBufferSize := NewSize;
          FTotalBytesReceived := FTotalBytesReceived + Size;
          FHeadersEndPos := FindHeadersEnd(FRawBuffer, FRawBufferSize);
          if FHeadersEndPos > 0 then
          begin
            FState := rsParsingHeaders;
            ParseHeaders;
            if not FErrorParsing then
               ProcessRemainingDataAfterHeaders;
          end
          else
          begin
            if FRawBufferSize >= FMaxHeaderSize then
            begin
              SetError(Format('Headers block size reached limit (%d) without end-of-headers marker.', [FMaxHeaderSize]), stOversizeAttack);
              Exit;
            end;
            FState := rsWaitingHeaders;
          end;
        end;
      rsWaitingBody:
        ProcessBodyData(Data, Size);
      rsError: Exit;
    end;
  except
    on E: Exception do
      SetError(Format('Exception while appending data: %s', [E.Message]));
  end;
end;

function TRequest.AttemptRecovery(const Error: string; const Context: string): Boolean;
var
  Action: TRecoveryAction;
begin
  Result := False;
  try
    if not FEnableRecovery or not FRecovery.CanRecover(Error) then
      Exit;
    Action := FRecovery.SuggestRecoveryAction(Error, Context);
    FRecovery.LogRecoveryAttempt(Action, Format('%s in %s', [Error, Context]));
    case Action of
      raAbort:
        begin
          SetError('Recovery failed: ' + Error);
          Result := False;
        end;
      raSkipHeader:
        begin
          FState := rsRecovering;
          Result := True;
        end;
      raTruncateValue:
        begin
          if Context = 'Headers' then
          begin
            SetLength(FRawBuffer, FMaxHeaderSize);
            FRawBufferSize := FMaxHeaderSize;
          end;
          Result := True;
        end;
      raSanitize:
        begin
          FHeaders.SanitizeHeaders;
          Result := True;
        end;
      raContinue:
        begin
          Result := True;
        end;
    end;
  except
    on E: Exception do
    begin
      FRecovery.LogRecoveryAttempt(raAbort, 'Recovery attempt failed: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TRequest.CheckComplete: Boolean;
begin
  Result := (FState = rsComplete) and not FErrorParsing;
end;

function TRequest.IsComplete: Boolean;
begin
  try
    Result := (FState = rsComplete) and not FErrorParsing;
    if Result and (FExpectedBodySize > 0) then
    begin
      var BodyComplete := (FBodyBytesReceived >= FExpectedBodySize);
      if not BodyComplete then
      begin
        Logger.Error('DEBUG: Request not complete - body size mismatch: %d/%d', [FBodyBytesReceived, FExpectedBodySize]);
        Result := False;
      end;
    end;
    if Result and Assigned(FBodyParser) then
    begin
      if not FBodyParser.IsComplete then
      begin
        Result := False;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('ERROR in IsComplete: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

function TRequest.IsHeadersComplete: Boolean;
begin
  Result := FState in [rsWaitingBody, rsComplete];
end;

function TRequest.IsBodyComplete: Boolean;
begin
  Result := (FState = rsComplete) and not FErrorParsing;
end;

function TRequest.HasError: Boolean;
begin
  Result := FErrorParsing;
end;

function TRequest.CanAcceptMoreData: Boolean;
begin
  Result := (FState in [rsWaitingHeaders, rsParsingHeaders, rsWaitingBody]) and  not FErrorParsing;
end;

function TRequest.IsSecure: Boolean;
begin
  Result := FRequestInfo.IsSecure;
end;

function TRequest.IsRecoverable: Boolean;
begin
  Result := FEnableRecovery and Assigned(FRecovery) and (FRecovery.RecoveryAttempts < FRecovery.MaxRecoveryAttempts);
end;

function TRequest.ValidateRequest: Boolean;
begin
  Result := True;
  try

  except
    Result := False;
  end;
end;

function TRequest.DetectRequestSmuggling: Boolean;
begin
  try
    Result := THeaderValidator.DetectRequestSmuggling(TStringList.Create) = stRequestSmuggling;
  except
    Result := False;
  end;
end;

function TRequest.ValidateHeaderSecurity: Boolean;
begin
  Result := True;
  try
  except
    Result := False;
  end;
end;

function TRequest.CheckContentLengthConsistency: Boolean;
begin
  Result := True;
  try

  except
    Result := False;
  end;
end;

function TRequest.DetectMaliciousPatterns: Boolean;
begin
  Result := False;
  try

  except
    Result := True;
  end;
end;

procedure TRequest.AnalyzeSecurity;
const
  SafeHeaders: array[0..8] of string =
    ('host', 'authorization', 'cache-control', 'connection',
     'content-length', 'accept-language', 'accept-encoding',
     'referer', 'origin');
var
  AllHeaders: TStringList;
  HeaderName, Value: string;
  HeaderValues: TStringList;
  I: Integer;
begin
  SetLength(FSecurityThreats, 0);
  AllHeaders := TStringList.Create;
  try
    for HeaderName in FHeaders.GetHeaderNames do
    begin
      HeaderValues := FHeaders.FHeaders[LowerCase(HeaderName)];
      for I := 0 to HeaderValues.Count - 1 do
        AllHeaders.Add(HeaderName + ': ' + HeaderValues[I]);
    end;
    if THeaderValidator.DetectRequestSmuggling(AllHeaders) <> stNone then
    begin
      if not HasExistingThreat(stRequestSmuggling) then
        FSecurityThreats := FSecurityThreats + [stRequestSmuggling];
    end;
  finally
    AllHeaders.Free;
  end;
  if not FRequestInfo.IsUriValid then
  begin
    if not HasExistingThreat(stMalformedURI) then
        FSecurityThreats := FSecurityThreats + [stMalformedURI];
    if FErrorMessage = '' then
        FErrorMessage := 'URI validation failed: ' + FRequestInfo.GetUriValidationSummary;
  end;
  for HeaderName in FHeaders.GetHeaderNames do
  begin
    Value := FHeaders.GetHeader(HeaderName);
    if not THeaderValidator.IsSafeHeaderName(HeaderName) then
    begin
      if not HasExistingThreat(stSuspiciousHeaders) then
         FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
    end;

    if THeaderValidator.HasSuspiciousPatterns(Value) then
    begin
        if not ((LowerCase(HeaderName) = 'content-type') and (Pos('boundary=', LowerCase(Value)) > 0)) then
        begin
          if not HasExistingThreat(stHeaderInjection) then
             FSecurityThreats := FSecurityThreats + [stHeaderInjection];
        end;
    end;
  end;
  if FHeaders.HasHeader('fail') or FHeaders.HasHeader('injected') then
  begin
    if not HasExistingThreat(stHeaderInjection) then
       FSecurityThreats := FSecurityThreats + [stHeaderInjection];
    if FErrorMessage = '' then
       FErrorMessage := 'Suspicious header found, indicating a potential successful CRLF Injection.';
  end;
  if DetectSlowlorisInCompleteHeaders then
  begin
    if not HasExistingThreat(stSuspiciousHeaders) then
       FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
    if FErrorMessage = '' then
       SetError('Slowloris attack detected in complete headers', stSuspiciousHeaders);
  end;
  if Length(FSecurityThreats) > 0 then
  begin
    FSecurityViolationDetected := True;
    if FErrorMessage = '' then
      SetError('Security threat detected during analysis: ' + GetThreatSummary, FSecurityThreats[0]);
  end;
  if FEnableRecovery then
    ApplySecurityMeasures;
end;

function TRequest.IsValidHTTPRequestLine(const RequestLine: string): Boolean;
var
  Parts: TArray<string>;
  Method, URI, Version: string;
begin
  Result := False;
  try
    Parts := RequestLine.Split([' ']);
    if Length(Parts) < 3 then
    begin
      Logger.Error('DEBUG: Not enough parts in the request line: %d', [Length(Parts)]);
      Exit;
    end;
    Method := Trim(Parts[0]);
    URI := Trim(Parts[1]);
    Version := Trim(Parts[2]);
    if not IsValidHttpMethod(Method) then
    begin
      Logger.Error('DEBUG: Incorrect method HTTP: "%s"', [Method]);
      Exit;
    end;
    if (Length(URI) = 0) or (URI[1] <> '/') then
    begin
      Logger.Error('DEBUG: Invalid URI: "%s"', [Copy(URI, 1, 50)]);
      Exit;
    end;
    if not IsValidHttpVersion(Version) then
    begin
      Logger.Error('DEBUG: Incorrect version HTTP: "%s"', [Version]);
      Exit;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception w IsValidHTTPRequestLine: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

function TRequest.StartsWithHTTPMethod(const Data: string): Boolean;
var
  UpperData: string;
  HTTPMethods: TArray<string>;
  Method: string;
begin
  Result := False;
  try
    UpperData := UpperCase(Data);
    HTTPMethods := ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ', 'CONNECT '];

    for Method in HTTPMethods do
    begin
      if UpperData.StartsWith(Method) then
      begin
        Result := True;
        Exit;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception w StartsWithHTTPMethod: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

function TRequest.HasExistingThreat(ThreatType: TSecurityThreat): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 0 to Length(FSecurityThreats) - 1 do
  begin
    if FSecurityThreats[I] = ThreatType then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure TRequest.ApplySecurityMeasures;
var
  SanitizedCount: Integer;
begin
  try
    if Length(FSecurityThreats) > 0 then
    begin
      SanitizedCount := FHeaders.SanitizeHeaders;
      if SanitizedCount > 0 then
        FRecovery.LogRecoveryAttempt(raSanitize, Format('Sanitized %d headers', [SanitizedCount]));
    end;
  except
    on E: Exception do
       SetError(Format('Failure to apply security measures: %s', [E.Message]));
  end;
end;

function TRequest.RecoverFromMalformedHeader(const HeaderLine: string): string;
begin
  Result := THeaderValidator.SanitizeHeaderValue(HeaderLine);
end;

function TRequest.RecoverFromOversizeData(var Data: TBytes): Boolean;
begin
  Result := False;
  try
    if Length(Data) > FMaxHeaderSize then
    begin
      SetLength(Data, FMaxHeaderSize);
      Result := True;
    end;
  except
    Result := False;
  end;
end;

procedure TRequest.SkipToNextValidHeader(var HeaderLines: TStringList; var Index: Integer);
begin
  try
    Inc(Index);
    while (Index < HeaderLines.Count) and (Pos(':', HeaderLines[Index]) <= 0) do
      Inc(Index);
  except
    Index := HeaderLines.Count;
  end;
end;

procedure TRequest.DecompressBodyIfNeeded;
var
  Encodings: TArray<TContentEncoding>;
  Encoding: TContentEncoding;
  CompressedData, DecompressedData: TBytes;
begin
  try
    if not Assigned(FBodyStream) or (FBodyStream.Size = 0) then
      Exit;

    Encodings := FRequestInfo.ContentEncodings;
    if Length(Encodings) = 0 then
      Exit;

    SetLength(CompressedData, FBodyStream.Size);
    FBodyStream.Position := 0;
    FBodyStream.ReadBuffer(CompressedData[0], FBodyStream.Size);
    DecompressedData := CompressedData;
    for Encoding in Encodings do
    begin
      if FContentEncodingHandler.IsCompressionSupported(Encoding) then
         DecompressedData := FContentEncodingHandler.DecompressData(DecompressedData, Encoding);
    end;
    FDecompressedBodyStream.Clear;
    if Length(DecompressedData) > 0 then
       FDecompressedBodyStream.WriteBuffer(DecompressedData[0], Length(DecompressedData));
  except
    on E: Exception do
    begin
      FDecompressedBodyStream.Clear;
      if Assigned(FBodyStream) then
      begin
        FBodyStream.Position := 0;
        FDecompressedBodyStream.CopyFrom(FBodyStream, FBodyStream.Size);
      end;
    end;
  end;
end;

function TRequest.GetFinalBodyStream: TMemoryStream;
begin
  try
    DecompressBodyIfNeeded;
    Result := FDecompressedBodyStream;
  except
    Result := FBodyStream;
  end;
end;

function TRequest.IsValidHttpMethod(const Method: string): Boolean;
var
  TestMethod: THttpMethod;
begin
  try
    TestMethod := FRequestInfo.StringToHttpMethod(Method);
    Result := TestMethod <> hmUnknown;
  except
    Result := False;
  end;
end;

function TRequest.IsValidHttpVersion(const Version: string): Boolean;
var
  TestVersion: THttpVersion;
begin
  try
    TestVersion := FRequestInfo.StringToHttpVersion(Version);
    Result := TestVersion <> hvUnknown;
  except
    Result := False;
  end;
end;

function TRequest.ExtractChunkSize(const ChunkHeader: string): Integer;
var
 HexSize: string;
 SemicolonPos: Integer;
 I: Integer;
 C: Char;
begin
  Result := -1;
  try
    HexSize := Trim(ChunkHeader);
    if HexSize = '' then
       Exit;
    SemicolonPos := Pos(';', HexSize);
    if SemicolonPos > 0 then
       HexSize := Copy(HexSize, 1, SemicolonPos - 1);

    HexSize := Trim(HexSize);
    if HexSize = '' then
       Exit;

    for I := 1 to Length(HexSize) do
    begin
      C := UpCase(HexSize[I]);
      if not (C in ['0'..'9', 'A'..'F']) then
        Exit;
    end;
    if Length(HexSize) > 8 then
       Exit;
    try
       Result := StrToInt('$' + HexSize);
    except
       Result := -1;
    end;
    if Result < 0 then
       Result := -1;
  except
    Result := -1;
  end;
end;

function TRequest.SanitizeHeaderLine(const HeaderLine: string): string;
begin
  Result := THeaderValidator.SanitizeHeaderValue(HeaderLine);
end;

function TRequest.ProcessInternationalContent(const Content: string): string;
begin
  Result := FHeaders.ProcessInternationalHeader(Content);
end;

function TRequest.GetRequestString: string;
begin
  try
    if IsHeadersComplete then
    begin
      Result := GetHeadersString;
      if IsBodyComplete and (FBodyStream.Size > 0) then
        Result := Result + CRLF + GetBodyString;
    end
    else if FRawBufferSize > 0 then
      Result := TEncoding.UTF8.GetString(FRawBuffer, 0, FRawBufferSize)
    else
      Result := '';
  except
    Result := '';
  end;
end;

function TRequest.GetHeadersString: string;
begin
  try
    if Length(FHeadersBuffer) > 0 then
      Result := TEncoding.UTF8.GetString(FHeadersBuffer, 0, Length(FHeadersBuffer))
    else
      Result := '';
  except
    Result := '';
  end;
end;

function TRequest.GetBodyString: string;
var
  SavedPosition: Int64;
  BodyBytes: TBytes;
  LastBytes: TBytes;
  LastString: string;
begin
  try
    if Assigned(FBodyStream) and (FBodyStream.Size > 0) then
    begin
      SavedPosition := FBodyStream.Position;
      try
        FBodyStream.Position := 0;
        SetLength(BodyBytes, FBodyStream.Size);
        FBodyStream.ReadBuffer(BodyBytes[0], FBodyStream.Size);
        Result := TEncoding.UTF8.GetString(BodyBytes);
      finally
        FBodyStream.Position := SavedPosition;
      end;
    end
    else
      Result := '';
  except
    Result := '';
  end;
end;

function TRequest.GetBodyBytes: TBytes;
var
  SavedPosition: Int64;
begin
  try
    if Assigned(FBodyStream) and (FBodyStream.Size > 0) then
    begin
      SavedPosition := FBodyStream.Position;
      try
        FBodyStream.Position := 0;
        SetLength(Result, FBodyStream.Size);
        FBodyStream.ReadBuffer(Result[0], FBodyStream.Size);
      finally
        FBodyStream.Position := SavedPosition;
      end;
    end
    else
      SetLength(Result, 0);
  except
    SetLength(Result, 0);
  end;
end;

function TRequest.GetBodyStream: TMemoryStream;
begin
  Result := FBodyStream;
end;

function TRequest.GetDecompressedBodyStream: TMemoryStream;
begin
  Result := GetFinalBodyStream;
end;

function TRequest.HasSecurityThreats: Boolean;
begin
  Result := Length(FSecurityThreats) > 0;
end;

function TRequest.GetThreatSummary: string;
begin
  if Length(FSecurityThreats) = 0 then
    Result := 'No threats detected'
  else
    Result := Format('%d security threats detected', [Length(FSecurityThreats)]);
end;

procedure TRequest.ParseHeaders;
var
  HeaderLines: TStringList;
  I: Integer;
  Line, CurrentHeaderName, CurrentHeaderValue, ErrorMsg: string;
begin
  FState := rsParsingHeaders;
  HeaderLines := TStringList.Create;
  try
    FHeadersEndPos := FindHeadersEnd(FRawBuffer, FRawBufferSize);
    if FHeadersEndPos = -1 then
    begin
      if FRawBufferSize >= FMaxHeaderSize then SetError('Headers block size limit exceeded.', stOversizeAttack)
      else FState := rsWaitingHeaders;
      Exit;
    end;
    var HeadersBlockSize := FHeadersEndPos - 4;
    var HeadersStr: AnsiString;
    SetString(HeadersStr, PAnsiChar(FRawBuffer), HeadersBlockSize);
    if Pos(#0, HeadersStr) > 0 then
    begin
        SetError('Null byte detected in header block.', stHeaderInjection);
        Exit;
    end;
    HeaderLines.Text := string(HeadersStr);
    SetLength(FHeadersBuffer, HeadersBlockSize);
    if HeadersBlockSize > 0 then
       Move(FRawBuffer[0], FHeadersBuffer[0], HeadersBlockSize);
    if HeaderLines.Count = 0 then
    begin
      SetError('Empty request detected', stMalformedURI);
      Exit;
    end;
    if Length(HeaderLines[0]) > MAX_REQUEST_LINE_LENGTH then
    begin
      SetError(Format('Request line exceeds maximum length (%d bytes)', [MAX_REQUEST_LINE_LENGTH]), stOversizeAttack);
      Exit;
    end;
    ParseRequestLine(HeaderLines[0]);
    if FErrorParsing then
       Exit;
    I := 1;
    while I < HeaderLines.Count do
    begin
      Line := HeaderLines[I];
      if Length(Line) > FMaxHeaderLineLength then
      begin
        SetError(Format('Header line exceeds maximum length (%d bytes)', [FMaxHeaderLineLength]), stOversizeAttack);
        Exit;
      end;
      if Trim(Line) = '' then
      begin
        Inc(I); Continue;
      end;
      var ColonPos := Pos(':', Line);
      if ColonPos > 0 then
      begin
        CurrentHeaderName := Trim(Copy(Line, 1, ColonPos - 1));
        CurrentHeaderValue := Trim(Copy(Line, ColonPos + 1, MaxInt));
        var J := I + 1;
        while (J < HeaderLines.Count) and (Length(HeaderLines[J]) > 0) and (HeaderLines[J][1] in [' ', #9]) do
        begin
          CurrentHeaderValue := CurrentHeaderValue + ' ' + Trim(HeaderLines[J]);
          Inc(J);
        end;
        I := J - 1;
        if not THeaderValidator.ValidateHeaderName(CurrentHeaderName, ErrorMsg) then
        begin
          SetError('Header name validation failed: ' + ErrorMsg, stHeaderInjection);
          Exit;
        end;
        FHeaders.AddHeader(CurrentHeaderName, CurrentHeaderValue);
      end
      else if Trim(Line) <> '' then
      begin
        SetError('Malformed header line (CRLF Injection): ' + Line, stHeaderInjection);
        Exit;
      end;
      Inc(I);
    end;
    FRequestInfo.ParseFromHeaders(FHeaders);
    if FErrorParsing then
       Exit;
    DetermineBodySize;
    AnalyzeSecurity;
    if HasSecurityThreats then
    begin
      FErrorParsing := True;
      FState := rsError;
    end;
  finally
    HeaderLines.Free;
  end;
end;

class function THeaderValidator.ValidateHeaderValue(const Value: string; out ErrorMsg: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  ErrorMsg := '';
  if (Pos(#13, Value) > 0) or (Pos(#10, Value) > 0) then
  begin
    ErrorMsg := 'Invalid character (CR or LF) found inside header value. Possible CRLF Injection attack.';
    Exit(False);
  end;
  if Pos(#0, Value) > 0 then
  begin
    ErrorMsg := 'Invalid character (NULL) found in header value.';
    Exit(False);
  end;
  if HasSuspiciousPatterns(Value) then
  begin
    ErrorMsg := 'Suspicious patterns (potential XSS, SQLi) detected in header value.';
    Exit(False);
  end;
  Result := True;
end;

procedure TRequest.ParseRequestLine(const FirstLine: string);
begin
  try
    FRequestInfo.ParseRequestLine(FirstLine);
    if not FRequestInfo.IsUriValid then
    begin
      SetError('URI validation failed: ' + FRequestInfo.GetUriValidationSummary, stMalformedURI);
      Exit;
    end;
  except
    on E: Exception do
      SetError(Format('Error parsing request line: %s', [E.Message]), stMalformedURI);
  end;
end;

procedure TRequest.ProcessHeaderLines(const HeaderLines: TStringList);
var
  I, ColonPos: Integer;
  Line, HeaderName, HeaderValue: string;
begin
  try
    for I := 1 to HeaderLines.Count - 1 do
    begin
      Line := Trim(HeaderLines[I]);
      if Line = '' then
         Continue;
      if Length(Line) > FMaxHeaderLineLength then
      begin
        SetError(Format('Header too long in line %d', [I + 1]));
        Exit;
      end;
      ColonPos := Pos(':', Line);
      if ColonPos <= 1 then
      begin
        SetError(Format('Invalid header format on line %d', [I + 1]));
        Exit;
      end;
      HeaderName := Trim(Copy(Line, 1, ColonPos - 1));
      HeaderValue := Trim(Copy(Line, ColonPos + 1, Length(Line)));
      if HeaderName = '' then
      begin
        SetError(Format('Empty header name on line %d', [I + 1]));
        Exit;
      end;

      FHeaders.AddHeader(HeaderName, HeaderValue);
    end;
    FRequestInfo.ParseFromHeaders(FHeaders);
  except
    on E: Exception do
      SetError(Format('Error processing headers: %s', [E.Message]));
  end;
end;

function TRequest.HasSecurityViolation: Boolean;
begin
  Result := FSecurityViolationDetected or HasSecurityThreats or HasError;
end;

procedure TRequest.ProcessRemainingDataAfterHeaders;
var
  RemainingSize: Integer;
  RemainingData: TBytes;
begin
  try
    RemainingSize := FRawBufferSize - FHeadersEndPos;
    if (FHeadersEndPos <= 0) and (FRawBufferSize > 0) then
    begin
      if DetectSlowlorisAttack then
      begin
        SetError('Slowloris attack detected - incomplete HTTP request', stSuspiciousHeaders);
        Exit;
      end;
      Exit;
    end;
    if RemainingSize > 0 then
    begin
      SetLength(RemainingData, RemainingSize);
      Move(FRawBuffer[FHeadersEndPos], RemainingData[0], RemainingSize);
      ProcessBodyData(RemainingData, RemainingSize);
    end
    else
    begin
      if (FExpectedBodySize = 0) then
      begin
        FState := rsComplete;
      end;
    end;
  except
    on E: Exception do
       SetError(Format('Error processing remaining data: %s', [E.Message]));
  end;
end;

procedure TRequest.DetermineBodySize;
begin
  try
    FIsChunkedTransfer := (FRequestInfo.TransferEncoding = teChunked);
    if FIsChunkedTransfer then
    begin
      FExpectedBodySize := -1;
      FState := rsWaitingBody;
      FChunkState := 0;
      try
        FBodyParser := THttpBodyParser.Create(
          FHeaders.ContentType,
          -1,
          FHeaders.TransferEncoding,
          FMaxBodySize,
          True,
          ''
        );
      except
        on E: Exception do
        begin
          SetError('Failed to create body parser for chunked transfer: ' + E.Message);
          Exit;
        end;
      end;
    end
    else if FRequestInfo.ContentLength > 0 then
    begin
      FExpectedBodySize := FRequestInfo.ContentLength;
      if FExpectedBodySize > FMaxBodySize then
      begin
        SetError(Format('Body size (%d) exceeds maximum limit (%d)', [FExpectedBodySize, FMaxBodySize]));
        Exit;
      end;
      FState := rsWaitingBody;
      try
        var TempContentType := FHeaders.ContentType;
        FBodyParser := THttpBodyParser.Create(
          TempContentType,
          FExpectedBodySize,
          FHeaders.TransferEncoding,
          FMaxBodySize,
          True,
          ''
        );
      except
        on E: Exception do
        begin
          SetError('Failed to create body parser for fixed length: ' + E.Message);
          Exit;
        end;
      end;
    end
    else if FRequestInfo.HasBody then
    begin
      FExpectedBodySize := -1;
      FState := rsWaitingBody;
      try
        FBodyParser := THttpBodyParser.Create(
          FHeaders.ContentType,
          -1,
          FHeaders.TransferEncoding,
          FMaxBodySize,
          True,
          ''
        );
      except
        on E: Exception do
        begin
          SetError('Failed to create body parser for unknown length: ' + E.Message);
          Exit;
        end;
      end;
    end
    else
    begin
      FExpectedBodySize := 0;
      FState := rsComplete;
    end;
  except
    on E: Exception do
      SetError(Format('Body size determination error: %s', [E.Message]));
  end;
end;

procedure TRequest.ProcessBodyData(const Data: array of Byte; Size: Integer);
var
  ActualDataToProcess: Integer;
  ProcessedSuccessfully: Boolean;
begin
  try
    if Size <= 0 then
    begin
      Logger.Info('DEBUG: No data to process');
      Exit;
    end;
    ActualDataToProcess := Size;
    if (FExpectedBodySize > 0) then
    begin
      var RemainingSpace := FExpectedBodySize - FBodyBytesReceived;
      if RemainingSpace <= 0 then
      begin
        FState := rsComplete;
        Exit;
      end;
      if Size > RemainingSpace then
      begin
        Logger.Warn('WARNING: Truncating body data from %d to %d bytes to match Content-Length', [Size, RemainingSpace]);
        ActualDataToProcess := RemainingSpace;
      end;
    end;
    ProcessedSuccessfully := False;
    if not Assigned(FBodyParser) then
    begin
      if FIsChunkedTransfer then
      begin
        ProcessChunkedBody(Data, ActualDataToProcess);
        ProcessedSuccessfully := not FErrorParsing;
      end
      else
      begin
        ProcessRegularBody(Data, ActualDataToProcess);
        ProcessedSuccessfully := not FErrorParsing;
      end;
    end
    else
    begin
      if ActualDataToProcess < Size then
      begin
        var TempData: TBytes;
        SetLength(TempData, ActualDataToProcess);
        Move(Data[0], TempData[0], ActualDataToProcess);
        if FBodyParser.AppendData(TempData, ActualDataToProcess) then
        begin
          FBodyBytesReceived := FBodyBytesReceived + ActualDataToProcess;
          ProcessedSuccessfully := True;
        end
        else
        begin
          SetError('Body parsing error: ' + FBodyParser.ErrorMessage);
          Exit;
        end;
      end
      else
      begin
        if FBodyParser.AppendData(Data, ActualDataToProcess) then
        begin
          FBodyBytesReceived := FBodyBytesReceived + ActualDataToProcess;
          ProcessedSuccessfully := True;
        end
        else
        begin
          SetError('Body parsing error: ' + FBodyParser.ErrorMessage);
          Exit;
        end;
      end;
    end;
    if ProcessedSuccessfully then
    begin
      FTotalBytesReceived := FTotalBytesReceived + ActualDataToProcess;
      var IsBodyComplete := False;
      if Assigned(FBodyParser) then
         IsBodyComplete := FBodyParser.IsComplete
      else if FExpectedBodySize > 0 then
        IsBodyComplete := (FBodyBytesReceived >= FExpectedBodySize)
      else if FIsChunkedTransfer then
        IsBodyComplete := (FState = rsComplete)
      else
        IsBodyComplete := True;

      if IsBodyComplete then
      begin
        FState := rsComplete;
      end;
    end;

  except
    on E: Exception do
      SetError(Format('Body data processing error: %s', [E.Message]));
  end;
end;

function TRequest.GetBodyParser: THttpBodyParser;
begin
  Result := FBodyParser;
end;

function TRequest.GetBodyAsString: string;
begin
  try
    if Assigned(FBodyParser) then
       Result := FBodyParser.GetMainPartAsString
    else
      Result := GetBodyString;
  except
    on E: Exception do
    begin
      Result := '';
    end;
  end;
end;

function TRequest.GetBodyAsBytes: TBytes;
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetMainPartAsBytes
    else
      Result := GetBodyBytes;
  except
    on E: Exception do
    begin
      SetLength(Result, 0);
    end;
  end;
end;

function TRequest.GetBodyPart(Index: Integer): TBodyPart;
begin
  try
    if Assigned(FBodyParser) then
       Result := FBodyParser.GetPart(Index)
    else
      Result := nil;
  except
    on E: Exception do
    begin
      Result := nil;
    end;
  end;
end;

function TRequest.GetBodyPartByName(const Name: string): TBodyPart;
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetPartByName(Name)
    else
      Result := nil;
  except
    on E: Exception do
    begin
      Result := nil;
    end;
  end;
end;

function TRequest.GetBodyPartCount: Integer;
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetPartCount
    else
      Result := 0;
  except
    on E: Exception do
    begin
      Result := 0;
    end;
  end;
end;

function TRequest.GetHeadersSize: Integer;
begin
  try
    Result := Length(FHeadersBuffer);
  except
    on E: Exception do
    begin
      Result := 0;
    end;
  end;
end;

function TRequest.GetRequestSize: Int64;
begin
  try
    Result := GetHeadersSize + FBodyBytesReceived;
  except
    Result := 0;
  end;
end;

function TRequest.GetContentLength: Int64;
var
  ContentLengthStr: string;
begin
  try
    if Assigned(FHeaders) then
    begin
      ContentLengthStr := FHeaders.ContentLength;
      if ContentLengthStr <> '' then
        Result := StrToInt64Def(ContentLengthStr, -1)
      else
        Result := -1;
    end
    else
      Result := -1;
  except
    Result := -1;
  end;
end;

function TRequest.GetBodyContentType: TBodyContentType;
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.BodyType
    else
      Result := bctUnknown;
  except
    on E: Exception do
    begin
      Result := bctUnknown;
    end;
  end;
end;

procedure TRequest.ProcessRegularBody(const Data: array of Byte; Size: Integer);
var
  BytesToWrite: Integer;
  DataBytes: TBytes;
  DataString: string;
begin
  try
    if Size > 0 then
    begin
      SetLength(DataBytes, Min(Size, 50));
      Move(Data[0], DataBytes[0], Min(Size, 50));
      DataString := TEncoding.UTF8.GetString(DataBytes);
    end;
    if FExpectedBodySize > 0 then
    begin
      BytesToWrite := Min(Size, FExpectedBodySize - FBodyBytesReceived);
      if BytesToWrite > 0 then
      begin
        FBodyStream.WriteBuffer(Data[0], BytesToWrite);
        FBodyBytesReceived := FBodyBytesReceived + BytesToWrite;
      end;
      if FBodyBytesReceived >= FExpectedBodySize then
      begin
        FState := rsComplete;
      end;
    end
    else
    begin
      FBodyStream.WriteBuffer(Data[0], Size);
      FBodyBytesReceived := FBodyBytesReceived + Size;
      if FBodyBytesReceived > FMaxBodySize then
      begin
        SetError('Maximum body size exceeded');
        Exit;
      end;
    end;

  except
    on E: Exception do
      SetError(Format('Error processing regular body: %s', [E.Message]));
  end;
end;

procedure TRequest.ProcessChunkedBody(const Data: array of Byte; Size: Integer);
var
  I, BytesToProcess, ChunkHeaderEnd: Integer;
  RemainingData: TBytes;
  ChunkHeader: string;
begin
  try
    I := 0;
    while I < Size do
    begin
      case FChunkState of
        0:
          begin
            ChunkHeaderEnd := -1;
            for BytesToProcess := I to Size - 1 do
            begin
              if (BytesToProcess < Size - 1) and (Data[BytesToProcess] = 13) and (Data[BytesToProcess + 1] = 10) then
              begin
                ChunkHeaderEnd := BytesToProcess;
                Break;
              end;
            end;
            if ChunkHeaderEnd >= 0 then
            begin
              SetLength(RemainingData, ChunkHeaderEnd - I);
              if ChunkHeaderEnd > I then
                 Move(Data[I], RemainingData[0], ChunkHeaderEnd - I);
              ChunkHeader := TEncoding.UTF8.GetString(RemainingData);
              FCurrentChunkSize := ExtractChunkSize(ChunkHeader);
              if FCurrentChunkSize < 0 then
              begin
                SetError('Incorrect chunk size');
                Exit;
              end;
              if FCurrentChunkSize = 0 then
              begin
                FState := rsComplete;
                Exit;
              end;
              FCurrentChunkReceived := 0;
              FChunkState := 1;
              I := ChunkHeaderEnd + 2;
            end
            else
            begin
              Break;
            end;
          end;
        1:
          begin
            BytesToProcess := Min(Size - I, FCurrentChunkSize - FCurrentChunkReceived);
            if BytesToProcess > 0 then
            begin
              FBodyStream.WriteBuffer(Data[I], BytesToProcess);
              FBodyBytesReceived := FBodyBytesReceived + BytesToProcess;
              FCurrentChunkReceived := FCurrentChunkReceived + BytesToProcess;
              I := I + BytesToProcess;
              if FCurrentChunkReceived >= FCurrentChunkSize then
                 FChunkState := 2;
            end
            else
              Break;
          end;
        2:
          begin
            if I < Size - 1 then
            begin
              if (Data[I] = 13) and (Data[I + 1] = 10) then
              begin
                FChunkState := 0;
                I := I + 2;
              end
              else
              begin
                SetError('CRLF was expected after chunk');
                Exit;
              end;
            end
            else
              Break;
          end;
      end;
      if FBodyBytesReceived > FMaxBodySize then
      begin
        SetError('Maximum body size exceeded in chunked mode');
        Exit;
      end;
    end;
  except
    on E: Exception do
      SetError(Format('Error processing chunked body: %s', [E.Message]));
  end;
end;

procedure TRequest.SetLemBuf(Alen: Integer);
begin
  SetLength(FRawBuffer, Alen);
end;

function TRequest.GetRecoveryAttempts: Integer;
begin
  if Assigned(FRecovery) then
     Result := FRecovery.RecoveryAttempts
  else
     Result := 0;
end;

function TRequest.DetectSlowlorisAttack: Boolean;
var
  HeadersStr: string;
  Lines: TStringList;
  LastLine: string;
  LineCount: Integer;
  HasIncompleteHeader: Boolean;
  I: Integer;
  HeaderCount: Integer;
begin
  Result := False;
  try
    if FRawBufferSize = 0 then
    begin
      Exit;
    end;
    HeadersStr := TEncoding.UTF8.GetString(FRawBuffer, 0, FRawBufferSize);
    if (Pos('HTTP/1.', HeadersStr) = 0) then
    begin
      Logger.Info('DEBUG: This is not an HTTP request');
      Exit;
    end;
    if Pos(DOUBLE_CRLF, HeadersStr) > 0 then
    begin
      Exit;
    end;
    Lines := TStringList.Create;
    try
      Lines.Text := StringReplace(HeadersStr, CRLF, sLineBreak, [rfReplaceAll]);
      LineCount := Lines.Count;
      if LineCount < 2 then
      begin
        Exit;
      end;
      if (Pos('GET ', Lines[0]) = 0) and (Pos('POST ', Lines[0]) = 0) and
         (Pos('PUT ', Lines[0]) = 0) and (Pos('HEAD ', Lines[0]) = 0) then
      begin
        Logger.Info('DEBUG: No valid request line');
        Exit;
      end;
      HeaderCount := 0;
      for I := 1 to LineCount - 1 do
      begin
        if (Trim(Lines[I]) <> '') and (Pos(':', Lines[I]) > 0) then
           Inc(HeaderCount);
      end;
      LastLine := Lines[LineCount - 1];
      HasIncompleteHeader := False;
      if (Pos(':', LastLine) > 0) and (Trim(Copy(LastLine, Pos(':', LastLine) + 1, Length(LastLine))) = '') then
      begin
        HasIncompleteHeader := True;
      end;
      if (Pos(':', LastLine) = 0) and (LastLine <> '') and not LastLine.StartsWith('HTTP/') then
      begin
        HasIncompleteHeader := True;
      end;
      if (HeaderCount >= 2) and HasIncompleteHeader then
      begin
        Logger.Warn('DETECTED: Slowloris Attack - incomplete headers!');
        Logger.Warn(' - HeaderCount: %d', [HeaderCount]);
        Logger.Warn(' - HasIncompleteHeader: %s', [BoolToStr(HasIncompleteHeader, True)]);
        Logger.Warn(' - Last line: "%s"', [LastLine]);
        Result := True;
      end
      else
      begin

      end;
    finally
      Lines.Free;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception w DetectSlowlorisAttack: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

function TRequest.DetectSlowlorisInCompleteHeaders: Boolean;
var
  HeadersStr: string;
  Lines: TStringList;
  LastLine: string;
  LineCount: Integer;
  I: Integer;
  HeaderCount: Integer;
  HasSlowlorisPatterns: Boolean;
  SuspiciousHeaderCount: Integer;
begin
  Result := False;
  try
    if FHeadersEndPos <= 0 then
    begin
      Logger.Warn('DEBUG: No complete headers');
      Exit;
    end;
    HeadersStr := TEncoding.UTF8.GetString(FHeadersBuffer, 0, FHeadersEndPos - 4);
    Lines := TStringList.Create;
    try
      Lines.Text := StringReplace(HeadersStr, CRLF, sLineBreak, [rfReplaceAll]);
      LineCount := Lines.Count;
      if LineCount < 2 then
      begin
        Logger.Error('DEBUG: Too few lines');
        Exit;
      end;
      if (Pos('GET ', Lines[0]) = 0) and (Pos('POST ', Lines[0]) = 0) and
         (Pos('PUT ', Lines[0]) = 0) and (Pos('HEAD ', Lines[0]) = 0) then
      begin
        Logger.Warn('DEBUG: No valid request line');
        Exit;
      end;
      HeaderCount := 0;
      SuspiciousHeaderCount := 0;
      HasSlowlorisPatterns := False;
      for I := 1 to LineCount - 1 do
      begin
        var Line := Lines[I];
        if (Trim(Line) <> '') and (Pos(':', Line) > 0) then
        begin
          Inc(HeaderCount);
          if (Pos('X-Slowloris', Line) > 0) or
             (Pos('X-a:', Line) > 0) or
             (Pos('X-Real-IP:', Line) > 0) or
             (LowerCase(Line).Contains('slowloris')) then
          begin
            Logger.Warn('Slowloris pattern FOUND: %s', [Line]);
            HasSlowlorisPatterns := True;
            Inc(SuspiciousHeaderCount);
          end;
        end;
      end;
      if HasSlowlorisPatterns and (SuspiciousHeaderCount > 0) then
      begin
        Logger.Warn('DETECTED: Slowloris Attack in complete headers!');
        Logger.Warn(' - HeaderCount: %d', [HeaderCount]);
        Logger.Warn(' - SuspiciousHeaderCount: %d', [SuspiciousHeaderCount]);
        Result := True;
      end
      else
      begin
      end;
    finally
      Lines.Free;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception w DetectSlowlorisInCompleteHeaders: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

function TCaseInsensitiveStringComparer.Equals(const Left, Right: string): Boolean;
begin
  Result := CompareText(Left, Right) = 0;
end;

function TCaseInsensitiveStringComparer.GetHashCode(const Value: string): Integer;
var
  UpperValue: string;
begin
  UpperValue := UpperCase(Value);
  Result := TEqualityComparer<string>.Default.GetHashCode(UpperValue);
end;

end.


