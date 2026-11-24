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

unit GRequest;

interface

uses
  GLogger, System.SysUtils, System.Classes, System.Threading, System.SyncObjs,
  System.Generics.Collections, System.Math, System.StrUtils, System.Character,
  Winapi.Windows, Winapi.WinSock2,
  System.NetEncoding, GRequestBody, System.Generics.Defaults, System.ZLib,
  GRequestTypes, GRequestUriValidator, GRequestHeaderValidator,
  GRequestEncodingAndRecovery, GRequestHeaders, GRequestInfo,
  GRequestHeaderFastParser;

type
  TGClientCertInfo = GRequestTypes.TGClientCertInfo;
  TClientCertValidateEvent = GRequestTypes.TClientCertValidateEvent;
  TCaseInsensitiveStringComparer = GRequestTypes.TCaseInsensitiveStringComparer;
  THttpMethod = GRequestTypes.THttpMethod;
  THttpVersion = GRequestTypes.THttpVersion;
  TRequestState = GRequestTypes.TRequestState;
  TTransferEncoding = GRequestTypes.TTransferEncoding;
  TConnectionType = GRequestTypes.TConnectionType;
  TSecurityThreat = GRequestTypes.TSecurityThreat;
  TRecoveryAction = GRequestTypes.TRecoveryAction;
  TValidationLevel = GRequestTypes.TValidationLevel;
  TUriValidator = GRequestUriValidator.TUriValidator;
  THeaderValidator = GRequestHeaderValidator.THeaderValidator;
  TContentEncodingHandler = GRequestEncodingAndRecovery.TContentEncodingHandler;
  TRequestRecovery = GRequestEncodingAndRecovery.TRequestRecovery;
  THttpHeaders = GRequestHeaders.THttpHeaders;
  THttpRequestInfo = GRequestInfo.THttpRequestInfo;

const
  hmUnknown = GRequestTypes.hmUnknown;
  hmGET = GRequestTypes.hmGET;
  hmPOST = GRequestTypes.hmPOST;
  hmPUT = GRequestTypes.hmPUT;
  hmDELETE = GRequestTypes.hmDELETE;
  hmHEAD = GRequestTypes.hmHEAD;
  hmOPTIONS = GRequestTypes.hmOPTIONS;
  hmPATCH = GRequestTypes.hmPATCH;
  hmTRACE = GRequestTypes.hmTRACE;
  hmCONNECT = GRequestTypes.hmCONNECT;

  hvUnknown = GRequestTypes.hvUnknown;
  hvHTTP10 = GRequestTypes.hvHTTP10;
  hvHTTP11 = GRequestTypes.hvHTTP11;
  hvHTTP20 = GRequestTypes.hvHTTP20;

  rsWaitingHeaders = GRequestTypes.rsWaitingHeaders;
  rsParsingHeaders = GRequestTypes.rsParsingHeaders;
  rsWaitingBody = GRequestTypes.rsWaitingBody;
  rsComplete = GRequestTypes.rsComplete;
  rsError = GRequestTypes.rsError;
  rsRecovering = GRequestTypes.rsRecovering;

  teNone = GRequestTypes.teNone;
  teChunked = GRequestTypes.teChunked;
  teCompress = GRequestTypes.teCompress;
  teDeflate = GRequestTypes.teDeflate;
  teGzip = GRequestTypes.teGzip;
  teIdentity = GRequestTypes.teIdentity;

  ctKeepAlive = GRequestTypes.ctKeepAlive;
  ctClose = GRequestTypes.ctClose;
  ctUpgrade = GRequestTypes.ctUpgrade;

  stNone = GRequestTypes.stNone;
  stRequestSmuggling = GRequestTypes.stRequestSmuggling;
  stHeaderInjection = GRequestTypes.stHeaderInjection;
  stOversizeAttack = GRequestTypes.stOversizeAttack;
  stMalformedURI = GRequestTypes.stMalformedURI;
  stInvalidEncoding = GRequestTypes.stInvalidEncoding;
  stSuspiciousHeaders = GRequestTypes.stSuspiciousHeaders;

  raAbort = GRequestTypes.raAbort;
  raSkipHeader = GRequestTypes.raSkipHeader;
  raTruncateValue = GRequestTypes.raTruncateValue;
  raSanitize = GRequestTypes.raSanitize;
  raContinue = GRequestTypes.raContinue;

  vlStrict = GRequestTypes.vlStrict;
  vlModerate = GRequestTypes.vlModerate;
  vlPermissive = GRequestTypes.vlPermissive;

type
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
    FAllowedFileExtensions: TStringList;
    FBlockedMimeTypes: TStringList;
    FClientCertInfo: TGClientCertInfo;
    FPrevUri: string;
    FPrevHeaderSlots: array[0..7] of string;
    procedure ConfigureBodyParserSecurity;
    function GetHeadersSize: Integer;
    function HasExistingThreat(ThreatType: TSecurityThreat): Boolean;
    procedure InitializeBuffers;
    procedure ClearBuffers;
    function FindHeadersEnd(const Buffer: TBytes; Size: Integer): Integer;
    procedure ParseRequestLine(const FirstLine: string);
    procedure ProcessRemainingDataAfterHeaders;
    procedure DetermineBodySize;
    procedure ProcessBodyData(const Data: array of Byte; Size: Integer);
    procedure ProcessChunkedBody(const Data: array of Byte; Size: Integer);
    procedure ProcessRegularBody(const Data: array of Byte; Size: Integer);
    procedure AnalyzeSecurity;
    procedure ApplySecurityMeasures;
    procedure DecompressBodyIfNeeded;
    function GetFinalBodyStream: TMemoryStream;
    procedure SetError(const ErrorMsg: string; Threat: TSecurityThreat = stNone);
    function IsValidHttpMethod(const Method: string): Boolean;
    function IsValidHttpVersion(const Version: string): Boolean;
    function ExtractChunkSize(const ChunkHeader: string): Integer;
    function DetectSlowlorisAttack: Boolean;
    function FindHeadersEndPtr(DataPtr: PByte; Size: Integer): Integer;
    function ParseHeadersFromPtr(DataPtr: PByte; HeadersEndPos: Integer): Boolean;
  protected
    function StartsWithHTTPMethod(const Data: string): Boolean;
    function IsValidHTTPRequestLine(const RequestLine: string): Boolean;
    procedure ProcessHeaderLines(const HeaderLines: TStringList);
    function AttemptRecovery(const Error: string; const Context: string): Boolean;
    function RecoverFromMalformedHeader(const HeaderLine: string): string;
    function RecoverFromOversizeData(var Data: TBytes): Boolean;
    procedure SkipToNextValidHeader(var HeaderLines: TStringList; var Index: Integer);
    function SanitizeHeaderLine(const HeaderLine: string): string;
    function ProcessInternationalContent(const Content: string): string;
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
    procedure AppendDataPtr(DataPtr: PByte; Size: Integer);
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
    property HeadersEndPos: Integer read FHeadersEndPos;
    property IsChunkedTransfer: Boolean read FIsChunkedTransfer;
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
    property AllowedFileExtensions: TStringList read FAllowedFileExtensions;
    property BlockedMimeTypes: TStringList read FBlockedMimeTypes;
    property RawBuffer: TBytes read FRawBuffer;
    property RawBufferSize: Integer read FRawBufferSize write FRawBufferSize;
    property ClientCertificate: TGClientCertInfo read FClientCertInfo write FClientCertInfo;
    function IsComplete: Boolean;
    function IsHeadersComplete: Boolean;
    function IsBodyComplete: Boolean;
    function HasError: Boolean;
    function CanAcceptMoreData: Boolean;
    function IsKeepAlive: Boolean;
    function IsSecure: Boolean;
    function IsRecoverable: Boolean;
  end;

function IsHexDigit(c: Char): Boolean;

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
  Result := GRequestTypes.IsHexDigit(c);
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
    FAllowedFileExtensions := TStringList.Create;
    FBlockedMimeTypes := TStringList.Create;
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
        FreeAndNil(FAllowedFileExtensions);
        FreeAndNil(FBlockedMimeTypes);
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
    FreeAndNil(FAllowedFileExtensions);
    FreeAndNil(FBlockedMimeTypes);
    FreeAndNil(FBodyStream);
    FreeAndNil(FDecompressedBodyStream);
    FreeAndNil(FBodyParser);
  finally
    inherited Destroy;
  end;
end;

procedure TRequest.InitializeBuffers;
var
  InitSize: Integer;
begin
  try
    InitSize := Min(4096, FMaxHeaderSize);
    if Length(FRawBuffer) < InitSize then
      SetLength(FRawBuffer, InitSize);
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
    FRawBufferSize := 0;
    if Length(FRawBuffer) > 16384 then
      SetLength(FRawBuffer, Min(4096, FMaxHeaderSize));
    if Length(FHeadersBuffer) > 0 then
      SetLength(FHeadersBuffer, 0);
    if Assigned(FBodyStream) and (FBodyStream.Size > 0) then
    begin
      FBodyStream.Clear;
      FBodyStream.Size := 0;
    end;
    if Assigned(FDecompressedBodyStream) and (FDecompressedBodyStream.Size > 0) then
    begin
      FDecompressedBodyStream.Clear;
      FDecompressedBodyStream.Size := 0;
    end;
    FillChar(FClientCertInfo, SizeOf(FClientCertInfo), 0);
    if Assigned(FHeaders) then
       FHeaders.Clear;
    if Assigned(FRequestInfo) then
       FRequestInfo.Clear;
    if Assigned(FRecovery) then
       FRecovery.Clear;
    if Assigned(FBodyParser) then
      FreeAndNil(FBodyParser);
    FState := rsWaitingHeaders;
    FHeadersSize := 0;
    FErrorParsing := False;
    FErrorMessage := '';
    if Length(FSecurityThreats) > 0 then
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
    if Length(FRawBuffer) = 0 then
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
  OldLen: Integer;
  ThreatsStr: string;
begin
  FErrorParsing := True;
  FErrorMessage := ErrorMsg;
  FState := rsError;
  if (Threat <> stNone) or (Pos('injection', LowerCase(ErrorMsg)) > 0) or (Pos('attack', LowerCase(ErrorMsg)) > 0) then
    FSecurityViolationDetected := True;

  if Threat <> stNone then
  begin
    if not HasExistingThreat(Threat) then
    begin
      OldLen := Length(FSecurityThreats);
      SetLength(FSecurityThreats, OldLen + 1);
      FSecurityThreats[OldLen] := Threat;
    end;
  end;
  ThreatsStr := '';
  for i := 0 to Length(FSecurityThreats) - 1 do
     ThreatsStr := ThreatsStr + IntToStr(Ord(FSecurityThreats[i])) + ' ';
end;

function TRequest.FindHeadersEnd(const Buffer: TBytes; Size: Integer): Integer;
var
  I: Integer;
  J: Integer;
  Limit8: Integer;
  P: PByte;
  Word64: UInt64;
  XorCR: UInt64;
  HasCR: UInt64;
begin
  Result := -1;
  if Size < 4 then
    Exit;

  P := @Buffer[0];
  I := 0;
  Limit8 := Size - 11;
  while I <= Limit8 do
  begin
    Word64 := PUInt64(P + I)^;
    XorCR := Word64 xor UInt64($0D0D0D0D0D0D0D0D);
    HasCR := (XorCR - UInt64($0101010101010101)) and (not XorCR) and UInt64($8080808080808080);
    if HasCR <> 0 then
    begin
      for J := I to I + 7 do
      begin
        if PCardinal(P + J)^ = $0A0D0A0D then
        begin
          Result := J + 4;
          Exit;
        end;
      end;
    end;
    Inc(I, 8);
  end;
  while I <= Size - 4 do
  begin
    if PCardinal(P + I)^ = $0A0D0A0D then
    begin
      Result := I + 4;
      Exit;
    end;
    Inc(I);
  end;
end;

procedure TRequest.AppendData(const Data: array of Byte; Size: Integer);
begin
  if FErrorParsing or (FState = rsComplete) then
    Exit;

  if Size <= 0 then
  begin
    if FTotalBytesReceived = 0 then
      SetError('Empty request detected', stMalformedURI);
    Exit;
  end;

  if FState = rsWaitingBody then
  begin
    try
      if FTotalBytesReceived + Size > FMaxHeaderSize + FMaxBodySize then
      begin
        SetError('Total request size exceeds maximum limit', stOversizeAttack);
        Exit;
      end;
      FTotalBytesReceived := FTotalBytesReceived + Size;
      ProcessBodyData(Data, Size);
    except
      on E: Exception do
        SetError(Format('Exception while appending data: %s', [E.Message]));
    end;
    Exit;
  end;

  if Length(Data) > 0 then
    AppendDataPtr(@Data[0], Size)
  else
    AppendDataPtr(nil, 0);
end;

procedure TRequest.AppendDataPtr(DataPtr: PByte; Size: Integer);
var
  NewSize: Integer;
  TempBody: TBytes;
begin
  if FErrorParsing or (FState = rsComplete) then
    Exit;

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
          if (FState = rsWaitingHeaders) and (FRawBufferSize = 0) then
          begin
            FHeadersEndPos := FindHeadersEndPtr(DataPtr, Size);
            if FHeadersEndPos > 0 then
            begin
              if FHeadersEndPos > FMaxHeaderSize then
              begin
                SetError(Format('Headers size exceeds maximum limit (%d bytes)', [FMaxHeaderSize]), stOversizeAttack);
                Exit;
              end;
              FState := rsParsingHeaders;
              if ParseHeadersFromPtr(DataPtr, FHeadersEndPos) then
              begin
                FTotalBytesReceived := FTotalBytesReceived + Size;
                if not FErrorParsing then
                begin
                  if (FExpectedBodySize = 0) and (not FIsChunkedTransfer) then
                    FState := rsComplete
                  else
                  begin
                    if Size > FHeadersEndPos then
                    begin
                      NewSize := Size - FHeadersEndPos;
                      if NewSize > Length(FRawBuffer) then
                        SetLength(FRawBuffer, NewSize);
                      Move(DataPtr[FHeadersEndPos], FRawBuffer[0], NewSize);
                      FRawBufferSize := NewSize;
                      SetLength(TempBody, NewSize);
                      Move(FRawBuffer[0], TempBody[0], NewSize);
                      ProcessBodyData(TempBody, NewSize);
                    end
                    else
                      FState := rsWaitingBody;
                  end;
                end;
                Exit;
              end;
            end;
          end;
          NewSize := FRawBufferSize + Size;
          if NewSize > Length(FRawBuffer) then
            SetLength(FRawBuffer, NewSize);
          Move(DataPtr^, FRawBuffer[FRawBufferSize], Size);
          FRawBufferSize := NewSize;
          FTotalBytesReceived := FTotalBytesReceived + Size;
          FHeadersEndPos := FindHeadersEnd(FRawBuffer, FRawBufferSize);
          if FHeadersEndPos > 0 then
          begin
            if FHeadersEndPos > FMaxHeaderSize then
            begin
              SetError(Format('Headers size exceeds maximum limit (%d bytes)', [FMaxHeaderSize]), stOversizeAttack);
              Exit;
            end;
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
        begin
          FTotalBytesReceived := FTotalBytesReceived + Size;
          SetLength(TempBody, Size);
          Move(DataPtr^, TempBody[0], Size);
          ProcessBodyData(TempBody, Size);
        end;
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
var
  BodyComplete: Boolean;
begin
  try
    Result := (FState = rsComplete) and not FErrorParsing;
    if Result and (FExpectedBodySize > 0) then
    begin
      BodyComplete := (FBodyBytesReceived >= FExpectedBodySize);
      if not BodyComplete then
      begin
        Logger.Error('DEBUG: Request not complete - body size mismatch: %d/%d', [FBodyBytesReceived, FExpectedBodySize]);
        Result := False;
      end;
    end;
    if Result and Assigned(FBodyParser) then
    begin
      if not FBodyParser.IsComplete then
        Result := False;
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
  Result := (FState in [rsWaitingHeaders, rsParsingHeaders, rsWaitingBody]) and not FErrorParsing;
end;

function TRequest.IsSecure: Boolean;
begin
  Result := FRequestInfo.IsSecure;
end;

function TRequest.IsRecoverable: Boolean;
begin
  Result := FEnableRecovery and Assigned(FRecovery) and (FRecovery.RecoveryAttempts < FRecovery.MaxRecoveryAttempts);
end;

procedure TRequest.AnalyzeSecurity;
var
  Pair: TPair<string, TStringList>;
  LowerKey: string;
  Value: string;
  Values: TStringList;
  I: Integer;
  HostCount: Integer;
  ContentLengthCount: Integer;
  TransferEncodingCount: Integer;
  HasContentLength: Boolean;
  HasChunked: Boolean;
begin
  if Length(FSecurityThreats) > 0 then
    SetLength(FSecurityThreats, 0);

  HostCount := 0;
  ContentLengthCount := 0;
  TransferEncodingCount := 0;
  HasContentLength := False;
  HasChunked := False;

  if not FHeaders.UseDict then
  begin
    if FHeaders.SlotCount > FMaxHeaderCount then
    begin
      if not HasExistingThreat(stOversizeAttack) then
        FSecurityThreats := FSecurityThreats + [stOversizeAttack];
      if FErrorMessage = '' then
        FErrorMessage := Format('Too many headers: %d exceeds maximum of %d', [FHeaders.SlotCount, FMaxHeaderCount]);
    end;
    for I := 0 to FHeaders.SlotCount - 1 do
    begin
      LowerKey := FHeaders.GetSlotName(I);
      Value := FHeaders.GetSlotValue(I);
      if LowerKey = 'host' then
        Inc(HostCount)
      else if LowerKey = 'content-length' then
      begin
        Inc(ContentLengthCount);
        HasContentLength := True;
      end
      else if LowerKey = 'transfer-encoding' then
      begin
        Inc(TransferEncodingCount);
        if FastContainsAsciiCI(Value, 'chunked') then
        begin
          HasChunked := True;
          if Pos(',', Value) > 0 then
          begin
            if not HasExistingThreat(stRequestSmuggling) then
              FSecurityThreats := FSecurityThreats + [stRequestSmuggling];
          end;
        end;
      end;

      if (LowerKey <> 'host') and (LowerKey <> 'user-agent') and (LowerKey <> 'accept') and
         (LowerKey <> 'connection') and (LowerKey <> 'content-length') and (LowerKey <> 'content-type') and
         (LowerKey <> 'accept-encoding') and (not THeaderValidator.IsSafeHeaderName(LowerKey)) then
      begin
        if not HasExistingThreat(stSuspiciousHeaders) then
          FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
      end;

      if (LowerKey = 'x-slowloris') or (LowerKey = 'x-a') or ((Length(LowerKey) >= 9) and (Pos('slowloris', LowerKey) > 0)) then
      begin
        if not HasExistingThreat(stSuspiciousHeaders) then
          FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
        if FErrorMessage = '' then
          SetError('Slowloris attack detected in complete headers', stSuspiciousHeaders);
      end;

      if (LowerKey <> 'authorization') and THeaderValidator.HasSuspiciousPatterns(Value) then
      begin
        if not ((LowerKey = 'content-type') and FastContainsAsciiCI(Value, 'boundary=')) then
        begin
          if not HasExistingThreat(stHeaderInjection) then
            FSecurityThreats := FSecurityThreats + [stHeaderInjection];
        end;
      end;
      if (Length(Value) >= 9) and FastContainsAsciiCI(Value, 'slowloris') then
      begin
        if not HasExistingThreat(stSuspiciousHeaders) then
          FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
        if FErrorMessage = '' then
          SetError('Slowloris attack detected in complete headers', stSuspiciousHeaders);
      end;
    end;
  end
  else
  begin
    if FHeaders.Headers.Count > FMaxHeaderCount then
    begin
      if not HasExistingThreat(stOversizeAttack) then
        FSecurityThreats := FSecurityThreats + [stOversizeAttack];
      if FErrorMessage = '' then
        FErrorMessage := Format('Too many headers: %d exceeds maximum of %d', [FHeaders.Headers.Count, FMaxHeaderCount]);
    end;

    for Pair in FHeaders.Headers do
    begin
      LowerKey := Pair.Key;
      Values := Pair.Value;

      if LowerKey = 'host' then
        HostCount := HostCount + Values.Count
      else if LowerKey = 'content-length' then
      begin
        ContentLengthCount := ContentLengthCount + Values.Count;
        HasContentLength := True;
      end
      else if LowerKey = 'transfer-encoding' then
      begin
        for I := 0 to Values.Count - 1 do
        begin
          Inc(TransferEncodingCount);
          Value := Values[I];
          if FastContainsAsciiCI(Value, 'chunked') then
          begin
            HasChunked := True;
            if Pos(',', Value) > 0 then
            begin
              if not HasExistingThreat(stRequestSmuggling) then
                FSecurityThreats := FSecurityThreats + [stRequestSmuggling];
            end;
          end;
        end;
      end;

      if not THeaderValidator.IsSafeHeaderName(LowerKey) then
      begin
        if not HasExistingThreat(stSuspiciousHeaders) then
          FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
      end;

      if (LowerKey = 'x-slowloris') or (LowerKey = 'x-a') or (Pos('slowloris', LowerKey) > 0) then
      begin
        if not HasExistingThreat(stSuspiciousHeaders) then
          FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
        if FErrorMessage = '' then
          SetError('Slowloris attack detected in complete headers', stSuspiciousHeaders);
      end;

      for I := 0 to Values.Count - 1 do
      begin
        Value := Values[I];
        if (LowerKey <> 'authorization') and THeaderValidator.HasSuspiciousPatterns(Value) then
        begin
          if not ((LowerKey = 'content-type') and FastContainsAsciiCI(Value, 'boundary=')) then
          begin
            if not HasExistingThreat(stHeaderInjection) then
              FSecurityThreats := FSecurityThreats + [stHeaderInjection];
          end;
        end;
        if FastContainsAsciiCI(Value, 'slowloris') then
        begin
          if not HasExistingThreat(stSuspiciousHeaders) then
            FSecurityThreats := FSecurityThreats + [stSuspiciousHeaders];
          if FErrorMessage = '' then
            SetError('Slowloris attack detected in complete headers', stSuspiciousHeaders);
        end;
      end;
    end;
  end;

  if (HostCount > 1) or (ContentLengthCount > 1) or (TransferEncodingCount > 1) or (HasContentLength and HasChunked) then
  begin
    if not HasExistingThreat(stRequestSmuggling) then
      FSecurityThreats := FSecurityThreats + [stRequestSmuggling];
  end;

  if not FRequestInfo.IsUriValid then
  begin
    if not HasExistingThreat(stMalformedURI) then
      FSecurityThreats := FSecurityThreats + [stMalformedURI];
    if FErrorMessage = '' then
      FErrorMessage := 'URI validation failed: ' + FRequestInfo.GetUriValidationSummary;
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
  Sp1: Integer;
  Sp2: Integer;
  Len: Integer;
  Method: string;
  URI: string;
  Version: string;
begin
  Result := False;
  try
    Len := Length(RequestLine);
    Sp1 := Pos(' ', RequestLine);
    if Sp1 <= 1 then
    begin
      Logger.Error('DEBUG: Not enough parts in the request line: %s', [RequestLine]);
      Exit;
    end;
    Sp2 := Pos(' ', RequestLine, Sp1 + 1);
    if Sp2 <= Sp1 + 1 then
    begin
      Logger.Error('DEBUG: Not enough parts in the request line: %s', [RequestLine]);
      Exit;
    end;
    Method := Trim(Copy(RequestLine, 1, Sp1 - 1));
    URI := Trim(Copy(RequestLine, Sp1 + 1, Sp2 - Sp1 - 1));
    Version := Trim(Copy(RequestLine, Sp2 + 1, Len - Sp2));
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
      if not CharInSet(C, ['0'..'9', 'A'..'F']) then
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
    if FHeadersEndPos >= 4 then
      Result := TEncoding.UTF8.GetString(FRawBuffer, 0, FHeadersEndPos - 4)
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
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetMainPartAsString
    else if Assigned(FBodyStream) and (FBodyStream.Size > 0) then
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
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetMainPartAsBytes
    else if Assigned(FBodyStream) and (FBodyStream.Size > 0) then
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

function TRequest.FindHeadersEndPtr(DataPtr: PByte; Size: Integer): Integer;
var
  I: Integer;
begin
  Result := -1;
  if (Size < 4) or (DataPtr = nil) then
    Exit;
  for I := 0 to Size - 4 do
  begin
    if PCardinal(DataPtr + I)^ = $0A0D0A0D then
    begin
      Result := I + 4;
      Exit;
    end;
  end;
end;

function TRequest.ParseHeadersFromPtr(DataPtr: PByte; HeadersEndPos: Integer): Boolean;
var
  HeadersBlockSize: Integer;
  PosIdx, LineStart, LineEnd, LineLen, NextPos, ColonPos: Integer;
  NameStart, NameEnd, ValStart, ValEnd, ValLen, I: Integer;
  IsFirstLine, HasNonSpace, IsKnownHeader, NeedFullSecurityAnalyze, HasContentEncoding: Boolean;
  HeaderCount, HostCount, ContentLengthCount, TransferEncodingCount: Integer;
  ContentLengthVal, ParsedCL: Int64;
  ConnType, FastConnType: TConnectionType;
  FastEncodings: TArray<TContentEncoding>;
  B: Byte;
  Line, CurrentHeaderName, CurrentHeaderValue, ErrorMsg: string;
begin
  HeadersBlockSize := HeadersEndPos - 4;
  if HeadersBlockSize <= 0 then
  begin
    SetError('Empty request detected', stMalformedURI);
    Exit(True);
  end;

  for I := 0 to HeadersBlockSize - 1 do
  begin
    B := DataPtr[I];
    if B = 0 then
    begin
      SetError('Null byte detected in header block.', stHeaderInjection);
      Exit(True);
    end;
    if B >= $80 then
      Exit(False);
  end;

  PosIdx := 0;
  IsFirstLine := True;
  HeaderCount := 0;
  HostCount := 0;
  ContentLengthCount := 0;
  TransferEncodingCount := 0;
  ContentLengthVal := -1;
  HasContentEncoding := False;
  NeedFullSecurityAnalyze := False;
  ConnType := ctKeepAlive;
  while PosIdx < HeadersBlockSize do
  begin
    LineStart := PosIdx;
    LineEnd := PosIdx;
    while (LineEnd < HeadersBlockSize) and (DataPtr[LineEnd] <> 10) and (DataPtr[LineEnd] <> 13) do
      Inc(LineEnd);
    NextPos := LineEnd;
    if (NextPos < HeadersBlockSize) and (DataPtr[NextPos] = 13) then
      Inc(NextPos);
    if (NextPos < HeadersBlockSize) and (DataPtr[NextPos] = 10) then
      Inc(NextPos);
    PosIdx := NextPos;
    LineLen := LineEnd - LineStart;
    if IsFirstLine then
    begin
      IsFirstLine := False;
      if LineLen > MAX_REQUEST_LINE_LENGTH then
      begin
        SetError(Format('Request line exceeds maximum length (%d bytes)', [MAX_REQUEST_LINE_LENGTH]), stOversizeAttack);
        Exit(True);
      end;
      if not FRequestInfo.ParseRequestLinePtr(DataPtr + LineStart, LineLen, FPrevUri) then
      begin
        AsciiBytesToStr(DataPtr + LineStart, LineLen, Line);
        if ((LineLen >= 4) and (Line[1] = 'g') and (Line[2] = 'e') and (Line[3] = 't') and (Line[4] = ' ')) or
           ((LineLen >= 5) and (Line[1] = 'p') and (Line[2] = 'o') and (Line[3] = 's') and (Line[4] = 't') and (Line[5] = ' ')) then
        begin
          SetError('RFC 9112 Violation in Request Line: ' + Line, stSuspiciousHeaders);
          Exit(True);
        end;
        ParseRequestLine(Line);
        if FErrorParsing then
          Exit(True);
        if FRequestInfo.Version = hvHTTP20 then
        begin
          SetError('RFC 9112 Violation in Request Line: ' + Line, stSuspiciousHeaders);
          Exit(True);
        end;
      end;
      Continue;
    end;
    if LineLen > FMaxHeaderLineLength then
    begin
      SetError(Format('Header line exceeds maximum length (%d bytes)', [FMaxHeaderLineLength]), stOversizeAttack);
      Exit(True);
    end;
    if LineLen = 0 then
      Continue;
    if (DataPtr[LineStart] = 32) or (DataPtr[LineStart] = 9) then
    begin
      HasNonSpace := False;
      for I := LineStart to LineEnd - 1 do
      begin
        if DataPtr[I] > 32 then
        begin
          HasNonSpace := True;
          Break;
        end;
      end;
      if not HasNonSpace then
        Continue;
      AsciiBytesToStr(DataPtr + LineStart, LineLen, Line);
      SetError('Obsolete line folding (obs-fold) is not permitted: ' + Line, stRequestSmuggling);
      Exit(True);
    end;
    ColonPos := -1;
    for I := LineStart to LineEnd - 1 do
    begin
      if DataPtr[I] = Ord(':') then
      begin
        ColonPos := I;
        Break;
      end;
    end;
    if ColonPos >= 0 then
    begin
      if (ColonPos > LineStart) and ((DataPtr[ColonPos - 1] = 32) or (DataPtr[ColonPos - 1] = 9)) then
      begin
        AsciiBytesToStr(DataPtr + LineStart, LineLen, Line);
        SetError('Whitespace before colon in header name (RFC 9112): ' + Line, stRequestSmuggling);
        Exit(True);
      end;
      NameStart := LineStart;
      NameEnd := ColonPos - 1;
      while (NameStart <= NameEnd) and (DataPtr[NameStart] <= 32) do
        Inc(NameStart);
      while (NameEnd >= NameStart) and (DataPtr[NameEnd] <= 32) do
        Dec(NameEnd);
      ValStart := ColonPos + 1;
      ValEnd := LineEnd - 1;
      while (ValStart <= ValEnd) and (DataPtr[ValStart] <= 32) do
        Inc(ValStart);
      while (ValEnd >= ValStart) and (DataPtr[ValEnd] <= 32) do
        Dec(ValEnd);
      Inc(HeaderCount);
      IsKnownHeader := (NameEnd >= NameStart) and MatchKnownHeaderPtr(DataPtr + NameStart, NameEnd - NameStart + 1, CurrentHeaderName);
      if not IsKnownHeader then
      begin
        NeedFullSecurityAnalyze := True;
        if NameEnd >= NameStart then
          AsciiBytesToStr(DataPtr + NameStart, NameEnd - NameStart + 1, CurrentHeaderName)
        else
          CurrentHeaderName := '';
        if not THeaderValidator.ValidateHeaderName(CurrentHeaderName, ErrorMsg) then
        begin
          SetError('Header name validation failed: ' + ErrorMsg, stHeaderInjection);
          Exit(True);
        end;
      end;
      if ValEnd >= ValStart then
      begin
        ValLen := ValEnd - ValStart + 1;
        if (HeaderCount <= 8) and AsciiEqualsStrPtr(DataPtr + ValStart, ValLen, FPrevHeaderSlots[HeaderCount - 1]) then
          CurrentHeaderValue := FPrevHeaderSlots[HeaderCount - 1]
        else
        begin
          if (not NeedFullSecurityAnalyze) and THeaderValidator.HasSuspiciousPatternsPtr(DataPtr + ValStart, ValLen) then
          begin
            NeedFullSecurityAnalyze := True;
            AsciiBytesToStr(DataPtr + ValStart, ValLen, CurrentHeaderValue);
          end
          else
          begin
            AsciiBytesToStr(DataPtr + ValStart, ValLen, CurrentHeaderValue);
            if (not NeedFullSecurityAnalyze) and (HeaderCount <= 8) then
              FPrevHeaderSlots[HeaderCount - 1] := CurrentHeaderValue;
          end;
        end;
      end
      else
      begin
        ValLen := 0;
        CurrentHeaderValue := '';
      end;
      if IsKnownHeader then
      begin
        if CurrentHeaderName = 'host' then
          Inc(HostCount)
        else if CurrentHeaderName = 'connection' then
        begin
          if (ValLen = 5) and ((DataPtr[ValStart] or $20) = Ord('c')) and ((DataPtr[ValStart + 1] or $20) = Ord('l')) and
             ((DataPtr[ValStart + 2] or $20) = Ord('o')) and ((DataPtr[ValStart + 3] or $20) = Ord('s')) and
             ((DataPtr[ValStart + 4] or $20) = Ord('e')) then
            ConnType := ctClose
          else if not ((ValLen = 10) and ((DataPtr[ValStart] or $20) = Ord('k')) and ((DataPtr[ValStart + 1] or $20) = Ord('e'))) then
            NeedFullSecurityAnalyze := True;
        end
        else if CurrentHeaderName = 'content-length' then
        begin
          Inc(ContentLengthCount);
          if ValLen > 0 then
          begin
            ParsedCL := 0;
            for I := 0 to ValLen - 1 do
            begin
              B := DataPtr[ValStart + I];
              if (B >= Ord('0')) and (B <= Ord('9')) then
                ParsedCL := ParsedCL * 10 + (B - Ord('0'))
              else
              begin
                NeedFullSecurityAnalyze := True;
                ParsedCL := -1;
                Break;
              end;
            end;
            ContentLengthVal := ParsedCL;
          end
          else
            NeedFullSecurityAnalyze := True;
        end
        else if CurrentHeaderName = 'transfer-encoding' then
        begin
          Inc(TransferEncodingCount);
          NeedFullSecurityAnalyze := True;
        end
        else if CurrentHeaderName = 'content-encoding' then
          HasContentEncoding := True;
        FHeaders.AddNormalizedHeader(CurrentHeaderName, CurrentHeaderValue);
      end
      else
        FHeaders.AddHeader(CurrentHeaderName, CurrentHeaderValue);
    end
    else
    begin
      AsciiBytesToStr(DataPtr + LineStart, LineLen, Line);
      SetError('Malformed header line (CRLF Injection): ' + Line, stHeaderInjection);
      Exit(True);
    end;
  end;
  if IsFirstLine then
  begin
    SetError('Empty request detected', stMalformedURI);
    Exit(True);
  end;
  if (not NeedFullSecurityAnalyze) and (HostCount = 1) and (ContentLengthCount <= 1) and
     (TransferEncodingCount = 0) and (HeaderCount <= FMaxHeaderCount) then
  begin
    if Length(FSecurityThreats) > 0 then
      SetLength(FSecurityThreats, 0);
    if FRequestInfo.Version = hvHTTP10 then
      FastConnType := ctClose
    else
      FastConnType := ConnType;
    if HasContentEncoding then
      FastEncodings := FHeaders.GetContentEncodings
    else
      SetLength(FastEncodings, 0);
    FRequestInfo.ApplyFastHeaderInfo(teNone, FastConnType, ContentLengthVal, FastEncodings, False);
    if ContentLengthVal <= 0 then
    begin
      FIsChunkedTransfer := False;
      FExpectedBodySize := 0;
      FState := rsComplete;
    end
    else
      DetermineBodySize;
    Result := True;
    Exit;
  end;
  FRequestInfo.ParseFromHeaders(FHeaders);
  if FErrorParsing then
    Exit(True);
  AnalyzeSecurity;
  if HasSecurityThreats then
  begin
    FErrorParsing := True;
    FState := rsError;
    Exit(True);
  end;
  DetermineBodySize;
  Result := True;
end;

procedure TRequest.ParseHeaders;
var
  Line, CurrentHeaderName, CurrentHeaderValue, ErrorMsg: string;
  HeadersBlockSize: Integer;
  HeadersStr: string;
  PosIdx, StrLen, LineStart, LineEnd, LineLen, NextPos, ColonPos: Integer;
  NameStart, NameEnd, ValStart, ValEnd, I: Integer;
  IsFirstLine, HasNonSpace, IsKnownHeader, IsPureAscii: Boolean;
  B: Byte;
  PSrc: PByte;
  PDst: PWideChar;
begin
  FState := rsParsingHeaders;
  if FHeadersEndPos <= 0 then
    FHeadersEndPos := FindHeadersEnd(FRawBuffer, FRawBufferSize);
  if FHeadersEndPos = -1 then
  begin
    if FRawBufferSize >= FMaxHeaderSize then
      SetError('Headers block size limit exceeded.', stOversizeAttack)
    else
      FState := rsWaitingHeaders;
    Exit;
  end;
  HeadersBlockSize := FHeadersEndPos - 4;
  if HeadersBlockSize <= 0 then
  begin
    SetError('Empty request detected', stMalformedURI);
    Exit;
  end;
  SetLength(HeadersStr, HeadersBlockSize);
  PSrc := @FRawBuffer[0];
  PDst := PWideChar(Pointer(HeadersStr));
  IsPureAscii := True;
  for I := 0 to HeadersBlockSize - 1 do
  begin
    B := PSrc[I];
    if B = 0 then
    begin
      SetError('Null byte detected in header block.', stHeaderInjection);
      Exit;
    end;
    if B >= $80 then
    begin
      IsPureAscii := False;
      Break;
    end;
    PDst[I] := WideChar(B);
  end;
  if not IsPureAscii then
  begin
    HeadersStr := TEncoding.UTF8.GetString(FRawBuffer, 0, HeadersBlockSize);
    if Pos(#0, HeadersStr) > 0 then
    begin
      SetError('Null byte detected in header block.', stHeaderInjection);
      Exit;
    end;
  end;
  StrLen := Length(HeadersStr);
  if StrLen = 0 then
  begin
    SetError('Empty request detected', stMalformedURI);
    Exit;
  end;
  PosIdx := 1;
  IsFirstLine := True;
  while PosIdx <= StrLen do
  begin
    LineStart := PosIdx;
    LineEnd := PosIdx;
    while (LineEnd <= StrLen) and (HeadersStr[LineEnd] <> #10) and (HeadersStr[LineEnd] <> #13) do
      Inc(LineEnd);
    NextPos := LineEnd;
    if (NextPos <= StrLen) and (HeadersStr[NextPos] = #13) then
      Inc(NextPos);
    if (NextPos <= StrLen) and (HeadersStr[NextPos] = #10) then
      Inc(NextPos);
    PosIdx := NextPos;
    LineLen := LineEnd - LineStart;
    if IsFirstLine then
    begin
      IsFirstLine := False;
      if LineLen > MAX_REQUEST_LINE_LENGTH then
      begin
        SetError(Format('Request line exceeds maximum length (%d bytes)', [MAX_REQUEST_LINE_LENGTH]), stOversizeAttack);
        Exit;
      end;
      Line := Copy(HeadersStr, LineStart, LineLen);
      if ((LineLen >= 4) and (Line[1] = 'g') and (Line[2] = 'e') and (Line[3] = 't') and (Line[4] = ' ')) or
         ((LineLen >= 5) and (Line[1] = 'p') and (Line[2] = 'o') and (Line[3] = 's') and (Line[4] = 't') and (Line[5] = ' ')) then
      begin
        SetError('RFC 9112 Violation in Request Line: ' + Line, stSuspiciousHeaders);
        Exit;
      end;
      ParseRequestLine(Line);
      if FErrorParsing then
        Exit;
      if FRequestInfo.Version = hvHTTP20 then
      begin
        SetError('RFC 9112 Violation in Request Line: ' + Line, stSuspiciousHeaders);
        Exit;
      end;
      Continue;
    end;
    if LineLen > FMaxHeaderLineLength then
    begin
      SetError(Format('Header line exceeds maximum length (%d bytes)', [FMaxHeaderLineLength]), stOversizeAttack);
      Exit;
    end;
    if LineLen = 0 then
      Continue;
    if (HeadersStr[LineStart] = ' ') or (HeadersStr[LineStart] = #9) then
    begin
      HasNonSpace := False;
      for I := LineStart to LineEnd - 1 do
      begin
        if HeadersStr[I] > ' ' then
        begin
          HasNonSpace := True;
          Break;
        end;
      end;
      if not HasNonSpace then
        Continue;
      SetError('Obsolete line folding (obs-fold) is not permitted: ' + Copy(HeadersStr, LineStart, LineLen), stRequestSmuggling);
      Exit;
    end;
    ColonPos := 0;
    for I := LineStart to LineEnd - 1 do
    begin
      if HeadersStr[I] = ':' then
      begin
        ColonPos := I;
        Break;
      end;
    end;
    if ColonPos > 0 then
    begin
      if (ColonPos > LineStart) and ((HeadersStr[ColonPos - 1] = ' ') or (HeadersStr[ColonPos - 1] = #9)) then
      begin
        SetError('Whitespace before colon in header name (RFC 9112): ' + Copy(HeadersStr, LineStart, LineLen), stRequestSmuggling);
        Exit;
      end;
      NameStart := LineStart;
      NameEnd := ColonPos - 1;
      while (NameStart <= NameEnd) and (HeadersStr[NameStart] <= ' ') do
        Inc(NameStart);
      while (NameEnd >= NameStart) and (HeadersStr[NameEnd] <= ' ') do
        Dec(NameEnd);
      ValStart := ColonPos + 1;
      ValEnd := LineEnd - 1;
      while (ValStart <= ValEnd) and (HeadersStr[ValStart] <= ' ') do
        Inc(ValStart);
      while (ValEnd >= ValStart) and (HeadersStr[ValEnd] <= ' ') do
        Dec(ValEnd);
      IsKnownHeader := (NameEnd >= NameStart) and MatchKnownHeaderSlice(HeadersStr, NameStart, NameEnd - NameStart + 1, CurrentHeaderName);
      if not IsKnownHeader then
      begin
        if NameEnd >= NameStart then
          CurrentHeaderName := Copy(HeadersStr, NameStart, NameEnd - NameStart + 1)
        else
          CurrentHeaderName := '';
        if not THeaderValidator.ValidateHeaderName(CurrentHeaderName, ErrorMsg) then
        begin
          SetError('Header name validation failed: ' + ErrorMsg, stHeaderInjection);
          Exit;
        end;
      end;
      if ValEnd >= ValStart then
        CurrentHeaderValue := Copy(HeadersStr, ValStart, ValEnd - ValStart + 1)
      else
        CurrentHeaderValue := '';
      if IsKnownHeader then
        FHeaders.AddNormalizedHeader(CurrentHeaderName, CurrentHeaderValue)
      else
        FHeaders.AddHeader(CurrentHeaderName, CurrentHeaderValue);
    end
    else
    begin
      SetError('Malformed header line (CRLF Injection): ' + Copy(HeadersStr, LineStart, LineLen), stHeaderInjection);
      Exit;
    end;
  end;
  if IsFirstLine then
  begin
    SetError('Empty request detected', stMalformedURI);
    Exit;
  end;
  FRequestInfo.ParseFromHeaders(FHeaders);
  if FErrorParsing then
     Exit;
  AnalyzeSecurity;
  if HasSecurityThreats then
  begin
    FErrorParsing := True;
    FState := rsError;
    Exit;
  end;
  DetermineBodySize;
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
    if (FExpectedBodySize = 0) and (not FIsChunkedTransfer) then
    begin
      FState := rsComplete;
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
        FState := rsComplete;
    end;
  except
    on E: Exception do
       SetError(Format('Error processing remaining data: %s', [E.Message]));
  end;
end;

procedure TRequest.ConfigureBodyParserSecurity;
begin
  if Assigned(FBodyParser) then
  begin
    if Assigned(FAllowedFileExtensions) and (FAllowedFileExtensions.Count > 0) then
      FBodyParser.SecuritySettings.AllowedFileExtensions.Assign(FAllowedFileExtensions);
    if Assigned(FBlockedMimeTypes) and (FBlockedMimeTypes.Count > 0) then
      FBodyParser.SecuritySettings.BlockedMimeTypes.Assign(FBlockedMimeTypes);
  end;
end;

procedure TRequest.DetermineBodySize;
var
  TempContentType: string;
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
        ConfigureBodyParserSecurity;
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
        TempContentType := FHeaders.ContentType;
        FBodyParser := THttpBodyParser.Create(
          TempContentType,
          FExpectedBodySize,
          FHeaders.TransferEncoding,
          FMaxBodySize,
          True,
          ''
        );
        ConfigureBodyParserSecurity;
      except
        on E: Exception do
        begin
          SetError('Failed to create body parser for fixed length: ' + E.Message);
          Exit;
        end;
      end;
    end
    else if FRequestInfo.HasBody and (FRequestInfo.ContentLength > 0) then
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
        ConfigureBodyParserSecurity;
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
  RemainingSpace: Int64;
  TempData: TBytes;
  ProcessedSuccessfully: Boolean;
  IsBodyComplete: Boolean;
  MainBytes: TBytes;
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
      RemainingSpace := FExpectedBodySize - FBodyBytesReceived;
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
        if Assigned(FBodyParser) and Assigned(FBodyStream) and (FBodyStream.Size = 0) then
        begin
          MainBytes := FBodyParser.GetMainPartAsBytes;
          if Length(MainBytes) > 0 then
            FBodyStream.WriteBuffer(MainBytes[0], Length(MainBytes));
        end;
        if Length(FRequestInfo.ContentEncodings) > 0 then
          DecompressBodyIfNeeded;
        FState := rsComplete;
      end;
    end;
  except
    on E: Exception do
      SetError(Format('Body data processing error: %s', [E.Message]));
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
              Break;
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
        FState := rsComplete;
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

function TRequest.GetBodyParser: THttpBodyParser;
begin
  Result := FBodyParser;
end;

function TRequest.GetBodyAsString: string;
var
  RawBytes: TBytes;
  Enc: TContentEncoding;
begin
  try
    if Assigned(FBodyParser) then
      RawBytes := FBodyParser.GetMainPartAsBytes
    else
      RawBytes := GetBodyBytes;

    if Length(RawBytes) > 0 then
    begin
      for Enc in FRequestInfo.ContentEncodings do
      begin
        if FContentEncodingHandler.IsCompressionSupported(Enc) then
          RawBytes := FContentEncodingHandler.DecompressData(RawBytes, Enc);
      end;
      Result := TEncoding.UTF8.GetString(RawBytes);
    end
    else
      Result := '';
  except
    on E: Exception do
      Result := '';
  end;
end;

function TRequest.GetBodyAsBytes: TBytes;
var
  Enc: TContentEncoding;
begin
  try
    if Assigned(FBodyParser) then
      Result := FBodyParser.GetMainPartAsBytes
    else
      Result := GetBodyBytes;

    if Length(Result) > 0 then
    begin
      for Enc in FRequestInfo.ContentEncodings do
      begin
        if FContentEncodingHandler.IsCompressionSupported(Enc) then
          Result := FContentEncodingHandler.DecompressData(Result, Enc);
      end;
    end;
  except
    on E: Exception do
      SetLength(Result, 0);
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
      Result := nil;
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
      Result := nil;
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
      Result := 0;
  end;
end;

function TRequest.GetHeadersSize: Integer;
begin
  try
    if FHeadersEndPos >= 4 then
      Result := FHeadersEndPos - 4
    else
      Result := 0;
  except
    on E: Exception do
      Result := 0;
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
      Result := bctUnknown;
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
      Exit;
    HeadersStr := TEncoding.UTF8.GetString(FRawBuffer, 0, FRawBufferSize);
    if (Pos('HTTP/1.', HeadersStr) = 0) then
    begin
      Logger.Info('DEBUG: This is not an HTTP request');
      Exit;
    end;
    if Pos(DOUBLE_CRLF, HeadersStr) > 0 then
      Exit;
    Lines := TStringList.Create;
    try
      Lines.Text := StringReplace(HeadersStr, CRLF, sLineBreak, [rfReplaceAll]);
      LineCount := Lines.Count;
      if LineCount < 2 then
        Exit;
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
        HasIncompleteHeader := True;
      if (Pos(':', LastLine) = 0) and (LastLine <> '') and not LastLine.StartsWith('HTTP/') then
        HasIncompleteHeader := True;
      if (HeaderCount >= 2) and HasIncompleteHeader then
      begin
        Logger.Warn('DETECTED: Slowloris Attack - incomplete headers!');
        Logger.Warn(' - HeaderCount: %d', [HeaderCount]);
        Logger.Warn(' - HasIncompleteHeader: %s', [BoolToStr(HasIncompleteHeader, True)]);
        Logger.Warn(' - Last line: "%s"', [LastLine]);
        Result := True;
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

function TRequest.IsKeepAlive: Boolean;
begin
  Result := False;
  if Assigned(FRequestInfo) then
  begin
    if FRequestInfo.Version = hvHTTP11 then
      Result := FRequestInfo.ConnectionType <> ctClose
    else if FRequestInfo.Version = hvHTTP10 then
      Result := FRequestInfo.ConnectionType = ctKeepAlive;
  end;
end;


end.
