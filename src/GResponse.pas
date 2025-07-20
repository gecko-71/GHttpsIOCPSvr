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

unit GResponse;

interface

uses
  Quick.Logger,
  System.SysUtils, System.Classes, System.Threading, System.SyncObjs,
  System.Generics.Collections, System.Math, System.IOUtils, System.DateUtils,
  Winapi.Windows, Winapi.WinSock2;

type
  THttpStatus = (
    // 1xx Informational
    hsContinue = 100,
    hsSwitchingProtocols = 101,
    hsProcessing = 102,

    // 2xx Success
    hsOK = 200,
    hsCreated = 201,
    hsAccepted = 202,
    hsNonAuthoritativeInformation = 203,
    hsNoContent = 204,
    hsResetContent = 205,
    hsPartialContent = 206,
    hsMultiStatus = 207,
    hsAlreadyReported = 208,
    hsIMUsed = 226,

    // 3xx Redirection
    hsMultipleChoices = 300,
    hsMovedPermanently = 301,
    hsFound = 302,
    hsSeeOther = 303,
    hsNotModified = 304,
    hsUseProxy = 305,
    hsTemporaryRedirect = 307,
    hsPermanentRedirect = 308,

    // 4xx Client Error
    hsBadRequest = 400,
    hsUnauthorized = 401,
    hsPaymentRequired = 402,
    hsForbidden = 403,
    hsNotFound = 404,
    hsMethodNotAllowed = 405,
    hsNotAcceptable = 406,
    hsProxyAuthenticationRequired = 407,
    hsRequestTimeout = 408,
    hsConflict = 409,
    hsGone = 410,
    hsLengthRequired = 411,
    hsPreconditionFailed = 412,
    hsPayloadTooLarge = 413,
    hsURITooLong = 414,
    hsUnsupportedMediaType = 415,
    hsRangeNotSatisfiable = 416,
    hsExpectationFailed = 417,
    hsImATeapot = 418,
    hsMisdirectedRequest = 421,
    hsUnprocessableEntity = 422,
    hsLocked = 423,
    hsFailedDependency = 424,
    hsTooEarly = 425,
    hsUpgradeRequired = 426,
    hsPreconditionRequired = 428,
    hsTooManyRequests = 429,
    hsRequestHeaderFieldsTooLarge = 431,
    hsUnavailableForLegalReasons = 451,

    // 5xx Server Error
    hsInternalServerError = 500,
    hsNotImplemented = 501,
    hsBadGateway = 502,
    hsServiceUnavailable = 503,
    hsGatewayTimeout = 504,
    hsHTTPVersionNotSupported = 505,
    hsVariantAlsoNegotiates = 506,
    hsInsufficientStorage = 507,
    hsLoopDetected = 508,
    hsNotExtended = 510,
    hsNetworkAuthenticationRequired = 511
  );

  TContentStorageMode = (
    csmMemory,
    csmFile
  );

  TMultipartType = (
    mpFormData,
    mpMixed,
    mpAlternative,
    mpRelated
  );

  TMultipartPart = class
  private
    FHeaders: TStringList;
    FContent: TBytes;
    FName: string;
    FFilename: string;
    FContentType: string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddHeader(const Name, Value: string);
    procedure SetContent(const Content: TBytes); overload;
    procedure SetContent(const Content: string); overload;
    procedure SetFileContent(const Filename: string);

    property Name: string read FName write FName;
    property Filename: string read FFilename write FFilename;
    property ContentType: string read FContentType write FContentType;
    property Headers: TStringList read FHeaders;
    property Content: TBytes read FContent;
  end;

  TResponse = class
  private
    FResponseTempDir: string;
    FSocket: TSocket;
    FStatus: THttpStatus;
    FHeaders: TStringList;
    FContentType: string;
    FHeadersData: TBytes;
    FHeadersBuilt: Boolean;
    FHeadersSent: Boolean;
    FBytesSent: Integer;
    FContentBytes: TBytes;
    FContentBytesBuilt: Boolean;
    FContentPosition: Int64;
    FStorageMode: TContentStorageMode;
    FTempFilePath: string;
    FTempFileStream: TFileStream;
    FMaxMemorySize: Int64;
    FTotalContentSize: Int64;
    FMultipartType: TMultipartType;
    FMultipartBoundary: string;
    FMultipartParts: TObjectList<TMultipartPart>;
    FIsMultipart: Boolean;
    FMultipartBuilt: Boolean;
    FSourceFileStream: TFileStream;
    FSourceFilePath: string;
    FUseSourceFile: Boolean;
    FSourceFileSize: Int64;
    FInMemoryFiles: TObjectList<TMemoryStream>;
    FCurrentInMemoryFile: TMemoryStream;
    FContentFinalized: Boolean;
    FHeaderPosition: Integer;
    procedure BuildHeaders;
    procedure BuildContentBytes;
    procedure BuildMultipartContent;
    procedure EnsureTempFile;
    procedure WriteToStorage(const Data: TBytes);
    function ReadFromStorage(Buffer: PByte; BufferSize: Integer): Integer;
    function GetStatusText(Status: THttpStatus): string;
    function GetContentTypeForMultipart(MultipartType: TMultipartType): string;
    function GenerateBoundary: string;
    procedure CleanupTempFile;
    procedure CleanupSourceFile;
    function HasHeader(const Name: string): Boolean;
    function GetNewTempFilePath(const Extension: string): string;
  public
    constructor Create(ASocket: TSocket);
    destructor Destroy; override;
    procedure RemoveHeader(const Name: string);
    procedure SetOrUpdateHeader(const Name, Value: string);
    procedure SetMaxMemorySize(const Value: Int64);
    procedure FinalizeContent;
    procedure SetStatus(AStatus: THttpStatus); overload;
    procedure SetStatus(AStatus: Integer); overload;
    procedure AddHeader(const Name, Value: string);
    procedure AddTextContent(const ContentType, Content: string);
    procedure AddBinaryContent(const ContentType: string; const Content: TBytes);
    procedure AddFileContent(const ContentType, Filename: string);
    procedure AddJSONContent(const JSON: string);
    procedure AddXMLContent(const XML: string);
    procedure AddHTMLContent(const HTML: string);
    procedure AddFileStreamContent(const ContentType, Filename: string);
    procedure AddFileStreamWithRange(const ContentType, Filename: string; StartPos, Length: Int64);
    procedure AddStreamContent(AContentType: string; ASourceStream: TStream);
    function CreateInMemoryFile(const Filename, ContentType: string): TMemoryStream;
    procedure FinishInMemoryFile;
    procedure AddInMemoryFileContent(const ContentType: string; MemoryFile: TMemoryStream; const Filename: string = '');
    procedure AddImageContent(const Filename: string);
    procedure AddDocumentContent(const Filename: string);
    function DetectContentTypeFromExtension(const Filename: string): string;
    procedure BeginMultipart(MultipartType: TMultipartType = mpFormData);
    function AddMultipartPart: TMultipartPart;
    procedure AddMultipartText(const Name, Value: string);
    procedure AddMultipartFile(const Name, Filename, ContentType: string; const Content: TBytes);
    procedure EndMultipart;
    function ReadNextChunk(Buffer: PByte; BufferSize: Integer): Integer;
    procedure UpdateSentBytes(BytesSent: Integer);
    function IsComplete: Boolean;
    procedure SetError(Status: THttpStatus; const Message: string = '');
    procedure SetBadRequest(const Message: string = 'Bad Request');
    procedure SetNotFound(const Message: string = 'Not Found');
    procedure SetInternalServerError(const Message: string = 'Internal Server Error');
    procedure SetUnauthorized(const Message: string = 'Unauthorized');
    procedure SetForbidden(const Message: string = 'Forbidden');
    procedure SetMethodNotAllowed(const Message: string = 'Method Not Allowed');
    procedure SetSeeOther(const URL: string);
    procedure SetTemporaryRedirect(const URL: string);
    procedure SetPermanentRedirect(const URL: string);
    procedure SetRedirect(const URL: string; Permanent: Boolean = False);
    procedure SetMovedPermanently(const URL: string);
    procedure SetFound(const URL: string);
    procedure Write(const Data: TBytes); overload;
    procedure Write(const Data: string); overload;
    property Socket: TSocket read FSocket;
    property BytesSent: Integer read FBytesSent;
    property Status: THttpStatus read FStatus;
    property MaxMemorySize: Int64 read FMaxMemorySize write FMaxMemorySize;
    property StorageMode: TContentStorageMode read FStorageMode;
    property TotalContentSize: Int64 read FTotalContentSize;
    property CurrentInMemoryFile: TMemoryStream read FCurrentInMemoryFile;
    property ContentPosition: Int64 read FContentPosition;
  end;

implementation

uses System.StrUtils;

const
  DEFAULT_MAX_MEMORY_SIZE = 10 * 1024 * 1024; // 10MB
  TEMP_FILE_PREFIX = 'GResponse_';

constructor TMultipartPart.Create;
begin
  inherited Create;
  try
    FHeaders := TStringList.Create;
    SetLength(FContent, 0);
    FName := '';
    FFilename := '';
    FContentType := 'text/plain';
  except
    on E: Exception do
    begin
      if Assigned(FHeaders) then
        FHeaders.Free;
      raise Exception.CreateFmt('Failed to create TMultipartPart: %s', [E.Message]);
    end;
  end;
end;

destructor TMultipartPart.Destroy;
begin
  try
    FHeaders.Free;
    SetLength(FContent, 0);
  finally
    inherited Destroy;
  end;
end;

procedure TMultipartPart.AddHeader(const Name, Value: string);
begin
  try
    FHeaders.Add(Name + ': ' + Value);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add header: %s', [E.Message]);
  end;
end;

procedure TMultipartPart.SetContent(const Content: TBytes);
begin
  try
    FContent := Copy(Content, 0, Length(Content));
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set content: %s', [E.Message]);
  end;
end;

procedure TMultipartPart.SetContent(const Content: string);
begin
  try
    FContent := TEncoding.UTF8.GetBytes(Content);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set string content: %s', [E.Message]);
  end;
end;

procedure TMultipartPart.SetFileContent(const Filename: string);
var
  FileBytes: TBytes;
  Ext: string;
begin
  try
    if not TFile.Exists(Filename) then
      raise Exception.CreateFmt('File not found: %s', [Filename]);

    FileBytes := TFile.ReadAllBytes(Filename);
    SetContent(FileBytes);

    if FFilename = '' then
      FFilename := ExtractFileName(Filename);

    if FContentType = 'text/plain' then
    begin
      Ext := LowerCase(ExtractFileExt(Filename));
      if Ext = '.html' then FContentType := 'text/html'
      else if Ext = '.css' then FContentType := 'text/css'
      else if Ext = '.js' then FContentType := 'application/javascript'
      else if Ext = '.json' then FContentType := 'application/json'
      else if Ext = '.xml' then FContentType := 'application/xml'
      else if Ext = '.pdf' then FContentType := 'application/pdf'
      else if Ext = '.jpg' then FContentType := 'image/jpeg'
      else if Ext = '.png' then FContentType := 'image/png'
      else if Ext = '.gif' then FContentType := 'image/gif'
      else FContentType := 'application/octet-stream';
    end;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set file content: %s', [E.Message]);
  end;
end;

constructor TResponse.Create(ASocket: TSocket);
begin
  inherited Create;
  try
    FHeaderPosition := 0;
    FSocket := ASocket;
    FStatus := hsOK;
    FHeaders := TStringList.Create;
    FContentType := 'text/plain';
    FBytesSent := 0;
    FHeadersBuilt := False;
    FHeadersSent := False;
    FContentBytesBuilt := False;
    FContentPosition := 0;
    FMaxMemorySize := DEFAULT_MAX_MEMORY_SIZE;
    FStorageMode := csmMemory;
    FTempFilePath := '';
    FTempFileStream := nil;
    FTotalContentSize := 0;
    FContentFinalized := False;
    FMultipartParts := TObjectList<TMultipartPart>.Create(True);
    FIsMultipart := False;
    FMultipartBuilt := False;
    FMultipartBoundary := '';
    FSourceFileStream := nil;
    FSourceFilePath := '';
    FUseSourceFile := False;
    FSourceFileSize := 0;
    FInMemoryFiles := TObjectList<TMemoryStream>.Create(True);
    FCurrentInMemoryFile := nil;
    SetLength(FHeadersData, 0);
    SetLength(FContentBytes, 0);
    FResponseTempDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'download_tmp');
    if not TDirectory.Exists(FResponseTempDir) then
      TDirectory.CreateDirectory(FResponseTempDir);
  except
    on E: Exception do
    begin
      if Assigned(FHeaders) then
        FHeaders.Free;
      if Assigned(FMultipartParts) then
        FMultipartParts.Free;
      if Assigned(FInMemoryFiles) then
        FInMemoryFiles.Free;
      raise Exception.CreateFmt('Failed to create TResponse: %s', [E.Message]);
    end;
  end;
end;

destructor TResponse.Destroy;
begin
  try
    CleanupSourceFile;
    CleanupTempFile;
  finally
    try
      FHeaders.Free;
      FMultipartParts.Free;
      FInMemoryFiles.Free;
      SetLength(FHeadersData, 0);
      SetLength(FContentBytes, 0);
    finally
      inherited Destroy;
    end;
  end;
end;

procedure TResponse.RemoveHeader(const Name: string);
var
  i: Integer;
begin
  for i := FHeaders.Count - 1 downto 0 do
  begin
    if StartsText(Name + ':', FHeaders[i]) then
      FHeaders.Delete(i);
  end;
end;

procedure TResponse.SetOrUpdateHeader(const Name, Value: string);
begin
  RemoveHeader(Name);
  FHeaders.Add(Name + ': ' + Value);
end;

function TResponse.HasHeader(const Name: string): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to FHeaders.Count - 1 do
  begin
    if StartsText(Name + ':', FHeaders[i]) then
    begin
      Result := True;
      Break;
    end;
  end;
end;

procedure TResponse.FinalizeContent;
begin
  if not FContentFinalized then
  begin
    SetOrUpdateHeader('Content-Length', IntToStr(FTotalContentSize));
    FContentFinalized := True;
  end;
end;

procedure TResponse.CleanupTempFile;
begin
  try
    if Assigned(FTempFileStream) then
    begin
      try
        FTempFileStream.Free;
      except
      end;
      FTempFileStream := nil;
    end;

    if (FTempFilePath <> '') and TFile.Exists(FTempFilePath) then
    begin
      try
        TFile.Delete(FTempFilePath);
      except
      end;
      FTempFilePath := '';
    end;
  except
  end;
end;

procedure TResponse.CleanupSourceFile;
begin
  if Assigned(FSourceFileStream) then
  begin
    FSourceFileStream.Free;
    FSourceFileStream := nil;
    FSourceFilePath := '';
    if (FSourceFilePath <> '') and
        SameText(TPath.GetDirectoryName(FSourceFilePath), FResponseTempDir) and
           TFile.Exists(FSourceFilePath) then
      TFile.Delete(FSourceFilePath);
  end;
  FSourceFilePath := '';
  FUseSourceFile := False;
  FSourceFileSize := 0;
end;

function TResponse.GetStatusText(Status: THttpStatus): string;
begin
  case Status of
    // 1xx Informational
    hsContinue: Result := 'Continue';
    hsSwitchingProtocols: Result := 'Switching Protocols';
    hsProcessing: Result := 'Processing';

    // 2xx Success
    hsOK: Result := 'OK';
    hsCreated: Result := 'Created';
    hsAccepted: Result := 'Accepted';
    hsNonAuthoritativeInformation: Result := 'Non-Authoritative Information';
    hsNoContent: Result := 'No Content';
    hsResetContent: Result := 'Reset Content';
    hsPartialContent: Result := 'Partial Content';
    hsMultiStatus: Result := 'Multi-Status';
    hsAlreadyReported: Result := 'Already Reported';
    hsIMUsed: Result := 'IM Used';

    // 3xx Redirection
    hsMultipleChoices: Result := 'Multiple Choices';
    hsMovedPermanently: Result := 'Moved Permanently';
    hsFound: Result := 'Found';
    hsSeeOther: Result := 'See Other';
    hsNotModified: Result := 'Not Modified';
    hsUseProxy: Result := 'Use Proxy';
    hsTemporaryRedirect: Result := 'Temporary Redirect';
    hsPermanentRedirect: Result := 'Permanent Redirect';

    // 4xx Client Error
    hsBadRequest: Result := 'Bad Request';
    hsUnauthorized: Result := 'Unauthorized';
    hsPaymentRequired: Result := 'Payment Required';
    hsForbidden: Result := 'Forbidden';
    hsNotFound: Result := 'Not Found';
    hsMethodNotAllowed: Result := 'Method Not Allowed';
    hsNotAcceptable: Result := 'Not Acceptable';
    hsProxyAuthenticationRequired: Result := 'Proxy Authentication Required';
    hsRequestTimeout: Result := 'Request Timeout';
    hsConflict: Result := 'Conflict';
    hsGone: Result := 'Gone';
    hsLengthRequired: Result := 'Length Required';
    hsPreconditionFailed: Result := 'Precondition Failed';
    hsPayloadTooLarge: Result := 'Payload Too Large';
    hsURITooLong: Result := 'URI Too Long';
    hsUnsupportedMediaType: Result := 'Unsupported Media Type';
    hsRangeNotSatisfiable: Result := 'Range Not Satisfiable';
    hsExpectationFailed: Result := 'Expectation Failed';
    hsImATeapot: Result := 'I''m a teapot';
    hsMisdirectedRequest: Result := 'Misdirected Request';
    hsUnprocessableEntity: Result := 'Unprocessable Entity';
    hsLocked: Result := 'Locked';
    hsFailedDependency: Result := 'Failed Dependency';
    hsTooEarly: Result := 'Too Early';
    hsUpgradeRequired: Result := 'Upgrade Required';
    hsPreconditionRequired: Result := 'Precondition Required';
    hsTooManyRequests: Result := 'Too Many Requests';
    hsRequestHeaderFieldsTooLarge: Result := 'Request Header Fields Too Large';
    hsUnavailableForLegalReasons: Result := 'Unavailable For Legal Reasons';

    // 5xx Server Error
    hsInternalServerError: Result := 'Internal Server Error';
    hsNotImplemented: Result := 'Not Implemented';
    hsBadGateway: Result := 'Bad Gateway';
    hsServiceUnavailable: Result := 'Service Unavailable';
    hsGatewayTimeout: Result := 'Gateway Timeout';
    hsHTTPVersionNotSupported: Result := 'HTTP Version Not Supported';
    hsVariantAlsoNegotiates: Result := 'Variant Also Negotiates';
    hsInsufficientStorage: Result := 'Insufficient Storage';
    hsLoopDetected: Result := 'Loop Detected';
    hsNotExtended: Result := 'Not Extended';
    hsNetworkAuthenticationRequired: Result := 'Network Authentication Required';
  else
    Result := 'Unknown Status';
  end;
end;

procedure TResponse.SetMaxMemorySize(const Value: Int64);
begin
  try
    if Value < 1024 then
      raise Exception.Create('MaxMemorySize must be at least 1KB');
    if Value > Int64.MaxValue div 2 then
      raise Exception.Create('MaxMemorySize too large');
    FMaxMemorySize := Value;
  except
    on E: Exception do
    begin
      Logger.Error('Failed to set MaxMemorySize: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to set MaxMemorySize: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.SetStatus(AStatus: THttpStatus);
begin
  try
    FStatus := AStatus;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set status: %s', [E.Message]);
  end;
end;

procedure TResponse.SetStatus(AStatus: Integer);
begin
  try
    FStatus := THttpStatus(AStatus);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set status from integer: %s', [E.Message]);
  end;
end;

procedure TResponse.AddHeader(const Name, Value: string);
begin
  try
    FHeaders.Add(Name + ': ' + Value);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add header: %s', [E.Message]);
  end;
end;

procedure TResponse.EnsureTempFile;
var
  TempDir: string;
  Guid: TGUID;
  GuidStr: string;
begin
  try
    if FTempFilePath = '' then
    begin
      TempDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'tmp');
      if not TDirectory.Exists(TempDir) then
        TDirectory.CreateDirectory(TempDir);
      CreateGUID(Guid);
      GuidStr := StringReplace(GuidToString(Guid), '-', '', [rfReplaceAll]);
      GuidStr := StringReplace(GuidStr, '{', '', [rfReplaceAll]);
      GuidStr := StringReplace(GuidStr, '}', '', [rfReplaceAll]);
      FTempFilePath := TPath.Combine(TempDir, TEMP_FILE_PREFIX + GuidStr + '.tmp');
    end;

    if not Assigned(FTempFileStream) then
      FTempFileStream := TFileStream.Create(FTempFilePath, fmCreate or fmOpenReadWrite);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to create temp file: %s', [E.Message]);
  end;
end;

procedure TResponse.WriteToStorage(const Data: TBytes);
var
  DataSize: Integer;
  OldLen: Integer;
begin
  try
    DataSize := Length(Data);
    if DataSize = 0 then
      Exit;
    FTotalContentSize := FTotalContentSize + DataSize;
    if (FStorageMode = csmMemory) and (FTotalContentSize > FMaxMemorySize) then
    begin
      FStorageMode := csmFile;
      EnsureTempFile;
      if Length(FContentBytes) > 0 then
      begin
        FTempFileStream.WriteBuffer(FContentBytes[0], Length(FContentBytes));
        SetLength(FContentBytes, 0);
      end;
    end;

    case FStorageMode of
      csmMemory:
        begin
          OldLen := Length(FContentBytes);
          SetLength(FContentBytes, OldLen + DataSize);
          Move(Data[0], FContentBytes[OldLen], DataSize);
        end;

      csmFile:
        begin
          EnsureTempFile;
          FTempFileStream.WriteBuffer(Data[0], DataSize);
        end;
    end;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to write to storage: %s', [E.Message]);
  end;
end;

function TResponse.ReadFromStorage(Buffer: PByte; BufferSize: Integer): Integer;
var
  BytesToRead: Integer;
  RemainingBytes: Integer;
begin
  Result := 0;
  try
    if FUseSourceFile and Assigned(FSourceFileStream) then
    begin
      Result := FSourceFileStream.Read(Buffer^, BufferSize);
      Inc(FContentPosition, Result);
      Exit;
    end;
    case FStorageMode of
      csmMemory:
        begin
          if not FContentBytesBuilt then
            BuildContentBytes;

          RemainingBytes := Length(FContentBytes) - FContentPosition;
          if RemainingBytes > 0 then
          begin
            BytesToRead := Min(RemainingBytes, BufferSize);
            Move(FContentBytes[FContentPosition], Buffer^, BytesToRead);
            Inc(FContentPosition, BytesToRead);
            Result := BytesToRead;
          end;
        end;

      csmFile:
        begin
          if Assigned(FTempFileStream) then
          begin
            FTempFileStream.Position := FContentPosition;
            Result := FTempFileStream.Read(Buffer^, BufferSize);
            Inc(FContentPosition, Result);
          end;
        end;
    end;
  except
    on E: Exception do
    begin
      Result := 0;
      raise Exception.CreateFmt('Failed to read from storage: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddTextContent(const ContentType, Content: string);
var
  ContentBytes: TBytes;
begin
  try
    FContentType := ContentType;
    ContentBytes := TEncoding.UTF8.GetBytes(Content);
    WriteToStorage(ContentBytes);
    FinalizeContent;
    var storMod := '';
    if FStorageMode = csmMemory then
      storMod := 'Memory'
      else storMod := 'File';
  except
    on E: Exception do
    begin
      Logger.Error('Failed to add text content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to add text content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddBinaryContent(const ContentType: string; const Content: TBytes);
begin
  try
    FContentType := ContentType;
    WriteToStorage(Content);
    FinalizeContent;
    var storMod := '';
    if FStorageMode = csmMemory then
       storMod := 'Memory'
    else
       storMod :='File';
  except
    on E: Exception do
    begin
      Logger.Error('Failed to add text content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to add binary content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddFileContent(const ContentType, Filename: string);
var
  FileBytes: TBytes;
begin
  try
    if not TFile.Exists(Filename) then
      raise Exception.CreateFmt('File not found: %s', [Filename]);
    FileBytes := TFile.ReadAllBytes(Filename);
    AddBinaryContent(ContentType, FileBytes);
    AddHeader('Content-Disposition', 'attachment; filename="' + ExtractFileName(Filename) + '"');
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add file content: %s', [E.Message]);
  end;
end;

procedure TResponse.AddJSONContent(const JSON: string);
begin
  try
    AddTextContent('application/json; charset=utf-8', JSON);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add JSON content: %s', [E.Message]);
  end;
end;

procedure TResponse.AddXMLContent(const XML: string);
begin
  try
    AddTextContent('application/xml; charset=utf-8', XML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add XML content: %s', [E.Message]);
  end;
end;

procedure TResponse.AddHTMLContent(const HTML: string);
begin
  try
    AddTextContent('text/html; charset=utf-8', HTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add HTML content: %s', [E.Message]);
  end;
end;

function TResponse.GenerateBoundary: string;
var
  Guid: TGUID;
begin
  try
    CreateGUID(Guid);
    Result := 'boundary_' + StringReplace(GuidToString(Guid), '-', '', [rfReplaceAll]);
    Result := StringReplace(Result, '{', '', [rfReplaceAll]);
    Result := StringReplace(Result, '}', '', [rfReplaceAll]);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to generate boundary: %s', [E.Message]);
  end;
end;

function TResponse.GetContentTypeForMultipart(MultipartType: TMultipartType): string;
begin
  case MultipartType of
    mpFormData: Result := 'multipart/form-data';
    mpMixed: Result := 'multipart/mixed';
    mpAlternative: Result := 'multipart/alternative';
    mpRelated: Result := 'multipart/related';
  else
    Result := 'multipart/mixed';
  end;
end;

function TResponse.DetectContentTypeFromExtension(const Filename: string): string;
var
  Ext: string;
begin
  Ext := LowerCase(ExtractFileExt(Filename));

  // Images
  if (Ext = '.jpg') or (Ext = '.jpeg') then Result := 'image/jpeg'
  else if Ext = '.png' then Result := 'image/png'
  else if Ext = '.gif' then Result := 'image/gif'
  else if Ext = '.bmp' then Result := 'image/bmp'
  else if Ext = '.webp' then Result := 'image/webp'
  else if Ext = '.svg' then Result := 'image/svg+xml'
  else if Ext = '.ico' then Result := 'image/x-icon'
  else if Ext = '.tiff' then Result := 'image/tiff'

  // Documents
  else if Ext = '.pdf' then Result := 'application/pdf'
  else if Ext = '.doc' then Result := 'application/msword'
  else if Ext = '.docx' then Result := 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  else if Ext = '.xls' then Result := 'application/vnd.ms-excel'
  else if Ext = '.xlsx' then Result := 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  else if Ext = '.ppt' then Result := 'application/vnd.ms-powerpoint'
  else if Ext = '.pptx' then Result := 'application/vnd.openxmlformats-officedocument.presentationml.presentation'

  // Text
  else if Ext = '.txt' then Result := 'text/plain'
  else if Ext = '.html' then Result := 'text/html'
  else if Ext = '.htm' then Result := 'text/html'
  else if Ext = '.css' then Result := 'text/css'
  else if Ext = '.js' then Result := 'application/javascript'
  else if Ext = '.json' then Result := 'application/json'
  else if Ext = '.xml' then Result := 'application/xml'
  else if Ext = '.csv' then Result := 'text/csv'

  // Archives
  else if Ext = '.zip' then Result := 'application/zip'
  else if Ext = '.rar' then Result := 'application/x-rar-compressed'
  else if Ext = '.7z' then Result := 'application/x-7z-compressed'
  else if Ext = '.tar' then Result := 'application/x-tar'
  else if Ext = '.gz' then Result := 'application/gzip'

  // Video
  else if Ext = '.mp4' then Result := 'video/mp4'
  else if Ext = '.avi' then Result := 'video/x-msvideo'
  else if Ext = '.mov' then Result := 'video/quicktime'
  else if Ext = '.wmv' then Result := 'video/x-ms-wmv'
  else if Ext = '.flv' then Result := 'video/x-flv'
  else if Ext = '.webm' then Result := 'video/webm'
  else if Ext = '.mkv' then Result := 'video/x-matroska'

  // Audio
  else if Ext = '.mp3' then Result := 'audio/mpeg'
  else if Ext = '.wav' then Result := 'audio/wav'
  else if Ext = '.ogg' then Result := 'audio/ogg'
  else if Ext = '.flac' then Result := 'audio/flac'
  else if Ext = '.aac' then Result := 'audio/aac'
  else if Ext = '.wma' then Result := 'audio/x-ms-wma'

  // Fonts
  else if Ext = '.ttf' then Result := 'font/ttf'
  else if Ext = '.otf' then Result := 'font/otf'
  else if Ext = '.woff' then Result := 'font/woff'
  else if Ext = '.woff2' then Result := 'font/woff2'

  else Result := 'application/octet-stream';
end;

procedure TResponse.AddFileStreamContent(const ContentType, Filename: string);
begin
  try
    if not TFile.Exists(Filename) then
      raise Exception.CreateFmt('File not found: %s', [Filename]);
    CleanupSourceFile;
    FSourceFileStream := TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite);
    FSourceFilePath := Filename;
    FSourceFileSize := FSourceFileStream.Size;
    FUseSourceFile := True;
    FStorageMode := csmFile;
    FTotalContentSize := FSourceFileSize;
    if ContentType <> '' then
      FContentType := ContentType
    else
      FContentType := DetectContentTypeFromExtension(Filename);
    SetOrUpdateHeader('Content-Length', IntToStr(FSourceFileSize));
    AddHeader('Content-Disposition', 'attachment; filename="' + ExtractFileName(Filename) + '"');
    AddHeader('Accept-Ranges', 'bytes');
    FContentFinalized := True;
  except
      on E: Exception do
      begin
        Logger.Error('Failed to add file stream content: %s', [E.Message]);
        raise Exception.CreateFmt('Failed to add file stream content: %s', [E.Message]);
      end;
  end;
end;


function TResponse.GetNewTempFilePath(const Extension: string): string;
var
  NewGuid: TGUID;
  GuidStr: string;
  FileName: string;
begin
  if CreateGUID(NewGuid) = S_OK then
    GuidStr := StringReplace(StringReplace(StringReplace(GUIDToString(NewGuid), '{', '', []), '}', '', []), '-', '', [rfReplaceAll])
  else
    GuidStr := IntToStr(Random(MaxInt)) + IntToStr(Random(MaxInt));
  FileName := FormatDateTime('yyyymmdd_hhnnsszzz', Now) + '_' + GuidStr + Extension;
  Result := TPath.Combine(FResponseTempDir, FileName);
end;

procedure TResponse.AddStreamContent(AContentType: string; ASourceStream: TStream);
var
  TempFilePath: string;
begin
  CleanupSourceFile;
  if not Assigned(ASourceStream) or (ASourceStream.Size = 0) then
  begin
    raise Exception.Create('Failed to add file stream content');
    Exit;
  end;
  try
    TempFilePath :=   GetNewTempFilePath('.bin');
    var TempFileStream := TFileStream.Create(TempFilePath, fmCreate);
    try
      ASourceStream.Position := 0;
      TempFileStream.CopyFrom(ASourceStream, ASourceStream.Size);
    finally
      TempFileStream.Free;
    end;
    FSourceFilePath := TempFilePath;
    FSourceFileStream := TFileStream.Create(FSourceFilePath, fmOpenRead or fmShareDenyWrite);
    FSourceFilePath := TPath.GetFileName(TempFilePath);
    FSourceFileSize := FSourceFileStream.Size;
    FUseSourceFile := True;
    FStorageMode := csmFile;
    FTotalContentSize := FSourceFileSize;
    if AContentType <> '' then
      FContentType := AContentType
    else
      FContentType := DetectContentTypeFromExtension(TPath.GetFileName(TempFilePath));
    SetOrUpdateHeader('Content-Type', AContentType);
    SetOrUpdateHeader('Content-Length', IntToStr(FSourceFileStream.Size));
    AddHeader('Content-Disposition', 'attachment; filename="' + TPath.GetFileName(TempFilePath) + '"');
    AddHeader('Accept-Ranges', 'bytes');
    FContentFinalized := True;
 except
    on E: Exception do
    begin
      CleanupSourceFile;
      Logger.Error('Failed to add file stream content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to add file stream content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddFileStreamWithRange(const ContentType, Filename: string; StartPos, Length: Int64);
var
  ActualFileSize: Int64;
  SourceStream: TFileStream;
  RangeData: TBytes;
begin
  try
    if not TFile.Exists(Filename) then
      raise Exception.CreateFmt('File not found: %s', [Filename]);
    SourceStream := TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite);
    try
      ActualFileSize := SourceStream.Size;
      if StartPos < 0 then StartPos := 0;
      if (StartPos >= ActualFileSize) then
        raise Exception.CreateFmt('Invalid start position: %d (file size: %d)', [StartPos, ActualFileSize]);
      if (Length <= 0) or (StartPos + Length > ActualFileSize) then
        Length := ActualFileSize - StartPos;
      SetLength(RangeData, Length);
      SourceStream.Position := StartPos;
      SourceStream.ReadBuffer(RangeData[0], Length);
      CleanupSourceFile;
      FUseSourceFile := False;
      if ContentType <> '' then
        FContentType := ContentType
      else
        FContentType := DetectContentTypeFromExtension(Filename);
      WriteToStorage(RangeData);
      SetOrUpdateHeader('Content-Length', IntToStr(Length));
      SetOrUpdateHeader('Content-Range', Format('bytes %d-%d/%d', [StartPos, StartPos + Length - 1, ActualFileSize]));
      AddHeader('Accept-Ranges', 'bytes');
      SetStatus(hsPartialContent);
      FContentFinalized := True;
    finally
      SourceStream.Free;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Failed to add file range content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to add file range content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddImageContent(const Filename: string);
begin
  try
    AddFileStreamContent(DetectContentTypeFromExtension(Filename), Filename);
    RemoveHeader('Content-Disposition');
    AddHeader('Content-Disposition', 'inline; filename="' + ExtractFileName(Filename) + '"');
    AddHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
    AddHeader('ETag', '"' + IntToStr(FSourceFileSize) + '-' + IntToStr(DateTimeToUnix(TFile.GetLastWriteTime(Filename))) + '"');
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add image content: %s', [E.Message]);
  end;
end;

procedure TResponse.AddDocumentContent(const Filename: string);
begin
  try
    AddFileStreamContent(DetectContentTypeFromExtension(Filename), Filename);
    AddHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    AddHeader('Pragma', 'no-cache');
    AddHeader('Expires', '0');
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add document content: %s', [E.Message]);
  end;
end;

function TResponse.CreateInMemoryFile(const Filename, ContentType: string): TMemoryStream;
begin
  try
    Result := TMemoryStream.Create;
    FInMemoryFiles.Add(Result);
    FCurrentInMemoryFile := Result;
    if ContentType <> '' then
      FContentType := ContentType
    else
      FContentType := DetectContentTypeFromExtension(Filename);
    if Filename <> '' then
      AddHeader('Content-Disposition', 'attachment; filename="' + ExtractFileName(Filename) + '"');
  except
    on E: Exception do
    begin
      Logger.Error('Failed to create in-memory file: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to create in-memory file: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.FinishInMemoryFile;
var
  ContentBytes: TBytes;
begin
  try
    if not Assigned(FCurrentInMemoryFile) then
      raise Exception.Create('No in-memory file to finish');
    SetLength(ContentBytes, FCurrentInMemoryFile.Size);
    FCurrentInMemoryFile.Position := 0;
    FCurrentInMemoryFile.ReadBuffer(ContentBytes[0], FCurrentInMemoryFile.Size);
    WriteToStorage(ContentBytes);
    FinalizeContent;
    FCurrentInMemoryFile := nil;
    var stomod := '';
    if FStorageMode = csmMemory then stomod := 'Memory' else stomod := 'File';
  except
    on E: Exception do
    begin
      Logger.Error('Failed to finish in-memory file: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to finish in-memory file: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.AddInMemoryFileContent(const ContentType: string; MemoryFile: TMemoryStream; const Filename: string);
var
  ContentBytes: TBytes;
begin
  try
    if not Assigned(MemoryFile) then
      raise Exception.Create('MemoryFile cannot be nil');
    if ContentType <> '' then
      FContentType := ContentType
    else if Filename <> '' then
      FContentType := DetectContentTypeFromExtension(Filename)
    else
      FContentType := 'application/octet-stream';
    SetLength(ContentBytes, MemoryFile.Size);
    MemoryFile.Position := 0;
    if MemoryFile.Size > 0 then
       MemoryFile.ReadBuffer(ContentBytes[0], MemoryFile.Size);
    WriteToStorage(ContentBytes);
    FinalizeContent;
    if Filename <> '' then
      AddHeader('Content-Disposition', 'attachment; filename="' + ExtractFileName(Filename) + '"');
  except
    on E: Exception do
    begin
      Logger.Error('Failed to add memory file content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to add memory file content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.BeginMultipart(MultipartType: TMultipartType);
begin
  try
    FIsMultipart := True;
    FMultipartType := MultipartType;
    FMultipartBoundary := GenerateBoundary;
    FMultipartParts.Clear;
    FContentType := GetContentTypeForMultipart(MultipartType) + '; boundary=' + FMultipartBoundary;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to begin multipart: %s', [E.Message]);
  end;
end;

function TResponse.AddMultipartPart: TMultipartPart;
begin
  try
    if not FIsMultipart then
      raise Exception.Create('Not in multipart mode. Call BeginMultipart first.');
    Result := TMultipartPart.Create;
    FMultipartParts.Add(Result);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add multipart part: %s', [E.Message]);
  end;
end;

procedure TResponse.AddMultipartText(const Name, Value: string);
var
  Part: TMultipartPart;
begin
  try
    Part := AddMultipartPart;
    Part.Name := Name;
    Part.ContentType := 'text/plain';
    Part.SetContent(Value);
    Part.AddHeader('Content-Disposition', 'form-data; name="' + Name + '"');
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add multipart text: %s', [E.Message]);
  end;
end;

procedure TResponse.AddMultipartFile(const Name, Filename, ContentType: string; const Content: TBytes);
var
  Part: TMultipartPart;
begin
  try
    Part := AddMultipartPart;
    Part.Name := Name;
    Part.Filename := Filename;
    Part.ContentType := ContentType;
    Part.SetContent(Content);
    Part.AddHeader('Content-Disposition',
      'form-data; name="' + Name + '"; filename="' + Filename + '"');
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to add multipart file: %s', [E.Message]);
  end;
end;

procedure TResponse.EndMultipart;
begin
  try
    if not FIsMultipart then
      raise Exception.Create('Not in multipart mode.');
    BuildMultipartContent;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to end multipart: %s', [E.Message]);
  end;
end;

procedure TResponse.BuildMultipartContent;
var
  ContentStream: TMemoryStream;
  Part: TMultipartPart;
  I, J: Integer;
  FinalContent: TBytes;
  BoundaryBytes, HeaderBytes, EmptyLineBytes, FinalBoundaryBytes: TBytes;
  ContentTypeBytes: TBytes;
  HasContentType: Boolean;
begin
  try
    if FMultipartBuilt then
      Exit;
    ContentStream := TMemoryStream.Create;
    try
      for I := 0 to FMultipartParts.Count - 1 do
      begin
        Part := FMultipartParts[I];
        BoundaryBytes := TEncoding.UTF8.GetBytes('--' + FMultipartBoundary + #13#10);
        ContentStream.WriteBuffer(BoundaryBytes[0], Length(BoundaryBytes));
        for J := 0 to Part.Headers.Count - 1 do
        begin
          HeaderBytes := TEncoding.UTF8.GetBytes(Part.Headers[J] + #13#10);
          ContentStream.WriteBuffer(HeaderBytes[0], Length(HeaderBytes));
        end;
        HasContentType := False;
        for J := 0 to Part.Headers.Count - 1 do
        begin
          if StartsText('Content-Type:', Part.Headers[J]) then
          begin
            HasContentType := True;
            Break;
          end;
        end;
        if not HasContentType then
        begin
          ContentTypeBytes := TEncoding.UTF8.GetBytes('Content-Type: ' + Part.ContentType + #13#10);
          ContentStream.WriteBuffer(ContentTypeBytes[0], Length(ContentTypeBytes));
        end;
        EmptyLineBytes := TEncoding.UTF8.GetBytes(#13#10);
        ContentStream.WriteBuffer(EmptyLineBytes[0], Length(EmptyLineBytes));
        if Length(Part.Content) > 0 then
          ContentStream.WriteBuffer(Part.Content[0], Length(Part.Content));
        ContentStream.WriteBuffer(EmptyLineBytes[0], Length(EmptyLineBytes));
      end;
      FinalBoundaryBytes := TEncoding.UTF8.GetBytes('--' + FMultipartBoundary + '--' + #13#10);
      ContentStream.WriteBuffer(FinalBoundaryBytes[0], Length(FinalBoundaryBytes));
      SetLength(FinalContent, ContentStream.Size);
      ContentStream.Position := 0;
      ContentStream.ReadBuffer(FinalContent[0], ContentStream.Size);
    finally
      ContentStream.Free;
    end;
    WriteToStorage(FinalContent);
    FinalizeContent;
    FMultipartBuilt := True;
    var stomod := '';
    if FStorageMode = csmMemory then stomod := 'Memory' else stomod := 'File';
  except
    on E: Exception do
    begin
      Logger.Error('Failed to build multipart content: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to build multipart content: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.BuildHeaders;
var
  StatusText: string;
  HeaderBuilder: TStringBuilder;
  I: Integer;
begin
  if FHeadersBuilt then
    Exit;
  try
    if not FContentFinalized then
      FinalizeContent;
    var FinalHeaders := TStringList.Create;
    try
      FinalHeaders.AddStrings(FHeaders);
      for I := FinalHeaders.Count - 1 downto 0 do
        if StartsText('Content-Type:', FinalHeaders[I]) then
          FinalHeaders.Delete(I);
      FinalHeaders.Insert(0, 'Content-Type: ' + FContentType);
      for I := FinalHeaders.Count - 1 downto 0 do
        if StartsText('Content-Length:', FinalHeaders[I]) then
          FinalHeaders.Delete(I);
      if (FStatus <> hsNoContent) and (FStatus <> hsNotModified) then
        FinalHeaders.Insert(1, 'Content-Length: ' + IntToStr(FTotalContentSize))
      else
        FinalHeaders.Insert(1, 'Content-Length: 0');
      if FinalHeaders.IndexOfName('Server') = -1 then
         FinalHeaders.Add('Server: GHttpsServerIOCP/2.0');
      if FinalHeaders.IndexOfName('Date') = -1 then
         FinalHeaders.Add('Date: ' + FormatDateTime('ddd, dd mmm yyyy hh:nn:ss', Now, TFormatSettings.Create('en-US')) + ' GMT');
      if FinalHeaders.IndexOfName('Connection') = -1 then
         FinalHeaders.Add('Connection: close');
      if FinalHeaders.IndexOfName('Strict-Transport-Security') = -1 then
         FinalHeaders.Add('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
      HeaderBuilder := TStringBuilder.Create;
      try
        StatusText := GetStatusText(FStatus);
        HeaderBuilder.AppendFormat('HTTP/1.1 %d %s'#13#10, [Integer(FStatus), StatusText]);
        for I := 0 to FinalHeaders.Count - 1 do
        begin
          HeaderBuilder.AppendLine(FinalHeaders[I]);
        end;
        HeaderBuilder.AppendLine;
        FHeadersData := TEncoding.UTF8.GetBytes(HeaderBuilder.ToString);
        FHeadersBuilt := True;
      finally
        HeaderBuilder.Free;
      end;
    finally
      FinalHeaders.Free;
    end;
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to build headers: %s', [E.Message]);
  end;
end;

procedure TResponse.BuildContentBytes;
begin
  try
    if FContentBytesBuilt or (FStorageMode = csmFile) then
      Exit;
    FContentBytesBuilt := True;
  except
    on E: Exception do
    begin
      Logger.Error('Failed to build content bytes: %s', [E.Message]);
      raise Exception.CreateFmt('Failed to build content bytes: %s', [E.Message]);
    end;
  end;
end;

function TResponse.ReadNextChunk(Buffer: PByte; BufferSize: Integer): Integer;
var
  BytesToCopy: Int64 ;
  RemainingHeaderBytes: Integer;
begin
  Result := 0;
  try
    if not FHeadersSent then
    begin
      if not FHeadersBuilt then
        BuildHeaders;
      if Length(FHeadersData) > 0 then
      begin
        RemainingHeaderBytes := Length(FHeadersData) - FHeaderPosition;
        if RemainingHeaderBytes > 0 then
        begin
          BytesToCopy := Min(RemainingHeaderBytes, BufferSize);
          Move(FHeadersData[FHeaderPosition], Buffer^, BytesToCopy);
          Inc(FHeaderPosition, BytesToCopy);
          Result := BytesToCopy;
          if FHeaderPosition >= Length(FHeadersData) then
            FHeadersSent := True;
          Exit;
        end;
      end;
    end;
    if (FStatus = hsNoContent) or (FStatus = hsNotModified) then
    begin
      Result := 0;
      Exit;
    end;
    if FIsMultipart and not FMultipartBuilt then
      BuildMultipartContent;
    Result := ReadFromStorage(Buffer, BufferSize);
  except
    on E: Exception do
    begin
      Result := 0;
      Logger.Error('Error in ReadNextChunk: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.UpdateSentBytes(BytesSent: Integer);
begin
  try
    Inc(FBytesSent, BytesSent);
  except
    on E: Exception do
    begin
      Logger.Error('Error updating sent bytes: %s', [E.Message]);
    end;
  end;
end;

function TResponse.IsComplete: Boolean;
begin
  try
    if not FHeadersSent then
    begin
      Result := False;
      Exit;
    end;
    if (FStatus = hsNoContent) or (FStatus = hsNotModified) then
    begin
      Result := True;
      Exit;
    end;
    if FUseSourceFile then
    begin
      Result := (FContentPosition >= FSourceFileSize);
    end
    else
    begin
      case FStorageMode of
        csmMemory:
          begin
            if not FContentBytesBuilt then
              BuildContentBytes;
            Result := (FContentPosition >= Length(FContentBytes));
          end;
        csmFile:
          begin
            Result := (FContentPosition >= FTotalContentSize);
          end;
      else
        Result := True;
      end;
    end;

  except
    on E: Exception do
    begin
      Result := True;
      Logger.Error('Error checking completion: %s', [E.Message]);
    end;
  end;
end;

procedure TResponse.SetBadRequest(const Message: string);
begin
  SetError(hsBadRequest, Message);
end;

procedure TResponse.SetNotFound(const Message: string);
begin
  SetError(hsNotFound, Message);
end;

procedure TResponse.SetInternalServerError(const Message: string);
begin
  SetError(hsInternalServerError, Message);
end;

procedure TResponse.SetUnauthorized(const Message: string);
begin
  SetError(hsUnauthorized, Message);
end;

procedure TResponse.SetForbidden(const Message: string);
begin
  SetError(hsForbidden, Message);
end;

procedure TResponse.SetMethodNotAllowed(const Message: string);
begin
  SetError(hsMethodNotAllowed, Message);
end;

procedure TResponse.SetError(Status: THttpStatus; const Message: string = '');
var
  ErrorHTML: string;
  StatusText: string;
  ErrorMessage: string;
begin
  try
    StatusText := GetStatusText(Status);
    ErrorMessage := Message;
    if ErrorMessage = '' then
      ErrorMessage := StatusText;

    ErrorHTML := Format(
      '<!DOCTYPE html>'#13#10 +
      '<html lang="en">'#13#10 +
      '<head>'#13#10 +
      '  <meta charset="UTF-8">'#13#10 +
      '  <title>%d %s</title>'#13#10 +
      '  <style>body{font-family:Arial,sans-serif;margin:40px;text-align:center;background:#f5f5f5;color:#333;}</style>'#13#10 +
      '</head>'#13#10 +
      '<body>'#13#10 +
      '  <h1>%d %s</h1>'#13#10 +
      '  <p>%s</p>'#13#10 +
      '  <hr>'#13#10 +
      '  <p><small>GHttpsServerIOCP Server</small></p>'#13#10 +
      '</body>'#13#10 +
      '</html>',
      [Integer(Status), StatusText, Integer(Status), StatusText, ErrorMessage]);

    SetStatus(Status);
    AddHTMLContent(ErrorHTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set error response: %s', [E.Message]);
  end;
end;

procedure TResponse.SetRedirect(const URL: string; Permanent: Boolean = False);
var
  RedirectHTML: string;
  Status: THttpStatus;
begin
  try
    if Permanent then
      Status := hsMovedPermanently
    else
      Status := hsFound;

    RedirectHTML := Format(
      '<!DOCTYPE html>'#13#10 +
      '<html lang="en">'#13#10 +
      '<head>'#13#10 +
      '  <meta charset="UTF-8">'#13#10 +
      '  <meta http-equiv="refresh" content="0;url=%s">'#13#10 +
      '  <title>Redirecting...</title>'#13#10 +
      '  <style>body{font-family:Arial,sans-serif;margin:40px;text-align:center;background:#f5f5f5;}</style>'#13#10 +
      '</head>'#13#10 +
      '<body>'#13#10 +
      '  <h1>Redirecting...</h1>'#13#10 +
      '  <p>If you are not redirected automatically, <a href="%s">click here</a>.</p>'#13#10 +
      '</body>'#13#10 +
      '</html>',
      [URL, URL]);

    SetStatus(Status);
    AddHeader('Location', URL);
    AddHTMLContent(RedirectHTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set redirect: %s', [E.Message]);
  end;
end;

procedure TResponse.SetMovedPermanently(const URL: string);
begin
  try
    SetRedirect(URL, True);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set permanent redirect: %s', [E.Message]);
  end;
end;

procedure TResponse.SetFound(const URL: string);
begin
  try
    SetRedirect(URL, False);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set temporary redirect: %s', [E.Message]);
  end;
end;

procedure TResponse.SetSeeOther(const URL: string);
var
  RedirectHTML: string;
  SafeURL: string;
begin
  try
    if Trim(URL) = '' then
      raise Exception.Create('Redirect URL cannot be empty');
    SafeURL := StringReplace(URL, '&', '&amp;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '<', '&lt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '>', '&gt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '"', '&quot;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '''', '&#39;', [rfReplaceAll]);
    RedirectHTML := Format(
      '<!DOCTYPE html>'#13#10 +
      '<html><head><title>See Other</title></head>'#13#10 +
      '<body><h1>See Other</h1><p>The resource has been moved to: <a href="%s">%s</a></p></body>'#13#10 +
      '</html>', [URL, SafeURL]);
    SetStatus(hsSeeOther);
    AddHeader('Location', URL);
    AddHeader('Cache-Control', 'no-cache');
    AddHTMLContent(RedirectHTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set See Other redirect: %s', [E.Message]);
  end;
end;

procedure TResponse.SetTemporaryRedirect(const URL: string);
var
  RedirectHTML: string;
  SafeURL: string;
begin
  try
    if Trim(URL) = '' then
      raise Exception.Create('Redirect URL cannot be empty');
    SafeURL := StringReplace(URL, '&', '&amp;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '<', '&lt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '>', '&gt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '"', '&quot;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '''', '&#39;', [rfReplaceAll]);
    RedirectHTML := Format(
      '<!DOCTYPE html>'#13#10 +
      '<html><head><title>Temporary Redirect</title></head>'#13#10 +
      '<body><h1>Temporary Redirect</h1><p>The resource has been temporarily moved to: <a href="%s">%s</a></p></body>'#13#10 +
      '</html>', [URL, SafeURL]);

    SetStatus(hsTemporaryRedirect);
    AddHeader('Location', URL);
    AddHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    AddHTMLContent(RedirectHTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set temporary redirect: %s', [E.Message]);
  end;
end;

procedure TResponse.Write(const Data: TBytes);
begin
  WriteToStorage(Data);
end;

procedure TResponse.Write(const Data: string);
var
  Bytes: TBytes;
begin
  Bytes := TEncoding.UTF8.GetBytes(Data);
  WriteToStorage(Bytes);
end;

procedure TResponse.SetPermanentRedirect(const URL: string);
var
  RedirectHTML: string;
  SafeURL: string;
begin
  try
    if Trim(URL) = '' then
      raise Exception.Create('Redirect URL cannot be empty');
    SafeURL := StringReplace(URL, '&', '&amp;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '<', '&lt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '>', '&gt;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '"', '&quot;', [rfReplaceAll]);
    SafeURL := StringReplace(SafeURL, '''', '&#39;', [rfReplaceAll]);
    RedirectHTML := Format(
      '<!DOCTYPE html>'#13#10 +
      '<html><head><title>Permanent Redirect</title></head>'#13#10 +
      '<body><h1>Permanent Redirect</h1><p>The resource has been permanently moved to: <a href="%s">%s</a></p></body>'#13#10 +
      '</html>', [URL, SafeURL]);
    SetStatus(hsPermanentRedirect);
    AddHeader('Location', URL);
    AddHeader('Cache-Control', 'public, max-age=31536000');
    AddHTMLContent(RedirectHTML);
  except
    on E: Exception do
      raise Exception.CreateFmt('Failed to set permanent redirect: %s', [E.Message]);
  end;
end;

end.
