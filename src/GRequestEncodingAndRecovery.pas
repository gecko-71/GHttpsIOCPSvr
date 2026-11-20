unit GRequestEncodingAndRecovery;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  System.ZLib,
  GLogger,
  GRequestBody,
  GRequestTypes;

type
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

implementation

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
  if LowerEncoding = 'gzip' then
    Result := ceGzip
  else if LowerEncoding = 'deflate' then
    Result := ceDeflate
  else if LowerEncoding = 'compress' then
    Result := ceCompress
  else if LowerEncoding = 'br' then
    Result := ceBrotli
  else if LowerEncoding = 'identity' then
    Result := ceIdentity
  else
    Result := ceNone;
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
const
  MAX_DECOMPRESSED_SIZE = 4 * 1024 * 1024;
var
  InStream: TBytesStream;
  OutStream: TBytesStream;
  Decompressor: TZDecompressionStream;
  Buffer: array[0..65535] of Byte;
  BytesRead: Integer;
  TotalRead: Int64;
begin
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  try
    InStream := TBytesStream.Create(Data);
    try
      OutStream := TBytesStream.Create;
      try
        Decompressor := TZDecompressionStream.Create(InStream, 15 + 16);
        try
          TotalRead := 0;
          repeat
            BytesRead := Decompressor.Read(Buffer[0], SizeOf(Buffer));
            if BytesRead > 0 then
            begin
              TotalRead := TotalRead + BytesRead;
              if TotalRead > MAX_DECOMPRESSED_SIZE then
              begin
                SetLength(Result, 0);
                Exit;
              end;
              OutStream.WriteBuffer(Buffer[0], BytesRead);
            end;
          until BytesRead <= 0;
        finally
          Decompressor.Free;
        end;
        Result := Copy(OutStream.Bytes, 0, OutStream.Size);
      finally
        OutStream.Free;
      end;
    finally
      InStream.Free;
    end;
  except
    on E: Exception do
      SetLength(Result, 0);
  end;
end;

function TContentEncodingHandler.DecompressDeflate(const Data: TBytes): TBytes;
var
  InStream: TBytesStream;
  OutStream: TBytesStream;
  Decompressor: TZDecompressionStream;
begin
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  try
    InStream := TBytesStream.Create(Data);
    try
      OutStream := TBytesStream.Create;
      try
        Decompressor := TZDecompressionStream.Create(InStream, 15);
        try
          OutStream.CopyFrom(Decompressor, 0);
        finally
          Decompressor.Free;
        end;
        Result := Copy(OutStream.Bytes, 0, OutStream.Size);
      finally
        OutStream.Free;
      end;
    finally
      InStream.Free;
    end;
  except
    on E: Exception do
    begin
      try
        InStream := TBytesStream.Create(Data);
        try
          OutStream := TBytesStream.Create;
          try
            Decompressor := TZDecompressionStream.Create(InStream, -15);
            try
              OutStream.CopyFrom(Decompressor, 0);
            finally
              Decompressor.Free;
            end;
            Result := Copy(OutStream.Bytes, 0, OutStream.Size);
          finally
            OutStream.Free;
          end;
        finally
          InStream.Free;
        end;
      except
        SetLength(Result, Length(Data));
        Move(Data[0], Result[0], Length(Data));
      end;
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
    on E: Exception do
      Logger.Warn('Failed to log recovery attempt: ' + E.Message);
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
    if Assigned(FRecoveryActions) then
      FRecoveryActions.Clear;
    if Assigned(FErrorLog) then
      FErrorLog.Clear;
    FRecoveryAttempts := 0;
  except
    on E: Exception do
      Logger.Warn('Failed to clear request recovery: ' + E.Message);
  end;
end;

end.
