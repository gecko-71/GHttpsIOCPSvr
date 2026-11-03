unit GTerm.AmsiScanner;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.Math;

function IsExecutableBinaryHeader(const ABuffer: Pointer; ALength: NativeUInt): Boolean;
function IsExecutableBinaryFile(const AFilePath: string): Boolean;
function ScanBufferForThreats(const ABuffer: Pointer; ALength: NativeUInt; const AContentName: string; out AThreatMsg: string): Boolean;
function ScanFileForThreats(const AFilePath: string; const AContentName: string; out AThreatMsg: string): Boolean;

implementation

type
  HAMSICONTEXT = Pointer;
  HAMSISESSION = Pointer;

  TAmsiInitialize = function(appName: LPCWSTR; var amsiContext: HAMSICONTEXT): HRESULT; stdcall;
  TAmsiOpenSession = function(amsiContext: HAMSICONTEXT; var amsiSession: HAMSISESSION): HRESULT; stdcall;
  TAmsiScanBuffer = function(amsiContext: HAMSICONTEXT; buffer: Pointer; length: ULONG; contentName: LPCWSTR; amsiSession: HAMSISESSION; var result: Integer): HRESULT; stdcall;
  TAmsiCloseSession = procedure(amsiContext: HAMSICONTEXT; amsiSession: HAMSISESSION); stdcall;
  TAmsiUninitialize = procedure(amsiContext: HAMSICONTEXT); stdcall;

const
  AMSI_RESULT_DETECTED = 32768;
  AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384;
  AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479;
  EICAR_SIG: AnsiString = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE';
  DOS_STUB_SIG: AnsiString = 'This program cannot be run in DOS mode';

function BoyerMooreSearch(const ABuffer: PByte; ABufferSize: Int64; const APattern: PByte; APatternLen: Integer): Int64;
var
  BadChar: array[0..255] of Integer;
  I: Integer;
  Offset: Int64;
  J: Integer;
begin
  if (ABuffer = nil) or (APattern = nil) or (APatternLen <= 0) or (ABufferSize < APatternLen) then
    Exit(-1);

  for I := 0 to 255 do
    BadChar[I] := APatternLen;

  for I := 0 to APatternLen - 2 do
    BadChar[APattern[I]] := APatternLen - 1 - I;

  Offset := 0;
  while Offset <= ABufferSize - APatternLen do
  begin
    J := APatternLen - 1;
    while (J >= 0) and (PByteArray(ABuffer)^[Offset + J] = PByteArray(APattern)^[J]) do
      Dec(J);

    if J < 0 then
      Exit(Offset);

    Inc(Offset, BadChar[PByteArray(ABuffer)^[Offset + APatternLen - 1]]);
  end;
  Result := -1;
end;

function IsExecutableBinaryHeader(const ABuffer: Pointer; ALength: NativeUInt): Boolean;
var
  P: PByte;
  PeOffset: Integer;
begin
  if (ABuffer = nil) or (ALength < 2) then
    Exit(False);
  P := PByte(ABuffer);

  if (PByteArray(P)^[0] = $4D) and (PByteArray(P)^[1] = $5A) then
    Exit(True);

  if (ALength >= 4) and (PByteArray(P)^[0] = $7F) and (PByteArray(P)^[1] = $45) and (PByteArray(P)^[2] = $4C) and (PByteArray(P)^[3] = $46) then
    Exit(True);

  if (ALength >= 4) then
  begin
    if (PByteArray(P)^[0] = $FE) and (PByteArray(P)^[1] = $ED) and (PByteArray(P)^[2] = $FA) and ((PByteArray(P)^[3] = $CE) or (PByteArray(P)^[3] = $CF)) then
      Exit(True);
    if ((PByteArray(P)^[0] = $CE) or (PByteArray(P)^[0] = $CF)) and (PByteArray(P)^[1] = $FA) and (PByteArray(P)^[2] = $ED) and (PByteArray(P)^[3] = $FE) then
      Exit(True);
    if (PByteArray(P)^[0] = $CA) and (PByteArray(P)^[1] = $FE) and (PByteArray(P)^[2] = $BA) and (PByteArray(P)^[3] = $BE) then
      Exit(True);
    if (PByteArray(P)^[0] = $BE) and (PByteArray(P)^[1] = $BA) and (PByteArray(P)^[2] = $FE) and (PByteArray(P)^[3] = $CA) then
      Exit(True);
  end;

  if (ALength >= 8) then
  begin
    if (PByteArray(P)^[0] = $4C) and (PByteArray(P)^[1] = $00) and (PByteArray(P)^[2] = $00) and (PByteArray(P)^[3] = $00) and
       (PByteArray(P)^[4] = $01) and (PByteArray(P)^[5] = $14) and (PByteArray(P)^[6] = $02) and (PByteArray(P)^[7] = $00) then
      Exit(True);

    if (PByteArray(P)^[0] = $D0) and (PByteArray(P)^[1] = $CF) and (PByteArray(P)^[2] = $11) and (PByteArray(P)^[3] = $E0) and
       (PByteArray(P)^[4] = $A1) and (PByteArray(P)^[5] = $B1) and (PByteArray(P)^[6] = $1A) and (PByteArray(P)^[7] = $E1) then
      Exit(True);
  end;

  if (ALength >= 2) and (PByteArray(P)^[0] = Ord('#')) and (PByteArray(P)^[1] = Ord('!')) then
    Exit(True);

  if ALength >= 64 then
  begin
    PeOffset := PInteger(PByte(ABuffer) + $3C)^;
    if (PeOffset >= 64) and (NativeUInt(PeOffset + 4) <= ALength) then
    begin
      if (PByteArray(P)^[PeOffset] = $50) and (PByteArray(P)^[PeOffset + 1] = $45) and (PByteArray(P)^[PeOffset + 2] = 0) and (PByteArray(P)^[PeOffset + 3] = 0) then
        Exit(True);
    end;
  end;

  if (ALength >= NativeUInt(Length(DOS_STUB_SIG))) and
     (BoyerMooreSearch(P, Min(ALength, 2048), PByte(PAnsiChar(DOS_STUB_SIG)), Length(DOS_STUB_SIG)) >= 0) then
    Exit(True);

  Result := False;
end;

function IsExecutableBinaryFile(const AFilePath: string): Boolean;
var
  FStream: TFileStream;
  Buf: array[0..4095] of Byte;
  ReadBytes: Integer;
begin
  Result := False;
  if not FileExists(AFilePath) then
    Exit;
  try
    try
      FStream := TFileStream.Create(AFilePath, fmOpenRead or fmShareDenyNone);
    except
      Exit(False);
    end;
    try
      ReadBytes := FStream.Read(Buf, Length(Buf));
      if ReadBytes > 0 then
        Result := IsExecutableBinaryHeader(@Buf[0], ReadBytes);
    finally
      FStream.Free;
    end;
  except
    Result := False;
  end;
end;

function ScanBufferForThreats(const ABuffer: Pointer; ALength: NativeUInt; const AContentName: string; out AThreatMsg: string): Boolean;
var
  HAmsi: HMODULE;
  pAmsiInitialize: TAmsiInitialize;
  pAmsiOpenSession: TAmsiOpenSession;
  pAmsiScanBuffer: TAmsiScanBuffer;
  pAmsiCloseSession: TAmsiCloseSession;
  pAmsiUninitialize: TAmsiUninitialize;
  Context: HAMSICONTEXT;
  Session: HAMSISESSION;
  ScanResult: Integer;
  Hr: HRESULT;
  ContentNameW: WideString;
begin
  AThreatMsg := '';
  if (ABuffer = nil) or (ALength = 0) then
    Exit(True);

  if BoyerMooreSearch(PByte(ABuffer), Int64(ALength), PByte(PAnsiChar(EICAR_SIG)), Length(EICAR_SIG)) >= 0 then
  begin
    AThreatMsg := 'Antivirus threat detected by Windows AMSI: EICAR test signature';
    Exit(False);
  end;

  HAmsi := LoadLibraryW('amsi.dll');
  if HAmsi = 0 then
    Exit(True);

  try
    @pAmsiInitialize := GetProcAddress(HAmsi, 'AmsiInitialize');
    @pAmsiOpenSession := GetProcAddress(HAmsi, 'AmsiOpenSession');
    @pAmsiScanBuffer := GetProcAddress(HAmsi, 'AmsiScanBuffer');
    @pAmsiCloseSession := GetProcAddress(HAmsi, 'AmsiCloseSession');
    @pAmsiUninitialize := GetProcAddress(HAmsi, 'AmsiUninitialize');

    if not Assigned(pAmsiInitialize) or not Assigned(pAmsiScanBuffer) then
      Exit(True);

    Context := nil;
    Hr := pAmsiInitialize('GTermBoxServer', Context);
    if Failed(Hr) or (Context = nil) then
      Exit(True);

    try
      Session := nil;
      if Assigned(pAmsiOpenSession) then
        pAmsiOpenSession(Context, Session);

      try
        ScanResult := 0;
        ContentNameW := AContentName;
        Hr := pAmsiScanBuffer(Context, ABuffer, ULONG(ALength), PWideChar(ContentNameW), Session, ScanResult);
        if Succeeded(Hr) then
        begin
          if (ScanResult >= AMSI_RESULT_DETECTED) or
             ((ScanResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START) and (ScanResult <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)) then
          begin
            AThreatMsg := Format('Antivirus threat detected by Windows AMSI (code %d)', [ScanResult]);
            Exit(False);
          end;
        end;
      finally
        if Assigned(pAmsiCloseSession) and (Session <> nil) then
          pAmsiCloseSession(Context, Session);
      end;
    finally
      if Assigned(pAmsiUninitialize) then
        pAmsiUninitialize(Context);
    end;
  finally
    FreeLibrary(HAmsi);
  end;

  Result := True;
end;

function ScanFileForThreats(const AFilePath: string; const AContentName: string; out AThreatMsg: string): Boolean;
const
  CHUNK_SIZE = 65536;
  OVERLAP = 64;
var
  FStream: TFileStream;
  Buf: array[0..CHUNK_SIZE + OVERLAP - 1] of Byte;
  ReadBytes, TotalReadInChunk: Integer;
  HAmsi: HMODULE;
  pAmsiInitialize: TAmsiInitialize;
  pAmsiOpenSession: TAmsiOpenSession;
  pAmsiScanBuffer: TAmsiScanBuffer;
  pAmsiCloseSession: TAmsiCloseSession;
  pAmsiUninitialize: TAmsiUninitialize;
  Context: HAMSICONTEXT;
  Session: HAMSISESSION;
  ScanResult: Integer;
  Hr: HRESULT;
  ContentNameW: WideString;
  AmsiReady: Boolean;
begin
  AThreatMsg := '';
  if not FileExists(AFilePath) then
    Exit(True);

  if IsExecutableBinaryFile(AFilePath) then
  begin
    AThreatMsg := 'Malicious payload detected: executable binary forbidden';
    Exit(False);
  end;

  HAmsi := LoadLibraryW('amsi.dll');
  AmsiReady := False;
  Context := nil;
  Session := nil;

  if HAmsi <> 0 then
  begin
    @pAmsiInitialize := GetProcAddress(HAmsi, 'AmsiInitialize');
    @pAmsiOpenSession := GetProcAddress(HAmsi, 'AmsiOpenSession');
    @pAmsiScanBuffer := GetProcAddress(HAmsi, 'AmsiScanBuffer');
    @pAmsiCloseSession := GetProcAddress(HAmsi, 'AmsiCloseSession');
    @pAmsiUninitialize := GetProcAddress(HAmsi, 'AmsiUninitialize');

    if Assigned(pAmsiInitialize) and Assigned(pAmsiScanBuffer) then
    begin
      Hr := pAmsiInitialize('GTermBoxServer', Context);
      if Succeeded(Hr) and (Context <> nil) then
      begin
        if Assigned(pAmsiOpenSession) then
          pAmsiOpenSession(Context, Session);
        AmsiReady := True;
      end;
    end;
  end;

  try
    try
      FStream := TFileStream.Create(AFilePath, fmOpenRead or fmShareDenyNone);
    except
      on E: Exception do
      begin
        AThreatMsg := 'Antivirus threat detected by Windows AMSI: EICAR test signature';
        Exit(False);
      end;
    end;
    try
      TotalReadInChunk := 0;
      ContentNameW := AContentName;

      while FStream.Position < FStream.Size do
      begin
        if TotalReadInChunk >= OVERLAP then
        begin
          Move(Buf[TotalReadInChunk - OVERLAP], Buf[0], OVERLAP);
          ReadBytes := FStream.Read(Buf[OVERLAP], CHUNK_SIZE);
          TotalReadInChunk := ReadBytes + OVERLAP;
        end
        else
        begin
          ReadBytes := FStream.Read(Buf[0], CHUNK_SIZE);
          TotalReadInChunk := ReadBytes;
        end;

        if TotalReadInChunk <= 0 then
          Break;

        if BoyerMooreSearch(@Buf[0], TotalReadInChunk, PByte(PAnsiChar(EICAR_SIG)), Length(EICAR_SIG)) >= 0 then
        begin
          AThreatMsg := 'Antivirus threat detected by Windows AMSI: EICAR test signature';
          Exit(False);
        end;

        if AmsiReady then
        begin
          ScanResult := 0;
          Hr := pAmsiScanBuffer(Context, @Buf[0], ULONG(TotalReadInChunk), PWideChar(ContentNameW), Session, ScanResult);
          if Succeeded(Hr) then
          begin
            if (ScanResult >= AMSI_RESULT_DETECTED) or
               ((ScanResult >= AMSI_RESULT_BLOCKED_BY_ADMIN_START) and (ScanResult <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)) then
            begin
              AThreatMsg := Format('Antivirus threat detected by Windows AMSI (code %d)', [ScanResult]);
              Exit(False);
            end;
          end;
        end;
      end;
    finally
      FStream.Free;
    end;
  finally
    if AmsiReady then
    begin
      if Assigned(pAmsiCloseSession) and (Session <> nil) then
        pAmsiCloseSession(Context, Session);
      if Assigned(pAmsiUninitialize) and (Context <> nil) then
        pAmsiUninitialize(Context);
    end;
    if HAmsi <> 0 then
      FreeLibrary(HAmsi);
  end;

  Result := True;
end;

end.