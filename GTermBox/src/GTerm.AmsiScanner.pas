unit GTerm.AmsiScanner;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes;

function IsExecutableBinaryHeader(const ABuffer: Pointer; ALength: NativeUInt): Boolean;
function ScanBufferForThreats(const ABuffer: Pointer; ALength: NativeUInt; const AContentName: string; out AThreatMsg: string): Boolean;

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

function IsExecutableBinaryHeader(const ABuffer: Pointer; ALength: NativeUInt): Boolean;
var
  P: PByte;
begin
  if (ABuffer = nil) or (ALength < 2) then
    Exit(False);
  P := PByte(ABuffer);
  if (P[0] = $4D) and (P[1] = $5A) then
    Exit(True);
  if (ALength >= 4) and (P[0] = $7F) and (P[1] = $45) and (P[2] = $4C) and (P[3] = $46) then
    Exit(True);
  Result := False;
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
  PAnsi: PAnsiChar;
  I: Int64;
  MaxLen: Int64;
  FoundEicar: Boolean;
const
  EICAR_SIG = 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE';
begin
  AThreatMsg := '';
  if (ABuffer = nil) or (ALength = 0) then
    Exit(True);

  if Int64(ALength) >= Length(EICAR_SIG) then
  begin
    PAnsi := PAnsiChar(ABuffer);
    FoundEicar := False;
    MaxLen := Int64(ALength) - Length(EICAR_SIG);
    for I := 0 to MaxLen do
    begin
      if (PAnsi[I] = 'E') and (PAnsi[I + 1] = 'I') and (PAnsi[I + 2] = 'C') and (PAnsi[I + 3] = 'A') and (PAnsi[I + 4] = 'R') then
      begin
        if CompareMem(@PAnsi[I], PAnsiChar(EICAR_SIG), Length(EICAR_SIG)) then
        begin
          FoundEicar := True;
          Break;
        end;
      end;
    end;
    if FoundEicar then
    begin
      AThreatMsg := 'Antivirus threat detected by Windows AMSI: EICAR test signature';
      Exit(False);
    end;
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

end.
