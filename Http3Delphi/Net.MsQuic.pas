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
unit Net.MsQuic;

interface

uses
  System.SysUtils, System.Classes, Winapi.Windows, Winapi.Winsock2, WinApi.MsQuic, WinApiAdditions;

type
  EMsQuicException = class(Exception)
  private
    FStatus: QUIC_STATUS;
  public
    constructor Create(const Msg: string; Status: QUIC_STATUS);
    property Status: QUIC_STATUS read FStatus;
  end;

  procedure CheckQuicStatus(Status: QUIC_STATUS; const ContextMsg: string = '');

type
  TMsQuicBase = class
  protected
    FApi: PQUIC_API_TABLE;
    FHandle: HQUIC;
    procedure CheckHandle;
  public
    constructor Create(Api: PQUIC_API_TABLE);
    destructor Destroy; override;
    property Handle: HQUIC read FHandle;
    property Api: PQUIC_API_TABLE read FApi;
  end;

  TMsQuicRegistration = class(TMsQuicBase)
  public
    constructor Create(Api: PQUIC_API_TABLE; const AppName: string; ExecutionProfile: ULONG = QUIC_EXECUTION_PROFILE_LOW_LATENCY);
    destructor Destroy; override;
    procedure Shutdown(Flags: ULONG = 1; ErrorCode: UInt64 = 0);
  end;

  TMsQuicConfiguration = class(TMsQuicBase)
  private
    FServerCertStore: HCERTSTORE;
  public
    constructor Create(Reg: TMsQuicRegistration; const AlpnList: TArray<string>; ApiVersion: Integer = 2);
    destructor Destroy; override;
    procedure LoadCredential(const CredConfig: PQUIC_CREDENTIAL_CONFIG);
    procedure LoadCredentialFromHash(const HashHex: string; const StoreName: string = 'My');
    procedure LoadCredentialFromContext(CertContext: Pointer);
    property ServerCertStore: HCERTSTORE read FServerCertStore write FServerCertStore;
  end;

  TMsQuicListener = class;
  TMsQuicConnection = class;
  TMsQuicStream = class;

  TQuicListenerNewConnectionEvent = procedure(Sender: TMsQuicListener; Connection: HQUIC) of object;

  TMsQuicListener = class(TMsQuicBase)
  private
    FOnNewConnection: TQuicListenerNewConnectionEvent;
    FStopEvent: THandle;
    function InternalHandleEvent(Event: PQUIC_LISTENER_EVENT): QUIC_STATUS;
  public
    constructor Create(Reg: TMsQuicRegistration);
    destructor Destroy; override;
    procedure Start(const AlpnList: TArray<string>; Port: Word = 0);
    procedure StopAndWait(TimeoutMs: DWORD = 5000);
    procedure Stop;
    property OnNewConnection: TQuicListenerNewConnectionEvent read FOnNewConnection write FOnNewConnection;
  end;

  TQuicConnectionConnectedEvent = procedure(Sender: TMsQuicConnection) of object;
  TQuicConnectionShutdownEvent = procedure(Sender: TMsQuicConnection) of object;
  TQuicConnectionPeerStreamStartedEvent = procedure(Sender: TMsQuicConnection; Stream: HQUIC; Flags: ULONG) of object;

  TMsQuicConnection = class(TMsQuicBase)
  private
    FOnConnected: TQuicConnectionConnectedEvent;
    FOnShutdown: TQuicConnectionShutdownEvent;
    FOnPeerStreamStarted: TQuicConnectionPeerStreamStartedEvent;
    function InternalHandleEvent(Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS;
  public
    constructor Create(Reg: TMsQuicRegistration); overload;
    constructor Create(Api: PQUIC_API_TABLE; ConnectionHandle: HQUIC); overload;
    destructor Destroy; override;
    procedure Start(Config: TMsQuicConfiguration; const ServerName: string; ServerPort: Word);
    procedure SetConfiguration(Config: TMsQuicConfiguration);
    procedure Shutdown(ErrorCode: UInt64 = 0);
    property OnConnected: TQuicConnectionConnectedEvent read FOnConnected write FOnConnected;
    property OnShutdown: TQuicConnectionShutdownEvent read FOnShutdown write FOnShutdown;
    property OnPeerStreamStarted: TQuicConnectionPeerStreamStartedEvent read FOnPeerStreamStarted write FOnPeerStreamStarted;
  end;

  TQuicStreamReceiveEvent = procedure(Sender: TMsQuicStream; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG) of object;
  TQuicStreamSendCompleteEvent = procedure(Sender: TMsQuicStream; Canceled: Boolean; Context: Pointer) of object;
  TQuicStreamShutdownCompleteEvent = procedure(Sender: TMsQuicStream) of object;

  TMsQuicStream = class(TMsQuicBase)
  private
    FConnection: TMsQuicConnection;
    FOnReceive: TQuicStreamReceiveEvent;
    FOnSendComplete: TQuicStreamSendCompleteEvent;
    FOnShutdownComplete: TQuicStreamShutdownCompleteEvent;
    FUserData: Pointer;
    function InternalHandleEvent(Event: PQUIC_STREAM_EVENT): QUIC_STATUS;
  public
    constructor Create(Connection: TMsQuicConnection; Flags: ULONG = QUIC_STREAM_OPEN_FLAG_NONE); overload;
    constructor Create(Api: PQUIC_API_TABLE; StreamHandle: HQUIC); overload;
    destructor Destroy; override;
    procedure Start(Flags: ULONG = QUIC_STREAM_START_FLAG_NONE);
    procedure Shutdown(Flags: ULONG; ErrorCode: UInt64 = 0);
    procedure Send(Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG; Context: Pointer = nil);
    function GetID: UInt64;
    procedure Detach;
    property Connection: TMsQuicConnection read FConnection write FConnection;
    property OnReceive: TQuicStreamReceiveEvent read FOnReceive write FOnReceive;
    property OnSendComplete: TQuicStreamSendCompleteEvent read FOnSendComplete write FOnSendComplete;
    property OnShutdownComplete: TQuicStreamShutdownCompleteEvent read FOnShutdownComplete write FOnShutdownComplete;
    property UserData: Pointer read FUserData write FUserData;
  end;

implementation

uses Quick.Logger;

function StaticListenerCallback(Listener: HQUIC; Context: Pointer; Event: PQUIC_LISTENER_EVENT): QUIC_STATUS; cdecl;
var Obj: TMsQuicListener;
begin
  Logger.Info(Format('[LOG-MSQUIC] StaticListenerCallback called! Context=%p, EventId=%d', [Context, Event.EventId]));
  if Context = nil then
    Exit(QUIC_STATUS_SUCCESS);
  Obj := TMsQuicListener(Context);
  try
    Result := Obj.InternalHandleEvent(Event);
  except
    on E: Exception do
    begin
      Logger.Error('[LOG-MSQUIC] StaticListenerCallback EXCEPTION: ' + E.Message);
      Result := QUIC_STATUS_SUCCESS;
    end;
  end;
end;

function StaticStreamCallback(Stream: HQUIC; Context: Pointer; Event: PQUIC_STREAM_EVENT): QUIC_STATUS; cdecl;
var Obj: TMsQuicStream;
begin
  if Context = nil then
    Exit(QUIC_STATUS_SUCCESS);
  Obj := TMsQuicStream(Context);
  try
    Result := Obj.InternalHandleEvent(Event);
  except
    on E: Exception do
    begin
      Writeln(Format('[LOG-MSQUIC-ERROR] StaticStreamCallback exception: %s', [E.Message]));
      Result := QUIC_STATUS_SUCCESS;
    end;
  end;
end;

function StaticConnectionCallback(Connection: HQUIC; Context: Pointer; Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS; cdecl;
var Obj: TMsQuicConnection;
begin
  if Context = nil then
    Exit(QUIC_STATUS_SUCCESS);
  Obj := TMsQuicConnection(Context);
  try
    Result := Obj.InternalHandleEvent(Event);
  except
    on E: Exception do
    begin
      Writeln(Format('[LOG-MSQUIC-ERROR] StaticConnectionCallback exception: %s', [E.Message]));
      Result := QUIC_STATUS_SUCCESS;
    end;
  end;
end;

constructor EMsQuicException.Create(const Msg: string; Status: QUIC_STATUS);
begin
  inherited CreateFmt('%s (Status: 0x%x)', [Msg, Status]);
  FStatus := Status;
end;

function QUIC_FAILED(Status: QUIC_STATUS): Boolean; inline;
begin
  Result := Integer(Status) < 0;
end;

procedure CheckQuicStatus(Status: QUIC_STATUS; const ContextMsg: string = '');
begin
  if QUIC_FAILED(Status) then
    raise EMsQuicException.Create(ContextMsg, Status);
end;

// --- TMsQuicBase ---
constructor TMsQuicBase.Create(Api: PQUIC_API_TABLE);
begin
  inherited Create;
  FApi := Api;
  FHandle := nil;
end;

destructor TMsQuicBase.Destroy;
begin
  inherited;
end;

procedure TMsQuicBase.CheckHandle;
begin
  if FHandle = nil then
    raise Exception.Create('Invalid MSQUIC Handle. Resource is closed or not opened properly.');
end;

// --- TMsQuicRegistration ---
constructor TMsQuicRegistration.Create(Api: PQUIC_API_TABLE; const AppName: string; ExecutionProfile: ULONG);
var
  Config: QUIC_REGISTRATION_CONFIG;
  Status: QUIC_STATUS;
begin
  inherited Create(Api);
  FillChar(Config, SizeOf(Config), 0);
  Config.AppName := PAnsiChar(AnsiString(AppName));
  Config.ExecutionProfile := ExecutionProfile;

  Status := FApi.RegistrationOpen(@Config, FHandle);
  CheckQuicStatus(Status, 'RegistrationOpen failed');
end;

procedure TMsQuicRegistration.Shutdown(Flags: ULONG = 1; ErrorCode: UInt64 = 0);
begin
  if FHandle <> nil then
    FApi.RegistrationShutdown(FHandle, Flags, ErrorCode);
end;

destructor TMsQuicRegistration.Destroy;
var
  H: HQUIC;
  LocalApi: PQUIC_API_TABLE;
  RegThread: TThread;
  WaitHandle: THandle;
begin
  if FHandle <> nil then
  begin
    H := FHandle;
    LocalApi := FApi;
    FHandle := nil;
    try
      LocalApi.RegistrationShutdown(H, 1, 0);
    except
      on E: Exception do
        Logger.Warn('[LOG-MSQUIC] RegistrationShutdown error: ' + E.Message);
    end;
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicRegistration.Destroy: spawning RegistrationClose thread (Thread:%d)', [GetCurrentThreadId]));

    RegThread := TThread.CreateAnonymousThread(
      procedure
      begin
        try
          Logger.Info(Format('[LOG-MSQUIC] RegistrationClose thread started (Thread:%d)', [GetCurrentThreadId]));
          LocalApi.RegistrationClose(H);
          Logger.Info('[LOG-MSQUIC] RegistrationClose thread: DONE');
        except
          on E: Exception do
            Logger.Warn('[LOG-MSQUIC] RegistrationClose thread EXCEPTION: ' + E.Message);
        end;
      end
    );
    RegThread.FreeOnTerminate := True;
    WaitHandle := RegThread.Handle;
    RegThread.Start;
    if WaitForSingleObject(WaitHandle, 3000) = WAIT_TIMEOUT then
      Logger.Warn('[LOG-MSQUIC] TMsQuicRegistration.Destroy: RegistrationClose TIMEOUT (3s) - continuing without block!')
    else
      Logger.Info('[LOG-MSQUIC] TMsQuicRegistration.Destroy: RegistrationClose RETURNED!');
  end;
  inherited;
end;

// --- TMsQuicConfiguration ---
constructor TMsQuicConfiguration.Create(Reg: TMsQuicRegistration; const AlpnList: TArray<string>; ApiVersion: Integer = 2);
var
  AlpnBuffers: array of QUIC_BUFFER;
  AnsiAlpnList: array of RawByteString;
  I: Integer;
  Status: QUIC_STATUS;
  SettingsV1: QUIC_SETTINGS_V1;
  SettingsV2: QUIC_SETTINGS_V2;
begin
  inherited Create(Reg.Api);

  SetLength(AnsiAlpnList, Length(AlpnList));
  SetLength(AlpnBuffers, Length(AlpnList));
  for I := Low(AlpnList) to High(AlpnList) do
  begin
    AnsiAlpnList[I] := UTF8Encode(AlpnList[I]);
    AlpnBuffers[I].Length := Length(AnsiAlpnList[I]);
    AlpnBuffers[I].Buffer := PByte(PAnsiChar(AnsiAlpnList[I]));
  end;

  FillChar(SettingsV2, SizeOf(SettingsV2), 0);
  SettingsV2.IsSetFlags := (UInt64(1) shl 18) or (UInt64(1) shl 19);
  SettingsV2.PeerBidiStreamCount := 1000;
  SettingsV2.PeerUnidiStreamCount := 1000;
  Status := FApi.ConfigurationOpen(Reg.Handle, @AlpnBuffers[0], Length(AlpnBuffers), @SettingsV2, SizeOf(SettingsV2), nil, FHandle);
  Logger.Info(Format('[H3-CONFIG] ConfigurationOpen SettingsV2 status=0x%x (size=%d)', [Status, SizeOf(SettingsV2)]));

  if Status <> 0 then
  begin
    FillChar(SettingsV1, SizeOf(SettingsV1), 0);
    SettingsV1.IsSetFlags := (UInt64(1) shl 16) or (UInt64(1) shl 17);
    SettingsV1.PeerBidiStreamCount := 1000;
    SettingsV1.PeerUnidiStreamCount := 1000;
    Status := FApi.ConfigurationOpen(Reg.Handle, @AlpnBuffers[0], Length(AlpnBuffers), @SettingsV1, SizeOf(SettingsV1), nil, FHandle);
    Logger.Info(Format('[H3-CONFIG] ConfigurationOpen SettingsV1 status=0x%x (size=%d)', [Status, SizeOf(SettingsV1)]));
  end;

  if Status <> 0 then
  begin
    Status := FApi.ConfigurationOpen(Reg.Handle, @AlpnBuffers[0], Length(AlpnBuffers), nil, 0, nil, FHandle);
    Logger.Info(Format('[H3-CONFIG] ConfigurationOpen FALLBACK nil status=0x%x', [Status]));
  end;

  CheckQuicStatus(Status, 'ConfigurationOpen failed');
end;

destructor TMsQuicConfiguration.Destroy;
begin
  if FHandle <> nil then
  begin
    FApi.ConfigurationClose(FHandle);
    FHandle := nil;
  end;
  inherited;
end;

procedure TMsQuicConfiguration.LoadCredential(const CredConfig: PQUIC_CREDENTIAL_CONFIG);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.ConfigurationLoadCredential(FHandle, CredConfig);
  CheckQuicStatus(Status, 'ConfigurationLoadCredential failed');
end;

function HexToBytes(const Hex: string): TArray<Byte>;
var
  I: Integer;
begin
  SetLength(Result, Length(Hex) div 2);
  for I := 1 to Length(Hex) div 2 do
    Result[I - 1] := StrToInt('$' + Copy(Hex, (I - 1) * 2 + 1, 2));
end;

procedure TMsQuicConfiguration.LoadCredentialFromHash(const HashHex: string; const StoreName: string);
var
  CredConfig: QUIC_CREDENTIAL_CONFIG;
  HashBytes: TArray<Byte>;
  CertHashStruct: packed record
    ShaHash: array[0..19] of Byte;
  end;
  CertStoreStruct: packed record
    Flags: ULONG;
    ShaHash: array[0..19] of Byte;
    StoreName: array[0..127] of AnsiChar;
  end;
  AnsiStore: AnsiString;
  Status: QUIC_STATUS;
begin
  HashBytes := HexToBytes(HashHex);
  if Length(HashBytes) <> 20 then
    raise Exception.Create('Invalid Hash length, must be 20 bytes for SHA-1');

  CheckHandle;
  Logger.Info(Format('[H3-CRED] LoadCredentialFromHash START hash=%s store=%s', [HashHex, StoreName]));

  FillChar(CertStoreStruct, SizeOf(CertStoreStruct), 0);
  CertStoreStruct.Flags := 1;
  Move(HashBytes[0], CertStoreStruct.ShaHash[0], 20);
  AnsiStore := AnsiString(StoreName);
  if Length(AnsiStore) <= 127 then
    Move(PAnsiChar(AnsiStore + #0)^, CertStoreStruct.StoreName[0], Length(AnsiStore) + 1);

  FillChar(CredConfig, SizeOf(CredConfig), 0);
  CredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE; // 2
  CredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
  CredConfig.CertificateContext := @CertStoreStruct;

  Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
  Logger.Info(Format('[H3-CRED] Step 1 LocalMachine\%s (Flags=1) status=0x%x (%d)', [StoreName, Status, Status]));
  if Status = 0 then
  begin
    Logger.Info(Format('[H3-CRED] SUCCESS Step 1 - Certificate loaded from LocalMachine\%s!', [StoreName]));
    Exit;
  end;

  FillChar(CertStoreStruct, SizeOf(CertStoreStruct), 0);
  CertStoreStruct.Flags := 1;
  Move(HashBytes[0], CertStoreStruct.ShaHash[0], 20);
  AnsiStore := 'My';
  Move(PAnsiChar(AnsiStore + #0)^, CertStoreStruct.StoreName[0], Length(AnsiStore) + 1);

  Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
  Logger.Info(Format('[H3-CRED] Step 2 LocalMachine\My (Flags=1) status=0x%x (%d)', [Status, Status]));
  if Status = 0 then
  begin
    Logger.Info('[H3-CRED] SUCCESS Step 2 - Certificate loaded from LocalMachine\My!');
    Exit;
  end;

  FillChar(CertStoreStruct, SizeOf(CertStoreStruct), 0);
  CertStoreStruct.Flags := 0;
  Move(HashBytes[0], CertStoreStruct.ShaHash[0], 20);
  AnsiStore := AnsiString(StoreName);
  Move(PAnsiChar(AnsiStore + #0)^, CertStoreStruct.StoreName[0], Length(AnsiStore) + 1);

  Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
  Logger.Info(Format('[H3-CRED] Step 3 LocalMachine\%s (Flags=0) status=0x%x (%d)', [StoreName, Status, Status]));
  if Status = 0 then
  begin
    Logger.Info(Format('[H3-CRED] SUCCESS Step 3 - Certificate loaded from LocalMachine\%s!', [StoreName]));
    Exit;
  end;

  FillChar(CertHashStruct, SizeOf(CertHashStruct), 0);
  Move(HashBytes[0], CertHashStruct.ShaHash[0], 20);
  FillChar(CredConfig, SizeOf(CredConfig), 0);
  CredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH; // 1
  CredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
  CredConfig.CertificateContext := @CertHashStruct;

  Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
  Logger.Info(Format('[H3-CRED] Step 4 HASH (Direct SHA-1) status=0x%x (%d)', [Status, Status]));
  if Status = 0 then
  begin
    Logger.Info(Format('[H3-CRED] SUCCESS Step 4 - Certificate loaded for SHA-1 hash %s!', [HashHex]));
    Exit;
  end;

  var hStoreToSearch: HCERTSTORE := FServerCertStore;
  var MustCloseStore := False;
  if hStoreToSearch = nil then
  begin
    hStoreToSearch := CertOpenSystemStore(0, PWideChar(StoreName));
    MustCloseStore := (hStoreToSearch <> nil);
    Logger.Info(Format('[H3-CRED] Step 5 CertOpenSystemStore(%s) = %p', [StoreName, hStoreToSearch]));
  end else
    Logger.Info(Format('[H3-CRED] Step 5 using pre-opened FServerCertStore = %p', [hStoreToSearch]));

  var hTmpStore := CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nil);
  Logger.Info(Format('[H3-CRED] Step 5 hTmpStore = %p', [hTmpStore]));
  if hTmpStore <> nil then
  begin
    try
      if hStoreToSearch <> nil then
      begin
        var pSearchContext := CertFindCertificateInStore(
          hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
          CERT_FIND_SHA1_HASH, @CertHashStruct.ShaHash[0], nil
        );
        Logger.Info(Format('[H3-CRED] Step 5 CertFind by SHA1 = %p', [pSearchContext]));
        if pSearchContext = nil then
        begin
          pSearchContext := CertFindCertificateInStore(
            hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR_W, PWideChar('localhost'), nil
          );
          Logger.Info(Format('[H3-CRED] Step 5 CertFind by Subject = %p', [pSearchContext]));
        end;

        if pSearchContext <> nil then
        begin
          try
            if CertAddCertificateContextToStore(hTmpStore, pSearchContext, CERT_STORE_ADD_ALWAYS, nil) then
            begin
              var PfxBlob: CRYPT_DATA_BLOB;
              FillChar(PfxBlob, SizeOf(PfxBlob), 0);
              const EXPORT_PRIVATE_KEYS = $0004;
              const REPORT_NO_PRIVATE_KEY = $0001;
              if PFXExportCertStoreEx(hTmpStore, @PfxBlob, nil, nil, EXPORT_PRIVATE_KEYS or REPORT_NO_PRIVATE_KEY) then
              begin
                GetMem(PfxBlob.pbData, PfxBlob.cbData);
                try
                  if PFXExportCertStoreEx(hTmpStore, @PfxBlob, nil, nil, EXPORT_PRIVATE_KEYS or REPORT_NO_PRIVATE_KEY) then
                  begin
                    var Pkcs12Struct: record
                      Asn1Blob: PByte;           // offset 0,  8 B
                      Asn1BlobLength: ULONG;     // offset 8,  4 B
                      Padding: DWORD;            // offset 12, 4 B
                      PrivateKeyPassword: PAnsiChar; // offset 16, 8 B
                    end;
                    FillChar(Pkcs12Struct, SizeOf(Pkcs12Struct), 0);
                    Pkcs12Struct.Asn1Blob := PfxBlob.pbData;
                    Pkcs12Struct.Asn1BlobLength := PfxBlob.cbData;
                    Pkcs12Struct.Padding := 0;
                    Pkcs12Struct.PrivateKeyPassword := nil;

                    FillChar(CredConfig, SizeOf(CredConfig), 0);
                    CredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12; // 6
                    CredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
                    CredConfig.CertificateContext := @Pkcs12Struct;

                    Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
                    Logger.Info(Format('[H3-CRED] Step 5 PKCS12 (PFX Blob %d B) status=0x%x (%d)', [PfxBlob.cbData, Status, Status]));
                    if Status = 0 then
                    begin
                      Logger.Info('[H3-CRED] SUCCESS Step 5 - Certificate loaded via PKCS12 PFX Blob!');
                      Exit;
                    end;
                  end;
                finally
                  FreeMem(PfxBlob.pbData);
                end;
              end;
            end;
          finally
            CertFreeCertificateContext(pSearchContext);
          end;
        end else
          Logger.Error('[H3-CRED] Step 5 - certificate not found in store!');
      end else
        Logger.Error('[H3-CRED] Step 5 - hStoreToSearch is nil, cannot search for cert!');
    finally
      CertCloseStore(hTmpStore, 0);
      if MustCloseStore and (hStoreToSearch <> nil) then
        CertCloseStore(hStoreToSearch, 0);
    end;
  end else
    Logger.Error('[H3-CRED] Step 5 - CertOpenStore(MEMORY) failed!');

  Logger.Error(Format('[H3-CRED] ALL STEPS FAILED! Last status=0x%x (%d) for hash %s store %s', [Status, Status, HashHex, StoreName]));
  raise EMsQuicException.Create(Format('ConfigurationLoadCredential failed for LocalMachine\%s - all 5 steps failed, last status=0x%x', [StoreName, Status]), Status);
end;

procedure TMsQuicConfiguration.LoadCredentialFromContext(CertContext: Pointer);
var
  CredConfig: QUIC_CREDENTIAL_CONFIG;
  Status: QUIC_STATUS;
  CertWrapper: record
    Context: Pointer;
  end;
begin
  CheckHandle;
  Logger.Info(Format('[H3-CRED] LoadCredentialFromContext CertContext=%p', [CertContext]));
  if CertContext <> nil then
  begin
    CertWrapper.Context := CertContext;
    FillChar(CredConfig, SizeOf(CredConfig), 0);
    CredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
    CredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
    CredConfig.CertificateContext := @CertWrapper;
    Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
    Logger.Info(Format('[H3-CRED] CERTIFICATE_CONTEXT (wrapper) status=0x%x', [Status]));
    if Status = 0 then
    begin
      Logger.Info('[H3-CRED] CERTIFICATE_CONTEXT SUCCESS');
      Exit;
    end;

    FillChar(CredConfig, SizeOf(CredConfig), 0);
    CredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
    CredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
    CredConfig.CertificateContext := CertContext;
    Status := FApi.ConfigurationLoadCredential(FHandle, @CredConfig);
    Logger.Info(Format('[H3-CRED] CERTIFICATE_CONTEXT (direct) status=0x%x', [Status]));
    if Status = 0 then
    begin
      Logger.Info('[H3-CRED] CERTIFICATE_CONTEXT SUCCESS');
      Exit;
    end;
  end;

  Logger.Error('[H3-CRED] LoadCredentialFromContext FAILED - No server certificate found!');
  CheckQuicStatus(Status, 'ConfigurationLoadCredential failed (Windows Schannel PCCERT_CONTEXT)');
end;


constructor TMsQuicListener.Create(Reg: TMsQuicRegistration);
var
  Status: QUIC_STATUS;
begin
  inherited Create(Reg.Api);
  FStopEvent := CreateEvent(nil, True, False, nil);
  Status := FApi.ListenerOpen(Reg.Handle, @StaticListenerCallback, Pointer(Self), FHandle);
  CheckQuicStatus(Status, 'ListenerOpen failed');
end;

destructor TMsQuicListener.Destroy;
begin
  Logger.Info('[LOG-MSQUIC] TMsQuicListener.Destroy: closing Listener...');
  if FHandle <> nil then
  begin
    FApi.ListenerStop(FHandle);
    FApi.ListenerClose(FHandle);
    FHandle := nil;
  end;
  if FStopEvent <> 0 then
  begin
    CloseHandle(FStopEvent);
    FStopEvent := 0;
  end;
  inherited;
end;

procedure TMsQuicListener.StopAndWait(TimeoutMs: DWORD);
var
  WaitResult: DWORD;
begin
  if FHandle = nil then
    Exit;
  Logger.Info('[LOG-MSQUIC] TMsQuicListener.StopAndWait: calling ListenerStop...');
  FApi.ListenerStop(FHandle);
  Logger.Info(Format('[LOG-MSQUIC] TMsQuicListener.StopAndWait: waiting for STOP_COMPLETE (timeout=%dms)...', [TimeoutMs]));
  WaitResult := WaitForSingleObject(FStopEvent, TimeoutMs);
  case WaitResult of
    WAIT_OBJECT_0: Logger.Info('[LOG-MSQUIC] TMsQuicListener.StopAndWait: STOP_COMPLETE received!');
    WAIT_TIMEOUT:  Logger.Warn('[LOG-MSQUIC] TMsQuicListener.StopAndWait: TIMEOUT - continuing anyway');
  else
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicListener.StopAndWait: WaitResult=%d', [WaitResult]));
  end;
end;


procedure TMsQuicListener.Start(const AlpnList: TArray<string>; Port: Word = 0);
var
  AlpnBuffers: array of QUIC_BUFFER;
  I: Integer;
  Addr: TSockAddrIn;
  Status: QUIC_STATUS;
begin
  CheckHandle;
  SetLength(AlpnBuffers, Length(AlpnList));
  for I := Low(AlpnList) to High(AlpnList) do
  begin
    AlpnBuffers[I].Length := Length(AlpnList[I]);
    AlpnBuffers[I].Buffer := PByte(PAnsiChar(AnsiString(AlpnList[I])));
  end;

  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port := htons(Port);
  Status := FApi.ListenerStart(FHandle, @AlpnBuffers[0], Length(AlpnBuffers), @Addr);
  CheckQuicStatus(Status, 'ListenerStart failed');
end;

procedure TMsQuicListener.Stop;
begin
  if FHandle <> nil then
    FApi.ListenerStop(FHandle);
end;

function TMsQuicListener.InternalHandleEvent(Event: PQUIC_LISTENER_EVENT): QUIC_STATUS;
begin
  Result := QUIC_STATUS_SUCCESS;
  Logger.Info(Format('[LOG-MSQUIC] TMsQuicListener.InternalHandleEvent: EventId = %d', [Event.EventId]));
  case Event.EventId of
    QUIC_LISTENER_EVENT_NEW_CONNECTION:
      begin
        if Assigned(FOnNewConnection) then
          FOnNewConnection(Self, Event.NewConnection.Connection);
      end;
    QUIC_LISTENER_EVENT_STOP_COMPLETE:
      begin
        Logger.Info('[LOG-MSQUIC] QUIC_LISTENER_EVENT_STOP_COMPLETE received - setting FStopEvent');
        if FStopEvent <> 0 then
          SetEvent(FStopEvent);
      end;
  end;
end;


// --- TMsQuicConnection ---
constructor TMsQuicConnection.Create(Reg: TMsQuicRegistration);
var
  Status: QUIC_STATUS;
begin
  inherited Create(Reg.Api);
  Status := FApi.ConnectionOpen(Reg.Handle, @StaticConnectionCallback, Pointer(Self), FHandle);
  CheckQuicStatus(Status, 'ConnectionOpen failed');
end;

constructor TMsQuicConnection.Create(Api: PQUIC_API_TABLE; ConnectionHandle: HQUIC);
begin
  inherited Create(Api);
  FHandle := ConnectionHandle;
  FApi.SetCallbackHandler(FHandle, @StaticConnectionCallback, Pointer(Self));
end;

destructor TMsQuicConnection.Destroy;
var
  H: HQUIC;
begin
  if FHandle <> nil then
  begin
    H := FHandle;
    FHandle := nil;
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicConnection.Destroy: SetCallbackHandler(nil) + ConnectionClose H=%p (Thread:%d)',
      [H, GetCurrentThreadId]));
    FApi.SetCallbackHandler(H, @StaticConnectionCallback, nil);
    FApi.ConnectionClose(H);
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicConnection.Destroy: ConnectionClose RETURNED H=%p', [H]));
  end;
  inherited;
end;

procedure TMsQuicConnection.Start(Config: TMsQuicConfiguration; const ServerName: string; ServerPort: Word);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.ConnectionStart(FHandle, Config.Handle, AF_UNSPEC, PAnsiChar(AnsiString(ServerName)), ServerPort);
  CheckQuicStatus(Status, 'ConnectionStart failed');
end;

procedure TMsQuicConnection.SetConfiguration(Config: TMsQuicConfiguration);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.ConnectionSetConfiguration(FHandle, Config.Handle);
  CheckQuicStatus(Status, 'ConnectionSetConfiguration failed');
end;

procedure TMsQuicConnection.Shutdown(ErrorCode: UInt64);
begin
  if FHandle <> nil then
    FApi.ConnectionShutdown(FHandle, 1, ErrorCode);
end;

function TMsQuicConnection.InternalHandleEvent(Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS;
begin
  Result := QUIC_STATUS_SUCCESS;
  case Event.EventId of
    QUIC_CONNECTION_EVENT_CONNECTED:
      begin
        Logger.Info('[LOG-H3-CONN] CONNECTED event received - TLS handshake OK!');
        if Assigned(FOnConnected) then
          FOnConnected(Self);
      end;

    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
      begin
        if (Event.ShutdownInitiatedByTransport.Status = $80410005) or (Event.ShutdownInitiatedByTransport.Status = $80410006) or (Event.ShutdownInitiatedByTransport.Status = 0) then
          Logger.Info(Format('[LOG-H3-CONN] Connection closed by TRANSPORT (Status=0x%x)', [Event.ShutdownInitiatedByTransport.Status]))
        else
          Logger.Error(Format('[LOG-H3-CONN] SHUTDOWN_BY_TRANSPORT Status=0x%x - TLS/QUIC error!', [Event.ShutdownInitiatedByTransport.Status]));
        if Assigned(FOnShutdown) then
         FOnShutdown(Self);
      end;

    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
      begin
        Logger.Info(Format('[LOG-H3-CONN] SHUTDOWN_BY_PEER ErrorCode=%d', [Event.ShutdownInitiatedByPeer.ErrorCode]));
        Logger.Info(Format('[LOG-MSQUIC] Connection shutdown by PEER (ErrorCode: %d)', [Event.ShutdownInitiatedByPeer.ErrorCode]));
        if Assigned(FOnShutdown) then
         FOnShutdown(Self);
      end;

    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
      begin
        Logger.Info('[LOG-H3-CONN] SHUTDOWN_COMPLETE');
        Logger.Info('[LOG-MSQUIC] Connection SHUTDOWN_COMPLETE');
        if Assigned(FOnShutdown) then
         FOnShutdown(Self);
      end;

    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
      if Assigned(FOnPeerStreamStarted) then
        FOnPeerStreamStarted(Self, Event.PeerStreamStarted.Stream, Event.PeerStreamStarted.Flags);
  end;
end;

// --- TMsQuicStream ---
constructor TMsQuicStream.Create(Connection: TMsQuicConnection; Flags: ULONG);
var
  Status: QUIC_STATUS;
begin
  inherited Create(Connection.Api);
  FConnection := Connection;
  Status := FApi.StreamOpen(Connection.Handle, Flags, @StaticStreamCallback, Pointer(Self), FHandle);
  CheckQuicStatus(Status, 'StreamOpen failed');
end;

constructor TMsQuicStream.Create(Api: PQUIC_API_TABLE; StreamHandle: HQUIC);
begin
  inherited Create(Api);
  FConnection := nil;
  FHandle := StreamHandle;
  FApi.SetCallbackHandler(FHandle, @StaticStreamCallback, Pointer(Self));
end;

destructor TMsQuicStream.Destroy;
var
  H: HQUIC;
begin
  if FHandle <> nil then
  begin
    H := FHandle;
    FHandle := nil;
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicStream.Destroy: StreamClose H=%p (Thread:%d)',
        [H, GetCurrentThreadId]));
    FApi.StreamClose(H);
    Logger.Info(Format('[LOG-MSQUIC] TMsQuicStream.Destroy: StreamClose RETURNED H=%p', [H]));
  end;
  inherited;
end;

procedure TMsQuicStream.Detach;
begin
  if FHandle <> nil then
  begin
    FApi.SetCallbackHandler(FHandle, @StaticStreamCallback, nil);
    FHandle := nil;
  end;
end;

procedure TMsQuicStream.Start(Flags: ULONG);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.StreamStart(FHandle, Flags);
  CheckQuicStatus(Status, 'StreamStart failed');
end;

procedure TMsQuicStream.Shutdown(Flags: ULONG; ErrorCode: UInt64);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.StreamShutdown(FHandle, Flags, ErrorCode);
  CheckQuicStatus(Status, 'StreamShutdown failed');
end;

procedure TMsQuicStream.Send(Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG; Context: Pointer);
var
  Status: QUIC_STATUS;
begin
  CheckHandle;
  Status := FApi.StreamSend(FHandle, Buffers, BufferCount, Flags, Context);
  CheckQuicStatus(Status, 'StreamSend failed');
end;

function TMsQuicStream.GetID: UInt64;
var
  Status: QUIC_STATUS;
  ValueSize: ULONG;
begin
  if FHandle = nil then
    Exit(0);
  ValueSize := SizeOf(Result);
  Result := 0;
  Status := FApi.GetParam(FHandle, QUIC_PARAM_STREAM_ID, ValueSize, @Result);
  if QUIC_FAILED(Status) then
    Result := 0;
end;

function TMsQuicStream.InternalHandleEvent(Event: PQUIC_STREAM_EVENT): QUIC_STATUS;
begin
  Result := QUIC_STATUS_SUCCESS;
  case Event.EventId of
    QUIC_STREAM_EVENT_RECEIVE:
      if Assigned(FOnReceive) then
         FOnReceive(Self, Event.Receive.Buffers, Event.Receive.BufferCount, Event.Receive.Flags);

    QUIC_STREAM_EVENT_SEND_COMPLETE:
      if Assigned(FOnSendComplete) then
         FOnSendComplete(Self, Event.SendComplete.Canceled <> 0, Event.SendComplete.ClientContext);

    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
      if Assigned(FOnShutdownComplete) then
         FOnShutdownComplete(Self);
  end;
end;

end.
