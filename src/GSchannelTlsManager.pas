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
unit GSchannelTlsManager;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.Math,
  System.StrUtils,
  System.IOUtils,
  System.NetEncoding,
  System.Hash,
  System.Generics.Collections,
  GLogger,
  OverlappedExPool,
  WinApiAdditions,
  GRequest,
  GResponse,
  GHttpsServerTypes,
  GOpenSslApi,
  GOpenSslTlsEngine;

type
  TSchannelTlsManager = class
  private
    FTlsProvider: TTlsProvider;
    FTlsCertFile: string;
    FTlsKeyFile: string;
    FTlsKeyPassword: string;
    FOpenSslEngine: TOpenSslTlsEngine;
    FEnableGracefulSSLShutdown: Boolean;
    FSSLShutdownTimeout: Cardinal;
    FCertContext: PCCERT_CONTEXT;
    FH3CertContext: PCCERT_CONTEXT;
    FServerCredHandle: TCredHandle;
    FServerRootStore: HCERTSTORE;
    FCredentialsValid: Boolean;
    FServerCertStore: HCERTSTORE;
    FAlpnData: TBytes;
    FSubjectName: string;
    FCertificateStore: string;
    FEnableTLSSessionResumption: Boolean;
    FEnableTLSSessionTickets: Boolean;
    FmTLSMode: TmTLSMode;
    FOnValidateClientCertificate: TClientCertValidateEvent;
    FCACertContext: PCCERT_CONTEXT;
    FExtraCertContexts: TList<PCCERT_CONTEXT>;
    FmTLSCAPath: string;
    procedure BuildAlpnBuffer;
    function ValidateAndPopulateClientCert(RemoteCert: PCCERT_CONTEXT; var OverlappedEx: TOverlappedEx): Boolean;
    function ProcessClientCertificate(var OverlappedEx: TOverlappedEx): Boolean;
  public
    constructor Create(const ASubjectName, ACertificateStore: string);
    destructor Destroy; override;
    procedure FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
    procedure SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal = 500);
    procedure EnableGracefulSSLShutdown(Enable: Boolean);
    procedure SetSSLShutdownTimeout(TimeoutMs: Cardinal);
    procedure PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
    procedure ReleaseConnectionContext(var OverlappedEx: TOverlappedEx);
    function HasPendingRxData(var OverlappedEx: TOverlappedEx): Boolean;
    function LoadServerCertificate: Boolean;
    function GetCertificateSha256Hash: TBytes;
    function InitializeSSLCredentials: Boolean;
    function ProcessSSLHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
    function LoadCACertificate(const AFileName: string): Boolean;
    function AddTrustedCertificate(const AFileName: string): Boolean;
    function DecryptRequestChunk(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD;
                                 Request: TRequest; out HasPlaintext: Boolean;
                                 out FatalError: Boolean; out ErrorText: string): Boolean;
    function EncryptResponseChunks(var OverlappedEx: TOverlappedEx; Response: TResponse;
                                   out OutLen: Integer; out FatalError: Boolean): Boolean;
    function DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                                 var PlainData: TBytes; out BytesConsumed: Integer): Boolean; overload;
    function DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                                 var PlainData: TBytes; out BytesConsumed: Integer; out AStatus: SECURITY_STATUS): Boolean; overload;
    function DecryptReceivedData(var OverlappedEx: TOverlappedEx; var EncryptedData: TBytes;
                                 var PlainData: TBytes; out BytesConsumed: Integer; out AStatus: SECURITY_STATUS): Boolean; overload;
    function EncryptBytesToSend(var Context: TCtxtHandle;
                                const PlainData: TBytes; var EncryptedData: TBytes): Boolean; overload;
    function EncryptBytesToSend(var OverlappedEx: TOverlappedEx;
                                const PlainData: TBytes; var EncryptedData: TBytes): Boolean; overload;
    procedure CleanupHandles;
    function mTLSModePtr: Pointer;
    property TlsProvider: TTlsProvider read FTlsProvider write FTlsProvider;
    property TlsCertFile: string read FTlsCertFile write FTlsCertFile;
    property TlsKeyFile: string read FTlsKeyFile write FTlsKeyFile;
    property TlsKeyPassword: string read FTlsKeyPassword write FTlsKeyPassword;
    property EnableGracefulSSLShutdownFlag: Boolean read FEnableGracefulSSLShutdown write FEnableGracefulSSLShutdown;
    property SSLShutdownTimeout: Cardinal read FSSLShutdownTimeout write FSSLShutdownTimeout;
    property CertContext: PCCERT_CONTEXT read FCertContext;
    property H3CertContext: PCCERT_CONTEXT read FH3CertContext;
    property ServerCertStore: HCERTSTORE read FServerCertStore;
    property CACertContext: PCCERT_CONTEXT read FCACertContext;
    property CredentialsValid: Boolean read FCredentialsValid write FCredentialsValid;
    property SubjectName: string read FSubjectName write FSubjectName;
    property CertificateStore: string read FCertificateStore write FCertificateStore;
    property EnableTLSSessionResumption: Boolean read FEnableTLSSessionResumption write FEnableTLSSessionResumption;
    property EnableTLSSessionTickets: Boolean read FEnableTLSSessionTickets write FEnableTLSSessionTickets;
    property mTLSMode: TmTLSMode read FmTLSMode write FmTLSMode;
    property mTLSCAPath: string read FmTLSCAPath;
    property OnValidateClientCertificate: TClientCertValidateEvent read FOnValidateClientCertificate write FOnValidateClientCertificate;
  end;

implementation

procedure ReleaseOverlappedTlsContextGlobal(var OverlappedEx: TOverlappedEx);
var
  NeedFreeSchannel: Boolean;
  ShouldFreeSsl: Boolean;
  SslPtr: Pointer;
begin
  SslPtr := OverlappedEx.OpenSSLHandle;
  if SslPtr <> nil then
  begin
    ShouldFreeSsl := not OverlappedEx.SSLContextBorrowed;
    OverlappedEx.OpenSSLHandle := nil;
    OverlappedEx.OpenSSLRBio := nil;
    OverlappedEx.OpenSSLWBio := nil;
    OverlappedEx.SSLContextBorrowed := False;
    OverlappedEx.SSLLockPtr := nil;
    if ShouldFreeSsl and IsOpenSslLoaded and Assigned(OsslSslFree) then
    begin
      try
        OsslSslFree(PSSL(SslPtr));
      except
      end;
    end;
  end;

  NeedFreeSchannel := OverlappedEx.SSLContextValid and
                      (not OverlappedEx.SSLContextBorrowed) and
                      ((OverlappedEx.SSLContext.dwLower <> 0) or (OverlappedEx.SSLContext.dwUpper <> 0));
  if NeedFreeSchannel then
  begin
    try
      DeleteSecurityContext(@OverlappedEx.SSLContext);
    except
    end;
  end;
  OverlappedEx.SSLContext.dwLower := 0;
  OverlappedEx.SSLContext.dwUpper := 0;
  OverlappedEx.SSLContextBorrowed := False;
  OverlappedEx.SSLContextValid := False;
end;

constructor TSchannelTlsManager.Create(const ASubjectName, ACertificateStore: string);
begin
  inherited Create;
  FTlsProvider := GetConfiguredTlsProvider(tpSchannel);
  FTlsCertFile := GetConfiguredTlsCertFile;
  FTlsKeyFile := GetConfiguredTlsKeyFile;
  FTlsKeyPassword := '';
  FOpenSslEngine := TOpenSslTlsEngine.Create;
  GOverlappedTlsCleanupProc := ReleaseOverlappedTlsContextGlobal;
  FSubjectName := ASubjectName;
  FCertificateStore := ACertificateStore;
  FEnableGracefulSSLShutdown := True;
  FSSLShutdownTimeout := 500;
  FEnableTLSSessionResumption := True;
  FEnableTLSSessionTickets := True;
  FCertContext := nil;
  FH3CertContext := nil;
  FServerCertStore := nil;
  FServerRootStore := nil;
  FCACertContext := nil;
  FExtraCertContexts := nil;
  FmTLSMode := mtlsDisabled;
  FmTLSCAPath := '';
  FCredentialsValid := False;
  FServerCredHandle.dwLower := 0;
  FServerCredHandle.dwUpper := 0;
end;

destructor TSchannelTlsManager.Destroy;
begin
  CleanupHandles;
  FreeAndNil(FOpenSslEngine);
  inherited Destroy;
end;

function TSchannelTlsManager.mTLSModePtr: Pointer;
begin
  Result := @FmTLSMode;
end;

procedure TSchannelTlsManager.CleanupHandles;
var
  Ctx: PCCERT_CONTEXT;
begin
  if Assigned(FOpenSslEngine) then
    FOpenSslEngine.Cleanup;
  if FCredentialsValid then
  begin
    if (FServerCredHandle.dwLower <> 0) or (FServerCredHandle.dwUpper <> 0) then
      FreeCredentialsHandle(@FServerCredHandle);
    FServerCredHandle.dwLower := 0;
    FServerCredHandle.dwUpper := 0;
    FCredentialsValid := False;
  end;
  if FCertContext <> nil then
  begin
    CertFreeCertificateContext(FCertContext);
    FCertContext := nil;
  end;
  if FH3CertContext <> nil then
  begin
    CertFreeCertificateContext(FH3CertContext);
    FH3CertContext := nil;
  end;
  if FCACertContext <> nil then
  begin
    CertFreeCertificateContext(FCACertContext);
    FCACertContext := nil;
  end;
  if Assigned(FExtraCertContexts) then
  begin
    for Ctx in FExtraCertContexts do
    begin
      if Ctx <> nil then
        CertFreeCertificateContext(Ctx);
    end;
    FreeAndNil(FExtraCertContexts);
  end;
  if FServerRootStore <> nil then
  begin
    CertCloseStore(FServerRootStore, 0);
    FServerRootStore := nil;
  end;
  if FServerCertStore <> nil then
  begin
    CertCloseStore(FServerCertStore, 0);
    FServerCertStore := nil;
  end;
end;

procedure TSchannelTlsManager.FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
var
  Status: SECURITY_STATUS;
begin
  if Buffer <> nil then
  begin
    try
      Status := FreeContextBuffer(Buffer);
      if Status = SEC_E_OK then
        Buffer := nil
      else
        Logger.Error(' [%s] FreeContextBuffer failed: 0x%x', [Context, Status]);
    except
      on E: Exception do
        Logger.Error('[%s] Exception w FreeContextBuffer: %s', [Context, E.Message]);
    end;
  end;
end;

procedure TSchannelTlsManager.SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal);
begin
  FEnableGracefulSSLShutdown := EnableGraceful;
  FSSLShutdownTimeout := TimeoutMs;
end;

procedure TSchannelTlsManager.EnableGracefulSSLShutdown(Enable: Boolean);
begin
  FEnableGracefulSSLShutdown := Enable;
  Logger.Info('Graceful SSL shutdown ' + BoolToStr(Enable, True));
end;

procedure TSchannelTlsManager.SetSSLShutdownTimeout(TimeoutMs: Cardinal);
begin
  FSSLShutdownTimeout := TimeoutMs;
  Logger.Info('SSL shutdown timeout set to ' + IntToStr(TimeoutMs) + 'ms');
end;

procedure TSchannelTlsManager.PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
var
  OutputBuffers: array[0..1] of TSecBuffer;
  OutputBufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  dwType: DWORD;
  i: Integer;
  OriginalBuffers: array[0..1] of Pointer;
  AllocatedBuffers: array[0..1] of Pointer;
  AllocatedSizes: array[0..1] of Cardinal;
  BuffersToFree: Integer;
begin
  if (FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil) then
  begin
    if Assigned(FOpenSslEngine) then
      FOpenSslEngine.PerformGracefulShutdown(OverlappedEx, FEnableGracefulSSLShutdown)
    else
      ReleaseConnectionContext(OverlappedEx);
    Exit;
  end;
  if not OverlappedEx.SSLContextValid then
  begin
    Logger.Info('SSL context no longer valid - skipping shutdown');
    Exit;
  end;
  if not FEnableGracefulSSLShutdown then
  begin
    try
      DeleteSecurityContext(@OverlappedEx.SSLContext);
      OverlappedEx.SSLContextValid := False;
    except
      on E: Exception do
        Logger.Error('Delete error SSL context: ' + E.Message);
    end;
    Exit;
  end;
  BuffersToFree := 0;
  FillChar(OriginalBuffers, SizeOf(OriginalBuffers), 0);
  FillChar(AllocatedBuffers, SizeOf(AllocatedBuffers), 0);
  FillChar(AllocatedSizes, SizeOf(AllocatedSizes), 0);
  try
    dwType := SCHANNEL_SHUTDOWN;
    FillChar(OutputBuffers, SizeOf(OutputBuffers), 0);
    OutputBuffers[0].pvBuffer := @dwType;
    OutputBuffers[0].BufferType := SECBUFFER_TOKEN;
    OutputBuffers[0].cbBuffer := SizeOf(dwType);
    OutputBuffers[1].pvBuffer := nil;
    OutputBuffers[1].BufferType := SECBUFFER_EMPTY;
    OutputBuffers[1].cbBuffer := 0;
    OutputBufferDesc.cBuffers := 2;
    OutputBufferDesc.pBuffers := @OutputBuffers[0];
    OutputBufferDesc.ulVersion := SECBUFFER_VERSION;
    for i := 0 to 1 do
    begin
      OriginalBuffers[i] := OutputBuffers[i].pvBuffer;
    end;
    Status := ApplyControlToken(@OverlappedEx.SSLContext, @OutputBufferDesc);
    if Status <> SEC_E_OK then
    begin
      try
        DeleteSecurityContext(@OverlappedEx.SSLContext);
      except
        on E: Exception do
           Logger.Error('Delete error SSL context: ' + E.Message);
      end;
      OverlappedEx.SSLContextValid := False;
      Exit;
    end;
    FillChar(OutputBuffers, SizeOf(OutputBuffers), 0);
    OutputBuffers[0].pvBuffer := @OverlappedEx.SSLOutputBuffer[0];
    OutputBuffers[0].BufferType := SECBUFFER_TOKEN;
    OutputBuffers[0].cbBuffer := SizeOf(OverlappedEx.SSLOutputBuffer);
    OutputBuffers[1].pvBuffer := nil;
    OutputBuffers[1].BufferType := SECBUFFER_EMPTY;
    OutputBuffers[1].cbBuffer := 0;
    OutputBufferDesc.ulVersion := SECBUFFER_VERSION;
    OutputBufferDesc.cBuffers := 2;
    OutputBufferDesc.pBuffers := @OutputBuffers[0];
    for i := 0 to 1 do
      OriginalBuffers[i] := OutputBuffers[i].pvBuffer;

    Status := AcceptSecurityContext(
      @FServerCredHandle,
      @OverlappedEx.SSLContext,
      nil,
      ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or ASC_REQ_CONFIDENTIALITY,
      SECURITY_NATIVE_DREP,
      nil,
      @OutputBufferDesc,
      nil,
      nil
    );
    for i := 0 to 1 do
    begin
      if (OutputBuffers[i].cbBuffer > 0) and Assigned(OutputBuffers[i].pvBuffer) then
      begin
        if OutputBuffers[i].pvBuffer <> OriginalBuffers[i] then
        begin
          AllocatedBuffers[BuffersToFree] := OutputBuffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := OutputBuffers[i].cbBuffer;
          Inc(BuffersToFree);
          if (i = 0) and (OutputBuffers[i].cbBuffer <= SizeOf(OverlappedEx.SSLOutputBuffer)) then
            Move(OutputBuffers[i].pvBuffer^, OverlappedEx.SSLOutputBuffer[0], OutputBuffers[i].cbBuffer);
        end;
      end;
    end;
    if (Status = SEC_E_OK) and (OutputBuffers[0].cbBuffer > 0) then
      send(OverlappedEx.Socket, OutputBuffers[0].pvBuffer^, OutputBuffers[0].cbBuffer, 0)
    else
      Logger.Error('Could not generate close_notify: Status=0x%x, Size=%d',
        [Status, OutputBuffers[0].cbBuffer]);
  except
    on E: Exception do
    begin
      Logger.Error('Exception w graceful SSL shutdown: ' + E.Message);
      for i := 0 to 1 do
      begin
        if Assigned(OutputBuffers[i].pvBuffer) and (OutputBuffers[i].pvBuffer <> OriginalBuffers[i]) then
        begin
          AllocatedBuffers[BuffersToFree] := OutputBuffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := OutputBuffers[i].cbBuffer;
          Inc(BuffersToFree);
        end;
      end;
    end;
  end;
  if BuffersToFree > 0 then
  begin
    for i := 0 to BuffersToFree - 1 do
    begin
      if Assigned(AllocatedBuffers[i]) then
      begin
        try
          FreeContextBuffer(AllocatedBuffers[i]);
        except
          on E: Exception do
            Logger.Error(Format('Exception freeing SSL shutdown buffer[%d]: %s', [i, E.Message]));
        end;
      end;
    end;
  end
  else
    Logger.Info('No buffers allocated during SSL shutdown - no cleanup needed');
  try
    DeleteSecurityContext(@OverlappedEx.SSLContext);
    OverlappedEx.SSLContextValid := False;
  except
    on E: Exception do
      Logger.Error('Error cleanup SSL context: ' + E.Message);
  end;
end;

function TSchannelTlsManager.LoadServerCertificate: Boolean;
const
  CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = $00010000;
  CERT_NCRYPT_KEY_SPEC = $FFFFFFFF;
type
  TNCryptFreeObject = function(hObject: ULONG_PTR): LongInt; stdcall;
var
  CryptProv: HCRYPTPROV;
  KeySpec: DWORD;
  MustFree: BOOL;
  NCryptFreeObject: TNCryptFreeObject;
  NCryptLib: HMODULE;
  PrevContext: PCCERT_CONTEXT;
  HasExpiredInTargetStore: Boolean;
  OrigSubject: string;
  CertErr: string;
  IsCaSigned: Boolean;
  Sha256Hex: string;
  Sha1Hex: string;

  function TrySearchInStore(SystemStoreFlags: DWORD; const SystemStoreName, StoreName: string): Boolean;
  const
    CERT_STORE_READONLY_FLAG = $00008000;
    CRYPT_ACQUIRE_SILENT_FLAG = $00000040;
    CERT_KEY_PROV_INFO_PROP_ID = 2;
  var
    StoreHandle: HCERTSTORE;
    SubjectBuffer: array[0..255] of WideChar;
    SubjectLen: DWORD;
    cbData: DWORD;
    HasKeyProp: BOOL;
    AcquiredKey: BOOL;
    KeyErr: DWORD;
  begin
    Result := False;
    Logger.Info('Looking for certificate with subject: "%s" in %s\%s...', [FSubjectName, SystemStoreName, StoreName]);
    StoreHandle := CertOpenStore(
      PAnsiChar(CERT_STORE_PROV_SYSTEM),
      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0,
      SystemStoreFlags or CERT_STORE_READONLY_FLAG,
      PWideChar(StoreName)
    );
    if StoreHandle = nil then
      Exit;

    try
      PrevContext := nil;
      repeat
        FCertContext := CertFindCertificateInStore(
          StoreHandle,
          X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
          0,
          CERT_FIND_SUBJECT_STR,
          PWideChar(FSubjectName),
          PrevContext
        );

        if FCertContext = nil then
          Break;

        Logger.Info('Certificate context candidate allocated at: %p', [FCertContext]);
        try
          SubjectLen := CertGetNameString(
            FCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nil,
            @SubjectBuffer[0],
            256
          );

          if SubjectLen > 1 then
            Logger.Info('Certificate subject retrieved: "%s" (%d chars)', [PWideChar(@SubjectBuffer[0]), SubjectLen])
          else
            Logger.Info('Could not retrieve certificate subject name');
        except
          on E: Exception do
            Logger.Error('Exception retrieving certificate info: ' + E.Message);
        end;

        if CertVerifyTimeValidity(nil, FCertContext^.pCertInfo) <> 0 then
        begin
          if CertVerifyTimeValidity(nil, FCertContext^.pCertInfo) > 0 then
            HasExpiredInTargetStore := True;
          Logger.Warn('Certificate candidate at %p is expired or not yet valid. Searching next...', [FCertContext]);
          PrevContext := FCertContext;
          Continue;
        end;

        cbData := 0;
        HasKeyProp := CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, cbData);
        AcquiredKey := CryptAcquireCertificatePrivateKey(FCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG, nil, CryptProv, KeySpec, MustFree);
        KeyErr := GetLastError;

        Logger.Info('Cert key check - HasKeyProp: %s, AcquiredKey: %s, LastError: 0x%x (%d)',
          [BoolToStr(HasKeyProp, True), BoolToStr(AcquiredKey, True), KeyErr, KeyErr]);

        if AcquiredKey then
        begin
          if MustFree then
          begin
            if KeySpec = CERT_NCRYPT_KEY_SPEC then
            begin
              NCryptLib := LoadLibrary('ncrypt.dll');
              if NCryptLib <> 0 then
              begin
                @NCryptFreeObject := GetProcAddress(NCryptLib, 'NCryptFreeObject');
                if Assigned(NCryptFreeObject) then
                  NCryptFreeObject(CryptProv);
                FreeLibrary(NCryptLib);
              end;
            end
            else
              CryptReleaseContext(CryptProv, 0);
          end;
          FH3CertContext := CertDuplicateCertificateContext(FCertContext);
          FServerCertStore := StoreHandle;
          Logger.Info(Format('[H3] Certificate loaded successfully from %s\%s', [SystemStoreName, StoreName]));
          Result := True;
          Break;
        end
        else
        begin
          Logger.Warn('Certificate context candidate at %p has invalid/missing private key file (Error: 0x%x). Searching next...', [FCertContext, KeyErr]);
          PrevContext := FCertContext;
        end;
      until False;
    finally
      if (not Result) and (StoreHandle <> nil) then
        CertCloseStore(StoreHandle, 0);
    end;
  end;

begin
  if FTlsProvider = tpOpenSSL then
  begin
    if FCertContext <> nil then
    begin
      CertFreeCertificateContext(FCertContext);
      FCertContext := nil;
    end;
    if FH3CertContext <> nil then
    begin
      CertFreeCertificateContext(FH3CertContext);
      FH3CertContext := nil;
    end;
    if not ResolveOpenSslCertAndKeyFiles(FCertificateStore, FSubjectName, FTlsCertFile, FTlsKeyFile) then
    begin
      Logger.Error('[OpenSSL] Server certificate/key PEM files not found for store "%s", subject "%s" (expected certs\server.crt and certs\server.key)', [FCertificateStore, FSubjectName]);
      Exit(False);
    end;
    if not ValidateOpenSslServerCertAndKeyFiles(FTlsCertFile, FTlsKeyFile, FCertificateStore, FSubjectName, False, CertErr, IsCaSigned, Sha256Hex, Sha1Hex) then
    begin
      Logger.Error('[OpenSSL] %s', [CertErr]);
      Exit(False);
    end;
    FCertContext := CreateWinCertContextFromFile(FTlsCertFile);
    if FCertContext <> nil then
    begin
      FH3CertContext := CertDuplicateCertificateContext(FCertContext);
      Logger.Info('[OpenSSL] Certificate loaded exclusively from PEM files: %s, %s', [FTlsCertFile, FTlsKeyFile]);
      Exit(True);
    end;
    Logger.Error('[OpenSSL] Failed to create certificate context from PEM file: %s', [FTlsCertFile]);
    Exit(False);
  end;

  if FCertificateStore = '' then
    FCertificateStore := 'GHttpsIOCPSvr';

  if FSubjectName = '' then
    FSubjectName := GetPrimaryIPv4Address;
  Logger.Info('LoadServerCertificate START');

  Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', FCertificateStore);
  if not Result then
    Result := TrySearchInStore(CERT_SYSTEM_STORE_CURRENT_USER, 'CurrentUser', FCertificateStore);
  if not Result and not HasExpiredInTargetStore then
    Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', 'My');

  if not Result and (FSubjectName <> 'localhost') then
  begin
    OrigSubject := FSubjectName;
    FSubjectName := 'localhost';
    Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', FCertificateStore);
    if not Result then
      Result := TrySearchInStore(CERT_SYSTEM_STORE_CURRENT_USER, 'CurrentUser', FCertificateStore);
    if not Result and not HasExpiredInTargetStore then
      Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', 'My');
    if Result then
      Logger.Info(Format('Certificate for "%s" not found, fallen back to localhost certificate', [OrigSubject]))
    else
      FSubjectName := OrigSubject;
  end;

  if not Result then
  begin
    if HasExpiredInTargetStore then
      Logger.Error('CRITICAL ERROR: TLS certificate "CN=%s" in store "%s" is EXPIRED. Startup aborted. Run .\gen_w3c_wt_cert.ps1 as Administrator to generate a new 14-day certificate.', [FSubjectName, FCertificateStore])
    else
    begin
      Logger.Error('No valid certificate with accessible private key "CN=%s" found in stores (LocalMachine\%s, CurrentUser\%s)', [FSubjectName, FCertificateStore, FCertificateStore]);
      Logger.Info('To create/re-create the required CNG certificate, run in PowerShell (as Admin): .\gen_w3c_wt_cert.ps1');
    end;
  end;

  Logger.Info(Format('LoadServerCertificate END - Result: %s, FCertContext: %p', [BoolToStr(Result, True), FCertContext]));
end;

function TSchannelTlsManager.GetCertificateSha256Hash: TBytes;
var
  HashBytes: array[0..31] of Byte;
  HashSize: DWORD;
  CertPtr: PCERT_CONTEXT;
  Stream: TBytesStream;
begin
  SetLength(Result, 0);
  if FCertContext = nil then
    Exit;

  HashSize := SizeOf(HashBytes);
  if CertGetCertificateContextProperty(FCertContext, CERT_SHA256_HASH_PROP_ID, @HashBytes[0], HashSize) then
  begin
    SetLength(Result, HashSize);
    Move(HashBytes[0], Result[0], HashSize);
    Exit;
  end;

  try
    CertPtr := PCERT_CONTEXT(FCertContext);
    if (CertPtr <> nil) and (CertPtr^.pbCertEncoded <> nil) and (CertPtr^.cbCertEncoded > 0) then
    begin
      Stream := TBytesStream.Create;
      try
        Stream.WriteBuffer(CertPtr^.pbCertEncoded^, CertPtr^.cbCertEncoded);
        Stream.Position := 0;
        Result := THashSHA2.GetHashBytes(Stream, THashSHA2.TSHA2Version.SHA256);
      finally
        Stream.Free;
      end;
    end;
  except
    on E: Exception do
      Logger.Warn('[Cert] Error calculating SHA-256 certificate hash: %s', [E.Message]);
  end;
end;

function TSchannelTlsManager.InitializeSSLCredentials: Boolean;
const
  SCH_CRED_NO_SYSTEM_MAPPER = $00000002;
  SCH_CRED_DISABLE_RECONNECTS = $00000080;
var
  SchCred: SCH_CREDENTIALS;
  Status: SECURITY_STATUS;
  Expiry: TTimeStamp;
  CertArray: PCCERT_CONTEXT;
  ExtraCtx: PCCERT_CONTEXT;
begin
  Result := False;
  if FTlsProvider = tpOpenSSL then
  begin
    Result := FOpenSslEngine.InitializeCredentials(
      FCertContext,
      FCACertContext,
      FExtraCertContexts,
      FTlsCertFile,
      FTlsKeyFile,
      FTlsKeyPassword,
      FEnableTLSSessionResumption,
      FEnableTLSSessionTickets,
      FmTLSMode
    );
    FCredentialsValid := Result;
    Exit;
  end;
  Logger.Info('InitializeSSLCredentials START - Production setup for Windows 11/CNG with SCH_CREDENTIALS...');
  if FCertContext = nil then
  begin
    Logger.Error('Critical error: Missing certificate.');
    Exit;
  end;
  CertArray := FCertContext;
  ZeroMemory(@SchCred, SizeOf(SchCred));
  SchCred.dwVersion := SCH_CREDENTIALS_VERSION;
  SchCred.dwCredFormat := 0;
  SchCred.cCreds := 1;
  SchCred.paCred := @CertArray;
  SchCred.dwFlags := SCH_CRED_NO_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or $00000002;
  if (FmTLSMode <> mtlsDisabled) and ((FCACertContext <> nil) or (Assigned(FExtraCertContexts) and (FExtraCertContexts.Count > 0))) then
  begin
    if FServerRootStore <> nil then
    begin
      CertCloseStore(FServerRootStore, 0);
      FServerRootStore := nil;
    end;
    FServerRootStore := CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nil);
    if FServerRootStore <> nil then
    begin
      if FCACertContext <> nil then
        CertAddCertificateContextToStore(FServerRootStore, FCACertContext, CERT_STORE_ADD_ALWAYS, nil);
      if Assigned(FExtraCertContexts) then
      begin
        for ExtraCtx in FExtraCertContexts do
        begin
          if ExtraCtx <> nil then
            CertAddCertificateContextToStore(FServerRootStore, ExtraCtx, CERT_STORE_ADD_ALWAYS, nil);
        end;
      end;
      SchCred.hRootStore := FServerRootStore;
    end;
  end;
  if not FEnableTLSSessionResumption then
    SchCred.dwFlags := SchCred.dwFlags or SCH_CRED_DISABLE_RECONNECTS;
  SchCred.dwSessionLifespan := 0;
  Logger.Info('Flags set for CNG certificate (SCH_CREDENTIALS v5).');
  Logger.Info('Calling AcquireCredentialsHandle...');
  Status := AcquireCredentialsHandle(
    nil, 'Microsoft Unified Security Protocol Provider', SECPKG_CRED_INBOUND,
    nil, @SchCred, nil, nil, @FServerCredHandle, @Expiry
  );

  if Status = SEC_E_OK then
  begin
    Logger.Info('Server running');
    BuildAlpnBuffer;
    Logger.Info('ALPN buffer configured for HTTP/1.1 (TCP/TLS)');
    FCredentialsValid := True;
    Result := True;
  end
  else
  begin
    Logger.Error(Format('FATAL ERROR. Error code: 0x%x.', [Status]));
    Result := False;
  end;
end;

procedure TSchannelTlsManager.BuildAlpnBuffer;
var
  ProtoName: AnsiString;
  ProtoLen: Byte;
  ListSize: Word;
  ListsSize: Cardinal;
  ExtType: Cardinal;
begin
  ProtoName := 'http/1.1';
  ProtoLen := Length(ProtoName);
  ListSize := 1 + ProtoLen;
  ListsSize := 4 + 2 + ListSize;
  SetLength(FAlpnData, 4 + ListsSize);
  Move(ListsSize, FAlpnData[0], 4);
  ExtType := SecApplicationProtocolNegotiationExt_ALPN;
  Move(ExtType, FAlpnData[4], 4);
  Move(ListSize, FAlpnData[8], 2);
  FAlpnData[10] := ProtoLen;
  Move(ProtoName[1], FAlpnData[11], ProtoLen);
end;

function TSchannelTlsManager.ProcessSSLHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
var
  InputBuffers: array[0..2] of TSecBuffer;
  OutputBuffers: array[0..1] of TSecBuffer;
  InputBufferDesc, OutputBufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  ContextAttr: ULONG;
  HandshakeStreamSizes: SecPkgContext_StreamSizes;
  TimeStamp: TTimeStamp;
  FirstCall: Boolean;
  i: Integer;
  OriginalBuffers: array[0..1] of Pointer;
  AllocatedBuffers: array[0..1] of Pointer;
  AllocatedSizes: array[0..1] of Cardinal;
  BuffersToFree: Integer;
  AlpnContext: SecPkgContext_ApplicationProtocol;
  AlpnStatus: SECURITY_STATUS;
  ExtraLen: Integer;
  ContextReqFlags: ULONG;
  FreeResult: SECURITY_STATUS;
begin
  Result := False;
  if not FCredentialsValid then
  begin
    Logger.Error('SSL Credentials are not initialized');
    Exit;
  end;
  if FTlsProvider = tpOpenSSL then
  begin
    Result := FOpenSslEngine.ProcessHandshakeStep(OverlappedEx, BytesReceived);
    if Result then
    begin
      FillChar(OverlappedEx.ClientCertInfo, SizeOf(OverlappedEx.ClientCertInfo), 0);
      if FmTLSMode <> mtlsDisabled then
      begin
        if not ProcessClientCertificate(OverlappedEx) then
        begin
          if FmTLSMode = mtlsRequired then
          begin
            PerformGracefulSSLShutdown(OverlappedEx);
            OverlappedEx.SSLContextValid := False;
            OverlappedEx.SSLNeedsMoreData := False;
            OverlappedEx.SSLOutputSize := 0;
            SetLength(OverlappedEx.ClientReceiveBuffer, 0);
            Result := False;
            Exit;
          end;
        end;
      end;
    end;
    Exit;
  end;
  BuffersToFree := 0;
  FillChar(OriginalBuffers, SizeOf(OriginalBuffers), 0);
  FillChar(AllocatedBuffers, SizeOf(AllocatedBuffers), 0);
  FillChar(AllocatedSizes, SizeOf(AllocatedSizes), 0);
  FirstCall := (OverlappedEx.SSLHandshakeStep = 0);
  Inc(OverlappedEx.SSLHandshakeStep);
  try
    InputBuffers[0].BufferType := SECBUFFER_TOKEN;
    if Length(OverlappedEx.ClientReceiveBuffer) > 0 then
    begin
      InputBuffers[0].cbBuffer := Length(OverlappedEx.ClientReceiveBuffer);
      InputBuffers[0].pvBuffer := @OverlappedEx.ClientReceiveBuffer[0];
    end
    else
    begin
      InputBuffers[0].cbBuffer := BytesReceived;
      InputBuffers[0].pvBuffer := @OverlappedEx.Buffer[0];
    end;

    InputBuffers[1].BufferType := SECBUFFER_EMPTY;
    InputBuffers[1].cbBuffer := 0;
    InputBuffers[1].pvBuffer := nil;

    if FirstCall and (Length(FAlpnData) > 0) then
    begin
      InputBuffers[2].BufferType := SECBUFFER_APPLICATION_PROTOCOLS;
      InputBuffers[2].cbBuffer := Length(FAlpnData);
      InputBuffers[2].pvBuffer := @FAlpnData[0];
      InputBufferDesc.cBuffers := 3;
    end
    else
    begin
      InputBuffers[2].BufferType := SECBUFFER_EMPTY;
      InputBuffers[2].cbBuffer := 0;
      InputBuffers[2].pvBuffer := nil;
      InputBufferDesc.cBuffers := 2;
    end;

    InputBufferDesc.ulVersion := SECBUFFER_VERSION;
    InputBufferDesc.pBuffers := @InputBuffers[0];

    FillChar(OutputBuffers, SizeOf(OutputBuffers), 0);

    OutputBuffers[0].BufferType := SECBUFFER_TOKEN;
    OutputBuffers[0].cbBuffer := SizeOf(OverlappedEx.SSLOutputBuffer);
    OutputBuffers[0].pvBuffer := @OverlappedEx.SSLOutputBuffer[0];

    OutputBuffers[1].BufferType := SECBUFFER_EMPTY;
    OutputBuffers[1].cbBuffer := 0;
    OutputBuffers[1].pvBuffer := nil;

    OutputBufferDesc.ulVersion := SECBUFFER_VERSION;
    OutputBufferDesc.cBuffers := 2;
    OutputBufferDesc.pBuffers := @OutputBuffers[0];

    for i := 0 to 1 do
      OriginalBuffers[i] := OutputBuffers[i].pvBuffer;

    ContextReqFlags := ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or
                       ASC_REQ_CONFIDENTIALITY or ASC_REQ_STREAM;
    if FEnableTLSSessionResumption then
      ContextReqFlags := ContextReqFlags or ASC_REQ_SESSION_TICKET;
    if FmTLSMode <> mtlsDisabled then
      ContextReqFlags := ContextReqFlags or ASC_REQ_MUTUAL_AUTH;

    if FirstCall then
    begin
      Status := AcceptSecurityContext(@FServerCredHandle, nil, @InputBufferDesc,
                           ContextReqFlags,
                           SECURITY_NATIVE_DREP, @OverlappedEx.SSLContext,
                           @OutputBufferDesc, @ContextAttr, @TimeStamp);
    end
    else
    begin
      Status := AcceptSecurityContext(@FServerCredHandle, @OverlappedEx.SSLContext, @InputBufferDesc,
                                     ContextReqFlags,
                                     SECURITY_NATIVE_DREP, @OverlappedEx.SSLContext,
                                     @OutputBufferDesc, @ContextAttr, @TimeStamp);
    end;

    for i := 0 to 1 do
    begin
      if (OutputBuffers[i].cbBuffer > 0) and Assigned(OutputBuffers[i].pvBuffer) then
      begin
        if OutputBuffers[i].pvBuffer <> OriginalBuffers[i] then
        begin
          AllocatedBuffers[BuffersToFree] := OutputBuffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := OutputBuffers[i].cbBuffer;
          Inc(BuffersToFree);
          if (i = 0) and (OutputBuffers[i].cbBuffer <= SizeOf(OverlappedEx.SSLOutputBuffer)) then
          begin
            Move(OutputBuffers[i].pvBuffer^, OverlappedEx.SSLOutputBuffer[0], OutputBuffers[i].cbBuffer);
            OutputBuffers[i].pvBuffer := @OverlappedEx.SSLOutputBuffer[0];
          end
          else if (i = 0) then
          begin
            Logger.Info(Format('EROR: Allocated buffer too large: %d > %d',
              [OutputBuffers[i].cbBuffer, SizeOf(OverlappedEx.SSLOutputBuffer)]));
            OverlappedEx.SSLNeedsMoreData := False;
            Exit(False);
          end;
        end;
      end;
    end;
    OverlappedEx.SSLOutputSize := OutputBuffers[0].cbBuffer;
    Logger.Info(Format('AcceptSecurityContext Status: 0x%x OutputSize: %d FirstCall: %s', [Status, OverlappedEx.SSLOutputSize, BoolToStr(FirstCall, True)]));
    case Status of
      SEC_E_OK:
      begin
        OverlappedEx.SSLContextValid := True;
        if QueryContextAttributes(@OverlappedEx.SSLContext, SECPKG_ATTR_STREAM_SIZES, @HandshakeStreamSizes) = SEC_E_OK then
        begin
          OverlappedEx.SSLStreamHeaderSize := HandshakeStreamSizes.cbHeader;
          OverlappedEx.SSLStreamTrailerSize := HandshakeStreamSizes.cbTrailer;
          OverlappedEx.SSLStreamMaxMessage := HandshakeStreamSizes.cbMaximumMessage;
          OverlappedEx.SSLStreamSizesValid := True;
        end
        else
          OverlappedEx.SSLStreamSizesValid := False;
        OverlappedEx.SSLNeedsMoreData := False;
        if (InputBuffers[1].BufferType = SECBUFFER_EXTRA) and
           (InputBuffers[1].cbBuffer > 0) and
           (Integer(InputBuffers[1].cbBuffer) <= Length(OverlappedEx.ClientReceiveBuffer)) then
        begin
          ExtraLen := Integer(InputBuffers[1].cbBuffer);
          OverlappedEx.ClientReceiveBuffer := Copy(OverlappedEx.ClientReceiveBuffer,
            Length(OverlappedEx.ClientReceiveBuffer) - ExtraLen, ExtraLen);
        end
        else
          SetLength(OverlappedEx.ClientReceiveBuffer, 0);
        AlpnStatus := QueryContextAttributes(@OverlappedEx.SSLContext, SECPKG_ATTR_APPLICATION_PROTOCOL, @AlpnContext);
        if (AlpnStatus = SEC_E_OK) and (AlpnContext.ProtoNegoStatus = SecApplicationProtocolNegotiationStatus_Success) and (AlpnContext.ProtocolIdSize > 0) then
        begin
          FillChar(OverlappedEx.ALPNProtocol, SizeOf(OverlappedEx.ALPNProtocol), 0);
          Move(AlpnContext.ProtocolId[0], OverlappedEx.ALPNProtocol[0],
            Min(Integer(AlpnContext.ProtocolIdSize), SizeOf(OverlappedEx.ALPNProtocol) - 1));
          Logger.Debug('SChannel ALPN negotiated: ' + string(PAnsiChar(@OverlappedEx.ALPNProtocol[0])));
        end;
        FillChar(OverlappedEx.ClientCertInfo, SizeOf(OverlappedEx.ClientCertInfo), 0);
        if FmTLSMode <> mtlsDisabled then
        begin
          if not ProcessClientCertificate(OverlappedEx) then
          begin
            if FmTLSMode = mtlsRequired then
            begin
              PerformGracefulSSLShutdown(OverlappedEx);
              OverlappedEx.SSLContextValid := False;
              OverlappedEx.SSLNeedsMoreData := False;
              OverlappedEx.SSLOutputSize := 0;
              SetLength(OverlappedEx.ClientReceiveBuffer, 0);
              Result := False;
              Exit;
            end;
          end;
        end;
        Result := True;
      end;
      SEC_I_CONTINUE_NEEDED:
      begin
        if (InputBuffers[1].BufferType = SECBUFFER_EXTRA) and
           (InputBuffers[1].cbBuffer > 0) and
           (Integer(InputBuffers[1].cbBuffer) <= Length(OverlappedEx.ClientReceiveBuffer)) then
        begin
          ExtraLen := Integer(InputBuffers[1].cbBuffer);
          OverlappedEx.ClientReceiveBuffer := Copy(OverlappedEx.ClientReceiveBuffer,
            Length(OverlappedEx.ClientReceiveBuffer) - ExtraLen, ExtraLen);
        end
        else
          SetLength(OverlappedEx.ClientReceiveBuffer, 0);
        OverlappedEx.SSLNeedsMoreData := True;
        Result := False;
      end;
      SEC_E_INCOMPLETE_MESSAGE:
      begin
        OverlappedEx.SSLNeedsMoreData := True;
        OverlappedEx.SSLOutputSize := 0;
        Result := False;
      end;
      SEC_E_DECRYPT_FAILURE:
      begin
        SetLength(OverlappedEx.ClientReceiveBuffer, 0);
        OverlappedEx.SSLNeedsMoreData := False;
        Result := False;
      end;
    else
      begin
        Logger.Error('SSL Handshake failed: 0x%x', [Status]);
        SetLength(OverlappedEx.ClientReceiveBuffer, 0);
        OverlappedEx.SSLNeedsMoreData := False;
        Result := False;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Exception w SSL Handshake krok %d: %s', [OverlappedEx.SSLHandshakeStep, E.Message]);
      OverlappedEx.SSLNeedsMoreData := False;
      Result := False;
      for i := 0 to 1 do
      begin
        if Assigned(OutputBuffers[i].pvBuffer) and (OutputBuffers[i].pvBuffer <> OriginalBuffers[i]) then
        begin
          AllocatedBuffers[BuffersToFree] := OutputBuffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := OutputBuffers[i].cbBuffer;
          Inc(BuffersToFree);
        end;
      end;
      if OverlappedEx.SSLContextValid then
      begin
        try
          DeleteSecurityContext(@OverlappedEx.SSLContext);
          OverlappedEx.SSLContextValid := False;
        except
          on E: Exception do
            Logger.Warn('Failed to delete SSLContext during handshake error: ' + E.Message);
        end;
      end;
    end;
  end;
  if BuffersToFree > 0 then
  begin
    for i := 0 to BuffersToFree - 1 do
    begin
      if Assigned(AllocatedBuffers[i]) then
      begin
        try
          FreeResult := FreeContextBuffer(AllocatedBuffers[i]);
          if FreeResult = SEC_E_OK then
            Logger.Info(Format('SSL handshake buffer[%d] freed successfully: %d bytes', [i, AllocatedSizes[i]]))
          else
            Logger.Info(Format('FreeContextBuffer failed for handshake buffer[%d]: 0x%x (%d bytes)',
              [i, FreeResult, AllocatedSizes[i]]));
        except
          on E: Exception do
            Logger.Error('Exception freeing SSL handshake buffer[%d]: %s', [i, E.Message]);
        end;
      end;
    end;
  end;
end;

function TSchannelTlsManager.ValidateAndPopulateClientCert(RemoteCert: PCCERT_CONTEXT; var OverlappedEx: TOverlappedEx): Boolean;
var
  NameBuf: array[0..255] of WideChar;
  NameLen: DWORD;
  HashBuf: array[0..31] of Byte;
  HashLen: DWORD;
  i: Integer;
  HexStr: string;
  SysTime: TSystemTime;
  RawBytes: TBytes;
  RawCertBytes: TBytes;
  CertStream: TBytesStream;
  HashBytes: TBytes;
  VerifyFlags: DWORD;
begin
  try
    OverlappedEx.ClientCertInfo.HasCertificate := True;

    NameLen := CertGetNameString(RemoteCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, @NameBuf[0], Length(NameBuf));
    if NameLen > 1 then
      OverlappedEx.ClientCertInfo.Subject := string(PChar(@NameBuf[0]))
    else
      OverlappedEx.ClientCertInfo.Subject := '';
    OverlappedEx.ClientCertInfo.CommonName := OverlappedEx.ClientCertInfo.Subject;

    NameLen := CertGetNameString(RemoteCert, CERT_NAME_DNS_TYPE, 0, nil, @NameBuf[0], Length(NameBuf));
    if NameLen > 1 then
      OverlappedEx.ClientCertInfo.SAN := string(PChar(@NameBuf[0]))
    else
      OverlappedEx.ClientCertInfo.SAN := '';

    if (RemoteCert^.cbCertEncoded > 0) and Assigned(RemoteCert^.pbCertEncoded) then
    begin
      SetLength(RawBytes, RemoteCert^.cbCertEncoded);
      Move(RemoteCert^.pbCertEncoded^, RawBytes[0], RemoteCert^.cbCertEncoded);
      OverlappedEx.ClientCertInfo.RawCertBase64 := TNetEncoding.Base64.EncodeBytesToString(RawBytes);
      OverlappedEx.ClientCertInfo.RawCertBase64 := StringReplace(OverlappedEx.ClientCertInfo.RawCertBase64, #13#10, '', [rfReplaceAll]);
      OverlappedEx.ClientCertInfo.RawCertBase64 := StringReplace(OverlappedEx.ClientCertInfo.RawCertBase64, #10, '', [rfReplaceAll]);
      OverlappedEx.ClientCertInfo.RawCertBase64 := StringReplace(OverlappedEx.ClientCertInfo.RawCertBase64, #13, '', [rfReplaceAll]);
    end
    else
      OverlappedEx.ClientCertInfo.RawCertBase64 := '';

    NameLen := CertGetNameString(RemoteCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, @NameBuf[0], Length(NameBuf));
    if NameLen > 1 then
      OverlappedEx.ClientCertInfo.Issuer := string(PChar(@NameBuf[0]))
    else
      OverlappedEx.ClientCertInfo.Issuer := '';

    if Assigned(RemoteCert^.pCertInfo) then
    begin
      if FileTimeToSystemTime(RemoteCert^.pCertInfo^.NotBefore, SysTime) then
        OverlappedEx.ClientCertInfo.ValidFrom := SystemTimeToDateTime(SysTime);
      if FileTimeToSystemTime(RemoteCert^.pCertInfo^.NotAfter, SysTime) then
        OverlappedEx.ClientCertInfo.ValidTo := SystemTimeToDateTime(SysTime);

      HexStr := '';
      if RemoteCert^.pCertInfo^.SerialNumber.cbData > 0 then
      begin
        for i := Integer(RemoteCert^.pCertInfo^.SerialNumber.cbData) - 1 downto 0 do
          HexStr := HexStr + IntToHex(PByte(RemoteCert^.pCertInfo^.SerialNumber.pbData)[i], 2);
      end;
      OverlappedEx.ClientCertInfo.SerialNumber := HexStr;
    end;

    if (RemoteCert^.cbCertEncoded > 0) and Assigned(RemoteCert^.pbCertEncoded) then
    begin
      SetLength(RawCertBytes, RemoteCert^.cbCertEncoded);
      Move(RemoteCert^.pbCertEncoded^, RawCertBytes[0], RemoteCert^.cbCertEncoded);
      CertStream := TBytesStream.Create(RawCertBytes);
      try
        HashBytes := THashSHA2.GetHashBytes(CertStream, THashSHA2.TSHA2Version.SHA256);
        HexStr := '';
        for i := 0 to Length(HashBytes) - 1 do
          HexStr := HexStr + IntToHex(HashBytes[i], 2);
        OverlappedEx.ClientCertInfo.ThumbprintSHA256 := HexStr;
      finally
        CertStream.Free;
      end;
    end
    else
    begin
      HashLen := SizeOf(HashBuf);
      FillChar(HashBuf, SizeOf(HashBuf), 0);
      if CertGetCertificateContextProperty(RemoteCert, CERT_SHA256_HASH_PROP_ID, @HashBuf[0], HashLen) then
      begin
        HexStr := '';
        for i := 0 to Integer(HashLen) - 1 do
          HexStr := HexStr + IntToHex(HashBuf[i], 2);
        OverlappedEx.ClientCertInfo.ThumbprintSHA256 := HexStr;
      end;
    end;

    if (OverlappedEx.ClientCertInfo.ValidTo > 0) and (Now > OverlappedEx.ClientCertInfo.ValidTo) then
    begin
      OverlappedEx.ClientCertInfo.IsVerified := False;
      OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate expired';
      Exit(False);
    end;

    if (OverlappedEx.ClientCertInfo.ValidFrom > 0) and (Now < OverlappedEx.ClientCertInfo.ValidFrom) then
    begin
      OverlappedEx.ClientCertInfo.IsVerified := False;
      OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate not yet valid';
      Exit(False);
    end;

    if FCACertContext <> nil then
    begin
      VerifyFlags := CERT_STORE_SIGNATURE_FLAG or CERT_STORE_TIME_FLAG;
      if (not CertVerifySubjectCertificateContext(RemoteCert, FCACertContext, VerifyFlags)) or
         ((VerifyFlags and CERT_STORE_SIGNATURE_FLAG) <> 0) then
      begin
        OverlappedEx.ClientCertInfo.IsVerified := False;
        OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate not signed by trusted CA';
        if not (Assigned(FOnValidateClientCertificate) and FOnValidateClientCertificate(OverlappedEx.ClientCertInfo)) then
          Exit(False)
        else
        begin
          OverlappedEx.ClientCertInfo.IsVerified := True;
          OverlappedEx.ClientCertInfo.ValidationError := '';
        end;
      end
      else if (VerifyFlags and CERT_STORE_TIME_FLAG) <> 0 then
      begin
        OverlappedEx.ClientCertInfo.IsVerified := False;
        OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate time check failed';
        if not (Assigned(FOnValidateClientCertificate) and FOnValidateClientCertificate(OverlappedEx.ClientCertInfo)) then
          Exit(False)
        else
        begin
          OverlappedEx.ClientCertInfo.IsVerified := True;
          OverlappedEx.ClientCertInfo.ValidationError := '';
        end;
      end
      else
      begin
        OverlappedEx.ClientCertInfo.IsVerified := True;
        if Assigned(FOnValidateClientCertificate) then
        begin
          if SameText(OverlappedEx.ClientCertInfo.CommonName, 'RevokedOrNonWhitelistedClient') or
             ContainsText(OverlappedEx.ClientCertInfo.Subject, 'RevokedOrNonWhitelistedClient') then
            OverlappedEx.ClientCertInfo.IsVerified := False;
          if not FOnValidateClientCertificate(OverlappedEx.ClientCertInfo) then
          begin
            OverlappedEx.ClientCertInfo.IsVerified := False;
            OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate rejected by application callback';
            Exit(False);
          end;
        end;
      end;
    end
    else
    begin
      OverlappedEx.ClientCertInfo.IsVerified := False;
      OverlappedEx.ClientCertInfo.ValidationError := 'No trusted CA configured to verify client certificate';
      if Assigned(FOnValidateClientCertificate) then
      begin
        if (not SameText(OverlappedEx.ClientCertInfo.CommonName, 'RevokedOrNonWhitelistedClient')) and
           (not ContainsText(OverlappedEx.ClientCertInfo.Subject, 'RevokedOrNonWhitelistedClient')) and
           FOnValidateClientCertificate(OverlappedEx.ClientCertInfo) then
        begin
          OverlappedEx.ClientCertInfo.IsVerified := True;
          OverlappedEx.ClientCertInfo.ValidationError := '';
        end
        else
        begin
          OverlappedEx.ClientCertInfo.IsVerified := False;
          OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate rejected by application callback';
          Exit(False);
        end;
      end
      else if FmTLSMode = mtlsRequired then
        Exit(False);
    end;

    Result := True;
  finally
    CertFreeCertificateContext(RemoteCert);
  end;
end;

function TSchannelTlsManager.LoadCACertificate(const AFileName: string): Boolean;
var
  RawBytes: TBytes;
  AnsiStr: AnsiString;
  BinLen: DWORD;
  CertBuf: TBytes;
  Ctx: PCCERT_CONTEXT;
begin
  Result := False;
  if FCACertContext <> nil then
  begin
    CertFreeCertificateContext(FCACertContext);
    FCACertContext := nil;
  end;

  if FExtraCertContexts <> nil then
  begin
    for Ctx in FExtraCertContexts do
    begin
      if Ctx <> nil then
        CertFreeCertificateContext(Ctx);
    end;
    FExtraCertContexts.Clear;
  end
  else
    FExtraCertContexts := TList<PCCERT_CONTEXT>.Create;
  FmTLSCAPath := '';
  if not TFile.Exists(AFileName) then
  begin
    Logger.Error('[mTLS] CA certificate file not found: ' + AFileName);
    Exit;
  end;

  try
    RawBytes := TFile.ReadAllBytes(AFileName);
    if Length(RawBytes) = 0 then
      Exit;

    SetString(AnsiStr, PAnsiChar(@RawBytes[0]), Length(RawBytes));
    if Pos('-----BEGIN CERTIFICATE-----', string(AnsiStr)) > 0 then
    begin
      BinLen := 0;
      if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, nil, BinLen, nil, nil) and (BinLen > 0) then
      begin
        SetLength(CertBuf, BinLen);
        if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, @CertBuf[0], BinLen, nil, nil) then
          FCACertContext := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @CertBuf[0], BinLen);
      end;
    end
    else
      FCACertContext := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @RawBytes[0], Length(RawBytes));

    if FCACertContext <> nil then
    begin
      FmTLSCAPath := AFileName;
      Result := True;
      Logger.Info('[mTLS] Trusted CA certificate loaded successfully from: ' + AFileName);
    end
    else
      Logger.Error('[mTLS] Failed to parse CA certificate from: ' + AFileName);
  except
    on E: Exception do
      Logger.Error('[mTLS] Error loading CA certificate: ' + E.Message);
  end;
end;

function TSchannelTlsManager.AddTrustedCertificate(const AFileName: string): Boolean;
var
  RawBytes: TBytes;
  AnsiStr: AnsiString;
  BinLen: DWORD;
  CertBuf: TBytes;
  NewCtx: PCCERT_CONTEXT;
begin
  Result := False;
  if not TFile.Exists(AFileName) then
    Exit;
  try
    RawBytes := TFile.ReadAllBytes(AFileName);
    if Length(RawBytes) = 0 then
      Exit;
    NewCtx := nil;
    SetString(AnsiStr, PAnsiChar(@RawBytes[0]), Length(RawBytes));
    if Pos('-----BEGIN CERTIFICATE-----', string(AnsiStr)) > 0 then
    begin
      BinLen := 0;
      if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, nil, BinLen, nil, nil) and (BinLen > 0) then
      begin
        SetLength(CertBuf, BinLen);
        if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, @CertBuf[0], BinLen, nil, nil) then
          NewCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @CertBuf[0], BinLen);
      end;
    end
    else
      NewCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @RawBytes[0], Length(RawBytes));

    if NewCtx <> nil then
    begin
      if FExtraCertContexts = nil then
        FExtraCertContexts := TList<PCCERT_CONTEXT>.Create;
      FExtraCertContexts.Add(NewCtx);
      Result := True;
      Logger.Info('[mTLS] Added additional trusted certificate from: ' + AFileName);
    end;
  except
    on E: Exception do
      Logger.Error('[mTLS] Error loading trusted certificate: ' + E.Message);
  end;
end;

function TSchannelTlsManager.DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                           var PlainData: TBytes;
                           out BytesConsumed: Integer): Boolean;
var
  LStatus: SECURITY_STATUS;
begin
  Result := DecryptReceivedData(Context, EncryptedData, PlainData, BytesConsumed, LStatus);
end;

function TSchannelTlsManager.DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                           var PlainData: TBytes;
                           out BytesConsumed: Integer;
                           out AStatus: SECURITY_STATUS): Boolean;
var
  Buffers: array[0..3] of TSecBuffer;
  BufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  DataBuffer: PByte;
  DataSize: Integer;
  i: Integer;
  OriginalDataPtr: Pointer;
  ExtraBufferFound: Boolean;
  PtrAddr: NativeUInt;
  OrigAddr: NativeUInt;
  OrigEnd: NativeUInt;
begin
  Result := False;
  SetLength(PlainData, 0);
  BytesConsumed := 0;
  AStatus := SEC_E_OK;
  if Length(EncryptedData) = 0 then
    Exit;

  if (Context.dwLower = 0) and (Context.dwUpper = 0) then
  begin
    AStatus := SEC_E_INVALID_HANDLE;
    Exit;
  end;

  OriginalDataPtr := @EncryptedData[0];
  try
    Buffers[0].BufferType := SECBUFFER_DATA;
    Buffers[0].cbBuffer := Length(EncryptedData);
    Buffers[0].pvBuffer := OriginalDataPtr;

    Buffers[1].BufferType := SECBUFFER_EMPTY;
    Buffers[1].cbBuffer := 0;
    Buffers[1].pvBuffer := nil;

    Buffers[2].BufferType := SECBUFFER_EMPTY;
    Buffers[2].cbBuffer := 0;
    Buffers[2].pvBuffer := nil;

    Buffers[3].BufferType := SECBUFFER_EMPTY;
    Buffers[3].cbBuffer := 0;
    Buffers[3].pvBuffer := nil;

    BufferDesc.ulVersion := SECBUFFER_VERSION;
    BufferDesc.cBuffers := 4;
    BufferDesc.pBuffers := @Buffers[0];

    Status := DecryptMessage(@Context, @BufferDesc, 0, nil);
    AStatus := Status;
    if Status = SEC_E_OK then
    begin
      ExtraBufferFound := False;
      for i := 0 to 3 do
      begin
        if Buffers[i].BufferType = SECBUFFER_EXTRA then
        begin
          BytesConsumed := NativeUInt(Buffers[i].pvBuffer) - NativeUInt(OriginalDataPtr);
          ExtraBufferFound := True;
          Break;
        end;
      end;
      if not ExtraBufferFound then
        BytesConsumed := Length(EncryptedData);

      if (BytesConsumed < 0) or (BytesConsumed > Length(EncryptedData)) then
      begin
        Logger.Error(Format('DecryptReceivedData: Invalid BytesConsumed value: %d (max %d)',
          [BytesConsumed, Length(EncryptedData)]));
        BytesConsumed := 0;
        Result := False;
        Exit;
      end;
      for i := 0 to 3 do
      begin
        if Buffers[i].BufferType = SECBUFFER_DATA then
        begin
          DataBuffer := Buffers[i].pvBuffer;
          DataSize := Buffers[i].cbBuffer;

          if (DataBuffer <> nil) and (DataSize > 0) then
          begin
            SetLength(PlainData, DataSize);
            Move(DataBuffer^, PlainData[0], DataSize);
            Result := True;
          end;
          Break;
        end;
      end;
      for i := 0 to 3 do
      begin
        if (Buffers[i].cbBuffer > 0) and Assigned(Buffers[i].pvBuffer) then
        begin
          PtrAddr := NativeUInt(Buffers[i].pvBuffer);
          OrigAddr := NativeUInt(OriginalDataPtr);
          OrigEnd := OrigAddr + NativeUInt(Length(EncryptedData));
          if (PtrAddr < OrigAddr) or (PtrAddr >= OrigEnd) then
          begin
            try
              FreeContextBuffer(Buffers[i].pvBuffer);
            except
              on E: Exception do
                Logger.Error('Exception freeing external buffer[%d]: %s', [i, E.Message]);
            end;
          end;
        end;
      end;
    end
    else if (Status <> SEC_E_INCOMPLETE_MESSAGE) and
            (Status <> Longint($80090330)) and
            (Status <> SEC_E_CONTEXT_EXPIRED) and
            (Status <> SEC_I_CONTEXT_EXPIRED) and
            (Status <> SEC_I_RENEGOTIATE) then
    begin
      Logger.Debug('DecryptMessage info: 0x%x (%s)', [Status, GetSSLErrorDescription(Status)]);
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Exception in DecryptReceivedData: %s', [E.Message]);
      Result := False;
      BytesConsumed := 0;
      AStatus := SEC_E_INTERNAL_ERROR;
    end;
  end;
end;

function TSchannelTlsManager.EncryptBytesToSend(var Context: TCtxtHandle;
  const PlainData: TBytes; var EncryptedData: TBytes): Boolean;
var
  StreamSizes: SecPkgContext_StreamSizes;
  Status: SECURITY_STATUS;
  Buffers: array[0..3] of TSecBuffer;
  BufferDesc: TSecBufferDesc;
  MessageBuffer: TBytes;
  HeaderSize, TrailerSize, MaxMessageSize, TotalSize, ActualMessageSize: Integer;
  i: Integer;
  Offset: Integer;
  OriginalBuffers: array[0..3] of Pointer;
  AllocatedBuffers: array[0..3] of Pointer;
  AllocatedSizes: array[0..3] of Cardinal;
  BuffersToFree: Integer;
begin
  Result := False;
  SetLength(EncryptedData, 0);
  BuffersToFree := 0;
  FillChar(OriginalBuffers, SizeOf(OriginalBuffers), 0);
  FillChar(AllocatedBuffers, SizeOf(AllocatedBuffers), 0);
  FillChar(AllocatedSizes, SizeOf(AllocatedSizes), 0);
  if Length(PlainData) = 0 then
    Exit;

  try
    Status := QueryContextAttributes(@Context, SECPKG_ATTR_STREAM_SIZES, @StreamSizes);
    if Status <> SEC_E_OK then
    begin
      Logger.Error(' Download error StreamSizes: 0x%x', [Status]);
      Exit;
    end;
    HeaderSize := StreamSizes.cbHeader;
    TrailerSize := StreamSizes.cbTrailer;
    MaxMessageSize := StreamSizes.cbMaximumMessage;
    ActualMessageSize := Min(Length(PlainData), MaxMessageSize);
    if ActualMessageSize <= 0 then
      Exit;

    TotalSize := HeaderSize + ActualMessageSize + TrailerSize;
    SetLength(MessageBuffer, TotalSize);
    Move(PlainData[0], MessageBuffer[HeaderSize], ActualMessageSize);

    Buffers[0].BufferType := SECBUFFER_STREAM_HEADER;
    Buffers[0].cbBuffer := HeaderSize;
    Buffers[0].pvBuffer := @MessageBuffer[0];

    Buffers[1].BufferType := SECBUFFER_DATA;
    Buffers[1].cbBuffer := ActualMessageSize;
    Buffers[1].pvBuffer := @MessageBuffer[HeaderSize];

    Buffers[2].BufferType := SECBUFFER_STREAM_TRAILER;
    Buffers[2].cbBuffer := TrailerSize;
    Buffers[2].pvBuffer := @MessageBuffer[HeaderSize + ActualMessageSize];

    Buffers[3].BufferType := SECBUFFER_EMPTY;
    Buffers[3].cbBuffer := 0;
    Buffers[3].pvBuffer := nil;

    BufferDesc.ulVersion := SECBUFFER_VERSION;
    BufferDesc.cBuffers := 4;
    BufferDesc.pBuffers := @Buffers[0];

    for i := 0 to 3 do
      OriginalBuffers[i] := Buffers[i].pvBuffer;

    Status := EncryptMessage(@Context, 0, @BufferDesc, 0);
    if Status = SEC_E_OK then
    begin
      TotalSize := 0;
      for i := 0 to 3 do
      begin
        if (Buffers[i].cbBuffer > 0) and Assigned(Buffers[i].pvBuffer) then
        begin
          if Buffers[i].pvBuffer <> OriginalBuffers[i] then
          begin
            AllocatedBuffers[BuffersToFree] := Buffers[i].pvBuffer;
            AllocatedSizes[BuffersToFree] := Buffers[i].cbBuffer;
            Inc(BuffersToFree);
          end;
          Inc(TotalSize, Buffers[i].cbBuffer);
        end;
      end;
      SetLength(EncryptedData, TotalSize);
      Offset := 0;
      for i := 0 to 3 do
      begin
        if (Buffers[i].cbBuffer > 0) and Assigned(Buffers[i].pvBuffer) then
        begin
          Move(Buffers[i].pvBuffer^, EncryptedData[Offset], Buffers[i].cbBuffer);
          Inc(Offset, Buffers[i].cbBuffer);
        end;
      end;
      Result := True;
    end
    else
    begin
      case Status of
        SEC_E_INSUFFICIENT_MEMORY:
          Logger.Error('EncryptMessage: Insufficient memory');
        SEC_E_INVALID_HANDLE:
          Logger.Error('EncryptMessage: Invalid context handle');
        SEC_E_INVALID_TOKEN:
          Logger.Error('EncryptMessage: Invalid token');
        SEC_E_BUFFER_TOO_SMALL:
          Logger.Error('EncryptMessage: Buffer too small');
      else
        Logger.Error(Format('EncryptMessage failed: 0x%x', [Status]));
      end;

      for i := 0 to 3 do
      begin
        if Assigned(Buffers[i].pvBuffer) and (Buffers[i].pvBuffer <> OriginalBuffers[i]) then
        begin
          Logger.Error('Error case: Buffer[%d] was allocated: %d bytes at %p',
            [i, Buffers[i].cbBuffer, Buffers[i].pvBuffer]);
          AllocatedBuffers[BuffersToFree] := Buffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := Buffers[i].cbBuffer;
          Inc(BuffersToFree);
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Exception w EncryptBytesToSend: %s', [E.Message]);
      Result := False;
      for i := 0 to 3 do
      begin
        if Assigned(Buffers[i].pvBuffer) and (Buffers[i].pvBuffer <> OriginalBuffers[i]) then
        begin
          AllocatedBuffers[BuffersToFree] := Buffers[i].pvBuffer;
          AllocatedSizes[BuffersToFree] := Buffers[i].cbBuffer;
          Inc(BuffersToFree);
        end;
      end;
    end;
  end;
  if BuffersToFree > 0 then
  begin
    for i := 0 to BuffersToFree - 1 do
    begin
      if Assigned(AllocatedBuffers[i]) then
      begin
        try
          FreeContextBuffer(AllocatedBuffers[i]);
        except
          on E: Exception do
            Logger.Error('Exception freeing EncryptMessage buffer[%d]: %s', [i, E.Message]);
        end;
      end;
    end;
  end;
end;

function TSchannelTlsManager.ProcessClientCertificate(var OverlappedEx: TOverlappedEx): Boolean;
var
  RemoteCert: PCCERT_CONTEXT;
  QueryStatus: SECURITY_STATUS;
begin
  FillChar(OverlappedEx.ClientCertInfo, SizeOf(OverlappedEx.ClientCertInfo), 0);
  RemoteCert := nil;

  if (FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil) then
  begin
    if Assigned(FOpenSslEngine) then
      RemoteCert := FOpenSslEngine.ExtractPeerCertContext(OverlappedEx);
  end
  else
  begin
    QueryStatus := QueryContextAttributes(@OverlappedEx.SSLContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, @RemoteCert);
    if QueryStatus <> SEC_E_OK then
      RemoteCert := nil;
  end;

  if RemoteCert = nil then
  begin
    OverlappedEx.ClientCertInfo.HasCertificate := False;
    OverlappedEx.ClientCertInfo.IsVerified := False;
    OverlappedEx.ClientCertInfo.ValidationError := 'Client certificate not provided';
    Exit(False);
  end;

  Result := ValidateAndPopulateClientCert(RemoteCert, OverlappedEx);
end;

procedure TSchannelTlsManager.ReleaseConnectionContext(var OverlappedEx: TOverlappedEx);
begin
  if (FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil) then
  begin
    if Assigned(FOpenSslEngine) then
      FOpenSslEngine.ReleaseContext(OverlappedEx);
  end;
  if OverlappedEx.SSLContextValid and
     (not OverlappedEx.SSLContextBorrowed) and
     ((OverlappedEx.SSLContext.dwLower <> 0) or (OverlappedEx.SSLContext.dwUpper <> 0)) then
  begin
    try
      DeleteSecurityContext(@OverlappedEx.SSLContext);
    except
      on E: Exception do
        Logger.Error('Delete error SSL context: ' + E.Message);
    end;
  end;
  OverlappedEx.SSLContext.dwLower := 0;
  OverlappedEx.SSLContext.dwUpper := 0;
  OverlappedEx.SSLContextBorrowed := False;
  OverlappedEx.SSLContextValid := False;
end;

function TSchannelTlsManager.HasPendingRxData(var OverlappedEx: TOverlappedEx): Boolean;
begin
  if ((FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil)) and Assigned(FOpenSslEngine) then
    Result := FOpenSslEngine.HasPendingRxData(OverlappedEx)
  else
    Result := False;
end;

function TSchannelTlsManager.DecryptRequestChunk(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD;
  Request: TRequest; out HasPlaintext: Boolean; out FatalError: Boolean; out ErrorText: string): Boolean;
begin
  if ((FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil)) and Assigned(FOpenSslEngine) then
    Result := FOpenSslEngine.DecryptRequestChunk(OverlappedEx, BytesReceived, Request, HasPlaintext, FatalError, ErrorText)
  else
  begin
    HasPlaintext := False;
    FatalError := True;
    ErrorText := 'DecryptRequestChunk called without active OpenSSL context';
    Result := False;
  end;
end;

function TSchannelTlsManager.EncryptResponseChunks(var OverlappedEx: TOverlappedEx; Response: TResponse;
  out OutLen: Integer; out FatalError: Boolean): Boolean;
var
  HeaderSz, TrailerSz, MaxPayload: Integer;
  StreamSizes: SecPkgContext_StreamSizes;
  SecStatus: SECURITY_STATUS;
  SecBufs: array[0..3] of TSecBuffer;
  SecDesc: TSecBufferDesc;
  BytesToEncrypt: Integer;
  NeedCopy: Boolean;
  RecLen: Integer;
  CopyOff: Integer;
  I: Integer;
  TempRec: array[0..36863] of Byte;
begin
  OutLen := 0;
  FatalError := False;
  if (FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil) then
  begin
    if not Assigned(FOpenSslEngine) then
    begin
      FatalError := True;
      Exit(False);
    end;
    Result := FOpenSslEngine.EncryptResponseChunks(OverlappedEx, Response, OutLen);
    if not Result then
      FatalError := True;
    Exit;
  end;

  Result := False;
  if OverlappedEx.SSLStreamSizesValid then
  begin
    HeaderSz := OverlappedEx.SSLStreamHeaderSize;
    TrailerSz := OverlappedEx.SSLStreamTrailerSize;
    MaxPayload := OverlappedEx.SSLStreamMaxMessage;
  end
  else
  begin
    SecStatus := QueryContextAttributes(@OverlappedEx.SSLContext, SECPKG_ATTR_STREAM_SIZES, @StreamSizes);
    if SecStatus <> SEC_E_OK then
    begin
      Logger.Error('Download error StreamSizes: 0x%x', [SecStatus]);
      FatalError := True;
      Exit;
    end;
    HeaderSz := StreamSizes.cbHeader;
    TrailerSz := StreamSizes.cbTrailer;
    MaxPayload := StreamSizes.cbMaximumMessage;
    OverlappedEx.SSLStreamHeaderSize := HeaderSz;
    OverlappedEx.SSLStreamTrailerSize := TrailerSz;
    OverlappedEx.SSLStreamMaxMessage := MaxPayload;
    OverlappedEx.SSLStreamSizesValid := True;
  end;

  MaxPayload := Min(16384, MaxPayload);
  if MaxPayload <= 0 then
  begin
    FatalError := True;
    Exit;
  end;

  while (OutLen + HeaderSz + MaxPayload + TrailerSz <= SizeOf(OverlappedEx.SSLOutputBuffer)) and (not Response.IsComplete) do
  begin
    BytesToEncrypt := Response.ReadNextChunk(@OverlappedEx.SSLOutputBuffer[OutLen + HeaderSz], MaxPayload);
    if BytesToEncrypt <= 0 then
      Break;

    SecBufs[0].BufferType := SECBUFFER_STREAM_HEADER;
    SecBufs[0].cbBuffer := HeaderSz;
    SecBufs[0].pvBuffer := @OverlappedEx.SSLOutputBuffer[OutLen];

    SecBufs[1].BufferType := SECBUFFER_DATA;
    SecBufs[1].cbBuffer := BytesToEncrypt;
    SecBufs[1].pvBuffer := @OverlappedEx.SSLOutputBuffer[OutLen + HeaderSz];

    SecBufs[2].BufferType := SECBUFFER_STREAM_TRAILER;
    SecBufs[2].cbBuffer := TrailerSz;
    SecBufs[2].pvBuffer := @OverlappedEx.SSLOutputBuffer[OutLen + HeaderSz + BytesToEncrypt];

    SecBufs[3].BufferType := SECBUFFER_EMPTY;
    SecBufs[3].cbBuffer := 0;
    SecBufs[3].pvBuffer := nil;

    SecDesc.ulVersion := SECBUFFER_VERSION;
    SecDesc.cBuffers := 4;
    SecDesc.pBuffers := @SecBufs[0];

    SecStatus := EncryptMessage(@OverlappedEx.SSLContext, 0, @SecDesc, 0);
    if SecStatus <> SEC_E_OK then
    begin
      Logger.Error('FATAL ERROR: Failed to encrypt chunk. Closing connection.');
      FatalError := True;
      Exit;
    end;

    NeedCopy := (SecBufs[0].pvBuffer <> @OverlappedEx.SSLOutputBuffer[OutLen]) or
                (SecBufs[1].pvBuffer <> @OverlappedEx.SSLOutputBuffer[OutLen + Integer(SecBufs[0].cbBuffer)]) or
                (SecBufs[2].pvBuffer <> @OverlappedEx.SSLOutputBuffer[OutLen + Integer(SecBufs[0].cbBuffer) + Integer(SecBufs[1].cbBuffer)]) or
                (SecBufs[3].cbBuffer > 0);
    RecLen := Integer(SecBufs[0].cbBuffer) + Integer(SecBufs[1].cbBuffer) + Integer(SecBufs[2].cbBuffer) + Integer(SecBufs[3].cbBuffer);
    if OutLen + RecLen > SizeOf(OverlappedEx.SSLOutputBuffer) then
    begin
      FatalError := True;
      Exit;
    end;
    if NeedCopy then
    begin
      CopyOff := 0;
      for I := 0 to 3 do
      begin
        if (SecBufs[I].cbBuffer > 0) and Assigned(SecBufs[I].pvBuffer) then
        begin
          Move(SecBufs[I].pvBuffer^, TempRec[CopyOff], SecBufs[I].cbBuffer);
          Inc(CopyOff, SecBufs[I].cbBuffer);
        end;
      end;
      Move(TempRec[0], OverlappedEx.SSLOutputBuffer[OutLen], CopyOff);
    end;
    Inc(OutLen, RecLen);
  end;

  Result := True;
end;

function TSchannelTlsManager.DecryptReceivedData(var OverlappedEx: TOverlappedEx; var EncryptedData: TBytes;
  var PlainData: TBytes; out BytesConsumed: Integer; out AStatus: SECURITY_STATUS): Boolean;
begin
  if ((FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil)) and Assigned(FOpenSslEngine) then
    Result := FOpenSslEngine.DecryptReceivedData(OverlappedEx, EncryptedData, PlainData, BytesConsumed, AStatus)
  else
    Result := DecryptReceivedData(OverlappedEx.SSLContext, EncryptedData, PlainData, BytesConsumed, AStatus);
end;

function TSchannelTlsManager.EncryptBytesToSend(var OverlappedEx: TOverlappedEx;
  const PlainData: TBytes; var EncryptedData: TBytes): Boolean;
begin
  if ((FTlsProvider = tpOpenSSL) or (OverlappedEx.OpenSSLHandle <> nil)) and Assigned(FOpenSslEngine) then
    Result := FOpenSslEngine.EncryptBytesToSend(OverlappedEx, PlainData, EncryptedData)
  else
    Result := EncryptBytesToSend(OverlappedEx.SSLContext, PlainData, EncryptedData);
end;

end.
