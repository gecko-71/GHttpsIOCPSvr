unit GOpenSslApi;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils,
  System.SyncObjs;

const
  SSL_ERROR_NONE = 0;
  SSL_ERROR_SSL = 1;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_SYSCALL = 5;
  SSL_ERROR_ZERO_RETURN = 6;

  SSL_VERIFY_NONE = $00;
  SSL_VERIFY_PEER = $01;
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = $02;

  SSL_TLSEXT_ERR_OK = 0;
  SSL_TLSEXT_ERR_ALERT_FATAL = 2;
  SSL_TLSEXT_ERR_NOACK = 3;

  SSL_CTRL_EXTRA_CHAIN_CERT = 14;
  SSL_CTRL_SET_SESS_CACHE_MODE = 44;
  SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
  SSL_CTRL_SET_MAX_PROTO_VERSION = 124;

  TLS1_2_VERSION = $0303;
  TLS1_3_VERSION = $0304;

  SSL_SESS_CACHE_OFF = $0000;
  SSL_SESS_CACHE_SERVER = $0002;

  SSL_OP_NO_TICKET = UInt64($00004000);
  SSL_OP_CIPHER_SERVER_PREFERENCE = UInt64($00400000);
  SSL_OP_NO_SSLv3 = UInt64($02000000);
  SSL_OP_NO_TLSv1 = UInt64($04000000);
  SSL_OP_NO_TLSv1_1 = UInt64($10000000);

  SSL_FILETYPE_PEM = 1;
  OPENSSL_INIT_LOAD_SSL_STRINGS = UInt64($00200000);
  OPENSSL_INIT_LOAD_CRYPTO_STRINGS = UInt64($00000002);
  OPENSSL_VERSION_STRING_ID = 0;
  EVP_PKEY_RSA = 6;
  EVP_PKEY_EC = 408;

type
  PSSL_METHOD = Pointer;
  PSSL_CTX = Pointer;
  PSSL = Pointer;
  PBIO_METHOD = Pointer;
  PBIO = Pointer;
  PX509 = Pointer;
  PX509_Ptr = ^PX509;
  PEVP_PKEY = Pointer;
  PEVP_PKEY_Ptr = ^PEVP_PKEY;
  PPKCS12 = Pointer;
  PX509_STORE = Pointer;
  PASN1_TIME = Pointer;
  PX509_NAME = Pointer;
  PEVP_MD = Pointer;
  PSTACK_OF_X509 = Pointer;
  PSTACK_OF_X509_Ptr = ^PSTACK_OF_X509;
  PPByte = ^PByte;

  TOpenSslVerifyCb = function(PreverifyOk: Integer; X509Ctx: Pointer): Integer; cdecl;
  TOpenSslAlpnSelectCb = function(Ssl: PSSL; OutProto: PPByte; OutLen: PByte;
    InProto: PByte; InLen: Cardinal; Arg: Pointer): Integer; cdecl;
  TOpenSslFreeElementProc = procedure(Element: Pointer); cdecl;

var
  OsslOpenSSLVersion: function(VersionType: Integer): PAnsiChar; cdecl = nil;
  OsslInitSsl: function(Opts: UInt64; Settings: Pointer): Integer; cdecl = nil;

  OsslTlsServerMethod: function: PSSL_METHOD; cdecl = nil;
  OsslTlsClientMethod: function: PSSL_METHOD; cdecl = nil;

  OsslSslCtxNew: function(Meth: PSSL_METHOD): PSSL_CTX; cdecl = nil;
  OsslSslCtxFree: procedure(Ctx: PSSL_CTX); cdecl = nil;
  OsslSslCtxCtrl: function(Ctx: PSSL_CTX; Cmd: Integer; Larg: LongInt; Parg: Pointer): LongInt; cdecl = nil;
  OsslSslCtxSetOptions: function(Ctx: PSSL_CTX; Options: UInt64): UInt64; cdecl = nil;
  OsslSslCtxClearOptions: function(Ctx: PSSL_CTX; Options: UInt64): UInt64; cdecl = nil;
  OsslSslCtxSetCipherList: function(Ctx: PSSL_CTX; Str: PAnsiChar): Integer; cdecl = nil;
  OsslSslCtxSetCiphersuites: function(Ctx: PSSL_CTX; Str: PAnsiChar): Integer; cdecl = nil;
  OsslSslCtxSetSessionIdContext: function(Ctx: PSSL_CTX; SidCtx: PByte; SidCtxLen: Cardinal): Integer; cdecl = nil;
  OsslSslCtxSetVerify: procedure(Ctx: PSSL_CTX; Mode: Integer; Callback: TOpenSslVerifyCb); cdecl = nil;
  OsslSslCtxGetCertStore: function(Ctx: PSSL_CTX): PX509_STORE; cdecl = nil;
  OsslSslCtxAddClientCA: function(Ctx: PSSL_CTX; Cert: PX509): Integer; cdecl = nil;
  OsslSslCtxUseCertificate: function(Ctx: PSSL_CTX; Cert: PX509): Integer; cdecl = nil;
  OsslSslCtxUsePrivateKey: function(Ctx: PSSL_CTX; PKey: PEVP_PKEY): Integer; cdecl = nil;
  OsslSslCtxUseCertificateChainFile: function(Ctx: PSSL_CTX; FileName: PAnsiChar): Integer; cdecl = nil;
  OsslSslCtxUsePrivateKeyFile: function(Ctx: PSSL_CTX; FileName: PAnsiChar; FileType: Integer): Integer; cdecl = nil;
  OsslSslCtxSetDefaultPasswdCbUserdata: procedure(Ctx: PSSL_CTX; UserData: Pointer); cdecl = nil;
  OsslSslCtxCheckPrivateKey: function(Ctx: PSSL_CTX): Integer; cdecl = nil;
  OsslSslCtxSetAlpnSelectCb: procedure(Ctx: PSSL_CTX; Cb: TOpenSslAlpnSelectCb; Arg: Pointer); cdecl = nil;

  OsslSslNew: function(Ctx: PSSL_CTX): PSSL; cdecl = nil;
  OsslSslFree: procedure(Ssl: PSSL); cdecl = nil;
  OsslSslSetAcceptState: procedure(Ssl: PSSL); cdecl = nil;
  OsslSslSetConnectState: procedure(Ssl: PSSL); cdecl = nil;
  OsslSslSetBio: procedure(Ssl: PSSL; RBio, WBio: PBIO); cdecl = nil;
  OsslSslAccept: function(Ssl: PSSL): Integer; cdecl = nil;
  OsslSslConnect: function(Ssl: PSSL): Integer; cdecl = nil;
  OsslSslReadEx: function(Ssl: PSSL; Buf: Pointer; Num: NativeUInt; var ReadBytes: NativeUInt): Integer; cdecl = nil;
  OsslSslWriteEx: function(Ssl: PSSL; Buf: Pointer; Num: NativeUInt; var Written: NativeUInt): Integer; cdecl = nil;
  OsslSslPending: function(Ssl: PSSL): Integer; cdecl = nil;
  OsslSslShutdown: function(Ssl: PSSL): Integer; cdecl = nil;
  OsslSslGetError: function(Ssl: PSSL; RetCode: Integer): Integer; cdecl = nil;
  OsslSslGet0AlpnSelected: procedure(Ssl: PSSL; out Data: PByte; out Len: Cardinal); cdecl = nil;
  OsslSslSetAlpnProtos: function(Ssl: PSSL; Protos: PByte; ProtosLen: Cardinal): Integer; cdecl = nil;
  OsslSslGet1PeerCertificate: function(Ssl: PSSL): PX509; cdecl = nil;
  OsslSslSessionReused: function(Ssl: PSSL): LongInt; cdecl = nil;

  OsslBioSMem: function: PBIO_METHOD; cdecl = nil;
  OsslBioNew: function(BioType: PBIO_METHOD): PBIO; cdecl = nil;
  OsslBioNewMemBuf: function(Buf: Pointer; Len: Integer): PBIO; cdecl = nil;
  OsslBioFree: function(Bio: PBIO): Integer; cdecl = nil;
  OsslBioRead: function(Bio: PBIO; Data: Pointer; Len: Integer): Integer; cdecl = nil;
  OsslBioWrite: function(Bio: PBIO; Data: Pointer; Len: Integer): Integer; cdecl = nil;
  OsslBioCtrlPending: function(Bio: PBIO): NativeUInt; cdecl = nil;

  OsslX509StoreAddCert: function(Store: PX509_STORE; Cert: PX509): Integer; cdecl = nil;
  OsslD2iX509: function(CertPtr: PX509_Ptr; InPtr: PPByte; Len: LongInt): PX509; cdecl = nil;
  OsslI2dX509: function(Cert: PX509; OutPtr: PPByte): Integer; cdecl = nil;
  OsslX509Free: procedure(Cert: PX509); cdecl = nil;
  OsslD2iAutoPrivateKey: function(KeyPtr: PEVP_PKEY_Ptr; InPtr: PPByte; Len: LongInt): PEVP_PKEY; cdecl = nil;
  OsslEvpPkeyFree: procedure(PKey: PEVP_PKEY); cdecl = nil;
  OsslD2iPkcs12Bio: function(Bio: PBIO; P12Ptr: Pointer): PPKCS12; cdecl = nil;
  OsslI2dPkcs12Bio: function(Bio: PBIO; P12: PPKCS12): Integer; cdecl = nil;
  OsslPkcs12Create: function(Pass: PAnsiChar; Name: PAnsiChar; PKey: PEVP_PKEY; Cert: PX509; Ca: PSTACK_OF_X509; NidKey, NidCert, Iter, MacIter, KeyType: Integer): PPKCS12; cdecl = nil;
  OsslPkcs12Parse: function(P12: PPKCS12; Pass: PAnsiChar; PKeyPtr: PEVP_PKEY_Ptr; CertPtr: PX509_Ptr; CaPtr: PSTACK_OF_X509_Ptr): Integer; cdecl = nil;
  OsslPkcs12Free: procedure(P12: PPKCS12); cdecl = nil;
  OsslPemReadBioX509: function(Bio: PBIO; X: PX509_Ptr; Cb: Pointer; U: Pointer): PX509; cdecl = nil;
  OsslPemReadBioPrivateKey: function(Bio: PBIO; X: PEVP_PKEY_Ptr; Cb: Pointer; U: Pointer): PEVP_PKEY; cdecl = nil;
  OsslX509Get0NotBefore: function(const X: PX509): PASN1_TIME; cdecl = nil;
  OsslX509Get0NotAfter: function(const X: PX509): PASN1_TIME; cdecl = nil;
  OsslX509CmpTime: function(const S: PASN1_TIME; CmpTime: PInt64): Integer; cdecl = nil;
  OsslAsn1TimeDiff: function(var PDay: Integer; var PSec: Integer; const FromTime: PASN1_TIME; const ToTime: PASN1_TIME): Integer; cdecl = nil;
  OsslX509Get0Pubkey: function(const X: PX509): PEVP_PKEY; cdecl = nil;
  OsslEvpPkeyGetBaseId: function(const PKey: PEVP_PKEY): Integer; cdecl = nil;
  OsslEvpPkeyGetBits: function(const PKey: PEVP_PKEY): Integer; cdecl = nil;
  OsslX509CheckPrivateKey: function(const X: PX509; const PKey: PEVP_PKEY): Integer; cdecl = nil;
  OsslX509GetSubjectName: function(const X: PX509): PX509_NAME; cdecl = nil;
  OsslX509GetIssuerName: function(const X: PX509): PX509_NAME; cdecl = nil;
  OsslX509NameCmp: function(const A: PX509_NAME; const B: PX509_NAME): Integer; cdecl = nil;
  OsslX509Digest: function(const Data: PX509; const MdType: PEVP_MD; Md: PByte; var Len: Cardinal): Integer; cdecl = nil;
  OsslEvpSha256: function: PEVP_MD; cdecl = nil;
  OsslEvpSha1: function: PEVP_MD; cdecl = nil;
  OsslSkNum: function(Stack: PSTACK_OF_X509): Integer; cdecl = nil;
  OsslSkValue: function(Stack: PSTACK_OF_X509; Idx: Integer): Pointer; cdecl = nil;
  OsslSkPop: function(Stack: PSTACK_OF_X509): Pointer; cdecl = nil;
  OsslSkFree: procedure(Stack: PSTACK_OF_X509); cdecl = nil;
  OsslSkPopFree: procedure(Stack: PSTACK_OF_X509; FreeFunc: TOpenSslFreeElementProc); cdecl = nil;

  OsslErrGetError: function: Cardinal; cdecl = nil;
  OsslErrErrorStringN: procedure(ErrCode: Cardinal; Buf: PAnsiChar; Len: NativeUInt); cdecl = nil;
  OsslErrClearError: procedure; cdecl = nil;
  OsslCryptoFree: procedure(Ptr: Pointer; FileName: PAnsiChar; LineNo: Integer); cdecl = nil;

procedure SetProcPtr(out ATarget; APtr: Pointer);
function EnsureOpenSslLoaded: Boolean;
function IsOpenSslLoaded: Boolean;
function GetOpenSslLoadError: string;
function GetOpenSslVersionText: string;
function GetLastOpenSslErrorString: string;
procedure ClearOpenSslErrors;

implementation

var
  GLoadLock: TCriticalSection = nil;
  GCryptoLib: HMODULE = 0;
  GSslLib: HMODULE = 0;
  GOpenSslLoaded: Boolean = False;
  GLastLoadError: string = '';

function LoadDllFromSearchPaths(const ADllName: string): HMODULE;
var
  ExeDir: string;
  Candidates: array[0..5] of string;
  I: Integer;
  FullPath: string;
begin
  ExeDir := ExcludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));
  if ExeDir <> '' then
  begin
    Candidates[0] := TPath.Combine(ExeDir, ADllName);
    Candidates[1] := TPath.GetFullPath(TPath.Combine(ExeDir, '..\Debug\' + ADllName));
    Candidates[2] := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\Win64\Debug\' + ADllName));
    Candidates[3] := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\..\Win64\Debug\' + ADllName));
    Candidates[4] := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\..\..\Win64\Debug\' + ADllName));
    Candidates[5] := TPath.Combine(GetCurrentDir, ADllName);
    for I := 0 to 5 do
    begin
      FullPath := Candidates[I];
      if FileExists(FullPath) then
      begin
        Result := LoadLibraryExW(PWideChar(FullPath), 0, LOAD_WITH_ALTERED_SEARCH_PATH);
        if Result <> 0 then
          Exit;
      end;
    end;
  end;
  Result := LoadLibraryW(PWideChar(ADllName));
end;

procedure SetProcPtr(out ATarget; APtr: Pointer);
begin
  Pointer(ATarget) := APtr;
end;

procedure BindProc(AModule: HMODULE; const AName: PAnsiChar; out ATarget; var AMissingList: string);
var
  P: Pointer;
begin
  P := GetProcAddress(AModule, AName);
  Pointer(ATarget) := P;
  if P = nil then
  begin
    if AMissingList <> '' then
      AMissingList := AMissingList + ', ';
    AMissingList := AMissingList + string(AName);
  end;
end;

function EnsureOpenSslLoaded: Boolean;
var
  CryptoName: string;
  SslName: string;
  Missing: string;
  SysErr: DWORD;
  TmpPtr: Pointer;
begin
  if GOpenSslLoaded then
    Exit(True);

  if not Assigned(GLoadLock) then
    Exit(False);

  GLoadLock.Enter;
  try
    if GOpenSslLoaded then
      Exit(True);

    GLastLoadError := '';
    Missing := '';
    {$IFDEF WIN64}
    CryptoName := 'libcrypto-3-x64.dll';
    SslName := 'libssl-3-x64.dll';
    {$ELSE}
    CryptoName := 'libcrypto-3.dll';
    SslName := 'libssl-3.dll';
    {$ENDIF}

    if GCryptoLib = 0 then
    begin
      GCryptoLib := LoadDllFromSearchPaths(CryptoName);
      if GCryptoLib = 0 then
      begin
        SysErr := GetLastError;
        GLastLoadError := Format('Failed to load %s (Win32 error %d: %s)', [CryptoName, SysErr, SysErrorMessage(SysErr)]);
        Exit(False);
      end;
    end;

    if GSslLib = 0 then
    begin
      GSslLib := LoadDllFromSearchPaths(SslName);
      if GSslLib = 0 then
      begin
        SysErr := GetLastError;
        GLastLoadError := Format('Failed to load %s (Win32 error %d: %s)', [SslName, SysErr, SysErrorMessage(SysErr)]);
        Exit(False);
      end;
    end;

    BindProc(GCryptoLib, 'OpenSSL_version', OsslOpenSSLVersion, Missing);
    BindProc(GSslLib, 'OPENSSL_init_ssl', OsslInitSsl, Missing);

    BindProc(GSslLib, 'TLS_server_method', OsslTlsServerMethod, Missing);
    BindProc(GSslLib, 'TLS_client_method', OsslTlsClientMethod, Missing);

    BindProc(GSslLib, 'SSL_CTX_new', OsslSslCtxNew, Missing);
    BindProc(GSslLib, 'SSL_CTX_free', OsslSslCtxFree, Missing);
    BindProc(GSslLib, 'SSL_CTX_ctrl', OsslSslCtxCtrl, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_options', OsslSslCtxSetOptions, Missing);
    BindProc(GSslLib, 'SSL_CTX_clear_options', OsslSslCtxClearOptions, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_cipher_list', OsslSslCtxSetCipherList, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_ciphersuites', OsslSslCtxSetCiphersuites, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_session_id_context', OsslSslCtxSetSessionIdContext, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_verify', OsslSslCtxSetVerify, Missing);
    BindProc(GSslLib, 'SSL_CTX_get_cert_store', OsslSslCtxGetCertStore, Missing);
    BindProc(GSslLib, 'SSL_CTX_add_client_CA', OsslSslCtxAddClientCA, Missing);
    BindProc(GSslLib, 'SSL_CTX_use_certificate', OsslSslCtxUseCertificate, Missing);
    BindProc(GSslLib, 'SSL_CTX_use_PrivateKey', OsslSslCtxUsePrivateKey, Missing);
    BindProc(GSslLib, 'SSL_CTX_use_certificate_chain_file', OsslSslCtxUseCertificateChainFile, Missing);
    BindProc(GSslLib, 'SSL_CTX_use_PrivateKey_file', OsslSslCtxUsePrivateKeyFile, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_default_passwd_cb_userdata', OsslSslCtxSetDefaultPasswdCbUserdata, Missing);
    BindProc(GSslLib, 'SSL_CTX_check_private_key', OsslSslCtxCheckPrivateKey, Missing);
    BindProc(GSslLib, 'SSL_CTX_set_alpn_select_cb', OsslSslCtxSetAlpnSelectCb, Missing);

    BindProc(GSslLib, 'SSL_new', OsslSslNew, Missing);
    BindProc(GSslLib, 'SSL_free', OsslSslFree, Missing);
    BindProc(GSslLib, 'SSL_set_accept_state', OsslSslSetAcceptState, Missing);
    BindProc(GSslLib, 'SSL_set_connect_state', OsslSslSetConnectState, Missing);
    BindProc(GSslLib, 'SSL_set_bio', OsslSslSetBio, Missing);
    BindProc(GSslLib, 'SSL_accept', OsslSslAccept, Missing);
    BindProc(GSslLib, 'SSL_connect', OsslSslConnect, Missing);
    BindProc(GSslLib, 'SSL_read_ex', OsslSslReadEx, Missing);
    BindProc(GSslLib, 'SSL_write_ex', OsslSslWriteEx, Missing);
    BindProc(GSslLib, 'SSL_pending', OsslSslPending, Missing);
    BindProc(GSslLib, 'SSL_shutdown', OsslSslShutdown, Missing);
    BindProc(GSslLib, 'SSL_get_error', OsslSslGetError, Missing);
    BindProc(GSslLib, 'SSL_get0_alpn_selected', OsslSslGet0AlpnSelected, Missing);
    BindProc(GSslLib, 'SSL_set_alpn_protos', OsslSslSetAlpnProtos, Missing);
    BindProc(GSslLib, 'SSL_session_reused', OsslSslSessionReused, Missing);

    TmpPtr := GetProcAddress(GSslLib, 'SSL_get1_peer_certificate');
    if TmpPtr = nil then
      TmpPtr := GetProcAddress(GSslLib, 'SSL_get_peer_certificate');
    SetProcPtr(OsslSslGet1PeerCertificate, TmpPtr);
    if TmpPtr = nil then
    begin
      if Missing <> '' then
        Missing := Missing + ', ';
      Missing := Missing + 'SSL_get1_peer_certificate';
    end;

    BindProc(GCryptoLib, 'BIO_s_mem', OsslBioSMem, Missing);
    BindProc(GCryptoLib, 'BIO_new', OsslBioNew, Missing);
    BindProc(GCryptoLib, 'BIO_new_mem_buf', OsslBioNewMemBuf, Missing);
    BindProc(GCryptoLib, 'BIO_free', OsslBioFree, Missing);
    BindProc(GCryptoLib, 'BIO_read', OsslBioRead, Missing);
    BindProc(GCryptoLib, 'BIO_write', OsslBioWrite, Missing);
    BindProc(GCryptoLib, 'BIO_ctrl_pending', OsslBioCtrlPending, Missing);

    BindProc(GCryptoLib, 'X509_STORE_add_cert', OsslX509StoreAddCert, Missing);
    BindProc(GCryptoLib, 'd2i_X509', OsslD2iX509, Missing);
    BindProc(GCryptoLib, 'i2d_X509', OsslI2dX509, Missing);
    BindProc(GCryptoLib, 'X509_free', OsslX509Free, Missing);
    BindProc(GCryptoLib, 'd2i_AutoPrivateKey', OsslD2iAutoPrivateKey, Missing);
    BindProc(GCryptoLib, 'EVP_PKEY_free', OsslEvpPkeyFree, Missing);
    BindProc(GCryptoLib, 'd2i_PKCS12_bio', OsslD2iPkcs12Bio, Missing);
    BindProc(GCryptoLib, 'i2d_PKCS12_bio', OsslI2dPkcs12Bio, Missing);
    BindProc(GCryptoLib, 'PKCS12_create', OsslPkcs12Create, Missing);
    BindProc(GCryptoLib, 'PKCS12_parse', OsslPkcs12Parse, Missing);
    BindProc(GCryptoLib, 'PKCS12_free', OsslPkcs12Free, Missing);
    BindProc(GCryptoLib, 'PEM_read_bio_X509', OsslPemReadBioX509, Missing);
    BindProc(GCryptoLib, 'PEM_read_bio_PrivateKey', OsslPemReadBioPrivateKey, Missing);
    BindProc(GCryptoLib, 'X509_get0_notBefore', OsslX509Get0NotBefore, Missing);
    BindProc(GCryptoLib, 'X509_get0_notAfter', OsslX509Get0NotAfter, Missing);
    BindProc(GCryptoLib, 'X509_cmp_time', OsslX509CmpTime, Missing);
    BindProc(GCryptoLib, 'ASN1_TIME_diff', OsslAsn1TimeDiff, Missing);
    BindProc(GCryptoLib, 'X509_get0_pubkey', OsslX509Get0Pubkey, Missing);
    BindProc(GCryptoLib, 'EVP_PKEY_get_base_id', OsslEvpPkeyGetBaseId, Missing);
    BindProc(GCryptoLib, 'EVP_PKEY_get_bits', OsslEvpPkeyGetBits, Missing);
    BindProc(GCryptoLib, 'X509_check_private_key', OsslX509CheckPrivateKey, Missing);
    BindProc(GCryptoLib, 'X509_get_subject_name', OsslX509GetSubjectName, Missing);
    BindProc(GCryptoLib, 'X509_get_issuer_name', OsslX509GetIssuerName, Missing);
    BindProc(GCryptoLib, 'X509_NAME_cmp', OsslX509NameCmp, Missing);
    BindProc(GCryptoLib, 'X509_digest', OsslX509Digest, Missing);
    BindProc(GCryptoLib, 'EVP_sha256', OsslEvpSha256, Missing);
    BindProc(GCryptoLib, 'EVP_sha1', OsslEvpSha1, Missing);
    BindProc(GCryptoLib, 'OPENSSL_sk_num', OsslSkNum, Missing);
    BindProc(GCryptoLib, 'OPENSSL_sk_value', OsslSkValue, Missing);
    BindProc(GCryptoLib, 'OPENSSL_sk_pop', OsslSkPop, Missing);
    BindProc(GCryptoLib, 'OPENSSL_sk_free', OsslSkFree, Missing);
    BindProc(GCryptoLib, 'OPENSSL_sk_pop_free', OsslSkPopFree, Missing);

    BindProc(GCryptoLib, 'ERR_get_error', OsslErrGetError, Missing);
    BindProc(GCryptoLib, 'ERR_error_string_n', OsslErrErrorStringN, Missing);
    BindProc(GCryptoLib, 'ERR_clear_error', OsslErrClearError, Missing);
    BindProc(GCryptoLib, 'CRYPTO_free', OsslCryptoFree, Missing);

    if Missing <> '' then
    begin
      GLastLoadError := 'Missing OpenSSL exports: ' + Missing;
      Exit(False);
    end;

    if Assigned(OsslInitSsl) then
      OsslInitSsl(OPENSSL_INIT_LOAD_SSL_STRINGS or OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nil);

    GOpenSslLoaded := True;
    Result := True;
  finally
    GLoadLock.Leave;
  end;
end;

function IsOpenSslLoaded: Boolean;
begin
  Result := GOpenSslLoaded;
end;

function GetOpenSslLoadError: string;
begin
  Result := GLastLoadError;
end;

function GetOpenSslVersionText: string;
var
  VerPtr: PAnsiChar;
begin
  Result := '';
  if not GOpenSslLoaded then
  begin
    if not EnsureOpenSslLoaded then
      Exit('');
  end;
  if Assigned(OsslOpenSSLVersion) then
  begin
    VerPtr := OsslOpenSSLVersion(OPENSSL_VERSION_STRING_ID);
    if VerPtr <> nil then
      Result := string(VerPtr);
  end;
end;

function GetLastOpenSslErrorString: string;
var
  ErrCode: Cardinal;
  Buf: array[0..511] of AnsiChar;
  Msg: string;
begin
  Result := '';
  if not GOpenSslLoaded then
    Exit(GLastLoadError);
  if not Assigned(OsslErrGetError) then
    Exit;
  while True do
  begin
    ErrCode := OsslErrGetError;
    if ErrCode = 0 then
      Break;
    FillChar(Buf, SizeOf(Buf), 0);
    if Assigned(OsslErrErrorStringN) then
      OsslErrErrorStringN(ErrCode, @Buf[0], SizeOf(Buf));
    Msg := string(PAnsiChar(@Buf[0]));
    if Result <> '' then
      Result := Result + '; ';
    Result := Result + Format('0x%x (%s)', [ErrCode, Msg]);
  end;
  if Result = '' then
    Result := 'No OpenSSL error in queue';
end;

procedure ClearOpenSslErrors;
begin
  if GOpenSslLoaded and Assigned(OsslErrClearError) then
    OsslErrClearError;
end;

initialization
  GLoadLock := TCriticalSection.Create;

finalization
  GOpenSslLoaded := False;
  GSslLib := 0;
  GCryptoLib := 0;
  FreeAndNil(GLoadLock);

end.
