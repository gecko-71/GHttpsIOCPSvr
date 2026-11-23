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
unit GOpenSslTlsEngine;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.Math,
  System.IOUtils,
  System.Generics.Collections,
  GLogger,
  GRequest,
  GResponse,
  WinApiAdditions,
  GHttpsServerTypes,
  GOpenSslApi;

type
  PRTLSRWLock = ^_RTL_SRWLOCK;

  TOpenSslTlsEngine = class
  private
    FSslCtx: PSSL_CTX;
    FCredentialsValid: Boolean;
    FAlpnProtoWire: TBytes;
    FKeyPasswordAnsi: AnsiString;
    function AcquireLockPtr(var OverlappedEx: TOverlappedEx): PRTLSRWLock;
    function DrainWBioIntoArray(AWBio: PBIO; OutBuf: PByte; MaxCap: Integer; out BytesRead: Integer): Boolean;
    procedure SendRawSocketAll(ASocket: TSocket; DataPtr: PByte; DataLen: Integer);
    procedure FlushPendingWBioToSocket(var OverlappedEx: TOverlappedEx; AWBio: PBIO);
    function AddTrustedCertToCtx(ACertCtx: PCCERT_CONTEXT): Boolean;
    procedure ReleaseContextUnlocked(var OverlappedEx: TOverlappedEx);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Cleanup;
    function InitializeCredentials(
      ACertContext: PCCERT_CONTEXT;
      ACACertContext: PCCERT_CONTEXT;
      AExtraCertContexts: TList<PCCERT_CONTEXT>;
      const ACertFile: string;
      const AKeyFile: string;
      const AKeyPassword: string;
      AEnableSessionResumption: Boolean;
      AEnableSessionTickets: Boolean;
      AmTLSMode: TmTLSMode): Boolean;
    function ProcessHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
    function ExtractPeerCertContext(var OverlappedEx: TOverlappedEx): PCCERT_CONTEXT;
    function HasPendingRxData(var OverlappedEx: TOverlappedEx): Boolean;
    function DecryptRequestChunk(
      var OverlappedEx: TOverlappedEx;
      BytesReceived: DWORD;
      Request: TRequest;
      out HasPlaintext: Boolean;
      out FatalError: Boolean;
      out ErrorText: string): Boolean;
    function DecryptReceivedData(
      var OverlappedEx: TOverlappedEx;
      var EncryptedData: TBytes;
      var PlainData: TBytes;
      out BytesConsumed: Integer;
      out AStatus: SECURITY_STATUS): Boolean;
    function EncryptBytesToSend(
      var OverlappedEx: TOverlappedEx;
      const PlainData: TBytes;
      var EncryptedData: TBytes): Boolean;
    function EncryptResponseChunks(
      var OverlappedEx: TOverlappedEx;
      Response: TResponse;
      out OutLen: Integer): Boolean;
    procedure PerformGracefulShutdown(var OverlappedEx: TOverlappedEx; EnableGraceful: Boolean);
    procedure ReleaseContext(var OverlappedEx: TOverlappedEx);
    property CredentialsValid: Boolean read FCredentialsValid;
    property SslCtx: PSSL_CTX read FSslCtx;
  end;

function CreateWinCertContextFromFile(const AFileName: string): PCCERT_CONTEXT;
function ValidateOpenSslServerCertAndKeyFiles(
  const ACertFile: string;
  const AKeyFile: string;
  const AStoreName: string;
  const ASubjectName: string;
  ARequireW3cWebTransport: Boolean;
  out AErrorDetail: string;
  out AIsCaSigned: Boolean;
  out ASha256Hex: string;
  out ASha1Hex: string): Boolean;
function BuildInMemoryPfxBytesFromPemFiles(
  const ACertFile: string;
  const AKeyFile: string;
  const APassword: AnsiString;
  out APfxBytes: TBytes): Boolean;

implementation

function OpenSslVerifyCallback(PreverifyOk: Integer; X509Ctx: Pointer): Integer; cdecl;
begin
  Result := 1;
end;

function OpenSslAlpnSelectCallback(Ssl: PSSL; OutProto: PPByte; OutLen: PByte;
  InProto: PByte; InLen: Cardinal; Arg: Pointer): Integer; cdecl;
var
  Idx: Cardinal;
  ProtoLen: Byte;
  ProtoPtr: PByte;
  Matched: Boolean;
  TargetName: AnsiString;
  J: Integer;
begin
  Result := SSL_TLSEXT_ERR_NOACK;
  if (InProto = nil) or (InLen = 0) then
    Exit;

  TargetName := 'http/1.1';
  Idx := 0;
  while Idx < InLen do
  begin
    ProtoLen := PByte(NativeUInt(InProto) + Idx)^;
    Inc(Idx);
    if Idx + ProtoLen > InLen then
      Break;
    if ProtoLen = Length(TargetName) then
    begin
      Matched := True;
      for J := 0 to ProtoLen - 1 do
      begin
        ProtoPtr := PByte(NativeUInt(InProto) + Idx + Cardinal(J));
        if ProtoPtr^ <> Byte(TargetName[J + 1]) then
        begin
          Matched := False;
          Break;
        end;
      end;
      if Matched then
      begin
        OutProto^ := PByte(NativeUInt(InProto) + Idx);
        OutLen^ := ProtoLen;
        Result := SSL_TLSEXT_ERR_OK;
        Exit;
      end;
    end;
    Inc(Idx, ProtoLen);
  end;
end;

function CreateWinCertContextFromFile(const AFileName: string): PCCERT_CONTEXT;
var
  RawBytes: TBytes;
  AnsiStr: AnsiString;
  BinLen: DWORD;
  CertBuf: TBytes;
  BeginPos: Integer;
  EndPos: Integer;
  PemBlock: AnsiString;
begin
  Result := nil;
  if not TFile.Exists(AFileName) then
    Exit;

  RawBytes := TFile.ReadAllBytes(AFileName);
  if Length(RawBytes) = 0 then
    Exit;

  SetString(AnsiStr, PAnsiChar(@RawBytes[0]), Length(RawBytes));
  BeginPos := Pos(AnsiString('-----BEGIN CERTIFICATE-----'), AnsiStr);
  if BeginPos > 0 then
  begin
    EndPos := Pos(AnsiString('-----END CERTIFICATE-----'), Copy(AnsiStr, BeginPos, MaxInt));
    if EndPos > 0 then
      PemBlock := Copy(AnsiStr, BeginPos, EndPos + Length('-----END CERTIFICATE-----') - 1)
    else
      PemBlock := AnsiStr;

    BinLen := 0;
    if CryptStringToBinary(PAnsiChar(PemBlock), Length(PemBlock), CRYPT_STRING_BASE64HEADER, nil, BinLen, nil, nil) and (BinLen > 0) then
    begin
      SetLength(CertBuf, BinLen);
      if CryptStringToBinary(PAnsiChar(PemBlock), Length(PemBlock), CRYPT_STRING_BASE64HEADER, @CertBuf[0], BinLen, nil, nil) then
        Result := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @CertBuf[0], BinLen);
    end;
  end
  else
    Result := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @RawBytes[0], Length(RawBytes));
end;

constructor TOpenSslTlsEngine.Create;
begin
  inherited Create;
  FSslCtx := nil;
  FCredentialsValid := False;
  FKeyPasswordAnsi := '';
  SetLength(FAlpnProtoWire, 9);
  FAlpnProtoWire[0] := 8;
  FAlpnProtoWire[1] := Ord('h');
  FAlpnProtoWire[2] := Ord('t');
  FAlpnProtoWire[3] := Ord('t');
  FAlpnProtoWire[4] := Ord('p');
  FAlpnProtoWire[5] := Ord('/');
  FAlpnProtoWire[6] := Ord('1');
  FAlpnProtoWire[7] := Ord('.');
  FAlpnProtoWire[8] := Ord('1');
end;

destructor TOpenSslTlsEngine.Destroy;
begin
  Cleanup;
  inherited Destroy;
end;

procedure TOpenSslTlsEngine.Cleanup;
begin
  if FSslCtx <> nil then
  begin
    if IsOpenSslLoaded and Assigned(OsslSslCtxFree) then
      OsslSslCtxFree(FSslCtx);
    FSslCtx := nil;
  end;
  FCredentialsValid := False;
  FKeyPasswordAnsi := '';
end;

function TOpenSslTlsEngine.AcquireLockPtr(var OverlappedEx: TOverlappedEx): PRTLSRWLock;
begin
  if OverlappedEx.SSLLockPtr <> nil then
    Result := @OverlappedEx.SSLLockPtr^.SSLLock
  else
    Result := @OverlappedEx.SSLLock;
end;

function TOpenSslTlsEngine.DrainWBioIntoArray(AWBio: PBIO; OutBuf: PByte; MaxCap: Integer; out BytesRead: Integer): Boolean;
var
  PendingBytes: NativeUInt;
  ToRead: Integer;
  ReadNow: Integer;
  Offset: Integer;
begin
  Result := True;
  BytesRead := 0;
  if (AWBio = nil) or (OutBuf = nil) or (MaxCap <= 0) then
    Exit;

  Offset := 0;
  while True do
  begin
    PendingBytes := OsslBioCtrlPending(AWBio);
    if PendingBytes = 0 then
      Break;
    if Offset >= MaxCap then
    begin
      Result := False;
      Break;
    end;
    ToRead := MaxCap - Offset;
    if PendingBytes < NativeUInt(ToRead) then
      ToRead := Integer(PendingBytes);
    ReadNow := OsslBioRead(AWBio, Pointer(NativeUInt(OutBuf) + NativeUInt(Offset)), ToRead);
    if ReadNow <= 0 then
      Break;
    Inc(Offset, ReadNow);
  end;
  BytesRead := Offset;
end;

procedure TOpenSslTlsEngine.SendRawSocketAll(ASocket: TSocket; DataPtr: PByte; DataLen: Integer);
var
  SentTotal: Integer;
  SentNow: Integer;
  WsaErr: Integer;
  WriteSet: TFDSet;
  TimeoutVal: TTimeVal;
  SelRes: Integer;
begin
  if (ASocket = INVALID_SOCKET) or (DataPtr = nil) or (DataLen <= 0) then
    Exit;

  SentTotal := 0;
  while SentTotal < DataLen do
  begin
    SentNow := send(ASocket, PByte(NativeUInt(DataPtr) + NativeUInt(SentTotal))^, DataLen - SentTotal, 0);
    if SentNow > 0 then
    begin
      Inc(SentTotal, SentNow);
      Continue;
    end;
    WsaErr := WSAGetLastError;
    if WsaErr = WSAEWOULDBLOCK then
    begin
      WriteSet.fd_count := 1;
      WriteSet.fd_array[0] := ASocket;
      TimeoutVal.tv_sec := 1;
      TimeoutVal.tv_usec := 0;
      SelRes := select(0, nil, @WriteSet, nil, @TimeoutVal);
      if SelRes > 0 then
        Continue;
    end;
    Break;
  end;
end;

procedure TOpenSslTlsEngine.FlushPendingWBioToSocket(var OverlappedEx: TOverlappedEx; AWBio: PBIO);
var
  ChunkBuf: array[0..16383] of Byte;
  ChunkLen: Integer;
begin
  if (AWBio = nil) or (OverlappedEx.Socket = INVALID_SOCKET) then
    Exit;
  while OsslBioCtrlPending(AWBio) > 0 do
  begin
    ChunkLen := OsslBioRead(AWBio, @ChunkBuf[0], SizeOf(ChunkBuf));
    if ChunkLen <= 0 then
      Break;
    SendRawSocketAll(OverlappedEx.Socket, @ChunkBuf[0], ChunkLen);
  end;
end;

function LoadX509AndKeyFromPemFiles(
  const ACertFile: string;
  const AKeyFile: string;
  out ACert: PX509;
  out AKey: PEVP_PKEY;
  out AErrorDetail: string): Boolean;
var
  CertBytes: TBytes;
  KeyBytes: TBytes;
  CertBio: PBIO;
  KeyBio: PBIO;
begin
  Result := False;
  ACert := nil;
  AKey := nil;
  AErrorDetail := '';

  if (ACertFile = '') or (AKeyFile = '') then
  begin
    AErrorDetail := 'Certificate or private key path is empty.';
    Exit;
  end;
  if not FileExists(ACertFile) then
  begin
    AErrorDetail := Format('Certificate file not found: %s', [ACertFile]);
    Exit;
  end;
  if not FileExists(AKeyFile) then
  begin
    AErrorDetail := Format('Private key file not found: %s', [AKeyFile]);
    Exit;
  end;

  CertBio := nil;
  KeyBio := nil;
  try
    CertBytes := TFile.ReadAllBytes(ACertFile);
    KeyBytes := TFile.ReadAllBytes(AKeyFile);
    if (Length(CertBytes) = 0) or (Length(KeyBytes) = 0) then
    begin
      AErrorDetail := Format('Empty certificate or private key file (%s, %s).', [ACertFile, AKeyFile]);
      Exit;
    end;

    ClearOpenSslErrors;
    CertBio := OsslBioNewMemBuf(@CertBytes[0], Length(CertBytes));
    if CertBio <> nil then
      ACert := OsslPemReadBioX509(CertBio, nil, nil, nil);
    if ACert = nil then
    begin
      AErrorDetail := Format('Failed to parse X.509 certificate from %s: %s', [ACertFile, GetLastOpenSslErrorString]);
      Exit;
    end;

    ClearOpenSslErrors;
    KeyBio := OsslBioNewMemBuf(@KeyBytes[0], Length(KeyBytes));
    if KeyBio <> nil then
      AKey := OsslPemReadBioPrivateKey(KeyBio, nil, nil, nil);
    if AKey = nil then
    begin
      AErrorDetail := Format('Failed to parse private key from %s: %s', [AKeyFile, GetLastOpenSslErrorString]);
      Exit;
    end;

    if OsslX509CheckPrivateKey(ACert, AKey) <> 1 then
    begin
      AErrorDetail := Format('Private key %s does not match certificate %s: %s', [AKeyFile, ACertFile, GetLastOpenSslErrorString]);
      Exit;
    end;

    Result := True;
  finally
    if Length(KeyBytes) > 0 then
      FillChar(KeyBytes[0], Length(KeyBytes), 0);
    if CertBio <> nil then
      OsslBioFree(CertBio);
    if KeyBio <> nil then
      OsslBioFree(KeyBio);
    if not Result then
    begin
      if ACert <> nil then
      begin
        OsslX509Free(ACert);
        ACert := nil;
      end;
      if AKey <> nil then
      begin
        OsslEvpPkeyFree(AKey);
        AKey := nil;
      end;
    end;
  end;
end;

function DigestX509Hex(ACert: PX509; AMd: PEVP_MD): string;
var
  Buf: array[0..63] of Byte;
  DigestLen: Cardinal;
  I: Cardinal;
begin
  Result := '';
  if (ACert = nil) or (AMd = nil) then
    Exit;
  DigestLen := SizeOf(Buf);
  if OsslX509Digest(ACert, AMd, @Buf[0], DigestLen) = 1 then
  begin
    I := 0;
    while I < DigestLen do
    begin
      Result := Result + IntToHex(Buf[I], 2);
      Inc(I);
    end;
  end;
end;

function ValidateOpenSslServerCertAndKeyFiles(
  const ACertFile: string;
  const AKeyFile: string;
  const AStoreName: string;
  const ASubjectName: string;
  ARequireW3cWebTransport: Boolean;
  out AErrorDetail: string;
  out AIsCaSigned: Boolean;
  out ASha256Hex: string;
  out ASha1Hex: string): Boolean;
var
  Cert: PX509;
  Key: PEVP_PKEY;
  NotBefore: PASN1_TIME;
  NotAfter: PASN1_TIME;
  SubjName: PX509_NAME;
  IssName: PX509_NAME;
  DiffDays: Integer;
  DiffSecs: Integer;
  TotalDays: Double;
  PubKey: PEVP_PKEY;
  KeyTypeId: Integer;
  KeyBits: Integer;
begin
  Result := False;
  AErrorDetail := '';
  AIsCaSigned := False;
  ASha256Hex := '';
  ASha1Hex := '';

  if not EnsureOpenSslLoaded then
  begin
    AErrorDetail := 'Failed to load OpenSSL library: ' + GetOpenSslLoadError;
    Exit;
  end;

  Cert := nil;
  Key := nil;
  if not LoadX509AndKeyFromPemFiles(ACertFile, AKeyFile, Cert, Key, AErrorDetail) then
    Exit;

  try
    ASha256Hex := DigestX509Hex(Cert, OsslEvpSha256());
    ASha1Hex := DigestX509Hex(Cert, OsslEvpSha1());

    SubjName := OsslX509GetSubjectName(Cert);
    IssName := OsslX509GetIssuerName(Cert);
    AIsCaSigned := (SubjName <> nil) and (IssName <> nil) and (OsslX509NameCmp(SubjName, IssName) <> 0);

    NotBefore := OsslX509Get0NotBefore(Cert);
    NotAfter := OsslX509Get0NotAfter(Cert);
    if (NotBefore = nil) or (NotAfter = nil) then
    begin
      AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) has invalid validity timestamps.', [AStoreName, ASubjectName, ACertFile]);
      Exit;
    end;

    if OsslX509CmpTime(NotAfter, nil) <= 0 then
    begin
      AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) is EXPIRED! The server cannot start with an expired certificate. Run .\gen_w3c_wt_cert.ps1 -TlsProvider tpOpenSSL to generate a fresh 14-day certificate.', [AStoreName, ASubjectName, ACertFile]);
      Exit;
    end;

    if OsslX509CmpTime(NotBefore, nil) > 0 then
    begin
      AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) is NOT YET VALID.', [AStoreName, ASubjectName, ACertFile]);
      Exit;
    end;

    if ARequireW3cWebTransport and (not AIsCaSigned) then
    begin
      DiffDays := 0;
      DiffSecs := 0;
      if OsslAsn1TimeDiff(DiffDays, DiffSecs, NotBefore, NotAfter) = 1 then
      begin
        TotalDays := DiffDays + (DiffSecs / 86400.0);
        if (DiffDays > 14) or ((DiffDays = 14) and (DiffSecs > 0)) then
        begin
          AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) validity duration is %.1f days, which exceeds the 14-day W3C WebTransport limit (NotAfter - NotBefore <= 14 days). Run .\gen_w3c_wt_cert.ps1 -TlsProvider tpOpenSSL to generate a compliant certificate.', [AStoreName, ASubjectName, ACertFile, TotalDays]);
          Exit;
        end;
      end;

      PubKey := OsslX509Get0Pubkey(Cert);
      if PubKey = nil then
      begin
        AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) has no readable public key.', [AStoreName, ASubjectName, ACertFile]);
        Exit;
      end;

      KeyTypeId := OsslEvpPkeyGetBaseId(PubKey);
      KeyBits := OsslEvpPkeyGetBits(PubKey);
      if (KeyTypeId <> EVP_PKEY_EC) or (KeyBits <> 256) then
      begin
        AErrorDetail := Format('TLS certificate in store "%s" (Subject: "%s", File: %s) key algorithm is type %d (%d bits). W3C WebTransport strictly requires ECDSA P-256 (256 bits). Run .\gen_w3c_wt_cert.ps1 -TlsProvider tpOpenSSL to generate a compliant certificate.', [AStoreName, ASubjectName, ACertFile, KeyTypeId, KeyBits]);
        Exit;
      end;
    end;

    Result := True;
  finally
    if Cert <> nil then
      OsslX509Free(Cert);
    if Key <> nil then
      OsslEvpPkeyFree(Key);
  end;
end;

function BuildInMemoryPfxBytesFromPemFiles(
  const ACertFile: string;
  const AKeyFile: string;
  const APassword: AnsiString;
  out APfxBytes: TBytes): Boolean;
var
  Cert: PX509;
  Key: PEVP_PKEY;
  P12: PPKCS12;
  BioOut: PBIO;
  PendingLen: NativeUInt;
  ReadTotal: Integer;
  ReadNow: Integer;
  ErrDetail: string;
  PassPtr: PAnsiChar;
begin
  Result := False;
  SetLength(APfxBytes, 0);

  if not EnsureOpenSslLoaded then
    Exit;

  Cert := nil;
  Key := nil;
  P12 := nil;
  BioOut := nil;
  if not LoadX509AndKeyFromPemFiles(ACertFile, AKeyFile, Cert, Key, ErrDetail) then
  begin
    Logger.Error('[OpenSSL] BuildInMemoryPfxBytesFromPemFiles: %s', [ErrDetail]);
    Exit;
  end;

  try
    ClearOpenSslErrors;
    if APassword <> '' then
      PassPtr := PAnsiChar(APassword)
    else
      PassPtr := nil;

    P12 := OsslPkcs12Create(PassPtr, PAnsiChar(AnsiString('localhost')), Key, Cert, nil, 0, 0, 0, 0, 0);
    if P12 = nil then
    begin
      Logger.Error('[OpenSSL] PKCS12_create failed: %s', [GetLastOpenSslErrorString]);
      Exit;
    end;

    BioOut := OsslBioNew(OsslBioSMem());
    if BioOut = nil then
      Exit;

    if OsslI2dPkcs12Bio(BioOut, P12) <> 1 then
    begin
      Logger.Error('[OpenSSL] i2d_PKCS12_bio failed: %s', [GetLastOpenSslErrorString]);
      Exit;
    end;

    PendingLen := OsslBioCtrlPending(BioOut);
    if PendingLen = 0 then
      Exit;

    SetLength(APfxBytes, Integer(PendingLen));
    ReadTotal := 0;
    while ReadTotal < Integer(PendingLen) do
    begin
      ReadNow := OsslBioRead(BioOut, @APfxBytes[ReadTotal], Integer(PendingLen) - ReadTotal);
      if ReadNow <= 0 then
        Break;
      Inc(ReadTotal, ReadNow);
    end;
    SetLength(APfxBytes, ReadTotal);
    Result := ReadTotal > 0;
  finally
    if BioOut <> nil then
      OsslBioFree(BioOut);
    if P12 <> nil then
      OsslPkcs12Free(P12);
    if Cert <> nil then
      OsslX509Free(Cert);
    if Key <> nil then
      OsslEvpPkeyFree(Key);
  end;
end;

function TOpenSslTlsEngine.AddTrustedCertToCtx(ACertCtx: PCCERT_CONTEXT): Boolean;
var
  DerPtr: PByte;
  X509Obj: PX509;
  StoreObj: PX509_STORE;
begin
  Result := False;
  if (FSslCtx = nil) or (ACertCtx = nil) or (ACertCtx^.pbCertEncoded = nil) or (ACertCtx^.cbCertEncoded = 0) then
    Exit;

  DerPtr := ACertCtx^.pbCertEncoded;
  X509Obj := OsslD2iX509(nil, @DerPtr, LongInt(ACertCtx^.cbCertEncoded));
  if X509Obj = nil then
    Exit;

  try
    StoreObj := OsslSslCtxGetCertStore(FSslCtx);
    if StoreObj <> nil then
      OsslX509StoreAddCert(StoreObj, X509Obj);
    OsslSslCtxAddClientCA(FSslCtx, X509Obj);
    Result := True;
  finally
    OsslX509Free(X509Obj);
  end;
end;

function TOpenSslTlsEngine.InitializeCredentials(
  ACertContext: PCCERT_CONTEXT;
  ACACertContext: PCCERT_CONTEXT;
  AExtraCertContexts: TList<PCCERT_CONTEXT>;
  const ACertFile: string;
  const AKeyFile: string;
  const AKeyPassword: string;
  AEnableSessionResumption: Boolean;
  AEnableSessionTickets: Boolean;
  AmTLSMode: TmTLSMode): Boolean;
var
  Meth: PSSL_METHOD;
  SessIdCtx: AnsiString;
  CertFileAnsi: UTF8String;
  KeyFileAnsi: UTF8String;
  VerifyFlags: Integer;
  ExtraCtx: PCCERT_CONTEXT;
  OptionsMask: UInt64;
begin
  Result := False;
  Cleanup;
  ClearOpenSslErrors;

  if not EnsureOpenSslLoaded then
  begin
    Logger.Error('[OpenSSL] Cannot initialize credentials: %s', [GetOpenSslLoadError]);
    Exit;
  end;

  Meth := OsslTlsServerMethod();
  if Meth = nil then
  begin
    Logger.Error('[OpenSSL] TLS_server_method returned nil');
    Exit;
  end;

  FSslCtx := OsslSslCtxNew(Meth);
  if FSslCtx = nil then
  begin
    Logger.Error('[OpenSSL] SSL_CTX_new failed: %s', [GetLastOpenSslErrorString]);
    Exit;
  end;

  OsslSslCtxCtrl(FSslCtx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nil);
  OsslSslCtxCtrl(FSslCtx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, nil);

  OptionsMask := SSL_OP_CIPHER_SERVER_PREFERENCE or SSL_OP_NO_SSLv3 or SSL_OP_NO_TLSv1 or SSL_OP_NO_TLSv1_1;
  OsslSslCtxSetOptions(FSslCtx, OptionsMask);

  if AEnableSessionResumption then
  begin
    SessIdCtx := 'GHttpsIOCPSvr';
    OsslSslCtxSetSessionIdContext(FSslCtx, @SessIdCtx[1], Cardinal(Length(SessIdCtx)));
    OsslSslCtxCtrl(FSslCtx, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_SERVER, nil);
  end
  else
    OsslSslCtxCtrl(FSslCtx, SSL_CTRL_SET_SESS_CACHE_MODE, SSL_SESS_CACHE_OFF, nil);

  if AEnableSessionTickets then
    OsslSslCtxClearOptions(FSslCtx, SSL_OP_NO_TICKET)
  else
    OsslSslCtxSetOptions(FSslCtx, SSL_OP_NO_TICKET);

  OsslSslCtxSetAlpnSelectCb(FSslCtx, @OpenSslAlpnSelectCallback, nil);

  if (ACertFile = '') or (AKeyFile = '') then
  begin
    Logger.Error('[OpenSSL] Certificate and private key PEM files are required in tpOpenSSL mode (Windows Certificate Store is disabled)');
    Cleanup;
    Exit;
  end;

  if (not FileExists(ACertFile)) or (not FileExists(AKeyFile)) then
  begin
    Logger.Error('[OpenSSL] Certificate or private key file does not exist (%s, %s)', [ACertFile, AKeyFile]);
    Cleanup;
    Exit;
  end;
  CertFileAnsi := UTF8String(ACertFile);
  KeyFileAnsi := UTF8String(AKeyFile);
  if AKeyPassword <> '' then
  begin
    FKeyPasswordAnsi := AnsiString(AKeyPassword);
    OsslSslCtxSetDefaultPasswdCbUserdata(FSslCtx, PAnsiChar(FKeyPasswordAnsi));
  end;
  if OsslSslCtxUseCertificateChainFile(FSslCtx, PAnsiChar(CertFileAnsi)) <> 1 then
  begin
    Logger.Error('[OpenSSL] SSL_CTX_use_certificate_chain_file failed: %s', [GetLastOpenSslErrorString]);
    Cleanup;
    Exit;
  end;
  if OsslSslCtxUsePrivateKeyFile(FSslCtx, PAnsiChar(KeyFileAnsi), SSL_FILETYPE_PEM) <> 1 then
  begin
    Logger.Error('[OpenSSL] SSL_CTX_use_PrivateKey_file failed: %s', [GetLastOpenSslErrorString]);
    Cleanup;
    Exit;
  end;
  if OsslSslCtxCheckPrivateKey(FSslCtx) <> 1 then
  begin
    Logger.Error('[OpenSSL] SSL_CTX_check_private_key failed for PEM files: %s', [GetLastOpenSslErrorString]);
    Cleanup;
    Exit;
  end;

  VerifyFlags := SSL_VERIFY_NONE;
  if AmTLSMode = mtlsOptional then
    VerifyFlags := SSL_VERIFY_PEER
  else if AmTLSMode = mtlsRequired then
    VerifyFlags := SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

  if AmTLSMode <> mtlsDisabled then
  begin
    if ACACertContext <> nil then
      AddTrustedCertToCtx(ACACertContext);
    if Assigned(AExtraCertContexts) then
    begin
      for ExtraCtx in AExtraCertContexts do
      begin
        if ExtraCtx <> nil then
          AddTrustedCertToCtx(ExtraCtx);
      end;
    end;
    OsslSslCtxSetVerify(FSslCtx, VerifyFlags, @OpenSslVerifyCallback);
  end
  else
    OsslSslCtxSetVerify(FSslCtx, SSL_VERIFY_NONE, nil);

  FCredentialsValid := True;
  Logger.Info('[OpenSSL] Credentials initialized (%s)', [GetOpenSslVersionText]);
  Result := True;
end;

function TOpenSslTlsEngine.ProcessHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  RBio: PBIO;
  WBio: PBIO;
  InLen: Integer;
  Written: Integer;
  TotalWritten: Integer;
  Ret: Integer;
  SslErr: Integer;
  PendingBytes: NativeUInt;
  OverflowLen: Integer;
  OverflowBuf: TBytes;
  OutBytesRead: Integer;
  AlpnPtr: PByte;
  AlpnLen: Cardinal;
begin
  Result := False;
  OverlappedEx.SSLOutputSize := 0;
  OverlappedEx.SSLNeedsMoreData := False;
  if (not FCredentialsValid) or (FSslCtx = nil) then
  begin
    Logger.Error('[OpenSSL] Credentials are not initialized');
    Exit;
  end;

  Inc(OverlappedEx.SSLHandshakeStep);
  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    ClearOpenSslErrors;
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    RBio := PBIO(OverlappedEx.OpenSSLRBio);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);

    if Ssl = nil then
    begin
      Ssl := OsslSslNew(FSslCtx);
      if Ssl = nil then
      begin
        Logger.Error('[OpenSSL] SSL_new failed: %s', [GetLastOpenSslErrorString]);
        Exit;
      end;
      RBio := OsslBioNew(OsslBioSMem());
      WBio := OsslBioNew(OsslBioSMem());
      if (RBio = nil) or (WBio = nil) then
      begin
        if RBio <> nil then
          OsslBioFree(RBio);
        if WBio <> nil then
          OsslBioFree(WBio);
        OsslSslFree(Ssl);
        Exit;
      end;
      OsslSslSetBio(Ssl, RBio, WBio);
      OsslSslSetAcceptState(Ssl);
      OverlappedEx.OpenSSLHandle := Ssl;
      OverlappedEx.OpenSSLRBio := RBio;
      OverlappedEx.OpenSSLWBio := WBio;
      OverlappedEx.SSLContextBorrowed := False;
      OverlappedEx.SSLLockPtr := @OverlappedEx;
    end;

    InLen := Length(OverlappedEx.ClientReceiveBuffer);
    if InLen > 0 then
    begin
      TotalWritten := 0;
      while TotalWritten < InLen do
      begin
        Written := OsslBioWrite(RBio, @OverlappedEx.ClientReceiveBuffer[TotalWritten], InLen - TotalWritten);
        if Written <= 0 then
        begin
          ReleaseContextUnlocked(OverlappedEx);
          Exit;
        end;
        Inc(TotalWritten, Written);
      end;
      SetLength(OverlappedEx.ClientReceiveBuffer, 0);
    end
    else if BytesReceived > 0 then
    begin
      TotalWritten := 0;
      while TotalWritten < Integer(BytesReceived) do
      begin
        Written := OsslBioWrite(RBio, @OverlappedEx.Buffer[TotalWritten], Integer(BytesReceived) - TotalWritten);
        if Written <= 0 then
        begin
          ReleaseContextUnlocked(OverlappedEx);
          Exit;
        end;
        Inc(TotalWritten, Written);
      end;
    end;

    Ret := OsslSslAccept(Ssl);

    PendingBytes := OsslBioCtrlPending(WBio);
    if PendingBytes > NativeUInt(SizeOf(OverlappedEx.SSLOutputBuffer)) then
    begin
      OverflowLen := Integer(PendingBytes) - SizeOf(OverlappedEx.SSLOutputBuffer);
      SetLength(OverflowBuf, OverflowLen);
      OverflowLen := OsslBioRead(WBio, @OverflowBuf[0], OverflowLen);
      if OverflowLen > 0 then
        SendRawSocketAll(OverlappedEx.Socket, @OverflowBuf[0], OverflowLen);
    end;

    DrainWBioIntoArray(WBio, @OverlappedEx.SSLOutputBuffer[0], SizeOf(OverlappedEx.SSLOutputBuffer), OutBytesRead);
    OverlappedEx.SSLOutputSize := DWORD(OutBytesRead);

    if Ret = 1 then
    begin
      OverlappedEx.SSLContextValid := True;
      OverlappedEx.SSLStreamHeaderSize := 29;
      OverlappedEx.SSLStreamTrailerSize := 32;
      OverlappedEx.SSLStreamMaxMessage := 16384;
      OverlappedEx.SSLStreamSizesValid := True;
      OverlappedEx.SSLNeedsMoreData := False;

      AlpnPtr := nil;
      AlpnLen := 0;
      OsslSslGet0AlpnSelected(Ssl, AlpnPtr, AlpnLen);
      FillChar(OverlappedEx.ALPNProtocol, SizeOf(OverlappedEx.ALPNProtocol), 0);
      if (AlpnPtr <> nil) and (AlpnLen > 0) then
        Move(AlpnPtr^, OverlappedEx.ALPNProtocol[0], Min(Integer(AlpnLen), SizeOf(OverlappedEx.ALPNProtocol) - 1));

      Result := True;
    end
    else
    begin
      SslErr := OsslSslGetError(Ssl, Ret);
      if (SslErr = SSL_ERROR_WANT_READ) or (SslErr = SSL_ERROR_WANT_WRITE) then
        OverlappedEx.SSLNeedsMoreData := True
      else
      begin
        OverlappedEx.SSLNeedsMoreData := False;
        Logger.Error('[OpenSSL] SSL_accept failed (SslErr=%d): %s', [SslErr, GetLastOpenSslErrorString]);
        if OverlappedEx.SSLOutputSize = 0 then
          ReleaseContextUnlocked(OverlappedEx);
      end;
      Result := False;
    end;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.ExtractPeerCertContext(var OverlappedEx: TOverlappedEx): PCCERT_CONTEXT;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  PeerX509: PX509;
  DerPtr: PByte;
  DerLen: Integer;
begin
  Result := nil;
  if not IsOpenSslLoaded then
    Exit;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    if Ssl = nil then
      Exit;

    PeerX509 := OsslSslGet1PeerCertificate(Ssl);
    if PeerX509 = nil then
      Exit;

    DerPtr := nil;
    try
      DerLen := OsslI2dX509(PeerX509, @DerPtr);
      if (DerLen > 0) and (DerPtr <> nil) then
        Result := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, DerPtr, DWORD(DerLen));
    finally
      if DerPtr <> nil then
        OsslCryptoFree(DerPtr, nil, 0);
      OsslX509Free(PeerX509);
    end;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.HasPendingRxData(var OverlappedEx: TOverlappedEx): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  RBio: PBIO;
begin
  Result := False;
  if (not IsOpenSslLoaded) or (OverlappedEx.OpenSSLHandle = nil) then
    Exit;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    RBio := PBIO(OverlappedEx.OpenSSLRBio);
    if (Ssl <> nil) and (OsslSslPending(Ssl) > 0) then
      Exit(True);
    if (RBio <> nil) and (OsslBioCtrlPending(RBio) > 0) then
      Exit(True);
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.DecryptRequestChunk(
  var OverlappedEx: TOverlappedEx;
  BytesReceived: DWORD;
  Request: TRequest;
  out HasPlaintext: Boolean;
  out FatalError: Boolean;
  out ErrorText: string): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  RBio: PBIO;
  WBio: PBIO;
  TotalWritten: Integer;
  Written: Integer;
  ReadBytes: NativeUInt;
  Ret: Integer;
  SslErr: Integer;
  StackPlain: array[0..16383] of Byte;
  CurLen: Integer;
  PlainExcess: Int64;
begin
  Result := False;
  HasPlaintext := False;
  FatalError := False;
  ErrorText := '';

  if not Assigned(Request) then
  begin
    FatalError := True;
    ErrorText := 'Request object is NIL during OpenSSL decryption';
    Exit;
  end;

  CurLen := Length(OverlappedEx.ClientReceiveBuffer);
  if CurLen > 0 then
  begin
    Request.AppendDataPtr(@OverlappedEx.ClientReceiveBuffer[0], CurLen);
    if Request.IsComplete and
       (not Request.IsChunkedTransfer) and
       (Request.HeadersEndPos > 0) and
       (Request.ExpectedBodySize >= 0) then
    begin
      PlainExcess := Request.TotalBytesReceived - (Int64(Request.HeadersEndPos) + Request.ExpectedBodySize);
      if (PlainExcess > 0) and (PlainExcess < CurLen) then
        OverlappedEx.ClientReceiveBuffer := Copy(OverlappedEx.ClientReceiveBuffer, CurLen - Integer(PlainExcess), Integer(PlainExcess))
      else
        SetLength(OverlappedEx.ClientReceiveBuffer, 0);
    end
    else
      SetLength(OverlappedEx.ClientReceiveBuffer, 0);
    HasPlaintext := True;
  end;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    RBio := PBIO(OverlappedEx.OpenSSLRBio);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);
    if (Ssl = nil) or (RBio = nil) then
    begin
      FatalError := True;
      ErrorText := 'OpenSSL context is not initialized';
      Exit;
    end;

    ClearOpenSslErrors;

    if BytesReceived > 0 then
    begin
      TotalWritten := 0;
      while TotalWritten < Integer(BytesReceived) do
      begin
        Written := OsslBioWrite(RBio, @OverlappedEx.Buffer[TotalWritten], Integer(BytesReceived) - TotalWritten);
        if Written <= 0 then
        begin
          FatalError := True;
          ErrorText := 'BIO_write failed on OpenSSL RBio';
          Exit;
        end;
        Inc(TotalWritten, Written);
      end;
    end;

    while (not Request.IsComplete) and Request.CanAcceptMoreData do
    begin
      ReadBytes := 0;
      Ret := OsslSslReadEx(Ssl, @StackPlain[0], SizeOf(StackPlain), ReadBytes);
      if Ret = 1 then
      begin
        if ReadBytes > 0 then
        begin
          HasPlaintext := True;
          Request.AppendDataPtr(@StackPlain[0], Integer(ReadBytes));
          if Request.IsComplete and
             (not Request.IsChunkedTransfer) and
             (Request.HeadersEndPos > 0) and
             (Request.ExpectedBodySize >= 0) then
          begin
            PlainExcess := Request.TotalBytesReceived - (Int64(Request.HeadersEndPos) + Request.ExpectedBodySize);
            if (PlainExcess > 0) and (PlainExcess <= Int64(ReadBytes)) then
            begin
              SetLength(OverlappedEx.ClientReceiveBuffer, Integer(PlainExcess));
              Move(StackPlain[Integer(ReadBytes) - Integer(PlainExcess)], OverlappedEx.ClientReceiveBuffer[0], Integer(PlainExcess));
            end;
          end;
        end
        else
          Break;
      end
      else
      begin
        SslErr := OsslSslGetError(Ssl, Ret);
        if (SslErr = SSL_ERROR_WANT_READ) or (SslErr = SSL_ERROR_WANT_WRITE) then
          Break
        else if SslErr = SSL_ERROR_ZERO_RETURN then
        begin
          if not HasPlaintext then
          begin
            FatalError := True;
            ErrorText := 'TLS peer closed connection (close_notify)';
          end;
          Break;
        end
        else
        begin
          FatalError := True;
          ErrorText := Format('OpenSSL SSL_read_ex failed (%d): %s', [SslErr, GetLastOpenSslErrorString]);
          Break;
        end;
      end;
    end;

    if (not FatalError) and (WBio <> nil) and (OsslBioCtrlPending(WBio) > 0) then
      FlushPendingWBioToSocket(OverlappedEx, WBio);

    Result := not FatalError;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.DecryptReceivedData(
  var OverlappedEx: TOverlappedEx;
  var EncryptedData: TBytes;
  var PlainData: TBytes;
  out BytesConsumed: Integer;
  out AStatus: SECURITY_STATUS): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  RBio: PBIO;
  WBio: PBIO;
  InLen: Integer;
  TotalWritten: Integer;
  Written: Integer;
  StackPlain: array[0..16383] of Byte;
  ReadBytes: NativeUInt;
  Ret: Integer;
  SslErr: Integer;
  OutLen: Integer;
  TotalOut: Integer;
begin
  Result := False;
  SetLength(PlainData, 0);
  BytesConsumed := 0;
  AStatus := SEC_E_OK;

  if not IsOpenSslLoaded then
  begin
    AStatus := SEC_E_INVALID_HANDLE;
    Exit;
  end;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    RBio := PBIO(OverlappedEx.OpenSSLRBio);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);
    if (Ssl = nil) or (RBio = nil) then
    begin
      AStatus := SEC_E_INVALID_HANDLE;
      Exit;
    end;

    ClearOpenSslErrors;

    InLen := Length(EncryptedData);
    if InLen > 0 then
    begin
      TotalWritten := 0;
      while TotalWritten < InLen do
      begin
        Written := OsslBioWrite(RBio, @EncryptedData[TotalWritten], InLen - TotalWritten);
        if Written <= 0 then
        begin
          AStatus := SEC_E_DECRYPT_FAILURE;
          Exit;
        end;
        Inc(TotalWritten, Written);
      end;
      BytesConsumed := InLen;
      SetLength(EncryptedData, 0);
    end;

    TotalOut := 0;
    while True do
    begin
      ReadBytes := 0;
      Ret := OsslSslReadEx(Ssl, @StackPlain[0], SizeOf(StackPlain), ReadBytes);
      if Ret = 1 then
      begin
        if ReadBytes > 0 then
        begin
          OutLen := Integer(ReadBytes);
          SetLength(PlainData, TotalOut + OutLen);
          Move(StackPlain[0], PlainData[TotalOut], OutLen);
          Inc(TotalOut, OutLen);
          Result := True;
        end
        else
          Break;
      end
      else
      begin
        SslErr := OsslSslGetError(Ssl, Ret);
        if (WBio <> nil) and (OsslBioCtrlPending(WBio) > 0) then
          FlushPendingWBioToSocket(OverlappedEx, WBio);

        if TotalOut > 0 then
        begin
          Result := True;
          AStatus := SEC_E_OK;
          Break;
        end;

        if (SslErr = SSL_ERROR_WANT_READ) or (SslErr = SSL_ERROR_WANT_WRITE) then
          AStatus := SEC_E_INCOMPLETE_MESSAGE
        else if SslErr = SSL_ERROR_ZERO_RETURN then
          AStatus := SEC_I_CONTEXT_EXPIRED
        else
        begin
          Logger.Debug('[OpenSSL] DecryptReceivedData error (%d): %s', [SslErr, GetLastOpenSslErrorString]);
          AStatus := SEC_E_DECRYPT_FAILURE;
        end;
        Break;
      end;
    end;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.EncryptBytesToSend(
  var OverlappedEx: TOverlappedEx;
  const PlainData: TBytes;
  var EncryptedData: TBytes): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  WBio: PBIO;
  TotalIn: Integer;
  Offset: Integer;
  ChunkLen: Integer;
  WrittenBytes: NativeUInt;
  Ret: Integer;
  PendingBytes: NativeUInt;
  OutOffset: Integer;
  OutRead: Integer;
begin
  Result := False;
  SetLength(EncryptedData, 0);
  if (Length(PlainData) = 0) or (not IsOpenSslLoaded) then
    Exit;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);
    if (Ssl = nil) or (WBio = nil) then
      Exit;

    ClearOpenSslErrors;

    TotalIn := Length(PlainData);
    Offset := 0;
    while Offset < TotalIn do
    begin
      ChunkLen := Min(16384, TotalIn - Offset);
      WrittenBytes := 0;
      Ret := OsslSslWriteEx(Ssl, @PlainData[Offset], NativeUInt(ChunkLen), WrittenBytes);
      if (Ret <> 1) or (WrittenBytes = 0) then
      begin
        Logger.Error('[OpenSSL] SSL_write_ex failed: %s', [GetLastOpenSslErrorString]);
        Exit;
      end;
      Inc(Offset, Integer(WrittenBytes));
    end;

    PendingBytes := OsslBioCtrlPending(WBio);
    if PendingBytes > 0 then
    begin
      SetLength(EncryptedData, Integer(PendingBytes));
      OutOffset := 0;
      while OutOffset < Integer(PendingBytes) do
      begin
        OutRead := OsslBioRead(WBio, @EncryptedData[OutOffset], Integer(PendingBytes) - OutOffset);
        if OutRead <= 0 then
          Break;
        Inc(OutOffset, OutRead);
      end;
      SetLength(EncryptedData, OutOffset);
      Result := OutOffset > 0;
    end;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

function TOpenSslTlsEngine.EncryptResponseChunks(
  var OverlappedEx: TOverlappedEx;
  Response: TResponse;
  out OutLen: Integer): Boolean;
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  WBio: PBIO;
  StackPlain: array[0..16383] of Byte;
  FreeCap: Integer;
  MaxPlain: Integer;
  BytesRead: Integer;
  WrittenBytes: NativeUInt;
  Ret: Integer;
  WBioRead: Integer;
  SafetyOverhead: Integer;
begin
  Result := False;
  OutLen := 0;
  if (not IsOpenSslLoaded) or (not Assigned(Response)) then
    Exit;

  SafetyOverhead := 128;
  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);
    if (Ssl = nil) or (WBio = nil) then
      Exit;

    ClearOpenSslErrors;

    while (not Response.IsComplete) do
    begin
      FreeCap := SizeOf(OverlappedEx.SSLOutputBuffer) - OutLen - Integer(OsslBioCtrlPending(WBio));
      if FreeCap <= SafetyOverhead then
        Break;

      MaxPlain := Min(16384, SizeOf(StackPlain));
      if MaxPlain > (FreeCap - SafetyOverhead) then
        MaxPlain := FreeCap - SafetyOverhead;
      if MaxPlain <= 0 then
        Break;

      BytesRead := Response.ReadNextChunk(@StackPlain[0], MaxPlain);
      if BytesRead <= 0 then
        Break;

      WrittenBytes := 0;
      Ret := OsslSslWriteEx(Ssl, @StackPlain[0], NativeUInt(BytesRead), WrittenBytes);
      if (Ret <> 1) or (WrittenBytes <> NativeUInt(BytesRead)) then
      begin
        Logger.Error('[OpenSSL] SSL_write_ex failed during response chunk: %s', [GetLastOpenSslErrorString]);
        Exit(False);
      end;

      DrainWBioIntoArray(WBio, @OverlappedEx.SSLOutputBuffer[OutLen], SizeOf(OverlappedEx.SSLOutputBuffer) - OutLen, WBioRead);
      Inc(OutLen, WBioRead);
    end;

    if OsslBioCtrlPending(WBio) > 0 then
    begin
      DrainWBioIntoArray(WBio, @OverlappedEx.SSLOutputBuffer[OutLen], SizeOf(OverlappedEx.SSLOutputBuffer) - OutLen, WBioRead);
      Inc(OutLen, WBioRead);
    end;

    Result := True;
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

procedure TOpenSslTlsEngine.PerformGracefulShutdown(var OverlappedEx: TOverlappedEx; EnableGraceful: Boolean);
var
  LockPtr: PRTLSRWLock;
  Ssl: PSSL;
  WBio: PBIO;
begin
  if not OverlappedEx.SSLContextValid then
    Exit;

  if not IsOpenSslLoaded then
  begin
    ReleaseContext(OverlappedEx);
    Exit;
  end;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    Ssl := PSSL(OverlappedEx.OpenSSLHandle);
    WBio := PBIO(OverlappedEx.OpenSSLWBio);
    if EnableGraceful and (Ssl <> nil) and (OverlappedEx.Socket <> INVALID_SOCKET) then
    begin
      ClearOpenSslErrors;
      OsslSslShutdown(Ssl);
      if WBio <> nil then
        FlushPendingWBioToSocket(OverlappedEx, WBio);
    end;
    ReleaseContextUnlocked(OverlappedEx);
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

procedure TOpenSslTlsEngine.ReleaseContextUnlocked(var OverlappedEx: TOverlappedEx);
begin
  if OverlappedEx.OpenSSLHandle <> nil then
  begin
    if (not OverlappedEx.SSLContextBorrowed) and IsOpenSslLoaded and Assigned(OsslSslFree) then
      OsslSslFree(PSSL(OverlappedEx.OpenSSLHandle));
  end;
  OverlappedEx.OpenSSLHandle := nil;
  OverlappedEx.OpenSSLRBio := nil;
  OverlappedEx.OpenSSLWBio := nil;
  OverlappedEx.SSLContextBorrowed := False;
  OverlappedEx.SSLLockPtr := nil;
  OverlappedEx.SSLContextValid := False;
end;

procedure TOpenSslTlsEngine.ReleaseContext(var OverlappedEx: TOverlappedEx);
var
  LockPtr: PRTLSRWLock;
begin
  if (OverlappedEx.OpenSSLHandle = nil) and (not OverlappedEx.SSLContextValid) then
    Exit;

  if OverlappedEx.SSLContextBorrowed then
  begin
    OverlappedEx.OpenSSLHandle := nil;
    OverlappedEx.OpenSSLRBio := nil;
    OverlappedEx.OpenSSLWBio := nil;
    OverlappedEx.SSLContextBorrowed := False;
    OverlappedEx.SSLLockPtr := nil;
    OverlappedEx.SSLContextValid := False;
    Exit;
  end;

  LockPtr := AcquireLockPtr(OverlappedEx);
  AcquireSRWLockExclusive(LockPtr^);
  try
    ReleaseContextUnlocked(OverlappedEx);
  finally
    ReleaseSRWLockExclusive(LockPtr^);
  end;
end;

end.
