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
unit MtlsClientUtils;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Net.URLClient,
  System.Net.HttpClient,
  System.Net.HttpClientComponent,
  Winapi.Windows,
  Winapi.Winsock2,
  WinApiAdditions,
  GOpenSslApi;

type
  TMtlsClientResult = record
    Success: Boolean;
    StatusCode: Integer;
    ResponseBody: string;
    ErrorMessage: string;
  end;

function EnsurePfxInStore(const PfxPath, Password: string): string;
function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string): TMtlsClientResult; overload;
function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string; ATlsProvider: TTlsProvider): TMtlsClientResult; overload;

implementation

uses
  System.Math;

type
  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  HCERTSTORE = Pointer;
  PCCERT_CONTEXT = Pointer;

function PFXImportCertStore(pPFX: PCRYPT_DATA_BLOB; szPassword: LPCWSTR; dwFlags: DWORD): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertOpenStore(lpszStoreProvider: LPCSTR; dwMsgAndCertEncodingType: DWORD; hCryptProv: ULONG_PTR; dwFlags: DWORD; pvPara: Pointer): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall; external 'crypt32.dll';
function CertEnumCertificatesInStore(hCertStore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall; external 'crypt32.dll';
function CertAddCertificateContextToStore(hCertStore: HCERTSTORE; pCertContext: PCCERT_CONTEXT; dwAddDisposition: DWORD; ppStoreContext: Pointer): BOOL; stdcall; external 'crypt32.dll';
function CertGetNameStringW(pCertContext: PCCERT_CONTEXT; dwType: DWORD; dwFlags: DWORD; pvTypePara: Pointer; pszNameString: PWideChar; cchNameString: DWORD): DWORD; stdcall; external 'crypt32.dll';
function CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT): BOOL; stdcall; external 'crypt32.dll';

type
  TMtlsHandler = class
  private
    FClientCertCN: string;
    procedure HandleValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
    procedure HandleNeedClientCertificate(const Sender: TObject; const ARequest: TURLRequest; const ACertificateList: TCertificateList; var AnIndex: Integer);
  public
    constructor Create(const AClientCertCN: string);
  end;

constructor TMtlsHandler.Create(const AClientCertCN: string);
begin
  inherited Create;
  FClientCertCN := AClientCertCN;
end;

procedure TMtlsHandler.HandleValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
begin
  Accepted := True;
end;

procedure TMtlsHandler.HandleNeedClientCertificate(const Sender: TObject; const ARequest: TURLRequest; const ACertificateList: TCertificateList; var AnIndex: Integer);
var
  I: Integer;
begin
  AnIndex := -1;
  if FClientCertCN <> '' then
  begin
    for I := 0 to ACertificateList.Count - 1 do
    begin
      if ACertificateList[I].Subject.Contains(FClientCertCN) or
         ACertificateList[I].CertName.Contains(FClientCertCN) then
      begin
        AnIndex := I;
        Exit;
      end;
    end;
  end;
end;

function EnsurePfxInStore(const PfxPath, Password: string): string;
var
  Blob: CRYPT_DATA_BLOB;
  PfxBytes: TBytes;
  PfxStore, MyStore: HCERTSTORE;
  pCert: PCCERT_CONTEXT;
  NameBuf: array[0..255] of WideChar;
begin
  Result := '';
  if (PfxPath = '') or not FileExists(PfxPath) then Exit;
  PfxBytes := TFile.ReadAllBytes(PfxPath);
  if Length(PfxBytes) = 0 then Exit;

  Blob.cbData := Length(PfxBytes);
  Blob.pbData := @PfxBytes[0];
  PfxStore := PFXImportCertStore(@Blob, PWideChar(Password), $00000001 or $00001000 or $00004000);
  if not Assigned(PfxStore) then
    PfxStore := PFXImportCertStore(@Blob, PWideChar(Password), $00000001 or $00001000);
  if not Assigned(PfxStore) then
    PfxStore := PFXImportCertStore(@Blob, PWideChar(Password), $00000001);

  if Assigned(PfxStore) then
  try
    pCert := CertEnumCertificatesInStore(PfxStore, nil);
    if Assigned(pCert) then
    try
      if CertGetNameStringW(pCert, 4, 0, nil, @NameBuf[0], Length(NameBuf)) > 0 then
        Result := NameBuf;

      MyStore := CertOpenStore(PAnsiChar(10), 0, 0, $00010000, PWideChar('MY'));
      if Assigned(MyStore) then
      try
        CertAddCertificateContextToStore(MyStore, pCert, 3, nil);
      finally
        CertCloseStore(MyStore, 0);
      end;
    finally
      CertFreeCertificateContext(pCert);
    end;
  finally
    CertCloseStore(PfxStore, 0);
  end;
end;

function FlushOsslWBioToSocket(ASock: TSocket; AWBio: PBIO): Boolean;
var
  Buf: array[0..16383] of Byte;
  Pending: NativeUInt;
  ReadNow: Integer;
  SentTotal: Integer;
  SentNow: Integer;
begin
  Result := True;
  while True do
  begin
    Pending := OsslBioCtrlPending(AWBio);
    if Pending = 0 then
      Break;
    ReadNow := OsslBioRead(AWBio, @Buf[0], SizeOf(Buf));
    if ReadNow <= 0 then
      Break;
    SentTotal := 0;
    while SentTotal < ReadNow do
    begin
      SentNow := send(ASock, Buf[SentTotal], ReadNow - SentTotal, 0);
      if SentNow <= 0 then
        Exit(False);
      Inc(SentTotal, SentNow);
    end;
  end;
end;

function FeedOsslSocketToRBio(ASock: TSocket; ARBio: PBIO): Integer;
var
  Buf: array[0..16383] of Byte;
begin
  Result := recv(ASock, Buf[0], SizeOf(Buf), 0);
  if Result > 0 then
    OsslBioWrite(ARBio, @Buf[0], Result);
end;

function LoadPfxIntoClientCtx(ACtx: PSSL_CTX; const PfxPath, Password: string; out AErrMsg: string): Boolean;
var
  PfxBytes: TBytes;
  PfxBio: PBIO;
  P12: PPKCS12;
  ClientCert: PX509;
  ClientKey: PEVP_PKEY;
  CaStack: PSTACK_OF_X509;
  ChainCert: PX509;
  PassAnsi: AnsiString;
begin
  Result := False;
  AErrMsg := '';
  if (PfxPath = '') or (not FileExists(PfxPath)) then
    Exit(True);

  PfxBytes := TFile.ReadAllBytes(PfxPath);
  if Length(PfxBytes) = 0 then
  begin
    AErrMsg := 'Empty PFX file: ' + PfxPath;
    Exit(False);
  end;

  P12 := nil;
  PfxBio := nil;
  ClientCert := nil;
  ClientKey := nil;
  CaStack := nil;
  try
    PfxBio := OsslBioNewMemBuf(@PfxBytes[0], Length(PfxBytes));
    if PfxBio = nil then
    begin
      AErrMsg := 'BIO_new_mem_buf failed';
      Exit;
    end;
    P12 := OsslD2iPkcs12Bio(PfxBio, nil);
    if P12 = nil then
    begin
      AErrMsg := 'd2i_PKCS12_bio failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    PassAnsi := AnsiString(Password);
    if OsslPkcs12Parse(P12, PAnsiChar(PassAnsi), @ClientKey, @ClientCert, @CaStack) <> 1 then
    begin
      AErrMsg := 'PKCS12_parse failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    if (ClientCert = nil) or (ClientKey = nil) then
    begin
      AErrMsg := 'PKCS12 bundle missing certificate or private key';
      Exit;
    end;
    if OsslSslCtxUseCertificate(ACtx, ClientCert) <> 1 then
    begin
      AErrMsg := 'SSL_CTX_use_certificate failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    if OsslSslCtxUsePrivateKey(ACtx, ClientKey) <> 1 then
    begin
      AErrMsg := 'SSL_CTX_use_PrivateKey failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    if CaStack <> nil then
    begin
      while OsslSkNum(CaStack) > 0 do
      begin
        ChainCert := OsslSkPop(CaStack);
        if ChainCert <> nil then
        begin
          if OsslSslCtxCtrl(ACtx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, ChainCert) <> 1 then
            OsslX509Free(ChainCert);
        end;
      end;
      OsslSkFree(CaStack);
      CaStack := nil;
    end;
    Result := OsslSslCtxCheckPrivateKey(ACtx) = 1;
    if not Result then
      AErrMsg := 'SSL_CTX_check_private_key failed: ' + GetLastOpenSslErrorString;
  finally
    if Length(PfxBytes) > 0 then
      FillChar(PfxBytes[0], Length(PfxBytes), 0);
    if CaStack <> nil then
      OsslSkFree(CaStack);
    if ClientCert <> nil then
      OsslX509Free(ClientCert);
    if ClientKey <> nil then
      OsslEvpPkeyFree(ClientKey);
    if P12 <> nil then
      OsslPkcs12Free(P12);
    if PfxBio <> nil then
      OsslBioFree(PfxBio);
  end;
end;

function SendMtlsRequestWithOpenSSL(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string): TMtlsClientResult;
var
  Ctx: PSSL_CTX;
  Ssl: PSSL;
  RBio, WBio: PBIO;
  WsaData: TWSAData;
  NeedWsaCleanup: Boolean;
  Sock: TSocket;
  Addr: TSockAddrIn;
  HostResolved: AnsiString;
  HostEnt: PHostEnt;
  InAddr: UInt32;
  TimeoutMs: DWORD;
  Ret: Integer;
  SslErr: Integer;
  Iter: Integer;
  ReqText: AnsiString;
  BodyBytes: TBytes;
  ReqBytes: TBytes;
  Written: NativeUInt;
  ReadBuf: array[0..8191] of Byte;
  ReadBytes: NativeUInt;
  RawResp: TBytes;
  RespLen: Integer;
  RespStr: string;
  HdrEnd: Integer;
  FirstLine: string;
  LineEnd: Integer;
  Space1, Space2: Integer;
  ErrText: string;
  LoadErr: string;
  RecvRes: Integer;
begin
  Result.Success := False;
  Result.StatusCode := 0;
  Result.ResponseBody := '';
  Result.ErrorMessage := '';

  if not EnsureOpenSslLoaded then
  begin
    Result.ErrorMessage := GetOpenSslLoadError;
    Exit;
  end;

  NeedWsaCleanup := False;
  if WSAStartup(MAKEWORD(2, 2), WsaData) = 0 then
    NeedWsaCleanup := True;

  Ctx := nil;
  Ssl := nil;
  Sock := INVALID_SOCKET;
  try
    ClearOpenSslErrors;
    Ctx := OsslSslCtxNew(OsslTlsClientMethod());
    if Ctx = nil then
    begin
      Result.ErrorMessage := 'SSL_CTX_new failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    OsslSslCtxSetVerify(Ctx, SSL_VERIFY_NONE, nil);

    if not LoadPfxIntoClientCtx(Ctx, PfxPath, Password, LoadErr) then
    begin
      Result.ErrorMessage := LoadErr;
      Exit;
    end;

    if Trim(ServerHost) = '' then
      HostResolved := '127.0.0.1'
    else
      HostResolved := AnsiString(Trim(ServerHost));

    InAddr := inet_addr(PAnsiChar(HostResolved));
    if InAddr = INADDR_NONE then
    begin
      HostEnt := gethostbyname(PAnsiChar(HostResolved));
      if (HostEnt = nil) or (HostEnt^.h_addr_list = nil) or (HostEnt^.h_addr_list^ = nil) then
      begin
        Result.ErrorMessage := 'Failed to resolve host: ' + string(HostResolved);
        Exit;
      end;
      InAddr := PInAddr(HostEnt^.h_addr_list^)^.S_addr;
    end;

    Sock := Winapi.Winsock2.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if Sock = INVALID_SOCKET then
    begin
      Result.ErrorMessage := 'Socket creation failed: ' + IntToStr(WSAGetLastError);
      Exit;
    end;

    TimeoutMs := 5000;
    setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, PAnsiChar(@TimeoutMs), SizeOf(TimeoutMs));
    setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, PAnsiChar(@TimeoutMs), SizeOf(TimeoutMs));

    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := htons(ServerPort);
    Addr.sin_addr.s_addr := InAddr;

    if connect(Sock, TSockAddr(Addr), SizeOf(Addr)) <> 0 then
    begin
      Result.ErrorMessage := 'TCP connect failed: ' + IntToStr(WSAGetLastError);
      Exit;
    end;

    Ssl := OsslSslNew(Ctx);
    if Ssl = nil then
    begin
      Result.ErrorMessage := 'SSL_new failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    RBio := OsslBioNew(OsslBioSMem());
    WBio := OsslBioNew(OsslBioSMem());
    OsslSslSetBio(Ssl, RBio, WBio);
    OsslSslSetConnectState(Ssl);

    Iter := 0;
    Ret := 0;
    while Iter < 64 do
    begin
      Inc(Iter);
      Ret := OsslSslConnect(Ssl);
      if not FlushOsslWBioToSocket(Sock, WBio) then
      begin
        Result.ErrorMessage := 'Socket send error during TLS handshake';
        Exit;
      end;
      if Ret = 1 then
        Break;
      SslErr := OsslSslGetError(Ssl, Ret);
      if (SslErr = SSL_ERROR_WANT_READ) or (SslErr = SSL_ERROR_WANT_WRITE) then
      begin
        if FeedOsslSocketToRBio(Sock, RBio) <= 0 then
        begin
          Result.ErrorMessage := 'TLS handshake closed or timed out by server';
          Exit;
        end;
      end
      else
      begin
        Result.ErrorMessage := 'TLS handshake error: ' + GetLastOpenSslErrorString;
        Exit;
      end;
    end;

    if Ret <> 1 then
    begin
      Result.ErrorMessage := 'TLS handshake did not complete';
      Exit;
    end;

    if SameText(Method, 'POST') then
    begin
      BodyBytes := TEncoding.UTF8.GetBytes(PostData);
      ReqText := AnsiString(Format('POST %s HTTP/1.1'#13#10'Host: %s:%d'#13#10'Content-Type: application/json'#13#10'Content-Length: %d'#13#10'Connection: close'#13#10#13#10,
        [Path, string(HostResolved), ServerPort, Length(BodyBytes)]));
      SetLength(ReqBytes, Length(ReqText) + Length(BodyBytes));
      if Length(ReqText) > 0 then
        Move(ReqText[1], ReqBytes[0], Length(ReqText));
      if Length(BodyBytes) > 0 then
        Move(BodyBytes[0], ReqBytes[Length(ReqText)], Length(BodyBytes));
    end
    else
    begin
      ReqText := AnsiString(Format('GET %s HTTP/1.1'#13#10'Host: %s:%d'#13#10'Connection: close'#13#10#13#10,
        [Path, string(HostResolved), ServerPort]));
      SetLength(ReqBytes, Length(ReqText));
      if Length(ReqText) > 0 then
        Move(ReqText[1], ReqBytes[0], Length(ReqText));
    end;

    Written := 0;
    if (Length(ReqBytes) > 0) and (OsslSslWriteEx(Ssl, @ReqBytes[0], NativeUInt(Length(ReqBytes)), Written) <> 1) then
    begin
      Result.ErrorMessage := 'SSL_write_ex failed: ' + GetLastOpenSslErrorString;
      Exit;
    end;
    if not FlushOsslWBioToSocket(Sock, WBio) then
    begin
      Result.ErrorMessage := 'Socket send error sending HTTPS request';
      Exit;
    end;

    SetLength(RawResp, 0);
    while True do
    begin
      ReadBytes := 0;
      Ret := OsslSslReadEx(Ssl, @ReadBuf[0], SizeOf(ReadBuf), ReadBytes);
      FlushOsslWBioToSocket(Sock, WBio);
      if (Ret = 1) and (ReadBytes > 0) then
      begin
        RespLen := Length(RawResp);
        SetLength(RawResp, RespLen + Integer(ReadBytes));
        Move(ReadBuf[0], RawResp[RespLen], Integer(ReadBytes));
      end
      else
      begin
        SslErr := OsslSslGetError(Ssl, Ret);
        if (SslErr = SSL_ERROR_WANT_READ) or (SslErr = SSL_ERROR_WANT_WRITE) then
        begin
          RecvRes := FeedOsslSocketToRBio(Sock, RBio);
          if RecvRes <= 0 then
            Break;
        end
        else if SslErr = SSL_ERROR_ZERO_RETURN then
          Break
        else
        begin
          ErrText := GetLastOpenSslErrorString;
          if Length(RawResp) = 0 then
          begin
            Result.ErrorMessage := 'TLS connection rejected: ' + ErrText;
            Exit;
          end;
          Break;
        end;
      end;
    end;

    if Length(RawResp) = 0 then
    begin
      Result.ErrorMessage := 'Empty HTTPS response or server closed connection after client certificate check';
      Exit;
    end;

    RespStr := TEncoding.UTF8.GetString(RawResp);
    HdrEnd := Pos(#13#10#13#10, RespStr);
    if HdrEnd > 0 then
      Result.ResponseBody := Copy(RespStr, HdrEnd + 4, MaxInt)
    else
      Result.ResponseBody := RespStr;

    LineEnd := Pos(#13#10, RespStr);
    if LineEnd > 0 then
      FirstLine := Copy(RespStr, 1, LineEnd - 1)
    else
      FirstLine := RespStr;
    Space1 := Pos(' ', FirstLine);
    if Space1 > 0 then
    begin
      Space2 := Pos(' ', Copy(FirstLine, Space1 + 1, MaxInt));
      if Space2 > 0 then
        Result.StatusCode := StrToIntDef(Copy(FirstLine, Space1 + 1, Space2 - 1), 0)
      else
        Result.StatusCode := StrToIntDef(Copy(FirstLine, Space1 + 1, MaxInt), 0);
    end;

    Result.Success := (Result.StatusCode >= 200) and (Result.StatusCode < 300);
    if (not Result.Success) and (Result.ErrorMessage = '') then
      Result.ErrorMessage := Format('HTTP %d: %s', [Result.StatusCode, Result.ResponseBody]);
  finally
    if Ssl <> nil then
      OsslSslFree(Ssl);
    if Sock <> INVALID_SOCKET then
      closesocket(Sock);
    if Ctx <> nil then
      OsslSslCtxFree(Ctx);
    if NeedWsaCleanup then
      WSACleanup;
  end;
end;

function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string): TMtlsClientResult;
begin
  Result := SendMtlsRequest(ServerHost, ServerPort, Path, Method, PfxPath, Password, PostData, GetConfiguredTlsProvider(tpSchannel));
end;

function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string; ATlsProvider: TTlsProvider): TMtlsClientResult;
var
  Client: TNetHTTPClient;
  Handler: TMtlsHandler;
  Response: IHTTPResponse;
  Url, CertSubject: string;
  BodyStream: TStringStream;
begin
  if ATlsProvider = tpOpenSSL then
  begin
    Result := SendMtlsRequestWithOpenSSL(ServerHost, ServerPort, Path, Method, PfxPath, Password, PostData);
    Exit;
  end;

  Result.Success := False;
  Result.StatusCode := 0;
  Result.ResponseBody := '';
  Result.ErrorMessage := '';

  CertSubject := EnsurePfxInStore(PfxPath, Password);

  Url := Format('https://%s:%d%s', [ServerHost, ServerPort, Path]);
  Handler := TMtlsHandler.Create(CertSubject);
  Client := TNetHTTPClient.Create(nil);
  try
    Client.CustomHeaders['Connection'] := 'close';
    Client.OnValidateServerCertificate := Handler.HandleValidateServerCertificate;
    Client.OnNeedClientCertificate := Handler.HandleNeedClientCertificate;
    try
      if SameText(Method, 'POST') then
      begin
        BodyStream := TStringStream.Create(PostData, TEncoding.UTF8);
        try
          Response := Client.Post(Url, BodyStream);
        finally
          BodyStream.Free;
        end;
      end
      else
        Response := Client.Get(Url);

      Result.StatusCode := Response.StatusCode;
      Result.ResponseBody := Response.ContentAsString;
      Result.Success := (Result.StatusCode >= 200) and (Result.StatusCode < 300);
    except
      on E: Exception do
        Result.ErrorMessage := E.Message;
    end;
  finally
    Client.Free;
    Handler.Free;
  end;
end;

end.
