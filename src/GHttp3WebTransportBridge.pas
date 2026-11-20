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
unit GHttp3WebTransportBridge;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.SyncObjs,
  System.Generics.Collections,
  GLogger,
  GJWTManager,
  GRequest,
  GResponse,
  Http3.Types,
  Http3.Server,
  Http3.Request,
  Http3.Response,
  WebTransport.Types,
  WebTransport.Server,
  WebTransport.Session,
  MsQuic.Types,
  WinApiAdditions,
  GHttpsServerTypes,
  GIpSecurityAndCors;

type
  THttp3EndpointLookupFunc = reference to function(
    AMethod: THttpMethod;
    const APath: string;
    out AAuthType: TAuthorizationType;
    out AKey: string
  ): Boolean;

  THttp3EndpointInvokeProc = reference to procedure(
    AMethod: THttpMethod;
    const APath: string;
    const ARequest: TRequest;
    const AResponse: TResponse
  );

  THttp3WebTransportBridge = class
  private
    FLock: TCriticalSection;
    FIpSecurity: TIpSecurityTracker;
    FCorsPolicy: TCorsAndOriginPolicy;
    FJWTManager: TJWTManager;
    FEnableHttp3: Boolean;
    FHttp3Server: THttp3Server;
    FHttp3SettingMaxFieldSectionSize: UInt64;
    FHttp3SettingQpackMaxTableCapacity: UInt64;
    FHttp3SettingQpackBlockedStreams: UInt64;
    FHttp3EnableDemoEndpoints: Boolean;
    FQuicRequiredServerName: string;
    FQuicForceStatelessRetry: Boolean;
    FQuicAlpnProtocol: string;
    FWebTransportRoutes: TDictionary<string, TWebTransportRouteItem>;
    FWebTransportSessionRoutes: TDictionary<TWTSessionId, string>;
    FRunningPtr: PBoolean;
    FRejectNewConnectionsPtr: PLongInt;
    FActiveConnectionsPtr: PInt64;
    FMaxConnectionsPtr: PInteger;
    FRequestsPerSecondCounterPtr: PLongInt;
    FMaxRequestHederSizePtr: PInteger;
    FMaxRequestSizePtr: PInt64;
    FmTLSModePtr: ^TmTLSMode;
    FAllowedFileExtensions: TStringList;
    FBlockedMimeTypes: TStringList;
    FOnEndpointLookup: THttp3EndpointLookupFunc;
    FOnEndpointInvoke: THttp3EndpointInvokeProc;
  public
    constructor Create(
      ALock: TCriticalSection;
      AIpSecurity: TIpSecurityTracker;
      ACorsPolicy: TCorsAndOriginPolicy;
      AJWTManager: TJWTManager;
      ARunningPtr: PBoolean;
      ARejectNewConnectionsPtr: PLongInt;
      AActiveConnectionsPtr: PInt64;
      AMaxConnectionsPtr: PInteger;
      ARequestsPerSecondCounterPtr: PLongInt;
      AMaxRequestHederSizePtr: PInteger;
      AMaxRequestSizePtr: PInt64;
      AmTLSModePtr: Pointer;
      AAllowedFileExtensions: TStringList;
      ABlockedMimeTypes: TStringList
    );
    destructor Destroy; override;
    procedure RegisterWebTransportRoute(const APath: string); overload;
    procedure RegisterWebTransportRoute(
      const APath: string;
      AOnSessionReady: TWebTransportSessionProc;
      AOnStreamData: TWebTransportStreamProc;
      AOnDatagram: TWebTransportDatagramProc;
      AOnSessionClosed: TWebTransportClosedProc = nil
    ); overload;
    procedure HandleHttp3Request(
      Sender: TObject;
      const AMethod, APath, ARemoteIP: string;
      const AHeaders: TArray<TPair<string, string>>;
      const ABody: TBytes;
      const AClientCert: TGClientCertInfo;
      out AStatusCode: Integer;
      out AContentType: string;
      out AResponseBody: TBytes;
      out AExtraHeaders: TArray<TPair<string, string>>
    );
    function WebTransportSessionRequest(Sender: TObject; const Info: TWTSessionInfo): Boolean;
    procedure WebTransportSessionReady(Sender: TObject; Session: PWTSessionContext);
    procedure WebTransportSessionClosed(Sender: TObject; SessionId: TWTSessionId);
    procedure WebTransportStreamData(Sender: TObject; Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes);
    procedure WebTransportDatagram(Sender: TObject; Session: PWTSessionContext; const Data: TBytes);
    procedure WebTransportDatagramPtr(Sender: TObject; Session: PWTSessionContext; DataPtr: PByte; DataLen: Cardinal);
    function HandleQuicBeforeAcceptConnection(Sender: TObject; const ARemoteIP: string): Boolean;
    procedure HandleQuicAfterCloseConnection(Sender: TObject; const ARemoteIP: string);
    procedure HandleQuicHandshakeFailed(Sender: TObject; const ARemoteIP: string);
    property EnableHttp3: Boolean read FEnableHttp3 write FEnableHttp3;
    property Http3Server: THttp3Server read FHttp3Server write FHttp3Server;
    property Http3SettingMaxFieldSectionSize: UInt64 read FHttp3SettingMaxFieldSectionSize write FHttp3SettingMaxFieldSectionSize;
    property Http3SettingQpackMaxTableCapacity: UInt64 read FHttp3SettingQpackMaxTableCapacity write FHttp3SettingQpackMaxTableCapacity;
    property Http3SettingQpackBlockedStreams: UInt64 read FHttp3SettingQpackBlockedStreams write FHttp3SettingQpackBlockedStreams;
    property Http3EnableDemoEndpoints: Boolean read FHttp3EnableDemoEndpoints write FHttp3EnableDemoEndpoints;
    property QuicRequiredServerName: string read FQuicRequiredServerName write FQuicRequiredServerName;
    property QuicForceStatelessRetry: Boolean read FQuicForceStatelessRetry write FQuicForceStatelessRetry;
    property QuicAlpnProtocol: string read FQuicAlpnProtocol write FQuicAlpnProtocol;
    property OnEndpointLookup: THttp3EndpointLookupFunc read FOnEndpointLookup write FOnEndpointLookup;
    property OnEndpointInvoke: THttp3EndpointInvokeProc read FOnEndpointInvoke write FOnEndpointInvoke;
  end;

function IsMsQuicDllAvailable(out AErrorDetails: string): Boolean; overload;
function IsMsQuicDllAvailable(out AErrorDetails: string; ATlsProvider: TTlsProvider): Boolean; overload;

implementation

function IsMsQuicDllAvailable(out AErrorDetails: string): Boolean;
begin
  Result := IsMsQuicDllAvailable(AErrorDetails, GetConfiguredTlsProvider(tpSchannel));
end;

function IsMsQuicDllAvailable(out AErrorDetails: string; ATlsProvider: TTlsProvider): Boolean;
var
  ExeDir, MsQuicDllName, MsQuicPath, LsQpackPath: string;
  HMsQuic, HLsQpack: HMODULE;
  OpenVerFunc: function(Version: Cardinal; out ApiTable: Pointer): Cardinal; cdecl;
  CloseFunc: procedure(ApiTable: Pointer); cdecl;
  ApiTable: Pointer;
  Status: Cardinal;
  OldErrorMode: UINT;
begin
  Result := False;
  AErrorDetails := '';

  ExeDir := ExtractFilePath(ParamStr(0));
  if ATlsProvider = tpOpenSSL then
    MsQuicDllName := 'msquicSSL.dll'
  else
    MsQuicDllName := 'msquic.dll';
  MsQuicPath := ExeDir + MsQuicDllName;
  LsQpackPath := ExeDir + 'ls-qpack.dll';

  if not FileExists(MsQuicPath) then
  begin
    AErrorDetails := Format('%s not found in server directory: %s', [MsQuicDllName, MsQuicPath]);
    Exit;
  end;

  if not FileExists(LsQpackPath) then
  begin
    AErrorDetails := Format('ls-qpack.dll not found in server directory: %s', [LsQpackPath]);
    Exit;
  end;

  OldErrorMode := SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
  try
    HMsQuic := LoadLibrary(PChar(MsQuicPath));
    if HMsQuic = 0 then
    begin
      AErrorDetails := Format('LoadLibrary("%s") failed (Error %d: %s)', [MsQuicPath, GetLastError, SysErrorMessage(GetLastError)]);
      Exit;
    end;

    try
      @OpenVerFunc := GetProcAddress(HMsQuic, 'MsQuicOpenVersion');
      @CloseFunc := GetProcAddress(HMsQuic, 'MsQuicClose');
      if not Assigned(@OpenVerFunc) then
      begin
        AErrorDetails := Format('%s in "%s" does not export "MsQuicOpenVersion"', [MsQuicDllName, MsQuicPath]);
        Exit;
      end;

      ApiTable := nil;
      Status := OpenVerFunc(2, ApiTable);
      if Status <> 0 then
      begin
        AErrorDetails := Format('MsQuicOpenVersion failed with status code 0x%x (%d)', [Status, Status]);
        Exit;
      end;
      if Assigned(@CloseFunc) and (ApiTable <> nil) then
        CloseFunc(ApiTable);
    finally
      FreeLibrary(HMsQuic);
    end;

    HLsQpack := LoadLibrary(PChar(LsQpackPath));
    if HLsQpack = 0 then
    begin
      AErrorDetails := Format('LoadLibrary("%s") failed (Error %d: %s)', [LsQpackPath, GetLastError, SysErrorMessage(GetLastError)]);
      Exit;
    end;

    try
      if (GetProcAddress(HLsQpack, 'lsqpack_enc_init') = nil) or
         (GetProcAddress(HLsQpack, 'lsqpack_dec_init') = nil) then
      begin
        AErrorDetails := Format('ls-qpack.dll in "%s" does not export required entry points (lsqpack_enc_init / lsqpack_dec_init)', [LsQpackPath]);
        Exit;
      end;
    finally
      FreeLibrary(HLsQpack);
    end;

    Result := True;
  finally
    SetErrorMode(OldErrorMode);
  end;
end;

constructor THttp3WebTransportBridge.Create(
  ALock: TCriticalSection;
  AIpSecurity: TIpSecurityTracker;
  ACorsPolicy: TCorsAndOriginPolicy;
  AJWTManager: TJWTManager;
  ARunningPtr: PBoolean;
  ARejectNewConnectionsPtr: PLongInt;
  AActiveConnectionsPtr: PInt64;
  AMaxConnectionsPtr: PInteger;
  ARequestsPerSecondCounterPtr: PLongInt;
  AMaxRequestHederSizePtr: PInteger;
  AMaxRequestSizePtr: PInt64;
  AmTLSModePtr: Pointer;
  AAllowedFileExtensions: TStringList;
  ABlockedMimeTypes: TStringList);
begin
  inherited Create;
  FLock := ALock;
  FIpSecurity := AIpSecurity;
  FCorsPolicy := ACorsPolicy;
  FJWTManager := AJWTManager;
  FRunningPtr := ARunningPtr;
  FRejectNewConnectionsPtr := ARejectNewConnectionsPtr;
  FActiveConnectionsPtr := AActiveConnectionsPtr;
  FMaxConnectionsPtr := AMaxConnectionsPtr;
  FRequestsPerSecondCounterPtr := ARequestsPerSecondCounterPtr;
  FMaxRequestHederSizePtr := AMaxRequestHederSizePtr;
  FMaxRequestSizePtr := AMaxRequestSizePtr;
  FmTLSModePtr := AmTLSModePtr;
  FAllowedFileExtensions := AAllowedFileExtensions;
  FBlockedMimeTypes := ABlockedMimeTypes;
  FEnableHttp3 := True;
  FHttp3Server := nil;
  FHttp3SettingMaxFieldSectionSize := 0;
  FHttp3SettingQpackMaxTableCapacity := 0;
  FHttp3SettingQpackBlockedStreams := 0;
  FHttp3EnableDemoEndpoints := True;
  FQuicRequiredServerName := '';
  FQuicForceStatelessRetry := False;
  FQuicAlpnProtocol := '';
  FWebTransportRoutes := TDictionary<string, TWebTransportRouteItem>.Create;
  FWebTransportSessionRoutes := TDictionary<TWTSessionId, string>.Create;
end;

destructor THttp3WebTransportBridge.Destroy;
var
  WtItem: TWebTransportRouteItem;
begin
  if Assigned(FHttp3Server) then
  begin
    FHttp3Server.Stop;
    FreeAndNil(FHttp3Server);
  end;
  if Assigned(FWebTransportRoutes) then
  begin
    for WtItem in FWebTransportRoutes.Values do
      WtItem.Free;
    FreeAndNil(FWebTransportRoutes);
  end;
  FreeAndNil(FWebTransportSessionRoutes);
  inherited Destroy;
end;

procedure THttp3WebTransportBridge.RegisterWebTransportRoute(const APath: string);
var
  LSessionReady: TWebTransportSessionProc;
  LStreamData: TWebTransportStreamProc;
  LDatagram: TWebTransportDatagramProc;
  LSessionClosed: TWebTransportClosedProc;
  LItem: TWebTransportRouteItem;
begin
  LSessionReady := nil;
  LSessionClosed := nil;
  LStreamData :=
    procedure(Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes)
    begin
      Session.SendOnStream(Stream, Data);
    end;
  LDatagram :=
    procedure(Session: PWTSessionContext; const Data: TBytes)
    begin
      Session.SendDatagram(Data);
    end;
  RegisterWebTransportRoute(APath, LSessionReady, LStreamData, LDatagram, LSessionClosed);
  FLock.Enter;
  try
    if FWebTransportRoutes.TryGetValue(LowerCase(APath), LItem) then
      LItem.IsEchoDefault := True;
  finally
    FLock.Leave;
  end;
end;

procedure THttp3WebTransportBridge.RegisterWebTransportRoute(
  const APath: string;
  AOnSessionReady: TWebTransportSessionProc;
  AOnStreamData: TWebTransportStreamProc;
  AOnDatagram: TWebTransportDatagramProc;
  AOnSessionClosed: TWebTransportClosedProc);
var
  Item: TWebTransportRouteItem;
  OldItem: TWebTransportRouteItem;
begin
  FLock.Enter;
  try
    if FWebTransportRoutes.TryGetValue(LowerCase(APath), OldItem) then
    begin
      if Assigned(OldItem) then
        OldItem.Free;
    end;
    Item := TWebTransportRouteItem.Create(APath, AOnSessionReady, AOnStreamData, AOnDatagram, AOnSessionClosed);
    FWebTransportRoutes.AddOrSetValue(LowerCase(APath), Item);
    Logger.Info(Format('Registered WebTransport route: %s (HasOnStreamData: %s, HasOnDatagram: %s)',
      [APath, BoolToStr(Assigned(AOnStreamData), True), BoolToStr(Assigned(AOnDatagram), True)]));
  finally
    FLock.Leave;
  end;
end;

procedure THttp3WebTransportBridge.HandleHttp3Request(
  Sender: TObject;
  const AMethod, APath, ARemoteIP: string;
  const AHeaders: TArray<TPair<string, string>>;
  const ABody: TBytes;
  const AClientCert: TGClientCertInfo;
  out AStatusCode: Integer;
  out AContentType: string;
  out AResponseBody: TBytes;
  out AExtraHeaders: TArray<TPair<string, string>>
);
var
  ReqInfo: THttpRequestInfo;
  EndpointFound: Boolean;
  AuthType: TAuthorizationType;
  Key: string;
  MethodEnum: THttpMethod;
  Request: TRequest;
  Response: TResponse;
  AuthHeader: string;
  JWT: TJWTToken;
  isAuthorized: Boolean;
  Hdr: TPair<string, string>;
  RemoteAddr: TSockAddrIn;
  H3Origin: string;
  H3ReqHeaders: string;
  H3AllowOrigin: string;
  HdrList: TList<TPair<string, string>>;
  TotalH3HeaderBytes: Integer;
  BodyStrm: TMemoryStream;
begin
  AStatusCode := 404;
  AContentType := 'text/plain';
  SetLength(AResponseBody, 0);
  SetLength(AExtraHeaders, 0);

  if FRejectNewConnectionsPtr^ = 1 then
  begin
    AStatusCode := 503;
    AResponseBody := TEncoding.UTF8.GetBytes('503 Service Unavailable');
    Exit;
  end;

  if (ARemoteIP <> '') and (not FIpSecurity.CheckIPRateLimit(ARemoteIP)) then
  begin
    AStatusCode := 429;
    SetLength(AExtraHeaders, 1);
    AExtraHeaders[0] := TPair<string, string>.Create('retry-after', '1');
    AResponseBody := TEncoding.UTF8.GetBytes('429 Too Many Requests');
    Exit;
  end;

  ReqInfo := THttpRequestInfo.Create;
  try
    if Length(APath) > 3072 then
    begin
      AStatusCode := 414;
      AContentType := 'text/plain';
      AResponseBody := TEncoding.UTF8.GetBytes('414 URI Too Long');
      Exit;
    end;

    ReqInfo.ParseUri(APath);

    if not ReqInfo.IsUriValid then
    begin
      AStatusCode := 400;
      AContentType := 'text/plain';
      AResponseBody := TEncoding.UTF8.GetBytes('400 Bad Request');
      Exit;
    end;

    TotalH3HeaderBytes := 0;
    for Hdr in AHeaders do
    begin
      Inc(TotalH3HeaderBytes, Length(Hdr.Key) + Length(Hdr.Value));
      if (Length(Hdr.Value) > 1024) or (TotalH3HeaderBytes > 1500) then
      begin
        AStatusCode := 431;
        AContentType := 'text/plain';
        AResponseBody := TEncoding.UTF8.GetBytes('431 Request Header Fields Too Large');
        Exit;
      end;
    end;

    H3Origin := '';
    H3ReqHeaders := '';
    for Hdr in AHeaders do
    begin
      if SameText(Hdr.Key, 'origin') then
        H3Origin := Hdr.Value
      else if SameText(Hdr.Key, 'access-control-request-headers') then
        H3ReqHeaders := Hdr.Value;
    end;

    if FCorsPolicy.EnableCORS and SameText(AMethod, 'OPTIONS') and (H3Origin <> '') then
    begin
      if not FCorsPolicy.IsOriginAllowed(H3Origin) then
      begin
        AStatusCode := 403;
        AContentType := 'text/plain';
        AResponseBody := TEncoding.UTF8.GetBytes('403 Forbidden');
        Exit;
      end;

      if FCorsPolicy.CORSAllowCredentials or (FCorsPolicy.CORSAllowedOrigins <> '*') then
        H3AllowOrigin := H3Origin
      else
        H3AllowOrigin := '*';

      AStatusCode := 204;
      AContentType := '';
      SetLength(AResponseBody, 0);

      HdrList := TList<TPair<string, string>>.Create;
      try
        HdrList.Add(TPair<string, string>.Create('access-control-allow-origin', H3AllowOrigin));
        HdrList.Add(TPair<string, string>.Create('access-control-allow-methods', FCorsPolicy.CORSAllowedMethods));
        if H3ReqHeaders <> '' then
          HdrList.Add(TPair<string, string>.Create('access-control-allow-headers', H3ReqHeaders))
        else if FCorsPolicy.CORSAllowedHeaders <> '' then
          HdrList.Add(TPair<string, string>.Create('access-control-allow-headers', FCorsPolicy.CORSAllowedHeaders));
        if FCorsPolicy.CORSMaxAge > 0 then
          HdrList.Add(TPair<string, string>.Create('access-control-max-age', IntToStr(FCorsPolicy.CORSMaxAge)));
        if FCorsPolicy.CORSAllowCredentials then
          HdrList.Add(TPair<string, string>.Create('access-control-allow-credentials', 'true'));
        HdrList.Add(TPair<string, string>.Create('vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers'));
        AExtraHeaders := HdrList.ToArray;
      finally
        HdrList.Free;
      end;
      Exit;
    end;

    if SameText(AMethod, 'GET') then
      MethodEnum := hmGET
    else if SameText(AMethod, 'POST') then
      MethodEnum := hmPOST
    else if SameText(AMethod, 'PUT') then
      MethodEnum := hmPUT
    else if SameText(AMethod, 'DELETE') then
      MethodEnum := hmDELETE
    else if SameText(AMethod, 'HEAD') then
      MethodEnum := hmHEAD
    else if SameText(AMethod, 'OPTIONS') then
      MethodEnum := hmOPTIONS
    else if SameText(AMethod, 'PATCH') then
      MethodEnum := hmPATCH
    else
      MethodEnum := hmUnknown;

    EndpointFound := False;
    AuthType := atNone;
    Key := '';
    if Assigned(FOnEndpointLookup) then
      EndpointFound := FOnEndpointLookup(MethodEnum, ReqInfo.Path, AuthType, Key);

    if not EndpointFound then
    begin
      AStatusCode := 404;
      AContentType := 'text/plain';
      AResponseBody := TEncoding.UTF8.GetBytes('404 Not Found');
      Exit;
    end;

    if (FmTLSModePtr^ = mtlsRequired) and ((not AClientCert.HasCertificate) or (not AClientCert.IsVerified)) then
    begin
      AStatusCode := 401;
      AContentType := 'application/json';
      AResponseBody := TEncoding.UTF8.GetBytes('{"error":"Client certificate required and verification failed"}');
      Exit;
    end;

    FillChar(RemoteAddr, SizeOf(RemoteAddr), 0);
    Request := TRequest.Create(INVALID_SOCKET, RemoteAddr, FMaxRequestHederSizePtr^, FMaxRequestSizePtr^);
    Request.ClientCertificate := AClientCert;
    if Assigned(FAllowedFileExtensions) and (FAllowedFileExtensions.Count > 0) then
      Request.AllowedFileExtensions.Assign(FAllowedFileExtensions);
    if Assigned(FBlockedMimeTypes) and (FBlockedMimeTypes.Count > 0) then
      Request.BlockedMimeTypes.Assign(FBlockedMimeTypes);
    Response := TResponse.Create(INVALID_SOCKET);
    try
      Request.RequestInfo.ParseRequestLine(AMethod + ' ' + APath + ' HTTP/1.1');
      AuthHeader := '';
      for Hdr in AHeaders do
      begin
        Request.Headers.AddHeader(Hdr.Key, Hdr.Value);
        if SameText(Hdr.Key, 'authorization') then
          AuthHeader := Hdr.Value;
      end;

      if Length(ABody) > 0 then
      begin
        BodyStrm := Request.GetBodyStream;
        if Assigned(BodyStrm) then
        begin
          BodyStrm.Clear;
          BodyStrm.WriteBuffer(ABody[0], Length(ABody));
          BodyStrm.Position := 0;
        end;
      end;

      if AuthType = atJWTBearer then
      begin
        isAuthorized := False;
        AuthHeader := FJWTManager.ExtractTokenFromAuthHeader(AuthHeader);
        if Length(AuthHeader) > 0 then
        begin
          JWT := nil;
          try
            if FJWTManager.ValidateToken(AuthHeader, JWT) then
              isAuthorized := True;
          finally
            if Assigned(JWT) then
              JWT.Free;
          end;
        end;
        if not isAuthorized then
        begin
          AStatusCode := 401;
          AContentType := 'application/json';
          AResponseBody := TEncoding.UTF8.GetBytes('{"error":"Unauthorized"}');
          Exit;
        end;
      end;

      try
        if Assigned(FOnEndpointInvoke) then
          FOnEndpointInvoke(MethodEnum, ReqInfo.Path, Request, Response);
      except
        on E: Exception do
        begin
          Logger.Error(Format('Error in H3 handler for endpoint %s: %s', [Key, E.Message]));
          Response.SetInternalServerError('An error occurred while processing your request.');
        end;
      end;

      AStatusCode := Ord(Response.Status);
      if AStatusCode = 0 then
        AStatusCode := 200;

      AContentType := Response.ContentType;
      if AContentType = '' then
        AContentType := 'text/html; charset=utf-8';

      AResponseBody := Response.GetBodyBytes;

      HdrList := TList<TPair<string, string>>.Create;
      try
        HdrList.Add(TPair<string, string>.Create('etag', '"h3-static-etag"'));
        HdrList.Add(TPair<string, string>.Create('cache-control', 'max-age=3600, public'));
        if FCorsPolicy.EnableCORS and (H3Origin <> '') and FCorsPolicy.IsOriginAllowed(H3Origin) then
        begin
          if FCorsPolicy.CORSAllowCredentials or (FCorsPolicy.CORSAllowedOrigins <> '*') then
            H3AllowOrigin := H3Origin
          else
            H3AllowOrigin := '*';

          HdrList.Add(TPair<string, string>.Create('access-control-allow-origin', H3AllowOrigin));
          if FCorsPolicy.CORSExposeHeaders <> '' then
            HdrList.Add(TPair<string, string>.Create('access-control-expose-headers', FCorsPolicy.CORSExposeHeaders));
          if FCorsPolicy.CORSAllowCredentials then
            HdrList.Add(TPair<string, string>.Create('access-control-allow-credentials', 'true'));
          HdrList.Add(TPair<string, string>.Create('vary', 'Origin'));
        end;
        AExtraHeaders := HdrList.ToArray;
      finally
        HdrList.Free;
      end;
    finally
      Request.Free;
      Response.Free;
    end;
  finally
    ReqInfo.Free;
  end;
end;

function THttp3WebTransportBridge.WebTransportSessionRequest(Sender: TObject; const Info: TWTSessionInfo): Boolean;
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  QMark: Integer;
begin
  Result := False;
  if not FCorsPolicy.IsWebTransportOriginAllowed(Info.Origin, Info.Authority) then
  begin
    Logger.Warn('[WT] WebTransportSessionRequest rejected: Origin "%s" or Authority "%s" not allowed', [Info.Origin, Info.Authority]);
    Exit;
  end;
  PurePath := LowerCase(Info.Path);
  QMark := Pos('?', PurePath);
  if QMark > 0 then
    PurePath := Copy(PurePath, 1, QMark - 1);

  FLock.Enter;
  try
    Result := FWebTransportRoutes.TryGetValue(PurePath, Item);
    if not Result then
      Logger.Warn('[WT] WebTransportSessionRequest rejected: Route not found for "%s"', [PurePath]);
  finally
    FLock.Leave;
  end;
end;

procedure THttp3WebTransportBridge.WebTransportSessionReady(Sender: TObject; Session: PWTSessionContext);
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  QMark: Integer;
begin
  if Session = nil then
    Exit;
  PurePath := LowerCase(Session^.Path);
  QMark := Pos('?', PurePath);
  if QMark > 0 then
    PurePath := Copy(PurePath, 1, QMark - 1);

  FLock.Enter;
  try
    if Assigned(FWebTransportSessionRoutes) then
      FWebTransportSessionRoutes.AddOrSetValue(Session^.SessionId, PurePath);
    if FWebTransportRoutes.TryGetValue(PurePath, Item) and Assigned(Item.OnSessionReady) then
      Item.OnSessionReady(Session);
  finally
    FLock.Leave;
  end;
end;

procedure THttp3WebTransportBridge.WebTransportSessionClosed(Sender: TObject; SessionId: TWTSessionId);
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  Callbacks: array of TWebTransportClosedProc;
  CB: TWebTransportClosedProc;
begin
  SetLength(Callbacks, 0);
  FLock.Enter;
  try
    if Assigned(FWebTransportSessionRoutes) and FWebTransportSessionRoutes.TryGetValue(SessionId, PurePath) then
    begin
      FWebTransportSessionRoutes.Remove(SessionId);
      if FWebTransportRoutes.TryGetValue(PurePath, Item) and Assigned(Item.OnSessionClosed) then
      begin
        SetLength(Callbacks, 1);
        Callbacks[0] := Item.OnSessionClosed;
      end;
    end
    else
    begin
      Logger.Info(Format('[WT] Closed untracked session: %d', [SessionId]));
    end;
  finally
    FLock.Leave;
  end;

  for CB in Callbacks do
    CB(SessionId);
end;

procedure THttp3WebTransportBridge.WebTransportStreamData(Sender: TObject; Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes);
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  QMark: Integer;
begin
  if Session = nil then
    Exit;
  PurePath := LowerCase(Session^.Path);
  QMark := Pos('?', PurePath);
  if QMark > 0 then
    PurePath := Copy(PurePath, 1, QMark - 1);

  FLock.Enter;
  try
    if FWebTransportRoutes.TryGetValue(PurePath, Item) and Assigned(Item.OnStreamData) then
      Item.OnStreamData(Session, Stream, Data);
  finally
    FLock.Leave;
  end;
end;

procedure THttp3WebTransportBridge.WebTransportDatagram(Sender: TObject; Session: PWTSessionContext; const Data: TBytes);
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  QMark: Integer;
  DatagramProc: TWebTransportDatagramProc;
begin
  if Session = nil then
    Exit;
  PurePath := LowerCase(Session^.Path);
  QMark := Pos('?', PurePath);
  if QMark > 0 then
    PurePath := Copy(PurePath, 1, QMark - 1);

  DatagramProc := nil;
  FLock.Enter;
  try
    if FWebTransportRoutes.TryGetValue(PurePath, Item) then
      DatagramProc := Item.OnDatagram;
  finally
    FLock.Leave;
  end;

  if Assigned(DatagramProc) then
    DatagramProc(Session, Data);
end;

procedure THttp3WebTransportBridge.WebTransportDatagramPtr(Sender: TObject; Session: PWTSessionContext; DataPtr: PByte; DataLen: Cardinal);
var
  Item: TWebTransportRouteItem;
  PurePath: string;
  QMark: Integer;
  DatagramProc: TWebTransportDatagramProc;
  IsEcho: Boolean;
  Data: TBytes;
begin
  if Session = nil then
    Exit;
  PurePath := LowerCase(Session^.Path);
  QMark := Pos('?', PurePath);
  if QMark > 0 then
    PurePath := Copy(PurePath, 1, QMark - 1);

  DatagramProc := nil;
  IsEcho := False;
  FLock.Enter;
  try
    if FWebTransportRoutes.TryGetValue(PurePath, Item) then
    begin
      IsEcho := Item.IsEchoDefault;
      if not IsEcho then
        DatagramProc := Item.OnDatagram;
    end;
  finally
    FLock.Leave;
  end;

  if IsEcho then
    Session^.SendDatagramPtr(DataPtr, DataLen)
  else if Assigned(DatagramProc) then
  begin
    if (DataPtr <> nil) and (DataLen > 0) then
    begin
      SetLength(Data, DataLen);
      Move(DataPtr^, Data[0], DataLen);
    end
    else
      SetLength(Data, 0);
    DatagramProc(Session, Data);
  end;
end;

function THttp3WebTransportBridge.HandleQuicBeforeAcceptConnection(Sender: TObject; const ARemoteIP: string): Boolean;
begin
  Result := False;
  if (not FRunningPtr^) or (FRejectNewConnectionsPtr^ = 1) or (FActiveConnectionsPtr^ >= FMaxConnectionsPtr^) then
  begin
    Logger.Warn('[QUIC] HandleQuicBeforeAcceptConnection rejected: Server state (running=%d, active=%d/%d)',
      [Ord(FRunningPtr^), FActiveConnectionsPtr^, FMaxConnectionsPtr^]);
    Exit;
  end;
  if not FIpSecurity.CheckAndResetQuicBlock(ARemoteIP) then
    Exit;
  if not FIpSecurity.TrackIPConnect(ARemoteIP) then
  begin
    Logger.Warn('[QUIC] HandleQuicBeforeAcceptConnection rejected: TrackIPConnect failed for %s', [ARemoteIP]);
    Exit;
  end;
  FIpSecurity.ClearQuicFailureCount(ARemoteIP);
  TInterlocked.Increment(FRequestsPerSecondCounterPtr^);
  InterlockedIncrement64(FActiveConnectionsPtr^);
  Result := True;
end;

procedure THttp3WebTransportBridge.HandleQuicAfterCloseConnection(Sender: TObject; const ARemoteIP: string);
begin
  InterlockedDecrement64(FActiveConnectionsPtr^);
  if ARemoteIP <> '' then
    FIpSecurity.TrackIPDisconnect(ARemoteIP);
end;

procedure THttp3WebTransportBridge.HandleQuicHandshakeFailed(Sender: TObject; const ARemoteIP: string);
begin
  FIpSecurity.RecordQuicHandshakeFailure(ARemoteIP, FmTLSModePtr^ = mtlsRequired);
end;

end.
