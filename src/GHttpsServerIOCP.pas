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

unit GHttpsServerIOCP;

interface

uses
  FASTMM5,
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.Math,
  System.SyncObjs,
  System.Generics.Collections,
  System.DateUtils,
  System.NetEncoding,
  System.StrUtils,
  System.IOUtils,
  System.JSON,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  GWebSocket,
  GJWTManager,
  GRequest,
  GRequestBody,
  GResponse,
  OverlappedExPool,
  WinApiAdditions,
  WinApi.MsQuic,
  Net.MsQuic,
  Net.Http3Frames,
  Net.QPACK.Huffman,
  Net.QPACK,
  Net.Http3Request,
  Net.Http3Response,
  Net.Http3Server;

type
  TServerProtocolMode = (
    pmHttpOnly,
    pmHttpsOnly,
    pmDualHttpAndHttps
  );

  THttpActionOnDualMode = (
    haServeNormally,
    haRedirectToHttps
  );

  TAuthorizationType = (atNone, atJWTBearer);

  TGHttpsServerIOCP = class;

  TEndpointEvent = procedure(Sender: TObject;
                             const ARequest: TRequest;
                             const AResponse: TResponse;
                             AServer:TGHttpsServerIOCP) of object;
  TEndpointEventProc = reference to procedure(Sender: TObject;
                                              const ARequest: TRequest;
                                              const AResponse: TResponse;
                                              AServer:TGHttpsServerIOCP) ;

  TWebSocketMessageProc = reference to procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const MessageText: string; Opcode: TWebSocketOpcode);
  TWebSocketConnectProc = reference to procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession);
  TWebSocketDisconnectProc = reference to procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const Reason: string);

  TEndpointItem = class
  private
    FPath: string;
    FMethod: THttpMethod;
    FHandler: TEndpointEvent;
    FHandlerProc: TEndpointEventProc;
    FServer:TGHttpsServerIOCP;
    FAuthorizationType: TAuthorizationType;
  public
    constructor Create(const APath: string;
                       AMethod: THttpMethod;
                       AHandler: TEndpointEvent;
                       AHandlerProc: TEndpointEventProc;
                       AAuthorizationType: TAuthorizationType;
                       AServer:TGHttpsServerIOCP);

    property Path: string read FPath;
    property Method: THttpMethod read FMethod;
    property Handler: TEndpointEvent read FHandler;
    property HandlerProc: TEndpointEventProc read FHandlerProc;
    property AuthorizationType: TAuthorizationType read FAuthorizationType;
  end;

  TGHttpsServerIOCP = class
  private
    OverlappedExG: POverlappedEx;
    FEnableGracefulSSLShutdown: Boolean;
    FSSLShutdownTimeout: Cardinal;
    FListenSocket: TSocket;
    FListenSocketHTTP: TSocket;
    FCompletionPort: THandle;
    FPort: Word;
    FHttpsPort: Word;
    FHttpPort: Word;
    FProtocolMode: TServerProtocolMode;
    FHttpAction: THttpActionOnDualMode;
    FRunning: Boolean;
    FWorkerThreads: TList<THandle>;
    FCertContext: PCCERT_CONTEXT;
    FH3CertContext: PCCERT_CONTEXT;
    FServerCredHandle: TCredHandle;
    FCredentialsValid: Boolean;
    FActiveConnections: Int64;
    FMaxConnections: Integer;
    FJWTManager: TJWTManager;
    FEndpoints: TDictionary<string, TEndpointItem>;
    FWebSocketRoutes: TDictionary<string, Boolean>;
    FWebSocketRouteHandlers: TDictionary<string, TWebSocketMessageProc>;
    FOnWebSocketMessage: TWebSocketMessageProc;
    FOnWebSocketConnect: TWebSocketConnectProc;
    FOnWebSocketDisconnect: TWebSocketDisconnectProc;
    FLock: TCriticalSection;
    FOverlappedPool: TOverlappedExPool;
    FMaxRequestHederSize:Integer;
    FMaxRequestSize: Int64;
    FMaxResponseSize: Int64;
    FChunkSize: Integer;
    FMonitorRun: Boolean;
    FMonitorThread: THandle;
    FRejectNewConnections: LongInt;
    FRequestsPerSecondCounter: LongInt;
    FMaxRequestsPerSecond: Integer;
    FThrottleNewConnections: LongInt;
    FSubjectName:String;
    FCertificateStore:String;
    FActiveOverlapped: TList<POverlappedEx>;
    FActiveOverlappedLock: TCriticalSection;
    FEnableKeepAlive: Boolean;
    FKeepAliveTimeoutMs: Cardinal;
    FMaxKeepAliveRequests: Integer;
    FEnableHttp3: Boolean;
    FHttp3Server: THttp3Server;
    FServerCertStore: HCERTSTORE;
    FWebSocketManager: TWebSocketManager;
    function InitializeWinsock: Boolean;
    function CreateListenSocket: Boolean;
    function CreateHttpListenSocket: Boolean;
    function CreateCompletionPort: Boolean;
    function LoadServerCertificate: Boolean;
    function InitializeSSLCredentials: Boolean;
    function CreateWorkerThreads: Boolean;
    procedure CleanupWinsock;
    procedure ListCertificatesInStore(const StoreName: string);
    procedure AcceptConnection2(Socket: TSocket);
    procedure HandleHttpsHandshake(ClientSocket: TSocket);
    procedure HandleHttpPlainConnection(ClientSocket: TSocket);
    function InitializeRequestProcessing(OverlappedEx: POverlappedEx): Boolean;
    procedure ContinueReadingRequest(OverlappedEx: POverlappedEx);
    function ProcessSSLHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
    function DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                             var PlainData: TBytes; out BytesConsumed: Integer): Boolean;
    function EncryptBytesToSend(var Context: TCtxtHandle; const PlainData: TBytes; var EncryptedData: TBytes): Boolean;
    class function WorkerThreadProc(Parameter: Pointer): DWORD; stdcall; static;
    class function MonitorThreadProc(Parameter: Pointer): DWORD; stdcall; static;
    procedure CleanupOverlappedEx(OverlappedEx: POverlappedEx);
    function IsRequestComplete(Request: TRequest): Boolean;
    procedure FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
    procedure ProcessHttpRequest(OverlappedEx: POverlappedEx);
    procedure ProcessHttp3Request(Req: THttp3Request; Resp: THttp3Response);
    procedure ContinueSendingResponse(OverlappedEx: POverlappedEx);
    procedure TransitionToWebSocket(OverlappedEx: POverlappedEx);
  public
    procedure TriggerWebSocketWrite(Session: TWebSocketSession);
    procedure CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
    constructor Create(APort: Word = 443;
                       ASubjectName:String = 'localhost';
                       ACertificateStore:String= 'GHttpsIOCPSvr';
                       ASecretKey:String = 'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!';
                       AMaxConnections: Integer = 2000;
                       AMaxRequestsPerSecond: Integer =  DEFAULT_MAXREQUESTSPERSECOND;
                       AMaxRequestHederSize: Int64 = DEFAULT_MAX_REQUEST_HEDER_SIZE;
                       AMaxRequestSize: Int64 = DEFAULT_MAX_REQUEST_SIZE;
                       AMaxResponseSize: Int64 = DEFAULT_MAX_RESPONSE_SIZE;
                       AChunkSize: Integer = DEFAULT_CHUNK_SIZE;
                       AMinFreeMemoryMb: Cardinal = 50;
                       AMaxMemoryLoadPercent: Byte = 95;
                       AMonitorRun:Boolean = True;
                       AEnableKeepAlive: Boolean = True;
                       AHttpPort: Word = 0;
                       AHttpAction: THttpActionOnDualMode = haServeNormally);
    destructor Destroy; override;
    procedure PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
    procedure SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal = 500);
    procedure EnableGracefulSSLShutdown(Enable: Boolean);
    procedure SetSSLShutdownTimeout(TimeoutMs: Cardinal);
    function Start: Boolean;
    procedure Stop;
    procedure BroadcastWebSocket(const AText: string);
    procedure BroadcastWebSocketBinary(const Data: TBytes);
    function GetWebSocketActiveCount: Integer;
    procedure RegisterEndpoint(const APath: string; AMethod: THttpMethod;
                               AHandler: TEndpointEvent;
                               AAuthorizationType: TAuthorizationType = atNone);
    procedure RegisterEndpointProc(const APath: string;
                                      AMethod: THttpMethod;
                                      AHandler: TEndpointEventProc;
                                      AAuthorizationType: TAuthorizationType = atNone );
    procedure RegisterWebSocketRoute(const APath: string); overload;
    procedure RegisterWebSocketRoute(const APath: string; AOnMessage: TWebSocketMessageProc); overload;
    property OnWebSocketMessage: TWebSocketMessageProc read FOnWebSocketMessage write FOnWebSocketMessage;
    property OnWebSocketConnect: TWebSocketConnectProc read FOnWebSocketConnect write FOnWebSocketConnect;
    property OnWebSocketDisconnect: TWebSocketDisconnectProc read FOnWebSocketDisconnect write FOnWebSocketDisconnect;
    property Running: Boolean read FRunning;
    property MaxRequestSize: Int64 read FMaxRequestSize write FMaxRequestSize;
    property MaxResponseSize: Int64 read FMaxResponseSize write FMaxResponseSize;
    property ChunkSize: Integer read FChunkSize write FChunkSize;
    property OverlappedPool: TOverlappedExPool read FOverlappedPool;
    property JWTManager: TJWTManager read FJWTManager;
    property EnableHttp3: Boolean read FEnableHttp3 write FEnableHttp3;
    property Http3Server: THttp3Server read FHttp3Server;
    property WebSocketManager: TWebSocketManager read FWebSocketManager;
    property ActiveConnections: Int64 read FActiveConnections;
    property EnableKeepAlive: Boolean read FEnableKeepAlive write FEnableKeepAlive;
    property KeepAliveTimeoutMs: Cardinal read FKeepAliveTimeoutMs write FKeepAliveTimeoutMs;
    property MaxKeepAliveRequests: Integer read FMaxKeepAliveRequests write FMaxKeepAliveRequests;
    property ProtocolMode: TServerProtocolMode read FProtocolMode;
    property HttpAction: THttpActionOnDualMode read FHttpAction write FHttpAction;
    property HttpsPort: Word read FHttpsPort;
    property HttpPort: Word read FHttpPort write FHttpPort;
  end;


implementation

uses TypInfo, System.Hash;

function IsMsQuicDllAvailable(out AErrorDetails: string): Boolean;
var
  ExeDir, DllPath: string;
  H: HMODULE;
  OpenVerFunc: function(Version: Cardinal; out ApiTable: Pointer): Cardinal; stdcall;
  ApiTable: Pointer;
  Status: Cardinal;
  OldErrorMode: UINT;
begin
  Result := False;
  AErrorDetails := '';

  ExeDir := ExtractFilePath(ParamStr(0));
  DllPath := ExeDir + 'msquic.dll';

  if not FileExists(DllPath) then
  begin
    AErrorDetails := Format('msquic.dll not found in server directory: %s', [DllPath]);
    Exit;
  end;

  OldErrorMode := SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
  try
    H := LoadLibrary(PChar(DllPath));
    if H = 0 then
    begin
      AErrorDetails := Format('LoadLibrary("%s") failed (Error %d: %s)', [DllPath, GetLastError, SysErrorMessage(GetLastError)]);
      Exit;
    end;

    try
      @OpenVerFunc := GetProcAddress(H, 'MsQuicOpenVersion');
      if not Assigned(@OpenVerFunc) then
      begin
        AErrorDetails := Format('msquic.dll in "%s" does not export "MsQuicOpenVersion"', [DllPath]);
        Exit;
      end;

      ApiTable := nil;
      Status := OpenVerFunc(2, ApiTable);
      if Status <> 0 then
      begin
        AErrorDetails := Format('MsQuicOpenVersion failed with status code 0x%x (%d)', [Status, Status]);
        Exit;
      end;

      Result := True;
    finally
      FreeLibrary(H);
    end;
  finally
    SetErrorMode(OldErrorMode);
  end;
end;


procedure CleanupConnectionWithReason(Server: TGHttpsServerIOCP; AOverlapped: POverlappedEx; const AReason: string);
begin
  if AOverlapped = nil then
    Exit;

  if AOverlapped^.OpType in [otWebSocketRead, otWebSocketWrite] then
  begin
    var WsSession := TWebSocketSession(AOverlapped^.WebSocketSession);
    if Assigned(WsSession) then
      Server.CleanupWebSocketSession(WsSession, AReason);
    SetLength(AOverlapped^.ClientReceiveBuffer, 0);
    AOverlapped^.WebSocketSession := nil;
    Server.FActiveOverlappedLock.Enter;
    try
      Server.FActiveOverlapped.Remove(AOverlapped);
    finally
      Server.FActiveOverlappedLock.Leave;
    end;
    Server.FOverlappedPool.Release(AOverlapped);
    Exit;
  end;
  try
    if AOverlapped^.Socket <> INVALID_SOCKET then
    begin
      InterlockedDecrement64(Server.FActiveConnections);
      if AOverlapped^.SSLContextValid then
      begin
        if not ContainsText(AReason, 'SSL shutdown completed') then
        begin
          try
            Server.PerformGracefulSSLShutdown(AOverlapped^);
          except
            on E: Exception do
              Logger.Info('Error SSL shutdown w cleanup: ' + E.Message);
          end;
        end
        else
        begin
          AOverlapped^.SSLContextValid := False;
        end;
      end;
      try
        shutdown(AOverlapped^.Socket, SD_SEND);
        Sleep(25);
        shutdown(AOverlapped^.Socket, SD_BOTH);
        Sleep(10);
      except
        on E: Exception do
          Logger.Error('TCP shutdown error: ' + E.Message);
      end;
      closesocket(AOverlapped^.Socket);
      AOverlapped^.Socket := INVALID_SOCKET;
    end;
    Server.CleanupOverlappedEx(AOverlapped);
    Server.FActiveOverlappedLock.Enter;
    try
      Server.FActiveOverlapped.Remove(AOverlapped);
    finally
      Server.FActiveOverlappedLock.Leave;
    end;

    Server.FOverlappedPool.Release(AOverlapped);
    AOverlapped := nil;
  except
    on E: Exception do
      Logger.Error('Error in CleanupConnectionWithReason: ' + E.Message);
  end;
end;

function GetEndpointKey(const AMethod: THttpMethod; const APath: string): string;
var
  MethodStr: string;
begin
  case AMethod of
    hmGET: MethodStr := 'GET';
    hmPOST: MethodStr := 'POST';
    hmPUT: MethodStr := 'PUT';
    hmDELETE: MethodStr := 'DELETE';
    hmHEAD: MethodStr := 'HEAD';
    hmOPTIONS: MethodStr := 'OPTIONS';
    hmPATCH: MethodStr := 'PATCH';
    hmTRACE: MethodStr := 'TRACE';
    hmCONNECT: MethodStr := 'CONNECT';
  else
    MethodStr := 'UNKNOWN';
  end;
  Result := MethodStr + ':' + APath;
end;

{ TEndpointItem }
constructor TEndpointItem.Create(const APath: string;
                                 AMethod: THttpMethod;
                                 AHandler: TEndpointEvent;
                                 AHandlerProc: TEndpointEventProc;
                                 AAuthorizationType: TAuthorizationType;
                                 AServer:TGHttpsServerIOCP) ;
begin
  inherited Create;
  FPath := APath;
  FMethod := AMethod;
  FHandler := AHandler;
  FHandlerProc := AHandlerProc;
  FServer := AServer;
  FAuthorizationType := AAuthorizationType;
end;



{ TGHttpsServerIOCP }
constructor TGHttpsServerIOCP.Create(APort: Word;
                                   ASubjectName:String;
                                   ACertificateStore:String;
                                   ASecretKey:String;
                                   AMaxConnections: Integer;
                                   AMaxRequestsPerSecond: Integer;
                                   AMaxRequestHederSize: Int64;
                                   AMaxRequestSize: Int64;
                                   AMaxResponseSize: Int64;
                                   AChunkSize: Integer;
                                   AMinFreeMemoryMb: Cardinal;
                                   AMaxMemoryLoadPercent: Byte;
                                   AMonitorRun:Boolean;
                                   AEnableKeepAlive: Boolean;
                                   AHttpPort: Word;
                                   AHttpAction: THttpActionOnDualMode);
begin
  inherited Create;

  FActiveOverlapped := TList<POverlappedEx>.Create;
  FActiveOverlappedLock := TCriticalSection.Create;

  FJWTManager := TJWTManager.Create(
    ASecretKey,
    'JWTManager',
    120,
    'GHttpsServerIOP'
  );
  OverlappedExG := nil;
  FEnableGracefulSSLShutdown := True;
  FSSLShutdownTimeout := 200;
  FPort := APort;
  FHttpsPort := APort;
  FHttpPort := AHttpPort;
  FHttpAction := AHttpAction;

  if (FHttpsPort > 0) and (FHttpPort > 0) then
    FProtocolMode := pmDualHttpAndHttps
  else if (FHttpsPort = 0) and (FHttpPort > 0) then
  begin
    FProtocolMode := pmHttpOnly;
    FPort := FHttpPort;
  end
  else
    FProtocolMode := pmHttpsOnly;

  FRunning := False;
  FListenSocket := INVALID_SOCKET;
  FListenSocketHTTP := INVALID_SOCKET;
  FCompletionPort := 0;
  FWorkerThreads := TList<THandle>.Create;
  FCertContext := nil;
  FH3CertContext := nil;
  FCredentialsValid := False;
  FActiveConnections := 0;
  FMaxConnections := AMaxConnections;
  FMaxRequestsPerSecond := AMaxRequestsPerSecond;
  FEndpoints := TDictionary<string, TEndpointItem>.Create;
  FLock := TCriticalSection.Create;
  FMaxRequestHederSize := AMaxRequestHederSize;
  FMaxRequestSize := AMaxRequestSize;
  FMaxResponseSize := AMaxResponseSize;
  FChunkSize := AChunkSize;
  FMonitorRun := AMonitorRun;
  FSubjectName := ASubjectName;
  FCertificateStore := ACertificateStore;
  FEnableHttp3 := (FProtocolMode <> pmHttpOnly);
  FHttp3Server := nil;
  FEnableKeepAlive := AEnableKeepAlive;
  FKeepAliveTimeoutMs := 5000;
  FMaxKeepAliveRequests := 1000;
  FWebSocketManager := TWebSocketManager.Create;
  FWebSocketRoutes := TDictionary<string, Boolean>.Create;
  FWebSocketRouteHandlers := TDictionary<string, TWebSocketMessageProc>.Create;
  ZeroMemory(@FServerCredHandle, SizeOf(FServerCredHandle));
  Logger.Info(Format('Creating OverlappedEx pool. Max connections: %d', [AMaxConnections]));
  FOverlappedPool := TOverlappedExPool.Create(AMaxConnections div 4, AMaxConnections, AMinFreeMemoryMb, AMaxMemoryLoadPercent);
  case FProtocolMode of
    pmHttpOnly:
      Logger.Info(Format('HTTP Server created (HTTP-Only on port %d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FHttpPort, FMaxRequestSize div 1048576, FMaxResponseSize div 1048576, FChunkSize div 1024]));
    pmDualHttpAndHttps:
      Logger.Info(Format('Dual-Stack Server created (HTTP:%d + HTTPS:%d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FHttpPort, FHttpsPort, FMaxRequestSize div 1048576, FMaxResponseSize div 1048576, FChunkSize div 1024]));
    pmHttpsOnly:
      Logger.Info(Format('HTTPS Server created (HTTPS-Only on port %d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FHttpsPort, FMaxRequestSize div 1048576, FMaxResponseSize div 1048576, FChunkSize div 1024]));
  end;
end;

destructor TGHttpsServerIOCP.Destroy;
var
  StartTime: TDateTime;
  ElapsedMs: Integer;
  Endpoint: TEndpointItem;
begin
  StartTime := Now;
  Logger.Info('Start cleanup TGHttpsServerIOCP...');

  Stop;

  if Assigned(FWebSocketManager) then
    FreeAndNil(FWebSocketManager);

  if Assigned(FLock) then
  begin
    FLock.Enter;
    try
      if Assigned(FEndpoints) then
      begin
        for Endpoint in FEndpoints.Values do
          if Assigned(Endpoint) then
             Endpoint.Free;
        FreeAndNil(FEndpoints);
      end;
    finally
      FLock.Leave;
    end;
    FreeAndNil(FLock);
  end
  else if Assigned(FEndpoints) then
  begin
    for Endpoint in FEndpoints.Values do
      if Assigned(Endpoint) then
         Endpoint.Free;
    FreeAndNil(FEndpoints);
  end;

  if Assigned(FWebSocketRoutes) then
    FreeAndNil(FWebSocketRoutes);

  if Assigned(FWebSocketRouteHandlers) then
    FreeAndNil(FWebSocketRouteHandlers);

  if Assigned(FOverlappedPool) then
  begin
    FOverlappedPool.Free;
    FOverlappedPool := nil;
  end;

  if Assigned(FWorkerThreads) then
  begin
    FWorkerThreads.Free;
    FWorkerThreads := nil;
  end;

  if Assigned(FHttp3Server) then
  begin
    try
      FreeAndNil(FHttp3Server);
    except
      on E: Exception do
        Logger.Error('[DESTROY-ERR-H3] Error freeing FHttp3Server in Destroy: ' + E.Message);
    end;
  end;

  if Assigned(FJWTManager) then
     FreeAndNil(FJWTManager);
  if Assigned(FActiveOverlapped) then
     FreeAndNil(FActiveOverlapped);
  if Assigned(FActiveOverlappedLock) then
     FreeAndNil(FActiveOverlappedLock);

  ElapsedMs := MilliSecondsBetween(Now, StartTime);
  Logger.Info('Cleanup TGHttpsServerIOCP end in %dms', [ElapsedMs]);

  inherited;
end;

procedure TGHttpsServerIOCP.FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
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

procedure TGHttpsServerIOCP.SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal = 500);
begin
  FEnableGracefulSSLShutdown := EnableGraceful;
  FSSLShutdownTimeout := TimeoutMs;
end;

procedure TGHttpsServerIOCP.PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
var
  OutputBuffers: array[0..1] of TSecBuffer;
  OutputBufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  dwType: DWORD;
  StartTime: Cardinal;
  BytesSent: Integer;
  i: Integer;
  OriginalBuffers: array[0..1] of Pointer;
  AllocatedBuffers: array[0..1] of Pointer;
  AllocatedSizes: array[0..1] of Cardinal;
  BuffersToFree: Integer;
begin
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
  StartTime := GetTickCount;
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
    begin
      OriginalBuffers[i] := OutputBuffers[i].pvBuffer;
    end;

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
      BytesSent := send(OverlappedEx.Socket, OutputBuffers[0].pvBuffer^, OutputBuffers[0].cbBuffer, 0)
    else
    begin
      Logger.Error('Could not generate close_notify: Status=0x%x, Size=%d',
        [Status, OutputBuffers[0].cbBuffer]);
    end;
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
          var FreeResult := FreeContextBuffer(AllocatedBuffers[i]);
        except
          on E: Exception do
            Logger.Error(Format('Exception freeing SSL shutdown buffer[%d]: %s', [i, E.Message]));
        end;
      end;
    end;
  end
  else
  begin
    Logger.Info('No buffers allocated during SSL shutdown - no cleanup needed');
  end;
  try
    DeleteSecurityContext(@OverlappedEx.SSLContext);
    OverlappedEx.SSLContextValid := False;
  except
    on E: Exception do
      Logger.Error('Error cleanup SSL context: ' + E.Message);
  end;
end;

procedure TGHttpsServerIOCP.CleanupOverlappedEx(OverlappedEx: POverlappedEx);
begin
  if not Assigned(OverlappedEx) then
    Exit;
  try
    var Req := TRequest(InterlockedExchangePointer(Pointer(OverlappedEx^.Request), nil));
    if Assigned(Req) then
      Req.Free;

    var Resp := TResponse(InterlockedExchangePointer(Pointer(OverlappedEx^.Response), nil));
    if Assigned(Resp) then
      Resp.Free;

    OverlappedEx^.SSLOutputSize := 0;
    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
  except
    on E: Exception do
      Logger.Error('Error in CleanupOverlappedEx [%s]: %s', [E.ClassName, E.Message]);
  end;
end;

function TGHttpsServerIOCP.IsRequestComplete(Request: TRequest): Boolean;
begin
  Result := Assigned(Request) and Request.IsComplete and not Request.HasError;
end;

function TGHttpsServerIOCP.InitializeRequestProcessing(OverlappedEx: POverlappedEx): Boolean;
var
  RemoteAddr: TSockAddrIn;
begin
  Result := False;
  try
    if FRejectNewConnections = 1 then
    begin
      CleanupConnectionWithReason(Self, OverlappedEx, 'Server overloaded: lack of resources');
      Exit;
    end;
    OverlappedEx^.Request := nil;
    ZeroMemory(@RemoteAddr, SizeOf(RemoteAddr));
    OverlappedEx^.Request := TRequest.Create(
      OverlappedEx^.Socket,
      RemoteAddr,
      FMaxRequestHederSize,
      FMaxRequestSize,
      vlModerate,
      False
    );
    Result := True;
  except
    on E: Exception do
    begin
      Logger.Error('Error initializing request processing: ' + E.Message);
      CleanupConnectionWithReason(Self, OverlappedEx, 'Error initializing request processing: ' + E.Message);
    end;
  end;
end;

function TGHttpsServerIOCP.InitializeWinsock: Boolean;
var
  WSAData: TWSAData;
begin
  Result := WSAStartup(MAKEWORD(2, 2), WSAData) = 0;
end;

function TGHttpsServerIOCP.CreateListenSocket: Boolean;
const
  SO_EXCLUSIVEADDRUSE = Integer(not SO_REUSEADDR);
var
  SockAddr: TSockAddr;
  SockAddrIn: TSockAddrIn absolute SockAddr;
  OptVal: Integer;
  ErrCode: Integer;
begin
  Result := False;
  FListenSocket := WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, WSA_FLAG_OVERLAPPED);
  if FListenSocket = INVALID_SOCKET then
  begin
    ErrCode := WSAGetLastError;
    Logger.Error('[SOCKET-ERROR] Cannot create TCP socket for port %d: Error %d', [FPort, ErrCode]);
    Exit;
  end;

  OptVal := 1;
  if setsockopt(FListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, @OptVal, SizeOf(OptVal)) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    Logger.Warn('[SOCKET-WARN] setsockopt SO_EXCLUSIVEADDRUSE failed on port %d: Error %d', [FPort, ErrCode]);
  end;

  FillChar(SockAddr, SizeOf(SockAddr), 0);
  SockAddrIn.sin_family := AF_INET;
  SockAddrIn.sin_addr.S_addr := INADDR_ANY;
  SockAddrIn.sin_port := htons(FPort);

  if bind(FListenSocket, SockAddr, SizeOf(SockAddr)) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    if (ErrCode = WSAEADDRINUSE) or (ErrCode = 10048) then
      Logger.Error(Format('CRITICAL ERROR: Failed to start server on port %d! Port is already in use by another application.', [FPort]))
    else
      Logger.Error(Format('CRITICAL ERROR: Failed to bind TCP socket on port %d! Error: %d', [FPort, ErrCode]));
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
    Exit;
  end;

  if listen(FListenSocket, SOMAXCONN) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    Logger.Error('[SOCKET-ERROR] Listen failed on TCP port %d: Error %d', [FPort, ErrCode]);
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
    Exit;
  end;
  Result := True;
end;

function TGHttpsServerIOCP.CreateHttpListenSocket: Boolean;
const
  SO_EXCLUSIVEADDRUSE = Integer(not SO_REUSEADDR);
var
  SockAddr: TSockAddr;
  SockAddrIn: TSockAddrIn absolute SockAddr;
  OptVal: Integer;
  ErrCode: Integer;
begin
  Result := False;
  if FHttpPort = 0 then
    Exit(True);

  FListenSocketHTTP := WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, WSA_FLAG_OVERLAPPED);
  if FListenSocketHTTP = INVALID_SOCKET then
  begin
    ErrCode := WSAGetLastError;
    Logger.Error('[SOCKET-ERROR] Cannot create HTTP TCP socket for port %d: Error %d', [FHttpPort, ErrCode]);
    Exit;
  end;

  OptVal := 1;
  if setsockopt(FListenSocketHTTP, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, @OptVal, SizeOf(OptVal)) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    Logger.Warn('[SOCKET-WARN] setsockopt SO_EXCLUSIVEADDRUSE failed on HTTP port %d: Error %d', [FHttpPort, ErrCode]);
  end;

  FillChar(SockAddr, SizeOf(SockAddr), 0);
  SockAddrIn.sin_family := AF_INET;
  SockAddrIn.sin_addr.S_addr := INADDR_ANY;
  SockAddrIn.sin_port := htons(FHttpPort);

  if bind(FListenSocketHTTP, SockAddr, SizeOf(SockAddr)) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    if (ErrCode = WSAEADDRINUSE) or (ErrCode = 10048) then
      Logger.Error(Format('CRITICAL ERROR: Failed to start HTTP server on port %d! Port is already in use by another application.', [FHttpPort]))
    else
      Logger.Error(Format('CRITICAL ERROR: Failed to bind HTTP TCP socket on port %d! Error: %d', [FHttpPort, ErrCode]));
    closesocket(FListenSocketHTTP);
    FListenSocketHTTP := INVALID_SOCKET;
    Exit;
  end;

  if listen(FListenSocketHTTP, SOMAXCONN) = SOCKET_ERROR then
  begin
    ErrCode := WSAGetLastError;
    Logger.Error('[SOCKET-ERROR] Listen failed on HTTP TCP port %d: Error %d', [FHttpPort, ErrCode]);
    closesocket(FListenSocketHTTP);
    FListenSocketHTTP := INVALID_SOCKET;
    Exit;
  end;
  Result := True;
end;

procedure TGHttpsServerIOCP.ContinueReadingRequest(OverlappedEx: POverlappedEx);
var
  WSABuf: TWSABUF;
  BytesReceived, Flags: DWORD;
begin
  try
    if not Assigned(OverlappedEx^.Request) then
    begin
      Logger.Error('Request object not initialized');
      CleanupConnectionWithReason(Self, OverlappedEx, 'Request object not initialized in ContinueReadingRequest');
      Exit;
    end;
    if IsRequestComplete(OverlappedEx^.Request) then
    begin
      Logger.Info('Request is complete, processing...');
      ProcessHttpRequest(OverlappedEx);
      Exit;
    end;
    if not OverlappedEx^.Request.CanAcceptMoreData then
    begin
      if OverlappedEx^.Request.HasError then
        Logger.Error('Request has error: ' + OverlappedEx^.Request.ErrorMessage);
      ProcessHttpRequest(OverlappedEx);
      Exit;
    end;
    WSABuf.len := SizeOf(OverlappedEx^.Buffer);
    WSABuf.buf := @OverlappedEx^.Buffer[0];
    Flags := 0;
    ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
    if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesReceived, Flags,
               @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
    begin
      if WSAGetLastError <> WSA_IO_PENDING then
      begin
        Logger.Error('Error continuing request read: ' + IntToStr(WSAGetLastError));
        CleanupConnectionWithReason(Self, OverlappedEx, 'Error continuing request read');
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Exception in ContinueReadingRequest: ' + E.Message);
      CleanupConnectionWithReason(Self, OverlappedEx, 'Exception in ContinueReadingRequest: ' + E.Message);
    end;
  end;
end;

function TGHttpsServerIOCP.CreateCompletionPort: Boolean;
begin
  FCompletionPort := CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
  if FCompletionPort <> 0 then
  begin
    Result := True;
    if FListenSocket <> INVALID_SOCKET then
      Result := Result and (CreateIoCompletionPort(FListenSocket, FCompletionPort,
                                                   ULONG_PTR(FListenSocket), 0) <> 0);
    if FListenSocketHTTP <> INVALID_SOCKET then
      Result := Result and (CreateIoCompletionPort(FListenSocketHTTP, FCompletionPort,
                                                   ULONG_PTR(FListenSocketHTTP), 0) <> 0);
  end
  else
    Result := False;
end;

function TGHttpsServerIOCP.LoadServerCertificate: Boolean;
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

  function TrySearchInStore(SystemStoreFlags: DWORD; const SystemStoreName, StoreName: string): Boolean;
  const CERT_STORE_READONLY_FLAG = $00008000;
  var StoreHandle: HCERTSTORE;
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
    if StoreHandle = nil then Exit;

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

        if FCertContext = nil then Break;

        Logger.Info('Certificate context candidate allocated at: %p', [FCertContext]);
        try
          var SubjectBuffer: array[0..255] of WideChar;
          var SubjectLen := CertGetNameString(
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

        const CRYPT_ACQUIRE_SILENT_FLAG = $00000040;
        const CERT_KEY_PROV_INFO_PROP_ID = 2;
        var cbData: DWORD := 0;
        var HasKeyProp := CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, cbData);
        var AcquiredKey := CryptAcquireCertificatePrivateKey(FCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG, nil, CryptProv, KeySpec, MustFree);
        var KeyErr := GetLastError;

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

    end;
  end;

begin
  Result := False;
  if FCertificateStore = '' then
    FCertificateStore := 'GHttpsIOCPSvr';

  FSubjectName := 'localhost';
  Logger.Info('LoadServerCertificate START');

  Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', FCertificateStore);
  if not Result then
    Result := TrySearchInStore(CERT_SYSTEM_STORE_CURRENT_USER, 'CurrentUser', FCertificateStore);
  if not Result then
    Result := TrySearchInStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, 'LocalMachine', 'My');

  if not Result then
  begin
    Logger.Error('No valid certificate with accessible private key "CN=%s" found in stores (LocalMachine\GHttpsIOCPSvr, CurrentUser\GHttpsIOCPSvr, LocalMachine\My)', [FSubjectName]);
    Logger.Info('To create/re-create the required CNG certificate, run in PowerShell (as Admin): .\gen_quic_cert.ps1');
  end;

  Logger.Info(Format('LoadServerCertificate END - Result: %s, FCertContext: %p', [BoolToStr(Result, True), FCertContext]));
end;



function TGHttpsServerIOCP.InitializeSSLCredentials: Boolean;
const
  SCH_CRED_NO_SYSTEM_MAPPER = $00000002;
  SCH_CRED_CACHE_SESSION    = $00000020;
var
  SchannelCred: SCHANNEL_CRED;
  Status: SECURITY_STATUS;
  Expiry: TTimeStamp;
  CertArray: PCCERT_CONTEXT;
  CipherSuitePriorityList: WideString;
begin
  Result := False;
  Logger.Info('InitializeSSLCredentials START - Production setup for Windows 11/CNG...');
  ZeroMemory(@SchannelCred, SizeOf(SchannelCred));
  SchannelCred.dwVersion := SCHANNEL_CRED_VERSION;
  if FCertContext = nil then
  begin
    Logger.Error('Błąd krytyczny: Brak certyfikatu.');
    Exit;
  end;
  CertArray := FCertContext;
  SchannelCred.cCreds := 1;
  SchannelCred.paCred := @CertArray;
  SchannelCred.dwFlags := SCH_CRED_USE_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or
                          SCH_CRED_CIPHER_SUITE_PRIORITY or SCH_CRED_NO_SYSTEM_MAPPER or SCH_CRED_CACHE_SESSION;
  Logger.Info('Flags set for CNG certificate (with NO_SYSTEM_MAPPER & CACHE_SESSION).');
  SchannelCred.grbitEnabledProtocols := SP_PROT_TLS1_3_SERVER or SP_PROT_TLS1_2_SERVER;
  Logger.Info('Protocol Policy: TLS ONLY Enabled 1.3 i TLS 1.2.');
  CipherSuitePriorityList :=
    'TLS_AES_128_GCM_SHA256;' +
    'TLS_AES_256_GCM_SHA384;' +
    'TLS_CHACHA20_POLY1305_SHA256;' +
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;' +
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;' +
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;';

  SchannelCred.pCipherSuitePriority := PWideChar(CipherSuitePriorityList);
  Logger.Info('A priority, secure cipher list has been set.');
  SchannelCred.dwMinimumCipherStrength := 0;
  SchannelCred.dwMaximumCipherStrength := 0;
  Logger.Info('Calling AcquireCredentialsHandle...');
  Status := AcquireCredentialsHandle(
    nil, 'Microsoft Unified Security Protocol Provider', SECPKG_CRED_INBOUND,
    nil, @SchannelCred, nil, nil, @FServerCredHandle, @Expiry
  );

  if Status = SEC_E_OK then
  begin
    Logger.Info('Server running');
    FCredentialsValid := True;
    Result := True;
  end
  else
  begin
    Logger.Error(Format('FATAL ERROR. Error code: 0x%x.', [Status]));
    Result := False;
  end;
end;

procedure TGHttpsServerIOCP.ListCertificatesInStore(const StoreName: string);
var
  CertStore: HCERTSTORE;
  CertContext: PCCERT_CONTEXT;
  SubjectName: array[0..255] of WideChar;
  NameSize: DWORD;
  Count: Integer;
  KeySpec: DWORD;
  MustFree: BOOL;
  CryptProv: HCRYPTPROV;
begin
  Logger.Info('=== CERTIFICATES IN THE STORE "' + StoreName + '" ===');

  CertStore := CertOpenSystemStore(0, PWideChar(StoreName));
  if CertStore = nil then
  begin
    Logger.Info('Cannot open the store "' + StoreName + '"');
    Exit;
  end;

  try
    Count := 0;
    CertContext := nil;
    repeat
      CertContext := CertFindCertificateInStore(
        CertStore,
        X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        nil,
        CertContext
      );

      if CertContext <> nil then
      begin
        Inc(Count);
        NameSize := CertGetNameString(
          CertContext,
          CERT_NAME_SIMPLE_DISPLAY_TYPE,
          0,
          nil,
          @SubjectName[0],
          SizeOf(SubjectName) div SizeOf(WideChar)
        );

        if NameSize > 1 then
          Logger.Info(Format('  %d. Subject: %s', [Count, SubjectName]))
        else
          Logger.Info(Format('  %d. Subject: <unreadable>', [Count]));
        if CryptAcquireCertificatePrivateKey(CertContext, 0, nil, CryptProv, KeySpec, MustFree) then
        begin
          Logger.Info('     ? Private key: AVAILABLE');
          if MustFree then
            CryptReleaseContext(CryptProv, 0);
        end
        else
          Logger.Info('     ? Private key: UNAVAILABLE');
      end;

    until CertContext = nil;

    if Count = 0 then
      Logger.Info('Store is empty')
    else
      Logger.Info(Format('Found %d certificate(s)', [Count]));

  finally
    CertCloseStore(CertStore, 0);
  end;

  Logger.Info('================================================');
end;

function TGHttpsServerIOCP.CreateWorkerThreads: Boolean;
var
  i: Integer;
  ThreadHandle: THandle;
  ThreadId: DWORD;
begin
  Result := True;

  for i := 0 to WORKER_THREAD_COUNT - 1 do
  begin
    ThreadHandle := CreateThread(nil, 0, @TGHttpsServerIOCP.WorkerThreadProc, Self, 0, ThreadId);
    if ThreadHandle <> 0 then
      FWorkerThreads.Add(ThreadHandle)
    else
    begin
      Result := False;
      Break;
    end;
  end;
end;

procedure TGHttpsServerIOCP.CleanupWinsock;
begin
  Logger.Info('CleanupWinsock START...');
  if FListenSocket <> INVALID_SOCKET then
  begin
    Logger.Info('Closing listen socket...');
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
    Logger.Info('Listen socket closed');
  end;

  if FCompletionPort <> 0 then
  begin
    Logger.Info('Closing completion port...');
    CloseHandle(FCompletionPort);
    FCompletionPort := 0;
    Logger.Info('Completion port closed');
  end;

  if FServerCertStore <> nil then
  begin
    Logger.Info('Closing server certificate store handle...');
    CertCloseStore(FServerCertStore, 0);
    FServerCertStore := nil;
  end;

  Logger.Info('Calling WSACleanup...');
  WSACleanup;
  Logger.Info('CleanupWinsock completed');
end;

procedure TGHttpsServerIOCP.EnableGracefulSSLShutdown(Enable: Boolean);
begin
  FEnableGracefulSSLShutdown := Enable;
  Logger.Info(Format('Graceful SSL shutdown %s', [IfThen(Enable, 'ENABLED', 'DISABLED')]));
end;

procedure TGHttpsServerIOCP.SetSSLShutdownTimeout(TimeoutMs: Cardinal);
begin
  FSSLShutdownTimeout := TimeoutMs;
  Logger.Info(Format('SSL shutdown timeout set in %dms', [TimeoutMs]));
end;

function TGHttpsServerIOCP.Start: Boolean;
begin

  Logger.Info('SSL Shutdown Configuration:');
  Logger.Info(Format('  Graceful shutdown: %s', [BoolToStr(FEnableGracefulSSLShutdown, True)]));
  Logger.Info(Format('  Timeout: %dms', [FSSLShutdownTimeout]));
  Result := False;
  if FRunning then
    Exit;

  var MsQuicErr: string;
  if FEnableHttp3 and (FProtocolMode <> pmHttpOnly) and not IsMsQuicDllAvailable(MsQuicErr) then
  begin
    Writeln;
    Writeln('================================================================');
    Writeln('  CRITICAL ERROR: Failed to load msquic.dll library!');
    Writeln('  Reason: ' + MsQuicErr);
    Writeln('  The server cannot start without a working msquic.dll.');
    Writeln(Format('  Place a valid 64-bit msquic.dll in: %smsquic.dll', [ExtractFilePath(ParamStr(0))]));
    Writeln('================================================================');
    Writeln;
    Logger.Error('CRITICAL ERROR: Failed to load msquic.dll: %s', [MsQuicErr]);
    Exit;
  end;

  if not InitializeWinsock then
  begin
    Logger.Info('Winsock initialization error');
    Exit;
  end;

  if FProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps] then
  begin
    if not CreateListenSocket then
    begin
      Logger.Error('[START-FAILED] Could not bind HTTPS TCP socket on port %d. Server startup aborted.', [FHttpsPort]);
      CleanupWinsock;
      Exit;
    end;
  end;

  if FProtocolMode in [pmHttpOnly, pmDualHttpAndHttps] then
  begin
    if not CreateHttpListenSocket then
    begin
      Logger.Error('[START-FAILED] Could not bind HTTP TCP socket on port %d. Server startup aborted.', [FHttpPort]);
      CleanupWinsock;
      Exit;
    end;
  end;

  if not CreateCompletionPort then
  begin
    Logger.Info('Failed to create Completion Port');
    CleanupWinsock;
    Exit;
  end;

  if FProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps] then
  begin
    if not LoadServerCertificate then
    begin
      Logger.Error('');
      Logger.Error('================================================================');
      Logger.Error('  CRITICAL ERROR: TLS certificate not found in Windows store!');
      Logger.Error('  The server cannot start without a valid TLS certificate.');
      Logger.Error('  Run from the project root directory:');
      Logger.Error('  powershell -ExecutionPolicy Bypass -File gen_quic_cert.ps1');
      Logger.Error('================================================================');
      Logger.Error('');
      CleanupWinsock;
      Exit;
    end;

    if not InitializeSSLCredentials then
    begin
      Logger.Error('Failed to initialize SSL credentials');
      CleanupWinsock;
      Exit;
    end;
  end;

  if not CreateWorkerThreads then
  begin
    Logger.Info('Failed to create worker threads');
    CleanupWinsock;
    Exit;
  end;

  FRejectNewConnections := 0;
  if FMonitorRun then
  begin
    var ThreadId: DWORD;
    FMonitorThread := CreateThread(nil, 0, @TGHttpsServerIOCP.MonitorThreadProc, Self, 0, ThreadId);
    if FMonitorThread = 0 then
    begin
      Logger.Error('Critical error: Failed to create monitoring thread.');
      Stop;
      Exit;
    end;
  end;
  FRunning := True;

  if FListenSocket <> INVALID_SOCKET then
  begin
    AcceptConnection2(FListenSocket);
    Logger.Info('HTTPS server listening on port ' + IntToStr(FHttpsPort));
  end;

  if FListenSocketHTTP <> INVALID_SOCKET then
  begin
    AcceptConnection2(FListenSocketHTTP);
    Logger.Info('HTTP server listening on port ' + IntToStr(FHttpPort));
  end;

  if FEnableHttp3 and (FProtocolMode <> pmHttpOnly) then
  begin
    try
      begin
        Logger.Info(Format('[H3] Starting HTTP/3 creation with FCertContext=%p, FH3CertContext=%p, FServerCertStore=%p, FCertificateStore=%s',
          [FCertContext, FH3CertContext, FServerCertStore, FCertificateStore]));
        var H3HashHex := '';
        if FCertContext <> nil then
        begin
          const CERT_SHA1_HASH_PROP_ID = 3;
          var HashBytes: array[0..19] of Byte;
          var HashSize: DWORD := 20;
          if CertGetCertificateContextProperty(FCertContext, CERT_SHA1_HASH_PROP_ID,
                                               @HashBytes[0], HashSize) then
          begin
            for var B in HashBytes do
              H3HashHex := H3HashHex + IntToHex(B, 2);
            Logger.Info('[H3] SHA-1 thumbprint extracted from FCertContext: ' + H3HashHex);
          end;
        end;

        Logger.Info(Format('[H3] Creating HTTP/3 server with SHA-1 hash %s from store LocalMachine\%s (StoreHandle=%p)', [H3HashHex, FCertificateStore, FServerCertStore]));
        FHttp3Server := THttp3Server.Create(H3HashHex, FCertificateStore, FServerCertStore);

        FHttp3Server.OnRequest := ProcessHttp3Request;
        FHttp3Server.Start(FHttpsPort);
        Logger.Info(Format('HTTP/3 (UDP) server listening on port %d', [FHttpsPort]));
      end;
    except
      on E: Exception do
      begin
        if (Pos('0x80072740', E.Message) > 0) or (Pos('Address in use', E.Message) > 0) then
          Logger.Error(Format('CRITICAL ERROR: Failed to start HTTP/3 (UDP) server on port %d! UDP Port is already in use by another application.', [FHttpsPort]))
        else
          Logger.Error(Format('CRITICAL ERROR: Failed to start HTTP/3 (UDP) server on port %d! Error: %s', [FHttpsPort, E.Message]));

        if Assigned(FHttp3Server) then
        begin
          try
            FHttp3Server.Free;
          except
          end;
          FHttp3Server := nil;
        end;
      end;
    end;
  end;

  Result := True;
end;

procedure TGHttpsServerIOCP.Stop;
var
  i: Integer;
  ThreadHandle: THandle;
  Handles: TArray<THandle>;
  ActiveListCopy: TArray<POverlappedEx>;
  Overlapped: POverlappedEx;
begin
  if not FRunning then
    Exit;
  Logger.Info('[STOP-1] Stopping the server...');
  FRunning := False;

  if Assigned(FWebSocketManager) then
  begin
    try
      Logger.Info('[STOP-1B] Sending WebSocket close frames (1001 Going Away)...');
      var SessionList := FWebSocketManager.AcquireSessionList;
      try
        for var WS_Session in SessionList do
        begin
          if Assigned(WS_Session) and (WS_Session.InCleanup = 0) then
          begin
            try
              WS_Session.QueueSendFrame(wsOpClose, [$03, $E9]); // Going Away  ???
              TriggerWebSocketWrite(WS_Session);
            except
              on E: Exception do
                Logger.Error('[STOP-WS-SENDCLOSE-ERR] Exception sending Close frame: %s', [E.Message]);
            end;
          end;
        end;

        Sleep(100);
      finally
        for var WS_Session in SessionList do
          WS_Session.Release;
        SessionList.Free;
      end;
    except
      on E: Exception do
        Logger.Error('[STOP-WS-ERR] Error in WebSocket stop loop: %s (%s)', [E.Message, E.ClassName]);
    end;
  end;

  if FHttp3Server <> nil then
  begin
    try
      Logger.Info('[STOP-2] Stopping HTTP/3 server...');
      FreeAndNil(FHttp3Server);
      Logger.Info('[STOP-3] HTTP/3 server stopped cleanly.');
    except
      on E: Exception do
        Logger.Error('[STOP-ERR-H3] Error stopping HTTP/3 server: ' + E.Message);
    end;
  end;

  if FListenSocket <> INVALID_SOCKET then
  begin
    Logger.Info('[STOP-4] Closing the HTTPS listening socket...');
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
  end;

  if FListenSocketHTTP <> INVALID_SOCKET then
  begin
    Logger.Info('[STOP-4B] Closing the HTTP listening socket...');
    closesocket(FListenSocketHTTP);
    FListenSocketHTTP := INVALID_SOCKET;
  end;

  Logger.Info('[STOP-5] Closing active client sockets...');
  FActiveOverlappedLock.Enter;
  try
    ActiveListCopy := FActiveOverlapped.ToArray;
    Logger.Info('[STOP-6] Found %d active connections to close.', [Length(ActiveListCopy)]);
  finally
    FActiveOverlappedLock.Leave;
  end;

  for Overlapped in ActiveListCopy do
  begin
    if Assigned(Overlapped) and (Overlapped^.Socket <> INVALID_SOCKET) then
    begin
      try
        shutdown(Overlapped^.Socket, SD_BOTH);
        closesocket(Overlapped^.Socket);
      except
        on E: Exception do
          Logger.Error('[STOP-7-ERR] Error closing client socket: %s', [E.Message]);
      end;
    end;
  end;

  if (FCompletionPort <> 0) and (FWorkerThreads.Count > 0) then
  begin
    Logger.Info('[STOP-8] Sending shutdown signals to worker threads...');
    for i := 1 to FWorkerThreads.Count do
      PostQueuedCompletionStatus(FCompletionPort, 0, 0, nil);
  end;

  Logger.Info('[STOP-9] Waiting for worker threads...');
  if FWorkerThreads.Count > 0 then
  begin
    SetLength(Handles, FWorkerThreads.Count);
    for i := 0 to FWorkerThreads.Count - 1 do
      Handles[i] := FWorkerThreads[i];

    var WaitResult := WaitForMultipleObjects(Min(Length(Handles), 64), @Handles[0], True, 1000);
    Logger.Info(Format('[STOP-10] WaitForMultipleObjects result: %d', [WaitResult]));
  end;

  if FMonitorRun then
  begin
    if FMonitorThread <> 0 then
    begin
      Logger.Info('[STOP-11] Waiting for monitoring thread...');
      WaitForSingleObject(FMonitorThread, 1000);
      CloseHandle(FMonitorThread);
      FMonitorThread := 0;
    end;
  end;

  for ThreadHandle in FWorkerThreads do
      CloseHandle(ThreadHandle);
  FWorkerThreads.Clear;

  if FCompletionPort <> 0 then
  begin
    Logger.Info('[STOP-12] Closing completion port...');
    CloseHandle(FCompletionPort);
    FCompletionPort := 0;
  end;

  Logger.Info('[STOP-13] SSL cleanup...');
  if FCredentialsValid then
  begin
    try
      FreeCredentialsHandle(@FServerCredHandle);
      FCredentialsValid := False;
    except
      on E: Exception do
        Logger.Error('Exception in FreeCredentialsHandle: ' + E.Message);
    end;
  end;

  if FCertContext <> nil then
  begin
    try
      CertFreeCertificateContext(FCertContext);
      FCertContext := nil;
    except
      on E: Exception do
        Logger.Error('Exception in CertFreeCertificateContext(FCertContext): ' + E.Message);
    end;
  end;

  if FH3CertContext <> nil then
  begin
    try
      CertFreeCertificateContext(FH3CertContext);
      FH3CertContext := nil;
    except
      on E: Exception do
        Logger.Error('Exception in CertFreeCertificateContext(FH3CertContext): ' + E.Message);
    end;
  end;

  Logger.Info('[STOP-14] Executing WSACleanup...');
  WSACleanup;
  Logger.Info('[STOP-15] Server shut down cleanly.');
end;

procedure TGHttpsServerIOCP.AcceptConnection2(Socket: TSocket);
const
  TEXT_START: string = 'START';
var
  OverlappedEx: POverlappedEx;
  ClientSocket: TSocket;
  BytesReceived: DWORD;
begin
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to accept connection: the OverlappedEx pool is full or out of memory.');
    Exit;
  end;
  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.Add(OverlappedEx);
  finally
    FActiveOverlappedLock.Leave;
  end;
  OverlappedEx^.OpType := otAccept;
  OverlappedEx^.Socket := Socket;
  ClientSocket := WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, WSA_FLAG_OVERLAPPED);
  if ClientSocket = INVALID_SOCKET then
  begin
    FOverlappedPool.Release(OverlappedEx);
    Exit;
  end;
  OverlappedEx^.ClientSocket := ClientSocket;
  if not AcceptEx(Socket, ClientSocket, @OverlappedEx^.Buffer[0], 0,
                  SizeOf(TSockAddrIn) + 16, SizeOf(TSockAddrIn) + 16,
                  BytesReceived, @OverlappedEx^.Overlapped) then
  begin
    if WSAGetLastError <> ERROR_IO_PENDING then
    begin
      closesocket(ClientSocket);
      FActiveOverlappedLock.Enter;
      try
        FActiveOverlapped.Remove(OverlappedEx);
      finally
        FActiveOverlappedLock.Leave;
      end;
      FOverlappedPool.Release(OverlappedEx);
      OverlappedEx := nil;
    end;
  end;
end;

procedure TGHttpsServerIOCP.HandleHttpsHandshake(ClientSocket: TSocket);
var
  OverlappedEx: POverlappedEx;
  WSABuf: TWSABUF;
  BytesReceived, Flags: DWORD;
  OptNoDelay: Integer;
begin
  // Wyciszenie algorytmu Nagle'a (TCP_NODELAY) dla natychmiastowej transmisji pakietów TLS
  // ???
  OptNoDelay := 1;
  setsockopt(ClientSocket, IPPROTO_TCP, TCP_NODELAY, @OptNoDelay, SizeOf(OptNoDelay));

  CreateIoCompletionPort(ClientSocket, FCompletionPort, ULONG_PTR(ClientSocket), 0);
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to start handshake for socket %d: the OverlappedEx pool is full.', [ClientSocket]);
    closesocket(ClientSocket);
    Exit;
  end;

  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.Add(OverlappedEx);
  finally
    FActiveOverlappedLock.Leave;
  end;

  OverlappedEx^.IsTLS := True;
  OverlappedEx^.ListenerPort := FHttpsPort;
  OverlappedEx^.OpType := otSSLHandshake;
  OverlappedEx^.Socket := ClientSocket;
  OverlappedEx^.SSLHandshakeStep := 0;
  OverlappedEx^.SSLNeedsMoreData := True;

  WSABuf.len := SizeOf(OverlappedEx^.Buffer);
  WSABuf.buf := @OverlappedEx^.Buffer[0];
  Flags := 0;

  if WSARecv(ClientSocket, @WSABuf, 1, BytesReceived, Flags,
             @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError <> WSA_IO_PENDING then
    begin
      var LReason := 'Failed to start SSL handshake: ' + IntToStr(WSAGetLastError);
      Logger.Error(LReason);
      CleanupConnectionWithReason(Self, OverlappedEx, LReason);
    end;
  end;
end;

procedure TGHttpsServerIOCP.HandleHttpPlainConnection(ClientSocket: TSocket);
var
  OverlappedEx: POverlappedEx;
  OptNoDelay: Integer;
begin
  // Wyciszenie algorytmu Nagle'a (TCP_NODELAY) dla natychmiastowej transmisji HTTP
  // ???
  OptNoDelay := 1;
  setsockopt(ClientSocket, IPPROTO_TCP, TCP_NODELAY, @OptNoDelay, SizeOf(OptNoDelay));

  CreateIoCompletionPort(ClientSocket, FCompletionPort, ULONG_PTR(ClientSocket), 0);
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to start HTTP connection for socket %d: the OverlappedEx pool is full.', [ClientSocket]);
    closesocket(ClientSocket);
    Exit;
  end;

  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.Add(OverlappedEx);
  finally
    FActiveOverlappedLock.Leave;
  end;

  OverlappedEx^.IsTLS := False;
  OverlappedEx^.ListenerPort := FHttpPort;
  OverlappedEx^.Socket := ClientSocket;
  OverlappedEx^.SSLContextValid := False;
  OverlappedEx^.OpType := otRead;
  OverlappedEx^.KeepAliveActive := True;
  OverlappedEx^.LastActivityTime := GetTickCount64;

  if InitializeRequestProcessing(OverlappedEx) then
    ContinueReadingRequest(OverlappedEx);
end;

function TGHttpsServerIOCP.ProcessSSLHandshakeStep(var OverlappedEx: TOverlappedEx; BytesReceived: DWORD): Boolean;
var
  InputBuffers: array[0..1] of TSecBuffer;
  OutputBuffers: array[0..1] of TSecBuffer;
  InputBufferDesc, OutputBufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  ContextAttr: ULONG;
  TimeStamp: TTimeStamp;
  FirstCall: Boolean;
  i: Integer;
  OriginalBuffers: array[0..1] of Pointer;
  AllocatedBuffers: array[0..1] of Pointer;
  AllocatedSizes: array[0..1] of Cardinal;
  BuffersToFree: Integer;
  StartTime: Cardinal;
begin
  Result := False;
  BuffersToFree := 0;
  StartTime := GetTickCount;
  FillChar(OriginalBuffers, SizeOf(OriginalBuffers), 0);
  FillChar(AllocatedBuffers, SizeOf(AllocatedBuffers), 0);
  FillChar(AllocatedSizes, SizeOf(AllocatedSizes), 0);
  if not FCredentialsValid then
  begin
    Logger.Error('SSL Credentials are not initialized');
    Exit;
  end;
  FirstCall := (OverlappedEx.SSLHandshakeStep = 0);
  Inc(OverlappedEx.SSLHandshakeStep);
  try
    InputBuffers[0].BufferType := SECBUFFER_TOKEN;
    InputBuffers[0].cbBuffer := BytesReceived;
    InputBuffers[0].pvBuffer := @OverlappedEx.Buffer[0];

    InputBuffers[1].BufferType := SECBUFFER_EMPTY;
    InputBuffers[1].cbBuffer := 0;
    InputBuffers[1].pvBuffer := nil;

    InputBufferDesc.ulVersion := SECBUFFER_VERSION;
    InputBufferDesc.cBuffers := 2;
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

    if FirstCall then
    begin
      Status := AcceptSecurityContext(@FServerCredHandle, nil, @InputBufferDesc,
                           ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or
                           ASC_REQ_CONFIDENTIALITY or ASC_REQ_STREAM,
                           SECURITY_NATIVE_DREP, @OverlappedEx.SSLContext,
                           @OutputBufferDesc, @ContextAttr, @TimeStamp);
    end
    else
    begin
      Status := AcceptSecurityContext(@FServerCredHandle, @OverlappedEx.SSLContext, @InputBufferDesc,
                                     ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or
                                     ASC_REQ_CONFIDENTIALITY or ASC_REQ_STREAM,
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
            Result := False;
          end;
        end
        else
        begin
        end;
      end;
    end;
    OverlappedEx.SSLOutputSize := OutputBuffers[0].cbBuffer;
    case Status of
      SEC_E_OK:
      begin
        OverlappedEx.SSLContextValid := True;
        OverlappedEx.SSLNeedsMoreData := False;
        Result := True;
      end;
      SEC_I_CONTINUE_NEEDED:
      begin
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
        // Sonda TLS / SChannel probe - wyciszona, aby nie zaśmiecać konsoli
        // ???
        OverlappedEx.SSLNeedsMoreData := False;
        Result := False;
      end;
    else
      begin
        Logger.Error('SSL Handshake failed: 0x%x', [Status]);
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
          var FreeResult := FreeContextBuffer(AllocatedBuffers[i]);
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

function TGHttpsServerIOCP.DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                           var PlainData: TBytes;
                           out BytesConsumed: Integer): Boolean;
var
  Buffers: array[0..3] of TSecBuffer;
  BufferDesc: TSecBufferDesc;
  Status: SECURITY_STATUS;
  DataBuffer: PByte;
  DataSize: Integer;
  i: Integer;
  OriginalDataPtr: Pointer;
  ExtraBufferFound: Boolean;
begin
  Result := False;
  SetLength(PlainData, 0);
  BytesConsumed := 0;
  if Length(EncryptedData) = 0 then
    Exit;

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
          var PtrAddr := NativeUInt(Buffers[i].pvBuffer);
          var OrigAddr := NativeUInt(OriginalDataPtr);
          var OrigEnd := OrigAddr + NativeUInt(Length(EncryptedData));
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
    else if Status <> SEC_E_INCOMPLETE_MESSAGE then
      Logger.Error('DecryptMessage failed with error: 0x%x', [Status]);
  except
    on E: Exception do
    begin
      Logger.Error('Exception w DecryptReceivedData: %s', [E.Message]);
      Result := False;
      BytesConsumed := 0;
    end;
  end;
end;

procedure TGHttpsServerIOCP.ProcessHttpRequest(OverlappedEx: POverlappedEx);
var
  Response: TResponse;
  Request: TRequest;
  Html, Json, FilePath: string;
  I: Integer;
  HeadersHtml: TStringBuilder;
  RawHeadersString: string;
  HeaderLines: TStringList;
  HeaderLine, HeaderName, HeaderValue: string;
  ColonPos: Integer;
  EmptyStream: TMemoryStream;
  Endpoint: TEndpointItem;
begin
  try
    if not Assigned(OverlappedEx) or not Assigned(OverlappedEx^.Request) then
    begin
      Logger.Error('Missing request object to process.');
      CleanupConnectionWithReason(Self, OverlappedEx, 'Missing request object');
      Exit;
    end;

    if FRejectNewConnections = 1 then
    begin
      CleanupConnectionWithReason(Self, OverlappedEx, 'Error lack of resources');
      exit;
    end;

    Request := OverlappedEx^.Request;
    OverlappedEx^.Response := TResponse.Create(OverlappedEx^.Socket);
    Response := OverlappedEx^.Response;
    Response.KeepAlive := FEnableKeepAlive and Assigned(Request) and Request.IsKeepAlive and (OverlappedEx^.KeepAliveRequestsCount < FMaxKeepAliveRequests);
    Response.SetMaxMemorySize(1 * 1024 * 1024);

    if FEnableHttp3 and (FHttpsPort > 0) and (FProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps]) then
      Response.AddHeader('Alt-Svc', Format('h3=":%d"; ma=86400', [FHttpsPort]));

    if (not OverlappedEx^.IsTLS) and (FHttpAction = haRedirectToHttps) and (FHttpsPort > 0) then
    begin
      var HostHeader := Request.Headers.GetHeader('Host');
      if Length(HostHeader) = 0 then
      begin
        Response.SetBadRequest('Missing Host Header');
        ContinueSendingResponse(OverlappedEx);
        Exit;
      end;
      if Pos(':', HostHeader) > 0 then
        HostHeader := Copy(HostHeader, 1, Pos(':', HostHeader) - 1);

      var RedirectUrl := Format('https://%s:%d%s', [HostHeader, FHttpsPort, Request.RequestInfo.RawUri]);
      Response.SetMovedPermanently(RedirectUrl);
      ContinueSendingResponse(OverlappedEx);
      Exit;
    end;

    var IsWebSocketRoute: Boolean := False;
    FLock.Enter;
    try
      IsWebSocketRoute := FWebSocketRoutes.ContainsKey(Request.RequestInfo.Path.ToLower);
    finally
      FLock.Leave;
    end;

    if IsWebSocketRoute then
    begin
      if not (SameText(Request.Headers.GetHeader('Upgrade'), 'websocket') and
              (ContainsText(Request.Headers.GetHeader('Connection'), 'Upgrade') or SameText(Request.Headers.GetHeader('Connection'), 'Upgrade'))) then
      begin
        Response.SetBadRequest('WebSocket Upgrade Header Required');
        ContinueSendingResponse(OverlappedEx);
        Exit;
      end;

      var Key: string := Request.Headers.GetHeader('Sec-WebSocket-Key');
      var DecodedBytes := TNetEncoding.Base64.DecodeStringToBytes(Key);
      if Length(DecodedBytes) <> 16 then
      begin
        Response.SetBadRequest('Invalid Sec-WebSocket-Key');
        ContinueSendingResponse(OverlappedEx);
        Exit;
      end;

      var MergedKey: string := Key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
      var Sha1Bytes := THashSHA1.GetHashBytes(MergedKey);
      var AcceptKey := TNetEncoding.Base64.EncodeBytesToString(Sha1Bytes).Trim;

      Response.SetStatus(101);
      Response.AddHeader('Upgrade', 'websocket');
      Response.AddHeader('Connection', 'Upgrade');
      Response.AddHeader('Sec-WebSocket-Accept', AcceptKey);
      Response.FinalizeContent;

      ContinueSendingResponse(OverlappedEx);
      Exit;
    end;

    if Request.HasSecurityViolation then
    begin
      Logger.Warn('Security violation detected: ' + Request.GetThreatSummary);
      Response.SetBadRequest('Security Violation Detected');
    end
    else
    begin
      var Key := GetEndpointKey(Request.RequestInfo.Method, Request.RequestInfo.Path);
      Endpoint := nil;
      if not FEndpoints.TryGetValue(Key, Endpoint) then
      begin
        if Request.RequestInfo.Method = hmGET then
        begin
          var RootKey := GetEndpointKey(hmGET, '/');
          FEndpoints.TryGetValue(RootKey, Endpoint);
        end;
      end;

      if Assigned(Endpoint) then
      begin
        try
          var isAuthorization:Boolean := True;
          if Endpoint.AuthorizationType = atJWTBearer then
          begin
            var AuthHeader: string := Request.Headers.Authorization;
            AuthHeader := FJWTManager.ExtractTokenFromAuthHeader(AuthHeader);
            if Length(AuthHeader) > 0 then
            begin
               isAuthorization:= False;
               var JWT: TJWTToken;
               if FJWTManager.ValidateToken(AuthHeader, JWT) then
                  isAuthorization:= True
               else
               begin
                 Response.SetUnauthorized();
                 isAuthorization:= False;
               end;

               if Assigned(JWT) then
                 JWT.Free;
            end
            else
            begin
               isAuthorization:= False;
               Response.SetUnauthorized();
            end;
          end;

          if isAuthorization then
          begin
            if Assigned(Endpoint.Handler) then
               Endpoint.Handler(self, Request, Response, self)
            else
               Endpoint.HandlerProc(self, Request, Response, self)
          end;
        except
          on E: Exception do
          begin
            Logger.Error(Format('Error in handler for endpoint %s: %s', [Key, E.Message]));
            Response.SetInternalServerError('An error occurred while processing your request.');
          end;
        end;
      end
      else
        Response.SetNotFound('The requested resource could not be found..');
    end;
    if Request.RequestInfo.Method = hmHEAD then
    begin
      EmptyStream := TMemoryStream.Create;
      try
        Response.AddInMemoryFileContent('application/octet-stream', EmptyStream);
      finally
        EmptyStream.Free;
      end;
    end;
    ContinueSendingResponse(OverlappedEx);
  except
    on E: Exception do
    begin
      Logger.Error('Exception in ProcessHttpRequest: %s', [E.Message]);
      if Assigned(OverlappedEx) then
      begin
        if not Assigned(OverlappedEx^.Response) then
          OverlappedEx^.Response := TResponse.Create(OverlappedEx^.Socket);
        OverlappedEx^.Response.SetInternalServerError('Server error while processing the request: ' + E.Message);
        ContinueSendingResponse(OverlappedEx);
      end
      else
      begin
        Logger.Error('Critical error: Missing OverlappedEx object in the exception handler.');
      end;
    end;
  end;
end;

class function TGHttpsServerIOCP.WorkerThreadProc(Parameter: Pointer): DWORD;
var
  Server: TGHttpsServerIOCP;
  BytesTransferred: DWORD;
  CompletionKey: ULONG_PTR;
  OverlappedEx: POverlappedEx;
  Status: DWORD;
  PlainData: string;
  EncryptedData, PlainBytes: TBytes;
  DecryptSuccess: Boolean;
  HandshakeComplete: Boolean;
  WSABuf: TWSABUF;
  Flags, BytesReceived: DWORD;
  GracefulShutdown: Boolean;
  ConsecutiveErrors: Integer;
  MemStatus: TMemoryStatusEx;
  FreeMemMb: Int64;
  RejectReason: string;
begin
  Result := 0;
  Server := TGHttpsServerIOCP(Parameter);
  GracefulShutdown := False;
  ConsecutiveErrors := 0;
  Logger.Info('Worker thread started');
  OverlappedEx := nil;
  while Server.FRunning and not GracefulShutdown do
  begin
    if GetQueuedCompletionStatus(Server.FCompletionPort, BytesTransferred,
                                CompletionKey, POverlapped(OverlappedEx), 2000) then  // 2 sec timeout
    begin
      ConsecutiveErrors := 0;
      if OverlappedEx = nil then
      begin
        Logger.Info('Worker thread received shutdown signal');
        Break;
      end;
      try
        case OverlappedEx^.OpType of
          otAccept:
          begin
            if Server.FRunning then
              Server.AcceptConnection2(OverlappedEx^.Socket);
            if Server.FActiveConnections >= Server.FMaxConnections then
            begin
              Logger.Warn('New connection REJECTED due to connection limit reached (%d).', [Server.FMaxConnections]);
              closesocket(OverlappedEx^.ClientSocket);
            end
            else if Server.FRejectNewConnections = 1 then // 1 = True
            begin
              Logger.Warn('New connection REJECTED due to system overload (monitor flag).');
              closesocket(OverlappedEx^.ClientSocket);
            end
            else
            begin
              TInterlocked.Increment(Server.FRequestsPerSecondCounter);
              InterlockedIncrement64(Server.FActiveConnections);
              if (Server.FListenSocketHTTP <> INVALID_SOCKET) and (OverlappedEx^.Socket = Server.FListenSocketHTTP) then
                Server.HandleHttpPlainConnection(OverlappedEx^.ClientSocket)
              else
                Server.HandleHttpsHandshake(OverlappedEx^.ClientSocket);
            end;
            Server.FActiveOverlappedLock.Enter;
            try
              Server.FActiveOverlapped.Remove(OverlappedEx);
            finally
              Server.FActiveOverlappedLock.Leave;
            end;
            Server.FOverlappedPool.Release(OverlappedEx);
          end;
          otSSLHandshake:
          begin
            if BytesTransferred > 0 then
            begin
              if (OverlappedEx^.SSLHandshakeStep = 0) and (BytesTransferred >= 4) then
              begin
                var FirstByte := OverlappedEx^.Buffer[0];
                if (FirstByte in [71, 80, 72, 68, 79, 67]) then // 'G', 'P', 'H', 'D', 'O', 'C'
                begin
                  var PlainHttpResponse :=
                    'HTTP/1.1 400 Bad Request' + #13#10 +
                    'Content-Type: text/html; charset=utf-8' + #13#10 +
                    'Connection: close' + #13#10 +
                    'Content-Length: 178' + #13#10#13#10 +
                    '<html>' + #13#10 +
                    '<head><title>400 Bad Request</title></head>' + #13#10 +
                    '<body>' + #13#10 +
                    '<center><h1>400 Bad Request</h1></center>' + #13#10 +
                    '<hr><center>The plain HTTP request was sent to HTTPS port</center>' + #13#10 +
                    '</body>' + #13#10 +
                    '</html>';
                  var ResponseBytes := TEncoding.UTF8.GetBytes(PlainHttpResponse);
                  send(OverlappedEx^.Socket, ResponseBytes[0], Length(ResponseBytes), 0);
                  CleanupConnectionWithReason(Server, OverlappedEx, 'Plain HTTP request sent to HTTPS port');
                  Continue;
                end;
              end;

              HandshakeComplete := Server.ProcessSSLHandshakeStep(OverlappedEx^, BytesTransferred);
              if OverlappedEx^.SSLOutputSize > 0 then
              begin
                if send(OverlappedEx^.Socket, OverlappedEx^.SSLOutputBuffer[0],
                       OverlappedEx^.SSLOutputSize, 0) = SOCKET_ERROR then
                begin
                  if WSAGetLastError <> WSAEWOULDBLOCK then
                  begin
                    CleanupConnectionWithReason(Server, OverlappedEx, 'Send error during SSL handshake');
                    Continue;
                  end;
                end;
              end;
              if HandshakeComplete then
              begin
                if Server.InitializeRequestProcessing(OverlappedEx) then
                begin
                  OverlappedEx^.OpType := otRead;
                  Server.ContinueReadingRequest(OverlappedEx);
                end;
              end
              else if OverlappedEx^.SSLNeedsMoreData then
              begin
                WSABuf.len := SizeOf(OverlappedEx^.Buffer);
                WSABuf.buf := @OverlappedEx^.Buffer[0];
                Flags := 0;
                ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));

                if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesReceived, Flags,
                          @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
                begin
                  if WSAGetLastError <> WSA_IO_PENDING then
                    CleanupConnectionWithReason(Server,OverlappedEx, 'SSL handshake read continuation error: ' + IntToStr(WSAGetLastError));
                end;
              end
              else
                CleanupConnectionWithReason(Server,OverlappedEx, 'SSL Handshake Failed');
            end else
              CleanupConnectionWithReason(Server,OverlappedEx, 'Client closed connection during handshake');
          end;
          otRead:
          begin
            if BytesTransferred > 0 then
            begin
              if not OverlappedEx^.IsTLS then
              begin
                if not Assigned(OverlappedEx^.Request) then
                  Server.InitializeRequestProcessing(OverlappedEx);

                if Assigned(OverlappedEx^.Request) then
                begin
                  OverlappedEx^.Request.AppendData(OverlappedEx^.Buffer, BytesTransferred);
                  if Server.IsRequestComplete(OverlappedEx^.Request) then
                    Server.ProcessHttpRequest(OverlappedEx)
                  else if not OverlappedEx^.Request.CanAcceptMoreData then
                    Server.ProcessHttpRequest(OverlappedEx)
                  else
                    Server.ContinueReadingRequest(OverlappedEx);
                end
                else
                  CleanupConnectionWithReason(Server, OverlappedEx, 'Request object NIL during plain HTTP read');
                Continue;
              end;

              if (Length(OverlappedEx^.ClientReceiveBuffer) + BytesTransferred) > (Server.FMaxRequestSize + MAX_SSL_TOKEN_SIZE) then
              begin
                 Logger.Error(Format('The client''s receive buffer has reached its limit (%d + %d > %d). I''m closing the connection.',
                   [Length(OverlappedEx^.ClientReceiveBuffer), BytesTransferred, (Server.FMaxRequestSize + MAX_SSL_TOKEN_SIZE)]));
                 CleanupConnectionWithReason(Server, OverlappedEx, 'Receive buffer overflow');
                 Continue;
              end;
              var CurrentBufferLen := Length(OverlappedEx^.ClientReceiveBuffer);
              SetLength(OverlappedEx^.ClientReceiveBuffer, CurrentBufferLen + BytesTransferred);
              Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[CurrentBufferLen], BytesTransferred);
              var DecryptedPlainData: TBytes;
              var CurrentAttemptConsumedBytes: Integer;
              while Length(OverlappedEx^.ClientReceiveBuffer) > 0 do
              begin
                DecryptSuccess := Server.DecryptReceivedData(OverlappedEx^.SSLContext,
                                                             OverlappedEx^.ClientReceiveBuffer,
                                                             DecryptedPlainData,
                                                             CurrentAttemptConsumedBytes);

                if DecryptSuccess then
                begin
                  if CurrentAttemptConsumedBytes > 0 then
                  begin
                    var RemainingBytes := Length(OverlappedEx^.ClientReceiveBuffer) - CurrentAttemptConsumedBytes;
                    if RemainingBytes > 0 then
                      OverlappedEx^.ClientReceiveBuffer := Copy(OverlappedEx^.ClientReceiveBuffer, CurrentAttemptConsumedBytes, RemainingBytes)
                    else
                      SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    if not Assigned(OverlappedEx^.Request) then
                      Server.InitializeRequestProcessing(OverlappedEx);

                    if Assigned(OverlappedEx^.Request) then
                    begin
                        if Length(DecryptedPlainData) > 0 then
                           OverlappedEx^.Request.AppendData(DecryptedPlainData, Length(DecryptedPlainData));
                    end
                    else
                    begin
                        Logger.Error('Fatal error: Request object is NIL while decrypting data. Closing connection.');
                        CleanupConnectionWithReason(Server, OverlappedEx, 'Request object NIL during decryption');
                        Break;
                    end;
                  end
                  else
                  begin
                    Logger.Error('DecryptReceivedData returned success, but 0 bytes were consumed. Closing connection.');
                    CleanupConnectionWithReason(Server, OverlappedEx, 'DecryptSuccess but ConsumedBytes = 0');
                    Break;
                  end;
                end
                else
                  Break;
              end;
              if Assigned(OverlappedEx^.Request) then
              begin
                  if Server.IsRequestComplete(OverlappedEx^.Request) then
                    Server.ProcessHttpRequest(OverlappedEx)
                  else if not OverlappedEx^.Request.CanAcceptMoreData then
                    Server.ProcessHttpRequest(OverlappedEx)
                  else
                    Server.ContinueReadingRequest(OverlappedEx);
              end
              else
              begin
                WSABuf.len := SizeOf(OverlappedEx^.Buffer);
                WSABuf.buf := @OverlappedEx^.Buffer[0];
                Flags := 0;
                ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
                if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesReceived, Flags,
                           @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
                begin
                  if WSAGetLastError <> WSA_IO_PENDING then
                    CleanupConnectionWithReason(Server, OverlappedEx, 'WSARecv continuation error waiting for complete TLS record');
                end;
              end;
            end
            else
              CleanupConnectionWithReason(Server, OverlappedEx, 'The client closed the connection while reading');
          end;
          otWriteChunk:
          begin
            if BytesTransferred > 0 then
              Server.ContinueSendingResponse(OverlappedEx)
            else
            begin
              Logger.Warn('Error sending chunk - 0 bytes sent');
              CleanupConnectionWithReason(Server, OverlappedEx, 'Error sending chunk - 0 bytes sent');
            end;
          end;
          otWebSocketRead:
          begin
            var WsSession := TWebSocketSession(OverlappedEx^.WebSocketSession);
            if not Assigned(WsSession) or (WsSession.InCleanup <> 0) then
            begin
              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
              OverlappedEx^.WebSocketSession := nil;
              Server.FOverlappedPool.Release(OverlappedEx);
            end
            else
            begin
              WsSession.AddRef;
              try
                try
                  if (BytesTransferred > 0) and (WsSession.InCleanup = 0) then
                  begin
                    var CloseConn: Boolean := False;

                    if not OverlappedEx^.IsTLS then
                    begin
                      var PlainChunk: TBytes;
                      SetLength(PlainChunk, BytesTransferred);
                      Move(OverlappedEx^.Buffer[0], PlainChunk[0], BytesTransferred);
                      var MsgArray := WsSession.ProcessIncomingPlaintext(PlainChunk, CloseConn);
                      for var MsgBytes in MsgArray do
                      begin
                        if WsSession.InCleanup <> 0 then Break;
                        var Opcode := WsSession.LastReceivedOpcode;
                        if Opcode in [wsOpText, wsOpBinary] then
                        begin
                          var MsgStr: string := '';
                          if Opcode = wsOpText then
                          begin
                            try
                              MsgStr := TEncoding.UTF8.GetString(MsgBytes);
                            except
                              on E: Exception do
                                MsgStr := TEncoding.Default.GetString(MsgBytes);
                            end;
                          end;
                          var Handled: Boolean := False;

                          Server.FLock.Enter;
                          try
                            var RouteHandler: TWebSocketMessageProc;
                            if Assigned(WsSession) and (WsSession.InCleanup = 0) and Server.FWebSocketRouteHandlers.TryGetValue(WsSession.RoutePath.ToLower, RouteHandler) and Assigned(RouteHandler) then
                            begin
                              Handled := True;
                              try
                                RouteHandler(Server, WsSession, MsgStr, Opcode);
                              except
                                on E: Exception do
                                  Logger.Error('Exception in WebSocket RouteHandler [%s]: %s', [E.ClassName, E.Message]);
                              end;
                            end;
                          finally
                            Server.FLock.Leave;
                          end;

                          if not Handled and Assigned(Server.FOnWebSocketMessage) and Assigned(WsSession) and (WsSession.InCleanup = 0) then
                          begin
                            Handled := True;
                            try
                              Server.FOnWebSocketMessage(Server, WsSession, MsgStr, Opcode);
                            except
                              on E: Exception do
                                Logger.Error('Exception in FOnWebSocketMessage [%s]: %s', [E.ClassName, E.Message]);
                            end;
                          end;

                          if Opcode = wsOpText then
                          begin
                            if not Handled and (WsSession.InCleanup = 0) then
                              Server.BroadcastWebSocket(MsgStr);
                          end
                          else if Opcode = wsOpBinary then
                          begin
                            if WsSession.InCleanup = 0 then
                            begin
                              WsSession.SendBinary(MsgBytes);
                              Server.TriggerWebSocketWrite(WsSession);
                            end;
                          end;
                        end;
                      end;

                      if WsSession.InCleanup = 0 then
                        Server.TriggerWebSocketWrite(WsSession);

                      if CloseConn then
                      begin
                        if WsSession.CloseReceived then
                          Server.CleanupWebSocketSession(WsSession, 'Client sent Close frame (Graceful WebSocket shutdown)')
                        else
                          Server.CleanupWebSocketSession(WsSession, 'WebSocket protocol violation / invalid frame payload');
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        OverlappedEx^.WebSocketSession := nil;
                        Server.FOverlappedPool.Release(OverlappedEx);
                        Continue;
                      end;
                    end
                    else
                    begin
                      var CurrentLen := Length(OverlappedEx^.ClientReceiveBuffer);
                      SetLength(OverlappedEx^.ClientReceiveBuffer, CurrentLen + BytesTransferred);
                      Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[CurrentLen], BytesTransferred);

                      var DecryptedPlainData: TBytes;
                      var ConsumedBytes: Integer;
                      while (Length(OverlappedEx^.ClientReceiveBuffer) > 0) and (WsSession.InCleanup = 0) do
                      begin
                        if Server.DecryptReceivedData(OverlappedEx^.SSLContext, OverlappedEx^.ClientReceiveBuffer, DecryptedPlainData, ConsumedBytes) then
                        begin
                          if ConsumedBytes > 0 then
                          begin
                            var RemainingBytes := Length(OverlappedEx^.ClientReceiveBuffer) - ConsumedBytes;
                            if RemainingBytes > 0 then
                              OverlappedEx^.ClientReceiveBuffer := Copy(OverlappedEx^.ClientReceiveBuffer, ConsumedBytes, RemainingBytes)
                            else
                              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);

                            if (Length(DecryptedPlainData) > 0) and (WsSession.InCleanup = 0) then
                            begin
                              var MsgArray := WsSession.ProcessIncomingPlaintext(DecryptedPlainData, CloseConn);
                              for var MsgBytes in MsgArray do
                              begin
                                if WsSession.InCleanup <> 0 then
                                   Break;
                                var Opcode := WsSession.LastReceivedOpcode;
                                if Opcode in [wsOpText, wsOpBinary] then
                                begin
                                  var MsgStr: string := '';
                                  if Opcode = wsOpText then
                                  begin
                                    try
                                      MsgStr := TEncoding.UTF8.GetString(MsgBytes);
                                    except
                                      on E: Exception do
                                        MsgStr := TEncoding.Default.GetString(MsgBytes);
                                    end;
                                  end;
                                  var Handled: Boolean := False;

                                  Server.FLock.Enter;
                                  try
                                    var RouteHandler: TWebSocketMessageProc;
                                    if Assigned(WsSession) and (WsSession.InCleanup = 0) and Server.FWebSocketRouteHandlers.TryGetValue(WsSession.RoutePath.ToLower, RouteHandler) and Assigned(RouteHandler) then
                                    begin
                                      Handled := True;
                                      try
                                        RouteHandler(Server, WsSession, MsgStr, Opcode);
                                      except
                                        on E: Exception do
                                          Logger.Error('Exception in WebSocket RouteHandler [%s]: %s', [E.ClassName, E.Message]);
                                      end;
                                    end;
                                  finally
                                    Server.FLock.Leave;
                                  end;

                                  if not Handled and Assigned(Server.FOnWebSocketMessage) and Assigned(WsSession) and (WsSession.InCleanup = 0) then
                                  begin
                                    Handled := True;
                                    try
                                      Server.FOnWebSocketMessage(Server, WsSession, MsgStr, Opcode);
                                    except
                                      on E: Exception do
                                        Logger.Error('Exception in FOnWebSocketMessage [%s]: %s', [E.ClassName, E.Message]);
                                    end;
                                  end;

                                  if Opcode = wsOpText then
                                  begin
                                    if not Handled and (WsSession.InCleanup = 0) then
                                      Server.BroadcastWebSocket(MsgStr);
                                  end
                                  else if Opcode = wsOpBinary then
                                  begin
                                    if WsSession.InCleanup = 0 then
                                    begin
                                      WsSession.SendBinary(MsgBytes);
                                      Server.TriggerWebSocketWrite(WsSession);
                                    end;
                                  end;
                                end;
                              end;

                              if WsSession.InCleanup = 0 then
                                Server.TriggerWebSocketWrite(WsSession);

                              if CloseConn then
                              begin
                                if WsSession.CloseReceived then
                                  Server.CleanupWebSocketSession(WsSession, 'Client sent Close frame (Graceful WebSocket shutdown)')
                                else
                                  Server.CleanupWebSocketSession(WsSession, 'WebSocket protocol violation / invalid frame payload');
                                SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                                OverlappedEx^.WebSocketSession := nil;
                                Server.FOverlappedPool.Release(OverlappedEx);
                                Break;
                              end;
                            end;
                          end
                          else
                            Break;
                        end
                        else
                          Break;
                      end;
                    end;

                    if not CloseConn and (WsSession.InCleanup = 0) then
                    begin
                      WSABuf.len := SizeOf(OverlappedEx^.Buffer);
                      WSABuf.buf := @OverlappedEx^.Buffer[0];
                      Flags := 0;
                      ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
                      if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesReceived, Flags, @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
                      begin
                        if WSAGetLastError <> WSA_IO_PENDING then
                        begin
                          Server.CleanupWebSocketSession(WsSession, 'WSARecv re-arm error');
                          SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                          OverlappedEx^.WebSocketSession := nil;
                          Server.FOverlappedPool.Release(OverlappedEx);
                        end;
                      end;
                    end;
                  end
                  else if WsSession.InCleanup = 0 then
                  begin
                    Server.CleanupWebSocketSession(WsSession, 'Client disconnected');
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Server.FOverlappedPool.Release(OverlappedEx);
                  end
                  else
                  begin
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Server.FOverlappedPool.Release(OverlappedEx);
                  end;
                except
                  on E: Exception do
                  begin
                    Logger.Error('Exception in otWebSocketRead [Socket:%d, %s]: %s', [OverlappedEx^.Socket, E.ClassName, E.Message]);
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Server.FOverlappedPool.Release(OverlappedEx);
                  end;
                end;
              finally
                WsSession.Release;
              end;
            end;
          end;
          otWebSocketWrite:
          begin
            var WsSession := TWebSocketSession(OverlappedEx^.WebSocketSession);
            if not Assigned(WsSession) or (WsSession.InCleanup <> 0) then
            begin
              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
              OverlappedEx^.WebSocketSession := nil;
              Server.FOverlappedPool.Release(OverlappedEx);
            end
            else
            begin
              WsSession.AddRef;
              try
                try
                  if (WsSession.InCleanup = 0) and (BytesTransferred > 0) then
                  begin
                    if WsSession.CloseReceived and not WsSession.HasPendingWrites then
                    begin
                      Server.CleanupWebSocketSession(WsSession, 'Graceful close completed');
                      var Detached := WsSession.DetachWriteOverlapped;
                      if Assigned(Detached) then
                      begin
                        SetLength(Detached^.ClientReceiveBuffer, 0);
                        Detached^.WebSocketSession := nil;
                        Server.FOverlappedPool.Release(Detached);
                      end;
                    end
                    else
                    begin
                      TInterlocked.Exchange(WsSession.WritePending, 0);
                      Server.TriggerWebSocketWrite(WsSession);
                    end;
                  end
                  else if WsSession.InCleanup = 0 then
                  begin
                    Server.CleanupWebSocketSession(WsSession, 'WSASend error');
                    var Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Server.FOverlappedPool.Release(Detached);
                    end;
                  end
                  else
                  begin
                    var Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Server.FOverlappedPool.Release(Detached);
                    end;
                  end;
                except
                  on E: Exception do
                  begin
                    Logger.Error('Exception in otWebSocketWrite [Socket:%d, %s]: %s', [OverlappedEx^.Socket, E.ClassName, E.Message]);
                    var Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Server.FOverlappedPool.Release(Detached);
                    end;
                  end;
                end;
              finally
                WsSession.Release;
              end;
            end;
          end;
        end;
      except
        on E: Exception do
        begin
          var SockId: TSocket := 0;
          var OpName: string := 'Unknown';
          if Assigned(OverlappedEx) then
          begin
            SockId := OverlappedEx^.Socket;
            case OverlappedEx^.OpType of
              otAccept: OpName := 'otAccept';
              otRead: OpName := 'otRead';
              otSSLHandshake: OpName := 'otSSLHandshake';
              otWriteChunk: OpName := 'otWriteChunk';
              otTimeoutClose: OpName := 'otTimeoutClose';
              otWebSocketRead: OpName := 'otWebSocketRead';
              otWebSocketWrite: OpName := 'otWebSocketWrite';
            end;
          end;
          Logger.Error('Exception in WorkerThreadProc loop [Socket:%d, Op:%s, %s]: %s', [SockId, OpName, E.ClassName, E.Message]);
          CleanupConnectionWithReason(Server, OverlappedEx, Format('Exception [%s] in loop: %s', [E.ClassName, E.Message]));
        end;
      end;
    end else
    begin
      Status := GetLastError;
      case Status of
        WAIT_TIMEOUT:
        begin
          if not Server.FRunning then
          begin
            Logger.Info('Server stopped - exiting worker thread');
            Break;
          end;
          Continue;
        end;
        ERROR_INVALID_HANDLE:
        begin
          Logger.Info('Completion port invalid - terminating thread');
          GracefulShutdown := True;
        end;

        ERROR_OPERATION_ABORTED:
        begin
          if Assigned(OverlappedEx) then
          begin
            var IsActive: Boolean := False;
            Server.FActiveOverlappedLock.Enter;
            try
              IsActive := Server.FActiveOverlapped.Contains(OverlappedEx);
            finally
              Server.FActiveOverlappedLock.Leave;
            end;
            if IsActive then
            begin
              Logger.Info(Format('Operation aborted for socket %d - code 995', [OverlappedEx^.Socket]));
              CleanupConnectionWithReason(Server,OverlappedEx, 'Operation aborted (ERROR_OPERATION_ABORTED)');
            end
            else
              Logger.Info('Operation aborted for already released overlapped - ignoring');
          end
          else
          begin
            Logger.Info('Operation aborted without context - continuing');
          end;
          if not Server.FRunning then
          begin
            Logger.Info('Server stopping - operation aborted is expected');
            Break;
          end;
        end;
        ERROR_CONNECTION_ABORTED,
        ERROR_NETNAME_DELETED:
        begin
          if Assigned(OverlappedEx) then
          begin
            var IsActive: Boolean := False;
            Server.FActiveOverlappedLock.Enter;
            try
              IsActive := Server.FActiveOverlapped.Contains(OverlappedEx);
            finally
              Server.FActiveOverlappedLock.Leave;
            end;
            if IsActive then
              CleanupConnectionWithReason(Server,OverlappedEx, Format('Connection interrupted (code: %d)', [Status]))
            else
              Logger.Info('Connection interrupted for already released overlapped - ignoring');
          end
          else
            Logger.Info(Format('Connection interrupted - no context (code: %d)', [Status]));
        end;
        else
        begin
          Inc(ConsecutiveErrors);
          if Assigned(OverlappedEx) then
          begin
            var IsActive: Boolean := False;
            Server.FActiveOverlappedLock.Enter;
            try
              IsActive := Server.FActiveOverlapped.Contains(OverlappedEx);
            finally
              Server.FActiveOverlappedLock.Leave;
            end;
            if IsActive then
            begin
              Logger.Info(Format('GetQueuedCompletionStatus error: %d for socket %d', [Status, OverlappedEx^.Socket]));
              CleanupConnectionWithReason(Server,OverlappedEx, Format('Error GetQueuedCompletionStatus: %d', [Status]));
            end
            else
              Logger.Info('GetQueuedCompletionStatus error for already released overlapped - ignoring');
          end
          else
            Logger.Info(Format('Fatal error GetQueuedCompletionStatus without context: %d (consecutive: %d)', [Status, ConsecutiveErrors]));

          if ConsecutiveErrors > 5 then
          begin
            Logger.Info('Too many GetQueuedCompletionStatus errors - closing thread');
            GracefulShutdown := True;
          end
          else
            Sleep(100);
        end;
      end;
    end;
  end;
  Logger.Info('Worker thread has finished work');
  Result := 0;
end;

const RESPONSE_CHUNK_SIZE = 8192; // 8KB
procedure TGHttpsServerIOCP.ContinueSendingResponse(OverlappedEx: POverlappedEx);
var
  PlainChunk: TBytes;
  EncryptedChunk: TBytes;
  BytesToEncrypt, BytesConsumed: Integer;
  WSABuf: TWSABUF;
  BytesSentIO, Flags: DWORD;
  Response: TResponse;
  PlainChunkBuffer: array[0..RESPONSE_CHUNK_SIZE-1] of Byte;
begin
  try
    if not Assigned(OverlappedEx) or not Assigned(OverlappedEx^.Response) then
    begin
      Logger.Error('Fatal error: Missing OverlappedEx structure or Response object in ContinueSendingResponse.');
      CleanupConnectionWithReason(Self, OverlappedEx, 'No data in ContinueSendingResponse');
      Exit;
    end;
    Response := OverlappedEx^.Response;
    if Response.IsComplete then
    begin
      if Response.Status = hsSwitchingProtocols then
      begin
        TransitionToWebSocket(OverlappedEx);
        Exit;
      end;

      if FEnableKeepAlive and Response.KeepAlive and
         (OverlappedEx^.KeepAliveRequestsCount < FMaxKeepAliveRequests) and
         (OverlappedEx^.SSLContextValid or (not OverlappedEx^.IsTLS)) then
      begin
        var OldResp := TResponse(InterlockedExchangePointer(Pointer(OverlappedEx^.Response), nil));
        if Assigned(OldResp) then
           OldResp.Free;
        var OldReq := TRequest(InterlockedExchangePointer(Pointer(OverlappedEx^.Request), nil));
        if Assigned(OldReq) then
           OldReq.Free;
        Inc(OverlappedEx^.KeepAliveRequestsCount);
        OverlappedEx^.KeepAliveActive := True;
        OverlappedEx^.LastActivityTime := GetTickCount64;

        if Length(OverlappedEx^.ClientReceiveBuffer) > 0 then
        begin
          OverlappedEx^.OpType := otRead;
          InitializeRequestProcessing(OverlappedEx);
          PostQueuedCompletionStatus(FCompletionPort, 0, ULONG_PTR(OverlappedEx), POverlapped(OverlappedEx));
          Exit;
        end;

        OverlappedEx^.OpType := otRead;
        ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
        WSABuf.len := SizeOf(OverlappedEx^.Buffer);
        WSABuf.buf := @OverlappedEx^.Buffer[0];
        Flags := 0;
        BytesSentIO := 0;
        if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesSentIO, Flags, @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
        begin
          if WSAGetLastError <> WSA_IO_PENDING then
            CleanupConnectionWithReason(Self, OverlappedEx, 'WSARecv Keep-Alive re-arm failed');
        end;
        Exit;
      end;

      var Reason := 'Transfer completed (SSL shutdown completed)';
      if OverlappedEx^.IsTLS and OverlappedEx^.SSLContextValid then
      begin
        try
          PerformGracefulSSLShutdown(OverlappedEx^);
        except
          on E: Exception do
            Logger.Error('Błąd SSL shutdown po transferze: ' + E.Message);
        end;
      end else
      begin
        Reason := 'Transfer completed (no SSL shutdown)';
      end;
      CleanupConnectionWithReason(Self, OverlappedEx, Reason);
      Exit;
    end;
    BytesToEncrypt := Response.ReadNextChunk(@PlainChunkBuffer[0], SizeOf(PlainChunkBuffer));
    if BytesToEncrypt <= 0 then
    begin
      if Response.IsComplete then
      begin
        ContinueSendingResponse(OverlappedEx);
        Exit;
      end else
      begin
         Logger.Error('ReadNextChunk returned 0, but the response is incomplete. Closing.');
         CleanupConnectionWithReason(Self, OverlappedEx, 'Response Streaming Error');
      end;
      Exit;
    end;
    SetLength(PlainChunk, BytesToEncrypt);
    Move(PlainChunkBuffer[0], PlainChunk[0], BytesToEncrypt);
    BytesConsumed := 0;
    if OverlappedEx^.IsTLS and OverlappedEx^.SSLContextValid then
    begin
      if not EncryptBytesToSend(OverlappedEx^.SSLContext, PlainChunk, EncryptedChunk) then
      begin
        Logger.Error('FATAL ERROR: Failed to encrypt chunk. Closing connection.');
        CleanupConnectionWithReason(Self, OverlappedEx, 'Chunk encryption error');
        Exit;
      end;
    end
    else
      EncryptedChunk := PlainChunk;

    if Length(EncryptedChunk) > SizeOf(OverlappedEx^.SSLOutputBuffer) then
    begin
      Logger.Error('FATAL ERROR: Encrypted chunk (%d) too large for buffer (%d).',
                 [Length(EncryptedChunk), SizeOf(OverlappedEx^.SSLOutputBuffer)]);
      CleanupConnectionWithReason(Self, OverlappedEx, 'Chunk too big for buffer');
      Exit;
    end;
    Move(EncryptedChunk[0], OverlappedEx^.SSLOutputBuffer[0], Length(EncryptedChunk));
    OverlappedEx^.OpType := otWriteChunk;
    WSABuf.len := Length(EncryptedChunk);
    WSABuf.buf := @OverlappedEx^.SSLOutputBuffer[0];
    ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
    if WSASend(OverlappedEx^.Socket, @WSABuf, 1, BytesSentIO, 0,
               @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
    begin
      if WSAGetLastError <> WSA_IO_PENDING then
      begin
        var ErrorCode := WSAGetLastError;
        if (ErrorCode = WSAECONNRESET) or (ErrorCode = WSAECONNABORTED) or (ErrorCode = WSAENOTSOCK) or (ErrorCode = 10038) then
          Logger.Info('Client disconnected during chunk upload (code %d)', [ErrorCode])
        else
          Logger.Error('Error starting chunk upload: %d', [ErrorCode]);
        CleanupConnectionWithReason(Self, OverlappedEx, Format('Error WSASend: %d', [ErrorCode]));

      end;
    end;

  except
    on E: Exception do
    begin
      var SockId: TSocket := 0;
      if Assigned(OverlappedEx) then
         SockId := OverlappedEx^.Socket;
      Logger.Error('Exception in ContinueSendingResponse [Socket:%d, %s]: %s', [SockId, E.ClassName, E.Message]);
      CleanupConnectionWithReason(Self, OverlappedEx, Format('Exception [%s] in ContinueSendingResponse: %s', [E.ClassName, E.Message]));
    end;
  end;
end;

function TGHttpsServerIOCP.EncryptBytesToSend(var Context: TCtxtHandle;
  const PlainData: TBytes; var EncryptedData: TBytes): Boolean;
var
  StreamSizes: SecPkgContext_StreamSizes;
  Status: SECURITY_STATUS;
  Buffers: array[0..3] of TSecBuffer;
  BufferDesc: TSecBufferDesc;
  MessageBuffer: TBytes;
  HeaderSize, TrailerSize, MaxMessageSize, TotalSize, ActualMessageSize: Integer;
  i: Integer;
  OriginalBuffers: array[0..3] of Pointer;
  AllocatedBuffers: array[0..3] of Pointer;
  AllocatedSizes: array[0..3] of Cardinal;
  BuffersToFree: Integer;
  StartTime: Cardinal;
begin
  Result := False;
  SetLength(EncryptedData, 0);
  BuffersToFree := 0;
  StartTime := GetTickCount;
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
    FillChar(MessageBuffer[0], TotalSize, 0);
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
          end
          else
          begin
            // ???
          end;
          Inc(TotalSize, Buffers[i].cbBuffer);
        end;
      end;
      SetLength(EncryptedData, TotalSize);
      var Offset := 0;
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

class function TGHttpsServerIOCP.MonitorThreadProc(Parameter: Pointer): DWORD;
  function FileTimeToInt64(const FT: TFileTime): Int64;
  begin
    Result := Int64(FT.dwLowDateTime) or (Int64(FT.dwHighDateTime) shl 32);
  end;
var
  Server: TGHttpsServerIOCP;
  MemStatus: TMemoryStatusEx;
  RejectReason: string;
  ShouldReject: Boolean;
  LastKernelTime, LastUserTime: TFileTime;
  LastCheckTime: Int64;
  ProcessHandle: THandle;
  CreationTime, ExitTime, KernelTime, UserTime: TFileTime;
  Now: TFileTime;
  KernelDiff, UserDiff, TimeDiff: Int64;
  CPUUsage: Double;
  ProcessorCount: Integer;
  Sy: TSystemInfo;
  CurrentRequests: LongInt;
begin
  Server := TGHttpsServerIOCP(Parameter);
  Result := 0;
  Logger.Info('A thread has been started to monitor the server status.');
  ProcessHandle := GetCurrentProcess;
  GetSystemInfo(Sy);
  ProcessorCount := Sy.dwNumberOfProcessors;
  GetProcessTimes(ProcessHandle, CreationTime, ExitTime, LastKernelTime, LastUserTime);
  GetSystemTimeAsFileTime(Now);
  LastCheckTime := FileTimeToInt64(Now);
  while Server.FRunning do
  begin
    var SleepSteps: Integer := 2;
    if Server.FRejectNewConnections = 1 then
      SleepSteps := 45;
    for var S := 1 to SleepSteps do
    begin
      Sleep(100);
      if not Server.FRunning then
        Break;
    end;
    if not Server.FRunning then
      Break;
    ShouldReject := False;
    RejectReason := '';
    try
      if GetProcessTimes(ProcessHandle, CreationTime, ExitTime, KernelTime, UserTime) then
      begin
        GetSystemTimeAsFileTime(Now);
        KernelDiff := FileTimeToInt64(KernelTime) - FileTimeToInt64(LastKernelTime);
        UserDiff := FileTimeToInt64(UserTime) - FileTimeToInt64(LastUserTime);
        TimeDiff := FileTimeToInt64(Now) - LastCheckTime;
        if (TimeDiff > 0) and (ProcessorCount > 0) then
        begin
          CPUUsage := (KernelDiff + UserDiff) * 100.0 / TimeDiff / ProcessorCount;
          LastKernelTime := KernelTime;
          LastUserTime := UserTime;
          LastCheckTime := FileTimeToInt64(Now);
          if CPUUsage > 95.0 then
          begin
            Logger.Warn('MONITOR: High CPU load from server process (%.1f%%)', [CPUUsage]);
          end;
        end;
      end;
      CurrentRequests := TInterlocked.Exchange(Server.FRequestsPerSecondCounter, 0);
      if CurrentRequests > Server.FMaxRequestsPerSecond then
      begin
        Logger.Warn('MONITOR: High request rate (%d req/s)', [CurrentRequests]);
      end;
      TInterlocked.Exchange(Server.FThrottleNewConnections, 0);

      MemStatus.dwLength := SizeOf(TMemoryStatusEx);
      if GlobalMemoryStatusEx(MemStatus) then
      begin
        if MemStatus.dwMemoryLoad >= Server.FOverlappedPool.FMaxMemoryLoadPercent then
        begin
          ShouldReject := True;
          RejectReason := Format('High system memory usage (%d%%)', [MemStatus.dwMemoryLoad]);
        end
        else if (MemStatus.ullAvailPhys div (1024 * 1024)) < Server.FOverlappedPool.MinFreeMemoryMb then
        begin
          ShouldReject := True;
          RejectReason := Format('Low free memory RAM (%d MB)', [MemStatus.ullAvailPhys div (1024 * 1024)]);
        end;
      end;
      if ShouldReject then
      begin
        if InterlockedCompareExchange(Server.FRejectNewConnections, 1, 0) = 0 then
          Logger.Warn('MONITOR: New call rejection mode has been activated. Reason: %s', [RejectReason]);
      end
      else
      begin
        if InterlockedCompareExchange(Server.FRejectNewConnections, 0, 1) = 1 then
          Logger.Info('MONITOR: Call rejection mode has been deactivated. Resources are back to normal.');
      end;

      if Assigned(Server.FWebSocketManager) then
      begin
        var SessionList := Server.FWebSocketManager.AcquireSessionList;
        try
          var CurrTime := GetTickCount64;
          for var WS_Session in SessionList do
          begin
            if WS_Session.InCleanup <> 0 then Continue;

            var IdleDuration := CurrTime - WS_Session.LastActivityTime;
            if IdleDuration > 660000 then
            begin
              Server.CleanupWebSocketSession(WS_Session, 'Idle Timeout (No Pong response)');
            end
            else if IdleDuration > 600000 then
            begin
              if WS_Session.PingPending = 0 then
              begin
                WS_Session.PingPending := 1;
                WS_Session.QueueSendFrame(wsOpPing, []);
                Server.TriggerWebSocketWrite(WS_Session);
              end;
            end;
          end;
        finally
          for var WS_Session in SessionList do
            WS_Session.Release;
          SessionList.Free;
        end;
      end;

      if Server.FEnableKeepAlive and Assigned(Server.FActiveOverlapped) and Assigned(Server.FActiveOverlappedLock) then
      begin
        var IdleList: TList<POverlappedEx> := nil;
        Server.FActiveOverlappedLock.Enter;
        try
          var CurrTick := GetTickCount64;
          for var Ov in Server.FActiveOverlapped do
          begin
            if Assigned(Ov) and Ov^.KeepAliveActive and (Ov^.OpType = otRead) and not Assigned(Ov^.Response) then
            begin
              if (CurrTick - Ov^.LastActivityTime) > Server.FKeepAliveTimeoutMs then
              begin
                if IdleList = nil then IdleList := TList<POverlappedEx>.Create;
                IdleList.Add(Ov);
              end;
            end;
          end;
        finally
          Server.FActiveOverlappedLock.Leave;
        end;

        if Assigned(IdleList) then
        begin
          try
            for var IdleOv in IdleList do
            begin
              if Assigned(IdleOv) and (IdleOv^.Socket <> INVALID_SOCKET) then
              begin
                IdleOv^.KeepAliveActive := False;
                CleanupConnectionWithReason(Server, IdleOv, 'HTTP Keep-Alive idle timeout');
              end;
            end;
          finally
            IdleList.Free;
          end;
        end;
      end;
    except
    end;
  end;
  RejectReason := '';
  Logger.Info('Monitoring thread terminated.');
end;

procedure TGHttpsServerIOCP.TransitionToWebSocket(OverlappedEx: POverlappedEx);
var
  Session: TWebSocketSession;
  WriteOverlapped: POverlappedEx;
  WSABuf: TWSABUF;
  Flags, BytesReceived: DWORD;
begin
  Logger.Info('Upgrading connection on socket %d to WebSocket', [OverlappedEx^.Socket]);

  var ReqPath: string := '';
  if Assigned(OverlappedEx^.Request) then
    ReqPath := OverlappedEx^.Request.RequestInfo.Path.ToLower;

  if Assigned(OverlappedEx^.Request) then
  begin
    OverlappedEx^.Request.Free;
    OverlappedEx^.Request := nil;
  end;
  if Assigned(OverlappedEx^.Response) then
  begin
    OverlappedEx^.Response.Free;
    OverlappedEx^.Response := nil;
  end;

  Session := TWebSocketSession.Create(OverlappedEx^.Socket, OverlappedEx, FOverlappedPool);
  Session.RoutePath := ReqPath;

  WriteOverlapped := FOverlappedPool.Acquire;
  if WriteOverlapped = nil then
  begin
    Logger.Error('TransitionToWebSocket: OverlappedExPool full, cannot acquire WriteOverlapped for socket %d. Aborting upgrade.', [OverlappedEx^.Socket]);
    Session.Free;
    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
    CleanupConnectionWithReason(Self, OverlappedEx, 'WebSocket upgrade failed: pool exhausted');
    Exit;
  end;

  WriteOverlapped^.Socket := OverlappedEx^.Socket;
  WriteOverlapped^.ClientSocket := OverlappedEx^.ClientSocket;
  WriteOverlapped^.IsTLS := OverlappedEx^.IsTLS;
  WriteOverlapped^.ListenerPort := OverlappedEx^.ListenerPort;
  WriteOverlapped^.SSLContext := OverlappedEx^.SSLContext;
  WriteOverlapped^.SSLContextValid := OverlappedEx^.SSLContextValid;
  WriteOverlapped^.OpType := otWebSocketWrite;
  WriteOverlapped^.WebSocketSession := Session;

  OverlappedEx^.OpType := otWebSocketRead;
  OverlappedEx^.WebSocketSession := Session;
  OverlappedEx^.WebSocketState := 1; // 1 = Open

  Session.ReadOverlapped := OverlappedEx;
  Session.WriteOverlapped := WriteOverlapped;

  FWebSocketManager.AddSession(Session);

  if Assigned(FOnWebSocketConnect) then
  begin
    try
      FOnWebSocketConnect(Self, Session);
    except
      on E: Exception do
        Logger.Error('Exception in FOnWebSocketConnect: %s', [E.Message]);
    end;
  end;

  // Uruchomienie wysyłania początkowych ramek zakolejkowanych podczas połączenia (np. init-segment wideo)
  TriggerWebSocketWrite(Session);

  WSABuf.len := SizeOf(OverlappedEx^.Buffer);
  WSABuf.buf := @OverlappedEx^.Buffer[0];
  Flags := 0;
  ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));

  if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, BytesReceived, Flags,
            @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError <> WSA_IO_PENDING then
    begin
      Logger.Error('WSARecv failed in TransitionToWebSocket: %d', [WSAGetLastError]);
      CleanupWebSocketSession(Session, 'WSARecv failed on transition');
    end;
  end;
end;

procedure TGHttpsServerIOCP.BroadcastWebSocket(const AText: string);
var
  Payload: TBytes;
  SessionList: TList<TWebSocketSession>;
  WS_Session: TWebSocketSession;
begin
  if not Assigned(FWebSocketManager) then Exit;
  Payload := TEncoding.UTF8.GetBytes(AText);
  SessionList := FWebSocketManager.AcquireSessionList;
  try
    for WS_Session in SessionList do
    begin
      if Assigned(WS_Session) and (WS_Session.InCleanup = 0) then
      begin
        WS_Session.QueueSendFrame(wsOpText, Payload);
        TriggerWebSocketWrite(WS_Session);
      end;
    end;
  finally
    for WS_Session in SessionList do
      WS_Session.Release;
    SessionList.Free;
  end;
end;

procedure TGHttpsServerIOCP.BroadcastWebSocketBinary(const Data: TBytes);
var
  SessionList: TList<TWebSocketSession>;
  WS_Session: TWebSocketSession;
begin
  if not Assigned(FWebSocketManager) or (Length(Data) = 0) then Exit;
  SessionList := FWebSocketManager.AcquireSessionList;
  try
    for WS_Session in SessionList do
    begin
      if Assigned(WS_Session) and (WS_Session.InCleanup = 0) then
      begin
        WS_Session.QueueSendFrame(wsOpBinary, Data);
        TriggerWebSocketWrite(WS_Session);
      end;
    end;
  finally
    for WS_Session in SessionList do
      WS_Session.Release;
    SessionList.Free;
  end;
end;

function TGHttpsServerIOCP.GetWebSocketActiveCount: Integer;
begin
  if Assigned(FWebSocketManager) then
    Result := FWebSocketManager.GetSessionCount
  else
    Result := 0;
end;

procedure TGHttpsServerIOCP.TriggerWebSocketWrite(Session: TWebSocketSession);
var
  PlainChunk, EncryptedChunk: TBytes;
  WSABuf: TWSABUF;
  BytesSent: DWORD;
  CurrentWriteOv: POverlappedEx;
begin
  if not Assigned(Session) or (Session.InCleanup <> 0) then Exit;
  CurrentWriteOv := Session.WriteOverlapped;
  if not Assigned(CurrentWriteOv) then Exit;

  if TInterlocked.CompareExchange(Session.WritePending, 1, 0) <> 0 then
    Exit;

  Session.AddRef;
  try
    CurrentWriteOv := Session.WriteOverlapped;
    if (Session.InCleanup <> 0) or not Assigned(CurrentWriteOv) then
    begin
      TInterlocked.Exchange(Session.WritePending, 0);
      Exit;
    end;

    if Session.DequeueNextWrite(PlainChunk) then
    begin
      CurrentWriteOv := Session.WriteOverlapped;
      if (Session.InCleanup <> 0) or not Assigned(CurrentWriteOv) then
      begin
        TInterlocked.Exchange(Session.WritePending, 0);
        Exit;
      end;

      if CurrentWriteOv^.IsTLS and CurrentWriteOv^.SSLContextValid then
      begin
        try
          if not EncryptBytesToSend(CurrentWriteOv^.SSLContext, PlainChunk, EncryptedChunk) then
          begin
            CleanupWebSocketSession(Session, 'Encryption error during WSASend');
            Exit;
          end;
        except
          on E: Exception do
          begin
            Logger.Info('SSPI Encrypt exception during WSASend: %s', [E.Message]);
            CleanupWebSocketSession(Session, 'SSPI Exception during WSASend: ' + E.Message);
            Exit;
          end;
        end;
      end
      else
        EncryptedChunk := PlainChunk;

      if Length(EncryptedChunk) > SizeOf(CurrentWriteOv^.SSLOutputBuffer) then
      begin
        CleanupWebSocketSession(Session, 'Encrypted frame too large');
        Exit;
      end;

      if Length(EncryptedChunk) > 0 then
      begin
        Move(EncryptedChunk[0], CurrentWriteOv^.SSLOutputBuffer[0], Length(EncryptedChunk));

        WSABuf.len := Length(EncryptedChunk);
        WSABuf.buf := @CurrentWriteOv^.SSLOutputBuffer[0];
        ZeroMemory(@CurrentWriteOv^.Overlapped, SizeOf(TOverlapped));
        if WSASend(Session.Socket, @WSABuf, 1, BytesSent, 0, @CurrentWriteOv^.Overlapped, nil) = SOCKET_ERROR then
        begin
          if WSAGetLastError <> WSA_IO_PENDING then
            CleanupWebSocketSession(Session, 'WSASend failed: ' + IntToStr(WSAGetLastError));
        end;
      end
      else
        TInterlocked.Exchange(Session.WritePending, 0);
    end
    else
      TInterlocked.Exchange(Session.WritePending, 0);
  finally
    Session.Release;
  end;
end;

procedure TGHttpsServerIOCP.CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
begin
  if not Assigned(Session) then Exit;

  if TInterlocked.CompareExchange(Session.InCleanup, 1, 0) <> 0 then
    Exit;

  if Assigned(Session.ReadOverlapped) then
    Session.ReadOverlapped^.WebSocketSession := nil;
  if Assigned(Session.WriteOverlapped) then
    Session.WriteOverlapped^.WebSocketSession := nil;

  try
    var LocalSocket := Session.Socket;
    Logger.Info('Closing WebSocket session for socket %d. Reason: %s', [LocalSocket, Reason]);

    if Assigned(FOnWebSocketDisconnect) then
    begin
      try
        FOnWebSocketDisconnect(Self, Session, Reason);
      except
        on E: Exception do
          Logger.Error('Exception in FOnWebSocketDisconnect: %s', [E.Message]);
      end;
    end;

    if Assigned(FWebSocketManager) then
      FWebSocketManager.RemoveSession(Session);

    if Assigned(FActiveOverlapped) and Assigned(FActiveOverlappedLock) then
    begin
      FActiveOverlappedLock.Enter;
      try
        if Assigned(Session.ReadOverlapped) then
          FActiveOverlapped.Remove(Session.ReadOverlapped);
        if Assigned(Session.WriteOverlapped) then
          FActiveOverlapped.Remove(Session.WriteOverlapped);
      finally
        FActiveOverlappedLock.Leave;
      end;
    end;

    if LocalSocket <> INVALID_SOCKET then
    begin
      InterlockedDecrement64(FActiveConnections);
      try
        shutdown(LocalSocket, SD_BOTH);
      except
      end;
      closesocket(LocalSocket);
    end;

    var WriteOv := Session.DetachWriteOverlapped;
    if Assigned(WriteOv) and (Session.WritePending = 0) then
    begin
      SetLength(WriteOv^.ClientReceiveBuffer, 0);
      WriteOv^.WebSocketSession := nil;
      if Assigned(FOverlappedPool) then
        FOverlappedPool.Release(WriteOv);
    end;

    Session.Release;
  except
    on E: Exception do
    begin
      var SockId: TSocket := 0;
      if Assigned(Session) then SockId := Session.Socket;
      Logger.Error('Exception in CleanupWebSocketSession [Socket:%d, %s]: %s', [SockId, E.ClassName, E.Message]);
    end;
  end;
end;

procedure TGHttpsServerIOCP.ProcessHttp3Request(Req: THttp3Request; Resp: THttp3Response);
var
  Endpoint: TEndpointItem;
  Key: string;
  Method: THttpMethod;
  DummyReq: TRequest;
  DummyResp: TResponse;
  RemoteAddr: TSockAddrIn;
  IsAuth: Boolean;
  AuthHeader: string;
  JWT: TJWTToken;
begin
  if Req = nil then
     Exit;

  if SameText(Req.Method, 'GET') then
     Method := hmGET
  else if SameText(Req.Method, 'POST') then
     Method := hmPOST
  else if SameText(Req.Method, 'PUT') then
     Method := hmPUT
  else if SameText(Req.Method, 'DELETE') then
     Method := hmDELETE
  else if SameText(Req.Method, 'HEAD') then
     Method := hmHEAD
  else if SameText(Req.Method, 'OPTIONS') then
     Method := hmOPTIONS
  else if SameText(Req.Method, 'PATCH') then
     Method := hmPATCH
  else
     Method := hmUnknown;

  var QueryPos: Integer := Pos('?', Req.Path);
  var PurePath: string;
  if QueryPos > 0 then
    PurePath := Copy(Req.Path, 1, QueryPos - 1)
  else
    PurePath := Req.Path;

  Key := GetEndpointKey(Method, PurePath);

  FillChar(RemoteAddr, SizeOf(RemoteAddr), 0);
  DummyReq := TRequest.Create(INVALID_SOCKET, RemoteAddr, FMaxRequestHederSize, FMaxRequestSize);
  DummyResp := TResponse.Create(INVALID_SOCKET);
  try
    var RawHeaderStr: string := Req.Method + ' ' + Req.Path + ' HTTP/1.1' + #13#10;
    var HasHost: Boolean := False;
    var HasContentLength: Boolean := False;
    for var H in Req.Headers do
    begin
      if (Length(H.Name) > 0) and (H.Name[1] <> ':') then
      begin
        RawHeaderStr := RawHeaderStr + H.Name + ': ' + H.Value + #13#10;
        if SameText(H.Name, 'host') then
           HasHost := True;
        if SameText(H.Name, 'content-length') then
           HasContentLength := True;
      end;
    end;
    if not HasHost and (Req.Host <> '') then
      RawHeaderStr := RawHeaderStr + 'Host: ' + Req.Host + #13#10;
    if not HasContentLength then
      RawHeaderStr := RawHeaderStr + 'Content-Length: ' + IntToStr(Length(Req.Body)) + #13#10;

    RawHeaderStr := RawHeaderStr + #13#10;

    var RawHeaderBytes: TBytes := TEncoding.UTF8.GetBytes(RawHeaderStr);
    var FullRawBytes: TBytes;
    SetLength(FullRawBytes, Length(RawHeaderBytes) + Length(Req.Body));
    if Length(RawHeaderBytes) > 0 then
      Move(RawHeaderBytes[0], FullRawBytes[0], Length(RawHeaderBytes));
    if Length(Req.Body) > 0 then
      Move(Req.Body[0], FullRawBytes[Length(RawHeaderBytes)], Length(Req.Body));

    if Length(FullRawBytes) > 0 then
      DummyReq.AppendData(FullRawBytes[0], Length(FullRawBytes));

    var HasEndpoint: Boolean := False;
    FLock.Enter;
    try
      HasEndpoint := FEndpoints.TryGetValue(Key, Endpoint);
    finally
      FLock.Leave;
    end;

    if HasEndpoint then
    begin
      IsAuth := True;
      if Endpoint.AuthorizationType = atJWTBearer then
      begin
        AuthHeader := Req.GetHeader('authorization');
        if (AuthHeader = '') and (DummyReq.Headers <> nil) then
          AuthHeader := DummyReq.Headers.Authorization;
        Logger.Info('[LOG-H3-AUTH] Raw AuthHeader=' + AuthHeader);
        AuthHeader := FJWTManager.ExtractTokenFromAuthHeader(AuthHeader);
        Logger.Info('[LOG-H3-AUTH] Extracted Token=' + AuthHeader);

        if Length(AuthHeader) > 0 then
        begin
          IsAuth := FJWTManager.ValidateToken(AuthHeader, JWT);
          Logger.Info(Format('[LOG-H3-AUTH] ValidateToken result=%s', [BoolToStr(IsAuth, True)]));
          if Assigned(JWT) then
             JWT.Free;
        end
        else
          IsAuth := False;


        if not IsAuth then
          DummyResp.SetUnauthorized();
      end;

      if IsAuth then
      begin
        if Assigned(Endpoint.Handler) then
          Endpoint.Handler(Self, DummyReq, DummyResp, Self)
        else if Assigned(Endpoint.HandlerProc) then
          Endpoint.HandlerProc(Self, DummyReq, DummyResp, Self);
      end;
    end
    else
      DummyResp.SetNotFound('The requested resource could not be found.');

    Resp.StatusCode := Ord(DummyResp.Status);
    Resp.AddHeader('Alt-Svc', Format('h3=":%d"; ma=86400', [FPort]));

    if DummyResp.Headers <> nil then
    begin
      for var I: Integer := 0 to DummyResp.Headers.Count - 1 do
      begin
        var HeaderStr: string := DummyResp.Headers[I];
        var ColonPos: Integer := Pos(':', HeaderStr);
        if ColonPos > 0 then
        begin
          var HName: string := Trim(Copy(HeaderStr, 1, ColonPos - 1));
          var HValue: string := Trim(Copy(HeaderStr, ColonPos + 1, MaxInt));
          if not SameText(HName, 'Content-Length') and not SameText(HName, 'Content-Type') then
            Resp.AddHeader(HName, HValue);
        end;
      end;
    end;

    var BodyBytes: TBytes := DummyResp.GetBodyBytes;
    if Length(BodyBytes) > 0 then
      Resp.SetBodyBytes(BodyBytes, DummyResp.ContentType);
  finally
    DummyReq.Free;
    DummyResp.Free;
  end;
end;

procedure TGHttpsServerIOCP.RegisterEndpoint(const APath: string; AMethod: THttpMethod;
                                            AHandler: TEndpointEvent;
                                            AAuthorizationType: TAuthorizationType = atNone );
var
  Key: string;
begin
  if not Assigned(AHandler) then
    raise Exception.Create('The handler for the endpoint cannot be nil.');
  Key := GetEndpointKey(AMethod, APath);
  FLock.Enter;
  try
    if FEndpoints.ContainsKey(Key) then
      raise Exception.CreateFmt('Endpoint "%s" is already registered.', [Key]);
    var LEndpoint := TEndpointItem.Create(APath, AMethod, AHandler, nil, AAuthorizationType,self);
    FEndpoints.Add(Key, LEndpoint);
    Logger.Info(Format('Registered endpoint: %s', [Key]));
  finally
    FLock.Leave;
  end;
end;

procedure TGHttpsServerIOCP.RegisterEndpointProc(const APath: string;
                                                AMethod: THttpMethod;
                                                AHandler: TEndpointEventProc;
                                                AAuthorizationType: TAuthorizationType);
var
  Key: string;
begin
  if not Assigned(AHandler) then
    raise Exception.Create('The handler for the endpoint cannot be nil.');
  Key := GetEndpointKey(AMethod, APath);
  FLock.Enter;
  try
    if FEndpoints.ContainsKey(Key) then
      raise Exception.CreateFmt('Endpoint "%s" is already registered.', [Key]);

    var LEndpoint := TEndpointItem.Create(APath, AMethod, nil, AHandler, AAuthorizationType,  self);
    FEndpoints.Add(Key, LEndpoint);
    Logger.Info(Format('Registered endpoint: %s', [Key]));
  finally
    FLock.Leave;
  end;
end;

procedure TGHttpsServerIOCP.RegisterWebSocketRoute(const APath: string);
begin
  RegisterWebSocketRoute(APath, nil);
end;

procedure TGHttpsServerIOCP.RegisterWebSocketRoute(const APath: string; AOnMessage: TWebSocketMessageProc);
begin
  FLock.Enter;
  try
    var CleanPath := APath.ToLower;
    FWebSocketRoutes.AddOrSetValue(CleanPath, True);
    if Assigned(AOnMessage) then
      FWebSocketRouteHandlers.AddOrSetValue(CleanPath, AOnMessage);
    Logger.Info(Format('Registered WebSocket route: %s (HasCustomHandler: %s)', [APath, BoolToStr(Assigned(AOnMessage), True)]));
  finally
    FLock.Leave;
  end;
end;

end.
