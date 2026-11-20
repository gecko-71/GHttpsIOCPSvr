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
unit GIocpWorkerEngine;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.Math,
  System.StrUtils,
  System.SyncObjs,
  System.Generics.Collections,
  GLogger,
  GWebSocket,
  GRequest,
  GResponse,
  OverlappedExPool,
  WinApiAdditions,
  GHttpsServerTypes,
  GSchannelTlsManager,
  GIpSecurityAndCors,
  GWebSocketBridge;

const
  RESPONSE_CHUNK_SIZE = 16384;

type
  TIocpProcessHttpRequestProc = reference to procedure(OverlappedEx: POverlappedEx);
  TIocpWebSocketRouteMessageProc = reference to procedure(const HandlerIntf: IInterface; Session: TWebSocketSession; const MsgStr: string; Opcode: TWebSocketOpcode);
  TIocpWebSocketRawRouteMessageProc = reference to procedure(const HandlerIntf: IInterface; Session: TWebSocketSession; DataPtr: PByte; DataLen: Integer; Opcode: TWebSocketOpcode);
  TIocpWebSocketGlobalMessageProc = reference to function(Session: TWebSocketSession; const MsgStr: string; Opcode: TWebSocketOpcode): Boolean;

  TIocpWorkerEngine = class
  private
    FListenSocket: TSocket;
    FListenSocketHTTP: TSocket;
    FCompletionPort: THandle;
    FPort: Word;
    FHttpsPort: Word;
    FHttpPort: Word;
    FBindAddress: string;
    FHttpBindAddress: string;
    FHttpsBindAddress: string;
    FHttp3BindAddress: string;
    FProtocolMode: TServerProtocolMode;
    FHttpAction: THttpActionOnDualMode;
    FRunning: Boolean;
    FWorkerThreads: TList<THandle>;
    FActiveConnections: Int64;
    FMaxConnections: Integer;
    FOverlappedPool: TOverlappedExPool;
    FMaxRequestHederSize: Integer;
    FMaxRequestSize: Int64;
    FMaxResponseSize: Int64;
    FChunkSize: Integer;
    FMonitorRun: Boolean;
    FMonitorThread: THandle;
    FRejectNewConnections: LongInt;
    FPendingHttpsAccepts: LongInt;
    FPendingHttpAccepts: LongInt;
    FTargetAcceptCount: Integer;
    FRequestsPerSecondCounter: LongInt;
    FMaxRequestsPerSecond: Integer;
    FThrottleNewConnections: LongInt;
    FActiveOverlapped: TDictionary<POverlappedEx, Byte>;
    FActiveOverlappedLock: TCriticalSection;
    FWorkerThreadCount: Integer;
    FEnableKeepAlive: Boolean;
    FKeepAliveTimeoutMs: Cardinal;
    FMaxKeepAliveRequests: Integer;
    FAllowedFileExtensions: TStringList;
    FBlockedMimeTypes: TStringList;
    FTlsManager: TSchannelTlsManager;
    FIpSecurity: TIpSecurityTracker;
    FWebSocketBridge: TWebSocketServerBridge;
    FOnProcessHttpRequest: TIocpProcessHttpRequestProc;
    FOnWebSocketRouteMessage: TIocpWebSocketRouteMessageProc;
    FOnWebSocketRawRouteMessage: TIocpWebSocketRawRouteMessageProc;
    FOnWebSocketGlobalMessage: TIocpWebSocketGlobalMessageProc;
  public
    constructor Create(
      APort: Word;
      AMaxConnections: Integer;
      AMaxRequestsPerSecond: Integer;
      AMaxRequestHederSize: Int64;
      AMaxRequestSize: Int64;
      AMaxResponseSize: Int64;
      AChunkSize: Integer;
      AMinFreeMemoryMb: Cardinal;
      AMaxMemoryLoadPercent: Byte;
      AMonitorRun: Boolean;
      AEnableKeepAlive: Boolean;
      AHttpPort: Word;
      AHttpAction: THttpActionOnDualMode;
      AWorkerThreadCount: Integer;
      ATlsManager: TSchannelTlsManager;
      AIpSecurity: TIpSecurityTracker
    );
    destructor Destroy; override;
    procedure CleanupConnectionWithReason(AOverlapped: POverlappedEx; const AReason: string);
    procedure CleanupOverlappedEx(OverlappedEx: POverlappedEx);
    function IsRequestComplete(Request: TRequest): Boolean;
    function InitializeRequestProcessing(OverlappedEx: POverlappedEx): Boolean;
    function InitializeWinsock: Boolean;
    function ResolveBindAddr(const AAddress: string; out AValue: u_long): Boolean;
    function EffectiveHttpBindAddress: string;
    function EffectiveHttpsBindAddress: string;
    function EffectiveHttp3BindAddress: string;
    function CreateListenSocket: Boolean;
    function CreateHttpListenSocket: Boolean;
    function IssueWSARecvEx(OverlappedEx: POverlappedEx; out SyncBytes: DWORD): Integer;
    function IssueWSARecv(OverlappedEx: POverlappedEx): Boolean;
    procedure ContinueReadingRequest(OverlappedEx: POverlappedEx);
    function CreateCompletionPort: Boolean;
    function CreateWorkerThreads: Boolean;
    procedure CleanupWinsock;
    procedure AdjustPendingAcceptCount(ListenSocket: TSocket; Delta: Integer);
    procedure HandleFailedAccept(OverlappedEx: POverlappedEx);
    function AcceptConnection2(Socket: TSocket): Boolean;
    procedure HandleHttpsHandshake(ClientSocket: TSocket; const AClientIP: string = '');
    procedure HandleHttpPlainConnection(ClientSocket: TSocket; const AClientIP: string = '');
    procedure ContinueSendingResponse(OverlappedEx: POverlappedEx);
    function CompletionPortPtr: PHandle;
    function ActiveConnectionsPtr: PInt64;
    function RunningPtr: PBoolean;
    function RejectNewConnectionsPtr: PLongInt;
    function MaxConnectionsPtr: PInteger;
    function RequestsPerSecondCounterPtr: PLongInt;
    function MaxRequestHederSizePtr: PInteger;
    function MaxRequestSizePtr: PInt64;
    procedure ResetPendingAccepts;
    class function WorkerThreadProc(Parameter: Pointer): DWORD; stdcall; static;
    class function MonitorThreadProc(Parameter: Pointer): DWORD; stdcall; static;
    property ListenSocket: TSocket read FListenSocket write FListenSocket;
    property ListenSocketHTTP: TSocket read FListenSocketHTTP write FListenSocketHTTP;
    property CompletionPort: THandle read FCompletionPort write FCompletionPort;
    property Port: Word read FPort write FPort;
    property HttpsPort: Word read FHttpsPort write FHttpsPort;
    property HttpPort: Word read FHttpPort write FHttpPort;
    property BindAddress: string read FBindAddress write FBindAddress;
    property HttpBindAddress: string read FHttpBindAddress write FHttpBindAddress;
    property HttpsBindAddress: string read FHttpsBindAddress write FHttpsBindAddress;
    property Http3BindAddress: string read FHttp3BindAddress write FHttp3BindAddress;
    property ProtocolMode: TServerProtocolMode read FProtocolMode write FProtocolMode;
    property HttpAction: THttpActionOnDualMode read FHttpAction write FHttpAction;
    property Running: Boolean read FRunning write FRunning;
    property WorkerThreads: TList<THandle> read FWorkerThreads;
    property ActiveConnections: Int64 read FActiveConnections write FActiveConnections;
    property MaxConnections: Integer read FMaxConnections write FMaxConnections;
    property OverlappedPool: TOverlappedExPool read FOverlappedPool;
    property MaxRequestHederSize: Integer read FMaxRequestHederSize write FMaxRequestHederSize;
    property MaxRequestSize: Int64 read FMaxRequestSize write FMaxRequestSize;
    property MaxResponseSize: Int64 read FMaxResponseSize write FMaxResponseSize;
    property ChunkSize: Integer read FChunkSize write FChunkSize;
    property MonitorRun: Boolean read FMonitorRun write FMonitorRun;
    property MonitorThread: THandle read FMonitorThread write FMonitorThread;
    property RejectNewConnections: LongInt read FRejectNewConnections write FRejectNewConnections;
    property PendingHttpsAccepts: LongInt read FPendingHttpsAccepts write FPendingHttpsAccepts;
    property PendingHttpAccepts: LongInt read FPendingHttpAccepts write FPendingHttpAccepts;
    property TargetAcceptCount: Integer read FTargetAcceptCount write FTargetAcceptCount;
    property RequestsPerSecondCounter: LongInt read FRequestsPerSecondCounter write FRequestsPerSecondCounter;
    property MaxRequestsPerSecond: Integer read FMaxRequestsPerSecond write FMaxRequestsPerSecond;
    property ThrottleNewConnections: LongInt read FThrottleNewConnections write FThrottleNewConnections;
    property ActiveOverlapped: TDictionary<POverlappedEx, Byte> read FActiveOverlapped;
    property ActiveOverlappedLock: TCriticalSection read FActiveOverlappedLock;
    property WorkerThreadCount: Integer read FWorkerThreadCount write FWorkerThreadCount;
    property EnableKeepAlive: Boolean read FEnableKeepAlive write FEnableKeepAlive;
    property KeepAliveTimeoutMs: Cardinal read FKeepAliveTimeoutMs write FKeepAliveTimeoutMs;
    property MaxKeepAliveRequests: Integer read FMaxKeepAliveRequests write FMaxKeepAliveRequests;
    property AllowedFileExtensions: TStringList read FAllowedFileExtensions;
    property BlockedMimeTypes: TStringList read FBlockedMimeTypes;
    property WebSocketBridge: TWebSocketServerBridge read FWebSocketBridge write FWebSocketBridge;
    property OnProcessHttpRequest: TIocpProcessHttpRequestProc read FOnProcessHttpRequest write FOnProcessHttpRequest;
    property OnWebSocketRouteMessage: TIocpWebSocketRouteMessageProc read FOnWebSocketRouteMessage write FOnWebSocketRouteMessage;
    property OnWebSocketRawRouteMessage: TIocpWebSocketRawRouteMessageProc read FOnWebSocketRawRouteMessage write FOnWebSocketRawRouteMessage;
    property OnWebSocketGlobalMessage: TIocpWebSocketGlobalMessageProc read FOnWebSocketGlobalMessage write FOnWebSocketGlobalMessage;
  end;

implementation

constructor TIocpWorkerEngine.Create(
  APort: Word;
  AMaxConnections: Integer;
  AMaxRequestsPerSecond: Integer;
  AMaxRequestHederSize: Int64;
  AMaxRequestSize: Int64;
  AMaxResponseSize: Int64;
  AChunkSize: Integer;
  AMinFreeMemoryMb: Cardinal;
  AMaxMemoryLoadPercent: Byte;
  AMonitorRun: Boolean;
  AEnableKeepAlive: Boolean;
  AHttpPort: Word;
  AHttpAction: THttpActionOnDualMode;
  AWorkerThreadCount: Integer;
  ATlsManager: TSchannelTlsManager;
  AIpSecurity: TIpSecurityTracker);
var
  InitialPoolSize: Integer;
begin
  inherited Create;
  FTlsManager := ATlsManager;
  FIpSecurity := AIpSecurity;
  FListenSocket := INVALID_SOCKET;
  FListenSocketHTTP := INVALID_SOCKET;
  FCompletionPort := 0;
  FPort := APort;
  FHttpsPort := APort;
  FHttpPort := AHttpPort;
  FBindAddress := '';
  FHttpBindAddress := '';
  FHttpsBindAddress := '';
  FHttp3BindAddress := '';
  FHttpAction := AHttpAction;
  if (APort > 0) and (AHttpPort > 0) then
    FProtocolMode := pmDualHttpAndHttps
  else if (APort = 0) and (AHttpPort > 0) then
    FProtocolMode := pmHttpOnly
  else
    FProtocolMode := pmHttpsOnly;
  FRunning := False;
  FWorkerThreads := TList<THandle>.Create;
  FActiveConnections := 0;
  FMaxConnections := AMaxConnections;
  FMaxRequestsPerSecond := AMaxRequestsPerSecond;
  FMaxRequestHederSize := AMaxRequestHederSize;
  FMaxRequestSize := AMaxRequestSize;
  FMaxResponseSize := AMaxResponseSize;
  FChunkSize := AChunkSize;
  FMonitorRun := AMonitorRun;
  FMonitorThread := 0;
  FRejectNewConnections := 0;
  FPendingHttpsAccepts := 0;
  FPendingHttpAccepts := 0;
  FTargetAcceptCount := 0;
  FRequestsPerSecondCounter := 0;
  FThrottleNewConnections := 0;
  FWorkerThreadCount := AWorkerThreadCount;
  FEnableKeepAlive := AEnableKeepAlive;
  FKeepAliveTimeoutMs := 5000;
  FMaxKeepAliveRequests := 1000;
  InitialPoolSize := AMaxConnections div 4;
  if InitialPoolSize > 256 then
    InitialPoolSize := 256;
  FOverlappedPool := TOverlappedExPool.Create(InitialPoolSize, AMaxConnections, AMinFreeMemoryMb, AMaxMemoryLoadPercent);
  FActiveOverlapped := TDictionary<POverlappedEx, Byte>.Create;
  FActiveOverlappedLock := TCriticalSection.Create;
  FAllowedFileExtensions := TStringList.Create;
  FBlockedMimeTypes := TStringList.Create;
end;

destructor TIocpWorkerEngine.Destroy;
begin
  FreeAndNil(FAllowedFileExtensions);
  FreeAndNil(FBlockedMimeTypes);
  FreeAndNil(FActiveOverlapped);
  FreeAndNil(FActiveOverlappedLock);
  FreeAndNil(FOverlappedPool);
  FreeAndNil(FWorkerThreads);
  inherited Destroy;
end;

function TIocpWorkerEngine.CompletionPortPtr: PHandle;
begin
  Result := @FCompletionPort;
end;

function TIocpWorkerEngine.ActiveConnectionsPtr: PInt64;
begin
  Result := @FActiveConnections;
end;

function TIocpWorkerEngine.RunningPtr: PBoolean;
begin
  Result := @FRunning;
end;

function TIocpWorkerEngine.RejectNewConnectionsPtr: PLongInt;
begin
  Result := @FRejectNewConnections;
end;

function TIocpWorkerEngine.MaxConnectionsPtr: PInteger;
begin
  Result := @FMaxConnections;
end;

function TIocpWorkerEngine.RequestsPerSecondCounterPtr: PLongInt;
begin
  Result := @FRequestsPerSecondCounter;
end;

function TIocpWorkerEngine.MaxRequestHederSizePtr: PInteger;
begin
  Result := @FMaxRequestHederSize;
end;

function TIocpWorkerEngine.MaxRequestSizePtr: PInt64;
begin
  Result := @FMaxRequestSize;
end;

procedure TIocpWorkerEngine.ResetPendingAccepts;
begin
  InterlockedExchange(FPendingHttpsAccepts, 0);
  InterlockedExchange(FPendingHttpAccepts, 0);
end;

procedure TIocpWorkerEngine.CleanupConnectionWithReason(AOverlapped: POverlappedEx; const AReason: string);
var
  WasActive: Boolean;
  WsSession: TWebSocketSession;
  ClientIP: string;
  IsAbrupt: Boolean;
begin
  if AOverlapped = nil then
    Exit;

  FActiveOverlappedLock.Enter;
  try
    WasActive := FActiveOverlapped.ContainsKey(AOverlapped);
    if WasActive then
      FActiveOverlapped.Remove(AOverlapped);
  finally
    FActiveOverlappedLock.Leave;
  end;
  if not WasActive then
    Exit;

  if AOverlapped^.OpType in [otWebSocketRead, otWebSocketWrite] then
  begin
    WsSession := TWebSocketSession(AOverlapped^.WebSocketSession);
    if Assigned(WsSession) and Assigned(FWebSocketBridge) then
      FWebSocketBridge.CleanupWebSocketSession(WsSession, AReason);
    SetLength(AOverlapped^.ClientReceiveBuffer, 0);
    AOverlapped^.WebSocketSession := nil;
    FOverlappedPool.Release(AOverlapped);
    Exit;
  end;
  try
    if AOverlapped^.Socket <> INVALID_SOCKET then
    begin
      InterlockedDecrement64(FActiveConnections);
      ClientIP := string(PAnsiChar(@AOverlapped^.ClientIP[0]));
      if ClientIP <> '' then
        FIpSecurity.TrackIPDisconnect(ClientIP);
      IsAbrupt := ContainsText(AReason, 'interrupted') or ContainsText(AReason, 'aborted') or ContainsText(AReason, 'reset');
      if AOverlapped^.SSLContextValid or (AOverlapped^.OpenSSLHandle <> nil) then
      begin
        if AOverlapped^.SSLContextValid and
           (not ContainsText(AReason, 'SSL shutdown completed')) and
           (not IsAbrupt) then
        begin
          try
            FTlsManager.PerformGracefulSSLShutdown(AOverlapped^);
          except
            on E: Exception do
              Logger.Info('Error SSL shutdown w cleanup: ' + E.Message);
          end;
        end;
        FTlsManager.ReleaseConnectionContext(AOverlapped^);
      end;
      try
        if not IsAbrupt then
          shutdown(AOverlapped^.Socket, SD_SEND)
        else
          shutdown(AOverlapped^.Socket, SD_BOTH);
      except
        on E: Exception do
          Logger.Error('TCP shutdown error: ' + E.Message);
      end;
      closesocket(AOverlapped^.Socket);
      AOverlapped^.Socket := INVALID_SOCKET;
    end;
    CleanupOverlappedEx(AOverlapped);
    FOverlappedPool.Release(AOverlapped);
  except
    on E: Exception do
      Logger.Error('Error in CleanupConnectionWithReason: ' + E.Message);
  end;
end;

procedure TIocpWorkerEngine.CleanupOverlappedEx(OverlappedEx: POverlappedEx);
var
  Req: TRequest;
  Resp: TResponse;
begin
  if not Assigned(OverlappedEx) then
    Exit;
  try
    Req := TRequest(InterlockedExchangePointer(Pointer(OverlappedEx^.Request), nil));
    if Assigned(Req) then
      Req.Free;

    Resp := TResponse(InterlockedExchangePointer(Pointer(OverlappedEx^.Response), nil));
    if Assigned(Resp) then
      Resp.Free;

    Resp := TResponse(InterlockedExchangePointer(Pointer(OverlappedEx^.CachedResponse), nil));
    if Assigned(Resp) then
      Resp.Free;

    OverlappedEx^.SSLOutputSize := 0;
    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
    if Assigned(FTlsManager) then
      FTlsManager.ReleaseConnectionContext(OverlappedEx^);
  except
    on E: Exception do
      Logger.Error('Error in CleanupOverlappedEx [%s]: %s', [E.ClassName, E.Message]);
  end;
end;

function TIocpWorkerEngine.IsRequestComplete(Request: TRequest): Boolean;
begin
  Result := Assigned(Request) and Request.IsComplete and not Request.HasError;
end;

function TIocpWorkerEngine.InitializeRequestProcessing(OverlappedEx: POverlappedEx): Boolean;
var
  RemoteAddr: TSockAddrIn;
  ClientIP: string;
  OldReq: TObject;
begin
  Result := False;
  try
    if FRejectNewConnections = 1 then
    begin
      CleanupConnectionWithReason(OverlappedEx, 'Server overloaded: lack of resources');
      Exit;
    end;
    OldReq := TObject(InterlockedExchangePointer(Pointer(OverlappedEx^.Request), nil));
    if Assigned(OldReq) then
      OldReq.Free;
    ZeroMemory(@RemoteAddr, SizeOf(RemoteAddr));
    ClientIP := string(PAnsiChar(@OverlappedEx^.ClientIP[0]));
    if ClientIP <> '' then
      RemoteAddr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(ClientIP)));
    OverlappedEx^.Request := TRequest.Create(
      OverlappedEx^.Socket,
      RemoteAddr,
      FMaxRequestHederSize,
      FMaxRequestSize,
      vlModerate,
      False
    );
    if Assigned(FAllowedFileExtensions) and (FAllowedFileExtensions.Count > 0) then
      OverlappedEx^.Request.AllowedFileExtensions.Assign(FAllowedFileExtensions);
    if Assigned(FBlockedMimeTypes) and (FBlockedMimeTypes.Count > 0) then
      OverlappedEx^.Request.BlockedMimeTypes.Assign(FBlockedMimeTypes);
    OverlappedEx^.Request.ClientCertificate := OverlappedEx^.ClientCertInfo;
    Result := True;
  except
    on E: Exception do
    begin
      Logger.Error('Error initializing request processing: ' + E.Message);
      CleanupConnectionWithReason(OverlappedEx, 'Error initializing request processing: ' + E.Message);
    end;
  end;
end;

function TIocpWorkerEngine.InitializeWinsock: Boolean;
var
  WSAData: TWSAData;
begin
  Result := WSAStartup(MAKEWORD(2, 2), WSAData) = 0;
end;

function TIocpWorkerEngine.ResolveBindAddr(const AAddress: string; out AValue: u_long): Boolean;
begin
  AValue := u_long(INADDR_ANY);
  if AAddress = '' then
    Exit(True);
  if SameText(AAddress, 'localhost') then
  begin
    AValue := inet_addr('127.0.0.1');
    Exit(True);
  end;
  AValue := inet_addr(PAnsiChar(AnsiString(AAddress)));
  Result := (AValue <> u_long(INADDR_NONE)) or (AAddress = '255.255.255.255');
end;

function TIocpWorkerEngine.EffectiveHttpBindAddress: string;
begin
  if FHttpBindAddress <> '' then
    Result := FHttpBindAddress
  else
    Result := FBindAddress;
end;

function TIocpWorkerEngine.EffectiveHttpsBindAddress: string;
begin
  if FHttpsBindAddress <> '' then
    Result := FHttpsBindAddress
  else
    Result := FBindAddress;
end;

function TIocpWorkerEngine.EffectiveHttp3BindAddress: string;
begin
  if FHttp3BindAddress <> '' then
    Result := FHttp3BindAddress
  else
    Result := EffectiveHttpsBindAddress;
end;

function TIocpWorkerEngine.CreateListenSocket: Boolean;
const
  SO_EXCLUSIVEADDRUSE = Integer(not SO_REUSEADDR);
var
  SockAddr: TSockAddr;
  SockAddrIn: TSockAddrIn absolute SockAddr;
  OptVal: Integer;
  ErrCode: Integer;
  BindValue: u_long;
begin
  Result := False;
  if not ResolveBindAddr(EffectiveHttpsBindAddress, BindValue) then
  begin
    Logger.Error('CRITICAL ERROR: Invalid HTTPS bind address: %s', [EffectiveHttpsBindAddress]);
    Exit;
  end;
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
  SockAddrIn.sin_addr.S_addr := BindValue;
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

function TIocpWorkerEngine.CreateHttpListenSocket: Boolean;
const
  SO_EXCLUSIVEADDRUSE = Integer(not SO_REUSEADDR);
var
  SockAddr: TSockAddr;
  SockAddrIn: TSockAddrIn absolute SockAddr;
  OptVal: Integer;
  ErrCode: Integer;
  BindValue: u_long;
begin
  Result := False;
  if FHttpPort = 0 then
    Exit(True);
  if not ResolveBindAddr(EffectiveHttpBindAddress, BindValue) then
  begin
    Logger.Error('CRITICAL ERROR: Invalid HTTP bind address: %s', [EffectiveHttpBindAddress]);
    Exit;
  end;

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
  SockAddrIn.sin_addr.S_addr := BindValue;
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

function TIocpWorkerEngine.IssueWSARecvEx(OverlappedEx: POverlappedEx; out SyncBytes: DWORD): Integer;
var
  WSABuf: TWSABUF;
  Flags: DWORD;
begin
  WSABuf.len := SizeOf(OverlappedEx^.Buffer);
  WSABuf.buf := @OverlappedEx^.Buffer[0];
  Flags := 0;
  SyncBytes := 0;
  ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
  if WSARecv(OverlappedEx^.Socket, @WSABuf, 1, SyncBytes, Flags,
             @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError = WSA_IO_PENDING then
      Result := 0
    else
      Result := -1;
    Exit;
  end;
  if OverlappedEx^.SkipIOCP then
    Result := 1
  else
    Result := 0;
end;

function TIocpWorkerEngine.IssueWSARecv(OverlappedEx: POverlappedEx): Boolean;
var
  SyncBytes: DWORD;
  Res: Integer;
begin
  Res := IssueWSARecvEx(OverlappedEx, SyncBytes);
  if Res = 1 then
  begin
    PostQueuedCompletionStatus(FCompletionPort, SyncBytes, ULONG_PTR(OverlappedEx^.Socket), POverlapped(OverlappedEx));
    Result := True;
  end
  else
    Result := (Res = 0);
end;

procedure TIocpWorkerEngine.ContinueReadingRequest(OverlappedEx: POverlappedEx);
var
  LastErr: Integer;
begin
  try
    if not Assigned(OverlappedEx^.Request) then
    begin
      Logger.Error('Request object not initialized');
      CleanupConnectionWithReason(OverlappedEx, 'Request object not initialized in ContinueReadingRequest');
      Exit;
    end;
    if IsRequestComplete(OverlappedEx^.Request) then
    begin
      Logger.Info('Request is complete, processing...');
      if Assigned(FOnProcessHttpRequest) then
        FOnProcessHttpRequest(OverlappedEx);
      Exit;
    end;
    if not OverlappedEx^.Request.CanAcceptMoreData then
    begin
      if OverlappedEx^.Request.HasError then
        Logger.Error('Request has error: ' + OverlappedEx^.Request.ErrorMessage);
      if Assigned(FOnProcessHttpRequest) then
        FOnProcessHttpRequest(OverlappedEx);
      Exit;
    end;
    if not IssueWSARecv(OverlappedEx) then
    begin
      LastErr := WSAGetLastError;
      if (LastErr = WSAECONNRESET) or (LastErr = 10054) then
        Logger.Error('Error continuing request read: 10054 (WSAECONNRESET: Connection forcibly closed or reset by the remote peer/client)')
      else
        Logger.Error('Error continuing request read: ' + IntToStr(LastErr));
      CleanupConnectionWithReason(OverlappedEx, 'Error continuing request read');
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Exception in ContinueReadingRequest: ' + E.Message);
      CleanupConnectionWithReason(OverlappedEx, 'Exception in ContinueReadingRequest: ' + E.Message);
    end;
  end;
end;

function TIocpWorkerEngine.CreateCompletionPort: Boolean;
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

function TIocpWorkerEngine.CreateWorkerThreads: Boolean;
var
  i: Integer;
  ThreadHandle: THandle;
  ThreadId: DWORD;
  TargetCount: Integer;
begin
  IsMultiThread := True;
  Result := True;
  TargetCount := FWorkerThreadCount;
  if TargetCount <= 0 then
    TargetCount := WORKER_THREAD_COUNT;

  for i := 0 to TargetCount - 1 do
  begin
    ThreadHandle := CreateThread(nil, 0, @TIocpWorkerEngine.WorkerThreadProc, Self, 0, ThreadId);
    if ThreadHandle <> 0 then
      FWorkerThreads.Add(ThreadHandle)
    else
    begin
      Result := False;
      Break;
    end;
  end;
end;

procedure TIocpWorkerEngine.CleanupWinsock;
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

  FTlsManager.CleanupHandles;

  Logger.Info('Calling WSACleanup...');
  WSACleanup;
  Logger.Info('CleanupWinsock completed');
end;

procedure TIocpWorkerEngine.AdjustPendingAcceptCount(ListenSocket: TSocket; Delta: Integer);
begin
  if ListenSocket = INVALID_SOCKET then
    Exit;
  if ListenSocket = FListenSocket then
    InterlockedExchangeAdd(FPendingHttpsAccepts, Delta)
  else if ListenSocket = FListenSocketHTTP then
    InterlockedExchangeAdd(FPendingHttpAccepts, Delta);
end;

procedure TIocpWorkerEngine.HandleFailedAccept(OverlappedEx: POverlappedEx);
var
  ListenSocket: TSocket;
  AcceptedSocket: TSocket;
begin
  if OverlappedEx = nil then
    Exit;
  ListenSocket := OverlappedEx^.Socket;
  AcceptedSocket := OverlappedEx^.ClientSocket;
  OverlappedEx^.ClientSocket := INVALID_SOCKET;
  if AcceptedSocket <> INVALID_SOCKET then
    closesocket(AcceptedSocket);
  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.Remove(OverlappedEx);
  finally
    FActiveOverlappedLock.Leave;
  end;
  FOverlappedPool.Release(OverlappedEx);
  AdjustPendingAcceptCount(ListenSocket, -1);
  if FRunning and (ListenSocket <> INVALID_SOCKET) then
    AcceptConnection2(ListenSocket);
end;

function TIocpWorkerEngine.AcceptConnection2(Socket: TSocket): Boolean;
var
  OverlappedEx: POverlappedEx;
  ClientSocket: TSocket;
  BytesReceived: DWORD;
  LastErr: Integer;
  Retries: Integer;
begin
  Result := False;
  if (not FRunning) or (Socket = INVALID_SOCKET) then
    Exit;
  Retries := 0;
  while FRunning and (Retries < 8) do
  begin
    Inc(Retries);
    OverlappedEx := FOverlappedPool.Acquire;
    if OverlappedEx = nil then
    begin
      Logger.Error('Failed to accept connection: the OverlappedEx pool is full or out of memory.');
      Exit;
    end;
    FActiveOverlappedLock.Enter;
    try
      FActiveOverlapped.AddOrSetValue(OverlappedEx, 1);
    finally
      FActiveOverlappedLock.Leave;
    end;
    OverlappedEx^.OpType := otAccept;
    OverlappedEx^.Socket := Socket;
    ClientSocket := WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, WSA_FLAG_OVERLAPPED);
    if ClientSocket = INVALID_SOCKET then
    begin
      FActiveOverlappedLock.Enter;
      try
        FActiveOverlapped.Remove(OverlappedEx);
      finally
        FActiveOverlappedLock.Leave;
      end;
      FOverlappedPool.Release(OverlappedEx);
      Continue;
    end;
    OverlappedEx^.ClientSocket := ClientSocket;
    ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
    AdjustPendingAcceptCount(Socket, 1);
    if not AcceptEx(Socket, ClientSocket, @OverlappedEx^.Buffer[0], 0,
                    SizeOf(TSockAddrIn) + 16, SizeOf(TSockAddrIn) + 16,
                    BytesReceived, @OverlappedEx^.Overlapped) then
    begin
      LastErr := WSAGetLastError;
      if LastErr <> ERROR_IO_PENDING then
      begin
        AdjustPendingAcceptCount(Socket, -1);
        closesocket(ClientSocket);
        FActiveOverlappedLock.Enter;
        try
          FActiveOverlapped.Remove(OverlappedEx);
        finally
          FActiveOverlappedLock.Leave;
        end;
        FOverlappedPool.Release(OverlappedEx);
        if (LastErr = WSAENOTSOCK) or (LastErr = WSAEINVAL) then
          Exit;
        Continue;
      end;
    end;
    Result := True;
    Exit;
  end;
end;

procedure TIocpWorkerEngine.HandleHttpsHandshake(ClientSocket: TSocket; const AClientIP: string);
var
  OverlappedEx: POverlappedEx;
  OptNoDelay: Integer;
  AnsiIP: AnsiString;
  LReason: string;
begin
  OptNoDelay := 1;
  setsockopt(ClientSocket, IPPROTO_TCP, TCP_NODELAY, @OptNoDelay, SizeOf(OptNoDelay));

  CreateIoCompletionPort(ClientSocket, FCompletionPort, ULONG_PTR(ClientSocket), 0);
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to start handshake for socket %d: the OverlappedEx pool is full.', [ClientSocket]);
    InterlockedDecrement64(FActiveConnections);
    if AClientIP <> '' then
      FIpSecurity.TrackIPDisconnect(AClientIP);
    closesocket(ClientSocket);
    Exit;
  end;

  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.AddOrSetValue(OverlappedEx, 1);
  finally
    FActiveOverlappedLock.Leave;
  end;

  OverlappedEx^.IsTLS := True;
  OverlappedEx^.SSLStreamSizesValid := False;
  OverlappedEx^.SkipIOCP := SetFileCompletionNotificationModes(ClientSocket, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
  OverlappedEx^.ListenerPort := FHttpsPort;
  OverlappedEx^.OpType := otSSLHandshake;
  OverlappedEx^.Socket := ClientSocket;
  OverlappedEx^.SSLHandshakeStep := 0;
  OverlappedEx^.SSLNeedsMoreData := True;
  FillChar(OverlappedEx^.ClientIP, SizeOf(OverlappedEx^.ClientIP), 0);
  if AClientIP <> '' then
  begin
    AnsiIP := AnsiString(AClientIP);
    Move(AnsiIP[1], OverlappedEx^.ClientIP[0], Min(Length(AnsiIP), SizeOf(OverlappedEx^.ClientIP) - 1));
  end;

  if not IssueWSARecv(OverlappedEx) then
  begin
    LReason := 'Failed to start SSL handshake: ' + IntToStr(WSAGetLastError);
    Logger.Error(LReason);
    CleanupConnectionWithReason(OverlappedEx, LReason);
  end;
end;

procedure TIocpWorkerEngine.HandleHttpPlainConnection(ClientSocket: TSocket; const AClientIP: string);
var
  OverlappedEx: POverlappedEx;
  OptNoDelay: Integer;
  AnsiIP: AnsiString;
begin
  OptNoDelay := 1;
  setsockopt(ClientSocket, IPPROTO_TCP, TCP_NODELAY, @OptNoDelay, SizeOf(OptNoDelay));

  CreateIoCompletionPort(ClientSocket, FCompletionPort, ULONG_PTR(ClientSocket), 0);
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to start HTTP connection for socket %d: the OverlappedEx pool is full.', [ClientSocket]);
    InterlockedDecrement64(FActiveConnections);
    if AClientIP <> '' then
      FIpSecurity.TrackIPDisconnect(AClientIP);
    closesocket(ClientSocket);
    Exit;
  end;

  FActiveOverlappedLock.Enter;
  try
    FActiveOverlapped.AddOrSetValue(OverlappedEx, 1);
  finally
    FActiveOverlappedLock.Leave;
  end;

  OverlappedEx^.IsTLS := False;
  OverlappedEx^.SkipIOCP := SetFileCompletionNotificationModes(ClientSocket, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
  OverlappedEx^.ListenerPort := FHttpPort;
  OverlappedEx^.Socket := ClientSocket;
  OverlappedEx^.SSLContextValid := False;
  OverlappedEx^.SSLStreamSizesValid := False;
  OverlappedEx^.OpType := otRead;
  OverlappedEx^.KeepAliveActive := True;
  OverlappedEx^.LastActivityTime := GetTickCount64;
  FillChar(OverlappedEx^.ClientIP, SizeOf(OverlappedEx^.ClientIP), 0);
  if AClientIP <> '' then
  begin
    AnsiIP := AnsiString(AClientIP);
    Move(AnsiIP[1], OverlappedEx^.ClientIP[0], Min(Length(AnsiIP), SizeOf(OverlappedEx^.ClientIP) - 1));
  end;

  if InitializeRequestProcessing(OverlappedEx) then
    ContinueReadingRequest(OverlappedEx);
end;

procedure TIocpWorkerEngine.ContinueSendingResponse(OverlappedEx: POverlappedEx);
var
  BytesToEncrypt: Integer;
  WSABuf: TWSABUF;
  BytesSentIO: DWORD;
  ErrorCode: Integer;
  Response: TResponse;
  OutOff: Integer;
  FatalEncryptErr: Boolean;
  SyncBytes: DWORD;
  RecvRes: Integer;
  OldResp: TResponse;
  Reason: string;
  SockId: TSocket;
begin
  try
    while True do
    begin
      if not Assigned(OverlappedEx) or not Assigned(OverlappedEx^.Response) then
      begin
        Logger.Error('Fatal error: Missing OverlappedEx structure or Response object in ContinueSendingResponse.');
        CleanupConnectionWithReason(OverlappedEx, 'No data in ContinueSendingResponse');
        Exit;
      end;
      Response := OverlappedEx^.Response;
      if Response.IsComplete then
      begin
        if Response.Status = hsSwitchingProtocols then
        begin
          if Assigned(FWebSocketBridge) then
            FWebSocketBridge.TransitionToWebSocket(OverlappedEx);
          Exit;
        end;

        if FEnableKeepAlive and Response.KeepAlive and
           (OverlappedEx^.KeepAliveRequestsCount < FMaxKeepAliveRequests) and
           (OverlappedEx^.SSLContextValid or (not OverlappedEx^.IsTLS)) then
        begin
          OldResp := TResponse(InterlockedExchangePointer(Pointer(OverlappedEx^.Response), nil));
          if Assigned(OldResp) then
          begin
            if not Assigned(OverlappedEx^.CachedResponse) then
              OverlappedEx^.CachedResponse := OldResp
            else
              OldResp.Free;
          end;
          if Assigned(OverlappedEx^.Request) then
          begin
            OverlappedEx^.Request.Reset;
            if OverlappedEx^.IsTLS then
              OverlappedEx^.Request.ClientCertificate := OverlappedEx^.ClientCertInfo;
          end;
          Inc(OverlappedEx^.KeepAliveRequestsCount);
          OverlappedEx^.KeepAliveActive := True;
          OverlappedEx^.LastActivityTime := GetTickCount64;

          if (Length(OverlappedEx^.ClientReceiveBuffer) > 0) or
             (OverlappedEx^.IsTLS and FTlsManager.HasPendingRxData(OverlappedEx^)) then
          begin
            OverlappedEx^.OpType := otRead;
            if not Assigned(OverlappedEx^.Request) then
              InitializeRequestProcessing(OverlappedEx);
            if OverlappedEx^.AllowInlineRecv then
            begin
              OverlappedEx^.InlineSyncBytes := 0;
              OverlappedEx^.InlineRecvReady := True;
            end
            else
              PostQueuedCompletionStatus(FCompletionPort, 0, ULONG_PTR(OverlappedEx^.Socket), POverlapped(OverlappedEx));
            Exit;
          end;

          OverlappedEx^.OpType := otRead;
          if OverlappedEx^.AllowInlineRecv then
          begin
            RecvRes := IssueWSARecvEx(OverlappedEx, SyncBytes);
            if RecvRes = 1 then
            begin
              OverlappedEx^.InlineSyncBytes := SyncBytes;
              OverlappedEx^.InlineRecvReady := True;
            end
            else if RecvRes < 0 then
              CleanupConnectionWithReason(OverlappedEx, 'WSARecv Keep-Alive re-arm failed');
          end
          else if not IssueWSARecv(OverlappedEx) then
            CleanupConnectionWithReason(OverlappedEx, 'WSARecv Keep-Alive re-arm failed');
          Exit;
        end;

        Reason := 'Transfer completed (SSL shutdown completed)';
        if OverlappedEx^.IsTLS and OverlappedEx^.SSLContextValid then
        begin
          try
            FTlsManager.PerformGracefulSSLShutdown(OverlappedEx^);
          except
            on E: Exception do
              Logger.Error('SSL shutdown error after transfer: ' + E.Message);
          end;
        end
        else
          Reason := 'Transfer completed (no SSL shutdown)';
        CleanupConnectionWithReason(OverlappedEx, Reason);
        Exit;
      end;
      if OverlappedEx^.IsTLS and OverlappedEx^.SSLContextValid then
      begin
        if (not FTlsManager.EncryptResponseChunks(OverlappedEx^, Response, OutOff, FatalEncryptErr)) or FatalEncryptErr then
        begin
          Logger.Error('FATAL ERROR: Failed to encrypt chunk. Closing connection.');
          CleanupConnectionWithReason(OverlappedEx, 'Chunk encryption error');
          Exit;
        end;
        if OutOff <= 0 then
        begin
          if Response.IsComplete then
            Continue
          else
          begin
            Logger.Error('ReadNextChunk returned 0, but the response is incomplete. Closing.');
            CleanupConnectionWithReason(OverlappedEx, 'Response Streaming Error');
          end;
          Exit;
        end;
        WSABuf.len := OutOff;
      end
      else
      begin
        BytesToEncrypt := Response.ReadNextChunk(@OverlappedEx^.SSLOutputBuffer[0], SizeOf(OverlappedEx^.SSLOutputBuffer));
        if BytesToEncrypt <= 0 then
        begin
          if Response.IsComplete then
            Continue
          else
          begin
            Logger.Error('ReadNextChunk returned 0, but the response is incomplete. Closing.');
            CleanupConnectionWithReason(OverlappedEx, 'Response Streaming Error');
          end;
          Exit;
        end;
        WSABuf.len := BytesToEncrypt;
      end;
      OverlappedEx^.OpType := otWriteChunk;
      WSABuf.buf := @OverlappedEx^.SSLOutputBuffer[0];
      ZeroMemory(@OverlappedEx^.Overlapped, SizeOf(TOverlapped));
      BytesSentIO := 0;
      if WSASend(OverlappedEx^.Socket, @WSABuf, 1, BytesSentIO, 0,
                 @OverlappedEx^.Overlapped, nil) = SOCKET_ERROR then
      begin
        ErrorCode := WSAGetLastError;
        if ErrorCode <> WSA_IO_PENDING then
        begin
          if (ErrorCode = WSAECONNRESET) or (ErrorCode = WSAECONNABORTED) or (ErrorCode = WSAENOTSOCK) or (ErrorCode = 10038) then
          begin
          end
          else
            Logger.Error('Error starting chunk upload: %d', [ErrorCode]);
          CleanupConnectionWithReason(OverlappedEx, Format('Error WSASend: %d', [ErrorCode]));
        end;
        Exit;
      end;
      if OverlappedEx^.SkipIOCP then
      begin
        if BytesSentIO > 0 then
          Continue
        else
        begin
          CleanupConnectionWithReason(OverlappedEx, 'Error sending chunk - 0 bytes sent');
          Exit;
        end;
      end;
      Exit;
    end;
  except
    on E: Exception do
    begin
      SockId := 0;
      if Assigned(OverlappedEx) then
        SockId := OverlappedEx^.Socket;
      Logger.Error('Exception in ContinueSendingResponse [Socket:%d, %s]: %s', [SockId, E.ClassName, E.Message]);
      CleanupConnectionWithReason(OverlappedEx, Format('Exception [%s] in ContinueSendingResponse: %s', [E.ClassName, E.Message]));
    end;
  end;
end;

class function TIocpWorkerEngine.WorkerThreadProc(Parameter: Pointer): DWORD;
var
  Engine: TIocpWorkerEngine;
  BytesTransferred: DWORD;
  CompletionKey: ULONG_PTR;
  OverlappedEx: POverlappedEx;
  Status: DWORD;
  DecryptSuccess: Boolean;
  HandshakeComplete: Boolean;
  GracefulShutdown: Boolean;
  ConsecutiveErrors: Integer;
  ListenSocket: TSocket;
  AcceptedSocket: TSocket;
  AcceptClientIP: string;
  PlainCurLen: Integer;
  PlainExcess: Int64;
  HandshakeBufLen: Integer;
  InPlaceBufs: array[0..3] of TSecBuffer;
  InPlaceDesc: TSecBufferDesc;
  InPlaceStatus: SECURITY_STATUS;
  PlainPtr, ExtraPtr: PByte;
  PlainSize, ExtraSize, BufIdx: Integer;
  SkipDequeue: Boolean;
  InlineIter: Integer;
  CompletionOK: Boolean;
  SyncWsBytes: DWORD;
  WsRecvRes: Integer;
  WsStackBuf: array[0..16383] of Byte;
  WsOutLen: Integer;
  WsOffset: Integer;
  WsConsumed: Integer;
  WsOutOp: TWebSocketOpcode;
  IsActiveCompletion: Boolean;
  CanCheckInlineRecv: Boolean;
  FirstByte: Byte;
  PlainHttpResponse: string;
  ResponseBytes: TBytes;
  DecryptedPlainData: TBytes;
  CurrentAttemptConsumedBytes: Integer;
  DecryptStatus: SECURITY_STATUS;
  FatalTlsError: Boolean;
  CurrentBufferLen: Integer;
  RemainingBytes: Integer;
  WsSession: TWebSocketSession;
  CloseConn: Boolean;
  WsFatalError: Boolean;
  MsgArray: TArray<TBytes>;
  MsgOpcodes: TArray<TWebSocketOpcode>;
  MsgIdx: Integer;
  MsgBytes: TBytes;
  Opcode: TWebSocketOpcode;
  MsgStr: string;
  Handled: Boolean;
  CurrentLen: Integer;
  ConsumedBytes: Integer;
  WsDecryptStatus: SECURITY_STATUS;
  Detached: POverlappedEx;
  SockId: TSocket;
  OpName: string;
  IsActive: Boolean;
  OsslHasPlain: Boolean;
  OsslErrMsg: string;
begin
  Engine := TIocpWorkerEngine(Parameter);
  GracefulShutdown := False;
  ConsecutiveErrors := 0;
  Logger.Info('Worker thread started');
  OverlappedEx := nil;
  SkipDequeue := False;
  InlineIter := 0;
  while Engine.FRunning and not GracefulShutdown do
  begin
    if not SkipDequeue then
    begin
      InlineIter := 0;
      CompletionOK := GetQueuedCompletionStatus(Engine.FCompletionPort, BytesTransferred,
                                                CompletionKey, POverlapped(OverlappedEx), 2000);
    end
    else
    begin
      SkipDequeue := False;
      CompletionOK := True;
    end;
    if CompletionOK then
    begin
      ConsecutiveErrors := 0;
      if OverlappedEx = nil then
      begin
        Logger.Info('Worker thread received shutdown signal');
        Break;
      end;

      if not Engine.FOverlappedPool.IsAllocated(OverlappedEx) then
        Continue;
      if OverlappedEx^.InPool <> 0 then
        Continue;

      if (CompletionKey <> 0) and (OverlappedEx^.OpType <> otAccept) and (CompletionKey <> ULONG_PTR(OverlappedEx^.Socket)) then
        Continue;

      try
        CanCheckInlineRecv := (OverlappedEx^.OpType in [otRead, otWriteChunk, otWebSocketRead]) and (InlineIter < 16);
        OverlappedEx^.InlineRecvReady := False;
        OverlappedEx^.AllowInlineRecv := CanCheckInlineRecv;
        case OverlappedEx^.OpType of
          otAccept:
          begin
            ListenSocket := OverlappedEx^.Socket;
            AcceptedSocket := OverlappedEx^.ClientSocket;
            AcceptClientIP := Engine.FIpSecurity.ExtractClientIP(AcceptedSocket, ListenSocket);
            Engine.FActiveOverlappedLock.Enter;
            try
              Engine.FActiveOverlapped.Remove(OverlappedEx);
            finally
              Engine.FActiveOverlappedLock.Leave;
            end;
            Engine.FOverlappedPool.Release(OverlappedEx);
            Engine.AdjustPendingAcceptCount(ListenSocket, -1);
            if Engine.FRunning then
              Engine.AcceptConnection2(ListenSocket);
            if (Engine.FMaxConnections > 0) and (InterlockedIncrement64(Engine.FActiveConnections) > Engine.FMaxConnections) then
            begin
              InterlockedDecrement64(Engine.FActiveConnections);
              Logger.Warn('New connection REJECTED due to connection limit reached (%d).', [Engine.FMaxConnections]);
              closesocket(AcceptedSocket);
            end
            else if Engine.FRejectNewConnections = 1 then
            begin
              if Engine.FMaxConnections > 0 then
                InterlockedDecrement64(Engine.FActiveConnections);
              Logger.Warn('New connection REJECTED due to system overload (monitor flag).');
              closesocket(AcceptedSocket);
            end
            else if not Engine.FIpSecurity.TrackIPConnect(AcceptClientIP) then
            begin
              if Engine.FMaxConnections > 0 then
                InterlockedDecrement64(Engine.FActiveConnections);
              Logger.Warn('New connection from %s REJECTED: per-IP connection limit reached (%d).', [AcceptClientIP, Engine.FIpSecurity.MaxConnectionsPerIP]);
              closesocket(AcceptedSocket);
            end
            else
            begin
              if Engine.FMaxConnections <= 0 then
                InterlockedIncrement64(Engine.FActiveConnections);
              TInterlocked.Increment(Engine.FRequestsPerSecondCounter);
              if (Engine.FListenSocketHTTP <> INVALID_SOCKET) and (ListenSocket = Engine.FListenSocketHTTP) then
                Engine.HandleHttpPlainConnection(AcceptedSocket, AcceptClientIP)
              else
                Engine.HandleHttpsHandshake(AcceptedSocket, AcceptClientIP);
            end;
          end;
          otSSLHandshake:
          begin
            if BytesTransferred > 0 then
            begin
              if (Length(OverlappedEx^.ClientReceiveBuffer) + Integer(BytesTransferred)) > MAX_SSL_TOKEN_SIZE * 4 then
              begin
                SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                Engine.CleanupConnectionWithReason(OverlappedEx, 'SSL handshake buffer overflow');
                Continue;
              end;
              HandshakeBufLen := Length(OverlappedEx^.ClientReceiveBuffer);
              SetLength(OverlappedEx^.ClientReceiveBuffer, HandshakeBufLen + Integer(BytesTransferred));
              Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[HandshakeBufLen], BytesTransferred);

              if (OverlappedEx^.SSLHandshakeStep = 0) and (Length(OverlappedEx^.ClientReceiveBuffer) >= 4) then
              begin
                FirstByte := OverlappedEx^.ClientReceiveBuffer[0];
                if (FirstByte in [71, 80, 72, 68, 79, 67]) then
                begin
                  PlainHttpResponse :=
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
                  ResponseBytes := TEncoding.UTF8.GetBytes(PlainHttpResponse);
                  send(OverlappedEx^.Socket, ResponseBytes[0], Length(ResponseBytes), 0);
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'Plain HTTP request sent to HTTPS port');
                  Continue;
                end;
              end;

              HandshakeComplete := Engine.FTlsManager.ProcessSSLHandshakeStep(OverlappedEx^, DWORD(Length(OverlappedEx^.ClientReceiveBuffer)));
              if OverlappedEx^.SSLOutputSize > 0 then
              begin
                if send(OverlappedEx^.Socket, OverlappedEx^.SSLOutputBuffer[0],
                       OverlappedEx^.SSLOutputSize, 0) = SOCKET_ERROR then
                begin
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'Send error during SSL handshake: ' + IntToStr(WSAGetLastError));
                  Continue;
                end;
              end;
              if HandshakeComplete then
              begin
                if Engine.InitializeRequestProcessing(OverlappedEx) then
                begin
                  OverlappedEx^.OpType := otRead;
                  if (Length(OverlappedEx^.ClientReceiveBuffer) > 0) or
                     Engine.FTlsManager.HasPendingRxData(OverlappedEx^) then
                  begin
                    if not PostQueuedCompletionStatus(Engine.FCompletionPort, 0, ULONG_PTR(OverlappedEx^.Socket), POverlapped(OverlappedEx)) then
                      Engine.CleanupConnectionWithReason(OverlappedEx, 'Failed to post completion for buffered post-handshake TLS data: ' + IntToStr(GetLastError));
                  end
                  else
                    Engine.ContinueReadingRequest(OverlappedEx);
                end;
              end
              else if OverlappedEx^.SSLNeedsMoreData then
              begin
                if not Engine.IssueWSARecv(OverlappedEx) then
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'SSL handshake read continuation error: ' + IntToStr(WSAGetLastError));
              end
              else
                Engine.CleanupConnectionWithReason(OverlappedEx, 'SSL Handshake Failed');
            end
            else
              Engine.CleanupConnectionWithReason(OverlappedEx, 'Client closed connection during handshake');
          end;
          otRead:
          begin
            if (BytesTransferred > 0) or (Length(OverlappedEx^.ClientReceiveBuffer) > 0) or
               (OverlappedEx^.IsTLS and Engine.FTlsManager.HasPendingRxData(OverlappedEx^)) then
            begin
              if Assigned(OverlappedEx^.Response) then
                Continue;

              if not OverlappedEx^.IsTLS then
              begin
                if not Assigned(OverlappedEx^.Request) then
                  Engine.InitializeRequestProcessing(OverlappedEx);

                if Assigned(OverlappedEx^.Request) then
                begin
                  if Length(OverlappedEx^.ClientReceiveBuffer) = 0 then
                  begin
                    if BytesTransferred > 0 then
                    begin
                      OverlappedEx^.Request.AppendDataPtr(@OverlappedEx^.Buffer[0], Integer(BytesTransferred));
                      if Engine.IsRequestComplete(OverlappedEx^.Request) and
                         (not OverlappedEx^.Request.IsChunkedTransfer) and
                         (OverlappedEx^.Request.HeadersEndPos > 0) and
                         (OverlappedEx^.Request.ExpectedBodySize >= 0) then
                      begin
                        PlainExcess := OverlappedEx^.Request.TotalBytesReceived - (Int64(OverlappedEx^.Request.HeadersEndPos) + OverlappedEx^.Request.ExpectedBodySize);
                        if (PlainExcess > 0) and (PlainExcess <= Integer(BytesTransferred)) then
                        begin
                          SetLength(OverlappedEx^.ClientReceiveBuffer, Integer(PlainExcess));
                          Move(OverlappedEx^.Buffer[Integer(BytesTransferred) - Integer(PlainExcess)], OverlappedEx^.ClientReceiveBuffer[0], Integer(PlainExcess));
                        end;
                      end;
                    end;
                  end
                  else
                  begin
                    if BytesTransferred > 0 then
                    begin
                      PlainCurLen := Length(OverlappedEx^.ClientReceiveBuffer);
                      SetLength(OverlappedEx^.ClientReceiveBuffer, PlainCurLen + Integer(BytesTransferred));
                      Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[PlainCurLen], BytesTransferred);
                    end;
                    OverlappedEx^.Request.AppendData(OverlappedEx^.ClientReceiveBuffer[0], Length(OverlappedEx^.ClientReceiveBuffer));
                    if Engine.IsRequestComplete(OverlappedEx^.Request) and
                       (not OverlappedEx^.Request.IsChunkedTransfer) and
                       (OverlappedEx^.Request.HeadersEndPos > 0) and
                       (OverlappedEx^.Request.ExpectedBodySize >= 0) then
                    begin
                      PlainExcess := OverlappedEx^.Request.TotalBytesReceived - (Int64(OverlappedEx^.Request.HeadersEndPos) + OverlappedEx^.Request.ExpectedBodySize);
                      if (PlainExcess > 0) and (PlainExcess <= Length(OverlappedEx^.ClientReceiveBuffer)) then
                        OverlappedEx^.ClientReceiveBuffer := Copy(OverlappedEx^.ClientReceiveBuffer, Length(OverlappedEx^.ClientReceiveBuffer) - Integer(PlainExcess), Integer(PlainExcess))
                      else
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    end
                    else
                      SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                  end;
                  if Engine.IsRequestComplete(OverlappedEx^.Request) or (not OverlappedEx^.Request.CanAcceptMoreData) then
                  begin
                    if (not Assigned(OverlappedEx^.Response)) and Assigned(Engine.FOnProcessHttpRequest) then
                      Engine.FOnProcessHttpRequest(OverlappedEx);
                  end
                  else
                    Engine.ContinueReadingRequest(OverlappedEx);
                end
                else
                begin
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'Request object NIL during plain HTTP read');
                  Continue;
                end;
              end
              else
              begin
                if OverlappedEx^.IsTLS and (not OverlappedEx^.SSLContextValid) then
                begin
                  SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'TLS context invalid or already terminated');
                  Continue;
                end;

                if (Int64(Length(OverlappedEx^.ClientReceiveBuffer)) + Int64(BytesTransferred)) > (Engine.FMaxRequestSize + MAX_SSL_TOKEN_SIZE) then
                begin
                  Logger.Error(Format('The client''s receive buffer has reached its limit (%d + %d > %d). I''m closing the connection.',
                    [Length(OverlappedEx^.ClientReceiveBuffer), BytesTransferred, (Engine.FMaxRequestSize + MAX_SSL_TOKEN_SIZE)]));
                  Engine.CleanupConnectionWithReason(OverlappedEx, 'Receive buffer overflow');
                  Continue;
                end;
                DecryptStatus := SEC_E_OK;
                FatalTlsError := False;
                if (Engine.FTlsManager.TlsProvider = tpOpenSSL) or (OverlappedEx^.OpenSSLHandle <> nil) then
                begin
                  if not Assigned(OverlappedEx^.Request) then
                    Engine.InitializeRequestProcessing(OverlappedEx);
                  if not Engine.FTlsManager.DecryptRequestChunk(OverlappedEx^, BytesTransferred, OverlappedEx^.Request, OsslHasPlain, FatalTlsError, OsslErrMsg) then
                  begin
                    if not FatalTlsError then
                      FatalTlsError := True;
                  end;
                  if FatalTlsError then
                    Engine.CleanupConnectionWithReason(OverlappedEx, OsslErrMsg);
                end
                else
                begin
                  if (Length(OverlappedEx^.ClientReceiveBuffer) = 0) and (BytesTransferred > 0) then
                  begin
                    InPlaceBufs[0].BufferType := SECBUFFER_DATA;
                    InPlaceBufs[0].cbBuffer := BytesTransferred;
                    InPlaceBufs[0].pvBuffer := @OverlappedEx^.Buffer[0];
                    InPlaceBufs[1].BufferType := SECBUFFER_EMPTY;
                    InPlaceBufs[1].cbBuffer := 0;
                    InPlaceBufs[1].pvBuffer := nil;
                    InPlaceBufs[2].BufferType := SECBUFFER_EMPTY;
                    InPlaceBufs[2].cbBuffer := 0;
                    InPlaceBufs[2].pvBuffer := nil;
                    InPlaceBufs[3].BufferType := SECBUFFER_EMPTY;
                    InPlaceBufs[3].cbBuffer := 0;
                    InPlaceBufs[3].pvBuffer := nil;
                    InPlaceDesc.ulVersion := SECBUFFER_VERSION;
                    InPlaceDesc.cBuffers := 4;
                    InPlaceDesc.pBuffers := @InPlaceBufs[0];
                    InPlaceStatus := DecryptMessage(@OverlappedEx^.SSLContext, @InPlaceDesc, 0, nil);
                    if InPlaceStatus = SEC_E_OK then
                    begin
                      PlainPtr := nil;
                      PlainSize := 0;
                      ExtraPtr := nil;
                      ExtraSize := 0;
                      for BufIdx := 0 to 3 do
                      begin
                        if InPlaceBufs[BufIdx].BufferType = SECBUFFER_DATA then
                        begin
                          PlainPtr := PByte(InPlaceBufs[BufIdx].pvBuffer);
                          PlainSize := InPlaceBufs[BufIdx].cbBuffer;
                        end
                        else if InPlaceBufs[BufIdx].BufferType = SECBUFFER_EXTRA then
                        begin
                          ExtraPtr := PByte(InPlaceBufs[BufIdx].pvBuffer);
                          ExtraSize := InPlaceBufs[BufIdx].cbBuffer;
                        end;
                      end;
                      if not Assigned(OverlappedEx^.Request) then
                        Engine.InitializeRequestProcessing(OverlappedEx);
                      if Assigned(OverlappedEx^.Request) then
                      begin
                        if (PlainSize > 0) and Assigned(PlainPtr) then
                          OverlappedEx^.Request.AppendDataPtr(PlainPtr, PlainSize);
                      end
                      else
                      begin
                        Logger.Error('Fatal error: Request object is NIL while decrypting data. Closing connection.');
                        Engine.CleanupConnectionWithReason(OverlappedEx, 'Request object NIL during decryption');
                        FatalTlsError := True;
                      end;
                      if (not FatalTlsError) and (ExtraSize > 0) and Assigned(ExtraPtr) then
                      begin
                        SetLength(OverlappedEx^.ClientReceiveBuffer, ExtraSize);
                        Move(ExtraPtr^, OverlappedEx^.ClientReceiveBuffer[0], ExtraSize);
                      end;
                    end
                    else if (InPlaceStatus = SEC_E_INCOMPLETE_MESSAGE) or (InPlaceStatus = Longint($80090330)) then
                    begin
                      SetLength(OverlappedEx^.ClientReceiveBuffer, BytesTransferred);
                      Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[0], BytesTransferred);
                    end
                    else
                    begin
                      FatalTlsError := True;
                      Engine.CleanupConnectionWithReason(OverlappedEx,
                        Format('TLS fatal decrypt error: %s (0x%x)', [GetSSLErrorDescription(InPlaceStatus), InPlaceStatus]));
                    end;
                  end
                  else if BytesTransferred > 0 then
                  begin
                    CurrentBufferLen := Length(OverlappedEx^.ClientReceiveBuffer);
                    SetLength(OverlappedEx^.ClientReceiveBuffer, CurrentBufferLen + Integer(BytesTransferred));
                    Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[CurrentBufferLen], BytesTransferred);
                  end;
                  while (not FatalTlsError) and (Length(OverlappedEx^.ClientReceiveBuffer) > 0) do
                  begin
                    DecryptSuccess := Engine.FTlsManager.DecryptReceivedData(OverlappedEx^.SSLContext,
                                                                 OverlappedEx^.ClientReceiveBuffer,
                                                                 DecryptedPlainData,
                                                                 CurrentAttemptConsumedBytes,
                                                                 DecryptStatus);

                    if DecryptSuccess then
                    begin
                      if CurrentAttemptConsumedBytes > 0 then
                      begin
                        RemainingBytes := Length(OverlappedEx^.ClientReceiveBuffer) - CurrentAttemptConsumedBytes;
                        if RemainingBytes > 0 then
                          OverlappedEx^.ClientReceiveBuffer := Copy(OverlappedEx^.ClientReceiveBuffer, CurrentAttemptConsumedBytes, RemainingBytes)
                        else
                          SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        if not Assigned(OverlappedEx^.Request) then
                          Engine.InitializeRequestProcessing(OverlappedEx);

                        if Assigned(OverlappedEx^.Request) then
                        begin
                          if Length(DecryptedPlainData) > 0 then
                            OverlappedEx^.Request.AppendData(DecryptedPlainData, Length(DecryptedPlainData));
                        end
                        else
                        begin
                          Logger.Error('Fatal error: Request object is NIL while decrypting data. Closing connection.');
                          FatalTlsError := True;
                          Engine.CleanupConnectionWithReason(OverlappedEx, 'Request object NIL during decryption');
                          Break;
                        end;
                      end
                      else
                      begin
                        Logger.Error('DecryptReceivedData returned success, but 0 bytes were consumed. Closing connection.');
                        FatalTlsError := True;
                        Engine.CleanupConnectionWithReason(OverlappedEx, 'DecryptSuccess but ConsumedBytes = 0');
                        Break;
                      end;
                    end
                    else
                    begin
                      if (DecryptStatus = SEC_E_INCOMPLETE_MESSAGE) or (DecryptStatus = Longint($80090330)) then
                        Break
                      else
                      begin
                        FatalTlsError := True;
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        Engine.CleanupConnectionWithReason(OverlappedEx,
                          Format('TLS fatal decrypt error: %s (0x%x)', [GetSSLErrorDescription(DecryptStatus), DecryptStatus]));
                        Break;
                      end;
                    end;
                  end;
                end;

                if FatalTlsError or (OverlappedEx^.Socket = INVALID_SOCKET) then
                  Continue;
                if Assigned(OverlappedEx^.Request) then
                begin
                  if Engine.IsRequestComplete(OverlappedEx^.Request) or (not OverlappedEx^.Request.CanAcceptMoreData) then
                  begin
                    if (not Assigned(OverlappedEx^.Response)) and Assigned(Engine.FOnProcessHttpRequest) then
                      Engine.FOnProcessHttpRequest(OverlappedEx);
                  end
                  else
                    Engine.ContinueReadingRequest(OverlappedEx);
                end
                else
                begin
                  if not Engine.IssueWSARecv(OverlappedEx) then
                    Engine.CleanupConnectionWithReason(OverlappedEx, 'WSARecv continuation error waiting for complete TLS record');
                end;
              end;
            end
            else
              Engine.CleanupConnectionWithReason(OverlappedEx, 'The client closed the connection while reading');
          end;
          otWriteChunk:
          begin
            if BytesTransferred > 0 then
              Engine.ContinueSendingResponse(OverlappedEx)
            else
            begin
              Logger.Warn('Error sending chunk - 0 bytes sent');
              Engine.CleanupConnectionWithReason(OverlappedEx, 'Error sending chunk - 0 bytes sent');
            end;
          end;
          otWebSocketRead:
          begin
            WsSession := TWebSocketSession(OverlappedEx^.WebSocketSession);
            if not Assigned(WsSession) or (WsSession.InCleanup <> 0) then
            begin
              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
              OverlappedEx^.WebSocketSession := nil;
              Engine.FOverlappedPool.Release(OverlappedEx);
            end
            else
            begin
              WsSession.AddRef;
              try
                try
                  if (BytesTransferred > 0) and (WsSession.InCleanup = 0) then
                  begin
                    CloseConn := False;
                    WsFatalError := False;

                    if not OverlappedEx^.IsTLS then
                    begin
                      WsOffset := 0;
                      if Assigned(WsSession.CachedRawRouteHandler) then
                      begin
                        if WsSession.TryProcessNextFramePtr(@OverlappedEx^.Buffer[0], Integer(BytesTransferred),
                             @WsStackBuf[0], SizeOf(WsStackBuf), WsOutLen, WsConsumed, WsOutOp, CloseConn) then
                        begin
                          WsOffset := WsConsumed;
                          if WsConsumed = Integer(BytesTransferred) then
                          begin
                            if WsSession.InCleanup = 0 then
                            begin
                              if Assigned(Engine.FOnWebSocketRawRouteMessage) then
                                Engine.FOnWebSocketRawRouteMessage(WsSession.CachedRawRouteHandler, WsSession, @WsStackBuf[0], WsOutLen, WsOutOp);
                            end;
                          end
                          else
                          begin
                            WsSession.BeginFastBatch;
                            try
                              if WsSession.InCleanup = 0 then
                              begin
                                if Assigned(Engine.FOnWebSocketRawRouteMessage) then
                                  Engine.FOnWebSocketRawRouteMessage(WsSession.CachedRawRouteHandler, WsSession, @WsStackBuf[0], WsOutLen, WsOutOp);
                              end;
                              while (WsOffset < Integer(BytesTransferred)) and (WsSession.InCleanup = 0) do
                              begin
                                if not WsSession.TryProcessNextFramePtr(@OverlappedEx^.Buffer[WsOffset], Integer(BytesTransferred) - WsOffset,
                                     @WsStackBuf[0], SizeOf(WsStackBuf), WsOutLen, WsConsumed, WsOutOp, CloseConn) then
                                  Break;
                                Inc(WsOffset, WsConsumed);
                                if WsSession.InCleanup = 0 then
                                begin
                                  if Assigned(Engine.FOnWebSocketRawRouteMessage) then
                                    Engine.FOnWebSocketRawRouteMessage(WsSession.CachedRawRouteHandler, WsSession, @WsStackBuf[0], WsOutLen, WsOutOp);
                                end;
                              end;
                            finally
                              WsSession.EndFastBatch;
                            end;
                          end;
                        end;
                      end;
                      if (WsOffset < Integer(BytesTransferred)) and (not CloseConn) and (WsSession.InCleanup = 0) then
                      begin
                        MsgArray := WsSession.ProcessIncomingPlaintextPtr(@OverlappedEx^.Buffer[WsOffset], Integer(BytesTransferred) - WsOffset, CloseConn);
                        MsgOpcodes := WsSession.LastMessageOpcodes;
                        for MsgIdx := 0 to High(MsgArray) do
                        begin
                          if WsSession.InCleanup <> 0 then
                            Break;
                          MsgBytes := MsgArray[MsgIdx];
                          if MsgIdx < Length(MsgOpcodes) then
                            Opcode := MsgOpcodes[MsgIdx]
                          else
                            Opcode := WsSession.LastReceivedOpcode;
                          if Opcode in [wsOpText, wsOpBinary] then
                          begin
                            MsgStr := '';
                            if Opcode = wsOpText then
                            begin
                              try
                                MsgStr := TEncoding.UTF8.GetString(MsgBytes);
                              except
                                on E: Exception do
                                  MsgStr := TEncoding.Default.GetString(MsgBytes);
                              end;
                            end;
                            Handled := False;

                            if Assigned(WsSession) and (WsSession.InCleanup = 0) and Assigned(WsSession.CachedRouteHandler) then
                            begin
                              if Assigned(Engine.FOnWebSocketRouteMessage) then
                              begin
                                Handled := True;
                                Engine.FOnWebSocketRouteMessage(WsSession.CachedRouteHandler, WsSession, MsgStr, Opcode);
                              end;
                            end;

                            if (not Handled) and Assigned(Engine.FOnWebSocketGlobalMessage) and Assigned(WsSession) and (WsSession.InCleanup = 0) then
                              Handled := Engine.FOnWebSocketGlobalMessage(WsSession, MsgStr, Opcode);

                            if Opcode = wsOpText then
                            begin
                              if (not Handled) and (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                                Engine.FWebSocketBridge.BroadcastWebSocket(MsgStr);
                            end
                            else if Opcode = wsOpBinary then
                            begin
                              if (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                              begin
                                WsSession.SendBinary(MsgBytes);
                                Engine.FWebSocketBridge.TriggerWebSocketWrite(WsSession);
                              end;
                            end;
                          end;
                        end;

                        if (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                          Engine.FWebSocketBridge.TriggerWebSocketWrite(WsSession);
                      end;

                      if CloseConn then
                      begin
                        if Assigned(Engine.FWebSocketBridge) then
                        begin
                          if WsSession.CloseReceived then
                            Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'Client sent Close frame (Graceful WebSocket shutdown)')
                          else
                            Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WebSocket protocol violation / invalid frame payload');
                        end;
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        OverlappedEx^.WebSocketSession := nil;
                        Engine.FOverlappedPool.Release(OverlappedEx);
                        Continue;
                      end;
                    end
                    else
                    begin
                      if OverlappedEx^.IsTLS and (not OverlappedEx^.SSLContextValid) then
                      begin
                        if Assigned(Engine.FWebSocketBridge) then
                          Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WebSocket TLS context invalid or released');
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        OverlappedEx^.WebSocketSession := nil;
                        Engine.FOverlappedPool.Release(OverlappedEx);
                        Continue;
                      end;

                      CurrentLen := Length(OverlappedEx^.ClientReceiveBuffer);
                      SetLength(OverlappedEx^.ClientReceiveBuffer, CurrentLen + Integer(BytesTransferred));
                      Move(OverlappedEx^.Buffer[0], OverlappedEx^.ClientReceiveBuffer[CurrentLen], BytesTransferred);

                      WsDecryptStatus := SEC_E_OK;
                      while (Length(OverlappedEx^.ClientReceiveBuffer) > 0) and (WsSession.InCleanup = 0) do
                      begin
                        if Engine.FTlsManager.DecryptReceivedData(OverlappedEx^, OverlappedEx^.ClientReceiveBuffer, DecryptedPlainData, ConsumedBytes, WsDecryptStatus) then
                        begin
                          if ConsumedBytes > 0 then
                          begin
                            RemainingBytes := Length(OverlappedEx^.ClientReceiveBuffer) - ConsumedBytes;
                            if RemainingBytes > 0 then
                              OverlappedEx^.ClientReceiveBuffer := Copy(OverlappedEx^.ClientReceiveBuffer, ConsumedBytes, RemainingBytes)
                            else
                              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);

                            if (Length(DecryptedPlainData) > 0) and (WsSession.InCleanup = 0) then
                            begin
                              MsgArray := WsSession.ProcessIncomingPlaintext(DecryptedPlainData, CloseConn);
                              MsgOpcodes := WsSession.LastMessageOpcodes;
                              for MsgIdx := 0 to High(MsgArray) do
                              begin
                                if WsSession.InCleanup <> 0 then
                                  Break;
                                MsgBytes := MsgArray[MsgIdx];
                                if MsgIdx < Length(MsgOpcodes) then
                                  Opcode := MsgOpcodes[MsgIdx]
                                else
                                  Opcode := WsSession.LastReceivedOpcode;
                                if Opcode in [wsOpText, wsOpBinary] then
                                begin
                                  MsgStr := '';
                                  if Opcode = wsOpText then
                                  begin
                                    try
                                      MsgStr := TEncoding.UTF8.GetString(MsgBytes);
                                    except
                                      on E: Exception do
                                        MsgStr := TEncoding.Default.GetString(MsgBytes);
                                    end;
                                  end;
                                  Handled := False;

                                  if Assigned(WsSession) and (WsSession.InCleanup = 0) and Assigned(WsSession.CachedRouteHandler) then
                                  begin
                                    if Assigned(Engine.FOnWebSocketRouteMessage) then
                                    begin
                                      Handled := True;
                                      Engine.FOnWebSocketRouteMessage(WsSession.CachedRouteHandler, WsSession, MsgStr, Opcode);
                                    end;
                                  end;

                                  if (not Handled) and Assigned(Engine.FOnWebSocketGlobalMessage) and Assigned(WsSession) and (WsSession.InCleanup = 0) then
                                    Handled := Engine.FOnWebSocketGlobalMessage(WsSession, MsgStr, Opcode);

                                  if Opcode = wsOpText then
                                  begin
                                    if (not Handled) and (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                                      Engine.FWebSocketBridge.BroadcastWebSocket(MsgStr);
                                  end
                                  else if Opcode = wsOpBinary then
                                  begin
                                    if (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                                    begin
                                      WsSession.SendBinary(MsgBytes);
                                      Engine.FWebSocketBridge.TriggerWebSocketWrite(WsSession);
                                    end;
                                  end;
                                end;
                              end;

                              if (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                                Engine.FWebSocketBridge.TriggerWebSocketWrite(WsSession);

                              if CloseConn then
                              begin
                                if Assigned(Engine.FWebSocketBridge) then
                                begin
                                  if WsSession.CloseReceived then
                                    Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'Client sent Close frame (Graceful WebSocket shutdown)')
                                  else
                                    Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WebSocket protocol violation / invalid frame payload');
                                end;
                                SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                                OverlappedEx^.WebSocketSession := nil;
                                Engine.FOverlappedPool.Release(OverlappedEx);
                                Break;
                              end;
                            end;
                          end
                          else
                            Break;
                        end
                        else
                        begin
                          if (WsDecryptStatus = SEC_E_INCOMPLETE_MESSAGE) or (WsDecryptStatus = Longint($80090330)) then
                            Break
                          else
                          begin
                            WsFatalError := True;
                            if Assigned(Engine.FWebSocketBridge) then
                              Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession,
                                Format('WebSocket TLS fatal decrypt error: %s (0x%x)', [GetSSLErrorDescription(WsDecryptStatus), WsDecryptStatus]));
                            SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                            OverlappedEx^.WebSocketSession := nil;
                            Engine.FOverlappedPool.Release(OverlappedEx);
                            Break;
                          end;
                        end;
                      end;
                    end;

                    if WsFatalError or CloseConn then
                      Continue;

                    if WsSession.InCleanup <> 0 then
                    begin
                      SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                      OverlappedEx^.WebSocketSession := nil;
                      Engine.FOverlappedPool.Release(OverlappedEx);
                      Continue;
                    end;

                    if (not CloseConn) and (WsSession.InCleanup = 0) then
                    begin
                      if OverlappedEx^.AllowInlineRecv then
                      begin
                        WsRecvRes := Engine.IssueWSARecvEx(OverlappedEx, SyncWsBytes);
                        if WsRecvRes = 1 then
                        begin
                          OverlappedEx^.InlineSyncBytes := SyncWsBytes;
                          OverlappedEx^.InlineRecvReady := True;
                        end
                        else if WsRecvRes < 0 then
                        begin
                          if Assigned(Engine.FWebSocketBridge) then
                            Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WSARecv re-arm error');
                          SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                          OverlappedEx^.WebSocketSession := nil;
                          Engine.FOverlappedPool.Release(OverlappedEx);
                        end;
                      end
                      else if not Engine.IssueWSARecv(OverlappedEx) then
                      begin
                        if Assigned(Engine.FWebSocketBridge) then
                          Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WSARecv re-arm error');
                        SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                        OverlappedEx^.WebSocketSession := nil;
                        Engine.FOverlappedPool.Release(OverlappedEx);
                      end;
                    end;
                  end
                  else if WsSession.InCleanup = 0 then
                  begin
                    if Assigned(Engine.FWebSocketBridge) then
                      Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'Client disconnected');
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Engine.FOverlappedPool.Release(OverlappedEx);
                  end
                  else
                  begin
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Engine.FOverlappedPool.Release(OverlappedEx);
                  end;
                except
                  on E: Exception do
                  begin
                    Logger.Error('Exception in otWebSocketRead [Socket:%d, %s]: %s', [OverlappedEx^.Socket, E.ClassName, E.Message]);
                    if Assigned(WsSession) and (WsSession.InCleanup = 0) and Assigned(Engine.FWebSocketBridge) then
                      Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'Unhandled exception in WebSocket handler: ' + E.Message);
                    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    OverlappedEx^.WebSocketSession := nil;
                    Engine.FOverlappedPool.Release(OverlappedEx);
                  end;
                end;
              finally
                WsSession.Release;
              end;
            end;
          end;
          otWebSocketWrite:
          begin
            WsSession := TWebSocketSession(OverlappedEx^.WebSocketSession);
            if not Assigned(WsSession) or (WsSession.InCleanup <> 0) then
            begin
              SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
              OverlappedEx^.WebSocketSession := nil;
              Engine.FOverlappedPool.Release(OverlappedEx);
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
                      TInterlocked.Exchange(WsSession.WritePending, 0);
                      if Assigned(Engine.FWebSocketBridge) then
                        Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'Graceful close completed');
                      Detached := WsSession.DetachWriteOverlapped;
                      if Assigned(Detached) then
                      begin
                        SetLength(Detached^.ClientReceiveBuffer, 0);
                        Detached^.WebSocketSession := nil;
                        Engine.FOverlappedPool.Release(Detached);
                      end;
                    end
                    else
                    begin
                      TInterlocked.Exchange(WsSession.WritePending, 0);
                      if Assigned(Engine.FWebSocketBridge) then
                        Engine.FWebSocketBridge.TriggerWebSocketWrite(WsSession);
                    end;
                  end
                  else if WsSession.InCleanup = 0 then
                  begin
                    TInterlocked.Exchange(WsSession.WritePending, 0);
                    if Assigned(Engine.FWebSocketBridge) then
                      Engine.FWebSocketBridge.CleanupWebSocketSession(WsSession, 'WSASend error');
                    Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Engine.FOverlappedPool.Release(Detached);
                    end;
                  end
                  else
                  begin
                    Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Engine.FOverlappedPool.Release(Detached);
                    end;
                  end;
                except
                  on E: Exception do
                  begin
                    Logger.Error('Exception in otWebSocketWrite [Socket:%d, %s]: %s', [OverlappedEx^.Socket, E.ClassName, E.Message]);
                    Detached := WsSession.DetachWriteOverlapped;
                    if Assigned(Detached) then
                    begin
                      SetLength(Detached^.ClientReceiveBuffer, 0);
                      Detached^.WebSocketSession := nil;
                      Engine.FOverlappedPool.Release(Detached);
                    end;
                  end;
                end;
              finally
                WsSession.Release;
              end;
            end;
          end;
        end;
        if CanCheckInlineRecv then
        begin
          if Engine.FOverlappedPool.IsAllocated(OverlappedEx) and (OverlappedEx^.InPool = 0) and OverlappedEx^.InlineRecvReady then
          begin
            OverlappedEx^.InlineRecvReady := False;
            Inc(InlineIter);
            BytesTransferred := OverlappedEx^.InlineSyncBytes;
            SkipDequeue := True;
          end;
        end;
      except
        on E: Exception do
        begin
          SockId := 0;
          OpName := 'Unknown';
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
          Engine.CleanupConnectionWithReason(OverlappedEx, Format('Exception [%s] in loop: %s', [E.ClassName, E.Message]));
        end;
      end;
    end
    else
    begin
      Status := GetLastError;
      case Status of
        WAIT_TIMEOUT:
        begin
          if not Engine.FRunning then
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
            Engine.FActiveOverlappedLock.Enter;
            try
              IsActiveCompletion := Engine.FActiveOverlapped.ContainsKey(OverlappedEx);
            finally
              Engine.FActiveOverlappedLock.Leave;
            end;
            if IsActiveCompletion then
            begin
              if (CompletionKey <> 0) and (OverlappedEx^.OpType <> otAccept) and (CompletionKey <> ULONG_PTR(OverlappedEx^.Socket)) then
                Continue;
              if OverlappedEx^.OpType = otAccept then
                Engine.HandleFailedAccept(OverlappedEx)
              else
              begin
                Logger.Info(Format('Operation aborted for socket %d - code 995', [OverlappedEx^.Socket]));
                Engine.CleanupConnectionWithReason(OverlappedEx, 'Operation aborted (ERROR_OPERATION_ABORTED)');
              end;
            end
            else
              Logger.Info('Operation aborted for already released overlapped - ignoring');
          end
          else
            Logger.Info('Operation aborted without context - continuing');
          if not Engine.FRunning then
          begin
            Logger.Info('Server stopping - operation aborted is expected');
            Break;
          end;
        end;
        ERROR_CONNECTION_ABORTED,
        ERROR_NETNAME_DELETED,
        WSAECONNRESET,
        WSAECONNABORTED,
        WSAENOTSOCK,
        WSAETIMEDOUT:
        begin
          if Assigned(OverlappedEx) then
          begin
            Engine.FActiveOverlappedLock.Enter;
            try
              IsActiveCompletion := Engine.FActiveOverlapped.ContainsKey(OverlappedEx);
            finally
              Engine.FActiveOverlappedLock.Leave;
            end;
            if IsActiveCompletion then
            begin
              if (CompletionKey <> 0) and (OverlappedEx^.OpType <> otAccept) and (CompletionKey <> ULONG_PTR(OverlappedEx^.Socket)) then
                Continue;
              if OverlappedEx^.OpType = otAccept then
                Engine.HandleFailedAccept(OverlappedEx)
              else
                Engine.CleanupConnectionWithReason(OverlappedEx, Format('Connection interrupted (code: %d)', [Status]));
            end
            else
              Logger.Info('Connection interrupted for already released overlapped - ignoring');
          end
          else
            Logger.Info(Format('Connection interrupted - no context (code: %d)', [Status]));
        end;
      else
        begin
          if Assigned(OverlappedEx) then
          begin
            Engine.FActiveOverlappedLock.Enter;
            try
              IsActive := Engine.FActiveOverlapped.ContainsKey(OverlappedEx);
            finally
              Engine.FActiveOverlappedLock.Leave;
            end;
            if IsActive then
            begin
              if OverlappedEx^.OpType = otAccept then
                Engine.HandleFailedAccept(OverlappedEx)
              else
              begin
                Logger.Info(Format('GetQueuedCompletionStatus socket error: %d for socket %d', [Status, OverlappedEx^.Socket]));
                Engine.CleanupConnectionWithReason(OverlappedEx, Format('Error GetQueuedCompletionStatus: %d', [Status]));
              end;
            end
            else
              Logger.Info('GetQueuedCompletionStatus error for already released overlapped - ignoring');
          end
          else
          begin
            Inc(ConsecutiveErrors);
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
  end;
  Logger.Info('Worker thread has finished work');
  Result := 0;
end;

class function TIocpWorkerEngine.MonitorThreadProc(Parameter: Pointer): DWORD;
  function FileTimeToInt64(const FT: TFileTime): Int64;
  begin
    Result := Int64(FT.dwLowDateTime) or (Int64(FT.dwHighDateTime) shl 32);
  end;
var
  Engine: TIocpWorkerEngine;
  MemStatus: TMemoryStatusEx;
  RejectReason: string;
  ShouldReject: Boolean;
  LastKernelTime, LastUserTime: TFileTime;
  LastCheckTime: Int64;
  ProcessHandle: THandle;
  CreationTime, ExitTime, KernelTime, UserTime: TFileTime;
  NowFT: TFileTime;
  KernelDiff, UserDiff, TimeDiff: Int64;
  CPUUsage: Double;
  ProcessorCount: Integer;
  Sy: TSystemInfo;
  CurrentRequests: LongInt;
  SleepSteps: Integer;
  S: Integer;
  SessionList: TList<TWebSocketSession>;
  CurrTime: UInt64;
  WS_Session: TWebSocketSession;
  IdleDuration: UInt64;
  CurrTick: UInt64;
  Ov: POverlappedEx;
begin
  Engine := TIocpWorkerEngine(Parameter);
  Result := 0;
  Logger.Info('A thread has been started to monitor the server status.');
  ProcessHandle := GetCurrentProcess;
  GetSystemInfo(Sy);
  ProcessorCount := Sy.dwNumberOfProcessors;
  GetProcessTimes(ProcessHandle, CreationTime, ExitTime, LastKernelTime, LastUserTime);
  GetSystemTimeAsFileTime(NowFT);
  LastCheckTime := FileTimeToInt64(NowFT);
  while Engine.FRunning do
  begin
    SleepSteps := 2;
    if Engine.FRejectNewConnections = 1 then
      SleepSteps := 45;
    for S := 1 to SleepSteps do
    begin
      Sleep(100);
      if not Engine.FRunning then
        Break;
    end;
    if not Engine.FRunning then
      Break;
    ShouldReject := False;
    RejectReason := '';
    try
      if (GetTickCount64 - Engine.FIpSecurity.LastIPPruneTick) >= 5000 then
      begin
        Engine.FIpSecurity.LastIPPruneTick := GetTickCount64;
        Engine.FIpSecurity.PruneInactiveIPTrackers;
      end;
      if GetProcessTimes(ProcessHandle, CreationTime, ExitTime, KernelTime, UserTime) then
      begin
        GetSystemTimeAsFileTime(NowFT);
        KernelDiff := FileTimeToInt64(KernelTime) - FileTimeToInt64(LastKernelTime);
        UserDiff := FileTimeToInt64(UserTime) - FileTimeToInt64(LastUserTime);
        TimeDiff := FileTimeToInt64(NowFT) - LastCheckTime;
        if (TimeDiff > 0) and (ProcessorCount > 0) then
        begin
          CPUUsage := (KernelDiff + UserDiff) * 100.0 / TimeDiff / ProcessorCount;
          LastKernelTime := KernelTime;
          LastUserTime := UserTime;
          LastCheckTime := FileTimeToInt64(NowFT);
          if CPUUsage > 95.0 then
            Logger.Warn('MONITOR: High CPU load from server process (%.1f%%)', [CPUUsage]);
        end;
      end;
      CurrentRequests := TInterlocked.Exchange(Engine.FRequestsPerSecondCounter, 0);
      if CurrentRequests > Engine.FMaxRequestsPerSecond then
        Logger.Warn('MONITOR: High request rate (%d req/s)', [CurrentRequests]);
      TInterlocked.Exchange(Engine.FThrottleNewConnections, 0);

      MemStatus.dwLength := SizeOf(TMemoryStatusEx);
      if GlobalMemoryStatusEx(MemStatus) then
      begin
        if (Engine.FOverlappedPool.FMaxMemoryLoadPercent > 0) and (MemStatus.dwMemoryLoad > Engine.FOverlappedPool.FMaxMemoryLoadPercent) then
        begin
          ShouldReject := True;
          RejectReason := Format('High system memory usage (%d%%)', [MemStatus.dwMemoryLoad]);
        end
        else if (Engine.FOverlappedPool.MinFreeMemoryMb > 0) and ((MemStatus.ullAvailPhys div (1024 * 1024)) < Engine.FOverlappedPool.MinFreeMemoryMb) then
        begin
          ShouldReject := True;
          RejectReason := Format('Low free memory RAM (%d MB)', [MemStatus.ullAvailPhys div (1024 * 1024)]);
        end;
      end;
      if ShouldReject then
      begin
        if InterlockedCompareExchange(Engine.FRejectNewConnections, 1, 0) = 0 then
          Logger.Warn('MONITOR: New call rejection mode has been activated. Reason: %s', [RejectReason]);
      end
      else
      begin
        if InterlockedCompareExchange(Engine.FRejectNewConnections, 0, 1) = 1 then
          Logger.Info('MONITOR: Call rejection mode has been deactivated. Resources are back to normal.');
      end;

      if Engine.FRunning and (Engine.FTargetAcceptCount > 0) then
      begin
        while Engine.FRunning and (Engine.FListenSocket <> INVALID_SOCKET) and (Engine.FPendingHttpsAccepts < Engine.FTargetAcceptCount) do
        begin
          if not Engine.AcceptConnection2(Engine.FListenSocket) then
            Break;
        end;
        while Engine.FRunning and (Engine.FListenSocketHTTP <> INVALID_SOCKET) and (Engine.FPendingHttpAccepts < Engine.FTargetAcceptCount) do
        begin
          if not Engine.AcceptConnection2(Engine.FListenSocketHTTP) then
            Break;
        end;
      end;

      if Assigned(Engine.FWebSocketBridge) and Assigned(Engine.FWebSocketBridge.WebSocketManager) then
      begin
        SessionList := Engine.FWebSocketBridge.WebSocketManager.AcquireSessionList;
        try
          CurrTime := GetTickCount64;
          for WS_Session in SessionList do
          begin
            if WS_Session.InCleanup <> 0 then
              Continue;

            IdleDuration := CurrTime - WS_Session.LastActivityTime;
            if IdleDuration > 660000 then
            begin
              Engine.FWebSocketBridge.CleanupWebSocketSession(WS_Session, 'Idle Timeout (No Pong response)');
            end
            else if IdleDuration > 600000 then
            begin
              if WS_Session.PingPending = 0 then
              begin
                WS_Session.PingPending := 1;
                WS_Session.QueueSendFrame(wsOpPing, []);
                Engine.FWebSocketBridge.TriggerWebSocketWrite(WS_Session);
              end;
            end;
          end;
        finally
          for WS_Session in SessionList do
            WS_Session.Release;
          SessionList.Free;
        end;
      end;

      if Engine.FEnableKeepAlive and Assigned(Engine.FActiveOverlapped) and Assigned(Engine.FActiveOverlappedLock) then
      begin
        Engine.FActiveOverlappedLock.Enter;
        try
          CurrTick := GetTickCount64;
          for Ov in Engine.FActiveOverlapped.Keys do
          begin
            if Assigned(Ov) and Ov^.KeepAliveActive and (Ov^.OpType = otRead) and not Assigned(Ov^.Response) and (Ov^.Socket <> INVALID_SOCKET) then
            begin
              if (CurrTick - Ov^.LastActivityTime) > Engine.FKeepAliveTimeoutMs then
              begin
                Ov^.KeepAliveActive := False;
                shutdown(Ov^.Socket, SD_BOTH);
              end;
            end;
          end;
        finally
          Engine.FActiveOverlappedLock.Leave;
        end;
      end;
    except
    end;
  end;
  RejectReason := '';
  Logger.Info('Monitoring thread terminated.');
end;

end.
