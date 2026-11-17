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
  System.Hash,
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
  Http3.Types,
  Http3.Server,
  Http3.Request,
  Http3.Response,
  WebTransport.Types,
  WebTransport.Server,
  WebTransport.Session,
  MsQuic.Types,
  GHttpsServerTypes,
  GSchannelTlsManager,
  GIpSecurityAndCors,
  GWebSocketBridge,
  GHttp3WebTransportBridge,
  GIocpWorkerEngine;

type
  TServerProtocolMode = GHttpsServerTypes.TServerProtocolMode;
  THttpActionOnDualMode = GHttpsServerTypes.THttpActionOnDualMode;
  TAuthorizationType = GHttpsServerTypes.TAuthorizationType;
  TmTLSMode = GHttpsServerTypes.TmTLSMode;

const
  pmHttpOnly = GHttpsServerTypes.pmHttpOnly;
  pmHttpsOnly = GHttpsServerTypes.pmHttpsOnly;
  pmDualHttpAndHttps = GHttpsServerTypes.pmDualHttpAndHttps;
  haServeNormally = GHttpsServerTypes.haServeNormally;
  haRedirectToHttps = GHttpsServerTypes.haRedirectToHttps;
  atNone = GHttpsServerTypes.atNone;
  atJWTBearer = GHttpsServerTypes.atJWTBearer;
  mtlsDisabled = GHttpsServerTypes.mtlsDisabled;
  mtlsOptional = GHttpsServerTypes.mtlsOptional;
  mtlsRequired = GHttpsServerTypes.mtlsRequired;

type

  THttp3Request = GHttpsServerTypes.THttp3Request;
  THttp3Response = GHttpsServerTypes.THttp3Response;

  TWebTransportSessionProc = GHttpsServerTypes.TWebTransportSessionProc;
  TWebTransportStreamProc = GHttpsServerTypes.TWebTransportStreamProc;
  TWebTransportDatagramProc = GHttpsServerTypes.TWebTransportDatagramProc;
  TWebTransportClosedProc = GHttpsServerTypes.TWebTransportClosedProc;
  TWebTransportRouteItem = GHttpsServerTypes.TWebTransportRouteItem;
  TIPClientInfo = GHttpsServerTypes.TIPClientInfo;

  TGHttpsServerIOCP = class;

  TEndpointEvent = procedure(Sender: TObject;
                             const ARequest: TRequest;
                             const AResponse: TResponse;
                             AServer: TGHttpsServerIOCP) of object;
  TEndpointEventProc = reference to procedure(Sender: TObject;
                                              const ARequest: TRequest;
                                              const AResponse: TResponse;
                                              AServer: TGHttpsServerIOCP);

  TWebSocketMessageProc = reference to procedure(AServer: TGHttpsServerIOCP;
                                             Session: TWebSocketSession;
                                             const MessageText: string;
                                             Opcode: TWebSocketOpcode);
  TWebSocketRawMessageProc = reference to procedure(AServer: TGHttpsServerIOCP;
                                                    Session: TWebSocketSession;
                                                    DataPtr: PByte;
                                                    DataLen: Integer;
                                                    Opcode: TWebSocketOpcode);

  TWebSocketConnectProc = reference to procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession);
  TWebSocketDisconnectProc = reference to procedure(AServer: TGHttpsServerIOCP;
                                                    Session: TWebSocketSession;
                                                    const Reason: string);

  TEndpointItem = class
  private
    FPath: string;
    FMethod: THttpMethod;
    FHandler: TEndpointEvent;
    FHandlerProc: TEndpointEventProc;
    FServer: TGHttpsServerIOCP;
    FAuthorizationType: TAuthorizationType;
  public
    constructor Create(const APath: string;
                       AMethod: THttpMethod;
                       AHandler: TEndpointEvent;
                       AHandlerProc: TEndpointEventProc;
                       AAuthorizationType: TAuthorizationType;
                       AServer: TGHttpsServerIOCP);

    property Path: string read FPath;
    property Method: THttpMethod read FMethod;
    property Handler: TEndpointEvent read FHandler;
    property HandlerProc: TEndpointEventProc read FHandlerProc;
    property AuthorizationType: TAuthorizationType read FAuthorizationType;
  end;

  TGHttpsServerIOCP = class
  private
    FLock: TCriticalSection;
    FJWTManager: TJWTManager;
    FEndpoints: TDictionary<string, TEndpointItem>;
    FRootGetEndpoint: TEndpointItem;
    FFastEndpoints: array[0..15] of TEndpointItem;
    FFastEndpointCount: Integer;
    FCachedAltSvcValue: string;
    FCachedAltSvcPort: Word;
    FOnWebSocketMessage: TWebSocketMessageProc;
    FOnWebSocketConnect: TWebSocketConnectProc;
    FOnWebSocketDisconnect: TWebSocketDisconnectProc;
    FTlsManager: TSchannelTlsManager;
    FIpSecurity: TIpSecurityTracker;
    FCorsPolicy: TCorsAndOriginPolicy;
    FWebSocketBridge: TWebSocketServerBridge;
    FHttp3Bridge: THttp3WebTransportBridge;
    FIocpEngine: TIocpWorkerEngine;
    function GetRunning: Boolean;
    function GetMaxRequestSize: Int64;
    procedure SetMaxRequestSize(const Value: Int64);
    function GetMaxResponseSize: Int64;
    procedure SetMaxResponseSize(const Value: Int64);
    function GetChunkSize: Integer;
    procedure SetChunkSize(const Value: Integer);
    function GetOverlappedPool: TOverlappedExPool;
    function GetEnableHttp3: Boolean;
    procedure SetEnableHttp3(const Value: Boolean);
    function GetHttp3Server: THttp3Server;
    function GetHttp3SettingMaxFieldSectionSize: UInt64;
    procedure SetHttp3SettingMaxFieldSectionSize(const Value: UInt64);
    function GetHttp3SettingQpackMaxTableCapacity: UInt64;
    procedure SetHttp3SettingQpackMaxTableCapacity(const Value: UInt64);
    function GetHttp3SettingQpackBlockedStreams: UInt64;
    procedure SetHttp3SettingQpackBlockedStreams(const Value: UInt64);
    function GetHttp3EnableDemoEndpoints: Boolean;
    procedure SetHttp3EnableDemoEndpoints(const Value: Boolean);
    function GetQuicRequiredServerName: string;
    procedure SetQuicRequiredServerName(const Value: string);
    function GetQuicForceStatelessRetry: Boolean;
    procedure SetQuicForceStatelessRetry(const Value: Boolean);
    function GetQuicAlpnProtocol: string;
    procedure SetQuicAlpnProtocol(const Value: string);
    function GetWebSocketManager: TWebSocketManager;
    function GetActiveConnections: Int64;
    function GetEnableKeepAlive: Boolean;
    procedure SetEnableKeepAlive(const Value: Boolean);
    function GetKeepAliveTimeoutMs: Cardinal;
    procedure SetKeepAliveTimeoutMs(const Value: Cardinal);
    function GetMaxKeepAliveRequests: Integer;
    procedure SetMaxKeepAliveRequests(const Value: Integer);
    function GetProtocolMode: TServerProtocolMode;
    function GetHttpAction: THttpActionOnDualMode;
    procedure SetHttpAction(const Value: THttpActionOnDualMode);
    function GetHttpsPort: Word;
    function GetHttpPort: Word;
    procedure SetHttpPort(const Value: Word);
    function GetBindAddress: string;
    procedure SetBindAddress(const Value: string);
    function GetHttpBindAddress: string;
    procedure SetHttpBindAddress(const Value: string);
    function GetHttpsBindAddress: string;
    procedure SetHttpsBindAddress(const Value: string);
    function GetHttp3BindAddress: string;
    procedure SetHttp3BindAddress(const Value: string);
    function GetEnableCORS: Boolean;
    procedure SetEnableCORS(const Value: Boolean);
    function GetCORSAllowedOrigins: string;
    procedure SetCORSAllowedOrigins(const Value: string);
    function GetCORSAllowedMethods: string;
    procedure SetCORSAllowedMethods(const Value: string);
    function GetCORSAllowedHeaders: string;
    procedure SetCORSAllowedHeaders(const Value: string);
    function GetCORSExposeHeaders: string;
    procedure SetCORSExposeHeaders(const Value: string);
    function GetCORSAllowCredentials: Boolean;
    procedure SetCORSAllowCredentials(const Value: Boolean);
    function GetCORSMaxAge: Integer;
    procedure SetCORSMaxAge(const Value: Integer);
    function GetMaxConnectionsPerIP: Integer;
    procedure SetMaxConnectionsPerIP(const Value: Integer);
    function GetWorkerThreadCount: Integer;
    procedure SetWorkerThreadCount(const Value: Integer);
    function GetEnableIPRateLimiting: Boolean;
    procedure SetEnableIPRateLimiting(const Value: Boolean);
    function GetMaxRequestsPerIPPerSecond: Integer;
    procedure SetMaxRequestsPerIPPerSecond(const Value: Integer);
    function GetEnableTLSSessionResumption: Boolean;
    procedure SetEnableTLSSessionResumption(const Value: Boolean);
    function GetEnableTLSSessionTickets: Boolean;
    procedure SetEnableTLSSessionTickets(const Value: Boolean);
    function GetIPTrackerInactiveTimeoutMs: UInt64;
    procedure SetIPTrackerInactiveTimeoutMs(const Value: UInt64);
    function GetAllowedFileExtensions: TStringList;
    function GetBlockedMimeTypes: TStringList;
    function GetAllowedWebSocketOrigins: string;
    procedure SetAllowedWebSocketOrigins(const Value: string);
    function GetAllowedWebTransportOrigins: string;
    procedure SetAllowedWebTransportOrigins(const Value: string);
    function GetSupportedWebSocketProtocols: TArray<string>;
    procedure SetSupportedWebSocketProtocols(const Value: TArray<string>);
    function GetmTLSMode: TmTLSMode;
    procedure SetmTLSMode(const Value: TmTLSMode);
    function GetmTLSCAPath: string;
    function GetOnValidateClientCertificate: TClientCertValidateEvent;
    procedure SetOnValidateClientCertificate(const Value: TClientCertValidateEvent);
    function FindEndpoint(AMethod: THttpMethod; const APath: string): TEndpointItem;
    procedure ProcessHttpRequest(OverlappedEx: POverlappedEx);
  protected
    function DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                             var PlainData: TBytes; out BytesConsumed: Integer): Boolean; overload;
    function DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
                             var PlainData: TBytes; out BytesConsumed: Integer; out AStatus: SECURITY_STATUS): Boolean; overload;
    procedure FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
  public
    procedure TriggerWebSocketWrite(Session: TWebSocketSession);
    procedure CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
    constructor Create(APort: Word = 443;
                       ASubjectName: String = '';
                       ACertificateStore: String = 'GHttpsIOCPSvr';
                       ASecretKey: String = 'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!';
                       AMaxConnections: Integer = 2000;
                       AMaxRequestsPerSecond: Integer = DEFAULT_MAXREQUESTSPERSECOND;
                       AMaxRequestHederSize: Int64 = DEFAULT_MAX_REQUEST_HEDER_SIZE;
                       AMaxRequestSize: Int64 = DEFAULT_MAX_REQUEST_SIZE;
                       AMaxResponseSize: Int64 = DEFAULT_MAX_RESPONSE_SIZE;
                       AChunkSize: Integer = DEFAULT_CHUNK_SIZE;
                       AMinFreeMemoryMb: Cardinal = 50;
                       AMaxMemoryLoadPercent: Byte = 95;
                       AMonitorRun: Boolean = True;
                       AEnableKeepAlive: Boolean = True;
                       AHttpPort: Word = 0;
                       AHttpAction: THttpActionOnDualMode = haServeNormally;
                       AWorkerThreadCount: Integer = 0);
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
                                      AAuthorizationType: TAuthorizationType = atNone);
    procedure RegisterWebSocketRoute(const APath: string); overload;
    procedure RegisterWebSocketRoute(const APath: string; AOnMessage: TWebSocketMessageProc); overload;
    procedure RegisterWebSocketRoute(const APath: string; AOnMessage: TWebSocketMessageProc; AAuthType: TAuthorizationType; const ASupportedProtocols: TArray<string> = nil); overload;
    procedure RegisterWebSocketRawRoute(const APath: string; AOnMessage: TWebSocketRawMessageProc; AAuthType: TAuthorizationType = atNone);
    procedure RevokeJWTToken(const AToken: string);
    function IsJWTTokenRevoked(const AToken: string): Boolean;
    procedure RegisterWebTransportRoute(const APath: string); overload;
    procedure RegisterWebTransportRoute(
      const APath: string;
      AOnSessionReady: TWebTransportSessionProc;
      AOnStreamData: TWebTransportStreamProc;
      AOnDatagram: TWebTransportDatagramProc;
      AOnSessionClosed: TWebTransportClosedProc = nil
    ); overload;
    function GetCertificateSha256Hash: TBytes;
    procedure PruneInactiveIPTrackers;
    function GetTrackedIPCount: Integer;
    function LoadCACertificate(const AFileName: string): Boolean;
    function AddTrustedCertificate(const AFileName: string): Boolean;
    property OnWebSocketMessage: TWebSocketMessageProc read FOnWebSocketMessage write FOnWebSocketMessage;
    property OnWebSocketConnect: TWebSocketConnectProc read FOnWebSocketConnect write FOnWebSocketConnect;
    property OnWebSocketDisconnect: TWebSocketDisconnectProc read FOnWebSocketDisconnect write FOnWebSocketDisconnect;
    property Running: Boolean read GetRunning;
    property MaxRequestSize: Int64 read GetMaxRequestSize write SetMaxRequestSize;
    property MaxResponseSize: Int64 read GetMaxResponseSize write SetMaxResponseSize;
    property ChunkSize: Integer read GetChunkSize write SetChunkSize;
    property OverlappedPool: TOverlappedExPool read GetOverlappedPool;
    property JWTManager: TJWTManager read FJWTManager;
    property EnableHttp3: Boolean read GetEnableHttp3 write SetEnableHttp3;
    property Http3Server: THttp3Server read GetHttp3Server;
    property Http3SettingMaxFieldSectionSize: UInt64 read GetHttp3SettingMaxFieldSectionSize write SetHttp3SettingMaxFieldSectionSize;
    property Http3SettingQpackMaxTableCapacity: UInt64 read GetHttp3SettingQpackMaxTableCapacity write SetHttp3SettingQpackMaxTableCapacity;
    property Http3SettingQpackBlockedStreams: UInt64 read GetHttp3SettingQpackBlockedStreams write SetHttp3SettingQpackBlockedStreams;
    property Http3EnableDemoEndpoints: Boolean read GetHttp3EnableDemoEndpoints write SetHttp3EnableDemoEndpoints;
    property QuicRequiredServerName: string read GetQuicRequiredServerName write SetQuicRequiredServerName;
    property QuicForceStatelessRetry: Boolean read GetQuicForceStatelessRetry write SetQuicForceStatelessRetry;
    property QuicAlpnProtocol: string read GetQuicAlpnProtocol write SetQuicAlpnProtocol;
    property WebSocketManager: TWebSocketManager read GetWebSocketManager;
    property ActiveConnections: Int64 read GetActiveConnections;
    property EnableKeepAlive: Boolean read GetEnableKeepAlive write SetEnableKeepAlive;
    property KeepAliveTimeoutMs: Cardinal read GetKeepAliveTimeoutMs write SetKeepAliveTimeoutMs;
    property MaxKeepAliveRequests: Integer read GetMaxKeepAliveRequests write SetMaxKeepAliveRequests;
    property ProtocolMode: TServerProtocolMode read GetProtocolMode;
    property HttpAction: THttpActionOnDualMode read GetHttpAction write SetHttpAction;
    property HttpsPort: Word read GetHttpsPort;
    property HttpPort: Word read GetHttpPort write SetHttpPort;
    property BindAddress: string read GetBindAddress write SetBindAddress;
    property HttpBindAddress: string read GetHttpBindAddress write SetHttpBindAddress;
    property HttpsBindAddress: string read GetHttpsBindAddress write SetHttpsBindAddress;
    property Http3BindAddress: string read GetHttp3BindAddress write SetHttp3BindAddress;
    property EnableCORS: Boolean read GetEnableCORS write SetEnableCORS;
    property CORSAllowedOrigins: string read GetCORSAllowedOrigins write SetCORSAllowedOrigins;
    property CORSAllowedMethods: string read GetCORSAllowedMethods write SetCORSAllowedMethods;
    property CORSAllowedHeaders: string read GetCORSAllowedHeaders write SetCORSAllowedHeaders;
    property CORSExposeHeaders: string read GetCORSExposeHeaders write SetCORSExposeHeaders;
    property CORSAllowCredentials: Boolean read GetCORSAllowCredentials write SetCORSAllowCredentials;
    property CORSMaxAge: Integer read GetCORSMaxAge write SetCORSMaxAge;
    property MaxConnectionsPerIP: Integer read GetMaxConnectionsPerIP write SetMaxConnectionsPerIP;
    property WorkerThreadCount: Integer read GetWorkerThreadCount write SetWorkerThreadCount;
    property EnableIPRateLimiting: Boolean read GetEnableIPRateLimiting write SetEnableIPRateLimiting;
    property MaxRequestsPerIPPerSecond: Integer read GetMaxRequestsPerIPPerSecond write SetMaxRequestsPerIPPerSecond;
    property EnableTLSSessionResumption: Boolean read GetEnableTLSSessionResumption write SetEnableTLSSessionResumption;
    property EnableTLSSessionTickets: Boolean read GetEnableTLSSessionTickets write SetEnableTLSSessionTickets;
    property IPTrackerInactiveTimeoutMs: UInt64 read GetIPTrackerInactiveTimeoutMs write SetIPTrackerInactiveTimeoutMs;
    property AllowedFileExtensions: TStringList read GetAllowedFileExtensions;
    property BlockedMimeTypes: TStringList read GetBlockedMimeTypes;
    property AllowedWebSocketOrigins: string read GetAllowedWebSocketOrigins write SetAllowedWebSocketOrigins;
    property AllowedWebTransportOrigins: string read GetAllowedWebTransportOrigins write SetAllowedWebTransportOrigins;
    property SupportedWebSocketProtocols: TArray<string> read GetSupportedWebSocketProtocols write SetSupportedWebSocketProtocols;
    property mTLSMode: TmTLSMode read GetmTLSMode write SetmTLSMode;
    property mTLSCAPath: string read GetmTLSCAPath;
    property OnValidateClientCertificate: TClientCertValidateEvent read GetOnValidateClientCertificate write SetOnValidateClientCertificate;
  end;

function GetPrimaryIPv4Address: string;

implementation

function GetPrimaryIPv4Address: string;
begin
  Result := GHttpsServerTypes.GetPrimaryIPv4Address;
end;

constructor TEndpointItem.Create(const APath: string;
                                 AMethod: THttpMethod;
                                 AHandler: TEndpointEvent;
                                 AHandlerProc: TEndpointEventProc;
                                 AAuthorizationType: TAuthorizationType;
                                 AServer: TGHttpsServerIOCP);
begin
  inherited Create;
  FPath := APath;
  FMethod := AMethod;
  FHandler := AHandler;
  FHandlerProc := AHandlerProc;
  FServer := AServer;
  FAuthorizationType := AAuthorizationType;
end;

constructor TGHttpsServerIOCP.Create(APort: Word;
                                   ASubjectName: String;
                                   ACertificateStore: String;
                                   ASecretKey: String;
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
                                   AWorkerThreadCount: Integer);
var
  AutoWorkers: Integer;
  ResolvedWorkerCount: Integer;
  ResolvedSubject: string;
  RunningPtr: PBoolean;
  RejectPtr: PLongInt;
  ActiveConnPtr: PInt64;
  MaxConnPtr: PInteger;
  ReqPerSecPtr: PLongInt;
  MaxHdrPtr: PInteger;
  MaxReqPtr: PInt64;
  MtlsModePtr: Pointer;
  CompPortPtr: PHandle;
begin
  inherited Create;

  if AWorkerThreadCount > 0 then
    ResolvedWorkerCount := AWorkerThreadCount
  else
  begin
    AutoWorkers := TThread.ProcessorCount * 2;
    if AutoWorkers < 4 then
      AutoWorkers := 4;
    if AutoWorkers > 32 then
      AutoWorkers := 32;
    ResolvedWorkerCount := AutoWorkers;
  end;

  if ASubjectName <> '' then
    ResolvedSubject := ASubjectName
  else
    ResolvedSubject := GetPrimaryIPv4Address;

  FLock := TCriticalSection.Create;
  FJWTManager := TJWTManager.Create(
    ASecretKey,
    'JWTManager',
    120,
    'GHttpsServerIOP'
  );
  FEndpoints := TDictionary<string, TEndpointItem>.Create;
  FRootGetEndpoint := nil;
  FFastEndpointCount := 0;
  FillChar(FFastEndpoints, SizeOf(FFastEndpoints), 0);
  FCachedAltSvcValue := '';
  FCachedAltSvcPort := 0;

  FTlsManager := TSchannelTlsManager.Create(ResolvedSubject, ACertificateStore);
  FTlsManager.SSLShutdownTimeout := 200;

  FIpSecurity := TIpSecurityTracker.Create;
  FIpSecurity.MaxConnectionsPerIP := 100;
  FIpSecurity.EnableIPRateLimiting := True;
  FIpSecurity.MaxRequestsPerIPPerSecond := 150;
  FIpSecurity.IPTrackerInactiveTimeoutMs := 60000;

  FCorsPolicy := TCorsAndOriginPolicy.Create;
  FCorsPolicy.EnableCORS := True;
  FCorsPolicy.CORSAllowedOrigins := '*';
  FCorsPolicy.CORSAllowedMethods := 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH';
  FCorsPolicy.CORSAllowedHeaders := 'Content-Type, Authorization, Accept, X-Requested-With, Origin, Access-Control-Request-Method, Access-Control-Request-Headers';
  FCorsPolicy.CORSExposeHeaders := 'Content-Length, Content-Encoding, Date, Server, Alt-Svc';
  FCorsPolicy.CORSAllowCredentials := False;
  FCorsPolicy.CORSMaxAge := 86400;
  FCorsPolicy.AllowedWebSocketOrigins := '*';
  FCorsPolicy.AllowedWebTransportOrigins := '*';

  FIocpEngine := TIocpWorkerEngine.Create(
    APort,
    AMaxConnections,
    AMaxRequestsPerSecond,
    AMaxRequestHederSize,
    AMaxRequestSize,
    AMaxResponseSize,
    AChunkSize,
    AMinFreeMemoryMb,
    AMaxMemoryLoadPercent,
    AMonitorRun,
    AEnableKeepAlive,
    AHttpPort,
    AHttpAction,
    ResolvedWorkerCount,
    FTlsManager,
    FIpSecurity
  );

  if (APort = 0) and (AHttpPort > 0) then
  begin
    FIocpEngine.ProtocolMode := pmHttpOnly;
    FIocpEngine.Port := AHttpPort;
  end;

  CompPortPtr := FIocpEngine.CompletionPortPtr;
  ActiveConnPtr := FIocpEngine.ActiveConnectionsPtr;
  FWebSocketBridge := TWebSocketServerBridge.Create(
    FLock,
    FTlsManager,
    FIocpEngine.OverlappedPool,
    FIocpEngine.ActiveOverlapped,
    FIocpEngine.ActiveOverlappedLock,
    CompPortPtr,
    ActiveConnPtr
  );
  FWebSocketBridge.OnConnectNotify :=
    procedure(Session: TWebSocketSession)
    begin
      if Assigned(FOnWebSocketConnect) then
        FOnWebSocketConnect(Self, Session);
    end;
  FWebSocketBridge.OnDisconnectNotify :=
    procedure(Session: TWebSocketSession; const Reason: string)
    begin
      if Assigned(FOnWebSocketDisconnect) then
        FOnWebSocketDisconnect(Self, Session, Reason);
    end;
  FWebSocketBridge.OnCleanupConnection :=
    procedure(OverlappedEx: POverlappedEx; const Reason: string)
    begin
      FIocpEngine.CleanupConnectionWithReason(OverlappedEx, Reason);
    end;
  FWebSocketBridge.OnIssueWSARecv :=
    function(OverlappedEx: POverlappedEx): Boolean
    begin
      Result := FIocpEngine.IssueWSARecv(OverlappedEx);
    end;
  FWebSocketBridge.OnTrackIPDisconnect :=
    procedure(const AIP: string)
    begin
      FIpSecurity.TrackIPDisconnect(AIP);
    end;

  FIocpEngine.WebSocketBridge := FWebSocketBridge;
  FIocpEngine.OnProcessHttpRequest :=
    procedure(OverlappedEx: POverlappedEx)
    begin
      ProcessHttpRequest(OverlappedEx);
    end;
  FIocpEngine.OnWebSocketRouteMessage :=
    procedure(const HandlerIntf: IInterface; Session: TWebSocketSession; const MsgStr: string; Opcode: TWebSocketOpcode)
    var
      H: TWebSocketMessageProc;
    begin
      PInterface(@H)^ := HandlerIntf;
      try
        H(Self, Session, MsgStr, Opcode);
      finally
        H := nil;
      end;
    end;
  FIocpEngine.OnWebSocketRawRouteMessage :=
    procedure(const HandlerIntf: IInterface; Session: TWebSocketSession; DataPtr: PByte; DataLen: Integer; Opcode: TWebSocketOpcode)
    var
      H: TWebSocketRawMessageProc;
    begin
      PInterface(@H)^ := HandlerIntf;
      try
        H(Self, Session, DataPtr, DataLen, Opcode);
      finally
        H := nil;
      end;
    end;
  FIocpEngine.OnWebSocketGlobalMessage :=
    function(Session: TWebSocketSession; const MsgStr: string; Opcode: TWebSocketOpcode): Boolean
    begin
      Result := False;
      if Assigned(FOnWebSocketMessage) then
      begin
        Result := True;
        FOnWebSocketMessage(Self, Session, MsgStr, Opcode);
      end;
    end;

  RunningPtr := FIocpEngine.RunningPtr;
  RejectPtr := FIocpEngine.RejectNewConnectionsPtr;
  MaxConnPtr := FIocpEngine.MaxConnectionsPtr;
  ReqPerSecPtr := FIocpEngine.RequestsPerSecondCounterPtr;
  MaxHdrPtr := FIocpEngine.MaxRequestHederSizePtr;
  MaxReqPtr := FIocpEngine.MaxRequestSizePtr;
  MtlsModePtr := FTlsManager.mTLSModePtr;
  FHttp3Bridge := THttp3WebTransportBridge.Create(
    FLock,
    FIpSecurity,
    FCorsPolicy,
    FJWTManager,
    RunningPtr,
    RejectPtr,
    ActiveConnPtr,
    MaxConnPtr,
    ReqPerSecPtr,
    MaxHdrPtr,
    MaxReqPtr,
    MtlsModePtr,
    FIocpEngine.AllowedFileExtensions,
    FIocpEngine.BlockedMimeTypes
  );
  FHttp3Bridge.EnableHttp3 := (FIocpEngine.ProtocolMode <> pmHttpOnly);
  FHttp3Bridge.Http3SettingMaxFieldSectionSize := 32768;
  FHttp3Bridge.Http3SettingQpackMaxTableCapacity := 4096;
  FHttp3Bridge.Http3SettingQpackBlockedStreams := 100;
  FHttp3Bridge.Http3EnableDemoEndpoints := False;
  FHttp3Bridge.QuicForceStatelessRetry := True;
  FHttp3Bridge.OnEndpointLookup :=
    function(AMethod: THttpMethod; const APath: string; out AAuthType: TAuthorizationType; out AKey: string): Boolean
    var
      Ep: TEndpointItem;
    begin
      Ep := FindEndpoint(AMethod, APath);
      Result := Assigned(Ep);
      if Result then
      begin
        AAuthType := Ep.AuthorizationType;
        AKey := APath;
      end
      else
      begin
        AAuthType := atNone;
        AKey := '';
      end;
    end;
  FHttp3Bridge.OnEndpointInvoke :=
    procedure(AMethod: THttpMethod; const APath: string; const ARequest: TRequest; const AResponse: TResponse)
    var
      Ep: TEndpointItem;
    begin
      Ep := FindEndpoint(AMethod, APath);
      if Assigned(Ep) then
      begin
        if Assigned(Ep.Handler) then
          Ep.Handler(Self, ARequest, AResponse, Self)
        else if Assigned(Ep.HandlerProc) then
          Ep.HandlerProc(Self, ARequest, AResponse, Self);
      end;
    end;

  Logger.Info(Format('Creating OverlappedEx pool. Max connections: %d', [AMaxConnections]));
  case FIocpEngine.ProtocolMode of
    pmHttpOnly:
      Logger.Info(Format('HTTP Server created (HTTP-Only on port %d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FIocpEngine.HttpPort, FIocpEngine.MaxRequestSize div 1048576, FIocpEngine.MaxResponseSize div 1048576, FIocpEngine.ChunkSize div 1024]));
    pmDualHttpAndHttps:
      Logger.Info(Format('Dual-Stack Server created (HTTP:%d + HTTPS:%d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FIocpEngine.HttpPort, FIocpEngine.HttpsPort, FIocpEngine.MaxRequestSize div 1048576, FIocpEngine.MaxResponseSize div 1048576, FIocpEngine.ChunkSize div 1024]));
    pmHttpsOnly:
      Logger.Info(Format('HTTPS Server created (HTTPS-Only on port %d) - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
                         [FIocpEngine.HttpsPort, FIocpEngine.MaxRequestSize div 1048576, FIocpEngine.MaxResponseSize div 1048576, FIocpEngine.ChunkSize div 1024]));
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

  FreeAndNil(FWebSocketBridge);
  FreeAndNil(FHttp3Bridge);

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
  FRootGetEndpoint := nil;
  FFastEndpointCount := 0;
  FillChar(FFastEndpoints, SizeOf(FFastEndpoints), 0);

  FreeAndNil(FIocpEngine);
  FreeAndNil(FJWTManager);
  FreeAndNil(FIpSecurity);
  FreeAndNil(FCorsPolicy);
  FreeAndNil(FTlsManager);

  ElapsedMs := Round((Now - StartTime) * 86400000);
  Logger.Info('Cleanup TGHttpsServerIOCP end in %dms', [ElapsedMs]);

  inherited;
end;

function TGHttpsServerIOCP.FindEndpoint(AMethod: THttpMethod; const APath: string): TEndpointItem;
var
  FastIdx: Integer;
  Key: string;
begin
  Result := nil;
  for FastIdx := 0 to FFastEndpointCount - 1 do
  begin
    if (FFastEndpoints[FastIdx].Method = AMethod) and
       (FFastEndpoints[FastIdx].Path = APath) then
    begin
      Result := FFastEndpoints[FastIdx];
      Exit;
    end;
  end;
  Key := GetEndpointKey(AMethod, APath);
  FLock.Enter;
  try
    if not FEndpoints.TryGetValue(Key, Result) then
    begin
      if (AMethod = hmGET) and (APath = '/') then
        FEndpoints.TryGetValue(GetEndpointKey(hmGET, '/'), Result);
    end;
  finally
    FLock.Leave;
  end;
end;

function TGHttpsServerIOCP.Start: Boolean;
const
  CERT_SHA1_HASH_PROP_ID = 3;
var
  AcceptIdx: Integer;
  InitialAcceptCount: Integer;
  Http3DllErr: string;
  ThreadId: DWORD;
  H3HashHex: string;
  HashBytes: array[0..19] of Byte;
  HashSize: DWORD;
  B: Byte;
  H3Svr: THttp3Server;
begin
  Logger.Info('SSL Shutdown Configuration:');
  Logger.Info(Format('  Graceful shutdown: %s', [BoolToStr(FTlsManager.EnableGracefulSSLShutdownFlag, True)]));
  Logger.Info(Format('  Timeout: %dms', [FTlsManager.SSLShutdownTimeout]));
  Result := False;
  if FIocpEngine.Running then
    Exit;

  if FHttp3Bridge.EnableHttp3 and (FIocpEngine.ProtocolMode <> pmHttpOnly) and not IsMsQuicDllAvailable(Http3DllErr) then
  begin
    Logger.Critical('CRITICAL ERROR: Failed to load required HTTP/3 libraries: ' + Http3DllErr);
    Logger.Critical('The server cannot start without working msquic.dll and ls-qpack.dll.');
    Logger.Critical(Format('Place valid 64-bit DLL files in: %s', [ExtractFilePath(ParamStr(0))]));
    Exit;
  end;

  if not FIocpEngine.InitializeWinsock then
  begin
    Logger.Info('Winsock initialization error');
    Exit;
  end;

  if FIocpEngine.ProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps] then
  begin
    if not FIocpEngine.CreateListenSocket then
    begin
      Logger.Error('[START-FAILED] Could not bind HTTPS TCP socket on port %d. Server startup aborted.', [FIocpEngine.HttpsPort]);
      FIocpEngine.CleanupWinsock;
      Exit;
    end;
  end;

  if FIocpEngine.ProtocolMode in [pmHttpOnly, pmDualHttpAndHttps] then
  begin
    if not FIocpEngine.CreateHttpListenSocket then
    begin
      Logger.Error('[START-FAILED] Could not bind HTTP TCP socket on port %d. Server startup aborted.', [FIocpEngine.HttpPort]);
      FIocpEngine.CleanupWinsock;
      Exit;
    end;
  end;

  if not FIocpEngine.CreateCompletionPort then
  begin
    Logger.Info('Failed to create Completion Port');
    FIocpEngine.CleanupWinsock;
    Exit;
  end;

  if FIocpEngine.ProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps] then
  begin
    if not FTlsManager.LoadServerCertificate then
    begin
      Logger.Error('');
      Logger.Error('================================================================');
      Logger.Error('  CRITICAL ERROR: TLS certificate not found in Windows store!');
      Logger.Error('  The server cannot start without a valid TLS certificate.');
      Logger.Error('  Run from the project root directory:');
      Logger.Error('  powershell -ExecutionPolicy Bypass -File gen_quic_cert.ps1');
      Logger.Error('================================================================');
      Logger.Error('');
      FIocpEngine.CleanupWinsock;
      Exit;
    end;

    if not FTlsManager.InitializeSSLCredentials then
    begin
      Logger.Error('Failed to initialize SSL credentials');
      FIocpEngine.CleanupWinsock;
      Exit;
    end;
  end;

  FIocpEngine.Running := True;

  if not FIocpEngine.CreateWorkerThreads then
  begin
    FIocpEngine.Running := False;
    Logger.Info('Failed to create worker threads');
    FIocpEngine.CleanupWinsock;
    Exit;
  end;

  FIocpEngine.RejectNewConnections := 0;
  if FIocpEngine.MonitorRun then
  begin
    FIocpEngine.MonitorThread := CreateThread(nil, 0, @TIocpWorkerEngine.MonitorThreadProc, FIocpEngine, 0, ThreadId);
    if FIocpEngine.MonitorThread = 0 then
    begin
      Logger.Error('Critical error: Failed to create monitoring thread.');
      Stop;
      Exit;
    end;
  end;

  InitialAcceptCount := 16;
  if FIocpEngine.MaxConnections > 0 then
  begin
    InitialAcceptCount := FIocpEngine.MaxConnections div 8;
    if InitialAcceptCount > 16 then
      InitialAcceptCount := 16;
    if InitialAcceptCount < 1 then
      InitialAcceptCount := 1;
  end;
  FIocpEngine.TargetAcceptCount := InitialAcceptCount;
  FIocpEngine.ResetPendingAccepts;

  if FIocpEngine.ListenSocket <> INVALID_SOCKET then
  begin
    for AcceptIdx := 1 to InitialAcceptCount do
      FIocpEngine.AcceptConnection2(FIocpEngine.ListenSocket);
    Logger.Info('HTTPS server listening on ' + IfThen(FIocpEngine.EffectiveHttpsBindAddress = '', '0.0.0.0', FIocpEngine.EffectiveHttpsBindAddress) + ':' + IntToStr(FIocpEngine.HttpsPort));
  end;

  if FIocpEngine.ListenSocketHTTP <> INVALID_SOCKET then
  begin
    for AcceptIdx := 1 to InitialAcceptCount do
      FIocpEngine.AcceptConnection2(FIocpEngine.ListenSocketHTTP);
    Logger.Info('HTTP server listening on ' + IfThen(FIocpEngine.EffectiveHttpBindAddress = '', '0.0.0.0', FIocpEngine.EffectiveHttpBindAddress) + ':' + IntToStr(FIocpEngine.HttpPort));
  end;

  if FHttp3Bridge.EnableHttp3 and (FIocpEngine.ProtocolMode <> pmHttpOnly) then
  begin
    try
      Logger.Info(Format('[H3] Starting HTTP/3 creation with FCertContext=%p, FH3CertContext=%p, FCertificateStore=%s',
        [FTlsManager.CertContext, FTlsManager.H3CertContext, FTlsManager.CertificateStore]));
      H3HashHex := '';
      if FTlsManager.CertContext <> nil then
      begin
        HashSize := 20;
        if CertGetCertificateContextProperty(FTlsManager.CertContext, CERT_SHA1_HASH_PROP_ID,
                                             @HashBytes[0], HashSize) then
        begin
          for B in HashBytes do
            H3HashHex := H3HashHex + IntToHex(B, 2);
          Logger.Info('[H3] SHA-1 thumbprint extracted from FCertContext: ' + H3HashHex);
        end;
      end;

      Logger.Info(Format('[H3] Creating HTTP/3 server with SHA-1 hash %s from store LocalMachine\%s', [H3HashHex, FTlsManager.CertificateStore]));
      H3Svr := THttp3Server.Create(H3HashHex, FTlsManager.CertificateStore, FTlsManager.SubjectName, FTlsManager.ServerCertStore);
      FHttp3Bridge.Http3Server := H3Svr;
      H3Svr.EnableWebTransport;
      H3Svr.WebTransport.AllowedOrigins := FCorsPolicy.AllowedWebTransportOrigins;
      H3Svr.OnHttpRequest := FHttp3Bridge.HandleHttp3Request;

      H3Svr.WebTransport.OnSessionRequest := FHttp3Bridge.WebTransportSessionRequest;
      H3Svr.WebTransport.OnSessionReady := FHttp3Bridge.WebTransportSessionReady;
      H3Svr.WebTransport.OnSessionClosed := FHttp3Bridge.WebTransportSessionClosed;
      H3Svr.WebTransport.OnStreamData := FHttp3Bridge.WebTransportStreamData;
      H3Svr.WebTransport.OnDatagram := FHttp3Bridge.WebTransportDatagram;
      H3Svr.WebTransport.OnDatagramPtr := FHttp3Bridge.WebTransportDatagramPtr;

      H3Svr.SettingMaxFieldSectionSize := FHttp3Bridge.Http3SettingMaxFieldSectionSize;
      H3Svr.SettingQpackMaxTableCapacity := FHttp3Bridge.Http3SettingQpackMaxTableCapacity;
      H3Svr.SettingQpackBlockedStreams := FHttp3Bridge.Http3SettingQpackBlockedStreams;
      H3Svr.EnableDemoEndpoints := FHttp3Bridge.Http3EnableDemoEndpoints;
      H3Svr.MaxRequestBodySize := UInt64(FIocpEngine.MaxRequestSize);
      if Assigned(H3Svr.QuicServer) then
      begin
        H3Svr.QuicServer.ForceStatelessRetry := FHttp3Bridge.QuicForceStatelessRetry;
        H3Svr.QuicServer.RequiredServerName := FHttp3Bridge.QuicRequiredServerName;
        H3Svr.QuicServer.BindAddress := FIocpEngine.EffectiveHttp3BindAddress;
        if FHttp3Bridge.QuicAlpnProtocol <> '' then
          H3Svr.QuicServer.AlpnProtocol := AnsiString(FHttp3Bridge.QuicAlpnProtocol);
        H3Svr.QuicServer.mTLSRequired := (FTlsManager.mTLSMode = mtlsRequired);
        H3Svr.QuicServer.mTLSOptional := (FTlsManager.mTLSMode = mtlsOptional);
        H3Svr.QuicServer.CACertContext := FTlsManager.CACertContext;
        H3Svr.QuicServer.OnValidateClientCertificate := FTlsManager.OnValidateClientCertificate;
        H3Svr.QuicServer.OnBeforeAcceptConnection := FHttp3Bridge.HandleQuicBeforeAcceptConnection;
        H3Svr.QuicServer.OnAfterCloseConnection := FHttp3Bridge.HandleQuicAfterCloseConnection;
        H3Svr.QuicServer.OnHandshakeFailed := FHttp3Bridge.HandleQuicHandshakeFailed;
      end;

      H3Svr.Start(FIocpEngine.HttpsPort);
      Logger.Info(Format('HTTP/3 & WebTransport (UDP) server listening on %s:%d', [IfThen(FIocpEngine.EffectiveHttp3BindAddress = '', '0.0.0.0', FIocpEngine.EffectiveHttp3BindAddress), FIocpEngine.HttpsPort]));
    except
      on E: Exception do
      begin
        if (Pos('0x80072740', E.Message) > 0) or (Pos('Address in use', E.Message) > 0) then
          Logger.Error(Format('CRITICAL ERROR: Failed to start HTTP/3 (UDP) server on port %d! UDP Port is already in use by another application.', [FIocpEngine.HttpsPort]))
        else
          Logger.Error(Format('CRITICAL ERROR: Failed to start HTTP/3 (UDP) server on port %d! Error: %s', [FIocpEngine.HttpsPort, E.Message]));

        if Assigned(FHttp3Bridge.Http3Server) then
        begin
          try
            FHttp3Bridge.Http3Server.Free;
          except
            Logger.Error('ERROR  FHttp3Server.Free : ' + E.Message);
          end;
          FHttp3Bridge.Http3Server := nil;
        end;

        Stop;
        Result := False;
        Exit;
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
  SessionList: TList<TWebSocketSession>;
  WS_Session: TWebSocketSession;
  WaitResult: DWORD;
begin
  if not FIocpEngine.Running then
    Exit;
  Logger.Info('[STOP-1] Stopping the server...');
  FIocpEngine.Running := False;

  if Assigned(FWebSocketBridge) and Assigned(FWebSocketBridge.WebSocketManager) then
  begin
    try
      Logger.Info('[STOP-1B] Sending WebSocket close frames (1001 Going Away)...');
      SessionList := FWebSocketBridge.WebSocketManager.AcquireSessionList;
      try
        for WS_Session in SessionList do
        begin
          if Assigned(WS_Session) and (WS_Session.InCleanup = 0) then
          begin
            try
              WS_Session.QueueSendFrame(wsOpClose, [$03, $E9]);
              FWebSocketBridge.TriggerWebSocketWrite(WS_Session);
            except
              on E: Exception do
                Logger.Error('[STOP-WS-SENDCLOSE-ERR] Exception sending Close frame: %s', [E.Message]);
            end;
          end;
        end;

        Sleep(100);
      finally
        for WS_Session in SessionList do
          WS_Session.Release;
        SessionList.Free;
      end;
    except
      on E: Exception do
        Logger.Error('[STOP-WS-ERR] Error in WebSocket stop loop: %s (%s)', [E.Message, E.ClassName]);
    end;
  end;

  if Assigned(FHttp3Bridge) and (FHttp3Bridge.Http3Server <> nil) then
  begin
    try
      Logger.Info('[STOP-2] Stopping HTTP/3 server...');
      FHttp3Bridge.Http3Server.Free;
      FHttp3Bridge.Http3Server := nil;
      Logger.Info('[STOP-3] HTTP/3 server stopped cleanly.');
    except
      on E: Exception do
        Logger.Error('[STOP-ERR-H3] Error stopping HTTP/3 server: ' + E.Message);
    end;
  end;

  if FIocpEngine.ListenSocket <> INVALID_SOCKET then
  begin
    Logger.Info('[STOP-4] Closing the HTTPS listening socket...');
    closesocket(FIocpEngine.ListenSocket);
    FIocpEngine.ListenSocket := INVALID_SOCKET;
  end;

  if FIocpEngine.ListenSocketHTTP <> INVALID_SOCKET then
  begin
    Logger.Info('[STOP-4B] Closing the HTTP listening socket...');
    closesocket(FIocpEngine.ListenSocketHTTP);
    FIocpEngine.ListenSocketHTTP := INVALID_SOCKET;
  end;

  Logger.Info('[STOP-5] Closing active client sockets...');
  FIocpEngine.ActiveOverlappedLock.Enter;
  try
    ActiveListCopy := FIocpEngine.ActiveOverlapped.Keys.ToArray;
    Logger.Info('[STOP-6] Found %d active connections to close.', [Length(ActiveListCopy)]);
  finally
    FIocpEngine.ActiveOverlappedLock.Leave;
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

  if (FIocpEngine.CompletionPort <> 0) and (FIocpEngine.WorkerThreads.Count > 0) then
  begin
    Logger.Info('[STOP-8] Sending shutdown signals to worker threads...');
    for i := 1 to FIocpEngine.WorkerThreads.Count do
      PostQueuedCompletionStatus(FIocpEngine.CompletionPort, 0, 0, nil);
  end;

  Logger.Info('[STOP-9] Waiting for worker threads...');
  if FIocpEngine.WorkerThreads.Count > 0 then
  begin
    SetLength(Handles, FIocpEngine.WorkerThreads.Count);
    for i := 0 to FIocpEngine.WorkerThreads.Count - 1 do
      Handles[i] := FIocpEngine.WorkerThreads[i];

    WaitResult := WaitForMultipleObjects(Min(Length(Handles), 64), @Handles[0], True, 1000);
    Logger.Info(Format('[STOP-10] WaitForMultipleObjects result: %d', [WaitResult]));
  end;

  if FIocpEngine.MonitorRun then
  begin
    if FIocpEngine.MonitorThread <> 0 then
    begin
      Logger.Info('[STOP-11] Waiting for monitoring thread...');
      WaitForSingleObject(FIocpEngine.MonitorThread, 1000);
      CloseHandle(FIocpEngine.MonitorThread);
      FIocpEngine.MonitorThread := 0;
    end;
  end;

  for ThreadHandle in FIocpEngine.WorkerThreads do
    CloseHandle(ThreadHandle);
  FIocpEngine.WorkerThreads.Clear;

  if FIocpEngine.CompletionPort <> 0 then
  begin
    Logger.Info('[STOP-12] Closing completion port...');
    CloseHandle(FIocpEngine.CompletionPort);
    FIocpEngine.CompletionPort := 0;
  end;

  Logger.Info('[STOP-13] SSL cleanup...');
  FTlsManager.CleanupHandles;

  Logger.Info('[STOP-14] Executing WSACleanup...');
  WSACleanup;
  Logger.Info('[STOP-15] Server shut down cleanly.');
end;

procedure TGHttpsServerIOCP.ProcessHttpRequest(OverlappedEx: POverlappedEx);
var
  Response: TResponse;
  Request: TRequest;
  EmptyStream: TMemoryStream;
  Endpoint: TEndpointItem;
  EndpointKey: string;
  RootKey: string;
  EndpointIdx: Integer;
  AcceptEnc: string;
  HostHeader: string;
  RedirectUrl: string;
  IsWebSocketRoute: Boolean;
  RouteAuth: TAuthorizationType;
  WSVersion: string;
  OriginHeader: string;
  Key: string;
  DecodedBytes: TBytes;
  TokenStr: string;
  JWTObj: TJWTToken;
  ClientProtocols: string;
  SelectedProtocol: string;
  MergedKey: string;
  Sha1Bytes: TBytes;
  AcceptKey: string;
  isAuthorization: Boolean;
  AuthHeader: string;
  JWT: TJWTToken;
begin
  try
    if not Assigned(OverlappedEx) or not Assigned(OverlappedEx^.Request) then
    begin
      Logger.Error('Missing request object to process.');
      FIocpEngine.CleanupConnectionWithReason(OverlappedEx, 'Missing request object');
      Exit;
    end;

    if FIocpEngine.RejectNewConnections = 1 then
    begin
      FIocpEngine.CleanupConnectionWithReason(OverlappedEx, 'Error lack of resources');
      Exit;
    end;

    Request := OverlappedEx^.Request;
    if Assigned(OverlappedEx^.CachedResponse) then
    begin
      OverlappedEx^.Response := OverlappedEx^.CachedResponse;
      OverlappedEx^.CachedResponse := nil;
      OverlappedEx^.Response.Reset(OverlappedEx^.Socket);
    end
    else
      OverlappedEx^.Response := TResponse.Create(OverlappedEx^.Socket);
    Response := OverlappedEx^.Response;
    Response.KeepAlive := FIocpEngine.EnableKeepAlive and Assigned(Request) and Request.IsKeepAlive and (OverlappedEx^.KeepAliveRequestsCount < FIocpEngine.MaxKeepAliveRequests);
    Response.SetMaxMemorySize(1 * 1024 * 1024);

    if FIpSecurity.EnableIPRateLimiting and (FIpSecurity.MaxRequestsPerIPPerSecond > 0) then
    begin
      if not FIpSecurity.CheckIPRateLimit(string(PAnsiChar(@OverlappedEx^.ClientIP[0]))) then
      begin
        Logger.Warn('Rate limit exceeded for IP: %s (%d req/s)', [string(PAnsiChar(@OverlappedEx^.ClientIP[0])), FIpSecurity.MaxRequestsPerIPPerSecond]);
        Response.SetStatus(hsTooManyRequests);
        Response.SetOrUpdateHeader('Retry-After', '1');
        Response.AddTextContent('application/json', '{"error":"Too Many Requests","message":"Rate limit exceeded per IP"}');
        if FCorsPolicy.EnableCORS then
          FCorsPolicy.ApplyCORSHeaders(Request, Response);
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;
    end;

    if FHttp3Bridge.EnableHttp3 and OverlappedEx^.IsTLS and (FIocpEngine.HttpsPort > 0) and (FIocpEngine.ProtocolMode in [pmHttpsOnly, pmDualHttpAndHttps]) then
    begin
      if FCachedAltSvcPort <> FIocpEngine.HttpsPort then
      begin
        TMonitor.Enter(FLock);
        try
          if FCachedAltSvcPort <> FIocpEngine.HttpsPort then
          begin
            FCachedAltSvcValue := 'Alt-Svc: h3=":' + IntToStr(FIocpEngine.HttpsPort) + '"; ma=86400'#13#10;
            FCachedAltSvcPort := FIocpEngine.HttpsPort;
          end;
        finally
          TMonitor.Exit(FLock);
        end;
      end;
      Response.SetAltSvcLine(FCachedAltSvcValue);
    end;

    if (not OverlappedEx^.IsTLS) and (FIocpEngine.HttpAction = haRedirectToHttps) and (FIocpEngine.HttpsPort > 0) then
    begin
      HostHeader := Request.Headers.GetHeader('Host');
      if Length(HostHeader) = 0 then
      begin
        Response.SetBadRequest('Missing Host Header');
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;
      if Pos(':', HostHeader) > 0 then
        HostHeader := Copy(HostHeader, 1, Pos(':', HostHeader) - 1);

      RedirectUrl := Format('https://%s:%d%s', [HostHeader, FIocpEngine.HttpsPort, Request.RequestInfo.RawUri]);
      Response.SetMovedPermanently(RedirectUrl);
      FIocpEngine.ContinueSendingResponse(OverlappedEx);
      Exit;
    end;

    if FCorsPolicy.EnableCORS and (Request.RequestInfo.Method = hmOPTIONS) then
    begin
      if FCorsPolicy.HandleCORSPreflight(Request, Response) then
      begin
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;
    end;

    IsWebSocketRoute := False;
    if (FWebSocketBridge.HasWebSocketRoutes <> 0) and (Request.RequestInfo.Method = hmGET) then
      IsWebSocketRoute := FWebSocketBridge.HasRoute(Request.RequestInfo.Path.ToLower);

    if IsWebSocketRoute then
    begin
      RouteAuth := atNone;
      FWebSocketBridge.TryGetRouteAuth(Request.RequestInfo.Path.ToLower, RouteAuth);

      if not (SameText(Request.Headers.GetHeader('Upgrade'), 'websocket') and
              (ContainsText(Request.Headers.GetHeader('Connection'), 'Upgrade') or SameText(Request.Headers.GetHeader('Connection'), 'Upgrade'))) then
      begin
        Response.SetBadRequest('WebSocket Upgrade Header Required');
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;

      WSVersion := Request.Headers.GetHeader('Sec-WebSocket-Version').Trim;
      if WSVersion <> '13' then
      begin
        Response.SetStatus(400);
        Response.AddHeader('Sec-WebSocket-Version', '13');
        Response.SetBadRequest('Unsupported Sec-WebSocket-Version');
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;

      OriginHeader := Request.Headers.GetHeader('Origin').Trim;
      if OriginHeader <> '' then
      begin
        if not FCorsPolicy.IsWebSocketOriginAllowed(OriginHeader, Request.Headers.GetHeader('Host')) then
        begin
          Response.SetForbidden('Origin not allowed for WebSocket upgrade');
          FIocpEngine.ContinueSendingResponse(OverlappedEx);
          Exit;
        end;
      end;

      Key := Request.Headers.GetHeader('Sec-WebSocket-Key');
      DecodedBytes := TNetEncoding.Base64.DecodeStringToBytes(Key);
      if Length(DecodedBytes) <> 16 then
      begin
        Response.SetBadRequest('Invalid Sec-WebSocket-Key');
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
        Exit;
      end;

      if RouteAuth = atJWTBearer then
      begin
        TokenStr := FJWTManager.ExtractTokenFromAuthHeader(Request.Headers.Authorization);
        if TokenStr = '' then
        begin
          if not Request.RequestInfo.QueryParameters.TryGetValue('token', TokenStr) then
            Request.RequestInfo.QueryParameters.TryGetValue('access_token', TokenStr);
        end;

        if TokenStr = '' then
        begin
          Response.SetUnauthorized();
          FIocpEngine.ContinueSendingResponse(OverlappedEx);
          Exit;
        end;

        JWTObj := nil;
        try
          if not FJWTManager.ValidateToken(TokenStr, JWTObj) then
          begin
            Response.SetUnauthorized();
            FIocpEngine.ContinueSendingResponse(OverlappedEx);
            Exit;
          end;
        finally
          if Assigned(JWTObj) then
            JWTObj.Free;
        end;
      end;

      ClientProtocols := Request.Headers.GetHeader('Sec-WebSocket-Protocol');
      SelectedProtocol := '';
      if ClientProtocols <> '' then
        SelectedProtocol := FWebSocketBridge.SelectWebSocketSubProtocol(Request.RequestInfo.Path.ToLower, ClientProtocols);

      MergedKey := Key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
      Sha1Bytes := THashSHA1.GetHashBytes(MergedKey);
      AcceptKey := TNetEncoding.Base64.EncodeBytesToString(Sha1Bytes).Trim;

      Response.SetStatus(101);
      Response.AddHeader('Upgrade', 'websocket');
      Response.AddHeader('Connection', 'Upgrade');
      Response.AddHeader('Sec-WebSocket-Accept', AcceptKey);
      if SelectedProtocol <> '' then
        Response.AddHeader('Sec-WebSocket-Protocol', SelectedProtocol);
      Response.FinalizeContent;

      FIocpEngine.ContinueSendingResponse(OverlappedEx);
      Exit;
    end;

    if Request.HasSecurityViolation then
    begin
      Logger.Warn('Security violation detected: ' + Request.GetThreatSummary);
      Response.KeepAlive := False;

      if ContainsText(Request.ErrorMessage, 'Request line exceeds') then
      begin
        Response.SetStatus(hsURITooLong);
        Response.AddTextContent('application/json', '{"error":"URI Too Long","message":"' + Request.ErrorMessage + '"}');
      end
      else if ContainsText(Request.ErrorMessage, 'Header line exceeds') or
              ContainsText(Request.ErrorMessage, 'Headers size will exceed') or
              ContainsText(Request.ErrorMessage, 'Headers block size') then
      begin
        Response.SetStatus(hsRequestHeaderFieldsTooLarge);
        Response.AddTextContent('application/json', '{"error":"Request Header Fields Too Large","message":"' + Request.ErrorMessage + '"}');
      end
      else if ContainsText(Request.ErrorMessage, 'exceed') or ContainsText(Request.GetThreatSummary, 'exceed') or
         ContainsText(Request.GetThreatSummary, 'limit') or ContainsText(Request.GetThreatSummary, 'oversize') then
      begin
        Response.SetStatus(hsPayloadTooLarge);
        Response.AddTextContent('application/json', '{"error":"Payload Too Large","message":"' + Request.ErrorMessage + '"}');
      end
      else
        Response.SetBadRequest('Security Violation Detected: ' + Request.GetThreatSummary);
    end
    else
    begin
      Endpoint := nil;
      if (Request.RequestInfo.Method = hmGET) and (Request.RequestInfo.Path = '/') and Assigned(FRootGetEndpoint) then
        Endpoint := FRootGetEndpoint
      else
      begin
        for EndpointIdx := 0 to FFastEndpointCount - 1 do
        begin
          if (FFastEndpoints[EndpointIdx].Method = Request.RequestInfo.Method) and
             (FFastEndpoints[EndpointIdx].Path = Request.RequestInfo.Path) then
          begin
            Endpoint := FFastEndpoints[EndpointIdx];
            Break;
          end;
        end;
        if Endpoint = nil then
        begin
          EndpointKey := GetEndpointKey(Request.RequestInfo.Method, Request.RequestInfo.Path);
          if not FEndpoints.TryGetValue(EndpointKey, Endpoint) then
          begin
            if (Request.RequestInfo.Method = hmGET) and (Request.RequestInfo.Path = '/') then
            begin
              RootKey := GetEndpointKey(hmGET, '/');
              FEndpoints.TryGetValue(RootKey, Endpoint);
            end;
          end;
        end;
      end;

      if Assigned(Endpoint) then
      begin
        try
          isAuthorization := True;
          if Endpoint.AuthorizationType = atJWTBearer then
          begin
            AuthHeader := Request.Headers.Authorization;
            AuthHeader := FJWTManager.ExtractTokenFromAuthHeader(AuthHeader);
            if Length(AuthHeader) > 0 then
            begin
              if FJWTManager.ValidateToken(AuthHeader, JWT) then
                isAuthorization := True
              else
              begin
                Response.SetUnauthorized();
                isAuthorization := False;
              end;

              if Assigned(JWT) then
                JWT.Free;
            end
            else
            begin
              isAuthorization := False;
              Response.SetUnauthorized();
            end;
          end;

          if isAuthorization then
          begin
            if Assigned(Endpoint.Handler) then
              Endpoint.Handler(Self, Request, Response, Self)
            else
              Endpoint.HandlerProc(Self, Request, Response, Self);
          end;
        except
          on E: Exception do
          begin
            Logger.Error(Format('Error in handler for endpoint %s: %s', [GetEndpointKey(Request.RequestInfo.Method, Request.RequestInfo.Path), E.Message]));
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
    end
    else
    begin
      if Response.CanCompressBody then
      begin
        AcceptEnc := Request.Headers.GetHeader('Accept-Encoding');
        if AcceptEnc <> '' then
          Response.ApplyContentEncoding(AcceptEnc);
      end;
    end;
    if FCorsPolicy.EnableCORS then
      FCorsPolicy.ApplyCORSHeaders(Request, Response);
    FIocpEngine.ContinueSendingResponse(OverlappedEx);
  except
    on E: Exception do
    begin
      Logger.Error('Exception in ProcessHttpRequest: %s', [E.Message]);
      if Assigned(OverlappedEx) then
      begin
        if not Assigned(OverlappedEx^.Response) then
          OverlappedEx^.Response := TResponse.Create(OverlappedEx^.Socket);
        OverlappedEx^.Response.SetInternalServerError('Server error while processing the request: ' + E.Message);
        FCorsPolicy.ApplyCORSHeaders(OverlappedEx^.Request, OverlappedEx^.Response);
        FIocpEngine.ContinueSendingResponse(OverlappedEx);
      end
      else
        Logger.Error('Critical error: Missing OverlappedEx object in the exception handler.');
    end;
  end;
end;

function TGHttpsServerIOCP.DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
  var PlainData: TBytes; out BytesConsumed: Integer): Boolean;
begin
  Result := FTlsManager.DecryptReceivedData(Context, EncryptedData, PlainData, BytesConsumed);
end;

function TGHttpsServerIOCP.DecryptReceivedData(var Context: TCtxtHandle; const EncryptedData: TBytes;
  var PlainData: TBytes; out BytesConsumed: Integer; out AStatus: SECURITY_STATUS): Boolean;
begin
  Result := FTlsManager.DecryptReceivedData(Context, EncryptedData, PlainData, BytesConsumed, AStatus);
end;

procedure TGHttpsServerIOCP.FreeSSLBuffer(var Buffer: Pointer; Size: Cardinal; const Context: string);
begin
  FTlsManager.FreeSSLBuffer(Buffer, Size, Context);
end;

procedure TGHttpsServerIOCP.PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
begin
  FTlsManager.PerformGracefulSSLShutdown(OverlappedEx);
end;

procedure TGHttpsServerIOCP.SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal);
begin
  FTlsManager.SetSSLShutdownOptions(EnableGraceful, TimeoutMs);
end;

procedure TGHttpsServerIOCP.EnableGracefulSSLShutdown(Enable: Boolean);
begin
  FTlsManager.EnableGracefulSSLShutdown(Enable);
end;

procedure TGHttpsServerIOCP.SetSSLShutdownTimeout(TimeoutMs: Cardinal);
begin
  FTlsManager.SetSSLShutdownTimeout(TimeoutMs);
end;

function TGHttpsServerIOCP.GetCertificateSha256Hash: TBytes;
begin
  Result := FTlsManager.GetCertificateSha256Hash;
end;

function TGHttpsServerIOCP.LoadCACertificate(const AFileName: string): Boolean;
begin
  Result := FTlsManager.LoadCACertificate(AFileName);
end;

function TGHttpsServerIOCP.AddTrustedCertificate(const AFileName: string): Boolean;
begin
  Result := FTlsManager.AddTrustedCertificate(AFileName);
end;

procedure TGHttpsServerIOCP.PruneInactiveIPTrackers;
begin
  FIpSecurity.PruneInactiveIPTrackers;
end;

function TGHttpsServerIOCP.GetTrackedIPCount: Integer;
begin
  Result := FIpSecurity.GetTrackedIPCount;
end;

procedure TGHttpsServerIOCP.TriggerWebSocketWrite(Session: TWebSocketSession);
begin
  FWebSocketBridge.TriggerWebSocketWrite(Session);
end;

procedure TGHttpsServerIOCP.CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
begin
  FWebSocketBridge.CleanupWebSocketSession(Session, Reason);
end;

procedure TGHttpsServerIOCP.BroadcastWebSocket(const AText: string);
begin
  FWebSocketBridge.BroadcastWebSocket(AText);
end;

procedure TGHttpsServerIOCP.BroadcastWebSocketBinary(const Data: TBytes);
begin
  FWebSocketBridge.BroadcastWebSocketBinary(Data);
end;

function TGHttpsServerIOCP.GetWebSocketActiveCount: Integer;
begin
  Result := FWebSocketBridge.GetWebSocketActiveCount;
end;

procedure TGHttpsServerIOCP.RegisterEndpoint(const APath: string; AMethod: THttpMethod;
  AHandler: TEndpointEvent; AAuthorizationType: TAuthorizationType);
var
  Key: string;
  LEndpoint: TEndpointItem;
begin
  if not Assigned(AHandler) then
    raise Exception.Create('The handler for the endpoint cannot be nil.');
  Key := GetEndpointKey(AMethod, APath);
  FLock.Enter;
  try
    if FEndpoints.ContainsKey(Key) then
      raise Exception.CreateFmt('Endpoint "%s" is already registered.', [Key]);
    LEndpoint := TEndpointItem.Create(APath, AMethod, AHandler, nil, AAuthorizationType, Self);
    FEndpoints.Add(Key, LEndpoint);
    if (AMethod = hmGET) and (APath = '/') then
      FRootGetEndpoint := LEndpoint;
    if FFastEndpointCount < 16 then
    begin
      FFastEndpoints[FFastEndpointCount] := LEndpoint;
      Inc(FFastEndpointCount);
    end;
    Logger.Info(Format('Registered endpoint: %s', [Key]));
  finally
    FLock.Leave;
  end;
end;

procedure TGHttpsServerIOCP.RegisterEndpointProc(const APath: string; AMethod: THttpMethod;
  AHandler: TEndpointEventProc; AAuthorizationType: TAuthorizationType);
var
  Key: string;
  LEndpoint: TEndpointItem;
begin
  if not Assigned(AHandler) then
    raise Exception.Create('The handler for the endpoint cannot be nil.');
  Key := GetEndpointKey(AMethod, APath);
  FLock.Enter;
  try
    if FEndpoints.ContainsKey(Key) then
      raise Exception.CreateFmt('Endpoint "%s" is already registered.', [Key]);
    LEndpoint := TEndpointItem.Create(APath, AMethod, nil, AHandler, AAuthorizationType, Self);
    FEndpoints.Add(Key, LEndpoint);
    if (AMethod = hmGET) and (APath = '/') then
      FRootGetEndpoint := LEndpoint;
    if FFastEndpointCount < 16 then
    begin
      FFastEndpoints[FFastEndpointCount] := LEndpoint;
      Inc(FFastEndpointCount);
    end;
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
  RegisterWebSocketRoute(APath, AOnMessage, atNone, nil);
end;

procedure TGHttpsServerIOCP.RegisterWebSocketRoute(const APath: string; AOnMessage: TWebSocketMessageProc;
  AAuthType: TAuthorizationType; const ASupportedProtocols: TArray<string>);
begin
  FWebSocketBridge.RegisterRoute(APath, PInterface(@AOnMessage)^, AAuthType, ASupportedProtocols);
end;

procedure TGHttpsServerIOCP.RegisterWebSocketRawRoute(const APath: string; AOnMessage: TWebSocketRawMessageProc;
  AAuthType: TAuthorizationType);
begin
  FWebSocketBridge.RegisterRawRoute(APath, PInterface(@AOnMessage)^, AAuthType);
end;

procedure TGHttpsServerIOCP.RevokeJWTToken(const AToken: string);
begin
  if Assigned(FJWTManager) then
    FJWTManager.RevokeToken(AToken);
end;

function TGHttpsServerIOCP.IsJWTTokenRevoked(const AToken: string): Boolean;
begin
  if Assigned(FJWTManager) then
    Result := FJWTManager.IsTokenRevoked(AToken)
  else
    Result := False;
end;

procedure TGHttpsServerIOCP.RegisterWebTransportRoute(const APath: string);
begin
  FHttp3Bridge.RegisterWebTransportRoute(APath);
end;

procedure TGHttpsServerIOCP.RegisterWebTransportRoute(const APath: string; AOnSessionReady: TWebTransportSessionProc;
  AOnStreamData: TWebTransportStreamProc; AOnDatagram: TWebTransportDatagramProc; AOnSessionClosed: TWebTransportClosedProc);
begin
  FHttp3Bridge.RegisterWebTransportRoute(APath, AOnSessionReady, AOnStreamData, AOnDatagram, AOnSessionClosed);
end;

function TGHttpsServerIOCP.GetRunning: Boolean;
begin
  Result := FIocpEngine.Running;
end;

function TGHttpsServerIOCP.GetMaxRequestSize: Int64;
begin
  Result := FIocpEngine.MaxRequestSize;
end;

procedure TGHttpsServerIOCP.SetMaxRequestSize(const Value: Int64);
begin
  FIocpEngine.MaxRequestSize := Value;
end;

function TGHttpsServerIOCP.GetMaxResponseSize: Int64;
begin
  Result := FIocpEngine.MaxResponseSize;
end;

procedure TGHttpsServerIOCP.SetMaxResponseSize(const Value: Int64);
begin
  FIocpEngine.MaxResponseSize := Value;
end;

function TGHttpsServerIOCP.GetChunkSize: Integer;
begin
  Result := FIocpEngine.ChunkSize;
end;

procedure TGHttpsServerIOCP.SetChunkSize(const Value: Integer);
begin
  FIocpEngine.ChunkSize := Value;
end;

function TGHttpsServerIOCP.GetOverlappedPool: TOverlappedExPool;
begin
  Result := FIocpEngine.OverlappedPool;
end;

function TGHttpsServerIOCP.GetEnableHttp3: Boolean;
begin
  Result := FHttp3Bridge.EnableHttp3;
end;

procedure TGHttpsServerIOCP.SetEnableHttp3(const Value: Boolean);
begin
  FHttp3Bridge.EnableHttp3 := Value;
end;

function TGHttpsServerIOCP.GetHttp3Server: THttp3Server;
begin
  Result := FHttp3Bridge.Http3Server;
end;

function TGHttpsServerIOCP.GetHttp3SettingMaxFieldSectionSize: UInt64;
begin
  Result := FHttp3Bridge.Http3SettingMaxFieldSectionSize;
end;

procedure TGHttpsServerIOCP.SetHttp3SettingMaxFieldSectionSize(const Value: UInt64);
begin
  FHttp3Bridge.Http3SettingMaxFieldSectionSize := Value;
end;

function TGHttpsServerIOCP.GetHttp3SettingQpackMaxTableCapacity: UInt64;
begin
  Result := FHttp3Bridge.Http3SettingQpackMaxTableCapacity;
end;

procedure TGHttpsServerIOCP.SetHttp3SettingQpackMaxTableCapacity(const Value: UInt64);
begin
  FHttp3Bridge.Http3SettingQpackMaxTableCapacity := Value;
end;

function TGHttpsServerIOCP.GetHttp3SettingQpackBlockedStreams: UInt64;
begin
  Result := FHttp3Bridge.Http3SettingQpackBlockedStreams;
end;

procedure TGHttpsServerIOCP.SetHttp3SettingQpackBlockedStreams(const Value: UInt64);
begin
  FHttp3Bridge.Http3SettingQpackBlockedStreams := Value;
end;

function TGHttpsServerIOCP.GetHttp3EnableDemoEndpoints: Boolean;
begin
  Result := FHttp3Bridge.Http3EnableDemoEndpoints;
end;

procedure TGHttpsServerIOCP.SetHttp3EnableDemoEndpoints(const Value: Boolean);
begin
  FHttp3Bridge.Http3EnableDemoEndpoints := Value;
end;

function TGHttpsServerIOCP.GetQuicRequiredServerName: string;
begin
  Result := FHttp3Bridge.QuicRequiredServerName;
end;

procedure TGHttpsServerIOCP.SetQuicRequiredServerName(const Value: string);
begin
  FHttp3Bridge.QuicRequiredServerName := Value;
end;

function TGHttpsServerIOCP.GetQuicForceStatelessRetry: Boolean;
begin
  Result := FHttp3Bridge.QuicForceStatelessRetry;
end;

procedure TGHttpsServerIOCP.SetQuicForceStatelessRetry(const Value: Boolean);
begin
  FHttp3Bridge.QuicForceStatelessRetry := Value;
end;

function TGHttpsServerIOCP.GetQuicAlpnProtocol: string;
begin
  Result := FHttp3Bridge.QuicAlpnProtocol;
end;

procedure TGHttpsServerIOCP.SetQuicAlpnProtocol(const Value: string);
begin
  FHttp3Bridge.QuicAlpnProtocol := Value;
end;

function TGHttpsServerIOCP.GetWebSocketManager: TWebSocketManager;
begin
  Result := FWebSocketBridge.WebSocketManager;
end;

function TGHttpsServerIOCP.GetActiveConnections: Int64;
begin
  Result := FIocpEngine.ActiveConnections;
end;

function TGHttpsServerIOCP.GetEnableKeepAlive: Boolean;
begin
  Result := FIocpEngine.EnableKeepAlive;
end;

procedure TGHttpsServerIOCP.SetEnableKeepAlive(const Value: Boolean);
begin
  FIocpEngine.EnableKeepAlive := Value;
end;

function TGHttpsServerIOCP.GetKeepAliveTimeoutMs: Cardinal;
begin
  Result := FIocpEngine.KeepAliveTimeoutMs;
end;

procedure TGHttpsServerIOCP.SetKeepAliveTimeoutMs(const Value: Cardinal);
begin
  FIocpEngine.KeepAliveTimeoutMs := Value;
end;

function TGHttpsServerIOCP.GetMaxKeepAliveRequests: Integer;
begin
  Result := FIocpEngine.MaxKeepAliveRequests;
end;

procedure TGHttpsServerIOCP.SetMaxKeepAliveRequests(const Value: Integer);
begin
  FIocpEngine.MaxKeepAliveRequests := Value;
end;

function TGHttpsServerIOCP.GetProtocolMode: TServerProtocolMode;
begin
  Result := FIocpEngine.ProtocolMode;
end;

function TGHttpsServerIOCP.GetHttpAction: THttpActionOnDualMode;
begin
  Result := FIocpEngine.HttpAction;
end;

procedure TGHttpsServerIOCP.SetHttpAction(const Value: THttpActionOnDualMode);
begin
  FIocpEngine.HttpAction := Value;
end;

function TGHttpsServerIOCP.GetHttpsPort: Word;
begin
  Result := FIocpEngine.HttpsPort;
end;

function TGHttpsServerIOCP.GetHttpPort: Word;
begin
  Result := FIocpEngine.HttpPort;
end;

procedure TGHttpsServerIOCP.SetHttpPort(const Value: Word);
begin
  FIocpEngine.HttpPort := Value;
end;

function TGHttpsServerIOCP.GetBindAddress: string;
begin
  Result := FIocpEngine.BindAddress;
end;

procedure TGHttpsServerIOCP.SetBindAddress(const Value: string);
begin
  FIocpEngine.BindAddress := Value;
end;

function TGHttpsServerIOCP.GetHttpBindAddress: string;
begin
  Result := FIocpEngine.HttpBindAddress;
end;

procedure TGHttpsServerIOCP.SetHttpBindAddress(const Value: string);
begin
  FIocpEngine.HttpBindAddress := Value;
end;

function TGHttpsServerIOCP.GetHttpsBindAddress: string;
begin
  Result := FIocpEngine.HttpsBindAddress;
end;

procedure TGHttpsServerIOCP.SetHttpsBindAddress(const Value: string);
begin
  FIocpEngine.HttpsBindAddress := Value;
end;

function TGHttpsServerIOCP.GetHttp3BindAddress: string;
begin
  Result := FIocpEngine.Http3BindAddress;
end;

procedure TGHttpsServerIOCP.SetHttp3BindAddress(const Value: string);
begin
  FIocpEngine.Http3BindAddress := Value;
end;

function TGHttpsServerIOCP.GetEnableCORS: Boolean;
begin
  Result := FCorsPolicy.EnableCORS;
end;

procedure TGHttpsServerIOCP.SetEnableCORS(const Value: Boolean);
begin
  FCorsPolicy.EnableCORS := Value;
end;

function TGHttpsServerIOCP.GetCORSAllowedOrigins: string;
begin
  Result := FCorsPolicy.CORSAllowedOrigins;
end;

procedure TGHttpsServerIOCP.SetCORSAllowedOrigins(const Value: string);
begin
  FCorsPolicy.CORSAllowedOrigins := Value;
end;

function TGHttpsServerIOCP.GetCORSAllowedMethods: string;
begin
  Result := FCorsPolicy.CORSAllowedMethods;
end;

procedure TGHttpsServerIOCP.SetCORSAllowedMethods(const Value: string);
begin
  FCorsPolicy.CORSAllowedMethods := Value;
end;

function TGHttpsServerIOCP.GetCORSAllowedHeaders: string;
begin
  Result := FCorsPolicy.CORSAllowedHeaders;
end;

procedure TGHttpsServerIOCP.SetCORSAllowedHeaders(const Value: string);
begin
  FCorsPolicy.CORSAllowedHeaders := Value;
end;

function TGHttpsServerIOCP.GetCORSExposeHeaders: string;
begin
  Result := FCorsPolicy.CORSExposeHeaders;
end;

procedure TGHttpsServerIOCP.SetCORSExposeHeaders(const Value: string);
begin
  FCorsPolicy.CORSExposeHeaders := Value;
end;

function TGHttpsServerIOCP.GetCORSAllowCredentials: Boolean;
begin
  Result := FCorsPolicy.CORSAllowCredentials;
end;

procedure TGHttpsServerIOCP.SetCORSAllowCredentials(const Value: Boolean);
begin
  FCorsPolicy.CORSAllowCredentials := Value;
end;

function TGHttpsServerIOCP.GetCORSMaxAge: Integer;
begin
  Result := FCorsPolicy.CORSMaxAge;
end;

procedure TGHttpsServerIOCP.SetCORSMaxAge(const Value: Integer);
begin
  FCorsPolicy.CORSMaxAge := Value;
end;

function TGHttpsServerIOCP.GetMaxConnectionsPerIP: Integer;
begin
  Result := FIpSecurity.MaxConnectionsPerIP;
end;

procedure TGHttpsServerIOCP.SetMaxConnectionsPerIP(const Value: Integer);
begin
  FIpSecurity.MaxConnectionsPerIP := Value;
end;

function TGHttpsServerIOCP.GetWorkerThreadCount: Integer;
begin
  Result := FIocpEngine.WorkerThreadCount;
end;

procedure TGHttpsServerIOCP.SetWorkerThreadCount(const Value: Integer);
begin
  FIocpEngine.WorkerThreadCount := Value;
end;

function TGHttpsServerIOCP.GetEnableIPRateLimiting: Boolean;
begin
  Result := FIpSecurity.EnableIPRateLimiting;
end;

procedure TGHttpsServerIOCP.SetEnableIPRateLimiting(const Value: Boolean);
begin
  FIpSecurity.EnableIPRateLimiting := Value;
end;

function TGHttpsServerIOCP.GetMaxRequestsPerIPPerSecond: Integer;
begin
  Result := FIpSecurity.MaxRequestsPerIPPerSecond;
end;

procedure TGHttpsServerIOCP.SetMaxRequestsPerIPPerSecond(const Value: Integer);
begin
  FIpSecurity.MaxRequestsPerIPPerSecond := Value;
end;

function TGHttpsServerIOCP.GetEnableTLSSessionResumption: Boolean;
begin
  Result := FTlsManager.EnableTLSSessionResumption;
end;

procedure TGHttpsServerIOCP.SetEnableTLSSessionResumption(const Value: Boolean);
begin
  FTlsManager.EnableTLSSessionResumption := Value;
end;

function TGHttpsServerIOCP.GetEnableTLSSessionTickets: Boolean;
begin
  Result := FTlsManager.EnableTLSSessionTickets;
end;

procedure TGHttpsServerIOCP.SetEnableTLSSessionTickets(const Value: Boolean);
begin
  FTlsManager.EnableTLSSessionTickets := Value;
end;

function TGHttpsServerIOCP.GetIPTrackerInactiveTimeoutMs: UInt64;
begin
  Result := FIpSecurity.IPTrackerInactiveTimeoutMs;
end;

procedure TGHttpsServerIOCP.SetIPTrackerInactiveTimeoutMs(const Value: UInt64);
begin
  FIpSecurity.IPTrackerInactiveTimeoutMs := Value;
end;

function TGHttpsServerIOCP.GetAllowedFileExtensions: TStringList;
begin
  Result := FIocpEngine.AllowedFileExtensions;
end;

function TGHttpsServerIOCP.GetBlockedMimeTypes: TStringList;
begin
  Result := FIocpEngine.BlockedMimeTypes;
end;

function TGHttpsServerIOCP.GetAllowedWebSocketOrigins: string;
begin
  Result := FCorsPolicy.AllowedWebSocketOrigins;
end;

procedure TGHttpsServerIOCP.SetAllowedWebSocketOrigins(const Value: string);
begin
  FCorsPolicy.AllowedWebSocketOrigins := Value;
end;

function TGHttpsServerIOCP.GetAllowedWebTransportOrigins: string;
begin
  Result := FCorsPolicy.AllowedWebTransportOrigins;
end;

procedure TGHttpsServerIOCP.SetAllowedWebTransportOrigins(const Value: string);
begin
  FCorsPolicy.AllowedWebTransportOrigins := Value;
end;

function TGHttpsServerIOCP.GetSupportedWebSocketProtocols: TArray<string>;
begin
  Result := FWebSocketBridge.SupportedWebSocketProtocols;
end;

procedure TGHttpsServerIOCP.SetSupportedWebSocketProtocols(const Value: TArray<string>);
begin
  FWebSocketBridge.SupportedWebSocketProtocols := Value;
end;

function TGHttpsServerIOCP.GetmTLSMode: TmTLSMode;
begin
  Result := FTlsManager.mTLSMode;
end;

procedure TGHttpsServerIOCP.SetmTLSMode(const Value: TmTLSMode);
begin
  FTlsManager.mTLSMode := Value;
end;

function TGHttpsServerIOCP.GetmTLSCAPath: string;
begin
  Result := FTlsManager.mTLSCAPath;
end;

function TGHttpsServerIOCP.GetOnValidateClientCertificate: TClientCertValidateEvent;
begin
  Result := FTlsManager.OnValidateClientCertificate;
end;

procedure TGHttpsServerIOCP.SetOnValidateClientCertificate(const Value: TClientCertValidateEvent);
begin
  FTlsManager.OnValidateClientCertificate := Value;
end;

end.
