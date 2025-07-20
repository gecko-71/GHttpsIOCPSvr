{
  MIT License

  Copyright (c) (c) 2025 GECKO-71

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
  Quick.Logger,
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.Classes,
  System.Math,
  System.Generics.Collections,
  WinApiAdditions,
  GRequest,
  System.DateUtils,
  GResponse,
  Psapi,
  System.Diagnostics,
  System.SyncObjs,
  OverlappedExPool, GJWTManager;

type
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
    FCompletionPort: THandle;
    FPort: Word;
    FRunning: Boolean;
    FWorkerThreads: TList<THandle>;
    FCertContext: PCCERT_CONTEXT;
    FServerCredHandle: TCredHandle;
    FCredentialsValid: Boolean;
    FActiveConnections: Int64;
    FMaxConnections: Integer;
    FJWTManager: TJWTManager;
    FEndpoints: TDictionary<string, TEndpointItem>;
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
    function InitializeWinsock: Boolean;
    function CreateListenSocket: Boolean;
    function CreateCompletionPort: Boolean;
    function LoadServerCertificate: Boolean;
    function InitializeSSLCredentials: Boolean;
    function CreateWorkerThreads: Boolean;
    procedure CleanupWinsock;
    procedure ListCertificatesInStore(const StoreName: string);
//    procedure AcceptConnection(Socket: TSocket);
    procedure AcceptConnection2(Socket: TSocket);
    procedure HandleHttpsHandshake(ClientSocket: TSocket);
    procedure InitializeRequestProcessing(OverlappedEx: POverlappedEx);
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
    procedure ContinueSendingResponse(OverlappedEx: POverlappedEx);
  public
    constructor Create(APort: Word = 443;
                       ASubjectName:String = 'localhost';
                       ACertificateStore:String= 'myHTTPSSvr';
                       ASecretKey:String = 'YourSuperSecretKeyThatIsVeryLongAndVerySecure123!';
                       AMaxConnections: Integer = 2000;
                       AMaxRequestsPerSecond: Integer =  DEFAULT_MAXREQUESTSPERSECOND;
                       AMaxRequestHederSize: Int64 = DEFAULT_MAX_REQUEST_HEDER_SIZE;
                       AMaxRequestSize: Int64 = DEFAULT_MAX_REQUEST_SIZE;
                       AMaxResponseSize: Int64 = DEFAULT_MAX_RESPONSE_SIZE;
                       AChunkSize: Integer = DEFAULT_CHUNK_SIZE;
                       AMinFreeMemoryMb: Cardinal = 50;
                       AMaxMemoryLoadPercent: Byte = 85;
                       AMonitorRun:Boolean = True);
    destructor Destroy; override;
    procedure PerformGracefulSSLShutdown(var OverlappedEx: TOverlappedEx);
    procedure SetSSLShutdownOptions(EnableGraceful: Boolean; TimeoutMs: Cardinal = 500);
    procedure EnableGracefulSSLShutdown(Enable: Boolean);
    procedure SetSSLShutdownTimeout(TimeoutMs: Cardinal);
    function Start: Boolean;
    procedure Stop;
    procedure RegisterEndpoint(const APath: string; AMethod: THttpMethod;
                               AHandler: TEndpointEvent;
                               AAuthorizationType: TAuthorizationType = atNone);
    procedure RegisterEndpointProc(const APath: string;
                                      AMethod: THttpMethod;
                                      AHandler: TEndpointEventProc;
                                      AAuthorizationType: TAuthorizationType = atNone );
    property Running: Boolean read FRunning;
    property MaxRequestSize: Int64 read FMaxRequestSize write FMaxRequestSize;
    property MaxResponseSize: Int64 read FMaxResponseSize write FMaxResponseSize;
    property ChunkSize: Integer read FChunkSize write FChunkSize;
    property OverlappedPool: TOverlappedExPool read FOverlappedPool;
    property JWTManager: TJWTManager read FJWTManager;
  end;


implementation

uses System.StrUtils, System.IOUtils,
     System.NetEncoding, GRequestBody, TypInfo;


procedure CleanupConnectionWithReason(Server: TGHttpsServerIOCP; AOverlapped: POverlappedEx; const AReason: string);
begin
  if AOverlapped = nil then
    Exit;
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
                                   AMonitorRun:Boolean);
begin
  inherited Create;

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
  FRunning := False;
  FListenSocket := INVALID_SOCKET;
  FCompletionPort := 0;
  FWorkerThreads := TList<THandle>.Create;
  FCertContext := nil;
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
  ZeroMemory(@FServerCredHandle, SizeOf(FServerCredHandle));
  Logger.Info(Format('Creating OverlappedEx pool. Max connections: %d', [AMaxConnections]));
  FOverlappedPool := TOverlappedExPool.Create(
    AMaxConnections div 4,
    AMaxConnections,
    AMinFreeMemoryMb,
    AMaxMemoryLoadPercent
  );

  Logger.Info(Format('HTTPS Server created - MaxRequest: %d MB, MaxResponse: %d MB, ChunkSize: %d KB',
             [FMaxRequestSize div 1048576, FMaxResponseSize div 1048576, FChunkSize div 1024]));
end;

destructor TGHttpsServerIOCP.Destroy;
var
  StartTime: TDateTime;
  ElapsedMs: Integer;
begin
  StartTime := Now;
  Logger.Info('Start cleanup TGHttpsServerIOCP...');
  Stop;
  var  Endpoint: TEndpointItem;
  FLock.Enter;
  try
    for Endpoint in FEndpoints.Values do
      Endpoint.Free;
    FEndpoints.Free;
  finally
    FLock.Leave;
  end;
  FLock.Free;
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
  ElapsedMs := MilliSecondsBetween(Now, StartTime);
  Logger.Info('Cleanup TGHttpsServerIOCP end in %dms', [ElapsedMs]);
  FJWTManager.Free;
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
      begin
        Buffer := nil;
      end
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
          begin
            Move(OutputBuffers[i].pvBuffer^, OverlappedEx.SSLOutputBuffer[0], OutputBuffers[i].cbBuffer);
          end;
        end
        else
        begin
        end;
      end;
    end;
    if (Status = SEC_E_OK) and (OutputBuffers[0].cbBuffer > 0) then
    begin
      BytesSent := send(OverlappedEx.Socket, OutputBuffers[0].pvBuffer^, OutputBuffers[0].cbBuffer, 0);
      if BytesSent = OutputBuffers[0].cbBuffer then
      begin
        Sleep(50);
      end
      else if BytesSent = SOCKET_ERROR then
      begin
      end
      else
      begin
      end;
    end
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
    if Assigned(OverlappedEx^.Response) then
    begin
      OverlappedEx^.Response.Free;
      OverlappedEx^.Response := nil;
    end;
    if Assigned(OverlappedEx^.Request) then
    begin
      OverlappedEx^.Request.Free;
      OverlappedEx^.Request := nil;
    end;
    OverlappedEx^.SSLOutputSize := 0;
  except
    on E: Exception do
      Logger.Error('Error in CleanupOverlappedEx: ' + E.Message);
  end;
end;

function TGHttpsServerIOCP.IsRequestComplete(Request: TRequest): Boolean;
begin
  Result := Assigned(Request) and Request.IsComplete and not Request.HasError;
end;

procedure TGHttpsServerIOCP.InitializeRequestProcessing(OverlappedEx: POverlappedEx);
var
  RemoteAddr: TSockAddrIn;
begin
  try
    if FRejectNewConnections = 1 then // 1 = True
      raise Exception.Create('Error lack of resources');
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
  except
    on E: Exception do
    begin
      Logger.Error('Error initializing request processing: ' + E.Message);
      CleanupOverlappedEx(OverlappedEx);
      raise;
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
var
  SockAddr: TSockAddr;
  SockAddrIn: TSockAddrIn absolute SockAddr;
  OptVal: Integer;
begin
  Result := False;
  FListenSocket := WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, WSA_FLAG_OVERLAPPED);
  if FListenSocket = INVALID_SOCKET then
    Exit;
  OptVal := 1;
  if setsockopt(FListenSocket, SOL_SOCKET, SO_REUSEADDR, @OptVal, SizeOf(OptVal)) = SOCKET_ERROR then
  begin
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
    Exit;
  end;
  FillChar(SockAddr, SizeOf(SockAddr), 0);
  SockAddrIn.sin_family := AF_INET;
  SockAddrIn.sin_addr.S_addr := INADDR_ANY;
  SockAddrIn.sin_port := htons(FPort);
  if bind(FListenSocket, SockAddr, SizeOf(SockAddr)) = SOCKET_ERROR then
  begin
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
    Exit;
  end;
  if listen(FListenSocket, SOMAXCONN) = SOCKET_ERROR then
  begin
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
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
    Result := CreateIoCompletionPort(FListenSocket, FCompletionPort,
                                   ULONG_PTR(FListenSocket), 0) <> 0;
  end
  else
    Result := False;
end;

function TGHttpsServerIOCP.LoadServerCertificate: Boolean;
var
  CertStore: HCERTSTORE;
begin
  Result := False;
  FSubjectName := 'localhost';
  Logger.Info('LoadServerCertificate START');
  Logger.Info('Looking for certificate with subject: "%s"', [FSubjectName]);
  Logger.Info('Opening certificate store "myHTTPSSvr"...');
  CertStore := CertOpenSystemStore(0, PWideChar(FCertificateStore));
  if CertStore = nil then
  begin
    var LastError := GetLastError;
    Logger.Error('Error: Could not open certificate store "myHTTPSSvr" (Error: %d)', [LastError]);
    Logger.Error('Make sure the certificate was created with the command:');
    Logger.Error('   makecert -r -pe -n "CN=localhost" -ss myHTTPSSvr localhost.cer');
    Exit;
  end;
  try
    Logger.Info('Searching for certificate by subject name...');
    Logger.Info('Search parameters: Subject="%s", Encoding=0x%x',
        [FSubjectName, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING]);

    FCertContext := CertFindCertificateInStore(
      CertStore,
      X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0,
      CERT_FIND_SUBJECT_STR,
      PWideChar(FSubjectName),
      nil
    );

    if FCertContext <> nil then
    begin
      Logger.Info('Certificate context allocated at: %p', [FCertContext]);
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
        begin
          Logger.Info('Certificate subject retrieved: "%s" (%d chars)',
            [PWideChar(@SubjectBuffer[0]), SubjectLen]);
        end
        else
        begin
          Logger.Info('Could not retrieve certificate subject name');
        end;
      except
        on E: Exception do
          Logger.Error('Exception retrieving certificate info: ' + E.Message);
      end;
      var CryptProv: HCRYPTPROV;
      var KeySpec: DWORD;
      var MustFree: BOOL;
      if CryptAcquireCertificatePrivateKey(FCertContext, 0, nil, CryptProv, KeySpec, MustFree) then
      begin
        Logger.Info('Key info - Provider: %d, KeySpec: %d, MustFree: %s',
          [CryptProv, KeySpec, BoolToStr(MustFree, True)]);

        if MustFree then
        begin
          Logger.Info('Releasing temporary crypto provider...');
          CryptReleaseContext(CryptProv, 0);
        end;
      end
      else
      begin
        var CryptError := GetLastError;
        Logger.Info(Format('Certificate private key not accessible (Error: %d)', [CryptError]));
      end;

      Result := True;
    end
    else
    begin
      var FindError := GetLastError;
      Logger.Error('Certificate "CN=localhost" not found in store "myHTTPSSvr" (Error: %d)', [FindError]);
      Logger.Info('Checking for ANY certificates in store...');
      var AnyCertContext := CertFindCertificateInStore(
        CertStore,
        X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_ANY,
        nil,
        nil
      );

      if AnyCertContext <> nil then
      begin
        Logger.Info('Alternative certificate context at: %p', [AnyCertContext]);
        try
          var AltSubjectBuffer: array[0..255] of WideChar;
          var AltSubjectLen := CertGetNameString(
            AnyCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            nil,
            @AltSubjectBuffer[0],
            256
          );
          if AltSubjectLen > 1 then
          begin
            Logger.Info(Format('🔍 Alternative certificate subject: "%s"', [PWideChar(@AltSubjectBuffer[0])]));
          end;
        except
          Logger.Error('Could not get alternative certificate subject');
        end;
        FCertContext := AnyCertContext;
        Result := True;
      end
      else
      begin
        Logger.Info('The "myHTTPSSvr" store is empty - no certificates found');
        Logger.Info('To create the required certificate:');
        Logger.Info('1. Open Command Prompt as Administrator');
        Logger.Info('2. Execute: makecert -r -pe -n "CN=localhost" -ss myHTTPSSvr -sky exchange localhost.cer');
        Logger.Info('3. Restart the server');
      end;
    end;

  finally
    Logger.Info('Closing certificate store...');
    if CertCloseStore(CertStore, 0) then
      Logger.Info('Certificate store closed successfully')
    else
      Logger.Error('Error closing certificate store: %d', [GetLastError]);
  end;

  Logger.Info(Format('LoadServerCertificate END - Result: %s, FCertContext: %p',
    [BoolToStr(Result, True), FCertContext]));
end;


function TGHttpsServerIOCP.InitializeSSLCredentials: Boolean;
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
  SchannelCred.dwFlags := SCH_CRED_USE_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or SCH_CRED_CIPHER_SUITE_PRIORITY;
  Logger.Info('Flags set for CNG certificate (from SCH_CRED_USE_DEFAULT_CREDS).');
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
  if not InitializeWinsock then
  begin
    Logger.Info('Winsock initialization error');
    Exit;
  end;
  if not CreateListenSocket then
  begin
    Logger.Info('Error creating listening socket');
    CleanupWinsock;
    Exit;
  end;

  if not CreateCompletionPort then
  begin
    Logger.Info('Failed to create Completion Port');
    CleanupWinsock;
    Exit;
  end;

  if not LoadServerCertificate then
  begin
    Logger.Info('');
    Logger.Info('Checking available certificate stores...');
    ListCertificatesInStore(FCertificateStore);
    ListCertificatesInStore('MY');
    Logger.Info('');
  end;

  if not InitializeSSLCredentials then
  begin
    Logger.Info('Failed to initialize SSL credentials');
    CleanupWinsock;
    Exit;
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
  AcceptConnection2(FListenSocket);
  Logger.Info('HTTPS server listening on port ' + IntToStr(FPort));
  Result := True;
end;

procedure TGHttpsServerIOCP.Stop;
var
  i: Integer;
  ThreadHandle: THandle;
  Handles: TArray<THandle>;
begin
  if not FRunning then
    Exit;
  Logger.Info('Stopping the server...');
  FRunning := False;
  if FListenSocket <> INVALID_SOCKET then
  begin
    Logger.Info('[STOP] Closing the listening socket to cancel the pending AcceptEx operation...');
    closesocket(FListenSocket);
    FListenSocket := INVALID_SOCKET;
  end;
  if (FCompletionPort <> 0) and (FWorkerThreads.Count > 0) then
  begin
    Logger.Info('[STOP] Sending shutdown signals to the worker threads...');
    for i := 1 to FWorkerThreads.Count do
      PostQueuedCompletionStatus(FCompletionPort, 0, 0, nil);
  end;
  Logger.Info('[STOP] Waiting for worker threads to terminate...');
  if FWorkerThreads.Count > 0 then
  begin
    SetLength(Handles, FWorkerThreads.Count);
    for i := 0 to FWorkerThreads.Count - 1 do
      Handles[i] := FWorkerThreads[i];

    var WaitResult := WaitForMultipleObjects(Length(Handles), @Handles[0], True, 2000);
    if WaitResult = WAIT_TIMEOUT then
      Logger.Info('[STOP] Timeout waiting for worker threads to terminate. Active connections may remain.')
    else
      Logger.Info('[STOP] All worker threads terminated successfully.');
  end;

  if FMonitorRun then
  begin
    if FMonitorThread <> 0 then
    begin
        Logger.Info('[STOP] Waiting for the monitoring thread to terminate...');
        WaitForSingleObject(FMonitorThread, 2000);
        CloseHandle(FMonitorThread);
        FMonitorThread := 0;
    end;
  end;
  for ThreadHandle in FWorkerThreads do
    CloseHandle(ThreadHandle);
  FWorkerThreads.Clear;
  if FCompletionPort <> 0 then
  begin
    Logger.Info('[STOP] Closing the completion port...');
    CloseHandle(FCompletionPort);
    FCompletionPort := 0;
  end;

  Logger.Info('[STOP] Initiating explicit SSL cleanup...');
  if FCredentialsValid then
  begin
    try
      var Status := FreeCredentialsHandle(@FServerCredHandle);
      if Status = SEC_E_OK then
        Logger.Info('[STOP] SSL credentials handle zwolniony pomyślnie')
      else
        Logger.Info(Format('[STOP] FreeCredentialsHandle failed: 0x%x', [Status]));
      FCredentialsValid := False;
    except
      on E: Exception do Logger.Info('[STOP] Exception w FreeCredentialsHandle: ' + E.Message);
    end;
  end;

  if FCertContext <> nil then
  begin
    try
      if CertFreeCertificateContext(FCertContext) then
        Logger.Info('[STOP] Certificate context freed successfully')
      else
        Logger.Info('[STOP] CertFreeCertificateContext failed');
      FCertContext := nil;
    except
      on E: Exception do Logger.Info('[STOP] Exception w CertFreeCertificateContext: ' + E.Message);
    end;
  end;
  Logger.Info('[STOP] Executing  WSACleanup...');
  WSACleanup;
  Logger.Info('Server shut down cleanly.');
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
begin
  CreateIoCompletionPort(ClientSocket, FCompletionPort, ULONG_PTR(ClientSocket), 0);
  OverlappedEx := FOverlappedPool.Acquire;
  if OverlappedEx = nil then
  begin
    Logger.Error('Failed to start handshake for socket %d: the OverlappedEx pool is full.', [ClientSocket]);
    closesocket(ClientSocket);
    Exit;
  end;

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
      Logger.Error('Failed to start SSL handshake: ' + IntToStr(WSAGetLastError));
      closesocket(ClientSocket);
      FOverlappedPool.Release(OverlappedEx);
    end;
  end;
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
    begin
      OriginalBuffers[i] := OutputBuffers[i].pvBuffer;
    end;

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
    else
      Logger.Error('SSL Handshake failed: 0x%x', [Status]);
      OverlappedEx.SSLNeedsMoreData := False;
      Result := False;
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
  end
  else
  begin
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
  begin
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
      begin
          BytesConsumed := Length(EncryptedData);
      end;
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
          end
          else
          begin
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
          var OrigEnd := OrigAddr + Length(EncryptedData);
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
    else if Status = SEC_E_INCOMPLETE_MESSAGE then
    begin
    end
    else
    begin
    end;
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
    Response.SetMaxMemorySize(1 * 1024 * 1024);

    if Request.HasSecurityViolation then
    begin
      Logger.Warn('Security violation detected: ' + Request.GetThreatSummary);
      Response.SetBadRequest('Security Violation Detected');
    end
    else
    begin
      var Key := GetEndpointKey(Request.RequestInfo.Method, Request.RequestInfo.Path);
      if FEndpoints.TryGetValue(Key, Endpoint) then
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
              Server.HandleHttpsHandshake(OverlappedEx^.ClientSocket);
            end;
            Server.FOverlappedPool.Release(OverlappedEx);
          end;
          otSSLHandshake:
          begin
            if BytesTransferred > 0 then
            begin
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
                Server.InitializeRequestProcessing(OverlappedEx);
                OverlappedEx^.OpType := otRead;
                Server.ContinueReadingRequest(OverlappedEx);
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
                    if CurrentAttemptConsumedBytes < Length(OverlappedEx^.ClientReceiveBuffer) then
                    begin
                      System.Move(OverlappedEx^.ClientReceiveBuffer[CurrentAttemptConsumedBytes],
                                  OverlappedEx^.ClientReceiveBuffer[0],
                                  Length(OverlappedEx^.ClientReceiveBuffer) - CurrentAttemptConsumedBytes);
                      SetLength(OverlappedEx^.ClientReceiveBuffer,
                                Length(OverlappedEx^.ClientReceiveBuffer) - CurrentAttemptConsumedBytes);
                    end
                    else
                    begin
                      SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
                    end;
                    if Assigned(OverlappedEx^.Request) then
                    begin
                        if Length(DecryptedPlainData) > 0 then
                        begin
                           OverlappedEx^.Request.AppendData(DecryptedPlainData, Length(DecryptedPlainData));
                        end;
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
                begin
                  Break;
                end;
              end;
              if Assigned(OverlappedEx^.Request) then
              begin
                  if Server.IsRequestComplete(OverlappedEx^.Request) then
                  begin
                    Server.ProcessHttpRequest(OverlappedEx);
                  end
                  else if not OverlappedEx^.Request.CanAcceptMoreData then
                  begin
                    Server.ProcessHttpRequest(OverlappedEx);
                  end
                  else
                  begin
                    Server.ContinueReadingRequest(OverlappedEx);
                  end;
              end
              else
              begin
                  Logger.Error('OverlappedEx^.Request is NIL in otRead after decryption loop. Closing connection.');
                  CleanupConnectionWithReason(Server, OverlappedEx, 'Request object missing after decryption loop');
              end;
            end
            else // BytesTransferred = 0 (client closed the connection)
            begin
              CleanupConnectionWithReason(Server, OverlappedEx, 'The client closed the connection while reading');
            end;
          end;
          otWriteChunk:
          begin
            if BytesTransferred > 0 then
            begin
              Server.ContinueSendingResponse(OverlappedEx);
            end
            else
            begin
              Logger.Warn('Error sending chunk - 0 bytes sent');
              CleanupConnectionWithReason(Server, OverlappedEx, 'Error sending chunk - 0 bytes sent');
            end;
          end;
        end;
      except
        on E: Exception do
        begin
          CleanupConnectionWithReason(Server,OverlappedEx, 'Exception  in loop: ' + E.Message);
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
            Logger.Info(Format('Operation aborted for socket %d - code 995', [OverlappedEx^.Socket]));
            CleanupConnectionWithReason(Server,OverlappedEx, 'Operation aborted (ERROR_OPERATION_ABORTED)');
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
            CleanupConnectionWithReason(Server,OverlappedEx, Format('Connection interrupted (code: %d)', [Status]))
          else
            Logger.Info(Format('Connection interrupted - no context (code: %d)', [Status]));
        end;
        else
        begin
          Inc(ConsecutiveErrors);
          if Assigned(OverlappedEx) then
          begin
            Logger.Info(Format('GetQueuedCompletionStatus error: %d for socket %d', [Status, OverlappedEx^.Socket]));
            CleanupConnectionWithReason(Server,OverlappedEx, Format('Error GetQueuedCompletionStatus: %d', [Status]));
          end
          else
          begin
            Logger.Info(Format('Fatal error GetQueuedCompletionStatus without context: %d (consecutive: %d)', [Status, ConsecutiveErrors]));
          end;
          if ConsecutiveErrors > 5 then
          begin
            Logger.Info('Too many GetQueuedCompletionStatus errors - closing thread');
            GracefulShutdown := True;
          end
          else
          begin
            Sleep(100);
          end;
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
  BytesSentIO: DWORD;
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
      var Reason := 'Transfer completed (SSL shutdown completed)';
      if OverlappedEx^.SSLContextValid then
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
    if OverlappedEx^.SSLContextValid then
    begin
      if not EncryptBytesToSend(OverlappedEx^.SSLContext, PlainChunk, EncryptedChunk) then
      begin
        Logger.Error('FATAL ERROR: Failed to encrypt chunk. Closing connection.');
        CleanupConnectionWithReason(Self, OverlappedEx, 'Chunk encryption error');
        Exit;
      end;
    end
    else
    begin
      EncryptedChunk := PlainChunk;
    end;
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
        Logger.Error('Error starting chunk upload: %d', [ErrorCode]);
        CleanupConnectionWithReason(Self, OverlappedEx, Format('Error WSASend: %d', [ErrorCode]));
      end;
    end;

  except
    on E: Exception do
    begin
      Logger.Error('Exception in ContinueSendingResponse: ' + E.Message);
      CleanupConnectionWithReason(Self, OverlappedEx, 'Exception in ContinueSendingResponse: ' + E.Message);
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
  begin
    Exit;
  end;
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
    begin
      Exit;
    end;
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
    begin
      OriginalBuffers[i] := Buffers[i].pvBuffer;
    end;
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
  end
  else
  begin
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
    if Server.FRejectNewConnections = 1 then
      Sleep(9000)
    else
      Sleep(200);
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
            ShouldReject := True;
            RejectReason := Format('High CPU load from server process (%.1f%%)', [CPUUsage]);
          end;
        end;
      end;
      CurrentRequests := TInterlocked.Exchange(Server.FRequestsPerSecondCounter, 0);
      if CurrentRequests > Server.FMaxRequestsPerSecond then
      begin
        ShouldReject := True;
        RejectReason := Format('Requests per second limit exceeded (%d > %d)',
          [CurrentRequests, Server.FMaxRequestsPerSecond]);
        TInterlocked.Exchange(Server.FThrottleNewConnections, 1);
      end
      else
      begin
        TInterlocked.Exchange(Server.FThrottleNewConnections, 0);
      end;
      if not ShouldReject then
      begin
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
    except
      on E: Exception do
        Logger.Error('Error in monitoring thread loop: ' + E.Message);
    end;
  end;
  Logger.Info('Monitoring thread terminated.');
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

end.
