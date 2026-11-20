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
unit GWebSocketBridge;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.TypInfo,
  System.SyncObjs,
  System.Generics.Collections,
  GLogger,
  WinApiAdditions,
  GWebSocket,
  OverlappedExPool,
  GSchannelTlsManager,
  GHttpsServerTypes;

type
  TWSBridgeConnectNotify = reference to procedure(Session: TWebSocketSession);
  TWSBridgeDisconnectNotify = reference to procedure(Session: TWebSocketSession; const Reason: string);
  TWSBridgeCleanupConnectionProc = reference to procedure(OverlappedEx: POverlappedEx; const Reason: string);
  TWSBridgeIssueWSARecvFunc = reference to function(OverlappedEx: POverlappedEx): Boolean;
  TWSBridgeTrackIPDisconnectProc = reference to procedure(const AIP: string);

  TWebSocketServerBridge = class
  private
    FLock: TCriticalSection;
    FWebSocketManager: TWebSocketManager;
    FWebSocketRoutes: TDictionary<string, Boolean>;
    FWebSocketRoutesLock: TLightweightMREW;
    FHasWebSocketRoutes: Integer;
    FWebSocketRouteHandlers: TDictionary<string, IInterface>;
    FWebSocketRawRouteHandlers: TDictionary<string, IInterface>;
    FWebSocketRouteAuth: TDictionary<string, TAuthorizationType>;
    FWebSocketRouteProtocols: TDictionary<string, TArray<string>>;
    FSupportedWebSocketProtocols: TArray<string>;
    FTlsManager: TSchannelTlsManager;
    FOverlappedPool: TOverlappedExPool;
    FActiveOverlapped: TDictionary<POverlappedEx, Byte>;
    FActiveOverlappedLock: TCriticalSection;
    FCompletionPortPtr: PHandle;
    FActiveConnectionsPtr: PInt64;
    FOnConnectNotify: TWSBridgeConnectNotify;
    FOnDisconnectNotify: TWSBridgeDisconnectNotify;
    FOnCleanupConnection: TWSBridgeCleanupConnectionProc;
    FOnIssueWSARecv: TWSBridgeIssueWSARecvFunc;
    FOnTrackIPDisconnect: TWSBridgeTrackIPDisconnectProc;
  public
    constructor Create(
      ALock: TCriticalSection;
      ATlsManager: TSchannelTlsManager;
      AOverlappedPool: TOverlappedExPool;
      AActiveOverlapped: TDictionary<POverlappedEx, Byte>;
      AActiveOverlappedLock: TCriticalSection;
      ACompletionPortPtr: PHandle;
      AActiveConnectionsPtr: PInt64
    );
    destructor Destroy; override;
    function SelectWebSocketSubProtocol(const APath, AClientProtocols: string): string;
    procedure TransitionToWebSocket(OverlappedEx: POverlappedEx);
    procedure BroadcastWebSocket(const AText: string);
    procedure BroadcastWebSocketBinary(const Data: TBytes);
    function GetWebSocketActiveCount: Integer;
    procedure TriggerWebSocketWrite(Session: TWebSocketSession);
    procedure CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
    procedure RegisterRoute(const APath: string; AOnMessageIntf: IInterface; AAuthType: TAuthorizationType; const ASupportedProtocols: TArray<string>);
    procedure RegisterRawRoute(const APath: string; AOnMessageIntf: IInterface; AAuthType: TAuthorizationType);
    function HasRoute(const APath: string): Boolean;
    function TryGetRouteAuth(const APath: string; out AAuthType: TAuthorizationType): Boolean;
    function TryGetRouteHandler(const APath: string; out AHandlerIntf: IInterface): Boolean;
    function TryGetRawRouteHandler(const APath: string; out AHandlerIntf: IInterface): Boolean;
    property WebSocketManager: TWebSocketManager read FWebSocketManager;
    property HasWebSocketRoutes: Integer read FHasWebSocketRoutes;
    property SupportedWebSocketProtocols: TArray<string> read FSupportedWebSocketProtocols write FSupportedWebSocketProtocols;
    property OnConnectNotify: TWSBridgeConnectNotify read FOnConnectNotify write FOnConnectNotify;
    property OnDisconnectNotify: TWSBridgeDisconnectNotify read FOnDisconnectNotify write FOnDisconnectNotify;
    property OnCleanupConnection: TWSBridgeCleanupConnectionProc read FOnCleanupConnection write FOnCleanupConnection;
    property OnIssueWSARecv: TWSBridgeIssueWSARecvFunc read FOnIssueWSARecv write FOnIssueWSARecv;
    property OnTrackIPDisconnect: TWSBridgeTrackIPDisconnectProc read FOnTrackIPDisconnect write FOnTrackIPDisconnect;
  end;

implementation

constructor TWebSocketServerBridge.Create(
  ALock: TCriticalSection;
  ATlsManager: TSchannelTlsManager;
  AOverlappedPool: TOverlappedExPool;
  AActiveOverlapped: TDictionary<POverlappedEx, Byte>;
  AActiveOverlappedLock: TCriticalSection;
  ACompletionPortPtr: PHandle;
  AActiveConnectionsPtr: PInt64);
begin
  inherited Create;
  FLock := ALock;
  FTlsManager := ATlsManager;
  FOverlappedPool := AOverlappedPool;
  FActiveOverlapped := AActiveOverlapped;
  FActiveOverlappedLock := AActiveOverlappedLock;
  FCompletionPortPtr := ACompletionPortPtr;
  FActiveConnectionsPtr := AActiveConnectionsPtr;
  FWebSocketRoutes := TDictionary<string, Boolean>.Create;
  FHasWebSocketRoutes := 0;
  FWebSocketRouteHandlers := TDictionary<string, IInterface>.Create;
  FWebSocketRawRouteHandlers := TDictionary<string, IInterface>.Create;
  FWebSocketRouteAuth := TDictionary<string, TAuthorizationType>.Create;
  FWebSocketRouteProtocols := TDictionary<string, TArray<string>>.Create;
  FWebSocketManager := TWebSocketManager.Create;
end;

destructor TWebSocketServerBridge.Destroy;
begin
  FreeAndNil(FWebSocketManager);
  FreeAndNil(FWebSocketRouteHandlers);
  FreeAndNil(FWebSocketRawRouteHandlers);
  FreeAndNil(FWebSocketRouteAuth);
  FreeAndNil(FWebSocketRouteProtocols);
  FreeAndNil(FWebSocketRoutes);
  inherited Destroy;
end;

function TWebSocketServerBridge.HasRoute(const APath: string): Boolean;
begin
  if InterlockedCompareExchange(FHasWebSocketRoutes, 0, 0) = 0 then
    Exit(False);
  FWebSocketRoutesLock.BeginRead;
  try
    Result := FWebSocketRoutes.ContainsKey(APath);
  finally
    FWebSocketRoutesLock.EndRead;
  end;
end;

function TWebSocketServerBridge.TryGetRouteAuth(const APath: string; out AAuthType: TAuthorizationType): Boolean;
begin
  FLock.Enter;
  try
    Result := FWebSocketRouteAuth.TryGetValue(APath, AAuthType);
  finally
    FLock.Leave;
  end;
end;

function TWebSocketServerBridge.TryGetRouteHandler(const APath: string; out AHandlerIntf: IInterface): Boolean;
begin
  FLock.Enter;
  try
    Result := FWebSocketRouteHandlers.TryGetValue(APath, AHandlerIntf);
  finally
    FLock.Leave;
  end;
end;

function TWebSocketServerBridge.TryGetRawRouteHandler(const APath: string; out AHandlerIntf: IInterface): Boolean;
begin
  FLock.Enter;
  try
    Result := FWebSocketRawRouteHandlers.TryGetValue(APath, AHandlerIntf);
  finally
    FLock.Leave;
  end;
end;

function TWebSocketServerBridge.SelectWebSocketSubProtocol(const APath, AClientProtocols: string): string;
var
  RouteProtocols: TArray<string>;
  ClientProtos: TArray<string>;
  ClientP, ServerP: string;
begin
  Result := '';
  if AClientProtocols = '' then
    Exit;
  ClientProtos := AClientProtocols.Split([',']);

  FLock.Enter;
  try
    if FWebSocketRouteProtocols.TryGetValue(APath, RouteProtocols) and (Length(RouteProtocols) > 0) then
    begin
      for ClientP in ClientProtos do
      begin
        for ServerP in RouteProtocols do
        begin
          if SameText(Trim(ClientP), Trim(ServerP)) then
          begin
            Result := Trim(ClientP);
            Exit;
          end;
        end;
      end;
    end
    else if Length(FSupportedWebSocketProtocols) > 0 then
    begin
      for ClientP in ClientProtos do
      begin
        for ServerP in FSupportedWebSocketProtocols do
        begin
          if SameText(Trim(ClientP), Trim(ServerP)) then
          begin
            Result := Trim(ClientP);
            Exit;
          end;
        end;
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TWebSocketServerBridge.TransitionToWebSocket(OverlappedEx: POverlappedEx);
var
  Session: TWebSocketSession;
  WriteOverlapped: POverlappedEx;
  CachedHandler: IInterface;
  CachedRawHandler: IInterface;
  ReqPath: string;
  SessionSubProtocol: string;
  LastErr: Integer;
begin
  ReqPath := '';
  SessionSubProtocol := '';
  if Assigned(OverlappedEx^.Request) then
    ReqPath := OverlappedEx^.Request.RequestInfo.Path.ToLower;
  if Assigned(OverlappedEx^.Response) then
    SessionSubProtocol := OverlappedEx^.Response.Headers.Values['Sec-WebSocket-Protocol'];

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
  Session.SubProtocol := SessionSubProtocol;
  CachedHandler := nil;
  CachedRawHandler := nil;
  if ReqPath <> '' then
  begin
    FLock.Enter;
    try
      if FWebSocketRouteHandlers.TryGetValue(ReqPath, CachedHandler) and Assigned(CachedHandler) then
        Session.CachedRouteHandler := CachedHandler;
      if FWebSocketRawRouteHandlers.TryGetValue(ReqPath, CachedRawHandler) and Assigned(CachedRawHandler) then
        Session.CachedRawRouteHandler := CachedRawHandler;
    finally
      FLock.Leave;
    end;
  end;

  WriteOverlapped := FOverlappedPool.Acquire;
  if WriteOverlapped = nil then
  begin
    Logger.Error('TransitionToWebSocket: OverlappedExPool full, cannot acquire WriteOverlapped for socket %d. Aborting upgrade.', [OverlappedEx^.Socket]);
    Session.Free;
    SetLength(OverlappedEx^.ClientReceiveBuffer, 0);
    if Assigned(FOnCleanupConnection) then
      FOnCleanupConnection(OverlappedEx, 'WebSocket upgrade failed: pool exhausted');
    Exit;
  end;

  WriteOverlapped^.Socket := OverlappedEx^.Socket;
  WriteOverlapped^.ClientSocket := OverlappedEx^.ClientSocket;
  WriteOverlapped^.IsTLS := OverlappedEx^.IsTLS;
  WriteOverlapped^.SkipIOCP := OverlappedEx^.SkipIOCP;
  WriteOverlapped^.ListenerPort := OverlappedEx^.ListenerPort;
  WriteOverlapped^.SSLContext := OverlappedEx^.SSLContext;
  WriteOverlapped^.SSLContextValid := OverlappedEx^.SSLContextValid;
  WriteOverlapped^.OpenSSLHandle := OverlappedEx^.OpenSSLHandle;
  WriteOverlapped^.OpenSSLRBio := OverlappedEx^.OpenSSLRBio;
  WriteOverlapped^.OpenSSLWBio := OverlappedEx^.OpenSSLWBio;
  WriteOverlapped^.SSLContextBorrowed := True;
  WriteOverlapped^.SSLLockPtr := OverlappedEx;
  OverlappedEx^.SSLLockPtr := OverlappedEx;
  WriteOverlapped^.OpType := otWebSocketWrite;
  WriteOverlapped^.WebSocketSession := Session;
  WriteOverlapped^.ClientIP := OverlappedEx^.ClientIP;

  OverlappedEx^.OpType := otWebSocketRead;
  OverlappedEx^.WebSocketSession := Session;
  OverlappedEx^.WebSocketState := 1;

  Session.ReadOverlapped := OverlappedEx;
  Session.WriteOverlapped := WriteOverlapped;

  FWebSocketManager.AddSession(Session);

  if Assigned(FOnConnectNotify) then
  begin
    try
      FOnConnectNotify(Session);
    except
      on E: Exception do
        Logger.Error('Exception in FOnWebSocketConnect: %s', [E.Message]);
    end;
  end;

  TriggerWebSocketWrite(Session);

  if Assigned(FOnIssueWSARecv) and (not FOnIssueWSARecv(OverlappedEx)) then
  begin
    LastErr := WSAGetLastError;
    if (LastErr = 10053) or (LastErr = 10054) or (LastErr = 10058) then
      Logger.Debug('Client disconnected during TransitionToWebSocket: %d', [LastErr])
    else
      Logger.Error('WSARecv failed in TransitionToWebSocket: %d', [LastErr]);
    CleanupWebSocketSession(Session, 'WSARecv failed on transition');
  end;
end;

procedure TWebSocketServerBridge.BroadcastWebSocket(const AText: string);
var
  Payload: TBytes;
  SessionList: TList<TWebSocketSession>;
  WS_Session: TWebSocketSession;
begin
  if not Assigned(FWebSocketManager) then
    Exit;
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

procedure TWebSocketServerBridge.BroadcastWebSocketBinary(const Data: TBytes);
var
  SessionList: TList<TWebSocketSession>;
  WS_Session: TWebSocketSession;
begin
  if not Assigned(FWebSocketManager) or (Length(Data) = 0) then
    Exit;
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

function TWebSocketServerBridge.GetWebSocketActiveCount: Integer;
begin
  if Assigned(FWebSocketManager) then
    Result := FWebSocketManager.GetSessionCount
  else
    Result := 0;
end;

procedure TWebSocketServerBridge.TriggerWebSocketWrite(Session: TWebSocketSession);
var
  PlainChunk, EncryptedChunk: TBytes;
  WSABuf: TWSABUF;
  BytesSent: DWORD;
  CurrentWriteOv: POverlappedEx;
  RetryWrite: Boolean;
  InlineCount: Integer;
begin
  if not Assigned(Session) or (Session.InCleanup <> 0) then
    Exit;
  CurrentWriteOv := Session.WriteOverlapped;
  if not Assigned(CurrentWriteOv) then
    Exit;

  InlineCount := 0;
  Session.AddRef;
  try
    repeat
      RetryWrite := False;
      if TInterlocked.CompareExchange(Session.WritePending, 1, 0) <> 0 then
        Exit;

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
            if not FTlsManager.EncryptBytesToSend(CurrentWriteOv^, PlainChunk, EncryptedChunk) then
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
            begin
              TInterlocked.Exchange(Session.WritePending, 0);
              CleanupWebSocketSession(Session, 'WSASend failed: ' + IntToStr(WSAGetLastError));
            end;
          end
          else if CurrentWriteOv^.SkipIOCP then
          begin
            if (BytesSent > 0) and not (Session.CloseReceived and not Session.HasPendingWrites) and (InlineCount < 16) then
            begin
              Inc(InlineCount);
              TInterlocked.Exchange(Session.WritePending, 0);
              if (Session.InCleanup = 0) and Session.HasPendingWrites then
                RetryWrite := True;
            end
            else
              PostQueuedCompletionStatus(FCompletionPortPtr^, BytesSent, ULONG_PTR(Session.Socket), POverlapped(CurrentWriteOv));
          end;
        end
        else
        begin
          TInterlocked.Exchange(Session.WritePending, 0);
          if (Session.InCleanup = 0) and Session.HasPendingWrites then
            RetryWrite := True;
        end;
      end
      else
      begin
        TInterlocked.Exchange(Session.WritePending, 0);
        if (Session.InCleanup = 0) and Session.HasPendingWrites then
          RetryWrite := True;
      end;
    until not RetryWrite;
  finally
    Session.Release;
  end;
end;

procedure TWebSocketServerBridge.CleanupWebSocketSession(Session: TWebSocketSession; const Reason: string);
var
  LocalSocket: TSocket;
  ClientIP: string;
  WriteOv: POverlappedEx;
  SockId: TSocket;
begin
  if not Assigned(Session) then
    Exit;

  if TInterlocked.CompareExchange(Session.InCleanup, 1, 0) <> 0 then
    Exit;

  if Assigned(Session.ReadOverlapped) then
    Session.ReadOverlapped^.WebSocketSession := nil;
  if Assigned(Session.WriteOverlapped) then
    Session.WriteOverlapped^.WebSocketSession := nil;

  try
    LocalSocket := Session.Socket;
    if Assigned(FOnDisconnectNotify) then
    begin
      try
        FOnDisconnectNotify(Session, Reason);
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
      InterlockedDecrement64(FActiveConnectionsPtr^);
      if Assigned(Session.ReadOverlapped) then
      begin
        ClientIP := string(PAnsiChar(@Session.ReadOverlapped^.ClientIP[0]));
        if (ClientIP <> '') and Assigned(FOnTrackIPDisconnect) then
          FOnTrackIPDisconnect(ClientIP);
      end;
      try
        shutdown(LocalSocket, SD_BOTH);
      except
      end;
      closesocket(LocalSocket);
    end;

    WriteOv := Session.DetachWriteOverlapped;
    if Assigned(WriteOv) then
    begin
      if Assigned(FTlsManager) then
        FTlsManager.ReleaseConnectionContext(WriteOv^);
      SetLength(WriteOv^.ClientReceiveBuffer, 0);
      WriteOv^.WebSocketSession := nil;
      if Assigned(FOverlappedPool) then
        FOverlappedPool.Release(WriteOv);
    end;

    Session.Release;
  except
    on E: Exception do
    begin
      SockId := 0;
      if Assigned(Session) then
        SockId := Session.Socket;
      Logger.Error('Exception in CleanupWebSocketSession [Socket:%d, %s]: %s', [SockId, E.ClassName, E.Message]);
    end;
  end;
end;

procedure TWebSocketServerBridge.RegisterRoute(const APath: string; AOnMessageIntf: IInterface; AAuthType: TAuthorizationType; const ASupportedProtocols: TArray<string>);
var
  CleanPath: string;
begin
  FLock.Enter;
  try
    CleanPath := APath.ToLower;
    FWebSocketRoutesLock.BeginWrite;
    try
      FWebSocketRoutes.AddOrSetValue(CleanPath, True);
      InterlockedExchange(FHasWebSocketRoutes, 1);
    finally
      FWebSocketRoutesLock.EndWrite;
    end;
    if Assigned(AOnMessageIntf) then
      FWebSocketRouteHandlers.AddOrSetValue(CleanPath, AOnMessageIntf);
    FWebSocketRouteAuth.AddOrSetValue(CleanPath, AAuthType);
    if Length(ASupportedProtocols) > 0 then
      FWebSocketRouteProtocols.AddOrSetValue(CleanPath, ASupportedProtocols);
    Logger.Info(Format('Registered WebSocket route: %s (HasCustomHandler: %s, AuthType: %s)', [APath, BoolToStr(Assigned(AOnMessageIntf), True), GetEnumName(TypeInfo(TAuthorizationType), Ord(AAuthType))]));
  finally
    FLock.Leave;
  end;
end;

procedure TWebSocketServerBridge.RegisterRawRoute(const APath: string; AOnMessageIntf: IInterface; AAuthType: TAuthorizationType);
var
  CleanPath: string;
begin
  FLock.Enter;
  try
    CleanPath := APath.ToLower;
    FWebSocketRoutesLock.BeginWrite;
    try
      FWebSocketRoutes.AddOrSetValue(CleanPath, True);
      InterlockedExchange(FHasWebSocketRoutes, 1);
    finally
      FWebSocketRoutesLock.EndWrite;
    end;
    if Assigned(AOnMessageIntf) then
      FWebSocketRawRouteHandlers.AddOrSetValue(CleanPath, AOnMessageIntf);
    FWebSocketRouteAuth.AddOrSetValue(CleanPath, AAuthType);
  finally
    FLock.Leave;
  end;
end;

end.
