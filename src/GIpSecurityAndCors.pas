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
unit GIpSecurityAndCors;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.StrUtils,
  System.SyncObjs,
  System.Generics.Collections,
  Quick.Logger,
  GRequest,
  GResponse,
  WinApiAdditions,
  GHttpsServerTypes;

type
  TIpSecurityTracker = class
  private
    FIPTracker: TDictionary<string, TIPClientInfo>;
    FIPTrackerLock: TCriticalSection;
    FIPTrackerInactiveTimeoutMs: UInt64;
    FLastIPPruneTick: UInt64;
    FMaxConnectionsPerIP: Integer;
    FEnableIPRateLimiting: Boolean;
    FMaxRequestsPerIPPerSecond: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    function ExtractClientIP(ClientSocket: TSocket; ListenSocket: TSocket): string;
    function TrackIPConnect(const AIP: string): Boolean;
    procedure TrackIPDisconnect(const AIP: string);
    procedure PruneInactiveIPTrackers;
    function GetTrackedIPCount: Integer;
    function CheckIPRateLimit(const AIP: string): Boolean;
    function CheckAndResetQuicBlock(const ARemoteIP: string): Boolean;
    procedure ClearQuicFailureCount(const ARemoteIP: string);
    procedure RecordQuicHandshakeFailure(const ARemoteIP: string; IsMTlsRequired: Boolean);
    property IPTrackerInactiveTimeoutMs: UInt64 read FIPTrackerInactiveTimeoutMs write FIPTrackerInactiveTimeoutMs;
    property LastIPPruneTick: UInt64 read FLastIPPruneTick write FLastIPPruneTick;
    property MaxConnectionsPerIP: Integer read FMaxConnectionsPerIP write FMaxConnectionsPerIP;
    property EnableIPRateLimiting: Boolean read FEnableIPRateLimiting write FEnableIPRateLimiting;
    property MaxRequestsPerIPPerSecond: Integer read FMaxRequestsPerIPPerSecond write FMaxRequestsPerIPPerSecond;
  end;

  TCorsAndOriginPolicy = class
  private
    FEnableCORS: Boolean;
    FCORSAllowedOrigins: string;
    FCORSAllowedMethods: string;
    FCORSAllowedHeaders: string;
    FCORSExposeHeaders: string;
    FCORSAllowCredentials: Boolean;
    FCORSMaxAge: Integer;
    FAllowedWebSocketOrigins: string;
    FAllowedWebTransportOrigins: string;
  public
    constructor Create;
    function IsOriginAllowed(const AOrigin: string): Boolean;
    function IsWebSocketOriginAllowed(const AOrigin: string; const AHost: string = ''): Boolean;
    function IsWebTransportOriginAllowed(const AOrigin: string; const AHost: string = ''): Boolean;
    function HandleCORSPreflight(Request: TRequest; Response: TResponse): Boolean;
    procedure ApplyCORSHeaders(Request: TRequest; Response: TResponse);
    property EnableCORS: Boolean read FEnableCORS write FEnableCORS;
    property CORSAllowedOrigins: string read FCORSAllowedOrigins write FCORSAllowedOrigins;
    property CORSAllowedMethods: string read FCORSAllowedMethods write FCORSAllowedMethods;
    property CORSAllowedHeaders: string read FCORSAllowedHeaders write FCORSAllowedHeaders;
    property CORSExposeHeaders: string read FCORSExposeHeaders write FCORSExposeHeaders;
    property CORSAllowCredentials: Boolean read FCORSAllowCredentials write FCORSAllowCredentials;
    property CORSMaxAge: Integer read FCORSMaxAge write FCORSMaxAge;
    property AllowedWebSocketOrigins: string read FAllowedWebSocketOrigins write FAllowedWebSocketOrigins;
    property AllowedWebTransportOrigins: string read FAllowedWebTransportOrigins write FAllowedWebTransportOrigins;
  end;

function IsLoopbackHostOrIP(const AHost: string): Boolean;

implementation

function IsLoopbackHostOrIP(const AHost: string): Boolean;
var
  H: string;
begin
  H := LowerCase(Trim(AHost));
  if Pos('::ffff:', H) = 1 then
    H := Copy(H, 8, MaxInt);
  Result := (H = 'localhost') or (H = '::1') or (H = '127.0.0.1') or (Pos('127.', H) = 1);
end;

constructor TIpSecurityTracker.Create;
begin
  inherited Create;
  FIPTracker := TDictionary<string, TIPClientInfo>.Create;
  FIPTrackerLock := TCriticalSection.Create;
  FIPTrackerInactiveTimeoutMs := 300000;
  FLastIPPruneTick := GetTickCount64;
  FMaxConnectionsPerIP := 10000;
  FEnableIPRateLimiting := False;
  FMaxRequestsPerIPPerSecond := 1000;
end;

destructor TIpSecurityTracker.Destroy;
var
  Info: TIPClientInfo;
begin
  if Assigned(FIPTrackerLock) and Assigned(FIPTracker) then
  begin
    FIPTrackerLock.Enter;
    try
      for Info in FIPTracker.Values do
        Info.Free;
      FIPTracker.Clear;
    finally
      FIPTrackerLock.Leave;
    end;
  end;
  FreeAndNil(FIPTracker);
  FreeAndNil(FIPTrackerLock);
  inherited Destroy;
end;

function TIpSecurityTracker.ExtractClientIP(ClientSocket: TSocket; ListenSocket: TSocket): string;
var
  PeerAddr: TSockAddrIn;
  AddrLen: Integer;
  P: PAnsiChar;
begin
  Result := '';
  if ClientSocket = INVALID_SOCKET then
    Exit;

  if ListenSocket <> INVALID_SOCKET then
    setsockopt(ClientSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, PAnsiChar(@ListenSocket), SizeOf(TSocket));

  AddrLen := SizeOf(PeerAddr);
  ZeroMemory(@PeerAddr, AddrLen);
  if getpeername(ClientSocket, TSockAddr(PeerAddr), AddrLen) = 0 then
  begin
    P := inet_ntoa(PeerAddr.sin_addr);
    if Assigned(P) then
      Result := string(P);
  end;
end;

function TIpSecurityTracker.TrackIPConnect(const AIP: string): Boolean;
var
  Info: TIPClientInfo;
begin
  Result := True;
  if (FMaxConnectionsPerIP <= 0) and (not FEnableIPRateLimiting) then
    Exit;
  if AIP = '' then
    Exit;

  FIPTrackerLock.Enter;
  try
    if not FIPTracker.TryGetValue(AIP, Info) then
    begin
      Info := TIPClientInfo.Create;
      FIPTracker.Add(AIP, Info);
    end;

    if (FMaxConnectionsPerIP > 0) and (Info.ActiveConnections >= FMaxConnectionsPerIP) then
    begin
      Result := False;
      Exit;
    end;

    Inc(Info.ActiveConnections);
  finally
    FIPTrackerLock.Leave;
  end;
end;

procedure TIpSecurityTracker.TrackIPDisconnect(const AIP: string);
var
  Info: TIPClientInfo;
begin
  if (FMaxConnectionsPerIP <= 0) and (not FEnableIPRateLimiting) then
    Exit;
  if AIP = '' then
    Exit;

  FIPTrackerLock.Enter;
  try
    if FIPTracker.TryGetValue(AIP, Info) then
    begin
      if Info.ActiveConnections > 0 then
        Dec(Info.ActiveConnections);

      if (Info.ActiveConnections <= 0) and (GetTickCount64 - Info.WindowStartTick > FIPTrackerInactiveTimeoutMs) then
      begin
        FIPTracker.Remove(AIP);
        Info.Free;
      end;
    end;
  finally
    FIPTrackerLock.Leave;
  end;
end;

procedure TIpSecurityTracker.PruneInactiveIPTrackers;
var
  IPList: TList<string>;
  NowTick: UInt64;
  Info: TIPClientInfo;
  Pair: TPair<string, TIPClientInfo>;
  IP: string;
begin
  if not Assigned(FIPTracker) or not Assigned(FIPTrackerLock) then
    Exit;

  NowTick := GetTickCount64;
  IPList := nil;

  FIPTrackerLock.Enter;
  try
    for Pair in FIPTracker do
    begin
      if (Pair.Value.ActiveConnections <= 0) and (NowTick - Pair.Value.WindowStartTick > FIPTrackerInactiveTimeoutMs) then
      begin
        if IPList = nil then
          IPList := TList<string>.Create;
        IPList.Add(Pair.Key);
      end;
    end;

    if Assigned(IPList) then
    begin
      Logger.Debug(Format('MONITOR: Pruned %d inactive IP address(es) from tracker', [IPList.Count]));
      for IP in IPList do
      begin
        if FIPTracker.TryGetValue(IP, Info) then
        begin
          FIPTracker.Remove(IP);
          Info.Free;
        end;
      end;
    end;
  finally
    FIPTrackerLock.Leave;
    if Assigned(IPList) then
      IPList.Free;
  end;
end;

function TIpSecurityTracker.GetTrackedIPCount: Integer;
begin
  Result := 0;
  if Assigned(FIPTrackerLock) and Assigned(FIPTracker) then
  begin
    FIPTrackerLock.Enter;
    try
      Result := FIPTracker.Count;
    finally
      FIPTrackerLock.Leave;
    end;
  end;
end;

function TIpSecurityTracker.CheckIPRateLimit(const AIP: string): Boolean;
var
  Info: TIPClientInfo;
  NowTick: UInt64;
begin
  Result := True;
  if not FEnableIPRateLimiting or (AIP = '') or (FMaxRequestsPerIPPerSecond <= 0) then
    Exit;

  NowTick := GetTickCount64;
  FIPTrackerLock.Enter;
  try
    if not FIPTracker.TryGetValue(AIP, Info) then
    begin
      Info := TIPClientInfo.Create;
      FIPTracker.Add(AIP, Info);
    end;

    if NowTick - Info.WindowStartTick >= 1000 then
    begin
      Info.WindowStartTick := NowTick;
      Info.RequestCount := 1;
    end
    else
    begin
      Inc(Info.RequestCount);
      if Info.RequestCount > FMaxRequestsPerIPPerSecond then
        Result := False;
    end;
  finally
    FIPTrackerLock.Leave;
  end;
end;

function TIpSecurityTracker.CheckAndResetQuicBlock(const ARemoteIP: string): Boolean;
var
  Info: TIPClientInfo;
  NowTick: UInt64;
begin
  Result := True;
  if ARemoteIP = '' then
    Exit;
  NowTick := GetTickCount64;
  FIPTrackerLock.Enter;
  try
    if FIPTracker.TryGetValue(ARemoteIP, Info) then
    begin
      if (Info.BlockedUntilTick > 0) and (NowTick < Info.BlockedUntilTick) then
      begin
        Logger.Warn('[QUIC] HandleQuicBeforeAcceptConnection rejected: IP %s blocked until tick %d (now %d)',
          [ARemoteIP, Info.BlockedUntilTick, NowTick]);
        Exit(False);
      end;
      if Info.BlockedUntilTick <= NowTick then
      begin
        Info.FailureCount := 0;
        Info.BlockedUntilTick := 0;
      end;
    end;
  finally
    FIPTrackerLock.Leave;
  end;
end;

procedure TIpSecurityTracker.ClearQuicFailureCount(const ARemoteIP: string);
var
  Info: TIPClientInfo;
begin
  if ARemoteIP = '' then
    Exit;
  FIPTrackerLock.Enter;
  try
    if FIPTracker.TryGetValue(ARemoteIP, Info) and (Info.BlockedUntilTick = 0) then
      Info.FailureCount := 0;
  finally
    FIPTrackerLock.Leave;
  end;
end;

procedure TIpSecurityTracker.RecordQuicHandshakeFailure(const ARemoteIP: string; IsMTlsRequired: Boolean);
var
  Info: TIPClientInfo;
  NowTick: UInt64;
  ShiftVal: Integer;
begin
  if ARemoteIP = '' then
    Exit;
  NowTick := GetTickCount64;
  FIPTrackerLock.Enter;
  try
    if not FIPTracker.TryGetValue(ARemoteIP, Info) then
    begin
      Info := TIPClientInfo.Create;
      FIPTracker.Add(ARemoteIP, Info);
    end;
    Inc(Info.FailureCount);
    if IsMTlsRequired or (Info.FailureCount >= 5) then
    begin
      ShiftVal := Info.FailureCount;
      if ShiftVal > 6 then
        ShiftVal := 6;
      Info.BlockedUntilTick := NowTick + UInt64(1000 shl ShiftVal);
      Logger.Warn('[QUIC] Handshake failed from %s (Failures=%d, BlockedUntilTick=%d)',
        [ARemoteIP, Info.FailureCount, Info.BlockedUntilTick]);
    end
    else
    begin
      Logger.Warn('[QUIC] Handshake failed from %s (Failures=%d/5, not blocked)',
        [ARemoteIP, Info.FailureCount]);
    end;
  finally
    FIPTrackerLock.Leave;
  end;
end;

constructor TCorsAndOriginPolicy.Create;
begin
  inherited Create;
  FEnableCORS := False;
  FCORSAllowedOrigins := '*';
  FCORSAllowedMethods := 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
  FCORSAllowedHeaders := 'Content-Type, Authorization, X-Requested-With';
  FCORSExposeHeaders := '';
  FCORSAllowCredentials := False;
  FCORSMaxAge := 86400;
  FAllowedWebSocketOrigins := '*';
  FAllowedWebTransportOrigins := '*';
end;

function TCorsAndOriginPolicy.IsOriginAllowed(const AOrigin: string): Boolean;
var
  AllowedList: TArray<string>;
  AllowedItem: string;
  TrimmedOrigin: string;
begin
  Result := False;
  TrimmedOrigin := Trim(AOrigin);
  if TrimmedOrigin = '' then
    Exit;

  if (FCORSAllowedOrigins = '*') or (FCORSAllowedOrigins = '') then
  begin
    Result := True;
    Exit;
  end;

  AllowedList := FCORSAllowedOrigins.Split([',', ';']);
  for AllowedItem in AllowedList do
  begin
    if SameText(Trim(AllowedItem), TrimmedOrigin) or (Trim(AllowedItem) = '*') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function TCorsAndOriginPolicy.IsWebSocketOriginAllowed(const AOrigin: string; const AHost: string): Boolean;
var
  AllowedList: TArray<string>;
  AllowedItem: string;
  TrimmedOrigin: string;
  TrimmedHost: string;
  OriginHost: string;
  HostNoPort: string;
  ColonPos: Integer;
begin
  Result := False;
  TrimmedOrigin := Trim(AOrigin);
  if TrimmedOrigin = '' then
  begin
    Result := True;
    Exit;
  end;

  if SameText(TrimmedOrigin, 'null') then
    Exit(False);

  TrimmedHost := Trim(AHost);
  if TrimmedHost <> '' then
  begin
    if SameText('http://' + TrimmedHost, TrimmedOrigin) or
       SameText('https://' + TrimmedHost, TrimmedOrigin) then
    begin
      Result := True;
      Exit;
    end;

    OriginHost := TrimmedOrigin;
    if Pos('://', OriginHost) > 0 then
      OriginHost := Copy(OriginHost, Pos('://', OriginHost) + 3, MaxInt);
    if Pos('/', OriginHost) > 0 then
      OriginHost := Copy(OriginHost, 1, Pos('/', OriginHost) - 1);
    if (Length(OriginHost) > 0) and (OriginHost[1] = '[') then
    begin
      if Pos(']', OriginHost) > 0 then
        OriginHost := Copy(OriginHost, 1, Pos(']', OriginHost));
    end
    else
    begin
      ColonPos := Pos(':', OriginHost);
      if ColonPos > 0 then
        OriginHost := Copy(OriginHost, 1, ColonPos - 1);
    end;

    HostNoPort := TrimmedHost;
    if (Length(HostNoPort) > 0) and (HostNoPort[1] = '[') then
    begin
      if Pos(']', HostNoPort) > 0 then
        HostNoPort := Copy(HostNoPort, 1, Pos(']', HostNoPort));
    end
    else
    begin
      ColonPos := Pos(':', HostNoPort);
      if ColonPos > 0 then
        HostNoPort := Copy(HostNoPort, 1, ColonPos - 1);
    end;

    if (OriginHost <> '') and (HostNoPort <> '') and
       (SameText(OriginHost, HostNoPort) or SameText(OriginHost, TrimmedHost) or
        (IsLoopbackHostOrIP(OriginHost) and IsLoopbackHostOrIP(HostNoPort))) then
    begin
      Result := True;
      Exit;
    end;
  end;

  if (FAllowedWebSocketOrigins = '') or (FAllowedWebSocketOrigins = '*') then
  begin
    if (FCORSAllowedOrigins <> '*') and (FCORSAllowedOrigins <> '') then
      Result := IsOriginAllowed(AOrigin)
    else
      Result := True;
    Exit;
  end;

  AllowedList := FAllowedWebSocketOrigins.Split([',', ';']);
  for AllowedItem in AllowedList do
  begin
    if SameText(Trim(AllowedItem), TrimmedOrigin) or (Trim(AllowedItem) = '*') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function TCorsAndOriginPolicy.IsWebTransportOriginAllowed(const AOrigin: string; const AHost: string): Boolean;
var
  AllowedList: TArray<string>;
  AllowedItem: string;
  TrimmedOrigin: string;
  TrimmedHost: string;
  OriginHost: string;
  HostNoPort: string;
  ColonPos: Integer;
begin
  Result := False;
  TrimmedOrigin := Trim(AOrigin);
  if TrimmedOrigin = '' then
  begin
    Result := True;
    Exit;
  end;

  if SameText(TrimmedOrigin, 'null') then
    Exit(False);

  TrimmedHost := Trim(AHost);
  if TrimmedHost <> '' then
  begin
    if SameText('http://' + TrimmedHost, TrimmedOrigin) or
       SameText('https://' + TrimmedHost, TrimmedOrigin) then
    begin
      Result := True;
      Exit;
    end;

    OriginHost := TrimmedOrigin;
    if Pos('://', OriginHost) > 0 then
      OriginHost := Copy(OriginHost, Pos('://', OriginHost) + 3, MaxInt);
    if Pos('/', OriginHost) > 0 then
      OriginHost := Copy(OriginHost, 1, Pos('/', OriginHost) - 1);
    if (Length(OriginHost) > 0) and (OriginHost[1] = '[') then
    begin
      if Pos(']', OriginHost) > 0 then
        OriginHost := Copy(OriginHost, 1, Pos(']', OriginHost));
    end
    else
    begin
      ColonPos := Pos(':', OriginHost);
      if ColonPos > 0 then
        OriginHost := Copy(OriginHost, 1, ColonPos - 1);
    end;

    HostNoPort := TrimmedHost;
    if (Length(HostNoPort) > 0) and (HostNoPort[1] = '[') then
    begin
      if Pos(']', HostNoPort) > 0 then
        HostNoPort := Copy(HostNoPort, 1, Pos(']', HostNoPort));
    end
    else
    begin
      ColonPos := Pos(':', HostNoPort);
      if ColonPos > 0 then
        HostNoPort := Copy(HostNoPort, 1, ColonPos - 1);
    end;

    if (OriginHost <> '') and (HostNoPort <> '') and
       (SameText(OriginHost, HostNoPort) or SameText(OriginHost, TrimmedHost) or
        (IsLoopbackHostOrIP(OriginHost) and IsLoopbackHostOrIP(HostNoPort))) then
    begin
      Result := True;
      Exit;
    end;
  end;

  if (FAllowedWebTransportOrigins = '') or (FAllowedWebTransportOrigins = '*') then
  begin
    if (FCORSAllowedOrigins <> '*') and (FCORSAllowedOrigins <> '') then
      Result := IsOriginAllowed(AOrigin)
    else
      Result := True;
    Exit;
  end;

  AllowedList := FAllowedWebTransportOrigins.Split([',', ';']);
  for AllowedItem in AllowedList do
  begin
    if SameText(Trim(AllowedItem), TrimmedOrigin) or (Trim(AllowedItem) = '*') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function TCorsAndOriginPolicy.HandleCORSPreflight(Request: TRequest; Response: TResponse): Boolean;
var
  Origin: string;
  ReqHeaders: string;
  AllowOriginValue: string;
begin
  Result := False;
  if not FEnableCORS then
    Exit;

  if not Assigned(Request) or not Assigned(Response) then
    Exit;

  if Request.RequestInfo.Method <> hmOPTIONS then
    Exit;

  Origin := Request.Headers.GetHeader('Origin');
  if Origin = '' then
    Exit;

  if not IsOriginAllowed(Origin) then
  begin
    Response.SetForbidden('CORS origin not allowed');
    Result := True;
    Exit;
  end;

  if FCORSAllowCredentials or (FCORSAllowedOrigins <> '*') then
    AllowOriginValue := Origin
  else
    AllowOriginValue := '*';

  Response.SetStatus(hsNoContent);
  Response.SetOrUpdateHeader('Access-Control-Allow-Origin', AllowOriginValue);
  Response.SetOrUpdateHeader('Access-Control-Allow-Methods', FCORSAllowedMethods);

  ReqHeaders := Request.Headers.GetHeader('Access-Control-Request-Headers');
  if ReqHeaders <> '' then
    Response.SetOrUpdateHeader('Access-Control-Allow-Headers', ReqHeaders)
  else if FCORSAllowedHeaders <> '' then
    Response.SetOrUpdateHeader('Access-Control-Allow-Headers', FCORSAllowedHeaders);

  if FCORSMaxAge > 0 then
    Response.SetOrUpdateHeader('Access-Control-Max-Age', IntToStr(FCORSMaxAge));

  if FCORSAllowCredentials then
    Response.SetOrUpdateHeader('Access-Control-Allow-Credentials', 'true');

  Response.SetOrUpdateHeader('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
  Response.FinalizeContent;
  Result := True;
end;

procedure TCorsAndOriginPolicy.ApplyCORSHeaders(Request: TRequest; Response: TResponse);
var
  Origin: string;
  AllowOriginValue: string;
  CurrentVary: string;
  i: Integer;
begin
  if not FEnableCORS then
    Exit;

  if not Assigned(Request) or not Assigned(Response) then
    Exit;

  Origin := Request.Headers.GetHeader('Origin');
  if Origin = '' then
    Exit;

  if not IsOriginAllowed(Origin) then
    Exit;

  if FCORSAllowCredentials or (FCORSAllowedOrigins <> '*') then
    AllowOriginValue := Origin
  else
    AllowOriginValue := '*';

  Response.SetOrUpdateHeader('Access-Control-Allow-Origin', AllowOriginValue);

  if FCORSExposeHeaders <> '' then
    Response.SetOrUpdateHeader('Access-Control-Expose-Headers', FCORSExposeHeaders);

  if FCORSAllowCredentials then
    Response.SetOrUpdateHeader('Access-Control-Allow-Credentials', 'true');

  CurrentVary := '';
  for i := 0 to Response.Headers.Count - 1 do
  begin
    if StartsText('Vary:', Response.Headers[i]) then
    begin
      CurrentVary := Trim(Copy(Response.Headers[i], 6, MaxInt));
      Break;
    end;
  end;

  if CurrentVary = '' then
    Response.AddHeader('Vary', 'Origin')
  else if not ContainsText(CurrentVary, 'Origin') then
    Response.SetOrUpdateHeader('Vary', CurrentVary + ', Origin');
end;

end.
