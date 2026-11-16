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
unit GHttpsServerTypes;

interface

uses
  Winapi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  GRequest,
  Http3.Request,
  Http3.Response,
  WebTransport.Types,
  WebTransport.Session,
  MsQuic.Types;

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
  TmTLSMode = (mtlsDisabled, mtlsOptional, mtlsRequired);

  THttp3Request = TQuicHttp3Request;
  THttp3Response = TQuicHttp3Response;

  TWebTransportSessionProc  = reference to procedure(Session: PWTSessionContext);
  TWebTransportStreamProc   = reference to procedure(Session: PWTSessionContext;
                                                     Stream: HQUIC;
                                                     const Data: TBytes);
  TWebTransportDatagramProc = reference to procedure(Session: PWTSessionContext;
                                                     const Data: TBytes);
  TWebTransportClosedProc   = reference to procedure(SessionId: TWTSessionId);

  TWebTransportRouteItem = class
  private
    FPath: string;
    FOnSessionReady: TWebTransportSessionProc;
    FOnStreamData: TWebTransportStreamProc;
    FOnDatagram: TWebTransportDatagramProc;
    FOnSessionClosed: TWebTransportClosedProc;
    FIsEchoDefault: Boolean;
  public
    constructor Create(const APath: string;
                       AOnSessionReady: TWebTransportSessionProc = nil;
                       AOnStreamData: TWebTransportStreamProc = nil;
                       AOnDatagram: TWebTransportDatagramProc = nil;
                       AOnSessionClosed: TWebTransportClosedProc = nil);

    property Path: string read FPath;
    property OnSessionReady: TWebTransportSessionProc read FOnSessionReady;
    property OnStreamData: TWebTransportStreamProc read FOnStreamData;
    property OnDatagram: TWebTransportDatagramProc read FOnDatagram;
    property OnSessionClosed: TWebTransportClosedProc read FOnSessionClosed;
    property IsEchoDefault: Boolean read FIsEchoDefault write FIsEchoDefault;
  end;

  TIPClientInfo = class
  public
    ActiveConnections: Integer;
    RequestCount: Integer;
    WindowStartTick: UInt64;
    FailureCount: Integer;
    BlockedUntilTick: UInt64;
    constructor Create;
  end;

function GetEndpointKey(const AMethod: THttpMethod; const APath: string): string;
function GetPrimaryIPv4Address: string;

implementation

function GetPrimaryIPv4Address: string;
var
  WSAData: TWSAData;
  NeedCleanup: Boolean;
  Sock: TSocket;
  TargetAddr, LocalAddr: sockaddr_in;
  LocalAddrLen: Integer;
  EnvHost: string;
  HostName: array[0..255] of AnsiChar;
  HostEnt: PHostEnt;
begin
  EnvHost := Trim(GetEnvironmentVariable('SERVER_HOST'));
  if EnvHost <> '' then
    Exit(EnvHost);

  Result := '127.0.0.1';
  NeedCleanup := False;
  if WSAStartup(MAKEWORD(2, 2), WSAData) = 0 then
    NeedCleanup := True;

  Sock := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if Sock <> INVALID_SOCKET then
  begin
    FillChar(TargetAddr, SizeOf(TargetAddr), 0);
    TargetAddr.sin_family := AF_INET;
    TargetAddr.sin_port := htons(53);
    TargetAddr.sin_addr.S_addr := inet_addr('1.1.1.1');

    if connect(Sock, TSockAddr(TargetAddr), SizeOf(TargetAddr)) = 0 then
    begin
      LocalAddrLen := SizeOf(LocalAddr);
      FillChar(LocalAddr, SizeOf(LocalAddr), 0);
      if getsockname(Sock, TSockAddr(LocalAddr), LocalAddrLen) = 0 then
      begin
        if LocalAddr.sin_addr.S_addr <> 0 then
          Result := string(inet_ntoa(LocalAddr.sin_addr));
      end;
    end;
    closesocket(Sock);
  end;

  if (Result = '127.0.0.1') or (Result = '0.0.0.0') then
  begin
    if gethostname(HostName, SizeOf(HostName)) = 0 then
    begin
      HostEnt := gethostbyname(HostName);
      if (HostEnt <> nil) and (HostEnt^.h_addr_list <> nil) and (HostEnt^.h_addr_list^ <> nil) then
        Result := string(inet_ntoa(PInAddr(HostEnt^.h_addr_list^)^));
    end;
  end;

  if NeedCleanup then
    WSACleanup;
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

constructor TWebTransportRouteItem.Create(const APath: string;
  AOnSessionReady: TWebTransportSessionProc;
  AOnStreamData: TWebTransportStreamProc;
  AOnDatagram: TWebTransportDatagramProc;
  AOnSessionClosed: TWebTransportClosedProc);
begin
  inherited Create;
  FPath := APath;
  FOnSessionReady := AOnSessionReady;
  FOnStreamData := AOnStreamData;
  FOnDatagram := AOnDatagram;
  FOnSessionClosed := AOnSessionClosed;
end;

constructor TIPClientInfo.Create;
begin
  inherited Create;
  ActiveConnections := 0;
  RequestCount := 0;
  WindowStartTick := GetTickCount64;
  FailureCount := 0;
  BlockedUntilTick := 0;
end;

end.
