{
  MIT License

  Copyright (c) 2026 GECKO-71

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

unit MsQuic.Listener;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  Winapi.Windows, Winapi.Winsock2, System.SysUtils,
  MsQuic.Types, MsQuic.ApiTable, MsQuic.Errors, MsQuic.Registration, MsQuic.Configuration;

type
  TQuicNewConnectionEvent = procedure(Sender: TObject; Connection: HQUIC; const Info: PQUIC_NEW_CONNECTION_INFO) of object;

  TMsQuicListener = class
  private
    FApi: PQuicApiTable;
    FRegistration: TMsQuicRegistration;
    FHandle: HQUIC;
    FOnNewConnection: TQuicNewConnectionEvent;

    FAlpnStorage: AnsiString;

    class function ListenerCallback(Listener: HQUIC; Context: Pointer; Event: PQUIC_LISTENER_EVENT): QUIC_STATUS; cdecl; static;
  public
    constructor Create(const AApi: PQuicApiTable; ARegistration: TMsQuicRegistration);
    destructor Destroy; override;

    procedure Start(const AlpnProtocol: AnsiString; Port: Word);
    procedure Stop;

    property Handle: HQUIC read FHandle;
    property OnNewConnection: TQuicNewConnectionEvent read FOnNewConnection write FOnNewConnection;
  end;

implementation

uses
  Quick.Logger;

constructor TMsQuicListener.Create(const AApi: PQuicApiTable; ARegistration: TMsQuicRegistration);
var
  Status: QUIC_STATUS;
begin
  inherited Create;
  FApi := AApi;
  FRegistration := ARegistration;
  FHandle := nil;

  if (FApi = nil) or (FRegistration = nil) then
    raise EMsQuicError.Create('Invalid MsQuic API table or Registration', $C000000D);

  Status := FApi.ListenerOpen(FRegistration.Handle, @TMsQuicListener.ListenerCallback, Self, FHandle);
  if QuicFailed(Status) then
    raise EMsQuicError.Create('Failed to open MsQuic Listener', Status);
end;

destructor TMsQuicListener.Destroy;
begin
  Stop;
  if (FHandle <> nil) and (FApi <> nil) then
  begin
    FApi.ListenerClose(FHandle);
    FHandle := nil;
  end;
  inherited Destroy;
end;

procedure TMsQuicListener.Start(const AlpnProtocol: AnsiString; Port: Word);
var
  AlpnBuffer: QUIC_BUFFER;
  Status: QUIC_STATUS;
  LocalAddr: TSOCKADDR_INET;
begin
  if (FApi = nil) or (FHandle = nil) then 
     Exit;

  if AlpnProtocol = '' then
    raise EMsQuicError.Create('ALPN protocol must be specified for Listener', $C000000D);

  FAlpnStorage := AlpnProtocol;
  AlpnBuffer.Length := Length(FAlpnStorage);
  AlpnBuffer.Buffer := PByte(PAnsiChar(FAlpnStorage));

  FillChar(LocalAddr, SizeOf(LocalAddr), 0);
  LocalAddr.si_family := AF_UNSPEC;
  LocalAddr.Ipv4.sin_port := htons(Port);

  Status := FApi.ListenerStart(FHandle, @AlpnBuffer, 1, @LocalAddr);
  if QuicFailed(Status) then
    raise EMsQuicError.Create('Failed to start MsQuic Listener', Status);
end;

procedure TMsQuicListener.Stop;
begin
  if (FApi <> nil) and (FHandle <> nil) then
     FApi.ListenerStop(FHandle);  
end;

class function TMsQuicListener.ListenerCallback(Listener: HQUIC; Context: Pointer; Event: PQUIC_LISTENER_EVENT): QUIC_STATUS; cdecl;
var
  SelfObj: TMsQuicListener;
begin
  Result := 0;
  SelfObj := TMsQuicListener(Context);
  if SelfObj = nil then 
     Exit;

  case Event.Type_ of
    QUIC_LISTENER_EVENT_NEW_CONNECTION:
      begin
        if Assigned(SelfObj.FOnNewConnection) then
        begin
          try
            SelfObj.FOnNewConnection(SelfObj, Event.Connection, Event.Info);
          except
            on E: Exception do
            begin
              Logger.Error('[MsQuic.Listener] Exception during accepting new QUIC connection: %s (%s)', [E.Message, E.ClassName]);
              Result := $80004005;
            end;
          end;
        end;
      end;
  end;
end;

end.
