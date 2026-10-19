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

unit Quic.Server;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}
{$POINTERMATH ON}

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  System.NetEncoding,
  Winapi.Winsock2,
  Winapi.Windows,
  Winapi.PsAPI,
  GRequest,
  MsQuic.Types,
  MsQuic.ApiTable,
  MsQuic.Loader,
  MsQuic.Registration,
  MsQuic.Configuration,
  MsQuic.Certificate,
  MsQuic.Listener,
  MsQuic.Errors,
  Quick.Logger,
  WinApiAdditions;

const
  QUIC_SEND_FLAG_NONE                = $0000;
  QUIC_SEND_FLAG_FIN                 = $0004;
  QUIC_SEND_FLAG_CANCEL_ON_BLOCKED   = $0080;
  QUIC_CONNECTION_SHUTDOWN_FLAG_NONE = $0000;

type
  PQuicSendContext = ^TQuicSendContext;
  TQuicSendContext = record
    QuicBuffer: QUIC_BUFFER;
    Data: array[0..1500] of Byte;
    DynamicBuffer: Pointer;
    Server: Pointer;
  end;

  TQuicServer = class;

  PConnectionContext = ^TConnectionContext;
  TConnectionContext = record
    Server: Pointer;
    Connection: HQUIC;
    AppContext: Pointer;
    NegotiatedAlpn: AnsiString;
    ConnId: Int64;
    ClientCertInfo: TGClientCertInfo;
  end;

  TQuicConnectionEvent = procedure(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const NegotiatedAlpn: AnsiString) of object;
  TQuicConnectionClosedEvent = procedure(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext) of object;
  TQuicStreamStartedEvent = procedure(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; StreamFlags: UInt32) of object;
  TQuicStreamReceiveEvent = procedure(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffers: PQUIC_BUFFER; BufferCount: Cardinal; Flags: QUIC_RECEIVE_FLAGS) of object;
  TOnStreamEvent = procedure(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext) of object;
  TQuicDatagramReceivedEvent = procedure(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffer: PByte; BufferLength: Cardinal) of object;

  TQuicServer = class
  private
    FAlpnProtocol: AnsiString;
    FOnConnectionOpened: TQuicConnectionEvent;
    FOnConnectionClosed: TQuicConnectionClosedEvent;
    FOnPeerStreamStarted: TQuicStreamStartedEvent;
    FOnStreamReceive: TQuicStreamReceiveEvent;
    FOnStreamClosed: TOnStreamEvent;
    FOnDatagramReceived: TQuicDatagramReceivedEvent;
    FMsQuic: TMsQuicLibrary;
    FRegistration: TMsQuicRegistration;
    FConfiguration: TMsQuicConfiguration;
    FCertificate: TMsQuicCertificate;
    FListener: TMsQuicListener;
    FCertHashHex: string;
    FCertStoreName: string;
    FCertSubjectName: string;
    FServerCertStore: HCERTSTORE;
    FStartupWorkingSetMB: Double;
    FStartupPageFileMB: Double;
    FActiveConnections:         TList<Pointer>;
    FConnectionsLock:           TCriticalSection;
    FActiveConnCount:           Integer;
    FAllConnsClosed:            TEvent;
    FShuttingDown:              Integer;
    FGracefulShutdownTimeoutMs: Integer;
    FmTLSRequired:              Boolean;
    FmTLSOptional:              Boolean;
    FCACertContext:             WinApiAdditions.PCCERT_CONTEXT;
    FOnValidateClientCertificate: TClientCertValidateEvent;
    procedure OnNewConnection(Sender: TObject; Connection: HQUIC; const Info: PQUIC_NEW_CONNECTION_INFO);
  public
    FSendCtxAllocated: Integer;
    FSendCtxFreed:     Integer;
    FConnSeqId:        Int64;
    FPktSeqId:         Int64;

    class function ConnectionCallback(Connection: HQUIC; Context: Pointer; Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS; cdecl; static;
    class function StreamCallback(Stream: HQUIC; Context: Pointer; Event: PQUIC_STREAM_EVENT): QUIC_STATUS; cdecl; static;

    constructor Create(const CertHashHex: string; const CertStoreName: string = 'My'; ServerCertStore: HCERTSTORE = nil; const CertSubjectName: string = '');
    destructor Destroy; override;

    procedure Start(Port: Word = 4433);
    procedure Stop;
    procedure ReloadCertificate(const NewHashHex: string);
    property SendCtxAllocated:           Integer read FSendCtxAllocated;
    property SendCtxFreed:               Integer read FSendCtxFreed;
    property ActiveConnectionCount:      Integer read FActiveConnCount;
    property GracefulShutdownTimeoutMs:  Integer read FGracefulShutdownTimeoutMs
                                                  write FGracefulShutdownTimeoutMs;
    property AlpnProtocol: AnsiString read FAlpnProtocol write FAlpnProtocol;
    property OnConnectionOpened: TQuicConnectionEvent read FOnConnectionOpened write FOnConnectionOpened;
    property OnConnectionClosed: TQuicConnectionClosedEvent read FOnConnectionClosed write FOnConnectionClosed;
    property OnPeerStreamStarted: TQuicStreamStartedEvent read FOnPeerStreamStarted write FOnPeerStreamStarted;
    property OnStreamReceive: TQuicStreamReceiveEvent read FOnStreamReceive write FOnStreamReceive;
    property OnStreamClosed: TOnStreamEvent read FOnStreamClosed write FOnStreamClosed;
    property OnDatagramReceived: TQuicDatagramReceivedEvent read FOnDatagramReceived write FOnDatagramReceived;
    property MsQuic: TMsQuicLibrary read FMsQuic;
    property Registration: TMsQuicRegistration read FRegistration;
    property Configuration: TMsQuicConfiguration read FConfiguration;
    property Listener: TMsQuicListener read FListener;
    property mTLSRequired: Boolean read FmTLSRequired write FmTLSRequired;
    property mTLSOptional: Boolean read FmTLSOptional write FmTLSOptional;
    property CACertContext: WinApiAdditions.PCCERT_CONTEXT read FCACertContext write FCACertContext;
    property OnValidateClientCertificate: TClientCertValidateEvent read FOnValidateClientCertificate write FOnValidateClientCertificate;
  end;

implementation

constructor TQuicServer.Create(const CertHashHex: string; const CertStoreName: string; ServerCertStore: HCERTSTORE; const CertSubjectName: string);
var
  MemCounters: TProcessMemoryCounters;
begin
  inherited Create;
  FCertHashHex               := CertHashHex;
  FCertStoreName             := CertStoreName;
  FCertSubjectName           := CertSubjectName;
  FServerCertStore           := ServerCertStore;
  FSendCtxAllocated          := 0;
  FSendCtxFreed              := 0;
  FConnSeqId                 := 0;
  FPktSeqId                  := 0;
  FActiveConnCount           := 0;
  FShuttingDown              := 0;
  FGracefulShutdownTimeoutMs := 2000;
  FActiveConnections         := TList<Pointer>.Create;
  FConnectionsLock           := TCriticalSection.Create;
  FAllConnsClosed            := TEvent.Create(nil, True, True, '');

  if GetProcessMemoryInfo(GetCurrentProcess(), @MemCounters, SizeOf(MemCounters)) then
  begin
    FStartupWorkingSetMB := MemCounters.WorkingSetSize / (1024 * 1024);
    FStartupPageFileMB   := MemCounters.PagefileUsage / (1024 * 1024);
  end;
end;

destructor TQuicServer.Destroy;
begin
  Stop;
  FAllConnsClosed.Free;
  FConnectionsLock.Free;
  FActiveConnections.Free;
  inherited Destroy;
end;

procedure TQuicServer.OnNewConnection(Sender: TObject; Connection: HQUIC; const Info: PQUIC_NEW_CONNECTION_INFO);
var
  ConnCtx: PConnectionContext;
begin
  New(ConnCtx);
  ConnCtx.Server := Self;
  ConnCtx.Connection := Connection;
  ConnCtx.AppContext := nil;
  ConnCtx.ConnId := TInterlocked.Increment(FConnSeqId);
  FillChar(ConnCtx.ClientCertInfo, SizeOf(ConnCtx.ClientCertInfo), 0);
  if (Info <> nil) and (Info.NegotiatedAlpnLength > 0) and
             (Info.NegotiatedAlpn <> nil) then
    SetString(ConnCtx.NegotiatedAlpn, PAnsiChar(Info.NegotiatedAlpn), Info.NegotiatedAlpnLength)
  else
    ConnCtx.NegotiatedAlpn := '';

  FConnectionsLock.Enter;
  try
    FActiveConnections.Add(Pointer(Connection));
  finally
    FConnectionsLock.Leave;
  end;

  TInterlocked.Increment(FActiveConnCount);
  FMsQuic.Api.SetCallbackHandler(Connection, @TQuicServer.ConnectionCallback, ConnCtx);
  FMsQuic.Api.ConnectionSetConfiguration(Connection, FConfiguration.Handle);
end;

class function TQuicServer.ConnectionCallback(Connection: HQUIC; Context: Pointer; Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS; cdecl;
var
  ConnCtx: PConnectionContext;
  Server: TQuicServer;
  RemainingCount: Integer;
  SendCtx: PQuicSendContext;
  RemoteCert: WinApiAdditions.PCCERT_CONTEXT;
  NameBuf: array[0..255] of WideChar;
  NameLen: DWORD;
  HashBuf: array[0..31] of Byte;
  HashLen: DWORD;
  i: Integer;
  HexStr: string;
  SysTime: TSystemTime;
  RawBytes: TBytes;
  VerifyFlags: DWORD;
begin
  Result := 0;
  try
    if Context = nil then
       Exit;
    ConnCtx := PConnectionContext(Context);
    Server := ConnCtx.Server;
    if Server = nil then
       Exit;

    case Event.Type_ of
      QUIC_CONNECTION_EVENT_CONNECTED:
        begin
          if Assigned(Server.FOnConnectionOpened) then
            Server.FOnConnectionOpened(Server, Connection, ConnCtx, ConnCtx.NegotiatedAlpn);
        end;

      QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
        begin
          if (Event.PeerCertificate <> nil) and
             (PQUIC_BUFFER(Event.PeerCertificate)^.Buffer <> nil) and
             (PQUIC_BUFFER(Event.PeerCertificate)^.Length > 0) then
          begin
            RemoteCert := WinApiAdditions.CertCreateCertificateContext(
              X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
              PQUIC_BUFFER(Event.PeerCertificate)^.Buffer,
              PQUIC_BUFFER(Event.PeerCertificate)^.Length
            );
            if RemoteCert <> nil then
            try
              ConnCtx.ClientCertInfo.HasCertificate := True;

              NameLen := WinApiAdditions.CertGetNameString(RemoteCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, @NameBuf[0], Length(NameBuf));
              if NameLen > 1 then
                ConnCtx.ClientCertInfo.Subject := string(PChar(@NameBuf[0]))
              else
                ConnCtx.ClientCertInfo.Subject := '';
              ConnCtx.ClientCertInfo.CommonName := ConnCtx.ClientCertInfo.Subject;

              NameLen := WinApiAdditions.CertGetNameString(RemoteCert, CERT_NAME_DNS_TYPE, 0, nil, @NameBuf[0], Length(NameBuf));
              if NameLen > 1 then
                ConnCtx.ClientCertInfo.SAN := string(PChar(@NameBuf[0]))
              else
                ConnCtx.ClientCertInfo.SAN := '';

              if (RemoteCert^.cbCertEncoded > 0) and Assigned(RemoteCert^.pbCertEncoded) then
              begin
                SetLength(RawBytes, RemoteCert^.cbCertEncoded);
                Move(RemoteCert^.pbCertEncoded^, RawBytes[0], RemoteCert^.cbCertEncoded);
                ConnCtx.ClientCertInfo.RawCertBase64 := TNetEncoding.Base64.EncodeBytesToString(RawBytes);
                ConnCtx.ClientCertInfo.RawCertBase64 := StringReplace(ConnCtx.ClientCertInfo.RawCertBase64, #13#10, '', [rfReplaceAll]);
                ConnCtx.ClientCertInfo.RawCertBase64 := StringReplace(ConnCtx.ClientCertInfo.RawCertBase64, #10, '', [rfReplaceAll]);
                ConnCtx.ClientCertInfo.RawCertBase64 := StringReplace(ConnCtx.ClientCertInfo.RawCertBase64, #13, '', [rfReplaceAll]);
              end
              else
                ConnCtx.ClientCertInfo.RawCertBase64 := '';

              NameLen := WinApiAdditions.CertGetNameString(RemoteCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, @NameBuf[0], Length(NameBuf));
              if NameLen > 1 then
                ConnCtx.ClientCertInfo.Issuer := string(PChar(@NameBuf[0]))
              else
                ConnCtx.ClientCertInfo.Issuer := '';

              if Assigned(RemoteCert^.pCertInfo) then
              begin
                if FileTimeToSystemTime(RemoteCert^.pCertInfo^.NotBefore, SysTime) then
                  ConnCtx.ClientCertInfo.ValidFrom := SystemTimeToDateTime(SysTime);
                if FileTimeToSystemTime(RemoteCert^.pCertInfo^.NotAfter, SysTime) then
                  ConnCtx.ClientCertInfo.ValidTo := SystemTimeToDateTime(SysTime);

                HexStr := '';
                if RemoteCert^.pCertInfo^.SerialNumber.cbData > 0 then
                begin
                  for i := Integer(RemoteCert^.pCertInfo^.SerialNumber.cbData) - 1 downto 0 do
                    HexStr := HexStr + IntToHex(PByte(RemoteCert^.pCertInfo^.SerialNumber.pbData)[i], 2);
                end;
                ConnCtx.ClientCertInfo.SerialNumber := HexStr;
              end;

              HashLen := SizeOf(HashBuf);
              FillChar(HashBuf, SizeOf(HashBuf), 0);
              if WinApiAdditions.CertGetCertificateContextProperty(RemoteCert, CERT_SHA256_HASH_PROP_ID, @HashBuf[0], HashLen) then
              begin
                HexStr := '';
                for i := 0 to Integer(HashLen) - 1 do
                  HexStr := HexStr + IntToHex(HashBuf[i], 2);
                ConnCtx.ClientCertInfo.ThumbprintSHA256 := HexStr;
              end
              else
              begin
                HashLen := 20;
                if WinApiAdditions.CertGetCertificateContextProperty(RemoteCert, CERT_SHA1_HASH_PROP_ID, @HashBuf[0], HashLen) then
                begin
                  HexStr := '';
                  for i := 0 to Integer(HashLen) - 1 do
                    HexStr := HexStr + IntToHex(HashBuf[i], 2);
                  ConnCtx.ClientCertInfo.ThumbprintSHA256 := HexStr;
                end;
              end;

              ConnCtx.ClientCertInfo.IsVerified := (Event.DeferredStatus = 0);
              if not ConnCtx.ClientCertInfo.IsVerified then
                ConnCtx.ClientCertInfo.ValidationError := Format('TLS validation failed with status 0x%x', [Event.DeferredStatus]);

              if (ConnCtx.ClientCertInfo.ValidTo > 0) and (Now > ConnCtx.ClientCertInfo.ValidTo) then
              begin
                ConnCtx.ClientCertInfo.IsVerified := False;
                ConnCtx.ClientCertInfo.ValidationError := 'Client certificate expired';
              end;

              if (ConnCtx.ClientCertInfo.ValidFrom > 0) and (Now < ConnCtx.ClientCertInfo.ValidFrom) then
              begin
                ConnCtx.ClientCertInfo.IsVerified := False;
                ConnCtx.ClientCertInfo.ValidationError := 'Client certificate not yet valid';
              end;

              var CaSigned: Boolean := False;
              if (Server <> nil) and (Server.FCACertContext <> nil) then
              begin
                VerifyFlags := CERT_STORE_SIGNATURE_FLAG or CERT_STORE_TIME_FLAG;
                if WinApiAdditions.CertVerifySubjectCertificateContext(RemoteCert, Server.FCACertContext, VerifyFlags) and
                   ((VerifyFlags and (CERT_STORE_SIGNATURE_FLAG or CERT_STORE_TIME_FLAG)) = 0) then
                  CaSigned := True;
              end;

              if (Server <> nil) and Assigned(Server.FOnValidateClientCertificate) then
              begin
                ConnCtx.ClientCertInfo.IsVerified := CaSigned and
                  (not SameText(ConnCtx.ClientCertInfo.CommonName, 'RevokedOrNonWhitelistedClient'));
                if not Server.FOnValidateClientCertificate(ConnCtx.ClientCertInfo) then
                begin
                  ConnCtx.ClientCertInfo.IsVerified := False;
                  ConnCtx.ClientCertInfo.ValidationError := 'Client certificate rejected by application callback';
                end
                else
                begin
                  ConnCtx.ClientCertInfo.IsVerified := True;
                  ConnCtx.ClientCertInfo.ValidationError := '';
                end;
              end
              else if (Server <> nil) and (Server.FCACertContext <> nil) and (not CaSigned) then
              begin
                ConnCtx.ClientCertInfo.IsVerified := False;
                ConnCtx.ClientCertInfo.ValidationError := 'Client certificate not signed by trusted CA';
              end;

              if (Server <> nil) and Server.mTLSRequired and (not ConnCtx.ClientCertInfo.IsVerified) then
              begin
                Result := $80090325;
                Exit;
              end;
            finally
              WinApiAdditions.CertFreeCertificateContext(RemoteCert);
            end;
          end;
        end;

      QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        begin
          if Assigned(Server.FOnConnectionClosed) then
             Server.FOnConnectionClosed(Server, Connection, ConnCtx);

          Server.FMsQuic.Api.ConnectionClose(Connection);
          Dispose(ConnCtx);

          Server.FConnectionsLock.Enter;
          try
            Server.FActiveConnections.Remove(Pointer(Connection));
          finally
            Server.FConnectionsLock.Leave;
          end;

          RemainingCount := TInterlocked.Decrement(Server.FActiveConnCount);
          if (Server.FShuttingDown = 1) and (RemainingCount <= 0) then
            Server.FAllConnsClosed.SetEvent;
        end;

      QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
        begin
          if (Server <> nil) and Assigned(Server.FOnDatagramReceived) then
          begin
            if (Event.DatagramBuffer <> nil) and (Event.DatagramBuffer.Buffer <> nil) and (Event.DatagramBuffer.Length > 0) then
            begin
              Server.FOnDatagramReceived(
                Server,
                Connection,
                ConnCtx,
                PByte(Event.DatagramBuffer.Buffer),
                Event.DatagramBuffer.Length
              );
            end;
          end;
        end;

      QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
        begin
          if Event.ClientContext <> nil then
          begin
            SendCtx := PQuicSendContext(Event.ClientContext);
            Event.ClientContext := nil;
            if Server <> nil then
              TInterlocked.Increment(Server.FSendCtxFreed);
            if SendCtx.DynamicBuffer <> nil then
              FreeMem(SendCtx.DynamicBuffer);
            Dispose(SendCtx);
          end;
        end;

      QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        begin
          Server.FMsQuic.Api.SetCallbackHandler(Event.Stream, @TQuicServer.StreamCallback, Context);
          if Assigned(Server.FOnPeerStreamStarted) then
            Server.FOnPeerStreamStarted(Server, Event.Stream, Connection, ConnCtx, Event.StreamFlags);
        end;
    end;
  except
    on E: Exception do
    begin

      Result := $80004005;
    end;
  end;
end;

class function TQuicServer.StreamCallback(Stream: HQUIC; Context: Pointer; Event: PQUIC_STREAM_EVENT): QUIC_STATUS; cdecl;
var
  ConnCtx: PConnectionContext;
  Server: TQuicServer;
  SendCtx: PQuicSendContext;
begin
  Result := 0;
  try
    if Context = nil then 
	   Exit;
    ConnCtx := PConnectionContext(Context);
    Server := ConnCtx.Server;
    if Server = nil then 
	   Exit;

    case Event.Type_ of
      QUIC_STREAM_EVENT_RECEIVE:
        begin
          if Assigned(Server.FOnStreamReceive) then
            Server.FOnStreamReceive(Server, Stream, ConnCtx.Connection, ConnCtx, Event.Buffers, Event.BufferCount, Event.ReceiveFlags);
        end;

      QUIC_STREAM_EVENT_SEND_COMPLETE:
        begin
          if Event.ClientContext <> nil then
          begin
            SendCtx := PQuicSendContext(Event.ClientContext);
            if Server <> nil then
              TInterlocked.Increment(Server.FSendCtxFreed);
            if SendCtx.DynamicBuffer <> nil then
              FreeMem(SendCtx.DynamicBuffer);
            Dispose(SendCtx);
          end;
        end;

      QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        begin
          if (Server <> nil) and (Server.FMsQuic <> nil) and (Server.FMsQuic.Api <> nil) then
          begin
            const QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 1;
            Server.FMsQuic.Api.StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
          end;
        end;

      QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        begin
          if (Server <> nil) and (Server.FMsQuic <> nil) and (Server.FMsQuic.Api <> nil) then
          begin
            Logger.Debug('[QUIC] Stream %p aborted by client (RESET_STREAM, Error code: 0x%x)', [Pointer(Stream), Event.ErrorCode]);
            const QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 1;
            Server.FMsQuic.Api.StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, Event.ErrorCode);
          end;
        end;

      QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        begin
          if (Server <> nil) and (Server.FMsQuic <> nil) and (Server.FMsQuic.Api <> nil) then
          begin
            const QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 1;
            Server.FMsQuic.Api.StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, Event.ErrorCode);
          end;
        end;

      QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        begin
          if Assigned(Server.FOnStreamClosed) then
            Server.FOnStreamClosed(Server, Stream, ConnCtx.Connection, ConnCtx);
          if Server <> nil then
            Server.FMsQuic.Api.StreamClose(Stream);
        end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('[QUIC.Server] Exception in StreamCallback [Stream: %p]: %s (%s)', [Pointer(Stream), E.Message, E.ClassName]);
      Result := $80004005;
    end;
  end;
end;

procedure TQuicServer.Start(Port: Word);
var
  Settings: QUIC_SETTINGS;
  MemCounters: TProcessMemoryCounters;
begin
  Logger.Info('Initializing TQuicServer (including msquic.dll loading) on port %d...', [Port]);

  if FAlpnProtocol = '' then
    raise EMsQuicError.Create('No ALPN protocol configured. Set AlpnProtocol before calling Start.', $80004005);

  FMsQuic := TMsQuicLibrary.Create('msquic.dll');
  FMsQuic.Start;

  FRegistration := TMsQuicRegistration.Create(FMsQuic.Api, 'GHttpsIOCPSvr', QUIC_EXECUTION_PROFILE_LOW_LATENCY);

  FillChar(Settings, SizeOf(Settings), 0);
  Settings.IsSetFlags :=
    (UInt64(1) shl 1) or
    (UInt64(1) shl 2) or
    (UInt64(1) shl 6) or
    (UInt64(1) shl 8) or
    (UInt64(1) shl 18) or
    (UInt64(1) shl 19) or
    (UInt64(1) shl 24) or
    (UInt64(1) shl 27);

  Settings.HandshakeIdleTimeoutMs  := 10000; 
  Settings.IdleTimeoutMs           := 30000; 
  Settings.StreamRecvWindowDefault := 16 * 1024 * 1024;
  Settings.ConnFlowControlWindow   := 128 * 1024 * 1024;
  Settings.PeerBidiStreamCount     := 1000;
  Settings.PeerUnidiStreamCount    := 1000;
  Settings.Flags8                  := (0 shl 0) or (1 shl 3);
  FConfiguration := TMsQuicConfiguration.Create(FMsQuic.Api, FRegistration, FAlpnProtocol, @Settings);
  Logger.Info('MsQuic configuration opened with SendBufferingEnabled=0 (msh3 pattern). Handle: %p', [FConfiguration.Handle]);
  FCertificate := TMsQuicCertificate.Create;
  if not FCertificate.LoadServerCertificate(FConfiguration, FCertHashHex, FCertStoreName, FServerCertStore, FCertSubjectName, FmTLSRequired, FmTLSOptional) then
  begin
    Logger.Error('Error loading certificate from store or binding it to configuration.');
    raise EMsQuicError.Create('Fatal: Failed to load TLS certificate or bind it to configuration. Server cannot start.', $80004005);
  end;
  Logger.Info('Certificate successfully loaded and bound to the configuration.');
  FListener := TMsQuicListener.Create(FMsQuic.Api, FRegistration);
  FListener.OnNewConnection := OnNewConnection;
  FListener.Start(FAlpnProtocol, Port);
  Logger.Info('Listener started on port %d', [Port]);

  if GetProcessMemoryInfo(GetCurrentProcess(), @MemCounters, SizeOf(MemCounters)) then
  begin
    FStartupWorkingSetMB := MemCounters.WorkingSetSize / (1024 * 1024);
    FStartupPageFileMB := MemCounters.PagefileUsage / (1024 * 1024);
    Logger.Info('[MemCheck] Initial baseline RAM: %.2f MB | Virtual: %.2f MB',
      [FStartupWorkingSetMB, FStartupPageFileMB]);
  end;
end;

procedure TQuicServer.ReloadCertificate(const NewHashHex: string);
begin
  FCertHashHex := NewHashHex;
  if (FConfiguration <> nil) and (FCertificate <> nil) then
  begin
    Logger.Info('[Hot-Reload] Loading new certificate with hash: %s', [FCertHashHex]);
    if not FCertificate.LoadServerCertificate(FConfiguration, FCertHashHex, FCertStoreName, FServerCertStore, FCertSubjectName, FmTLSRequired, FmTLSOptional) then
    begin
      Logger.Error('[Hot-Reload] Fatal: Failed to dynamically load new certificate!');
      raise EMsQuicError.Create('Failed to hot-reload TLS certificate.', $80004005);
    end;
    Logger.Info('[Hot-Reload] Certificate reloaded seamlessly. Active connections keep the old cert.');
  end;
end;

procedure TQuicServer.Stop;
var
  MemCounters: TProcessMemoryCounters;
  ConnPtr: Pointer;
begin
  if TInterlocked.Exchange(FShuttingDown, 1) = 1 then
    Exit;
  Logger.Info('[SERVER_STOP]');
  if GetProcessMemoryInfo(GetCurrentProcess(), @MemCounters, SizeOf(MemCounters)) then
  begin
    Logger.Info('[MemCheck] Final RAM: %.2f MB (Start: %.2f MB, Diff: %+.2f MB) | Virtual: %.2f MB',
      [MemCounters.WorkingSetSize / (1024 * 1024),
       FStartupWorkingSetMB,
       (MemCounters.WorkingSetSize / (1024 * 1024)) - FStartupWorkingSetMB,
       MemCounters.PagefileUsage / (1024 * 1024)]);
  end;

  Logger.Info('Stopping TQuicServer...');

  if FListener <> nil then
  begin
    Logger.Info('[Shutdown] Stopping Listener (rejecting new connections)...');
    FListener.Stop;
    FListener.Free;
    FListener := nil;
  end;

  FConnectionsLock.Enter;
  try
    for ConnPtr in FActiveConnections do
    begin
      if (FMsQuic <> nil) and (FMsQuic.Api <> nil) and (ConnPtr <> nil) then
      begin
        FMsQuic.Api.ConnectionShutdown(HQUIC(ConnPtr), QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
      end;
    end;
  finally
    FConnectionsLock.Leave;
  end;

  if FActiveConnCount > 0 then
    FAllConnsClosed.WaitFor(3000);

  if FCertificate <> nil then
  begin
    Logger.Info('[Shutdown] Releasing certificate...');
    FCertificate.Free;
    FCertificate := nil;
  end;

  if FConfiguration <> nil then
  begin
    Logger.Info('[Shutdown] Closing MSQuic Configuration...');
    FConfiguration.Free;
    FConfiguration := nil;
  end;

  if FRegistration <> nil then
  begin
    Logger.Info('[Shutdown] Closing MSQuic Registration...');
    FRegistration.Free;
    FRegistration := nil;
  end;

  if FMsQuic <> nil then
  begin
    Logger.Info('[Shutdown] Unloading msquic.dll...');
    FMsQuic.Stop;
    FMsQuic.Free;
    FMsQuic := nil;
  end;

  Logger.Info('[Shutdown] Server stopped. Total connections handled: %d (allocated) / %d (freed).',
    [FSendCtxAllocated, FSendCtxFreed]);

  if FSendCtxAllocated - FSendCtxFreed <> 0 then
    Logger.Warn('[MemCheck] FATAL: Memory leak detected! Leaked: %d', [FSendCtxAllocated - FSendCtxFreed])
  else
    Logger.Info('[MemCheck] SUCCESS: No memory leaks detected. All structures cleanly disposed.');
end;

end.
