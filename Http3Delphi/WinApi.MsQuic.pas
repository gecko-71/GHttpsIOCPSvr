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
unit WinApi.MsQuic;


interface

uses
  Winapi.Windows, Winapi.Winsock2, System.SysUtils;

const
  MSQUIC_DLL = 'msquic.dll';

  // MsQuic API Versions
  QUIC_API_VERSION_1 = 1;
  QUIC_API_VERSION_2 = 2;
  
  // Status Codes (HRESULT / QUIC_STATUS)
  QUIC_STATUS_SUCCESS = $00000000;
  QUIC_STATUS_PENDING = $703E0000;
  QUIC_STATUS_INVALID_PARAMETER = $80070057;
  QUIC_STATUS_INVALID_STATE = $8000000B;
  QUIC_STATUS_NOT_SUPPORTED = $80004001;
  QUIC_STATUS_BUFFER_TOO_SMALL = $8007007A;
  QUIC_STATUS_HANDSHAKE_FAILURE = $80070490;
  QUIC_STATUS_ADDRESS_IN_USE = $80072740;

  // Execution Profiles
  QUIC_EXECUTION_PROFILE_LOW_LATENCY = 0;
  QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT = 1;
  QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER = 2;
  QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME = 3;

  // Credential Types (TLS)
  QUIC_CREDENTIAL_TYPE_NONE = 0;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH = 1;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE = 2;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT = 3;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE = 4;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED = 5;
  QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12 = 6;

  // Credential Flags (TLS)
  QUIC_CREDENTIAL_FLAG_NONE = $00000000;
  QUIC_CREDENTIAL_FLAG_CLIENT = $00000001;
  QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION = $00000002;
  QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION = $00000004;
  QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION = $00000008;

  // SetParam / GetParam parameters (QUIC_PARAM_LEVEL)
  QUIC_PARAM_LEVEL_GLOBAL = 0;
  QUIC_PARAM_LEVEL_REGISTRATION = 1;
  QUIC_PARAM_LEVEL_CONFIGURATION = 2;
  QUIC_PARAM_LEVEL_LISTENER = 3;
  QUIC_PARAM_LEVEL_CONNECTION = 4;
  QUIC_PARAM_LEVEL_STREAM = 5;
  QUIC_PARAM_STREAM_ID = $08000000; // Fixed constant (stream level is $08000000)

  // Connection / configuration parameter identifiers
  QUIC_PARAM_CONN_SETTINGS = $05000000;
  QUIC_PARAM_CONN_IDLE_TIMEOUT = $05000001;
  QUIC_PARAM_CONN_PEER_ADDRESS = $05000002;
  QUIC_PARAM_CONN_LOCAL_ADDRESS = $05000003;
  QUIC_PARAM_CONN_STATISTICS = $05000004;

  // Stream open and start flags
  QUIC_STREAM_OPEN_FLAG_NONE = $00000000;
  QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL = $00000001;
  QUIC_STREAM_START_FLAG_NONE = $00000000;
  QUIC_STREAM_START_FLAG_IMMEDIATE = $00000001;
  QUIC_STREAM_START_FLAG_FAIL_BLOCKED = $00000002;

  // Data send flags
  QUIC_SEND_FLAG_NONE = $00000000;
  QUIC_SEND_FLAG_ALLOW_0_RTT = $00000001;
  QUIC_SEND_FLAG_START = $00000002;
  QUIC_SEND_FLAG_FIN = $00000004;

  // Data receive flags
  QUIC_RECEIVE_FLAG_NONE = $00000000;
  QUIC_RECEIVE_FLAG_0_RTT = $00000001;
  QUIC_RECEIVE_FLAG_FIN = $00000002;

  // Stream shutdown flags
  QUIC_STREAM_SHUTDOWN_FLAG_NONE = $00000000;
  QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL = $00000001;
  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND = $00000002;
  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE = $00000004;
  QUIC_STREAM_SHUTDOWN_FLAG_ABORT = QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND or QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE;

  // Connection Events
  QUIC_CONNECTION_EVENT_CONNECTED = 0;
  QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = 1;
  QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 2;
  QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = 3;
  QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = 4;
  QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = 5;
  QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 6;
  QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = 7;
  QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = 8;
  QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED = 9;
  QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = 10;

  // Listener Events
  QUIC_LISTENER_EVENT_NEW_CONNECTION = 0;
  QUIC_LISTENER_EVENT_STOP_COMPLETE = 1;

  // Stream Events
  QUIC_STREAM_EVENT_START_COMPLETE = 0;
  QUIC_STREAM_EVENT_RECEIVE = 1;
  QUIC_STREAM_EVENT_SEND_COMPLETE = 2;
  QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN = 3;
  QUIC_STREAM_EVENT_PEER_SEND_ABORTED = 4;
  QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED = 5;
  QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE = 6;
  QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE = 7;

type
  QUIC_STATUS = ULONG;
  HQUIC = Pointer;
  
  PQUIC_ADDR = ^TSockAddrIn;

  // Registration Configuration
  QUIC_REGISTRATION_CONFIG = record
    AppName: PAnsiChar;
    ExecutionProfile: ULONG;
  end;
  PQUIC_REGISTRATION_CONFIG = ^QUIC_REGISTRATION_CONFIG;

  // MsQuic Data Buffer
  QUIC_BUFFER = record
    Length: ULONG;
    Buffer: PByte;
  end;
  PQUIC_BUFFER = ^QUIC_BUFFER;

  // Connection settings structure for MSQuic v1
  QUIC_SETTINGS_V1 = record
    IsSetFlags: UInt64;
    MaxBytesPerKey: UInt64;
    HandshakeIdleTimeoutMs: UInt64;
    IdleTimeoutMs: UInt64;
    TlsClientMaxSendBuffer: ULONG;
    TlsServerMaxSendBuffer: ULONG;
    StreamRecvWindowDefault: ULONG;
    StreamRecvBufferDefault: ULONG;
    ConnFlowControlWindow: ULONG;
    MaxWorkerQueueDelayUs: ULONG;
    MaxStatelessOperations: ULONG;
    InitialWindowPackets: ULONG;
    SendIdleTimeoutMs: ULONG;
    InitialRttMs: ULONG;
    MaxAckDelayMs: ULONG;
    DisconnectTimeoutMs: ULONG;
    KeepAliveIntervalMs: ULONG;
    PeerBidiStreamCount: Word;
    PeerUnidiStreamCount: Word;
    RetryMemoryLimit: Word;
    LoadBalancingMode: Word;
    MaxOperationsPerDrain: Byte;
    Flags: Byte; // SendBufferingEnabled, PacingEnabled, MigrationEnabled, DatagramReceiveEnabled
    ServerResumptionLevel: Byte;
    VersionNegotiationExtEnabled_Reserved: Byte;
    DesiredVersionsList: Pointer;
    DesiredVersionsListLength: ULONG;
    MinimumMtu: Word;
    MaximumMtu: Word;
    MtuDiscoverySearchCompleteTimeoutUs: UInt64;
    MtuDiscoveryMissingProbeCount: Byte;
    Pad: array[0..2] of Byte; // Alignment to 4 bytes before uint16
    MaxBindingStatelessOperations: Word;
    StatelessOperationExpirationMs: Word;
    CongestionControlAlgorithm: Word; // QUIC_CONGESTION_CONTROL_ALGORITHM
    Pad2: Word; // Alignment to 8 bytes
  end;

  // Connection settings structure for MSQuic v2
  QUIC_SETTINGS_V2 = record
    IsSetFlags: UInt64;
    MaxBytesPerKey: UInt64;
    HandshakeIdleTimeoutMs: UInt64;
    IdleTimeoutMs: UInt64;
    MtuDiscoverySearchCompleteTimeoutUs: UInt64;
    TlsClientMaxSendBuffer: ULONG;
    TlsServerMaxSendBuffer: ULONG;
    StreamRecvWindowDefault: ULONG;
    StreamRecvBufferDefault: ULONG;
    ConnFlowControlWindow: ULONG;
    MaxWorkerQueueDelayUs: ULONG;
    MaxStatelessOperations: ULONG;
    InitialWindowPackets: ULONG;
    SendIdleTimeoutMs: ULONG;
    InitialRttMs: ULONG;
    MaxAckDelayMs: ULONG;
    DisconnectTimeoutMs: ULONG;
    KeepAliveIntervalMs: ULONG;
    CongestionControlAlgorithm: Word;
    PeerBidiStreamCount: Word;
    PeerUnidiStreamCount: Word;
    MaxBindingStatelessOperations: Word;
    StatelessOperationExpirationMs: Word;
    MinimumMtu: Word;
    MaximumMtu: Word;
    Flags: Byte;
    ServerResumptionLevel: Byte;
    MaxOperationsPerDrain: Byte;
    MtuDiscoveryMissingProbeCount: Byte;
    DestCidUpdateIdleTimeoutMs: ULONG;
    Flags2: UInt64;
    StreamRecvWindowBidiLocalDefault: ULONG;
    StreamRecvWindowBidiRemoteDefault: ULONG;
    StreamRecvWindowUnidiDefault: ULONG;
  end;
  PQUIC_SETTINGS_V2 = ^QUIC_SETTINGS_V2;
  PQUIC_SETTINGS = Pointer;

  // TLS credential configuration (QUIC_CREDENTIAL_CONFIG - 56 bytes in x64 C++)
  QUIC_CREDENTIAL_CONFIG = record
    Type_: ULONG;
    Flags: ULONG;
    CertificateContext: Pointer;
    Principal: PAnsiChar;
    Reserved: Pointer;
    AsyncHandler: Pointer;
    AllowedCipherSuites: DWORD;
    Reserved2: DWORD;
    CaCertificateFile: PAnsiChar;
  end;
  PQUIC_CREDENTIAL_CONFIG = ^QUIC_CREDENTIAL_CONFIG;

  // Event structures
  QUIC_LISTENER_EVENT = record
    EventId: ULONG;
    case Integer of
      0: (
        NewConnection: record
          Info: Pointer;
          Connection: HQUIC;
        end;
      );
      1: (
        StopComplete: record
          AppCloseInProgress: Byte;
        end;
      );
  end;
  PQUIC_LISTENER_EVENT = ^QUIC_LISTENER_EVENT;

  QUIC_CONNECTION_EVENT = record
    EventId: ULONG;
    case Integer of
      0: ( Connected: record SessionResumed: Byte; NegotiatedAlpnLength: Byte; NegotiatedAlpn: PAnsiChar; end; );
      1: ( ShutdownInitiatedByTransport: record Status: QUIC_STATUS; ErrorCode: UInt64; end; );
      2: ( ShutdownInitiatedByPeer: record ErrorCode: UInt64; end; );
      3: ( ShutdownComplete: record HandshakeCompleted: Byte; PeerAcknowledged: Byte; AppCloseInProgress: Byte; end; );
      4: ( LocalAddressChanged: record Address: Pointer; end; );
      5: ( PeerAddressChanged: record Address: Pointer; end; );
      6: ( PeerStreamStarted: record Stream: HQUIC; Flags: ULONG; end; );
      7: ( StreamsAvailable: record BidirectionalCount: Word; UnidirectionalCount: Word; end; );
      8: ( PeerNeedsStreams: record Bidirectional: Byte; end; );
      9: ( DatagramReceived: record Buffer: PQUIC_BUFFER; Flags: ULONG; end; );
  end;
  PQUIC_CONNECTION_EVENT = ^QUIC_CONNECTION_EVENT;

  QUIC_STREAM_EVENT = record
    EventId: ULONG;
    case Integer of
      0: ( StartComplete: record Status: QUIC_STATUS; ID: UInt64; end; );
      1: ( Receive: record AbsoluteOffset: UInt64; TotalBufferLength: UInt64; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG; end; );
      2: ( SendComplete: record Canceled: Byte; ClientContext: Pointer; end; );
      3: ( PeerSendShutdown: record IsGraceful: Byte; end; );
      4: ( PeerSendAborted: record ErrorCode: UInt64; end; );
      5: ( PeerReceiveAborted: record ErrorCode: UInt64; end; );
      6: ( SendShutdownComplete: record Graceful: Byte; end; );
      7: ( ShutdownComplete: record ConnectionShutdown: Byte; AppCloseInProgress: Byte; ConnectionErrorCode: UInt64; ConnectionClosedRemotely: Byte; end; );
  end;
  PQUIC_STREAM_EVENT = ^QUIC_STREAM_EVENT;

  // Callback definitions
  QUIC_LISTENER_CALLBACK = function(Listener: HQUIC; Context: Pointer; Event: PQUIC_LISTENER_EVENT): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_CALLBACK = function(Connection: HQUIC; Context: Pointer; Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS; cdecl;
  QUIC_STREAM_CALLBACK = function(Stream: HQUIC; Context: Pointer; Event: PQUIC_STREAM_EVENT): QUIC_STATUS; cdecl;

  // Complete MsQuic API function table
  QUIC_API_TABLE = record
    SetContext: procedure(Handle: HQUIC; Context: Pointer); cdecl;
    GetContext: function(Handle: HQUIC): Pointer; cdecl;
    SetCallbackHandler: procedure(Handle: HQUIC; Handler: Pointer; Context: Pointer); cdecl;
    SetParam: function(Handle: HQUIC; Param: ULONG; BufferLength: ULONG; Buffer: Pointer): QUIC_STATUS; cdecl;
    GetParam: function(Handle: HQUIC; Param: ULONG; var BufferLength: ULONG; Buffer: Pointer): QUIC_STATUS; cdecl;
    
    RegistrationOpen: function(const Config: PQUIC_REGISTRATION_CONFIG; out Registration: HQUIC): QUIC_STATUS; cdecl;
    RegistrationClose: procedure(Registration: HQUIC); cdecl;
    RegistrationShutdown: procedure(Registration: HQUIC; Flags: ULONG; ErrorCode: UInt64); cdecl;

    ConfigurationOpen: function(Registration: HQUIC; const AlpnBuffers: PQUIC_BUFFER; AlpnBufferCount: ULONG; const Settings: PQUIC_SETTINGS; SettingsSize: ULONG; Context: Pointer; out Configuration: HQUIC): QUIC_STATUS; cdecl;
    ConfigurationClose: procedure(Configuration: HQUIC); cdecl;
    ConfigurationLoadCredential: function(Configuration: HQUIC; const CredConfig: PQUIC_CREDENTIAL_CONFIG): QUIC_STATUS; cdecl;

    ListenerOpen: function(Registration: HQUIC; Handler: QUIC_LISTENER_CALLBACK; Context: Pointer; out Listener: HQUIC): QUIC_STATUS; cdecl;
    ListenerClose: procedure(Listener: HQUIC); cdecl;
    ListenerStart: function(Listener: HQUIC; const AlpnBuffers: PQUIC_BUFFER; AlpnBufferCount: ULONG; const LocalAddress: PQUIC_ADDR): QUIC_STATUS; cdecl;
    ListenerStop: procedure(Listener: HQUIC); cdecl;

    ConnectionOpen: function(Registration: HQUIC; Handler: QUIC_CONNECTION_CALLBACK; Context: Pointer; out Connection: HQUIC): QUIC_STATUS; cdecl;
    ConnectionClose: procedure(Connection: HQUIC); cdecl;
    ConnectionShutdown: procedure(Connection: HQUIC; Flags: ULONG; ErrorCode: UInt64); cdecl;
    ConnectionStart: function(Connection: HQUIC; Configuration: HQUIC; Family: Word; ServerName: PAnsiChar; ServerPort: Word): QUIC_STATUS; cdecl;
    ConnectionSetConfiguration: function(Connection: HQUIC; Configuration: HQUIC): QUIC_STATUS; cdecl;
    ConnectionSendResumptionTicket: function(Connection: HQUIC; Flags: ULONG; DataLength: ULONG; Data: PByte): QUIC_STATUS; cdecl;
    
    StreamOpen: function(Connection: HQUIC; Flags: ULONG; Handler: QUIC_STREAM_CALLBACK; Context: Pointer; out Stream: HQUIC): QUIC_STATUS; cdecl;
    StreamClose: procedure(Stream: HQUIC); cdecl;
    StreamStart: function(Stream: HQUIC; Flags: ULONG): QUIC_STATUS; cdecl;
    StreamShutdown: function(Stream: HQUIC; Flags: ULONG; ErrorCode: UInt64): QUIC_STATUS; cdecl;
    StreamSend: function(Stream: HQUIC; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG; ClientSendContext: Pointer): QUIC_STATUS; cdecl;
    StreamReceiveComplete: procedure(Stream: HQUIC; BufferLength: UInt64); cdecl;
    StreamReceiveSetEnabled: function(Stream: HQUIC; IsEnabled: Byte): QUIC_STATUS; cdecl;
    
    DatagramSend: function(Connection: HQUIC; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG; ClientSendContext: Pointer): QUIC_STATUS; cdecl;
  end;
  PQUIC_API_TABLE = ^QUIC_API_TABLE;

type
  TMsQuicOpenVersionFunc = function(Version: Cardinal; out QuicApi: PQUIC_API_TABLE): QUIC_STATUS; cdecl;
  TMsQuicCloseFunc = procedure(QuicApi: PQUIC_API_TABLE); cdecl;

function MsQuicOpenVersion(Version: Cardinal; out QuicApi: PQUIC_API_TABLE): QUIC_STATUS;
procedure MsQuicClose(QuicApi: PQUIC_API_TABLE);

implementation

var
  FLibHandle: HMODULE = 0;
  FMsQuicOpenVersion: TMsQuicOpenVersionFunc = nil;
  FMsQuicClose: TMsQuicCloseFunc = nil;

function LoadMsQuicDll: Boolean;
var
  ExeDir, FullDllPath: string;
  OldErrorMode: UINT;
begin
  if FLibHandle <> 0 then Exit(True);
  ExeDir := ExtractFilePath(ParamStr(0));
  FullDllPath := ExeDir + MSQUIC_DLL;
  if not FileExists(FullDllPath) then
    Exit(False);

  OldErrorMode := SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
  try
    FLibHandle := LoadLibrary(PChar(FullDllPath));
    if FLibHandle <> 0 then
    begin
      @FMsQuicOpenVersion := GetProcAddress(FLibHandle, 'MsQuicOpenVersion');
      @FMsQuicClose := GetProcAddress(FLibHandle, 'MsQuicClose');
    end;
    Result := (FLibHandle <> 0) and Assigned(FMsQuicOpenVersion) and Assigned(FMsQuicClose);
  finally
    SetErrorMode(OldErrorMode);
  end;
end;

function MsQuicOpenVersion(Version: Cardinal; out QuicApi: PQUIC_API_TABLE): QUIC_STATUS;
begin
  if not LoadMsQuicDll then
  begin
    Writeln('  [DEBUG] LoadMsQuicDll failed! GetLastError = ', GetLastError, ': ', SysErrorMessage(GetLastError));
    Exit(QUIC_STATUS($8007007E));
  end;

  Result := FMsQuicOpenVersion(Version, QuicApi);
  if Result <> 0 then
    Writeln(Format('  [DEBUG] FMsQuicOpenVersion returned status 0x%x', [Result]));
end;

procedure MsQuicClose(QuicApi: PQUIC_API_TABLE);
begin
  if Assigned(FMsQuicClose) then
    FMsQuicClose(QuicApi);
end;

initialization

finalization
  if FLibHandle <> 0 then
  begin
    FreeLibrary(FLibHandle);
    FLibHandle := 0;
  end;

end.
