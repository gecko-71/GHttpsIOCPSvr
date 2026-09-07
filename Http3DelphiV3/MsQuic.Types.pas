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

unit MsQuic.Types;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Winapi.Windows, Winapi.Winsock2;

const
  QUIC_API_VERSION_2 = 2;
  QUIC_ALPN_H3: AnsiString = 'h3';

type

  QUIC_STATUS = UInt32;
  PQUIC_STATUS = ^QUIC_STATUS;

  HQUIC = Pointer;
  PHQUIC = ^HQUIC;

  QUIC_UINT62 = UInt64;

  TQuicIn6Addr = record
    case Integer of
      0: (Byte: array[0..15] of Byte);
      1: (Word: array[0..7] of UInt16);
  end;

  TQuicSockAddrIn6 = record
    sin6_family: u_short;
    sin6_port: u_short;
    sin6_flowinfo: UInt32;
    sin6_addr: TQuicIn6Addr;
    sin6_scope_id: UInt32;
  end;

  TSOCKADDR_INET = record
    case Integer of
      0: (Ipv4: TSockAddrIn);
      1: (Ipv6: TQuicSockAddrIn6);
      2: (si_family: u_short);
  end;
  PSOCKADDR_INET = ^TSOCKADDR_INET;

  QUIC_ADDR = TSOCKADDR_INET;
  PQUIC_ADDR = ^QUIC_ADDR;

  QUIC_CREDENTIAL_TYPE = (
    QUIC_CREDENTIAL_TYPE_NONE = 0,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH = 1,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE = 2,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT = 3,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE = 4,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED = 5,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12 = 6,
    QUIC_CREDENTIAL_TYPE_SYMMETRIC = 7
  );

  QUIC_CREDENTIAL_FLAGS = UInt32;
const
  QUIC_CREDENTIAL_FLAG_NONE                         = $00000000;
  QUIC_CREDENTIAL_FLAG_CLIENT                       = $00000001;
  QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION= $00000002;
  QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION = $00000004;
  QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION    = $00000008;
  QUIC_CREDENTIAL_FLAG_ENABLE_OCSP                  = $00000010;
  QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED= $00000020;
  QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES    = $00000080;

type
  QUIC_CERTIFICATE_PKCS12 = record
    Asn1Blob: PByte;
    Asn1BlobLength: UInt32;
    PrivateKeyPassword: PAnsiChar;
  end;
  PQUIC_CERTIFICATE_PKCS12 = ^QUIC_CERTIFICATE_PKCS12;

  QUIC_EXECUTION_PROFILE = UInt32;
const
  QUIC_EXECUTION_PROFILE_LOW_LATENCY = 0;
  QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT = 1;
  QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER = 2;
  QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME = 3;

type
  QUIC_REGISTRATION_CONFIG = record
    AppName: PAnsiChar;
    ExecutionProfile: QUIC_EXECUTION_PROFILE;
  end;
  PQUIC_REGISTRATION_CONFIG = ^QUIC_REGISTRATION_CONFIG;

  QUIC_BUFFER = record
    Length: UInt32;
    Buffer: PByte;
  end;
  PQUIC_BUFFER = ^QUIC_BUFFER;

  QUIC_SETTINGS = record
    IsSetFlags: UInt64;
    MaxBytesPerKey: UInt64;
    HandshakeIdleTimeoutMs: UInt64;
    IdleTimeoutMs: UInt64;
    MtuDiscoverySearchCompleteTimeoutUs: UInt64;
    TlsClientMaxSendBuffer: UInt32;
    TlsServerMaxSendBuffer: UInt32;
    StreamRecvWindowDefault: UInt32;
    StreamRecvBufferDefault: UInt32;
    ConnFlowControlWindow: UInt32;
    MaxWorkerQueueDelayUs: UInt32;
    MaxStatelessOperations: UInt32;
    InitialWindowPackets: UInt32;
    SendIdleTimeoutMs: UInt32;
    InitialRttMs: UInt32;
    MaxAckDelayMs: UInt32;
    DisconnectTimeoutMs: UInt32;
    KeepAliveIntervalMs: UInt32;
    CongestionControlAlgorithm: UInt16;
    PeerBidiStreamCount: UInt16;
    PeerUnidiStreamCount: UInt16;
    MaxBindingStatelessOperations: UInt16;
    StatelessOperationExpirationMs: UInt16;
    MinimumMtu: UInt16;
    MaximumMtu: UInt16;
    Flags8: Byte;

    Padding: array[0..32] of Byte;
  end;
  PQUIC_SETTINGS = ^QUIC_SETTINGS;

  QUIC_CREDENTIAL_CONFIG = record
    Type_: QUIC_CREDENTIAL_TYPE;
    Flags: QUIC_CREDENTIAL_FLAGS;
    Certificate: Pointer;
    Principal: PAnsiChar;
    Reserved: Pointer;
    AsyncHandler: Pointer;
  end;
  PQUIC_CREDENTIAL_CONFIG = ^QUIC_CREDENTIAL_CONFIG;

  QUIC_NEW_CONNECTION_INFO = record
    QuicVersion: UInt32;
    LocalAddress: PQUIC_ADDR;
    RemoteAddress: PQUIC_ADDR;
    CryptoBufferLength: UInt32;
    ClientAlpnListLength: UInt16;
    ServerNameLength: UInt16;
    NegotiatedAlpnLength: Byte;
    CryptoBuffer: PByte;
    ClientAlpnList: PByte;
    NegotiatedAlpn: PByte;
    ServerName: PAnsiChar;
  end;
  PQUIC_NEW_CONNECTION_INFO = ^QUIC_NEW_CONNECTION_INFO;

  QUIC_LISTENER_EVENT_TYPE = (
    QUIC_LISTENER_EVENT_NEW_CONNECTION = 0,
    QUIC_LISTENER_EVENT_STOP_COMPLETE = 1,
    QUIC_LISTENER_EVENT_DOS_MODE_CHANGED = 2
  );

  QUIC_LISTENER_EVENT = record
    Type_: QUIC_LISTENER_EVENT_TYPE;
    case Integer of
      0: (
        Info: PQUIC_NEW_CONNECTION_INFO;
        Connection: HQUIC;
      );

      1: (
        Flags: Byte;
      );
  end;
  PQUIC_LISTENER_EVENT = ^QUIC_LISTENER_EVENT;

  QUIC_LISTENER_CALLBACK_HANDLER = function(Listener: HQUIC; Context: Pointer; Event: PQUIC_LISTENER_EVENT): QUIC_STATUS; cdecl;

  QUIC_CONNECTION_EVENT_TYPE = (
    QUIC_CONNECTION_EVENT_CONNECTED = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = 1,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 2,
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE = 3,
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = 12,
    QUIC_CONNECTION_EVENT_RESUMED = 13,
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = 14,
    QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED = 15
  );

  QUIC_RECEIVE_FLAGS = UInt32;

const
  QUIC_RECEIVE_FLAG_NONE  = $0000;
  QUIC_RECEIVE_FLAG_0_RTT = $0001;
  QUIC_RECEIVE_FLAG_FIN   = $0002;

type
  QUIC_DATAGRAM_SEND_STATE = (
    QUIC_DATAGRAM_SEND_UNKNOWN = 0,
    QUIC_DATAGRAM_SEND_SENT = 1,
    QUIC_DATAGRAM_SEND_LOST_SUSPECT = 2,
    QUIC_DATAGRAM_SEND_LOST_DISCARDED = 3,
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED = 4,
    QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS = 5,
    QUIC_DATAGRAM_SEND_CANCELED = 6
  );

  QUIC_CONNECTION_EVENT = record
    Type_: QUIC_CONNECTION_EVENT_TYPE;
    _ReservedPadding: UInt32;
    case Integer of
      0: (SessionResumed: Byte; NegotiatedAlpnLength: Byte; _AlpnPadding: array[0..5] of Byte; NegotiatedAlpn: PByte);
      1: (Status: QUIC_STATUS; _StatusPadding: UInt32; ErrorCode: QUIC_UINT62);
      2: (PeerErrorCode: QUIC_UINT62);
      3: (Flags: Byte);
      4: (Address: PQUIC_ADDR);
      6: (Stream: HQUIC; StreamFlags: UInt32);
      10: (SendEnabled: Byte; _SendPadding: Byte; MaxSendLength: UInt16);
      11: (DatagramBuffer: PQUIC_BUFFER; DatagramFlags: QUIC_RECEIVE_FLAGS);
      12: (ClientContext: Pointer; State: QUIC_DATAGRAM_SEND_STATE);
      99: (Padding: array[0..63] of Byte);
  end;
  PQUIC_CONNECTION_EVENT = ^QUIC_CONNECTION_EVENT;

  QUIC_CONNECTION_CALLBACK_HANDLER = function(Connection: HQUIC; Context: Pointer; Event: PQUIC_CONNECTION_EVENT): QUIC_STATUS; cdecl;

  QUIC_STREAM_EVENT_TYPE = (
    QUIC_STREAM_EVENT_START_COMPLETE = 0,
    QUIC_STREAM_EVENT_RECEIVE = 1,
    QUIC_STREAM_EVENT_SEND_COMPLETE = 2,
    QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN = 3,
    QUIC_STREAM_EVENT_PEER_SEND_ABORTED = 4,
    QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED = 5,
    QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE = 6,
    QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE = 7,
    QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE = 8,
    QUIC_STREAM_EVENT_PEER_ACCEPTED = 9
  );

  QUIC_STREAM_EVENT = record
    Type_: QUIC_STREAM_EVENT_TYPE;
    _ReservedPadding: UInt32;
    case Integer of
      0: (Status: QUIC_STATUS; _StatusPadding: UInt32; ID: QUIC_UINT62);
      1: (AbsoluteOffset: UInt64; TotalBufferLength: UInt64; Buffers: PQUIC_BUFFER; BufferCount: UInt32; ReceiveFlags: QUIC_RECEIVE_FLAGS);
      2: (Canceled: Byte; _CancelPadding: array[0..6] of Byte; ClientContext: Pointer);
      3: (ErrorCode: QUIC_UINT62);
      7: (ConnectionShutdown: Byte; _ShutdownPadding: array[0..6] of Byte; ConnectionErrorCode: QUIC_UINT62; ConnectionCloseStatus: QUIC_STATUS);
      99: (Padding: array[0..63] of Byte);
  end;
  PQUIC_STREAM_EVENT = ^QUIC_STREAM_EVENT;

  QUIC_STREAM_CALLBACK_HANDLER = function(Stream: HQUIC; Context: Pointer; Event: PQUIC_STREAM_EVENT): QUIC_STATUS; cdecl;

implementation

end.
