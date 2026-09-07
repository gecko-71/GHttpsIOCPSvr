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

unit MsQuic.ApiTable;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Winapi.Windows, MsQuic.Types;

type

  QUIC_SET_CONTEXT_FN = procedure(Handle: HQUIC; Context: Pointer); cdecl;
  QUIC_GET_CONTEXT_FN = function(Handle: HQUIC): Pointer; cdecl;
  QUIC_SET_CALLBACK_HANDLER_FN = procedure(Handle: HQUIC; Handler: Pointer; Context: Pointer); cdecl;

  QUIC_SET_PARAM_FN = function(Handle: HQUIC; Param: UInt32; BufferLength: UInt32; const Buffer: Pointer): QUIC_STATUS; cdecl;
  QUIC_GET_PARAM_FN = function(Handle: HQUIC; Param: UInt32; var BufferLength: UInt32; Buffer: Pointer): QUIC_STATUS; cdecl;

  QUIC_REGISTRATION_OPEN_FN = function(const Config: Pointer; var Registration: HQUIC): QUIC_STATUS; cdecl;
  QUIC_REGISTRATION_CLOSE_FN = procedure(Registration: HQUIC); cdecl;
  QUIC_REGISTRATION_SHUTDOWN_FN = procedure(Registration: HQUIC; Flags: UInt32; ErrorCode: QUIC_UINT62); cdecl;

  QUIC_CONFIGURATION_OPEN_FN = function(Registration: HQUIC; const AlpnBuffers: Pointer; AlpnBufferCount: UInt32; const Settings: Pointer; SettingsSize: UInt32; Context: Pointer; var Configuration: HQUIC): QUIC_STATUS; cdecl;
  QUIC_CONFIGURATION_CLOSE_FN = procedure(Configuration: HQUIC); cdecl;
  QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN = function(Configuration: HQUIC; const CredConfig: PQUIC_CREDENTIAL_CONFIG): QUIC_STATUS; cdecl;

  QUIC_LISTENER_OPEN_FN = function(Registration: HQUIC; Handler: Pointer; Context: Pointer; var Listener: HQUIC): QUIC_STATUS; cdecl;
  QUIC_LISTENER_CLOSE_FN = procedure(Listener: HQUIC); cdecl;
  QUIC_LISTENER_START_FN = function(Listener: HQUIC; const AlpnBuffers: Pointer; AlpnBufferCount: UInt32; const LocalAddress: Pointer): QUIC_STATUS; cdecl;
  QUIC_LISTENER_STOP_FN = procedure(Listener: HQUIC); cdecl;

  QUIC_CONNECTION_OPEN_FN = function(Registration: HQUIC; Handler: Pointer; Context: Pointer; var Connection: HQUIC): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_CLOSE_FN = procedure(Connection: HQUIC); cdecl;
  QUIC_CONNECTION_SHUTDOWN_FN = procedure(Connection: HQUIC; Flags: UInt32; ErrorCode: QUIC_UINT62); cdecl;
  QUIC_CONNECTION_START_FN = function(Connection: HQUIC; Configuration: HQUIC; Family: UInt16; const ServerName: PAnsiChar; ServerPort: UInt16): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_SET_CONFIGURATION_FN = function(Connection: HQUIC; Configuration: HQUIC): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_SEND_RESUMPTION_FN = function(Connection: HQUIC; Flags: UInt32; DataLength: UInt16; const Data: PByte): QUIC_STATUS; cdecl;

  QUIC_STREAM_OPEN_FN = function(Connection: HQUIC; Flags: UInt32; Handler: Pointer; Context: Pointer; var Stream: HQUIC): QUIC_STATUS; cdecl;
  QUIC_STREAM_CLOSE_FN = procedure(Stream: HQUIC); cdecl;
  QUIC_STREAM_START_FN = function(Stream: HQUIC; Flags: UInt32): QUIC_STATUS; cdecl;
  QUIC_STREAM_SHUTDOWN_FN = function(Stream: HQUIC; Flags: UInt32; ErrorCode: QUIC_UINT62): QUIC_STATUS; cdecl;
  QUIC_STREAM_SEND_FN = function(Stream: HQUIC; const Buffers: Pointer; BufferCount: UInt32; Flags: UInt32; ClientSendContext: Pointer): QUIC_STATUS; cdecl;
  QUIC_STREAM_RECEIVE_COMPLETE_FN = procedure(Stream: HQUIC; BufferLength: UInt64); cdecl;
  QUIC_STREAM_RECEIVE_SET_ENABLED_FN = function(Stream: HQUIC; IsEnabled: Boolean): QUIC_STATUS; cdecl;

  QUIC_DATAGRAM_SEND_FN = function(Connection: HQUIC; const Buffers: Pointer; BufferCount: UInt32; Flags: UInt32; ClientSendContext: Pointer): QUIC_STATUS; cdecl;

  QUIC_CONNECTION_COMP_RESUMPTION_FN = function(Connection: HQUIC; Result: Boolean): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_COMP_CERT_FN = function(Connection: HQUIC; Result: Boolean; Status: QUIC_STATUS): QUIC_STATUS; cdecl;
  QUIC_CONNECTION_OPEN_IN_PARTITION_FN = function(Registration: HQUIC; PartitionIndex: UInt16; Handler: Pointer; Context: Pointer; var Connection: HQUIC): QUIC_STATUS; cdecl;

  TQuicApiTable = record
    SetContext: QUIC_SET_CONTEXT_FN;
    GetContext: QUIC_GET_CONTEXT_FN;
    SetCallbackHandler: QUIC_SET_CALLBACK_HANDLER_FN;

    SetParam: QUIC_SET_PARAM_FN;
    GetParam: QUIC_GET_PARAM_FN;

    RegistrationOpen: QUIC_REGISTRATION_OPEN_FN;
    RegistrationClose: QUIC_REGISTRATION_CLOSE_FN;
    RegistrationShutdown: QUIC_REGISTRATION_SHUTDOWN_FN;

    ConfigurationOpen: QUIC_CONFIGURATION_OPEN_FN;
    ConfigurationClose: QUIC_CONFIGURATION_CLOSE_FN;
    ConfigurationLoadCredential: QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN;

    ListenerOpen: QUIC_LISTENER_OPEN_FN;
    ListenerClose: QUIC_LISTENER_CLOSE_FN;
    ListenerStart: QUIC_LISTENER_START_FN;
    ListenerStop: QUIC_LISTENER_STOP_FN;

    ConnectionOpen: QUIC_CONNECTION_OPEN_FN;
    ConnectionClose: QUIC_CONNECTION_CLOSE_FN;
    ConnectionShutdown: QUIC_CONNECTION_SHUTDOWN_FN;
    ConnectionStart: QUIC_CONNECTION_START_FN;
    ConnectionSetConfiguration: QUIC_CONNECTION_SET_CONFIGURATION_FN;
    ConnectionSendResumptionTicket: QUIC_CONNECTION_SEND_RESUMPTION_FN;

    StreamOpen: QUIC_STREAM_OPEN_FN;
    StreamClose: QUIC_STREAM_CLOSE_FN;
    StreamStart: QUIC_STREAM_START_FN;
    StreamShutdown: QUIC_STREAM_SHUTDOWN_FN;
    StreamSend: QUIC_STREAM_SEND_FN;
    StreamReceiveComplete: QUIC_STREAM_RECEIVE_COMPLETE_FN;
    StreamReceiveSetEnabled: QUIC_STREAM_RECEIVE_SET_ENABLED_FN;

    DatagramSend: QUIC_DATAGRAM_SEND_FN;

    ConnectionResumptionTicketValidationComplete: QUIC_CONNECTION_COMP_RESUMPTION_FN;
    ConnectionCertificateValidationComplete: QUIC_CONNECTION_COMP_CERT_FN;

    ConnectionOpenInPartition: QUIC_CONNECTION_OPEN_IN_PARTITION_FN;
  end;
  PQuicApiTable = ^TQuicApiTable;

implementation

end.
