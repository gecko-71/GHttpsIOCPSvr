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

unit WebTransport.Session;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.SyncObjs,
  MsQuic.Types,
  MsQuic.ApiTable,
  MsQuic.Errors,
  Quic.Server,
  Http3.Frames,
  WebTransport.Types;

function AllocWTSendContext(ConnCtx: PConnectionContext; Size: Integer): PQuicSendContext;
procedure FreeWTSendContextOnError(SendCtx: PQuicSendContext);
procedure WTSendConnect200(Api: PQuicApiTable; ConnCtx: Pointer; Stream: HQUIC; SessionId: TWTSessionId);
procedure WTSendOnStream(Api: PQuicApiTable; ConnCtx: Pointer; Stream: HQUIC; const Data: TBytes; CloseSend: Boolean = False);
procedure WTSendDatagram(Api: PQuicApiTable; ConnCtx: Pointer; Connection: HQUIC; const Data: TBytes); overload;
procedure WTSendDatagram(Api: PQuicApiTable; ConnCtx: Pointer; Connection: HQUIC; SessionId: TWTSessionId; const Data: TBytes); overload;
procedure WTCloseSession(Api: PQuicApiTable; Session: PWTSessionContext; ErrorCode: UInt64 = WT_SESSION_GONE);

type
  TWTSessionContextHelper = record helper for TWTSessionContext
  public
    procedure SendOnStream(Stream: HQUIC; const Data: TBytes; CloseSend: Boolean = False);
    procedure SendDatagram(const Data: TBytes);
    procedure Close(ErrorCode: UInt64 = WT_SESSION_GONE);
  end;

implementation

uses
  Quick.Logger;

function AllocWTSendContext(ConnCtx: PConnectionContext; Size: Integer): PQuicSendContext;
var
  SendCtx: PQuicSendContext;
  Svr: TQuicServer;
begin
  New(SendCtx);
  SendCtx.QuicBuffer.Length := Size;

  if Size <= 1500 then
  begin
    SendCtx.DynamicBuffer := nil;
    SendCtx.QuicBuffer.Buffer := @SendCtx.Data[0];
  end
  else
  begin
    GetMem(SendCtx.DynamicBuffer, Size);
    SendCtx.QuicBuffer.Buffer := SendCtx.DynamicBuffer;
  end;

  if (ConnCtx <> nil) and (ConnCtx.Server <> nil) then
  begin
    Svr := TQuicServer(ConnCtx.Server);
    SendCtx.Server := Svr;
    TInterlocked.Increment(Svr.FSendCtxAllocated);
  end
  else
    SendCtx.Server := nil;

  Result := SendCtx;
end;

procedure FreeWTSendContextOnError(SendCtx: PQuicSendContext);
var
  Svr: TQuicServer;
begin
  if SendCtx = nil then 
     Exit;
  if SendCtx.Server <> nil then
  begin
    Svr := TQuicServer(SendCtx.Server);
    TInterlocked.Increment(Svr.FSendCtxFreed);
  end;

  if SendCtx.DynamicBuffer <> nil then
    FreeMem(SendCtx.DynamicBuffer);
  Dispose(SendCtx);
end;

procedure WTSendConnect200(Api: PQuicApiTable; ConnCtx: Pointer; Stream: HQUIC; SessionId: TWTSessionId);
const
  Connect200Frame: array[0..42] of Byte = (
    $01, $29, $00, $00, $D9, $27, $15,
    Ord('s'), Ord('e'), Ord('c'), Ord('-'), Ord('w'), Ord('e'), Ord('b'), Ord('t'), Ord('r'),
    Ord('a'), Ord('n'), Ord('s'), Ord('p'), Ord('o'), Ord('r'), Ord('t'), Ord('-'), Ord('h'),
    Ord('t'), Ord('t'), Ord('p'), Ord('3'), Ord('-'), Ord('d'), Ord('r'), Ord('a'), Ord('f'),
    Ord('t'), $07, Ord('d'), Ord('r'), Ord('a'), Ord('f'), Ord('t'), Ord('0'), Ord('2')
  );
var
  SendCtx: PQuicSendContext;
  Status: QUIC_STATUS;
begin
  if (Api = nil) or (Stream = nil) or (ConnCtx = nil) then 
     Exit;

  SendCtx := AllocWTSendContext(PConnectionContext(ConnCtx), Length(Connect200Frame));
  Move(Connect200Frame[0], SendCtx.QuicBuffer.Buffer^, Length(Connect200Frame));

  Status := Api.StreamSend(Stream, @SendCtx.QuicBuffer, 1, QUIC_SEND_FLAG_NONE, SendCtx);
  if QuicFailed(Status) then
  begin
    FreeWTSendContextOnError(SendCtx);
  end;
end;

procedure WTSendOnStream(Api: PQuicApiTable; ConnCtx: Pointer; Stream: HQUIC; const Data: TBytes; CloseSend: Boolean = False);
var
  SendCtx: PQuicSendContext;
  SendFlags: UInt32;
  Status: QUIC_STATUS;
begin
  if (Api = nil) or (Stream = nil) or (ConnCtx = nil) 
              or (Length(Data) = 0) then 
	 Exit;

  SendCtx := AllocWTSendContext(PConnectionContext(ConnCtx), Length(Data));
  Move(Data[0], SendCtx.QuicBuffer.Buffer^, Length(Data));

  SendFlags := QUIC_SEND_FLAG_NONE;
  if CloseSend then
    SendFlags := QUIC_SEND_FLAG_FIN;

  Status := Api.StreamSend(Stream, @SendCtx.QuicBuffer, 1, SendFlags, SendCtx);
  if QuicFailed(Status) then
  begin
    FreeWTSendContextOnError(SendCtx);
  end;
end;

procedure WTSendDatagram(Api: PQuicApiTable; ConnCtx: Pointer; Connection: HQUIC; SessionId: TWTSessionId; const Data: TBytes);
var
  SendCtx: PQuicSendContext;
  Status: QUIC_STATUS;
  QuarterStreamId: UInt64;
  PrefixBytes: TBytes;
  TotalSize: Integer;
begin
  if (Api = nil) or (Connection = nil) or (ConnCtx = nil) or (Length(Data) = 0) then Exit;

  QuarterStreamId := SessionId shr 2;
  PrefixBytes := TQuicVarInt.Encode(QuarterStreamId);
  TotalSize := Length(PrefixBytes) + Length(Data);

  SendCtx := AllocWTSendContext(PConnectionContext(ConnCtx), TotalSize);
  Move(PrefixBytes[0], SendCtx.QuicBuffer.Buffer^, Length(PrefixBytes));
  Move(Data[0], (PByte(SendCtx.QuicBuffer.Buffer) + Length(PrefixBytes))^, Length(Data));

  Status := Api.DatagramSend(Connection, @SendCtx.QuicBuffer, 1, QUIC_SEND_FLAG_NONE, SendCtx);
  if QuicFailed(Status) then
  begin
    Logger.Warn('[WT] WTSendDatagram failed to send datagram (SessionId: %d, Status: 0x%x)', [SessionId, Status]);
    FreeWTSendContextOnError(SendCtx);
  end;
end;

procedure WTSendDatagram(Api: PQuicApiTable; ConnCtx: Pointer; Connection: HQUIC; const Data: TBytes);
begin
  WTSendDatagram(Api, ConnCtx, Connection, 0, Data);
end;

procedure WTCloseSession(Api: PQuicApiTable; Session: PWTSessionContext; ErrorCode: UInt64 = WT_SESSION_GONE);
const
  QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 1;
begin
  if (Api = nil) or (Session = nil) or (Session.ConnectStream = nil) then Exit;
  Api.StreamShutdown(Session.ConnectStream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, ErrorCode);
  Session.Active := False;
end;

procedure TWTSessionContextHelper.SendOnStream(Stream: HQUIC; const Data: TBytes; CloseSend: Boolean);
var
  PConn: PConnectionContext;
  Svr: TQuicServer;
begin
  PConn := PConnectionContext(ConnCtx);
  if (PConn = nil) or (PConn.Server = nil) then 
     Exit;
  Svr := TQuicServer(PConn.Server);
  if (Svr.MsQuic = nil) or (Svr.MsQuic.Api = nil) then 
     Exit;
  WTSendOnStream(Svr.MsQuic.Api, ConnCtx, Stream, Data, CloseSend);
end;

procedure TWTSessionContextHelper.SendDatagram(const Data: TBytes);
var
  PConn: PConnectionContext;
  Svr: TQuicServer;
begin
  PConn := PConnectionContext(ConnCtx);
  if (PConn = nil) or (PConn.Server = nil) then 
     Exit;
  Svr := TQuicServer(PConn.Server);
  if (Svr.MsQuic = nil) or (Svr.MsQuic.Api = nil) then 
     Exit;
  WTSendDatagram(Svr.MsQuic.Api, ConnCtx, Connection, StreamId, Data);
end;

procedure TWTSessionContextHelper.Close(ErrorCode: UInt64);
var
  PConn: PConnectionContext;
  Svr: TQuicServer;
begin
  PConn := PConnectionContext(ConnCtx);
  if (PConn = nil) or (PConn.Server = nil) then 
     Exit;
  Svr := TQuicServer(PConn.Server);
  if (Svr.MsQuic = nil) or (Svr.MsQuic.Api = nil) then 
     Exit;
  WTCloseSession(Svr.MsQuic.Api, @Self, ErrorCode);
end;

end.
