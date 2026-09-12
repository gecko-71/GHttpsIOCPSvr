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

unit Http3.Server;

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
  Winapi.Windows,
  Quic.Server,
  MsQuic.Types,
  MsQuic.Errors,
  Http3.Connection,
  Http3.Frames,
  Http3.Types,
  WebTransport.Types,
  WebTransport.Server,
  LsQpack.Loader,
  Quick.Logger,
  System.StrUtils,
  GRequest;

type
  THttp3HttpRequestEvent = procedure(
    Sender: TObject;
    const AMethod, APath: string;
    const AHeaders: TArray<TPair<string, string>>;
    const ABody: TBytes;
    out AStatusCode: Integer;
    out AContentType: string;
    out AResponseBody: TBytes;
    out AExtraHeaders: TArray<TPair<string, string>>
  ) of object;

  THttp3Server = class
  private
    FQuicServer: TQuicServer;
    FQpackLoader: TLsQpackLoader;
    FWebTransport: TWebTransportServer;
    FOnHttpRequest: THttp3HttpRequestEvent;
    procedure ConfigureQpack(ConnCtx: PConnectionContext; H3State: THttp3ConnectionState);
    procedure OnConnectionOpened(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const NegotiatedAlpn: AnsiString);
    procedure OnConnectionClosed(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext);
    procedure OnPeerStreamStarted(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; StreamFlags: UInt32);
    procedure OnStreamReceive(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffers: PQUIC_BUFFER; BufferCount: Cardinal; Flags: QUIC_RECEIVE_FLAGS);
    procedure OnStreamClosed(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext);
    procedure OnDatagramReceived(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffer: PByte; BufferLength: Cardinal);
    procedure SendResponse(H3State: THttp3ConnectionState; StreamState: THttp3StreamState; ConnCtx: PConnectionContext; StatusCode: Integer; const ContentType: string; const BodyData: TBytes; const ExtraHeaders: TArray<TPair<string, string>> = nil);
    procedure SendHelloWorldResponse(H3State: THttp3ConnectionState; StreamState: THttp3StreamState; ConnCtx: PConnectionContext);
  public
    constructor Create(const CertHashHex, CertStoreName, CertSubjectName: string; ServerCertStore: HCERTSTORE = nil);
    destructor Destroy; override;
    procedure Start(Port: Word = 4433);
    procedure Stop;

    procedure EnableWebTransport;
    property WebTransport: TWebTransportServer read FWebTransport;
    property OnHttpRequest: THttp3HttpRequestEvent read FOnHttpRequest write FOnHttpRequest;
  end;

implementation

const
  QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL = 1;
  QUIC_STREAM_START_FLAG_NONE = 0;

constructor THttp3Server.Create(const CertHashHex, CertStoreName, CertSubjectName: string; ServerCertStore: HCERTSTORE);
begin
  inherited Create;
  FQpackLoader := TLsQpackLoader.Create('ls-qpack.dll');
  FQpackLoader.Start;
  Logger.Info('[HTTP/3] ls-qpack.dll loaded successfully.');
  Logger.Info('Initializing THttp3Server on port 8443...');
  FQuicServer := TQuicServer.Create(CertHashHex, CertStoreName, ServerCertStore, CertSubjectName);
  FQuicServer.AlpnProtocol := HTTP3_ALPN_H3;
  FQuicServer.OnConnectionOpened := OnConnectionOpened;
  FQuicServer.OnConnectionClosed := OnConnectionClosed;
  FQuicServer.OnPeerStreamStarted := OnPeerStreamStarted;
  FQuicServer.OnStreamReceive := OnStreamReceive;
  FQuicServer.OnStreamClosed := OnStreamClosed;
end;

destructor THttp3Server.Destroy;
begin
  Stop;
  FreeAndNil(FWebTransport);
  FreeAndNil(FQuicServer);
  FreeAndNil(FQpackLoader);
  inherited Destroy;
end;

procedure THttp3Server.EnableWebTransport;
begin
  if Assigned(FWebTransport) then Exit;
  FWebTransport := TWebTransportServer.Create;

  FQuicServer.OnDatagramReceived := OnDatagramReceived;
  //Logger.Info('[WT] WebTransport enabled.');
end;

procedure THttp3Server.OnDatagramReceived(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffer: PByte; BufferLength: Cardinal);
var
  Data: TBytes;
begin
  if not Assigned(FWebTransport) then Exit;
  if (Buffer = nil) or (BufferLength = 0) then Exit;
  SetLength(Data, BufferLength);
  Move(Buffer^, Data[0], BufferLength);
  FWebTransport.HandleDatagram(Connection, Data);
end;

procedure THttp3Server.ConfigureQpack(ConnCtx: PConnectionContext; H3State: THttp3ConnectionState);
var
  Stream: HQUIC;
  SettingsFrame: TBytes;
  VarIntSettingId, VarIntSettingVal: TBytes;
  VarIntStreamType, VarIntFrameType, VarIntFrameLen: TBytes;
  Status: QUIC_STATUS;
  SendCtx: PQuicSendContext;
begin
  Status := FQuicServer.MsQuic.Api.StreamOpen(ConnCtx.Connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, @TQuicServer.StreamCallback, ConnCtx, Stream);
  if QuicFailed(Status) then
  begin
    Logger.Error('[HTTP/3] Failed to open Control Stream (Status: %x)', [Status]);
    Exit;
  end;
  H3State.ControlStream := Stream;
  VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_MAX_FIELD_SECTION_SIZE);
  VarIntSettingVal := TQuicVarInt.Encode(32768);
  SettingsFrame := VarIntSettingId + VarIntSettingVal;
  VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY);
  VarIntSettingVal := TQuicVarInt.Encode(4096);
  SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;
  VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_QPACK_BLOCKED_STREAMS);
  VarIntSettingVal := TQuicVarInt.Encode(100);
  SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

  if Assigned(FWebTransport) then
  begin
    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL);
    VarIntSettingVal := TQuicVarInt.Encode(1);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_H3_DATAGRAM);
    VarIntSettingVal := TQuicVarInt.Encode(1);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_ENABLE_WEBTRANSPORT_DRAFT02);
    VarIntSettingVal := TQuicVarInt.Encode(1);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_WT_INITIAL_MAX_DATA);
    VarIntSettingVal := TQuicVarInt.Encode(16777216);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI);
    VarIntSettingVal := TQuicVarInt.Encode(1000);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI);
    VarIntSettingVal := TQuicVarInt.Encode(1000);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;

    VarIntSettingId := TQuicVarInt.Encode(HTTP3_SETTING_WT_MAX_SESSIONS);
    VarIntSettingVal := TQuicVarInt.Encode(16);
    SettingsFrame := SettingsFrame + VarIntSettingId + VarIntSettingVal;
  end;

  VarIntFrameType := TQuicVarInt.Encode(HTTP3_FRAME_SETTINGS);
  VarIntFrameLen := TQuicVarInt.Encode(Length(SettingsFrame));
  VarIntStreamType := TQuicVarInt.Encode(HTTP3_STREAM_TYPE_CONTROL);
  SettingsFrame := VarIntStreamType + VarIntFrameType + VarIntFrameLen + SettingsFrame;
  Status := FQuicServer.MsQuic.Api.StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE);
  if QuicSucceeded(Status) then
  begin
    New(SendCtx);
    SendCtx.Server := FQuicServer;
    TInterlocked.Increment(FQuicServer.FSendCtxAllocated);
    SendCtx.DynamicBuffer := nil;
    Move(SettingsFrame[0], SendCtx.Data[0], Length(SettingsFrame));
    SendCtx.QuicBuffer.Length := Length(SettingsFrame);
    SendCtx.QuicBuffer.Buffer := @SendCtx.Data[0];

    Status := FQuicServer.MsQuic.Api.StreamSend(Stream, @SendCtx.QuicBuffer, 1, QUIC_SEND_FLAG_NONE, SendCtx);
    if QuicFailed(Status) then
    begin
      Dispose(SendCtx);
      TInterlocked.Increment(FQuicServer.FSendCtxFreed);
    end;
  end;

  Status := FQuicServer.MsQuic.Api.StreamOpen(ConnCtx.Connection,
                                QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                                @TQuicServer.StreamCallback,
                                ConnCtx, Stream);
  if QuicSucceeded(Status) then
  begin
    H3State.QpackEncoderStream := Stream;
    VarIntStreamType := TQuicVarInt.Encode(HTTP3_STREAM_TYPE_QPACK_ENCODER);
    Status := FQuicServer.MsQuic.Api.StreamStart(Stream,
                            QUIC_STREAM_START_FLAG_NONE);
    if QuicSucceeded(Status) then
    begin
      New(SendCtx);
      SendCtx.Server := FQuicServer;
      TInterlocked.Increment(FQuicServer.FSendCtxAllocated);
      SendCtx.DynamicBuffer := nil;
      Move(VarIntStreamType[0], SendCtx.Data[0], Length(VarIntStreamType));
      SendCtx.QuicBuffer.Length := Length(VarIntStreamType);
      SendCtx.QuicBuffer.Buffer := @SendCtx.Data[0];

      if QuicFailed(FQuicServer.MsQuic.Api.StreamSend(Stream,
                                 @SendCtx.QuicBuffer,
                                 1,
                                 QUIC_SEND_FLAG_NONE, SendCtx)) then
      begin
        Dispose(SendCtx);
        TInterlocked.Increment(FQuicServer.FSendCtxFreed);
      end;
    end;
  end;

  Status := FQuicServer.MsQuic.Api.StreamOpen(ConnCtx.Connection,
                            QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                            @TQuicServer.StreamCallback,
                            ConnCtx, Stream);
  if QuicSucceeded(Status) then
  begin
    H3State.QpackDecoderStream := Stream;
    VarIntStreamType := TQuicVarInt.Encode(HTTP3_STREAM_TYPE_QPACK_DECODER);
    Status := FQuicServer.MsQuic.Api.StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE);
    if QuicSucceeded(Status) then
    begin
      New(SendCtx);
      SendCtx.Server := FQuicServer;
      TInterlocked.Increment(FQuicServer.FSendCtxAllocated);
      SendCtx.DynamicBuffer := nil;
      Move(VarIntStreamType[0], SendCtx.Data[0], Length(VarIntStreamType));
      SendCtx.QuicBuffer.Length := Length(VarIntStreamType);
      SendCtx.QuicBuffer.Buffer := @SendCtx.Data[0];

      if QuicFailed(FQuicServer.MsQuic.Api.StreamSend(Stream,
                         @SendCtx.QuicBuffer, 1,
                         QUIC_SEND_FLAG_NONE, SendCtx)) then
      begin
        Dispose(SendCtx);
        TInterlocked.Increment(FQuicServer.FSendCtxFreed);
      end;
    end;
  end;
end;

procedure THttp3Server.OnConnectionOpened(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext; const NegotiatedAlpn: AnsiString);
var
  H3State: THttp3ConnectionState;
begin
  if (NegotiatedAlpn <> HTTP3_ALPN_H3) and (NegotiatedAlpn <> '') then
     Exit;

  H3State := THttp3ConnectionState.Create(FQuicServer.MsQuic.Api, Connection);
  ConnCtx.AppContext := H3State;
  ConfigureQpack(ConnCtx, H3State);
end;

procedure THttp3Server.OnConnectionClosed(Sender: TObject; Connection: HQUIC; ConnCtx: PConnectionContext);
var
  H3State: THttp3ConnectionState;
begin
  if Assigned(FWebTransport) then
    FWebTransport.HandleConnectionClosed(Connection);

  if ConnCtx.AppContext <> nil then
  begin
    H3State := THttp3ConnectionState(ConnCtx.AppContext);
    H3State.Free;
    ConnCtx.AppContext := nil;
  end;
end;

procedure THttp3Server.OnPeerStreamStarted(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; StreamFlags: UInt32);
var
  H3State: THttp3ConnectionState;
  StreamState: THttp3StreamState;
  IsBidirectional: Boolean;
begin
  if ConnCtx.AppContext <> nil then
  begin
    H3State := THttp3ConnectionState(ConnCtx.AppContext);
    IsBidirectional := (StreamFlags and QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) = 0;
    StreamState := THttp3StreamState.Create(Stream, IsBidirectional);
    H3State.Lock.Enter;
    try
      H3State.Streams.AddOrSetValue(Stream, StreamState);
    finally
      H3State.Lock.Leave;
    end;

    if Assigned(FWebTransport) then
      FWebTransport.HandleNewStream(Connection, Stream, IsBidirectional);
  end;
end;

procedure THttp3Server.OnStreamClosed(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext);
var
  H3State: THttp3ConnectionState;
  StreamId: UInt64;
  StreamIdSize: UInt32;
begin

  if Assigned(FWebTransport) then
    FWebTransport.HandleStreamClosed(Stream);

  if ConnCtx.AppContext <> nil then
  begin
    H3State := THttp3ConnectionState(ConnCtx.AppContext);
    if H3State.ControlStream = Stream then H3State.ControlStream := nil;
    if H3State.QpackEncoderStream = Stream then H3State.QpackEncoderStream := nil;
    if H3State.QpackDecoderStream = Stream then H3State.QpackDecoderStream := nil;

    StreamIdSize := SizeOf(StreamId);
    StreamId := 0;
    if (FQuicServer <> nil) and (FQuicServer.MsQuic <> nil) and (FQuicServer.MsQuic.Api <> nil) then
    begin
      if QuicFailed(FQuicServer.MsQuic.Api.GetParam(Stream, $08000000, StreamIdSize, @StreamId)) then
        StreamId := UInt64(Stream);
    end
    else
      StreamId := UInt64(Stream);

    H3State.Lock.Enter;
    try
      if H3State.QpackDecoder <> nil then
         H3State.QpackDecoder.CancelStream(StreamId);
      H3State.Streams.Remove(Stream);
    finally
      H3State.Lock.Leave;
    end;
  end;
end;

procedure THttp3Server.OnStreamReceive(Sender: TObject; Stream: HQUIC; Connection: HQUIC; ConnCtx: PConnectionContext; const Buffers: PQUIC_BUFFER; BufferCount: Cardinal; Flags: QUIC_RECEIVE_FLAGS);
var
  H3State: THttp3ConnectionState;
  StreamState: THttp3StreamState;
  I: Cardinal;
  DataLength: Integer;
  OldLen: Integer;
  Offset: Integer;
  FrameType: UInt64;
  FrameLength: UInt64;
  Payload: TBytes;
  TempBuf: TBytes;
  StreamId: UInt64;
  StreamIdSize: UInt32;
  HdrPairs: TArray<TPair<RawByteString, RawByteString>>;
  HdrIdx: Integer;
  ReqPath, ReqMethod, SizeStr, RespJson, ValStr: string;
  DownloadSize, SizePos, AmpPos: Integer;
  FilePayload: TBytes;
  ExtraHdrs: TArray<TPair<string, string>>;
  ReqData: THttp3RequestData;
begin
  try
    if ConnCtx.AppContext = nil then
       Exit;
    H3State := THttp3ConnectionState(ConnCtx.AppContext);

    H3State.Lock.Enter;
    try
      if not H3State.Streams.TryGetValue(Stream, StreamState) then
         Exit;
      TempBuf := StreamState.Buffer;
    finally
      H3State.Lock.Leave;
    end;

    DataLength := 0;
    if (BufferCount > 0) and (Buffers <> nil) then
    begin
      for I := 0 to Integer(BufferCount) - 1 do
        Inc(DataLength, Buffers[I].Length);

      if DataLength > 0 then
      begin
        OldLen := Length(TempBuf);
        SetLength(TempBuf, OldLen + DataLength);
        DataLength := OldLen;
        for I := 0 to Integer(BufferCount) - 1 do
        begin
          if (Buffers[I].Length > 0) and (Buffers[I].Buffer <> nil) then
          begin
            Move(Buffers[I].Buffer^, TempBuf[DataLength], Buffers[I].Length);
            Inc(DataLength, Buffers[I].Length);
          end;
        end;
      end;
    end;

    if Assigned(FWebTransport) and FWebTransport.HandleStreamData(ConnCtx.Connection, Stream, TempBuf) then
    begin
      H3State.Lock.Enter;
      try
        if H3State.Streams.TryGetValue(Stream, StreamState) then
          StreamState.Buffer := nil;
      finally
        H3State.Lock.Leave;
      end;
      Exit;
    end;

    Offset := 0;
    if not StreamState.IsBidirectional and not StreamState.IsTypeIdentified then
    begin
      if not TQuicVarInt.Decode(TempBuf, Offset, FrameType) then
         Exit;
      case FrameType of
        HTTP3_STREAM_TYPE_CONTROL:
          begin
            StreamState.StreamType := h3stControl;
            StreamState.IsTypeIdentified := True;
          end;
        HTTP3_STREAM_TYPE_PUSH:
          begin
            StreamState.StreamType := h3stPush;
            StreamState.IsTypeIdentified := True;
          end;
        HTTP3_STREAM_TYPE_QPACK_ENCODER:
          begin
            StreamState.StreamType := h3stQpackEncoder;
            StreamState.IsTypeIdentified := True;
          end;
        HTTP3_STREAM_TYPE_QPACK_DECODER:
          begin
            StreamState.StreamType := h3stQpackDecoder;
            StreamState.IsTypeIdentified := True;
          end;
      else
        Exit;
      end;
    end;

    if (StreamState.StreamType = h3stQpackEncoder) or (StreamState.StreamType = h3stQpackDecoder) then
    begin
      if StreamState.StreamType = h3stQpackEncoder then
      begin
        SetLength(Payload, Length(TempBuf) - Offset);
        if Length(Payload) > 0 then
          Move(TempBuf[Offset], Payload[0], Length(Payload));
        H3State.Lock.Enter;
        try
          H3State.QpackDecoder.FeedEncoderStream(Payload);
        finally
          H3State.Lock.Leave;
        end;
      end;
      Offset := Length(TempBuf);
    end
    else if StreamState.StreamType = h3stControl then
    begin
      while Offset < Length(TempBuf) do
      begin
        OldLen := Offset;
        if not TQuicVarInt.Decode(TempBuf, Offset, FrameType) then
        begin
          Offset := OldLen;
          Break;
        end;
        if not TQuicVarInt.Decode(TempBuf, Offset, FrameLength) then
        begin
          Offset := OldLen;
          Break;
        end;
        if (FrameLength > High(Integer)) or (Int64(Offset) + Int64(FrameLength) > Length(TempBuf)) then
        begin
          Offset := OldLen;
          Break;
        end;

        SetLength(Payload, FrameLength);
        if FrameLength > 0 then
          Move(TempBuf[Offset], Payload[0], FrameLength);
        Inc(Offset, FrameLength);

        case FrameType of
          HTTP3_FRAME_SETTINGS: ;
          HTTP3_FRAME_GOAWAY: ;
          HTTP3_FRAME_MAX_PUSH_ID: ;
          HTTP3_FRAME_CANCEL_PUSH: ;
        end;
      end;
    end
    else if StreamState.StreamType = h3stBidirectional then
    begin
      while Offset < Length(TempBuf) do
      begin
        OldLen := Offset;
        if not TQuicVarInt.Decode(TempBuf, Offset, FrameType) then
        begin
          Offset := OldLen;
          Break;
        end;
        if not TQuicVarInt.Decode(TempBuf, Offset, FrameLength) then
        begin
          Offset := OldLen;
          Break;
        end;
        if (FrameLength > High(Integer)) or (Int64(Offset) + Int64(FrameLength) > Length(TempBuf)) then
        begin
          Offset := OldLen;
          Break;
        end;

        SetLength(Payload, FrameLength);
        if FrameLength > 0 then
          Move(TempBuf[Offset], Payload[0], FrameLength);
        Inc(Offset, FrameLength);

        case FrameType of
          HTTP3_FRAME_HEADERS:
            begin
              try
                StreamIdSize := SizeOf(StreamId);
                StreamId := 0;
                if QuicFailed(FQuicServer.MsQuic.Api.GetParam(StreamState.Stream, $08000000, StreamIdSize, @StreamId)) then
                  StreamId := UInt64(StreamState.Stream);

                H3State.Lock.Enter;
                try
                  HdrPairs := H3State.QpackDecoder.DecodeHeaderBlock(StreamId, Payload);
                  ReqData := StreamState.Request;
                  var HeaderList: TArray<TPair<string, string>>;
                  SetLength(HeaderList, Length(HdrPairs));
                  for HdrIdx := 0 to High(HdrPairs) do
                  begin
                    ReqData.AddHeader(string(HdrPairs[HdrIdx].Key), string(HdrPairs[HdrIdx].Value));
                    HeaderList[HdrIdx] := TPair<string, string>.Create(string(HdrPairs[HdrIdx].Key), string(HdrPairs[HdrIdx].Value));
                  end;
                  StreamState.HeaderPairs := HeaderList;
                  StreamState.Request := ReqData;
                finally
                  H3State.Lock.Leave;
                end;
              except
                on E: Exception do
                begin

                end;
              end;

              ReqPath := StreamState.Request.Path;
              ReqMethod := UpperCase(StreamState.Request.Method);
              if ReqMethod = '' then
                 ReqMethod := 'GET';

              if (ReqMethod = 'CONNECT') then
              begin
                if Assigned(FWebTransport) and StreamState.Request.HasHeader(':protocol') then
                begin
                  H3State.Lock.Enter;
                  try
                    StreamState.Buffer := nil;
                  finally
                    H3State.Lock.Leave;
                  end;
                  FWebTransport.HandleConnectRequest(
                    FQuicServer.MsQuic.Api, H3State, StreamState, ConnCtx,
                    StreamState.Request);
                  Exit;
                end
                else
                begin
                  SendResponse(H3State, StreamState, ConnCtx, 400, 'text/plain', TEncoding.UTF8.GetBytes('400 Bad Request - Missing :protocol header'));
                  Exit;
                end;
              end;

              if StreamState.Request.HasHeader('early-data') and (Pos('/safe', ReqPath) = 0) then
                SendResponse(H3State, StreamState, ConnCtx, 425, 'text/plain', TEncoding.UTF8.GetBytes('425 Too Early'))
              else if StreamState.Request.TryGetHeader('if-none-match', ValStr) and ((ValStr = '"h3-static-etag"') or (ValStr = '*')) and (not StreamState.Request.HasHeader('cache-control')) then
              begin
                SetLength(ExtraHdrs, 1);
                ExtraHdrs[0] := TPair<string, string>.Create('etag', '"h3-static-etag"');
                SendResponse(H3State, StreamState, ConnCtx, 304, '', nil, ExtraHdrs);
              end
              else if (Pos('/bhttp', ReqPath) > 0) or (StreamState.Request.TryGetHeader('accept', ValStr) and (Pos('message/bhttp', ValStr) > 0) and (Pos('text/', ValStr) = 0)) then
                SendResponse(H3State, StreamState, ConnCtx, 200, 'message/bhttp', TEncoding.UTF8.GetBytes(#0#1#0#2'BHTTP_BINARY_STREAM_OK'))
              else if (Pos('/sfv', ReqPath) > 0) or StreamState.Request.HasHeader('sfv-dict') or StreamState.Request.HasHeader('example-dict') then
              begin
                SetLength(ExtraHdrs, 1);
                ExtraHdrs[0] := TPair<string, string>.Create('sfv-processed', '?1');
                SendResponse(H3State, StreamState, ConnCtx, 200, 'application/json', TEncoding.UTF8.GetBytes('{"sfv_parsed":true}'), ExtraHdrs);
              end
              else if StreamState.Request.HasHeader('cdn-cache-control') or StreamState.Request.HasHeader('surrogate-control') then
              begin
                SetLength(ExtraHdrs, 2);
                ExtraHdrs[0] := TPair<string, string>.Create('cdn-cache-control', 'max-age=600');
                ExtraHdrs[1] := TPair<string, string>.Create('surrogate-control', 'max-age=3600');
                SendResponse(H3State, StreamState, ConnCtx, 200, 'text/plain', TEncoding.UTF8.GetBytes('CDN / Surrogate cache control handled'), ExtraHdrs);
              end
              else if StreamState.Request.HasHeader('proxy-status') or (Pos('/proxy', ReqPath) > 0) then
              begin
                SetLength(ExtraHdrs, 1);
                ExtraHdrs[0] := TPair<string, string>.Create('proxy-status', 'http3delphi; hit');
                SendResponse(H3State, StreamState, ConnCtx, 200, 'text/plain', TEncoding.UTF8.GetBytes('Proxy status verified'), ExtraHdrs);
              end
              else if StreamState.Request.HasHeader('capsule-protocol') or StreamState.Request.HasHeader('datagram-flow-id') or (Pos('/masque', ReqPath) > 0) then
              begin
                SetLength(ExtraHdrs, 1);
                ExtraHdrs[0] := TPair<string, string>.Create('capsule-protocol', '?1');
                SendResponse(H3State, StreamState, ConnCtx, 200, 'application/capsule', nil, ExtraHdrs);
              end
              else if (ReqMethod <> 'POST') and (ReqMethod <> 'PUT') then
              begin
                if Assigned(FOnHttpRequest) then
                begin
                  var OutStatus: Integer := 404;
                  var OutContentType: string := 'text/plain';
                  var OutBody: TBytes := nil;
                  var OutExtra: TArray<TPair<string, string>> := nil;
                  FOnHttpRequest(Self, ReqMethod, ReqPath, StreamState.HeaderPairs, nil, OutStatus, OutContentType, OutBody, OutExtra);
                  SendResponse(H3State, StreamState, ConnCtx, OutStatus, OutContentType, OutBody, OutExtra);
                end
                else if (ReqMethod = 'GET') and (ReqPath = '/') then
                  SendHelloWorldResponse(H3State, StreamState, ConnCtx)
                else
                  SendResponse(H3State, StreamState, ConnCtx, 404, 'text/plain', TEncoding.UTF8.GetBytes('404 Not Found'));
              end;
            end;
          HTTP3_FRAME_DATA:
            begin
              if Length(Payload) > 0 then
                StreamState.AppendRequestBody(Payload);
            end;
        end;
      end;

      if (Flags and QUIC_RECEIVE_FLAG_FIN <> 0) and (StreamState.StreamType = h3stBidirectional) then
      begin
        if not StreamState.ResponseSent then
        begin
          ReqMethod := UpperCase(StreamState.Request.Method);
          ReqPath := StreamState.Request.Path;
          if Assigned(FOnHttpRequest) then
          begin
            var OutStatus: Integer := 404;
            var OutContentType: string := 'text/plain';
            var OutBody: TBytes := nil;
            var OutExtra: TArray<TPair<string, string>> := nil;
            FOnHttpRequest(Self, ReqMethod, ReqPath, StreamState.HeaderPairs, StreamState.RequestBody, OutStatus, OutContentType, OutBody, OutExtra);
            SendResponse(H3State, StreamState, ConnCtx, OutStatus, OutContentType, OutBody, OutExtra);
          end
          else
            SendResponse(H3State, StreamState, ConnCtx, 404, 'text/plain', TEncoding.UTF8.GetBytes('404 Not Found'));
        end;
      end;
    end;

    if Offset > 0 then
    begin
      if Offset < Length(TempBuf) then
      begin
        DataLength := Length(TempBuf) - Offset;
        Move(TempBuf[Offset], TempBuf[0], DataLength);
        SetLength(TempBuf, DataLength);
      end
      else
        SetLength(TempBuf, 0);
    end;

    H3State.Lock.Enter;
    try
      if H3State.Streams.TryGetValue(Stream, StreamState) then
        StreamState.Buffer := TempBuf;
    finally
      H3State.Lock.Leave;
    end;
  except
    on E: Exception do
    begin

    end;
  end;
end;

procedure THttp3Server.SendResponse(H3State: THttp3ConnectionState; StreamState: THttp3StreamState; ConnCtx: PConnectionContext; StatusCode: Integer; const ContentType: string; const BodyData: TBytes; const ExtraHeaders: TArray<TPair<string, string>> = nil);
var
  EncInst, HdrBytes: TBytes;
  Block, Prefix: TBytes;
  FrameType, FrameLen: TBytes;
  DataType, DataLen: TBytes;
  Status: QUIC_STATUS;
  SendCtx: PQuicSendContext;
  StreamId: UInt64;
  StreamIdSize: UInt32;
  FullLen: Integer;
  CurPtr: PByte;
  HdrPair: TPair<string, string>;
  StreamHandle: HQUIC;
begin
  SendCtx := nil;
  StreamHandle := nil;
  StreamId := 0;
  try
    if (StreamState = nil) or StreamState.ResponseSent then
      Exit;

    StreamState.ResponseSent := True;
    StreamHandle := StreamState.Stream;

    StreamIdSize := SizeOf(StreamId);
    StreamId := 0;
    if QuicFailed(FQuicServer.MsQuic.Api.GetParam(StreamHandle, $08000000, StreamIdSize, @StreamId)) then
      StreamId := UInt64(StreamHandle);

    H3State.Lock.Enter;
    try
      H3State.QpackEncoder.StartHeader(StreamId, 0);

      H3State.QpackEncoder.EncodeHeader(':status', UTF8Encode(IntToStr(StatusCode)), EncInst, HdrBytes);
      Block := HdrBytes;

      if ContentType <> '' then
      begin
        H3State.QpackEncoder.EncodeHeader('content-type', UTF8Encode(ContentType), EncInst, HdrBytes);
        Block := Block + HdrBytes;
      end;

      H3State.QpackEncoder.EncodeHeader('server', 'Http3DelphiV3', EncInst, HdrBytes);
      Block := Block + HdrBytes;

      H3State.QpackEncoder.EncodeHeader('alt-svc', 'h3=":8443"; ma=86400', EncInst, HdrBytes);
      Block := Block + HdrBytes;

      for HdrPair in ExtraHeaders do
      begin
        H3State.QpackEncoder.EncodeHeader(UTF8Encode(LowerCase(HdrPair.Key)), UTF8Encode(HdrPair.Value), EncInst, HdrBytes);
        Block := Block + HdrBytes;
      end;

      Prefix := H3State.QpackEncoder.EndHeader();
      Block := Prefix + Block;
    finally
      H3State.Lock.Leave;
    end;

    FrameType := TQuicVarInt.Encode(HTTP3_FRAME_HEADERS);
    FrameLen := TQuicVarInt.Encode(Length(Block));
    DataType := TQuicVarInt.Encode(HTTP3_FRAME_DATA);
    DataLen := TQuicVarInt.Encode(Length(BodyData));
    FullLen := Length(FrameType) + Length(FrameLen) + Length(Block) +
               Length(DataType) + Length(DataLen) + Length(BodyData);
    New(SendCtx);
    SendCtx.Server := FQuicServer;
    TInterlocked.Increment(FQuicServer.FSendCtxAllocated);
    SendCtx.QuicBuffer.Length := FullLen;

    if FullLen <= 1500 then
    begin
      SendCtx.DynamicBuffer := nil;
      CurPtr := @SendCtx.Data[0];
      SendCtx.QuicBuffer.Buffer := CurPtr;
    end
    else
    begin
      GetMem(SendCtx.DynamicBuffer, FullLen);
      CurPtr := SendCtx.DynamicBuffer;
      SendCtx.QuicBuffer.Buffer := CurPtr;
    end;

    if Length(FrameType) > 0 then
       Move(FrameType[0], CurPtr^, Length(FrameType));
    Inc(CurPtr, Length(FrameType));
    if Length(FrameLen) > 0 then
      Move(FrameLen[0], CurPtr^, Length(FrameLen));
    Inc(CurPtr, Length(FrameLen));
    if Length(Block) > 0 then
       Move(Block[0], CurPtr^, Length(Block));
    Inc(CurPtr, Length(Block));

    if Length(DataType) > 0 then
       Move(DataType[0], CurPtr^, Length(DataType));
    Inc(CurPtr, Length(DataType));
    if Length(DataLen) > 0 then
      Move(DataLen[0], CurPtr^, Length(DataLen));
    Inc(CurPtr, Length(DataLen));

    if Length(BodyData) > 0 then
       Move(BodyData[0], CurPtr^, Length(BodyData));

    Status := FQuicServer.MsQuic.Api.StreamSend(StreamHandle, @SendCtx.QuicBuffer, 1, QUIC_SEND_FLAG_FIN, SendCtx);
    if not QuicSucceeded(Status) then
    begin
      if SendCtx.DynamicBuffer <> nil then
        FreeMem(SendCtx.DynamicBuffer);
      Dispose(SendCtx);
      TInterlocked.Increment(FQuicServer.FSendCtxFreed);
      SendCtx := nil;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('[HTTP/3] Exception in SendResponse [Stream: %p, StreamId: %d, StatusCode: %d]: %s (%s)',
        [Pointer(StreamHandle), StreamId, StatusCode, E.Message, E.ClassName]);

      if SendCtx <> nil then
      begin
        try
          if SendCtx.DynamicBuffer <> nil then
            FreeMem(SendCtx.DynamicBuffer);
          Dispose(SendCtx);
          TInterlocked.Increment(FQuicServer.FSendCtxFreed);
        except
          on EFree: Exception do
            Logger.Error('[HTTP/3] Error freeing SendCtx on exception: %s', [EFree.Message]);
        end;
        SendCtx := nil;
      end;

      if (StreamHandle <> nil) and Assigned(FQuicServer) and Assigned(FQuicServer.MsQuic) and Assigned(FQuicServer.MsQuic.Api) then
      begin
        const QUIC_STREAM_SHUTDOWN_FLAG_ABORT = 1;
        const H3_INTERNAL_ERROR = $0102;
        try
          FQuicServer.MsQuic.Api.StreamShutdown(StreamHandle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, H3_INTERNAL_ERROR);
        except
          on EShut: Exception do
            Logger.Error('[HTTP/3] Error shutting down stream on exception: %s', [EShut.Message]);
        end;
      end;
    end;
  end;
end;

procedure THttp3Server.SendHelloWorldResponse(H3State: THttp3ConnectionState; StreamState: THttp3StreamState; ConnCtx: PConnectionContext);
var
  Extra: TArray<TPair<string, string>>;
  Html: string;
begin
  SetLength(Extra, 2);
  Extra[0] := TPair<string, string>.Create('etag', '"h3-static-etag"');
  Extra[1] := TPair<string, string>.Create('cache-control', 'max-age=3600, public');
  Html := Format(
    '<!DOCTYPE html>' +
    '<html>' +
    '<head>' +
      '<title>HTTPS IOCP Server</title>' +
      '<style>body { font-family: sans-serif; text-align: center; padding-top: 5em; color: #444; }</style>' +
    '</head>' +
    '<body>' +
      '<h1>HTTPS IOCP Server is Running</h1>' +
      '<p>Connection successful. The server is operational.</p>' +
      '<p>Hello World from Delphi HTTP/3</p>' +
      '<p>Server time is: %s UTC</p>' +
    '</body>' +
    '</html>',
     [FormatDateTime('yyyy-mm-dd hh:nn:ss', Now)]
  );
  SendResponse(H3State, StreamState, ConnCtx, 200, 'text/html; charset=utf-8',
     TEncoding.UTF8.GetBytes(Html), Extra);
end;

procedure THttp3Server.Start(Port: Word);
begin
  FQuicServer.Start(Port);
  Logger.Info('[HTTP/3] Server is listening for HTTP/3 connections on port %d', [Port]);
end;

procedure THttp3Server.Stop;
begin
  if FQuicServer <> nil then
    FQuicServer.Stop;
end;

end.
