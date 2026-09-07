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

unit WebTransport.Server;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  MsQuic.Types,
  MsQuic.ApiTable,
  Quic.Server,
  Http3.Types,
  Http3.Frames,
  Http3.Connection,
  WebTransport.Types,
  WebTransport.Session;

type

  TWebTransportServer = class
  private
    FSessions: TDictionary<HQUIC, TWTSessionContext>;
    FStreamToSession: TDictionary<HQUIC, HQUIC>;
    FLock: TCriticalSection;
    FNextSessionId: Int64;
    FOnSessionRequest: TOnWTSessionRequest;
    FOnSessionReady:   TOnWTSessionReady;
    FOnSessionClosed:  TOnWTSessionClosed;
    FOnStreamData:     TOnWTStreamData;
    FOnDatagram:       TOnWTDatagram;
    procedure Send403(Api: PQuicApiTable; ConnCtx: PConnectionContext; ConnectStream: HQUIC);
  public
    constructor Create;
    destructor Destroy; override;
    function HandleConnectRequest(Api: PQuicApiTable;
      H3State: THttp3ConnectionState;
      StreamState: THttp3StreamState;
      ConnCtx: PConnectionContext;
      const Request: THttp3RequestData): Boolean;
    procedure HandleStreamClosed(ConnectStreamOrDataStream: HQUIC);
    procedure HandleConnectionClosed(Connection: HQUIC);
    function HandleNewStream(Connection: HQUIC; Stream: HQUIC; IsBidi: Boolean): Boolean;
    function HandleStreamData(Stream: HQUIC; const Data: TBytes): Boolean;
    procedure HandleDatagram(Connection: HQUIC; const Data: TBytes);
    property OnSessionRequest: TOnWTSessionRequest read FOnSessionRequest write FOnSessionRequest;
    property OnSessionReady:   TOnWTSessionReady   read FOnSessionReady   write FOnSessionReady;
    property OnSessionClosed:  TOnWTSessionClosed  read FOnSessionClosed  write FOnSessionClosed;
    property OnStreamData:     TOnWTStreamData     read FOnStreamData     write FOnStreamData;
    property OnDatagram:       TOnWTDatagram       read FOnDatagram       write FOnDatagram;
  end;

implementation

uses
  MsQuic.Errors,
  Quick.Logger;

const
  QUIC_SEND_FLAG_NONE = 0;

constructor TWebTransportServer.Create;
begin
  inherited Create;
  FLock            := TCriticalSection.Create;
  FSessions        := TDictionary<HQUIC, TWTSessionContext>.Create;
  FStreamToSession := TDictionary<HQUIC, HQUIC>.Create;
  FNextSessionId   := 0;
end;

destructor TWebTransportServer.Destroy;
begin
  FLock.Enter;
  try
    FSessions.Free;
    FStreamToSession.Free;
  finally
    FLock.Leave;
  end;
  FLock.Free;
  inherited Destroy;
end;

function TWebTransportServer.HandleConnectRequest(Api: PQuicApiTable;
  H3State: THttp3ConnectionState;
  StreamState: THttp3StreamState;
  ConnCtx: PConnectionContext;
  const Request: THttp3RequestData): Boolean;
var
  SessionId: TWTSessionId;
  StreamIdSize: UInt32;
  LocalStreamId: UInt64;
  Info: TWTSessionInfo;
  Accepted: Boolean;
  SessCtx: TWTSessionContext;
  ProtoVal: string;
  OriginVal: string;
begin
  Result := False;

  if not SameText(Request.Method, 'CONNECT') then 
     Exit;
  if not Request.TryGetHeader(':protocol', ProtoVal) or 
          not SameText(ProtoVal, WT_PROTOCOL_HEADER_VALUE) then 
	 Exit;

  OriginVal := '';
  Request.TryGetHeader('origin', OriginVal);

  LocalStreamId := 0;
  StreamIdSize := SizeOf(LocalStreamId);
  if (Api <> nil) then
    Api.GetParam(StreamState.Stream, $08000000, StreamIdSize, @LocalStreamId);

  SessionId := InterlockedIncrement64(FNextSessionId);
  Info.SessionId := SessionId;
  Info.Path      := Request.Path;
  Info.Origin    := OriginVal;
  Accepted := True;
  if Assigned(FOnSessionRequest) then
  begin
    try
      Accepted := FOnSessionRequest(Self, Info);
    except
      on E: Exception do
      begin
        Accepted := False;
      end;
    end;
  end;

  if not Accepted then
  begin
    Send403(Api, ConnCtx, StreamState.Stream);
    Exit;
  end;

  SessCtx               := Default(TWTSessionContext);
  SessCtx.SessionId     := SessionId;
  SessCtx.StreamId      := LocalStreamId;
  SessCtx.ConnectStream := StreamState.Stream;
  SessCtx.Connection    := ConnCtx.Connection;
  SessCtx.ConnCtx       := ConnCtx;
  SessCtx.Path          := Request.Path;
  SessCtx.Origin        := OriginVal;
  SessCtx.Active        := True;
  SessCtx.StreamCount   := 0;

  FLock.Enter;
  try
    FSessions.AddOrSetValue(StreamState.Stream, SessCtx);
  finally
    FLock.Leave;
  end;

  WTSendConnect200(Api, ConnCtx, StreamState.Stream, SessionId);
  if Assigned(FOnSessionReady) then
  begin
    FLock.Enter;
    try
      if FSessions.TryGetValue(StreamState.Stream, SessCtx) then
        FOnSessionReady(Self, @SessCtx);
    finally
      FLock.Leave;
    end;
  end;
  Result := True;
end;

procedure TWebTransportServer.HandleStreamClosed(ConnectStreamOrDataStream: HQUIC);
var
  SessCtx: TWTSessionContext;
  ConnectStream: HQUIC;
  ClosedSessionId: TWTSessionId;
  HasSessionClosed: Boolean;
  DataStreamList: TList<HQUIC>;
  Pair: TPair<HQUIC, HQUIC>;
begin
  HasSessionClosed := False;
  ClosedSessionId  := 0;
  DataStreamList   := TList<HQUIC>.Create;
  try
    FLock.Enter;
    try
      if FSessions.TryGetValue(ConnectStreamOrDataStream, SessCtx) then
      begin
        ClosedSessionId := SessCtx.SessionId;
        HasSessionClosed := True;
        FSessions.Remove(ConnectStreamOrDataStream);
        for Pair in FStreamToSession do
          if Pair.Value = ConnectStreamOrDataStream then
            DataStreamList.Add(Pair.Key);

        for ConnectStream in DataStreamList do
          FStreamToSession.Remove(ConnectStream);
      end
      else
      if FStreamToSession.TryGetValue(ConnectStreamOrDataStream, ConnectStream) then
      begin
        FStreamToSession.Remove(ConnectStreamOrDataStream);
        if FSessions.TryGetValue(ConnectStream, SessCtx) then
        begin
          if SessCtx.StreamCount > 0 then
            Dec(SessCtx.StreamCount);
          FSessions.AddOrSetValue(ConnectStream, SessCtx);
        end;
      end;
    finally
      FLock.Leave;
    end;

    if HasSessionClosed and Assigned(FOnSessionClosed) then
    begin
      try
        FOnSessionClosed(Self, ClosedSessionId);
      except
        on E: Exception do
          Logger.Error('[WebTransport] Exception in OnSessionClosed event (SessionId: %d): %s (%s)',
            [ClosedSessionId, E.Message, E.ClassName]);
      end;
    end;
  finally
    DataStreamList.Free;
  end;
end;

procedure TWebTransportServer.HandleConnectionClosed(Connection: HQUIC);
var
  SessList: TList<TWTSessionContext>;
  DataStreamList: TList<HQUIC>;
  Pair: TPair<HQUIC, TWTSessionContext>;
  StreamPair: TPair<HQUIC, HQUIC>;
  Sess: TWTSessionContext;
  StreamH: HQUIC;
begin
  SessList := TList<TWTSessionContext>.Create;
  DataStreamList := TList<HQUIC>.Create;
  try
    FLock.Enter;
    try
      for Pair in FSessions do
      begin
        if Pair.Value.Connection = Connection then
          SessList.Add(Pair.Value);
      end;

      for Sess in SessList do
      begin
        FSessions.Remove(Sess.ConnectStream);
        DataStreamList.Clear;
        for StreamPair in FStreamToSession do
        begin
          if StreamPair.Value = Sess.ConnectStream then
            DataStreamList.Add(StreamPair.Key);
        end;
        for StreamH in DataStreamList do
          FStreamToSession.Remove(StreamH);
      end;
    finally
      FLock.Leave;
    end;

    if Assigned(FOnSessionClosed) then
    begin
      for Sess in SessList do
      begin
        try
          FOnSessionClosed(Self, Sess.SessionId);
        except
          on E: Exception do
            Logger.Error('[WebTransport] Exception in OnSessionClosed event (SessionId: %d): %s (%s)',
              [Sess.SessionId, E.Message, E.ClassName]);
        end;
      end;
    end;
  finally
    DataStreamList.Free;
    SessList.Free;
  end;
end;

function TWebTransportServer.HandleNewStream(Connection: HQUIC; Stream: HQUIC; IsBidi: Boolean): Boolean;
begin
  Result := False;
end;

function TWebTransportServer.HandleStreamData(Stream: HQUIC; const Data: TBytes): Boolean;
var
  SessCtx: TWTSessionContext;
  ConnectStream: HQUIC;
  DecodeOffset: Integer;
  FrameType: UInt64;
  SessionId: UInt64;
  PayloadOffset: Integer;
  PayloadData: TBytes;
  TargetConnectStream: HQUIC;
  Found: Boolean;
  Pair: TPair<HQUIC, TWTSessionContext>;
begin
  Result := False;
  if Length(Data) = 0 then 
     Exit;

  TargetConnectStream := nil;
  PayloadOffset := 0;

  FLock.Enter;
  try
    if FStreamToSession.TryGetValue(Stream, ConnectStream) then
    begin
      TargetConnectStream := ConnectStream;
      PayloadOffset := 0;
    end
    else
    begin
      DecodeOffset := 0;
      if TQuicVarInt.Decode(Data, DecodeOffset, FrameType) then
      begin
        if (FrameType = WT_FRAME_BIDIR_STREAM) or (FrameType = WT_STREAM_TYPE_SESSION) then
        begin
          if TQuicVarInt.Decode(Data, DecodeOffset, SessionId) then
          begin
            Found := False;
            for Pair in FSessions do
            begin
              if (Pair.Value.StreamId = SessionId) or (Pair.Value.SessionId = SessionId) or (FSessions.Count = 1) then
              begin
                TargetConnectStream := Pair.Key;
                FStreamToSession.AddOrSetValue(Stream, TargetConnectStream);
                PayloadOffset := DecodeOffset;
                Found := True;
                Break;
              end;
            end;
            if not Found then 
			   Exit;
          end;
        end;
      end;
    end;

    if TargetConnectStream = nil then 
	   Exit;
    if not FSessions.TryGetValue(TargetConnectStream, SessCtx) then 
	   Exit;
  finally
    FLock.Leave;
  end;

  if PayloadOffset > 0 then
  begin
    if Length(Data) > PayloadOffset then
    begin
      SetLength(PayloadData, Length(Data) - PayloadOffset);
      Move(Data[PayloadOffset], PayloadData[0], Length(PayloadData));
    end
    else
      SetLength(PayloadData, 0);
  end
  else
    PayloadData := Data;

  Result := True;

  if (Length(PayloadData) > 0) and Assigned(FOnStreamData) then
  begin
    try
      FOnStreamData(Self, @SessCtx, Stream, PayloadData);
    except
      on E: Exception do
        Logger.Error('[WebTransport] Exception in OnStreamData event (SessionId: %d, Stream: %p): %s (%s)',
          [SessCtx.SessionId, Pointer(Stream), E.Message, E.ClassName]);
    end;
  end;
end;

procedure TWebTransportServer.HandleDatagram(Connection: HQUIC; const Data: TBytes);
var
  SessCtx: TWTSessionContext;
  Pair: TPair<HQUIC, TWTSessionContext>;
  Found: Boolean;
  DecodeOffset: Integer;
  QuarterStreamId: UInt64;
  TargetSessionId: TWTSessionId;
  Payload: TBytes;
begin
  if (Length(Data) = 0) or (not Assigned(FOnDatagram)) then Exit;

  DecodeOffset := 0;
  if TQuicVarInt.Decode(Data, DecodeOffset, QuarterStreamId) then
    TargetSessionId := QuarterStreamId shl 2
  else
    TargetSessionId := 0;

  Found := False;
  FLock.Enter;
  try
    for Pair in FSessions do
    begin
      if (Pair.Value.Connection = Connection) and
         ((Pair.Value.StreamId = TargetSessionId) or (Pair.Value.SessionId = TargetSessionId) or (FSessions.Count = 1)) then
      begin
        SessCtx := Pair.Value;
        Found := True;
        Break;
      end;
    end;
  finally
    FLock.Leave;
  end;

  if Found then
  begin
    if DecodeOffset < Length(Data) then
    begin
      SetLength(Payload, Length(Data) - DecodeOffset);
      Move(Data[DecodeOffset], Payload[0], Length(Payload));
    end
    else
      SetLength(Payload, 0);

    try
      FOnDatagram(Self, @SessCtx, Payload);
    except
      on E: Exception do
        Logger.Error('[WebTransport] Exception in OnDatagram event (SessionId: %d): %s (%s)',
          [SessCtx.SessionId, E.Message, E.ClassName]);
    end;
  end;
end;

procedure TWebTransportServer.Send403(Api: PQuicApiTable; ConnCtx: PConnectionContext; ConnectStream: HQUIC);
var
  SendCtx: PQuicSendContext;
  HdrBytes: TBytes;
  Status: QUIC_STATUS;
begin
  if (Api = nil) or (ConnectStream = nil) or (ConnCtx = nil) then 
     Exit;

  SetLength(HdrBytes, 6);
  HdrBytes[0] := $01;
  HdrBytes[1] := $04;
  HdrBytes[2] := $00;
  HdrBytes[3] := $00;
  HdrBytes[4] := $FF;
  HdrBytes[5] := $05;

  SendCtx := AllocWTSendContext(ConnCtx, Length(HdrBytes));
  Move(HdrBytes[0], SendCtx.QuicBuffer.Buffer^, Length(HdrBytes));

  Status := Api.StreamSend(ConnectStream, @SendCtx.QuicBuffer, 1, QUIC_SEND_FLAG_NONE, SendCtx);
  if QuicFailed(Status) then
  begin
    FreeWTSendContextOnError(SendCtx);
  end;
end;

end.
