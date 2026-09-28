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
    FAllowedOrigins: string;
    FDefaultAllowSessionWithoutHandler: Boolean;
    FSendDraft02Header: Boolean;
    FApi: PQuicApiTable;
    FOnSessionRequest: TOnWTSessionRequest;
    FOnSessionReady:   TOnWTSessionReady;
    FOnSessionClosed:  TOnWTSessionClosed;
    FOnStreamData:     TOnWTStreamData;
    FOnDatagram:       TOnWTDatagram;
    function IsOriginAllowed(const AOrigin: string): Boolean;
    procedure Send403(Api: PQuicApiTable; ConnCtx: PConnectionContext; ConnectStream: HQUIC);
  public
    constructor Create;
    destructor Destroy; override;
    procedure CloseSession(ConnectStream: HQUIC; ErrorCode: UInt64 = WT_SESSION_GONE);
    function HandleConnectRequest(Api: PQuicApiTable;
      H3State: THttp3ConnectionState;
      StreamState: THttp3StreamState;
      ConnCtx: PConnectionContext;
      const Request: THttp3RequestData): Boolean;
    procedure HandleStreamClosed(ConnectStreamOrDataStream: HQUIC);
    procedure HandleConnectionClosed(Connection: HQUIC);
    function HandleNewStream(Connection: HQUIC; Stream: HQUIC; IsBidi: Boolean): Boolean;
    function HandleStreamData(Connection: HQUIC; Stream: HQUIC; const Data: TBytes): Boolean; overload;
    function HandleStreamData(Stream: HQUIC; const Data: TBytes): Boolean; overload;
    procedure HandleDatagram(Connection: HQUIC; const Data: TBytes);
    property AllowedOrigins: string read FAllowedOrigins write FAllowedOrigins;
    property DefaultAllowSessionWithoutHandler: Boolean read FDefaultAllowSessionWithoutHandler write FDefaultAllowSessionWithoutHandler;
    property SendDraft02Header: Boolean read FSendDraft02Header write FSendDraft02Header;
    property Api: PQuicApiTable read FApi write FApi;
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

function TWebTransportServer.IsOriginAllowed(const AOrigin: string): Boolean;
var
  AllowedList: TArray<string>;
  AllowedItem: string;
  TrimmedOrigin: string;
begin
  Result := False;
  TrimmedOrigin := Trim(AOrigin);
  if TrimmedOrigin = '' then
    Exit(True);

  if (FAllowedOrigins = '*') or (FAllowedOrigins = '') then
    Exit(True);

  AllowedList := FAllowedOrigins.Split([',', ';']);
  for AllowedItem in AllowedList do
  begin
    if SameText(Trim(AllowedItem), TrimmedOrigin) or (Trim(AllowedItem) = '*') then
      Exit(True);
  end;
end;

constructor TWebTransportServer.Create;
begin
  inherited Create;
  FLock            := TCriticalSection.Create;
  FSessions        := TDictionary<HQUIC, TWTSessionContext>.Create;
  FStreamToSession := TDictionary<HQUIC, HQUIC>.Create;
  FNextSessionId   := 0;
  FAllowedOrigins  := '*';
  FDefaultAllowSessionWithoutHandler := False;
  FSendDraft02Header := False;
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

procedure TWebTransportServer.CloseSession(ConnectStream: HQUIC; ErrorCode: UInt64 = WT_SESSION_GONE);
const
  QUIC_STREAM_SHUTDOWN_FLAG_ABORT = $0006;
var
  ChildStreams: TList<HQUIC>;
  ChildStream: HQUIC;
  Pair: TPair<HQUIC, HQUIC>;
  SessCtx: TWTSessionContext;
  Api: PQuicApiTable;
  SessionId: TWTSessionId;
  HasSession: Boolean;
begin
  if ConnectStream = nil then Exit;
  ChildStreams := TList<HQUIC>.Create;
  try
    HasSession := False;
    SessionId := 0;
    Api := FApi;
    FLock.Enter;
    try
      if FSessions.TryGetValue(ConnectStream, SessCtx) then
      begin
        HasSession := True;
        SessionId := SessCtx.SessionId;
        if (Api = nil) and (SessCtx.ConnCtx <> nil) and (PConnectionContext(SessCtx.ConnCtx).Server <> nil) then
        begin
          var Svr := TQuicServer(PConnectionContext(SessCtx.ConnCtx).Server);
          if Svr.MsQuic <> nil then
            Api := Svr.MsQuic.Api;
        end;
      end;

      for Pair in FStreamToSession do
      begin
        if Pair.Value = ConnectStream then
          ChildStreams.Add(Pair.Key);
      end;

      for ChildStream in ChildStreams do
        FStreamToSession.Remove(ChildStream);

      if HasSession then
        FSessions.Remove(ConnectStream);
    finally
      FLock.Leave;
    end;

    if Api <> nil then
    begin
      for ChildStream in ChildStreams do
      begin
        try
          Api.StreamShutdown(ChildStream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, ErrorCode);
        except
        end;
      end;
      try
        Api.StreamShutdown(ConnectStream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, ErrorCode);
      except
      end;
    end;

    if HasSession and Assigned(FOnSessionClosed) then
    begin
      try
        FOnSessionClosed(Self, SessionId);
      except
        on E: Exception do
          Logger.Error('[WebTransport] Exception in OnSessionClosed: %s', [E.Message]);
      end;
    end;
  finally
    ChildStreams.Free;
  end;
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

  if Api <> nil then
    FApi := Api;

  if not SameText(Request.Method, 'CONNECT') then 
     Exit;
  if not Request.TryGetHeader(':protocol', ProtoVal) or 
          not SameText(ProtoVal, WT_PROTOCOL_HEADER_VALUE) then 
	 Exit;

  OriginVal := '';
  Request.TryGetHeader('origin', OriginVal);

  if not IsOriginAllowed(OriginVal) then
  begin
    Logger.Warn('[WebTransport] Session request rejected: disallowed origin "%s"', [OriginVal]);
    Send403(Api, ConnCtx, StreamState.Stream);
    Exit;
  end;

  LocalStreamId := 0;
  StreamIdSize := SizeOf(LocalStreamId);
  if (Api <> nil) then
    Api.GetParam(StreamState.Stream, $08000000, StreamIdSize, @LocalStreamId);

  SessionId := InterlockedIncrement64(FNextSessionId);
  Info.SessionId := SessionId;
  Info.Path      := Request.Path;
  Info.Origin    := OriginVal;

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
  end
  else
    Accepted := FDefaultAllowSessionWithoutHandler;

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
  SessCtx.Server        := Self;

  FLock.Enter;
  try
    FSessions.AddOrSetValue(StreamState.Stream, SessCtx);
  finally
    FLock.Leave;
  end;

  WTSendConnect200(Api, ConnCtx, StreamState.Stream, SessionId, FSendDraft02Header);
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
  IsConnectStream: Boolean;
begin
  if ConnectStreamOrDataStream = nil then Exit;
  IsConnectStream := False;
  FLock.Enter;
  try
    IsConnectStream := FSessions.ContainsKey(ConnectStreamOrDataStream);
    if not IsConnectStream then
      FStreamToSession.Remove(ConnectStreamOrDataStream);
  finally
    FLock.Leave;
  end;

  if IsConnectStream then
    CloseSession(ConnectStreamOrDataStream, WT_SESSION_GONE);
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
begin
  Result := HandleStreamData(nil, Stream, Data);
end;

function TWebTransportServer.HandleStreamData(Connection: HQUIC; Stream: HQUIC; const Data: TBytes): Boolean;
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
              if (Connection <> nil) and (Pair.Value.Connection <> Connection) then
                Continue;

              if (Pair.Value.StreamId = SessionId) or (Pair.Value.SessionId = SessionId) then
              begin
                TargetConnectStream := Pair.Key;
                FStreamToSession.AddOrSetValue(Stream, TargetConnectStream);
                PayloadOffset := DecodeOffset;
                Found := True;
                Break;
              end;
            end;

            if (not Found) and (Connection <> nil) then
            begin
              for Pair in FSessions do
              begin
                if (Pair.Value.Connection = Connection) and
                   ((Pair.Value.StreamId = SessionId) or (Pair.Value.SessionId = SessionId)) then
                begin
                  TargetConnectStream := Pair.Key;
                  FStreamToSession.AddOrSetValue(Stream, TargetConnectStream);
                  PayloadOffset := DecodeOffset;
                  Found := True;
                  Break;
                end;
              end;
            end;

            if not Found then 
            begin
              Logger.Warn('[WebTransport] Stream rejected: session %d not found on connection', [SessionId]);
              Exit;
            end;
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
  if not TQuicVarInt.Decode(Data, DecodeOffset, QuarterStreamId) then
  begin
    Logger.Warn('[WebTransport] Failed to decode Quarter Stream ID from datagram');
    Exit;
  end;

  TargetSessionId := QuarterStreamId shl 2;

  Found := False;
  FLock.Enter;
  try
    for Pair in FSessions do
    begin
      if (Pair.Value.Connection = Connection) and
         ((Pair.Value.StreamId = TargetSessionId) or (Pair.Value.SessionId = TargetSessionId) or
          ((Pair.Value.StreamId shr 2) = QuarterStreamId)) then
      begin
        SessCtx := Pair.Value;
        Found := True;
        Break;
      end;
    end;
  finally
    FLock.Leave;
  end;

  if not Found then
  begin
    Logger.Warn('[WebTransport] Dropped datagram for unknown session (QuarterStreamId: %d, TargetSessionId: %d)',
      [QuarterStreamId, TargetSessionId]);
    Exit;
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
