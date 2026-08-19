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
unit Net.Http3Server;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections, System.SyncObjs,
  Winapi.Windows, WinApi.MsQuic, Net.MsQuic, Net.Http3Frames, Net.QPACK,
  Net.Http3Request, Net.Http3Response;

type
  TOnHttp3Request = procedure(Request: THttp3Request; Response: THttp3Response) of object;

  PHttp3SendContext = ^THttp3SendContext;
  THttp3SendContext = record
    QuicBuf: Pointer;
    BufferCount: Integer;
    IsFin: Boolean;
    FullBody: TBytes;
    CurrentOffset: Integer;
    TotalSize: Integer;
    ChunkSize: Integer;
    IsStreaming: Boolean;
  end;


  PQUIC_BUFFER_ARRAY = ^TQUIC_BUFFER_ARRAY;
  TQUIC_BUFFER_ARRAY = array[0..63] of QUIC_BUFFER;

  TStreamState = class
  public
    Stream: TMsQuicStream;
    IsControlStream: Boolean;
    RecvBuffer: TBytes;
    HeadersDecoded: Boolean;
    RequestHeaders: THttpHeaders;
    RequestBody: TBytes;
    IsUnidi: Boolean;
    UnidiTypeParsed: Boolean;
    UnidiType: UInt64;
    VarIntScratchBuf: TBytes;
    SendCompleted: Boolean;
    ShutdownCompleted: Boolean;
    ResponseSent: Boolean;
    ActiveSendCtx: Pointer; // Wskaźnik do aktywnego PHttp3SendContext (do bezpiecznego czyszczenia wycieków)
    Lock: TCriticalSection;
    constructor Create(AStream: TMsQuicStream);
    destructor Destroy; override;
  end;

  THttp3Server = class
  private
    FApi: PQUIC_API_TABLE;
    FVersion: Integer;
    FRegistration: TMsQuicRegistration;
    FConfig: TMsQuicConfiguration;
    FListener: TMsQuicListener;
    FOnRequest: TOnHttp3Request;

    FConnections: TObjectList<TMsQuicConnection>;
    FStreams: TObjectDictionary<HQUIC, TStreamState>;
    FLock: TCriticalSection;
    FStoppingFlag: Integer;
    FStopping: Boolean;
    procedure OnNewConnection(Sender: TMsQuicListener; ConnHandle: HQUIC);
    procedure OnConnected(Sender: TMsQuicConnection);
    procedure OnConnectionShutdown(Sender: TMsQuicConnection);
    procedure OnPeerStreamStarted(Sender: TMsQuicConnection; StrmHandle: HQUIC; Flags: ULONG);
    procedure OnStreamReceive(Sender: TMsQuicStream; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG);
    procedure OnStreamSendComplete(Sender: TMsQuicStream; Canceled: Boolean; Context: Pointer);
    procedure OnStreamShutdownComplete(Sender: TMsQuicStream);
    procedure OnControlStreamSendComplete(Sender: TMsQuicStream; Canceled: Boolean; Context: Pointer);
    procedure CleanupConnectionStreams(Conn: TMsQuicConnection; DetachOnly: Boolean = False);
    procedure ProcessStreamData(State: TStreamState);
  public
    constructor Create(const CertHashHex: string; const CertStoreName: string = 'My'; ServerCertStore: HCERTSTORE = nil);
    constructor CreateWithCertContext(CertContext: Pointer);
    destructor Destroy; override;
    procedure Start(Port: Word = 4433);
    procedure Stop;
    property OnRequest: TOnHttp3Request read FOnRequest write FOnRequest;
  end;

implementation

uses Quick.Logger, GRequest;

{ TStreamState }
constructor TStreamState.Create(AStream: TMsQuicStream);
begin
  inherited Create;
  Lock := TCriticalSection.Create;
  Stream := AStream;
  IsControlStream := False;
  HeadersDecoded := False;
  if Stream <> nil then
    IsUnidi := (Stream.GetID and 2) <> 0
  else
    IsUnidi := False;
  UnidiTypeParsed := False;
  UnidiType := 0;
  SetLength(RecvBuffer, 0);
  SetLength(RequestBody, 0);
  SetLength(RequestHeaders, 0);
  SetLength(VarIntScratchBuf, 0);
  SendCompleted := False;
  ShutdownCompleted := False;
  ActiveSendCtx := nil;
end;

destructor TStreamState.Destroy;
var
  SendCtx: PHttp3SendContext;
  BufArray: PQUIC_BUFFER_ARRAY;
  I: Integer;
begin
  // Czyszczenie aktywnego kontekstu wysyłania HTTP/3 w przypadku nagłego zamknięcia strumienia
  if ActiveSendCtx <> nil then
  begin
    SendCtx := PHttp3SendContext(ActiveSendCtx);
    ActiveSendCtx := nil;
    if SendCtx^.QuicBuf <> nil then
    begin
      BufArray := PQUIC_BUFFER_ARRAY(SendCtx^.QuicBuf);
      for I := 0 to SendCtx^.BufferCount - 1 do
      begin
        if BufArray^[I].Buffer <> nil then
          FreeMem(BufArray^[I].Buffer);
      end;
      FreeMem(SendCtx^.QuicBuf);
      SendCtx^.QuicBuf := nil;
    end;
    SetLength(SendCtx^.FullBody, 0);
    FreeMem(SendCtx);
  end;

  if Assigned(Stream) then
  begin
    try
      Stream.Free;
    except
      on E: Exception do
        Logger.Warn('Error freeing H3 stream: ' + E.Message);
    end;
    Stream := nil;
  end;
  if Assigned(Lock) then
  begin
    try
      Lock.Free;
    except
      on E: Exception do
        Logger.Warn('Error freeing H3 stream lock: ' + E.Message);
    end;
    Lock := nil;
  end;
  inherited;
end;

{ THttp3Server }
constructor THttp3Server.Create(const CertHashHex: string; const CertStoreName: string; ServerCertStore: HCERTSTORE);
var
  Status: QUIC_STATUS;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FConnections := TObjectList<TMsQuicConnection>.Create(True); // OwnsObjects = True
  FStreams := TObjectDictionary<HQUIC, TStreamState>.Create([doOwnsValues]);

  Status := MsQuicOpenVersion(2, FApi);
  FVersion := 2;
  if Status <> 0 then
  begin
    Status := MsQuicOpenVersion(1, FApi);
    FVersion := 1;
  end;
    
  if Status <> 0 then
    raise Exception.CreateFmt('Failed to open MsQuic API (Status: 0x%x)', [Status]);

  FRegistration := TMsQuicRegistration.Create(FApi, 'Http3Server');
  FConfig := TMsQuicConfiguration.Create(FRegistration, ['h3'], FVersion);
  FConfig.ServerCertStore := ServerCertStore;
  FConfig.LoadCredentialFromHash(CertHashHex, CertStoreName);
  FListener := TMsQuicListener.Create(FRegistration);
  FListener.OnNewConnection := OnNewConnection;
end;

constructor THttp3Server.CreateWithCertContext(CertContext: Pointer);
var
  Status: QUIC_STATUS;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FConnections := TObjectList<TMsQuicConnection>.Create(True);
  FStreams := TObjectDictionary<HQUIC, TStreamState>.Create([doOwnsValues]);

  Status := MsQuicOpenVersion(2, FApi);
  FVersion := 2;
  if Status <> 0 then
  begin
    Status := MsQuicOpenVersion(1, FApi);
    FVersion := 1;
  end;

  if Status <> 0 then
    raise Exception.CreateFmt('Failed to open MsQuic API (Status: 0x%x)', [Status]);

  FRegistration := TMsQuicRegistration.Create(FApi, 'Http3Server');
  FConfig := TMsQuicConfiguration.Create(FRegistration, ['h3'], FVersion);
  FConfig.LoadCredentialFromContext(CertContext);
  FListener := TMsQuicListener.Create(FRegistration);
  FListener.OnNewConnection := OnNewConnection;
end;

destructor THttp3Server.Destroy;
begin
  Logger.Info(Format('[LOG-H3-STOP-1] THttp3Server.Destroy START (Thread:%d)', [GetCurrentThreadId]));
  try
    Stop;
  except
    on E: Exception do
      Logger.Info('[LOG-H3-STOP-ERR-STOP] Error in Stop: ' + E.Message);
  end;
  Logger.Info('[LOG-H3-STOP-2] Stop completed');

  if FStreams <> nil then
  begin
    try
      Logger.Info(Format('[LOG-H3-STOP-3] Freeing FStreams (count=%d)', [FStreams.Count]));
      FreeAndNil(FStreams);
      Logger.Info('[LOG-H3-STOP-3-DONE] FStreams freed');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-STREAMS] Ignorowanie błędu zwalniania FStreams: ' + E.Message);
    end;
  end;

  if FConnections <> nil then
  begin
    try
      Logger.Info(Format('[LOG-H3-STOP-4] Freeing FConnections (count=%d)', [FConnections.Count]));
      FreeAndNil(FConnections);
      Logger.Info('[LOG-H3-STOP-4-DONE] FConnections freed');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-CONNS] Ignorowanie błędu zwalniania FConnections: ' + E.Message);
    end;
  end;

  if FListener <> nil then
  begin
    try
      Logger.Info('[LOG-H3-STOP-5] Freeing FListener...');
      FreeAndNil(FListener);
      Logger.Info('[LOG-H3-STOP-5-DONE] FListener freed');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-LISTENER] Ignorowanie błędu zwalniania FListener: ' + E.Message);
    end;
  end;

  if FConfig <> nil then
  begin
    try
      Logger.Info('[LOG-H3-STOP-6] Freeing FConfig...');
      FreeAndNil(FConfig);
      Logger.Info('[LOG-H3-STOP-6-DONE] FConfig freed');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-CONFIG] Ignorowanie błędu zwalniania FConfig: ' + E.Message);
    end;
  end;

  if FRegistration <> nil then
  begin
    try
      Logger.Info('[LOG-H3-STOP-7] Freeing FRegistration (calling RegistrationClose)...');
      FreeAndNil(FRegistration);
      Logger.Info('[LOG-H3-STOP-7-DONE] FRegistration freed - RegistrationClose returned!');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-REG] Ignorowanie błędu zwalniania FRegistration: ' + E.Message);
    end;
  end;

  if FApi <> nil then
  begin
    try
      Logger.Info('[LOG-H3-STOP-7B] Calling MsQuicClose...');
      MsQuicClose(FApi);
      FApi := nil;
      Logger.Info('[LOG-H3-STOP-7B-DONE] MsQuicClose returned');
    except
      on E: Exception do
        Logger.Info('[LOG-H3-STOP-ERR-API] Ignorowanie błędu zamknięcia MsQuic API: ' + E.Message);
    end;
  end;

  if FLock <> nil then
  begin
    try
      FreeAndNil(FLock);
    except
      on E: Exception do
        Logger.Warn('Error freeing H3 server lock: ' + E.Message);
    end;
  end;

  Logger.Info('[LOG-H3-STOP-8] THttp3Server.Destroy END - SUCCESS!');
  inherited;
end;



procedure THttp3Server.Start(Port: Word);
begin
  FListener.Start(['h3'], Port);
end;

procedure THttp3Server.Stop;
var
  PrevFlag: Integer;
  I: Integer;
begin
  PrevFlag := InterlockedCompareExchange(FStoppingFlag, 1, 0);
  if PrevFlag <> 0 then
  begin
    Logger.Info(Format('[LOG-H3-STOP-RACE] THttp3Server.Stop wywołany po raz 2+ (Thread:%d) - ignoruję!', [GetCurrentThreadId]));
    Exit;
  end;
  FStopping := True;
  Logger.Info(Format('[LOG-H3-STOP-SUB-1] THttp3Server.Stop START (Thread:%d)', [GetCurrentThreadId]));

  if FListener <> nil then
  begin
    Logger.Info('[LOG-H3-STOP-SUB-2] ListenerStop...');
    FListener.Stop;
    Logger.Info('[LOG-H3-STOP-SUB-2-DONE] ListenerStop returned');
  end;

  if (FConnections <> nil) and (FConnections.Count > 0) then
  begin
    Logger.Info(Format('[LOG-H3-STOP-SUB-3] ConnectionShutdown SILENT dla %d połączeń...', [FConnections.Count]));
    for I := 0 to FConnections.Count - 1 do
    begin
      try
        if FConnections[I] <> nil then
          FConnections[I].Shutdown(0);
      except
        Logger.Info('Ignoruj błędy - połączenie mogło już być zamknięte');
      end;
    end;
    Logger.Info('[LOG-H3-STOP-SUB-3-DONE] ConnectionShutdown done');
    Sleep(100);
  end;

  FLock.Enter;
  try
    if FStreams <> nil then
    begin
      Logger.Info(Format('[LOG-H3-STOP-SUB-5] Clearing FStreams (count=%d)...', [FStreams.Count]));
      FStreams.Clear;
      Logger.Info('[LOG-H3-STOP-SUB-5-DONE] FStreams.Clear returned');
    end;

    if FConnections <> nil then
    begin
      Logger.Info(Format('[LOG-H3-STOP-SUB-6] Clearing FConnections (count=%d)...', [FConnections.Count]));
      FConnections.Clear;
      Logger.Info('[LOG-H3-STOP-SUB-6-DONE] FConnections.Clear returned');
    end;
  finally
    FLock.Leave;
  end;

  Logger.Info('[LOG-H3-STOP-SUB-7] THttp3Server.Stop END');
end;


procedure THttp3Server.OnNewConnection(Sender: TMsQuicListener; ConnHandle: HQUIC);
var
  Conn: TMsQuicConnection;
begin
  if FStopping then
  begin
    FApi.ConnectionClose(ConnHandle);
    Exit;
  end;

  Conn := TMsQuicConnection.Create(FApi, ConnHandle);
  Conn.SetConfiguration(FConfig);
  Conn.OnConnected := OnConnected;
  Conn.OnShutdown := OnConnectionShutdown;
  Conn.OnPeerStreamStarted := OnPeerStreamStarted;

  FLock.Enter;
  try
    FConnections.Add(Conn);
  finally
    FLock.Leave;
  end;
end;

procedure THttp3Server.OnConnected(Sender: TMsQuicConnection);
var
  ControlStream, QEncoderStream, QDecoderStream: TMsQuicStream;
  SettingsPayload, ControlPrefix, FullData, QEncPrefix, QDecPrefix: TBytes;
  QuicBuf, QuicBufEnc, QuicBufDec: PQUIC_BUFFER;
  QuicBufContext: PHttp3SendContext;
  StateControl, StateEncoder, StateDecoder, OldState: TStreamState;
begin
  if FStopping then Exit;
  Logger.Info(Format('[LOG-H3] THttp3Server.OnConnected (Thread:%d)', [GetCurrentThreadId]));

  ControlStream := TMsQuicStream.Create(Sender, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
  ControlStream.OnSendComplete := OnControlStreamSendComplete;
  ControlStream.OnShutdownComplete := OnStreamShutdownComplete;
  ControlStream.Start(QUIC_STREAM_START_FLAG_NONE);

  SettingsPayload := BuildSettingsFrame([
    HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0,
    HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE, 65536,
    HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS, 0
  ]);

  ControlPrefix := VarIntEncode(0); // Control Stream Type 0x00
  SetLength(FullData, Length(ControlPrefix) + Length(SettingsPayload));
  Move(ControlPrefix[0], FullData[0], Length(ControlPrefix));
  Move(SettingsPayload[0], FullData[Length(ControlPrefix)], Length(SettingsPayload));

  QuicBuf := AllocMem(SizeOf(QUIC_BUFFER));
  QuicBuf^.Length := Length(FullData);
  QuicBuf^.Buffer := AllocMem(QuicBuf^.Length);
  Move(FullData[0], QuicBuf^.Buffer^, QuicBuf^.Length);

  StateControl := TStreamState.Create(ControlStream);
  StateControl.IsControlStream := True;
  StateControl.IsUnidi := True;
  ControlStream.UserData := StateControl;

  QEncoderStream := TMsQuicStream.Create(Sender, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
  QEncoderStream.OnSendComplete := OnControlStreamSendComplete;
  QEncoderStream.OnShutdownComplete := OnStreamShutdownComplete;
  QEncoderStream.Start(QUIC_STREAM_START_FLAG_NONE);
  
  QEncPrefix := VarIntEncode(2);
  QuicBufEnc := AllocMem(SizeOf(QUIC_BUFFER));
  QuicBufEnc^.Length := Length(QEncPrefix);
  QuicBufEnc^.Buffer := AllocMem(QuicBufEnc^.Length);
  Move(QEncPrefix[0], QuicBufEnc^.Buffer^, QuicBufEnc^.Length);
  
  StateEncoder := TStreamState.Create(QEncoderStream);
  StateEncoder.IsControlStream := True;
  StateEncoder.IsUnidi := True;
  QEncoderStream.UserData := StateEncoder;

  QDecoderStream := TMsQuicStream.Create(Sender, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL);
  QDecoderStream.OnSendComplete := OnControlStreamSendComplete;
  QDecoderStream.OnShutdownComplete := OnStreamShutdownComplete;
  QDecoderStream.Start(QUIC_STREAM_START_FLAG_NONE);

  QDecPrefix := VarIntEncode(3);
  QuicBufDec := AllocMem(SizeOf(QUIC_BUFFER));
  QuicBufDec^.Length := Length(QDecPrefix);
  QuicBufDec^.Buffer := AllocMem(QuicBufDec^.Length);
  Move(QDecPrefix[0], QuicBufDec^.Buffer^, QuicBufDec^.Length);

  StateDecoder := TStreamState.Create(QDecoderStream);
  StateDecoder.IsControlStream := True;
  StateDecoder.IsUnidi := True;
  QDecoderStream.UserData := StateDecoder;

  FLock.Enter;
  try
    if FStreams.TryGetValue(ControlStream.Handle, OldState) then
    begin
      OldState.Stream.Detach;
      FStreams.Remove(ControlStream.Handle);
    end;
    FStreams.Add(ControlStream.Handle, StateControl);

    if FStreams.TryGetValue(QEncoderStream.Handle, OldState) then
    begin
      OldState.Stream.Detach;
      FStreams.Remove(QEncoderStream.Handle);
    end;
    FStreams.Add(QEncoderStream.Handle, StateEncoder);

    if FStreams.TryGetValue(QDecoderStream.Handle, OldState) then
    begin
      OldState.Stream.Detach;
      FStreams.Remove(QDecoderStream.Handle);
    end;
    FStreams.Add(QDecoderStream.Handle, StateDecoder);
  finally
    FLock.Leave;
  end;

  QuicBufContext := AllocMem(SizeOf(THttp3SendContext));
  QuicBufContext^.QuicBuf := QuicBuf;
  QuicBufContext^.BufferCount := 1;
  QuicBufContext^.IsFin := False;
  ControlStream.Send(QuicBuf, 1, QUIC_SEND_FLAG_NONE, QuicBufContext);

  QuicBufContext := AllocMem(SizeOf(THttp3SendContext));
  QuicBufContext^.QuicBuf := QuicBufEnc;
  QuicBufContext^.BufferCount := 1;
  QuicBufContext^.IsFin := False;
  QEncoderStream.Send(QuicBufEnc, 1, QUIC_SEND_FLAG_NONE, QuicBufContext);

  QuicBufContext := AllocMem(SizeOf(THttp3SendContext));
  QuicBufContext^.QuicBuf := QuicBufDec;
  QuicBufContext^.BufferCount := 1;
  QuicBufContext^.IsFin := False;
  QDecoderStream.Send(QuicBufDec, 1, QUIC_SEND_FLAG_NONE, QuicBufContext);
end;


procedure THttp3Server.OnControlStreamSendComplete(Sender: TMsQuicStream; Canceled: Boolean; Context: Pointer);
var
  SendCtx: PHttp3SendContext;
  BufArray: PQUIC_BUFFER_ARRAY;
begin
  if Context <> nil then
  begin
    SendCtx := PHttp3SendContext(Context);
    if SendCtx^.QuicBuf <> nil then
    begin
      BufArray := PQUIC_BUFFER_ARRAY(SendCtx^.QuicBuf);
      if (SendCtx^.BufferCount > 0) and (BufArray^[0].Buffer <> nil) then
        FreeMem(BufArray^[0].Buffer);
      FreeMem(SendCtx^.QuicBuf);
    end;
    FreeMem(SendCtx);
  end;
end;

procedure THttp3Server.CleanupConnectionStreams(Conn: TMsQuicConnection; DetachOnly: Boolean);
var
  StreamHandle: HQUIC;
  State: TStreamState;
  KeysToRemove: TList<HQUIC>;
begin
  KeysToRemove := TList<HQUIC>.Create;
  try
    for StreamHandle in FStreams.Keys do
    begin
      State := FStreams[StreamHandle];
      if (State <> nil) and (State.Stream <> nil) and (State.Stream.Connection = Conn) then
        KeysToRemove.Add(StreamHandle);
    end;
    
    for StreamHandle in KeysToRemove do
    begin
      if FStreams.TryGetValue(StreamHandle, State) then
      begin
        if (State <> nil) and (State.Stream <> nil) then
          State.Stream.Detach;
        FStreams.Remove(StreamHandle);
      end;
    end;
  finally
    KeysToRemove.Free;
  end;
end;

procedure THttp3Server.OnConnectionShutdown(Sender: TMsQuicConnection);
begin
  if FStopping then
     Exit;
  FLock.Enter;
  try
    CleanupConnectionStreams(Sender, True);
    try
      FConnections.Remove(Sender);
    except
      on E: Exception do
        Logger.Warn('Error removing H3 connection: ' + E.Message);
    end;
  finally
    FLock.Leave;
  end;
end;


procedure THttp3Server.OnPeerStreamStarted(Sender: TMsQuicConnection; StrmHandle: HQUIC; Flags: ULONG);
var
  Stream: TMsQuicStream;
  State, OldState: TStreamState;
begin
  if FStopping then Exit;
  Logger.Info(Format('[LOG-H3] OnPeerStreamStarted: StrmHandle=%p (Thread:%d)', [Pointer(StrmHandle), GetCurrentThreadId]));

  Stream := TMsQuicStream.Create(FApi, StrmHandle);
  Stream.Connection := Sender;
  Stream.OnReceive := OnStreamReceive;
  Stream.OnSendComplete := OnStreamSendComplete;
  Stream.OnShutdownComplete := OnStreamShutdownComplete;

  State := TStreamState.Create(Stream);
  State.IsUnidi := (Flags and QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) <> 0;
  Stream.UserData := State;

  FLock.Enter;
  try
    if FStreams.TryGetValue(StrmHandle, OldState) then
    begin
      OldState.Stream.Detach;
      FStreams.Remove(StrmHandle);
    end;
    FStreams.Add(StrmHandle, State);
  finally
    FLock.Leave;
  end;
end;


procedure THttp3Server.OnStreamReceive(Sender: TMsQuicStream; Buffers: PQUIC_BUFFER; BufferCount: ULONG; Flags: ULONG);
var
  State: TStreamState;
  I: Integer;
  OldLen: Integer;
  Request: THttp3Request;
  Response: THttp3Response;
  HeadersFrame, DataFrameHeader, ChunkData, HeaderCombined, Body: TBytes;
  TotalBodyLen, InitialChunkLen, TotalInitialLen: Integer;
  STREAM_CHUNK_SIZE: Integer;
  SendFlags: ULONG;
  QuicBufArray: PQUIC_BUFFER_ARRAY;
  QuicBufContext: PHttp3SendContext;
  HasState: Boolean;
  LogLen: Integer;
begin
  if FStopping then Exit;
  Logger.Info(Format('[LOG-H3-DEBUG] OnStreamReceive triggered for StrmHandle=%p', [Pointer(Sender.Handle)]));

  State := TStreamState(Sender.UserData);
  if State = nil then
  begin
    FLock.Enter;
    try
      if not FStreams.TryGetValue(Sender.Handle, State) then
      begin
        Logger.Info(Format('[LOG-H3-ERROR] OnStreamReceive: FStreams.TryGetValue failed for StrmHandle=%p', [Pointer(Sender.Handle)]));
        Exit;
      end;
      Sender.UserData := State;
    finally
      FLock.Leave;
    end;
  end;

  State.Lock.Enter;
  try
    LogLen := 0;
    if (BufferCount > 0) and (Buffers <> nil) then
      LogLen := Buffers^.Length;
    Logger.Info(Format('[LOG-H3] OnStreamReceive: %d buffers, total len=%d (Thread:%d)', [BufferCount, LogLen, GetCurrentThreadId]));

    if (BufferCount > 0) and (Buffers <> nil) then
    begin
      for I := 0 to BufferCount - 1 do
      begin
        OldLen := Length(State.RecvBuffer);
        SetLength(State.RecvBuffer, OldLen + Integer(Buffers^.Length));
        Move(Buffers^.Buffer^, State.RecvBuffer[OldLen], Buffers^.Length);
        Inc(Buffers);
      end;
    end;

    ProcessStreamData(State);

    Logger.Info(Format('[LOG-H3-DEBUG] OnStreamReceive flags: 0x%x (FIN=%s, HeadersDecoded=%s, IsControl=%s)', [
      Flags,
      BoolToStr((Flags and QUIC_RECEIVE_FLAG_FIN) <> 0, True),
      BoolToStr(State.HeadersDecoded, True),
      BoolToStr(State.IsControlStream, True)
    ]));

    if (Flags and QUIC_RECEIVE_FLAG_FIN) <> 0 then
    begin
      if Assigned(FOnRequest) and State.HeadersDecoded and not State.IsControlStream and not State.ResponseSent then
      begin
        State.ResponseSent := True;
        Request := THttp3Request.Create(State.RequestHeaders, Sender.Handle);
        Response := THttp3Response.Create;
        try
          Request.AppendBody(State.RequestBody);
          try
            var UriErr: string;
            if not TUriValidator.ValidateURI(Request.Path, UriErr) then
            begin
              Logger.Warn('H3 WAF: Security violation detected in URI: ' + Request.Path + ' Error: ' + UriErr);
              Response.StatusCode := 400;
              Response.SetBodyString('400 Bad Request: Security violation detected', 'text/html');
            end
            else
              FOnRequest(Request, Response);
          except
            on E: Exception do
            begin
              Logger.Info(Format('[LOG-H3-ERROR] Exception in FOnRequest: %s', [E.Message]));
              Response.StatusCode := 500;
              Response.SetBodyString('500 Internal Server Error: ' + E.Message, 'text/plain');
            end;
          end;

          HeadersFrame := Response.GetHeadersFrame;
          Body := Response.BodyBytes;
          TotalBodyLen := Length(Body);

          DataFrameHeader := VarIntEncode(HTTP3_FRAME_DATA);
          ChunkData := VarIntEncode(TotalBodyLen);

          SetLength(HeaderCombined, Length(HeadersFrame) + Length(DataFrameHeader) + Length(ChunkData));
          if Length(HeadersFrame) > 0 then
            Move(HeadersFrame[0], HeaderCombined[0], Length(HeadersFrame));
          Move(DataFrameHeader[0], HeaderCombined[Length(HeadersFrame)], Length(DataFrameHeader));
          Move(ChunkData[0], HeaderCombined[Length(HeadersFrame) + Length(DataFrameHeader)], Length(ChunkData));

          TotalInitialLen := Length(HeaderCombined) + TotalBodyLen;
          QuicBufArray := PQUIC_BUFFER_ARRAY(AllocMem(SizeOf(QUIC_BUFFER)));
          QuicBufArray^[0].Length := TotalInitialLen;
          QuicBufArray^[0].Buffer := AllocMem(TotalInitialLen);

          if Length(HeaderCombined) > 0 then
            Move(HeaderCombined[0], QuicBufArray^[0].Buffer^, Length(HeaderCombined));
          if TotalBodyLen > 0 then
            Move(Body[0], PByte(QuicBufArray^[0].Buffer)[Length(HeaderCombined)], TotalBodyLen);

          QuicBufContext := AllocMem(SizeOf(THttp3SendContext));
          QuicBufContext^.QuicBuf := QuicBufArray;
          QuicBufContext^.BufferCount := 1;
          QuicBufContext^.FullBody := Body;
          QuicBufContext^.CurrentOffset := TotalBodyLen;
          QuicBufContext^.TotalSize := TotalBodyLen;
          QuicBufContext^.IsFin := True;
          QuicBufContext^.IsStreaming := False;
          State.ActiveSendCtx := QuicBufContext;

          Sender.Send(PQUIC_BUFFER(QuicBufArray), 1, QUIC_SEND_FLAG_FIN, QuicBufContext);

        finally
          Request.Free;
          Response.Free;
        end;
      end;
    end;
  finally
    State.Lock.Leave;
  end;
end;

procedure THttp3Server.OnStreamSendComplete(Sender: TMsQuicStream; Canceled: Boolean; Context: Pointer);
var
  SendCtx: PHttp3SendContext;
  BufArray: PQUIC_BUFFER_ARRAY;
  I: Integer;
  NextChunkLen: Integer;
  NextBufArray: PQUIC_BUFFER_ARRAY;
  SendFlags: ULONG;
  State: TStreamState;
begin
  if Context = nil then Exit;

  SendCtx := PHttp3SendContext(Context);

  if SendCtx^.QuicBuf <> nil then
  begin
    BufArray := PQUIC_BUFFER_ARRAY(SendCtx^.QuicBuf);
    for I := 0 to SendCtx^.BufferCount - 1 do
    begin
      if BufArray^[I].Buffer <> nil then
        FreeMem(BufArray^[I].Buffer);
    end;
    FreeMem(SendCtx^.QuicBuf);
    SendCtx^.QuicBuf := nil;
  end;

  if Canceled or SendCtx^.IsFin or (SendCtx^.CurrentOffset >= SendCtx^.TotalSize) or not SendCtx^.IsStreaming then
  begin
    FLock.Enter;
    try
      if FStreams.TryGetValue(Sender.Handle, State) then
      begin
        if State.ActiveSendCtx = Context then
          State.ActiveSendCtx := nil;
      end;
    finally
      FLock.Leave;
    end;
    SetLength(SendCtx^.FullBody, 0);
    FreeMem(SendCtx);
    Exit;
  end;

  NextChunkLen := SendCtx^.TotalSize - SendCtx^.CurrentOffset;
  if NextChunkLen > SendCtx^.ChunkSize then
    NextChunkLen := SendCtx^.ChunkSize;

  NextBufArray := PQUIC_BUFFER_ARRAY(AllocMem(SizeOf(QUIC_BUFFER)));
  NextBufArray^[0].Length := NextChunkLen;
  NextBufArray^[0].Buffer := AllocMem(NextChunkLen);
  Move(SendCtx^.FullBody[SendCtx^.CurrentOffset], NextBufArray^[0].Buffer^, NextChunkLen);

  Inc(SendCtx^.CurrentOffset, NextChunkLen);

  SendCtx^.QuicBuf := NextBufArray;
  SendCtx^.BufferCount := 1;

  if SendCtx^.CurrentOffset >= SendCtx^.TotalSize then
  begin
    SendCtx^.IsFin := True;
    SendFlags := QUIC_SEND_FLAG_FIN;
  end
  else
  begin
    SendFlags := 0;
  end;

  try
    Sender.Send(PQUIC_BUFFER(NextBufArray), 1, SendFlags, SendCtx);
  except
    on E: Exception do
    begin
      Logger.Error('Error sending next QUIC stream chunk: ' + E.Message);
      if NextBufArray^[0].Buffer <> nil then
        FreeMem(NextBufArray^[0].Buffer);
      FreeMem(NextBufArray);
      SetLength(SendCtx^.FullBody, 0);
      FreeMem(SendCtx);
    end;
  end;
end;

procedure THttp3Server.OnStreamShutdownComplete(Sender: TMsQuicStream);
var
  State: TStreamState;
begin
  if FStopping then Exit;

  FLock.Enter;
  try
    if FStreams.TryGetValue(Sender.Handle, State) then
    begin
      if State.IsControlStream or State.IsUnidi then
         Exit;

      if (State <> nil) and (State.Stream <> nil) then
        State.Stream.Detach;
      FStreams.Remove(Sender.Handle);
    end;
  finally
    FLock.Leave;
  end;
end;


procedure THttp3Server.ProcessStreamData(State: TStreamState);
var
  Offset: Integer;
  Frame: THttp3Frame;
  OldLen, ExpectedLen, Available: Integer;
  Prefix: Byte;
begin
  if State.IsUnidi then
  begin
    if not State.UnidiTypeParsed then
    begin
      if Length(State.RecvBuffer) > 0 then
      begin
        OldLen := Length(State.VarIntScratchBuf);
        SetLength(State.VarIntScratchBuf, OldLen + Length(State.RecvBuffer));
        Move(State.RecvBuffer[0], State.VarIntScratchBuf[OldLen], Length(State.RecvBuffer));
        SetLength(State.RecvBuffer, 0);
      end;

      if Length(State.VarIntScratchBuf) > 0 then
      begin
        Prefix := State.VarIntScratchBuf[0] shr 6;
        case Prefix of
          0: ExpectedLen := 1;
          1: ExpectedLen := 2;
          2: ExpectedLen := 4;
          3: ExpectedLen := 8;
        else ExpectedLen := 1;
        end;

        if Length(State.VarIntScratchBuf) >= ExpectedLen then
        begin
          Offset := 0;
          try
            State.UnidiType := VarIntDecode(State.VarIntScratchBuf, Offset);
            State.UnidiTypeParsed := True;
            Available := Length(State.VarIntScratchBuf) - Offset;
            if Available > 0 then
            begin
              SetLength(State.RecvBuffer, Available);
              Move(State.VarIntScratchBuf[Offset], State.RecvBuffer[0], Available);
            end;
            SetLength(State.VarIntScratchBuf, 0);
          except
            on E: Exception do
              Exit;
          end;
        end
        else
          Exit;
      end
      else
        Exit;
    end;

    if State.UnidiTypeParsed and (State.UnidiType <> 0) then
    begin
      SetLength(State.RecvBuffer, 0);
      Exit;
    end;
  end;

  Offset := 0;

  Logger.Info(Format('[LOG-H3-DEBUG] ProcessStreamData BIDI: buffer len=%d', [Length(State.RecvBuffer)]));

  while Offset < Length(State.RecvBuffer) do
  begin
    if ParseHttp3Frame(State.RecvBuffer, Offset, Frame) then
    begin
      Logger.Info(Format('[LOG-H3-DEBUG] Parsed frame: Type=%d, PayloadLen=%d', [Frame.FrameType, Length(Frame.Payload)]));
      try
        case Frame.FrameType of
          HTTP3_FRAME_HEADERS:
            begin
              State.RequestHeaders := QpackDecode(Frame.Payload);
              State.HeadersDecoded := True;
              Logger.Info(Format('[LOG-H3-HDR] Decoded %d headers:', [Length(State.RequestHeaders)]));
              for var HIdx: Integer := 0 to Length(State.RequestHeaders) - 1 do
                Logger.Info(Format('[LOG-H3-HDR]   %s: %s', [State.RequestHeaders[HIdx].Name, State.RequestHeaders[HIdx].Value]));
            end;

          HTTP3_FRAME_DATA:
            begin
              OldLen := Length(State.RequestBody);
              SetLength(State.RequestBody, OldLen + Length(Frame.Payload));
              Move(Frame.Payload[0], State.RequestBody[OldLen], Length(Frame.Payload));
            end;
        end;
      except
        on E: Exception do
        begin
          Logger.Info('[LOG-H3-ERROR] Błąd dekodowania ramki: ' + E.Message);
          State.Stream.Shutdown(QUIC_STREAM_SHUTDOWN_FLAG_ABORT, $0200);
          Exit;
        end;
      end;

      OldLen := Length(State.RecvBuffer) - Offset;
      if OldLen > 0 then
      begin
        Move(State.RecvBuffer[Offset], State.RecvBuffer[0], OldLen);
        SetLength(State.RecvBuffer, OldLen);
      end
      else
        SetLength(State.RecvBuffer, 0);
      Offset := 0;
    end
    else
    begin
      Logger.Info('[LOG-H3-DEBUG] ParseHttp3Frame returned False (waiting for more data).');
      Break;
    end;
  end;
end;

end.
