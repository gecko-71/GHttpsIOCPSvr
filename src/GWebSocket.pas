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

unit GWebSocket;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections, System.SyncObjs,
  Winapi.Windows, Winapi.WinSock2, WinApiAdditions, OverlappedExPool;

const
  MAX_WS_MESSAGE_SIZE = 10485760;

type
  TWebSocketOpcode = (
    wsOpContinuation = $0,
    wsOpText = $1,
    wsOpBinary = $2,
    wsOpClose = $8,
    wsOpPing = $9,
    wsOpPong = $A
  );

  TWebSocketFrame = record
    Fin: Boolean;
    Opcode: TWebSocketOpcode;
    Masked: Boolean;
    PayloadLen: UInt64;
    MaskKey: array[0..3] of Byte;
    Payload: TBytes;
    class function Decode(const RawData: TBytes; var Offset: Integer; out Frame: TWebSocketFrame; var ErrorMsg: string): Boolean; static;
    class function IsValidUTF8(const Bytes: TBytes): Boolean; static;
    class function Encode(Opcode: TWebSocketOpcode; const Payload: TBytes; Fin: Boolean = True): TBytes; static;
  end;

  TWebSocketSession = class
  private
    FSocket: TSocket;
    FReadOverlapped: POverlappedEx;
    FWriteOverlapped: POverlappedEx;
    FIncomingBuffer: TBytes;
    FFramePayloadBuffer: TBytes;
    FCurrentOpcode: TWebSocketOpcode;
    FWriteQueue: TQueue<TBytes>;
    FLock: TCriticalSection;
    FLastActivityTime: UInt64;
    FRefCount: Integer;
    FOverlappedPool: TOverlappedExPool;
    FRoutePath: string;
    procedure Unmask(var Frame: TWebSocketFrame);
    function GetIsTLS: Boolean;
  public
    WritePending: Integer;
    InCleanup: Integer;
    CloseReceived: Boolean;
    PingPending: Integer;
    procedure AddRef;
    procedure Release;
    constructor Create(ASocket: TSocket; AReadOverlapped: POverlappedEx; AOverlappedPool: TOverlappedExPool);
    destructor Destroy; override;
    procedure QueueSendFrame(Opcode: TWebSocketOpcode; const Payload: TBytes);
    procedure SendText(const Text: string);
    procedure SendBinary(const Data: TBytes);
    function DequeueNextWrite(out Chunk: TBytes): Boolean;
    function HasPendingWrites: Boolean;
    function ProcessIncomingPlaintext(const PlainData: TBytes; out CloseConnection: Boolean): TArray<TBytes>;
    function DetachWriteOverlapped: POverlappedEx;
    property Socket: TSocket read FSocket;
    property ReadOverlapped: POverlappedEx read FReadOverlapped write FReadOverlapped;
    property WriteOverlapped: POverlappedEx read FWriteOverlapped write FWriteOverlapped;
    property LastActivityTime: UInt64 read FLastActivityTime write FLastActivityTime;
    property RoutePath: string read FRoutePath write FRoutePath;
    property LastReceivedOpcode: TWebSocketOpcode read FCurrentOpcode;
    property IsTLS: Boolean read GetIsTLS;
    property IsSecure: Boolean read GetIsTLS;
  end;

  TWebSocketManager = class
  private
    FSessions: TObjectList<TWebSocketSession>;
    FLock: TCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddSession(Session: TWebSocketSession);
    procedure RemoveSession(Session: TWebSocketSession);
    procedure Broadcast(const MessageText: string);
    function AcquireSessionList: TList<TWebSocketSession>;
    function GetSessionCount: Integer;
  end;

implementation

{ TWebSocketFrame }

class function TWebSocketFrame.Decode(const RawData: TBytes; var Offset: Integer; out Frame: TWebSocketFrame; var ErrorMsg: string): Boolean;
var
  LenByte: Byte;
  I: Integer;
  LocalOffset: Integer;
begin
  Result := False;
  ErrorMsg := '';
  LocalOffset := Offset;
  
  if Length(RawData) - LocalOffset < 2 then
    Exit;

  Frame.Fin := (RawData[LocalOffset] and $80) <> 0;
  var OpVal: Byte := RawData[LocalOffset] and $0F;
  case OpVal of
    $0: Frame.Opcode := wsOpContinuation;
    $1: Frame.Opcode := wsOpText;
    $2: Frame.Opcode := wsOpBinary;
    $8: Frame.Opcode := wsOpClose;
    $9: Frame.Opcode := wsOpPing;
    $A: Frame.Opcode := wsOpPong;
  else
    begin
      ErrorMsg := 'Invalid or reserved opcode: ' + IntToStr(OpVal);
      Exit;
    end;
  end;

  LenByte := RawData[LocalOffset + 1];
  Frame.Masked := (LenByte and $80) <> 0;
  Frame.PayloadLen := LenByte and $7F;

  Inc(LocalOffset, 2);

  if Frame.PayloadLen = 126 then
  begin
    if Length(RawData) - LocalOffset < 2 then Exit;
    Frame.PayloadLen := (RawData[LocalOffset] shl 8) or RawData[LocalOffset + 1];
    Inc(LocalOffset, 2);
  end
  else if Frame.PayloadLen = 127 then
  begin
    if Length(RawData) - LocalOffset < 8 then
      Exit;
    if (RawData[LocalOffset] and $80) <> 0 then
    begin
      ErrorMsg := 'Invalid MSB in 64-bit frame length';
      Exit;
    end;
    {$Q-}
    Frame.PayloadLen := 0;
    for I := 0 to 7 do
      Frame.PayloadLen := (Frame.PayloadLen shl 8) or UInt64(RawData[LocalOffset + I]);
    {$IFDEF OVERFLOWCHECKS_ON}{$Q+}{$ENDIF}
    Inc(LocalOffset, 8);
  end;

  if (Frame.Opcode in [wsOpClose, wsOpPing, wsOpPong]) and (Frame.PayloadLen > 125) then
  begin
    ErrorMsg := 'Control frame payload exceeds 125 bytes (RFC 6455 5.5)';
    Exit;
  end;

  if Frame.Masked then
  begin
    if Length(RawData) - LocalOffset < 4 then 
	   Exit;
    Move(RawData[LocalOffset], Frame.MaskKey[0], 4);
    Inc(LocalOffset, 4);
  end;

  if Frame.PayloadLen > MAX_WS_MESSAGE_SIZE then
  begin
    ErrorMsg := 'Payload too large';
    Exit;
  end;

  var RemainingBytes: Int64 := Int64(Length(RawData)) - Int64(LocalOffset);
  if (RemainingBytes < 0) or (UInt64(RemainingBytes) < Frame.PayloadLen) then
    Exit;

  SetLength(Frame.Payload, Frame.PayloadLen);
  if Frame.PayloadLen > 0 then
  begin
    Move(RawData[LocalOffset], Frame.Payload[0], Frame.PayloadLen);
    Inc(LocalOffset, Frame.PayloadLen);
  end;

  Offset := LocalOffset;
  Result := True;
end;

class function TWebSocketFrame.IsValidUTF8(const Bytes: TBytes): Boolean;
var
  I, Len, Needed: Integer;
  B: Byte;
begin
  Result := True;
  Len := Length(Bytes);
  I := 0;
  while I < Len do
  begin
    B := Bytes[I];
    if B <= $7F then
    begin
      Inc(I);
      Continue;
    end;

    if (B < $C2) or (B > $F4) then
      Exit(False);

    if B <= $DF then
      Needed := 1
    else if B <= $EF then
      Needed := 2
    else
      Needed := 3;

    if I + Needed >= Len then
      Exit(False);

    if (B = $E0) and (Bytes[I + 1] < $A0) then
      Exit(False);
    if (B = $ED) and (Bytes[I + 1] > $9F) then
      Exit(False);
    if (B = $F0) and (Bytes[I + 1] < $90) then
      Exit(False);
    if (B = $F4) and (Bytes[I + 1] > $8F) then
      Exit(False);

    Inc(I);
    while Needed > 0 do
    begin
      if (Bytes[I] < $80) or (Bytes[I] > $BF) then
        Exit(False);
      Inc(I);
      Dec(Needed);
    end;
  end;
end;

class function TWebSocketFrame.Encode(Opcode: TWebSocketOpcode; const Payload: TBytes; Fin: Boolean): TBytes;
var
  HeaderLen: Integer;
  PayloadLen: UInt64;
  Offset: Integer;
  I: Integer;
begin
  PayloadLen := Length(Payload);
  HeaderLen := 2;
  if PayloadLen >= 65536 then
    HeaderLen := HeaderLen + 8
  else if PayloadLen >= 126 then
    HeaderLen := HeaderLen + 2;

  SetLength(Result, HeaderLen + Integer(PayloadLen));
  if Fin then
    Result[0] := $80 or Byte(Opcode)
  else
    Result[0] := $00 or Byte(Opcode);

  Offset := 1;
  if PayloadLen < 126 then
  begin
    Result[Offset] := Byte(PayloadLen);
    Inc(Offset);
  end
  else if PayloadLen < 65536 then
  begin
    Result[Offset] := 126;
    Result[Offset + 1] := (PayloadLen shr 8) and $FF;
    Result[Offset + 2] := PayloadLen and $FF;
    Inc(Offset, 3);
  end
  else
  begin
    Result[Offset] := 127;
    Inc(Offset);
    for I := 7 downto 0 do
    begin
      Result[Offset + I] := (PayloadLen and $FF);
      PayloadLen := PayloadLen shr 8;
    end;
    Inc(Offset, 8);
  end;

  if Length(Payload) > 0 then
    Move(Payload[0], Result[Offset], Length(Payload));
end;

{ TWebSocketSession }
constructor TWebSocketSession.Create(ASocket: TSocket; AReadOverlapped: POverlappedEx; AOverlappedPool: TOverlappedExPool);
begin
  inherited Create;
  FSocket := ASocket;
  FReadOverlapped := AReadOverlapped;
  FOverlappedPool := AOverlappedPool;
  FLock := TCriticalSection.Create;
  FWriteQueue := TQueue<TBytes>.Create;
  WritePending := 0;
  InCleanup := 0;
  FRefCount := 1;
  CloseReceived := False;
  FLastActivityTime := GetTickCount64;
  SetLength(FIncomingBuffer, 0);
  SetLength(FFramePayloadBuffer, 0);
end;

procedure TWebSocketSession.AddRef;
begin
  TInterlocked.Increment(FRefCount);
end;

procedure TWebSocketSession.Release;
begin
  if TInterlocked.Decrement(FRefCount) <= 0 then
    Free;
end;

function TWebSocketSession.GetIsTLS: Boolean;
begin
  if Assigned(FReadOverlapped) then
    Result := FReadOverlapped^.IsTLS
  else
    Result := False;
end;

destructor TWebSocketSession.Destroy;
var
  LocalQueue: TQueue<TBytes>;
  LocalLock: TCriticalSection;
  Chunk: TBytes;
begin
  LocalQueue := nil;
  LocalLock := FLock;
  if Assigned(LocalLock) then
  begin
    LocalLock.Enter;
    try
      LocalQueue := FWriteQueue;
      FWriteQueue := nil;
    finally
      LocalLock.Leave;
    end;
  end
  else
  begin
    LocalQueue := FWriteQueue;
    FWriteQueue := nil;
  end;

  if Assigned(LocalQueue) then
  begin
    while LocalQueue.Count > 0 do
    begin
      Chunk := LocalQueue.Dequeue;
      SetLength(Chunk, 0);
    end;
    LocalQueue.Free;
  end;

  SetLength(FIncomingBuffer, 0);
  SetLength(FFramePayloadBuffer, 0);

  if Assigned(LocalLock) then
  begin
    FLock := nil;
    LocalLock.Free;
  end;

  inherited Destroy;
end;

procedure TWebSocketSession.Unmask(var Frame: TWebSocketFrame);
var
  PayloadLength: Integer;
  Mask32: UInt32;
  P32: PCardinal;
  P8: PByte;
  Chunks, Remainder, I: Integer;
begin
  if not Frame.Masked then
    Exit;
  PayloadLength := Length(Frame.Payload);
  if PayloadLength <= 0 then
    Exit;

  Move(Frame.MaskKey[0], Mask32, 4);

  P32 := PCardinal(@Frame.Payload[0]);
  Chunks := PayloadLength div 4;
  Remainder := PayloadLength mod 4;

  for I := 0 to Chunks - 1 do
  begin
    P32^ := P32^ xor Mask32;
    Inc(P32);
  end;

  if Remainder > 0 then
  begin
    P8 := PByte(P32);
    for I := 0 to Remainder - 1 do
    begin
      P8^ := P8^ xor Frame.MaskKey[I];
      Inc(P8);
    end;
  end;
end;

function TWebSocketSession.ProcessIncomingPlaintext(const PlainData: TBytes; out CloseConnection: Boolean): TArray<TBytes>;
var
  Offset, PrevOffset: Integer;
  Frame: TWebSocketFrame;
  ErrorMsg: string;
  MsgList: TList<TBytes>;
  Lock: TCriticalSection;
begin
  CloseConnection := False;
  if InCleanup <> 0 then
  begin
    CloseConnection := True;
    Exit(nil);
  end;

  MsgList := TList<TBytes>.Create;
  try
    Lock := FLock;
    if not Assigned(Lock) or (InCleanup <> 0) then
    begin
      CloseConnection := True;
      Exit;
    end;

    Lock.Acquire;
    try
      if InCleanup <> 0 then
      begin
        CloseConnection := True;
        Exit;
      end;

      if Length(PlainData) > 0 then
      begin
        var PrevLen := Length(FIncomingBuffer);
        SetLength(FIncomingBuffer, PrevLen + Length(PlainData));
        Move(PlainData[0], FIncomingBuffer[PrevLen], Length(PlainData));
      end;

      Offset := 0;
      while Offset < Length(FIncomingBuffer) do
      begin
        PrevOffset := Offset;
        ErrorMsg := '';
        if not TWebSocketFrame.Decode(FIncomingBuffer, Offset, Frame, ErrorMsg) then
        begin
          if ErrorMsg <> '' then
          begin
            CloseConnection := True;
            Exit;
          end;
          if Offset = PrevOffset then
            Break;

          CloseConnection := True;
          Exit;
        end;

        if not Frame.Masked then
        begin
          CloseConnection := True;
          Exit;
        end;

        Unmask(Frame);

        if (Frame.Opcode = wsOpText) and not TWebSocketFrame.IsValidUTF8(Frame.Payload) then
        begin
          QueueSendFrame(wsOpClose, [$03, $EF]);
          CloseConnection := True;
          Exit;
        end;

        if Frame.Opcode in [wsOpClose, wsOpPing, wsOpPong] then
        begin
          if not Frame.Fin then
          begin
            CloseConnection := True;
            Exit;
          end;

          case Frame.Opcode of
            wsOpPing:
            begin
              FLastActivityTime := GetTickCount64;
              QueueSendFrame(wsOpPong, Frame.Payload);
            end;
            wsOpPong:
            begin
              PingPending := 0;
            end;
            wsOpClose:
            begin
              QueueSendFrame(wsOpClose, Frame.Payload);
              CloseReceived := True;
              CloseConnection := True;
              Exit;
            end;

          end;
          Continue;
        end;

        FLastActivityTime := GetTickCount64;
        if Frame.Opcode = wsOpText then
        begin
          if Length(FFramePayloadBuffer) > 0 then
          begin
            CloseConnection := True;
            Exit;
          end;
          if UInt64(Length(Frame.Payload)) > MAX_WS_MESSAGE_SIZE then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $F1));
            CloseConnection := True;
            Exit;
          end;
          FCurrentOpcode := wsOpText;
          FFramePayloadBuffer := Copy(Frame.Payload, 0, Length(Frame.Payload));
        end
        else if Frame.Opcode = wsOpBinary then
        begin
          if Length(FFramePayloadBuffer) > 0 then
          begin
            CloseConnection := True;
            Exit;
          end;
          if UInt64(Length(Frame.Payload)) > MAX_WS_MESSAGE_SIZE then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $F1));
            CloseConnection := True;
            Exit;
          end;
          FCurrentOpcode := wsOpBinary;
          FFramePayloadBuffer := Copy(Frame.Payload, 0, Length(Frame.Payload));
        end
        else if Frame.Opcode = wsOpContinuation then
        begin
          if Length(FFramePayloadBuffer) = 0 then
          begin
            CloseConnection := True;
            Exit;
          end;

          if UInt64(Length(FFramePayloadBuffer)) + UInt64(Length(Frame.Payload)) > MAX_WS_MESSAGE_SIZE then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $F1));
            CloseConnection := True;
            Exit;
          end;

          if Length(Frame.Payload) > 0 then
          begin
            var OldLen := Length(FFramePayloadBuffer);
            SetLength(FFramePayloadBuffer, OldLen + Length(Frame.Payload));
            Move(Frame.Payload[0], FFramePayloadBuffer[OldLen], Length(Frame.Payload));
          end;
        end;

        if Frame.Fin and (Frame.Opcode in [wsOpText, wsOpBinary, wsOpContinuation]) then
        begin
          MsgList.Add(Copy(FFramePayloadBuffer, 0, Length(FFramePayloadBuffer)));
          SetLength(FFramePayloadBuffer, 0);
        end;
      end;

      if Offset > 0 then
      begin
        if Offset < Length(FIncomingBuffer) then
        begin
          System.Move(FIncomingBuffer[Offset], FIncomingBuffer[0], Length(FIncomingBuffer) - Offset);
          SetLength(FIncomingBuffer, Length(FIncomingBuffer) - Offset);
        end
        else
          SetLength(FIncomingBuffer, 0);
      end;
    finally
      FLock.Leave;
    end;
    Result := MsgList.ToArray;
  finally
    MsgList.Free;
  end;
end;

procedure TWebSocketSession.QueueSendFrame(Opcode: TWebSocketOpcode; const Payload: TBytes);
var
  RawFrame: TBytes;
  ChunkSize: Integer;
  Offset: Integer;
  CurrentChunk: TBytes;
  CurrentOpcode: TWebSocketOpcode;
  IsFin: Boolean;
begin
  ChunkSize := 8192;

  if Length(Payload) <= ChunkSize then
  begin
    RawFrame := TWebSocketFrame.Encode(Opcode, Payload, True);
    var Lock := FLock;
    if Assigned(Lock) then
    begin
      Lock.Acquire;
      try
        if Assigned(FWriteQueue) then
          FWriteQueue.Enqueue(RawFrame);
      finally
        Lock.Leave;
      end;
    end;
  end
  else
  begin
    Offset := 0;
    CurrentOpcode := Opcode;
    while Offset < Length(Payload) do
    begin
      var Remaining := Length(Payload) - Offset;
      var Len := ChunkSize;
      if Remaining < Len then
        Len := Remaining;

      SetLength(CurrentChunk, Len);
      Move(Payload[Offset], CurrentChunk[0], Len);

      IsFin := (Offset + Len) >= Length(Payload);
      RawFrame := TWebSocketFrame.Encode(CurrentOpcode, CurrentChunk, IsFin);

      var Lock := FLock;
      if Assigned(Lock) then
      begin
        Lock.Acquire;
        try
          if Assigned(FWriteQueue) then
            FWriteQueue.Enqueue(RawFrame);
        finally
          Lock.Leave;
        end;
      end;

      Inc(Offset, Len);
      CurrentOpcode := wsOpContinuation;
    end;
  end;
end;

procedure TWebSocketSession.SendText(const Text: string);
begin
  QueueSendFrame(wsOpText, TEncoding.UTF8.GetBytes(Text));
end;

procedure TWebSocketSession.SendBinary(const Data: TBytes);
begin
  QueueSendFrame(wsOpBinary, Data);
end;

function TWebSocketSession.DequeueNextWrite(out Chunk: TBytes): Boolean;
var
  Lock: TCriticalSection;
begin
  Result := False;
  Lock := FLock;
  if Assigned(Lock) then
  begin
    Lock.Acquire;
    try
      if Assigned(FWriteQueue) and (FWriteQueue.Count > 0) then
      begin
        Chunk := FWriteQueue.Dequeue;
        Result := True;
      end;
    finally
      Lock.Leave;
    end;
  end;
end;

function TWebSocketSession.DetachWriteOverlapped: POverlappedEx;
begin
  Result := POverlappedEx(InterlockedExchangePointer(Pointer(FWriteOverlapped), nil));
end;

function TWebSocketSession.HasPendingWrites: Boolean;
var
  Lock: TCriticalSection;
begin
  Result := False;
  Lock := FLock;
  if Assigned(Lock) then
  begin
    Lock.Acquire;
    try
      if Assigned(FWriteQueue) then
        Result := FWriteQueue.Count > 0;
    finally
      Lock.Leave;
    end;
  end;
end;

{ TWebSocketManager }

constructor TWebSocketManager.Create;
begin
  inherited Create;
  FSessions := TObjectList<TWebSocketSession>.Create(False);
  FLock := TCriticalSection.Create;
end;

destructor TWebSocketManager.Destroy;
var
  Session: TWebSocketSession;
begin
  FLock.Acquire;
  try
    if Assigned(FSessions) then
    begin
      for Session in FSessions do
      begin
        if Assigned(Session) then
        begin
          TInterlocked.Exchange(Session.InCleanup, 1);
          Session.Release;
        end;
      end;
      FSessions.Clear;
    end;
  finally
    FLock.Leave;
  end;
  if Assigned(FSessions) then 
     FreeAndNil(FSessions);
  if Assigned(FLock) then 
     FreeAndNil(FLock);
  inherited Destroy;
end;

procedure TWebSocketManager.AddSession(Session: TWebSocketSession);
begin
  FLock.Acquire;
  try
    FSessions.Add(Session);
  finally
    FLock.Leave;
  end;
end;

procedure TWebSocketManager.RemoveSession(Session: TWebSocketSession);
begin
  FLock.Acquire;
  try
    FSessions.Remove(Session);
  finally
    FLock.Leave;
  end;
end;

function TWebSocketManager.AcquireSessionList: TList<TWebSocketSession>;
var
  Session: TWebSocketSession;
begin
  Result := TList<TWebSocketSession>.Create;
  FLock.Acquire;
  try
    for Session in FSessions do
    begin
      if Assigned(Session) and (Session.InCleanup = 0) then
      begin
        Session.AddRef;
        Result.Add(Session);
      end;
    end;
  finally
    FLock.Leave;
  end;
end;

procedure TWebSocketManager.Broadcast(const MessageText: string);
var
  List: TList<TWebSocketSession>;
  Session: TWebSocketSession;
  Payload: TBytes;
begin
  Payload := TEncoding.UTF8.GetBytes(MessageText);
  List := AcquireSessionList;
  try
    for Session in List do
    begin
      if Assigned(Session) and (Session.InCleanup = 0) then
        Session.QueueSendFrame(wsOpText, Payload);
    end;
  finally
    for Session in List do
      Session.Release;
    List.Free;
  end;
end;

function TWebSocketManager.GetSessionCount: Integer;
var
  Session: TWebSocketSession;
begin
  Result := 0;
  FLock.Acquire;
  try
    for Session in FSessions do
    begin
      if Assigned(Session) and (Session.InCleanup = 0) then
        Inc(Result);
    end;
  finally
    FLock.Leave;
  end;
end;

end.
