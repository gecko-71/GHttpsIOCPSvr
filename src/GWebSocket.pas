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
    class function IsValidUTF8Ptr(P: PByte; Len: Integer): Boolean; static;
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
    FLastMessageOpcodes: TArray<TWebSocketOpcode>;
    FFragmentInProgress: Boolean;
    FWriteQueue: TQueue<TBytes>;
    FLock: TCriticalSection;
    FLastActivityTime: UInt64;
    FRefCount: Integer;
    FOverlappedPool: TOverlappedExPool;
    FRoutePath: string;
    FSubProtocol: string;
    FCachedRouteHandler: IInterface;
    FCachedRawRouteHandler: IInterface;
    FBatchActive: Boolean;
    FBatchLen: Integer;
    FBatchOverlapped: POverlappedEx;
    FWriteQueueCount: Integer;
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
    function TryFastSendText(const Text: string): Boolean;
    function TryFastSendRaw(Opcode: TWebSocketOpcode; PayloadPtr: PByte; PayloadLen: Integer): Boolean;
    procedure BeginFastBatch;
    procedure EndFastBatch;
    procedure SendText(const Text: string);
    procedure SendRaw(Opcode: TWebSocketOpcode; PayloadPtr: PByte; PayloadLen: Integer);
    procedure SendBinary(const Data: TBytes);
    function DequeueNextWrite(out Chunk: TBytes): Boolean;
    function HasPendingWrites: Boolean;
    function ProcessIncomingPlaintext(const PlainData: TBytes; out CloseConnection: Boolean): TArray<TBytes>;
    function ProcessIncomingPlaintextPtr(DataPtr: PByte; DataLen: Integer; out CloseConnection: Boolean): TArray<TBytes>;
    function TryProcessSingleFramePtr(DataPtr: PByte; DataLen: Integer; OutBuf: PByte; OutBufCap: Integer;
      out OutLen: Integer; out OutOpcode: TWebSocketOpcode; out CloseConnection: Boolean): Boolean;
    function TryProcessNextFramePtr(DataPtr: PByte; DataLen: Integer; OutBuf: PByte; OutBufCap: Integer;
      out OutLen, ConsumedBytes: Integer; out OutOpcode: TWebSocketOpcode; out CloseConnection: Boolean): Boolean;
    function DetachWriteOverlapped: POverlappedEx;
    property Socket: TSocket read FSocket;
    property ReadOverlapped: POverlappedEx read FReadOverlapped write FReadOverlapped;
    property WriteOverlapped: POverlappedEx read FWriteOverlapped write FWriteOverlapped;
    property LastActivityTime: UInt64 read FLastActivityTime write FLastActivityTime;
    property RoutePath: string read FRoutePath write FRoutePath;
    property SubProtocol: string read FSubProtocol write FSubProtocol;
    property CachedRouteHandler: IInterface read FCachedRouteHandler write FCachedRouteHandler;
    property CachedRawRouteHandler: IInterface read FCachedRawRouteHandler write FCachedRawRouteHandler;
    property LastReceivedOpcode: TWebSocketOpcode read FCurrentOpcode;
    property LastMessageOpcodes: TArray<TWebSocketOpcode> read FLastMessageOpcodes;
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
  if (RawData[LocalOffset] and $70) <> 0 then
  begin
    ErrorMsg := 'Non-zero RSV bits received without negotiated extension (RFC 6455 5.2)';
    Exit;
  end;
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
    if Length(RawData) - LocalOffset < 2 then
      Exit;
    Frame.PayloadLen := (RawData[LocalOffset] shl 8) or RawData[LocalOffset + 1];
    if Frame.PayloadLen < 126 then
    begin
      ErrorMsg := 'Non-minimal 16-bit payload length encoding (RFC 6455 5.2)';
      Exit;
    end;
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
    if Frame.PayloadLen < 65536 then
    begin
      ErrorMsg := 'Non-minimal 64-bit payload length encoding (RFC 6455 5.2)';
      Exit;
    end;
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

class function TWebSocketFrame.IsValidUTF8Ptr(P: PByte; Len: Integer): Boolean;
var
  I, Needed: Integer;
  B: Byte;
begin
  Result := True;
  if (Len <= 0) or (P = nil) then
    Exit;
  I := 0;
  while I < Len do
  begin
    B := P[I];
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

    if (B = $E0) and (P[I + 1] < $A0) then
      Exit(False);
    if (B = $ED) and (P[I + 1] > $9F) then
      Exit(False);
    if (B = $F0) and (P[I + 1] < $90) then
      Exit(False);
    if (B = $F4) and (P[I + 1] > $8F) then
      Exit(False);

    Inc(I);
    while Needed > 0 do
    begin
      if (P[I] < $80) or (P[I] > $BF) then
        Exit(False);
      Inc(I);
      Dec(Needed);
    end;
  end;
end;

class function TWebSocketFrame.IsValidUTF8(const Bytes: TBytes): Boolean;
begin
  if Length(Bytes) = 0 then
    Exit(True);
  Result := IsValidUTF8Ptr(@Bytes[0], Length(Bytes));
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
  FCachedRouteHandler := nil;
  FCachedRawRouteHandler := nil;
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
  FCachedRouteHandler := nil;
  FCachedRawRouteHandler := nil;

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

function TWebSocketSession.TryProcessSingleFramePtr(DataPtr: PByte; DataLen: Integer; OutBuf: PByte; OutBufCap: Integer;
  out OutLen: Integer; out OutOpcode: TWebSocketOpcode; out CloseConnection: Boolean): Boolean;
var
  Consumed: Integer;
begin
  Result := TryProcessNextFramePtr(DataPtr, DataLen, OutBuf, OutBufCap, OutLen, Consumed, OutOpcode, CloseConnection) and
            (Consumed = DataLen);
end;

function TWebSocketSession.TryProcessNextFramePtr(DataPtr: PByte; DataLen: Integer; OutBuf: PByte; OutBufCap: Integer;
  out OutLen, ConsumedBytes: Integer; out OutOpcode: TWebSocketOpcode; out CloseConnection: Boolean): Boolean;
var
  B0, B1, Rsv, OpByte, Len7: Byte;
  HdrLen, PayLen, I, Chunks, Rem: Integer;
  MaskKey: array[0..3] of Byte;
  Mask32: UInt32;
  Src32, Dst32: PCardinal;
  Src8, Dst8: PByte;
begin
  Result := False;
  OutLen := 0;
  ConsumedBytes := 0;
  OutOpcode := wsOpText;
  CloseConnection := False;
  if (InCleanup <> 0) or (DataLen < 6) or (DataPtr = nil) or (OutBuf = nil) then
    Exit;

  if (Length(FIncomingBuffer) <> 0) or FFragmentInProgress then
    Exit;

  B0 := DataPtr[0];
  B1 := DataPtr[1];
  Rsv := B0 and $70;
  OpByte := B0 and $0F;
  Len7 := B1 and $7F;
  if ((B0 and $80) = 0) or (Rsv <> 0) or ((B1 and $80) = 0) or
     ((OpByte <> Byte(Ord(wsOpText))) and (OpByte <> Byte(Ord(wsOpBinary)))) or (Len7 >= 127) then
    Exit;

  if Len7 < 126 then
  begin
    HdrLen := 6;
    PayLen := Len7;
  end
  else
  begin
    if DataLen < 8 then
      Exit;
    HdrLen := 8;
    PayLen := (Integer(DataPtr[2]) shl 8) or Integer(DataPtr[3]);
    if PayLen < 126 then
      Exit;
  end;

  if (HdrLen + PayLen > DataLen) or (PayLen > OutBufCap) or (PayLen > MAX_WS_MESSAGE_SIZE) then
    Exit;

  Move(DataPtr[HdrLen - 4], MaskKey[0], 4);
  if PayLen > 0 then
  begin
    Move(MaskKey[0], Mask32, 4);
    Src32 := PCardinal(@DataPtr[HdrLen]);
    Dst32 := PCardinal(OutBuf);
    Chunks := PayLen div 4;
    Rem := PayLen mod 4;
    for I := 0 to Chunks - 1 do
    begin
      Dst32^ := Src32^ xor Mask32;
      Inc(Src32);
      Inc(Dst32);
    end;
    if Rem > 0 then
    begin
      Src8 := PByte(Src32);
      Dst8 := PByte(Dst32);
      for I := 0 to Rem - 1 do
      begin
        Dst8^ := Src8^ xor MaskKey[I];
        Inc(Src8);
        Inc(Dst8);
      end;
    end;
  end;
  if (OpByte = Byte(Ord(wsOpText))) and not TWebSocketFrame.IsValidUTF8Ptr(OutBuf, PayLen) then
  begin
    QueueSendFrame(wsOpClose, TBytes.Create($03, $EF));
    CloseConnection := True;
    Exit;
  end;
  FLastActivityTime := GetTickCount64;
  FCurrentOpcode := TWebSocketOpcode(OpByte);
  OutLen := PayLen;
  ConsumedBytes := HdrLen + PayLen;
  OutOpcode := FCurrentOpcode;
  Result := True;
end;

function TWebSocketSession.ProcessIncomingPlaintext(const PlainData: TBytes; out CloseConnection: Boolean): TArray<TBytes>;
begin
  if Length(PlainData) > 0 then
    Result := ProcessIncomingPlaintextPtr(@PlainData[0], Length(PlainData), CloseConnection)
  else
    Result := ProcessIncomingPlaintextPtr(nil, 0, CloseConnection);
end;

function TWebSocketSession.ProcessIncomingPlaintextPtr(DataPtr: PByte; DataLen: Integer; out CloseConnection: Boolean): TArray<TBytes>;
var
  Offset, PrevOffset: Integer;
  Frame: TWebSocketFrame;
  ErrorMsg: string;
  MsgList: TList<TBytes>;
  OpcodeList: TList<TWebSocketOpcode>;
  Lock: TCriticalSection;
  PrevLen: Integer;
  B0, B1, Rsv, OpByte, Len7: Byte;
  HdrLen, PayLen, I, Chunks, Rem: Integer;
  MaskKey: array[0..3] of Byte;
  Mask32: UInt32;
  Src32, Dst32: PCardinal;
  Src8, Dst8: PByte;
  MsgBytes: TBytes;
begin
  CloseConnection := False;
  SetLength(FLastMessageOpcodes, 0);
  if InCleanup <> 0 then
  begin
    CloseConnection := True;
    Exit(nil);
  end;

  Lock := FLock;
  if not Assigned(Lock) or (InCleanup <> 0) then
  begin
    CloseConnection := True;
    Exit(nil);
  end;

  if (DataLen >= 6) and Assigned(DataPtr) then
  begin
    B0 := DataPtr[0];
    B1 := DataPtr[1];
    Rsv := B0 and $70;
    OpByte := B0 and $0F;
    Len7 := B1 and $7F;
    if ((B0 and $80) <> 0) and (Rsv = 0) and ((B1 and $80) <> 0) and
       ((OpByte = Byte(Ord(wsOpText))) or (OpByte = Byte(Ord(wsOpBinary)))) and (Len7 < 127) then
    begin
      if Len7 < 126 then
      begin
        HdrLen := 6;
        PayLen := Len7;
      end
      else
      begin
        if DataLen < 8 then
          HdrLen := DataLen + 1
        else
        begin
          HdrLen := 8;
          PayLen := (Integer(DataPtr[2]) shl 8) or Integer(DataPtr[3]);
          if PayLen < 126 then
            HdrLen := DataLen + 1;
        end;
      end;

      if (HdrLen + PayLen = DataLen) and (UInt64(PayLen) <= MAX_WS_MESSAGE_SIZE) then
      begin
        Lock.Acquire;
        try
          if InCleanup <> 0 then
          begin
            CloseConnection := True;
            Exit(nil);
          end;
          if (Length(FIncomingBuffer) = 0) and (not FFragmentInProgress) then
          begin
            Move(DataPtr[HdrLen - 4], MaskKey[0], 4);
            SetLength(MsgBytes, PayLen);
            if PayLen > 0 then
            begin
              Move(MaskKey[0], Mask32, 4);
              Src32 := PCardinal(@DataPtr[HdrLen]);
              Dst32 := PCardinal(@MsgBytes[0]);
              Chunks := PayLen div 4;
              Rem := PayLen mod 4;
              for I := 0 to Chunks - 1 do
              begin
                Dst32^ := Src32^ xor Mask32;
                Inc(Src32);
                Inc(Dst32);
              end;
              if Rem > 0 then
              begin
                Src8 := PByte(Src32);
                Dst8 := PByte(Dst32);
                for I := 0 to Rem - 1 do
                begin
                  Dst8^ := Src8^ xor MaskKey[I];
                  Inc(Src8);
                  Inc(Dst8);
                end;
              end;
            end;
            if (OpByte = Byte(Ord(wsOpText))) and not TWebSocketFrame.IsValidUTF8(MsgBytes) then
            begin
              QueueSendFrame(wsOpClose, TBytes.Create($03, $EF));
              CloseConnection := True;
              Exit(nil);
            end;
            FLastActivityTime := GetTickCount64;
            FCurrentOpcode := TWebSocketOpcode(OpByte);
            SetLength(FLastMessageOpcodes, 1);
            FLastMessageOpcodes[0] := FCurrentOpcode;
            SetLength(Result, 1);
            Result[0] := MsgBytes;
            Exit;
          end;
        finally
          Lock.Leave;
        end;
      end;
    end;
  end;

  MsgList := TList<TBytes>.Create;
  OpcodeList := TList<TWebSocketOpcode>.Create;
  try
    Lock.Acquire;
    try
      if InCleanup <> 0 then
      begin
        CloseConnection := True;
        Exit;
      end;

      if (DataLen > 0) and Assigned(DataPtr) then
      begin
        PrevLen := Length(FIncomingBuffer);
        SetLength(FIncomingBuffer, PrevLen + DataLen);
        Move(DataPtr^, FIncomingBuffer[PrevLen], DataLen);
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
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
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
          QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
          CloseConnection := True;
          Exit;
        end;

        Unmask(Frame);

        if Frame.Opcode in [wsOpClose, wsOpPing, wsOpPong] then
        begin
          if not Frame.Fin then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
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
              var ClosePayloadLen := Length(Frame.Payload);
              if ClosePayloadLen = 1 then
              begin
                QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
                CloseReceived := True;
                CloseConnection := True;
                Exit;
              end
              else if ClosePayloadLen >= 2 then
              begin
                var StatusCode: Word := (Word(Frame.Payload[0]) shl 8) or Word(Frame.Payload[1]);
                var IsValidCode: Boolean := False;
                if (StatusCode = 1000) or (StatusCode = 1001) or (StatusCode = 1002) or
                   (StatusCode = 1003) or (StatusCode = 1007) or (StatusCode = 1008) or
                   (StatusCode = 1009) or (StatusCode = 1010) or (StatusCode = 1011) or
                   ((StatusCode >= 3000) and (StatusCode <= 4999)) then
                  IsValidCode := True;

                if not IsValidCode then
                begin
                  QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
                  CloseReceived := True;
                  CloseConnection := True;
                  Exit;
                end;

                if ClosePayloadLen > 2 then
                begin
                  var ReasonBytes := Copy(Frame.Payload, 2, ClosePayloadLen - 2);
                  if not TWebSocketFrame.IsValidUTF8(ReasonBytes) then
                  begin
                    QueueSendFrame(wsOpClose, TBytes.Create($03, $EF));
                    CloseReceived := True;
                    CloseConnection := True;
                    Exit;
                  end;
                end;

                QueueSendFrame(wsOpClose, Copy(Frame.Payload, 0, 2));
              end
              else
              begin
                QueueSendFrame(wsOpClose, nil);
              end;

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
          if FFragmentInProgress then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
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
          FFragmentInProgress := not Frame.Fin;
          FFramePayloadBuffer := Copy(Frame.Payload, 0, Length(Frame.Payload));
        end
        else if Frame.Opcode = wsOpBinary then
        begin
          if FFragmentInProgress then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
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
          FFragmentInProgress := not Frame.Fin;
          FFramePayloadBuffer := Copy(Frame.Payload, 0, Length(Frame.Payload));
        end
        else if Frame.Opcode = wsOpContinuation then
        begin
          if not FFragmentInProgress then
          begin
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EA));
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
          FFragmentInProgress := not Frame.Fin;
        end;

        if Frame.Fin and (Frame.Opcode in [wsOpText, wsOpBinary, wsOpContinuation]) then
        begin
          if (FCurrentOpcode = wsOpText) and not TWebSocketFrame.IsValidUTF8(FFramePayloadBuffer) then
          begin
            SetLength(FFramePayloadBuffer, 0);
            QueueSendFrame(wsOpClose, TBytes.Create($03, $EF));
            CloseConnection := True;
            Exit;
          end;
          MsgList.Add(Copy(FFramePayloadBuffer, 0, Length(FFramePayloadBuffer)));
          OpcodeList.Add(FCurrentOpcode);
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
    FLastMessageOpcodes := OpcodeList.ToArray;
    Result := MsgList.ToArray;
  finally
    OpcodeList.Free;
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
  Lock: TCriticalSection;
  Remaining: Integer;
  Len: Integer;
begin
  ChunkSize := 8192;

  if Length(Payload) <= ChunkSize then
  begin
    RawFrame := TWebSocketFrame.Encode(Opcode, Payload, True);
    Lock := FLock;
    if Assigned(Lock) then
    begin
      Lock.Acquire;
      try
        if Assigned(FWriteQueue) then
        begin
          FWriteQueue.Enqueue(RawFrame);
          TInterlocked.Increment(FWriteQueueCount);
        end;
      finally
        Lock.Leave;
      end;
    end;
  end
  else
  begin
    Lock := FLock;
    if Assigned(Lock) then
    begin
      Lock.Acquire;
      try
        Offset := 0;
        CurrentOpcode := Opcode;
        while Offset < Length(Payload) do
        begin
          Remaining := Length(Payload) - Offset;
          Len := ChunkSize;
          if Remaining < Len then
            Len := Remaining;

          SetLength(CurrentChunk, Len);
          Move(Payload[Offset], CurrentChunk[0], Len);

          IsFin := (Offset + Len) >= Length(Payload);
          RawFrame := TWebSocketFrame.Encode(CurrentOpcode, CurrentChunk, IsFin);
          if Assigned(FWriteQueue) then
          begin
            FWriteQueue.Enqueue(RawFrame);
            TInterlocked.Increment(FWriteQueueCount);
          end;

          Inc(Offset, Len);
          CurrentOpcode := wsOpContinuation;
        end;
      finally
        Lock.Leave;
      end;
    end;
  end;
end;

function TWebSocketSession.TryFastSendText(const Text: string): Boolean;
var
  WriteOv: POverlappedEx;
  Utf8Len: Integer;
  StartIdx: Integer;
  FrameLen: Integer;
  WSABuf: TWSABUF;
  BytesSent: DWORD;
begin
  Result := False;
  if (InCleanup <> 0) or (Length(Text) > 4096) then
    Exit;

  WriteOv := FWriteOverlapped;
  if (not Assigned(WriteOv)) or WriteOv^.IsTLS then
    Exit;

  if TInterlocked.CompareExchange(WritePending, 1, 0) <> 0 then
    Exit;

  if (InCleanup <> 0) or (FWriteOverlapped <> WriteOv) or HasPendingWrites then
  begin
    TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;

  if Length(Text) = 0 then
    Utf8Len := 0
  else
  begin
    Utf8Len := WideCharToMultiByte(CP_UTF8, 0, PWideChar(Pointer(Text)), Length(Text),
      PAnsiChar(@WriteOv^.SSLOutputBuffer[4]), SizeOf(WriteOv^.SSLOutputBuffer) - 4, nil, nil);
    if Utf8Len <= 0 then
    begin
      TInterlocked.Exchange(WritePending, 0);
      Exit;
    end;
  end;

  if Utf8Len < 126 then
  begin
    StartIdx := 2;
    WriteOv^.SSLOutputBuffer[2] := $81;
    WriteOv^.SSLOutputBuffer[3] := Byte(Utf8Len);
    FrameLen := 2 + Utf8Len;
  end
  else
  begin
    StartIdx := 0;
    WriteOv^.SSLOutputBuffer[0] := $81;
    WriteOv^.SSLOutputBuffer[1] := 126;
    WriteOv^.SSLOutputBuffer[2] := Byte(Utf8Len shr 8);
    WriteOv^.SSLOutputBuffer[3] := Byte(Utf8Len and $FF);
    FrameLen := 4 + Utf8Len;
  end;

  WSABuf.len := FrameLen;
  WSABuf.buf := @WriteOv^.SSLOutputBuffer[StartIdx];
  ZeroMemory(@WriteOv^.Overlapped, SizeOf(TOverlapped));
  BytesSent := 0;
  if WSASend(FSocket, @WSABuf, 1, BytesSent, 0, @WriteOv^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError = WSA_IO_PENDING then
      Result := True
    else
      TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;

  if WriteOv^.SkipIOCP then
  begin
    if BytesSent > 0 then
    begin
      TInterlocked.Exchange(WritePending, 0);
      Result := True;
    end
    else
      TInterlocked.Exchange(WritePending, 0);
  end
  else
    Result := True;
end;

procedure TWebSocketSession.BeginFastBatch;
var
  WriteOv: POverlappedEx;
begin
  if FBatchActive or (InCleanup <> 0) then
    Exit;
  WriteOv := FWriteOverlapped;
  if (not Assigned(WriteOv)) or WriteOv^.IsTLS then
    Exit;
  if TInterlocked.CompareExchange(WritePending, 1, 0) <> 0 then
    Exit;
  if (InCleanup <> 0) or (FWriteOverlapped <> WriteOv) or HasPendingWrites then
  begin
    TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;
  FBatchActive := True;
  FBatchLen := 0;
  FBatchOverlapped := WriteOv;
end;

procedure TWebSocketSession.EndFastBatch;
var
  WriteOv: POverlappedEx;
  SendLen: Integer;
  WSABuf: TWSABUF;
  BytesSent: DWORD;
begin
  if not FBatchActive then
    Exit;
  FBatchActive := False;
  WriteOv := FBatchOverlapped;
  SendLen := FBatchLen;
  FBatchOverlapped := nil;
  FBatchLen := 0;
  if (SendLen <= 0) or (not Assigned(WriteOv)) or (InCleanup <> 0) or (FWriteOverlapped <> WriteOv) then
  begin
    TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;
  WSABuf.len := SendLen;
  WSABuf.buf := @WriteOv^.SSLOutputBuffer[0];
  ZeroMemory(@WriteOv^.Overlapped, SizeOf(TOverlapped));
  BytesSent := 0;
  if WSASend(FSocket, @WSABuf, 1, BytesSent, 0, @WriteOv^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError <> WSA_IO_PENDING then
      TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;
  if WriteOv^.SkipIOCP then
    TInterlocked.Exchange(WritePending, 0);
end;

function TWebSocketSession.TryFastSendRaw(Opcode: TWebSocketOpcode; PayloadPtr: PByte; PayloadLen: Integer): Boolean;
var
  WriteOv: POverlappedEx;
  StartIdx: Integer;
  FrameLen: Integer;
  HdrBytes: Integer;
  WSABuf: TWSABUF;
  BytesSent: DWORD;
  FirstByte: Byte;
begin
  Result := False;
  if (InCleanup <> 0) or (PayloadLen < 0) or (PayloadLen > 4096) then
    Exit;

  if FBatchActive and Assigned(FBatchOverlapped) then
  begin
    WriteOv := FBatchOverlapped;
    if PayloadLen < 126 then
      HdrBytes := 2
    else
      HdrBytes := 4;
    if (InCleanup = 0) and (FWriteOverlapped = WriteOv) and
       (FBatchLen + HdrBytes + PayloadLen <= SizeOf(WriteOv^.SSLOutputBuffer)) then
    begin
      FirstByte := $80 or Byte(Ord(Opcode));
      if PayloadLen < 126 then
      begin
        WriteOv^.SSLOutputBuffer[FBatchLen] := FirstByte;
        WriteOv^.SSLOutputBuffer[FBatchLen + 1] := Byte(PayloadLen);
      end
      else
      begin
        WriteOv^.SSLOutputBuffer[FBatchLen] := FirstByte;
        WriteOv^.SSLOutputBuffer[FBatchLen + 1] := 126;
        WriteOv^.SSLOutputBuffer[FBatchLen + 2] := Byte(PayloadLen shr 8);
        WriteOv^.SSLOutputBuffer[FBatchLen + 3] := Byte(PayloadLen and $FF);
      end;
      if (PayloadLen > 0) and Assigned(PayloadPtr) then
        Move(PayloadPtr^, WriteOv^.SSLOutputBuffer[FBatchLen + HdrBytes], PayloadLen);
      Inc(FBatchLen, HdrBytes + PayloadLen);
      Result := True;
      Exit;
    end;
    EndFastBatch;
  end;

  WriteOv := FWriteOverlapped;
  if (not Assigned(WriteOv)) or WriteOv^.IsTLS then
    Exit;

  if TInterlocked.CompareExchange(WritePending, 1, 0) <> 0 then
    Exit;

  if (InCleanup <> 0) or (FWriteOverlapped <> WriteOv) or HasPendingWrites then
  begin
    TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;

  if (PayloadLen > 0) and Assigned(PayloadPtr) then
    Move(PayloadPtr^, WriteOv^.SSLOutputBuffer[4], PayloadLen);

  FirstByte := $80 or Byte(Ord(Opcode));
  if PayloadLen < 126 then
  begin
    StartIdx := 2;
    WriteOv^.SSLOutputBuffer[2] := FirstByte;
    WriteOv^.SSLOutputBuffer[3] := Byte(PayloadLen);
    FrameLen := 2 + PayloadLen;
  end
  else
  begin
    StartIdx := 0;
    WriteOv^.SSLOutputBuffer[0] := FirstByte;
    WriteOv^.SSLOutputBuffer[1] := 126;
    WriteOv^.SSLOutputBuffer[2] := Byte(PayloadLen shr 8);
    WriteOv^.SSLOutputBuffer[3] := Byte(PayloadLen and $FF);
    FrameLen := 4 + PayloadLen;
  end;

  WSABuf.len := FrameLen;
  WSABuf.buf := @WriteOv^.SSLOutputBuffer[StartIdx];
  ZeroMemory(@WriteOv^.Overlapped, SizeOf(TOverlapped));
  BytesSent := 0;
  if WSASend(FSocket, @WSABuf, 1, BytesSent, 0, @WriteOv^.Overlapped, nil) = SOCKET_ERROR then
  begin
    if WSAGetLastError = WSA_IO_PENDING then
      Result := True
    else
      TInterlocked.Exchange(WritePending, 0);
    Exit;
  end;

  if WriteOv^.SkipIOCP then
  begin
    if BytesSent > 0 then
    begin
      TInterlocked.Exchange(WritePending, 0);
      Result := True;
    end
    else
      TInterlocked.Exchange(WritePending, 0);
  end
  else
    Result := True;
end;

procedure TWebSocketSession.SendRaw(Opcode: TWebSocketOpcode; PayloadPtr: PByte; PayloadLen: Integer);
var
  Buf: TBytes;
begin
  if TryFastSendRaw(Opcode, PayloadPtr, PayloadLen) then
    Exit;
  if (PayloadLen > 0) and Assigned(PayloadPtr) then
  begin
    SetLength(Buf, PayloadLen);
    Move(PayloadPtr^, Buf[0], PayloadLen);
  end
  else
    SetLength(Buf, 0);
  QueueSendFrame(Opcode, Buf);
end;

procedure TWebSocketSession.SendText(const Text: string);
begin
  if TryFastSendText(Text) then
    Exit;
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
        TInterlocked.Decrement(FWriteQueueCount);
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
begin
  Result := TInterlocked.CompareExchange(FWriteQueueCount, 0, 0) <> 0;
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
