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

unit Net.Http3Frames;

interface

uses
  System.SysUtils, System.Classes;

const
  // HTTP/3 Frame Types (RFC 9114)
  HTTP3_FRAME_DATA     = $0;
  HTTP3_FRAME_HEADERS  = $1;
  HTTP3_FRAME_CANCEL_PUSH = $3;
  HTTP3_FRAME_SETTINGS = $4;
  HTTP3_FRAME_PUSH_PROMISE = $5;
  HTTP3_FRAME_GOAWAY   = $7;
  HTTP3_FRAME_MAX_PUSH_ID = $D;

  // SETTINGS Settings (RFC 9114)
  HTTP3_SETTINGS_QPACK_MAX_TABLE_CAPACITY  = $1;
  HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE    = $6;
  HTTP3_SETTINGS_QPACK_BLOCKED_STREAMS     = $7;

type
  THttp3Frame = record
    FrameType: UInt64;
    PayloadLen: UInt64;
    Payload: TBytes;
  end;

// VarInt encoding/decoding
function VarIntSize(Value: UInt64): Integer;
function VarIntEncode(Value: UInt64): TBytes;
function VarIntDecode(const Data: TBytes; var Offset: Integer): UInt64;

// Parsing HTTP/3 frames
function ParseHttp3Frame(const Data: TBytes; var Offset: Integer; out Frame: THttp3Frame): Boolean;
function BuildHttp3Frame(FrameType: UInt64; const Payload: TBytes): TBytes;
function BuildSettingsFrame(const Settings: array of UInt64): TBytes; // Array of pairs: [Id1, Val1, Id2, Val2...]
function BuildGoAwayFrame(StreamID: UInt64): TBytes;

implementation

function VarIntSize(Value: UInt64): Integer;
begin
  if Value <= $3F then
    Result := 1
  else if Value <= $3FFF then
    Result := 2
  else if Value <= $3FFFFFFF then
    Result := 4
  else if Value <= $3FFFFFFFFFFFFFFF then
    Result := 8
  else
    raise Exception.Create('Value too large for VarInt encoding');
end;

function VarIntEncode(Value: UInt64): TBytes;
begin
  if Value <= $3F then
  begin
    SetLength(Result, 1);
    Result[0] := Byte(Value);
  end
  else if Value <= $3FFF then
  begin
    SetLength(Result, 2);
    Result[0] := Byte((Value shr 8) or $40);
    Result[1] := Byte(Value and $FF);
  end
  else if Value <= $3FFFFFFF then
  begin
    SetLength(Result, 4);
    Result[0] := Byte((Value shr 24) or $80);
    Result[1] := Byte((Value shr 16) and $FF);
    Result[2] := Byte((Value shr 8) and $FF);
    Result[3] := Byte(Value and $FF);
  end
  else if Value <= $3FFFFFFFFFFFFFFF then
  begin
    SetLength(Result, 8);
    Result[0] := Byte((Value shr 56) or $C0);
    Result[1] := Byte((Value shr 48) and $FF);
    Result[2] := Byte((Value shr 40) and $FF);
    Result[3] := Byte((Value shr 32) and $FF);
    Result[4] := Byte((Value shr 24) and $FF);
    Result[5] := Byte((Value shr 16) and $FF);
    Result[6] := Byte((Value shr 8) and $FF);
    Result[7] := Byte(Value and $FF);
  end
  else
    raise Exception.Create('Value too large for VarInt encoding');
end;

function VarIntDecode(const Data: TBytes; var Offset: Integer): UInt64;
var
  Prefix: Byte;
  Len: Integer;
  I: Integer;
begin
  if Offset >= Length(Data) then
    raise Exception.Create('Not enough data to decode VarInt');

  Prefix := Data[Offset] shr 6;
  case Prefix of
    0: Len := 1;
    1: Len := 2;
    2: Len := 4;
    3: Len := 8;
  else
    Len := 1; // Never reached
  end;

  if Offset + Len > Length(Data) then
    raise Exception.Create('Not enough data to decode VarInt length');

  Result := Data[Offset] and $3F;
  for I := 1 to Len - 1 do
  begin
    Result := (Result shl 8) or Data[Offset + I];
  end;

  Inc(Offset, Len);
end;

function ParseHttp3Frame(const Data: TBytes; var Offset: Integer; out Frame: THttp3Frame): Boolean;
var
  StartOffset: Integer;
begin
  Result := False;
  StartOffset := Offset;
  try
    if Offset >= Length(Data) then Exit;

    Frame.FrameType := VarIntDecode(Data, Offset);
    Frame.PayloadLen := VarIntDecode(Data, Offset);

    if Offset + Integer(Frame.PayloadLen) > Length(Data) then
    begin
      Offset := StartOffset; // Restore offset in case of error
      Exit;
    end;

    SetLength(Frame.Payload, Frame.PayloadLen);
    if Frame.PayloadLen > 0 then
      Move(Data[Offset], Frame.Payload[0], Frame.PayloadLen);
    
    Inc(Offset, Frame.PayloadLen);
    Result := True;
  except
    on E: Exception do
    begin
      Offset := StartOffset;
      Result := False;
    end;
  end;
end;

function BuildHttp3Frame(FrameType: UInt64; const Payload: TBytes): TBytes;
var
  EncType, EncLen: TBytes;
begin
  EncType := VarIntEncode(FrameType);
  EncLen := VarIntEncode(Length(Payload));

  SetLength(Result, Length(EncType) + Length(EncLen) + Length(Payload));
  Move(EncType[0], Result[0], Length(EncType));
  Move(EncLen[0], Result[Length(EncType)], Length(EncLen));
  if Length(Payload) > 0 then
    Move(Payload[0], Result[Length(EncType) + Length(EncLen)], Length(Payload));
end;

function BuildSettingsFrame(const Settings: array of UInt64): TBytes;
var
  Payload: TBytes;
  I: Integer;
  EncID, EncValue: TBytes;
  CurrLen: Integer;
begin
  SetLength(Payload, 0);
  I := 0;
  while I < Length(Settings) do
  begin
    EncID := VarIntEncode(Settings[I]);
    EncValue := VarIntEncode(Settings[I + 1]);
    
    CurrLen := Length(Payload);
    SetLength(Payload, CurrLen + Length(EncID) + Length(EncValue));
    
    Move(EncID[0], Payload[CurrLen], Length(EncID));
    Move(EncValue[0], Payload[CurrLen + Length(EncID)], Length(EncValue));
    
    Inc(I, 2);
  end;
  Result := BuildHttp3Frame(HTTP3_FRAME_SETTINGS, Payload);
end;

function BuildGoAwayFrame(StreamID: UInt64): TBytes;
begin
  Result := BuildHttp3Frame(HTTP3_FRAME_GOAWAY, VarIntEncode(StreamID));
end;

end.
