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

unit Http3.Frames;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils;

type
  THttp3Frame = record
    FrameType: UInt64;
    PayloadLength: UInt64;
    Payload: TBytes;
  end;

  TQuicVarInt = record
    class function Decode(const Buffer: TBytes; var Offset: Integer; out Value: UInt64): Boolean; static;
    class function Encode(Value: UInt64): TBytes; static;
  end;

implementation

class function TQuicVarInt.Decode(const Buffer: TBytes; var Offset: Integer; out Value: UInt64): Boolean;
var
  BufLen: Integer;
  B: Byte;
begin
  Value := 0;
  BufLen := Length(Buffer);
  if (Offset < 0) or (Offset >= BufLen) then
    Exit(False);

  B := Buffer[Offset];
  if B < $40 then
  begin
    Value := B;
    Inc(Offset, 1);
  end
  else if B < $80 then
  begin
    if BufLen - Offset < 2 then
      Exit(False);
    Value := (UInt64(B and $3F) shl 8) or UInt64(Buffer[Offset + 1]);
    Inc(Offset, 2);
  end
  else if B < $C0 then
  begin
    if BufLen - Offset < 4 then
      Exit(False);
    Value := (UInt64(B and $3F) shl 24) or
             (UInt64(Buffer[Offset + 1]) shl 16) or
             (UInt64(Buffer[Offset + 2]) shl 8) or
             UInt64(Buffer[Offset + 3]);
    Inc(Offset, 4);
  end
  else
  begin
    if BufLen - Offset < 8 then
      Exit(False);
    Value := (UInt64(B and $3F) shl 56) or
             (UInt64(Buffer[Offset + 1]) shl 48) or
             (UInt64(Buffer[Offset + 2]) shl 40) or
             (UInt64(Buffer[Offset + 3]) shl 32) or
             (UInt64(Buffer[Offset + 4]) shl 24) or
             (UInt64(Buffer[Offset + 5]) shl 16) or
             (UInt64(Buffer[Offset + 6]) shl 8) or
             UInt64(Buffer[Offset + 7]);
    Inc(Offset, 8);
  end;
  Result := True;
end;

class function TQuicVarInt.Encode(Value: UInt64): TBytes;
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
    raise Exception.Create('VarInt value too large');
end;

end.
