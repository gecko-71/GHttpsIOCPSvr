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
unit Net.QPACK;

interface

uses
  System.SysUtils, System.Classes;

type
  TQpackStaticEntry = record
    Name: string;
    Value: string;
  end;

  THttpHeader = record
    Name: string;
    Value: string;
  end;
  THttpHeaders = TArray<THttpHeader>;

const QPACK_STATIC_TABLE: array[0..98] of TQpackStaticEntry = (
  (Name: ':authority'; Value: ''), // 0
  (Name: ':path'; Value: '/'), // 1
  (Name: 'age'; Value: '0'), // 2
  (Name: 'content-disposition'; Value: ''), // 3
  (Name: 'content-length'; Value: '0'), // 4
  (Name: 'cookie'; Value: ''), // 5
  (Name: 'date'; Value: ''), // 6
  (Name: 'etag'; Value: ''), // 7
  (Name: 'if-modified-since'; Value: ''), // 8
  (Name: 'if-none-match'; Value: ''), // 9
  (Name: 'last-modified'; Value: ''), // 10
  (Name: 'link'; Value: ''), // 11
  (Name: 'location'; Value: ''), // 12
  (Name: 'referer'; Value: ''), // 13
  (Name: 'set-cookie'; Value: ''), // 14
  (Name: ':method'; Value: 'CONNECT'), // 15
  (Name: ':method'; Value: 'DELETE'), // 16
  (Name: ':method'; Value: 'GET'), // 17
  (Name: ':method'; Value: 'HEAD'), // 18
  (Name: ':method'; Value: 'OPTIONS'), // 19
  (Name: ':method'; Value: 'POST'), // 20
  (Name: ':method'; Value: 'PUT'), // 21
  (Name: ':scheme'; Value: 'http'), // 22
  (Name: ':scheme'; Value: 'https'), // 23
  (Name: ':status'; Value: '103'), // 24
  (Name: ':status'; Value: '200'), // 25
  (Name: ':status'; Value: '304'), // 26
  (Name: ':status'; Value: '404'), // 27
  (Name: ':status'; Value: '503'), // 28
  (Name: 'accept'; Value: '*/*'), // 29
  (Name: 'accept'; Value: 'application/dns-message'), // 30 (corrected)
  (Name: 'accept-encoding'; Value: 'gzip, deflate, br'), // 31
  (Name: 'accept-ranges'; Value: 'bytes'), // 32
  (Name: 'access-control-allow-headers'; Value: 'cache-control'), // 33
  (Name: 'access-control-allow-headers'; Value: 'content-type'), // 34
  (Name: 'access-control-allow-origin'; Value: '*'), // 35
  (Name: 'cache-control'; Value: 'max-age=0'), // 36
  (Name: 'cache-control'; Value: 'max-age=2592000'), // 37
  (Name: 'cache-control'; Value: 'max-age=604800'), // 38
  (Name: 'cache-control'; Value: 'no-cache'), // 39
  (Name: 'cache-control'; Value: 'no-store'), // 40
  (Name: 'cache-control'; Value: 'public, max-age=31536000'), // 41 (corrected)
  (Name: 'content-encoding'; Value: 'br'), // 42
  (Name: 'content-encoding'; Value: 'gzip'), // 43
  (Name: 'content-type'; Value: 'application/dns-message'), // 44 (corrected)
  (Name: 'content-type'; Value: 'application/javascript'), // 45 (corrected)
  (Name: 'content-type'; Value: 'application/json'), // 46
  (Name: 'content-type'; Value: 'application/x-www-form-urlencoded'), // 47 (corrected)
  (Name: 'content-type'; Value: 'image/gif'), // 48
  (Name: 'content-type'; Value: 'image/jpeg'), // 49
  (Name: 'content-type'; Value: 'image/png'), // 50
  (Name: 'content-type'; Value: 'text/css'), // 51
  (Name: 'content-type'; Value: 'text/html; charset=utf-8'), // 52 (corrected)
  (Name: 'content-type'; Value: 'text/plain'), // 53
  (Name: 'content-type'; Value: 'text/plain;charset=utf-8'), // 54 (corrected)
  (Name: 'range'; Value: 'bytes=0-'), // 55
  (Name: 'strict-transport-security'; Value: 'max-age=31536000'), // 56
  (Name: 'strict-transport-security'; Value: 'max-age=31536000; includesubdomains'), // 57 (corrected)
  (Name: 'strict-transport-security'; Value: 'max-age=31536000; includesubdomains; preload'), // 58 (corrected)
  (Name: 'vary'; Value: 'accept-encoding'), // 59
  (Name: 'vary'; Value: 'origin'), // 60
  (Name: 'x-content-type-options'; Value: 'nosniff'), // 61
  (Name: 'x-xss-protection'; Value: '1; mode=block'), // 62
  (Name: ':status'; Value: '100'), // 63
  (Name: ':status'; Value: '204'), // 64
  (Name: ':status'; Value: '206'), // 65
  (Name: ':status'; Value: '302'), // 66
  (Name: ':status'; Value: '400'), // 67
  (Name: ':status'; Value: '403'), // 68
  (Name: ':status'; Value: '421'), // 69
  (Name: ':status'; Value: '425'), // 70
  (Name: ':status'; Value: '500'), // 71
  (Name: 'accept-language'; Value: ''), // 72
  (Name: 'access-control-allow-credentials'; Value: 'FALSE'), // 73
  (Name: 'access-control-allow-credentials'; Value: 'TRUE'), // 74
  (Name: 'access-control-allow-headers'; Value: '*'), // 75
  (Name: 'access-control-allow-methods'; Value: 'get'), // 76
  (Name: 'access-control-allow-methods'; Value: 'get, post, options'), // 77
  (Name: 'access-control-allow-methods'; Value: 'options'), // 78
  (Name: 'access-control-expose-headers'; Value: 'content-length'), // 79
  (Name: 'access-control-request-headers'; Value: 'content-type'), // 80
  (Name: 'access-control-request-method'; Value: 'get'), // 81
  (Name: 'access-control-request-method'; Value: 'post'), // 82
  (Name: 'alt-svc'; Value: 'clear'), // 83
  (Name: 'authorization'; Value: ''), // 84
  (Name: 'content-security-policy'; Value: 'script-src ''none''; object-src ''none''; base-uri ''none'''), // 85 (corrected)
  (Name: 'early-data'; Value: '1'), // 86
  (Name: 'expect-ct'; Value: ''), // 87
  (Name: 'forwarded'; Value: ''), // 88
  (Name: 'if-range'; Value: ''), // 89
  (Name: 'origin'; Value: ''), // 90
  (Name: 'purpose'; Value: 'prefetch'), // 91
  (Name: 'server'; Value: ''), // 92
  (Name: 'timing-allow-origin'; Value: '*'), // 93
  (Name: 'upgrade-insecure-requests'; Value: '1'), // 94
  (Name: 'user-agent'; Value: ''), // 95
  (Name: 'x-forwarded-for'; Value: ''), // 96
  (Name: 'x-frame-options'; Value: 'deny'), // 97
  (Name: 'x-frame-options'; Value: 'sameorigin') // 98
);

function FindStaticIndex(const Name, Value: string): Integer;
function FindStaticIndexByName(const Name: string): Integer;

function DecodeString(const Data: TBytes; var Offset: Integer): string;

function QpackDecode(const Data: TBytes): THttpHeaders;
function QpackEncode(const Headers: THttpHeaders): TBytes;

implementation

uses Net.Http3Frames, Net.QPACK.Huffman, Quick.Logger;

function FindStaticIndex(const Name, Value: string): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := Low(QPACK_STATIC_TABLE) to High(QPACK_STATIC_TABLE) do
  begin
    if (QPACK_STATIC_TABLE[I].Name = Name) and (QPACK_STATIC_TABLE[I].Value = Value) then
      Exit(I);
  end;
end;

function FindStaticIndexByName(const Name: string): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := Low(QPACK_STATIC_TABLE) to High(QPACK_STATIC_TABLE) do
  begin
    if QPACK_STATIC_TABLE[I].Name = Name then
      Exit(I);
  end;
end;

function DecodeInteger(const Data: TBytes; var Offset: Integer; PrefixBits: Integer): Integer;
var
  Mask: Byte;
  Value: Integer;
  Shift: Integer;
  B: Byte;
begin
  Mask := (1 shl PrefixBits) - 1;
  Value := Data[Offset] and Mask;
  if Value < Mask then
  begin
    Inc(Offset);
    Exit(Value);
  end;
  
  Inc(Offset);
  Shift := 0;
  while Offset < Length(Data) do
  begin
    B := Data[Offset];
    Inc(Offset);
    Value := Value + (B and 127) shl Shift;
    if (B and 128) = 0 then
      Break;
    Inc(Shift, 7);
  end;
  Result := Value;
end;

{$I '..\huff.pas'}

const
  MAX_QPACK_STRING_LEN = 65536; // 64 KB limit to prevent OOM

function DecodeStringEx(const Data: TBytes; var Offset: Integer; PrefixLen: Integer; HBitMask: Byte): string;
var
  H: Boolean;
  Len: Integer;
  B: Byte;
  U: UTF8String;
  State: Integer;
  Sym: Integer;
  I, j: Integer;
  UIndex: Integer;
begin
  if Offset >= Length(Data) then
    raise Exception.Create('Unexpected end of data in QPACK string');

  B := Data[Offset];
  H := (B and HBitMask) <> 0;
  Len := DecodeInteger(Data, Offset, PrefixLen);
  
  if Len > MAX_QPACK_STRING_LEN then
    raise Exception.Create('QPACK string length exceeds maximum allowed limit');

  if Offset + Len > Length(Data) then
    raise Exception.Create('QPACK string length exceeds buffer');

  if not H then
  begin
    SetLength(U, Len);
    if Len > 0 then Move(Data[Offset], U[1], Len);
    Result := string(U);
    Inc(Offset, Len);
  end
  else
  begin
    SetLength(U, Len * 2);
    UIndex := 1;
    State := 0; // Root node
    for I := 0 to Len - 1 do
    begin
      B := Data[Offset + I];
      for j := 7 downto 0 do
      begin
        if ((B shr j) and 1) = 1 then
          State := HUFF_TREE_1[State]
        else
          State := HUFF_TREE_0[State];
          
        if State = -1 then
           raise Exception.Create('Invalid Huffman code');

        if State >= 1000000 then
        begin
          Sym := State - 1000000;
          if Sym = 256 then raise Exception.Create('Huffman EOS symbol not allowed inside string');

          if UIndex > Length(U) then
            SetLength(U, Length(U) * 2);
          U[UIndex] := AnsiChar(Sym);
          Inc(UIndex);
          State := 0;
        end;
      end;
    end;
    
    if (State > 0) and (State > 7) then
      raise Exception.Create('Invalid Huffman padding');
    
    SetLength(U, UIndex - 1);
    Result := string(U);
    Inc(Offset, Len);
  end;
end;

function DecodeString(const Data: TBytes; var Offset: Integer): string;
begin
  Result := DecodeStringEx(Data, Offset, 7, $80);
end;

procedure EncodeInteger(var Buf: TBytes; Value: Integer; PrefixLen: Integer; InitialByte: Byte);
var
  Mask: Integer;
begin
  Mask := (1 shl PrefixLen) - 1;
  if Value < Mask then
  begin
    SetLength(Buf, Length(Buf) + 1);
    Buf[Length(Buf) - 1] := InitialByte or Byte(Value);
  end
  else
  begin
    SetLength(Buf, Length(Buf) + 1);
    Buf[Length(Buf) - 1] := InitialByte or Byte(Mask);
    Value := Value - Mask;
    while Value >= 128 do
    begin
      SetLength(Buf, Length(Buf) + 1);
      Buf[Length(Buf) - 1] := Byte((Value mod 128) + 128);
      Value := Value div 128;
    end;
    SetLength(Buf, Length(Buf) + 1);
    Buf[Length(Buf) - 1] := Byte(Value);
  end;
end;

procedure EncodeStringEx(var Buf: TBytes; const S: string; PrefixLen: Integer; HBitMask, InitialByte: Byte);
var
  U: UTF8String;
  Len: Integer;
begin
  U := UTF8String(S);
  Len := Length(U);
  EncodeInteger(Buf, Len, PrefixLen, InitialByte);
  if Len > 0 then
  begin
    SetLength(Buf, Length(Buf) + Len);
    Move(U[1], Buf[Length(Buf) - Len], Len);
  end;
end;

procedure EncodeString(var Buf: TBytes; const S: string);
begin
  EncodeStringEx(Buf, S, 7, $80, 0);
end;

function QpackDecode(const Data: TBytes): THttpHeaders;
var
  Offset: Integer;
  B: Byte;
  Index: Integer;
  HName, HValue: string;
begin
  SetLength(Result, 0);
  Offset := 0;
  if Offset + 2 <= Length(Data) then
    Inc(Offset, 2);

  while Offset < Length(Data) do
  begin
    B := Data[Offset];
    if (B and $C0) = $C0 then // 11xxxxxx = Indexed Field Line (Static Table)
    begin
      Index := DecodeInteger(Data, Offset, 6);
      if Index <= High(QPACK_STATIC_TABLE) then
      begin
        SetLength(Result, Length(Result) + 1);
        Result[Length(Result) - 1].Name := QPACK_STATIC_TABLE[Index].Name;
        Result[Length(Result) - 1].Value := QPACK_STATIC_TABLE[Index].Value;
      end;
    end
    else if ((B and $C0) = $40) then // 01xxxxxx = Literal Field Line with Name Ref (Static or Dynamic Table)
    begin
      Index := DecodeInteger(Data, Offset, 4);
      HValue := DecodeString(Data, Offset);
      if Index <= High(QPACK_STATIC_TABLE) then
      begin
        SetLength(Result, Length(Result) + 1);
        Result[Length(Result) - 1].Name := QPACK_STATIC_TABLE[Index].Name;
        Result[Length(Result) - 1].Value := HValue;
      end;
    end
    else if ((B and $E0) = $20) or ((B and $F0) = $00) then // 0010xxxx or 0000xxxx = Literal Field Line with Literal Name (No Ref)
    begin
      // Literal Field Line With Literal Name (001NHLLL)
      HName := DecodeStringEx(Data, Offset, 3, $08);
      HValue := DecodeString(Data, Offset);
      SetLength(Result, Length(Result) + 1);
      Result[Length(Result) - 1].Name := HName;
      Result[Length(Result) - 1].Value := HValue;
    end
    else
      raise Exception.CreateFmt('Unsupported QPACK instruction byte: %x', [B]);
  end;
end;

function QpackEncode(const Headers: THttpHeaders): TBytes;
var
  I: Integer;
  Idx: Integer;
  H: THttpHeader;
begin
  SetLength(Result, 2);
  // Required Insert Count = 0, Base = 0 dla tabeli statycznej w 100%
  Result[0] := 0;
  Result[1] := 0;

  for I := Low(Headers) to High(Headers) do
  begin
    H := Headers[I];
    Idx := FindStaticIndex(H.Name, H.Value);
    if Idx >= 0 then
    begin
      // Indexed Field Line (Static Table) - 11xxxxxx (prefix 6)
      EncodeInteger(Result, Idx, 6, $C0);
    end
    else
    begin
      Idx := FindStaticIndexByName(H.Name);
      if Idx >= 0 then
      begin
        // Literal Field Line with Name Ref (Static) - 0101xxxx (prefix 4)
        EncodeInteger(Result, Idx, 4, $50);
        EncodeString(Result, H.Value);
      end
      else
      begin
        // Literal Field Line with Literal Name - 0010xxxx (prefix 3, H=0 w MVP)
        EncodeStringEx(Result, H.Name, 3, $08, $20);
        EncodeString(Result, H.Value);
      end;
    end;
  end;
end;

end.
