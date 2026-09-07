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

unit LsQpack.Encoder;

interface

uses
  System.SysUtils, System.Math, LsQpack.Types, LsQpack.Loader, LsQpack.Errors;

type

  TQpackEncoder = class
  private
    FBlock: TLsQpackEncHandle;
  public
    constructor Create(ADynTableSize: Cardinal = 0; AMaxRiskedStreams: Cardinal = 0);
    destructor Destroy; override;

    procedure StartHeader(StreamId: UInt64; Seqno: Integer);
    procedure EncodeHeader(const AName, AValue: RawByteString;
      out AEncoderInstructions, AHeaderBytes: TBytes);
    function EndHeader: TBytes;
  end;

implementation

constructor TQpackEncoder.Create(ADynTableSize: Cardinal; AMaxRiskedStreams: Cardinal);
var
  SdtcBuf: array[0..15] of Byte;
  SdtcSz: NativeUInt;
  MaxTableSize: Cardinal;
begin
  inherited Create;
  if not Assigned(lsqpack_enc_init) then
     raise EQpackError.CreateCode('ls-qpack API not loaded - initialize the loader first.', -1);

  FBlock := AllocMem(LSQPACK_ENC_STRUCT_SIZE);
  if FBlock = nil then
    raise EOutOfMemory.Create('Failed to allocate lsqpack_enc block');

  MaxTableSize := Max(4096, ADynTableSize);
  SdtcSz := SizeOf(SdtcBuf);
  CheckQpackStatus(
    lsqpack_enc_init(FBlock, nil, MaxTableSize, ADynTableSize, AMaxRiskedStreams, 0, @SdtcBuf[0], SdtcSz),
    'lsqpack_enc_init'
  );
end;

destructor TQpackEncoder.Destroy;
begin
  if FBlock <> nil then
  begin
    if Assigned(lsqpack_enc_cleanup) then
      lsqpack_enc_cleanup(FBlock);
    FreeMem(FBlock);
    FBlock := nil;
  end;
  inherited Destroy;
end;

procedure TQpackEncoder.StartHeader(StreamId: UInt64; Seqno: Integer);
begin
  CheckQpackStatus(lsqpack_enc_start_header(FBlock, StreamId, Seqno), 'lsqpack_enc_start_header');
end;

procedure TQpackEncoder.EncodeHeader(const AName, AValue: RawByteString;
  out AEncoderInstructions, AHeaderBytes: TBytes);
var
  Xhdr: TLsxpackHeader;
  EncSz, HeaSz: NativeUInt;
  ValBuf: array[0..1023] of AnsiChar;
  DynValBuf: TBytes;
  EncBuf: array[0..511] of Byte;
  HeaBuf: array[0..2047] of Byte;
  NameLen, ValLen, TotalLen: Integer;
begin
  NameLen := Length(AName);
  ValLen := Length(AValue);
  TotalLen := NameLen + ValLen + 4;

  FillChar(Xhdr, SizeOf(Xhdr), 0);

  if TotalLen <= SizeOf(ValBuf) then
  begin
    if NameLen > 0 then  
	   Move(AName[1], ValBuf[0], NameLen);
    if ValLen > 0 then 
	   Move(AValue[1], ValBuf[NameLen + 2], ValLen);
    Xhdr.buf := @ValBuf[0];
  end
  else
  begin
    SetLength(DynValBuf, TotalLen);
    if NameLen > 0 then 
	   Move(AName[1], DynValBuf[0], NameLen);
    if ValLen > 0 then 
	   Move(AValue[1], DynValBuf[NameLen + 2], ValLen);
    Xhdr.buf := PAnsiChar(@DynValBuf[0]);
  end;

  Xhdr.name_offset := 0;
  Xhdr.name_len := NameLen;
  Xhdr.val_offset := NameLen + 2;
  Xhdr.val_len := ValLen;

  EncSz := SizeOf(EncBuf);
  HeaSz := SizeOf(HeaBuf);

  CheckQpackStatus(
    lsqpack_enc_encode(FBlock, @EncBuf[0], EncSz,
                       @HeaBuf[0], HeaSz, @Xhdr, 1),
    'lsqpack_enc_encode'
  );

  SetLength(AEncoderInstructions, EncSz);
  if EncSz > 0 then
    Move(EncBuf[0], AEncoderInstructions[0], EncSz);

  SetLength(AHeaderBytes, HeaSz);
  if HeaSz > 0 then
    Move(HeaBuf[0], AHeaderBytes[0], HeaSz);
end;

function TQpackEncoder.EndHeader: TBytes;
var
  PrefBuf: array[0..31] of Byte;
  HeaSz: NativeUInt;
  Res: NativeInt;
begin
  HeaSz := SizeOf(PrefBuf);

  Res := lsqpack_enc_end_header(FBlock, @PrefBuf[0], HeaSz, nil);
  if Res < 0 then
    raise EQpackError.CreateCode('lsqpack_enc_end_header failed', Res);

  SetLength(Result, Res);
  if Res > 0 then
    Move(PrefBuf[0], Result[0], Res);
end;

end.
