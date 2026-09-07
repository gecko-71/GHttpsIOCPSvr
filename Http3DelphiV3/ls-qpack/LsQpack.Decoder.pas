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

unit LsQpack.Decoder;

interface

uses
  System.SysUtils, System.Generics.Collections, LsQpack.Types, LsQpack.Loader, LsQpack.Errors;

type
  TQpackDecoder = class
  private
    FBlock: TLsQpackDecHandle;
  public
    constructor Create(ADynTableSize: Cardinal = 0; AMaxRiskedStreams: Cardinal = 0);
    destructor Destroy; override;

    procedure FeedEncoderStream(const AData: TBytes);
    function DecodeHeaderBlock(StreamId: UInt64;
      const AData: TBytes): TArray<TPair<RawByteString, RawByteString>>;
    procedure CancelStream(StreamId: UInt64);
  end;

  TDecodeContext = class
  public
    Pairs: TList<TPair<RawByteString, RawByteString>>;
    CurrentHeader: TLsxpackHeader;
    DecodeBuf: array[0..4095] of AnsiChar;
    DynamicBuf: Pointer;
    DynamicBufCap: NativeUInt;
    constructor Create;
    destructor Destroy; override;
  end;

implementation

constructor TDecodeContext.Create;
begin
  inherited Create;
  Pairs := TList<TPair<RawByteString, RawByteString>>.Create;
  DynamicBuf := nil;
  DynamicBufCap := 0;
  FillChar(CurrentHeader, SizeOf(TLsxpackHeader), 0);
end;

destructor TDecodeContext.Destroy;
begin
  if DynamicBuf <> nil then
  begin
    FreeMem(DynamicBuf);
    DynamicBuf := nil;
  end;
  Pairs.Free;
  inherited;
end;

procedure DecoderUnblocked(HblockCtx: Pointer); cdecl;
begin

end;

function DecoderPrepareDecode(HblockCtx: Pointer; Hdr: PTLsxpackHeader; Space: NativeUInt): PTLsxpackHeader; cdecl;
var
  Ctx: TDecodeContext;
  TargetBuf: PAnsiChar;
begin
  Ctx := TDecodeContext(HblockCtx);
  if (Ctx = nil) or (Space > $FFFF) then
    Exit(nil);

  if Space <= SizeOf(Ctx.DecodeBuf) then
    TargetBuf := @Ctx.DecodeBuf[0]
  else
  begin
    if Space > Ctx.DynamicBufCap then
    begin
      ReallocMem(Ctx.DynamicBuf, Space);
      Ctx.DynamicBufCap := Space;
    end;
    TargetBuf := PAnsiChar(Ctx.DynamicBuf);
  end;

  if Hdr <> nil then
  begin
    Ctx.CurrentHeader.buf := TargetBuf;
    Ctx.CurrentHeader.val_len := Space;
    Result := @Ctx.CurrentHeader;
  end
  else
  begin
    FillChar(Ctx.CurrentHeader, SizeOf(TLsxpackHeader), 0);
    Ctx.CurrentHeader.buf := TargetBuf;
    Ctx.CurrentHeader.name_offset := 0;
    Ctx.CurrentHeader.val_len := Space;
    Result := @Ctx.CurrentHeader;
  end;
end;

function DecoderProcessHeader(HblockCtx: Pointer; Hdr: PTLsxpackHeader): Integer; cdecl;
var
  Ctx: TDecodeContext;
  Name, Value: RawByteString;
begin
  if (HblockCtx <> nil) and (Hdr <> nil) then
  begin
    Ctx := TDecodeContext(HblockCtx);

    SetLength(Name, Hdr^.name_len);
    if Hdr^.name_len > 0 then
      Move(Hdr^.buf[Hdr^.name_offset], Name[1], Hdr^.name_len);

    SetLength(Value, Hdr^.val_len);
    if Hdr^.val_len > 0 then
      Move(Hdr^.buf[Hdr^.val_offset], Value[1], Hdr^.val_len);

    Ctx.Pairs.Add(TPair<RawByteString, RawByteString>.Create(Name, Value));
    FillChar(Ctx.CurrentHeader, SizeOf(TLsxpackHeader), 0);
  end;

  Result := 0;
end;

var
  GHsetIf: TLsqpackDecHsetIf;

constructor TQpackDecoder.Create(ADynTableSize: Cardinal; AMaxRiskedStreams: Cardinal);
begin
  inherited Create;
  if not Assigned(lsqpack_dec_init) then
    raise EQpackError.CreateCode('ls-qpack API not loaded', -1);

  FBlock := AllocMem(LSQPACK_DEC_STRUCT_SIZE);
  if FBlock = nil then
    raise EOutOfMemory.Create('Failed to allocate lsqpack_dec block');

  lsqpack_dec_init(FBlock, nil, ADynTableSize, AMaxRiskedStreams, @GHsetIf, 0);
end;

destructor TQpackDecoder.Destroy;
begin
  if FBlock <> nil then
  begin
    if Assigned(lsqpack_dec_cleanup) then
      lsqpack_dec_cleanup(FBlock);
    FreeMem(FBlock);
    FBlock := nil;
  end;
  inherited Destroy;
end;

procedure TQpackDecoder.FeedEncoderStream(const AData: TBytes);
var
  Res: Integer;
begin
  if Length(AData) > 0 then
  begin
    Res := lsqpack_dec_enc_in(FBlock, PByte(@AData[0]), Length(AData));
    if Res < 0 then
      raise EQpackError.CreateCode('Error parsing QPACK encoder stream', Res);
  end;
end;

function TQpackDecoder.DecodeHeaderBlock(StreamId: UInt64;
  const AData: TBytes): TArray<TPair<RawByteString, RawByteString>>;
var
  Res: Integer;
  BufPtr: PByte;
  Ctx: TDecodeContext;
  I: Integer;
begin
  if Length(AData) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  Ctx := TDecodeContext.Create;
  try
    BufPtr := @AData[0];

    Res := lsqpack_dec_header_in(
      FBlock,
      Pointer(Ctx),
      StreamId,
      Length(AData),
      @BufPtr,
      Length(AData),
      nil,
      nil
    );

    if (Res = 3) or (Res < 0) then
      raise EQpackError.CreateCode('Error decoding header block', Res);

    SetLength(Result, Ctx.Pairs.Count);
    for I := 0 to Ctx.Pairs.Count - 1 do
      Result[I] := Ctx.Pairs[I];
  finally
    Ctx.Free;
  end;
end;

procedure TQpackDecoder.CancelStream(StreamId: UInt64);
var
  CancelBuf: array[0..31] of Byte;
begin
  if (FBlock <> nil) and Assigned(lsqpack_dec_cancel_stream_id) then
  begin
    lsqpack_dec_cancel_stream_id(FBlock, StreamId, @CancelBuf[0], SizeOf(CancelBuf));
  end;
end;

initialization
  GHsetIf.dhi_unblocked := DecoderUnblocked;
  GHsetIf.dhi_prepare_decode := DecoderPrepareDecode;
  GHsetIf.dhi_process_header := DecoderProcessHeader;

end.
