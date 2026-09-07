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

unit LsQpack.Types;

interface

const

  LSQPACK_ENC_STRUCT_SIZE = 4096;
  LSQPACK_DEC_STRUCT_SIZE = 2048;

type

  TLsQpackEncHandle = Pointer;
  TLsQpackDecHandle = Pointer;

  PPByte = ^PByte;

  TLsxpackFlag = (
    LSXPACK_HPACK_VAL_MATCHED = 1,
    LSXPACK_QPACK_IDX = 2,
    LSXPACK_APP_IDX = 4,
    LSXPACK_NAME_HASH = 8,
    LSXPACK_NAMEVAL_HASH = 16,
    LSXPACK_VAL_MATCHED = 32,
    LSXPACK_NEVER_INDEX = 64
  );
  TLsxpackFlags = set of TLsxpackFlag;

  PTLsxpackHeader = ^TLsxpackHeader;
  TLsxpackHeader = record
    buf: PAnsiChar;
    name_hash: UInt32;
    nameval_hash: UInt32;
    name_offset: Int32;
    val_offset: Int32;
    name_len: UInt16;
    val_len: UInt16;
    chain_next_idx: UInt16;
    hpack_index: UInt8;
    qpack_index: UInt8;
    app_index: UInt8;
    flags: UInt8;
    indexed_type: UInt8;
    dec_overhead: UInt8;
    _padding: array[0..31] of Byte;
  end;

  TDhiUnblockedFunc = procedure(HblockCtx: Pointer); cdecl;
  TDhiPrepareDecodeFunc = function(HblockCtx: Pointer; Hdr: PTLsxpackHeader; Space: NativeUInt): PTLsxpackHeader; cdecl;
  TDhiProcessHeaderFunc = function(HblockCtx: Pointer; Hdr: PTLsxpackHeader): Integer; cdecl;

  PTLsqpackDecHsetIf = ^TLsqpackDecHsetIf;
  TLsqpackDecHsetIf = record
    dhi_unblocked: TDhiUnblockedFunc;
    dhi_prepare_decode: TDhiPrepareDecodeFunc;
    dhi_process_header: TDhiProcessHeaderFunc;
  end;

implementation

end.
