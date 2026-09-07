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

unit LsQpack.Loader;

interface

uses
  System.SysUtils, Winapi.Windows, LsQpack.Types, LsQpack.Errors;

type

  TLsqpackEncPreinit = procedure(Enc: Pointer; LoggerCtx: Pointer); cdecl;
  TLsqpackEncInit = function(Enc: Pointer; LoggerCtx: Pointer;
    MaxTableSize, DynTableSize, MaxRiskedStreams: Cardinal;
    Opts: Integer; SdtcBuf: PByte; var SdtcBufSz: NativeUInt): Integer; cdecl;
  TLsqpackEncCleanup = procedure(Enc: Pointer); cdecl;
  TLsqpackEncStartHeader = function(Enc: Pointer; StreamId: UInt64;
    Seqno: Integer): Integer; cdecl;
  TLsqpackEncEncode = function(Enc: Pointer;
    EncBuf: PByte; var EncSz: NativeUInt;
    HeaBuf: PByte; var HeaSz: NativeUInt;
    Xhdr: PTLsxpackHeader; Flags: Integer): Integer; cdecl;
  TLsqpackEncEndHeader = function(Enc: Pointer;
    HeaBuf: PByte; HeaSz: NativeUInt; Flags: PInteger): NativeInt; cdecl;

  TLsqpackDecInit = procedure(Dec: Pointer; LoggerCtx: Pointer;
    DynTableSize, MaxRiskedStreams: Cardinal; HsetIf: PTLsqpackDecHsetIf; Opts: Integer); cdecl;
  TLsqpackDecCleanup = procedure(Dec: Pointer); cdecl;
  TLsqpackDecEncIn = function(Dec: Pointer; Buf: PByte; Sz: NativeUInt): Integer; cdecl;
  TLsqpackDecHeaderIn = function(Dec: Pointer; StreamCtx: Pointer; StreamId: UInt64;
    HeaderBlockSize: NativeUInt; Buf: PPByte; BufSz: NativeUInt;
    DecBuf: PByte; DecBufSz: PNativeUInt): Integer; cdecl;

  TLsqpackDecCancelStreamId = function(Dec: Pointer; StreamId: UInt64;
    Buf: PByte; BufSz: NativeUInt): NativeInt; cdecl;

var
  lsqpack_enc_preinit: TLsqpackEncPreinit = nil;
  lsqpack_enc_init: TLsqpackEncInit = nil;
  lsqpack_enc_cleanup: TLsqpackEncCleanup = nil;
  lsqpack_enc_start_header: TLsqpackEncStartHeader = nil;
  lsqpack_enc_encode: TLsqpackEncEncode = nil;
  lsqpack_enc_end_header: TLsqpackEncEndHeader = nil;

  lsqpack_dec_init: TLsqpackDecInit = nil;
  lsqpack_dec_cleanup: TLsqpackDecCleanup = nil;
  lsqpack_dec_enc_in: TLsqpackDecEncIn = nil;
  lsqpack_dec_header_in: TLsqpackDecHeaderIn = nil;
  lsqpack_dec_cancel_stream_id: TLsqpackDecCancelStreamId = nil;

type

  TLsQpackLoader = class
  private
    FDllHandle: THandle;
    FLoaded: Boolean;
    procedure ResolveEntryPoints;
  public
    constructor Create(const ADllPath: string = 'ls-qpack.dll');
    destructor Destroy; override;

    procedure Start(const ADllPath: string = 'ls-qpack.dll');
    procedure Stop;

    property Loaded: Boolean read FLoaded;
  end;

implementation

constructor TLsQpackLoader.Create(const ADllPath: string);
begin
  inherited Create;
  FLoaded := False;
  FDllHandle := 0;
end;

destructor TLsQpackLoader.Destroy;
begin
  Stop;
  inherited Destroy;
end;

procedure TLsQpackLoader.ResolveEntryPoints;
begin
  @lsqpack_enc_preinit := GetProcAddress(FDllHandle, 'lsqpack_enc_preinit');
  @lsqpack_enc_init := GetProcAddress(FDllHandle, 'lsqpack_enc_init');
  @lsqpack_enc_cleanup := GetProcAddress(FDllHandle, 'lsqpack_enc_cleanup');
  @lsqpack_enc_start_header := GetProcAddress(FDllHandle, 'lsqpack_enc_start_header');
  @lsqpack_enc_encode := GetProcAddress(FDllHandle, 'lsqpack_enc_encode');
  @lsqpack_enc_end_header := GetProcAddress(FDllHandle, 'lsqpack_enc_end_header');

  @lsqpack_dec_init := GetProcAddress(FDllHandle, 'lsqpack_dec_init');
  @lsqpack_dec_cleanup := GetProcAddress(FDllHandle, 'lsqpack_dec_cleanup');
  @lsqpack_dec_enc_in := GetProcAddress(FDllHandle, 'lsqpack_dec_enc_in');
  @lsqpack_dec_header_in := GetProcAddress(FDllHandle, 'lsqpack_dec_header_in');
  @lsqpack_dec_cancel_stream_id := GetProcAddress(FDllHandle, 'lsqpack_dec_cancel_stream_id');

  if not Assigned(lsqpack_enc_init) or not Assigned(lsqpack_dec_init) then
    raise EQpackError.CreateCode('Could not find required entry points in ls-qpack.dll', -3);
end;

procedure TLsQpackLoader.Start(const ADllPath: string);
begin
  if FLoaded then Exit;

  FDllHandle := LoadLibrary(PChar(ADllPath));
  if FDllHandle = 0 then
    raise EQpackError.CreateCode('Failed to load ' + ADllPath, GetLastError);

  try
    ResolveEntryPoints;
    FLoaded := True;
  except
    FreeLibrary(FDllHandle);
    FDllHandle := 0;
    raise;
  end;
end;

procedure TLsQpackLoader.Stop;
begin
  if not FLoaded then 
     Exit;

  @lsqpack_enc_preinit := nil;
  @lsqpack_enc_init := nil;
  @lsqpack_enc_cleanup := nil;
  @lsqpack_enc_start_header := nil;
  @lsqpack_enc_encode := nil;
  @lsqpack_enc_end_header := nil;
  @lsqpack_dec_init := nil;
  @lsqpack_dec_cleanup := nil;
  @lsqpack_dec_enc_in := nil;
  @lsqpack_dec_header_in := nil;

  FreeLibrary(FDllHandle);
  FDllHandle := 0;
  FLoaded := False;
end;

end.
