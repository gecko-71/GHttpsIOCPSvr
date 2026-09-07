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

unit MsQuic.Loader;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  Winapi.Windows, System.SysUtils, System.SyncObjs,
  Quick.Logger,
  MsQuic.Types, MsQuic.ApiTable, MsQuic.Errors;

type

  TQuicOpenVersionFn = function(Version: UInt32; out QuicApi: PQuicApiTable): QUIC_STATUS; cdecl;
  TQuicCloseFn = procedure(QuicApi: Pointer); cdecl;

  TMsQuicLibrary = class
  private
    FDllHandle: THandle;
    FApiTable: PQuicApiTable;
    FLoaded: Boolean;
    FDllPath: string;
    FLock: TCriticalSection;
    FMsQuicOpenVersion: TQuicOpenVersionFn;
    FMsQuicClose: TQuicCloseFn;
    procedure ResolveEntryPoints;
  public
    constructor Create(const ADllPath: string = 'msquic.dll');
    destructor Destroy; override;
    procedure Start;
    procedure Stop;
    property Loaded: Boolean read FLoaded;
    property Api: PQuicApiTable read FApiTable;
  end;

implementation

constructor TMsQuicLibrary.Create(const ADllPath: string);
begin
  inherited Create;
  FDllPath := ADllPath;
  FLoaded := False;
  FDllHandle := 0;
  FApiTable := nil;
  FMsQuicOpenVersion := nil;
  FMsQuicClose := nil;
  FLock := TCriticalSection.Create;
end;

destructor TMsQuicLibrary.Destroy;
begin
  Stop;
  FLock.Free;
  inherited Destroy;
end;

procedure TMsQuicLibrary.ResolveEntryPoints;
begin
  @FMsQuicOpenVersion := GetProcAddress(FDllHandle, 'MsQuicOpenVersion');
  if not Assigned(FMsQuicOpenVersion) then
    raise EMsQuicError.Create('Function MsQuicOpenVersion not found in library', 0);

  @FMsQuicClose := GetProcAddress(FDllHandle, 'MsQuicClose');
  if not Assigned(FMsQuicClose) then
    raise EMsQuicError.Create('Function MsQuicClose not found in library', 0);
end;

procedure TMsQuicLibrary.Start;
var
  Status: QUIC_STATUS;
  ErrCode: DWORD;
  LibVer: array[0..3] of UInt32;
  LibVerSize: UInt32;
begin
  FLock.Acquire;
  try
    if FLoaded then 
	   Exit;

    FDllHandle := LoadLibrary(PChar(FDllPath));
    if FDllHandle = 0 then
    begin
      ErrCode := GetLastError;
      if ErrCode = ERROR_BAD_EXE_FORMAT then
        raise EMsQuicError.Create('Failed to load library: ' + FDllPath + '. Architecture mismatch (e.g. 32-bit vs 64-bit). GetLastError=' + IntToStr(ErrCode), 0)
      else
        raise EMsQuicError.Create('Failed to load library: ' + FDllPath + '. GetLastError=' + IntToStr(ErrCode), 0);
    end;

    try
      ResolveEntryPoints;
      Status := FMsQuicOpenVersion(QUIC_API_VERSION_2, FApiTable);
      if QuicFailed(Status) then
        raise EMsQuicError.Create('MsQuicOpenVersion failed', Status);

      LibVerSize := SizeOf(LibVer);
      FillChar(LibVer, LibVerSize, 0);
      Status := FApiTable^.GetParam(nil, $01000004, LibVerSize, @LibVer);
      if QuicSucceeded(Status) then
      begin
        if LibVer[0] <> 2 then
        begin
          raise EMsQuicError.Create('Version Guard: Incompatible msquic.dll version! ' +
            'Expected Major Version 2, but found ' + IntToStr(LibVer[0]) + '.' + IntToStr(LibVer[1]) +
            '. Please update your msquic.dll to a compatible Version 2 release.', 0);
        end;

        Logger.Info('[Version Guard] MSQuic ABI Version verified. Loaded msquic.dll v%d.%d.%d.%d',
          [LibVer[0], LibVer[1], LibVer[2], LibVer[3]]);
      end
      else
      begin
        Logger.Warn('[Version Guard] Could not query msquic.dll library version! GetParam returned: 0x%x', [Status]);
      end;

      FLoaded := True;
    except
      FreeLibrary(FDllHandle);
      FDllHandle := 0;
      FMsQuicOpenVersion := nil;
      FMsQuicClose := nil;
      FApiTable := nil;
      raise;
    end;
  finally
    FLock.Release;
  end;
end;

procedure TMsQuicLibrary.Stop;
begin
  FLock.Acquire;
  try
    if not FLoaded then 
	   Exit;

    if Assigned(FApiTable) and Assigned(FMsQuicClose) then
    begin
      FMsQuicClose(FApiTable);
      FApiTable := nil;
    end;

    FLoaded := False;
  finally
    FLock.Release;
  end;
end;

end.
