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
unit GTerm.ConPty.Loader;

interface

uses
  Winapi.Windows, System.SysUtils;

type
  PHPCON = ^HPCON;
  HPCON = THandle;

  TCreatePseudoConsoleFunc = function(
    size: COORD;
    hInput: THandle;
    hOutput: THandle;
    dwFlags: DWORD;
    phPC: PHPCON
  ): HRESULT; stdcall;

  TResizePseudoConsoleFunc = function(
    hPC: HPCON;
    size: COORD
  ): HRESULT; stdcall;

  TClosePseudoConsoleFunc = procedure(
    hPC: HPCON
  ); stdcall;

  TGTermConPtyLoader = class
  private
    class var FModule: HMODULE;
    class var FInitialized: Boolean;
    class var FCreatePseudoConsole: TCreatePseudoConsoleFunc;
    class var FResizePseudoConsole: TResizePseudoConsoleFunc;
    class var FClosePseudoConsole: TClosePseudoConsoleFunc;
    class function TryBind(AModule: HMODULE): Boolean;
  public
    class procedure Initialize;
    class function CreatePseudoConsole(size: COORD; hInput, hOutput: THandle; dwFlags: DWORD; phPC: PHPCON): HRESULT;
    class function ResizePseudoConsole(hPC: HPCON; size: COORD): HRESULT;
    class procedure ClosePseudoConsole(hPC: HPCON);
    class function IsAvailable: Boolean;
  end;

implementation

class function TGTermConPtyLoader.TryBind(AModule: HMODULE): Boolean;
begin
  Result := False;
  if AModule = 0 then
    Exit;
  @FCreatePseudoConsole := GetProcAddress(AModule, 'CreatePseudoConsole');
  @FResizePseudoConsole := GetProcAddress(AModule, 'ResizePseudoConsole');
  @FClosePseudoConsole := GetProcAddress(AModule, 'ClosePseudoConsole');
  Result := Assigned(FCreatePseudoConsole) and Assigned(FResizePseudoConsole) and Assigned(FClosePseudoConsole);
end;

class procedure TGTermConPtyLoader.Initialize;
var
  TargetDll: string;
  ModHandle: HMODULE;
begin
  if FInitialized then
    Exit;
  FInitialized := True;

  TargetDll := ExtractFilePath(ParamStr(0)) + 'conpty.dll';
  if FileExists(TargetDll) then
  begin
    ModHandle := LoadLibrary(PChar(TargetDll));
    if ModHandle <> 0 then
    begin
      if TryBind(ModHandle) then
      begin
        FModule := ModHandle;
        Exit;
      end;
      FreeLibrary(ModHandle);
    end;
  end;

  ModHandle := GetModuleHandle('kernel32.dll');
  if ModHandle <> 0 then
  begin
    if TryBind(ModHandle) then
    begin
      FModule := ModHandle;
      Exit;
    end;
  end;

  ModHandle := LoadLibrary('kernelbase.dll');
  if ModHandle <> 0 then
  begin
    if TryBind(ModHandle) then
    begin
      FModule := ModHandle;
      Exit;
    end;
  end;
end;

class function TGTermConPtyLoader.CreatePseudoConsole(size: COORD; hInput, hOutput: THandle; dwFlags: DWORD; phPC: PHPCON): HRESULT;
begin
  Initialize;
  if Assigned(FCreatePseudoConsole) then
    Result := FCreatePseudoConsole(size, hInput, hOutput, dwFlags, phPC)
  else
    Result := E_NOTIMPL;
end;

class function TGTermConPtyLoader.ResizePseudoConsole(hPC: HPCON; size: COORD): HRESULT;
begin
  Initialize;
  if Assigned(FResizePseudoConsole) then
    Result := FResizePseudoConsole(hPC, size)
  else
    Result := E_NOTIMPL;
end;

class procedure TGTermConPtyLoader.ClosePseudoConsole(hPC: HPCON);
begin
  Initialize;
  if Assigned(FClosePseudoConsole) then
    FClosePseudoConsole(hPC);
end;

class function TGTermConPtyLoader.IsAvailable: Boolean;
begin
  Initialize;
  Result := Assigned(FCreatePseudoConsole);
end;

initialization

finalization
  if (TGTermConPtyLoader.FModule <> 0) and (TGTermConPtyLoader.FModule <> GetModuleHandle('kernel32.dll')) then
  begin
    FreeLibrary(TGTermConPtyLoader.FModule);
    TGTermConPtyLoader.FModule := 0;
  end;

end.
