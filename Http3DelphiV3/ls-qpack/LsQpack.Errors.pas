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

unit LsQpack.Errors;

interface

uses
  System.SysUtils;

type

  EQpackError = class(Exception)
  public
    Code: Integer;
    constructor CreateCode(const Msg: string; ACode: Integer);
  end;

procedure CheckQpackStatus(ACode: Integer; const AOperation: string);

implementation

constructor EQpackError.CreateCode(const Msg: string; ACode: Integer);
begin
  inherited Create(Msg + ' (Code: ' + IntToStr(ACode) + ')');
  Code := ACode;
end;

procedure CheckQpackStatus(ACode: Integer; const AOperation: string);
begin

  if ACode <> 0 then
    raise EQpackError.CreateCode('Operation ' + AOperation + ' failed', ACode);
end;

end.
