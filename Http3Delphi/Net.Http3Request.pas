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

unit Net.Http3Request;

interface

uses
  System.SysUtils, System.Classes, Net.QPACK, WinApi.MsQuic;

type
  THttp3Request = class
  private
    FMethod: string;
    FPath: string;
    FScheme: string;
    FAuthority: string;
    FHeaders: THttpHeaders;
    FBody: TBytes;
    FStreamHandle: HQUIC;
  public
    constructor Create(const AHeaders: THttpHeaders; AStreamHandle: HQUIC);
    
    procedure AppendBody(const Data: TBytes);
    function GetHeader(const Name: string): string;

    property Method: string read FMethod;
    property Path: string read FPath;
    property Scheme: string read FScheme;
    property Authority: string read FAuthority;
    property Host: string read FAuthority;
    property Headers: THttpHeaders read FHeaders;
    property Body: TBytes read FBody;
    property StreamHandle: HQUIC read FStreamHandle;
  end;

implementation

constructor THttp3Request.Create(const AHeaders: THttpHeaders; AStreamHandle: HQUIC);
var
  I: Integer;
begin
  inherited Create;
  FHeaders := AHeaders;
  FStreamHandle := AStreamHandle;
  SetLength(FBody, 0);

  for I := Low(FHeaders) to High(FHeaders) do
  begin
    if FHeaders[I].Name = ':method' then
      FMethod := FHeaders[I].Value
    else if FHeaders[I].Name = ':path' then
      FPath := FHeaders[I].Value
    else if FHeaders[I].Name = ':scheme' then
      FScheme := FHeaders[I].Value
    else if FHeaders[I].Name = ':authority' then
      FAuthority := FHeaders[I].Value;
  end;
end;

procedure THttp3Request.AppendBody(const Data: TBytes);
var
  OldLen, NewLen: Integer;
begin
  if Length(Data) = 0 then
    Exit;
  OldLen := Length(FBody);
  NewLen := OldLen + Length(Data);
  SetLength(FBody, NewLen);
  Move(Data[0], FBody[OldLen], Length(Data));
end;

function THttp3Request.GetHeader(const Name: string): string;
var
  I: Integer;
  LowerName: string;
begin
  Result := '';
  LowerName := LowerCase(Name);
  for I := Low(FHeaders) to High(FHeaders) do
  begin
    if LowerCase(FHeaders[I].Name) = LowerName then
      Exit(FHeaders[I].Value);
  end;
end;

end.
