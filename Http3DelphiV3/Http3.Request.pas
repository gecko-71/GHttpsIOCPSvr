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

unit Http3.Request;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  MsQuic.Types;

type
  TQuicHttp3Request = class
  private
    FStream: HQUIC;
    FHeaders: TDictionary<string, string>;
    FMethod: string;
    FPath: string;
    FScheme: string;
    FAuthority: string;
    FBody: TBytes;
    FHasInvalidHeader: Boolean;
    FHasRegularHeaderSeen: Boolean;
    FErrorMessage: string;
  public
    constructor Create(AStream: HQUIC);
    destructor Destroy; override;

    function AddHeader(const Name, Value: string): Boolean;
    procedure AppendBody(const Data: PByte; Length: Integer);

    property Stream: HQUIC read FStream;
    property Method: string read FMethod;
    property Path: string read FPath;
    property Scheme: string read FScheme;
    property Authority: string read FAuthority;
    property Headers: TDictionary<string, string> read FHeaders;
    property Body: TBytes read FBody;
    property HasInvalidHeader: Boolean read FHasInvalidHeader;
    property ErrorMessage: string read FErrorMessage;
  end;

implementation

constructor TQuicHttp3Request.Create(AStream: HQUIC);
begin
  inherited Create;
  FStream := AStream;
  FHeaders := TDictionary<string, string>.Create;
  SetLength(FBody, 0);
end;

destructor TQuicHttp3Request.Destroy;
begin
  FHeaders.Free;
  inherited Destroy;
end;

function TQuicHttp3Request.AddHeader(const Name, Value: string): Boolean;
var
  LowerName: string;
begin
  Result := False;
  LowerName := LowerCase(Trim(Name));

  if (LowerName = 'connection') or (LowerName = 'keep-alive') or
     (LowerName = 'proxy-connection') or (LowerName = 'transfer-encoding') or
     (LowerName = 'upgrade') or ((LowerName = 'te') and (LowerCase(Trim(Value)) <> 'trailers')) then
  begin
    FHasInvalidHeader := True;
    FErrorMessage := 'Prohibited connection-specific header: ' + LowerName;
    Exit(False);
  end;

  if (Length(LowerName) > 0) and (LowerName[1] = ':') then
  begin
    if FHasRegularHeaderSeen then
    begin
      FHasInvalidHeader := True;
      FErrorMessage := 'Pseudo-header appeared after regular header: ' + LowerName;
      Exit(False);
    end;
    if not ((LowerName = ':method') or (LowerName = ':path') or
            (LowerName = ':scheme') or (LowerName = ':authority') or
            (LowerName = ':protocol') or (LowerName = ':status')) then
    begin
      FHasInvalidHeader := True;
      FErrorMessage := 'Unknown pseudo-header: ' + LowerName;
      Exit(False);
    end;
  end
  else
    FHasRegularHeaderSeen := True;

  if LowerName = ':method' then
    FMethod := Value
  else if LowerName = ':path' then
    FPath := Value
  else if LowerName = ':scheme' then
    FScheme := Value
  else if LowerName = ':authority' then
    FAuthority := Value
  else
    FHeaders.AddOrSetValue(LowerName, Value);
  Result := True;
end;

procedure TQuicHttp3Request.AppendBody(const Data: PByte; Length: Integer);
var
  OldLen: Integer;
begin
  if (Data = nil) or (Length <= 0) then Exit;
  OldLen := System.Length(FBody);
  SetLength(FBody, OldLen + Length);
  Move(Data^, FBody[OldLen], Length);
end;

end.
