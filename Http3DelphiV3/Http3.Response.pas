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

unit Http3.Response;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  MsQuic.Types, MsQuic.ApiTable, Quic.Server;

type
  TQuicHttp3Response = class
  private
    FStream: HQUIC;
    FMsQuicApi: PQuicApiTable;
    FHeaders: TDictionary<string, string>;
    FStatusCode: Integer;
    FBody: TBytes;
  public
    constructor Create(AApi: PQuicApiTable; AStream: HQUIC);
    destructor Destroy; override;
    procedure AddHeader(const Name, Value: string);
    procedure SetBodyBytes(const ABytes: TBytes; const AContentType: string = '');
    property StatusCode: Integer read FStatusCode write FStatusCode;
    property Body: TBytes read FBody;
  end;

implementation

constructor TQuicHttp3Response.Create(AApi: PQuicApiTable; AStream: HQUIC);
begin
  inherited Create;
  FMsQuicApi := AApi;
  FStream := AStream;
  FHeaders := TDictionary<string, string>.Create;
  FStatusCode := 200;
  SetLength(FBody, 0);
end;

destructor TQuicHttp3Response.Destroy;
begin
  FHeaders.Free;
  inherited Destroy;
end;

procedure TQuicHttp3Response.AddHeader(const Name, Value: string);
begin
  FHeaders.AddOrSetValue(Name, Value);
end;

procedure TQuicHttp3Response.SetBodyBytes(const ABytes: TBytes; const AContentType: string);
begin
  FBody := Copy(ABytes);
  if AContentType <> '' then
    AddHeader('content-type', AContentType);
  if Length(ABytes) > 0 then
    AddHeader('content-length', IntToStr(Length(ABytes)));
end;

end.
