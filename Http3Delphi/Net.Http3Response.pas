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
unit Net.Http3Response;

interface

uses
  System.SysUtils, System.Classes, Net.QPACK, Net.Http3Frames;

type
  THttp3Response = class
  private
    FStatus: Integer;
    FHeaders: THttpHeaders;
    FBody: TBytes;
  public
    constructor Create;
    procedure SetStatus(Code: Integer);
    procedure AddHeader(const Name, Value: string);
    procedure SetBody(const Content: string; const ContentType: string = 'text/html');
    procedure SetBodyString(const Content: string; const ContentType: string = 'text/html');
    procedure SetBodyBytes(const Data: TBytes; const ContentType: string);
    property StatusCode: Integer read FStatus write SetStatus;
    property BodyBytes: TBytes read FBody;
    function GetHeadersFrame: TBytes;
    function ToHttp3Frames: TBytes;
  end;

implementation

constructor THttp3Response.Create;
begin
  inherited Create;
  FStatus := 200;
  SetLength(FHeaders, 0);
  SetLength(FBody, 0);
end;

procedure THttp3Response.SetStatus(Code: Integer);
begin
  FStatus := Code;
end;

procedure THttp3Response.AddHeader(const Name, Value: string);
var
  Idx: Integer;
begin
  Idx := Length(FHeaders);
  SetLength(FHeaders, Idx + 1);
  FHeaders[Idx].Name := LowerCase(Name);
  FHeaders[Idx].Value := Value;
end;

procedure THttp3Response.SetBody(const Content: string; const ContentType: string);
begin
  FBody := TEncoding.UTF8.GetBytes(Content);
  AddHeader('content-type', ContentType);
  AddHeader('content-length', IntToStr(Length(FBody)));
end;

procedure THttp3Response.SetBodyString(const Content: string; const ContentType: string);
begin
  SetBody(Content, ContentType);
end;

procedure THttp3Response.SetBodyBytes(const Data: TBytes; const ContentType: string);
begin
  FBody := Copy(Data, 0, Length(Data));
  AddHeader('content-type', ContentType);
  AddHeader('content-length', IntToStr(Length(FBody)));
end;

function THttp3Response.GetHeadersFrame: TBytes;
var
  QpackHeaders: THttpHeaders;
  EncodedHeaders: TBytes;
  I: Integer;
begin
  SetLength(QpackHeaders, 0);

  SetLength(QpackHeaders, 1);
  QpackHeaders[0].Name := ':status';
  QpackHeaders[0].Value := IntToStr(FStatus);

  for I := Low(FHeaders) to High(FHeaders) do
  begin
    if (Length(FHeaders[I].Name) > 0) and (FHeaders[I].Name[1] = ':') then
    begin
      SetLength(QpackHeaders, Length(QpackHeaders) + 1);
      QpackHeaders[Length(QpackHeaders) - 1] := FHeaders[I];
    end;
  end;

  for I := Low(FHeaders) to High(FHeaders) do
  begin
    if (Length(FHeaders[I].Name) = 0) or (FHeaders[I].Name[1] <> ':') then
    begin
      SetLength(QpackHeaders, Length(QpackHeaders) + 1);
      QpackHeaders[Length(QpackHeaders) - 1] := FHeaders[I];
    end;
  end;

  EncodedHeaders := QpackEncode(QpackHeaders);
  Result := BuildHttp3Frame(HTTP3_FRAME_HEADERS, EncodedHeaders);
end;

function THttp3Response.ToHttp3Frames: TBytes;
var
  HeadersFrame, DataFrame: TBytes;
begin
  HeadersFrame := GetHeadersFrame;

  if Length(FBody) > 0 then
    DataFrame := BuildHttp3Frame(HTTP3_FRAME_DATA, FBody)
  else
    SetLength(DataFrame, 0);

  SetLength(Result, Length(HeadersFrame) + Length(DataFrame));
  if Length(HeadersFrame) > 0 then
    Move(HeadersFrame[0], Result[0], Length(HeadersFrame));
  if Length(DataFrame) > 0 then
    Move(DataFrame[0], Result[Length(HeadersFrame)], Length(DataFrame));
end;

end.

