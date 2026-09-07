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

unit Http3.Connection;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils, System.Generics.Collections, System.SyncObjs,
  MsQuic.Types,
  MsQuic.ApiTable,
  Quic.Server,
  LsQpack.Encoder,
  LsQpack.Decoder;

type
  THttp3StreamType = (h3stUnknown, h3stBidirectional, h3stControl, h3stQpackEncoder, h3stQpackDecoder, h3stPush);

  THttp3HeaderEntry = record
    Name: string;
    Value: string;
  end;

  THttp3RequestData = record
  private
    FHeaders: array[0..31] of THttp3HeaderEntry;
    FHeaderCount: Integer;
    FMethod: string;
    FPath: string;
    FScheme: string;
    FAuthority: string;
  public
    procedure Clear;
    procedure AddHeader(const AName, AValue: string);
    function TryGetHeader(const AName: string; out AValue: string): Boolean;
    function HasHeader(const AName: string): Boolean;

    property Method: string read FMethod write FMethod;
    property Path: string read FPath write FPath;
    property Scheme: string read FScheme write FScheme;
    property Authority: string read FAuthority write FAuthority;
    property HeaderCount: Integer read FHeaderCount;
  end;

  THttp3StreamState = class
  private
    FStream: HQUIC;
    FBuffer: TBytes;
    FRequest: THttp3RequestData;
    FStreamType: THttp3StreamType;
    FIsTypeIdentified: Boolean;
    FIsBidirectional: Boolean;
    FResponseSent: Boolean;
    FRequestBody: TBytes;
    FHeaderPairs: TArray<TPair<string, string>>;
  public
    constructor Create(AStream: HQUIC; AIsBidirectional: Boolean);
    destructor Destroy; override;
    procedure AppendRequestBody(const Data: TBytes);
    procedure ClearRequestBody;

    property Stream: HQUIC read FStream;
    property Buffer: TBytes read FBuffer write FBuffer;
    property Request: THttp3RequestData read FRequest write FRequest;
    property RequestBody: TBytes read FRequestBody write FRequestBody;
    property HeaderPairs: TArray<TPair<string, string>> read FHeaderPairs write FHeaderPairs;
    property StreamType: THttp3StreamType read FStreamType write FStreamType;
    property IsTypeIdentified: Boolean read FIsTypeIdentified write FIsTypeIdentified;
    property IsBidirectional: Boolean read FIsBidirectional;
    property ResponseSent: Boolean read FResponseSent write FResponseSent;
  end;

  THttp3ConnectionState = class
  private
    FConnection: HQUIC;
    FMsQuicApi: PQuicApiTable;
    FQpackEncoder: TQpackEncoder;
    FQpackDecoder: TQpackDecoder;
    FControlStream: HQUIC;
    FQpackEncoderStream: HQUIC;
    FQpackDecoderStream: HQUIC;
    FStreams: TObjectDictionary<HQUIC, THttp3StreamState>;
    FLock: TCriticalSection;
  public
    constructor Create(AApi: PQuicApiTable; AConnection: HQUIC);
    destructor Destroy; override;

    property Connection: HQUIC read FConnection;
    property ControlStream: HQUIC read FControlStream write FControlStream;
    property QpackEncoderStream: HQUIC read FQpackEncoderStream write FQpackEncoderStream;
    property QpackDecoderStream: HQUIC read FQpackDecoderStream write FQpackDecoderStream;
    property QpackEncoder: TQpackEncoder read FQpackEncoder;
    property QpackDecoder: TQpackDecoder read FQpackDecoder;
    property Streams: TObjectDictionary<HQUIC, THttp3StreamState> read FStreams;
    property Lock: TCriticalSection read FLock;
  end;

implementation

procedure THttp3RequestData.Clear;
begin
  FHeaderCount := 0;
  FMethod := '';
  FPath := '';
  FScheme := '';
  FAuthority := '';
end;

procedure THttp3RequestData.AddHeader(const AName, AValue: string);
var
  LowerName: string;
begin
  LowerName := LowerCase(AName);
  if LowerName = ':method' then
    FMethod := AValue
  else if LowerName = ':path' then
    FPath := AValue
  else if LowerName = ':scheme' then
    FScheme := AValue
  else if LowerName = ':authority' then
    FAuthority := AValue
  else if FHeaderCount < Length(FHeaders) then
  begin
    FHeaders[FHeaderCount].Name := LowerName;
    FHeaders[FHeaderCount].Value := AValue;
    Inc(FHeaderCount);
  end;
end;

function THttp3RequestData.TryGetHeader(const AName: string; out AValue: string): Boolean;
var
  I: Integer;
  LowerName: string;
begin
  LowerName := LowerCase(AName);
  for I := 0 to FHeaderCount - 1 do
  begin
    if FHeaders[I].Name = LowerName then
    begin
      AValue := FHeaders[I].Value;
      Exit(True);
    end;
  end;
  AValue := '';
  Result := False;
end;

function THttp3RequestData.HasHeader(const AName: string): Boolean;
var
  Dummy: string;
begin
  Result := TryGetHeader(AName, Dummy);
end;

constructor THttp3StreamState.Create(AStream: HQUIC; AIsBidirectional: Boolean);
begin
  inherited Create;
  FStream := AStream;
  SetLength(FBuffer, 0);
  FRequest.Clear;
  FResponseSent := False;
  FIsBidirectional := AIsBidirectional;
  if AIsBidirectional then
  begin
    FStreamType := h3stBidirectional;
    FIsTypeIdentified := True;
  end
  else
  begin
    FStreamType := h3stUnknown;
    FIsTypeIdentified := False;
  end;
end;

destructor THttp3StreamState.Destroy;
begin
  SetLength(FBuffer, 0);
  SetLength(FRequestBody, 0);
  inherited Destroy;
end;

procedure THttp3StreamState.AppendRequestBody(const Data: TBytes);
var
  OldSize: Integer;
begin
  if Length(Data) = 0 then Exit;
  OldSize := Length(FRequestBody);
  SetLength(FRequestBody, OldSize + Length(Data));
  Move(Data[0], FRequestBody[OldSize], Length(Data));
end;

procedure THttp3StreamState.ClearRequestBody;
begin
  SetLength(FRequestBody, 0);
end;

constructor THttp3ConnectionState.Create(AApi: PQuicApiTable; AConnection: HQUIC);
begin
  inherited Create;
  FMsQuicApi := AApi;
  FConnection := AConnection;
  FControlStream := nil;
  FStreams := TObjectDictionary<HQUIC, THttp3StreamState>.Create([doOwnsValues]);

  FLock := TCriticalSection.Create;
  FQpackEncoder := TQpackEncoder.Create(4096, 100);
  FQpackDecoder := TQpackDecoder.Create(4096, 100);
end;

destructor THttp3ConnectionState.Destroy;
begin
  if FMsQuicApi <> nil then
  begin
    if FControlStream <> nil then
    begin
      FMsQuicApi.StreamClose(FControlStream);
      FControlStream := nil;
    end;
    if FQpackEncoderStream <> nil then
    begin
      FMsQuicApi.StreamClose(FQpackEncoderStream);
      FQpackEncoderStream := nil;
    end;
    if FQpackDecoderStream <> nil then
    begin
      FMsQuicApi.StreamClose(FQpackDecoderStream);
      FQpackDecoderStream := nil;
    end;
  end;

  FQpackEncoder.Free;
  FQpackDecoder.Free;
  FStreams.Free;
  FLock.Free;
  inherited Destroy;
end;

end.
