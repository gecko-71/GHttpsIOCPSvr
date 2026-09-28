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
  LsQpack.Decoder,
  Http3.Types;

type
  THttp3StreamType = (h3stUnknown, h3stBidirectional, h3stControl, h3stQpackEncoder, h3stQpackDecoder, h3stPush);

  THttp3HeaderEntry = record
    Name: string;
    Value: string;
  end;

  THttp3RequestData = record
  private
    FHeaders: TArray<THttp3HeaderEntry>;
    FHeaderCount: Integer;
    FMethod: string;
    FPath: string;
    FScheme: string;
    FAuthority: string;
    FHasInvalidHeader: Boolean;
    FHasRegularHeaderSeen: Boolean;
    FErrorMessage: string;
    FErrorCode: UInt64;
  public
    procedure Clear;
    function AddHeader(const AName, AValue: string): Boolean;
    function TryGetHeader(const AName: string; out AValue: string): Boolean;
    function HasHeader(const AName: string): Boolean;

    property Method: string read FMethod write FMethod;
    property Path: string read FPath write FPath;
    property Scheme: string read FScheme write FScheme;
    property Authority: string read FAuthority write FAuthority;
    property HeaderCount: Integer read FHeaderCount;
    property HasInvalidHeader: Boolean read FHasInvalidHeader;
    property ErrorMessage: string read FErrorMessage;
    property ErrorCode: UInt64 read FErrorCode;
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
    FSettingsReceived: Boolean;
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
    property SettingsReceived: Boolean read FSettingsReceived write FSettingsReceived;
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
    FClientControlStream: HQUIC;
    FClientQpackEncoderStream: HQUIC;
    FClientQpackDecoderStream: HQUIC;
    FPeerQpackMaxTableCapacity: UInt64;
    FPeerQpackBlockedStreams: UInt64;
    FPeerMaxFieldSectionSize: UInt64;
    FPeerEnableConnectProtocol: Boolean;
    FPeerH3Datagram: Boolean;
    FClientGoAwayReceived: Boolean;
    FClientGoAwayStreamId: UInt64;
    FHasMaxPushId: Boolean;
    FClientMaxPushId: UInt64;
    FStreams: TObjectDictionary<HQUIC, THttp3StreamState>;
    FLock: TCriticalSection;
  public
    constructor Create(AApi: PQuicApiTable; AConnection: HQUIC);
    destructor Destroy; override;
    procedure ApplyPeerSettings;

    property Connection: HQUIC read FConnection;
    property ControlStream: HQUIC read FControlStream write FControlStream;
    property QpackEncoderStream: HQUIC read FQpackEncoderStream write FQpackEncoderStream;
    property QpackDecoderStream: HQUIC read FQpackDecoderStream write FQpackDecoderStream;
    property ClientControlStream: HQUIC read FClientControlStream write FClientControlStream;
    property ClientQpackEncoderStream: HQUIC read FClientQpackEncoderStream write FClientQpackEncoderStream;
    property ClientQpackDecoderStream: HQUIC read FClientQpackDecoderStream write FClientQpackDecoderStream;
    property PeerQpackMaxTableCapacity: UInt64 read FPeerQpackMaxTableCapacity write FPeerQpackMaxTableCapacity;
    property PeerQpackBlockedStreams: UInt64 read FPeerQpackBlockedStreams write FPeerQpackBlockedStreams;
    property PeerMaxFieldSectionSize: UInt64 read FPeerMaxFieldSectionSize write FPeerMaxFieldSectionSize;
    property PeerEnableConnectProtocol: Boolean read FPeerEnableConnectProtocol write FPeerEnableConnectProtocol;
    property PeerH3Datagram: Boolean read FPeerH3Datagram write FPeerH3Datagram;
    property ClientGoAwayReceived: Boolean read FClientGoAwayReceived write FClientGoAwayReceived;
    property ClientGoAwayStreamId: UInt64 read FClientGoAwayStreamId write FClientGoAwayStreamId;
    property HasMaxPushId: Boolean read FHasMaxPushId write FHasMaxPushId;
    property ClientMaxPushId: UInt64 read FClientMaxPushId write FClientMaxPushId;
    property QpackEncoder: TQpackEncoder read FQpackEncoder;
    property QpackDecoder: TQpackDecoder read FQpackDecoder;
    property Streams: TObjectDictionary<HQUIC, THttp3StreamState> read FStreams;
    property Lock: TCriticalSection read FLock;
  end;

implementation

procedure THttp3RequestData.Clear;
begin
  FHeaderCount := 0;
  SetLength(FHeaders, 32);
  FMethod := '';
  FPath := '';
  FScheme := '';
  FAuthority := '';
  FHasInvalidHeader := False;
  FHasRegularHeaderSeen := False;
  FErrorMessage := '';
  FErrorCode := 0;
end;

function THttp3RequestData.AddHeader(const AName, AValue: string): Boolean;
var
  LowerName: string;
begin
  Result := False;
  LowerName := LowerCase(Trim(AName));

  if (LowerName = 'connection') or (LowerName = 'keep-alive') or
     (LowerName = 'proxy-connection') or (LowerName = 'transfer-encoding') or
     (LowerName = 'upgrade') or ((LowerName = 'te') and (LowerCase(Trim(AValue)) <> 'trailers')) then
  begin
    FHasInvalidHeader := True;
    FErrorMessage := 'Prohibited connection-specific header: ' + LowerName;
    FErrorCode := H3_MESSAGE_ERROR;
    Exit(False);
  end;

  if (Length(LowerName) > 0) and (LowerName[1] = ':') then
  begin
    if FHasRegularHeaderSeen then
    begin
      FHasInvalidHeader := True;
      FErrorMessage := 'Pseudo-header appeared after regular header: ' + LowerName;
      FErrorCode := H3_MESSAGE_ERROR;
      Exit(False);
    end;
    if not ((LowerName = ':method') or (LowerName = ':path') or
            (LowerName = ':scheme') or (LowerName = ':authority') or
            (LowerName = ':protocol') or (LowerName = ':status')) then
    begin
      FHasInvalidHeader := True;
      FErrorMessage := 'Unknown pseudo-header: ' + LowerName;
      FErrorCode := H3_MESSAGE_ERROR;
      Exit(False);
    end;
  end
  else
    FHasRegularHeaderSeen := True;

  if LowerName = ':method' then
    FMethod := AValue
  else if LowerName = ':path' then
    FPath := AValue
  else if LowerName = ':scheme' then
    FScheme := AValue
  else if LowerName = ':authority' then
    FAuthority := AValue
  else
  begin
    if Length(FHeaders) = 0 then
      SetLength(FHeaders, 32);
    if FHeaderCount >= Length(FHeaders) then
    begin
      if Length(FHeaders) >= 128 then
      begin
        FHasInvalidHeader := True;
        FErrorMessage := 'Header count limit exceeded';
        FErrorCode := H3_EXCESSIVE_LOAD;
        Exit(False);
      end;
      SetLength(FHeaders, Length(FHeaders) * 2);
    end;
    FHeaders[FHeaderCount].Name := LowerName;
    FHeaders[FHeaderCount].Value := AValue;
    Inc(FHeaderCount);
  end;
  Result := True;
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

procedure THttp3ConnectionState.ApplyPeerSettings;
begin
  FLock.Enter;
  try
    FQpackEncoder.Free;
    FQpackEncoder := TQpackEncoder.Create(Cardinal(FPeerQpackMaxTableCapacity), Cardinal(FPeerQpackBlockedStreams));
  finally
    FLock.Leave;
  end;
end;

end.
