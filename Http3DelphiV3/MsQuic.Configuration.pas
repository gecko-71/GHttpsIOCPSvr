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

unit MsQuic.Configuration;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  MsQuic.Types, MsQuic.ApiTable, MsQuic.Errors, MsQuic.Registration, System.SysUtils;

type
  TMsQuicConfiguration = class
  private
    FApi: PQuicApiTable;
    FHandle: HQUIC;

    FAlpnStorage: AnsiString;
  public
    constructor Create(const AApi: PQuicApiTable; ARegistration: TMsQuicRegistration; const AlpnProtocol: AnsiString; const Settings: PQUIC_SETTINGS);
    destructor Destroy; override;

    function LoadCredential(const CredConfig: PQUIC_CREDENTIAL_CONFIG): Boolean;

    property Handle: HQUIC read FHandle;
  end;

implementation

constructor TMsQuicConfiguration.Create(const AApi: PQuicApiTable; ARegistration: TMsQuicRegistration; const AlpnProtocol: AnsiString; const Settings: PQUIC_SETTINGS);
var
  Status: QUIC_STATUS;
  AlpnBuffer: QUIC_BUFFER;
begin
  inherited Create;
  FApi := AApi;
  FHandle := nil;

  if (FApi = nil) or (ARegistration = nil) then
    raise EMsQuicError.Create('Invalid MsQuic API table or Registration', $C000000D);

  if AlpnProtocol = '' then
    raise EMsQuicError.Create('ALPN protocol must be specified', $C000000D);

  FAlpnStorage := AlpnProtocol;
  AlpnBuffer.Length := Length(FAlpnStorage);
  AlpnBuffer.Buffer := PByte(PAnsiChar(FAlpnStorage));

  Status := FApi.ConfigurationOpen(
    ARegistration.Handle,
    @AlpnBuffer,
    1,
    Settings,
    SizeOf(QUIC_SETTINGS),
    nil,
    FHandle
  );
  if QuicFailed(Status) then
    raise EMsQuicError.Create('Failed to open MsQuic Configuration', Status);
end;

destructor TMsQuicConfiguration.Destroy;
begin
  if (FHandle <> nil) and (FApi <> nil) then
  begin
    FApi.ConfigurationClose(FHandle);
    FHandle := nil;
  end;
  inherited Destroy;
end;

function TMsQuicConfiguration.LoadCredential(const CredConfig: PQUIC_CREDENTIAL_CONFIG): Boolean;
var
  Status: QUIC_STATUS;
begin
  if (FApi = nil) or (FHandle = nil) then
    Exit(False);

  Status := FApi.ConfigurationLoadCredential(FHandle, CredConfig);
  Result := not QuicFailed(Status);
end;

end.
