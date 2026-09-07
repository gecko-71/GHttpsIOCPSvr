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

unit MsQuic.Registration;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  MsQuic.Types, MsQuic.ApiTable, MsQuic.Errors, System.SysUtils;

type
  TMsQuicRegistration = class
  private
    FApi: PQuicApiTable;
    FHandle: HQUIC;
  public
    constructor Create(const AApi: PQuicApiTable; const AAppName: string; AProfile: QUIC_EXECUTION_PROFILE = QUIC_EXECUTION_PROFILE_LOW_LATENCY);
    destructor Destroy; override;
    property Handle: HQUIC read FHandle;
  end;

implementation

constructor TMsQuicRegistration.Create(const AApi: PQuicApiTable; const AAppName: string; AProfile: QUIC_EXECUTION_PROFILE);
var
  Config: QUIC_REGISTRATION_CONFIG;
  AppNameAnsi: AnsiString;
  Status: QUIC_STATUS;
begin
  inherited Create;
  FApi := AApi;
  FHandle := nil;

  if FApi = nil then
    raise EMsQuicError.Create('MsQuic API table is nil', $C000000D);

  AppNameAnsi := AnsiString(AAppName);
  FillChar(Config, SizeOf(Config), 0);
  Config.AppName := PAnsiChar(AppNameAnsi);
  Config.ExecutionProfile := AProfile;

  Status := FApi.RegistrationOpen(@Config, FHandle);
  if QuicFailed(Status) then
    raise EMsQuicError.Create('Failed to open MsQuic Registration', Status);
end;

destructor TMsQuicRegistration.Destroy;
begin
  if (FHandle <> nil) and (FApi <> nil) then
  begin
    FApi.RegistrationShutdown(FHandle, 1 , 0);
    FApi.RegistrationClose(FHandle);
    FHandle := nil;
  end;
  inherited Destroy;
end;

end.
