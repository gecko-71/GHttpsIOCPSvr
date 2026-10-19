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

program mTLSAuthSimpleClient;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  Winapi.Windows,
  Winapi.WinHTTP,
  MtlsClientUtils in '..\10_mTLSAuthServerAndClient\MtlsClientUtils.pas';

var
  ServerHost: string = 'localhost';
  ServerPort: Word = 8454;
  EndpointPath: string = '/api/secret-data';
  PfxPath: string;
  PfxPassword: string = 'Simple123!';
  Res: TMtlsClientResult;
begin
  try
    PfxPath := 'client_certificates\client.pfx';

    Writeln('============================================================');
    Writeln('  GHttpsIOCPSvr DEMO 11: Simple mTLS Direct Trust Client');
    Writeln('============================================================');
    Writeln('Target Server: https://', ServerHost, ':', ServerPort, EndpointPath);
    Writeln('Client PFX:    ', PfxPath);
    Writeln('------------------------------------------------------------');

    if not FileExists(PfxPath) then
    begin
      Writeln('[ERROR] Client certificate file not found: ', PfxPath);
      Writeln('Run setup_simple_mtls_certs.ps1 to generate keys.');
      ExitCode := 1;
      Exit;
    end;

    Writeln('Sending HTTPS request with client certificate...');
    Res := SendMtlsRequest(ServerHost, ServerPort, EndpointPath, 'GET', PfxPath, PfxPassword, '');

    Writeln('Response Status: ', Res.StatusCode);
    if Res.Success and (Res.StatusCode = 200) then
    begin
      Writeln('[SUCCESS] mTLS Authentication succeeded!');
      Writeln('Server Response:');
      Writeln(Res.ResponseBody);
    end
    else
    begin
      Writeln('[FAILED] mTLS Authentication failed or rejected:');
      Writeln('Error: ', Res.ErrorMessage);
      Writeln('Body:  ', Res.ResponseBody);
      ExitCode := 1;
    end;
    Writeln('============================================================');
  except
    on E: Exception do
    begin
      Writeln('[ERROR] Exception: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
