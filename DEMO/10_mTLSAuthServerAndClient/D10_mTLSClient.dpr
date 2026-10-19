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
program D10_mTLSClient;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  Winapi.Windows,
  WinApiAdditions in '..\..\src\WinApiAdditions.pas',
  MtlsClientUtils in 'MtlsClientUtils.pas';

var
  ServerHost: string = '127.0.0.1';
  ServerPort: Word = 8453;
  CertsDir: string = 'cercts_client';

procedure RunScenarioValidCert;
var
  Res1, Res2: TMtlsClientResult;
  PfxPath: string;
begin
  Writeln('------------------------------------------------------------');
  Writeln('[SCENARIO 1] Connecting with VALID Client Certificate (CA Signed)');
  Writeln('------------------------------------------------------------');
  PfxPath := TPath.Combine(CertsDir, 'client_valid.pfx');
  Writeln('Using PFX: ', PfxPath);

  Writeln('>> Requesting GET /api/client-identity...');
  Res1 := SendMtlsRequest(ServerHost, ServerPort, '/api/client-identity', 'GET', PfxPath, '1234', '');
  if Res1.Success then
  begin
    Writeln('  Status: HTTP ', Res1.StatusCode, ' OK');
    Writeln('  Response: ', Res1.ResponseBody);
  end
  else
  begin
    Writeln('  FAILED! Status: ', Res1.StatusCode, ', Error: ', Res1.ErrorMessage);
  end;

  Writeln('>> Requesting POST /api/secure-m2m...');
  Res2 := SendMtlsRequest(ServerHost, ServerPort, '/api/secure-m2m', 'POST', PfxPath, '1234', '{"action":"telemetry","data":"SensorReadingsA1"}');
  if Res2.Success then
  begin
    Writeln('  Status: HTTP ', Res2.StatusCode, ' OK');
    Writeln('  Response: ', Res2.ResponseBody);
    Writeln('[PASS] Scenario 1 completed successfully.');
  end
  else
  begin
    Writeln('  FAILED! Status: ', Res2.StatusCode, ', Error: ', Res2.ErrorMessage);
    Writeln('[FAIL] Scenario 1 did not succeed.');
  end;
  Writeln;
end;

procedure RunScenarioNoCert;
var
  Res: TMtlsClientResult;
begin
  Writeln('------------------------------------------------------------');
  Writeln('[SCENARIO 2] Connecting WITHOUT Client Certificate');
  Writeln('------------------------------------------------------------');
  Writeln('>> Requesting GET /api/client-identity (No Client Cert)...');
  Res := SendMtlsRequest(ServerHost, ServerPort, '/api/client-identity', 'GET', '', '', '');
  if not Res.Success then
  begin
    Writeln('  Connection rejected by server as expected.');
    Writeln('  Transport/Security Result: ', Res.ErrorMessage);
    Writeln('[PASS] Scenario 2: Unauthorized client blocked.');
  end
  else
  begin
    Writeln('  UNEXPECTED SUCCESS! Status: ', Res.StatusCode);
    Writeln('  Response: ', Res.ResponseBody);
    Writeln('[FAIL] Server should have rejected connection without cert.');
  end;
  Writeln;
end;

procedure RunScenarioUntrustedCert;
var
  Res: TMtlsClientResult;
  PfxPath: string;
begin
  Writeln('------------------------------------------------------------');
  Writeln('[SCENARIO 3] Connecting with UNTRUSTED/ROGUE CA Certificate');
  Writeln('------------------------------------------------------------');
  PfxPath := TPath.Combine(CertsDir, 'client_untrusted.pfx');
  Writeln('Using PFX: ', PfxPath);
  Writeln('>> Requesting GET /api/client-identity...');
  Res := SendMtlsRequest(ServerHost, ServerPort, '/api/client-identity', 'GET', PfxPath, '1234', '');
  if not Res.Success then
  begin
    Writeln('  Certificate rejected by server SChannel verification.');
    Writeln('  Transport/Security Result: ', Res.ErrorMessage);
    Writeln('[PASS] Scenario 3: Untrusted certificate rejected.');
  end
  else
  begin
    Writeln('  UNEXPECTED SUCCESS! Status: ', Res.StatusCode);
    Writeln('  Response: ', Res.ResponseBody);
    Writeln('[FAIL] Server accepted an untrusted certificate.');
  end;
  Writeln;
end;

procedure RunScenarioExpiredCert;
var
  Res: TMtlsClientResult;
  PfxPath: string;
begin
  Writeln('------------------------------------------------------------');
  Writeln('[SCENARIO 4] Connecting with EXPIRED Certificate');
  Writeln('------------------------------------------------------------');
  PfxPath := TPath.Combine(CertsDir, 'client_expired.pfx');
  Writeln('Using PFX: ', PfxPath);
  Writeln('>> Requesting GET /api/client-identity...');
  Res := SendMtlsRequest(ServerHost, ServerPort, '/api/client-identity', 'GET', PfxPath, '1234', '');
  if not Res.Success then
  begin
    Writeln('  Expired certificate rejected as expected.');
    Writeln('  Transport/Security Result: ', Res.ErrorMessage);
    Writeln('[PASS] Scenario 4: Expired certificate rejected.');
  end
  else
  begin
    Writeln('  UNEXPECTED SUCCESS! Status: ', Res.StatusCode);
    Writeln('  Response: ', Res.ResponseBody);
    Writeln('[FAIL] Server accepted an expired certificate.');
  end;
  Writeln;
end;

procedure RunScenarioPinnedCert;
var
  Res1, Res2: TMtlsClientResult;
  PfxPath: string;
begin
  Writeln('------------------------------------------------------------');
  Writeln('[SCENARIO 5] Connecting with PINNED Certificate (Direct Trust)');
  Writeln('------------------------------------------------------------');
  PfxPath := TPath.Combine(CertsDir, 'client_pinned.pfx');
  Writeln('Using PFX: ', PfxPath);

  Writeln('>> Requesting GET /api/client-identity...');
  Res1 := SendMtlsRequest(ServerHost, ServerPort, '/api/client-identity', 'GET', PfxPath, '1234', '');
  if Res1.Success then
  begin
    Writeln('  Status: HTTP ', Res1.StatusCode, ' OK');
    Writeln('  Response: ', Res1.ResponseBody);
  end
  else
  begin
    Writeln('  Result: Status ', Res1.StatusCode, ', Info: ', Res1.ErrorMessage);
  end;

  Writeln('>> Requesting POST /api/secure-m2m...');
  Res2 := SendMtlsRequest(ServerHost, ServerPort, '/api/secure-m2m', 'POST', PfxPath, '1234', '{"action":"direct_trust_ping","data":"DeviceSensor99"}');
  if Res2.Success then
  begin
    Writeln('  Status: HTTP ', Res2.StatusCode, ' OK');
    Writeln('  Response: ', Res2.ResponseBody);
    Writeln('[PASS] Scenario 5 completed successfully.');
  end
  else
  begin
    Writeln('  FAILED! Status: ', Res2.StatusCode, ', Error: ', Res2.ErrorMessage);
    Writeln('[FAIL] Scenario 5 did not succeed.');
  end;
  Writeln;
end;

procedure RunAllScenarios;
begin
  Writeln('============================================================');
  Writeln('  GHttpsIOCPSvr mTLS Delphi Client Demonstration Suite');
  Writeln('  Target: https://', ServerHost, ':', ServerPort);
  Writeln('============================================================');
  Writeln;

  RunScenarioValidCert;
  RunScenarioNoCert;
  RunScenarioUntrustedCert;
  RunScenarioExpiredCert;
  RunScenarioPinnedCert;

  Writeln('============================================================');
  Writeln('  All mTLS client test scenarios finished.');
  Writeln('============================================================');
end;

procedure RunInteractiveMenu;
var
  Choice: string;
begin
  repeat
    Writeln('============================================================');
    Writeln('  GHttpsIOCPSvr mTLS Client - Interactive Menu');
    Writeln('  Target: https://', ServerHost, ':', ServerPort);
    Writeln('============================================================');
    Writeln('  [1] Send request with VALID certificate (client_valid.pfx)');
    Writeln('  [2] Send request WITHOUT certificate (anonymous)');
    Writeln('  [3] Send request with UNTRUSTED certificate (client_untrusted.pfx)');
    Writeln('  [4] Send request with EXPIRED certificate (client_expired.pfx)');
    Writeln('  [5] Send request with PINNED certificate (client_pinned.pfx) [Direct Trust]');
    Writeln('  [A] Run ALL scenarios sequentially');
    Writeln('  [Q] Quit');
    Write('Select option: ');
    if Eof then
      Break;
    Readln(Choice);
    Writeln;

    Choice := UpperCase(Trim(Choice));
    if Choice = '1' then
      RunScenarioValidCert
    else if Choice = '2' then
      RunScenarioNoCert
    else if Choice = '3' then
      RunScenarioUntrustedCert
    else if Choice = '4' then
      RunScenarioExpiredCert
    else if Choice = '5' then
      RunScenarioPinnedCert
    else if Choice = 'A' then
      RunAllScenarios
    else if (Choice = 'Q') or (Choice = '') then
      Break;
  until False;
end;

begin
  try
    CertsDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'cercts_client');
    if not DirectoryExists(CertsDir) then
    begin
      var FallbackDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'certs_client');
      if DirectoryExists(FallbackDir) then
        CertsDir := FallbackDir;
    end;

    RunInteractiveMenu;
  except
    on E: Exception do
    begin
      Writeln('[ERROR] Exception: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
