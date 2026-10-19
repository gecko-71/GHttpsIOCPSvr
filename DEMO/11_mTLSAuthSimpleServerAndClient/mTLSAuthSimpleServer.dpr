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
program mTLSAuthSimpleServer;

{$APPTYPE CONSOLE}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.DateUtils,
  System.SyncObjs,
  System.Hash,
  System.NetEncoding,
  Winapi.Windows,
  Winapi.WinSock2,
  GHttpsServerIOCP in '..\..\src\GHttpsServerIOCP.pas',
  GWebSocket in '..\..\src\GWebSocket.pas',
  GJWTManager in '..\..\src\GJWTManager.pas',
  GRequest in '..\..\src\GRequest.pas',
  GRequestBody in '..\..\src\GRequestBody.pas',
  GResponse in '..\..\src\GResponse.pas',
  OverlappedExPool in '..\..\src\OverlappedExPool.pas',
  WinApiAdditions in '..\..\src\WinApiAdditions.pas';

var
  HttpsPortParam: Integer = 8454;
  CertStoreNameParam: string = 'GHttpsIOCPSvr';
  PinnedClientThumbprint: string = '';

function LoadClientThumbprint: string;
var
  CertText: string;
  DerBytes: TBytes;
  Stream: TBytesStream;
begin
  if FileExists('server_certificates\client.sha256') then
    Exit(UpperCase(Trim(TFile.ReadAllText('server_certificates\client.sha256'))));

  if FileExists('server_certificates\client.crt') then
  begin
    CertText := TFile.ReadAllText('server_certificates\client.crt');
    CertText := CertText.Replace('-----BEGIN CERTIFICATE-----', '')
                        .Replace('-----END CERTIFICATE-----', '')
                        .Replace(#13, '').Replace(#10, '').Trim;
    DerBytes := TNetEncoding.Base64.DecodeStringToBytes(CertText);
    Stream := TBytesStream.Create(DerBytes);
    try
      Exit(THashSHA2.GetHashString(Stream).ToUpper);
    finally
      Stream.Free;
    end;
  end;

  Result := '';
end;

var
  Server: TGHttpsServerIOCP;
begin
  try
    SetInOutRes(0);
    PinnedClientThumbprint := LoadClientThumbprint;

    Logger.Providers.Add(GlobalLogConsoleProvider);
    with GlobalLogConsoleProvider do
    begin
      LogLevel := LOG_DEBUG;
      ShowEventColors := True;
      Enabled := True;
    end;

    Logger.Info('============================================================');
    Logger.Info('  GHttpsIOCPSvr DEMO 11: Simple mTLS Direct Trust Server');
    Logger.Info('============================================================');
    Logger.Info('  Secure HTTPS mTLS Port: %d', [HttpsPortParam]);
    Logger.Info('  Server Cert Store:      %s', [CertStoreNameParam]);
    Logger.Info('  Client Thumbprint (USB):%s', [PinnedClientThumbprint]);
    Logger.Info('============================================================');

    Server := TGHttpsServerIOCP.Create(HttpsPortParam, 'localhost', CertStoreNameParam,
                                      'SuperSecretSimpleMtlsKey123456789!',
                                      2000, 1000000,
                                      DEFAULT_MAX_REQUEST_HEDER_SIZE,
                                      DEFAULT_MAX_REQUEST_SIZE,
                                      DEFAULT_MAX_RESPONSE_SIZE,
                                      DEFAULT_CHUNK_SIZE,
                                      50, 85, True, False, 0, haServeNormally);
    try
      Server.SetSSLShutdownOptions(True, 200);
      Server.EnableHttp3 := False;
      Server.mTLSMode := mtlsRequired;

      Server.OnValidateClientCertificate :=
        function(const CertInfo: TGClientCertInfo): Boolean
        begin
          if (PinnedClientThumbprint <> '') and SameText(CertInfo.ThumbprintSHA256, PinnedClientThumbprint) then
          begin
            Logger.Info('[mTLS AUTH] SUCCESS: Client %s verified via Pendrive Direct Trust (SHA-256: %s)',
              [CertInfo.CommonName, CertInfo.ThumbprintSHA256]);
            Exit(True);
          end;
          Logger.Warn('[mTLS AUTH] REJECTED: Client %s thumbprint %s does not match Pendrive certificate',
            [CertInfo.CommonName, CertInfo.ThumbprintSHA256]);
          Result := False;
        end;

      Server.RegisterEndpointProc('/api/secret-data', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          JObj: TJSONObject;
        begin
          JObj := TJSONObject.Create;
          try
            JObj.AddPair('status', 'access_granted');
            JObj.AddPair('message', 'Welcome to secure mTLS Direct Trust system!');
            JObj.AddPair('client_common_name', ARequest.ClientCertificate.CommonName);
            JObj.AddPair('client_sha256', ARequest.ClientCertificate.ThumbprintSHA256);
            JObj.AddPair('server_timestamp', DateToISO8601(Now));
            AResponse.SetStatus(200);
            AResponse.AddJSONContent(JObj.ToJSON);
          finally
            JObj.Free;
          end;
        end
      );

      if not Server.Start then
      begin
        Writeln('[ERROR] Failed to start simple mTLS server on port ', HttpsPortParam);
        ExitCode := 1;
        Exit;
      end;

      Logger.Info('[INFO] Simple mTLS server is running.');
      Logger.Info('  Secured endpoint: https://localhost:%d/api/secret-data', [HttpsPortParam]);
      Logger.Info('  Press [ENTER] to stop the server.');
      Logger.Info('------------------------------------------------------------');

      try
        Readln;
      except
        while Server.Running do
          Sleep(500);
      end;

      Logger.Info('[INFO] Shutting down simple mTLS server...');
      Server.Stop;
      Logger.Info('[INFO] Server stopped cleanly.');
    finally
      Server.Free;
    end;
  except
    on E: Exception do
    begin
      Writeln('[ERROR] Fatal exception: ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
