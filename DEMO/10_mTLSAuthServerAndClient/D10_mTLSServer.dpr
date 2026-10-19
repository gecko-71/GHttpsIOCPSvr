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
program D10_mTLSServer;

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
  HttpPortParam: Integer = 8090;
  HttpsPortParam: Integer = 8453;
  CertStoreNameParam: string = 'GHttpsIOCPSvr';
  mTLSModeParam: TmTLSMode = mtlsRequired;
  mTLSModeStr: string = 'required';
  PinnedThumbprint: string = '';

function LoadPinnedThumbprint(const CertsDir: string): string;
var
  ShaPath, CrtPath: string;
  RawBytes, CertBuf: TBytes;
  AnsiStr: AnsiString;
  BinLen, HashLen: DWORD;
  CertCtx: PCCERT_CONTEXT;
  HashBuf: array[0..31] of Byte;
  HexStr: string;
  I: Integer;
begin
  Result := '';
  ShaPath := TPath.Combine(CertsDir, 'client_pinned.sha256');
  if FileExists(ShaPath) then
  begin
    Result := UpperCase(Trim(TFile.ReadAllText(ShaPath)));
    if Result <> '' then
      Exit;
  end;
  CrtPath := TPath.Combine(CertsDir, 'client_pinned.crt');
  if FileExists(CrtPath) then
  begin
    RawBytes := TFile.ReadAllBytes(CrtPath);
    if Length(RawBytes) > 0 then
    begin
      SetString(AnsiStr, PAnsiChar(@RawBytes[0]), Length(RawBytes));
      if Pos('-----BEGIN CERTIFICATE-----', string(AnsiStr)) > 0 then
      begin
        BinLen := 0;
        if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, nil, BinLen, nil, nil) and (BinLen > 0) then
        begin
          SetLength(CertBuf, BinLen);
          if CryptStringToBinary(PAnsiChar(AnsiStr), Length(AnsiStr), CRYPT_STRING_BASE64HEADER, @CertBuf[0], BinLen, nil, nil) then
            CertCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @CertBuf[0], BinLen)
          else
            CertCtx := nil;
        end
        else
          CertCtx := nil;
      end
      else
        CertCtx := CertCreateCertificateContext(X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, @RawBytes[0], Length(RawBytes));

      if CertCtx <> nil then
      try
        HashLen := SizeOf(HashBuf);
        if CertGetCertificateContextProperty(CertCtx, CERT_SHA256_HASH_PROP_ID, @HashBuf[0], HashLen) then
        begin
          HexStr := '';
          for I := 0 to Integer(HashLen) - 1 do
            HexStr := HexStr + IntToHex(HashBuf[I], 2);
          Result := HexStr;
        end;
      finally
        CertFreeCertificateContext(CertCtx);
      end;
    end;
  end;
end;

var
  Server: TGHttpsServerIOCP;
  ServerCertsDir: string;
  CaCertFile: string;
begin
  try
    SetInOutRes(0);

    ServerCertsDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'cercts_server');
    if not DirectoryExists(ServerCertsDir) then
    begin
      var FallbackDir := TPath.Combine(ExtractFilePath(ParamStr(0)), 'certs_server');
      if DirectoryExists(FallbackDir) then
        ServerCertsDir := FallbackDir;
    end;

    CaCertFile := TPath.Combine(ServerCertsDir, 'test_root_ca.crt');
    PinnedThumbprint := LoadPinnedThumbprint(ServerCertsDir);

    Logger.Providers.Add(GlobalLogConsoleProvider);
    with GlobalLogConsoleProvider do
    begin
      LogLevel := LOG_DEBUG;
      ShowEventColors := True;
      Enabled := True;
    end;

    Logger.Info('============================================================');
    Logger.Info('  GHttpsIOCPSvr DEMO 10: mTLS Mutual Authentication Server');
    Logger.Info('============================================================');
    Logger.Info('  Plaintext HTTP Port: %d', [HttpPortParam]);
    Logger.Info('  Secure HTTPS Port:   %d', [HttpsPortParam]);
    Logger.Info('  Server Cert Store:   %s', [CertStoreNameParam]);
    Logger.Info('  Server Certs Dir:    %s', [ServerCertsDir]);
    Logger.Info('  Hierarchical CA:     %s', [CaCertFile]);
    Logger.Info('  Direct Trust SHA-256:%s', [PinnedThumbprint]);
    Logger.Info('  Active mTLS Level:   %s', [mTLSModeStr]);
    Logger.Info('============================================================');

    Server := TGHttpsServerIOCP.Create(HttpsPortParam, 'localhost',
                                       CertStoreNameParam,
                                      'SuperSecretDemo10MtlsKey1234567890!',
                                      2000, 1000000,
                                      DEFAULT_MAX_REQUEST_HEDER_SIZE,
                                      DEFAULT_MAX_REQUEST_SIZE,
                                      DEFAULT_MAX_RESPONSE_SIZE,
                                      DEFAULT_CHUNK_SIZE,
                                      50, 85, True, True, HttpPortParam,
                                      haServeNormally);
    try
      Server.SetSSLShutdownOptions(True, 200);
      Server.EnableHttp3 := False;
      Server.mTLSMode := mTLSModeParam;

      if FileExists(CaCertFile) then
      begin
        Server.LoadCACertificate(CaCertFile);
        Logger.Info('Loaded trusted mTLS Root CA from: %s', [CaCertFile]);
      end
      else
        Logger.Warn('Trusted CA certificate file not found: %s', [CaCertFile]);

      Server.OnValidateClientCertificate :=
        function(const CertInfo: TGClientCertInfo): Boolean
        begin
          if (PinnedThumbprint <> '') and SameText(CertInfo.ThumbprintSHA256, PinnedThumbprint) then
          begin
            Logger.Info('[AUTH] Client %s authorized via DIRECT TRUST (SHA-256: %s)', [CertInfo.CommonName, CertInfo.ThumbprintSHA256]);
            Exit(True);
          end;

          if CertInfo.IsVerified then
          begin
            Logger.Info('[AUTH] Client %s authorized via ROOT CA (Issuer: %s)', [CertInfo.CommonName, CertInfo.Issuer]);
            Exit(True);
          end;

          Logger.Warn('[AUTH] Client %s REJECTED: Not signed by trusted CA and not matching pinned thumbprint', [CertInfo.CommonName]);
          Result := False;
        end;

      Server.RegisterEndpointProc('/api/client-identity', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          JObj: TJSONObject;
          TraefikInfoStr: string;
        begin
          JObj := TJSONObject.Create;
          try
            JObj.AddPair('status', 'success');
            JObj.AddPair('has_certificate', TJSONBool.Create(ARequest.ClientCertificate.HasCertificate));
            JObj.AddPair('is_verified', TJSONBool.Create(ARequest.ClientCertificate.IsVerified));
            JObj.AddPair('common_name', ARequest.ClientCertificate.CommonName);
            JObj.AddPair('subject', ARequest.ClientCertificate.Subject);
            JObj.AddPair('issuer', ARequest.ClientCertificate.Issuer);
            JObj.AddPair('san', ARequest.ClientCertificate.SAN);
            JObj.AddPair('serial_number', ARequest.ClientCertificate.SerialNumber);
            JObj.AddPair('thumbprint_sha256', ARequest.ClientCertificate.ThumbprintSHA256);
            if ARequest.ClientCertificate.ValidFrom > 0 then
              JObj.AddPair('valid_from', DateToISO8601(ARequest.ClientCertificate.ValidFrom))
            else
              JObj.AddPair('valid_from', '');
            if ARequest.ClientCertificate.ValidTo > 0 then
              JObj.AddPair('valid_to', DateToISO8601(ARequest.ClientCertificate.ValidTo))
            else
              JObj.AddPair('valid_to', '');
            JObj.AddPair('validation_error', ARequest.ClientCertificate.ValidationError);
            JObj.AddPair('raw_cert_base64', ARequest.ClientCertificate.RawCertBase64);

            TraefikInfoStr := '';
            if ARequest.ClientCertificate.HasCertificate then
            begin
              TraefikInfoStr := 'Subject="CN=' + ARequest.ClientCertificate.CommonName + '";Issuer="CN=' + ARequest.ClientCertificate.Issuer + '";SerialNumber="' + ARequest.ClientCertificate.SerialNumber + '"';
              if ARequest.ClientCertificate.SAN <> '' then
                TraefikInfoStr := TraefikInfoStr + ';SAN="' + ARequest.ClientCertificate.SAN + '"';
            end;
            JObj.AddPair('x_forwarded_tls_client_cert_info', TraefikInfoStr);

            AResponse.SetStatus(200);
            AResponse.AddJSONContent(JObj.ToJSON);
          finally
            JObj.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/secure-m2m', hmPOST,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        var
          Json: TJSONObject;
        begin
          if (not ARequest.ClientCertificate.HasCertificate) or (not ARequest.ClientCertificate.IsVerified) then
          begin
            AResponse.SetForbidden('Client certificate required or untrusted');
            Exit;
          end;

          Json := TJSONObject.Create;
          try
            Json.AddPair('status', 'm2m_authorized');
            Json.AddPair('authenticated_client', ARequest.ClientCertificate.CommonName);
            Json.AddPair('issuer', ARequest.ClientCertificate.Issuer);
            Json.AddPair('received_payload', ARequest.BodyAsString);
            Json.AddPair('timestamp', DateToISO8601(Now));

            AResponse.SetStatus(200);
            AResponse.AddJSONContent(Json.ToJSON);
          finally
            Json.Free;
          end;
        end
      );

      Server.RegisterEndpointProc('/api/public', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                                   const AResponse: TResponse;
                                   AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(200);
          AResponse.AddJSONContent('{"status":"public_access_granted","info":"Open information endpoint"}');
        end
      );

      if not Server.Start then
      begin
        Writeln('[ERROR] Failed to start mTLS server on ports ', HttpPortParam, ' / ', HttpsPortParam);
        ExitCode := 1;
        Exit;
      end;

      Logger.Info('[INFO] Server is running.');
      Logger.Info('  Endpoints: /api/client-identity, /api/secure-m2m, /api/public');
      Logger.Info('  Press [ENTER] to stop the server.');
      Logger.Info('------------------------------------------------------------');

      try
        Readln;
      except
        while Server.Running do
          Sleep(500);
      end;

      Logger.Info('[INFO] Shutting down mTLS server...');
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
