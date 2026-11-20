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

unit MsQuic.Certificate;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  Winapi.Windows, System.SysUtils,
  MsQuic.Types, MsQuic.Configuration, WinApiAdditions;

const
  CERT_STORE_PROV_SYSTEM        = Pointer(10);
  CERT_STORE_PROV_MEMORY        = Pointer(2);
  CERT_SYSTEM_STORE_LOCAL_MACHINE = $00020000;
  CERT_SYSTEM_STORE_CURRENT_USER  = $00010000;
  CERT_STORE_READONLY_FLAG        = $00008000;
  CERT_STORE_ADD_ALWAYS           = 4;

  X509_ASN_ENCODING             = $00000001;
  PKCS_7_ASN_ENCODING           = $00010000;

  CERT_FIND_ANY                 = 0;
  CERT_FIND_SUBJECT_STR         = $00080007;

  EXPORT_PRIVATE_KEYS           = $0004;
  REPORT_NO_PRIVATE_KEY         = $0001;

  DEFAULT_QUIC_CERT_STORE       = 'GHttpsIOCPSvr';
  DEFAULT_QUIC_CERT_SUBJECT     = 'localhost';

type
  HCERTSTORE = WinApiAdditions.HCERTSTORE;
  CERT_CONTEXT = WinApiAdditions.CERT_CONTEXT;
  PCCERT_CONTEXT = WinApiAdditions.PCCERT_CONTEXT;
  CRYPT_DATA_BLOB = WinApiAdditions.CRYPT_DATA_BLOB;
  PCRYPT_DATA_BLOB = WinApiAdditions.PCRYPT_DATA_BLOB;

  TMsQuicCertificate = class
  private
    FCredConfig: QUIC_CREDENTIAL_CONFIG;
    FPkcs12: QUIC_CERTIFICATE_PKCS12;
    FPfxBlob: PByte;
    FPfxBlobSize: Cardinal;
    FCertFile: QUIC_CERTIFICATE_FILE;
    FCertFileAnsi: UTF8String;
    FKeyFileAnsi: UTF8String;
    FEphemeralStore: HCERTSTORE;
    FEphemeralCertCtx: PCCERT_CONTEXT;
    procedure Clear;
    function HexToBytes(const Hex: string): TBytes;
    function TryLoadCredentialWithMtls(
      AConfig: TMsQuicConfiguration;
      ACredType: QUIC_CREDENTIAL_TYPE;
      ACertPtr: Pointer;
      AmTLSRequired: Boolean;
      AmTLSOptional: Boolean
    ): Boolean;
    function LoadServerCertificateFromFiles(
      AConfig: TMsQuicConfiguration;
      const ACertFile: string;
      const AKeyFile: string;
      const AmTLSRequired: Boolean = False;
      const AmTLSOptional: Boolean = False
    ): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    function LoadServerCertificate(
      AConfig: TMsQuicConfiguration;
      const CertHashHex: string;
      const StoreName: string;
      ServerCertStore: HCERTSTORE = nil;
      const CertSubjectName: string = '';
      const AmTLSRequired: Boolean = False;
      const AmTLSOptional: Boolean = False;
      const ACertFile: string = '';
      const AKeyFile: string = ''
    ): Boolean;

  end;

function CertOpenStore(
  lpszStoreProvider: LPCSTR;
  dwMsgAndCertEncodingType: DWORD;
  hCryptProv: ULONG_PTR;
  dwFlags: DWORD;
  pvPara: Pointer
): HCERTSTORE; stdcall; external 'crypt32.dll' name 'CertOpenStore';

function CertCloseStore(
  hCertStore: HCERTSTORE;
  dwFlags: DWORD
): BOOL; stdcall; external 'crypt32.dll' name 'CertCloseStore';

function CertFindCertificateInStore(
  hCertStore: HCERTSTORE;
  dwCertEncodingType: DWORD;
  dwFindFlags: DWORD;
  dwFindType: DWORD;
  pvFindPara: Pointer;
  pPrevCertContext: PCCERT_CONTEXT
): PCCERT_CONTEXT; stdcall; external 'crypt32.dll' name 'CertFindCertificateInStore';

function CertOpenSystemStore(
  hProv: ULONG_PTR;
  szSubsystemProtocol: LPCWSTR
): HCERTSTORE; stdcall; external 'crypt32.dll' name 'CertOpenSystemStoreW';

function CertFreeCertificateContext(
  pCertContext: PCCERT_CONTEXT
): BOOL; stdcall; external 'crypt32.dll' name 'CertFreeCertificateContext';

function CertAddCertificateContextToStore(
  hCertStore: HCERTSTORE;
  pCertContext: PCCERT_CONTEXT;
  dwAddDisposition: DWORD;
  ppStoreContext: PCCERT_CONTEXT
): BOOL; stdcall; external 'crypt32.dll' name 'CertAddCertificateContextToStore';

function PFXExportCertStoreEx(
  hStore: HCERTSTORE;
  pPFX: PCRYPT_DATA_BLOB;
  szPassword: LPCWSTR;
  pvReserved: Pointer;
  dwFlags: DWORD
): BOOL; stdcall; external 'crypt32.dll' name 'PFXExportCertStoreEx';

implementation

uses
  GOpenSslApi, GOpenSslTlsEngine;

const
  CERT_FIND_SHA1_HASH = $00010000;
  CERT_FIND_SUBJECT_STR_W = $00080007;
  CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = $00010000;
  CRYPT_ACQUIRE_SILENT_FLAG = $00000040;
  CERT_NCRYPT_KEY_SPEC = $FFFFFFFF;
  CRYPT_EXPORTABLE_FLAG = $00000001;

type
  TNCryptDeleteKeyProc = function(hKey: ULONG_PTR; dwFlags: DWORD): LongInt; stdcall;
  TNCryptFreeObjectProc = function(hObject: ULONG_PTR): LongInt; stdcall;

function TMsQuicCertificate.HexToBytes(const Hex: string): TBytes;
var
  I: Integer;
  ByteVal: Integer;
  CleanHex: string;
begin
  Result := nil;
  CleanHex := Trim(Hex);
  if (CleanHex = '') or ((Length(CleanHex) mod 2) <> 0) then
    Exit;

  SetLength(Result, Length(CleanHex) div 2);
  for I := 1 to Length(CleanHex) div 2 do
  begin
    if not TryStrToInt('$' + Copy(CleanHex, (I - 1) * 2 + 1, 2), ByteVal) then
    begin
      Result := nil;
      Exit;
    end;
    Result[I - 1] := Byte(ByteVal);
  end;
end;

constructor TMsQuicCertificate.Create;
begin
  inherited Create;
  FPfxBlob := nil;
  FPfxBlobSize := 0;
  FCertFileAnsi := '';
  FKeyFileAnsi := '';
  FEphemeralStore := nil;
  FEphemeralCertCtx := nil;
  FillChar(FCredConfig, SizeOf(FCredConfig), 0);
  FillChar(FPkcs12, SizeOf(FPkcs12), 0);
  FillChar(FCertFile, SizeOf(FCertFile), 0);
end;

destructor TMsQuicCertificate.Destroy;
begin
  Clear;
  inherited Destroy;
end;

procedure TMsQuicCertificate.Clear;
var
  KeyProv: WinApiAdditions.HCRYPTPROV;
  KeySpec: DWORD;
  MustFree: BOOL;
  NCryptLib: HMODULE;
  DeleteKeyProc: TNCryptDeleteKeyProc;
  FreeObjProc: TNCryptFreeObjectProc;
  DelStatus: LongInt;
begin
  if FEphemeralCertCtx <> nil then
  begin
    KeyProv := 0;
    KeySpec := 0;
    MustFree := False;
    if CryptAcquireCertificatePrivateKey(
         FEphemeralCertCtx,
         CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG or CRYPT_ACQUIRE_SILENT_FLAG,
         nil,
         KeyProv,
         KeySpec,
         MustFree) then
    begin
      if KeySpec = CERT_NCRYPT_KEY_SPEC then
      begin
        NCryptLib := LoadLibraryW('ncrypt.dll');
        if NCryptLib <> 0 then
        begin
          @DeleteKeyProc := GetProcAddress(NCryptLib, 'NCryptDeleteKey');
          @FreeObjProc := GetProcAddress(NCryptLib, 'NCryptFreeObject');
          DelStatus := -1;
          if Assigned(DeleteKeyProc) then
            DelStatus := DeleteKeyProc(KeyProv, 0);
          if (DelStatus <> 0) and MustFree and Assigned(FreeObjProc) then
            FreeObjProc(KeyProv);
          FreeLibrary(NCryptLib);
        end;
      end
      else if MustFree then
        CryptReleaseContext(KeyProv, 0);
    end;
    CertFreeCertificateContext(FEphemeralCertCtx);
    FEphemeralCertCtx := nil;
  end;

  if FEphemeralStore <> nil then
  begin
    CertCloseStore(FEphemeralStore, 0);
    FEphemeralStore := nil;
  end;

  if FPfxBlob <> nil then
  begin
    if FPfxBlobSize > 0 then
      FillChar(FPfxBlob^, FPfxBlobSize, 0);
    FreeMem(FPfxBlob);
    FPfxBlob := nil;
    FPfxBlobSize := 0;
  end;

  FCertFileAnsi := '';
  FKeyFileAnsi := '';
  FillChar(FCredConfig, SizeOf(FCredConfig), 0);
  FillChar(FPkcs12, SizeOf(FPkcs12), 0);
  FillChar(FCertFile, SizeOf(FCertFile), 0);
end;

function TMsQuicCertificate.TryLoadCredentialWithMtls(
  AConfig: TMsQuicConfiguration;
  ACredType: QUIC_CREDENTIAL_TYPE;
  ACertPtr: Pointer;
  AmTLSRequired: Boolean;
  AmTLSOptional: Boolean
): Boolean;
begin
  FillChar(FCredConfig, SizeOf(FCredConfig), 0);
  FCredConfig.Type_ := ACredType;
  FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
  if AmTLSRequired or AmTLSOptional then
    FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
  FCredConfig.Certificate := ACertPtr;
  Result := AConfig.LoadCredential(@FCredConfig);

  if (not Result) and (FCredConfig.Flags <> QUIC_CREDENTIAL_FLAG_NONE) then
  begin
    FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
    Result := AConfig.LoadCredential(@FCredConfig);
  end;

  if (not Result) and (not AmTLSRequired) and AmTLSOptional then
  begin
    FillChar(FCredConfig, SizeOf(FCredConfig), 0);
    FCredConfig.Type_ := ACredType;
    FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
    FCredConfig.Certificate := ACertPtr;
    Result := AConfig.LoadCredential(@FCredConfig);
  end;
end;

function TMsQuicCertificate.LoadServerCertificateFromFiles(
  AConfig: TMsQuicConfiguration;
  const ACertFile: string;
  const AKeyFile: string;
  const AmTLSRequired: Boolean;
  const AmTLSOptional: Boolean
): Boolean;
begin
  Result := False;
  if (AConfig = nil) or (ACertFile = '') or (AKeyFile = '') then
    Exit;
  if (not FileExists(ACertFile)) or (not FileExists(AKeyFile)) then
    Exit;

  FCertFileAnsi := UTF8String(ACertFile);
  FKeyFileAnsi := UTF8String(AKeyFile);
  FCertFile.CertificateFile := PAnsiChar(FCertFileAnsi);
  FCertFile.PrivateKeyFile := PAnsiChar(FKeyFileAnsi);

  Result := TryLoadCredentialWithMtls(AConfig, QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, @FCertFile, AmTLSRequired, AmTLSOptional);
end;

function TMsQuicCertificate.LoadServerCertificate(
  AConfig: TMsQuicConfiguration;
  const CertHashHex: string;
  const StoreName: string;
  ServerCertStore: HCERTSTORE;
  const CertSubjectName: string;
  const AmTLSRequired: Boolean;
  const AmTLSOptional: Boolean;
  const ACertFile: string;
  const AKeyFile: string
): Boolean;
var
  hStoreToSearch, hTmpStore: HCERTSTORE;
  MustCloseStore: Boolean;
  pSearchContext: PCCERT_CONTEXT;
  PfxData: CRYPT_DATA_BLOB;
  HashBytes: CRYPT_DATA_BLOB;
  HashData: TBytes;
  FallbackSubject: string;
  ResolvedCertFile: string;
  ResolvedKeyFile: string;
begin
  Clear;
  Result := False;

  if AConfig = nil then
    Exit;

  if CertHashHex <> '' then
    HashData := HexToBytes(CertHashHex);

  if (GetConfiguredTlsProvider(tpSchannel) = tpOpenSSL) or ((ACertFile <> '') and (AKeyFile <> '')) then
  begin
    ResolvedCertFile := ACertFile;
    ResolvedKeyFile := AKeyFile;
    if not ResolveOpenSslCertAndKeyFiles(StoreName, CertSubjectName, ResolvedCertFile, ResolvedKeyFile) then
      Exit(False);
    Result := LoadServerCertificateFromFiles(AConfig, ResolvedCertFile, ResolvedKeyFile, AmTLSRequired, AmTLSOptional);
    Exit;
  end;

  hStoreToSearch := ServerCertStore;
  MustCloseStore := False;

  if hStoreToSearch = nil then
  begin
    hStoreToSearch := CertOpenSystemStore(0, PWideChar(StoreName));
    MustCloseStore := (hStoreToSearch <> nil);
  end;

  if hStoreToSearch = nil then
    Exit;

  hTmpStore := CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nil);
  if hTmpStore = nil then
  begin
    if MustCloseStore then CertCloseStore(hStoreToSearch, 0);
    Exit;
  end;

  try
    pSearchContext := nil;

    if CertHashHex <> '' then
    begin
      HashData := HexToBytes(CertHashHex);
      if Length(HashData) > 0 then
      begin
        HashBytes.cbData := Length(HashData);
        HashBytes.pbData := @HashData[0];
        pSearchContext := CertFindCertificateInStore(
          hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
          CERT_FIND_SHA1_HASH, @HashBytes, nil
        );
      end;
    end;

    if pSearchContext = nil then
    begin
      FallbackSubject := CertSubjectName;
      if FallbackSubject = '' then
        FallbackSubject := 'localhost';

      pSearchContext := CertFindCertificateInStore(
        hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_STR_W, PWideChar(FallbackSubject), nil
      );

      if (pSearchContext = nil) and (FallbackSubject <> 'localhost') then
      begin
        pSearchContext := CertFindCertificateInStore(
          hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
          CERT_FIND_SUBJECT_STR_W, PWideChar('localhost'), nil
        );
      end;
    end;

    if pSearchContext <> nil then
    begin
      try
        FillChar(FCredConfig, SizeOf(FCredConfig), 0);
        FCredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
        FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
        if AmTLSRequired or AmTLSOptional then
          FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        FCredConfig.Certificate := pSearchContext;
        Result := AConfig.LoadCredential(@FCredConfig);
        if (not Result) and (FCredConfig.Flags <> QUIC_CREDENTIAL_FLAG_NONE) then
        begin
          FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
          Result := AConfig.LoadCredential(@FCredConfig);
        end;
        if (not Result) and (not AmTLSRequired) and AmTLSOptional then
        begin
          FillChar(FCredConfig, SizeOf(FCredConfig), 0);
          FCredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
          FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
          FCredConfig.Certificate := pSearchContext;
          Result := AConfig.LoadCredential(@FCredConfig);
        end;

        if (not Result) and CertAddCertificateContextToStore(hTmpStore, pSearchContext, CERT_STORE_ADD_ALWAYS, nil) then
        begin
          FillChar(PfxData, SizeOf(PfxData), 0);
          if PFXExportCertStoreEx(hTmpStore, @PfxData, nil, nil, EXPORT_PRIVATE_KEYS or REPORT_NO_PRIVATE_KEY) then
          begin
            GetMem(FPfxBlob, PfxData.cbData);
            FPfxBlobSize := PfxData.cbData;
            PfxData.pbData := FPfxBlob;

            if PFXExportCertStoreEx(hTmpStore, @PfxData, nil, nil, EXPORT_PRIVATE_KEYS or REPORT_NO_PRIVATE_KEY) then
            begin
              FPkcs12.Asn1Blob := FPfxBlob;
              FPkcs12.Asn1BlobLength := FPfxBlobSize;
              FPkcs12.PrivateKeyPassword := nil;

              FillChar(FCredConfig, SizeOf(FCredConfig), 0);
              FCredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
              FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
              if AmTLSRequired or AmTLSOptional then
                FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
              FCredConfig.Certificate := @FPkcs12;

              Result := AConfig.LoadCredential(@FCredConfig);
              if (not Result) and (FCredConfig.Flags <> QUIC_CREDENTIAL_FLAG_NONE) then
              begin
                FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES or QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION or QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION or QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
                Result := AConfig.LoadCredential(@FCredConfig);
              end;
              if (not Result) and (not AmTLSRequired) and AmTLSOptional then
              begin
                FillChar(FCredConfig, SizeOf(FCredConfig), 0);
                FCredConfig.Type_ := QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
                FCredConfig.Flags := QUIC_CREDENTIAL_FLAG_NONE;
                FCredConfig.Certificate := @FPkcs12;
                Result := AConfig.LoadCredential(@FCredConfig);
              end;

              if (FPfxBlob <> nil) and (FPfxBlobSize > 0) then
              begin
                FillChar(FPfxBlob^, FPfxBlobSize, 0);
                FreeMem(FPfxBlob);
                FPfxBlob := nil;
                FPfxBlobSize := 0;
                FPkcs12.Asn1Blob := nil;
                FPkcs12.Asn1BlobLength := 0;
              end;
            end;
          end;
        end;
      finally
        CertFreeCertificateContext(pSearchContext);
      end;
    end;
  finally
    CertCloseStore(hTmpStore, 0);
    if MustCloseStore then
      CertCloseStore(hStoreToSearch, 0);
  end;
end;

end.
