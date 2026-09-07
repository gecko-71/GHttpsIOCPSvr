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
  MsQuic.Types, MsQuic.Configuration;

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
  HCERTSTORE = Pointer;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: Pointer;
    hCertStore: HCERTSTORE;
  end;
  PCCERT_CONTEXT = ^CERT_CONTEXT;

  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;

  TMsQuicCertificate = class
  private
    FCredConfig: QUIC_CREDENTIAL_CONFIG;
    FPkcs12: QUIC_CERTIFICATE_PKCS12;
    FPfxBlob: PByte;
    FPfxBlobSize: Cardinal;
    procedure Clear;
    function HexToBytes(const Hex: string): TBytes;
  public
    constructor Create;
    destructor Destroy; override;

    function LoadServerCertificate(
      AConfig: TMsQuicConfiguration;
      const CertHashHex: string;
      const StoreName: string;
      ServerCertStore: HCERTSTORE = nil;
      const CertSubjectName: string = ''
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

function TMsQuicCertificate.HexToBytes(const Hex: string): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(Hex) div 2);
  for I := 1 to Length(Hex) div 2 do
    Result[I - 1] := StrToInt('$' + Copy(Hex, (I - 1) * 2 + 1, 2));
end;

constructor TMsQuicCertificate.Create;
begin
  inherited Create;
  FPfxBlob := nil;
  FPfxBlobSize := 0;
  FillChar(FCredConfig, SizeOf(FCredConfig), 0);
  FillChar(FPkcs12, SizeOf(FPkcs12), 0);
end;

destructor TMsQuicCertificate.Destroy;
begin
  Clear;
  inherited Destroy;
end;

procedure TMsQuicCertificate.Clear;
begin
  if FPfxBlob <> nil then
  begin
    FreeMem(FPfxBlob);
    FPfxBlob := nil;
    FPfxBlobSize := 0;
  end;

  FillChar(FCredConfig, SizeOf(FCredConfig), 0);
  FillChar(FPkcs12, SizeOf(FPkcs12), 0);
end;

const
  CERT_FIND_SHA1_HASH = $00010000;
  CERT_FIND_SUBJECT_STR_W = $00080007;

function TMsQuicCertificate.LoadServerCertificate(
  AConfig: TMsQuicConfiguration;
  const CertHashHex: string;
  const StoreName: string;
  ServerCertStore: HCERTSTORE;
  const CertSubjectName: string
): Boolean;
var
  hStoreToSearch, hTmpStore: HCERTSTORE;
  MustCloseStore: Boolean;
  pSearchContext: PCCERT_CONTEXT;
  PfxData: CRYPT_DATA_BLOB;
  HashBytes: CRYPT_DATA_BLOB;
  HashData: TBytes;
  FallbackSubject: string;
begin
  Clear;
  Result := False;

  if AConfig = nil then Exit;

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
      HashBytes.cbData := Length(HashData);
      HashBytes.pbData := @HashData[0];
      pSearchContext := CertFindCertificateInStore(
        hStoreToSearch, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0,
        CERT_FIND_SHA1_HASH, @HashBytes, nil
      );
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
    end;

    if pSearchContext <> nil then
    begin
      try
        if CertAddCertificateContextToStore(hTmpStore, pSearchContext, CERT_STORE_ADD_ALWAYS, nil) then
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
              FCredConfig.Certificate := @FPkcs12;

              Result := AConfig.LoadCredential(@FCredConfig);
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
