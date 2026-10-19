unit MtlsClientUtils;

interface

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.Net.URLClient,
  System.Net.HttpClient,
  System.Net.HttpClientComponent,
  Winapi.Windows;

type
  TMtlsClientResult = record
    Success: Boolean;
    StatusCode: Integer;
    ResponseBody: string;
    ErrorMessage: string;
  end;

function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string): TMtlsClientResult;

implementation

type
  CRYPT_DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;
  PCRYPT_DATA_BLOB = ^CRYPT_DATA_BLOB;
  HCERTSTORE = Pointer;
  PCCERT_CONTEXT = Pointer;

function PFXImportCertStore(pPFX: PCRYPT_DATA_BLOB; szPassword: LPCWSTR; dwFlags: DWORD): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertOpenStore(lpszStoreProvider: LPCSTR; dwMsgAndCertEncodingType: DWORD; hCryptProv: ULONG_PTR; dwFlags: DWORD; pvPara: Pointer): HCERTSTORE; stdcall; external 'crypt32.dll';
function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall; external 'crypt32.dll';
function CertEnumCertificatesInStore(hCertStore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall; external 'crypt32.dll';
function CertAddCertificateContextToStore(hCertStore: HCERTSTORE; pCertContext: PCCERT_CONTEXT; dwAddDisposition: DWORD; ppStoreContext: Pointer): BOOL; stdcall; external 'crypt32.dll';
function CertGetNameStringW(pCertContext: PCCERT_CONTEXT; dwType: DWORD; dwFlags: DWORD; pvTypePara: Pointer; pszNameString: PWideChar; cchNameString: DWORD): DWORD; stdcall; external 'crypt32.dll';

type
  TMtlsHandler = class
  private
    FClientCertCN: string;
    procedure HandleValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
    procedure HandleNeedClientCertificate(const Sender: TObject; const ARequest: TURLRequest; const ACertificateList: TCertificateList; var AnIndex: Integer);
  public
    constructor Create(const AClientCertCN: string);
  end;

constructor TMtlsHandler.Create(const AClientCertCN: string);
begin
  inherited Create;
  FClientCertCN := AClientCertCN;
end;

procedure TMtlsHandler.HandleValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
begin
  Accepted := True;
end;

procedure TMtlsHandler.HandleNeedClientCertificate(const Sender: TObject; const ARequest: TURLRequest; const ACertificateList: TCertificateList; var AnIndex: Integer);
var
  I: Integer;
begin
  AnIndex := -1;
  if FClientCertCN <> '' then
  begin
    for I := 0 to ACertificateList.Count - 1 do
    begin
      if ACertificateList[I].Subject.Contains(FClientCertCN) or
         ACertificateList[I].CertName.Contains(FClientCertCN) then
      begin
        AnIndex := I;
        Exit;
      end;
    end;
  end;
end;

function EnsurePfxInStore(const PfxPath, Password: string): string;
var
  Blob: CRYPT_DATA_BLOB;
  PfxBytes: TBytes;
  PfxStore, MyStore: HCERTSTORE;
  pCert: PCCERT_CONTEXT;
  NameBuf: array[0..255] of WideChar;
begin
  Result := '';
  if (PfxPath = '') or not FileExists(PfxPath) then Exit;
  PfxBytes := TFile.ReadAllBytes(PfxPath);
  if Length(PfxBytes) = 0 then Exit;

  Blob.cbData := Length(PfxBytes);
  Blob.pbData := @PfxBytes[0];
  PfxStore := PFXImportCertStore(@Blob, PWideChar(Password), $00000001 or $00001000);
  if not Assigned(PfxStore) then
    PfxStore := PFXImportCertStore(@Blob, PWideChar(Password), $00000001);

  if Assigned(PfxStore) then
  try
    pCert := CertEnumCertificatesInStore(PfxStore, nil);
    if Assigned(pCert) then
    begin
      if CertGetNameStringW(pCert, 4, 0, nil, @NameBuf[0], Length(NameBuf)) > 0 then
        Result := NameBuf;

      MyStore := CertOpenStore(PAnsiChar(10), 0, 0, $00010000, PWideChar('MY'));
      if Assigned(MyStore) then
      try
        CertAddCertificateContextToStore(MyStore, pCert, 3, nil);
      finally
        CertCloseStore(MyStore, 0);
      end;
    end;
  finally
    CertCloseStore(PfxStore, 0);
  end;
end;

function SendMtlsRequest(const ServerHost: string; ServerPort: Word; const Path, Method, PfxPath, Password, PostData: string): TMtlsClientResult;
var
  Client: TNetHTTPClient;
  Handler: TMtlsHandler;
  Response: IHTTPResponse;
  Url, CertSubject: string;
  BodyStream: TStringStream;
begin
  Result.Success := False;
  Result.StatusCode := 0;
  Result.ResponseBody := '';
  Result.ErrorMessage := '';

  CertSubject := EnsurePfxInStore(PfxPath, Password);

  Url := Format('https://%s:%d%s', [ServerHost, ServerPort, Path]);
  Handler := TMtlsHandler.Create(CertSubject);
  Client := TNetHTTPClient.Create(nil);
  try
    Client.OnValidateServerCertificate := Handler.HandleValidateServerCertificate;
    Client.OnNeedClientCertificate := Handler.HandleNeedClientCertificate;
    try
      if SameText(Method, 'POST') then
      begin
        BodyStream := TStringStream.Create(PostData, TEncoding.UTF8);
        try
          Response := Client.Post(Url, BodyStream);
        finally
          BodyStream.Free;
        end;
      end
      else
        Response := Client.Get(Url);

      Result.StatusCode := Response.StatusCode;
      Result.ResponseBody := Response.ContentAsString;
      Result.Success := (Result.StatusCode >= 200) and (Result.StatusCode < 300);
    except
      on E: Exception do
        Result.ErrorMessage := E.Message;
    end;
  finally
    Client.Free;
    Handler.Free;
  end;
end;

end.
