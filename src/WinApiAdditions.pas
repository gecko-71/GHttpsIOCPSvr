{
  MIT License

  Copyright (c) (c) 2025 GECKO-71

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

unit WinApiAdditions;

interface

uses
   Quick.Logger, Winapi.Windows, Winapi.Winsock2,
   GRequest,
   GResponse,
   System.Classes,
   System.SysUtils;

const
  DEFAULT_RECEIVE_CHUNK_SIZE = 8192; // 8KB - standard size for a single WSARecv
  MAX_SSL_TOKEN_SIZE = 16384 + 512;

type
  PTimeStamp = ^TTimeStamp;
  TTimeStamp = record
    LowPart: DWORD;
    HighPart: Longint;
  end;

  SECURITY_STATUS = Longint;

  PSecHandle = ^TSecHandle;
  TSecHandle = record
    dwLower: ULONG_PTR;
    dwUpper: ULONG_PTR;
  end;

  TCredHandle = TSecHandle;
  PCredHandle = ^TCredHandle;
  TCtxtHandle = TSecHandle;
  PCtxtHandle = ^TCtxtHandle;

  TOperationType = (otAccept,
                    otRead,
                    otSSLHandshake,
                    otWriteChunk,
                    otTimeoutClose);

  POverlappedEx = ^TOverlappedEx;
  TOverlappedEx = record
    Overlapped: TOverlapped;
    OpType: TOperationType;
    Socket: TSocket;
    Buffer: array[0..DEFAULT_RECEIVE_CHUNK_SIZE-1] of Byte;
    ClientReceiveBuffer: TBytes;
    BytesTransferred: DWORD;
    ClientSocket: TSocket;
    SSLContext: TCtxtHandle;
    SSLContextValid: Boolean;
    SSLHandshakeStep: Integer;
    SSLNeedsMoreData: Boolean;
    SSLOutputBuffer: array[0..65535] of Byte;
    SSLOutputSize: DWORD;
    Request: TRequest;
    Response: TResponse;
    LastActivityTime: UInt64;
  end;


const
  //WORKER_THREAD_COUNT = 8;
  WORKER_THREAD_COUNT = 48;
  //WORKER_THREAD_COUNT = 256;

  DEFAULT_REQUEST_TIMEOUT = 30;

  SECBUFFER_VERSION = 0;
  SCHANNEL_CRED_VERSION = 4;
  SECURITY_NATIVE_DREP = $00000010;

  SECPKG_CRED_INBOUND = 1;
  SECPKG_CRED_OUTBOUND = 2;
  SCH_CRED_AUTO_CRED_VALIDATION = $00000020;
  SCH_CRED_NO_DEFAULT_CREDS = $00000010;
  SCH_CRED_USE_DEFAULT_CREDS = $00000040;

  SCH_CRED_MANUAL_CRED_VALIDATION = $00000008;
  SCH_CRED_CIPHER_SUITE_PRIORITY  = $00000080;

  SECPKG_ATTR_STREAM_SIZES = 4;
  SECPKG_ATTR_CONNECTION_INFO = 90;
  SECBUFFER_EMPTY = 0;
  SECBUFFER_DATA = 1;
  SECBUFFER_TOKEN = 2;
  SECBUFFER_EXTRA = 5;
  SECBUFFER_STREAM_TRAILER = 6;
  SECBUFFER_STREAM_HEADER = 7;
  ISC_REQ_SEQUENCE_DETECT = $00000008;
  ISC_REQ_REPLAY_DETECT = $00000010;
  ISC_REQ_CONFIDENTIALITY = $00000020;
  ISC_REQ_ALLOCATE_MEMORY = $00000100;
  ISC_REQ_STREAM = $00008000;
  ASC_REQ_SEQUENCE_DETECT = $00000008;
  ASC_REQ_REPLAY_DETECT = $00000010;
  ASC_REQ_CONFIDENTIALITY = $00000020;
  ASC_REQ_ALLOCATE_MEMORY = $00000100;
  ASC_REQ_STREAM = $00008000;
  SEC_E_OK = 0;
  SEC_I_CONTINUE_NEEDED = $90312;
  SEC_I_COMPLETE_NEEDED = $90313;
  SEC_I_COMPLETE_AND_CONTINUE = $90314;
  SEC_E_INCOMPLETE_MESSAGE = Longint($80090318);
  SEC_I_INCOMPLETE_CREDENTIALS = $90320;
  SEC_E_INVALID_HANDLE = Longint($80090301);
  SEC_E_UNSUPPORTED_FUNCTION = Longint($80090302);
  SEC_E_TARGET_UNKNOWN = Longint($80090303);
  SEC_E_INTERNAL_ERROR = Longint($80090304);
  SEC_E_SECPKG_NOT_FOUND = Longint($80090305);
  SEC_E_INVALID_TOKEN = Longint($80090308);
  SEC_E_NO_CREDENTIALS = Longint($80090311);
  SEC_E_ALGORITHM_MISMATCH = Longint($80090326);
  SEC_E_UNKNOWN_CREDENTIALS = Longint($80090331);
  SEC_E_INSUFFICIENT_MEMORY = Longint($80090300);
  SEC_E_BUFFER_TOO_SMALL = Longint($8009032F);
  SEC_E_CONTEXT_EXPIRED = Longint($8009032D);
  SEC_E_MESSAGE_ALTERED = Longint($80090328);
  SEC_E_OUT_OF_SEQUENCE = Longint($8009032A);
  SEC_E_ENCRYPT_FAILURE = Longint($80090325);
  SEC_E_DECRYPT_FAILURE = Longint($80090327);
  SEC_E_BAD_PKGID = Longint($8009032C);
  SEC_E_NO_AUTHENTICATING_AUTHORITY = Longint($8009032B);
  SEC_E_WRONG_PRINCIPAL = Longint($80090330);
  SEC_E_MESSAGE_TOO_LARGE = Longint($8009030D);
  SEC_E_INVALID_PARAMETER = Longint($8009030F);
  SEC_E_NO_CONTEXT = Longint($80090312);
  SEC_E_PKU2U_CERT_FAILURE = Longint($80090313);
  SEC_E_MUTUAL_AUTH_FAILED = Longint($80090314);
  SEC_E_ONLY_HTTPS = Longint($80090315);
  SEC_E_DOWNGRADE_DETECTED = Longint($80090316);
  SEC_E_APPLICATION_PROTOCOL_MISMATCH = Longint($80090317);
  SEC_E_INVALID_UPN_NAME = Longint($80090319);
  SEC_E_CERT_UNKNOWN = Longint($80090320);
  SEC_E_CERT_EXPIRED = Longint($80090321);
  SEC_E_POLICY_NLTM_ONLY = Longint($80090332);
  SEC_E_LOGON_DENIED = Longint($8009030C);
  SEC_E_NO_IMPERSONATION = Longint($8009030B);
  SEC_E_UNSUPPORTED_PREAUTH = Longint($80090343);
  SEC_E_DELEGATION_POLICY = Longint($80090357);
  SEC_E_POLICY_NLTM_ONLY_2 = Longint($80090358);
  SP_PROT_TLS1_0_SERVER = $00000040;
  SP_PROT_TLS1_0_CLIENT = $00000080;
  SP_PROT_TLS1_1_SERVER = $00000100;
  SP_PROT_TLS1_1_CLIENT = $00000200;
  SP_PROT_TLS1_2_SERVER = $00000400;
  SP_PROT_TLS1_2_CLIENT = $00000800;
  SP_PROT_TLS1_3_SERVER = $00001000;
  SP_PROT_TLS1_3_CLIENT = $00002000;
  SSL_MAX_SAFE_MESSAGE_SIZE = 8192;
  SSL_MIN_MESSAGE_SIZE = 512;
  SSL_RETRY_ATTEMPTS = 5;
  SSL_ENCRYPTION_CHUNK_SIZE = 16000;
  SP_PROT_TLS1_0 = SP_PROT_TLS1_0_CLIENT;
  SP_PROT_TLS1_1 = SP_PROT_TLS1_1_CLIENT;
  SP_PROT_TLS1_2 = SP_PROT_TLS1_2_CLIENT;
  SP_PROT_TLS1_3 = SP_PROT_TLS1_3_CLIENT;

type
  PSecBuffer = ^TSecBuffer;
  TSecBuffer = record
    cbBuffer: ULONG;
    BufferType: ULONG;
    pvBuffer: Pointer;
  end;

  PSecBufferDesc = ^TSecBufferDesc;
  TSecBufferDesc = record
    ulVersion: ULONG;
    cBuffers: ULONG;
    pBuffers: PSecBuffer;
  end;

  PSecPkgInfo = ^TSecPkgInfo;
  TSecPkgInfo = record
    fCapabilities: ULONG;
    wVersion: Word;
    wRPCID: Word;
    cbMaxToken: ULONG;
    Name: LPWSTR;
    Comment: LPWSTR;
  end;

  SCHANNEL_CRED = record
    dwVersion: DWORD;
    cCreds: DWORD;
    paCred: Pointer;
    hRootStore: HCERTSTORE;
    cMappers: DWORD;
    aphMappers: Pointer;
    cSupportedAlgs: DWORD;
    palgSupportedAlgs: Pointer;
    grbitEnabledProtocols: DWORD;
    dwMinimumCipherStrength: DWORD;
    dwMaximumCipherStrength: DWORD;
    dwSessionLifespan: DWORD;
    dwFlags: DWORD;
    dwCredFormat: DWORD;
    pCipherSuitePriority: PWideChar;
  end;
  PSCHANNEL_CRED = ^SCHANNEL_CRED;

  SecPkgContext_StreamSizes = record
    cbHeader: ULONG;
    cbTrailer: ULONG;
    cbMaximumMessage: ULONG;
    cBuffers: ULONG;
    cbBlockSize: ULONG;
  end;

function AcquireCredentialsHandle(pszPrincipal, pszPackage: LPWSTR; fCredentialUse: ULONG;
  pvLogonId: Pointer; pAuthData: Pointer; pGetKeyFn: Pointer; pvGetKeyArgument: Pointer;
  phCredential: PCredHandle; ptsExpiry: PTimeStamp): SECURITY_STATUS; stdcall;
  external 'secur32.dll' name 'AcquireCredentialsHandleW';

function AcceptSecurityContext(phCredential: PCredHandle; phContext: PCtxtHandle;
  pInput: PSecBufferDesc; fContextReq: ULONG; TargetDataRep: ULONG;
  phNewContext: PCtxtHandle; pOutput: PSecBufferDesc; pfContextAttr: PULONG;
  ptsTimeStamp: PTimeStamp): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

function QueryContextAttributes(phContext: PCtxtHandle; ulAttribute: ULONG;
  pBuffer: Pointer): SECURITY_STATUS; stdcall;
  external 'secur32.dll' name 'QueryContextAttributesW';

function EncryptMessage(phContext: PCtxtHandle; fQOP: ULONG;
  pMessage: PSecBufferDesc; MessageSeqNo: ULONG): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

function DecryptMessage(phContext: PCtxtHandle; pMessage: PSecBufferDesc;
  MessageSeqNo: ULONG; pfQOP: PULONG): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

function DeleteSecurityContext(phContext: PCtxtHandle): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

function FreeCredentialsHandle(phCredential: PCredHandle): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

function ComapreCAS_OpType(var AOpType: TOperationType; ANewValue, AComparand: TOperationType): Boolean;

const
  DEFAULT_MAXREQUESTSPERSECOND = 55 * 5;
  DEFAULT_MAX_REQUEST_HEDER_SIZE = 16384 ; //8192;
  DEFAULT_MAX_REQUEST_SIZE = 10485760;  // 10MB
  DEFAULT_MAX_RESPONSE_SIZE = 104857600; // 100MB
  DEFAULT_CHUNK_SIZE = 65536; // 64KB
  CERT_STORE_PROV_SYSTEM = 10;
  CERT_SYSTEM_STORE_CURRENT_USER = $00010000;
  CERT_SYSTEM_STORE_LOCAL_MACHINE = $00020000;
  X509_ASN_ENCODING = $00000001;
  PKCS_7_ASN_ENCODING = $00010000;
  CERT_FIND_ANY = 0;
  CERT_FIND_SUBJECT_STR = $00080007;
  SCHANNEL_SHUTDOWN = 1;

type
  HCERTSTORE = Pointer;
  PCCERT_CONTEXT = Pointer;
  HCRYPTPROV = ULONG_PTR;

function ApplyControlToken(
  phContext: PCtxtHandle;
  pInput: PSecBufferDesc
): SECURITY_STATUS; stdcall; external 'secur32.dll';

function CertOpenSystemStore(hProv: HCRYPTPROV; szSubsystemProtocol: LPCWSTR): HCERTSTORE; stdcall;
  external 'crypt32.dll' name 'CertOpenSystemStoreW';

function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: DWORD): BOOL; stdcall;
  external 'crypt32.dll';

function CertFindCertificateInStore(hCertStore: HCERTSTORE; dwCertEncodingType: DWORD;
  dwFindFlags: DWORD; dwFindType: DWORD; pvFindPara: Pointer;
  pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall;
  external 'crypt32.dll';

function CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT): BOOL; stdcall;
  external 'crypt32.dll';

function CertGetNameString(pCertContext: PCCERT_CONTEXT; dwType: DWORD;
  dwFlags: DWORD; pvTypePara: Pointer; pszNameString: PWideChar;
  cchNameString: DWORD): DWORD; stdcall;
  external 'crypt32.dll' name 'CertGetNameStringW';

function CryptAcquireCertificatePrivateKey(pCert: PCCERT_CONTEXT; dwFlags: DWORD;
  pvReserved: Pointer; var phCryptProv: HCRYPTPROV; var pdwKeySpec: DWORD;
  var pfCallerFreeProv: BOOL): BOOL; stdcall;
  external 'crypt32.dll';

function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall;
  external 'advapi32.dll';

const
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

function AcceptEx(sListenSocket, sAcceptSocket: TSocket; lpOutputBuffer: Pointer;
  dwReceiveDataLength, dwLocalAddressLength, dwRemoteAddressLength: DWORD;
  var lpdwBytesReceived: DWORD; lpOverlapped: POverlapped): BOOL; stdcall;
  external 'mswsock.dll';

function GetSSLErrorDescription(Status: SECURITY_STATUS): string;
function IsSSLErrorRecoverable(Status: SECURITY_STATUS): Boolean;

function FreeContextBuffer(pvContextBuffer: Pointer): SECURITY_STATUS; stdcall;
procedure SafeFreeSSLBuffer(var Buffer: Pointer);
procedure AppendBytesToFile(const FileName: string; const Data: TBytes);

implementation

uses System.SyncObjs;

function FreeContextBuffer(pvContextBuffer: Pointer): SECURITY_STATUS; stdcall;
  external 'secur32.dll';

procedure SafeFreeSSLBuffer(var Buffer: Pointer);
begin
  if Assigned(Buffer) then
  begin
    try
      FreeContextBuffer(Buffer);
    except
      Logger.Error('FreeContextBuffer exception');
    end;
    Buffer := nil;
  end;
end;

function GetSSLErrorDescription(Status: SECURITY_STATUS): string;
begin
  case Status of
    SEC_E_OK:
      Result := 'SEC_E_OK - Operation successful';
    SEC_I_CONTINUE_NEEDED:
      Result := 'SEC_I_CONTINUE_NEEDED - Continue needed';
    SEC_I_COMPLETE_NEEDED:
      Result := 'SEC_I_COMPLETE_NEEDED - Complete needed';
    SEC_I_COMPLETE_AND_CONTINUE:
      Result := 'SEC_I_COMPLETE_AND_CONTINUE - Complete and continue';
    SEC_I_INCOMPLETE_CREDENTIALS:
      Result := 'SEC_I_INCOMPLETE_CREDENTIALS - Incomplete credentials';
    SEC_E_INSUFFICIENT_MEMORY:
      Result := 'SEC_E_INSUFFICIENT_MEMORY - Insufficient memory';
    SEC_E_INVALID_HANDLE:
      Result := 'SEC_E_INVALID_HANDLE - Invalid handle';
    SEC_E_UNSUPPORTED_FUNCTION:
      Result := 'SEC_E_UNSUPPORTED_FUNCTION - Unsupported function';
    SEC_E_TARGET_UNKNOWN:
      Result := 'SEC_E_TARGET_UNKNOWN - Target unknown';
    SEC_E_INTERNAL_ERROR:
      Result := 'SEC_E_INTERNAL_ERROR - Internal error';
    SEC_E_SECPKG_NOT_FOUND:
      Result := 'SEC_E_SECPKG_NOT_FOUND - Security package not found';
    SEC_E_INVALID_TOKEN:
      Result := 'SEC_E_INVALID_TOKEN - Invalid token';
    SEC_E_NO_CREDENTIALS:
      Result := 'SEC_E_NO_CREDENTIALS - No credentials';
    SEC_E_ALGORITHM_MISMATCH:
      Result := 'SEC_E_ALGORITHM_MISMATCH - Algorithm mismatch';
    SEC_E_UNKNOWN_CREDENTIALS:
      Result := 'SEC_E_UNKNOWN_CREDENTIALS - Unknown credentials';
    SEC_E_INCOMPLETE_MESSAGE:
      Result := 'SEC_E_INCOMPLETE_MESSAGE - Incomplete message';
    SEC_E_ENCRYPT_FAILURE:
      Result := 'SEC_E_ENCRYPT_FAILURE - Encryption failure';
    SEC_E_DECRYPT_FAILURE:
      Result := 'SEC_E_DECRYPT_FAILURE - Decryption failure';
    SEC_E_MESSAGE_ALTERED:
      Result := 'SEC_E_MESSAGE_ALTERED - Message has been altered';
    SEC_E_OUT_OF_SEQUENCE:
      Result := 'SEC_E_OUT_OF_SEQUENCE - Message out of sequence';
    SEC_E_NO_AUTHENTICATING_AUTHORITY:
      Result := 'SEC_E_NO_AUTHENTICATING_AUTHORITY - No authenticating authority';
    SEC_E_BAD_PKGID:
      Result := 'SEC_E_BAD_PKGID - Bad package ID';
    SEC_E_CONTEXT_EXPIRED:
      Result := 'SEC_E_CONTEXT_EXPIRED - Security context has expired';
    SEC_E_BUFFER_TOO_SMALL:
      Result := 'SEC_E_BUFFER_TOO_SMALL - Supplied buffer is too small';
    SEC_E_WRONG_PRINCIPAL:
      Result := 'SEC_E_WRONG_PRINCIPAL - Wrong principal';
    SEC_E_MESSAGE_TOO_LARGE:
      Result := 'SEC_E_MESSAGE_TOO_LARGE - Message too large for encryption';
    SEC_E_INVALID_PARAMETER:
      Result := 'SEC_E_INVALID_PARAMETER - Invalid parameter';
    SEC_E_NO_CONTEXT:
      Result := 'SEC_E_NO_CONTEXT - No security context available';
    SEC_E_PKU2U_CERT_FAILURE:
      Result := 'SEC_E_PKU2U_CERT_FAILURE - PKU2U certificate failure';
    SEC_E_MUTUAL_AUTH_FAILED:
      Result := 'SEC_E_MUTUAL_AUTH_FAILED - Mutual authentication failed';
    SEC_E_ONLY_HTTPS:
      Result := 'SEC_E_ONLY_HTTPS - Only HTTPS scheme allowed';
    SEC_E_DOWNGRADE_DETECTED:
      Result := 'SEC_E_DOWNGRADE_DETECTED - Security downgrade detected';
    SEC_E_APPLICATION_PROTOCOL_MISMATCH:
      Result := 'SEC_E_APPLICATION_PROTOCOL_MISMATCH - Application protocol mismatch';
    SEC_E_INVALID_UPN_NAME:
      Result := 'SEC_E_INVALID_UPN_NAME - Invalid UPN name';
    SEC_E_CERT_UNKNOWN:
      Result := 'SEC_E_CERT_UNKNOWN - Certificate unknown';
    SEC_E_CERT_EXPIRED:
      Result := 'SEC_E_CERT_EXPIRED - Certificate expired';
    SEC_E_POLICY_NLTM_ONLY:
      Result := 'SEC_E_POLICY_NLTM_ONLY - Policy requires NTLM only';
    SEC_E_LOGON_DENIED:
      Result := 'SEC_E_LOGON_DENIED - Logon denied';
    SEC_E_NO_IMPERSONATION:
      Result := 'SEC_E_NO_IMPERSONATION - No impersonation';
    else
      if (Status and $80000000) <> 0 then
         Result := Format('Unknown SSL Error: 0x%s (HRESULT: %d)', [IntToHex(Status, 8), Status])
      else
         Result := Format('Unknown SSL Status: 0x%s (%d)', [IntToHex(Status, 8), Status]);
  end;
end;

function IsSSLErrorRecoverable(Status: SECURITY_STATUS): Boolean;
begin
  case Status of
    SEC_E_BUFFER_TOO_SMALL,
    SEC_E_MESSAGE_TOO_LARGE,
    SEC_E_MESSAGE_ALTERED,
    SEC_E_INCOMPLETE_MESSAGE,
    SEC_E_INVALID_PARAMETER:
      Result := True;
    SEC_E_INVALID_HANDLE,
    SEC_E_NO_CREDENTIALS,
    SEC_E_CONTEXT_EXPIRED,
    SEC_E_INVALID_TOKEN,
    SEC_E_INTERNAL_ERROR,
    SEC_E_SECPKG_NOT_FOUND,
    SEC_E_NO_CONTEXT,
    SEC_E_CERT_EXPIRED,
    SEC_E_CERT_UNKNOWN,
    SEC_E_ALGORITHM_MISMATCH,
    SEC_E_UNKNOWN_CREDENTIALS:
      Result := False;
    else
      Result := False;
  end;
end;

function ComapreCAS_OpType(var AOpType: TOperationType; ANewValue, AComparand: TOperationType): Boolean;
var
  AlignedPtr: PInteger;
  OldIntValue, NewIntValue: Integer;
  ByteOffset, ShiftAmount: Cardinal;
  Mask: Integer;
begin
  AlignedPtr := PInteger(NativeUInt(@AOpType) and not 3);
  ByteOffset := NativeUInt(@AOpType) mod 4;
  ShiftAmount := ByteOffset * 8;
  Mask := not ($FF shl ShiftAmount);
  repeat
    OldIntValue := AlignedPtr^;
    if ((OldIntValue shr ShiftAmount) and $FF) <> Integer(AComparand) then
      Exit(False);
    NewIntValue := (OldIntValue and Mask) or (Integer(ANewValue) shl ShiftAmount);
  until TInterlocked.CompareExchange(AlignedPtr^, NewIntValue, OldIntValue) = OldIntValue;
  Result := True;
end;

procedure AppendBytesToFile(const FileName: string; const Data: TBytes);
var
  FileStream: TFileStream;
begin
  if FileExists(FileName) then
    FileStream := TFileStream.Create(FileName, fmOpenReadWrite or fmShareDenyNone)
  else
    FileStream := TFileStream.Create(FileName, fmCreate or fmShareDenyNone);

  try
    FileStream.Seek(0, soEnd);
    if Length(Data) > 0 then
      FileStream.WriteBuffer(Data[0], Length(Data));
  finally
    FileStream.Free;
  end;
end;


end.
