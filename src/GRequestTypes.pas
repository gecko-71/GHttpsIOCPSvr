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
unit GRequestTypes;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.Generics.Defaults;

type
  TGClientCertInfo = record
    HasCertificate: Boolean;
    IsVerified: Boolean;
    Subject: string;
    CommonName: string;
    Issuer: string;
    SerialNumber: string;
    ThumbprintSHA256: string;
    ValidFrom: TDateTime;
    ValidTo: TDateTime;
    ValidationError: string;
    SAN: string;
    RawCertBase64: string;
  end;

  TClientCertValidateEvent = reference to function(const CertInfo: TGClientCertInfo): Boolean;

  TCaseInsensitiveStringComparer = class(TInterfacedObject, IEqualityComparer<string>)
  public
    function Equals(const Left, Right: string): Boolean; reintroduce; overload;
    function GetHashCode(const Value: string): Integer; reintroduce; overload;
  end;

  THttpMethod = (hmUnknown, hmGET, hmPOST, hmPUT, hmDELETE, hmHEAD, hmOPTIONS, hmPATCH, hmTRACE, hmCONNECT);
  THttpVersion = (hvUnknown, hvHTTP10, hvHTTP11, hvHTTP20);
  TRequestState = (rsWaitingHeaders, rsParsingHeaders, rsWaitingBody, rsComplete, rsError, rsRecovering);
  TTransferEncoding = (teNone, teChunked, teCompress, teDeflate, teGzip, teIdentity);
  TConnectionType = (ctKeepAlive, ctClose, ctUpgrade);
  TSecurityThreat = (stNone, stRequestSmuggling, stHeaderInjection, stOversizeAttack,
                    stMalformedURI, stInvalidEncoding, stSuspiciousHeaders);
  TRecoveryAction = (raAbort, raSkipHeader, raTruncateValue, raSanitize, raContinue);
  TValidationLevel = (vlStrict, vlModerate, vlPermissive);

function IsHexDigit(c: Char): Boolean;

implementation

function IsHexDigit(c: Char): Boolean;
begin
  Result := ((c >= '0') and (c <= '9')) or
            ((c >= 'A') and (c <= 'F')) or
            ((c >= 'a') and (c <= 'f'));
end;

function TCaseInsensitiveStringComparer.Equals(const Left, Right: string): Boolean;
begin
  Result := CompareText(Left, Right) = 0;
end;

function TCaseInsensitiveStringComparer.GetHashCode(const Value: string): Integer;
var
  UpperValue: string;
begin
  UpperValue := UpperCase(Value);
  Result := TEqualityComparer<string>.Default.GetHashCode(UpperValue);
end;

end.
