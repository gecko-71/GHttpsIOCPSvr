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

unit MsQuic.Errors;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils, MsQuic.Types;

type
  EMsQuicError = class(Exception)
  private
    FStatus: QUIC_STATUS;
  public
    constructor Create(const Msg: string; AStatus: QUIC_STATUS);
    property Status: QUIC_STATUS read FStatus;
  end;

function QuicFailed(Status: QUIC_STATUS): Boolean; inline;
function QuicSucceeded(Status: QUIC_STATUS): Boolean; inline;
function QuicStatusToStr(Status: QUIC_STATUS): string;

implementation

constructor EMsQuicError.Create(const Msg: string; AStatus: QUIC_STATUS);
begin
  inherited Create(Format('%s (Status: 0x%x)', [Msg, AStatus]));
  FStatus := AStatus;
end;

function QuicFailed(Status: QUIC_STATUS): Boolean; inline;
begin

  Result := (Integer(Status) < 0);
end;

function QuicSucceeded(Status: QUIC_STATUS): Boolean; inline;
begin
  Result := (Integer(Status) >= 0);
end;

function QuicStatusToStr(Status: QUIC_STATUS): string;
begin
  case Status of
    $00000000: Result := 'SUCCESS';
    $C000009A: Result := 'INSUFFICIENT_RESOURCES / OUT_OF_MEMORY';
    $C000000D: Result := 'INVALID_PARAMETER';
    $C00000BB: Result := 'NOT_SUPPORTED';
    $C0000120: Result := 'CANCELED';
    $C0000241: Result := 'CONNECTION_REFUSED';
    else Result := Format('Unknown status 0x%x', [Status]);
  end;
end;

end.
