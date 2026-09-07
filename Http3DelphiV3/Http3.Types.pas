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

unit Http3.Types;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  System.SysUtils;

const

  HTTP3_ALPN_H3           : AnsiString = 'h3';
  HTTP3_ALPN_H3_29        : AnsiString = 'h3-29';

  HTTP3_STREAM_TYPE_CONTROL       = $00;
  HTTP3_STREAM_TYPE_PUSH          = $01;
  HTTP3_STREAM_TYPE_QPACK_ENCODER = $02;
  HTTP3_STREAM_TYPE_QPACK_DECODER = $03;

  HTTP3_FRAME_DATA          = $00;
  HTTP3_FRAME_HEADERS       = $01;
  HTTP3_FRAME_CANCEL_PUSH   = $03;
  HTTP3_FRAME_SETTINGS      = $04;
  HTTP3_FRAME_PUSH_PROMISE  = $05;
  HTTP3_FRAME_GOAWAY        = $07;
  HTTP3_FRAME_MAX_PUSH_ID   = $0D;

  HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY  = $01;
  HTTP3_SETTING_MAX_FIELD_SECTION_SIZE    = $06;
  HTTP3_SETTING_QPACK_BLOCKED_STREAMS     = $07;
  HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL   = $08;
  HTTP3_SETTING_H3_DATAGRAM               = $33;
  HTTP3_SETTING_WT_INITIAL_MAX_DATA       = $2B61;
  HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI= $2B64;
  HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI=$2B65;
  HTTP3_SETTING_ENABLE_WEBTRANSPORT_DRAFT02 = $2B603742;
  HTTP3_SETTING_WT_MAX_SESSIONS           = $14E9CD29;

  H3_NO_ERROR              = $0100;
  H3_GENERAL_PROTOCOL_ERROR= $0101;
  H3_INTERNAL_ERROR        = $0102;
  H3_STREAM_CREATION_ERROR = $0103;
  H3_CLOSED_CRITICAL_STREAM= $0104;
  H3_FRAME_UNEXPECTED      = $0105;
  H3_FRAME_ERROR           = $0106;
  H3_EXCESSIVE_LOAD        = $0107;
  H3_ID_ERROR              = $0108;
  H3_SETTINGS_ERROR        = $0109;
  H3_MISSING_SETTINGS      = $010A;
  H3_REQUEST_REJECTED      = $010B;
  H3_REQUEST_CANCELLED     = $010C;
  H3_REQUEST_INCOMPLETE    = $010D;
  H3_MESSAGE_ERROR         = $010E;
  H3_CONNECT_ERROR         = $010F;
  H3_VERSION_FALLBACK      = $0110;

  QPACK_DECOMPRESSION_FAILED = $0200;
  QPACK_ENCODER_STREAM_ERROR = $0201;
  QPACK_DECODER_STREAM_ERROR = $0202;

implementation

end.
