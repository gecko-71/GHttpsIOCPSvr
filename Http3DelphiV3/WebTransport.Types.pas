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

unit WebTransport.Types;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$ALIGN 8}
{$MINENUMSIZE 4}

interface

uses
  Winapi.Windows,
  System.SysUtils,
  MsQuic.Types,
  MsQuic.ApiTable;

const

  WT_FRAME_BIDIR_STREAM         = $41;
  WT_STREAM_TYPE_SESSION        = $54;

  WT_SESSION_GONE               = $170D45;
  WT_SEND_STREAM_GONE           = $170D46;
  WT_STREAM_VIOLATION           = $170D47;

  WT_PROTOCOL_HEADER_VALUE      = 'webtransport';
  WT_ORIGIN_HEADER              = 'origin';

  WT_MAX_SESSIONS_PER_CONNECTION = 100;
  WT_MAX_STREAMS_PER_SESSION     = 1000;
  WT_MAX_DATAGRAM_SIZE           = 65536;

type

  TWTSessionId = UInt64;

  TWTStreamPhase = (
    wtspUnknown,
    wtspIdentified,
    wtspData
  );

  TWTStreamContext = record
    Stream:      HQUIC;
    SessionId:   TWTSessionId;
    Phase:       TWTStreamPhase;
    IsBidi:      Boolean;
    IsWT:        Boolean;
  end;
  PWTStreamContext = ^TWTStreamContext;

  PWTSessionContext = ^TWTSessionContext;
  TWTSessionContext = record
    SessionId:     TWTSessionId;
    StreamId:      UInt64;
    ConnectStream: HQUIC;
    Connection:    HQUIC;
    ConnCtx:       Pointer;
    Path:          string;
    Origin:        string;
    Active:        Boolean;
    StreamCount:   Integer;
  end;

  TWTSessionInfo = record
    SessionId: TWTSessionId;
    Path:      string;
    Origin:    string;
  end;

  TOnWTSessionRequest = function(Sender: TObject; const Info: TWTSessionInfo): Boolean of object;
  TOnWTSessionReady   = procedure(Sender: TObject; Session: PWTSessionContext) of object;
  TOnWTSessionClosed  = procedure(Sender: TObject; SessionId: TWTSessionId) of object;
  TOnWTStreamData     = procedure(Sender: TObject; Session: PWTSessionContext; Stream: HQUIC; const Data: TBytes) of object;
  TOnWTDatagram       = procedure(Sender: TObject; Session: PWTSessionContext; const Data: TBytes) of object;

implementation

end.
