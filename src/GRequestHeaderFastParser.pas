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
unit GRequestHeaderFastParser;

interface

uses
  System.SysUtils;

function MatchKnownHeaderSlice(const S: string; StartIdx, NameLen: Integer; out CanonicalName: string): Boolean;
procedure AsciiBytesToStr(P: PByte; Len: Integer; out S: string);
function MatchKnownHeaderPtr(P: PByte; NameLen: Integer; out CanonicalName: string): Boolean;

implementation

function MatchKnownHeaderSlice(const S: string; StartIdx, NameLen: Integer; out CanonicalName: string): Boolean;
begin
  Result := False;
  case NameLen of
    4:
      if ((Ord(S[StartIdx]) or $20) = Ord('h')) and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('o')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('s')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'host';
        Exit(True);
      end;
    6:
      if ((Ord(S[StartIdx]) or $20) = Ord('a')) and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('c')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('c')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 4]) or $20) = Ord('p')) and
         ((Ord(S[StartIdx + 5]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'accept';
        Exit(True);
      end;
    10:
      if ((Ord(S[StartIdx]) or $20) = Ord('u')) and
         (S[StartIdx + 4] = '-') and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('s')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('r')) and
         ((Ord(S[StartIdx + 5]) or $20) = Ord('a')) and
         ((Ord(S[StartIdx + 6]) or $20) = Ord('g')) and
         ((Ord(S[StartIdx + 7]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 8]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 9]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'user-agent';
        Exit(True);
      end
      else if ((Ord(S[StartIdx]) or $20) = Ord('c')) and
              ((Ord(S[StartIdx + 1]) or $20) = Ord('o')) and
              ((Ord(S[StartIdx + 2]) or $20) = Ord('n')) and
              ((Ord(S[StartIdx + 3]) or $20) = Ord('n')) and
              ((Ord(S[StartIdx + 4]) or $20) = Ord('e')) and
              ((Ord(S[StartIdx + 5]) or $20) = Ord('c')) and
              ((Ord(S[StartIdx + 6]) or $20) = Ord('t')) and
              ((Ord(S[StartIdx + 7]) or $20) = Ord('i')) and
              ((Ord(S[StartIdx + 8]) or $20) = Ord('o')) and
              ((Ord(S[StartIdx + 9]) or $20) = Ord('n')) then
      begin
        CanonicalName := 'connection';
        Exit(True);
      end;
    12:
      if ((Ord(S[StartIdx]) or $20) = Ord('c')) and
         (S[StartIdx + 7] = '-') and
         ((Ord(S[StartIdx + 8]) or $20) = Ord('t')) and
         ((Ord(S[StartIdx + 9]) or $20) = Ord('y')) and
         ((Ord(S[StartIdx + 10]) or $20) = Ord('p')) and
         ((Ord(S[StartIdx + 11]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('o')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('t')) and
         ((Ord(S[StartIdx + 4]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 5]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 6]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'content-type';
        Exit(True);
      end;
    14:
      if ((Ord(S[StartIdx]) or $20) = Ord('c')) and
         (S[StartIdx + 7] = '-') and
         ((Ord(S[StartIdx + 8]) or $20) = Ord('l')) and
         ((Ord(S[StartIdx + 9]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 10]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 11]) or $20) = Ord('g')) and
         ((Ord(S[StartIdx + 12]) or $20) = Ord('t')) and
         ((Ord(S[StartIdx + 13]) or $20) = Ord('h')) and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('o')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('t')) and
         ((Ord(S[StartIdx + 4]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 5]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 6]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'content-length';
        Exit(True);
      end;
    15:
      if ((Ord(S[StartIdx]) or $20) = Ord('a')) and
         (S[StartIdx + 6] = '-') and
         ((Ord(S[StartIdx + 7]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 8]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 9]) or $20) = Ord('c')) and
         ((Ord(S[StartIdx + 10]) or $20) = Ord('o')) and
         ((Ord(S[StartIdx + 11]) or $20) = Ord('d')) and
         ((Ord(S[StartIdx + 12]) or $20) = Ord('i')) and
         ((Ord(S[StartIdx + 13]) or $20) = Ord('n')) and
         ((Ord(S[StartIdx + 14]) or $20) = Ord('g')) and
         ((Ord(S[StartIdx + 1]) or $20) = Ord('c')) and
         ((Ord(S[StartIdx + 2]) or $20) = Ord('c')) and
         ((Ord(S[StartIdx + 3]) or $20) = Ord('e')) and
         ((Ord(S[StartIdx + 4]) or $20) = Ord('p')) and
         ((Ord(S[StartIdx + 5]) or $20) = Ord('t')) then
      begin
        CanonicalName := 'accept-encoding';
        Exit(True);
      end;
  end;
end;

procedure AsciiBytesToStr(P: PByte; Len: Integer; out S: string);
var
  I: Integer;
  PDst: PWideChar;
begin
  if Len <= 0 then
  begin
    S := '';
    Exit;
  end;
  SetLength(S, Len);
  PDst := PWideChar(Pointer(S));
  for I := 0 to Len - 1 do
    PDst[I] := WideChar(P[I]);
end;

function MatchKnownHeaderPtr(P: PByte; NameLen: Integer; out CanonicalName: string): Boolean;
begin
  Result := False;
  case NameLen of
    4:
      if ((P[0] or $20) = Ord('h')) and
         ((P[1] or $20) = Ord('o')) and
         ((P[2] or $20) = Ord('s')) and
         ((P[3] or $20) = Ord('t')) then
      begin
        CanonicalName := 'host';
        Exit(True);
      end;
    6:
      if ((P[0] or $20) = Ord('a')) and
         ((P[1] or $20) = Ord('c')) and
         ((P[2] or $20) = Ord('c')) and
         ((P[3] or $20) = Ord('e')) and
         ((P[4] or $20) = Ord('p')) and
         ((P[5] or $20) = Ord('t')) then
      begin
        CanonicalName := 'accept';
        Exit(True);
      end
      else if ((P[0] or $20) = Ord('o')) and
              ((P[1] or $20) = Ord('r')) and
              ((P[2] or $20) = Ord('i')) and
              ((P[3] or $20) = Ord('g')) and
              ((P[4] or $20) = Ord('i')) and
              ((P[5] or $20) = Ord('n')) then
      begin
        CanonicalName := 'origin';
        Exit(True);
      end;
    7:
      if ((P[0] or $20) = Ord('u')) and
         ((P[1] or $20) = Ord('p')) and
         ((P[2] or $20) = Ord('g')) and
         ((P[3] or $20) = Ord('r')) and
         ((P[4] or $20) = Ord('a')) and
         ((P[5] or $20) = Ord('d')) and
         ((P[6] or $20) = Ord('e')) then
      begin
        CanonicalName := 'upgrade';
        Exit(True);
      end;
    10:
      if ((P[0] or $20) = Ord('u')) and
         (P[4] = Ord('-')) and
         ((P[1] or $20) = Ord('s')) and
         ((P[2] or $20) = Ord('e')) and
         ((P[3] or $20) = Ord('r')) and
         ((P[5] or $20) = Ord('a')) and
         ((P[6] or $20) = Ord('g')) and
         ((P[7] or $20) = Ord('e')) and
         ((P[8] or $20) = Ord('n')) and
         ((P[9] or $20) = Ord('t')) then
      begin
        CanonicalName := 'user-agent';
        Exit(True);
      end
      else if ((P[0] or $20) = Ord('c')) and
              ((P[1] or $20) = Ord('o')) and
              ((P[2] or $20) = Ord('n')) and
              ((P[3] or $20) = Ord('n')) and
              ((P[4] or $20) = Ord('e')) and
              ((P[5] or $20) = Ord('c')) and
              ((P[6] or $20) = Ord('t')) and
              ((P[7] or $20) = Ord('i')) and
              ((P[8] or $20) = Ord('o')) and
              ((P[9] or $20) = Ord('n')) then
      begin
        CanonicalName := 'connection';
        Exit(True);
      end;
    12:
      if ((P[0] or $20) = Ord('c')) and
         (P[7] = Ord('-')) and
         ((P[8] or $20) = Ord('t')) and
         ((P[9] or $20) = Ord('y')) and
         ((P[10] or $20) = Ord('p')) and
         ((P[11] or $20) = Ord('e')) and
         ((P[1] or $20) = Ord('o')) and
         ((P[2] or $20) = Ord('n')) and
         ((P[3] or $20) = Ord('t')) and
         ((P[4] or $20) = Ord('e')) and
         ((P[5] or $20) = Ord('n')) and
         ((P[6] or $20) = Ord('t')) then
      begin
        CanonicalName := 'content-type';
        Exit(True);
      end;
    14:
      if ((P[0] or $20) = Ord('c')) and
         (P[7] = Ord('-')) and
         ((P[8] or $20) = Ord('l')) and
         ((P[9] or $20) = Ord('e')) and
         ((P[10] or $20) = Ord('n')) and
         ((P[11] or $20) = Ord('g')) and
         ((P[12] or $20) = Ord('t')) and
         ((P[13] or $20) = Ord('h')) and
         ((P[1] or $20) = Ord('o')) and
         ((P[2] or $20) = Ord('n')) and
         ((P[3] or $20) = Ord('t')) and
         ((P[4] or $20) = Ord('e')) and
         ((P[5] or $20) = Ord('n')) and
         ((P[6] or $20) = Ord('t')) then
      begin
        CanonicalName := 'content-length';
        Exit(True);
      end;
    15:
      if ((P[0] or $20) = Ord('a')) and
         (P[6] = Ord('-')) and
         ((P[7] or $20) = Ord('e')) and
         ((P[8] or $20) = Ord('n')) and
         ((P[9] or $20) = Ord('c')) and
         ((P[10] or $20) = Ord('o')) and
         ((P[11] or $20) = Ord('d')) and
         ((P[12] or $20) = Ord('i')) and
         ((P[13] or $20) = Ord('n')) and
         ((P[14] or $20) = Ord('g')) and
         ((P[1] or $20) = Ord('c')) and
         ((P[2] or $20) = Ord('c')) and
         ((P[3] or $20) = Ord('e')) and
         ((P[4] or $20) = Ord('p')) and
         ((P[5] or $20) = Ord('t')) then
      begin
        CanonicalName := 'accept-encoding';
        Exit(True);
      end;
  end;
end;

end.
