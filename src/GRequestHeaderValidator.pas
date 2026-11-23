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
unit GRequestHeaderValidator;

interface

uses
  System.SysUtils,
  System.Classes,
  System.StrUtils,
  System.Character,
  GRequestTypes;

type
  THeaderValidator = class
  protected
    class function IsValidTokenChar(C: Char): Boolean;
    class function IsValidFieldVChar(C: Char): Boolean;
    class function IsObsText(C: Char): Boolean;
    class function DetectInjectionAttempt(const Value: string): Boolean;
  public
    class function HasSuspiciousPatterns(const Value: string): Boolean;
    class function ValidateHeaderName(const Name: string; out ErrorMsg: string): Boolean;
    class function ValidateHeaderValue(const AHeaderName, Value: string; out ErrorMsg: string): Boolean;
    class function SanitizeHeaderValue(const Value: string): string;
    class function IsSafeHeaderName(const Name: string): Boolean;
    class function HasSuspiciousPatternsPtr(P: PByte; Len: Integer): Boolean;
    class function DetectRequestSmuggling(const Headers: TStringList): TSecurityThreat;
  end;

function FastContainsAsciiCI(const Haystack, LowerNeedle: string): Boolean;

implementation

function MatchAsciiCIEq(P: PByte; const Lit: AnsiString): Boolean; inline;
var
  I, L: Integer;
begin
  L := Length(Lit);
  for I := 0 to L - 1 do
  begin
    if (P[I] or $20) <> Ord(Lit[I + 1]) then
      Exit(False);
  end;
  Result := True;
end;

class function THeaderValidator.IsValidTokenChar(C: Char): Boolean;
begin
  Result := C.IsLetterOrDigit or
           CharInSet(C, ['-', '.', '_', '~', '^', '`', '|']);
end;

class function THeaderValidator.IsValidFieldVChar(C: Char): Boolean;
begin
  Result := (Ord(C) >= $21) and (Ord(C) <= $7E);
end;

class function THeaderValidator.IsObsText(C: Char): Boolean;
begin
  Result := (Ord(C) >= $80) and (Ord(C) <= $FF);
end;

class function THeaderValidator.HasSuspiciousPatternsPtr(P: PByte; Len: Integer): Boolean;
var
  I: Integer;
  B, BL: Byte;
begin
  Result := False;
  if (P = nil) or (Len <= 0) then
    Exit;

  for I := 0 to Len - 1 do
  begin
    B := P[I];
    case B of
      0, 10, 13, 34, 36, 37, 38, 39, 40, 42, 59, 60, 61, 62, 92, 96, 123, 124:
        Exit(True);
      46:
        if (I + 1 < Len) and (P[I + 1] = 46) then
          Exit(True);
      58:
        if (I + 2 < Len) and (P[I + 1] = Ord('2')) and (P[I + 2] = Ord('2')) then
          Exit(True);
      47:
        if (I + 4 < Len) and MatchAsciiCIEq(P + I + 1, 'etc/') then
          Exit(True);
      Ord('s'), Ord('S'):
        if ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'slowloris')) or
           ((I + 4 <= Len) and MatchAsciiCIEq(P + I, 'sys.')) or
           ((I + 6 <= Len) and MatchAsciiCIEq(P + I, 'sleep(')) or
           ((I + 3 <= Len) and MatchAsciiCIEq(P + I, 'sp_')) then
          Exit(True);
      Ord('j'), Ord('J'):
        if (I + 11 <= Len) and MatchAsciiCIEq(P + I, 'javascript:') then
          Exit(True);
      Ord('v'), Ord('V'):
        if (I + 9 <= Len) and MatchAsciiCIEq(P + I, 'vbscript:') then
          Exit(True);
      Ord('d'), Ord('D'):
        if ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'data:text')) or
           ((I + 7 <= Len) and MatchAsciiCIEq(P + I, 'delete ')) or
           ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'deletefrom')) or
           ((I + 5 <= Len) and MatchAsciiCIEq(P + I, 'drop ')) or
           ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'droptable')) or
           ((I + 12 <= Len) and MatchAsciiCIEq(P + I, 'dropdatabase')) or
           ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'dbms_pipe')) then
          Exit(True);
      Ord('x'), Ord('X'):
        if ((I + 17 <= Len) and MatchAsciiCIEq(P + I, 'x-injected-header')) or
           ((I + 16 <= Len) and MatchAsciiCIEq(P + I, 'x-forwarded-host')) or
           ((I + 15 <= Len) and MatchAsciiCIEq(P + I, 'x-original-host')) or
           ((I + 11 <= Len) and MatchAsciiCIEq(P + I, 'xp_cmdshell')) then
          Exit(True);
      Ord('w'), Ord('W'):
        if ((I + 7 <= Len) and MatchAsciiCIEq(P + I, 'win.ini')) or
           ((I + 7 <= Len) and MatchAsciiCIEq(P + I, 'waitfor')) then
          Exit(True);
      Ord('b'), Ord('B'):
        if ((I + 8 <= Len) and MatchAsciiCIEq(P + I, 'boot.ini')) or
           ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'benchmark(')) then
          Exit(True);
      Ord('p'), Ord('P'):
        if ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'powershell')) or
           ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'pg_sleep(')) then
          Exit(True);
      Ord('t'), Ord('T'):
        if ((I + 13 <= Len) and MatchAsciiCIEq(P + I, 'this.password')) or
           ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'truncate ')) or
           ((I + 13 <= Len) and MatchAsciiCIEq(P + I, 'truncatetable')) then
          Exit(True);
      Ord('u'), Ord('U'):
        if ((I + 6 <= Len) and MatchAsciiCIEq(P + I, 'union ')) or
           ((I + 11 <= Len) and MatchAsciiCIEq(P + I, 'unionselect')) or
           ((I + 14 <= Len) and MatchAsciiCIEq(P + I, 'unionallselect')) or
           ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'updatexml(')) or
           ((I + 9 <= Len) and MatchAsciiCIEq(P + I, 'utl_inaddr')) then
          Exit(True);
      Ord('i'), Ord('I'):
        if ((I + 7 <= Len) and MatchAsciiCIEq(P + I, 'insert ')) or
           ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'insertinto')) or
           ((I + 18 <= Len) and MatchAsciiCIEq(P + I, 'information_schema')) then
          Exit(True);
      Ord('a'), Ord('A'):
        if ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'all_tables')) or
           ((I + 6 <= Len) and MatchAsciiCIEq(P + I, 'alter ')) or
           ((I + 10 <= Len) and MatchAsciiCIEq(P + I, 'altertable')) or
           ((I + 5 <= Len) and MatchAsciiCIEq(P + I, 'admin')) then
          Exit(True);
      Ord('e'), Ord('E'):
        if (I + 13 <= Len) and MatchAsciiCIEq(P + I, 'extractvalue(') then
          Exit(True);
      Ord('c'), Ord('C'):
        if ((I + 5 <= Len) and MatchAsciiCIEq(P + I, 'cat /')) or
           ((I + 7 <= Len) and MatchAsciiCIEq(P + I, 'ctxsys.')) then
          Exit(True);
      Ord('o'), Ord('O'):
        if (I + 5 <= Len) and MatchAsciiCIEq(P + I, 'on') then
        begin
          BL := P[I + 2] or $20;
          if (BL = Ord('l')) or (BL = Ord('e')) or (BL = Ord('c')) or (BL = Ord('m')) then
            Exit(True);
        end;
      Ord('0'):
        if (I + 4 <= Len) and ((P[I + 1] or $20) = Ord('x')) and (P[I + 2] = Ord('7')) and ((P[I + 3] or $20) = Ord('f')) then
          Exit(True);
      Ord('1'):
        if (I + 7 <= Len) and (P[I + 1] = Ord('6')) and (P[I + 2] = Ord('9')) and (P[I + 3] = Ord('.')) then
          Exit(True);
    end;
  end;
end;

class function THeaderValidator.HasSuspiciousPatterns(const Value: string): Boolean;
const
  SUSPICIOUS_PATTERNS: array[0..51] of string = (
    'javascript:', 'data:text/html', 'vbscript:', '<script', '</script>', '<svg', '<iframe',
    'onload=', 'onerror=', 'onclick=', 'onmouseover=',
    'x-injected-header', 'x-forwarded-host', 'x-original-host',
    '../..', '..\..', '..%2f', '..%5c', '..%5C', '..\', '%252e%252e', '%c0%af', '%c0', '%e0%80%af', '%f0%80%80%af',
    '/etc/passwd', 'win.ini', 'boot.ini', '\\192.168.',
    'cat /etc', 'cat /', 'cat$ifs', '*(|', '%s%s%s', '%n%n%n%n', #13#10, '\r\n',
    '${jndi:', '169.254.169.254', '0x7f000001', '127.0.0.1:22',
    '{{', '${', 'powershell', '&&', '||', '$(', '`',
    '''$gt''', '''$ne''', '''$where''', 'this.password'
  );
  SQL_PATTERNS: array[0..40] of string = (
    'or 1=1', 'or ''1''=''1''', 'or ''1''=''1', 'or ''1'' = ''1''', 'or ''a''=''a',
    'and 1=1', 'and 1=2', '1''=''1', '1=1--', ''' or ''=''',
    'waitfor delay', 'sleep(', 'pg_sleep(', 'benchmark(', 'dbms_pipe.receive_message',
    'sp_executesql', 'xp_cmdshell', '; shutdown', '; drop',
    'information_schema', 'sys.tables', 'sys.objects', 'sys.user_tables', 'all_tables',
    'extractvalue(', 'updatexml(', 'utl_inaddr.', 'ctxsys.driths.',
    '1;--', 'admin''--', 'admin''#', 'admin''/*',
    'union select', 'union all select', 'union distinct select',
    'insert into', 'delete from',
    'drop table', 'drop database', 'alter table', 'truncate table'
  );
  SQL_PATTERNS_NOWS: array[0..40] of string = (
    'or1=1', 'or''1''=''1''', 'or''1''=''1', 'or''1''=''1''', 'or''a''=''a',
    'and1=1', 'and1=2', '1''=''1', '1=1--', '''or''=''',
    'waitfordelay', 'sleep(', 'pg_sleep(', 'benchmark(', 'dbms_pipe.receive_message',
    'sp_executesql', 'xp_cmdshell', ';shutdown', ';drop',
    'information_schema', 'sys.tables', 'sys.objects', 'sys.user_tables', 'all_tables',
    'extractvalue(', 'updatexml(', 'utl_inaddr.', 'ctxsys.driths.',
    '1;--', 'admin''--', 'admin''#', 'admin''/*',
    'unionselect', 'unionallselect', 'uniondistinctselect',
    'insertinto', 'deletefrom',
    'droptable', 'dropdatabase', 'altertable', 'truncatetable'
  );
var
  LowerValue: string;
  NoWsValue: string;
  CollapsedValue: string;
  CleanComments: string;
  I: Integer;
  J: Integer;
  Len: Integer;
  SelPos: Integer;
  UpdPos: Integer;
  LastWasSpace: Boolean;
  HasWhitespace: Boolean;
  IsSimpleSafeChars: Boolean;
  HasDot, HasSlash, HasStar, HasColon, Has1, Has0: Boolean;
  CharMask: Cardinal;
  C: Char;
begin
  Result := False;
  Len := Length(Value);
  if Len = 0 then
    Exit;

  HasWhitespace := False;
  IsSimpleSafeChars := Len <= 64;
  HasDot := False;
  HasSlash := False;
  HasStar := False;
  HasColon := False;
  Has1 := False;
  Has0 := False;
  CharMask := 0;

  for I := 1 to Len do
  begin
    C := Value[I];
    if C = #0 then
      Exit(True);
    if (Ord(C) < 32) and (C <> #9) and (C <> #10) and (C <> #13) then
      Exit(True);
    if (C = ' ') or (C = #9) or (C = #10) or (C = #13) then
      HasWhitespace := True;
    if IsSimpleSafeChars then
    begin
      if (C >= 'a') and (C <= 'z') then
        CharMask := CharMask or (Cardinal(1) shl (Ord(C) - Ord('a')))
      else if (C >= 'A') and (C <= 'Z') then
        CharMask := CharMask or (Cardinal(1) shl (Ord(C) - Ord('A')))
      else if C = '.' then
      begin
        if (I > 1) and (Value[I - 1] = '.') then
          Exit(True);
        HasDot := True;
      end
      else if C = '/' then
        HasSlash := True
      else if C = '*' then
        HasStar := True
      else if C = ':' then
        HasColon := True
      else if C = '1' then
        Has1 := True
      else if C = '0' then
        Has0 := True
      else if not (((C >= '2') and (C <= '9')) or (C = '-') or (C = '+')) then
        IsSimpleSafeChars := False;
    end;
  end;

  if IsSimpleSafeChars then
  begin
    if HasSlash and HasStar and (Value <> '*/*') then
    begin
      LowerValue := LowerCase(Value);
      if (Pos('/*', LowerValue) > 0) or (Pos('*/', LowerValue) > 0) then
      begin
        CleanComments := StringReplace(LowerValue, '*/*', '', [rfReplaceAll]);
        if (Pos('*/', CleanComments) > 0) or (Pos('/*!', LowerValue) > 0) or (Pos('/*', CleanComments) > 0) then
          Exit(True);
      end;
    end;
    if HasColon and (Len >= 10) then
    begin
      if ((CharMask and (1 shl 9)) <> 0) and FastContainsAsciiCI(Value, 'javascript:') then
        Exit(True);
      if ((CharMask and (1 shl 21)) <> 0) and FastContainsAsciiCI(Value, 'vbscript:') then
        Exit(True);
      if ((CharMask and (1 shl 3)) <> 0) and FastContainsAsciiCI(Value, 'data:text/html') then
        Exit(True);
      if Has1 and FastContainsAsciiCI(Value, '127.0.0.1:22') then
        Exit(True);
    end;
    if ((CharMask and (1 shl 23)) <> 0) and (Len >= 15) then
    begin
      if FastContainsAsciiCI(Value, 'x-injected-header') or FastContainsAsciiCI(Value, 'x-forwarded-host') or
         FastContainsAsciiCI(Value, 'x-original-host') then
        Exit(True);
    end;
    if HasDot and (Len >= 7) then
    begin
      if Has1 and FastContainsAsciiCI(Value, '169.254.169.254') then
        Exit(True);
      if CharMask <> 0 then
      begin
        if ((CharMask and (1 shl 19)) <> 0) and FastContainsAsciiCI(Value, 'this.password') then
          Exit(True);
        if ((CharMask and (1 shl 22)) <> 0) and FastContainsAsciiCI(Value, 'win.ini') then
          Exit(True);
        if ((CharMask and (1 shl 1)) <> 0) and FastContainsAsciiCI(Value, 'boot.ini') then
          Exit(True);
        if ((CharMask and ((1 shl 18) or (1 shl 24))) = ((1 shl 18) or (1 shl 24))) and
           (FastContainsAsciiCI(Value, 'sys.tables') or FastContainsAsciiCI(Value, 'sys.objects') or FastContainsAsciiCI(Value, 'sys.user')) then
          Exit(True);
        if ((CharMask and (1 shl 20)) <> 0) and FastContainsAsciiCI(Value, 'utl_inaddr.') then
          Exit(True);
        if ((CharMask and (1 shl 2)) <> 0) and FastContainsAsciiCI(Value, 'ctxsys.driths.') then
          Exit(True);
      end;
    end;
    if HasSlash and (Len >= 11) and ((CharMask and (1 shl 4)) <> 0) and FastContainsAsciiCI(Value, '/etc/passwd') then
      Exit(True);
    if Has0 and (Len >= 10) and ((CharMask and (1 shl 23)) <> 0) and FastContainsAsciiCI(Value, '0x7f000001') then
      Exit(True);
    if (Len >= 10) and ((CharMask and ((1 shl 15) or (1 shl 22))) = ((1 shl 15) or (1 shl 22))) and FastContainsAsciiCI(Value, 'powershell') then
      Exit(True);
    if (Len >= 6) and ((CharMask and ((1 shl 18) or (1 shl 4) or (1 shl 11))) = ((1 shl 18) or (1 shl 4) or (1 shl 11))) and FastContainsAsciiCI(Value, 'select') then
      Exit(True);
    if (Len >= 6) and ((CharMask and ((1 shl 20) or (1 shl 15) or (1 shl 3))) = ((1 shl 20) or (1 shl 15) or (1 shl 3))) and FastContainsAsciiCI(Value, 'update') then
      Exit(True);
    Exit(False);
  end;

  if (Pos('%00', Value) > 0) then
    Exit(True);

  LowerValue := LowerCase(Value);

  if HasWhitespace then
  begin
    SetLength(NoWsValue, Len);
    J := 0;
    for I := 1 to Len do
    begin
      if not CharInSet(LowerValue[I], [' ', #9, #10, #13]) then
      begin
        Inc(J);
        NoWsValue[J] := LowerValue[I];
      end;
    end;
    SetLength(NoWsValue, J);

    SetLength(CollapsedValue, Len);
    J := 0;
    LastWasSpace := False;
    for I := 1 to Len do
    begin
      if CharInSet(LowerValue[I], [' ', #9]) then
      begin
        if not LastWasSpace then
        begin
          Inc(J);
          CollapsedValue[J] := ' ';
          LastWasSpace := True;
        end;
      end
      else
      begin
        Inc(J);
        CollapsedValue[J] := LowerValue[I];
        LastWasSpace := False;
      end;
    end;
    SetLength(CollapsedValue, J);
  end
  else
  begin
    NoWsValue := LowerValue;
    CollapsedValue := LowerValue;
  end;

  for I := 0 to High(SUSPICIOUS_PATTERNS) do
  begin
    if (Pos(SUSPICIOUS_PATTERNS[I], LowerValue) > 0) or
       (HasWhitespace and ((Pos(SUSPICIOUS_PATTERNS[I], NoWsValue) > 0) or
                           (Pos(SUSPICIOUS_PATTERNS[I], CollapsedValue) > 0))) then
      Exit(True);
  end;

  if (Pos('/*', LowerValue) > 0) or (Pos('*/', LowerValue) > 0) then
  begin
    CleanComments := StringReplace(LowerValue, '*/*', '', [rfReplaceAll]);
    if (Pos('*/', CleanComments) > 0) or (Pos('/*!', LowerValue) > 0) then
      Exit(True);
    I := Pos('/*', CleanComments);
    while I > 0 do
    begin
      if (I > 1) and CharInSet(CleanComments[I - 1], ['a'..'z', '0'..'9', '-', '+', '.']) and
         ((I + 2 > Length(CleanComments)) or CharInSet(CleanComments[I + 2], [',', ';', ' ', #9])) then
        I := PosEx('/*', CleanComments, I + 2)
      else
        Exit(True);
    end;
  end;

  for I := 0 to High(SQL_PATTERNS) do
  begin
    if (Pos(SQL_PATTERNS[I], CollapsedValue) > 0) or
       (Pos(SQL_PATTERNS_NOWS[I], NoWsValue) > 0) then
      Exit(True);
  end;

  SelPos := Pos('select', NoWsValue);
  if SelPos > 0 then
  begin
    if Pos('from', Copy(NoWsValue, SelPos + 6, MaxInt)) > 0 then
      Exit(True);
    if (Pos('select*', NoWsValue) > 0) or
       (Pos('select@@', NoWsValue) > 0) or
       (Pos('selectnull', NoWsValue) > 0) or
       (Pos('selectchar(', NoWsValue) > 0) then
      Exit(True);
  end;

  UpdPos := Pos('update', NoWsValue);
  if UpdPos > 0 then
  begin
    if Pos('set', Copy(NoWsValue, UpdPos + 6, MaxInt)) > 0 then
      Exit(True);
  end;
end;

class function THeaderValidator.DetectInjectionAttempt(const Value: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to Length(Value) do
  begin
    if (Value[I] = #13) or (Value[I] = #10) or (Value[I] = #0) then
    begin
      Result := True;
      Exit;
    end;
    if (Ord(Value[I]) < 32) and (Value[I] <> #9) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

class function THeaderValidator.ValidateHeaderName(const Name: string; out ErrorMsg: string): Boolean;
var
  I: Integer;
  Len: Integer;
  LowerName: string;
begin
  Result := False;
  ErrorMsg := '';
  try
    Len := Length(Name);
    if Len = 0 then
    begin
      ErrorMsg := 'Header name cannot be empty';
      Exit;
    end;

    if Len > 256 then
    begin
      ErrorMsg := 'Header name too long (>256 characters)';
      Exit;
    end;
    if ((Len = 4) and SameText(Name, 'Host')) or
       ((Len = 10) and (SameText(Name, 'User-Agent') or SameText(Name, 'Connection'))) or
       ((Len = 6) and SameText(Name, 'Accept')) or
       ((Len = 14) and SameText(Name, 'Content-Length')) or
       ((Len = 12) and SameText(Name, 'Content-Type')) or
       ((Len = 15) and (SameText(Name, 'Accept-Encoding') or SameText(Name, 'Accept-Language'))) then
    begin
      Result := True;
      Exit;
    end;
    for I := 1 to Len do
    begin
      if not IsValidTokenChar(Name[I]) then
      begin
        ErrorMsg := Format('Invalid character in header name: %s (code: %d, position %d', [Name[I], Ord(Name[I]), I]);
        Exit;
      end;
    end;
    LowerName := LowerCase(Name);
    if (Pos('script', LowerName) > 0) or
       (Pos('javascript', LowerName) > 0) or
       (Pos('vbscript', LowerName) > 0) then
    begin
      ErrorMsg := 'Forbidden pattern in header name: ' + Name;
      Exit;
    end;
    if HasSuspiciousPatterns(Name) then
    begin
      ErrorMsg := 'Suspicious patterns detected in header name: ' + Name;
      Exit;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      ErrorMsg := 'Header name validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function THeaderValidator.ValidateHeaderValue(const AHeaderName, Value: string; out ErrorMsg: string): Boolean;
var
  I: Integer;
  Ch: Char;
begin
  ErrorMsg := '';
  for I := 1 to Length(Value) do
  begin
    Ch := Value[I];
    if (Ch = #13) or (Ch = #10) then
    begin
      ErrorMsg := 'Invalid character (CR or LF) found inside header value. Possible CRLF Injection attack.';
      Exit(False);
    end;
    if Ch = #0 then
    begin
      ErrorMsg := 'Invalid character (NULL) found in header value.';
      Exit(False);
    end;
  end;

  if not ((Length(AHeaderName) = 13) and SameText(AHeaderName, 'Authorization')) and HasSuspiciousPatterns(Value) then
  begin
    ErrorMsg := 'Suspicious patterns (potential XSS, SQLi) detected in header value.';
    Exit(False);
  end;
  Result := True;
end;

class function THeaderValidator.SanitizeHeaderValue(const Value: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(Value) do
  begin
    C := Value[I];
    if (Ord(C) < 32) and (C <> ' ') and (C <> #9) then
      Continue;
    if CharInSet(C, [#13, #10, #0]) then
      Continue;
    Result := Result + C;
  end;
  Result := Trim(Result);
  if Length(Result) > 8192 then
    Result := Copy(Result, 1, 8192);
end;

const
  CSafeHeaders: array[0..16] of string = (
    'accept', 'accept-encoding', 'accept-language', 'authorization',
    'cache-control', 'connection', 'content-length', 'content-type',
    'cookie', 'host', 'referer', 'user-agent', 'x-requested-with',
    'x-forwarded-for', 'x-real-ip', 'if-none-match', 'if-modified-since'
  );
  CUnsafeHeaders: array[0..7] of string = (
    'x-forwarded-host', 'x-original-host', 'x-rewrite-url',
    'x-original-url', 'x-override-url', 'x-http-destip',
    'x-http-host-override', 'x-forwarded-server'
  );

function FastContainsAsciiCI(const Haystack, LowerNeedle: string): Boolean;
var
  HLen, NLen, I, J: Integer;
  C1, C2: Word;
begin
  NLen := Length(LowerNeedle);
  if NLen = 0 then
    Exit(True);
  HLen := Length(Haystack);
  if HLen < NLen then
    Exit(False);
  for I := 1 to HLen - NLen + 1 do
  begin
    C1 := Ord(Haystack[I]);
    if (C1 >= Ord('A')) and (C1 <= Ord('Z')) then
      C1 := C1 or $20;
    if C1 = Ord(LowerNeedle[1]) then
    begin
      Result := True;
      for J := 2 to NLen do
      begin
        C2 := Ord(Haystack[I + J - 1]);
        if (C2 >= Ord('A')) and (C2 <= Ord('Z')) then
          C2 := C2 or $20;
        if C2 <> Ord(LowerNeedle[J]) then
        begin
          Result := False;
          Break;
        end;
      end;
      if Result then
        Exit(True);
    end;
  end;
  Result := False;
end;

class function THeaderValidator.IsSafeHeaderName(const Name: string): Boolean;
var
  I: Integer;
  Len: Integer;
  NeedsNorm: Boolean;
  NormalizedName: string;
begin
  Len := Length(Name);
  if Len = 0 then
    Exit(False);
  NeedsNorm := (Name[1] <= ' ') or (Name[Len] <= ' ');
  if not NeedsNorm then
  begin
    for I := 1 to Len do
    begin
      if (Name[I] >= 'A') and (Name[I] <= 'Z') then
      begin
        NeedsNorm := True;
        Break;
      end;
    end;
  end;
  if NeedsNorm then
    NormalizedName := LowerCase(Trim(Name))
  else
    NormalizedName := Name;
  if Length(NormalizedName) = 0 then
    Exit(False);

  for I := 0 to High(CUnsafeHeaders) do
  begin
    if NormalizedName = CUnsafeHeaders[I] then
      Exit(False);
  end;

  for I := 0 to High(CSafeHeaders) do
  begin
    if NormalizedName = CSafeHeaders[I] then
      Exit(True);
  end;

  if (Length(NormalizedName) >= 2) and (NormalizedName[1] = 'x') and (NormalizedName[2] = '-') then
  begin
    if THeaderValidator.HasSuspiciousPatterns(NormalizedName) then
      Exit(False);
    Exit(Length(NormalizedName) <= 64);
  end;
  Result := (Length(NormalizedName) <= 64) and NormalizedName[1].IsLetter;
end;

class function THeaderValidator.DetectRequestSmuggling(const Headers: TStringList): TSecurityThreat;
var
  I, ContentLengthCount, TransferEncodingCount: Integer;
  Line, Name, Value: string;
  ColonPos: Integer;
  ContentLengthValues: TStringList;
  HasChunked, HasContentLength: Boolean;
  HostCount: Integer;
  LowerVal: string;
begin
  Result := stNone;
  ContentLengthCount := 0;
  TransferEncodingCount := 0;
  HasChunked := False;
  HasContentLength := False;
  ContentLengthValues := TStringList.Create;
  try
    HostCount := 0;
    for I := 0 to Headers.Count - 1 do
    begin
      Line := Headers[I];
      ColonPos := Pos(':', Line);
      if ColonPos > 0 then
      begin
        if (ColonPos > 1) and (Line[ColonPos - 1] = ' ') then
        begin
          Result := stRequestSmuggling;
          Exit;
        end;

        Name := LowerCase(Trim(Copy(Line, 1, ColonPos - 1)));
        Value := Trim(Copy(Line, ColonPos + 1, Length(Line)));

        if Name = 'host' then
        begin
          Inc(HostCount);
          if HostCount > 1 then
          begin
            Result := stRequestSmuggling;
            Exit;
          end;
        end
        else if Name = 'content-length' then
        begin
          Inc(ContentLengthCount);
          ContentLengthValues.Add(Value);
          HasContentLength := True;
        end
        else if Name = 'transfer-encoding' then
        begin
          Inc(TransferEncodingCount);
          LowerVal := LowerCase(Value);
          if Pos('chunked', LowerVal) > 0 then
            HasChunked := True;

          if (Pos(',', LowerVal) > 0) and (Pos('chunked', LowerVal) > 0) then
          begin
            Result := stRequestSmuggling;
            Exit;
          end;
        end;
      end;
    end;

    if ContentLengthCount > 1 then
    begin
      Result := stRequestSmuggling;
      Exit;
    end;
    if HasContentLength and HasChunked then
    begin
      Result := stRequestSmuggling;
      Exit;
    end;

    if TransferEncodingCount > 1 then
    begin
      Result := stRequestSmuggling;
      Exit;
    end;
  finally
    ContentLengthValues.Free;
  end;
end;

end.
