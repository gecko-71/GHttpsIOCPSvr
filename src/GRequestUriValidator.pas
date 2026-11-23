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
unit GRequestUriValidator;

interface

uses
  System.SysUtils,
  System.Classes,
  System.Math,
  System.Character,
  System.NetEncoding,
  GLogger,
  GRequestTypes,
  GRequestHeaderValidator;

type
  TUriValidator = class
  protected
    class function IsUnreserved(C: Char): Boolean;
    class function IsReserved(C: Char): Boolean;
    class function IsGenDelim(C: Char): Boolean;
    class function IsSubDelim(C: Char): Boolean;
    class function IsValidFragment(const Fragment: string): Boolean;
    class function DecodePercentEncoding(const Input: string): string;
    class function IsValidPercentEncoded(const Input: string; Pos: Integer): Boolean;
  public
    class function IsValidPath(const Path: string): Boolean;
    class function IsValidQuery(const Query: string): Boolean;
    class function ValidateURI(const URI: string; out ErrorMsg: string): Boolean;
    class function ValidateAbsolutePath(const Path: string; out ErrorMsg: string): Boolean;
    class function SanitizeURI(const URI: string): string;
    class function NormalizeURI(const URI: string): string;
    class function IsValidScheme(const Scheme: string): Boolean;
    class function IsValidAuthority(const Authority: string): Boolean;
  end;

implementation

type
  THeaderValidatorAccess = class(THeaderValidator);

class function TUriValidator.IsUnreserved(C: Char): Boolean;
begin
  Result := C.IsLetterOrDigit or (C = '-') or (C = '.') or (C = '_') or (C = '~');
end;

class function TUriValidator.IsReserved(C: Char): Boolean;
begin
  Result := IsGenDelim(C) or IsSubDelim(C);
end;

class function TUriValidator.IsGenDelim(C: Char): Boolean;
begin
  Result := CharInSet(C, [':', '/', '?', '#', '[', ']', '@']);
end;

class function TUriValidator.IsSubDelim(C: Char): Boolean;
begin
  Result := CharInSet(C, ['!', '$', '&', '''', '(', ')', '*', '+', ',', ';', '=']);
end;

class function TUriValidator.IsValidScheme(const Scheme: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  if Length(Scheme) = 0 then
    Exit;
  if not Scheme[1].IsLetter then
    Exit;
  for I := 2 to Length(Scheme) do
  begin
    if not (Scheme[I].IsLetterOrDigit or CharInSet(Scheme[I], ['+', '-', '.'])) then
      Exit;
  end;
  Result := True;
end;

class function TUriValidator.IsValidAuthority(const Authority: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;

  for I := 1 to Length(Authority) do
  begin
    C := Authority[I];
    if not (IsUnreserved(C) or
            IsSubDelim(C) or
            (C = ':') or
            (C = '@') or
            (C = '[') or
            (C = ']')) then
    begin
      if (C = '%') and (I <= Length(Authority) - 2) then
      begin
        if not IsValidPercentEncoded(Authority, I) then
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidPath(const Path: string): Boolean;
var
  I: Integer;
  C: Char;
  DecodedPath: string;
begin
  Result := True;
  if Length(Path) = 0 then
    Exit(True);
  DecodedPath := TNetEncoding.URL.Decode(Path);
  if (Pos('..', DecodedPath) > 0) or THeaderValidatorAccess.HasSuspiciousPatterns(DecodedPath) then
    Exit(False);

  try
    I := 1;
    while I <= Length(Path) do
    begin
      C := Path[I];
      if IsUnreserved(C) or
         IsSubDelim(C) or
         (C = ':') or
         (C = '@') or
         (C = '/') then
      begin
        Inc(I);
        Continue;
      end;
      if (C = '%') and (I <= Length(Path) - 2) then
      begin
        if IsValidPercentEncoded(Path, I) then
        begin
          Inc(I, 3);
          Continue;
        end
        else
        begin
          Result := False;
          Exit;
        end;
      end;
      Result := False;
      Exit;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('DEBUG: Exception in IsValidPath: %s', [E.Message]);
      Result := False;
    end;
  end;
end;

class function TUriValidator.IsValidQuery(const Query: string): Boolean;
var
  I: Integer;
  C: Char;
  DecodedQuery: string;
begin
  Result := True;
  if Length(Query) > 1000 then
    Exit(False);

  DecodedQuery := TNetEncoding.URL.Decode(Query);
  if THeaderValidatorAccess.HasSuspiciousPatterns(DecodedQuery) then
    Exit(False);

  for I := 1 to Length(Query) do
  begin
    C := Query[I];
    if not (IsUnreserved(C) or
            IsSubDelim(C) or
            (C = ':') or
            (C = '@') or
            (C = '/') or
            (C = '?')) then
    begin
      if (C = '%') and (I <= Length(Query) - 2) then
      begin
        if not IsValidPercentEncoded(Query, I) then
        begin
          Result := False;
          Exit;
        end;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidFragment(const Fragment: string): Boolean;
var
  I: Integer;
  C: Char;
begin
  Result := True;
  for I := 1 to Length(Fragment) do
  begin
    C := Fragment[I];
    if not (IsUnreserved(C) or
            IsSubDelim(C) or
            (C = ':') or
            (C = '@') or
            (C = '/') or
            (C = '?')) then
    begin
      if (C = '%') and (I <= Length(Fragment) - 2) then
      begin
        if not IsValidPercentEncoded(Fragment, I) then
        begin
          Result := False;
          Exit;
        end;
      end
      else
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
end;

class function TUriValidator.IsValidPercentEncoded(const Input: string; Pos: Integer): Boolean;
begin
  Result := False;
  if (Pos > Length(Input) - 2) then
    Exit;
  if Input[Pos] <> '%' then
    Exit;
  Result := IsHexDigit(Input[Pos + 1]) and IsHexDigit(Input[Pos + 2]);
end;

class function TUriValidator.DecodePercentEncoding(const Input: string): string;
var
  I: Integer;
  HexStr: string;
  ByteValue: Byte;
begin
  Result := '';
  I := 1;
  while I <= Length(Input) do
  begin
    if (Input[I] = '%') and (I <= Length(Input) - 2) and IsValidPercentEncoded(Input, I) then
    begin
      HexStr := Copy(Input, I + 1, 2);
      try
        ByteValue := StrToInt('$' + HexStr);
        Result := Result + Chr(ByteValue);
        Inc(I, 3);
      except
        Result := Result + Input[I];
        Inc(I);
      end;
    end
    else
    begin
      Result := Result + Input[I];
      Inc(I);
    end;
  end;
end;

class function TUriValidator.ValidateURI(const URI: string; out ErrorMsg: string): Boolean;
var
  SchemeEnd, AuthorityStart, AuthorityEnd, PathEnd, QueryEnd: Integer;
  Scheme, Authority, Path, Query, Fragment: string;
begin
  Result := False;
  ErrorMsg := '';
  try
    if Length(URI) = 0 then
    begin
      ErrorMsg := 'URI cannot be empty';
      Exit;
    end;
    if Length(URI) > 2048 then
    begin
      ErrorMsg := 'URI too long (>2048 characters)';
      Exit;
    end;
    SchemeEnd := Pos(':', URI);
    if SchemeEnd > 0 then
    begin
      Scheme := Copy(URI, 1, SchemeEnd - 1);
      if not IsValidScheme(Scheme) then
      begin
        ErrorMsg := 'Incorrect schema URI: ' + Scheme;
        Exit;
      end;
    end;
    AuthorityEnd := 0;
    if (SchemeEnd > 0) and (SchemeEnd < Length(URI) - 1) and
       (Copy(URI, SchemeEnd + 1, 2) = '//') then
    begin
      AuthorityStart := SchemeEnd + 3;
      AuthorityEnd := AuthorityStart;

      while (AuthorityEnd <= Length(URI)) and
            not CharInSet(URI[AuthorityEnd], ['/', '?', '#']) do
        Inc(AuthorityEnd);
      Dec(AuthorityEnd);
      if AuthorityEnd >= AuthorityStart then
      begin
        Authority := Copy(URI, AuthorityStart, AuthorityEnd - AuthorityStart + 1);
        if not IsValidAuthority(Authority) then
        begin
          ErrorMsg := 'Incorrect authority in URI: ' + Authority;
          Exit;
        end;
      end;
    end;
    PathEnd := Length(URI);
    QueryEnd := Pos('?', URI);
    if QueryEnd > 0 then
      PathEnd := QueryEnd - 1;
    if Pos('#', URI) > 0 then
      PathEnd := Min(PathEnd, Pos('#', URI) - 1);
    if AuthorityEnd > 0 then
      Path := Copy(URI, AuthorityEnd + 1, PathEnd - AuthorityEnd)
    else if SchemeEnd > 0 then
      Path := Copy(URI, SchemeEnd + 1, PathEnd - SchemeEnd)
    else
      Path := Copy(URI, 1, PathEnd);
    if not IsValidPath(Path) then
    begin
      ErrorMsg := 'Invalid path in URI: ' + Path;
      Exit;
    end;
    if QueryEnd > 0 then
    begin
      QueryEnd := Pos('#', URI);
      if QueryEnd = 0 then
        QueryEnd := Length(URI)
      else
        Dec(QueryEnd);

      Query := Copy(URI, Pos('?', URI) + 1, QueryEnd - Pos('?', URI));
      if not IsValidQuery(Query) then
      begin
        ErrorMsg := 'Invalid query string in URI: ' + Query;
        Exit;
      end;
    end;
    if Pos('#', URI) > 0 then
    begin
      Fragment := Copy(URI, Pos('#', URI) + 1, Length(URI));
      if not IsValidFragment(Fragment) then
      begin
        ErrorMsg := 'Invalid fragment in URI: ' + Fragment;
        Exit;
      end;
    end;

    Result := True;

  except
    on E: Exception do
    begin
      ErrorMsg := 'URI validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function TUriValidator.ValidateAbsolutePath(const Path: string; out ErrorMsg: string): Boolean;
begin
  Result := False;
  ErrorMsg := '';
  try
    if Length(Path) = 0 then
    begin
      ErrorMsg := 'The path cannot be empty';
      Exit;
    end;

    if Path[1] <> '/' then
    begin
      ErrorMsg := 'The path must be absolute (start with /)';
      Exit;
    end;

    if not IsValidPath(Path) then
    begin
      ErrorMsg := 'Invalid characters in path';
      Exit;
    end;

    Result := True;

  except
    on E: Exception do
    begin
      ErrorMsg := 'Path validation error: ' + E.Message;
      Result := False;
    end;
  end;
end;

class function TUriValidator.SanitizeURI(const URI: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(URI) do
  begin
    C := URI[I];
    if IsUnreserved(C) or IsReserved(C) or (C = '%') then
      Result := Result + C
    else
      Result := Result + '%' + IntToHex(Ord(C), 2);
  end;
end;

class function TUriValidator.NormalizeURI(const URI: string): string;
var
  Scheme, Authority, Path, Query, Fragment, Host, Port, HostPart, UserInfo: string;
  SchemeEnd, AuthorityStart, PathStart, QueryStart, FragmentStart, AtPos, ColonPos: Integer;
  PathSegments, NormalizedSegments: TStringList;
  I: Integer;
  Segment: string;
begin
  if (Length(URI) > 0) and (URI[1] = '/') and (Pos('?', URI) = 0) and (Pos('#', URI) = 0) and
     (Pos('%', URI) = 0) and (Pos('//', URI) = 0) and (Pos('/.', URI) = 0) and (Pos('\', URI) = 0) then
  begin
    Result := URI;
    Exit;
  end;
  Scheme := ''; Authority := ''; Path := URI; Query := ''; Fragment := '';
  SchemeEnd := Pos(':', URI);
  if (SchemeEnd > 0) and (Pos('//', URI) = SchemeEnd + 1) then
  begin
    Scheme := Copy(URI, 1, SchemeEnd - 1);
    AuthorityStart := SchemeEnd + 3;
    PathStart := Pos('/', URI, AuthorityStart);
    if PathStart = 0 then
    begin
      Authority := Copy(URI, AuthorityStart, Length(URI));
      Path := '/';
    end
    else
    begin
      Authority := Copy(URI, AuthorityStart, PathStart - AuthorityStart);
      Path := Copy(URI, PathStart, Length(URI));
    end;
  end;
  FragmentStart := Pos('#', Path);
  if FragmentStart > 0 then
  begin
    Fragment := Copy(Path, FragmentStart, Length(Path));
    Path := Copy(Path, 1, FragmentStart - 1);
  end;
  QueryStart := Pos('?', Path);
  if QueryStart > 0 then
  begin
    Query := Copy(Path, QueryStart, Length(Path));
    Path := Copy(Path, 1, QueryStart - 1);
  end;
  Scheme := LowerCase(Scheme);
  if Authority <> '' then
  begin
    AtPos := Pos('@', Authority);
    HostPart := Authority;
    UserInfo := '';
    if AtPos > 0 then
    begin
      UserInfo := Copy(Authority, 1, AtPos);
      HostPart := Copy(Authority, AtPos + 1, Length(Authority));
    end;
    ColonPos := Pos(':', HostPart);
    if ColonPos > 0 then
    begin
      Host := Copy(HostPart, 1, ColonPos - 1);
      Port := Copy(HostPart, ColonPos + 1, Length(HostPart));
    end
    else
    begin
      Host := HostPart;
      Port := '';
    end;
    Host := LowerCase(Host);
    if ((Scheme = 'http') and (Port = '80')) or ((Scheme = 'https') and (Port = '443')) then
      Port := '';
    Authority := Host;
    if Port <> '' then
      Authority := Authority + ':' + Port;
    if AtPos > 0 then
      Authority := UserInfo + Authority;
  end;

  if Path <> '' then
  begin
    PathSegments := TStringList.Create;
    NormalizedSegments := TStringList.Create;
    try
      PathSegments.Delimiter := '/';
      PathSegments.DelimitedText := Path;
      for I := 0 to PathSegments.Count - 1 do
      begin
        Segment := PathSegments[I];
        if Segment = '..' then
        begin
          if (NormalizedSegments.Count > 0) and (NormalizedSegments.Count > NormalizedSegments.IndexOf('')) then
            NormalizedSegments.Delete(NormalizedSegments.Count - 1);
        end
        else if (Segment <> '.') then
          NormalizedSegments.Add(Segment);
      end;
      Path := string.Join('/', NormalizedSegments.ToStringArray);
    finally
      PathSegments.Free;
      NormalizedSegments.Free;
    end;
  end;
  if Path = '' then
    Path := '/';
  Result := '';
  if Scheme <> '' then
    Result := Scheme + '://' + Authority;
  Result := Result + Path + Query + Fragment;
end;

end.
