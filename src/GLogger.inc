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
{$IFDEF FPC}
  {$MODE DELPHI}
  {$H+}
  {$MODESWITCH UNICODESTRINGS}
{$ENDIF}

{$IFNDEF GLOGGER_OVERRIDE}
  {$DEFINE GLOGGER_BACKEND_FAST}
{$ENDIF}

{$IFDEF GLOGGER_BACKEND_LOGGERPRO}
  {$MESSAGE ERROR 'GLOGGER_BACKEND_LOGGERPRO is not implemented. Use GLOGGER_BACKEND_FAST, GLOGGER_BACKEND_QUICKLOGGER, or GLOGGER_BACKEND_CUSTOM.'}
{$ENDIF}

{$IFDEF GLOGGER_DISABLED}
  {$UNDEF GLOGGER_BACKEND_QUICKLOGGER}
  {$UNDEF GLOGGER_BACKEND_FAST}
  {$UNDEF GLOGGER_BACKEND_CUSTOM}
{$ELSE}
  {$IFDEF GLOGGER_BACKEND_QUICKLOGGER}
    {$IF DEFINED(FPC) OR NOT DEFINED(DCC)}
      {$UNDEF GLOGGER_BACKEND_QUICKLOGGER}
      {$DEFINE GLOGGER_BACKEND_FAST}
      {$UNDEF GLOGGER_BACKEND_CUSTOM}
    {$ELSE}
      {$UNDEF GLOGGER_BACKEND_FAST}
      {$UNDEF GLOGGER_BACKEND_CUSTOM}
    {$IFEND}
  {$ELSE}
    {$IFDEF GLOGGER_BACKEND_CUSTOM}
      {$UNDEF GLOGGER_BACKEND_FAST}
    {$ELSE}
      {$IFNDEF GLOGGER_BACKEND_FAST}
        {$DEFINE GLOGGER_DISABLED}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
