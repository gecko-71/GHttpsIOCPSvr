unit GLogger;

{$I GLogger.inc}

interface

uses
{$IFDEF FPC}
  SysUtils;
{$ELSE}
  System.SysUtils;
{$ENDIF}

type
  TGLogLevel = (llTrace, llDebug, llInfo, llWarn, llError, llCritical, llOff);
  TGLogTimeFormat = (ltfLocal, ltfUtc);
  TGLogDropPolicy = (dpTailDrop, dpHeadDrop);

  TGLogConfig = record
    Enabled: Boolean;
    MinLevel: TGLogLevel;
    EnableConsole: Boolean;
    ConsoleMinLevel: TGLogLevel;
    ConsoleColors: Boolean;
    EnableFile: Boolean;
    FileMinLevel: TGLogLevel;
    FileName: string;
    DailyRotate: Boolean;
    MaxFileSizeMB: Integer;
    MaxFileSizeBytes: Int64;
    MaxRotatedFiles: Integer;
    AutoFlush: Boolean;
    FlushIntervalMs: Integer;
    BufferSizeKB: Integer;
    WaitForFlushSeconds: Integer;
    TimeFormat: TGLogTimeFormat;
    DropPolicy: TGLogDropPolicy;
    class function Default: TGLogConfig; static;
  end;

  IGLogSink = interface
    ['{8F2C6B41-3E7D-4C9A-A152-9D4E7B61F302}']
    procedure WriteLog(ALevel: TGLogLevel; const AMsg: string);
    procedure Flush;
  end;

  TGLogger = record
  public
    class procedure Configure(const AConfig: TGLogConfig); static;
    class procedure InitDefault(const ALogFileName: string; AEnabled: Boolean = True;
      AEnableConsole: Boolean = True; ADailyRotate: Boolean = True;
      AMaxFileSizeMB: Integer = 50; AAutoFlush: Boolean = False;
      AWaitForFlushSeconds: Integer = 10); static;
    class procedure Shutdown; static;
    class procedure Flush; static;
    class procedure SetEnabled(AEnabled: Boolean); static;
    class procedure SetMinLevel(ALevel: TGLogLevel); static;
    class procedure SetCustomSink(const ASink: IGLogSink); static;

    class function BackendName: string; static;
    class function IsCompiledEnabled: Boolean; static; inline;
    class function IsEnabled: Boolean; static;
    class function IsLevelEnabled(ALevel: TGLogLevel): Boolean; static;
    class function DroppedCount: Int64; static;
    class function ErrorCount: Int64; static;
    class procedure ResetCounters; static;

    class procedure Log(ALevel: TGLogLevel; const AMsg: string); overload; static;
    class procedure Log(ALevel: TGLogLevel; const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Trace(const AMsg: string); overload; static;
    class procedure Trace(const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Debug(const AMsg: string); overload; static;
    class procedure Debug(const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Info(const AMsg: string); overload; static;
    class procedure Info(const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Warn(const AMsg: string); overload; static;
    class procedure Warn(const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Error(const AMsg: string); overload; static;
    class procedure Error(const AFmt: string; const AArgs: array of const); overload; static;
    class procedure Critical(const AMsg: string); overload; static;
    class procedure Critical(const AFmt: string; const AArgs: array of const); overload; static;
  end;

  GLog = TGLogger;
{$IFNDEF GLOGGER_NO_LOGGER_ALIAS}
  Logger = TGLogger;
{$ENDIF}

implementation

{$IFNDEF GLOGGER_DISABLED}
uses
{$IFDEF FPC}
  Classes,
  SyncObjs,
  DateUtils
  {$IFDEF UNIX}, BaseUnix{$ENDIF}
{$ELSE}
  System.Classes,
  System.SyncObjs,
  System.DateUtils
  {$IFDEF POSIX}, Posix.Unistd, Posix.Fcntl, Posix.Pthread{$ENDIF}
{$ENDIF}
{$IFDEF MSWINDOWS}
  {$IFDEF FPC}, Windows{$ELSE}, Winapi.Windows{$ENDIF}
{$ENDIF}
{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  , Quick.Logger
  , Quick.Logger.Provider.Files
  , Quick.Logger.Provider.Console
{$IFEND}
  ;
{$ENDIF}

var
  GConfig: TGLogConfig;
  GEnabled: Boolean = False;
  GMinLevel: TGLogLevel = {$IFDEF GLOGGER_DISABLED}llOff{$ELSE}llTrace{$ENDIF};
  GClosed: Boolean = False;
  GFinalizing: Boolean = False;
  GDroppedTotal: Int64 = 0;
  GDroppedPendingReport: Int64 = 0;
  GErrorTotal: Int64 = 0;
  GTimeFormat: TGLogTimeFormat = ltfLocal;
  GDropPolicy: TGLogDropPolicy = dpTailDrop;
{$IFDEF MSWINDOWS}
  GOrigConsoleOutputCP: Cardinal = 0;
{$ENDIF}

{$IFNDEF GLOGGER_DISABLED}
function AtomicInc64(var ATarget: Int64): Int64;
begin
{$IFDEF FPC}
  Result := InterlockedIncrement64(ATarget);
{$ELSE}
  Result := TInterlocked.Increment(ATarget);
{$ENDIF}
end;

function AtomicXchg64(var ATarget: Int64; AValue: Int64): Int64;
begin
{$IFDEF FPC}
  Result := InterlockedExchange64(ATarget, AValue);
{$ELSE}
  Result := TInterlocked.Exchange(ATarget, AValue);
{$ENDIF}
end;

function AtomicAdd64(var ATarget: Int64; AValue: Int64): Int64;
begin
{$IFDEF FPC}
  Result := InterlockedExchangeAdd64(ATarget, AValue) + AValue;
{$ELSE}
  Result := TInterlocked.Add(ATarget, AValue);
{$ENDIF}
end;

function AtomicRead64(var ATarget: Int64): Int64;
begin
{$IF DEFINED(CPUX64)}
  Result := PInt64(@ATarget)^;
{$ELSE}
  {$IFDEF FPC}
  Result := InterlockedCompareExchange64(ATarget, 0, 0);
  {$ELSE}
  Result := TInterlocked.Read(ATarget);
  {$ENDIF}
{$IFEND}
end;

function GetMonoTick64: UInt64; inline;
begin
{$IFDEF FPC}
  Result := SysUtils.GetTickCount64;
{$ELSE}
  Result := TThread.GetTickCount64;
{$ENDIF}
end;

function SafeFormatMessage(const AFmt: string; const AArgs: array of const): string;
begin
  try
    Result := Format(AFmt, AArgs);
  except
    on E: Exception do
    begin
      AtomicInc64(GErrorTotal);
      Result := AFmt + ' [FORMAT_ERROR: ' + E.Message + ']';
    end;
  end;
end;
{$ENDIF}

{$IFDEF GLOGGER_BACKEND_FAST}
const
  CShardCount = 32;
  CMaxShardBytes = 16 * 1024 * 1024;
  CMaxRetainedShardBytes = 1024 * 1024;
  CTimeLen = 23;
  CLevelTagLen = 9;
  CLevelTags: array[TGLogLevel] of array[0..CLevelTagLen - 1] of AnsiChar = (
    ' [TRACE] ', ' [DEBUG] ', ' [INFO ] ', ' [WARN ] ', ' [ERROR] ', ' [CRIT ] ', ' [OFF  ] '
  );
{$IFDEF MSWINDOWS}
  FILE_APPEND_DATA_FLAG = $0004;
  FILE_READ_ATTRIBUTES_FLAG = $0080;
  ENABLE_VIRTUAL_TERMINAL_PROCESSING_FLAG = $0004;
{$ENDIF}

type
  TGLogTimeBuf = array[0..CTimeLen - 1] of AnsiChar;

  TGLogShardCore = record
    Lock: {$IFDEF FPC}TCriticalSection{$ELSE}TSpinLock{$ENDIF};
    Buf: TBytes;
    Len: Integer;
    WakeSent: Boolean;
  end;

  TGLogShard = record
    Core: TGLogShardCore;
    Pad: array[0..(128 - (SizeOf(TGLogShardCore) and 127)) - 1] of Byte;
  end;

  TLogFlushThread = class(TThread)
  protected
    procedure Execute; override;
  end;

threadvar
  GInLoggerThread: Boolean;

var
  GShards: array[0..CShardCount - 1] of TGLogShard;
  GShardsReady: Boolean = False;
  GTimeLock: {$IFDEF FPC}TCriticalSection{$ELSE}TSpinLock{$ENDIF};
  GTimeSeq: Int64 = 0;
  GLastWallSec: UInt64 = 0;
  GCurrentDay: Integer = 0;
  GCachedTimeUtf8: array[0..18] of AnsiChar;
  GWriteLock: TCriticalSection = nil;
  GFlushEvent: TEvent = nil;
  GFlushDoneEvent: TEvent = nil;
  GFlushBuf: TBytes;
  GFilteredBuf: TBytes;
  GRetryFileBuf: TBytes;
  GRetryFileLen: Integer = 0;
{$IFDEF MSWINDOWS}
  GFileHandle: THandle = INVALID_HANDLE_VALUE;
{$ELSE}
  GFileStream: TFileStream = nil;
{$ENDIF}
  GFileSize: Int64 = 0;
  GLastFileDay: Integer = 0;
  GRotateCooldownUntilTick: UInt64 = 0;
  GFlushThread: TLogFlushThread = nil;
  GFlushThreadBodyActive: Integer = 0;
  GRotateSeq: Integer = 0;
  GFlushIntervalMs: Integer = 50;
  GEnableFile: Boolean = False;
  GEnableConsole: Boolean = False;
  GConsoleColors: Boolean = True;
  GAutoFlush: Boolean = False;
  GFileMinLevel: TGLogLevel = llTrace;
  GConsoleMinLevel: TGLogLevel = llDebug;
  GDefaultShardCap: Integer = 262144;
  GHighWatermark: Integer = 131072;
  GNextFileCheckTick: UInt64 = 0;
  GNextShardRoundRobin: Integer = 0;

threadvar
  GThreadShardIdx: Integer;

procedure MarkFlushThreadBodyDone;
begin
{$IFDEF FPC}
  InterlockedExchange(GFlushThreadBodyActive, 0);
{$ELSE}
  TInterlocked.Exchange(GFlushThreadBodyActive, 0);
{$ENDIF}
  if GFlushDoneEvent <> nil then
    GFlushDoneEvent.SetEvent;
end;

function IsFlushThreadBodyActive: Boolean;
begin
{$IFDEF FPC}
  Result := InterlockedCompareExchange(GFlushThreadBodyActive, 0, 0) <> 0;
{$ELSE}
  Result := TInterlocked.CompareExchange(GFlushThreadBodyActive, 0, 0) <> 0;
{$ENDIF}
end;

function GetShardIndex: Integer;
var
  ShardIdx: Integer;
begin
  ShardIdx := GThreadShardIdx;
  if ShardIdx > 0 then
  begin
    Result := ShardIdx - 1;
    Exit;
  end;
{$IFDEF FPC}
  ShardIdx := InterlockedIncrement(GNextShardRoundRobin) and (CShardCount - 1);
{$ELSE}
  ShardIdx := TInterlocked.Increment(GNextShardRoundRobin) and (CShardCount - 1);
{$ENDIF}
  GThreadShardIdx := ShardIdx + 1;
  Result := ShardIdx;
end;

procedure WriteTwoDigits(AValue: Word; ADest: PAnsiChar); inline;
begin
  ADest[0] := AnsiChar(Ord('0') + (AValue div 10) mod 10);
  ADest[1] := AnsiChar(Ord('0') + (AValue mod 10));
end;

procedure FormatSysTimeAscii(AYear, AMonth, ADay, AHour, AMin, ASec: Word; ADest: PAnsiChar);
begin
  WriteTwoDigits(AYear div 100, ADest);
  WriteTwoDigits(AYear mod 100, ADest + 2);
  ADest[4] := '-';
  WriteTwoDigits(AMonth, ADest + 5);
  ADest[7] := '-';
  WriteTwoDigits(ADay, ADest + 8);
  ADest[10] := ' ';
  WriteTwoDigits(AHour, ADest + 11);
  ADest[13] := ':';
  WriteTwoDigits(AMin, ADest + 14);
  ADest[16] := ':';
  WriteTwoDigits(ASec, ADest + 17);
end;

procedure RefreshTimeCache(AWallSec: UInt64; ADayVal: Integer;
  AYear, AMonth, ADay, AHour, AMin, ASec: Word);
begin
  GTimeLock.Enter;
  try
    if AWallSec <> GLastWallSec then
    begin
      AtomicInc64(GTimeSeq);
      FormatSysTimeAscii(AYear, AMonth, ADay, AHour, AMin, ASec, @GCachedTimeUtf8[0]);
      GCurrentDay := ADayVal;
      GLastWallSec := AWallSec;
      AtomicInc64(GTimeSeq);
    end;
  finally
{$IFDEF FPC}
    GTimeLock.Leave;
{$ELSE}
    GTimeLock.Exit;
{$ENDIF}
  end;
end;

procedure InvalidateTimeCache;
begin
{$IFDEF FPC}
  if GTimeLock = nil then
    Exit;
  GTimeLock.Enter;
{$ELSE}
  GTimeLock.Enter;
{$ENDIF}
  try
    AtomicInc64(GTimeSeq);
    GLastWallSec := 0;
    GCachedTimeUtf8[0] := #0;
    AtomicInc64(GTimeSeq);
  finally
{$IFDEF FPC}
    GTimeLock.Leave;
{$ELSE}
    GTimeLock.Exit;
{$ENDIF}
  end;
end;

procedure GetCurrentTimeAndDay(out ATimeBuf: TGLogTimeBuf; out ADay: Integer);
var
{$IFDEF MSWINDOWS}
  FT, LocalFT: TFileTime;
  FT64: UInt64;
  SysTime: TSystemTime;
{$ELSE}
  NowDt: TDateTime;
  Y, M, D, H, N, S: Word;
{$ENDIF}
  MSec: Word;
  WallSec, CachedSec: UInt64;
  DayVal: Integer;
  Seq1, Seq2: Int64;
begin
  repeat
{$IFDEF MSWINDOWS}
    GetSystemTimeAsFileTime(FT);
    FT64 := UInt64(FT.dwLowDateTime) or (UInt64(FT.dwHighDateTime) shl 32);
    WallSec := FT64 div 10000000;
    MSec := Word((FT64 div 10000) mod 1000);
    if (WallSec <> GLastWallSec) or (GCachedTimeUtf8[0] = #0) then
    begin
      if GTimeFormat = ltfUtc then
        FileTimeToSystemTime(FT, SysTime)
      else
      begin
        FileTimeToLocalFileTime(FT, LocalFT);
        FileTimeToSystemTime(LocalFT, SysTime);
      end;
      DayVal := Integer(SysTime.wYear) * 10000 + Integer(SysTime.wMonth) * 100 + Integer(SysTime.wDay);
      RefreshTimeCache(WallSec, DayVal, SysTime.wYear, SysTime.wMonth, SysTime.wDay,
        SysTime.wHour, SysTime.wMinute, SysTime.wSecond);
    end;
{$ELSE}
    NowDt := Now;
    WallSec := UInt64(Trunc(NowDt * 86400.0));
    MSec := Word(Trunc(Frac(NowDt * 86400.0) * 1000.0) mod 1000);
    if (WallSec <> GLastWallSec) or (GCachedTimeUtf8[0] = #0) then
    begin
      if GTimeFormat = ltfUtc then
{$IFDEF FPC}
        NowDt := LocalTimeToUniversal(NowDt);
{$ELSE}
        NowDt := TTimeZone.Local.ToUniversalTime(NowDt);
{$ENDIF}
      DecodeDate(NowDt, Y, M, D);
      DecodeTime(NowDt, H, N, S, MSec);
      DayVal := Integer(Y) * 10000 + Integer(M) * 100 + Integer(D);
      RefreshTimeCache(WallSec, DayVal, Y, M, D, H, N, S);
    end;
{$ENDIF}

    Seq1 := AtomicRead64(GTimeSeq);
    if (Seq1 and 1) <> 0 then
      Continue;
    Move(GCachedTimeUtf8[0], ATimeBuf[0], 19);
    ADay := GCurrentDay;
    CachedSec := GLastWallSec;
    Seq2 := AtomicRead64(GTimeSeq);
    if (Seq1 = Seq2) and ((Seq1 and 1) = 0) then
    begin
      if CachedSec = WallSec then
        Break;
      if CachedSec > WallSec then
        Continue;
      Break;
    end;
  until False;

  ATimeBuf[19] := '.';
  ATimeBuf[20] := AnsiChar(Ord('0') + (MSec div 100));
  ATimeBuf[21] := AnsiChar(Ord('0') + ((MSec div 10) mod 10));
  ATimeBuf[22] := AnsiChar(Ord('0') + (MSec mod 10));
end;

function ShardReserve(var AShard: TGLogShard; ALen: Integer; out AOffset: Integer): Boolean; inline;
var
  ReqLen, NewCap, DropBytesNeeded, ChunkDrop, CutPos, I, LinesDropped, MaxBytes: Integer;
begin
  MaxBytes := GDefaultShardCap;
  if MaxBytes <= 0 then
    MaxBytes := CMaxShardBytes;

  if (ALen <= 0) or (ALen > MaxBytes) then
  begin
    if ALen > 0 then
    begin
      AtomicInc64(GDroppedTotal);
      AtomicInc64(GDroppedPendingReport);
    end;
    AOffset := 0;
    Result := False;
    Exit;
  end;

  if ALen > MaxBytes - AShard.Core.Len then
  begin
    if GDropPolicy = dpTailDrop then
    begin
      AtomicInc64(GDroppedTotal);
      AtomicInc64(GDroppedPendingReport);
      AOffset := 0;
      Result := False;
      Exit;
    end;

    DropBytesNeeded := ALen - (MaxBytes - AShard.Core.Len);
    ChunkDrop := AShard.Core.Len div 4;
    if ChunkDrop < DropBytesNeeded then
      ChunkDrop := DropBytesNeeded;
    if ChunkDrop > AShard.Core.Len then
      ChunkDrop := AShard.Core.Len;

    CutPos := ChunkDrop - 1;
    if CutPos < 0 then
      CutPos := 0;
    while (CutPos < AShard.Core.Len) and (AShard.Core.Buf[CutPos] <> 10) do
      Inc(CutPos);

    if CutPos < AShard.Core.Len then
      Inc(CutPos)
    else
      CutPos := AShard.Core.Len;

    LinesDropped := 0;
    for I := 0 to CutPos - 1 do
    begin
      if AShard.Core.Buf[I] = 10 then
        Inc(LinesDropped);
    end;
    if LinesDropped = 0 then
      LinesDropped := 1;

    if CutPos < AShard.Core.Len then
    begin
      Move(AShard.Core.Buf[CutPos], AShard.Core.Buf[0], AShard.Core.Len - CutPos);
      Dec(AShard.Core.Len, CutPos);
    end
    else
      AShard.Core.Len := 0;

    AtomicAdd64(GDroppedTotal, LinesDropped);
    AtomicAdd64(GDroppedPendingReport, LinesDropped);
  end;

  ReqLen := AShard.Core.Len + ALen;
  if ReqLen > Length(AShard.Core.Buf) then
  begin
    NewCap := Length(AShard.Core.Buf) * 2;
    if NewCap < GDefaultShardCap then
      NewCap := GDefaultShardCap;
    if NewCap < ReqLen then
      NewCap := ReqLen + 65536;
    if NewCap > MaxBytes then
      NewCap := MaxBytes;
    SetLength(AShard.Core.Buf, NewCap);
  end;
  AOffset := AShard.Core.Len;
  AShard.Core.Len := ReqLen;
  Result := True;
end;

function StackAppendUtf8Ptr(ADest: PAnsiChar; ADestCap: Integer; var APos: Integer;
  ASrc: PWideChar; ACount: Integer): Boolean;
var
  I: Integer;
  W1, W2: Word;
  CP: Cardinal;
begin
  if ACount <= 0 then
  begin
    Result := ACount = 0;
    Exit;
  end;

  I := 0;
  while I < ACount do
  begin
    W1 := Word(ASrc[I]);
    if W1 < $80 then
    begin
      if APos >= ADestCap then
      begin
        Result := False;
        Exit;
      end;
      if (W1 = 0) or (W1 = 10) or (W1 = 13) then
        ADest[APos] := ' '
      else
        ADest[APos] := AnsiChar(W1);
      Inc(APos);
    end
    else if W1 < $800 then
    begin
      if 2 > ADestCap - APos then
      begin
        Result := False;
        Exit;
      end;
      ADest[APos] := AnsiChar($C0 or (W1 shr 6));
      ADest[APos + 1] := AnsiChar($80 or (W1 and $3F));
      Inc(APos, 2);
    end
    else if (W1 >= $D800) and (W1 <= $DBFF) then
    begin
      if I + 1 < ACount then
      begin
        W2 := Word(ASrc[I + 1]);
        if (W2 >= $DC00) and (W2 <= $DFFF) then
        begin
          if 4 > ADestCap - APos then
          begin
            Result := False;
            Exit;
          end;
          CP := $10000 + ((Cardinal(W1 - $D800) shl 10) or Cardinal(W2 - $DC00));
          ADest[APos] := AnsiChar($F0 or (CP shr 18));
          ADest[APos + 1] := AnsiChar($80 or ((CP shr 12) and $3F));
          ADest[APos + 2] := AnsiChar($80 or ((CP shr 6) and $3F));
          ADest[APos + 3] := AnsiChar($80 or (CP and $3F));
          Inc(APos, 4);
          Inc(I, 2);
          Continue;
        end;
      end;
      if 3 > ADestCap - APos then
      begin
        Result := False;
        Exit;
      end;
      ADest[APos] := #$EF;
      ADest[APos + 1] := #$BF;
      ADest[APos + 2] := #$BD;
      Inc(APos, 3);
    end
    else if (W1 >= $DC00) and (W1 <= $DFFF) then
    begin
      if 3 > ADestCap - APos then
      begin
        Result := False;
        Exit;
      end;
      ADest[APos] := #$EF;
      ADest[APos + 1] := #$BF;
      ADest[APos + 2] := #$BD;
      Inc(APos, 3);
    end
    else
    begin
      if 3 > ADestCap - APos then
      begin
        Result := False;
        Exit;
      end;
      ADest[APos] := AnsiChar($E0 or (W1 shr 12));
      ADest[APos + 1] := AnsiChar($80 or ((W1 shr 6) and $3F));
      ADest[APos + 2] := AnsiChar($80 or (W1 and $3F));
      Inc(APos, 3);
    end;
    Inc(I);
  end;

  Result := True;
end;

function EncodeSanitizedUtf8(const AMsg: string): UTF8String;
var
  SLen, MaxLen, OutPos: Integer;
begin
  SLen := Length(AMsg);
  if SLen = 0 then
  begin
    Result := '';
    Exit;
  end;
  MaxLen := SLen * 3;
  SetLength(Result, MaxLen);
  OutPos := 0;
  StackAppendUtf8Ptr(PAnsiChar(Pointer(Result)), MaxLen, OutPos, PWideChar(Pointer(AMsg)), SLen);
  SetLength(Result, OutPos);
end;

function StackAppendUInt64(ADest: PAnsiChar; ADestCap: Integer; var APos: Integer; AUVal: UInt64): Boolean;
var
  Digits: array[0..23] of AnsiChar;
  P: Integer;
  UVal: UInt64;
begin
  if AUVal = 0 then
  begin
    if APos >= ADestCap then
    begin
      Result := False;
      Exit;
    end;
    ADest[APos] := '0';
    Inc(APos);
    Result := True;
    Exit;
  end;

  UVal := AUVal;
  P := 24;
  while UVal > 0 do
  begin
    Dec(P);
    Digits[P] := AnsiChar(Ord('0') + (UVal mod 10));
    UVal := UVal div 10;
  end;

  if 24 - P > ADestCap - APos then
  begin
    Result := False;
    Exit;
  end;
  Move(Digits[P], ADest[APos], 24 - P);
  Inc(APos, 24 - P);
  Result := True;
end;

function StackAppendInt64(ADest: PAnsiChar; ADestCap: Integer; var APos: Integer; AValue: Int64): Boolean;
var
  Digits: array[0..23] of AnsiChar;
  P: Integer;
  Neg: Boolean;
  UVal: UInt64;
begin
  if AValue = 0 then
  begin
    if APos >= ADestCap then
    begin
      Result := False;
      Exit;
    end;
    ADest[APos] := '0';
    Inc(APos);
    Result := True;
    Exit;
  end;

  Neg := AValue < 0;
  if Neg then
    UVal := UInt64(not AValue) + 1
  else
    UVal := UInt64(AValue);

  P := 24;
  while UVal > 0 do
  begin
    Dec(P);
    Digits[P] := AnsiChar(Ord('0') + (UVal mod 10));
    UVal := UVal div 10;
  end;

  if Neg then
  begin
    Dec(P);
    Digits[P] := '-';
  end;

  if 24 - P > ADestCap - APos then
  begin
    Result := False;
    Exit;
  end;
  Move(Digits[P], ADest[APos], 24 - P);
  Inc(APos, 24 - P);
  Result := True;
end;

function TryFastFormatToStack(ADest: PAnsiChar; ADestCap: Integer; var APos: Integer;
  const AFmt: string; const AArgs: array of const): Boolean;
var
  I, J, Len, ArgIdx, StartPos, SArgLen: Integer;
  Spec: WideChar;
  FmtPtr, ArgPtr: PWideChar;
  AnsiPtr: PAnsiChar;
  UV: UInt64;
  B: Byte;
begin
  Result := False;
  Len := Length(AFmt);
  if Len = 0 then
  begin
    Result := True;
    Exit;
  end;
  FmtPtr := PWideChar(Pointer(AFmt));

  ArgIdx := 0;
  I := 0;
  StartPos := 0;

  while I < Len do
  begin
    if FmtPtr[I] = '%' then
    begin
      if I > StartPos then
      begin
        if not StackAppendUtf8Ptr(ADest, ADestCap, APos, FmtPtr + StartPos, I - StartPos) then
          Exit;
      end;

      if I + 1 >= Len then
        Exit;

      Spec := FmtPtr[I + 1];
      if Spec = '%' then
      begin
        if APos >= ADestCap then
          Exit;
        ADest[APos] := '%';
        Inc(APos);
        Inc(I, 2);
        StartPos := I;
        Continue;
      end;

      if ArgIdx > High(AArgs) then
        Exit;

      case Spec of
        's', 'S':
          case AArgs[ArgIdx].VType of
            vtUnicodeString:
              begin
                ArgPtr := PWideChar(AArgs[ArgIdx].VUnicodeString);
                if ArgPtr <> nil then
                begin
                  SArgLen := Length(UnicodeString(AArgs[ArgIdx].VUnicodeString));
                  if not StackAppendUtf8Ptr(ADest, ADestCap, APos, ArgPtr, SArgLen) then
                    Exit;
                end;
              end;
            vtAnsiString:
              begin
                AnsiPtr := PAnsiChar(AArgs[ArgIdx].VAnsiString);
                if AnsiPtr <> nil then
                begin
                  SArgLen := Length(AnsiString(AArgs[ArgIdx].VAnsiString));
                  if (SArgLen < 0) or (SArgLen > ADestCap - APos) then
                    Exit;
                  for J := 0 to SArgLen - 1 do
                  begin
                    B := Byte(AnsiPtr[J]);
                    if B >= 128 then
                      Exit;
                    if (B = 0) or (B = 10) or (B = 13) then
                      ADest[APos + J] := ' '
                    else
                      ADest[APos + J] := AnsiChar(B);
                  end;
                  Inc(APos, SArgLen);
                end;
              end;
          else
            Exit;
          end;
        'd', 'D':
          case AArgs[ArgIdx].VType of
            vtInteger:
              if not StackAppendInt64(ADest, ADestCap, APos, AArgs[ArgIdx].VInteger) then
                Exit;
            vtInt64:
              if not StackAppendInt64(ADest, ADestCap, APos, AArgs[ArgIdx].VInt64^) then
                Exit;
          else
            Exit;
          end;
        'u', 'U':
          case AArgs[ArgIdx].VType of
            vtInteger:
              begin
                if AArgs[ArgIdx].VInteger >= 0 then
                  UV := UInt64(AArgs[ArgIdx].VInteger)
                else
                  UV := UInt64(High(Cardinal)) - UInt64(not AArgs[ArgIdx].VInteger);
                if not StackAppendUInt64(ADest, ADestCap, APos, UV) then
                  Exit;
              end;
            vtInt64:
              if not StackAppendUInt64(ADest, ADestCap, APos, PUInt64(AArgs[ArgIdx].VInt64)^) then
                Exit;
          else
            Exit;
          end;
      else
        Exit;
      end;

      Inc(ArgIdx);
      Inc(I, 2);
      StartPos := I;
    end
    else
      Inc(I);
  end;

  if StartPos < Len then
  begin
    if not StackAppendUtf8Ptr(ADest, ADestCap, APos, FmtPtr + StartPos, Len - StartPos) then
      Exit;
  end;

  Result := True;
end;

function FormatDayStr(ADay: Integer): string;
var
  Y, M, D: Integer;
begin
  Y := ADay div 10000;
  M := (ADay div 100) mod 100;
  D := ADay mod 100;
  Result := Format('%.4d-%.2d-%.2d', [Y, M, D]);
end;

procedure CloseLogFile;
begin
{$IFDEF MSWINDOWS}
  if GFileHandle <> INVALID_HANDLE_VALUE then
  begin
    CloseHandle(GFileHandle);
    GFileHandle := INVALID_HANDLE_VALUE;
  end;
{$ELSE}
  FreeAndNil(GFileStream);
{$ENDIF}
end;

function IsLogFileOpen: Boolean; inline;
begin
{$IFDEF MSWINDOWS}
  Result := GFileHandle <> INVALID_HANDLE_VALUE;
{$ELSE}
  Result := GFileStream <> nil;
{$ENDIF}
end;

function GetFileModificationDay(AHandle: THandle; const AFileName: string): Integer;
var
{$IFDEF MSWINDOWS}
  FtWrite, FtLocal: TFileTime;
  St: TSystemTime;
{$ELSE}
  FileDt: TDateTime;
  Y, M, D: Word;
{$ENDIF}
begin
  Result := 0;
{$IFDEF MSWINDOWS}
  if (AHandle <> INVALID_HANDLE_VALUE) and (AHandle <> 0) then
  begin
    FillChar(FtWrite, SizeOf(FtWrite), 0);
    if GetFileTime(AHandle, nil, nil, @FtWrite) then
    begin
      FillChar(St, SizeOf(St), 0);
      if GTimeFormat = ltfUtc then
      begin
        if FileTimeToSystemTime(FtWrite, St) then
          Result := Integer(St.wYear) * 10000 + Integer(St.wMonth) * 100 + Integer(St.wDay);
      end
      else
      begin
        FillChar(FtLocal, SizeOf(FtLocal), 0);
        if FileTimeToLocalFileTime(FtWrite, FtLocal) then
        begin
          if FileTimeToSystemTime(FtLocal, St) then
            Result := Integer(St.wYear) * 10000 + Integer(St.wMonth) * 100 + Integer(St.wDay);
        end;
      end;
    end;
  end;
{$ELSE}
  if FileAge(AFileName, FileDt) then
  begin
    if GTimeFormat = ltfUtc then
{$IFDEF FPC}
      FileDt := LocalTimeToUniversal(FileDt);
{$ELSE}
      FileDt := TTimeZone.Local.ToUniversalTime(FileDt);
{$ENDIF}
    DecodeDate(FileDt, Y, M, D);
    Result := Integer(Y) * 10000 + Integer(M) * 100 + Integer(D);
  end;
{$ENDIF}
end;

procedure OpenLogFile(ACurDay: Integer);
var
  LogDir: string;
{$IFDEF MSWINDOWS}
  FileSz: Int64;
{$ENDIF}
begin
  if IsLogFileOpen or (not GEnableFile) or (GConfig.FileName = '') then
    Exit;

  LogDir := ExtractFileDir(GConfig.FileName);
  if (LogDir <> '') and (not DirectoryExists(LogDir)) then
    ForceDirectories(LogDir);

{$IFDEF MSWINDOWS}
  GFileHandle := CreateFileW(
    PWideChar(GConfig.FileName),
    FILE_APPEND_DATA_FLAG or FILE_READ_ATTRIBUTES_FLAG or SYNCHRONIZE,
    FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
    nil,
    OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    0);
  if GFileHandle = INVALID_HANDLE_VALUE then
    RaiseLastOSError;
  FileSz := 0;
{$IFDEF FPC}
  if GetFileSizeEx(GFileHandle, PLARGE_INTEGER(@FileSz)) then
{$ELSE}
  if GetFileSizeEx(GFileHandle, FileSz) then
{$ENDIF}
    GFileSize := FileSz
  else
    GFileSize := 0;
{$ELSE}
  if FileExists(GConfig.FileName) then
  begin
    GFileStream := TFileStream.Create(GConfig.FileName, fmOpenWrite or fmShareDenyNone);
    GFileSize := GFileStream.Seek(0, soEnd);
  end
  else
  begin
    GFileStream := TFileStream.Create(GConfig.FileName, fmCreate or fmShareDenyNone);
    GFileSize := 0;
  end;
{$IFDEF POSIX}
  {$IFDEF FPC}
  fpfcntl(GFileStream.Handle, F_SETFL, fpfcntl(GFileStream.Handle, F_GETFL, 0) or O_APPEND);
  {$ELSE}
  fcntl(GFileStream.Handle, F_SETFL, fcntl(GFileStream.Handle, F_GETFL, 0) or O_APPEND);
  {$ENDIF}
{$ENDIF}
{$ENDIF}
  if (GLastFileDay = 0) and (GFileSize > 0) then
  begin
{$IFDEF MSWINDOWS}
    GLastFileDay := GetFileModificationDay(GFileHandle, GConfig.FileName);
{$ELSE}
    GLastFileDay := GetFileModificationDay(0, GConfig.FileName);
{$ENDIF}
  end;
  if GLastFileDay = 0 then
    GLastFileDay := ACurDay;
end;

function WriteRawToLogFile(AData: PByte; ALen: Integer; out ABytesWritten: Integer): Boolean;
var
{$IFDEF MSWINDOWS}
  Written, TotalWritten: DWORD;
{$ELSE}
  TotalWritten, StepWritten: Integer;
{$ENDIF}
begin
  ABytesWritten := 0;
  Result := False;
  if (AData = nil) or (ALen <= 0) or (not IsLogFileOpen) then
  begin
    Result := ALen <= 0;
    Exit;
  end;

{$IFDEF MSWINDOWS}
  TotalWritten := 0;
  while Integer(TotalWritten) < ALen do
  begin
    Written := 0;
    if not WriteFile(GFileHandle, (AData + TotalWritten)^, DWORD(ALen) - TotalWritten, Written, nil) then
      Break;
    if Written = 0 then
      Break;
    Inc(TotalWritten, Written);
  end;
  ABytesWritten := Integer(TotalWritten);
  if TotalWritten > 0 then
    Inc(GFileSize, TotalWritten);
  if Integer(TotalWritten) < ALen then
    Exit;
  if GAutoFlush then
    FlushFileBuffers(GFileHandle);
  Result := True;
{$ELSE}
  TotalWritten := 0;
  try
    while TotalWritten < ALen do
    begin
      StepWritten := GFileStream.Write((AData + TotalWritten)^, ALen - TotalWritten);
      if StepWritten <= 0 then
        Break;
      Inc(TotalWritten, StepWritten);
    end;
  except
    ABytesWritten := TotalWritten;
    if TotalWritten > 0 then
      Inc(GFileSize, TotalWritten);
    Exit;
  end;
  ABytesWritten := TotalWritten;
  if TotalWritten > 0 then
    Inc(GFileSize, TotalWritten);
  if TotalWritten < ALen then
    Exit;
  {$IFDEF FPC}
    {$IFDEF UNIX}
  if GAutoFlush then
    fpfsync(GFileStream.Handle);
    {$ENDIF}
  {$ELSE}
    {$IFDEF POSIX}
  if GAutoFlush then
    fsync(GFileStream.Handle);
    {$ENDIF}
  {$ENDIF}
  Result := True;
{$ENDIF}
end;

function IsRotatedArchiveFileName(const AFileNameOnly, ABaseFileOnly, AExtName: string): Boolean;
var
  ExtOnly, NameNoExt, Prefix: string;
  PrefixLen, I: Integer;
begin
  Result := False;
  ExtOnly := ExtractFileExt(AFileNameOnly);
  if not SameFileName(ExtOnly, AExtName) then
    Exit;

  NameNoExt := ChangeFileExt(AFileNameOnly, '');
  Prefix := ABaseFileOnly + '_';
  PrefixLen := Length(Prefix);
  if Length(NameNoExt) < PrefixLen + 14 then
    Exit;
  if not SameFileName(Copy(NameNoExt, 1, PrefixLen), Prefix) then
    Exit;

  for I := PrefixLen + 1 to PrefixLen + 4 do
  begin
    if (NameNoExt[I] < '0') or (NameNoExt[I] > '9') then
      Exit;
  end;
  if NameNoExt[PrefixLen + 5] <> '-' then
    Exit;
  for I := PrefixLen + 6 to PrefixLen + 7 do
  begin
    if (NameNoExt[I] < '0') or (NameNoExt[I] > '9') then
      Exit;
  end;
  if NameNoExt[PrefixLen + 8] <> '-' then
    Exit;
  for I := PrefixLen + 9 to PrefixLen + 10 do
  begin
    if (NameNoExt[I] < '0') or (NameNoExt[I] > '9') then
      Exit;
  end;
  if NameNoExt[PrefixLen + 11] <> '_' then
    Exit;
  for I := PrefixLen + 12 to Length(NameNoExt) do
  begin
    if (NameNoExt[I] < '0') or (NameNoExt[I] > '9') then
      Exit;
  end;

  Result := True;
end;

function CompareArchiveFileNames(List: TStringList; Index1, Index2: Integer): Integer;
var
  Name1, Name2, Base1, Base2, Date1, Date2, SeqStr1, SeqStr2: string;
  LastUnderscore1, LastUnderscore2, Seq1, Seq2: Integer;
begin
  Name1 := ChangeFileExt(ExtractFileName(List[Index1]), '');
  Name2 := ChangeFileExt(ExtractFileName(List[Index2]), '');
  LastUnderscore1 := LastDelimiter('_', Name1);
  LastUnderscore2 := LastDelimiter('_', Name2);
  if (LastUnderscore1 > 11) and (LastUnderscore2 > 11) and
     (Name1[LastUnderscore1 - 11] = '_') and (Name2[LastUnderscore2 - 11] = '_') then
  begin
    Base1 := Copy(Name1, 1, LastUnderscore1 - 12);
    Base2 := Copy(Name2, 1, LastUnderscore2 - 12);
    if not SameFileName(Base1, Base2) then
    begin
      Result := CompareStr(Base1, Base2);
      Exit;
    end;
    Date1 := Copy(Name1, LastUnderscore1 - 10, 10);
    Date2 := Copy(Name2, LastUnderscore2 - 10, 10);
    if Date1 <> Date2 then
    begin
      Result := CompareStr(Date1, Date2);
      Exit;
    end;
    SeqStr1 := Copy(Name1, LastUnderscore1 + 1, MaxInt);
    SeqStr2 := Copy(Name2, LastUnderscore2 + 1, MaxInt);
    Seq1 := StrToIntDef(SeqStr1, 0);
    Seq2 := StrToIntDef(SeqStr2, 0);
    if Seq1 <> Seq2 then
    begin
      Result := Seq1 - Seq2;
      Exit;
    end;
  end;
  Result := CompareStr(List[Index1], List[Index2]);
end;

procedure EnforceFileRetention(const ABaseName, AExtName: string; AMaxFiles: Integer);
var
  DirPath, Pattern, FullCand, BaseFileOnly: string;
  SR: TSearchRec;
  Files: TStringList;
  I, DeleteCount: Integer;
begin
  if AMaxFiles <= 0 then
    Exit;

  DirPath := ExtractFilePath(ABaseName);
  if DirPath <> '' then
    DirPath := IncludeTrailingPathDelimiter(DirPath);
  BaseFileOnly := ExtractFileName(ABaseName);
  Pattern := ABaseName + '_*' + AExtName;

  Files := TStringList.Create;
  try
    Files.Sorted := False;
    if FindFirst(Pattern, faAnyFile, SR) = 0 then
    begin
      try
        repeat
          if (SR.Attr and faDirectory) = 0 then
          begin
            FullCand := DirPath + SR.Name;
            if (not SameFileName(FullCand, GConfig.FileName)) and
               IsRotatedArchiveFileName(SR.Name, BaseFileOnly, AExtName) then
              Files.Add(FullCand);
          end;
        until FindNext(SR) <> 0;
      finally
{$IFDEF FPC}
        SysUtils.FindClose(SR);
{$ELSE}
        System.SysUtils.FindClose(SR);
{$ENDIF}
      end;
    end;

    if Files.Count > AMaxFiles then
    begin
      Files.CustomSort(CompareArchiveFileNames);
      DeleteCount := Files.Count - AMaxFiles;
      for I := 0 to DeleteCount - 1 do
{$IFDEF FPC}
        SysUtils.DeleteFile(Files[I]);
{$ELSE}
        System.SysUtils.DeleteFile(Files[I]);
{$ENDIF}
    end;
  finally
    Files.Free;
  end;
end;

function FindMaxRotateSeqForDay(const ABaseName, AExtName, ADayStr: string): Integer;
var
  BaseFileOnly, Prefix, Pattern, NameNoExt, SeqPart: string;
  SR: TSearchRec;
  PrefixLen, SeqVal: Integer;
begin
  Result := 0;
  BaseFileOnly := ExtractFileName(ABaseName);
  Prefix := BaseFileOnly + '_' + ADayStr + '_';
  PrefixLen := Length(Prefix);
  Pattern := ABaseName + '_' + ADayStr + '_*' + AExtName;
  if FindFirst(Pattern, faAnyFile, SR) = 0 then
  begin
    try
      repeat
        if (SR.Attr and faDirectory) = 0 then
        begin
          if IsRotatedArchiveFileName(SR.Name, BaseFileOnly, AExtName) then
          begin
            NameNoExt := ChangeFileExt(SR.Name, '');
            if Length(NameNoExt) > PrefixLen then
            begin
              SeqPart := Copy(NameNoExt, PrefixLen + 1, MaxInt);
              SeqVal := StrToIntDef(SeqPart, 0);
              if SeqVal > Result then
                Result := SeqVal;
            end;
          end;
        end;
      until FindNext(SR) <> 0;
    finally
{$IFDEF FPC}
      SysUtils.FindClose(SR);
{$ELSE}
      System.SysUtils.FindClose(SR);
{$ENDIF}
    end;
  end;
end;

function PerformFileRotation(ARotDay, ANewDay: Integer): Boolean;
var
  BaseName, ExtName, RotName, DayStr: string;
  NowTick: UInt64;
begin
  Result := False;
  NowTick := GetMonoTick64;
  if NowTick < GRotateCooldownUntilTick then
    Exit;

  CloseLogFile;
  BaseName := ChangeFileExt(GConfig.FileName, '');
  ExtName := ExtractFileExt(GConfig.FileName);
  DayStr := FormatDayStr(ARotDay);
  if GRotateSeq = 0 then
    GRotateSeq := FindMaxRotateSeqForDay(BaseName, ExtName, DayStr);
  repeat
    Inc(GRotateSeq);
    RotName := BaseName + '_' + DayStr + '_' + Format('%.3d', [GRotateSeq]) + ExtName;
  until not FileExists(RotName);

  if RenameFile(GConfig.FileName, RotName) then
  begin
    GFileSize := 0;
    GLastFileDay := ANewDay;
    if ARotDay <> ANewDay then
      GRotateSeq := 0;
    EnforceFileRetention(BaseName, ExtName, GConfig.MaxRotatedFiles);
    OpenLogFile(ANewDay);
    Result := True;
  end
  else
  begin
    AtomicInc64(GErrorTotal);
    Dec(GRotateSeq);
    GRotateCooldownUntilTick := NowTick + 1000;
    OpenLogFile(ANewDay);
  end;
end;

function FindLineFitLength(AData: PByte; ARemLen: Integer; AAvailBytes: Int64): Integer;
var
  I, MaxCheck, LastNL: Integer;
begin
  Result := 0;
  if (AData = nil) or (ARemLen <= 0) or (AAvailBytes <= 0) then
    Exit;

  if Int64(ARemLen) <= AAvailBytes then
  begin
    Result := ARemLen;
    Exit;
  end;

  MaxCheck := Integer(AAvailBytes);
  LastNL := 0;
  for I := 0 to MaxCheck - 1 do
  begin
    if AData[I] = 10 then
      LastNL := I + 1;
  end;
  Result := LastNL;
end;

function FindFirstLineLength(AData: PByte; ARemLen: Integer): Integer;
var
  I: Integer;
begin
  for I := 0 to ARemLen - 1 do
  begin
    if AData[I] = 10 then
    begin
      Result := I + 1;
      Exit;
    end;
  end;
  Result := ARemLen;
end;

procedure QueueRetryBytes(AData: PByte; ALen: Integer);
var
  NewCap, SpaceLeft, CopyLen, DroppedBytes: Integer;
begin
  if (AData = nil) or (ALen <= 0) then
    Exit;

  SpaceLeft := CMaxShardBytes - GRetryFileLen;
  if SpaceLeft <= 0 then
  begin
    AtomicInc64(GDroppedTotal);
    AtomicInc64(GDroppedPendingReport);
    Exit;
  end;

  if ALen <= SpaceLeft then
    CopyLen := ALen
  else
  begin
    CopyLen := FindLineFitLength(AData, ALen, SpaceLeft);
    DroppedBytes := ALen - CopyLen;
    if DroppedBytes > 0 then
    begin
      AtomicInc64(GDroppedTotal);
      AtomicInc64(GDroppedPendingReport);
    end;
  end;

  if CopyLen <= 0 then
    Exit;

  if GRetryFileLen + CopyLen > Length(GRetryFileBuf) then
  begin
    NewCap := Length(GRetryFileBuf) * 2;
    if NewCap < 65536 then
      NewCap := 65536;
    if NewCap < GRetryFileLen + CopyLen then
      NewCap := GRetryFileLen + CopyLen + 65536;
    if NewCap > CMaxShardBytes then
      NewCap := CMaxShardBytes;
    SetLength(GRetryFileBuf, NewCap);
  end;
  Move(AData^, GRetryFileBuf[GRetryFileLen], CopyLen);
  Inc(GRetryFileLen, CopyLen);
end;

function AppendBytesToLogFile(AData: Pointer; ALen: Integer; ADay: Integer;
  out ABytesCommitted: Integer): Boolean;
var
  Ptr: PByte;
  Offset, Rem, ChunkLen, ChunkWritten: Integer;
  MaxBytes, Avail: Int64;
  NowTick: UInt64;
begin
  ABytesCommitted := 0;
  if (not GEnableFile) or (GConfig.FileName = '') or (AData = nil) or (ALen <= 0) then
  begin
    Result := True;
    Exit;
  end;

  Result := False;
  Ptr := PByte(AData);
  Offset := 0;

  try
    if IsLogFileOpen and (GFileSize > 0) then
    begin
      NowTick := GetMonoTick64;
      if NowTick >= GNextFileCheckTick then
      begin
        GNextFileCheckTick := NowTick + 1000;
        if not FileExists(GConfig.FileName) then
        begin
          CloseLogFile;
          OpenLogFile(ADay);
        end;
      end;
    end
    else
      OpenLogFile(ADay);

    if not IsLogFileOpen then
      Exit;

    if GConfig.MaxFileSizeBytes > 0 then
      MaxBytes := GConfig.MaxFileSizeBytes
    else
      MaxBytes := Int64(GConfig.MaxFileSizeMB) * 1024 * 1024;

    if GConfig.DailyRotate and (GLastFileDay > 0) and (ADay <> GLastFileDay) and (GFileSize > 0) then
      PerformFileRotation(GLastFileDay, ADay);

    while Offset < ALen do
    begin
      Rem := ALen - Offset;
      if MaxBytes > 0 then
      begin
        Avail := MaxBytes - GFileSize;
        if Avail <= 0 then
        begin
          if GFileSize > 0 then
          begin
            if PerformFileRotation(ADay, ADay) then
              Continue;
            ChunkLen := Rem;
          end
          else
            ChunkLen := FindFirstLineLength(Ptr + Offset, Rem);
        end
        else
        begin
          ChunkLen := FindLineFitLength(Ptr + Offset, Rem, Avail);
          if ChunkLen = 0 then
          begin
            if GFileSize > 0 then
            begin
              NowTick := GetMonoTick64;
              if (NowTick >= GRotateCooldownUntilTick) and PerformFileRotation(ADay, ADay) then
                Continue;
            end;
            ChunkLen := FindFirstLineLength(Ptr + Offset, Rem);
          end;
        end;
      end
      else
        ChunkLen := Rem;

      if not WriteRawToLogFile(Ptr + Offset, ChunkLen, ChunkWritten) then
      begin
        if ChunkWritten > 0 then
        begin
          Inc(Offset, ChunkWritten);
          ABytesCommitted := Offset;
        end;
        AtomicInc64(GErrorTotal);
        CloseLogFile;
        Exit;
      end;
      Inc(Offset, ChunkWritten);
      ABytesCommitted := Offset;
    end;

    Result := True;
  except
    AtomicInc64(GErrorTotal);
    CloseLogFile;
    ABytesCommitted := Offset;
  end;
end;

procedure FilterBufferByMinLevel(ASrc: PAnsiChar; ASrcLen: Integer; AMinLevel: TGLogLevel;
  var ADest: TBytes; out ADestLen: Integer);
var
  Pos, LineStart, LineEnd, LineLen: Integer;
  RowLevel: TGLogLevel;
  KeepCurrent: Boolean;
begin
  ADestLen := 0;
  if (ASrc = nil) or (ASrcLen <= 0) then
    Exit;
  if Length(ADest) < ASrcLen then
    SetLength(ADest, ASrcLen);

  KeepCurrent := False;
  Pos := 0;
  while Pos < ASrcLen do
  begin
    LineStart := Pos;
    while (Pos < ASrcLen) and (ASrc[Pos] <> #10) do
      Inc(Pos);
    if Pos < ASrcLen then
      Inc(Pos);
    LineEnd := Pos;
    LineLen := LineEnd - LineStart;

    if (LineLen >= CTimeLen + CLevelTagLen) and
       (ASrc[LineStart + 4] = '-') and (ASrc[LineStart + 7] = '-') and
       (ASrc[LineStart + 10] = ' ') and (ASrc[LineStart + 19] = '.') and
       (ASrc[LineStart + CTimeLen] = ' ') and (ASrc[LineStart + CTimeLen + 1] = '[') and
       (ASrc[LineStart + CTimeLen + 7] = ']') then
    begin
      case ASrc[LineStart + CTimeLen + 2] of
        'T': RowLevel := llTrace;
        'D': RowLevel := llDebug;
        'I': RowLevel := llInfo;
        'W': RowLevel := llWarn;
        'E': RowLevel := llError;
        'C': RowLevel := llCritical;
      else
        RowLevel := llInfo;
      end;
      KeepCurrent := RowLevel >= AMinLevel;
    end;

    if KeepCurrent then
    begin
      Move(ASrc[LineStart], ADest[ADestLen], LineLen);
      Inc(ADestLen, LineLen);
    end;
  end;
end;

function GetAnsiColorForChar(ALevelChar: AnsiChar): AnsiString;
begin
  case ALevelChar of
    'T': Result := #27'[95m';
    'D': Result := #27'[96m';
    'I': Result := #27'[97m';
    'W': Result := #27'[93m';
    'E': Result := #27'[91m';
    'C': Result := #27'[97;41m';
  else
    Result := '';
  end;
end;

procedure WriteConsoleFiltered(AData: PAnsiChar; ALen: Integer);
var
  ConStr, ColorSeq, ResetSeq: RawByteString;
  Pos, LineStart, LineEnd, LineLen, OutPos: Integer;
begin
  if (not GEnableConsole) or (not IsConsole) or (AData = nil) or (ALen <= 0) then
    Exit;
  try
    if not GConsoleColors then
    begin
      SetLength(ConStr, ALen);
      Move(AData^, ConStr[1], ALen);
      Write(ConStr);
      Exit;
    end;

    ResetSeq := #27'[0m';
    SetLength(ConStr, ALen + 1024);
    OutPos := 0;
    Pos := 0;
    while Pos < ALen do
    begin
      LineStart := Pos;
      while (Pos < ALen) and (AData[Pos] <> #10) do
        Inc(Pos);
      if Pos < ALen then
        Inc(Pos);
      LineEnd := Pos;
      LineLen := LineEnd - LineStart;

      ColorSeq := '';
      if (LineLen >= CTimeLen + CLevelTagLen) and (AData[LineStart + CTimeLen + 1] = '[') then
        ColorSeq := GetAnsiColorForChar(AData[LineStart + CTimeLen + 2]);

      if OutPos + Length(ColorSeq) + LineLen + Length(ResetSeq) > Length(ConStr) then
        SetLength(ConStr, Length(ConStr) * 2 + LineLen + 256);

      if Length(ColorSeq) > 0 then
      begin
        Move(ColorSeq[1], ConStr[OutPos + 1], Length(ColorSeq));
        Inc(OutPos, Length(ColorSeq));
      end;
      Move(AData[LineStart], ConStr[OutPos + 1], LineLen);
      Inc(OutPos, LineLen);
      if Length(ColorSeq) > 0 then
      begin
        Move(ResetSeq[1], ConStr[OutPos + 1], Length(ResetSeq));
        Inc(OutPos, Length(ResetSeq));
      end;
    end;
    SetLength(ConStr, OutPos);
    Write(ConStr);
  except
    AtomicInc64(GErrorTotal);
  end;
end;

procedure DeliverFileBytes(AData: PByte; ALen, ADay: Integer);
var
  Committed: Integer;
begin
  if (AData = nil) or (ALen <= 0) then
    Exit;
  if GRetryFileLen > 0 then
  begin
    QueueRetryBytes(AData, ALen);
    Exit;
  end;
  if not AppendBytesToLogFile(AData, ALen, ADay, Committed) then
    QueueRetryBytes(AData + Committed, ALen - Committed);
end;

procedure FlushRetryFileBuffer(ADay: Integer);
var
  Committed, Remaining: Integer;
begin
  if (not GEnableFile) or (GFileMinLevel >= llOff) or (GRetryFileLen <= 0) then
    Exit;
  if AppendBytesToLogFile(@GRetryFileBuf[0], GRetryFileLen, ADay, Committed) then
  begin
    GRetryFileLen := 0;
    if Length(GRetryFileBuf) > CMaxRetainedShardBytes then
      SetLength(GRetryFileBuf, 0);
  end
  else if Committed > 0 then
  begin
    Remaining := GRetryFileLen - Committed;
    Move(GRetryFileBuf[Committed], GRetryFileBuf[0], Remaining);
    GRetryFileLen := Remaining;
  end;
end;

procedure DrainQueue;
var
  I, FlushLen, FilteredLen, CurDay: Integer;
  SwapBuf: TBytes;
  TimeBuf: TGLogTimeBuf;
  DroppedNow: Int64;
  WarnStr: RawByteString;
begin
  if GWriteLock = nil then
    Exit;

  GWriteLock.Enter;
  try
    if not GShardsReady then
      Exit;
    GetCurrentTimeAndDay(TimeBuf, CurDay);

    FlushRetryFileBuffer(CurDay);

    for I := 0 to CShardCount - 1 do
    begin
      GShards[I].Core.Lock.Enter;
      try
        FlushLen := GShards[I].Core.Len;
        if FlushLen > 0 then
        begin
          SwapBuf := GShards[I].Core.Buf;
          GShards[I].Core.Buf := GFlushBuf;
          GFlushBuf := SwapBuf;
          GShards[I].Core.Len := 0;
        end;
        GShards[I].Core.WakeSent := False;
      finally
{$IFDEF FPC}
        GShards[I].Core.Lock.Leave;
{$ELSE}
        GShards[I].Core.Lock.Exit;
{$ENDIF}
      end;

      if FlushLen = 0 then
        Continue;

      if GEnableFile and (GFileMinLevel < llOff) then
      begin
        if GFileMinLevel <= GMinLevel then
          DeliverFileBytes(@GFlushBuf[0], FlushLen, CurDay)
        else
        begin
          FilterBufferByMinLevel(@GFlushBuf[0], FlushLen, GFileMinLevel, GFilteredBuf, FilteredLen);
          if FilteredLen > 0 then
            DeliverFileBytes(@GFilteredBuf[0], FilteredLen, CurDay);
        end;
      end;

      if GEnableConsole and IsConsole and (GConsoleMinLevel < llOff) then
      begin
        if GConsoleMinLevel <= GMinLevel then
          WriteConsoleFiltered(@GFlushBuf[0], FlushLen)
        else
        begin
          FilterBufferByMinLevel(@GFlushBuf[0], FlushLen, GConsoleMinLevel, GFilteredBuf, FilteredLen);
          if FilteredLen > 0 then
            WriteConsoleFiltered(@GFilteredBuf[0], FilteredLen);
        end;
      end;

      if Length(GFlushBuf) > CMaxRetainedShardBytes then
        SetLength(GFlushBuf, GDefaultShardCap);
    end;

    if Length(GFilteredBuf) > CMaxRetainedShardBytes then
      SetLength(GFilteredBuf, 0);

    DroppedNow := AtomicXchg64(GDroppedPendingReport, 0);
    if DroppedNow > 0 then
    begin
      SetLength(WarnStr, CTimeLen);
      Move(TimeBuf[0], WarnStr[1], CTimeLen);
      WarnStr := WarnStr + RawByteString(' [WARN ] [GLogger] Dropped ' + IntToStr(DroppedNow) + ' log entries due to buffer limit' + #13#10);
      if GEnableFile and (GFileMinLevel <= llWarn) then
        DeliverFileBytes(@WarnStr[1], Length(WarnStr), CurDay);
      if GEnableConsole and IsConsole and (GConsoleMinLevel <= llWarn) then
        WriteConsoleFiltered(@WarnStr[1], Length(WarnStr));
    end;
  finally
    GWriteLock.Leave;
  end;
end;

procedure LogInternal(ALevel: TGLogLevel; const AMsg: string; ATryStack: Boolean);
var
  CurDay, Idx, LineLen, Utf8Len, TotalLen, WriteOff: Integer;
  LineBuf: array[0..515] of AnsiChar;
  TimeBuf: TGLogTimeBuf;
  Utf8: UTF8String;
  UseStack, NeedWake, DroppedHere: Boolean;
begin
  if GInLoggerThread then
    Exit;

  Idx := GetShardIndex;
  GetCurrentTimeAndDay(TimeBuf, CurDay);

  if ATryStack then
  begin
    LineLen := CTimeLen;
    Move(TimeBuf[0], LineBuf[0], CTimeLen);
    Move(CLevelTags[ALevel][0], LineBuf[LineLen], CLevelTagLen);
    Inc(LineLen, CLevelTagLen);
    if Length(AMsg) > 0 then
      UseStack := StackAppendUtf8Ptr(@LineBuf[0], SizeOf(LineBuf) - 2, LineLen, PWideChar(Pointer(AMsg)), Length(AMsg))
    else
      UseStack := True;
  end
  else
  begin
    LineLen := 0;
    UseStack := False;
  end;

  NeedWake := False;
  DroppedHere := False;

  GInLoggerThread := True;
  try
    try
      if UseStack then
      begin
        LineBuf[LineLen] := #13;
        LineBuf[LineLen + 1] := #10;
        Inc(LineLen, 2);

        GShards[Idx].Core.Lock.Enter;
        try
          if (not GShardsReady) or GClosed then
            Exit;
          if ShardReserve(GShards[Idx], LineLen, WriteOff) then
          begin
            Move(LineBuf[0], GShards[Idx].Core.Buf[WriteOff], LineLen);
            if (not GShards[Idx].Core.WakeSent) and (GShards[Idx].Core.Len >= GHighWatermark) then
            begin
              GShards[Idx].Core.WakeSent := True;
              NeedWake := True;
            end;
          end
          else
            DroppedHere := True;
        finally
{$IFDEF FPC}
          GShards[Idx].Core.Lock.Leave;
{$ELSE}
          GShards[Idx].Core.Lock.Exit;
{$ENDIF}
        end;
      end
      else
      begin
        Utf8 := EncodeSanitizedUtf8(AMsg);
        Utf8Len := Length(Utf8);
        TotalLen := CTimeLen + CLevelTagLen + Utf8Len + 2;

        GShards[Idx].Core.Lock.Enter;
        try
          if (not GShardsReady) or GClosed then
            Exit;
          if ShardReserve(GShards[Idx], TotalLen, WriteOff) then
          begin
            Move(TimeBuf[0], GShards[Idx].Core.Buf[WriteOff], CTimeLen);
            Inc(WriteOff, CTimeLen);
            Move(CLevelTags[ALevel][0], GShards[Idx].Core.Buf[WriteOff], CLevelTagLen);
            Inc(WriteOff, CLevelTagLen);
            if Utf8Len > 0 then
            begin
              Move(Pointer(Utf8)^, GShards[Idx].Core.Buf[WriteOff], Utf8Len);
              Inc(WriteOff, Utf8Len);
            end;
            GShards[Idx].Core.Buf[WriteOff] := 13;
            GShards[Idx].Core.Buf[WriteOff + 1] := 10;
            if (not GShards[Idx].Core.WakeSent) and (GShards[Idx].Core.Len >= GHighWatermark) then
            begin
              GShards[Idx].Core.WakeSent := True;
              NeedWake := True;
            end;
          end
          else
            DroppedHere := True;
        finally
{$IFDEF FPC}
          GShards[Idx].Core.Lock.Leave;
{$ELSE}
          GShards[Idx].Core.Lock.Exit;
{$ENDIF}
        end;
      end;

      if (ALevel >= llCritical) or DroppedHere then
        NeedWake := True;
      if NeedWake and (not GFinalizing) and (GFlushEvent <> nil) then
        GFlushEvent.SetEvent;
    except
      AtomicInc64(GErrorTotal);
    end;
  finally
    GInLoggerThread := False;
  end;
end;

procedure TLogFlushThread.Execute;
var
  IntervalMs: Integer;
begin
  try
    while not Terminated do
    begin
      IntervalMs := GFlushIntervalMs;
      if IntervalMs < 10 then
        IntervalMs := 10;
      if GFlushEvent <> nil then
        GFlushEvent.WaitFor(Cardinal(IntervalMs))
      else
        Sleep(IntervalMs);
      if Terminated then
        Break;
      try
        DrainQueue;
      except
        AtomicInc64(GErrorTotal);
      end;
    end;
  finally
    MarkFlushThreadBodyDone;
  end;
end;

procedure EnsureFlushThreadRunning;
var
  NewThread: TLogFlushThread;
begin
  if GFinalizing or GClosed or (not GEnabled) or (GFlushThread <> nil) then
    Exit;

  NewThread := nil;
  try
    NewThread := TLogFlushThread.Create(True);
    NewThread.FreeOnTerminate := False;
    if GFlushDoneEvent <> nil then
      GFlushDoneEvent.ResetEvent;
{$IFDEF FPC}
    InterlockedExchange(GFlushThreadBodyActive, 1);
{$ELSE}
    TInterlocked.Exchange(GFlushThreadBodyActive, 1);
{$ENDIF}
    NewThread.Start;
    GFlushThread := NewThread;
  except
    AtomicInc64(GErrorTotal);
    MarkFlushThreadBodyDone;
    if NewThread <> nil then
      FreeAndNil(NewThread);
    GFlushThread := nil;
  end;
end;
{$ENDIF}

{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
var
  GQuickFileAdded: Boolean = False;
  GQuickConsoleAdded: Boolean = False;

function MapQuickLevel(ALevel: TGLogLevel): TLogLevel;
begin
  case ALevel of
    llTrace:
      Result := LOG_ALL;
    llDebug:
      Result := LOG_DEBUG;
    llInfo:
      Result := [etHeader, etInfo, etSuccess, etWarning, etError, etCritical, etException];
    llWarn:
      Result := [etWarning, etError, etCritical, etException];
    llError:
      Result := [etError, etCritical, etException];
    llCritical:
      Result := [etCritical, etException];
  else
    Result := [];
  end;
end;
{$IFEND}

{$IFDEF GLOGGER_BACKEND_CUSTOM}
var
  GSinkLock: TCriticalSection = nil;
  GSink: IGLogSink = nil;
{$ENDIF}

class function TGLogConfig.Default: TGLogConfig;
begin
  Result.Enabled := True;
  Result.MinLevel := llTrace;
  Result.EnableConsole := True;
  Result.ConsoleMinLevel := llDebug;
  Result.ConsoleColors := True;
  Result.EnableFile := True;
  Result.FileMinLevel := llTrace;
  Result.FileName := '';
  Result.DailyRotate := True;
  Result.MaxFileSizeMB := 50;
  Result.MaxFileSizeBytes := 0;
  Result.MaxRotatedFiles := 0;
  Result.AutoFlush := False;
  Result.FlushIntervalMs := 50;
  Result.BufferSizeKB := 128;
  Result.WaitForFlushSeconds := 10;
  Result.TimeFormat := ltfLocal;
  Result.DropPolicy := dpTailDrop;
end;

class procedure TGLogger.Configure(const AConfig: TGLogConfig);
{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
var
  LogDir: string;
{$IFEND}
{$IFDEF GLOGGER_BACKEND_FAST}
var
  NewCap, I: Integer;
  RequestedBytes: Int64;
  NewMin: TGLogLevel;
  SameFile: Boolean;
  OldThread: TLogFlushThread;
{$IFDEF MSWINDOWS}
  ConHandle: THandle;
  ConMode: DWORD;
{$ENDIF}
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if GFinalizing then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GWriteLock <> nil then
  begin
    GWriteLock.Enter;
    try
      if GFinalizing then
        Exit;
      if GClosed then
      begin
        if GFlushThread <> nil then
        begin
          OldThread := GFlushThread;
          GFlushThread := nil;
          GWriteLock.Leave;
          try
            OldThread.Terminate;
            if GFlushEvent <> nil then
              GFlushEvent.SetEvent;
            OldThread.WaitFor;
            OldThread.Free;
            MarkFlushThreadBodyDone;
          finally
            GWriteLock.Enter;
          end;
          if GFinalizing then
            Exit;
        end;
        GClosed := False;
      end;

      SameFile := SameFileName(GConfig.FileName, AConfig.FileName);
      DrainQueue;
      CloseLogFile;
      if not SameFile then
      begin
        GRetryFileLen := 0;
        GRotateSeq := 0;
        GLastFileDay := 0;
      end;
      GRotateCooldownUntilTick := 0;
      GFileSize := 0;

      GConfig := AConfig;
      GFlushIntervalMs := AConfig.FlushIntervalMs;
      if GFlushIntervalMs < 10 then
        GFlushIntervalMs := 10;
      GEnableFile := AConfig.EnableFile and (AConfig.FileName <> '');
      GEnableConsole := AConfig.EnableConsole;
      GConsoleColors := AConfig.ConsoleColors;
      GAutoFlush := AConfig.AutoFlush;
      GTimeFormat := AConfig.TimeFormat;
      GDropPolicy := AConfig.DropPolicy;
      GNextFileCheckTick := 0;
      InvalidateTimeCache;

      if AConfig.FileMinLevel > AConfig.MinLevel then
        GFileMinLevel := AConfig.FileMinLevel
      else
        GFileMinLevel := AConfig.MinLevel;

      if AConfig.ConsoleMinLevel > AConfig.MinLevel then
        GConsoleMinLevel := AConfig.ConsoleMinLevel
      else
        GConsoleMinLevel := AConfig.MinLevel;

      NewMin := AConfig.MinLevel;
      if GEnableFile and GEnableConsole then
      begin
        if GFileMinLevel < GConsoleMinLevel then
          NewMin := GFileMinLevel
        else
          NewMin := GConsoleMinLevel;
      end
      else if GEnableFile then
        NewMin := GFileMinLevel
      else if GEnableConsole then
        NewMin := GConsoleMinLevel;

      GMinLevel := NewMin;
      GEnabled := AConfig.Enabled;

      if AConfig.BufferSizeKB > 0 then
      begin
        RequestedBytes := Int64(AConfig.BufferSizeKB) * 1024;
        if RequestedBytes < 16384 then
          NewCap := 16384
        else if RequestedBytes > CMaxShardBytes then
          NewCap := CMaxShardBytes
        else
          NewCap := Integer(RequestedBytes);
      end
      else
        NewCap := 262144;
      GDefaultShardCap := NewCap;
      GHighWatermark := NewCap div 2;

      if GShardsReady then
      begin
        for I := 0 to CShardCount - 1 do
        begin
          GShards[I].Core.Lock.Enter;
          try
            if Length(GShards[I].Core.Buf) < GDefaultShardCap then
              SetLength(GShards[I].Core.Buf, GDefaultShardCap);
          finally
{$IFDEF FPC}
            GShards[I].Core.Lock.Leave;
{$ELSE}
            GShards[I].Core.Lock.Exit;
{$ENDIF}
          end;
        end;
      end;

{$IFDEF MSWINDOWS}
      if GEnableConsole and IsConsole then
      begin
        if GOrigConsoleOutputCP = 0 then
          GOrigConsoleOutputCP := GetConsoleOutputCP;
        SetConsoleOutputCP(CP_UTF8);
        if GConsoleColors then
        begin
          ConHandle := GetStdHandle(STD_OUTPUT_HANDLE);
          if (ConHandle <> INVALID_HANDLE_VALUE) and (ConHandle <> 0) then
          begin
            ConMode := 0;
            if GetConsoleMode(ConHandle, ConMode) then
            begin
              if not SetConsoleMode(ConHandle, ConMode or ENABLE_VIRTUAL_TERMINAL_PROCESSING_FLAG) then
                GConsoleColors := False;
            end
            else
              GConsoleColors := False;
          end
          else
            GConsoleColors := False;
        end;
      end;
{$ENDIF}

      EnsureFlushThreadRunning;
    finally
      GWriteLock.Leave;
    end;
  end;
{$ELSE}
  if GClosed then
    GClosed := False;
  GConfig := AConfig;
  GTimeFormat := AConfig.TimeFormat;
  GDropPolicy := AConfig.DropPolicy;
  GEnabled := AConfig.Enabled;
  GMinLevel := AConfig.MinLevel;
  if AConfig.EnableFile and (AConfig.FileMinLevel < GMinLevel) then
    GMinLevel := AConfig.FileMinLevel;
  if AConfig.EnableConsole and (AConfig.ConsoleMinLevel < GMinLevel) then
    GMinLevel := AConfig.ConsoleMinLevel;
{$ENDIF}

{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  Quick.Logger.Logger.WaitForFlushBeforeExit := AConfig.WaitForFlushSeconds;
  if AConfig.EnableFile and (AConfig.FileName <> '') then
  begin
    LogDir := ExtractFileDir(AConfig.FileName);
    if AConfig.Enabled and (LogDir <> '') and (not DirectoryExists(LogDir)) then
      ForceDirectories(LogDir);
    if not GQuickFileAdded then
    begin
      Quick.Logger.Logger.Providers.Add(GlobalLogFileProvider);
      GQuickFileAdded := True;
    end;
    GlobalLogFileProvider.FileName := AConfig.FileName;
    GlobalLogFileProvider.DailyRotate := AConfig.DailyRotate;
    GlobalLogFileProvider.MaxFileSizeInMB := AConfig.MaxFileSizeMB;
    GlobalLogFileProvider.AutoFlush := AConfig.AutoFlush;
    GlobalLogFileProvider.LogLevel := MapQuickLevel(AConfig.FileMinLevel);
    GlobalLogFileProvider.Enabled := AConfig.Enabled;
  end
  else if GQuickFileAdded then
    GlobalLogFileProvider.Enabled := False;

  if AConfig.EnableConsole then
  begin
    if not GQuickConsoleAdded then
    begin
      Quick.Logger.Logger.Providers.Add(GlobalLogConsoleProvider);
      GQuickConsoleAdded := True;
    end;
    GlobalLogConsoleProvider.LogLevel := MapQuickLevel(AConfig.ConsoleMinLevel);
    GlobalLogConsoleProvider.ShowEventColors := AConfig.ConsoleColors;
    GlobalLogConsoleProvider.Enabled := AConfig.Enabled;
  end
  else if GQuickConsoleAdded then
    GlobalLogConsoleProvider.Enabled := False;
{$IFEND}
{$ENDIF}
end;

class procedure TGLogger.InitDefault(const ALogFileName: string; AEnabled: Boolean;
  AEnableConsole: Boolean; ADailyRotate: Boolean; AMaxFileSizeMB: Integer;
  AAutoFlush: Boolean; AWaitForFlushSeconds: Integer);
{$IFNDEF GLOGGER_DISABLED}
var
  Cfg: TGLogConfig;
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  Cfg := TGLogConfig.Default;
  Cfg.Enabled := AEnabled;
  Cfg.FileName := ALogFileName;
  Cfg.EnableFile := ALogFileName <> '';
  Cfg.EnableConsole := AEnableConsole;
  Cfg.DailyRotate := ADailyRotate;
  Cfg.MaxFileSizeMB := AMaxFileSizeMB;
  Cfg.AutoFlush := AAutoFlush;
  Cfg.WaitForFlushSeconds := AWaitForFlushSeconds;
  Configure(Cfg);
{$ENDIF}
end;

class procedure TGLogger.Flush;
{$IFDEF GLOGGER_BACKEND_CUSTOM}
var
  LocalSink: IGLogSink;
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if GClosed then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  try
    DrainQueue;
  except
    AtomicInc64(GErrorTotal);
  end;
{$ENDIF}

{$IFDEF GLOGGER_BACKEND_CUSTOM}
  if GSinkLock <> nil then
  begin
    GSinkLock.Enter;
    try
      LocalSink := GSink;
    finally
      GSinkLock.Leave;
    end;
    if LocalSink <> nil then
    begin
      try
        LocalSink.Flush;
      except
        AtomicInc64(GErrorTotal);
      end;
    end;
  end;
{$ENDIF}
{$ENDIF}
end;

class procedure TGLogger.Shutdown;
{$IFDEF GLOGGER_BACKEND_FAST}
var
  I: Integer;
{$IFDEF MSWINDOWS}
  WaitMs, WaitRes: DWORD;
{$ENDIF}
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if GClosed then
  begin
{$IFDEF GLOGGER_BACKEND_FAST}
    if not (GFinalizing and (GFlushThread <> nil)) then
      Exit;
{$ELSE}
    Exit;
{$ENDIF}
  end;
  GClosed := True;
  GEnabled := False;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GShardsReady then
  begin
    for I := 0 to CShardCount - 1 do
    begin
      GShards[I].Core.Lock.Enter;
      try
      finally
{$IFDEF FPC}
        GShards[I].Core.Lock.Leave;
{$ELSE}
        GShards[I].Core.Lock.Exit;
{$ENDIF}
      end;
    end;
  end;

  if GFlushThread <> nil then
  begin
    GFlushThread.Terminate;
    if GFlushEvent <> nil then
      GFlushEvent.SetEvent;

{$IFDEF MSWINDOWS}
    if GConfig.WaitForFlushSeconds > 0 then
      WaitMs := DWORD(GConfig.WaitForFlushSeconds) * 1000
    else
      WaitMs := 2000;
    if GFinalizing and IsLibrary and (WaitMs > 200) then
      WaitMs := 200;

    if GFinalizing and IsLibrary then
    begin
      if GFlushDoneEvent <> nil then
        GFlushDoneEvent.WaitFor(WaitMs);
      if WaitForSingleObject(GFlushThread.Handle, 0) = WAIT_OBJECT_0 then
      begin
        GFlushThread.WaitFor;
        FreeAndNil(GFlushThread);
        MarkFlushThreadBodyDone;
      end;
    end
    else
    begin
      WaitRes := WaitForSingleObject(GFlushThread.Handle, WaitMs);
      if (WaitRes <> WAIT_OBJECT_0) and GFinalizing then
        WaitRes := WaitForSingleObject(GFlushThread.Handle, INFINITE);
      if WaitRes = WAIT_OBJECT_0 then
      begin
        GFlushThread.WaitFor;
        FreeAndNil(GFlushThread);
        MarkFlushThreadBodyDone;
      end;
    end;
{$ELSE}
    GFlushThread.WaitFor;
    FreeAndNil(GFlushThread);
    MarkFlushThreadBodyDone;
{$ENDIF}
  end;

  if (GFlushThread = nil) or (not IsFlushThreadBodyActive) then
  begin
    try
      try
        DrainQueue;
      except
        AtomicInc64(GErrorTotal);
      end;
    finally
      if GWriteLock <> nil then
      begin
        GWriteLock.Enter;
        try
          CloseLogFile;
        finally
          GWriteLock.Leave;
        end;
      end;
    end;
  end;
{$ENDIF}

{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  if GQuickFileAdded then
    GlobalLogFileProvider.Enabled := False;
  if GQuickConsoleAdded then
    GlobalLogConsoleProvider.Enabled := False;
{$IFEND}

{$IFDEF GLOGGER_BACKEND_CUSTOM}
  if GSinkLock <> nil then
  begin
    GSinkLock.Enter;
    try
      if GSink <> nil then
        GSink.Flush;
      GSink := nil;
    finally
      GSinkLock.Leave;
    end;
  end;
{$ENDIF}
{$IFDEF MSWINDOWS}
  if GOrigConsoleOutputCP <> 0 then
  begin
    SetConsoleOutputCP(GOrigConsoleOutputCP);
    GOrigConsoleOutputCP := 0;
  end;
{$ENDIF}
{$ENDIF}
end;

class procedure TGLogger.SetEnabled(AEnabled: Boolean);
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if GClosed then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GWriteLock <> nil then
  begin
    GWriteLock.Enter;
    try
      GConfig.Enabled := AEnabled;
      GEnabled := AEnabled;
      if GEnabled then
        EnsureFlushThreadRunning;
    finally
      GWriteLock.Leave;
    end;
  end
  else
  begin
    GConfig.Enabled := AEnabled;
    GEnabled := AEnabled;
  end;
{$ELSE}
  GConfig.Enabled := AEnabled;
  GEnabled := AEnabled;
{$ENDIF}

{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  if GQuickFileAdded then
    GlobalLogFileProvider.Enabled := AEnabled and GConfig.EnableFile;
  if GQuickConsoleAdded then
    GlobalLogConsoleProvider.Enabled := AEnabled and GConfig.EnableConsole;
{$IFEND}
{$ENDIF}
end;

class procedure TGLogger.SetMinLevel(ALevel: TGLogLevel);
{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
var
  MappedLevel: TLogLevel;
{$IFEND}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if GClosed then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GWriteLock <> nil then
  begin
    GWriteLock.Enter;
    try
      GConfig.MinLevel := ALevel;
      GConfig.FileMinLevel := ALevel;
      GConfig.ConsoleMinLevel := ALevel;
      GFileMinLevel := ALevel;
      GConsoleMinLevel := ALevel;
      GMinLevel := ALevel;
    finally
      GWriteLock.Leave;
    end;
  end
  else
  begin
    GConfig.MinLevel := ALevel;
    GConfig.FileMinLevel := ALevel;
    GConfig.ConsoleMinLevel := ALevel;
    GFileMinLevel := ALevel;
    GConsoleMinLevel := ALevel;
    GMinLevel := ALevel;
  end;
{$ELSE}
  GConfig.MinLevel := ALevel;
  GConfig.FileMinLevel := ALevel;
  GConfig.ConsoleMinLevel := ALevel;
  GMinLevel := ALevel;
  {$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  MappedLevel := MapQuickLevel(ALevel);
  if GQuickFileAdded then
    GlobalLogFileProvider.LogLevel := MappedLevel;
  if GQuickConsoleAdded then
    GlobalLogConsoleProvider.LogLevel := MappedLevel;
  {$IFEND}
{$ENDIF}
{$ENDIF}
end;

class procedure TGLogger.SetCustomSink(const ASink: IGLogSink);
begin
{$IFDEF GLOGGER_BACKEND_CUSTOM}
  if GSinkLock <> nil then
  begin
    GSinkLock.Enter;
    try
      GSink := ASink;
    finally
      GSinkLock.Leave;
    end;
  end;
{$ENDIF}
end;

class function TGLogger.BackendName: string;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := 'Disabled (NoOp)';
{$ELSEIF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  Result := 'QuickLogger (Delphi)';
{$ELSEIF DEFINED(GLOGGER_BACKEND_FAST)}
  Result := 'GLogger Fast (Async UTF-8)';
{$ELSEIF DEFINED(GLOGGER_BACKEND_CUSTOM)}
  Result := 'Custom Sink (IGLogSink)';
{$ELSE}
  Result := 'Unknown';
{$IFEND}
end;

class function TGLogger.IsCompiledEnabled: Boolean;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := False;
{$ELSE}
  Result := True;
{$ENDIF}
end;

class function TGLogger.IsEnabled: Boolean;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := False;
{$ELSE}
  Result := GEnabled and (not GClosed);
{$ENDIF}
end;

class function TGLogger.IsLevelEnabled(ALevel: TGLogLevel): Boolean;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := False;
{$ELSE}
  Result := GEnabled and (not GClosed) and (ALevel < llOff) and (ALevel >= GMinLevel);
{$ENDIF}
end;

class function TGLogger.DroppedCount: Int64;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := 0;
{$ELSE}
  Result := AtomicRead64(GDroppedTotal);
{$ENDIF}
end;

class function TGLogger.ErrorCount: Int64;
begin
{$IFDEF GLOGGER_DISABLED}
  Result := 0;
{$ELSE}
  Result := AtomicRead64(GErrorTotal);
{$ENDIF}
end;

class procedure TGLogger.ResetCounters;
begin
{$IFNDEF GLOGGER_DISABLED}
  AtomicXchg64(GDroppedTotal, 0);
  AtomicXchg64(GDroppedPendingReport, 0);
  AtomicXchg64(GErrorTotal, 0);
{$ENDIF}
end;

class procedure TGLogger.Log(ALevel: TGLogLevel; const AMsg: string);
{$IFDEF GLOGGER_BACKEND_CUSTOM}
var
  LocalSink: IGLogSink;
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if not IsLevelEnabled(ALevel) then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GShardsReady then
    LogInternal(ALevel, AMsg, True);
{$ENDIF}

{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  case ALevel of
    llTrace:
      Quick.Logger.Logger.Trace(AMsg);
    llDebug:
      Quick.Logger.Logger.Debug(AMsg);
    llInfo:
      Quick.Logger.Logger.Info(AMsg);
    llWarn:
      Quick.Logger.Logger.Warn(AMsg);
    llError:
      Quick.Logger.Logger.Error(AMsg);
    llCritical:
      Quick.Logger.Logger.Critical(AMsg);
  end;
{$IFEND}

{$IFDEF GLOGGER_BACKEND_CUSTOM}
  if GSinkLock <> nil then
  begin
    GSinkLock.Enter;
    try
      LocalSink := GSink;
    finally
      GSinkLock.Leave;
    end;
    if LocalSink <> nil then
      LocalSink.WriteLog(ALevel, AMsg);
  end;
{$ENDIF}
{$ENDIF}
end;

class procedure TGLogger.Log(ALevel: TGLogLevel; const AFmt: string; const AArgs: array of const);
{$IFDEF GLOGGER_BACKEND_FAST}
var
  CurDay, Idx, LineLen, WriteOff: Integer;
  LineBuf: array[0..515] of AnsiChar;
  TimeBuf: TGLogTimeBuf;
  NeedWake, DroppedHere: Boolean;
  FmtMsg: string;
{$ENDIF}
begin
{$IFDEF GLOGGER_DISABLED}
  Exit;
{$ELSE}
  if not IsLevelEnabled(ALevel) then
    Exit;

{$IFDEF GLOGGER_BACKEND_FAST}
  if GInLoggerThread then
    Exit;

  if GShardsReady then
  begin
    LineLen := CTimeLen;
    Move(CLevelTags[ALevel][0], LineBuf[LineLen], CLevelTagLen);
    Inc(LineLen, CLevelTagLen);

    if TryFastFormatToStack(@LineBuf[0], SizeOf(LineBuf) - 2, LineLen, AFmt, AArgs) then
    begin
      Idx := GetShardIndex;
      GetCurrentTimeAndDay(TimeBuf, CurDay);
      Move(TimeBuf[0], LineBuf[0], CTimeLen);
      LineBuf[LineLen] := #13;
      LineBuf[LineLen + 1] := #10;
      Inc(LineLen, 2);

      NeedWake := False;
      DroppedHere := False;
      GInLoggerThread := True;
      try
        GShards[Idx].Core.Lock.Enter;
        try
          if (not GShardsReady) or GClosed then
            Exit;
          if ShardReserve(GShards[Idx], LineLen, WriteOff) then
          begin
            Move(LineBuf[0], GShards[Idx].Core.Buf[WriteOff], LineLen);
            if (not GShards[Idx].Core.WakeSent) and (GShards[Idx].Core.Len >= GHighWatermark) then
            begin
              GShards[Idx].Core.WakeSent := True;
              NeedWake := True;
            end;
          end
          else
            DroppedHere := True;
        finally
{$IFDEF FPC}
          GShards[Idx].Core.Lock.Leave;
{$ELSE}
          GShards[Idx].Core.Lock.Exit;
{$ENDIF}
        end;
      finally
        GInLoggerThread := False;
      end;

      if (ALevel >= llCritical) or DroppedHere then
        NeedWake := True;
      if NeedWake and (not GFinalizing) and (GFlushEvent <> nil) then
        GFlushEvent.SetEvent;
      Exit;
    end;

    FmtMsg := SafeFormatMessage(AFmt, AArgs);
    LogInternal(ALevel, FmtMsg, False);
    Exit;
  end;
  Log(ALevel, SafeFormatMessage(AFmt, AArgs));
{$ELSE}
  Log(ALevel, SafeFormatMessage(AFmt, AArgs));
{$ENDIF}
{$ENDIF}
end;

class procedure TGLogger.Trace(const AMsg: string);
begin
  Log(llTrace, AMsg);
end;

class procedure TGLogger.Trace(const AFmt: string; const AArgs: array of const);
begin
  Log(llTrace, AFmt, AArgs);
end;

class procedure TGLogger.Debug(const AMsg: string);
begin
  Log(llDebug, AMsg);
end;

class procedure TGLogger.Debug(const AFmt: string; const AArgs: array of const);
begin
  Log(llDebug, AFmt, AArgs);
end;

class procedure TGLogger.Info(const AMsg: string);
begin
  Log(llInfo, AMsg);
end;

class procedure TGLogger.Info(const AFmt: string; const AArgs: array of const);
begin
  Log(llInfo, AFmt, AArgs);
end;

class procedure TGLogger.Warn(const AMsg: string);
begin
  Log(llWarn, AMsg);
end;

class procedure TGLogger.Warn(const AFmt: string; const AArgs: array of const);
begin
  Log(llWarn, AFmt, AArgs);
end;

class procedure TGLogger.Error(const AMsg: string);
begin
  Log(llError, AMsg);
end;

class procedure TGLogger.Error(const AFmt: string; const AArgs: array of const);
begin
  Log(llError, AFmt, AArgs);
end;

class procedure TGLogger.Critical(const AMsg: string);
begin
  Log(llCritical, AMsg);
end;

class procedure TGLogger.Critical(const AFmt: string; const AArgs: array of const);
begin
  Log(llCritical, AFmt, AArgs);
end;

{$IFDEF GLOGGER_BACKEND_FAST}
procedure FreeShards;
var
  I: Integer;
{$IFNDEF FPC}
  Ev1, Ev2: TEvent;
  WLock: TCriticalSection;
{$ENDIF}
begin
  GShardsReady := False;
  for I := 0 to CShardCount - 1 do
  begin
    GShards[I].Core.Buf := nil;
    GShards[I].Core.Len := 0;
{$IFDEF FPC}
    if not GFinalizing then
      FreeAndNil(GShards[I].Core.Lock);
{$ENDIF}
  end;
{$IFDEF FPC}
  if not GFinalizing then
    FreeAndNil(GTimeLock);
{$ENDIF}
  GFlushBuf := nil;
  GFilteredBuf := nil;
  GRetryFileBuf := nil;
  GRetryFileLen := 0;
{$IFDEF FPC}
  if not GFinalizing then
  begin
    FreeAndNil(GFlushDoneEvent);
    FreeAndNil(GFlushEvent);
    FreeAndNil(GWriteLock);
  end;
{$ELSE}
  Ev1 := GFlushDoneEvent;
  GFlushDoneEvent := nil;
  FreeAndNil(Ev1);
  Ev2 := GFlushEvent;
  GFlushEvent := nil;
  FreeAndNil(Ev2);
  WLock := GWriteLock;
  GWriteLock := nil;
  FreeAndNil(WLock);
{$ENDIF}
end;

procedure InitShards;
var
  I: Integer;
begin
  GShardsReady := False;
{$IFDEF FPC}
  GTimeLock := nil;
{$ENDIF}
  GWriteLock := nil;
  GFlushEvent := nil;
  GFlushDoneEvent := nil;
  GFlushThreadBodyActive := 0;
  for I := 0 to CShardCount - 1 do
  begin
{$IFDEF FPC}
    GShards[I].Core.Lock := nil;
{$ENDIF}
    GShards[I].Core.Buf := nil;
    GShards[I].Core.Len := 0;
    GShards[I].Core.WakeSent := False;
  end;

  try
    GTimeLock := {$IFDEF FPC}TCriticalSection.Create{$ELSE}TSpinLock.Create(False){$ENDIF};
    FillChar(GCachedTimeUtf8[0], SizeOf(GCachedTimeUtf8), 0);
    GWriteLock := TCriticalSection.Create;
    GFlushEvent := TEvent.Create(nil, False, False, '');
    GFlushDoneEvent := TEvent.Create(nil, True, True, '');
    SetLength(GFlushBuf, 262144);
    for I := 0 to CShardCount - 1 do
    begin
      GShards[I].Core.Lock := {$IFDEF FPC}TCriticalSection.Create{$ELSE}TSpinLock.Create(False){$ENDIF};
      SetLength(GShards[I].Core.Buf, 262144);
    end;
    GShardsReady := True;
  except
    AtomicInc64(GErrorTotal);
    FreeShards;
  end;
end;
{$ENDIF}

initialization
{$IF DEFINED(DCC) AND DEFINED(GLOGGER_BACKEND_QUICKLOGGER)}
  IOResult;
{$IFEND}
  GConfig := TGLogConfig.Default;
{$IFDEF GLOGGER_BACKEND_FAST}
  InitShards;
{$ENDIF}
{$IFDEF GLOGGER_BACKEND_CUSTOM}
  GSinkLock := TCriticalSection.Create;
{$ENDIF}

finalization
  GFinalizing := True;
  TGLogger.Shutdown;
{$IFDEF GLOGGER_BACKEND_FAST}
  if (GFlushThread = nil) and (not IsFlushThreadBodyActive) then
    FreeShards;
{$ENDIF}
{$IFDEF GLOGGER_BACKEND_CUSTOM}
  FreeAndNil(GSinkLock);
{$ENDIF}

end.
