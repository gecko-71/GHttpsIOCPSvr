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

unit OverlappedExPool;

interface

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Generics.Collections,
  Winapi.Windows,
  WinApiAdditions;

type
  TOverlappedExPool = class
  private
    FPool: TQueue<POverlappedEx>;
    FAllAllocated: TDictionary<POverlappedEx, Byte>;
    FLock: _RTL_SRWLOCK;
    FInitialSize: Integer;
    FTotalCreated: Integer;
    FMaxSize: Integer;
    FMinFreeMemoryMb: Cardinal;
    procedure FillPool(ACount: Integer);
    function HasSufficientMemory: Boolean;
  public
    FMaxMemoryLoadPercent: Byte;
    constructor Create(AInitialSize: Integer = 100; AMaxSize: Integer = 500;
            AMinFreeMemoryMb: Cardinal = 50; AMaxMemoryLoadPercent: Byte = 98);
    destructor Destroy; override;
    function Acquire: POverlappedEx;
    procedure Release(AOverlapped: POverlappedEx);
    function IsAllocated(AOverlapped: POverlappedEx): Boolean;
    function GetCount: Integer;
    property Count: Integer read GetCount;
    property TotalCreated: Integer read FTotalCreated;
    property MaxSize: Integer read FMaxSize;
    property MaxMemoryLoadPercent: Byte read FMaxMemoryLoadPercent;
    property MinFreeMemoryMb: Cardinal read FMinFreeMemoryMb;
  end;

implementation

constructor TOverlappedExPool.Create(AInitialSize, AMaxSize: Integer;
  AMinFreeMemoryMb: Cardinal; AMaxMemoryLoadPercent: Byte);
var
  LInitialFillCount: Integer;
begin
  inherited Create;
  FPool := TQueue<POverlappedEx>.Create;
  FAllAllocated := TDictionary<POverlappedEx, Byte>.Create;
  InitializeSRWLock(FLock);
  FInitialSize := AInitialSize;
  FMaxSize := AMaxSize;
  FTotalCreated := 0;
  FMinFreeMemoryMb := AMinFreeMemoryMb;
  FMaxMemoryLoadPercent := AMaxMemoryLoadPercent;
  if FMaxMemoryLoadPercent > 100 then
    FMaxMemoryLoadPercent := 100;
  LInitialFillCount := FInitialSize;
  if (FMaxSize > 0) and (LInitialFillCount > FMaxSize) then
    LInitialFillCount := FMaxSize;
  if LInitialFillCount > 0 then
    FillPool(LInitialFillCount);
end;

destructor TOverlappedExPool.Destroy;
var
  Overlapped: POverlappedEx;
  Req, Resp: TObject;
begin
  AcquireSRWLockExclusive(FLock);
  try
    if Assigned(FPool) then
      FPool.Clear;
    if Assigned(FAllAllocated) then
    begin
      for Overlapped in FAllAllocated.Keys do
      begin
        if Assigned(Overlapped) then
        begin
          try
            Req := TObject(InterlockedExchangePointer(Pointer(Overlapped^.Request), nil));
            if Assigned(Req) then
              Req.Free;
          except
          end;
          try
            Resp := TObject(InterlockedExchangePointer(Pointer(Overlapped^.Response), nil));
            if Assigned(Resp) then
              Resp.Free;
          except
          end;
          try
            Resp := TObject(InterlockedExchangePointer(Pointer(Overlapped^.CachedResponse), nil));
            if Assigned(Resp) then
              Resp.Free;
          except
          end;
          Dispose(Overlapped);
        end;
      end;
      FAllAllocated.Free;
      FAllAllocated := nil;
    end;
  finally
    ReleaseSRWLockExclusive(FLock);
  end;
  FPool.Free;
  inherited;
end;

procedure TOverlappedExPool.FillPool(ACount: Integer);
var
  i: Integer;
  Overlapped: POverlappedEx;
begin
  for i := 1 to ACount do
  begin
    New(Overlapped);
    Finalize(Overlapped^);
    FillChar(Overlapped^, SizeOf(TOverlappedEx), 0);
    Initialize(Overlapped^);
    Overlapped^.InPool := 1;
    FAllAllocated.AddOrSetValue(Overlapped, 1);
    FPool.Enqueue(Overlapped);
    Inc(FTotalCreated);
  end;
end;

function TOverlappedExPool.HasSufficientMemory: Boolean;
var
  MemStatus: TMemoryStatusEx;
begin
  if (FMinFreeMemoryMb = 0) and (FMaxMemoryLoadPercent = 0) then
    Exit(True);
  MemStatus.dwLength := SizeOf(TMemoryStatusEx);
  if not GlobalMemoryStatusEx(MemStatus) then
  begin
    Exit(True);
  end;
  if (FMaxMemoryLoadPercent > 0) and (MemStatus.dwMemoryLoad > FMaxMemoryLoadPercent) then
    Exit(False);
  if (FMinFreeMemoryMb > 0) and (MemStatus.ullAvailPhys < UInt64(FMinFreeMemoryMb) * 1024 * 1024) then
    Exit(False);
  Result := True;
end;

function TOverlappedExPool.Acquire: POverlappedEx;
var
  LNewTotal: Integer;
begin
  AcquireSRWLockExclusive(FLock);
  try
    if FPool.Count > 0 then
      Result := FPool.Dequeue
    else
      Result := nil;
  finally
    ReleaseSRWLockExclusive(FLock);
  end;
  if not Assigned(Result) then
  begin
    if FMaxSize > 0 then
    begin
      LNewTotal := InterlockedIncrement(FTotalCreated);
      if LNewTotal > FMaxSize then
      begin
        InterlockedDecrement(FTotalCreated);
        Exit(nil);
      end;
    end
    else
      InterlockedIncrement(FTotalCreated);
    if not HasSufficientMemory then
    begin
      InterlockedDecrement(FTotalCreated);
      Exit(nil);
    end;
    try
      New(Result);
    except
      InterlockedDecrement(FTotalCreated);
      raise;
    end;
    AcquireSRWLockExclusive(FLock);
    try
      FAllAllocated.AddOrSetValue(Result, 1);
    finally
      ReleaseSRWLockExclusive(FLock);
    end;
  end;
  if Assigned(Result) then
  begin
    Finalize(Result^);
    FillChar(Result^, SizeOf(TOverlappedEx), 0);
    Initialize(Result^);
    Result^.InPool := 0;
  end;
end;

procedure TOverlappedExPool.Release(AOverlapped: POverlappedEx);
var
  Req, Resp: TObject;
  ShouldFree: Boolean;
begin
  if not Assigned(AOverlapped) then
    Exit;
  if InterlockedCompareExchange(AOverlapped^.InPool, 1, 0) <> 0 then
    Exit;

  ShouldFree := False;
  AcquireSRWLockExclusive(FLock);
  try
    if FPool.Count >= 256 then
    begin
      if Assigned(FAllAllocated) then
        FAllAllocated.Remove(AOverlapped);
      InterlockedDecrement(FTotalCreated);
      ShouldFree := True;
    end
    else
      FPool.Enqueue(AOverlapped);
  finally
    ReleaseSRWLockExclusive(FLock);
  end;

  if ShouldFree then
  begin
    try
      Req := TObject(InterlockedExchangePointer(Pointer(AOverlapped^.Request), nil));
      if Assigned(Req) then
        Req.Free;
    except
    end;
    try
      Resp := TObject(InterlockedExchangePointer(Pointer(AOverlapped^.Response), nil));
      if Assigned(Resp) then
        Resp.Free;
    except
    end;
    try
      Resp := TObject(InterlockedExchangePointer(Pointer(AOverlapped^.CachedResponse), nil));
      if Assigned(Resp) then
        Resp.Free;
    except
    end;
    Dispose(AOverlapped);
  end;
end;

function TOverlappedExPool.IsAllocated(AOverlapped: POverlappedEx): Boolean;
begin
  if AOverlapped = nil then
    Exit(False);
  AcquireSRWLockShared(FLock);
  try
    Result := FAllAllocated.ContainsKey(AOverlapped);
  finally
    ReleaseSRWLockShared(FLock);
  end;
end;

function TOverlappedExPool.GetCount: Integer;
begin
  AcquireSRWLockShared(FLock);
  try
    Result := FPool.Count;
  finally
    ReleaseSRWLockShared(FLock);
  end;
end;

end.
