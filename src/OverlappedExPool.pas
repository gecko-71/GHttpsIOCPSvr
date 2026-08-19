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
    FAllAllocated: TList<POverlappedEx>;
    FLock: TObject;
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
begin
  inherited Create;
  FPool := TQueue<POverlappedEx>.Create;
  FAllAllocated := TList<POverlappedEx>.Create;
  FLock := TObject.Create;
  FInitialSize := AInitialSize;
  FMaxSize := AMaxSize;
  FTotalCreated := 0;
  FMinFreeMemoryMb := AMinFreeMemoryMb;
  FMaxMemoryLoadPercent := AMaxMemoryLoadPercent;
  if FMaxMemoryLoadPercent > 100 then
    FMaxMemoryLoadPercent := 100;
  var LInitialFillCount := FInitialSize;
  if (FMaxSize > 0) and (LInitialFillCount > FMaxSize) then
    LInitialFillCount := FMaxSize;
  FillPool(LInitialFillCount);
end;

destructor TOverlappedExPool.Destroy;
var
  Overlapped: POverlappedEx;
begin
  TMonitor.Enter(FLock);
  try
    if Assigned(FPool) then
      FPool.Clear;
    if Assigned(FAllAllocated) then
    begin
      for Overlapped in FAllAllocated do
      begin
        if Assigned(Overlapped) then
        begin
          try
            var Req := TObject(InterlockedExchangePointer(Pointer(Overlapped^.Request), nil));
            if Assigned(Req) then
              Req.Free;
          except
          end;
          try
            var Resp := TObject(InterlockedExchangePointer(Pointer(Overlapped^.Response), nil));
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
    TMonitor.Exit(FLock);
  end;
  FPool.Free;
  FLock.Free;
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
    ZeroMemory(Overlapped, SizeOf(TOverlappedEx));
    Overlapped^.InPool := 1;
    FAllAllocated.Add(Overlapped);
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
  if (FMinFreeMemoryMb > 0) and (MemStatus.ullAvailPhys < FMinFreeMemoryMb * 1024 * 1024) then
    Exit(False);
  Result := True;
end;

function TOverlappedExPool.Acquire: POverlappedEx;
var
  LNewTotal: Integer;
begin
  TMonitor.Enter(FLock);
  try
    if FPool.Count > 0 then
      Result := FPool.Dequeue
    else
      Result := nil;
  finally
    TMonitor.Exit(FLock);
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
    New(Result);
    TMonitor.Enter(FLock);
    try
      FAllAllocated.Add(Result);
    finally
      TMonitor.Exit(FLock);
    end;
  end;
  if Assigned(Result) then
  begin
    SetLength(Result^.ClientReceiveBuffer, 0);
    ZeroMemory(Result, SizeOf(TOverlappedEx));
    Result^.InPool := 0;
  end;
end;

procedure TOverlappedExPool.Release(AOverlapped: POverlappedEx);
begin
  if not Assigned(AOverlapped) then
    Exit;
  if InterlockedCompareExchange(AOverlapped^.InPool, 1, 0) <> 0 then
    Exit;

  TMonitor.Enter(FLock);
  try
    FPool.Enqueue(AOverlapped);
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TOverlappedExPool.GetCount: Integer;
begin
  TMonitor.Enter(FLock);
  try
    Result := FPool.Count;
  finally
    TMonitor.Exit(FLock);
  end;
end;

end.
