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
unit GTerm.ConPty;

interface

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.StrUtils, System.IOUtils,
  System.SyncObjs, System.Hash, System.Generics.Collections, Quick.Logger, GTerm.ConPty.Loader, GTerm.Types;

const
  PROC_THREAD_ATTRIBUTE_HANDLE_LIST          = $00020002;
  PIPE_ACCESS_INBOUND                         = $00000001;
  PIPE_ACCESS_OUTBOUND                        = $00000002;
  PIPE_TYPE_BYTE                              = $00000000;
  PIPE_READMODE_BYTE                          = $00000000;
  PIPE_WAIT                                   = $00000000;
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE         = $00020016;
  PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = $00020009;
  EXTENDED_STARTUPINFO_PRESENT                = $00080000;
  ACCESS_ALLOWED_ACE_HEADER_SIZE              = 12;
  CREATE_UNICODE_ENVIRONMENT                  = $00000400;
  JOB_OBJECT_LIMIT_ACTIVE_PROCESS             = $00000008;
  JOB_OBJECT_LIMIT_JOB_MEMORY                 = $00000200;

type
  PPSID = ^PSID;
  PPROC_THREAD_ATTRIBUTE_LIST = Pointer;

  TStartupInfoExW = record
    StartupInfo: TStartupInfoW;
    lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST;
  end;

  PSID_AND_ATTRIBUTES = ^SID_AND_ATTRIBUTES;
  SID_AND_ATTRIBUTES = record
    Sid: PSID;
    Attributes: DWORD;
  end;

  SECURITY_CAPABILITIES = record
    AppContainerSid: PSID;
    Capabilities: PSID_AND_ATTRIBUTES;
    CapabilityCount: DWORD;
    Reserved: DWORD;
  end;
  PSECURITY_CAPABILITIES = ^SECURITY_CAPABILITIES;

  TDataReceivedEvent = procedure(const AData: TBytes; ACount: Integer) of object;
  TProcessTerminatedEvent = procedure(AExitCode: DWORD) of object;

  TPtyReaderThread = class(TThread)
  private
    FReadPipe: THandle;
    FStopEvent: THandle;
    FOnData: TDataReceivedEvent;
    FLock: TCriticalSection;
  protected
    procedure Execute; override;
  public
    constructor Create(AReadPipe: THandle; AStopEvent: THandle; AOnData: TDataReceivedEvent);
    destructor Destroy; override;
    procedure ClearHandler;
  end;

  TProcessWatcherThread = class(TThread)
  private
    FProcessHandle: THandle;
    FOnTerminated: TProcessTerminatedEvent;
    FLock: TCriticalSection;
  protected
    procedure Execute; override;
  public
    constructor Create(AProcessHandle: THandle; AOnTerminated: TProcessTerminatedEvent);
    destructor Destroy; override;
    procedure ClearHandler;
  end;

  TGTermConPty = class
  private
    FHPty: HPCON;
    FInputRead: THandle;
    FInputWrite: THandle;
    FOutputRead: THandle;
    FOutputWrite: THandle;
    FProcessInfo: TProcessInformation;
    FReaderThread: TPtyReaderThread;
    FWatcherThread: TProcessWatcherThread;
    FCols: Integer;
    FRows: Integer;
    FRunning: Boolean;
    FOnDataReceived: TDataReceivedEvent;
    FOnProcessTerminated: TProcessTerminatedEvent;
    FSandboxMode: TSandboxMode;
    FJobHandle: THandle;
    FAppContainerSid: PSID;
    FAppContainerName: string;
    FStopping: Integer;
    FStopEvent: THandle;
    FGrantedDirs: TArray<string>;
    FUsername: string;
    procedure CreatePipes;
    procedure ClosePipes;
    procedure SetupJobSandbox;
    function SetupAppContainer(const AWorkingDir: string; const AExeDir: string = ''; const AAllowedDirsRead: TArray<string> = nil; const AAllowedDirsWrite: TArray<string> = nil; const ANetworkCaps: TArray<SID_AND_ATTRIBUTES> = nil): Boolean;
    procedure CleanupSandbox;
    procedure GrantDirAccessToAppContainer(const ADir: string; AFullAccess: Boolean = True);
    procedure RevokeDirAccessFromAppContainer(const ADir: string);
    function BuildSandboxEnvironment(const AWorkingDir: string; const AExtraEnv: TArray<string>): string;
    procedure SetupPowerShellProfile(const AWorkingDir: string; const AExtraEnv: TArray<string> = nil);
  public
    constructor Create(ACols: Integer = 80; ARows: Integer = 25);
    destructor Destroy; override;
    function StartProcess(const ACommandLine: string; const AWorkingDir: string = ''; const AAllowedDirsRead: TArray<string> = nil; const AAllowedDirsWrite: TArray<string> = nil; const AEnvironmentVars: TArray<string> = nil; ANetworkAccess: Boolean = False): Boolean;
    procedure StopProcess;
    function Resize(ACols, ARows: Integer): Boolean;
    function WriteInput(const AData: TBytes): Integer; overload;
    function WriteInput(const AStr: string): Integer; overload;
    property Running: Boolean read FRunning;
    property Cols: Integer read FCols;
    property Rows: Integer read FRows;
    property ProcessHandle: THandle read FProcessInfo.hProcess;
    property ProcessId: DWORD read FProcessInfo.dwProcessId;
    property OnDataReceived: TDataReceivedEvent read FOnDataReceived write FOnDataReceived;
    property OnProcessTerminated: TProcessTerminatedEvent read FOnProcessTerminated write FOnProcessTerminated;
    property SandboxMode: TSandboxMode read FSandboxMode write FSandboxMode;
    property Username: string read FUsername write FUsername;
  end;

function InitializeProcThreadAttributeList(
  lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST;
  dwAttributeCount: DWORD;
  dwFlags: DWORD;
  var lpSize: SIZE_T
): BOOL; stdcall; external kernel32 name 'InitializeProcThreadAttributeList';

function UpdateProcThreadAttribute(
  lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST;
  dwFlags: DWORD;
  Attribute: DWORD_PTR;
  lpValue: Pointer;
  cbSize: SIZE_T;
  lpPreviousValue: Pointer;
  lpReturnSize: PSIZE_T
): BOOL; stdcall; external kernel32 name 'UpdateProcThreadAttribute';

procedure DeleteProcThreadAttributeList(
  lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST
); stdcall; external kernel32 name 'DeleteProcThreadAttributeList';

function CreateNamedPipeW(lpName: PWideChar; dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut: DWORD; lpSecurityAttributes: PSecurityAttributes): THandle; stdcall; external kernel32 name 'CreateNamedPipeW';
function CancelIoEx(hFile: THandle; lpOverlapped: POverlapped): BOOL; stdcall; external kernel32 name 'CancelIoEx';
function ConvertStringSecurityDescriptorToSecurityDescriptorW(StringSecurityDescriptor: PWideChar;
  StringSDRevision: DWORD; var SecurityDescriptor: Pointer; SecurityDescriptorSize: PULONG): BOOL; stdcall;
  external advapi32 name 'ConvertStringSecurityDescriptorToSecurityDescriptorW';
function ConvertSidToStringSidW(Sid: PSID; var StringSid: LPWSTR): BOOL; stdcall;
  external advapi32 name 'ConvertSidToStringSidW';

function CreateProcessExW(
  lpApplicationName: LPCWSTR;
  lpCommandLine: LPWSTR;
  lpProcessAttributes: PSecurityAttributes;
  lpThreadAttributes: PSecurityAttributes;
  bInheritHandles: BOOL;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: LPCWSTR;
  const lpStartupInfo: TStartupInfoExW;
  var lpProcessInformation: TProcessInformation
): BOOL; stdcall; external kernel32 name 'CreateProcessW';

implementation

const
  JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE         = $00002000;
  JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = $00000400;

  JOB_OBJECT_CPU_RATE_CONTROL_ENABLE         = $00000001;
  JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP       = $00000004;

type
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = record
    ControlFlags: DWORD;
    CpuRate: DWORD;
  end;

type
  JOBOBJECT_BASIC_LIMIT_INFORMATION = record
    PerProcessUserTimeLimit: LARGE_INTEGER;
    PerJobUserTimeLimit: LARGE_INTEGER;
    LimitFlags: DWORD;
    MinimumWorkingSetSize: SIZE_T;
    MaximumWorkingSetSize: SIZE_T;
    ActiveProcessLimit: DWORD;
    Affinity: ULONG_PTR;
    PriorityClass: DWORD;
    SchedulingClass: DWORD;
  end;

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION = record
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION;
    IoInfo: record
      ReadOperationCount: ULONGLONG;
      WriteOperationCount: ULONGLONG;
      OtherOperationCount: ULONGLONG;
      ReadTransferCount: ULONGLONG;
      WriteTransferCount: ULONGLONG;
      OtherTransferCount: ULONGLONG;
    end;
    ProcessMemoryLimit: SIZE_T;
    JobMemoryLimit: SIZE_T;
    PeakProcessMemoryUsed: SIZE_T;
    PeakJobMemoryUsed: SIZE_T;
  end;

const
  JOB_OBJECT_UILIMIT_HANDLES = $00000001;
  JOB_OBJECT_UILIMIT_DESKTOP = $00000040;

type
  JOBOBJECT_BASIC_UI_RESTRICTIONS = record
    UIRestrictionsClass: DWORD;
  end;

function CreateJobObjectW(lpJobAttributes: Pointer; lpName: PWideChar): THandle;
  stdcall; external kernel32 name 'CreateJobObjectW';

function AssignProcessToJobObject(hJob, hProcess: THandle): BOOL;
  stdcall; external kernel32 name 'AssignProcessToJobObject';

function SetInformationJobObject(hJob: THandle; JobObjectInfoClass: DWORD;
  lpJobObjectInfo: Pointer; cbJobObjectInfoLength: DWORD): BOOL;
  stdcall; external kernel32 name 'SetInformationJobObject';

function CreateAppContainerProfile(
  pszAppContainerName: PWideChar;
  pszDisplayName: PWideChar;
  pszDescription: PWideChar;
  pCapabilities: Pointer;
  dwCapabilityCount: DWORD;
  out ppSidAppContainerSid: PSID
): HRESULT; stdcall; external 'userenv.dll' name 'CreateAppContainerProfile';

function DeleteAppContainerProfile(
  pszAppContainerName: PWideChar
): HRESULT; stdcall; external 'userenv.dll' name 'DeleteAppContainerProfile';

function DeriveAppContainerSidFromAppContainerName(
  pszAppContainerName: PWideChar;
  out ppSidAppContainerSid: PSID
): HRESULT; stdcall; external 'userenv.dll' name 'DeriveAppContainerSidFromAppContainerName';

function FreeSid(pSid: PSID): Pointer; stdcall; external advapi32 name 'FreeSid';

function ConvertStringSidToSidW(
  StringSid: PWideChar;
  out Sid: PSID
): BOOL; stdcall; external advapi32 name 'ConvertStringSidToSidW';

function GetNamedSecurityInfoW(
  pObjectName: PWideChar;
  ObjectType: DWORD;
  SecurityInfo: DWORD;
  ppsidOwner: PPSID;
  ppsidGroup: PPSID;
  ppDacl: Pointer;
  ppSacl: Pointer;
  ppSecurityDescriptor: PPointer
): DWORD; stdcall; external advapi32 name 'GetNamedSecurityInfoW';

function SetNamedSecurityInfoW(
  pObjectName: PWideChar;
  ObjectType: DWORD;
  SecurityInfo: DWORD;
  psidOwner: PSID;
  psidGroup: PSID;
  pDacl: Pointer;
  pSacl: Pointer
): DWORD; stdcall; external advapi32 name 'SetNamedSecurityInfoW';


function GetAclInformation(
  pAcl: Pointer;
  pAclInformation: Pointer;
  nAclInformationLength: DWORD;
  dwAclInformationClass: DWORD
): BOOL; stdcall; external advapi32 name 'GetAclInformation';

function InitializeAcl(
  pAcl: Pointer;
  nAclLength: DWORD;
  dwAclRevision: DWORD
): BOOL; stdcall; external advapi32 name 'InitializeAcl';


function GetAce(pAcl: Pointer; dwAceIndex: DWORD; out pAce: Pointer): BOOL;
  stdcall; external advapi32 name 'GetAce';

function AddAce(pAcl: Pointer; dwAceRevision, dwStartingAceIndex: DWORD;
  pAceList: Pointer; nAceListLength: DWORD): BOOL;
  stdcall; external advapi32 name 'AddAce';
function DeleteAce(pAcl: Pointer; dwAceIndex: DWORD): BOOL;
  stdcall; external advapi32 name 'DeleteAce';

function GetLengthSid(pSid: PSID): DWORD; stdcall; external advapi32 name 'GetLengthSid';
function EqualSid(pSid1, pSid2: PSID): BOOL; stdcall; external advapi32 name 'EqualSid';

function AddAccessAllowedAceEx(
  pAcl: Pointer;
  dwAceRevision: DWORD;
  AceFlags: DWORD;
  AccessMask: DWORD;
  pSid: PSID
): BOOL; stdcall; external advapi32 name 'AddAccessAllowedAceEx';

function ResumeThread(hThread: THandle): DWORD; stdcall; external kernel32 name 'ResumeThread';

const
  SE_FILE_OBJECT               = 1;
  DACL_SECURITY_INFORMATION    = 4;
  FILE_ALL_ACCESS              = $001F01FF;
  ACL_REVISION                 = 2;
  AclSizeInformation           = 2;
  OBJECT_INHERIT_ACE           = 1;
  CONTAINER_INHERIT_ACE        = 2;
  FILE_GENERIC_READ_EXECUTE    = DWORD($001200A9);

type
  TACL_SIZE_INFORMATION = record
    AceCount: DWORD;
    AclBytesInUse: DWORD;
    AclBytesFree: DWORD;
  end;
  
function BuildNetworkCapabilities(out ACaps: TArray<SID_AND_ATTRIBUTES>): Boolean;
var
  NetSid1, NetSid2: PSID;
begin
  SetLength(ACaps, 0);
  NetSid1 := nil;
  NetSid2 := nil;
  if ConvertStringSidToSidW('S-1-15-3-1', NetSid1) then
  begin
    SetLength(ACaps, Length(ACaps) + 1);
    ACaps[High(ACaps)].Sid := NetSid1;
    ACaps[High(ACaps)].Attributes := $00000004;
  end;
  if ConvertStringSidToSidW('S-1-15-3-3', NetSid2) then
  begin
    SetLength(ACaps, Length(ACaps) + 1);
    ACaps[High(ACaps)].Sid := NetSid2;
    ACaps[High(ACaps)].Attributes := $00000004;
  end;
  Result := Length(ACaps) > 0;
end;  

constructor TPtyReaderThread.Create(AReadPipe: THandle; AStopEvent: THandle; AOnData: TDataReceivedEvent);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FLock := TCriticalSection.Create;
  FReadPipe := AReadPipe;
  FStopEvent := AStopEvent;
  FOnData := AOnData;
end;

destructor TPtyReaderThread.Destroy;
begin
  ClearHandler;
  FreeAndNil(FLock);
  inherited Destroy;
end;

procedure TPtyReaderThread.ClearHandler;
begin
  if Assigned(FLock) then
  begin
    FLock.Enter;
    try
      FOnData := nil;
    finally
      FLock.Leave;
    end;
  end;
end;

procedure TPtyReaderThread.Execute;
var
  Buffer: array[0..8191] of Byte;
  BytesRead: DWORD;
  DataBytes: TBytes;
  Handler: TDataReceivedEvent;
  Overlapped: TOverlapped;
  Events: array[0..1] of THandle;
  WaitRes: DWORD;
begin
  FillChar(Overlapped, SizeOf(Overlapped), 0);
  Overlapped.hEvent := CreateEvent(nil, True, False, nil);
  try
    Events[0] := FStopEvent;
    Events[1] := Overlapped.hEvent;
    while not Terminated do
    begin
      BytesRead := 0;
      ResetEvent(Overlapped.hEvent);
      if not ReadFile(FReadPipe, Buffer[0], SizeOf(Buffer), BytesRead, @Overlapped) then
      begin
        if GetLastError = ERROR_IO_PENDING then
        begin
          WaitRes := WaitForMultipleObjects(2, @Events[0], False, INFINITE);
          if (WaitRes <> WAIT_OBJECT_0 + 1) or Terminated then
          begin
            CancelIoEx(FReadPipe, @Overlapped);
            Break;
          end;
          if not GetOverlappedResult(FReadPipe, Overlapped, BytesRead, False) then
          begin
            Logger.Warn(Format('[ConPTY] GetOverlappedResult failed: %d', [GetLastError]));
            Break;
          end;
        end
        else
        begin
          Logger.Warn(Format('[ConPTY] ReadFile failed immediately: %d', [GetLastError]));
          Break;
        end;
      end;
      

      if Terminated then Break;
      if BytesRead > 0 then
      begin
        SetLength(DataBytes, BytesRead);
        Move(Buffer[0], DataBytes[0], BytesRead);
        Handler := nil;
        if Assigned(FLock) then
        begin
          FLock.Enter;
          try
            Handler := FOnData;
          finally
            FLock.Leave;
          end;
        end;
        if Assigned(Handler) and not Terminated then
        begin
          try
            Handler(DataBytes, BytesRead);
          except
            Break;
          end;
        end;
      end;
    end;
  finally
    if Overlapped.hEvent <> 0 then
      CloseHandle(Overlapped.hEvent);
  end;
end;

constructor TProcessWatcherThread.Create(AProcessHandle: THandle; AOnTerminated: TProcessTerminatedEvent);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FLock := TCriticalSection.Create;
  FProcessHandle := AProcessHandle;
  FOnTerminated := AOnTerminated;
end;

destructor TProcessWatcherThread.Destroy;
begin
  ClearHandler;
  FreeAndNil(FLock);
  inherited Destroy;
end;

procedure TProcessWatcherThread.ClearHandler;
begin
  if Assigned(FLock) then
  begin
    FLock.Enter;
    try
      FOnTerminated := nil;
    finally
      FLock.Leave;
    end;
  end;
end;

procedure TProcessWatcherThread.Execute;
var
  WaitRes: DWORD;
  ExitCode: DWORD;
  Handler: TProcessTerminatedEvent;
begin
  while not Terminated do
  begin
    if FProcessHandle = 0 then Exit;
    WaitRes := WaitForSingleObject(FProcessHandle, 200);
    if WaitRes = WAIT_OBJECT_0 then
    begin
      ExitCode := 0;
      GetExitCodeProcess(FProcessHandle, ExitCode);
      Handler := nil;
      if Assigned(FLock) then
      begin
        FLock.Enter;
        try
          Handler := FOnTerminated;
        finally
          FLock.Leave;
        end;
      end;
      if not Terminated and Assigned(Handler) then
      begin
        try
          Handler(ExitCode);
        except
        end;
      end;
      Break;
    end
    else if WaitRes <> WAIT_TIMEOUT then
      Break;
  end;
end;

constructor TGTermConPty.Create(ACols: Integer; ARows: Integer);
begin
  inherited Create;
  FCols := ACols;
  FRows := ARows;
  FHPty := 0;
  FInputRead := 0;
  FInputWrite := 0;
  FOutputRead := 0;
  FOutputWrite := 0;
  FillChar(FProcessInfo, SizeOf(FProcessInfo), 0);
  FRunning := False;
  FStopping := 0;
  FStopEvent := CreateEvent(nil, True, False, nil);
  FSandboxMode := smNone;
  FJobHandle := 0;
  FAppContainerSid := nil;
  FAppContainerName := '';
end;

destructor TGTermConPty.Destroy;
begin
  FOnDataReceived := nil;
  FOnProcessTerminated := nil;
  StopProcess;
  if FStopEvent <> 0 then
  begin
    CloseHandle(FStopEvent);
    FStopEvent := 0;
  end;
  inherited Destroy;
end;

var
  GPipeCounter: Integer = 0;

procedure TGTermConPty.CreatePipes;
var
  Sa: TSecurityAttributes;
  PipeInName, PipeOutName: string;
  UniqueId: Integer;
  PipeSd: Pointer;
begin
  PipeSd := nil;
  FillChar(Sa, SizeOf(Sa), 0);
  Sa.nLength := SizeOf(Sa);
  Sa.bInheritHandle := True;
  if ConvertStringSecurityDescriptorToSecurityDescriptorW(PWideChar('D:(A;;GA;;;WD)(A;;GA;;;AC)'), 1, PipeSd, nil) then
    Sa.lpSecurityDescriptor := PipeSd;
  try
    UniqueId := TInterlocked.Increment(GPipeCounter);
    PipeInName := Format('\\.\pipe\GTermBox_PTY_In_%d_%d_%d', [GetCurrentProcessId, GetTickCount, UniqueId]);
    PipeOutName := Format('\\.\pipe\GTermBox_PTY_Out_%d_%d_%d', [GetCurrentProcessId, GetTickCount, UniqueId]);

    FInputRead := CreateNamedPipeW(
      PWideChar(PipeInName),
      PIPE_ACCESS_INBOUND,
      PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT,
      1,
      1024 * 1024,
      1024 * 1024,
      0,
      @Sa
    );
    FInputWrite := CreateFileW(
      PWideChar(PipeInName),
      GENERIC_WRITE,
      0,
      @Sa,
      OPEN_EXISTING,
      0,
      0
    );

    FOutputRead := CreateNamedPipeW(
      PWideChar(PipeOutName),
      PIPE_ACCESS_INBOUND or FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT,
      1,
      1024 * 1024,
      1024 * 1024,
      0,
      @Sa
    );
    FOutputWrite := CreateFileW(
      PWideChar(PipeOutName),
      GENERIC_WRITE,
      0,
      @Sa,
      OPEN_EXISTING,
      0,
      0
    );

    SetHandleInformation(FInputRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(FOutputWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
  finally
    if PipeSd <> nil then
      LocalFree(HLOCAL(PipeSd));
  end;
end;

procedure TGTermConPty.ClosePipes;
begin
  if FStopEvent <> 0 then
    SetEvent(FStopEvent);
  if FOutputRead <> 0 then
    CancelIoEx(FOutputRead, nil);
  if FInputRead <> 0 then begin CloseHandle(FInputRead); FInputRead := 0; end;
  if FInputWrite <> 0 then begin CloseHandle(FInputWrite); FInputWrite := 0; end;
  if FOutputWrite <> 0 then begin CloseHandle(FOutputWrite); FOutputWrite := 0; end;
  if FOutputRead <> 0 then begin CloseHandle(FOutputRead); FOutputRead := 0; end;
end;

procedure TGTermConPty.SetupJobSandbox;
var
  JobInfo: JOBOBJECT_EXTENDED_LIMIT_INFORMATION;
  CpuInfo: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION;
begin
  FJobHandle := CreateJobObjectW(nil, nil);
  if FJobHandle = 0 then
  begin
    Logger.Warn(Format('[ConPTY] CreateJobObject failed: %d', [GetLastError]));
    Exit;
  end;

  FillChar(JobInfo, SizeOf(JobInfo), 0);
  JobInfo.BasicLimitInformation.LimitFlags :=
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE or
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION or
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS or
    JOB_OBJECT_LIMIT_JOB_MEMORY or
    JOB_OBJECT_LIMIT_PROCESS_MEMORY;
  JobInfo.BasicLimitInformation.ActiveProcessLimit := 30;
  JobInfo.ProcessMemoryLimit := SIZE_T(512) * 1024 * 1024;
  JobInfo.JobMemoryLimit := SIZE_T(512) * 1024 * 1024;

  if not SetInformationJobObject(FJobHandle, 9, @JobInfo, SizeOf(JobInfo)) then
    Logger.Warn(Format('[ConPTY] SetInformationJobObject (memory) failed: %d', [GetLastError]))
  else
    Logger.Info('[ConPTY] Job Object sandbox created (kill-on-close, max 30 procs, 512MB RAM limit)');

  FillChar(CpuInfo, SizeOf(CpuInfo), 0);
  CpuInfo.ControlFlags := JOB_OBJECT_CPU_RATE_CONTROL_ENABLE or JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
  CpuInfo.CpuRate := 5000;
  SetInformationJobObject(FJobHandle, 6, @CpuInfo, SizeOf(CpuInfo));

  var UiInfo: JOBOBJECT_BASIC_UI_RESTRICTIONS;
  FillChar(UiInfo, SizeOf(UiInfo), 0);
  UiInfo.UIRestrictionsClass := JOB_OBJECT_UILIMIT_DESKTOP or JOB_OBJECT_UILIMIT_HANDLES;
  if not SetInformationJobObject(FJobHandle, 4, @UiInfo, SizeOf(UiInfo)) then
    Logger.Warn(Format('[ConPTY] SetInformationJobObject (UI limits) failed: %d', [GetLastError]));
end;

const
  SANDBOX_DESKTOP_NAME = 'GTermBoxSandbox';
  SANDBOX_DESKTOP_SDDL = 'D:(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)(A;;GA;;;AC)';

var
  GSandboxDesktopLock: TCriticalSection = nil;
  GUserDesktops: TDictionary<string, THandle> = nil;
  GUserDesktopPaths: TDictionary<string, string> = nil;

procedure TGTermConPty.GrantDirAccessToAppContainer(const ADir: string; AFullAccess: Boolean);
var
  OldDacl: Pointer;
  Sd: Pointer;
  AclInfo: TACL_SIZE_INFORMATION;
  NewAclSize: DWORD;
  NewDacl: Pointer;
  AcePtr: Pointer;
  I: DWORD;
  AccessMask: DWORD;
  WinDir: string;
  CleanDir: string;
  AlreadyGranted: Boolean;
begin
  if ADir = '' then Exit;

  WinDir := ExcludeTrailingPathDelimiter(LowerCase(GetEnvironmentVariable('SystemRoot')));
  CleanDir := ExcludeTrailingPathDelimiter(LowerCase(ADir));
  if (WinDir <> '') and ((CleanDir = WinDir) or StartsText(WinDir + '\', CleanDir)) then
    Exit;

  if not DirectoryExists(ADir) then
    ForceDirectories(ADir);
  if not DirectoryExists(ADir) then Exit;
  if FAppContainerSid = nil then Exit;

  var FileAttr: DWORD;
  FileAttr := GetFileAttributesW(PWideChar(ADir));
  if (FileAttr <> INVALID_FILE_ATTRIBUTES) and ((FileAttr and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
  begin
    Logger.Warn(Format('[ConPTY] Skipping reparse point: %s', [ADir]));
    Exit;
  end;

  if AFullAccess then
    AccessMask := FILE_ALL_ACCESS
  else
    AccessMask := FILE_GENERIC_READ_EXECUTE;

  if GSandboxDesktopLock <> nil then
    GSandboxDesktopLock.Enter;
  try
    Sd := nil;
    OldDacl := nil;
    if GetNamedSecurityInfoW(PWideChar(ADir), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
         nil, nil, @OldDacl, nil, @Sd) <> 0 then
    begin
      Logger.Warn(Format('[ConPTY] GetNamedSecurityInfo failed for: %s', [ADir]));
      Exit;
    end;

    try
      FillChar(AclInfo, SizeOf(AclInfo), 0);
      AlreadyGranted := False;
      if (OldDacl <> nil) and GetAclInformation(OldDacl, @AclInfo, SizeOf(AclInfo), AclSizeInformation) and (AclInfo.AceCount > 0) then
      begin
        for I := 0 to AclInfo.AceCount - 1 do
          if GetAce(OldDacl, I, AcePtr) then
          begin
            if (PByte(AcePtr)^ = 0) and EqualSid(PSID(PByte(AcePtr) + 8), FAppContainerSid) and
               ((PDWORD(PByte(AcePtr) + 4)^ and AccessMask) = AccessMask) then
            begin
              AlreadyGranted := True;
              Break;
            end;
          end;
      end;

      if AlreadyGranted then
        Exit;

      NewAclSize := AclInfo.AclBytesInUse + ACCESS_ALLOWED_ACE_HEADER_SIZE + GetLengthSid(FAppContainerSid) + 32;
      GetMem(NewDacl, NewAclSize);
      try
        if not InitializeAcl(NewDacl, NewAclSize, ACL_REVISION) then
          Logger.Error(Format('[ConPTY] InitializeAcl failed: %d', [GetLastError]));

        if not AddAccessAllowedAceEx(NewDacl, ACL_REVISION, OBJECT_INHERIT_ACE or CONTAINER_INHERIT_ACE, AccessMask, FAppContainerSid) then
          Logger.Error(Format('[ConPTY] AddAccessAllowedAceEx failed: %d', [GetLastError]));

        if (OldDacl <> nil) and (AclInfo.AceCount > 0) then
          for I := 0 to AclInfo.AceCount - 1 do
            if GetAce(OldDacl, I, AcePtr) then
              if not EqualSid(PSID(PByte(AcePtr) + 8), FAppContainerSid) then
                AddAce(NewDacl, ACL_REVISION, MAXDWORD, AcePtr,
                  PDWORD(AcePtr)^ shr 16);

        var SetRes := SetNamedSecurityInfoW(PWideChar(ADir), SE_FILE_OBJECT,
             DACL_SECURITY_INFORMATION, nil, nil, NewDacl, nil);
        if SetRes = 0 then
        begin
          Logger.Info(Format('[ConPTY] Granted AppContainer access to: %s', [ADir]));
          var FoundDir := False;
          for var G in FGrantedDirs do
            if SameText(G, ADir) then begin FoundDir := True; Break; end;
          if not FoundDir then
          begin
            SetLength(FGrantedDirs, Length(FGrantedDirs) + 1);
            FGrantedDirs[High(FGrantedDirs)] := ADir;
          end;
        end
        else
        begin
          Logger.Warn(Format('[ConPTY] SetNamedSecurityInfo failed (%d) for: %s, attempting icacls fallback...', [SetRes, ADir]));
          var StrSid: LPWSTR := nil;
          if ConvertSidToStringSidW(FAppContainerSid, StrSid) and (StrSid <> nil) then
          begin
            try
              var SidStr := string(StrSid);
              var PermStr: string;
              if AFullAccess then PermStr := ':(OI)(CI)F' else PermStr := ':(OI)(CI)RX';
              var IcaclsCmd := Format('icacls "%s" /grant "*%s%s" /T /Q', [ADir, SidStr, PermStr]);
              var SI: TStartupInfo;
              var PI: TProcessInformation;
              FillChar(SI, SizeOf(SI), 0);
              SI.cb := SizeOf(SI);
              SI.dwFlags := STARTF_USESHOWWINDOW;
              SI.wShowWindow := SW_HIDE;
              UniqueString(IcaclsCmd);
              if CreateProcess(nil, PChar(IcaclsCmd), nil, nil, False, CREATE_NO_WINDOW, nil, nil, SI, PI) then
              begin
                if WaitForSingleObject(PI.hProcess, 10000) = WAIT_OBJECT_0 then
                begin
                  var ExitCode: DWORD := 0;
                  if GetExitCodeProcess(PI.hProcess, ExitCode) and (ExitCode = 0) then
                  begin
                    Logger.Info(Format('[ConPTY] icacls granted AppContainer access to: %s', [ADir]));
                    var FoundDir := False;
                    for var G in FGrantedDirs do
                      if SameText(G, ADir) then begin FoundDir := True; Break; end;
                    if not FoundDir then
                    begin
                      SetLength(FGrantedDirs, Length(FGrantedDirs) + 1);
                      FGrantedDirs[High(FGrantedDirs)] := ADir;
                    end;
                  end
                  else
                    Logger.Warn(Format('[ConPTY] icacls fallback failed with exit code %d for: %s', [ExitCode, ADir]));
                end
                else
                begin
                  TerminateProcess(PI.hProcess, 1);
                  Logger.Warn(Format('[ConPTY] icacls fallback timed out for: %s', [ADir]));
                end;
                CloseHandle(PI.hProcess);
                CloseHandle(PI.hThread);
              end;
            finally
              LocalFree(HLOCAL(StrSid));
            end;
          end;
        end;
      finally
        FreeMem(NewDacl);
      end;
    finally
      if Sd <> nil then LocalFree(HLOCAL(Sd));
    end;
  finally
    if GSandboxDesktopLock <> nil then
      GSandboxDesktopLock.Leave;
  end;
end;

function GetSandboxDesktopPath(const AUsername: string = ''): string;
var
  Sd: Pointer;
  Sa: TSecurityAttributes;
  WinStaName: array[0..255] of WideChar;
  Needed: DWORD;
  CleanUser: string;
  DeskName: string;
  HDesk: THandle;
begin
  Result := '';
  CleanUser := Trim(AUsername);
  if CleanUser = '' then CleanUser := 'default';
  DeskName := 'GTermBox_' + CleanUser;

  if GSandboxDesktopLock = nil then Exit;
  GSandboxDesktopLock.Enter;
  try
    if (GUserDesktopPaths <> nil) and GUserDesktopPaths.TryGetValue(CleanUser, Result) and (Result <> '') then
      Exit;

    FillChar(WinStaName, SizeOf(WinStaName), 0);
    Needed := 0;
    if not GetUserObjectInformationW(GetProcessWindowStation, UOI_NAME, @WinStaName[0], SizeOf(WinStaName), Needed) then
    begin
      Logger.Warn(Format('[ConPTY] GetUserObjectInformation failed: %d', [GetLastError]));
      Exit;
    end;

    Sd := nil;
    if not ConvertStringSecurityDescriptorToSecurityDescriptorW(PWideChar(SANDBOX_DESKTOP_SDDL), 1, Sd, nil) then
    begin
      Logger.Warn(Format('[ConPTY] Sandbox desktop SDDL conversion failed: %d', [GetLastError]));
      Exit;
    end;
    try
      FillChar(Sa, SizeOf(Sa), 0);
      Sa.nLength := SizeOf(Sa);
      Sa.lpSecurityDescriptor := Sd;
      Sa.bInheritHandle := False;
      HDesk := CreateDesktopW(PWideChar(DeskName), nil, nil, 0, GENERIC_ALL, @Sa);
    finally
      LocalFree(HLOCAL(Sd));
    end;

    if HDesk = 0 then
    begin
      Logger.Warn(Format('[ConPTY] CreateDesktop failed for "%s": %d', [DeskName, GetLastError]));
      Exit;
    end;

    Result := string(PWideChar(@WinStaName[0])) + '\' + DeskName;
    if GUserDesktops <> nil then
      GUserDesktops.AddOrSetValue(CleanUser, HDesk);
    if GUserDesktopPaths <> nil then
      GUserDesktopPaths.AddOrSetValue(CleanUser, Result);
    Logger.Info(Format('[ConPTY] User sandbox desktop ready: %s', [Result]));
  finally
    GSandboxDesktopLock.Leave;
  end;
end;

procedure FreeNetworkCapabilities(var ACaps: TArray<SID_AND_ATTRIBUTES>);
var
  I: Integer;
begin
  for I := 0 to High(ACaps) do
  begin
    if ACaps[I].Sid <> nil then
      LocalFree(HLOCAL(ACaps[I].Sid));
  end;
  SetLength(ACaps, 0);
end;

function TGTermConPty.SetupAppContainer(const AWorkingDir: string; const AExeDir: string = ''; const AAllowedDirsRead: TArray<string> = nil; const AAllowedDirsWrite: TArray<string> = nil; const ANetworkCaps: TArray<SID_AND_ATTRIBUTES> = nil): Boolean;
var
  Hr: HRESULT;
  TempSid: PSID;
  ContainerName: string;
  ServerDir: string;
  ExtraDir: string;
  CapsPtr: Pointer;
  CapsCount: DWORD;
  PathHash: string;
begin
  var Leaf := ExtractFileName(ExcludeTrailingPathDelimiter(AWorkingDir));
  var SafeLeaf := '';
  for var Ch in Leaf do
    if CharInSet(Ch, ['a'..'z', 'A'..'Z', '0'..'9', '_', '-']) then
      SafeLeaf := SafeLeaf + Ch;
  if SafeLeaf = '' then
    SafeLeaf := Copy(TGUID.NewGuid.ToString, 2, 36);

  PathHash := Copy(THashSHA2.GetHashString(TPath.GetFullPath(AWorkingDir)), 1, 12);
  ContainerName := 'GTermBox.' + SafeLeaf + '.' + PathHash;
  FAppContainerName := ContainerName;

  CapsPtr := nil;
  CapsCount := 0;
  if Length(ANetworkCaps) > 0 then
  begin
    CapsPtr := @ANetworkCaps[0];
    CapsCount := Length(ANetworkCaps);
  end;

  Hr := CreateAppContainerProfile(
    PWideChar(ContainerName),
    PWideChar('GTermBox App'),
    PWideChar('GTermBox terminal sandbox'),
    CapsPtr, CapsCount,
    TempSid);

  if Hr = HRESULT($800700B7) then
  begin
    Hr := DeriveAppContainerSidFromAppContainerName(
      PWideChar(ContainerName), TempSid);
    if FAILED(Hr) then
    begin
      Logger.Error(Format('[ConPTY] DeriveAppContainerSid failed: 0x%x', [Hr]));
      FAppContainerName := '';
      Exit(False);
    end;
    Logger.Info(Format('[ConPTY] AppContainer profile reused: %s', [ContainerName]));
  end
  else if FAILED(Hr) then
  begin
    Logger.Error(Format('[ConPTY] CreateAppContainerProfile failed: 0x%x', [Hr]));
    FAppContainerName := '';
    Exit(False);
  end
  else
    Logger.Info(Format('[ConPTY] AppContainer profile created: %s', [ContainerName]));

  FAppContainerSid := TempSid;

  ServerDir := ExcludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0)));

  if (AExeDir <> '') and not SameText(ExcludeTrailingPathDelimiter(AExeDir), ServerDir) then
    GrantDirAccessToAppContainer(AExeDir, False);
  if (AWorkingDir <> '') and not SameText(ExcludeTrailingPathDelimiter(AWorkingDir), ServerDir) and
     not SameText(ExcludeTrailingPathDelimiter(AWorkingDir), ExcludeTrailingPathDelimiter(AExeDir)) then
    GrantDirAccessToAppContainer(AWorkingDir, True);

  for ExtraDir in AAllowedDirsRead do
  begin
    if (ExtraDir <> '') and (ExtraDir <> '*') and DirectoryExists(ExtraDir) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ServerDir) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ExcludeTrailingPathDelimiter(AExeDir)) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ExcludeTrailingPathDelimiter(AWorkingDir)) then
      GrantDirAccessToAppContainer(ExtraDir, False);
  end;

  for ExtraDir in AAllowedDirsWrite do
  begin
    if (ExtraDir <> '') and (ExtraDir <> '*') and DirectoryExists(ExtraDir) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ServerDir) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ExcludeTrailingPathDelimiter(AExeDir)) and
       not SameText(ExcludeTrailingPathDelimiter(ExtraDir), ExcludeTrailingPathDelimiter(AWorkingDir)) then
      GrantDirAccessToAppContainer(ExtraDir, True);
  end;

  Result := True;
end;

procedure TGTermConPty.RevokeDirAccessFromAppContainer(const ADir: string);
var
  OldDacl, Sd, AcePtr: Pointer;
  AclInfo: TACL_SIZE_INFORMATION;
  I: Integer;
begin
  if (ADir = '') or (FAppContainerSid = nil) or not DirectoryExists(ADir) then Exit;
  Sd := nil;
  OldDacl := nil;
  if GetNamedSecurityInfoW(PWideChar(ADir), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
       nil, nil, @OldDacl, nil, @Sd) <> 0 then Exit;
  try
    if OldDacl = nil then Exit;
    FillChar(AclInfo, SizeOf(AclInfo), 0);
    GetAclInformation(OldDacl, @AclInfo, SizeOf(AclInfo), AclSizeInformation);
    for I := Integer(AclInfo.AceCount) - 1 downto 0 do
    begin
      if GetAce(OldDacl, DWORD(I), AcePtr) then
      begin
        if EqualSid(PSID(PByte(AcePtr) + 8), FAppContainerSid) then
          DeleteAce(OldDacl, DWORD(I));
      end;
    end;
    SetNamedSecurityInfoW(PWideChar(ADir), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, OldDacl, nil);
  finally
    if Sd <> nil then LocalFree(HLOCAL(Sd));
  end;
end;

procedure TGTermConPty.CleanupSandbox;
var
  D: string;
begin
  if FJobHandle <> 0 then
  begin
    CloseHandle(FJobHandle);
    FJobHandle := 0;
  end;

  if FAppContainerSid <> nil then
  begin
    for D in FGrantedDirs do
      RevokeDirAccessFromAppContainer(D);
    SetLength(FGrantedDirs, 0);

    FreeSid(FAppContainerSid);
    FAppContainerSid := nil;
  end;

  FAppContainerName := '';
end;

procedure TGTermConPty.SetupPowerShellProfile(const AWorkingDir: string; const AExtraEnv: TArray<string> = nil);
const
  PS_PROFILE_CONTENT = '(Get-PSProvider FileSystem).Home = $env:USERPROFILE' + #13#10 +
                       'New-PSDrive -Name home -PSProvider FileSystem -Root "$env:USERPROFILE" | Out-Null' + #13#10 +
                       'Microsoft.PowerShell.Management\Set-Location -LiteralPath ''home:\''' + #13#10 +
                       'New-Item -Path Function:\__GTermResolve -Options Constant,AllScope -Value {' + #13#10 +
                       '  param([string]$RawPath)' + #13#10 +
                       '  $root = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd(''\'', ''/'')' + #13#10 +
                       '  $base = (Microsoft.PowerShell.Management\Get-Location).ProviderPath.TrimEnd(''\'', ''/'')' + #13#10 +
                       '  if (-not $base.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { $base = $root }' + #13#10 +
                       '  if (-not $RawPath) { return $base }' + #13#10 +
                       '  if (($RawPath -match ''^[a-zA-Z0-9_]+:'' -and $RawPath -notmatch ''^(?i)home:'') -or ($RawPath -match ''^\\\\'')) { return $null }' + #13#10 +
                       '  $clean = $RawPath' + #13#10 +
                       '  if ($clean -match ''^(?i)home:([\\/]|$)'') { $base = $root; $clean = $clean -replace ''^(?i)home:[\\/]*'', '''' }' + #13#10 +
                       '  elseif ($clean -match ''^(?i)home:'') { $clean = $clean -replace ''^(?i)home:'', '''' }' + #13#10 +
                       '  if ($clean -match ''^~([\\/]|$)'') { $base = $root; $clean = $clean -replace ''^~[\\/]*'', '''' }' + #13#10 +
                       '  if (-not $clean) { return $base }' + #13#10 +
                       '  try {' + #13#10 +
                       '    $full = if ([System.IO.Path]::IsPathRooted($clean)) { [System.IO.Path]::GetFullPath($clean) } else { [System.IO.Path]::GetFullPath((Join-Path $base $clean)) }' + #13#10 +
                       '  } catch { return $null }' + #13#10 +
                       '  $fullTrim = $full.TrimEnd(''\'', ''/'')' + #13#10 +
                       '  if ($fullTrim.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or $fullTrim.StartsWith($root + ''\'', [System.StringComparison]::OrdinalIgnoreCase)) { return $fullTrim }' + #13#10 +
                       '  return $null' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Set-Location -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param([Parameter(Position=0, ValueFromPipeline=$true)][string]$Path = ''home:\'', [string]$LiteralPath)' + #13#10 +
                       '  $t = if ($LiteralPath) { $LiteralPath } else { $Path }' + #13#10 +
                       '  $full = __GTermResolve $t' + #13#10 +
                       '  if (-not $full) {' + #13#10 +
                       '    $ex = New-Object System.UnauthorizedAccessException("Access to the path ''$t'' is denied.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''PathAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $t)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '  $root = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd(''\'', ''/'')' + #13#10 +
                       '  $rel = $full.Substring($root.Length).TrimStart(''\'', ''/'')' + #13#10 +
                       '  $targetHome = if ($rel) { "home:\$rel" } else { ''home:\'' }' + #13#10 +
                       '  Microsoft.PowerShell.Management\Set-Location -LiteralPath $targetHome' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Push-Location -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param([Parameter(Position=0, ValueFromPipeline=$true)][string]$Path = ''home:\'', [string]$LiteralPath)' + #13#10 +
                       '  $t = if ($LiteralPath) { $LiteralPath } else { $Path }' + #13#10 +
                       '  $full = __GTermResolve $t' + #13#10 +
                       '  if (-not $full) {' + #13#10 +
                       '    $ex = New-Object System.UnauthorizedAccessException("Access to the path ''$t'' is denied.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''PathAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $t)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '  $root = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd(''\'', ''/'')' + #13#10 +
                       '  $rel = $full.Substring($root.Length).TrimStart(''\'', ''/'')' + #13#10 +
                       '  $targetHome = if ($rel) { "home:\$rel" } else { ''home:\'' }' + #13#10 +
                       '  Microsoft.PowerShell.Management\Push-Location -LiteralPath $targetHome' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Get-ChildItem -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param([Parameter(Position=0, ValueFromPipeline=$true)][string]$Path, [string]$LiteralPath, [string]$Filter, [switch]$Force, [switch]$Recurse, [switch]$Name)' + #13#10 +
                       '  $t = if ($LiteralPath) { $LiteralPath } else { $Path }' + #13#10 +
                       '  if ($t -match ''^(?i)env:[\\/]*$'') { Microsoft.PowerShell.Management\Get-ChildItem -Path Env:; return }' + #13#10 +
                       '  $check = if ($t) { $t -replace ''[\*\?]'', ''_'' } else { '''' }' + #13#10 +
                       '  $full = __GTermResolve $check' + #13#10 +
                       '  if (-not $full) {' + #13#10 +
                       '    $ex = New-Object System.UnauthorizedAccessException("Access to the path ''$t'' is denied.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''DirUnauthorizedAccessError'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $t)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '  $root = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd(''\'', ''/'')' + #13#10 +
                       '  $rel = $full.Substring($root.Length).TrimStart(''\'', ''/'')' + #13#10 +
                       '  $targetHome = if ($rel) { "home:\$rel" } else { ''home:\'' }' + #13#10 +
                       '  if ($t -match ''[\*\?]'') {' + #13#10 +
                       '    $wrel = ($t -replace ''^(?i)home:[\\/]*'', '''').TrimStart(''\'', ''/'')' + #13#10 +
                       '    $p = @{ Path = "home:\$wrel" }' + #13#10 +
                       '  } else { $p = @{ LiteralPath = $targetHome } }' + #13#10 +
                       '  if ($Filter) { $p[''Filter''] = $Filter }' + #13#10 +
                       '  if ($Force) { $p[''Force''] = $true }' + #13#10 +
                       '  if ($Recurse) { $p[''Recurse''] = $true }' + #13#10 +
                       '  if ($Name) { $p[''Name''] = $true }' + #13#10 +
                       '  Microsoft.PowerShell.Management\Get-ChildItem @p' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\New-PSDrive -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param()' + #13#10 +
                       '  $ex = New-Object System.UnauthorizedAccessException("Creating new PSDrives is denied in sandbox.")' + #13#10 +
                       '  $er = New-Object System.Management.Automation.ErrorRecord($ex, ''PSDriveAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)' + #13#10 +
                       '  $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Remove-PSDrive -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param()' + #13#10 +
                       '  $ex = New-Object System.UnauthorizedAccessException("Removing PSDrives is denied in sandbox.")' + #13#10 +
                       '  $er = New-Object System.Management.Automation.ErrorRecord($ex, ''PSDriveAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)' + #13#10 +
                       '  $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\powershell -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param()' + #13#10 +
                       '  $ex = New-Object System.UnauthorizedAccessException("Spawning nested PowerShell processes is denied in sandbox.")' + #13#10 +
                       '  $er = New-Object System.Management.Automation.ErrorRecord($ex, ''SubshellAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)' + #13#10 +
                       '  $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\powershell.exe -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param()' + #13#10 +
                       '  $ex = New-Object System.UnauthorizedAccessException("Spawning nested PowerShell processes is denied in sandbox.")' + #13#10 +
                       '  $er = New-Object System.Management.Automation.ErrorRecord($ex, ''SubshellAccessDenied'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)' + #13#10 +
                       '  $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Get-Location -Options Constant,AllScope -Value {' + #13#10 +
                       '  if ((Microsoft.PowerShell.Management\Get-Location).Drive.Name -ne ''home'') { Microsoft.PowerShell.Management\Set-Location -LiteralPath ''home:\'' -ErrorAction SilentlyContinue }' + #13#10 +
                       '  if ([System.IO.Directory]::GetCurrentDirectory() -ne $env:USERPROFILE) { [System.IO.Directory]::SetCurrentDirectory($env:USERPROFILE) }' + #13#10 +
                       '  Microsoft.PowerShell.Management\Get-Location @args' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'New-Item -Path Function:\Remove-Item -Options Constant,AllScope -Value {' + #13#10 +
                       '  [CmdletBinding()] param([Parameter(Position=0, ValueFromPipeline=$true)][string]$Path, [string]$LiteralPath, [switch]$Force, [switch]$Recurse)' + #13#10 +
                       '  $t = if ($LiteralPath) { $LiteralPath } else { $Path }' + #13#10 +
                       '  if (-not $t) { return }' + #13#10 +
                       '  if ($t -match ''^(Function:|Alias:|Variable:|Env:|HKLM:|HKCU:|Cert:|WSMan:)'' ) {' + #13#10 +
                       '    $ex = New-Object System.UnauthorizedAccessException("Access to the path ''$t'' is denied.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''RemoveItemUnauthorizedAccessError'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $t)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '  $full = __GTermResolve $t' + #13#10 +
                       '  $root = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd(''\'', ''/'')' + #13#10 +
                       '  if ((-not $full) -or ($full.Length -le $root.Length) -or ($full -match ''(?i)\\Documents(\\(Windows)?PowerShell|$)'')) {' + #13#10 +
                       '    $ex = New-Object System.UnauthorizedAccessException("Access to the path ''$t'' is denied.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''RemoveItemUnauthorizedAccessError'', [System.Management.Automation.ErrorCategory]::PermissionDenied, $t)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '  if ([System.IO.File]::Exists($full)) { [System.IO.File]::Delete($full) }' + #13#10 +
                       '  elseif ([System.IO.Directory]::Exists($full)) { [System.IO.Directory]::Delete($full, [bool]$Recurse) }' + #13#10 +
                       '  else {' + #13#10 +
                       '    $ex = New-Object System.IO.FileNotFoundException("Cannot find path ''$full'' because it does not exist.")' + #13#10 +
                       '    $er = New-Object System.Management.Automation.ErrorRecord($ex, ''PathNotFound'', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $full)' + #13#10 +
                       '    $PSCmdlet.ThrowTerminatingError($er)' + #13#10 +
                       '  }' + #13#10 +
                       '} | Out-Null' + #13#10 +
                       'Microsoft.PowerShell.Management\Remove-Item -Path Function:\prompt -Force -ErrorAction SilentlyContinue' + #13#10 +
                       'New-Item -Path Function:\prompt -Options Constant,AllScope -Value {' + #13#10 +
                       '  if ((Microsoft.PowerShell.Management\Get-Location).Drive.Name -ne ''home'') { Microsoft.PowerShell.Management\Set-Location -LiteralPath ''home:\'' -ErrorAction SilentlyContinue }' + #13#10 +
                       '  if ([System.IO.Directory]::GetCurrentDirectory() -ne $env:USERPROFILE) { [System.IO.Directory]::SetCurrentDirectory($env:USERPROFILE) }' + #13#10 +
                       '  "PS $($executionContext.SessionState.Path.CurrentLocation)$(''>'' * ($nestedPromptLevel + 1)) "' + #13#10 +
                       '} | Out-Null' + #13#10;
  PS_GUI_BLOCKER     = '$ExecutionContext.InvokeCommand.PostCommandLookupAction = {' + #13#10 +
                       '  param($cmdName, $cmdArgs)' + #13#10 +
                       '  if ($cmdArgs.Command -and ($cmdArgs.Command.CommandType -eq ''Application'')) {' + #13#10 +
                       '    $p = $cmdArgs.Command.Path' + #13#10 +
                       '    if ($p -and [System.IO.File]::Exists($p)) {' + #13#10 +
                       '      try {' + #13#10 +
                       '        $fs = [System.IO.File]::OpenRead($p)' + #13#10 +
                       '        $buf = [byte[]]::new(1024)' + #13#10 +
                       '        $null = $fs.Read($buf, 0, 1024)' + #13#10 +
                       '        $fs.Close()' + #13#10 +
                       '        if ($buf[0] -eq 0x4D -and $buf[1] -eq 0x5A) {' + #13#10 +
                       '          $peOff = [System.BitConverter]::ToInt32($buf, 0x3C)' + #13#10 +
                       '          if ($peOff -gt 0 -and ($peOff + 94) -lt $buf.Length) {' + #13#10 +
                       '            if ([System.BitConverter]::ToUInt16($buf, $peOff + 24 + 68) -eq 2) {' + #13#10 +
                       '              [Console]::WriteLine("[GTermBox Warning] ''" + $cmdName + "'' is a graphical (GUI) application. GUI windows are isolated on the background sandbox desktop.")' + #13#10 +
                       '            }' + #13#10 +
                       '          }' + #13#10 +
                       '        }' + #13#10 +
                       '      } catch {}' + #13#10 +
                       '    }' + #13#10 +
                       '  }' + #13#10 +
                       '}' + #13#10;
var
  ProfileDir5: string;
  ProfileFile5: string;
  ProfileDir7: string;
  ProfileFile7: string;
  SL: TStringList;
  MustRestrict: Boolean;
  EnvVar: string;
  ProfileContent: string;
begin
  ProfileDir5  := TPath.Combine(AWorkingDir, 'Documents\WindowsPowerShell');
  ProfileFile5 := TPath.Combine(ProfileDir5,  'Microsoft.PowerShell_profile.ps1');
  ProfileDir7  := TPath.Combine(AWorkingDir, 'Documents\PowerShell');
  ProfileFile7 := TPath.Combine(ProfileDir7,  'Microsoft.PowerShell_profile.ps1');

  MustRestrict := False;
  if FSandboxMode = smStandard then
    MustRestrict := True
  else
  begin
    for EnvVar in AExtraEnv do
      if SameText(EnvVar, 'GTERM_RESTRICT_PS=1') then
      begin
        MustRestrict := True;
        Break;
      end;
  end;

  ForceDirectories(ProfileDir5);
  ForceDirectories(ProfileDir7);

  var Attr5, Attr7: DWORD;
  Attr5 := GetFileAttributesW(PWideChar(ProfileFile5));
  if (Attr5 <> INVALID_FILE_ATTRIBUTES) and ((Attr5 and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    Exit;
  Attr7 := GetFileAttributesW(PWideChar(ProfileFile7));
  if (Attr7 <> INVALID_FILE_ATTRIBUTES) and ((Attr7 and FILE_ATTRIBUTE_REPARSE_POINT) <> 0) then
    Exit;

  ProfileContent := PS_GUI_BLOCKER;
  if MustRestrict then
    ProfileContent := ProfileContent + PS_PROFILE_CONTENT;

  SL := TStringList.Create;
  try
    SL.Text := ProfileContent;
    if (not FileExists(ProfileFile5)) or (TFile.ReadAllText(ProfileFile5, TEncoding.UTF8) <> ProfileContent) then
    begin
      SetFileAttributesW(PWideChar(ProfileFile5), FILE_ATTRIBUTE_NORMAL);
      SL.SaveToFile(ProfileFile5, TEncoding.UTF8);
      Logger.Info(Format('[ConPTY] PS profile updated: %s', [ProfileFile5]));
    end;
    SetFileAttributesW(PWideChar(ProfileFile5), FILE_ATTRIBUTE_READONLY);
    if (not FileExists(ProfileFile7)) or (TFile.ReadAllText(ProfileFile7, TEncoding.UTF8) <> ProfileContent) then
    begin
      SetFileAttributesW(PWideChar(ProfileFile7), FILE_ATTRIBUTE_NORMAL);
      SL.SaveToFile(ProfileFile7, TEncoding.UTF8);
      Logger.Info(Format('[ConPTY] PS7 profile updated: %s', [ProfileFile7]));
    end;
    SetFileAttributesW(PWideChar(ProfileFile7), FILE_ATTRIBUTE_READONLY);
  finally
    SL.Free;
  end;

  if FAppContainerSid <> nil then
  begin
    GrantDirAccessToAppContainer(ProfileDir5, False);
    GrantDirAccessToAppContainer(ProfileDir7, False);
  end;
end;

function TGTermConPty.BuildSandboxEnvironment(const AWorkingDir: string; const AExtraEnv: TArray<string>): string;
var
  EnvMap: TStringList;
  RawEnv: PWideChar;
  P: PWideChar;
  I: Integer;
  Line: string;
  EqPos: Integer;
  AppDataVal, LocalAppDataVal, TempVal: string;
  DrivePart, PathPart, PathVal: string;
begin
  EnvMap := TStringList.Create;
  EnvMap.NameValueSeparator := '=';
  EnvMap.CaseSensitive := False;
  try
    RawEnv := GetEnvironmentStringsW;
    try
      P := RawEnv;
      while P^ <> #0 do
      begin
        Line := WideCharToString(P);
        if (Line <> '') and (Line[1] <> '=') then
        begin
          EqPos := Pos('=', Line);
          if EqPos > 1 then
            EnvMap.Values[Copy(Line, 1, EqPos - 1)] := Copy(Line, EqPos + 1, MaxInt);
        end;
        Inc(P, Length(Line) + 1);
      end;
    finally
      FreeEnvironmentStringsW(RawEnv);
    end;

    if AWorkingDir <> '' then
    begin
      AppDataVal      := TPath.Combine(AWorkingDir, 'AppData\Roaming');
      LocalAppDataVal := TPath.Combine(AWorkingDir, 'AppData\Local');
      TempVal         := TPath.Combine(AWorkingDir, 'tmp');

      ForceDirectories(AppDataVal);
      ForceDirectories(LocalAppDataVal);
      ForceDirectories(TempVal);
      ForceDirectories(TPath.Combine(AWorkingDir, 'Documents\WindowsPowerShell'));

      if FAppContainerSid <> nil then
      begin
        GrantDirAccessToAppContainer(TPath.Combine(AWorkingDir, 'AppData'), True);
        GrantDirAccessToAppContainer(AppDataVal, True);
        GrantDirAccessToAppContainer(LocalAppDataVal, True);
        GrantDirAccessToAppContainer(TempVal, True);
        GrantDirAccessToAppContainer(TPath.Combine(AWorkingDir, 'Documents'), True);
        GrantDirAccessToAppContainer(TPath.Combine(AWorkingDir, 'Documents\WindowsPowerShell'), True);
      end;

      DrivePart := ExtractFileDrive(AWorkingDir);
      PathPart  := Copy(AWorkingDir, Length(DrivePart) + 1, MaxInt);
      PathVal   := EnvMap.Values['PATH'];

      EnvMap.Values['USERPROFILE']  := AWorkingDir;
      EnvMap.Values['APPDATA']      := AppDataVal;
      EnvMap.Values['LOCALAPPDATA'] := LocalAppDataVal;
      EnvMap.Values['HOMEDRIVE']    := DrivePart;
      EnvMap.Values['HOMEPATH']     := PathPart;
      EnvMap.Values['TEMP']         := TempVal;
      EnvMap.Values['TMP']          := TempVal;
      EnvMap.Values['PATH']         := PathVal + ';' + AWorkingDir;
      EnvMap.Values['PSModulePath'] := GetEnvironmentVariable('SystemRoot') +
                                       '\System32\WindowsPowerShell\v1.0\Modules';
      if TDirectory.Exists(TPath.Combine(AWorkingDir, 'apps\python')) then
      begin
        EnvMap.Values['PYTHONHOME'] := TPath.Combine(AWorkingDir, 'apps\python');
        EnvMap.Values['PYTHONNOUSERSITE'] := '1';
      end
      else if TDirectory.Exists(TPath.Combine(ExtractFilePath(ParamStr(0)), 'Python')) then
      begin
        EnvMap.Values['PYTHONHOME'] := TPath.Combine(ExtractFilePath(ParamStr(0)), 'Python');
        EnvMap.Values['PYTHONNOUSERSITE'] := '1';
      end;

      if DrivePart <> '' then
        EnvMap.Add('=' + DrivePart + '=' + AWorkingDir);

      SetupPowerShellProfile(AWorkingDir, AExtraEnv);
    end;

    for I := 0 to High(AExtraEnv) do
    begin
      Line := AExtraEnv[I];
      EqPos := Pos('=', Line);
      if EqPos > 1 then
        EnvMap.Values[Copy(Line, 1, EqPos - 1)] := Copy(Line, EqPos + 1, MaxInt);
    end;

    for I := EnvMap.Count - 1 downto 0 do
    begin
      var K := LowerCase(EnvMap.Names[I]);
      if (K = 'gterm_jwt_secret') or (K = 'jwt_secret') or (K = 'secret_key') or (K = 'gterm_config') then
        EnvMap.Delete(I);
    end;

    Result := '';
    for I := 0 to EnvMap.Count - 1 do
      Result := Result + EnvMap[I] + #0;
    Result := Result + #0;
  finally
    EnvMap.Free;
  end;
end;

function TGTermConPty.StartProcess(const ACommandLine: string; const AWorkingDir: string = ''; const AAllowedDirsRead: TArray<string> = nil; const AAllowedDirsWrite: TArray<string> = nil; const AEnvironmentVars: TArray<string> = nil; ANetworkAccess: Boolean = False): Boolean;
var
  Size: COORD;
  Hr: HRESULT;
  AttrSize: SIZE_T;
  AttrList: PPROC_THREAD_ATTRIBUTE_LIST;
  SiEx: TStartupInfoExW;
  CmdLineBuf: array[0..32767] of WideChar;
  WorkingDirPtr: PWideChar;
  ExeDir: string;
  CleanCmd: string;
  PQuote, PSpace: Integer;
  NetCaps: TArray<SID_AND_ATTRIBUTES>;
  SecCap: SECURITY_CAPABILITIES;
  UseAppContainer: Boolean;
  DesktopPath: string;
  CreationFlags: DWORD;
  EnvBlock: string;
  EnvPtr: Pointer;
  AttrCount: DWORD;
  InheritedHandles: array[0..1] of THandle;
begin
  Result := False;
  if FRunning then Exit;

  Logger.Info(Format('[ConPTY] Starting process: "%s" (Cols=%d, Rows=%d, Sandbox=%d)',
    [ACommandLine, FCols, FRows, Ord(FSandboxMode)]));

  CreatePipes;

  Size.X := FCols;
  Size.Y := FRows;

  Hr := TGTermConPtyLoader.CreatePseudoConsole(Size, FInputRead, FOutputWrite, 0, @FHPty);
  if FAILED(Hr) then
  begin
    Logger.Error(Format('[ConPTY] CreatePseudoConsole failed: 0x%x', [Hr]));
    ClosePipes;
    Exit(False);
  end;

  SetLength(NetCaps, 0);
  if (FSandboxMode = smStandard) and ANetworkAccess then
    BuildNetworkCapabilities(NetCaps);

  try
    CleanCmd := Trim(ACommandLine);
    if CleanCmd.StartsWith('"') then
    begin
      CleanCmd := Copy(CleanCmd, 2, Length(CleanCmd));
      PQuote := Pos('"', CleanCmd);
      if PQuote > 0 then
        CleanCmd := Copy(CleanCmd, 1, PQuote - 1);
    end
    else
    begin
      PSpace := Pos(' ', CleanCmd);
      if PSpace > 0 then
        CleanCmd := Copy(CleanCmd, 1, PSpace - 1);
    end;
    ExeDir := ExtractFilePath(CleanCmd);

    if FSandboxMode = smStandard then
    begin
      if not SetupAppContainer(AWorkingDir, ExeDir, AAllowedDirsRead, AAllowedDirsWrite, NetCaps) then
      begin
        Logger.Error('[ConPTY] AppContainer setup failed. Aborting process creation (Fail-Closed).');
        ClosePipes;
        Exit(False);
      end;
      UseAppContainer := True;
    end
    else
      UseAppContainer := False;

    InheritedHandles[0] := FInputRead;
    InheritedHandles[1] := FOutputWrite;

    AttrCount := 2;
    if UseAppContainer then
      Inc(AttrCount);

    AttrSize := 0;
    InitializeProcThreadAttributeList(nil, AttrCount, 0, AttrSize);
    GetMem(AttrList, AttrSize);
    try
      if not InitializeProcThreadAttributeList(AttrList, AttrCount, 0, AttrSize) then
      begin
        Logger.Error(Format('[ConPTY] InitializeProcThreadAttributeList failed: %d', [GetLastError]));
        ClosePipes;
        Exit(False);
      end;

      if not UpdateProcThreadAttribute(AttrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
           Pointer(FHPty), SizeOf(HPCON), nil, nil) then
      begin
        Logger.Error(Format('[ConPTY] UpdateProcThreadAttribute (ConPTY) failed: %d', [GetLastError]));
        ClosePipes;
        Exit(False);
      end;

      if not UpdateProcThreadAttribute(AttrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
           @InheritedHandles[0], Length(InheritedHandles) * SizeOf(THandle), nil, nil) then
      begin
        Logger.Error(Format('[ConPTY] UpdateProcThreadAttribute (HandleList) failed: %d', [GetLastError]));
        ClosePipes;
        Exit(False);
      end;

      if UseAppContainer then
      begin
        FillChar(SecCap, SizeOf(SecCap), 0);
        SecCap.AppContainerSid := FAppContainerSid;
        if Length(NetCaps) > 0 then
        begin
          SecCap.Capabilities := @NetCaps[0];
          SecCap.CapabilityCount := Length(NetCaps);
        end
        else
        begin
          SecCap.Capabilities := nil;
          SecCap.CapabilityCount := 0;
        end;

        if not UpdateProcThreadAttribute(AttrList, 0,
             PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
             @SecCap, SizeOf(SecCap), nil, nil) then
        begin
          Logger.Error(Format('[ConPTY] UpdateProcThreadAttribute (AppContainer) failed: %d', [GetLastError]));
          ClosePipes;
          Exit(False);
        end;
      end;

      FillChar(SiEx, SizeOf(SiEx), 0);
      SiEx.StartupInfo.cb := SizeOf(TStartupInfoExW);
      SiEx.StartupInfo.dwFlags := STARTF_USESTDHANDLES;
      SiEx.StartupInfo.hStdInput := 0;
      SiEx.StartupInfo.hStdOutput := 0;
      SiEx.StartupInfo.hStdError := 0;
      SiEx.lpAttributeList := AttrList;

      DesktopPath := GetSandboxDesktopPath(FUsername);
      if DesktopPath <> '' then
        SiEx.StartupInfo.lpDesktop := PWideChar(DesktopPath);

      StringToWideChar(ACommandLine, CmdLineBuf, Length(CmdLineBuf));

      if AWorkingDir <> '' then
        WorkingDirPtr := PWideChar(AWorkingDir)
      else
        WorkingDirPtr := nil;

      SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
      CreationFlags := EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED or CREATE_UNICODE_ENVIRONMENT;

      EnvBlock := BuildSandboxEnvironment(AWorkingDir, AEnvironmentVars);
      EnvPtr := PWideChar(EnvBlock);

      SetConsoleCtrlHandler(nil, False);
      try
        Result := CreateProcessExW(
          nil,
          CmdLineBuf,
          nil,
          nil,
          True,
          CreationFlags,
          EnvPtr,
          WorkingDirPtr,
          SiEx,
          FProcessInfo
        );
      finally
        SetConsoleCtrlHandler(nil, True);
      end;

      if not Result then
        Logger.Error(Format('[ConPTY] CreateProcessW failed: %d for: %s', [GetLastError, ACommandLine]))
      else
      begin
        Logger.Info(Format('[ConPTY] Process created (PID: %d) sandbox=%s network=%s',
          [FProcessInfo.dwProcessId,
           IfThen(FSandboxMode = smStandard, 'standard', IfThen(FSandboxMode = smJobOnly, 'job-only', 'none')),
           IfThen(ANetworkAccess, 'true', 'false')]));
      end;

      DeleteProcThreadAttributeList(AttrList);
    finally
      FreeMem(AttrList);
    end;

  finally
    FreeNetworkCapabilities(NetCaps);
  end;

  if Result then
  begin
    FRunning := True;

    if (FSandboxMode = smStandard) or (FSandboxMode = smJobOnly) then
    begin
      SetupJobSandbox;
      if (FJobHandle = 0) or not AssignProcessToJobObject(FJobHandle, FProcessInfo.hProcess) then
      begin
        Logger.Error(Format('[ConPTY] Failed to assign process to Job Object (LastError: %d). Terminating.', [GetLastError]));
        TerminateProcess(FProcessInfo.hProcess, 1);
        CloseHandle(FProcessInfo.hProcess);
        CloseHandle(FProcessInfo.hThread);
        FillChar(FProcessInfo, SizeOf(FProcessInfo), 0);
        CleanupSandbox;
        StopProcess;
        Exit(False);
      end;
    end;

    ResumeThread(FProcessInfo.hThread);

    if FInputRead <> 0 then begin CloseHandle(FInputRead); FInputRead := 0; end;
    if FOutputWrite <> 0 then begin CloseHandle(FOutputWrite); FOutputWrite := 0; end;

    FReaderThread := TPtyReaderThread.Create(FOutputRead, FStopEvent, FOnDataReceived);
    FWatcherThread := TProcessWatcherThread.Create(FProcessInfo.hProcess, FOnProcessTerminated);
  end
  else
  begin
    CleanupSandbox;
    StopProcess;
  end;
end;

procedure TGTermConPty.StopProcess;
var
  ExitCode: DWORD;
  ReaderToFree: TPtyReaderThread;
  WatcherToFree: TProcessWatcherThread;
begin
  if TInterlocked.CompareExchange(FStopping, 1, 0) <> 0 then Exit;
  if not FRunning and (FHPty = 0) then Exit;
  FRunning := False;

  if FStopEvent <> 0 then
    SetEvent(FStopEvent);
  if FOutputRead <> 0 then
    CancelIoEx(FOutputRead, nil);

  if Assigned(FReaderThread) then
    FReaderThread.ClearHandler;
  if Assigned(FWatcherThread) then
    FWatcherThread.ClearHandler;

  if Assigned(FWatcherThread) then
  begin
    WatcherToFree := FWatcherThread;
    FWatcherThread := nil;
    if WatcherToFree.ThreadID <> GetCurrentThreadId then
    begin
      WatcherToFree.Terminate;
      try
        WatcherToFree.WaitFor;
      except
      end;
      WatcherToFree.Free;
    end
    else
      WatcherToFree.FreeOnTerminate := True;
  end;

  if FProcessInfo.hProcess <> 0 then
  begin
    TerminateProcess(FProcessInfo.hProcess, 0);
    WaitForSingleObject(FProcessInfo.hProcess, 500);
    GetExitCodeProcess(FProcessInfo.hProcess, ExitCode);
    CloseHandle(FProcessInfo.hProcess);
    CloseHandle(FProcessInfo.hThread);
    FillChar(FProcessInfo, SizeOf(FProcessInfo), 0);
  end;

  CleanupSandbox;

  if FHPty <> 0 then
  begin
    TGTermConPtyLoader.ClosePseudoConsole(FHPty);
    FHPty := 0;
  end;

  ClosePipes;

  if Assigned(FReaderThread) then
  begin
    ReaderToFree := FReaderThread;
    FReaderThread := nil;
    if ReaderToFree.ThreadID <> GetCurrentThreadId then
    begin
      ReaderToFree.Terminate;
      try
        ReaderToFree.WaitFor;
      except
      end;
      ReaderToFree.Free;
    end
    else
      ReaderToFree.FreeOnTerminate := True;
  end;
end;

function TGTermConPty.Resize(ACols, ARows: Integer): Boolean;
var
  Size: COORD;
  Hr: HRESULT;
begin
  Result := False;
  if ACols < 10 then ACols := 10;
  if ACols > 500 then ACols := 500;
  if ARows < 5 then ARows := 5;
  if ARows > 200 then ARows := 200;
  FCols := ACols;
  FRows := ARows;
  if FHPty <> 0 then
  begin
    Size.X := ACols;
    Size.Y := ARows;
    Hr := TGTermConPtyLoader.ResizePseudoConsole(FHPty, Size);
    Result := SUCCEEDED(Hr);
  end;
end;

function TGTermConPty.WriteInput(const AData: TBytes): Integer;
var
  BytesWritten: DWORD;
begin
  Result := 0;
  if Length(AData) = 0 then Exit;

  if FInputWrite <> 0 then
  begin
    BytesWritten := 0;
    if WriteFile(FInputWrite, AData[0], Length(AData), BytesWritten, nil) then
      Result := Integer(BytesWritten);
  end;
end;

function TGTermConPty.WriteInput(const AStr: string): Integer;
var
  Bytes: TBytes;
begin
  Bytes := TEncoding.UTF8.GetBytes(AStr);
  Result := WriteInput(Bytes);
end;

initialization
  GSandboxDesktopLock := TCriticalSection.Create;
  GUserDesktops := TDictionary<string, THandle>.Create;
  GUserDesktopPaths := TDictionary<string, string>.Create;

finalization
  if GUserDesktops <> nil then
  begin
    for var D in GUserDesktops.Values do
      if D <> 0 then CloseDesktop(D);
    FreeAndNil(GUserDesktops);
  end;
  if GUserDesktopPaths <> nil then
    FreeAndNil(GUserDesktopPaths);
  FreeAndNil(GSandboxDesktopLock);

end.
