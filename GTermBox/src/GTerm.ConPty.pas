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
  System.SyncObjs, Quick.Logger, GTerm.ConPty.Loader, GTerm.Types;

const
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
    FOnData: TDataReceivedEvent;
    FLock: TCriticalSection;
  protected
    procedure Execute; override;
  public
    constructor Create(AReadPipe: THandle; AOnData: TDataReceivedEvent);
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
    procedure CreatePipes;
    procedure ClosePipes;
    procedure SetupJobSandbox;
    function SetupAppContainer(const AWorkingDir: string; const AExeDir: string = ''; const AAllowedDirsRead: TArray<string> = nil; const AAllowedDirsWrite: TArray<string> = nil; const ANetworkCaps: TArray<SID_AND_ATTRIBUTES> = nil): Boolean;
    procedure CleanupSandbox;
    procedure GrantDirAccessToAppContainer(const ADir: string; AFullAccess: Boolean = True);
    function BuildSandboxEnvironment(const AWorkingDir: string; const AExtraEnv: TArray<string>): string;
    procedure SetupPowerShellProfile(const AWorkingDir: string);
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

function GetLengthSid(pSid: PSID): DWORD; stdcall; external advapi32 name 'GetLengthSid';

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

constructor TPtyReaderThread.Create(AReadPipe: THandle; AOnData: TDataReceivedEvent);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FLock := TCriticalSection.Create;
  FReadPipe := AReadPipe;
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
begin
  while not Terminated do
  begin
    BytesRead := 0;
    if ReadFile(FReadPipe, Buffer[0], SizeOf(Buffer), BytesRead, nil) then
    begin
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
    end
    else
      Break;
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
  inherited Destroy;
end;

procedure TGTermConPty.CreatePipes;
begin
  CreatePipe(FInputRead, FInputWrite, nil, 0);
  CreatePipe(FOutputRead, FOutputWrite, nil, 0);
end;

procedure TGTermConPty.ClosePipes;
begin
  if FInputRead <> 0 then begin CloseHandle(FInputRead); FInputRead := 0; end;
  if FInputWrite <> 0 then begin CloseHandle(FInputWrite); FInputWrite := 0; end;
  if FOutputRead <> 0 then begin CloseHandle(FOutputRead); FOutputRead := 0; end;
  if FOutputWrite <> 0 then begin CloseHandle(FOutputWrite); FOutputWrite := 0; end;
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
end;

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
    if OldDacl <> nil then
      GetAclInformation(OldDacl, @AclInfo, SizeOf(AclInfo), AclSizeInformation);

    NewAclSize := AclInfo.AclBytesInUse + ACCESS_ALLOWED_ACE_HEADER_SIZE + GetLengthSid(FAppContainerSid) + 32;
    GetMem(NewDacl, NewAclSize);
    try
      if not InitializeAcl(NewDacl, NewAclSize, ACL_REVISION) then
        Logger.Error(Format('[ConPTY] InitializeAcl failed: %d', [GetLastError]));

      if AFullAccess then
        AccessMask := FILE_ALL_ACCESS
      else
        AccessMask := FILE_GENERIC_READ_EXECUTE;

      if not AddAccessAllowedAceEx(NewDacl, ACL_REVISION, OBJECT_INHERIT_ACE or CONTAINER_INHERIT_ACE, AccessMask, FAppContainerSid) then
        Logger.Error(Format('[ConPTY] AddAccessAllowedAceEx failed: %d', [GetLastError]));

      if OldDacl <> nil then
        for I := 0 to AclInfo.AceCount - 1 do
          if GetAce(OldDacl, I, AcePtr) then
            AddAce(NewDacl, ACL_REVISION, MAXDWORD, AcePtr,
              PDWORD(AcePtr)^ shr 16);

      if SetNamedSecurityInfoW(PWideChar(ADir), SE_FILE_OBJECT,
           DACL_SECURITY_INFORMATION, nil, nil, NewDacl, nil) = 0 then
        Logger.Info(Format('[ConPTY] Granted AppContainer access to: %s', [ADir]))
      else
        Logger.Warn(Format('[ConPTY] SetNamedSecurityInfo failed for: %s', [ADir]));
    finally
      FreeMem(NewDacl);
    end;
  finally
    if Sd <> nil then LocalFree(HLOCAL(Sd));
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
begin
  Result := False;
  ContainerName := 'GTermBox.' + Copy(TGUID.NewGuid.ToString, 2, 36);
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
      Exit;
    end;
    Logger.Info(Format('[ConPTY] AppContainer profile reused: %s', [ContainerName]));
  end
  else if FAILED(Hr) then
  begin
    Logger.Error(Format('[ConPTY] CreateAppContainerProfile failed: 0x%x — falling back to no sandbox', [Hr]));
    FAppContainerName := '';
    Exit;
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

procedure TGTermConPty.CleanupSandbox;
var
  ContainerToDelete: string;
begin
  if FJobHandle <> 0 then
  begin
    CloseHandle(FJobHandle);
    FJobHandle := 0;
  end;

  if FAppContainerSid <> nil then
  begin
    FreeSid(FAppContainerSid);
    FAppContainerSid := nil;
  end;

  ContainerToDelete := FAppContainerName;
  FAppContainerName := '';
  if ContainerToDelete <> '' then
  begin
    DeleteAppContainerProfile(PWideChar(ContainerToDelete));
    Logger.Info(Format('[ConPTY] AppContainer profile deleted: %s', [ContainerToDelete]));
  end;
end;

procedure TGTermConPty.SetupPowerShellProfile(const AWorkingDir: string);
const
  PS_PROFILE_CONTENT = 'New-PSDrive -Name home -PSProvider FileSystem -Root $env:USERPROFILE | Out-Null' + #13#10 +
                       'Set-Location home:' + #13#10;
var
  ProfileDir5: string;
  ProfileFile5: string;
  ProfileDir7: string;
  ProfileFile7: string;
  SL: TStringList;
begin
  ProfileDir5  := TPath.Combine(AWorkingDir, 'Documents\WindowsPowerShell');
  ProfileFile5 := TPath.Combine(ProfileDir5,  'Microsoft.PowerShell_profile.ps1');
  ProfileDir7  := TPath.Combine(AWorkingDir, 'Documents\PowerShell');
  ProfileFile7 := TPath.Combine(ProfileDir7,  'Microsoft.PowerShell_profile.ps1');

  ForceDirectories(ProfileDir5);
  ForceDirectories(ProfileDir7);

  if FAppContainerSid <> nil then
  begin
    GrantDirAccessToAppContainer(ProfileDir5, True);
    GrantDirAccessToAppContainer(ProfileDir7, True);
  end;

  SL := TStringList.Create;
  try
    SL.Text := PS_PROFILE_CONTENT;
    if (not FileExists(ProfileFile5)) or (TFile.ReadAllText(ProfileFile5, TEncoding.UTF8) <> PS_PROFILE_CONTENT) then
    begin
      SL.SaveToFile(ProfileFile5, TEncoding.UTF8);
      Logger.Info(Format('[ConPTY] PS profile updated: %s', [ProfileFile5]));
    end;
    if (not FileExists(ProfileFile7)) or (TFile.ReadAllText(ProfileFile7, TEncoding.UTF8) <> PS_PROFILE_CONTENT) then
    begin
      SL.SaveToFile(ProfileFile7, TEncoding.UTF8);
      Logger.Info(Format('[ConPTY] PS7 profile updated: %s', [ProfileFile7]));
    end;
  finally
    SL.Free;
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
      EnvMap.Values['PATH']         := AWorkingDir + ';' + PathVal;
      EnvMap.Values['PSModulePath'] := GetEnvironmentVariable('SystemRoot') +
                                       '\System32\WindowsPowerShell\v1.0\Modules';
      EnvMap.Values['PSExecutionPolicyPreference'] := 'Bypass';

      if DrivePart <> '' then
        EnvMap.Add('=' + DrivePart + '=' + AWorkingDir);

      SetupPowerShellProfile(AWorkingDir);
    end;

    for I := 0 to High(AExtraEnv) do
    begin
      Line := AExtraEnv[I];
      EqPos := Pos('=', Line);
      if EqPos > 1 then
        EnvMap.Values[Copy(Line, 1, EqPos - 1)] := Copy(Line, EqPos + 1, MaxInt);
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
  AttrCount: DWORD;
  AttrSize: SIZE_T;
  AttrList: PPROC_THREAD_ATTRIBUTE_LIST;
  SiEx: TStartupInfoExW;
  CmdLineBuf: array[0..32767] of WideChar;
  WorkingDirPtr: PWideChar;
  SecCap: SECURITY_CAPABILITIES;
  UseAppContainer: Boolean;
  CreationFlags: DWORD;
  CleanCmd: string;
  ExeDir: string;
  PQuote, PSpace: Integer;
  EnvBlock: string;
  EnvPtr: PWideChar;
  NetCaps: TArray<SID_AND_ATTRIBUTES>;
begin
  Result := False;
  StopProcess;
  FStopping := 0;

  Logger.Info(Format('[ConPTY] Starting: %s (size: %dx%d) sandbox=%d',
    [ACommandLine, FCols, FRows, Ord(FSandboxMode)]));

  CreatePipes;

  Size.X := FCols;
  Size.Y := FRows;

  Hr := TGTermConPtyLoader.CreatePseudoConsole(Size, FInputRead, FOutputWrite, 0, @FHPty);
  if FAILED(Hr) then
  begin
    Logger.Error(Format('[ConPTY] CreatePseudoConsole failed: 0x%x', [Hr]));
    ClosePipes;
    Exit;
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

    UseAppContainer := (FSandboxMode = smStandard) and
                       SetupAppContainer(AWorkingDir, ExeDir, AAllowedDirsRead, AAllowedDirsWrite, NetCaps);

    AttrCount := 1;
    if UseAppContainer then
      AttrCount := 2;

    AttrSize := 0;
    InitializeProcThreadAttributeList(nil, AttrCount, 0, AttrSize);
    GetMem(AttrList, AttrSize);
    try
      if not InitializeProcThreadAttributeList(AttrList, AttrCount, 0, AttrSize) then
      begin
        Logger.Error(Format('[ConPTY] InitializeProcThreadAttributeList failed: %d', [GetLastError]));
        Exit;
      end;

      if not UpdateProcThreadAttribute(AttrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
           Pointer(FHPty), SizeOf(HPCON), nil, nil) then
      begin
        Logger.Error(Format('[ConPTY] UpdateProcThreadAttribute (ConPTY) failed: %d', [GetLastError]));
        Exit;
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
          Logger.Warn(Format('[ConPTY] UpdateProcThreadAttribute (AppContainer) failed: %d — running without AppContainer', [GetLastError]));
      end;

      FillChar(SiEx, SizeOf(SiEx), 0);
      SiEx.StartupInfo.cb := SizeOf(TStartupInfoExW);
      SiEx.lpAttributeList := AttrList;

      StringToWideChar(ACommandLine, CmdLineBuf, Length(CmdLineBuf));

      if AWorkingDir <> '' then
        WorkingDirPtr := PWideChar(AWorkingDir)
      else
        WorkingDirPtr := nil;

      SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
      CreationFlags := EXTENDED_STARTUPINFO_PRESENT or CREATE_SUSPENDED;

      EnvBlock := '';
      EnvPtr := nil;
      if AWorkingDir <> '' then
      begin
        EnvBlock := BuildSandboxEnvironment(AWorkingDir, AEnvironmentVars);
        CreationFlags := CreationFlags or CREATE_UNICODE_ENVIRONMENT;
        EnvPtr := PWideChar(EnvBlock);
      end;

      Result := CreateProcessExW(
        nil,
        CmdLineBuf,
        nil,
        nil,
        False,
        CreationFlags,
        EnvPtr,
        WorkingDirPtr,
        SiEx,
        FProcessInfo
      );

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
      SetupJobSandbox;

    if FJobHandle <> 0 then
      AssignProcessToJobObject(FJobHandle, FProcessInfo.hProcess);

    ResumeThread(FProcessInfo.hThread);

    if FInputRead <> 0 then begin CloseHandle(FInputRead); FInputRead := 0; end;
    if FOutputWrite <> 0 then begin CloseHandle(FOutputWrite); FOutputWrite := 0; end;

    FReaderThread := TPtyReaderThread.Create(FOutputRead, FOnDataReceived);
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

end.
