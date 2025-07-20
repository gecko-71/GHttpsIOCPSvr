{
  MIT License

  Copyright (c) (c) 2025 GECKO-71

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

unit GRequestBody;

interface

uses
  Quick.Logger, System.SysUtils, System.Classes, System.Generics.Collections,
  System.StrUtils, System.Character, System.Math,
  System.NetEncoding, System.IOUtils, System.DateUtils, Winapi.Windows;

type
  TProgressEvent = procedure(Sender: TObject; BytesReceived, TotalBytes: Int64; const PartName: string) of object;

  TErrorEvent = procedure(Sender: TObject; const ErrorMessage: string) of object;

  TStreamingMode = (smMemory, smFile, smCallback);

  TDataStreamCallback = procedure(const Data: TBytes; const IsLast: Boolean) of object;

  TDataStreamCallbackProc = reference to procedure(const Data: TBytes; const IsLast: Boolean);

  TSecuritySettings = class
  public
    MaxBodySize: Int64;
    MaxPartCount: Integer;
    MaxFieldNameLength: Integer;
    MaxFieldValueLength: Integer;
    MaxFilenameLength: Integer;
    AllowedFileExtensions: TStringList;
    BlockedMimeTypes: TStringList;
    MaxNestingLevel: Integer;
    constructor Create;
    destructor Destroy; override;
  end;

  TContentEncoding = (ceNone, ceGzip, ceDeflate, ceCompress, ceBrotli, ceIdentity);

  TBodyContentType = (
    bctUnknown,
    bctApplicationJson,
    bctApplicationFormUrlEncoded,
    bctTextPlain,
    bctApplicationXml,
    bctTextHtml,
    bctApplicationOctetStream,
    bctApplicationPdf,
    bctImagePng,
    bctImageJpeg,
    bctImageGif,
    bctImageWebp,
    bctImageSvg,
    bctMultipartFormData,
    bctMultipartMixed,
    bctApplicationJavascript,
    bctApplicationCss,
    bctApplicationZip,
    bctApplicationRar,
    bctVideo,
    bctAudio,
    bctApplicationMsgPack,
    bctApplicationProtobuf,
    bctApplicationCbor
  );

  TBodyParseState = (
    bpsWaitingData,
    bpsParsingHeaders,
    bpsParsingContent,
    bpsComplete,
    bpsError
  );


  TDiskFileManager = class
  private
    FUploadTmpDir: string;
    FCreatedFiles: TStringList;
    FMaxFilesPerDir: Integer;
    FCurrentSubDir: Integer;
    function CreateUniqueFileName(const Extension: string): string;
    function GetCurrentUploadDir: string;
    procedure EnsureUploadDirExists;
    function GetFileCountInDir(const DirPath: string): Integer;
    procedure CreateSubDirIfNeeded;
  public
    constructor Create(const BaseUploadDir: string = '');
    destructor Destroy; override;
    function GetNewTempFilePath(const Extension: string = '.tmp'): string;
    procedure RegisterFile(const FilePath: string);
    procedure CleanupAllFiles;
    property UploadTmpDir: string read FUploadTmpDir;
    property CreatedFiles: TStringList read FCreatedFiles;
  end;

  TBodyPartCollection = class;
  THttpBodyParser = class;

  TBodyPart = class abstract
  private
    FName: string;
    FContentType: string;
    FContentDisposition: string;
    FHeaders: TStringList;
    FSize: Int64;
    FMaxSize: Int64;
    FParseState: TBodyParseState;
    FErrorMessage: string;
    FDiskFileManager: TDiskFileManager;
    FUseDiskStorage: Boolean;
  protected
    procedure SetError(const ErrorMsg: string);
    function GetContentLength: Int64; virtual; abstract;
    function GetIsComplete: Boolean; virtual; abstract;
    function GetAsString: string; virtual; abstract;
    function GetAsBytes: TBytes; virtual; abstract;
  public
    constructor Create(const AName: string = ''; AMaxSize: Int64 = 10485760;
                      ADiskFileManager: TDiskFileManager = nil; AUseDiskStorage: Boolean = True);
    destructor Destroy; override;
    procedure Clear; virtual;
    procedure AddHeader(const HeaderName, HeaderValue: string);
    function GetHeader(const HeaderName: string): string;
    function AppendData(const Data: array of Byte; Size: Integer): Boolean; virtual; abstract;
    procedure SetContentTypeAndDetectEncoding(const ContentType: string); virtual;
    function IsDataAvailable: Boolean; virtual;
    function SaveToFile(const FileName: string): Boolean; virtual;
    function MoveTo(const DestFileName: string): Boolean; virtual; abstract;
    property Name: string read FName write FName;
    property ContentType: string read FContentType write FContentType;
    property ContentDisposition: string read FContentDisposition write FContentDisposition;
    property Headers: TStringList read FHeaders;
    property Size: Int64 read FSize;
    property MaxSize: Int64 read FMaxSize write FMaxSize;
    property ParseState: TBodyParseState read FParseState;
    property ErrorMessage: string read FErrorMessage;
    property ContentLength: Int64 read GetContentLength;
    property IsComplete: Boolean read GetIsComplete;
    property AsString: string read GetAsString;
    property AsBytes: TBytes read GetAsBytes;
    property UseDiskStorage: Boolean read FUseDiskStorage write FUseDiskStorage;
    property DiskFileManager: TDiskFileManager read FDiskFileManager;
  end;

  TPartCompleteEvent = procedure(Sender: TObject; Part: TBodyPart) of object;

  TTextBodyPart = class(TBodyPart)
  private
    FContent: TStringList;
    FEncoding: TEncoding;
    FExpectedLength: Int64;
    FCurrentLength: Int64;
    FTempFilePath: string;
    FTempFileStream: TFileStream;
    function DetectEncodingFromContentType(const ContentType: string): TEncoding;
    function DetectEncodingFromBOM(const Data: TBytes): TEncoding;
    procedure InitializeDiskStorage;
    procedure FinalizeDiskStorage;
    function ReadContentFromDisk: string;
  protected
    function GetContentLength: Int64; override;
    function GetIsComplete: Boolean; override;
    function GetAsString: string; override;
    function GetAsBytes: TBytes; override;
  public
    constructor Create(const AName: string = ''; AMaxSize: Int64 = 10485760;
                      ADiskFileManager: TDiskFileManager = nil; AUseDiskStorage: Boolean = True);
    destructor Destroy; override;
    procedure Clear; override;
    function AppendData(const Data: array of Byte; Size: Integer): Boolean; override;
    procedure SetContentTypeAndDetectEncoding(const ContentType: string); override;
    function MoveTo(const DestFileName: string): Boolean; override;
    function IsDataAvailable: Boolean; override;
    function ReadContentFromDiskFixed: TBytes;
    function GetAsStringFixed: string;
    function GetFormField(const FieldName: string): string;
    function GetAllFormFields: TStringList;
    function SaveToFile(const FileName: string): Boolean;override;
    property Encoding: TEncoding read FEncoding write FEncoding;
    property ExpectedLength: Int64 read FExpectedLength write FExpectedLength;
    property CurrentLength: Int64 read FCurrentLength;
    property TempFilePath: string read FTempFilePath;
  end;

  TBinaryBodyPart = class(TBodyPart)
  private
    FStream: TMemoryStream;
    FExpectedLength: Int64;
    FFileName: string;
    FStreamingMode: TStreamingMode;
    FFileStream: TFileStream;
    FStreamCallback: TDataStreamCallback;
    FTempFilePath: string;
    FDiskFileStream: TFileStream;
    FStreamCallbackProc: TDataStreamCallbackProc;
    procedure InitializeDiskStorage;
    procedure FinalizeDiskStorage;
  protected
    function GetContentLength: Int64; override;
    function GetIsComplete: Boolean; override;
    function GetAsString: string; override;
    function GetAsBytes: TBytes; override;
  public
    constructor Create(const AName: string = ''; AMaxSize: Int64 = 10485760;
                      ADiskFileManager: TDiskFileManager = nil; AUseDiskStorage: Boolean = True);
    destructor Destroy; override;
    procedure Clear; override;
    function AppendData(const Data: array of Byte; Size: Integer): Boolean; override;
    function IsDataAvailable: Boolean; override;
    function GetAsBytesFixed: TBytes;
    procedure SetStreamingCallback(Callback: TDataStreamCallback);
    procedure SetFileStreaming(const TargetFilePath: string);
    function GetDiskFilePath: string;
    function SaveToFile(const FileName: string): Boolean; override;
    procedure SetStreamingMode(Mode: TStreamingMode; const FilePath: string = '';
                             Callback: TDataStreamCallback = nil); overload;
    procedure SetStreamingMode(Mode: TStreamingMode; const FilePath: string;
                             CallbackProc: TDataStreamCallbackProc); overload;
    function AppendDataStreaming(const Data: array of Byte; Size: Integer): Boolean;
    function MoveTo(const DestFileName: string): Boolean; override;
    function ExtractStream: TStream;
    property FileName: string read FFileName write FFileName;
    property StreamingMode: TStreamingMode read FStreamingMode;
    property ExpectedLength: Int64 read FExpectedLength write FExpectedLength;
    property Stream: TMemoryStream read FStream;
    property TempFilePath: string read FTempFilePath;
    property DiskFileStream: TFileStream read FDiskFileStream;
  end;

  TMultipartBodyPart = class(TBodyPart)
  private
    FBoundary: string;
    FBoundaryBytes: TBytes;
    FParts: TObjectList<TBodyPart>;
    FCurrentPart: TBodyPart;
    FBuffer: TMemoryStream;
    FParsingHeaders: Boolean;
    FHeaderBuffer: TStringList;
    FOnPartComplete: TPartCompleteEvent;
  protected
    function GetContentLength: Int64; override;
    function GetIsComplete: Boolean; override;
    function GetAsString: string; override;
    function GetAsBytes: TBytes; override;

    procedure ParsePartHeaders(const HeaderData: string);
    function CreatePartFromHeaders: TBodyPart;
    function FindBoundary(const Data: TBytes; StartPos: Integer; out IsFinal: Boolean): Integer;
    procedure ProcessData;
  public
    constructor Create(const ABoundary: string; const AName: string = ''; AMaxSize: Int64 = 10485760;
                      ADiskFileManager: TDiskFileManager = nil; AUseDiskStorage: Boolean = True);
    destructor Destroy; override;
    procedure Clear; override;
    function AppendData(const Data: array of Byte; Size: Integer): Boolean; override;
    function IsDataAvailable: Boolean; override;
    function GetPart(Index: Integer): TBodyPart;
    function GetPartByName(const PartName: string): TBodyPart;
    function GetPartCount: Integer;
    property Boundary: string read FBoundary;
    property Parts: TObjectList<TBodyPart> read FParts;
    property PartCount: Integer read GetPartCount;
    property OnPartComplete: TPartCompleteEvent read FOnPartComplete write FOnPartComplete;
  end;

  TBodyPartCollection = class
  private
    FParts: TObjectList<TBodyPart>;
    FMaxTotalSize: Int64;
    FCurrentTotalSize: Int64;
  public
    constructor Create(AMaxTotalSize: Int64 = 10485760);
    destructor Destroy; override;
    procedure Clear;
    function AddPart(Part: TBodyPart): Boolean;
    function GetPart(Index: Integer): TBodyPart;
    function GetPartByName(const PartName: string): TBodyPart;
    function GetCount: Integer;
    property Parts: TObjectList<TBodyPart> read FParts;
    property MaxTotalSize: Int64 read FMaxTotalSize write FMaxTotalSize;
    property CurrentTotalSize: Int64 read FCurrentTotalSize;
    property Count: Integer read GetCount;
  end;

  THttpBodyParser = class
  private
    FContentType: string;
    FContentLength: Int64;
    FTransferEncoding: string;
    FBoundary: string;
    FBodyType: TBodyContentType;
    FMaxBodySize: Int64;
    FCurrentSize: Int64;
    FIsComplete: Boolean;
    FHasError: Boolean;
    FErrorMessage: string;
    FParts: TBodyPartCollection;
    FMainPart: TBodyPart;
    FBuffer: TMemoryStream;
    FOnProgress: TProgressEvent;
    FOnPartComplete: TPartCompleteEvent;
    FOnError: TErrorEvent;
    FLastProgressReport: TDateTime;
    FProgressReportInterval: Integer;
    FDiskFileManager: TDiskFileManager;
    FUseDiskStorage: Boolean;
    FIsChunked: Boolean;
    FChunkState: Integer; // 0=reading size, 1=reading data, 2=reading CRLF
    FCurrentChunkSize: Integer;
    FCurrentChunkReceived: Integer;
    FContentEncoding: TContentEncoding;
    FSecuritySettings: TSecuritySettings;
    function ValidateFilename(const Filename: string): Boolean;
    function ValidateMimeType(const MimeType: string): Boolean;
    function SanitizeFieldName(const FieldName: string): string;
    function DetectContentEncoding(const EncodingHeader: string): TContentEncoding;
    function DecompressData(const Data: TBytes; Encoding: TContentEncoding): TBytes;
    procedure DetermineBodyType;
    procedure ParseContentType;
    function ExtractBoundary(const ContentTypeHeader: string): string;
    function GetBodyContentType(const ContentTypeStr: string): TBodyContentType;
    procedure SetError(const ErrorMsg: string);
    function ProcessChunkedData(const Data: array of Byte; Size: Integer): TBytes;
    function ExtractChunkSize(const ChunkHeader: string): Integer;
  protected
    procedure DoProgress(BytesReceived, TotalBytes: Int64; const PartName: string);
    procedure DoPartComplete(Part: TBodyPart);
    procedure DoError(const ErrorMessage: string);
  public
    constructor Create(const AContentType: string; AContentLength: Int64;
                      const ATransferEncoding: string = ''; AMaxBodySize: Int64 = 10485760;
                      AUseDiskStorage: Boolean = True; const AUploadTmpDir: string = 'UPLOAD_TEMP');
    destructor Destroy; override;
    procedure Clear;
    function GetPart(Index: Integer): TBodyPart;
    function GetPartCount: Integer;
    function GetPartByName(const Name: string): TBodyPart;
    function AppendData(const Data: array of Byte; Size: Integer): Boolean;
    function GetMainPartAsString: string;
    function GetMainPartAsBytes: TBytes;
    function GetBodyDebugInfo: string;
    function IsMainPartDataAvailable: Boolean;
    property ContentType: string read FContentType;
    property ContentLength: Int64 read FContentLength;
    property TransferEncoding: string read FTransferEncoding;
    property Boundary: string read FBoundary;
    property BodyType: TBodyContentType read FBodyType;
    property MaxBodySize: Int64 read FMaxBodySize write FMaxBodySize;
    property CurrentSize: Int64 read FCurrentSize;
    property IsComplete: Boolean read FIsComplete;
    property HasError: Boolean read FHasError;
    property ErrorMessage: string read FErrorMessage;
    property Parts: TBodyPartCollection read FParts;
    property MainPart: TBodyPart read FMainPart;
    property IsChunked: Boolean read FIsChunked;
    property OnProgress: TProgressEvent read FOnProgress write FOnProgress;
    property OnPartComplete: TPartCompleteEvent read FOnPartComplete write FOnPartComplete;
    property OnError: TErrorEvent read FOnError write FOnError;
    property ProgressReportInterval: Integer read FProgressReportInterval write FProgressReportInterval;
    property UseDiskStorage: Boolean read FUseDiskStorage write FUseDiskStorage;
    property DiskFileManager: TDiskFileManager read FDiskFileManager;
  end;

function GetTempDir: string;
function GetUploadTmpDir: string;
function HTMLEncode(const Input: string): string;

implementation

function GetTempDir: string;
var
  ExeDir, TempPath: string;
begin
  ExeDir := TPath.GetDirectoryName(GetModuleName(HInstance));
  TempPath := TPath.Combine(ExeDir, 'temp');
  if not TDirectory.Exists(TempPath) then
     TDirectory.CreateDirectory(TempPath);
  Result := TempPath;
end;

function GetUploadTmpDir: string;
var
  ExeDir, UploadPath: string;
begin
  ExeDir := TPath.GetDirectoryName(GetModuleName(HInstance));
  UploadPath := TPath.Combine(ExeDir, 'UPLOAD_TMP');
  if not TDirectory.Exists(UploadPath) then
     TDirectory.CreateDirectory(UploadPath);
  Result := UploadPath;
end;

function HTMLEncode(const Input: string): string;
begin
  Result := Input;
  Result := StringReplace(Result, '&', '&amp;', [rfReplaceAll]);
  Result := StringReplace(Result, '<', '&lt;', [rfReplaceAll]);
  Result := StringReplace(Result, '>', '&gt;', [rfReplaceAll]);
  Result := StringReplace(Result, '"', '&quot;', [rfReplaceAll]);
  Result := StringReplace(Result, '''', '&#39;', [rfReplaceAll]);
end;

constructor TSecuritySettings.Create;
begin
  inherited Create;
  MaxBodySize := 10485760; // 10MB
  MaxPartCount := 100;
  MaxFieldNameLength := 255;
  MaxFieldValueLength := 1048576; // 1MB
  MaxFilenameLength := 255;
  AllowedFileExtensions := TStringList.Create;
  BlockedMimeTypes := TStringList.Create;
  MaxNestingLevel := 10;
end;

destructor TSecuritySettings.Destroy;
begin
  AllowedFileExtensions.Free;
  BlockedMimeTypes.Free;
  inherited Destroy;
end;

constructor TDiskFileManager.Create(const BaseUploadDir: string);
begin
  inherited Create;
  try
    if BaseUploadDir <> '' then
       FUploadTmpDir := BaseUploadDir
    else
       FUploadTmpDir := GetUploadTmpDir;
    FCreatedFiles := TStringList.Create;
    FCreatedFiles.Sorted := False;
    FCreatedFiles.Duplicates := dupIgnore;
    FMaxFilesPerDir := 500;
    FCurrentSubDir := 0;
    EnsureUploadDirExists;
  except
    on E: Exception do
    begin
      if Assigned(FCreatedFiles) then
         FreeAndNil(FCreatedFiles);
      raise Exception.CreateFmt('Failed to create DiskFileManager: %s', [E.Message]);
    end;
  end;
end;

destructor TDiskFileManager.Destroy;
begin
  try
    if Assigned(FCreatedFiles) then
    begin
      CleanupAllFiles;
      FreeAndNil(FCreatedFiles);
    end;
  except
    on E: Exception do
    begin
      Logger.Info('Error in DiskFileManager destructor: ' + E.Message);
    end;
  end;
  inherited Destroy;
end;

procedure TDiskFileManager.EnsureUploadDirExists;
begin
  try
    if not TDirectory.Exists(FUploadTmpDir) then
      TDirectory.CreateDirectory(FUploadTmpDir);
  except
    on E: Exception do
      raise Exception.CreateFmt('Cannot create upload directory %s: %s', [FUploadTmpDir, E.Message]);
  end;
end;

function TDiskFileManager.GetFileCountInDir(const DirPath: string): Integer;
var
  SearchRec: TSearchRec;
begin
  Result := 0;
  try
    if FindFirst(TPath.Combine(DirPath, '*.*'), faAnyFile, SearchRec) = 0 then
    begin
      repeat
        if (SearchRec.Attr and faDirectory) = 0 then
          Inc(Result);
      until FindNext(SearchRec) <> 0;
      System.SysUtils.FindClose(SearchRec);
    end;
  except
    Result := 0;
  end;
end;

procedure TDiskFileManager.CreateSubDirIfNeeded;
var
  CurrentDir: string;
  FileCount: Integer;
begin
  try
    CurrentDir := GetCurrentUploadDir;
    if TDirectory.Exists(CurrentDir) then
    begin
      FileCount := GetFileCountInDir(CurrentDir);
      if FileCount >= FMaxFilesPerDir then
      begin
        Inc(FCurrentSubDir);
        CurrentDir := GetCurrentUploadDir;
        if not TDirectory.Exists(CurrentDir) then
           TDirectory.CreateDirectory(CurrentDir);
      end;
    end
    else
    begin
      TDirectory.CreateDirectory(CurrentDir);
    end;
  except
    on E: Exception do
    begin
      Logger.Info('Error creating subdirectory: ' + E.Message);
    end;
  end;
end;

function TDiskFileManager.GetCurrentUploadDir: string;
begin
  if FCurrentSubDir > 0 then
     Result := TPath.Combine(FUploadTmpDir, 'sub' + IntToStr(FCurrentSubDir))
  else
     Result := FUploadTmpDir;
end;

function TDiskFileManager.CreateUniqueFileName(const Extension: string): string;
var
  Timestamp: string;
  GUID: TGUID;
  GUIDStr: string;
begin
  Timestamp := FormatDateTime('yyyymmdd_hhnnsszzz', Now);
  if CreateGUID(GUID) = S_OK then
  begin
    GUIDStr := GUIDToString(GUID);
    GUIDStr := StringReplace(GUIDStr, '{', '', [rfReplaceAll]);
    GUIDStr := StringReplace(GUIDStr, '}', '', [rfReplaceAll]);
    GUIDStr := StringReplace(GUIDStr, '-', '', [rfReplaceAll]);
  end
  else
    GUIDStr := IntToStr(Random(MaxInt));

  Result := Timestamp + '_' + GUIDStr + Extension;
end;

function TDiskFileManager.GetNewTempFilePath(const Extension: string): string;
var
  FileName: string;
  FullPath: string;
  Attempts: Integer;
begin
  CreateSubDirIfNeeded;
  Attempts := 0;
  repeat
    FileName := CreateUniqueFileName(Extension);
    FullPath := TPath.Combine(GetCurrentUploadDir, FileName);
    Inc(Attempts);
  until (not TFile.Exists(FullPath)) or (Attempts > 10);

  if Attempts > 10 then
     raise Exception.Create('Cannot generate unique temp file name after 10 attempts');
  Result := FullPath;
  RegisterFile(Result);
end;

procedure TDiskFileManager.RegisterFile(const FilePath: string);
begin
  if not Assigned(FCreatedFiles) then
     Exit;
  if FilePath = '' then
     Exit;
  try
    if FCreatedFiles.IndexOf(FilePath) = -1 then
      FCreatedFiles.Add(FilePath);
  except
    on E: Exception do
    begin
      Logger.Info(Format('Error registering file %s: %s', [FilePath, E.Message]));
    end;
  end;
end;

procedure TDiskFileManager.CleanupAllFiles;
var
  I: Integer;
  FilePath: string;
  FilesToDelete: TArray<string>;
  SuccessCount, ErrorCount: Integer;
begin
  if not Assigned(FCreatedFiles) then
     Exit;
  SuccessCount := 0;
  ErrorCount := 0;
  try
    SetLength(FilesToDelete, FCreatedFiles.Count);
    for I := 0 to FCreatedFiles.Count - 1 do
       FilesToDelete[I] := FCreatedFiles[I];
    FCreatedFiles.Clear;
    for I := 0 to Length(FilesToDelete) - 1 do
    begin
      FilePath := FilesToDelete[I];
      if FilePath <> '' then
      begin
        try
          if TFile.Exists(FilePath) then
          begin
            TFile.Delete(FilePath);
            Inc(SuccessCount);
          end;
        except
          on E: Exception do
          begin
            Inc(ErrorCount);
          end;
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Critical error in CleanupAllFiles: %s', [E.Message]);
    end;
  end;
end;

constructor TBodyPart.Create(const AName: string; AMaxSize: Int64;
                            ADiskFileManager: TDiskFileManager; AUseDiskStorage: Boolean);
begin
  inherited Create;
  FName := AName;
  FMaxSize := AMaxSize;
  FHeaders := TStringList.Create;
  FHeaders.NameValueSeparator := ':';
  FSize := 0;
  FParseState := bpsWaitingData;
  FErrorMessage := '';
  FDiskFileManager := ADiskFileManager;
  FUseDiskStorage := AUseDiskStorage;
end;

destructor TBodyPart.Destroy;
begin
  FHeaders.Free;
  inherited Destroy;
end;

procedure TBodyPart.Clear;
begin
  FHeaders.Clear;
  FSize := 0;
  FParseState := bpsWaitingData;
  FErrorMessage := '';
end;

procedure TBodyPart.SetError(const ErrorMsg: string);
begin
  FErrorMessage := ErrorMsg;
  FParseState := bpsError;
  Logger.Info(Format('BodyPart ERROR [%s]: %s', [FName, ErrorMsg]));
end;

procedure TBodyPart.AddHeader(const HeaderName, HeaderValue: string);
begin
  if not Assigned(FHeaders) then
     FHeaders := TStringList.Create;
  FHeaders.Values[HeaderName] := HeaderValue;
end;

function TBodyPart.SaveToFile(const FileName: string): Boolean;
begin

end;

function TBodyPart.GetHeader(const HeaderName: string): string;
var
  I: Integer;
  LowerHeaderName: string;
begin
  Result := '';
  LowerHeaderName := LowerCase(HeaderName);
  if Assigned(FHeaders) then
  begin
    for I := 0 to FHeaders.Count - 1 do
    begin
      if LowerCase(FHeaders.Names[I]) = LowerHeaderName then
      begin
        Result := FHeaders.ValueFromIndex[I];
        Break;
      end;
    end;
  end;
end;

procedure TBodyPart.SetContentTypeAndDetectEncoding(const ContentType: string);
begin
  FContentType := ContentType;
end;

function TBodyPart.IsDataAvailable: Boolean;
begin
  Result := FSize > 0;
end;

constructor TTextBodyPart.Create(const AName: string; AMaxSize: Int64;
                                ADiskFileManager: TDiskFileManager; AUseDiskStorage: Boolean);
begin
  inherited Create(AName, AMaxSize, ADiskFileManager, AUseDiskStorage);
  FContent := TStringList.Create;
  FEncoding := TEncoding.UTF8;
  FExpectedLength := -1;
  FCurrentLength := 0;
  FTempFilePath := '';
  FTempFileStream := nil;
  if FUseDiskStorage and Assigned(FDiskFileManager) then
     InitializeDiskStorage;
end;

destructor TTextBodyPart.Destroy;
begin
  FinalizeDiskStorage;
  FContent.Free;
  inherited Destroy;
end;

procedure TTextBodyPart.InitializeDiskStorage;
begin
  if Assigned(FDiskFileManager) then
  begin
    try
      FTempFilePath := FDiskFileManager.GetNewTempFilePath('.txt');
      FTempFileStream := TFileStream.Create(FTempFilePath, fmCreate);
    except
      on E: Exception do
      begin
        SetError('Failed to initialize disk storage: ' + E.Message);
        FUseDiskStorage := False;
        Logger.Error('Failed to initialize disk storage: ' + E.Message);
      end;
    end;
  end;
end;

procedure TTextBodyPart.FinalizeDiskStorage;
begin
  if Assigned(FTempFileStream) then
  begin
    try
      FTempFileStream.Free;
      FTempFileStream := nil;
    except
      on E: Exception do
      begin
        Logger.Error('Error closing temp file stream: %s', [E.Message]);
      end;
    end;
  end;
end;

procedure TTextBodyPart.Clear;
begin
  inherited Clear;
  FContent.Clear;
  FCurrentLength := 0;
  FExpectedLength := -1;

  FinalizeDiskStorage;

  if FUseDiskStorage and Assigned(FDiskFileManager) then
    InitializeDiskStorage;
end;

function TTextBodyPart.SaveToFile(const FileName: string): Boolean;
begin
  Result := False;
  try
    if FUseDiskStorage and (FTempFilePath <> '') and TFile.Exists(FTempFilePath) then
    begin
      if Assigned(DiskFileManager) then FinalizeDiskStorage;
      TFile.Copy(FTempFilePath, FileName, True);
      if FUseDiskStorage and Assigned(FDiskFileManager) then
         InitializeDiskStorage;
      Result := True;
    end
    else
      Result := false;
  except
    on E: Exception do
    begin
      SetError('Failed to save to file: ' + E.Message);
      Result := False;
    end;
  end;
end;



procedure TTextBodyPart.SetContentTypeAndDetectEncoding(const ContentType: string);
begin
  inherited SetContentTypeAndDetectEncoding(ContentType);
  FEncoding := DetectEncodingFromContentType(ContentType);
  if not Assigned(FEncoding) then
     FEncoding := TEncoding.UTF8;
end;

function TTextBodyPart.IsDataAvailable: Boolean;
begin
  if FUseDiskStorage then
    Result := (FTempFilePath <> '') and TFile.Exists(FTempFilePath)
  else
    Result := FContent.Count > 0;
end;

function TTextBodyPart.ReadContentFromDiskFixed: TBytes;
var
  FileStream: TFileStream;
  FileSize: Int64;
begin
  SetLength(Result, 0);
  if FTempFilePath = '' then
     Exit;
  if not TFile.Exists(FTempFilePath) then
  begin
    Exit;
  end;

  try
    if Assigned(FTempFileStream) then
    begin
      var CurrentPos := FTempFileStream.Position;
      try
        FTempFileStream.Position := 0;
        FileSize := FTempFileStream.Size;
        if FileSize > 0 then
        begin
          SetLength(Result, FileSize);
          FTempFileStream.ReadBuffer(Result[0], FileSize);
        end;
      finally
        FTempFileStream.Position := CurrentPos;
      end;
    end
    else
    begin
      Result := TFile.ReadAllBytes(FTempFilePath);
    end;

  except
    on E: Exception do
    begin
      Logger.Error('ReadContentFromDiskFixed failed: ' + E.Message + ' for file: ' + FTempFilePath);
      SetLength(Result, 0);
    end;
  end;
end;

function TTextBodyPart.GetAsStringFixed: string;
var
  FileContent: TBytes;
begin
  Result := '';
  try
    if FUseDiskStorage and (FTempFilePath <> '') then
    begin
      FileContent := ReadContentFromDiskFixed;
      if Length(FileContent) > 0 then
      begin
        try
          Result := FEncoding.GetString(FileContent);
        except
          on E: EEncodingError do
          begin
            Logger.Warn('Encoding error, trying UTF-8: ' + E.Message);
            try
              Result := TEncoding.UTF8.GetString(FileContent);
            except
              Logger.Warn('UTF-8 failed, using ANSI fallback');
              Result := TEncoding.ANSI.GetString(FileContent);
            end;
          end;
        end;
      end;
    end
    else
    begin
      if FContent.Count > 0 then
      begin
        for var i := 0 to FContent.Count - 1 do
          Result := Result + FContent[i];
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('GetAsStringFixed failed: ' + E.Message);
      if FContent.Count > 0 then
      begin
        try
          for var i := 0 to FContent.Count - 1 do
            Result := Result + FContent[i];
        except
          Result := '';
        end;
      end;
    end;
  end;
end;

function TTextBodyPart.ReadContentFromDisk: string;
var
  FileContent: TBytes;
begin
  Result := '';
  if FUseDiskStorage and (FTempFilePath <> '') then
  begin
    try
      if Assigned(FTempFileStream) then
      begin
        var CurrentPos := FTempFileStream.Position;
        try
          FTempFileStream.Position := 0;
          SetLength(FileContent, FTempFileStream.Size);
          if FTempFileStream.Size > 0 then
          begin
            FTempFileStream.ReadBuffer(FileContent[0], FTempFileStream.Size);
            Result := FEncoding.GetString(FileContent);
          end;
        finally
          FTempFileStream.Position := CurrentPos;
        end;
      end
      else if TFile.Exists(FTempFilePath) then
      begin
        FileContent := TFile.ReadAllBytes(FTempFilePath);
        if Length(FileContent) > 0 then
          Result := FEncoding.GetString(FileContent);
      end;
    except
      on E: Exception do
      begin
        Logger.Info(Format('Error reading from disk file %s: %s', [FTempFilePath, E.Message]));
        if FContent.Count > 0 then
        begin
          Result := '';
          for var i := 0 to FContent.Count - 1 do
            Result := Result + FContent[i];
        end;
      end;
    end;
  end
  else
  begin
    if FContent.Count > 0 then
    begin
      Result := '';
      for var i := 0 to FContent.Count - 1 do
        Result := Result + FContent[i];
    end;
  end;
end;

function TTextBodyPart.DetectEncodingFromContentType(const ContentType: string): TEncoding;
var
  CharsetPos: Integer;
  CharsetStr: string;
begin
  Result := TEncoding.UTF8;
  CharsetPos := Pos('charset=', LowerCase(ContentType));
  if CharsetPos > 0 then
  begin
    CharsetStr := LowerCase(Copy(ContentType, CharsetPos + 8, Length(ContentType)));
    CharsetStr := Trim(StringReplace(CharsetStr, '"', '', [rfReplaceAll]));
    if Pos(';', CharsetStr) > 0 then
       CharsetStr := Copy(CharsetStr, 1, Pos(';', CharsetStr) - 1);
    if CharsetStr = 'utf-8' then
       Result := TEncoding.UTF8
    else if CharsetStr = 'utf-16' then
            Result := TEncoding.Unicode
    else if CharsetStr = 'utf-16le' then
            Result := TEncoding.Unicode
    else if CharsetStr = 'utf-16be' then
            Result := TEncoding.BigEndianUnicode
    else if CharsetStr = 'iso-8859-1' then
            Result := TEncoding.ANSI
    else if CharsetStr = 'latin1' then
            Result := TEncoding.ANSI
    else if CharsetStr = 'windows-1252' then
            Result := TEncoding.ANSI;
  end;
end;

function TTextBodyPart.DetectEncodingFromBOM(const Data: TBytes): TEncoding;
begin
  Result := TEncoding.UTF8;
  if Length(Data) >= 3 then
  begin
    if (Data[0] = $EF) and (Data[1] = $BB) and (Data[2] = $BF) then
      Result := TEncoding.UTF8
    else if (Data[0] = $FF) and (Data[1] = $FE) then
      Result := TEncoding.Unicode
    else if (Data[0] = $FE) and (Data[1] = $FF) then
      Result := TEncoding.BigEndianUnicode;
  end;
end;

function TTextBodyPart.GetContentLength: Int64;
begin
  if FUseDiskStorage and (FTempFilePath <> '') then
  begin
    if Assigned(FTempFileStream) then
      Result := FTempFileStream.Size
    else
    begin
      try
        if TFile.Exists(FTempFilePath) then
          Result := TFile.GetSize(FTempFilePath)
        else
          Result := FCurrentLength;
      except
        Result := FCurrentLength;
      end;
    end;
  end
  else
    Result := FCurrentLength;
end;

function TTextBodyPart.GetIsComplete: Boolean;
begin
  if FExpectedLength > 0 then
    Result := FCurrentLength >= FExpectedLength
  else
    Result := FParseState = bpsComplete;
end;

function TTextBodyPart.GetAsString: string;
begin
  Result := GetAsStringFixed;
end;

function TTextBodyPart.GetAsBytes: TBytes;
var
  Content: string;
begin
  try
    if FUseDiskStorage and (FTempFilePath <> '') then
    begin
      Result := ReadContentFromDiskFixed;
    end
    else
    begin
      Content := GetAsStringFixed;
      if Content <> '' then
        Result := FEncoding.GetBytes(Content)
      else
        SetLength(Result, 0);
    end;
  except
    on E: Exception do
    begin
      Logger.Error('TTextBodyPart.GetAsBytes failed: ' + E.Message);
      SetLength(Result, 0);
    end;
  end;
end;

function TTextBodyPart.AppendData(const Data: array of Byte; Size: Integer): Boolean;
var
  DataBytes: TBytes;
  TextData: string;
  NewLength: Int64;
begin
  Result := False;
  try
    if Size <= 0 then
    begin
      Result := True;
      Exit;
    end;
    NewLength := FCurrentLength + Size;
    if (FMaxSize > 0) and (NewLength > FMaxSize) then
    begin
      SetError(Format('Data size exceeds maximum allowed (%d bytes)', [FMaxSize]));
      Exit;
    end;
    SetLength(DataBytes, Size);
    if Size > 0 then
       Move(Data[0], DataBytes[0], Size);
    if FCurrentLength = 0 then
       FEncoding := DetectEncodingFromBOM(DataBytes);
    if FUseDiskStorage and Assigned(FTempFileStream) then
    begin
      try
        FTempFileStream.WriteBuffer(DataBytes[0], Size);
        FlushFileBuffers(FTempFileStream.Handle);
      except
        on E: Exception do
        begin
          SetError('Failed to write to disk file: ' + E.Message);
          Exit;
        end;
      end;
    end
    else
    begin
      try
        TextData := FEncoding.GetString(DataBytes);
      except
        on E: Exception do
        begin
          SetError('Failed to decode text data: ' + E.Message);
          Exit;
        end;
      end;
      if FContent.Count = 0 then
         FContent.Add(TextData)
      else
         FContent[FContent.Count - 1] := FContent[FContent.Count - 1] + TextData;
    end;
    FCurrentLength := NewLength;
    FSize := FCurrentLength;
    if (FExpectedLength > 0) and (FCurrentLength >= FExpectedLength) then
    begin
      FParseState := bpsComplete;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      SetError('Exception in AppendData: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TTextBodyPart.GetFormField(const FieldName: string): string;
var
  FormData: string;
  Fields: TArray<string>;
  Field: string;
  EqualPos: Integer;
  Name, Value: string;
begin
  Result := '';
  try
    FormData := GetAsStringFixed;
    Fields := FormData.Split(['&']);
    for Field in Fields do
    begin
      EqualPos := Pos('=', Field);
      if EqualPos > 0 then
      begin
        Name := Copy(Field, 1, EqualPos - 1);
        Value := Copy(Field, EqualPos + 1, Length(Field));
        try
          Name := TNetEncoding.URL.Decode(Name);
          Value := TNetEncoding.URL.Decode(Value);
        except
          Name := StringReplace(Name, '+', ' ', [rfReplaceAll]);
          Value := StringReplace(Value, '+', ' ', [rfReplaceAll]);
        end;

        if SameText(Name, FieldName) then
        begin
          Result := Value;
          Exit;
        end;
      end;
    end;

  except
    on E: Exception do
    begin
      Logger.Error('ERROR in GetFormField: ' + E.Message);
      Result := '';
    end;
  end;
end;

function TTextBodyPart.GetAllFormFields: TStringList;
var
  FormFields: TStringList;
  FormData: string;
  Fields: TArray<string>;
  Field: string;
  EqualPos: Integer;
  Name, Value: string;
begin
  FormFields := TStringList.Create;
  Result := FormFields;
  try
    FormData := GetAsStringFixed;
    Fields := FormData.Split(['&']);
    for Field in Fields do
    begin
      EqualPos := Pos('=', Field);
      if EqualPos > 0 then
      begin
        Name := Copy(Field, 1, EqualPos - 1);
        Value := Copy(Field, EqualPos + 1, Length(Field));
        try
          Name := TNetEncoding.URL.Decode(Name);
          Value := TNetEncoding.URL.Decode(Value);
        except
          Name := StringReplace(Name, '+', ' ', [rfReplaceAll]);
          Value := StringReplace(Value, '+', ' ', [rfReplaceAll]);
        end;
        FormFields.Values[Name] := Value;
      end;
    end;
  except
    on E: Exception do
    begin
      Logger.Info('ERROR in GetAllFormFields: ' + E.Message);
      FormFields.Free;
      Result := nil;
    end;
  end;
end;

constructor TBinaryBodyPart.Create(const AName: string; AMaxSize: Int64;
                                  ADiskFileManager: TDiskFileManager; AUseDiskStorage: Boolean);
begin
  inherited Create(AName, AMaxSize, ADiskFileManager, AUseDiskStorage);
  FStream := TMemoryStream.Create;
  FExpectedLength := -1;
  FFileName := '';
  FStreamingMode := smMemory;
  FFileStream := nil;
  FStreamCallback := nil;
  FTempFilePath := '';
  FDiskFileStream := nil;
  if FUseDiskStorage and Assigned(FDiskFileManager) then
     InitializeDiskStorage;
end;

destructor TBinaryBodyPart.Destroy;
begin
  FinalizeDiskStorage;
  if Assigned(FFileStream) then
  begin
    FFileStream.Free;
    FFileStream := nil;
  end;
  FStream.Free;
  inherited Destroy;
end;

procedure TBinaryBodyPart.InitializeDiskStorage;
begin
  if Assigned(FDiskFileManager) then
  begin
    try
      FTempFilePath := FDiskFileManager.GetNewTempFilePath('.bin');
      FDiskFileStream := TFileStream.Create(FTempFilePath, fmCreate);
    except
      on E: Exception do
      begin
        SetError('Failed to initialize disk storage: ' + E.Message);
        FUseDiskStorage := False;
        Logger.Error('Failed to initialize disk storage: ' + E.Message);
      end;
    end;
  end;
end;

procedure TBinaryBodyPart.FinalizeDiskStorage;
begin
  if Assigned(FDiskFileStream) then
  begin
    try
      FDiskFileStream.Free;
      FDiskFileStream := nil;
    except
      on E: Exception do
      begin
        Logger.Info(Format('Error closing disk file stream: %s', [E.Message]));
      end;
    end;
  end;
end;

procedure TBinaryBodyPart.Clear;
begin
  inherited Clear;
  FStream.Clear;
  FStream.Size := 0;
  FExpectedLength := -1;
  FFileName := '';
  FinalizeDiskStorage;
  if FUseDiskStorage and Assigned(FDiskFileManager) then
     InitializeDiskStorage;
end;

procedure TBinaryBodyPart.SetStreamingMode(Mode: TStreamingMode;
  const FilePath: string; Callback: TDataStreamCallback);
begin
  FStreamingMode := Mode;
  FStreamCallback := nil;
  FStreamCallbackProc := nil;

  case Mode of
    smFile:
      begin
        FTempFilePath := FilePath;
        if FTempFilePath = '' then
           FTempFilePath := TPath.Combine(GetTempDir, Format('upload_%s.tmp', [FormatDateTime('yyyymmdd_hhnnss', Now)]));
        try
          if Assigned(FFileStream) then
          begin
            FFileStream.Free;
            FFileStream := nil;
          end;
          FFileStream := TFileStream.Create(FTempFilePath, fmCreate);
        except
          on E: Exception do
          begin
            SetError('Failed to create file stream: ' + E.Message);
            Exit;
          end;
        end;
      end;
    smCallback:
      begin
        if Assigned(Callback) then
          FStreamCallback := Callback
        else
        begin
          SetError('Callback not assigned');
          Exit;
        end;
      end;
    smMemory:
      ;
  end;
end;

procedure TBinaryBodyPart.SetStreamingMode(Mode: TStreamingMode;
                               const FilePath: string; CallbackProc: TDataStreamCallbackProc);
begin
  FStreamingMode := Mode;
  FStreamCallback := nil;
  FStreamCallbackProc := nil;
  case Mode of
    smFile:
      begin
        FTempFilePath := FilePath;
        if FTempFilePath = '' then
           FTempFilePath := TPath.Combine(GetTempDir, Format('upload_%s.tmp', [FormatDateTime('yyyymmdd_hhnnss', Now)]));
        try
          if Assigned(FFileStream) then
          begin
            FFileStream.Free;
            FFileStream := nil;
          end;
          FFileStream := TFileStream.Create(FTempFilePath, fmCreate);
        except
          on E: Exception do
          begin
            SetError('Failed to create file stream: ' + E.Message);
            Exit;
          end;
        end;
      end;
    smCallback:
      begin
        if Assigned(CallbackProc) then
          FStreamCallbackProc := CallbackProc
        else
        begin
          SetError('Callback procedure not assigned');
          Exit;
        end;
      end;
    smMemory:
      ;
  end;
end;

function TTextBodyPart.MoveTo(const DestFileName: string): Boolean;
begin
  Result := False;
  try
    if FUseDiskStorage and (FTempFilePath <> '') and TFile.Exists(FTempFilePath) then
    begin
      FinalizeDiskStorage;
      TFile.Move(FTempFilePath, DestFileName);
      if Assigned(FDiskFileManager) and (FDiskFileManager.FCreatedFiles.IndexOf(FTempFilePath) > -1) then
      begin
        FDiskFileManager.FCreatedFiles.Delete(FDiskFileManager.FCreatedFiles.IndexOf(FTempFilePath));
      end;
      FTempFilePath := '';
      Result := True;
    end
    else if FContent.Count > 0 then
    begin
      FContent.SaveToFile(DestFileName, FEncoding);
      Result := True;
    end;
  except
    on E: Exception do
    begin
      SetError('Failed to move text part to file: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TBinaryBodyPart.ExtractStream: TStream;
begin
  if FUseDiskStorage and Assigned(FDiskFileStream) then
    Result := FDiskFileStream
  else if Assigned(FStream) then
    Result := FStream
  else
    Result := nil;
end;

function TBinaryBodyPart.MoveTo(const DestFileName: string): Boolean;
begin
  Result := False;
  try
    if FUseDiskStorage and (FTempFilePath <> '') and TFile.Exists(FTempFilePath) then
    begin
      FinalizeDiskStorage;
      TFile.Move(FTempFilePath, DestFileName);
      if Assigned(FDiskFileManager) and (FDiskFileManager.FCreatedFiles.IndexOf(FTempFilePath) > -1) then
      begin
        FDiskFileManager.FCreatedFiles.Delete(FDiskFileManager.FCreatedFiles.IndexOf(FTempFilePath));
      end;
      FTempFilePath := '';
      Result := True;
    end
    else if FStream.Size > 0 then
    begin
      FStream.SaveToFile(DestFileName);
      FStream.Clear;
      Result := True;
    end;
  except
    on E: Exception do
    begin
      SetError('Failed to move binary part to file: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TBinaryBodyPart.AppendDataStreaming(const Data: array of Byte; Size: Integer): Boolean;
var
  DataBytes: TBytes;
  NewSize: Int64;
begin
  Result := False;
  try
    if FParseState = bpsError then
       Exit;
    if Size <= 0 then
    begin
      Result := True;
      Exit;
    end;
    NewSize := FSize + Size;
     if NewSize > FMaxSize then
    begin
      SetError(Format('Binary part size (%d) exceeds maximum (%d)', [NewSize, FMaxSize]));
      Exit;
    end;
    if (FExpectedLength > 0) and (NewSize > FExpectedLength) then
    begin
      SetError(Format('Binary part size (%d) exceeds expected length (%d)', [NewSize, FExpectedLength]));
      Exit;
    end;
    FParseState := bpsParsingContent;
    SetLength(DataBytes, Size);
    Move(Data[0], DataBytes[0], Size);
    case FStreamingMode of
      smMemory:
        begin
          FStream.WriteBuffer(Data[0], Size);
          Result := True;
        end;
      smFile:
        begin
          if Assigned(FFileStream) then
          begin
            FFileStream.WriteBuffer(Data[0], Size);
            Result := True;
          end
          else
            SetError('File stream not initialized');
        end;
      smCallback:
        begin
          if Assigned(FStreamCallback) then
          begin
            FStreamCallback(DataBytes, False);
            Result := True;
          end
          else if Assigned(FStreamCallbackProc) then
          begin
            FStreamCallbackProc(DataBytes, False);
            Result := True;
          end
          else
            SetError('No callback assigned');
        end;
    end;
    if Result then
    begin
      FSize := NewSize;
      if (FExpectedLength > 0) and (FSize >= FExpectedLength) then
      begin
        FParseState := bpsComplete;
        if FStreamingMode = smCallback then
        begin
          if Assigned(FStreamCallback) then
             FStreamCallback(DataBytes, True)
          else if Assigned(FStreamCallbackProc) then
             FStreamCallbackProc(DataBytes, True);
        end;
      end;
    end;
  except
    on E: Exception do
    begin
      SetError('Exception in AppendDataStreaming: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TBinaryBodyPart.GetContentLength: Int64;
begin
  if FUseDiskStorage and (FTempFilePath <> '') then
  begin
    if Assigned(FDiskFileStream) then
       Result := FDiskFileStream.Size
    else
    begin
      try
        if TFile.Exists(FTempFilePath) then
          Result := TFile.GetSize(FTempFilePath)
        else
          Result := FStream.Size;
      except
        Result := FStream.Size;
      end;
    end;
  end
  else
    Result := FStream.Size;
end;

function TBinaryBodyPart.GetIsComplete: Boolean;
begin
  if FExpectedLength > 0 then
    Result := GetContentLength >= FExpectedLength
  else
    Result := FParseState = bpsComplete;
end;

function TBinaryBodyPart.SaveToFile(const FileName: string): Boolean;
begin
  Result := False;
  try
    if FUseDiskStorage and (FTempFilePath <> '') and TFile.Exists(FTempFilePath) then
    begin
      if Assigned(FDiskFileStream) then
         FinalizeDiskStorage;
      TFile.Copy(FTempFilePath, FileName, True);
      if FUseDiskStorage and Assigned(FDiskFileManager) then
         InitializeDiskStorage;
      Result := True;
    end
    else if FStream.Size > 0 then
    begin
      FStream.SaveToFile(FileName);
      Result := True;
    end;
  except
    on E: Exception do
    begin
      SetError('Failed to save to file: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TBinaryBodyPart.GetDiskFilePath: string;
begin
  if FUseDiskStorage then
    Result := FTempFilePath
  else
    Result := '';
end;

function TBinaryBodyPart.IsDataAvailable: Boolean;
begin
  if FUseDiskStorage then
    Result := (FTempFilePath <> '') and TFile.Exists(FTempFilePath)
  else
    Result := FStream.Size > 0;
end;

function TBinaryBodyPart.GetAsString: string;
begin
  if FUseDiskStorage then
     Result := Format('Binary data: %d bytes, filename: %s, type: %s, disk file: %s', [GetContentLength, FFileName, FContentType, FTempFilePath])
  else
     Result := Format('Binary data: %d bytes, filename: %s, type: %s', [FStream.Size, FFileName, FContentType]);
end;

function TBinaryBodyPart.GetAsBytes: TBytes;
begin
  Result := GetAsBytesFixed;
end;

function TBinaryBodyPart.GetAsBytesFixed: TBytes;
begin
  SetLength(Result, 0);
  try
    if FUseDiskStorage and (FTempFilePath <> '') then
    begin
      if Assigned(FDiskFileStream) then
      begin
        var CurrentPos := FDiskFileStream.Position;
        try
          FDiskFileStream.Position := 0;
          SetLength(Result, FDiskFileStream.Size);
          if FDiskFileStream.Size > 0 then
            FDiskFileStream.ReadBuffer(Result[0], FDiskFileStream.Size);
        finally
          FDiskFileStream.Position := CurrentPos;
        end;
      end
      else if TFile.Exists(FTempFilePath) then
      begin
        Result := TFile.ReadAllBytes(FTempFilePath);
      end
      else
      begin
        FStream.Position := 0;
        SetLength(Result, FStream.Size);
        if FStream.Size > 0 then
           FStream.ReadBuffer(Result[0], FStream.Size);
      end;
    end
    else
    begin
      FStream.Position := 0;
      SetLength(Result, FStream.Size);
      if FStream.Size > 0 then
        FStream.ReadBuffer(Result[0], FStream.Size);
    end;
  except
    on E: Exception do
    begin
      Logger.Error('TBinaryBodyPart.GetAsBytesFixed failed: ' + E.Message);
      SetLength(Result, 0);
    end;
  end;
end;

function TBinaryBodyPart.AppendData(const Data: array of Byte; Size: Integer): Boolean;
var
  NewSize: Int64;
begin
  Result := False;
  try
    if Size <= 0 then
    begin
      Result := True;
      Exit;
    end;
    NewSize := GetContentLength + Size;
    if (FMaxSize > 0) and (NewSize > FMaxSize) then
    begin
      SetError(Format('Binary data size exceeds maximum allowed (%d bytes)', [FMaxSize]));
      Exit;
    end;
    case FStreamingMode of
      smMemory:
      begin
        if FUseDiskStorage and Assigned(FDiskFileStream) then
        begin
          try
            FDiskFileStream.WriteBuffer(Data[0], Size);
            FlushFileBuffers(FDiskFileStream.Handle);
          except
            on E: Exception do
            begin
              SetError('Failed to write binary data to disk: ' + E.Message);
              Exit;
            end;
          end;
        end
        else
        begin
          FStream.WriteBuffer(Data[0], Size);
        end;
      end;
      smFile:
      begin
        if Assigned(FFileStream) then
        begin
          FFileStream.WriteBuffer(Data[0], Size);
        end
        else
        begin
          SetError('File stream not initialized for file streaming mode');
          Exit;
        end;
      end;
      smCallback:
      begin
        if Assigned(FStreamCallback) then
        begin
          var DataCopy: TBytes;
          SetLength(DataCopy, Size);
          Move(Data[0], DataCopy[0], Size);
          FStreamCallback(DataCopy, False);
        end
        else
        begin
          SetError('Callback not set for callback streaming mode');
          Exit;
        end;
      end;
    end;
    FSize := NewSize;
    if (FExpectedLength > 0) and (FSize >= FExpectedLength) then
    begin
      FParseState := bpsComplete;
      if (FStreamingMode = smCallback) and Assigned(FStreamCallback) then
      begin
        var EmptyData: TBytes;
        SetLength(EmptyData, 0);
        FStreamCallback(EmptyData, True);
      end;
    end;
    Result := True;
  except
    on E: Exception do
    begin
      SetError('Exception in BinaryBodyPart.AppendData: ' + E.Message);
      Result := False;
    end;
  end;
end;

procedure TBinaryBodyPart.SetStreamingCallback(Callback: TDataStreamCallback);
begin
  FStreamCallback := Callback;
  FStreamingMode := smCallback;
end;

procedure TBinaryBodyPart.SetFileStreaming(const TargetFilePath: string);
begin
  try
    if Assigned(FFileStream) then
    begin
      FFileStream.Free;
      FFileStream := nil;
    end;
    FFileStream := TFileStream.Create(TargetFilePath, fmCreate);
    FStreamingMode := smFile;
    FFileName := ExtractFileName(TargetFilePath);
  except
    on E: Exception do
    begin
      SetError('Failed to set file streaming: ' + E.Message);
      FStreamingMode := smMemory;
      Logger.Error('Failed to initialize disk storage: ' + E.Message);
    end;
  end;
end;

constructor TBodyPartCollection.Create(AMaxTotalSize: Int64);
begin
  inherited Create;
  FParts := TObjectList<TBodyPart>.Create(True);
  FMaxTotalSize := AMaxTotalSize;
  FCurrentTotalSize := 0;
end;

destructor TBodyPartCollection.Destroy;
begin
  FParts.Free;
  inherited Destroy;
end;

procedure TBodyPartCollection.Clear;
begin
  FParts.Clear;
  FCurrentTotalSize := 0;
end;

function TBodyPartCollection.AddPart(Part: TBodyPart): Boolean;
begin
  Result := False;
  if not Assigned(Part) then
     Exit;
  try
    if (FMaxTotalSize > 0) and (FCurrentTotalSize + Part.Size > FMaxTotalSize) then
    begin
      Logger.Warn(Format('Cannot add part: would exceed total size limit (%d bytes)', [FMaxTotalSize]));
      Exit;
    end;
    FParts.Add(Part);
    FCurrentTotalSize := FCurrentTotalSize + Part.Size;
    Result := True;
  except
    on E: Exception do
    begin
      Logger.Error('Error adding part to collection: ' + E.Message);
      Result := False;
    end;
  end;
end;

function TBodyPartCollection.GetPart(Index: Integer): TBodyPart;
begin
  Result := nil;

  if (Index >= 0) and (Index < FParts.Count) then
    Result := FParts[Index];
end;

function TBodyPartCollection.GetPartByName(const PartName: string): TBodyPart;
var
  I: Integer;
begin
  Result := nil;

  for I := 0 to FParts.Count - 1 do
  begin
    if SameText(FParts[I].Name, PartName) then
    begin
      Result := FParts[I];
      Break;
    end;
  end;
end;

function TBodyPartCollection.GetCount: Integer;
begin
  Result := FParts.Count;
end;

constructor TMultipartBodyPart.Create(const ABoundary: string; const AName: string;
                                     AMaxSize: Int64; ADiskFileManager: TDiskFileManager;
                                     AUseDiskStorage: Boolean);
begin
  inherited Create(AName, AMaxSize, ADiskFileManager, AUseDiskStorage);
  FBoundary := ABoundary;
  FBoundaryBytes := TEncoding.ASCII.GetBytes('--' + FBoundary);
  FParts := TObjectList<TBodyPart>.Create(True);
  FCurrentPart := nil;
  FBuffer := TMemoryStream.Create;
  FHeaderBuffer := TStringList.Create;
  FParseState := bpsWaitingData;
end;

destructor TMultipartBodyPart.Destroy;
begin
  FHeaderBuffer.Free;
  FBuffer.Free;
  FParts.Free;
  inherited Destroy;
end;

procedure TMultipartBodyPart.Clear;
begin
  inherited Clear;
  FParts.Clear;
  FCurrentPart := nil;
  FBuffer.Clear;
  FHeaderBuffer.Clear;
  FParseState := bpsWaitingData;
end;

function TMultipartBodyPart.IsDataAvailable: Boolean;
begin
  Result := FParts.Count > 0;
end;


function TMultipartBodyPart.GetContentLength: Int64;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to FParts.Count - 1 do
    Result := Result + FParts[I].ContentLength;
end;

function TMultipartBodyPart.GetIsComplete: Boolean;
begin
  Result := (FParseState = bpsComplete);
end;


function TMultipartBodyPart.GetAsString: string;
var
  I: Integer;
begin
  if FParts.Count = 0 then
    Exit('Multipart data with 0 parts');
  Result := Format('Multipart data with %d parts:', [FParts.Count]);
  for I := 0 to FParts.Count - 1 do
  begin
    if Assigned(FParts[I]) then
      Result := Result + #13#10 + Format('  Part %d [%s]: %s (%d bytes)',
        [I + 1, FParts[I].Name, FParts[I].ContentType, FParts[I].Size])
    else
      Result := Result + #13#10 + Format('  Part %d: NIL', [I + 1]);
  end;
end;

function TMultipartBodyPart.GetAsBytes: TBytes;
var
  I: Integer;
  PartBytes: TBytes;
  MS: TMemoryStream;
begin
  MS := TMemoryStream.Create;
  try
    for I := 0 to FParts.Count - 1 do
    begin
      PartBytes := FParts[I].AsBytes;
      if Length(PartBytes) > 0 then
        MS.WriteBuffer(PartBytes[0], Length(PartBytes));
    end;
    SetLength(Result, MS.Size);
    if MS.Size > 0 then
    begin
      MS.Position := 0;
      MS.ReadBuffer(Result[0], MS.Size);
    end;
  finally
    MS.Free;
  end;
end;

function TMultipartBodyPart.GetPart(Index: Integer): TBodyPart;
begin
  Result := nil;
  if (Index >= 0) and (Index < FParts.Count) then
    Result := FParts[Index];
end;

function TMultipartBodyPart.GetPartByName(const PartName: string): TBodyPart;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to FParts.Count - 1 do
  begin
    if SameText(FParts[I].Name, PartName) then
    begin
      Result := FParts[I];
      Break;
    end;
  end;
end;

function TMultipartBodyPart.GetPartCount: Integer;
begin
  Result := FParts.Count;
end;

function TMultipartBodyPart.AppendData(const Data: array of Byte; Size: Integer): Boolean;
begin
  Result := False;
  try
    if FParseState in [bpsComplete, bpsError] then
       Exit(True);
    if Size <= 0 then
       Exit(True);

    FBuffer.Position := FBuffer.Size;
    FBuffer.WriteBuffer(Data[0], Size);
    ProcessData;
    Result := not (FParseState = bpsError);
  except
    on E: Exception do
    begin
      SetError('Exception in TMultipartBodyPart.AppendData: ' + E.Message);
      Result := False;
    end;
  end;
end;

procedure TMultipartBodyPart.ProcessData;
const
  DOUBLE_CRLF: TBytes = [13, 10, 13, 10];
var
  BufferBytes: TBytes;
  BufferPos: Integer;
  BoundaryPos, HeadersEndPos, PartDataLen: Integer;
  IsFinalBoundary: Boolean;
  PartData: TBytes;
begin
  if FParseState in [bpsComplete, bpsError] then Exit;

  BufferPos := 0;
  FBuffer.Position := 0;
  SetLength(BufferBytes, FBuffer.Size);
  if FBuffer.Size > 0 then
     FBuffer.Read(BufferBytes, FBuffer.Size);
  while (BufferPos < Length(BufferBytes)) and not (FParseState in [bpsComplete, bpsError]) do
  begin
    case FParseState of
      bpsWaitingData:
      begin
        BoundaryPos := FindBoundary(BufferBytes, BufferPos, IsFinalBoundary);
        if (BoundaryPos = 0) then
        begin
          BufferPos := Length(FBoundaryBytes);
          if (BufferPos + 1 < Length(BufferBytes)) and (BufferBytes[BufferPos] = 13) and (BufferBytes[BufferPos+1] = 10) then
            Inc(BufferPos, 2);
          FParseState := bpsParsingHeaders;
        end else
        begin
          if Length(BufferBytes) > (Length(FBoundaryBytes) + 10) then
              SetError('Invalid multipart format: missing initial boundary at position 0');
          Break;
        end;
      end;
      bpsParsingHeaders:
      begin
        var HeaderData: TBytes;
        HeadersEndPos := -1;
        if Length(BufferBytes) - BufferPos >= Length(DOUBLE_CRLF) then
          for var i := BufferPos to Length(BufferBytes) - Length(DOUBLE_CRLF) do
            if CompareMem(@BufferBytes[i], @DOUBLE_CRLF[0], Length(DOUBLE_CRLF)) then
            begin
              HeadersEndPos := i;
              Break;
            end;
        if HeadersEndPos > -1 then
        begin
          HeaderData := Copy(BufferBytes, BufferPos, HeadersEndPos - BufferPos);
          ParsePartHeaders(TEncoding.UTF8.GetString(HeaderData));
          if FParseState = bpsError then Break;
          BufferPos := HeadersEndPos + Length(DOUBLE_CRLF);
          FParseState := bpsParsingContent;
        end else
          Break;
      end;
      bpsParsingContent:
      begin
        if not Assigned(FCurrentPart) then
        begin
          SetError('Internal error: current part is null');
          Break;
        end;
        BoundaryPos := FindBoundary(BufferBytes, BufferPos, IsFinalBoundary);
        if BoundaryPos > -1 then
        begin
          PartDataLen := BoundaryPos - BufferPos - 2;
          if PartDataLen > 0 then
          begin
            PartData := Copy(BufferBytes, BufferPos, PartDataLen);
            if not FCurrentPart.AppendData(PartData, PartDataLen) then
            begin
              SetError('Failed to append final data to part: ' + FCurrentPart.ErrorMessage);
              Break;
            end;
          end;
          FCurrentPart.FParseState := bpsComplete;
          if Assigned(FOnPartComplete) then
             FOnPartComplete(Self, FCurrentPart);
          BufferPos := BoundaryPos + Length(FBoundaryBytes);
          if IsFinalBoundary then
          begin
             if (BufferPos + 1 < Length(BufferBytes)) and
                (BufferBytes[BufferPos] = Ord('-') ) and
                (BufferBytes[BufferPos+1] = Ord('-')) then
                Inc(BufferPos, 2);
             FParseState := bpsComplete;
          end
          else
          begin
             if (BufferPos + 1 < Length(BufferBytes)) and
                (BufferBytes[BufferPos] = 13) and
                (BufferBytes[BufferPos+1] = 10) then
                Inc(BufferPos, 2);
             FParseState := bpsParsingHeaders;
          end;
        end
        else
        begin
          var TailSize := Length(FBoundaryBytes) + 6;
          var DataLen := Length(BufferBytes) - BufferPos;
          var BytesToProcess := Max(0, DataLen - TailSize);
          if BytesToProcess > 0 then
          begin
            PartData := Copy(BufferBytes, BufferPos, BytesToProcess);
            if not FCurrentPart.AppendData(PartData, BytesToProcess) then
            begin
              SetError('Failed to append chunked data to part: ' + FCurrentPart.ErrorMessage);
              Break;
            end;
            Inc(BufferPos, BytesToProcess);
          end;
          Break;
        end;
      end;
    end;
  end;
  if BufferPos > 0 then
  begin
    var RemainingBytes := FBuffer.Size - BufferPos;
    if RemainingBytes > 0 then
    begin
       FBuffer.Position := BufferPos;
       var Ptr := FBuffer.Memory;
       Move(Pointer(IntPtr(Ptr) + BufferPos)^, Ptr^, RemainingBytes);
       FBuffer.Size := RemainingBytes;
    end
    else
    begin
      FBuffer.Clear;
    end;
  end;
end;


function TMultipartBodyPart.FindBoundary(const Data: TBytes; StartPos: Integer; out IsFinal: Boolean): Integer;
var
  I: Integer;
begin
  Result := -1;
  IsFinal := False;
  if (Length(FBoundaryBytes) = 0) or (Length(Data) = 0) then
     Exit;
  if Length(Data) - StartPos < Length(FBoundaryBytes) then
     Exit;
  for I := StartPos to Length(Data) - Length(FBoundaryBytes) do
  begin
    if CompareMem(@Data[I], @FBoundaryBytes[0], Length(FBoundaryBytes)) then
    begin
      Result := I;
      var CheckPos := I + Length(FBoundaryBytes);
      if (CheckPos + 1 < Length(Data)) and (Data[CheckPos] = Ord('-')) and (Data[CheckPos + 1] = Ord('-')) then
         IsFinal := True;
      Exit;
    end;
  end;
end;

procedure TMultipartBodyPart.ParsePartHeaders(const HeaderData: string);
var
  Lines: TArray<string>;
  Line: string;
  ColonPos: Integer;
  HeaderName, HeaderValue, Disposition, PartName, Filename: string;
  TrimmedPart: string;
begin
  FHeaderBuffer.Clear;
  PartName := 'part_' + IntToStr(FParts.Count);
  Filename := '';
  Lines := HeaderData.Split([#13#10, #10], TStringSplitOptions.ExcludeEmpty);
  for Line in Lines do
  begin
    ColonPos := Pos(':', Line);
    if ColonPos > 0 then
    begin
      HeaderName := LowerCase(Trim(Copy(Line, 1, ColonPos - 1)));
      HeaderValue := Trim(Copy(Line, ColonPos + 1, Length(Line)));
      FHeaderBuffer.Values[HeaderName] := HeaderValue;
      if HeaderName = 'content-disposition' then
      begin
        Disposition := HeaderValue;
        var Parts := Disposition.Split([';']);
        for var partStr in Parts do
        begin
          TrimmedPart := Trim(partStr);
          if TrimmedPart.StartsWith('name=') then
            PartName := Trim(StringReplace(TrimmedPart.Substring(5), '"', '', [rfReplaceAll]))
          else if TrimmedPart.StartsWith('filename=') then
            Filename := Trim(StringReplace(TrimmedPart.Substring(9), '"', '', [rfReplaceAll]));
        end;
      end;
    end;
  end;
  FCurrentPart := CreatePartFromHeaders;
  if Assigned(FCurrentPart) then
  begin
    FCurrentPart.Name := PartName;
    if (FCurrentPart is TBinaryBodyPart) then
      TBinaryBodyPart(FCurrentPart).FileName := Filename;
    FParts.Add(FCurrentPart);
  end else
  begin
    SetError('Failed to create body part from headers.');
  end;
end;

function TMultipartBodyPart.CreatePartFromHeaders: TBodyPart;
var
  ContentType, Disposition: string;
begin
  Result := nil;
  try
    ContentType := FHeaderBuffer.Values['content-type'];
    Disposition := FHeaderBuffer.Values['content-disposition'];
    if Pos('filename=', LowerCase(Disposition)) > 0 then
       Result := TBinaryBodyPart.Create('', FMaxSize, FDiskFileManager, FUseDiskStorage)
    else
       Result := TTextBodyPart.Create('', FMaxSize, FDiskFileManager, FUseDiskStorage);
    Result.ContentType := ContentType;
    for var I := 0 to FHeaderBuffer.Count - 1 do
       Result.AddHeader(FHeaderBuffer.Names[I], FHeaderBuffer.ValueFromIndex[I]);
  except
    on E: Exception do
      Result := nil;
  end;
end;

constructor THttpBodyParser.Create(const AContentType: string; AContentLength: Int64;
                                  const ATransferEncoding: string; AMaxBodySize: Int64;
                                  AUseDiskStorage: Boolean; const AUploadTmpDir: string);
begin
  inherited Create;
  FContentType := AContentType;
  FContentLength := AContentLength;
  FTransferEncoding := ATransferEncoding;
  FMaxBodySize := AMaxBodySize;
  FCurrentSize := 0;
  FIsComplete := False;
  FHasError := False;
  FErrorMessage := '';
  FUseDiskStorage := AUseDiskStorage;
  FParts := TBodyPartCollection.Create(FMaxBodySize);
  FMainPart := nil;
  FBuffer := TMemoryStream.Create;
  if FUseDiskStorage then
  begin
    try
      if AUploadTmpDir <> '' then
        FDiskFileManager := TDiskFileManager.Create(AUploadTmpDir)
      else
        FDiskFileManager := TDiskFileManager.Create(GetUploadTmpDir);
    except
      on E: Exception do
      begin
        FUseDiskStorage := False;
        FDiskFileManager := nil;
      end;
    end;
  end
  else
    FDiskFileManager := nil;

  FLastProgressReport := Now;
  FProgressReportInterval := 1000;
  FIsChunked := SameText(FTransferEncoding, 'chunked');
  FChunkState := 0;
  FCurrentChunkSize := 0;
  FCurrentChunkReceived := 0;
  FSecuritySettings := TSecuritySettings.Create;
  ParseContentType;
  DetermineBodyType;
end;

destructor THttpBodyParser.Destroy;
begin
  if Assigned(FParts) then
     FParts.Free;

  if Assigned(FDiskFileManager) then
    FDiskFileManager.Free;

  if Assigned(FSecuritySettings) then
     FSecuritySettings.Free;
  if Assigned(FBuffer) then
     FBuffer.Free;

  FParts := nil;
  FDiskFileManager := nil;
  FSecuritySettings := nil;
  FBuffer := nil;

  inherited Destroy;
end;

function THttpBodyParser.GetPart(Index: Integer): TBodyPart;
begin
  Result := nil;
  try
    if Assigned(FMainPart) and (FMainPart is TMultipartBodyPart) then
    begin
      Result := TMultipartBodyPart(FMainPart).GetPart(Index);
    end
    else if (Index = 0) and Assigned(FMainPart) then
    begin
      Result := FMainPart;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Error getting body part: ' + E.Message);
    end;
  end;
end;

function THttpBodyParser.GetPartCount: Integer;
begin
  try
    if Assigned(FMainPart) and (FMainPart is TMultipartBodyPart) then
      Result := TMultipartBodyPart(FMainPart).PartCount
    else if Assigned(FMainPart) then
      Result := 1
    else
      Result := 0;
  except
    Result := 0;
  end;
end;


function THttpBodyParser.GetPartByName(const Name: string): TBodyPart;
begin
  Result := nil;
  try
    if Assigned(FMainPart) and (FMainPart is TMultipartBodyPart) then
    begin
      Result := TMultipartBodyPart(FMainPart).GetPartByName(Name);
    end
    else if Assigned(FMainPart) and SameText(FMainPart.Name, Name) then
    begin
      Result := FMainPart;
    end;
  except
    on E: Exception do
    begin
      Logger.Error('Error getting body part by name: ' + E.Message);
    end;
  end;
end;

procedure THttpBodyParser.Clear;
begin
  FParts.Clear;
  FMainPart := nil;
  FBuffer.Clear;
  FCurrentSize := 0;
  FIsComplete := False;
  FHasError := False;
  FErrorMessage := '';
  FChunkState := 0;
  FCurrentChunkSize := 0;
  FCurrentChunkReceived := 0;
end;

procedure THttpBodyParser.SetError(const ErrorMsg: string);
begin
  FErrorMessage := ErrorMsg;
  FHasError := True;
  DoError(ErrorMsg);
  Logger.Error('BodyParser ERROR: ' + ErrorMsg);
end;

procedure THttpBodyParser.DoProgress(BytesReceived, TotalBytes: Int64; const PartName: string);
begin
  if Assigned(FOnProgress) and (MilliSecondsBetween(Now, FLastProgressReport) >= FProgressReportInterval) then
  begin
    FOnProgress(Self, BytesReceived, TotalBytes, PartName);
    FLastProgressReport := Now;
  end;
end;

procedure THttpBodyParser.DoPartComplete(Part: TBodyPart);
begin
  if Assigned(FOnPartComplete) then
     FOnPartComplete(Self, Part);
end;

procedure THttpBodyParser.DoError(const ErrorMessage: string);
begin
  if Assigned(FOnError) then
    FOnError(Self, ErrorMessage);
end;

function THttpBodyParser.IsMainPartDataAvailable: Boolean;
begin
  Result := Assigned(FMainPart) and FMainPart.IsDataAvailable;
end;

function THttpBodyParser.GetBodyDebugInfo: string;
var
  MainPartInfo: string;
begin
  Result := Format('Body info: type=%d, size=%d/%d, complete=%s, chunked=%s, parts=%d',
    [Ord(FBodyType), FCurrentSize, FContentLength, BoolToStr(FIsComplete, True),
     BoolToStr(FIsChunked, True), FParts.Count]);

  if Assigned(FMainPart) then
  begin
    MainPartInfo := Format(', main_part=[name=%s, size=%d, complete=%s, available=%s]',
      [FMainPart.Name, FMainPart.Size, BoolToStr(FMainPart.IsComplete, True),
       BoolToStr(FMainPart.IsDataAvailable, True)]);
    Result := Result + MainPartInfo;
  end
  else
    Result := Result + ', main_part=nil';
end;

procedure THttpBodyParser.ParseContentType;
var
  LowerContentType: string;
begin
  LowerContentType := LowerCase(Trim(FContentType));
  if Pos('multipart/', LowerContentType) = 1 then
  begin
    FBoundary := ExtractBoundary(FContentType);
  end;
  FContentEncoding := DetectContentEncoding(FContentType);
end;

function THttpBodyParser.ExtractBoundary(const ContentTypeHeader: string): string;
var
  BoundaryPos: Integer;
  BoundaryStart: Integer;
  BoundaryEnd: Integer;
  BoundaryValue: string;
begin
  Result := '';
  BoundaryPos := Pos('boundary=', LowerCase(ContentTypeHeader));
  if BoundaryPos > 0 then
  begin
    BoundaryStart := BoundaryPos + 9;
    if (BoundaryStart <= Length(ContentTypeHeader)) and (ContentTypeHeader[BoundaryStart] = '"') then
    begin
      Inc(BoundaryStart);
      BoundaryEnd := Pos('"', ContentTypeHeader, BoundaryStart);
      if BoundaryEnd = 0 then BoundaryEnd := Length(ContentTypeHeader) + 1;
    end
    else
    begin
      BoundaryEnd := Pos(';', ContentTypeHeader, BoundaryStart);
      if BoundaryEnd = 0 then BoundaryEnd := Length(ContentTypeHeader) + 1;
    end;
    BoundaryValue := Copy(ContentTypeHeader, BoundaryStart, BoundaryEnd - BoundaryStart);
    Result := Trim(BoundaryValue);
  end;
end;

function THttpBodyParser.GetBodyContentType(const ContentTypeStr: string): TBodyContentType;
var
  LowerType: string;
begin
  LowerType := LowerCase(Trim(ContentTypeStr));

  if LowerType = '' then
    Result := bctUnknown
  else if Pos('application/json', LowerType) = 1 then
    Result := bctApplicationJson
  else if Pos('application/x-www-form-urlencoded', LowerType) = 1 then
    Result := bctApplicationFormUrlEncoded
  else if Pos('text/plain', LowerType) = 1 then
    Result := bctTextPlain
  else if Pos('application/xml', LowerType) = 1 then
    Result := bctApplicationXml
  else if Pos('text/xml', LowerType) = 1 then
    Result := bctApplicationXml
  else if Pos('text/html', LowerType) = 1 then
    Result := bctTextHtml
  else if Pos('application/octet-stream', LowerType) = 1 then
    Result := bctApplicationOctetStream
  else if Pos('application/pdf', LowerType) = 1 then
    Result := bctApplicationPdf
  else if Pos('image/png', LowerType) = 1 then
    Result := bctImagePng
  else if Pos('image/jpeg', LowerType) = 1 then
    Result := bctImageJpeg
  else if Pos('image/jpg', LowerType) = 1 then
    Result := bctImageJpeg
  else if Pos('image/gif', LowerType) = 1 then
    Result := bctImageGif
  else if Pos('image/webp', LowerType) = 1 then
    Result := bctImageWebp
  else if Pos('image/svg', LowerType) = 1 then
    Result := bctImageSvg
  else if Pos('multipart/form-data', LowerType) = 1 then
    Result := bctMultipartFormData
  else if Pos('multipart/mixed', LowerType) = 1 then
    Result := bctMultipartMixed
  else if Pos('application/javascript', LowerType) = 1 then
    Result := bctApplicationJavascript
  else if Pos('text/css', LowerType) = 1 then
    Result := bctApplicationCss
  else if Pos('application/zip', LowerType) = 1 then
    Result := bctApplicationZip
  else if Pos('application/rar', LowerType) = 1 then
    Result := bctApplicationRar
  else if Pos('video/', LowerType) = 1 then
    Result := bctVideo
  else if Pos('audio/', LowerType) = 1 then
    Result := bctAudio
  else if Pos('application/msgpack', LowerType) = 1 then
    Result := bctApplicationMsgPack
  else if Pos('application/protobuf', LowerType) = 1 then
    Result := bctApplicationProtobuf
  else if Pos('application/cbor', LowerType) = 1 then
    Result := bctApplicationCbor
  else
    Result := bctUnknown;
end;

procedure THttpBodyParser.DetermineBodyType;
begin
  FBodyType := GetBodyContentType(FContentType);
  case FBodyType of
    bctMultipartFormData, bctMultipartMixed:
      if FBoundary <> '' then
      begin
        FMainPart := TMultipartBodyPart.Create(FBoundary, 'main', FMaxBodySize,
                                              FDiskFileManager, FUseDiskStorage);
        if Assigned(FOnPartComplete) then
          TMultipartBodyPart(FMainPart).OnPartComplete := FOnPartComplete;
      end
      else
         SetError('Multipart content type without boundary');

    bctApplicationOctetStream, bctApplicationPdf, bctImagePng, bctImageJpeg,
    bctImageGif, bctImageWebp, bctImageSvg, bctApplicationZip,
    bctApplicationRar, bctVideo, bctAudio:
      FMainPart := TBinaryBodyPart.Create('main', FMaxBodySize, FDiskFileManager, FUseDiskStorage);

  else
    FMainPart := TTextBodyPart.Create('main', FMaxBodySize, FDiskFileManager, FUseDiskStorage);
  end;

  if Assigned(FMainPart) then
  begin
    if FContentLength > 0 then
    begin
      if FMainPart is TTextBodyPart then
         TTextBodyPart(FMainPart).ExpectedLength := FContentLength
      else if FMainPart is TBinaryBodyPart then
            TBinaryBodyPart(FMainPart).ExpectedLength := FContentLength;
    end;
    FParts.AddPart(FMainPart);
  end;
end;

function THttpBodyParser.DetectContentEncoding(const EncodingHeader: string): TContentEncoding;
var
  LowerEncoding: string;
begin
  LowerEncoding := LowerCase(Trim(EncodingHeader));

  if Pos('gzip', LowerEncoding) > 0 then
    Result := ceGzip
  else if Pos('deflate', LowerEncoding) > 0 then
    Result := ceDeflate
  else if Pos('br', LowerEncoding) > 0 then
    Result := ceBrotli
  else
    Result := ceNone;
end;

function THttpBodyParser.AppendData(const Data: array of Byte; Size: Integer): Boolean;
var
  DataToProcess: TBytes;
  ChunkHeader: AnsiString;
  LineEndPos: Integer;
  P: PByte;
  EndPtr: PByte;
  TempStream: TMemoryStream;
begin
  Result := False;
  if FHasError or FIsComplete then Exit(True);
  if Size <= 0 then Exit(True);

  if not FIsChunked then
  begin
    if (FMaxBodySize > 0) and (FCurrentSize + Size > FMaxBodySize) then
    begin
      SetError(Format('Body size exceeds maximum allowed (%d bytes)', [FMaxBodySize]));
      Exit;
    end;
    if Assigned(FMainPart) then
    begin
      if not FMainPart.AppendData(Data, Size) then
      begin
        SetError('Failed to append data to main part: ' + FMainPart.ErrorMessage);
        Exit;
      end;
    end;
    FCurrentSize := FCurrentSize + Size;
    if (FContentLength > 0) and (FCurrentSize >= FContentLength) then
      FIsComplete := True;
    Result := True;
  end
  else
  begin
    FBuffer.Position := FBuffer.Size;
    FBuffer.Write(Data, Size);
    FBuffer.Position := 0;
    while (FBuffer.Position < FBuffer.Size) and not FIsComplete do
    begin
      P := Pointer(IntPtr(FBuffer.Memory) + FBuffer.Position);
      EndPtr := Pointer(IntPtr(FBuffer.Memory) + FBuffer.Size);
      case FChunkState of
        0:
        begin
          var SearchPtr := P;
          LineEndPos := -1;
          while SearchPtr < (EndPtr - 1) do
          begin
            if (SearchPtr^ = 13) and ((SearchPtr+1)^ = 10) then
            begin
              LineEndPos := SearchPtr - PByte(FBuffer.Memory);
              break;
            end;
            Inc(SearchPtr);
          end;
          if LineEndPos > -1 then
          begin
            var LineLen := LineEndPos - FBuffer.Position;
            SetString(ChunkHeader, PAnsiChar(P), LineLen);
            FBuffer.Position := LineEndPos + 2;
            FCurrentChunkSize := ExtractChunkSize(string(ChunkHeader));
            if FCurrentChunkSize < 0 then
            begin
              SetError('Invalid chunk size format');
              Exit;
            end;
            if FCurrentChunkSize = 0 then FChunkState := 2 else
            begin
              FCurrentChunkReceived := 0;
              FChunkState := 1;
            end;
          end else
            Break;
        end;
        1:
        begin
          var BytesAvailable := EndPtr - P;
          var BytesToRead := Min(FCurrentChunkSize - FCurrentChunkReceived, BytesAvailable);
          if BytesToRead > 0 then
          begin
            SetLength(DataToProcess, BytesToRead);
            FBuffer.ReadBuffer(DataToProcess[0], BytesToRead);
            if Assigned(FMainPart) and not FMainPart.AppendData(DataToProcess, BytesToRead) then
            begin
              SetError('Failed to append chunk data to part');
              Exit;
            end;
            FCurrentSize := FCurrentSize + BytesToRead;
            FCurrentChunkReceived := FCurrentChunkReceived + BytesToRead;
          end;
          if FCurrentChunkReceived >= FCurrentChunkSize then
            FChunkState := 2
          else
            Break;
        end;
        2:
        begin
          if (EndPtr - P) >= 2 then
          begin
            if (P^ = 13) and ((P+1)^ = 10) then
            begin
              FBuffer.Position := FBuffer.Position + 2;
              if FCurrentChunkSize = 0 then
              begin
                FIsComplete := True;
                Break;
              end else
                FChunkState := 0;
            end else
            begin
              SetError('Missing CRLF after chunk data');
              Exit;
            end;
          end else
            Break;
        end;
      end;
    end;
    var RemainingBytes := FBuffer.Size - FBuffer.Position;
    if RemainingBytes > 0 then
    begin
      SetLength(DataToProcess, RemainingBytes);
      FBuffer.ReadBuffer(DataToProcess[0], RemainingBytes);
      FBuffer.Clear;
      FBuffer.WriteBuffer(DataToProcess[0], RemainingBytes);
    end
    else if FBuffer.Position >= FBuffer.Size then
    begin
      FBuffer.Clear;
    end;
    Result := True;
  end;
end;

function THttpBodyParser.GetMainPartAsString: string;
begin
  try
    if Assigned(FMainPart) and (FMainPart is TMultipartBodyPart) then
    begin
      Result := TMultipartBodyPart(FMainPart).GetAsString;
    end
    else if Assigned(FMainPart) then
    begin
      Result := FMainPart.AsString;
    end
    else
    begin
      Result := '';
    end;
  except
    on E: Exception do
      Result := 'Error getting main part as string: ' + E.Message;
  end;
end;

function THttpBodyParser.GetMainPartAsBytes: TBytes;
begin
  SetLength(Result, 0);

  try
    if Assigned(FMainPart) then
      Result := FMainPart.AsBytes;
  except
    on E: Exception do
    begin
      Logger.Error('GetMainPartAsBytes failed: ' + E.Message);
      SetLength(Result, 0);
    end;
  end;
end;

function THttpBodyParser.ProcessChunkedData(const Data: array of Byte; Size: Integer): TBytes;
var
  I: Integer;
  ChunkHeader: string;
  ChunkSize: Integer;
  DataToProcess: TBytes;
  ResultSize: Integer;
begin
  SetLength(Result, 0);
  ResultSize := 0;
  FBuffer.WriteBuffer(Data[0], Size);
  FBuffer.Position := 0;
  SetLength(DataToProcess, FBuffer.Size);
  if FBuffer.Size > 0 then
     FBuffer.ReadBuffer(DataToProcess[0], FBuffer.Size);
  I := 0;
  while I < Length(DataToProcess) do
  begin
    case FChunkState of
      0:
      begin
        ChunkHeader := '';
        while (I < Length(DataToProcess)) and (DataToProcess[I] <> 13) and (DataToProcess[I] <> 10) do
        begin
          ChunkHeader := ChunkHeader + Chr(DataToProcess[I]);
          Inc(I);
        end;
        if (I < Length(DataToProcess)) and (DataToProcess[I] = 13) then
           Inc(I);
        if (I < Length(DataToProcess)) and (DataToProcess[I] = 10) then
           Inc(I);

        if ChunkHeader <> '' then
        begin
          FCurrentChunkSize := ExtractChunkSize(ChunkHeader);
          FCurrentChunkReceived := 0;
          if FCurrentChunkSize = 0 then
          begin
            FIsComplete := True;
            Break;
          end
          else
          begin
            FChunkState := 1;
          end;
        end;
      end;
      1:
      begin
        var BytesToRead := Min(FCurrentChunkSize - FCurrentChunkReceived,
                              Length(DataToProcess) - I);
        if BytesToRead > 0 then
        begin
          SetLength(Result, ResultSize + BytesToRead);
          Move(DataToProcess[I], Result[ResultSize], BytesToRead);
          ResultSize := ResultSize + BytesToRead;

          FCurrentChunkReceived := FCurrentChunkReceived + BytesToRead;
          I := I + BytesToRead;
        end;
        if FCurrentChunkReceived >= FCurrentChunkSize then
        begin
          FChunkState := 2;
        end;
      end;
      2:
      begin
        if (I < Length(DataToProcess)) and (DataToProcess[I] = 13) then
           Inc(I);
        if (I < Length(DataToProcess)) and (DataToProcess[I] = 10) then
          Inc(I);

        FChunkState := 0;
      end;
    end;
  end;
  FBuffer.Clear;
end;

function THttpBodyParser.ExtractChunkSize(const ChunkHeader: string): Integer;
var
  HexSize: string;
  SemicolonPos: Integer;
begin
  Result := 0;
  try
    HexSize := Trim(ChunkHeader);
    SemicolonPos := Pos(';', HexSize);
    if SemicolonPos > 0 then
       HexSize := Copy(HexSize, 1, SemicolonPos - 1);
    HexSize := Trim(HexSize);
     if HexSize <> '' then
       Result := StrToInt('$' + HexSize);
  except
    on E: Exception do
    begin
      Logger.Error('Failed to parse chunk size: ' + ChunkHeader + ', error: ' + E.Message);
      Result := 0;
    end;
  end;
end;

function THttpBodyParser.DecompressData(const Data: TBytes; Encoding: TContentEncoding): TBytes;
begin
  SetLength(Result, Length(Data));
  if Length(Data) > 0 then
     Move(Data[0], Result[0], Length(Data));
end;

function THttpBodyParser.ValidateFilename(const Filename: string): Boolean;
var
  Extension: string;
begin
  Result := True;
  if Filename = '' then
     Exit;
  if Length(Filename) > FSecuritySettings.MaxFilenameLength then
  begin
    Result := False;
    Exit;
  end;
  if FSecuritySettings.AllowedFileExtensions.Count > 0 then
  begin
    Extension := LowerCase(ExtractFileExt(Filename));
    Result := FSecuritySettings.AllowedFileExtensions.IndexOf(Extension) >= 0;
  end;
end;

function THttpBodyParser.ValidateMimeType(const MimeType: string): Boolean;
begin
  Result := True;
  if MimeType = '' then
     Exit;
  Result := FSecuritySettings.BlockedMimeTypes.IndexOf(LowerCase(MimeType)) = -1;
end;

function THttpBodyParser.SanitizeFieldName(const FieldName: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';

  for I := 1 to Length(FieldName) do
  begin
    C := FieldName[I];
    if CharInSet(C, ['a'..'z', 'A'..'Z', '0'..'9', '_', '-']) then
       Result := Result + C;
  end;
  if Length(Result) > FSecuritySettings.MaxFieldNameLength then
     Result := Copy(Result, 1, FSecuritySettings.MaxFieldNameLength);
end;


end.
