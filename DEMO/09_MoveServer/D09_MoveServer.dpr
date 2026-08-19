program D09_MoveServer;

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

{$APPTYPE CONSOLE}

{$R *.res}

uses
  FASTMM5,
  Quick.Logger,
  Quick.Logger.Provider.Files,
  Quick.Logger.Provider.Console,
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  System.SyncObjs,
  System.DateUtils,
  System.StrUtils,
  System.IOUtils,
  System.JSON,
  System.Math,
  Winapi.Windows,
  Winapi.WinSock2,
  GWebSocket in '..\..\src\GWebSocket.pas',
  GHttpsServerIOCP in '..\..\src\GHttpsServerIOCP.pas',
  GJWTManager in '..\..\src\GJWTManager.pas',
  GRequest in '..\..\src\GRequest.pas',
  GRequestBody in '..\..\src\GRequestBody.pas',
  GResponse in '..\..\src\GResponse.pas',
  OverlappedExPool in '..\..\src\OverlappedExPool.pas',
  WinApiAdditions in '..\..\src\WinApiAdditions.pas';

procedure ConfigureFastMM;
begin
  FastMM_EnterDebugMode;
  FastMM_MessageBoxEvents := [];
  FastMM_LogToFileEvents := FastMM_LogToFileEvents + [mmetUnexpectedMemoryLeakDetail,
                            mmetUnexpectedMemoryLeakSummary,
                            mmetDebugBlockDoubleFree,
                            mmetDebugBlockReallocOfFreedBlock];
end;

const
  SERVER_PORT = 8089;
  CertStoreName = 'GHttpsIOCPSvr';
  DEFAULT_TS_FILENAME = 'stream_live.ts';
  SEGMENT_DURATION_SEC = 2.0;

type
  TDynamicHlsLiveEngine = class
  private
    FSourcePath: string;
    FLastModTime: Int64;
    FSegments: TArray<TBytes>;
    FSegmentCount: Integer;
    FStartTime: TDateTime;
    FLock: TCriticalSection;
    procedure CheckAndReloadSource;
  public
    constructor Create(const ASourcePath: string);
    destructor Destroy; override;
    function GetLiveManifest: string;
    function GetSegment(SeqNumber: Integer): TBytes;
    function GetStatusJSON(ActiveViewers: Integer): string;
    property SegmentCount: Integer read FSegmentCount;
    property SourcePath: string read FSourcePath;
  end;

  TDynamicTelemetryThread = class(TThread)
  private
    FServer: TGHttpsServerIOCP;
    FEngine: TDynamicHlsLiveEngine;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TGHttpsServerIOCP; AEngine: TDynamicHlsLiveEngine);
  end;

var
  GLiveEngine: TDynamicHlsLiveEngine = nil;
  GTelemetryThread: TDynamicTelemetryThread = nil;

{ TDynamicHlsLiveEngine }

constructor TDynamicHlsLiveEngine.Create(const ASourcePath: string);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FSourcePath := ASourcePath;
  FLastModTime := 0;
  FStartTime := Now;
  CheckAndReloadSource;
end;

destructor TDynamicHlsLiveEngine.Destroy;
begin
  FLock.Free;
  inherited Destroy;
end;

procedure TDynamicHlsLiveEngine.CheckAndReloadSource;
var
  ModTime: Int64;
  FileBytes: TBytes;
  TotalPackets, I, PacketOffset: Integer;
  Pkt: PByte;
  Pusi: Boolean;
  Pid, Afc, Offset, PayloadLen: Integer;
  IsKeyframe: Boolean;
  GopOffsets: TList<Integer>;
  StartIdx, EndIdx, SegLen, S: Integer;
  PatPmtHeader: TBytes;
begin
  if not FileExists(FSourcePath) then
     Exit;

  ModTime := DateTimeToUnix(TFile.GetLastWriteTime(FSourcePath));
  if (ModTime = FLastModTime) and (FSegmentCount > 0) then
    Exit;

  FLock.Enter;
  try
    if (ModTime = FLastModTime) and (FSegmentCount > 0) then
      Exit;

    FileBytes := TFile.ReadAllBytes(FSourcePath);
    if Length(FileBytes) < 188 then
      Exit;

    TotalPackets := Length(FileBytes) div 188;
    GopOffsets := TList<Integer>.Create;
    try
      SetLength(PatPmtHeader, 0);
      if TotalPackets >= 3 then
      begin
        SetLength(PatPmtHeader, 564);
        Move(FileBytes[0], PatPmtHeader[0], 564);
      end;

      for I := 0 to TotalPackets - 1 do
      begin
        PacketOffset := I * 188;
        Pkt := @FileBytes[PacketOffset];
        if Pkt^ <> $47 then
          Continue;

        Pusi := (PByte(Pkt + 1)^ and $40) <> 0;
        Pid := ((PByte(Pkt + 1)^ and $1F) shl 8) or PByte(Pkt + 2)^;

        if Pusi and (Pid >= 256) and (Pid <= 258) then
        begin
          Afc := (PByte(Pkt + 3)^ shr 4) and 3;
          Offset := 4;
          if (Afc = 2) or (Afc = 3) then
            Offset := Offset + 1 + PByte(Pkt + 4)^;

          if Offset < 184 then
          begin
            PayloadLen := 188 - Offset;
            IsKeyframe := False;
            for S := Offset to 188 - 5 do
            begin
              if (FileBytes[PacketOffset + S] = 0) and
                 (FileBytes[PacketOffset + S + 1] = 0) and
                 ((FileBytes[PacketOffset + S + 2] = 1) and
                  ((FileBytes[PacketOffset + S + 3] and $1F) = 7) or
                  (FileBytes[PacketOffset + S + 2] = 0) and
                   (FileBytes[PacketOffset + S + 3] = 1) and
                     ((FileBytes[PacketOffset + S + 4] and $1F) = 7)) then
              begin
                IsKeyframe := True;
                Break;
              end;
            end;

            if IsKeyframe then
            begin
              var SegStartPacket := I;
              if (I > 0) and (FileBytes[(I-1)*188] = $47) and
                 ((((FileBytes[(I-1)*188 + 1] and $1F) shl 8) or
                    FileBytes[(I-1)*188 + 2]) = 0) then
                SegStartPacket := I - 1;
              GopOffsets.Add(SegStartPacket * 188);
            end;
          end;
        end;
      end;

      if GopOffsets.Count = 0 then
      begin
        var PacketsPerSegment := TotalPackets div 15;
        if PacketsPerSegment < 1 then
           PacketsPerSegment := TotalPackets;
        I := 0;
        while I < TotalPackets do
        begin
          GopOffsets.Add(I * 188);
          Inc(I, PacketsPerSegment);
        end;
      end;

      if GopOffsets.Count > 0 then
        GopOffsets[0] := 0;

      FSegmentCount := GopOffsets.Count;
      SetLength(FSegments, FSegmentCount);

      for I := 0 to FSegmentCount - 1 do
      begin
        StartIdx := GopOffsets[I];
        if I < FSegmentCount - 1 then
          EndIdx := GopOffsets[I + 1]
        else
          EndIdx := Length(FileBytes);

        SegLen := EndIdx - StartIdx;
        if (I = 0) or (Length(PatPmtHeader) = 0) then
        begin
          SetLength(FSegments[I], SegLen);
          Move(FileBytes[StartIdx], FSegments[I][0], SegLen);
        end
        else
        begin
          SetLength(FSegments[I], Length(PatPmtHeader) + SegLen);
          Move(PatPmtHeader[0], FSegments[I][0], Length(PatPmtHeader));
          Move(FileBytes[StartIdx], FSegments[I][Length(PatPmtHeader)], SegLen);
        end;
      end;

      FLastModTime := ModTime;
      Logger.Info('HLS Dynamic Engine natively parsed %d MPEG-TS segments into RAM (100%% pure Delphi, zero external tools)',
        [FSegmentCount]);
    finally
      GopOffsets.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

function OffsetTsSegment(const ASrcBytes: TBytes; DeltaSeconds: Double): TBytes;
var
  DeltaPts, TotalLen, PktOffset: Int64;
  Pusi: Boolean;
  Afc, AfLen, PayloadOffset, PtsDtsFlags: Integer;
  PcrBase, NewPcr: Int64;
  Pts, NewPts, Dts, NewDts: Int64;
  B0, B1, B2, B3, B4: Byte;
begin
  if (DeltaSeconds <= 0.0001) or (Length(ASrcBytes) < 188) then
    Exit(ASrcBytes);

  DeltaPts := Round(DeltaSeconds * 90000.0);
  TotalLen := Length(ASrcBytes);
  SetLength(Result, TotalLen);
  Move(ASrcBytes[0], Result[0], TotalLen);

  PktOffset := 0;
  while PktOffset <= TotalLen - 188 do
  begin
    if Result[PktOffset] = $47 then
    begin
      Pusi := (Result[PktOffset + 1] and $40) <> 0;
      Afc := (Result[PktOffset + 3] shr 4) and 3;

      if (Afc = 2) or (Afc = 3) then
      begin
        AfLen := Result[PktOffset + 4];
        if (AfLen >= 7) and ((Result[PktOffset + 5] and $10) <> 0) then
        begin
          PcrBase := (Int64(Result[PktOffset + 6]) shl 25) or
                     (Int64(Result[PktOffset + 7]) shl 17) or
                     (Int64(Result[PktOffset + 8]) shl 9)  or
                     (Int64(Result[PktOffset + 9]) shl 1)  or
                     (Int64(Result[PktOffset + 10]) shr 7);

          NewPcr := (PcrBase + DeltaPts) and $1FFFFFFFF;

          Result[PktOffset + 6]  := Byte((NewPcr shr 25) and $FF);
          Result[PktOffset + 7]  := Byte((NewPcr shr 17) and $FF);
          Result[PktOffset + 8]  := Byte((NewPcr shr 9) and $FF);
          Result[PktOffset + 9]  := Byte((NewPcr shr 1) and $FF);
          Result[PktOffset + 10] := Byte((Result[PktOffset + 10] and $7F) or ((NewPcr and 1) shl 7));
        end;
      end;

      if Pusi and ((Afc = 1) or (Afc = 3)) then
      begin
        PayloadOffset := 4;
        if Afc = 3 then
           PayloadOffset := 5 + Result[PktOffset + 4];

        if (PayloadOffset + 14 <= 188) and
           (Result[PktOffset + PayloadOffset] = 0) and
           (Result[PktOffset + PayloadOffset + 1] = 0) and
           (Result[PktOffset + PayloadOffset + 2] = 1) and
           (Result[PktOffset + PayloadOffset + 3] >= $E0) and
           (Result[PktOffset + PayloadOffset + 3] <= $EF) then
        begin
          PtsDtsFlags := (Result[PktOffset + PayloadOffset + 7] shr 6) and 3;

          if (PtsDtsFlags in [2, 3]) and (PayloadOffset + 14 <= 188) then
          begin
            B0 := Result[PktOffset + PayloadOffset + 9];
            B1 := Result[PktOffset + PayloadOffset + 10];
            B2 := Result[PktOffset + PayloadOffset + 11];
            B3 := Result[PktOffset + PayloadOffset + 12];
            B4 := Result[PktOffset + PayloadOffset + 13];

            Pts := (Int64(B0 and $0E) shl 29) or
                   (Int64(B1) shl 22) or
                   (Int64(B2 and $FE) shl 14) or
                   (Int64(B3) shl 7) or
                   (Int64(B4) shr 1);

            NewPts := (Pts + DeltaPts) and $1FFFFFFFF;

            Result[PktOffset + PayloadOffset + 9]  := Byte((Result[PktOffset + PayloadOffset + 9] and $F0) or ((NewPts shr 29) and $0E) or 1);
            Result[PktOffset + PayloadOffset + 10] := Byte((NewPts shr 22) and $FF);
            Result[PktOffset + PayloadOffset + 11] := Byte(((NewPts shr 14) and $FE) or 1);
            Result[PktOffset + PayloadOffset + 12] := Byte((NewPts shr 7) and $FF);
            Result[PktOffset + PayloadOffset + 13] := Byte(((NewPts shl 1) and $FE) or 1);
          end;

          if (PtsDtsFlags = 3) and (PayloadOffset + 19 <= 188) then
          begin
            B0 := Result[PktOffset + PayloadOffset + 14];
            B1 := Result[PktOffset + PayloadOffset + 15];
            B2 := Result[PktOffset + PayloadOffset + 16];
            B3 := Result[PktOffset + PayloadOffset + 17];
            B4 := Result[PktOffset + PayloadOffset + 18];

            Dts := (Int64(B0 and $0E) shl 29) or
                   (Int64(B1) shl 22) or
                   (Int64(B2 and $FE) shl 14) or
                   (Int64(B3) shl 7) or
                   (Int64(B4) shr 1);

            NewDts := (Dts + DeltaPts) and $1FFFFFFFF;

            Result[PktOffset + PayloadOffset + 14] := Byte((Result[PktOffset + PayloadOffset + 14] and $F0) or ((NewDts shr 29) and $0E) or 1);
            Result[PktOffset + PayloadOffset + 15] := Byte((NewDts shr 22) and $FF);
            Result[PktOffset + PayloadOffset + 16] := Byte(((NewDts shr 14) and $FE) or 1);
            Result[PktOffset + PayloadOffset + 17] := Byte((NewDts shr 7) and $FF);
            Result[PktOffset + PayloadOffset + 18] := Byte(((NewDts shl 1) and $FE) or 1);
          end;
        end;
      end;
    end;
    Inc(PktOffset, 188);
  end;
end;

function TDynamicHlsLiveEngine.GetLiveManifest: string;
var
  ElapsedSec: Double;
  CurrentSeq: Integer;
  StartSeq, I, Seq: Integer;
  SB: TStringBuilder;
  WindowCount: Integer;
begin
  CheckAndReloadSource;

  FLock.Enter;
  try
    if FSegmentCount <= 0 then
    begin
      Result := '#EXTM3U' + sLineBreak +
                '#EXT-X-VERSION:3' + sLineBreak +
                '#EXT-X-TARGETDURATION:2' + sLineBreak +
                '#EXT-X-MEDIA-SEQUENCE:0' + sLineBreak;
      Exit;
    end;

    ElapsedSec := (Now - FStartTime) * 86400.0;
    CurrentSeq := Trunc(ElapsedSec / SEGMENT_DURATION_SEC);

    WindowCount := 5;
    StartSeq := Max(0, CurrentSeq - (WindowCount - 1));

    SB := TStringBuilder.Create;
    try
      SB.AppendLine('#EXTM3U');
      SB.AppendLine('#EXT-X-VERSION:3');
      SB.AppendLine('#EXT-X-TARGETDURATION:2');
      SB.AppendLine(Format('#EXT-X-MEDIA-SEQUENCE:%d', [StartSeq]));

      for I := 0 to WindowCount - 1 do
      begin
        Seq := StartSeq + I;
        SB.AppendLine('#EXTINF:2.000,');
        SB.AppendLine(Format('/live/segment_%d.ts', [Seq]));
      end;

      Result := SB.ToString;
    finally
      SB.Free;
    end;
  finally
    FLock.Leave;
  end;
end;

function TDynamicHlsLiveEngine.GetSegment(SeqNumber: Integer): TBytes;
var
  LocalIdx, LoopIdx: Integer;
  DeltaSec: Double;
  RawBytes: TBytes;
begin
  CheckAndReloadSource;

  FLock.Enter;
  try
    if FSegmentCount <= 0 then
    begin
      SetLength(Result, 0);
      Exit;
    end;

    LocalIdx := SeqNumber mod FSegmentCount;
    if LocalIdx < 0 then
      LocalIdx := (LocalIdx + FSegmentCount) mod FSegmentCount;

    LoopIdx := SeqNumber div FSegmentCount;
    DeltaSec := LoopIdx * (FSegmentCount * SEGMENT_DURATION_SEC);

    RawBytes := FSegments[LocalIdx];

    if DeltaSec > 0.0001 then
      Result := OffsetTsSegment(RawBytes, DeltaSec)
    else
      Result := RawBytes;
  finally
    FLock.Leave;
  end;
end;

function TDynamicHlsLiveEngine.GetStatusJSON(ActiveViewers: Integer): string;
var
  ElapsedSec: Double;
  CurrentSeq, LocalIdx, LoopIdx: Integer;
  RemainingLoopSec: Double;
  TotalDur: Double;
begin
  CheckAndReloadSource;

  FLock.Enter;
  try
    ElapsedSec := (Now - FStartTime) * 86400.0;
    if FSegmentCount > 0 then
    begin
      CurrentSeq := Trunc(ElapsedSec / SEGMENT_DURATION_SEC);
      LocalIdx := CurrentSeq mod FSegmentCount;
      if LocalIdx < 0 then
         LocalIdx := 0;
      LoopIdx := CurrentSeq div FSegmentCount;
      TotalDur := FSegmentCount * SEGMENT_DURATION_SEC;
      RemainingLoopSec := Max(0.0, TotalDur - (LocalIdx * SEGMENT_DURATION_SEC));
    end
    else
    begin
      CurrentSeq := 0;
      LocalIdx := 0;
      LoopIdx := 0;
      RemainingLoopSec := 0.0;
      TotalDur := 0.0;
    end;

    Result := Format(
      '{"status":"broadcasting",' +
      '"uptime_sec":%.1f,' +
      '"current_seq":%d,' +
      '"segment_index":%d,' +
      '"loop_number":%d,' +
      '"segment_count":%d,' +
      '"total_duration_sec":%.1f,' +
      '"remaining_loop_sec":%.1f,' +
      '"active_viewers":%d,' +
      '"protocol":"HLS Live (RFC 8216)",' +
      '"video_source":"%s"}',
      [ElapsedSec, CurrentSeq, LocalIdx, LoopIdx, FSegmentCount, TotalDur, RemainingLoopSec, ActiveViewers, ExtractFileName(FSourcePath)],
      TFormatSettings.Invariant
    );
  finally
    FLock.Leave;
  end;
end;

{ TDynamicTelemetryThread }

constructor TDynamicTelemetryThread.Create(AServer: TGHttpsServerIOCP; AEngine: TDynamicHlsLiveEngine);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FServer := AServer;
  FEngine := AEngine;
end;

procedure TDynamicTelemetryThread.Execute;
begin
  while not Terminated do
  begin
    if Assigned(FServer) and Assigned(FEngine) then
      FServer.BroadcastWebSocket(FEngine.GetStatusJSON(FServer.GetWebSocketActiveCount));
    Sleep(1000);
  end;
end;

function GetWebRootDir: string;
begin
  Result := TPath.Combine(ExtractFilePath(ParamStr(0)), 'www');
end;

function ResolveSourceFilePath: string;
var
  ExeDir, CandidateFile: string;
begin
  if (ParamCount >= 1) and FileExists(ParamStr(1)) then
    Exit(ParamStr(1));

  ExeDir := ExtractFilePath(ParamStr(0));

  CandidateFile := TPath.Combine(ExeDir, DEFAULT_TS_FILENAME);
  if TFile.Exists(CandidateFile) then
     Exit(CandidateFile);

  CandidateFile := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\' + DEFAULT_TS_FILENAME));
  if TFile.Exists(CandidateFile) then
     Exit(CandidateFile);

  Result := TPath.Combine(ExeDir, DEFAULT_TS_FILENAME);
end;

function TryServeStaticFile(const FilePath: string; const ARequest: TRequest; const AResponse: TResponse): Boolean;
var
  Ext, ContentType: string;
  FileBytes: TBytes;
  ETagVal: string;
begin
  Result := False;
  if not FileExists(FilePath) then Exit;

  Ext := LowerCase(TPath.GetExtension(FilePath));
  if Ext = '.html' then
     ContentType := 'text/html; charset=utf-8'
  else if Ext = '.css' then
     ContentType := 'text/css'
  else if Ext = '.js' then
     ContentType := 'application/javascript'
  else if Ext = '.png' then
     ContentType := 'image/png'
  else if Ext = '.json' then
     ContentType := 'application/json'
  else if Ext = '.m3u8' then
     ContentType := 'application/vnd.apple.mpegurl; charset=utf-8'
  else if Ext = '.ts' then
     ContentType := 'video/mp2t'
  else if Ext = '.mp4' then
     ContentType := 'video/mp4'
  else
     ContentType := 'application/octet-stream';

  FileBytes := TFile.ReadAllBytes(FilePath);
  ETagVal := Format('"%d-%d"', [Length(FileBytes), DateTimeToUnix(TFile.GetLastWriteTime(FilePath))]);

  if (ARequest.Headers.GetHeader('If-None-Match') = ETagVal) then
  begin
    AResponse.SetStatus(304);
    AResponse.AddHeader('ETag', ETagVal);
    Exit(True);
  end;

  AResponse.SetStatus(200);
  AResponse.AddHeader('ETag', ETagVal);
  AResponse.AddHeader('Access-Control-Allow-Origin', '*');
  AResponse.AddBinaryContent(ContentType, FileBytes);
  Result := True;
end;

begin
  ConfigureFastMM;
  try
    Logger.Providers.Add(GlobalLogFileProvider);
    Logger.Providers.Add(GlobalLogConsoleProvider);

    var LogDir := '.\Log';
    if not TDirectory.Exists(LogDir) then
      TDirectory.CreateDirectory(LogDir);

    with GlobalLogFileProvider do
    begin
      FileName := LogDir + '\Logger.log';
      DailyRotate := True;
      MaxFileSizeInMB := 50;
      LogLevel := LOG_ALL;
      Enabled := True;
    end;

    with GlobalLogConsoleProvider do
    begin
      LogLevel := LOG_DEBUG;
      ShowEventColors := True;
      Enabled := True;
    end;

    Logger.Info('=====================================================');
    Logger.Info('  DEMO 09: Universal HLS Live Server (VLC & Web)');
    Logger.Info('=====================================================');

    var WebRootDir := GetWebRootDir;
    var SourceFile := ResolveSourceFilePath;
    Logger.Info('Web Root Directory: ' + WebRootDir);
    Logger.Info('Active Video File:  ' + SourceFile);

    GLiveEngine := TDynamicHlsLiveEngine.Create(SourceFile);

    var Server := TGHttpsServerIOCP.Create(SERVER_PORT,
                                           'localhost',
                                           CertStoreName,
                                           'Abcd1234Efgh5678Ijkl9012Mnop3456Qrst7890Uvwx1234Yz!',
                                           2000,
                                           1000000);
    try
      Server.SetSSLShutdownOptions(True, 200);

      var TelemetryThread := TDynamicTelemetryThread.Create(Server, GLiveEngine);
      GTelemetryThread := TelemetryThread;

      Server.RegisterEndpointProc('/live/stream.m3u8', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest;
                           const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          if Assigned(GLiveEngine) then
          begin
            var ManifestText := GLiveEngine.GetLiveManifest;
            AResponse.SetStatus(200);
            AResponse.AddHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            AResponse.AddHeader('Access-Control-Allow-Origin', '*');
            AResponse.AddTextContent('application/vnd.apple.mpegurl; charset=utf-8', ManifestText);
          end
          else
            AResponse.SetNotFound('HLS Live Stream Engine not ready.');
        end);

      Server.RegisterEndpointProc('/api/status', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(200);
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if Assigned(GLiveEngine) then
            AResponse.AddJSONContent(GLiveEngine.GetStatusJSON(AServer.GetWebSocketActiveCount))
          else
            AResponse.AddJSONContent('{"status":"idle"}');
        end);

      Server.OnWebSocketConnect := procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession)
        begin
          if Assigned(GLiveEngine) and Assigned(Session) then
          begin
            Session.SendText(GLiveEngine.GetStatusJSON(AServer.GetWebSocketActiveCount));
            AServer.TriggerWebSocketWrite(Session);
          end;
        end;

      Server.RegisterWebSocketRoute('/status-ws',
        procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession;
                  const MessageText: string; Opcode: TWebSocketOpcode)
        begin
          if Assigned(GLiveEngine) and Assigned(Session) then
          begin
            Session.SendText(GLiveEngine.GetStatusJSON(AServer.GetWebSocketActiveCount));
            AServer.TriggerWebSocketWrite(Session);
          end;
        end);

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          Uri, SegNumStr, RelPath, FullPath: string;
          SegNum: Integer;
          SegBytes: TBytes;
        begin
          Uri := ARequest.RequestInfo.Path;

          if Uri.StartsWith('/live/segment_') and Uri.EndsWith('.ts') then
          begin
            SegNumStr := Copy(Uri, 15, Length(Uri) - 17);
            if TryStrToInt(SegNumStr, SegNum) and Assigned(GLiveEngine) then
            begin
              SegBytes := GLiveEngine.GetSegment(SegNum);
              if Length(SegBytes) > 0 then
              begin
                AResponse.SetStatus(200);
                AResponse.AddHeader('Content-Type', 'video/mp2t');
                AResponse.AddHeader('Cache-Control', 'public, max-age=60');
                AResponse.AddHeader('Access-Control-Allow-Origin', '*');
                AResponse.AddBinaryContent('video/mp2t', SegBytes);
                Exit;
              end;
            end;
          end;

          RelPath := Uri;
          while (Length(RelPath) > 0) and ((RelPath[1] = '/') or (RelPath[1] = '\')) do
            Delete(RelPath, 1, 1);

          if RelPath = '' then
             RelPath := 'index.html';
          FullPath := TPath.Combine(WebRootDir, RelPath);

          if TryServeStaticFile(FullPath, ARequest, AResponse) then Exit;

          FullPath := TPath.Combine(WebRootDir, 'index.html');
          if not TryServeStaticFile(FullPath, ARequest, AResponse) then
            AResponse.SetNotFound('Resource not found: ' + Uri);
        end);

      Server.Start;
      Logger.Info('=====================================================');
      Logger.Info('  HLS Live Cinema Broadcast Running on port: ' + IntToStr(SERVER_PORT));
      Logger.Info('  Web UI Stream URL:  https://localhost:' + IntToStr(SERVER_PORT) + '/');
      Logger.Info('  VLC Stream URL:     https://localhost:' + IntToStr(SERVER_PORT) + '/live/stream.m3u8');
      Logger.Info('  WebSocket Status:   wss://localhost:' + IntToStr(SERVER_PORT) + '/status-ws');
      Logger.Info('=====================================================');
      Logger.Info('Press ENTER to shut down server cleanly...');

      ReadLn;

      Logger.Info('Stopping telemetry thread...');
      TelemetryThread.Terminate;
      TelemetryThread.WaitFor;
      TelemetryThread.Free;
      GTelemetryThread := nil;

      Logger.Info('Stopping IOCP server...');
      Server.Stop;
    finally
      if Assigned(GLiveEngine) then
      begin
        GLiveEngine.Free;
        GLiveEngine := nil;
      end;
      Server.Free;
    end;
  except
    on E: Exception do
      Logger.Error('Fatal error: ' + E.ClassName + ': ' + E.Message);
  end;
end.
