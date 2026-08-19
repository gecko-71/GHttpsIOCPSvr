{
  MIT License

  Copyright (c) 2026 GECKO-71

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

program D08_MorseAudioServer;

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
  System.NetEncoding,
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
  SERVER_PORT = 8088;
  CertStoreName = 'GHttpsIOCPSvr';
  DEFAULT_BROADCAST_TEXT = 
    'RAGE SING GODDESS THE DESTRUCTIVE RAGE OF ACHILLES SON OF PELEUS THAT BROUGHT COUNTLESS WOES UPON THE ACHAEANS ' +
    'LIKE THE GENERATIONS OF LEAVES SUCH IS THAT OF MEN ' +
    'THE WIND SCATTERS THE LEAVES UPON THE EARTH BUT THE FOREST BURGEONS AGAIN AND OTHER LEAVES GROW IN THE SPRINGTIME ' +
    'SO IS THE RACE OF MEN ONE GENERATION SPRINGS UP AND ANOTHER PASSES AWAY ' +
    'I HAVE ENDURED WHAT NO OTHER MORTAL ON EARTH HAS EVER ENDURED TO PUT MY LIPS TO THE HAND OF THE MAN WHO KILLED MY SON ' +
    'THERE IS A TIME FOR MANY WORDS AND THERE IS ALSO A TIME FOR SLEEP ' +
    'FOR EVEN IN DEATH THE BRAVE LIVES FOREVER IN THE MEMORY OF MEN';
  SAMPLE_RATE = 44100;
  TONE_FREQ = 800;
  DIT_MS = 100;
  DAH_MS = 300;
  ELEMENT_PAUSE_MS = 100;
  LETTER_PAUSE_MS = 300;
  WORD_PAUSE_MS = 700;

type
  TMorseElement = record
    Symbol: string;
    ElementType: string;
    DurationMs: Integer;
    Char: Char;
    CharIndex: Integer;
  end;

  TMorseHelper = class
  public
    class function CharToMorse(C: Char): string;
    class function TextToMorse(const AText: string): string;
    class function GetElements(const AText: string): TArray<TMorseElement>;
    class function GenerateWaveAudio(const AText: string): TBytes;
  end;

  TMorseBroadcastThread = class(TThread)
  private
    FServer: TGHttpsServerIOCP;
    FText: string;
    FElements: TArray<TMorseElement>;
    FTotalDurationMs: Integer;
    FStartTime: TDateTime;
    FCriticalSection: TCriticalSection;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: TGHttpsServerIOCP; const AText: string);
    destructor Destroy; override;
    function GetSyncPayload: string;
  end;

var
  GBroadcastThread: TMorseBroadcastThread = nil;

{ TMorseHelper }

class function TMorseHelper.CharToMorse(C: Char): string;
begin
  C := UpCase(C);
  case C of
    'A': Result := '.-';
    'B': Result := '-...';
    'C': Result := '-.-.';
    'D': Result := '-..';
    'E': Result := '.';
    'F': Result := '..-.';
    'G': Result := '--.';
    'H': Result := '....';
    'I': Result := '..';
    'J': Result := '.---';
    'K': Result := '-.-';
    'L': Result := '.-..';
    'M': Result := '--';
    'N': Result := '-.';
    'O': Result := '---';
    'P': Result := '.--.';
    'Q': Result := '--.-';
    'R': Result := '.-.';
    'S': Result := '...';
    'T': Result := '-';
    'U': Result := '..-';
    'V': Result := '...-';
    'W': Result := '.--';
    'X': Result := '-..-';
    'Y': Result := '-.--';
    'Z': Result := '--..';
    '1': Result := '.----';
    '2': Result := '..---';
    '3': Result := '...--';
    '4': Result := '....-';
    '5': Result := '.....';
    '6': Result := '-....';
    '7': Result := '--...';
    '8': Result := '---..';
    '9': Result := '----.';
    '0': Result := '-----';
    ' ': Result := '/';
  else
    Result := '';
  end;
end;

class function TMorseHelper.TextToMorse(const AText: string): string;
var
  I: Integer;
  M: string;
begin
  Result := '';
  for I := 1 to Length(AText) do
  begin
    M := CharToMorse(AText[I]);
    if M <> '' then
    begin
      if Result <> '' then
        Result := Result + ' ';
      Result := Result + M;
    end;
  end;
end;

class function TMorseHelper.GetElements(const AText: string): TArray<TMorseElement>;
var
  List: TList<TMorseElement>;
  I, J: Integer;
  C: Char;
  M: string;
  Elem: TMorseElement;
begin
  List := TList<TMorseElement>.Create;
  try
    for I := 1 to Length(AText) do
    begin
      C := UpCase(AText[I]);
      Elem.CharIndex := I - 1;

      if C = ' ' then
      begin
        Elem.Symbol := '/';
        Elem.ElementType := 'word_pause';
        Elem.DurationMs := WORD_PAUSE_MS;
        Elem.Char := ' ';
        List.Add(Elem);
        Continue;
      end;

      M := CharToMorse(C);
      for J := 1 to Length(M) do
      begin
        Elem.Char := C;
        if M[J] = '.' then
        begin
          Elem.Symbol := '.';
          Elem.ElementType := 'dit';
          Elem.DurationMs := DIT_MS;
        end
        else if M[J] = '-' then
        begin
          Elem.Symbol := '-';
          Elem.ElementType := 'dah';
          Elem.DurationMs := DAH_MS;
        end;
        List.Add(Elem);

        if J < Length(M) then
        begin
          Elem.Symbol := '';
          Elem.ElementType := 'element_pause';
          Elem.DurationMs := ELEMENT_PAUSE_MS;
          Elem.Char := C;
          List.Add(Elem);
        end;
      end;

      if (I < Length(AText)) and (AText[I + 1] <> ' ') then
      begin
        Elem.Symbol := '';
        Elem.ElementType := 'letter_pause';
        Elem.DurationMs := LETTER_PAUSE_MS;
        Elem.Char := C;
        List.Add(Elem);
      end;
    end;

    Result := List.ToArray;
  finally
    List.Free;
  end;
end;

class function TMorseHelper.GenerateWaveAudio(const AText: string): TBytes;
var
  Elements: TArray<TMorseElement>;
  I, SampleCount, TotalSamples: Integer;
  ToneSamples, SilenceSamples: Integer;
  BufferStream: TMemoryStream;
  SampleVal: SmallInt;
  Angle: Double;
  Header: packed record
    RIFF: array[0..3] of AnsiChar;
    FileSize: UInt32;
    WAVE: array[0..3] of AnsiChar;
    fmt: array[0..3] of AnsiChar;
    Subchunk1Size: UInt32;
    AudioFormat: UInt16;
    NumChannels: UInt16;
    SampleRate: UInt32;
    ByteRate: UInt32;
    BlockAlign: UInt16;
    BitsPerSample: UInt16;
    Data: array[0..3] of AnsiChar;
    DataSize: UInt32;
  end;
begin
  Elements := GetElements(AText);
  TotalSamples := 0;
  for I := 0 to High(Elements) do
    TotalSamples := TotalSamples + Round((Elements[I].DurationMs / 1000.0) * SAMPLE_RATE);

  BufferStream := TMemoryStream.Create;
  try
    FillChar(Header, SizeOf(Header), 0);
    Header.RIFF := 'RIFF';
    Header.WAVE := 'WAVE';
    Header.fmt := 'fmt ';
    Header.Subchunk1Size := 16;
    Header.AudioFormat := 1;
    Header.NumChannels := 1;
    Header.SampleRate := SAMPLE_RATE;
    Header.BitsPerSample := 16;
    Header.ByteRate := SAMPLE_RATE * 1 * 2;
    Header.BlockAlign := 2;
    Header.Data := 'data';
    Header.DataSize := TotalSamples * 2;
    Header.FileSize := Header.DataSize + 36;

    BufferStream.WriteBuffer(Header, SizeOf(Header));

    for I := 0 to High(Elements) do
    begin
      SampleCount := Round((Elements[I].DurationMs / 1000.0) * SAMPLE_RATE);
      if (Elements[I].ElementType = 'dit') or (Elements[I].ElementType = 'dah') then
      begin
        for ToneSamples := 0 to SampleCount - 1 do
        begin
          Angle := 2.0 * Pi * TONE_FREQ * (ToneSamples / SAMPLE_RATE);
          SampleVal := Round(32767.0 * 0.5 * Sin(Angle));
          BufferStream.WriteBuffer(SampleVal, SizeOf(SampleVal));
        end;
      end
      else
      begin
        SampleVal := 0;
        for SilenceSamples := 0 to SampleCount - 1 do
          BufferStream.WriteBuffer(SampleVal, SizeOf(SampleVal));
      end;
    end;

    SetLength(Result, BufferStream.Size);
    BufferStream.Position := 0;
    BufferStream.ReadBuffer(Result[0], BufferStream.Size);
  finally
    BufferStream.Free;
  end;
end;

{ TMorseBroadcastThread }

constructor TMorseBroadcastThread.Create(AServer: TGHttpsServerIOCP; const AText: string);
begin
  inherited Create(False);
  FreeOnTerminate := False;
  FServer := AServer;
  FText := AText;
  FElements := TMorseHelper.GetElements(FText);
  FTotalDurationMs := 0;
  for var E in FElements do
    Inc(FTotalDurationMs, E.DurationMs);
  if FTotalDurationMs = 0 then FTotalDurationMs := 1000;
  FStartTime := Now;
  FCriticalSection := TCriticalSection.Create;
end;

destructor TMorseBroadcastThread.Destroy;
begin
  Terminate;
  WaitFor;
  FCriticalSection.Free;
  inherited Destroy;
end;

function TMorseBroadcastThread.GetSyncPayload: string;
var
  ElapsedMs, CycleOffsetMs, AccumMs: Integer;
  FoundIndex, I: Integer;
  Elem: TMorseElement;
  JSON: TJSONObject;
begin
  FCriticalSection.Enter;
  try
    ElapsedMs := MilliSecondsBetween(Now, FStartTime);
    CycleOffsetMs := ElapsedMs mod FTotalDurationMs;

    AccumMs := 0;
    FoundIndex := 0;
    for I := 0 to High(FElements) do
    begin
      Inc(AccumMs, FElements[I].DurationMs);
      if AccumMs >= CycleOffsetMs then
      begin
        FoundIndex := I;
        Break;
      end;
    end;

    Elem := FElements[FoundIndex];
    JSON := TJSONObject.Create;
    try
      JSON.AddPair('event', 'sync');
      JSON.AddPair('text', FText);
      JSON.AddPair('element_index', TJSONNumber.Create(FoundIndex));
      JSON.AddPair('char_index', TJSONNumber.Create(Elem.CharIndex));
      JSON.AddPair('total_elements', TJSONNumber.Create(Length(FElements)));
      JSON.AddPair('current_char', string(Elem.Char));
      JSON.AddPair('symbol', Elem.Symbol);
      JSON.AddPair('element_type', Elem.ElementType);
      JSON.AddPair('duration_ms', TJSONNumber.Create(Elem.DurationMs));
      JSON.AddPair('elapsed_ms', TJSONNumber.Create(ElapsedMs));
      JSON.AddPair('cycle_offset_ms', TJSONNumber.Create(CycleOffsetMs));
      JSON.AddPair('total_cycle_ms', TJSONNumber.Create(FTotalDurationMs));
      Result := JSON.ToJSON;
    finally
      JSON.Free;
    end;
  finally
    FCriticalSection.Leave;
  end;
end;

procedure TMorseBroadcastThread.Execute;
var
  Payload: string;
begin
  while not Terminated do
  begin
    Payload := GetSyncPayload;
    if Assigned(FServer) then
      FServer.BroadcastWebSocket(Payload);
    Sleep(100);
  end;
end;

function GetQueryParam(const AReq: TRequest; const AParamName: string): string;
var
  QS, Pair: string;
  PosEq: Integer;
  Pairs: TArray<string>;
begin
  Result := '';
  if not Assigned(AReq) then
     Exit;
  if not Assigned(AReq.RequestInfo) then
     Exit;

  QS := AReq.RequestInfo.QueryString;
  if QS = '' then
  begin
    QS := AReq.RequestInfo.RawUri;
    PosEq := Pos('?', QS);
    if PosEq > 0 then
      QS := Copy(QS, PosEq + 1, Length(QS))
    else
      QS := '';
  end;

  if QS = '' then
     Exit;

  if (Length(QS) > 0) and (QS[1] = '?') then
    Delete(QS, 1, 1);

  Pairs := QS.Split(['&']);
  for Pair in Pairs do
  begin
    PosEq := Pos('=', Pair);
    if PosEq > 0 then
    begin
      if SameText(Copy(Pair, 1, PosEq - 1), AParamName) then
      begin
        Result := TNetEncoding.URL.Decode(Copy(Pair, PosEq + 1, Length(Pair)));
        Exit;
      end;
    end;
  end;
end;

function GetMimeType(const AExtension: string): string;
var
  Ext: string;
begin
  Ext := LowerCase(AExtension);
  if (Ext = '.html') or (Ext = '.htm') then
     Exit('text/html; charset=utf-8');
  if Ext = '.css' then
     Exit('text/css; charset=utf-8');
  if Ext = '.js' then
     Exit('application/javascript; charset=utf-8');
  if Ext = '.json' then
     Exit('application/json; charset=utf-8');
  if Ext = '.wav' then
     Exit('audio/wav');
  Result := 'application/octet-stream';
end;

function GetWebRootDir: string;
var
  ExeDir: string;
begin
  ExeDir := ExtractFilePath(ParamStr(0));
  Result := TPath.Combine(ExeDir, 'www');
  if not TDirectory.Exists(Result) then
    Result := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\www'));
  if not TDirectory.Exists(Result) then
    Result := TPath.GetFullPath(TPath.Combine(ExeDir, '..\..\DEMO\08_MorseAudioServer\www'));
  if not TDirectory.Exists(Result) then
    Result := TPath.GetFullPath('DEMO\08_MorseAudioServer\www');
  if not TDirectory.Exists(Result) then
    Result := TPath.GetFullPath('www');
end;

function TryServeStaticFile(const AFilePath: string; const ARequest: TRequest; const AResponse: TResponse): Boolean;
var
  LFileBytes: TBytes;
  LFileStream: TFileStream;
begin
  Result := False;
  if not TFile.Exists(AFilePath) then
     Exit;

  try
    LFileStream := TFileStream.Create(AFilePath, fmOpenRead or fmShareDenyNone);
    try
      SetLength(LFileBytes, LFileStream.Size);
      if LFileStream.Size > 0 then
        LFileStream.ReadBuffer(LFileBytes[0], LFileStream.Size);
    finally
      LFileStream.Free;
    end;

    AResponse.SetStatus(200);
    AResponse.AddHeader('Cache-Control', 'no-cache');
    AResponse.AddBinaryContent(GetMimeType(TPath.GetExtension(AFilePath)), LFileBytes);
    Result := True;
  except
    on E: Exception do
      Result := False;
  end;
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
    Logger.Info('  DEMO 08: Morse Audio Radio Server (IOCP)');
    Logger.Info('=====================================================');

    var WebRootDir := GetWebRootDir;
    Logger.Info('Web Root Directory: ' + WebRootDir);

    var Server := TGHttpsServerIOCP.Create(SERVER_PORT, 'localhost', CertStoreName, 'YourSuperSecretKeyThatIsVeryLongAndVerySecure123!', 2000, 1000000);
    try
      Server.SetSSLShutdownOptions(True, 200);

      Server.RegisterEndpointProc('/api/morse/broadcast', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        begin
          AResponse.SetStatus(200);
          AResponse.AddHeader('Cache-Control', 'no-cache');
          if Assigned(GBroadcastThread) then
            AResponse.AddJSONContent(GBroadcastThread.GetSyncPayload);
        end);

      Server.RegisterEndpointProc('/api/morse/encode', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          InputText, MorseText: string;
          Elements: TArray<TMorseElement>;
          JSON, ElemObj: TJSONObject;
          ElemArray: TJSONArray;
          I: Integer;
          E: TMorseElement;
        begin
          InputText := GetQueryParam(ARequest, 'text');
          if InputText = '' then
             InputText := 'SOS';

          MorseText := TMorseHelper.TextToMorse(InputText);
          Elements := TMorseHelper.GetElements(InputText);

          JSON := TJSONObject.Create;
          try
            JSON.AddPair('text', InputText);
            JSON.AddPair('morse', MorseText);

            ElemArray := TJSONArray.Create;
            for I := 0 to High(Elements) do
            begin
              E := Elements[I];
              ElemObj := TJSONObject.Create;
              ElemObj.AddPair('char', string(E.Char));
              ElemObj.AddPair('symbol', E.Symbol);
              ElemObj.AddPair('type', E.ElementType);
              ElemObj.AddPair('duration_ms', TJSONNumber.Create(E.DurationMs));
              ElemArray.AddElement(ElemObj);
            end;
            JSON.AddPair('elements', ElemArray);

            AResponse.SetStatus(200);
            AResponse.AddHeader('Cache-Control', 'no-cache');
            AResponse.AddJSONContent(JSON.ToJSON);
          finally
            JSON.Free;
          end;
        end);

      Server.RegisterEndpointProc('/api/morse/audio', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          InputText: string;
          WavBytes: TBytes;
        begin
          InputText := GetQueryParam(ARequest, 'text');
          if InputText = '' then
             InputText := 'SOS';

          WavBytes := TMorseHelper.GenerateWaveAudio(InputText);

          AResponse.SetStatus(200);
          AResponse.AddHeader('Cache-Control', 'public, max-age=3600');
          AResponse.AddHeader('Content-Disposition', 'inline; filename="morse.wav"');
          AResponse.AddBinaryContent('audio/wav', WavBytes);
        end);

      Server.RegisterEndpointProc('/api/status', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          JSON: TJSONObject;
          SessionList: TList<TWebSocketSession>;
          ActiveCount: Integer;
          Session: TWebSocketSession;
        begin
          ActiveCount := 0;
          if Assigned(AServer.WebSocketManager) then
          begin
            SessionList := AServer.WebSocketManager.AcquireSessionList;
            try
              ActiveCount := SessionList.Count;
            finally
              for Session in SessionList do
                  Session.Release;
              SessionList.Free;
            end;
          end;

          JSON := TJSONObject.Create;
          try
            JSON.AddPair('status', 'online');
            JSON.AddPair('server', 'GHttpsIOCPSvr-MorseAudio');
            JSON.AddPair('active_listeners', TJSONNumber.Create(ActiveCount));
            JSON.AddPair('broadcast_text', DEFAULT_BROADCAST_TEXT);

            AResponse.SetStatus(200);
            AResponse.AddHeader('Cache-Control', 'no-cache');
            AResponse.AddJSONContent(JSON.ToJSON);
          finally
            JSON.Free;
          end;
        end);

      Server.RegisterWebSocketRoute('/morse-stream',
        procedure(AServer: TGHttpsServerIOCP; Session: TWebSocketSession; const MessageText: string; Opcode: TWebSocketOpcode)
        begin
          if Assigned(GBroadcastThread) and Assigned(Session) then
            Session.SendText(GBroadcastThread.GetSyncPayload);
        end);

      Server.RegisterEndpointProc('/', hmGET,
        procedure(Sender: TObject; const ARequest: TRequest; const AResponse: TResponse; AServer: TGHttpsServerIOCP)
        var
          RelPath, FullPath: string;
        begin
          RelPath := ARequest.RequestInfo.Path;
          while (Length(RelPath) > 0) and ((RelPath[1] = '/') or (RelPath[1] = '\')) do
            Delete(RelPath, 1, 1);

          if RelPath = '' then
             RelPath := 'index.html';
          FullPath := TPath.Combine(WebRootDir, RelPath);

          if TryServeStaticFile(FullPath, ARequest, AResponse) then
             Exit;

          FullPath := TPath.Combine(WebRootDir, 'index.html');
          if not TryServeStaticFile(FullPath, ARequest, AResponse) then
            AResponse.SetNotFound('404 Not Found - DEMO 08 Morse Audio Server');
        end);

      if Server.Start then
      begin
        Logger.Info(Format('Morse Audio Radio server started successfully at https://localhost:%d/', [SERVER_PORT]));

        var BroadcastThread := TMorseBroadcastThread.Create(Server, DEFAULT_BROADCAST_TEXT);
        GBroadcastThread := BroadcastThread;
        try
          Logger.Info('Press [ENTER] to stop the demo server...');
          Readln;
        finally
          GBroadcastThread := nil;
          BroadcastThread.Terminate;
          BroadcastThread.WaitFor;
          BroadcastThread.Free;
        end;

        Server.Stop;
      end;
    finally
      Server.Free;
    end;

    Logger.Info('Server stopped successfully.');
  except
    on E: Exception do
      Logger.Error('Critical server error: ' + E.ClassName + ': ' + E.Message);
  end;
end.
