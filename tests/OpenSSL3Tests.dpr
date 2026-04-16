program OpenSSL3Tests;

{$APPTYPE CONSOLE}
//{$STRONGLINKTYPES ON}
//{$SetPEFlags $20}  // IMAGE_FILE_LARGE_ADDRESS_AWARE
//{$MAXSTACKSIZE 16777216}  // 16 MB stack — OpenSSL asm routines need room
uses
  {$IFDEF EurekaLog}
  EMemLeaks,
  EResLeaks,
  EDebugJCL,
  EDebugExports,
  EFixSafeCallException,
  EMapWin32,
  EAppConsole,
  EDialogConsole,
  ExceptionLog7,
  {$ENDIF EurekaLog}
  System.SysUtils,
  Winapi.Windows,
  DUnitX.TestFramework,
  libOpenSSL3,
  TestOpenSSL3API in 'TestOpenSSL3API.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;
  Logger: ITestLogger;
begin
  // Suppress crash dialogs (WER) for unattended execution
  SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX);
  try
    TDUnitX.CheckCommandLine;
    Runner := TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Logger := TOpenSSLTestLogger.Create;
    Runner.AddLogger(Logger);
    Runner.FailsOnNoAsserts := False;

    Results := Runner.Execute;
    if not Results.AllPassed then
      System.ExitCode := 1
    else
      System.ExitCode := 0;
  except
    on E: Exception do
    begin
      System.ExitCode := 1;
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;

  {$IFNDEF CI}
  if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
  begin
    Write('Press Enter to exit...');
    Readln;
  end;
  {$ENDIF}
end.





