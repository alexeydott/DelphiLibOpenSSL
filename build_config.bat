@echo off
REM ============================================================================
REM  build_config.bat <target>
REM
REM  Shared configuration for all OpenSSL 3.x/4.x build scripts.
REM  Edit the machine-specific paths below to match your environment.
REM
REM  Environment:
REM    OPENSSL_BRANCH   3 or 4 (default=4). Controls source path and output dirs.
REM
REM  Targets:
REM    bcc32_classic  Embarcadero BCC32 classic (C89, register), Win32
REM    bcc32c         Embarcadero BCC32C Clang (C11, cdecl), Win32
REM    bcc64          Embarcadero BCC64 Clang (C11, cdecl), Win64
REM    msvc_win32     Microsoft Visual C x86
REM    msvc_win64     Microsoft Visual C x64
REM
REM  Usage (from a build script):
REM    call "%~dp0build_config.bat" bcc32_classic
REM    if errorlevel 1 exit /b 1
REM ============================================================================

REM === Machine-specific paths (edit for your environment) ====================
set "PERL_DIR=C:\programdata\strawberry\perl\bin"
set "RAD_STUDIO=D:\Embarcadero RAD Studio\23.0"
set "VS_BUILD=D:\VisualStudio2019\VC\Auxiliary\Build"
REM ============================================================================

REM === OpenSSL branch selection (default=4) ===
if not defined OPENSSL_BRANCH set "OPENSSL_BRANCH=4"

REM === Version-to-path mapping ===
if "%OPENSSL_BRANCH%"=="3" set "OPENSSL_SRC=%~dp0c_src\openssl-openssl-3.6.1"
if "%OPENSSL_BRANCH%"=="4" set "OPENSSL_SRC=%~dp0c_src\openssl-openssl-4.0.0"
if "%OPENSSL_BRANCH%"=="3" set "OBJ_DIR=obj3"
if "%OPENSSL_BRANCH%"=="4" set "OBJ_DIR=obj4"
set "INC_PREFIX=%OBJ_DIR%_"

REM === Validate OPENSSL_BRANCH ===
if not defined OBJ_DIR (
    echo ERROR: Invalid OPENSSL_BRANCH=%OPENSSL_BRANCH%. Must be 3 or 4.
    exit /b 1
)

REM === Clear per-target variables ===
set "RSVARS="
set "OBJ_OUT="

REM === Per-target: RSVARS and OBJ_OUT ===
if "%~1"=="bcc32_classic" set "RSVARS=%RAD_STUDIO%\bin\rsvars.bat"
if "%~1"=="bcc32_classic" set "OBJ_OUT=%~dp0%OBJ_DIR%\win32\bcc"
if "%~1"=="bcc32c"        set "RSVARS=%RAD_STUDIO%\bin\rsvars.bat"
if "%~1"=="bcc32c"        set "OBJ_OUT=%~dp0%OBJ_DIR%\win32\bcc32c"
if "%~1"=="bcc64"         set "RSVARS=%RAD_STUDIO%\bin64\rsvars64.bat"
if "%~1"=="bcc64"         set "OBJ_OUT=%~dp0%OBJ_DIR%\win64\bcc"
if "%~1"=="msvc_win32"    set "RSVARS=%VS_BUILD%\vcvars32.bat"
if "%~1"=="msvc_win32"    set "OBJ_OUT=%~dp0%OBJ_DIR%\win32\vc"
if "%~1"=="msvc_win64"    set "RSVARS=%VS_BUILD%\vcvars64.bat"
if "%~1"=="msvc_win64"    set "OBJ_OUT=%~dp0%OBJ_DIR%\win64\vc"

REM === Validate target ===
if not defined RSVARS goto :bad_target

REM === Add Perl to PATH ===
set "PATH=%PERL_DIR%;%PATH%"

REM === Validate environment setup script exists ===
if not exist "%RSVARS%" goto :no_rsvars

REM === Initialize compiler environment ===
call "%RSVARS%"
if errorlevel 1 goto :rsvars_failed

REM === Guarantee correct compiler/tools version on PATH ===
for %%I in ("%RSVARS%") do set "PATH=%%~dpI;%PATH%"

goto :eof

:bad_target
echo ERROR: Unknown build target "%~1"
echo Valid targets: bcc32_classic, bcc32c, bcc64, msvc_win32, msvc_win64
exit /b 1

:no_rsvars
echo ERROR: Environment setup script not found:
echo   %RSVARS%
echo.
echo Edit build_config.bat to set the correct paths for your machine.
exit /b 1

:rsvars_failed
echo ERROR: Failed to initialize compiler environment from:
echo   %RSVARS%
exit /b 1
