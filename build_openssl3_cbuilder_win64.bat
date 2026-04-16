@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM  Build OpenSSL 3.x/4.x for Win64 using Embarcadero C++Builder
REM
REM  Uses the BC-64 configuration from Configurations/50-cppbuilder.conf
REM  Compiler: bcc64 (Clang-based 64-bit)
REM
REM  Prerequisites:
REM    - RAD Studio / C++Builder installed
REM    - Perl (e.g. Strawberry Perl) in PATH
REM
REM  NOTE: Assembly is disabled (no-asm) because NASM output is not
REM        compatible with the Embarcadero toolchain.
REM
REM  Usage:
REM    build_openssl3_cbuilder_win64.bat
REM
REM  Output:
REM    .\%OBJ_DIR%\win64\bcc\*_win64.obj  -  object files for static linking with Delphi
REM ============================================================================

echo [1/7] Setting up environment...
call "%~dp0build_config.bat" bcc64
if errorlevel 1 exit /b 1

REM === Check prerequisites ===
echo [2/7] Checking prerequisites...

where perl >nul 2>&1
if errorlevel 1 (
    echo ERROR: Perl not found in PATH.
    echo Install Strawberry Perl from https://strawberryperl.com/
    exit /b 1
)
echo   Perl: OK

where bcc64.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: bcc64.exe not found. RAD Studio environment not set up correctly.
    exit /b 1
)
echo   bcc64.exe: OK

where make.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: make.exe not found.
    exit /b 1
)
echo   make.exe: OK

REM === Configure OpenSSL ===
echo [3/7] Configuring OpenSSL for BC-64...

cd /d "%OPENSSL_SRC%"
if errorlevel 1 (
    echo ERROR: OpenSSL source directory not found: %OPENSSL_SRC%
    exit /b 1
)

REM no-asm is required: NASM output is incompatible with Embarcadero toolchain
REM no-shared: we need static .obj files only
REM --prefix=%CD%: install into the source tree
set "CONFIGURE_OPTS=BC-64 --prefix=%CD% no-makedepend no-asm no-shared no-tests no-module"

REM --- Feature flags matching libOpenSSL3.pas {$IFDEF OPENSSL3} directives ---
REM These must stay in sync with the Delphi-side {$DEFINE OPENSSL_NO_*} block.
REM no-engine is always active in OpenSSL 4.x (engines removed); kept for 3.x compat
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-engine"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-ssl-trace"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-ssl3-method"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-autoload-config"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-crypto-mdebug"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-egd"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-md2"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-rc5"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-sctp"
set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-unit-test"

REM STATIC_LEGACY registers the legacy provider in the built-in provider table
REM DECLSPEC_IMPORT= removes __declspec(dllimport) from API declarations
REM   so obj files reference e.g. GetProcAddress instead of __imp_GetProcAddress.
REM   This lets the Delphi linker resolve them from Winapi.Windows imports.
REM OPENSSL_NO_LOCALE  — disables locale-dependent functions (Embarcadero CRT limitation)
REM _locale_t=void*    — satisfies _locale_t references without locale support
REM _WIN32_WINNT       — Windows 7+ target (required for some winsock2 APIs)
REM _WSPIAPI_H_        — prevents wspiapi.h inclusion (incompatible with Embarcadero)
REM _MSTCPIP_          — prevents mstcpip.h re-inclusion
REM -Xclang -include   — force-includes case-collision rename header via Clang backend.
REM   bcc64's wrapper misparses bare -include as -i (Borland flag), so bypass with -Xclang.
set "FIX_HEADER=%~dp0helpers\openssl_fix_case_collisions.h"
REM Note: bcc64's wrapper misparses -DFOO= (empty value) as -DFOO (=1).
REM Use -Xclang to bypass the wrapper for DECLSPEC_IMPORT= and -include.
set "EXTRA_CFLAGS=-DSTATIC_LEGACY -DOPENSSL_STATIC_LINK -Xclang -DDECLSPEC_IMPORT= -DOPENSSL_NO_LOCALE -D_locale_t=void* -D_WIN32_WINNT=0x0601 -D_WSPIAPI_H_ -D_MSTCPIP_ -Xclang -include -Xclang "%FIX_HEADER%""

REM === Patch sources for static linking ===
echo [3.5/7] Patching OpenSSL sources for static linking...

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH. Required for patching.
    exit /b 1
)

python "%~dp0helpers\patch_static_link.py" --apply
if errorlevel 1 (
    echo WARNING: Static-link patching reported errors.
)

perl Configure %CONFIGURE_OPTS% CFLAGS="%EXTRA_CFLAGS%"
if errorlevel 1 (
    echo ERROR: OpenSSL Configure failed.
    exit /b 1
)

REM === Patch Makefile for Borland make compatibility ===
echo [3.7/7] Patching Makefile for Borland make compatibility...
python "%~dp0helpers\patch_makefile_borland.py"
if errorlevel 1 (
    echo WARNING: Makefile patching reported errors. Build may fail.
)

REM === Build ===
echo [4/7] Building OpenSSL (this may take several minutes)...

make -N clean >nul 2>&1

REM Step 1: build_generated — runs Perl scripts to generate headers/incs
make -N build_generated
if errorlevel 1 (
    echo ERROR: OpenSSL build_generated failed.
    exit /b 1
)
echo   build_generated completed.

REM Step 2: Compile library targets (skip apps/ and template provider)
REM Build each library target separately to work around Borland make's inline response
REM file bug (MAKE0003+ temp files get corrupted when building multiple AR targets).
set MAKEFLAGS=
for %%L in (libcrypto.lib libssl.lib providers\libcommon.lib providers\libdefault.lib providers\liblegacy.lib) do (
    set MAKEFLAGS=
    make -N %%L
    if errorlevel 1 (
        echo ERROR: Failed to build %%L
        echo.
        echo Check the output above for compilation errors.
        exit /b 1
    )
)
echo   build_libs completed successfully.

REM === Restore original sources ===
echo Restoring original OpenSSL sources...
python "%~dp0helpers\patch_static_link.py" --restore

REM === Collect object files ===
echo [5/7] Creating output directory...

if not exist "%OBJ_OUT%" mkdir "%OBJ_OUT%"

echo [6/7] Collecting object files...

set "OBJ_COUNT=0"

REM BC-64 produces .o files (ELF/COFF), not .obj
REM Collect only library objects (libcrypto, libssl, libdefault, liblegacy, libcommon)
for /R "%OPENSSL_SRC%" %%f in (*.obj *.o) do (
    set "FNAME=%%~nf"
    set "FEXT=%%~xf"
    echo !FNAME! | findstr /I /B /C:"libcrypto-lib-" /C:"libssl-lib-" /C:"libdefault-lib-" /C:"liblegacy-lib-" /C:"libcommon-lib-" >nul
    if not errorlevel 1 (
        if /I "!FEXT!"==".o" (
            copy /Y "%%f" "%OBJ_OUT%\!FNAME!_win64.o" >nul
        ) else (
            copy /Y "%%f" "%OBJ_OUT%\!FNAME!_win64.obj" >nul
        )
        set /a OBJ_COUNT+=1
    )
)

echo   Collected !OBJ_COUNT! object files.

REM === Generate Delphi .inc file ===
echo [7/7] Generating %OBJ_DIR%_L_win64_bcc.inc...

set "INC_FILE=%~dp0%OBJ_DIR%_L_win64_bcc.inc"
set "INC_PATH=%OBJ_DIR%\win64\bcc"
set "INC_COUNT=0"

> "%INC_FILE%" echo // Auto-generated by %~nx0
for %%f in ("%OBJ_OUT%\*_win64.obj" "%OBJ_OUT%\*_win64.o") do (
    set "ONAME=%%~nf"
    >> "%INC_FILE%" echo {$L %INC_PATH%\!ONAME!}
    set /a INC_COUNT+=1
)

echo   Generated !INC_COUNT! {$L} directives in %OBJ_DIR%_L_win64_bcc.inc

REM === Done ===
echo.
echo.
echo Object files are in: %OBJ_OUT%
echo Naming convention: {name}_win64.obj or {name}_win64.o
echo.
echo Include path: %OPENSSL_SRC%\include
echo.
echo NOTE: C++Builder 64-bit OpenSSL support is experimental.
echo Set your include search path to: %OPENSSL_SRC%\include
echo Set your library search path to: %OBJ_OUT%
echo.

endlocal
