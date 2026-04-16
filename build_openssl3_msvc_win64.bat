@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM  Build OpenSSL 3.x/4.x for Win64 using Microsoft Visual C (MSVC)
REM
REM  Prerequisites:
REM    - Visual Studio 2019+ with C++ workload installed
REM    - Perl (e.g. Strawberry Perl) in PATH
REM    - NASM assembler in PATH (optional: use no-asm to skip)
REM
REM  Usage:
REM    build_openssl3_msvc_win64.bat [no-asm]
REM
REM  Output:
REM    .\%OBJ_DIR%\win64\vc\*_win64.obj  -  object files for static linking with Delphi
REM ============================================================================

set "USE_ASM=0"

REM Check for no-asm argument
if /I "%~1"=="no-asm" set "USE_ASM=0"

echo [1/7] Setting up environment...
call "%~dp0build_config.bat" msvc_win64
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

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: cl.exe not found. Visual C environment not set up correctly.
    exit /b 1
)
echo   cl.exe: OK

where nmake.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: nmake.exe not found.
    exit /b 1
)
echo   nmake.exe: OK

if "%USE_ASM%"=="1" (
    where nasm >nul 2>&1
    if errorlevel 1 (
        echo WARNING: NASM not found. Building without assembly optimizations.
        echo Install NASM from https://www.nasm.us/ for better performance.
        set "USE_ASM=0"
    ) else (
        echo   NASM: OK
    )
)

REM === Configure OpenSSL ===
echo [3/7] Configuring OpenSSL for VC-WIN64A...

cd /d "%OPENSSL_SRC%"
if errorlevel 1 (
    echo ERROR: OpenSSL source directory not found: %OPENSSL_SRC%
    exit /b 1
)

REM --- Base configure options ---
set "CONFIGURE_OPTS=VC-WIN64A no-makedepend no-shared no-tests no-module"
if "%USE_ASM%"=="0" set "CONFIGURE_OPTS=%CONFIGURE_OPTS% no-asm"

REM --- Feature flags matching libOpenSSL3.pas {$IFDEF OPENSSL3} directives ---
REM These must stay in sync with the Delphi-side {$DEFINE OPENSSL_NO_*} block.
REM Options marked (default) are already off in OpenSSL 3.x but listed explicitly
REM for documentation and forward-compatibility.
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

REM --- CFLAGS ---
REM DECLSPEC_IMPORT=  — removes __declspec(dllimport) from Windows API declarations
REM   so obj files reference e.g. GetProcAddress instead of __imp_GetProcAddress.
REM   This lets the Delphi linker resolve them from Winapi.Windows imports.
REM /GS-             — disables buffer security checks (__security_cookie)
REM                    which Delphi cannot provide.
REM STATIC_LEGACY    — registers the legacy provider in the built-in provider table
REM                    so it can be loaded without a separate DLL.
REM /Gs4096          — restores default stack probe threshold (4096 bytes).
REM                    OpenSSL sets /Gs0 which forces __chkstk on EVERY function.
REM                    /Gs4096 overrides it: only >4KB frames call __chkstk.
REM                    Note: /Gs without a number equals /Gs0, must specify 4096.
REM _NO_CRT_STDIO_INLINE — prevents UCRT headers from inlining stdio functions as
REM                    __stdio_common_* wrappers. Objects call fprintf/sprintf directly,
REM                    matching the reference build and avoiding ucrtbase.dll dependency.
REM /FI — force-includes openssl_fix_case_collisions.h that renames internal
REM                    functions whose names collide case-insensitively with
REM                    public API wrappers (e.g. ossl_provider_query_operation
REM                    vs OSSL_PROVIDER_query_operation). Delphi's linker is
REM                    case-insensitive and merges them, creating self-calling
REM                    thunks that crash with stack overflow.
set "FIX_HEADER=%~dp0helpers\openssl_fix_case_collisions.h"
REM /MT              — use static C runtime (replaces enable-static-vcruntime removed in 3.6.1)
set "EXTRA_CFLAGS=/MT /DDECLSPEC_IMPORT= /GS- /Gs4096 /D_NO_CRT_STDIO_INLINE /DSTATIC_LEGACY /DOPENSSL_STATIC_LINK /FI"%FIX_HEADER%""

REM === Patch sources for static linking ===
echo [3.5/7] Patching OpenSSL sources for static linking...
python "%~dp0helpers\patch_static_link.py" --apply
if errorlevel 1 (
    echo WARNING: Static-link patching reported errors.
)

perl Configure %CONFIGURE_OPTS% CFLAGS="%EXTRA_CFLAGS%"
if errorlevel 1 (
    echo ERROR: OpenSSL Configure failed.
    exit /b 1
)

REM === Build ===
echo [4/7] Building OpenSSL (this may take several minutes)...

nmake clean >nul 2>&1
nmake build_libs
if errorlevel 1 (
    echo ERROR: OpenSSL build failed.
    exit /b 1
)

REM === Restore original sources ===
echo Restoring original OpenSSL sources...
python "%~dp0helpers\patch_static_link.py" --restore

REM === Collect object files ===
echo [5/7] Creating output directory...

if not exist "%OBJ_OUT%" mkdir "%OBJ_OUT%"

echo [6/7] Collecting object files...

set "OBJ_COUNT=0"

REM Collect only library .obj files (libcrypto, libssl, libdefault, liblegacy, libcommon)
for /R "%OPENSSL_SRC%" %%f in (*.obj) do (
    set "FNAME=%%~nf"
    echo !FNAME! | findstr /I /B /C:"libcrypto-lib-" /C:"libssl-lib-" /C:"libdefault-lib-" /C:"liblegacy-lib-" /C:"libcommon-lib-" >nul
    if not errorlevel 1 (
        copy /Y "%%f" "%OBJ_OUT%\!FNAME!_win64.obj" >nul
        set /a OBJ_COUNT+=1
    )
)

REM Copy MSVC-specific ucrt helper (provides bio_lookup_lock, bio_type_count stubs)
if exist "%~dp0helpers\ossl%OPENSSL_BRANCH%_ucrt_helper_win64.obj" (
    copy /Y "%~dp0helpers\ossl%OPENSSL_BRANCH%_ucrt_helper_win64.obj" "%OBJ_OUT%\ossl%OPENSSL_BRANCH%_ucrt_helper_win64.obj" >nul
    echo   Copied ossl%OPENSSL_BRANCH%_ucrt_helper_win64.obj
    set /a OBJ_COUNT+=1
)

echo   Collected !OBJ_COUNT! object files.

REM === Generate Delphi .inc file ===
echo [7/7] Generating %OBJ_DIR%_L_win64_vc.inc...

set "INC_FILE=%~dp0%OBJ_DIR%_L_win64_vc.inc"
set "INC_PATH=%OBJ_DIR%\win64\vc"
set "INC_COUNT=0"

> "%INC_FILE%" echo // Auto-generated by %~nx0
for %%f in ("%OBJ_OUT%\*_win64.obj") do (
    set "ONAME=%%~nf"
    >> "%INC_FILE%" echo {$L %INC_PATH%\!ONAME!}
    set /a INC_COUNT+=1
)

echo   Generated !INC_COUNT! {$L} directives in %OBJ_DIR%_L_win64_vc.inc

REM === Done ===
echo.
echo.
echo Object files are in: %OBJ_OUT%
echo Naming convention: {name}_win64.obj
echo.
echo Include path: %OPENSSL_SRC%\include
echo.

endlocal
