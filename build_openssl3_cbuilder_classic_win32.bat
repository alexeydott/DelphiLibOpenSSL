@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM  Build OpenSSL 3.x/4.x for Win32 using Embarcadero C++Builder
REM
REM  Uses the BC-32-classic configuration from Configurations/50-cppbuilder.conf
REM  Compiler: bcc32 (classic 32-bit with -pr register calling convention)
REM
REM  Prerequisites:
REM    - RAD Studio / C++Builder installed
REM    - Perl (e.g. Strawberry Perl) in PATH
REM
REM  NOTE: Assembly is disabled (no-asm) because NASM output is not
REM        compatible with the Embarcadero toolchain.
REM
REM  Usage:
REM    build_openssl3_cbuilder_win32.bat
REM
REM  Output:
REM    .\%OBJ_DIR%\win32\bcc\*_win32.obj  -  object files for static linking with Delphi
REM ============================================================================

echo [1/9] Setting up environment...
call "%~dp0build_config.bat" bcc32_classic
if errorlevel 1 exit /b 1

REM NOTE: BDS_JUNCTION is NOT needed. Borland make's CC path-with-spaces issue
REM is handled by patch_makefile_borland.py (CC=cmd /c bcc32), and bcc32.cfg
REM paths work fine with quoted paths containing spaces.

REM === Check prerequisites ===
echo [2/9] Checking prerequisites...

where perl >nul 2>&1
if errorlevel 1 (
    echo ERROR: Perl not found in PATH.
    echo Install Strawberry Perl from https://strawberryperl.com/
    exit /b 1
)
echo   Perl: OK

where bcc32.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: bcc32.exe not found. RAD Studio environment not set up correctly.
    exit /b 1
)
echo   bcc32.exe: OK

where make.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: make.exe not found.
    exit /b 1
)
echo   make.exe: OK

REM === Ensure BC-32-classic target exists in 50-cppbuilder.conf ===
echo [3/9] Ensuring BC-32-classic configuration...
python "%~dp0helpers\ensure_bcc32_classic_conf.py"
if errorlevel 1 (
    echo WARNING: Failed to generate BC-32-classic config. Build may fail.
)

REM === Patch sources for static linking (all compilers) ===
echo [4/9] Patching OpenSSL sources for static linking...

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH. Required for patching.
    exit /b 1
)

python "%~dp0helpers\patch_static_link.py" --apply
if errorlevel 1 (
    echo WARNING: Static-link patching reported errors.
)

REM === Patch sources for C89 compatibility (BCC32 classic) ===
echo     Patching for BCC32 C89 compatibility...

python "%~dp0helpers\patch_c89.py" --apply
if errorlevel 1 (
    echo WARNING: C89 patching reported errors. Build may fail.
)

REM === Configure OpenSSL ===
echo [5/9] Configuring OpenSSL for BC-32-classic...

cd /d "%OPENSSL_SRC%"
if errorlevel 1 (
    echo ERROR: OpenSSL source directory not found: %OPENSSL_SRC%
    exit /b 1
)

REM no-asm is required: NASM output is incompatible with Embarcadero toolchain
REM no-shared: we need static .obj files only
REM --prefix=%CD%: install into the source tree
set "CONFIGURE_OPTS=BC-32-classic --prefix=%CD% no-makedepend no-asm no-shared no-tests no-module"

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
REM Case-collision renames are baked into the BC-32-classic target defines
perl Configure %CONFIGURE_OPTS% CFLAGS="-DSTATIC_LEGACY -DOPENSSL_STATIC_LINK -DDECLSPEC_IMPORT="
if errorlevel 1 (
    echo ERROR: OpenSSL Configure failed.
    exit /b 1
)

REM === Fix bcc32.cfg for classic compiler ===
REM The global bcc32.cfg (in BDS\bin) uses semicolons in -I paths which classic bcc32
REM doesn't support (that syntax is for bcc32c/Clang). We temporarily replace it.
echo [5.5/9] Fixing bcc32.cfg for classic compiler...
if exist "%BDS%\bin\bcc32.cfg" (
    if not exist "%BDS%\bin\bcc32.cfg.bak" (
        copy /y "%BDS%\bin\bcc32.cfg" "%BDS%\bin\bcc32.cfg.bak" >nul
    )
)
(
echo -I"%BDS%\include"
echo -I"%BDS%\include\dinkumware"
echo -I"%BDS%\include\windows\crtl"
echo -I"%BDS%\include\windows\sdk"
echo -L"%BDS%\lib\win32\release"
echo -L"%BDS%\lib\win32\release\psdk"
) > "%BDS%\bin\bcc32.cfg"

REM === Patch Makefile for Borland make compatibility ===
echo [6/9] Patching Makefile for Borland make compatibility...
python "%~dp0helpers\patch_makefile_borland.py"
if errorlevel 1 (
    echo WARNING: Makefile patching reported errors. Build may fail.
)

REM === Build ===
echo [7/9] Building OpenSSL (this may take several minutes)...

make -N clean >nul 2>&1

REM Step 1: build_generated — runs Perl scripts to generate headers/incs
make -N build_generated
if errorlevel 1 (
    echo ERROR: OpenSSL build_generated failed.
    exit /b 1
)
echo   build_generated completed.

REM Step 2: Compile library targets (skip apps/ and template provider)
REM We target specific .lib files instead of build_libs_nodep to avoid
REM compiling apps/ (OpenSSL CLI tools) which have C99 code not covered by patch_c89.
REM Build each library target separately to work around Borland make's inline response
REM file bug (MAKE0003+ temp files get corrupted when building multiple AR targets).
REM Delete MAKE*.@@@ temp files between each invocation to reset the counter.
set MAKEFLAGS=
for %%L in (libcrypto.lib libssl.lib providers\libcommon.lib providers\libdefault.lib providers\liblegacy.lib) do (
    del /q MAKE*.@@@ >nul 2>&1
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

REM === Restore original sources and bcc32.cfg ===
echo Restoring original OpenSSL sources...
python "%~dp0helpers\patch_c89.py" --restore
python "%~dp0helpers\patch_static_link.py" --restore
REM Restore original bcc32.cfg
if exist "%BDS%\bin\bcc32.cfg.bak" (
    copy /y "%BDS%\bin\bcc32.cfg.bak" "%BDS%\bin\bcc32.cfg" >nul
    echo   bcc32.cfg restored.
)

REM === Collect object files ===
echo [8/9] Creating output directory and collecting object files...

if not exist "%OBJ_OUT%" mkdir "%OBJ_OUT%"

set "OBJ_COUNT=0"

REM Collect only library .obj files (libcrypto, libssl, libdefault, liblegacy, libcommon)
for /R "%OPENSSL_SRC%" %%f in (*.obj) do (
    set "FNAME=%%~nf"
    echo !FNAME! | findstr /I /B /C:"libcrypto-lib-" /C:"libssl-lib-" /C:"libdefault-lib-" /C:"liblegacy-lib-" /C:"libcommon-lib-" >nul
    if not errorlevel 1 (
        copy /Y "%%f" "%OBJ_OUT%\!FNAME!_win32.obj" >nul
        set /a OBJ_COUNT+=1
    )
)

echo   Collected !OBJ_COUNT! object files.

REM === Generate Delphi .inc file ===
echo [9/9] Generating %OBJ_DIR%_L_win32_bcc.inc...

set "INC_FILE=%~dp0%OBJ_DIR%_L_win32_bcc.inc"
set "INC_PATH=%OBJ_DIR%\win32\bcc"
set "INC_COUNT=0"

> "%INC_FILE%" echo // Auto-generated by %~nx0
for %%f in ("%OBJ_OUT%\*_win32.obj") do (
    set "ONAME=%%~nf"
    >> "%INC_FILE%" echo {$L %INC_PATH%\!ONAME!}
    set /a INC_COUNT+=1
)

echo   Generated !INC_COUNT! {$L} directives in %OBJ_DIR%_L_win32_bcc.inc

REM === Verify: check for uncovered case-insensitive collisions ===
echo.
echo [POST] Checking for uncovered symbol collisions...
python "%~dp0helpers\gen_case_collision_fixes.py" --verify --compiler bcc32
if errorlevel 1 (
    echo.
    echo WARNING: New case-insensitive symbol collisions detected!
    echo Run:  python helpers\gen_case_collision_fixes.py --update
    echo Then rebuild to apply the updated header.
)

REM === Done ===
echo.
echo.
echo Object files are in: %OBJ_OUT%
echo Naming convention: {name}_win32.obj
echo.
echo Include path: %OPENSSL_SRC%\include
echo.
echo NOTE: C++Builder OpenSSL support is experimental.
echo Set your include search path to: %OPENSSL_SRC%\include
echo Set your library search path to: %OBJ_OUT%
echo.

endlocal
