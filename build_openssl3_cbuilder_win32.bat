@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM  Build OpenSSL 3.x/4.x for Win32 using Embarcadero bcc32c (Clang-based)
REM
REM  Uses the standard BC-32 configuration from Configurations/50-cppbuilder.conf
REM  Compiler: bcc32c (Clang-based 32-bit with cdecl calling convention)
REM
REM  Produces OMF-format object files with cdecl calling convention and
REM  underscore prefix (_functionName) - compatible with dcc32 when using
REM  cdecl + external name '_' + 'functionName' pattern.
REM
REM  Prerequisites:
REM    - RAD Studio / C++Builder with bcc32c installed
REM    - Perl (e.g. Strawberry Perl) in PATH
REM    - Python 3 in PATH (for source patching)
REM
REM  NOTE: Assembly is disabled (no-asm) because NASM output is not
REM        compatible with the Embarcadero toolchain.
REM
REM  Usage:
REM    build_openssl3_bcc32c_win32.bat
REM
REM  Output:
REM    .\%OBJ_DIR%\win32\bcc32c\*_win32.obj  -  OMF object files for static linking with dcc32
REM
REM  NOTE: These objects use cdecl convention (different from bcc32 -pr register).
REM    In libOpenSSL3.pas, enable C_COMPILER_BCC32C to link from %OBJ_DIR%\win32\bcc32c\.
REM ============================================================================

echo [1/8] Setting up environment...
call "%~dp0build_config.bat" bcc32c
if errorlevel 1 exit /b 1

REM === Check prerequisites ===
echo [2/8] Checking prerequisites...

where perl >nul 2>&1
if errorlevel 1 (
    echo ERROR: Perl not found in PATH.
    echo Install Strawberry Perl from https://strawberryperl.com/
    exit /b 1
)
echo   Perl: OK

where bcc32c.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: bcc32c.exe not found. RAD Studio environment not set up correctly.
    exit /b 1
)
echo   bcc32c.exe: OK

where make.exe >nul 2>&1
if errorlevel 1 (
    echo ERROR: make.exe not found.
    exit /b 1
)
echo   make.exe: OK

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH. Required for patching.
    exit /b 1
)
echo   Python: OK

REM === Patch sources for static linking (all compilers) ===
echo [3/8] Patching OpenSSL sources for static linking...

python "%~dp0helpers\patch_static_link.py" --apply
if errorlevel 1 (
    echo WARNING: Static-link patching reported errors.
)

REM === Configure OpenSSL ===
echo [4/8] Configuring OpenSSL for BC-32 (bcc32c)...

cd /d "%OPENSSL_SRC%"
if errorlevel 1 (
    echo ERROR: OpenSSL source directory not found: %OPENSSL_SRC%
    exit /b 1
)

REM no-asm is required: NASM output is incompatible with Embarcadero toolchain
REM no-shared: we need static .obj files only
REM --prefix=%CD%: install into the source tree
set "CONFIGURE_OPTS=BC-32 --prefix=%CD% no-makedepend no-asm no-shared no-tests no-module"

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

REM --- CFLAGS ---
REM STATIC_LEGACY      — registers the legacy provider in the built-in provider table
REM DECLSPEC_IMPORT=   — removes __declspec(dllimport) from API declarations
REM OPENSSL_STATIC_LINK — enables static linking mode
REM OPENSSL_NO_LOCALE  — disables locale-dependent functions (Embarcadero CRT limitation)
REM _locale_t=void*    — satisfies _locale_t references without locale support
REM _WIN32_WINNT       — Windows 7+ target (required for some winsock2 APIs)
REM _WSPIAPI_H_        — prevents wspiapi.h inclusion (incompatible with Embarcadero)
REM _MSTCPIP_          — prevents mstcpip.h re-inclusion
REM -Xclang -include   — force-includes case-collision rename header via Clang backend.
REM                      bcc32c's wrapper misparses bare -include as -i (Borland flag) + "nclude",
REM                      so we bypass the wrapper with -Xclang.
set "FIX_HEADER=%~dp0helpers\openssl_fix_case_collisions.h"
REM Note: bcc32c's wrapper misparses -DFOO= (empty value) as -DFOO (=1).
REM Use -Xclang to bypass the wrapper for DECLSPEC_IMPORT= and -include.
set "EXTRA_CFLAGS=-DSTATIC_LEGACY -DOPENSSL_STATIC_LINK -Xclang -DDECLSPEC_IMPORT= -DOPENSSL_NO_LOCALE -D_locale_t=void* -D_WIN32_WINNT=0x0601 -D_WSPIAPI_H_ -D_MSTCPIP_ -Xclang -include -Xclang "%FIX_HEADER%""

perl Configure %CONFIGURE_OPTS% CFLAGS="%EXTRA_CFLAGS%"
if errorlevel 1 (
    echo ERROR: OpenSSL Configure failed.
    exit /b 1
)

REM === Patch Makefile for Borland make compatibility ===
echo [5/8] Patching Makefile for Borland make compatibility...
python "%~dp0helpers\patch_makefile_borland.py"
if errorlevel 1 (
    echo WARNING: Makefile patching reported errors. Build may fail.
)

REM === Build ===
echo [6/8] Building OpenSSL (this may take several minutes)...

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
REM compiling apps/ (OpenSSL CLI tools) which are not needed for static linking.
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
echo [7/8] Creating output directory and collecting object files...

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
echo [8/8] Generating %OBJ_DIR%_L_win32_bcc32c.inc...

set "INC_FILE=%~dp0%OBJ_DIR%_L_win32_bcc32c.inc"
set "INC_PATH=%OBJ_DIR%\win32\bcc32c"
set "INC_COUNT=0"

> "%INC_FILE%" echo // Auto-generated by %~nx0
for %%f in ("%OBJ_OUT%\*_win32.obj") do (
    set "ONAME=%%~nf"
    >> "%INC_FILE%" echo {$L %INC_PATH%\!ONAME!}
    set /a INC_COUNT+=1
)

echo   Generated !INC_COUNT! {$L} directives in %OBJ_DIR%_L_win32_bcc32c.inc

REM === Verify: check for uncovered case-insensitive collisions ===
echo.
echo [POST] Checking for uncovered symbol collisions...
python "%~dp0helpers\gen_case_collision_fixes.py" --verify --compiler bcc32c
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
echo Format: OMF (compatible with dcc32)
echo Convention: cdecl with underscore prefix (_functionName)
echo.
echo Include path: %OPENSSL_SRC%\include
echo.
echo To use these objects in libOpenSSL3.pas, enable C_COMPILER_BCC32C.

endlocal
