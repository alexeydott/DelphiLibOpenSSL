@echo off
setlocal EnableDelayedExpansion

REM ============================================================================
REM  Run all OpenSSL3 tests for Win32 and Win64
REM
REM  Prerequisites:
REM    - Delphi compiler (dcc32/dcc64) in PATH via rsvars.bat
REM    - libOpenSSL3.pas compiled / obj files present in obj3\obj4
REM
REM  Usage:
REM    tests\run_tests.bat [win32|win64|all]
REM    Default: all
REM ============================================================================

set "PROJ_ROOT=%~dp0.."
set "TEST_DIR=%~dp0"
set "RUN_WIN32=0"
set "RUN_WIN64=0"

if /I "%~1"=="win32" (set "RUN_WIN32=1") else if /I "%~1"=="win64" (set "RUN_WIN64=1") else (set "RUN_WIN32=1" & set "RUN_WIN64=1")

REM === Setup (reuse centralized config for Delphi compiler env) ===
call "%PROJ_ROOT%\build_config.bat" bcc32_classic
if errorlevel 1 (
    echo ERROR: build_config.bat failed. Check paths in build_config.bat.
    exit /b 1
)

set /a TOTAL_PASS=0
set /a TOTAL_FAIL=0
set /a TOTAL_SKIP=0

echo ============================================================
echo   OpenSSL3 Test Suite
echo ============================================================
echo.

REM === Win32 Tests ===
if "%RUN_WIN32%"=="1" (
    echo --- Win32 Tests ---
    echo.

    where dcc32.exe >nul 2>&1
    if errorlevel 1 (
        echo SKIP: dcc32.exe not found, skipping Win32 tests.
        set /a TOTAL_SKIP+=4

        REM DUnitX test suite
        echo Compiling OpenSSL3Tests ^(Win32^)...
        dcc32 -Q -B "%TEST_DIR%OpenSSL3Tests.dpr" -U"%PROJ_ROOT%" -N0"%TEST_DIR%" >nul 2>&1
        if errorlevel 1 (
            echo   COMPILE FAIL: OpenSSL3Tests
            set /a TOTAL_FAIL+=1
        ) else (
            echo   Running OpenSSL3Tests...
            "%TEST_DIR%OpenSSL3Tests.exe"
            if errorlevel 1 (
                echo   TEST FAIL: OpenSSL3Tests
                set /a TOTAL_FAIL+=1
            ) else (
                echo   TEST PASS: OpenSSL3Tests
                set /a TOTAL_PASS+=1
            )
        )
        echo.
    )
)

REM === Win64 Tests ===
if "%RUN_WIN64%"=="1" (
    echo --- Win64 Tests ---
    echo.

    where dcc64.exe >nul 2>&1
    if errorlevel 1 (
        echo SKIP: dcc64.exe not found, skipping Win64 tests.
        set /a TOTAL_SKIP+=4

        REM DUnitX test suite (Win64)
        echo Compiling OpenSSL3Tests ^(Win64^)...
        dcc64 -Q -B "%TEST_DIR%OpenSSL3Tests.dpr" -U"%PROJ_ROOT%" -N0"%TEST_DIR%" >nul 2>&1
        if errorlevel 1 (
            echo   COMPILE FAIL: OpenSSL3Tests ^(Win64^)
            set /a TOTAL_FAIL+=1
        ) else (
            echo   Running OpenSSL3Tests ^(Win64^)...
            "%TEST_DIR%OpenSSL3Tests.exe"
            if errorlevel 1 (
                echo   TEST FAIL: OpenSSL3Tests ^(Win64^)
                set /a TOTAL_FAIL+=1
            ) else (
                echo   TEST PASS: OpenSSL3Tests ^(Win64^)
                set /a TOTAL_PASS+=1
            )
        )
        echo.
    )
)

REM === Summary ===
echo ============================================================
echo   Results: !TOTAL_PASS! passed, !TOTAL_FAIL! failed, !TOTAL_SKIP! skipped
echo ============================================================

if !TOTAL_FAIL! GTR 0 exit /b 1
exit /b 0
