@echo off
setlocal
REM Run every compiler configuration for the selected platform and branch.
REM Usage: tests\run_tests.bat [win32|win64|all]
REM OPENSSL_BRANCH selects 3 or 4; by default both branches are tested.
set "PLATFORM=%~1"
if not defined PLATFORM set "PLATFORM=all"
set "BRANCH_ARG="
if defined OPENSSL_BRANCH set "BRANCH_ARG=-Branches %OPENSSL_BRANCH%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-matrix.ps1" %BRANCH_ARG% -Platform %PLATFORM%
exit /b %errorlevel%
