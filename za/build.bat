@echo off
REM sigfind build script (MSVC)
REM uses absolute paths so it works from any working directory

setlocal

set "SIGFIND_DIR=%~dp0"
set "VC_INCLUDE=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.52.37025\include"
set "VC_CRT=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.52.37025\crt\include"
set "WIN10_UCRT=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt"
set "WIN10_UM=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um"
set "WIN10_SHARED=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"
set "WIN10_WINRT=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\winrt"
set "WIN10_LIB_UM=C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\um\x64"
set "WIN10_LIB_UCRT=C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\ucrt\x64"
set "VC_LIB=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.52.37025\lib\x64"

echo [1/2] compiling sigfind...
cl.exe /EHsc /O2 /W3 /std:c++17 ^
  /I"%VC_INCLUDE%" /I"%VC_CRT%" /I"%WIN10_UCRT%" /I"%WIN10_UM%" /I"%WIN10_SHARED%" /I"%WIN10_WINRT%" ^
  /I"%SIGFIND_DIR%" ^
  "%SIGFIND_DIR%main.cpp" ^
  /link user32.lib kernel32.lib psapi.lib advapi32.lib libcpmt.lib ^
  /LIBPATH:"%WIN10_LIB_UM%" /LIBPATH:"%WIN10_LIB_UCRT%" /LIBPATH:"%VC_LIB%" ^
  /out:"%SIGFIND_DIR%sigfind.exe"
if %errorlevel% neq 0 (
    echo [FAIL] sigfind compile failed
    pause
    exit /b 1
)

echo [2/2] done: sigfind.exe
echo.
echo usage examples:
echo   "%SIGFIND_DIR%sigfind.exe" dump --name FiveM_b3890_GTAProcess
echo   "%SIGFIND_DIR%sigfind.exe" scan-offline --dump dumps\build_12345.bin --out results.json --build 3890
echo   "%SIGFIND_DIR%sigfind.exe" diff --old results_old.json --new results_new.json
echo   "%SIGFIND_DIR%sigfind.exe" gen --build 3890 --in results.json --out snippet.h
pause
