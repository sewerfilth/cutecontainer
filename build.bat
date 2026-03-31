@echo off
REM cutecontainer build script — Windows (MSVC or MinGW via CMake)
REM
REM Usage:
REM   build.bat                     Build native Release
REM   build.bat --debug             Build Debug
REM   build.bat --test              Build + run tests
REM   build.bat --clean             Clean build output
REM   build.bat --mingw             Force MinGW Makefiles generator
REM
REM Requires: CMake 3.16+, Visual Studio Build Tools (or MinGW)

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BUILD_TYPE=Release"
set "ACTION=build"
set "GENERATOR="
set "BUILDDIR=build\win"

REM ── Parse args ─────────────────────────────────────────────────────

:parse_args
if "%~1"=="" goto configure
if /i "%~1"=="--debug"   ( set "BUILD_TYPE=Debug" & shift & goto parse_args )
if /i "%~1"=="--test"    ( set "ACTION=test" & shift & goto parse_args )
if /i "%~1"=="--clean"   ( if exist build rmdir /s /q build & echo cleaned. & exit /b 0 )
if /i "%~1"=="--mingw"   ( set "GENERATOR=-G \"MinGW Makefiles\"" & shift & goto parse_args )
if /i "%~1"=="--help"    ( goto usage )
echo unknown option: %~1
exit /b 1

:usage
echo Usage: build.bat [--debug] [--test] [--clean] [--mingw]
exit /b 0

REM ── Check CMake ────────────────────────────────────────────────────

:configure
where cmake >nul 2>&1
if errorlevel 1 (
    echo error: cmake not found. Install CMake from https://cmake.org
    exit /b 1
)

if not exist "%BUILDDIR%" mkdir "%BUILDDIR%"

echo build type: %BUILD_TYPE%
echo output: %BUILDDIR%\

REM ── CMake configure ────────────────────────────────────────────────

cmake -S . -B "%BUILDDIR%" %GENERATOR% ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
if errorlevel 1 exit /b 1

REM ── CMake build ────────────────────────────────────────────────────

cmake --build "%BUILDDIR%" --config %BUILD_TYPE% -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 exit /b 1

REM ── Test ───────────────────────────────────────────────────────────

if "%ACTION%"=="test" (
    echo.
    echo === running tests ===
    cd "%BUILDDIR%"
    ctest --build-config %BUILD_TYPE% --output-on-failure
    cd /d "%~dp0"
)

echo.
echo done: %BUILDDIR%\
dir /b "%BUILDDIR%\*.lib" "%BUILDDIR%\*.a" "%BUILDDIR%\*.exe" 2>nul

endlocal
