@echo off
setlocal EnableDelayedExpansion
title OpenKey Companion - Standalone Release Packager (Windows)
echo ================================================================
echo   OpenKey Companion - Standalone Release Packager (.exe / .msi)
echo ================================================================
echo.

cd /d "%~dp0"

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Rust / Cargo was not found on your system PATH.
    echo.
    echo To build native Windows executables (.exe / .msi), Rust is required.
    echo.
    echo [Option 1 - Automatic via winget]:
    echo   winget install Rustlang.Rustup
    echo.
    echo [Option 2 - Manual installer]:
    echo   1. Download rustup-init from https://rustup.rs
    echo   2. Run rustup-init.exe (select default MSVC toolchain)
    echo   3. Ensure Visual Studio Build Tools (C++ workload) is installed
    echo.
    set /p INSTALL_RUST="Would you like to run 'winget install Rustlang.Rustup' now? (y/n): "
    if /i "!INSTALL_RUST!"=="y" (
        echo Installing Rustup via winget...
        winget install Rustlang.Rustup
        echo.
        echo Please restart your terminal/PowerShell after installation and run this script again.
        pause
        exit /b 0
    )
    exit /b 1
)

echo [1/3] Verifying Node.js and NPM dependencies...
call npm install

echo.
echo [2/3] Building native standalone release binaries (Tauri/Rust)...
echo Compiling optimized release build...
call npx --yes @tauri-apps/cli build

echo.
if %errorlevel% equ 0 (
    echo ================================================================
    echo [✓] Build Succeeded! Executable binaries generated:
    echo ================================================================
    echo.
    echo 1. Standalone Portable Executable:
    echo    src-tauri\target\release\openkey-desktop-manager.exe
    echo.
    echo 2. Windows Installer (.msi):
    echo    src-tauri\target\release\bundle\msi\
    echo.
    echo Opening output folder...
    start "" "%~dp0src-tauri\target\release\bundle\msi"
) else (
    echo.
    echo [X] Build encountered an error. Please inspect the log messages above.
)

pause
