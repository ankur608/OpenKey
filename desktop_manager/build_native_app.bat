@echo off
title OpenKey Companion - Native Desktop App Builder
echo ===================================================
echo   OpenKey Companion - Native Desktop App (Rust/Tauri)
echo ===================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Rust/Cargo was not found on your PATH.
    echo.
    echo To compile the native desktop executable (.exe), please install Rust:
    echo 1. Download rustup from: https://rustup.rs
    echo 2. Run rustup-init.exe (Default installation: x86_64-pc-windows-msvc)
    echo 3. Ensure Visual Studio C++ Build Tools or Build Tools for VS is installed.
    echo.
    echo Press any key to open the Rust download page, or close this window.
    pause
    start https://rustup.rs
    exit /b 1
)

echo [✓] Rust/Cargo detected!
echo [1] Compiling and running OpenKey Companion in development mode...
cd "%~dp0"
call npx --yes @tauri-apps/cli dev
pause
