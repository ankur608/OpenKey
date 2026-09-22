@echo off
title Push OpenKey to GitHub
cd /d "%~dp0"
echo ========================================================
echo   Syncing OpenKey to https://github.com/ankur608/OpenKey
echo ========================================================
echo.
echo Pushing commit to GitHub...
echo If a browser window opens, please sign in / authorize as 'ankur608'.
echo.
git push -u origin main
echo.
if %errorlevel% equ 0 (
    echo [✓] Successfully pushed to https://github.com/ankur608/OpenKey!
    echo.
    echo To trigger Method 1 (Multi-OS Build for Windows, macOS, Linux):
    echo Run the following commands:
    echo   git tag v1.0.0
    echo   git push origin v1.0.0
) else (
    echo [!] Push encountered an authentication error.
    echo Please review the instructions provided in the chat.
)
pause
