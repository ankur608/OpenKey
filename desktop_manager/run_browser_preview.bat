@echo off
title OpenKey Companion - Browser Mode
echo ===================================================
echo   OpenKey Companion App (Interactive Browser Mode)
echo ===================================================
echo.
echo Launching local server on http://localhost:3000 ...
start http://localhost:3000
python -m http.server 3000 --directory "%~dp0ui"
pause
