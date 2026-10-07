@echo off
title Risk Intelligence System (CRIE)
cd /d "%~dp0"
echo ========================================================
echo   Launching Risk Intelligence System (CRIE)...
echo ========================================================
python start.py
if errorlevel 1 (
    echo.
    echo [ERROR] An error occurred while launching.
    pause
)

