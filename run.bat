@echo off
title SafeCheck - Risk Intelligence System
cd /d "%~dp0"

echo ========================================================
echo   Launching SafeCheck System...
echo ========================================================

:: Check if virtual environment python exists, fallback to system python
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" start.py
) else (
    python start.py
)

if errorlevel 1 (
    echo.
    echo [ERROR] An error occurred while launching.
    pause
)
