@echo off
REM Link Recon - Virtual Environment Setup Script
REM Run this to create a clean Python virtual environment

echo ============================================
echo   Link Recon - VENV Setup
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

echo [1/3] Creating virtual environment...
python -m venv venv

echo [2/3] Activating virtual environment...
call venv\Scripts\activate

echo [3/3] Verifying installation...
python --version
echo.
echo Virtual environment created successfully!
echo.
echo To run the tool:
echo   1. Run: call venv\Scripts\activate
echo   2. Run: python infogather.py
echo.
echo Or use the run.bat script:
echo   run.bat
echo.
pause
