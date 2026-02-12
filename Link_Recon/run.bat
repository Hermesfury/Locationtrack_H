@echo off
REM Link Recon - Run Script
REM Activates venv and runs the tool

echo ============================================
echo   Link Recon - Starting
echo ============================================
echo.

REM Check if venv exists
if not exist venv\Scripts\activate.bat (
    echo ERROR: Virtual environment not found!
    echo Please run setup_venv.bat first to create the venv.
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate

echo.
echo Running Link Recon...
echo.

REM Run the tool with any passed arguments
python infogather.py %*

echo.
pause
