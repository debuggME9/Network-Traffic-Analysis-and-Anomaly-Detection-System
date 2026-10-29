@echo off
REM Double-click this file to set up (first time only) and start the app on Windows.
cd /d "%~dp0"

if not exist .venv (
    echo First run: creating the virtual environment and installing libraries...
    python -m venv .venv || goto :error
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip
    pip install -r requirements.txt || goto :error
) else (
    call .venv\Scripts\activate.bat
)

echo Starting the app. Close this window to stop it.
streamlit run app.py
goto :eof

:error
echo.
echo Setup failed. Check that 64-bit Python 3.11, 3.12 or 3.13 is installed
echo with "Add python.exe to PATH" ticked, then see README.md - Troubleshooting.
pause
