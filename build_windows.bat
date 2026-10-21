@echo off
rem Builds dist\FileProtect.exe. Run from the project folder on Windows with Python 3.9+ installed.
setlocal
cd /d "%~dp0"

if not exist .venv (
    py -3 -m venv .venv || python -m venv .venv || goto :error
)
call .venv\Scripts\activate.bat || goto :error

python -m pip install --upgrade pip || goto :error
python -m pip install -r requirements-build.txt || goto :error
python -m PyInstaller --clean --noconfirm FileProtect.spec || goto :error

echo.
echo Build complete: %cd%\dist\FileProtect.exe
exit /b 0

:error
echo.
echo Build failed.
exit /b 1
