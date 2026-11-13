@echo off
cd /d "%~dp0"
py -m pip install -r requirements.txt
if errorlevel 1 (
  echo Could not use py. Trying python...
  python -m pip install -r requirements.txt
)
pause
