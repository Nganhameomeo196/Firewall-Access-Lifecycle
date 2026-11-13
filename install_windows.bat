@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Neu Python khong co trong PATH, thu: py -m pip install -r requirements.txt
  pause
)
