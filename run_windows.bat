@echo off
cd /d "%~dp0"
python -m streamlit run app.py
if errorlevel 1 (
  echo Neu Python khong co trong PATH, thu: py -m streamlit run app.py
  pause
)
