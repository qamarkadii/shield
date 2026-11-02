@echo off
REM Starts Shield: analyst dashboard (port 8000) + public site (port 8001) + live radar.
REM Keep this window open. Closing it takes aidashield.tech offline (502).
cd /d %~dp0
if not exist .venv\Scripts\activate.bat (
  echo [Shield] .venv not found. Run first:  py -3.14 -m venv .venv
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
python run_shield.py --radar
echo.
echo [Shield] stopped. Read the message above, then press any key.
pause
