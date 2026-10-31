@echo off
cd /d "%~dp0"
echo [1/3] Python environment
python -m venv backend\.venv || goto :err
call backend\.venv\Scripts\activate
pip install -r backend\requirements.txt || goto :err
echo [2/3] Certificate
cd lab-server & python generate_certificate.py || goto :err
cd ..\frontend
echo [3/3] Frontend packages
call npm install || goto :err
echo Setup complete. Run run_all.bat next.
pause & exit /b
:err
echo Setup failed. Check that Python 3.10+ and Node.js 18+ are installed.
pause
