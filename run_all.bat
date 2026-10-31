@echo off
cd /d "%~dp0"
start "Lab server" cmd /k "cd lab-server && ..\backend\.venv\Scripts\python app.py"
start "API" cmd /k "cd backend && .venv\Scripts\python -m uvicorn main:app --port 8000"
start "Frontend" cmd /k "cd frontend && npm run dev"
timeout /t 6 >nul
start http://localhost:5173
