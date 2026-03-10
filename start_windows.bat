@echo off
echo =======================================================
echo   STARTING RANSOMGUARD DETECTION SYSTEM (WINDOWS)
echo =======================================================

echo [1/3] Starting Backend API...
start cmd /k "python backend\app.py"

echo [2/3] Starting React Frontend Dashboard...
cd frontend
start cmd /k "npm run dev"
cd ..

echo [3/3] Starting File System Monitor Detector...
start cmd /k "python main.py"

echo All 3 components successfully launched in separate windows!
echo Feel free to close this window.
pause
