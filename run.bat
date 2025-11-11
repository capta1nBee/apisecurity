@echo off
echo ========================================
echo API Security Dashboard
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    echo.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
echo.

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
echo.

REM Set environment variables
set FLASK_APP=app.py
set FLASK_ENV=development

REM Run the application
echo ========================================
echo Starting API Security Dashboard...
echo Access the dashboard at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo ========================================
echo.

python app.py

pause

