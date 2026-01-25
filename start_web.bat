@echo off
REM Startup script for EsecAi Web Interface (Windows)

echo ================================
echo  Starting EsecAi Web Interface
echo ================================
echo.

REM Check if virtual environment exists
@REM if not exist "venv\" (
@REM     echo Creating virtual environment...
@REM     python -m venv venv
@REM )

REM Activate virtual environment
@REM call venv\Scripts\activate.bat

REM Install/update dependencies
echo Installing dependencies...
@REM pip install -r requirements.txt
pip install -r requirements_web.txt

REM Start Streamlit app
echo.
echo ================================
echo  Starting web server...
echo  Web interface: http://localhost:8501
echo ================================
echo.

streamlit run web_app.py --server.port 8501 --server.address localhost
