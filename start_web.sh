#!/bin/bash
# Startup script for EsecAi Web Interface

echo "🚀 Starting EsecAi Web Interface..."
echo "=================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "⚠️  Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/update dependencies
echo "📦 Installing dependencies..."
# pip install -r requirements.txt
pip install -r requirements_web.txt

# Start Streamlit app
echo "✅ Starting web server..."
echo "🌐 Web interface will open at: http://localhost:8501"
echo "=================================="

streamlit run web_app.py --server.port 8501 --server.address localhost
