#!/bin/bash
# Installation script for SEC-AI

echo "🔐 SEC-AI Installation Script"
echo "=============================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "❌ This script is designed for Linux systems"
    exit 1
fi

# Check for Python 3.9+
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.9"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,9) else 1)"; then
    echo "❌ Python 3.9 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version detected"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

if [ $? -ne 0 ]; then
    echo "❌ Failed to create virtual environment"
    exit 1
fi

echo "✅ Virtual environment created"

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file..."
    cp .env.example .env
    echo "✅ .env file created. Please edit it with your API keys."
fi

# Check for pentesting tools
echo ""
echo "Checking for pentesting tools..."
echo ""

tools=("nmap" "sqlmap" "hydra" "msfconsole")
missing_tools=()

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✅ $tool is installed"
    else
        echo "❌ $tool is NOT installed"
        missing_tools+=($tool)
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo ""
    echo "⚠️  Missing tools: ${missing_tools[*]}"
    echo ""
    echo "Install missing tools using your package manager:"
    echo "  sudo apt install nmap sqlmap hydra metasploit-framework"
    echo ""
fi

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p logs
mkdir -p reports_output
echo "✅ Directories created"

# Installation complete
echo ""
echo "=============================="
echo "✅ Installation Complete!"
echo "=============================="
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API keys"
echo "2. Install missing pentesting tools (if any)"
echo "3. Run the application:"
echo "   - GUI mode: python main.py"
echo "   - CLI mode: python main.py --cli --target <target>"
echo ""
echo "⚠️  LEGAL WARNING:"
echo "Only use this tool on systems you own or have explicit permission to test."
echo "Unauthorized access to computer systems is illegal."
echo ""
