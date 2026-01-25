# EsecAi Web Interface

## 🌐 Overview

Fully functional web-based interface for EsecAi penetration testing platform, built with Streamlit. Access all Phase 1-5 and Phase 12 capabilities through your browser!

## ✨ Features

### 🎯 Complete Functionality
- **Phase 1: Reconnaissance** - Network discovery, port scanning, OSINT
- **Phase 2: Vulnerability Scanning** - Web scanning, CVE correlation
- **Phase 3: Exploitation** - LLM-driven exploit execution
- **Phase 4: Post-Exploitation** - Privilege escalation, credential harvesting
- **Phase 5: Lateral Movement** - AD attacks, domain dominance
- **Phase 12: AI Adaptive** - Reinforcement learning, adversarial ML

### 🖥️ Web Interface Features
- **Real-time Results** - Live pentest progress and results
- **Interactive Dashboard** - Comprehensive metrics and visualizations
- **Phase Selection** - Enable/disable specific phases
- **Quick Workflows** - One-click preset configurations
- **Export Reports** - Generate JSON and HTML reports
- **Dark Theme** - Cybersecurity-themed UI matching desktop app

## 🚀 Quick Start

### Windows
```powershell
# Run the startup script
.\start_web.bat
```

### Linux/Mac
```bash
# Make script executable
chmod +x start_web.sh

# Run the startup script
./start_web.sh
```

### Manual Start
```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements_web.txt

# Run the web app
streamlit run web_app.py
```

The web interface will open automatically at: **http://localhost:8501**

## 📋 Prerequisites

### Required
- Python 3.8+
- OpenAI API key or Anthropic API key (set in `.env`)
- All dependencies from `requirements.txt`

### Additional Web Dependencies
```bash
streamlit>=1.31.0
pandas>=2.0.0
plotly>=5.18.0
```

## 🎨 Interface Guide

### Dashboard Page
```
┌─────────────────────────────────────────┐
│          ⚡ EsecAi                      │
│   AI-Powered Penetration Testing       │
├─────────────────────────────────────────┤
│ Navigation Sidebar                      │
│ • 🏠 Dashboard                          │
│ • ⚙️ Phase Selection                   │
│ • 🔍 Phase 1: Reconnaissance           │
│ • 🎯 Phase 2: Vulnerability Scanning   │
│ • 💣 Phase 3: Exploitation             │
│ • 🔓 Phase 4: Post-Exploitation        │
│ • 🌐 Phase 5: Lateral Movement         │
│ • 🤖 Phase 12: AI Adaptive             │
│ • 🔧 Configuration                     │
│ • 🛠️ Tools Status                      │
└─────────────────────────────────────────┘
```

### Main Dashboard
- **Target Configuration**: Enter target IP/domain
- **Quick Phase Selection**: Preset workflow buttons
  - 🔍 Recon Only (Phase 1)
  - 🎯 Recon + Vuln Scan (1→2)
  - 💥 Through Exploitation (1→2→3)
  - 🔓 Through Post-Exploit (1→2→3→4)
  - 🔥 Complete Pentest (1→2→3→4→5)
  - 🤖 AI Adaptive (Phase 12)
- **Control Buttons**: Start, Stop, Export Report
- **Results Display**: Multi-tab result viewer

## 📊 Features by Page

### 1. Dashboard (🏠)
- Quick start pentest execution
- Target configuration
- Quick phase selection buttons
- Real-time progress tracking
- Results overview with metrics
- Multi-tab detailed results:
  - Overview (executive summary)
  - Phase 1-2 (recon & vulnerabilities)
  - Phase 3 (exploitation)
  - Phase 4 (post-exploitation)
  - Phase 5 (lateral movement)

### 2. Phase Selection (⚙️)
- Enable/disable individual phases
- View phase descriptions
- Configure phase execution order

### 3. Phase 1: Reconnaissance (🔍)
- Scan mode selection (quick/balanced/deep)
- OSINT toggle
- Subdomain enumeration toggle
- Configuration persistence

### 4. Phase 2: Vulnerability Scanning (🎯)
- Scan mode selection (quick/balanced/deep/aggressive)
- CVE correlation toggle
- Severity threshold selection

### 5. Phase 3: Exploitation (💣)
- Max attempts configuration
- Exploit timeout settings
- Safe mode toggle
- Aggressive mode toggle
- Metasploit integration
- Custom exploit generator

### 6. Phase 4: Post-Exploitation (🔓)
- Privilege escalation settings
- Credential harvesting options
  - Mimikatz/Pypykatz
  - Browser dumps
  - Memory scraping
- Persistence configuration
  - Stealth mode
  - Max mechanisms

### 7. Phase 5: Lateral Movement (🌐)
- Lateral movement settings
  - Max hops
  - Stealth mode
- Active Directory attacks
  - Kerberoasting
  - AS-REP Roasting
  - DCSync
  - BloodHound
- Domain dominance options

### 8. Phase 12: AI Adaptive (🤖)
- Reinforcement learning settings
- Adversarial ML configuration
- NLP exploitation
- Autonomous research options

### 9. Configuration (🔧)
- LLM provider selection (OpenAI/Anthropic)
- Model selection
- API key configuration
- Performance options
- Output directory settings

### 10. Tools Status (🛠️)
- View installed tools
- Check tool availability
- Installation status indicators

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# OpenAI Configuration
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4

# Or Anthropic Configuration
ANTHROPIC_API_KEY=sk-ant-your-key-here
ANTHROPIC_MODEL=claude-3-opus-20240229

# Performance
LOW_CONTEXT_MODE=false
LOW_CONTEXT_CHUNK_SIZE=4000

# Output
REPORT_OUTPUT_DIR=./reports
```

### Streamlit Configuration
Create `.streamlit/config.toml`:

```toml
[server]
port = 8501
address = "localhost"
maxUploadSize = 200

[theme]
primaryColor = "#58a6ff"
backgroundColor = "#0d1117"
secondaryBackgroundColor = "#161b22"
textColor = "#c9d1d9"
font = "sans serif"
```

## 📱 Usage Examples

### 1. Quick Reconnaissance
1. Navigate to Dashboard
2. Enter target: `192.168.1.0/24`
3. Click "🔍 Recon Only (Phase 1)"
4. Click "🚀 Start Pentest"

### 2. Full Vulnerability Assessment
1. Navigate to Dashboard
2. Enter target: `example.com`
3. Click "🎯 Recon + Vuln Scan (1→2)"
4. Click "🚀 Start Pentest"

### 3. Complete Pentest
1. Navigate to Dashboard
2. Enter target: `192.168.1.100`
3. Click "🔥 Complete Pentest (1→2→3→4→5)"
4. Enable Safe Mode
5. Click "🚀 Start Pentest"
6. Monitor real-time progress
7. View results in tabs
8. Click "📄 Export Report"

### 4. Custom Phase Selection
1. Navigate to "⚙️ Phase Selection"
2. Enable desired phases
3. Return to Dashboard
4. Configure target
5. Click "🚀 Start Pentest"

## 📊 Results Display

### Executive Summary
- Duration and status
- Phases completed
- Risk level (Critical/High/Medium/Low)
- Key metrics:
  - Targets scanned
  - Vulnerabilities found
  - Successful exploits
  - Compromised hosts
  - Credentials harvested
  - Lateral movements

### Detailed Results
Each phase shows:
- **Phase 1**: Discovered hosts, services, ports
- **Phase 2**: Vulnerabilities by severity, CVE details
- **Phase 3**: Exploitation attempts, successful exploits, shells
- **Phase 4**: Privilege escalation, credentials, persistence
- **Phase 5**: Lateral movement paths, AD attacks, domain admin status

## 🎨 UI Customization

### Color Scheme
The interface uses GitHub's dark theme:
- Background: `#0d1117`
- Secondary: `#161b22`
- Primary (Blue): `#58a6ff`
- Success (Green): `#238636`
- Danger (Red): `#da3633`
- Warning (Yellow): `#d29922`
- Text: `#c9d1d9`

### Custom CSS
Modify the custom CSS in `web_app.py` to change appearance:

```python
st.markdown("""
<style>
    /* Your custom styles here */
</style>
""", unsafe_allow_html=True)
```

## 🔒 Security Considerations

### Access Control
The web interface runs on **localhost** by default for security:
- Only accessible from the machine running the server
- No external network exposure
- No authentication required (local use only)

### Production Deployment
⚠️ **WARNING**: This tool is designed for authorized penetration testing only!

If deploying to production:
1. **Add authentication** (Streamlit doesn't include auth by default)
2. **Use HTTPS** with proper certificates
3. **Implement rate limiting**
4. **Add audit logging**
5. **Restrict network access**
6. **Use environment variables** for all secrets

### Recommended Production Setup
```bash
# Use authentication reverse proxy (nginx, Apache)
# Enable HTTPS
# Set strong authentication
# Restrict to authorized users only
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change port in start script
streamlit run web_app.py --server.port 8502
```

### Dependencies Not Found
```bash
# Reinstall all dependencies
pip install -r requirements.txt -r requirements_web.txt --force-reinstall
```

### API Key Not Detected
1. Check `.env` file exists in project root
2. Verify environment variables are set
3. Restart the web app

### Results Not Displaying
1. Ensure pentest completed successfully
2. Check browser console for errors
3. Refresh the page (F5)

## 🚀 Performance Tips

### Large Networks
- Use "Quick" scan mode for Phase 1
- Limit max iterations
- Enable low context mode

### Memory Usage
- Enable "Low Context Mode" in Configuration
- Reduce chunk size
- Close unused browser tabs

### Speed Optimization
- Use local LLM models if available
- Disable unnecessary phases
- Use aggressive mode cautiously

## 📄 Report Export

### Available Formats
- **JSON**: Machine-readable results
- **HTML**: Human-readable report with styling

### Export Location
Reports are saved to: `./reports/`

### Report Contents
- Executive summary
- Detailed phase results
- Vulnerability listings
- Exploitation logs
- Credentials found
- Attack paths
- Recommendations

## 🔄 Updates

### Checking for Updates
```bash
git pull origin main
pip install -r requirements.txt -r requirements_web.txt --upgrade
```

### Version
Current version: **1.0.0**
- Full Phase 1-5 support
- Phase 12 integration
- Real-time results
- Export functionality

## 🤝 Comparison: Web vs Desktop

| Feature | Web Interface | Desktop GUI |
|---------|--------------|-------------|
| Platform | Cross-platform (browser) | Windows/Linux/Mac |
| Installation | Lightweight | Requires PyQt5 |
| Access | Remote capable | Local only |
| Performance | Slightly slower | Faster |
| UI Updates | Real-time | Real-time |
| Mobile Support | Yes (responsive) | No |
| Export Reports | Yes | Yes |
| All Phases | ✅ Yes | ✅ Yes |

## 📝 License

Same as main project. See LICENSE file.

## ⚠️ Legal Disclaimer

**ONLY USE ON AUTHORIZED SYSTEMS**

This tool is designed for:
- Authorized penetration testing
- Security research
- Educational purposes

**NEVER** use without explicit written permission!

## 🆘 Support

Issues? Check:
1. [GitHub Issues](https://github.com/your-repo/sec-ai/issues)
2. Documentation files (PHASE*_IMPLEMENTATION.md)
3. Main README.md

## 🎯 Quick Reference

### Start Web Interface
```bash
# Windows
.\start_web.bat

# Linux/Mac
./start_web.sh
```

### Access URL
```
http://localhost:8501
```

### Stop Server
Press `Ctrl+C` in terminal

---

**Enjoy the EsecAi Web Interface!** 🚀🔒
