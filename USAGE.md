# SEC-AI Phase 1 - Usage Guide

## Quick Start

### GUI Mode (Recommended)
```bash
# Activate virtual environment
source venv/bin/activate

# Run GUI
python main.py
```

### CLI Mode
```bash
# Activate virtual environment
source venv/bin/activate

# Run pentest
python main.py --cli --target 192.168.1.100 --max-iterations 10
```

## Configuration

### 1. API Keys

Edit `.env` file:
```bash
# For OpenAI
OPENAI_API_KEY=sk-your-key-here
LLM_PROVIDER=openai
LLM_MODEL=gpt-4-turbo-preview

# OR for Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-your-key-here
LLM_PROVIDER=anthropic
LLM_MODEL=claude-3-opus-20240229
```

### 2. Tool Configuration

Edit `config/config.yaml` to customize:
- Tool timeouts
- Default flags
- Scan behavior
- Report formats

## Using the GUI

### Main Interface

1. **Target Configuration**
   - Enter target IP, domain, or URL
   - Select max iterations (5-20)

2. **Start Pentest**
   - Click "Start Pentest"
   - Confirm you have authorization
   - Monitor progress in output area

3. **View Results**
   - Real-time output in console
   - Automatic report generation
   - Export reports in multiple formats

### Configuration Tab

- Set LLM provider (OpenAI/Anthropic)
- Configure model
- Enter API key

### Tools Status Tab

- Check which tools are installed
- Verify tool availability
- Refresh status

## CLI Usage Examples

### Basic Scan
```bash
python main.py --cli --target example.com
```

### Custom Iterations
```bash
python main.py --cli --target 192.168.1.100 --max-iterations 15
```

### Custom Report Formats
```bash
python main.py --cli --target example.com --formats json html txt
```

## Understanding the Workflow

### Phase 1: Target Analysis
- LLM analyzes target type
- Recommends initial scanning strategy
- Identifies potential attack vectors

### Phase 2: Reconnaissance
- Runs nmap service scan
- Identifies open ports and services
- Detects OS and versions

### Phase 3: Autonomous Scanning
- LLM decides next action based on findings
- Executes tools sequentially:
  - **nmap**: Network scanning
  - **sqlmap**: SQL injection testing
  - **hydra**: Password cracking
  - **metasploit**: Exploitation
- Adapts strategy based on results

### Phase 4: Report Generation
- Analyzes all findings
- Generates recommendations
- Creates formatted reports

## Report Formats

### JSON Report
- Raw structured data
- All scan results
- Machine-readable format
- Location: `reports_output/report_target_timestamp.json`

### HTML Report
- Human-readable format
- Formatted tables and sections
- Color-coded severity levels
- Location: `reports_output/report_target_timestamp.html`

### Text Report
- Plain text format
- Simple to parse
- Good for automation
- Location: `reports_output/report_target_timestamp.txt`

## Safety Features

### Safe Mode (Default: ON)
- Prevents destructive actions
- Limits exploitation attempts
- Requires explicit confirmation

### Authorization Check
- GUI prompts for confirmation
- Reminds user of legal requirements
- Logs all actions

## Troubleshooting

### "Tool not found" Error
```bash
# Install missing tools
sudo apt install nmap sqlmap hydra metasploit-framework
```

### "No API key" Error
```bash
# Set API key in .env file
echo 'OPENAI_API_KEY=your-key-here' >> .env
```

### Permission Errors
```bash
# Some tools require sudo
sudo python main.py --cli --target 192.168.1.100
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

## Best Practices

1. **Always Get Authorization**
   - Never test systems without permission
   - Document authorization
   - Follow scope of engagement

2. **Start Conservative**
   - Use low iteration counts initially
   - Review results before escalating
   - Monitor resource usage

3. **Review Reports**
   - Verify findings manually
   - Check for false positives
   - Validate vulnerabilities

4. **Secure Your Environment**
   - Protect API keys
   - Use dedicated testing network
   - Isolate from production

## Advanced Usage

### Custom Wordlists
Place wordlists in project directory and reference in LLM decisions:
```
wordlists/
├── usernames.txt
├── passwords.txt
└── common_paths.txt
```

### Integration with Other Tools
Results are in JSON format and can be parsed by other tools:
```python
import json

with open('reports_output/report_target_123.json') as f:
    results = json.load(f)
    
# Process results
for scan in results['scan_results']:
    print(f"Tool: {scan['tool']}")
    print(f"Findings: {scan['result']['parsed']}")
```

### Extending Functionality
Add new tool modules in `modules/` directory following the `BaseTool` pattern.

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only.

- Unauthorized access to computer systems is **ILLEGAL**
- Always obtain written permission before testing
- Respect scope and boundaries
- Follow responsible disclosure practices
- Comply with local laws and regulations

The authors are not responsible for misuse of this tool.

## Support

For issues and questions:
1. Check logs in `logs/sec-ai.log`
2. Review configuration in `config/config.yaml`
3. Verify tool installation with Tools Status tab
4. Check API key configuration

## Next Phases

Phase 1 provides the foundation. Future phases will add:
- Advanced exploitation capabilities
- Machine learning for pattern recognition
- Collaborative multi-agent systems
- Custom exploit development
- And more...

Stay tuned for Phase 2!
