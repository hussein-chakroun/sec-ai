# Desktop GUI Quick Start Guide

## Starting the Desktop Application

### Windows:
```bash
python main.py --gui
```

### Linux/Mac:
```bash
python3 main.py --gui
```

## Using the New Interface

### 1. Main Pentest Tab - Running a Complete Test

#### Step-by-Step:

1. **Enter Your Target**
   - Type in the URL or IP address
   - Examples: `192.168.1.1`, `example.com`, `http://target.com`

2. **Select Phases**
   
   **Quick Select (Recommended for beginners):**
   - Click "Phase 1 Only" - Just reconnaissance
   - Click "1→2" - Reconnaissance + Vulnerability Scanning
   - Click "Full (1→2→3→4→5)" - Complete penetration test
   
   **Manual Select:**
   - Check boxes for phases you want
   - ⚠️ You CANNOT skip phases! Must run 1 before 2, 2 before 3, etc.

3. **Set Iterations**
   - Default: 10 (good for most cases)
   - Lower (1-5): Faster but less thorough
   - Higher (20-100): Slower but more comprehensive

4. **Click "🚀 Start Pentest"**
   - Confirm you have authorization
   - Watch the console output for progress

5. **Monitor Progress**
   
   The console will show:
   ```
   🔷 STARTING: Reconnaissance & Information Gathering
   📡 Step 1: Initializing reconnaissance orchestrator...
   🛠️ Step 2: Configuring tools: nmap, dns, whois
   🔍 Step 3: Starting reconnaissance scan...
   ✅ Phase 1 completed successfully!
   ```

6. **Wait for Completion**
   - Each phase will complete one by one
   - Progress bar shows overall completion
   - Console shows detailed steps

7. **Get Results**
   - Automatic reports in `./reports/` folder
   - Phase results in `./phase_results/` folder
   - Click "📄 Export Report" to save elsewhere

## Console Output Explained

### What You'll See:

```
================================================================================
🚀 COMPREHENSIVE PENTEST STARTED
================================================================================
Target: example.com
Phases: Phase 1 → Phase 2 → Phase 3
Iterations: 10
================================================================================

🔷 PHASE 1: Reconnaissance & Information Gathering
================================================================================
📡 Step 1: Initializing reconnaissance orchestrator...
🛠️ Step 2: Configuring tools: nmap, dns, whois, subdomain, service
🔍 Step 3: Starting reconnaissance scan...
   [Scanning] Performing port scan on example.com
   [Analysis] Analyzing discovered services...
📊 Step 4: Analysis complete
   - Hosts discovered: 1
   - Open ports found: 15
   - Services identified: 12
✅ Phase 1 completed successfully!
   Results saved to: ./phase_results/phase1_20260126_143025.json

🔷 PHASE 2: Vulnerability Scanning & Analysis
================================================================================
...
```

### Icon Legend:
- 🚀 = Starting
- 🔷 = Phase information
- 📡📊🛠️🔍 = Different steps
- ✅ = Success
- ❌ = Error
- ⚠️ = Warning
- 💾 = Saved

## Using Individual Phase Tabs

### When to Use Individual Tabs:
- You want to configure specific phase options
- You want to re-run a single phase with different settings
- You have results from a previous run and want to continue

### Example: Running Phase 1 Separately

1. Go to "🔍 Phase 1: Recon" tab
2. Enter your target
3. Select scanning mode (Quick/Balanced/Deep/Stealth)
4. Check which tools to use
5. Click "🚀 Start Reconnaissance"
6. Results appear in the output area
7. Click "📄 Export Results" to save

### Example: Continuing from Phase 1 Results

1. Run Phase 1 (either from main tab or Phase 1 tab)
2. Go to "🎯 Phase 2: Vuln Scan" tab
3. Click "📂 Load Phase 1 Results"
4. Status will show "Phase 1 data loaded ✅"
5. Configure Phase 2 options
6. Click "🚀 Start Vulnerability Scan"

## Configuration Tab

### Setting Up LLM (Required!)

**Using LM Studio (Recommended for offline):**
1. Start LM Studio application
2. Load a model (e.g., llama-3.1-8b-instruct)
3. Start the server (default port: 1234)
4. In GUI Config tab:
   - Select "lmstudio" as provider
   - Host: `http://localhost:1234`
   - Click "🔌 Test Connection"
   - Should see: "✅ Connected"
5. Click "💾 Apply Configuration"

**Using OpenAI:**
1. Get API key from platform.openai.com
2. In GUI Config tab:
   - Select "openai" as provider
   - Enter API key
   - Model: gpt-4-turbo-preview
5. Click "💾 Apply Configuration"

**Using Anthropic:**
1. Get API key from console.anthropic.com
2. In GUI Config tab:
   - Select "anthropic" as provider
   - Enter API key
   - Model: claude-3-sonnet-20240229
3. Click "💾 Apply Configuration"

## Understanding Phase Dependencies

### Why Phases Must Be Sequential:

```
Phase 1 (Recon) → Discovers:
  - IP addresses
  - Open ports
  - Services running
  
Phase 2 (Vuln Scan) → Uses Phase 1 to:
  - Know which ports to scan
  - Target specific services
  - Find vulnerabilities
  
Phase 3 (Exploit) → Uses Phase 2 to:
  - Know which vulnerabilities exist
  - Choose appropriate exploits
  - Compromise systems
  
Phase 4 (Post-Exploit) → Uses Phase 3 to:
  - Access compromised systems
  - Escalate privileges
  - Harvest credentials
  
Phase 5 (Lateral Movement) → Uses Phase 4 to:
  - Use harvested credentials
  - Move to other systems
  - Achieve domain dominance
```

### What Happens If You Try to Skip:
- The GUI will prevent it!
- Warning message explains why
- You must enable prerequisite phases first

## Results and Reports

### Where to Find Results:

```
./phase_results/
  ├── phase1_20260126_143025.json
  ├── phase2_20260126_143025.json
  ├── phase3_20260126_143025.json
  ├── phase4_20260126_143025.json
  ├── phase5_20260126_143025.json
  └── session_20260126_143025.json

./reports/
  ├── comprehensive_report_20260126_143025.json
  └── comprehensive_report_20260126_143025.html
```

### Opening Reports:

**JSON Reports:**
- Open in text editor
- Or use: `python -m json.tool report.json`
- Contains all raw data

**HTML Reports:**
- Open in web browser
- Professional formatted report
- Includes statistics and graphs
- Ready to share with team/management

## Common Workflows

### Workflow 1: Quick Scan
```
1. Enter target
2. Click "Phase 1 Only"
3. Click "🚀 Start Pentest"
4. Wait 2-5 minutes
5. Review results
```

### Workflow 2: Find Vulnerabilities
```
1. Enter target
2. Click "1→2"
3. Click "🚀 Start Pentest"
4. Wait 5-10 minutes
5. Review vulnerability report
```

### Workflow 3: Complete Pentest
```
1. Enter target
2. Click "Full (1→2→3→4→5)"
3. Set iterations to 10-20
4. Click "🚀 Start Pentest"
5. Wait 30-60 minutes
6. Review comprehensive report
```

### Workflow 4: Continue from Previous Session
```
1. Check ./phase_results/ for previous session
2. Note the session_id
3. Results auto-load OR
4. Use "📂 Load Phase N Results" buttons
5. Continue from next phase
```

## Troubleshooting

### "Engine not initialized"
- Go to Configuration tab
- Set up LLM provider
- Click "💾 Apply Configuration"

### "Cannot enable Phase X without Phase Y"
- This is correct behavior
- Enable prerequisite phases first
- Or use quick select buttons

### Console shows errors
- Check if tools are installed
- Go to "🛠️ Tools Status" tab
- Click "Install Missing Tools"
- Follow installation instructions

### Pentest running too slow
- Lower iterations (try 5 instead of 10)
- Use "Quick" scan mode in individual phases
- Enable Low Context Mode if using local LLM

### Results not saving
- Check write permissions on ./phase_results/ folder
- Check disk space
- Look for error messages in console

## Tips and Best Practices

### ✅ DO:
- Always get authorization before testing
- Start with Phase 1 only to test setup
- Use stealth mode on production systems
- Keep iterations reasonable (10-20)
- Review console output during execution
- Save reports immediately after completion

### ❌ DON'T:
- Don't test unauthorized targets
- Don't skip phases (system prevents it anyway)
- Don't run with 100 iterations on first try
- Don't ignore error messages
- Don't run aggressive scans without permission

## Getting Help

### If something goes wrong:

1. **Check Console Output**
   - Look for ❌ error messages
   - Note which phase/step failed
   
2. **Check Log Files**
   - Look in `./logs/` folder
   - Most recent log has detailed errors

3. **Review Documentation**
   - Read DESKTOP_GUI_IMPROVEMENTS.md for details
   - Check phase-specific documentation

4. **Check Results**
   - Even if it errors, partial results may be saved
   - Check ./phase_results/ folder

## Advanced Features

### Customizing Individual Phases:
- Each phase tab has advanced options
- Configure tools, modes, and behavior
- Results saved separately for each phase

### Mixing Old and New Results:
- Run Phase 1 today
- Run Phase 2 tomorrow using yesterday's Phase 1
- Each phase result is independent

### Session Management:
- Each run gets unique session ID
- Session ID format: YYYYMMDD_HHMMSS
- All files tagged with session ID
- Easy to track multiple test sessions

## Keyboard Shortcuts

*Note: Currently no keyboard shortcuts implemented*
*Future enhancement: Ctrl+S to save, Ctrl+R to run, etc.*

## Performance Tips

### For Faster Scans:
- Lower iterations (1-5)
- Use "Quick" scan mode
- Disable optional tools
- Run fewer phases

### For More Thorough Scans:
- Higher iterations (20-50)
- Use "Deep" or "Aggressive" mode
- Enable all tools
- Run all phases

### For Stealth Operations:
- Use "Stealth" scan mode
- Lower iterations
- Enable IDS/IPS evasion
- Longer timeouts

## Conclusion

The desktop GUI is now a professional-grade penetration testing platform. Take time to explore each phase tab, understand the phase dependencies, and review the detailed console output. The system is designed to guide you through the pentesting process while providing maximum visibility into what's happening at each step.

Happy testing! 🚀🔒
