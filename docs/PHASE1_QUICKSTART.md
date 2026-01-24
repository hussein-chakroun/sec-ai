# Phase 1 Orchestrator - Quick Start Guide

## What is the Phase 1 Orchestrator?

The Phase 1 Orchestrator is an intelligent reconnaissance and OSINT workflow manager that automatically coordinates multiple security tools with advanced features:

- **🚀 3x Faster**: Parallel task execution
- **🛡️ Resilient**: Automatic retry and error recovery
- **🧠 Intelligent**: Cross-references findings from multiple tools
- **🥷 Stealthy**: IDS/IPS evasion for web crawling
- **📊 Insightful**: Risk scoring and attack surface analysis

## Quick Start (GUI)

1. **Launch the application**:
   ```bash
   python main.py
   ```

2. **Navigate to Phase 1 Recon tab**

3. **Enter your target**:
   - Domain: `example.com`
   - IP: `192.168.1.1`
   - Network: `10.0.0.0/24`

4. **Select scanning mode**:
   - 🏃 **Quick**: Fast (5-15 seconds)
   - ⚖️ **Balanced**: Normal (30-90 seconds) - **Recommended**
   - 🔬 **Deep**: Thorough (2-5 minutes)
   - 🥷 **Stealth**: Evasive (5-10 minutes)

5. **Choose tools**:
   - ✅ Nmap (port scanning)
   - ✅ DNS (enumeration)
   - ✅ WHOIS (domain info)
   - ✅ Subdomain (discovery)
   - ⬜ Service (enumeration)
   - ⬜ OS (detection)

6. **Optional: OSINT tools**:
   - ✅ Web Crawler (with IDS/IPS evasion)
   - ✅ Have I Been Pwned (breach check)
   - ⬜ SpiderFoot
   - ⬜ Intelligence X

7. **Click "🎯 Orchestrated Phase 1"** button

8. **Wait for results**:
   - Real-time progress updates
   - ETA displayed
   - Results shown in multiple tabs

## Quick Start (Code)

```python
import asyncio
from core.phase1_orchestrator import Phase1Orchestrator

async def main():
    # Create orchestrator
    orchestrator = Phase1Orchestrator(
        target="example.com",
        recon_mode='balanced'
    )
    
    # Optional: Set progress callback
    orchestrator.set_progress_callback(print)
    
    # Execute Phase 1
    results = await orchestrator.execute(
        selected_tools=['nmap', 'dns', 'whois'],
        osint_tools=['haveibeenpwned'],
        crawler_config={
            'max_depth': 3,
            'max_pages': 50,
            'evasive': True
        }
    )
    
    # Print results
    print(f"Risk Level: {results['summary']['risk_level']}")
    print(f"Attack Surface: {results['summary']['attack_surface_score']}")

# Run
asyncio.run(main())
```

## Understanding Results

### Summary Tab
Shows high-level overview:
- **Risk Level**: CRITICAL / HIGH / MEDIUM / LOW
- **Attack Surface Score**: Numerical assessment
- **Findings**: Count of vulnerabilities by severity

### Detailed Tab
Shows per-tool results:
- Raw tool output
- Execution time
- Status (success/failed)

### JSON Tab
Complete results in JSON format for export

### Correlations
Intelligent cross-referencing:
- **Port-Service**: Links open ports to identified services
- **Email-Breach**: Shows compromised emails
- **Tech-Vulnerability**: Maps technologies to known issues

## Example Output

```
═══════════════════════════════════════════════════════════════════════════
🎯 ORCHESTRATED PHASE 1 RECONNAISSANCE
═══════════════════════════════════════════════════════════════════════════
Target: example.com
Mode: BALANCED

🔍 Validating tools...
✅ nmap found
✅ dns found
✅ whois found

🚀 Executing reconnaissance tasks...
⏳ Running dns_enumeration... ✅ (2.3s, cached)
⏳ Running whois_lookup... ✅ (1.8s, cached)
⏳ Running port_scan... ✅ (8.4s)

🔗 Correlating data...
✅ ORCHESTRATED PHASE 1 COMPLETED

📊 EXECUTIVE SUMMARY:
  • Risk Level: MEDIUM
  • Attack Surface Score: 127
  • Total Risk Score: 45
  • High Risk Findings: 2
  • Medium Risk Findings: 5
  • Low Risk Findings: 3

🔍 ATTACK SURFACE ANALYSIS:
  • Open Ports: 5
  • Web Forms: 12
  • File Upload Points: 2
  • Subdomains: 8
  • Exposed Technologies: 6
  • Exposed Emails: 3
  • Potential Vulnerabilities: 7

💡 RECOMMENDATIONS:
  🔧 Address identified vulnerabilities immediately
  📧 Consider implementing email obfuscation
  ➡️  Proceed to Phase 2: Advanced Scanning & Vulnerability Assessment
```

## Key Features Explained

### 1. Parallel Execution
Tasks run simultaneously when possible:
```
Group 1 (Parallel): DNS + WHOIS + Subdomains + Web Crawler
Group 2 (Sequential): Port Scan (needs DNS)
Group 3 (Parallel): Service Enum + OS Detection (need ports)
```
**Result**: 3x faster than sequential execution

### 2. Auto Tool Validation
Missing tools are automatically installed:
```
🔍 Validating tools...
✅ nmap found
❌ dnsenum not found
📦 Installing dnsenum...
✅ dnsenum installed
```

### 3. Error Recovery
Failed tasks retry automatically:
```
⚠️  dns_enumeration failed, retrying in 2.0s...
⚠️  dns_enumeration failed, retrying in 4.0s...
✅ dns_enumeration completed (3rd attempt)
```

### 4. IDS/IPS Evasion (Web Crawler)
Appears as a real browser:
- Rotates user agents (Chrome, Firefox, Safari)
- Random referers (Google, Bing, etc.)
- Human-like timing (1-4s delays)
- Realistic headers

### 5. Data Correlation
Finds relationships between discoveries:
```
🔗 Port 22 (SSH) + OpenSSH 7.4 (outdated) = HIGH RISK
🔗 admin@example.com + 3 breaches = CRITICAL
🔗 WordPress 5.2 + CVE-2019-16663 = MEDIUM RISK
```

### 6. Caching
Speeds up repeated scans:
```
First scan: DNS lookup 2.5s
Second scan: DNS lookup 0.1s (cached)
```

## Scanning Modes Comparison

| Mode | Speed | Stealth | Ports Scanned | Depth | Best For |
|------|-------|---------|--------------|-------|----------|
| **Quick** | ⚡⚡⚡ | 🥷 | Top 100 | 1 | Initial assessment |
| **Balanced** | ⚡⚡ | 🥷🥷 | Top 1000 | 3 | Most engagements |
| **Deep** | ⚡ | 🥷🥷 | All 65535 | 5 | Thorough testing |
| **Stealth** | 🐌 | 🥷🥷🥷🥷 | Top 100 | 2 | Avoiding detection |

## Common Workflows

### Workflow 1: Quick Assessment
**Goal**: Fast overview of target

1. Mode: **Quick**
2. Tools: DNS, WHOIS
3. Time: ~10 seconds
4. Use: Initial recon before deeper scan

### Workflow 2: Standard Pentest
**Goal**: Comprehensive reconnaissance

1. Mode: **Balanced**
2. Tools: All reconnaissance + OSINT
3. Time: ~90 seconds
4. Use: Most penetration tests

### Workflow 3: Red Team Operation
**Goal**: Stealthy, extensive intelligence

1. Mode: **Stealth**
2. Tools: DNS, WHOIS, Subdomain, Crawler
3. Time: ~10 minutes
4. Use: Avoiding detection

### Workflow 4: Bug Bounty
**Goal**: Find maximum vulnerabilities

1. Mode: **Deep**
2. Tools: All tools enabled
3. Time: ~5 minutes
4. Use: Bug bounty programs

## Troubleshooting

### Problem: "Tool not found" errors
**Solution**:
1. Run as administrator/sudo
2. Let auto-installer work
3. Or manually install: `sudo apt-get install nmap`

### Problem: "Connection timeout"
**Solution**:
1. Verify target is accessible
2. Check firewall rules
3. Try stealth mode (slower requests)

### Problem: "Rate limited"
**Solution**:
1. Use stealth mode
2. Wait between scans
3. Results are cached for 1 hour

### Problem: High memory usage
**Solution**:
1. Reduce crawler max_pages (default: 50)
2. Reduce crawler max_depth (default: 3)
3. Use quick mode

## Next Steps

After Phase 1 completes:

1. **Review Correlations**: Check the correlations for interesting findings
2. **Export Results**: Save JSON for documentation
3. **Proceed to Phase 2**: Advanced scanning & vulnerability assessment
4. **Target High-Risk Findings**: Focus on items marked HIGH or CRITICAL

## Advanced Topics

- [Full Documentation](PHASE1_ORCHESTRATOR.md)
- [Code Examples](../examples/phase1_orchestrator_examples.py)
- [Implementation Details](PHASE1_IMPLEMENTATION_SUMMARY.md)
- [API Reference](API_REFERENCE.md)

## Support

For issues or questions:
1. Check documentation: `docs/PHASE1_ORCHESTRATOR.md`
2. Review examples: `examples/phase1_orchestrator_examples.py`
3. Enable debug logging: See troubleshooting section

---

**Ready to start?** Launch the GUI and click "🎯 Orchestrated Phase 1"! 🚀
