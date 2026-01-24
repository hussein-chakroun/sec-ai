# Phase 1 Orchestrator Documentation

## Overview

The Phase 1 Orchestrator is an intelligent reconnaissance and OSINT workflow manager that coordinates multiple security tools with advanced features including parallel execution, error recovery, data correlation, and IDS/IPS evasion.

## Features

### 🚀 Core Capabilities

1. **Intelligent Workflow Management**
   - Automatic task dependency resolution
   - Parallel execution of independent tasks
   - Sequential execution of dependent tasks
   - Dynamic task planning based on selected tools

2. **Error Recovery & Resilience**
   - Automatic retry with exponential backoff
   - Continue-on-failure (graceful degradation)
   - Detailed error logging and user notifications
   - Configurable retry attempts (default: 3)

3. **Tool Validation & Auto-Installation**
   - Pre-execution tool validation
   - Automatic installation of missing tools
   - Graceful fallback when tools unavailable
   - Support for both required and optional tools

4. **Data Correlation Engine**
   - Cross-reference findings from multiple tools
   - Port-to-service correlation
   - Email breach correlation
   - Technology-to-vulnerability mapping
   - Attack surface calculation
   - Risk score assessment

5. **Performance Optimization**
   - DNS/WHOIS result caching (1-hour TTL)
   - Parallel task execution
   - Async/await operations
   - Progress tracking with ETA

6. **IDS/IPS Evasion (Web Crawler)**
   - User agent rotation (6 realistic agents)
   - Referer header randomization
   - Accept-Language variation
   - Timing randomization (1-4 second delays)
   - Request jitter
   - Session cookie maintenance

## Architecture

```
Phase1Orchestrator
├── ToolValidator
│   ├── validate_all()
│   ├── validate_tool()
│   └── auto_install_tool()
│
├── ResultCache
│   ├── get()
│   ├── set()
│   └── clear()
│
├── DataCorrelationEngine
│   ├── add_data()
│   ├── correlate()
│   ├── _correlate_ports_services()
│   ├── _correlate_domains_ips()
│   ├── _correlate_emails_breaches()
│   ├── _correlate_tech_vulns()
│   ├── _correlate_subdomains_services()
│   ├── _correlate_whois_dns()
│   ├── _calculate_attack_surface()
│   └── _calculate_risk_score()
│
└── Workflow Engine
    ├── execute()
    ├── _validate_and_install_tools()
    ├── _plan_execution()
    ├── _execute_plan()
    └── _execute_task_with_retry()
```

## Usage

### From GUI

1. Navigate to **Phase 1 Recon** tab
2. Enter target (domain or IP)
3. Select scanning mode (Quick/Balanced/Deep/Stealth)
4. Choose reconnaissance tools (Nmap, DNS, WHOIS, etc.)
5. Choose OSINT tools (optional)
6. Configure web crawler (optional)
7. Click **🎯 Orchestrated Phase 1** button

### From Code

```python
from core.phase1_orchestrator import Phase1Orchestrator
import asyncio

# Create orchestrator
orchestrator = Phase1Orchestrator(
    target="example.com",
    recon_mode='balanced'
)

# Set progress callback
orchestrator.set_progress_callback(lambda msg: print(msg))

# Execute Phase 1
results = asyncio.run(
    orchestrator.execute(
        selected_tools=['nmap', 'dns', 'whois', 'subdomain'],
        osint_tools=['haveibeenpwned'],
        crawler_config={
            'max_depth': 3,
            'max_pages': 50,
            'evasive': True
        }
    )
)

# Access results
print(f"Risk Level: {results['summary']['risk_level']}")
print(f"Attack Surface Score: {results['summary']['attack_surface_score']}")
```

## Execution Workflow

### Phase 1a: Basic Reconnaissance (Parallel Group 1)
- DNS Enumeration (cacheable)
- WHOIS Lookup (cacheable)
- Subdomain Enumeration
- Web Crawler (optional, parallel with recon)

### Phase 1b: Port Scanning (Parallel Group 2)
- Nmap/Port Scan
- Depends on: None (can run independently)

### Phase 1c: Service Analysis (Parallel Group 3)
- Service Enumeration
- OS Detection
- Depends on: Port Scan

### Phase 1d: OSINT (Parallel Groups 4-5)
- SpiderFoot (optional)
- Breach Check (depends on Web Crawler for emails)

## Tool Support

### Automatically Validated & Installed

| Tool | Required | Install Command (Linux) | Install Command (Windows) |
|------|----------|------------------------|---------------------------|
| nmap | Yes | `sudo apt-get install -y nmap` | `winget install nmap` |
| dnsenum | No | `sudo apt-get install -y dnsenum` | Manual |
| whois | No | `sudo apt-get install -y whois` | Manual |
| subfinder | No | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Same |
| spiderfoot | No | `pip install spiderfoot` | `pip install spiderfoot` |

### Python-Based Tools (Always Available)

- Web Crawler with IDS/IPS evasion
- Have I Been Pwned checker
- Service enumeration
- OS detection

## Output Structure

```json
{
  "target": "example.com",
  "mode": "balanced",
  "timestamp": "2024-01-15T10:30:00",
  "progress": {
    "total_tasks": 8,
    "completed": 8,
    "failed": 0,
    "percentage": 100.0
  },
  "task_results": {
    "dns_enumeration": {
      "status": "success",
      "duration": 2.5,
      "data": {...}
    },
    ...
  },
  "correlations": {
    "ports_and_services": [...],
    "domains_and_ips": [...],
    "emails_and_breaches": [...],
    "technologies_and_vulnerabilities": [...],
    "attack_surface": {
      "open_ports": 5,
      "web_forms": 12,
      "file_uploads": 2,
      "subdomains": 8,
      "surface_score": 127
    },
    "risk_score": {
      "risk_level": "MEDIUM",
      "total_risk_score": 45,
      "high_risk_count": 2,
      "medium_risk_count": 5,
      "low_risk_count": 3
    }
  },
  "summary": {
    "attack_surface_score": 127,
    "risk_level": "MEDIUM",
    "total_risk_score": 45,
    "high_risk_findings": 2,
    "medium_risk_findings": 5,
    "low_risk_findings": 3
  },
  "recommendations": [
    "⚠️ Reduce attack surface: Close unnecessary ports",
    "🔧 Address identified vulnerabilities immediately",
    "➡️ Proceed to Phase 2: Advanced Scanning & Vulnerability Assessment"
  ]
}
```

## Risk Scoring

### Risk Levels

- **CRITICAL**: Total risk score > 100
- **HIGH**: Total risk score > 50
- **MEDIUM**: Total risk score > 20
- **LOW**: Total risk score ≤ 20

### Risk Calculation

```python
total_risk_score = (
    high_vulnerabilities * 10 +
    medium_vulnerabilities * 5 +
    low_vulnerabilities * 1 +
    breached_emails * 8 +
    attack_surface_score // 10
)
```

### Attack Surface Score

```python
surface_score = (
    open_ports * 5 +
    web_forms * 3 +
    file_uploads * 10 +
    subdomains * 2 +
    potential_vulnerabilities * 15
)
```

## IDS/IPS Evasion Techniques

### Web Crawler Evasion

1. **User Agent Rotation**
   - 6 realistic user agents (Chrome, Firefox, Safari, Edge)
   - 30% rotation probability per request

2. **Referer Randomization**
   - Google, Bing, DuckDuckGo, Yahoo search engines
   - Empty referer (direct navigation)

3. **Timing Evasion**
   - Base delay: 1-4 seconds (randomized)
   - Jitter: ±0.5 seconds
   - Human-like browsing patterns

4. **Header Variety**
   - Accept-Language rotation (20% probability)
   - Realistic browser headers
   - Session cookie maintenance

### Configuration

```python
# Enable evasive mode
crawler = WebCrawler(max_depth=3, max_pages=50, evasive=True)

# Disable evasive mode (faster, but detectable)
crawler = WebCrawler(max_depth=3, max_pages=50, evasive=False)
```

## Caching System

### Cached Operations

1. **DNS Enumeration** (1 hour TTL)
2. **WHOIS Lookup** (1 hour TTL)
3. **Breach Check** (1 hour TTL)

### Cache Benefits

- Faster repeated scans
- Reduced API rate limiting
- Lower network overhead
- Consistent results during session

### Cache Invalidation

```python
orchestrator.cache.clear()  # Clear all cached data
```

## Error Handling

### Retry Logic

```python
MAX_RETRIES = 3
RETRY_DELAY = 2.0  # seconds

# Exponential backoff
delay = RETRY_DELAY * (2 ** attempt)
```

### Error Categories

1. **Tool Not Found**: Auto-install attempted
2. **Network Timeout**: Retry with backoff
3. **Permission Denied**: Skip tool, continue
4. **Invalid Target**: Fail immediately (no retry)

### Continue-on-Failure

If a tool fails after retries:
1. Log error with full traceback
2. Notify user via progress callback
3. Mark task as "failed"
4. Continue with remaining tasks
5. Include partial results in final report

## Performance Tuning

### Parallel Execution

```python
# Group 1: DNS, WHOIS, Subdomains, Web Crawler (parallel)
# Group 2: Port Scan (after Group 1)
# Group 3: Service Enum, OS Detection (after Group 2)
# Group 4: SpiderFoot (parallel with Groups 1-3)
# Group 5: Breach Check (after Web Crawler)
```

### Optimization Tips

1. **Use Quick Mode** for fast scans (fewer ports, shallower depth)
2. **Enable Caching** for repeated scans of same target
3. **Disable OSINT tools** if not needed
4. **Reduce crawler depth** for faster web enumeration
5. **Use Stealth Mode** for slower but evasive scans

## Integration with Other Phases

### Phase 2 Integration

```python
# Phase 1 discovers attack surface
phase1_results = orchestrator.execute(...)

# Extract targets for Phase 2
open_ports = phase1_results['correlations']['attack_surface']['open_ports']
web_forms = phase1_results['correlations']['attack_surface']['web_forms']

# Pass to Phase 2 vulnerability scanner
phase2.scan_ports(open_ports)
phase2.scan_web_forms(web_forms)
```

### Data Export

```python
import json

# Export to JSON
with open('phase1_report.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)

# Export summary to text
with open('phase1_summary.txt', 'w') as f:
    f.write(f"Risk Level: {results['summary']['risk_level']}\n")
    f.write(f"Attack Surface: {results['summary']['attack_surface_score']}\n")
    # ...
```

## Troubleshooting

### Common Issues

1. **"Tool not found" errors**
   - Run as administrator/sudo for auto-install
   - Manually install tools if auto-install fails
   - Check PATH environment variable

2. **"Rate limited" errors**
   - Enable caching to reduce API calls
   - Use stealth mode for slower requests
   - Wait between repeated scans

3. **"Connection timeout" errors**
   - Check network connectivity
   - Verify target is accessible
   - Increase timeout in config

4. **High memory usage**
   - Reduce crawler max_pages
   - Reduce crawler max_depth
   - Clear cache periodically

### Debug Mode

```python
from loguru import logger

# Enable debug logging
logger.add("phase1_debug.log", level="DEBUG")

# Run orchestrator
orchestrator = Phase1Orchestrator(target, mode)
results = asyncio.run(orchestrator.execute(...))
```

## Best Practices

1. **Start with Quick Mode** to verify target accessibility
2. **Use Balanced Mode** for most engagements
3. **Reserve Deep Mode** for thorough assessments
4. **Enable Stealth Mode** when avoiding detection is critical
5. **Review correlations** before proceeding to Phase 2
6. **Export results** after each phase for documentation
7. **Cache results** to speed up iterative testing

## API Reference

See [API_REFERENCE.md](API_REFERENCE.md) for complete API documentation.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](../LICENSE) for details.
