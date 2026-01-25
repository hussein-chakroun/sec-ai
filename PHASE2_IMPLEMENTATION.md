# Phase 2 Implementation Guide

## Advanced Scanning & Vulnerability Assessment

**Status**: ✅ **IMPLEMENTED**

**Version**: 1.0.0

**Date**: January 25, 2026

---

## Overview

Phase 2 bridges the gap between reconnaissance (Phase 1) and exploitation (Phase 3+) by providing intelligent vulnerability assessment capabilities. It consumes Phase 1 reconnaissance data and performs targeted vulnerability scans including:

- Web application security testing (SQLi, XSS, etc.)
- CVE correlation against discovered services
- SSL/TLS security analysis
- Network vulnerability scanning
- Attack surface analysis and prioritization

---

## Architecture

### Core Components

1. **Phase 2 Orchestrator** ([core/phase2_orchestrator.py](core/phase2_orchestrator.py))
   - Main coordination engine
   - Parallel task execution
   - Progress tracking and reporting
   - Result aggregation and prioritization

2. **Vulnerability Scanners** ([modules/](modules/))
   - **SQLMapScanner** - SQL injection detection (existing)
   - **NiktoScanner** - Web server vulnerability scanning (NEW)
   - **XSSScanner** - Cross-site scripting detection (NEW)
   - **SSLTester** - SSL/TLS security analysis (NEW)
   - **CVECorrelationEngine** - Service-to-CVE matching (NEW)

3. **GUI Integration** ([gui/main_window.py](gui/main_window.py))
   - Dedicated Phase 2 tab
   - Real-time progress tracking
   - Vulnerability visualization
   - HTML/JSON report generation

---

## Implementation Details

### 1. Phase 2 Orchestrator

**Location**: [core/phase2_orchestrator.py](core/phase2_orchestrator.py)

**Key Features**:
- Consumes Phase 1 reconnaissance outputs
- Analyzes attack surface (web targets, network services, hosts)
- Creates intelligent scan plan based on target types
- Executes scans in parallel with dependency management
- Aggregates and prioritizes vulnerability findings
- Generates actionable recommendations

**Scan Modes**:
- **Quick**: Fast vulnerability detection with minimal testing
- **Balanced**: Moderate depth and speed (default)
- **Deep**: Comprehensive vulnerability analysis
- **Aggressive**: Maximum coverage (may trigger IDS/IPS)

**Stealth Mode**: Integrates with existing evasion modules for low-noise scanning

**Usage**:
```python
from core.phase2_orchestrator import Phase2Orchestrator

# Create orchestrator with configuration
config = {
    'scan_mode': 'balanced',
    'stealth_mode': False,
    'enable_web_scanning': True,
    'enable_cve_matching': True,
    'enable_ssl_testing': True,
    'max_parallel_tasks': 5
}

orchestrator = Phase2Orchestrator(config)

# Load Phase 1 results
orchestrator.load_phase1_results(phase1_data)

# Create scan plan
orchestrator.create_scan_plan()

# Execute (async)
import asyncio
results = asyncio.run(orchestrator.execute_scan_plan())

# Save results
orchestrator.save_results("./reports/phase2")
```

### 2. Nikto Scanner

**Location**: [modules/nikto_scanner.py](modules/nikto_scanner.py)

**Features**:
- Web server vulnerability detection
- Misconfiguration identification
- OSVDB reference integration
- Stealth scanning support

**Methods**:
- `scan(target, options)` - Full customizable scan
- `quick_scan(target)` - Fast scan with minimal tuning
- `full_scan(target)` - Comprehensive scan (all tests)
- `stealth_scan(target)` - IDS evasion enabled

**Example**:
```python
from modules.nikto_scanner import NiktoScanner

scanner = NiktoScanner()
results = scanner.scan("https://example.com", {
    'tuning': '1',  # File upload tests
    'timeout': 10
})

# Results contain vulnerabilities list
vulnerabilities = results['vulnerabilities']
```

### 3. XSS Scanner

**Location**: [modules/xss_scanner.py](modules/xss_scanner.py)

**Features**:
- Reflected XSS detection
- Form-based XSS testing
- Multiple payload variants
- Encoded payload support
- Automatic context detection

**Payloads Tested**:
- Script tags (`<script>alert('XSS')</script>`)
- Event handlers (`<img src=x onerror=alert('XSS')>`)
- SVG vectors (`<svg/onload=alert('XSS')>`)
- JavaScript URIs (`javascript:alert('XSS')`)
- Encoded variants (URL, HTML entity encoding)

**Example**:
```python
from modules.xss_scanner import XSSScanner

scanner = XSSScanner(timeout=10, max_payloads=10)
results = scanner.scan_url("http://example.com/search?q=test", crawl=True)

# Check for vulnerabilities
if results['vulnerabilities']:
    for vuln in results['vulnerabilities']:
        print(f"XSS found in: {vuln['affected_target']}")
```

### 4. SSL/TLS Tester

**Location**: [modules/ssl_tester.py](modules/ssl_tester.py)

**Features**:
- Certificate validation and expiry checking
- Protocol version testing (SSLv2, SSLv3, TLS 1.0-1.3)
- Weak cipher detection
- Security score calculation
- Known vulnerability identification (POODLE, etc.)

**Tested Vulnerabilities**:
- Expired/expiring certificates
- Weak protocols (SSLv2, SSLv3, TLS 1.0/1.1)
- Weak cipher suites (NULL, EXPORT, DES, RC4, MD5)
- Low encryption strength (<128 bits)

**Example**:
```python
from modules.ssl_tester import SSLTester

tester = SSLTester(timeout=10)
results = tester.test_url("https://example.com")

# Check security score
security_score = results['security_score']  # 0-100
vulnerabilities = results['vulnerabilities']
protocol_support = results['protocol_support']
```

### 5. CVE Correlation Engine

**Location**: [modules/cve_correlation.py](modules/cve_correlation.py)

**Features**:
- NVD (National Vulnerability Database) API integration
- Service version to CVE mapping
- CVSSv3 scoring and severity classification
- Exploit availability detection
- Smart caching (24-hour TTL)
- Relevance scoring for accurate matching

**Data Sources**:
- NVD API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- Cached local database for offline operation

**Example**:
```python
from modules.cve_correlation import CVECorrelationEngine

engine = CVECorrelationEngine()

# Correlate single service
results = engine.correlate_service(
    service='apache',
    version='2.4.41',
    vendor='apache'
)

# Check results
print(f"Found {results['total_cves']} CVEs")
print(f"Critical: {results['critical_count']}")
print(f"Exploits available: {results['exploits_available']}")

# Batch correlation for multiple services
services = [
    {'service': 'openssh', 'version': '7.9p1'},
    {'service': 'mysql', 'version': '5.7.30'},
]
batch_results = engine.batch_correlate(services)
```

### 6. GUI Integration

**Location**: [gui/main_window.py](gui/main_window.py)

**New Components**:
- **Phase 2 Tab**: Dedicated vulnerability scanning interface
- **Phase 1 Integration**: Load Phase 1 results directly
- **Scan Configuration**: Mode selection, stealth options, tool selection
- **Real-time Progress**: Progress bar with ETA and statistics
- **Multi-view Results**:
  - Vulnerabilities view (color-coded by severity)
  - Statistics view (scan metrics, recommendations)
  - JSON export view

**Workflow**:
1. Load Phase 1 reconnaissance results (optional but recommended)
2. Configure scan mode and options
3. Select vulnerability scanners to use
4. Start scan
5. View real-time progress and results
6. Export to JSON, TXT, or HTML format

---

## Data Flow

```
Phase 1 (Recon)
    |
    | - Discovered hosts, services, versions, URLs
    |
    v
Phase 2 Orchestrator
    |
    ├─> Attack Surface Analyzer
    |   └─> Prioritize targets (web > databases > other)
    |
    ├─> Scan Plan Generator
    |   ├─> Web targets → SQLMap, Nikto, XSS Scanner
    |   ├─> Services with versions → CVE Matcher
    |   ├─> HTTPS targets → SSL Tester
    |   └─> Network services → Nmap vuln scripts
    |
    ├─> Parallel Execution Engine
    |   └─> Execute scans with dependency management
    |
    └─> Result Aggregator
        ├─> Deduplicate findings
        ├─> Calculate risk scores
        ├─> Generate recommendations
        └─> Prepare for Phase 3+ (exploitation)
```

---

## Configuration

### Environment Variables

```bash
# NVD API Key (optional, for higher rate limits)
export NVD_API_KEY="your-api-key-here"

# Cache directory for CVE data
export CVE_CACHE_DIR="./data/cve_cache"

# Phase 2 results directory
export PHASE2_REPORTS_DIR="./reports/phase2"
```

### Configuration Dictionary

```python
config = {
    # Scan mode: quick, balanced, deep, aggressive
    'scan_mode': 'balanced',
    
    # Enable stealth techniques
    'stealth_mode': False,
    
    # Maximum parallel scan tasks
    'max_parallel_tasks': 5,
    
    # Timeout per task (seconds)
    'timeout_per_task': 300,
    
    # Tool toggles
    'enable_web_scanning': True,
    'enable_cve_matching': True,
    'enable_network_vuln': True,
    'enable_ssl_testing': True,
    'enable_default_creds': False,
}
```

---

## Output Format

### Vulnerability Finding Structure

```json
{
  "vuln_id": "CVE-2023-12345",
  "title": "Apache HTTP Server Path Traversal",
  "severity": "critical",
  "cvss_score": 9.8,
  "description": "Path traversal vulnerability in Apache HTTP Server...",
  "affected_target": "192.168.1.100:80",
  "affected_service": "apache",
  "affected_version": "2.4.41",
  "exploit_available": true,
  "exploit_references": [
    "https://www.exploit-db.com/exploits/12345",
    "https://github.com/user/exploit-repo"
  ],
  "remediation": "Update Apache to version 2.4.50 or later",
  "confidence": 0.95,
  "evidence": [
    "Version banner: Apache/2.4.41 (Ubuntu)",
    "CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  ],
  "tool_source": "cve_matcher",
  "timestamp": "2026-01-25T10:30:00"
}
```

### Complete Scan Results

```json
{
  "scan_summary": {
    "total_tasks": 25,
    "completed_tasks": 23,
    "failed_tasks": 1,
    "skipped_tasks": 1,
    "scan_duration": 245.6,
    "scan_mode": "balanced"
  },
  "vulnerability_summary": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 2
  },
  "vulnerabilities": [ /* array of vulnerability objects */ ],
  "attack_surface": {
    "web_targets": [ /* discovered web applications */ ],
    "network_services": [ /* discovered network services */ ],
    "hosts": [ /* discovered hosts */ ]
  },
  "scan_tasks": [ /* task execution details */ ],
  "recommendations": [
    {
      "priority": "critical",
      "target": "192.168.1.100",
      "message": "URGENT: 2 critical vulnerabilities found. Immediate remediation required.",
      "affected_vulns": ["CVE-2023-12345", "CVE-2023-67890"]
    }
  ]
}
```

---

## Integration Examples

### Standalone Execution

```python
import asyncio
from core.phase2_orchestrator import Phase2Orchestrator

async def main():
    # Configuration
    config = {
        'scan_mode': 'balanced',
        'stealth_mode': False,
        'enable_web_scanning': True,
        'enable_cve_matching': True,
    }
    
    # Create orchestrator
    orchestrator = Phase2Orchestrator(config)
    
    # Load Phase 1 data (from file or object)
    import json
    with open('reports/phase1/recon_results.json', 'r') as f:
        phase1_data = json.load(f)
    
    orchestrator.load_phase1_results(phase1_data)
    
    # Create and execute scan plan
    orchestrator.create_scan_plan()
    results = await orchestrator.execute_scan_plan()
    
    # Save results
    output_file = orchestrator.save_results()
    print(f"Results saved to: {output_file}")
    
    # Access results
    print(f"Found {results['vulnerability_summary']['total']} vulnerabilities")
    print(f"Critical: {results['vulnerability_summary']['critical']}")

# Run
asyncio.run(main())
```

### Integration with Existing Workflow

```python
from core.phase1_orchestrator import Phase1Orchestrator
from core.phase2_orchestrator import Phase2Orchestrator
import asyncio

async def full_workflow(target):
    # Phase 1: Reconnaissance
    print("[Phase 1] Running reconnaissance...")
    phase1 = Phase1Orchestrator(target=target, mode='balanced')
    phase1_results = await phase1.run_reconnaissance()
    
    # Phase 2: Vulnerability Scanning
    print("[Phase 2] Starting vulnerability assessment...")
    phase2 = Phase2Orchestrator({'scan_mode': 'balanced'})
    phase2.load_phase1_results(phase1_results)
    phase2.create_scan_plan()
    phase2_results = await phase2.execute_scan_plan()
    
    # Print summary
    vuln_summary = phase2_results['vulnerability_summary']
    print(f"\n[Summary]")
    print(f"Total Vulnerabilities: {vuln_summary['total']}")
    print(f"Critical: {vuln_summary['critical']}")
    print(f"High: {vuln_summary['high']}")
    
    return phase1_results, phase2_results

# Execute
asyncio.run(full_workflow("example.com"))
```

---

## Performance & Optimization

### Parallel Execution

Phase 2 orchestrator executes scans in parallel with configurable concurrency:

```python
config = {
    'max_parallel_tasks': 10,  # Run up to 10 scans simultaneously
}
```

**Recommendations**:
- **Quick scans**: 10-15 parallel tasks
- **Balanced scans**: 5-8 parallel tasks
- **Deep scans**: 3-5 parallel tasks
- **Stealth mode**: 1-2 parallel tasks

### Caching

**CVE Correlation Engine** caches NVD API responses for 24 hours to:
- Reduce API calls (avoid rate limiting)
- Speed up repeated scans
- Enable offline operation

Cache location: `./data/cve_cache/*.json`

### Resource Management

- **Timeouts**: Each task has configurable timeout (default 300s)
- **Retry Logic**: Failed tasks can be retried automatically
- **Graceful Degradation**: If a tool is unavailable, that task is skipped
- **Memory Efficiency**: Results are streamed, not held in memory

---

## Security Considerations

### Legal & Ethical Use

⚠️ **WARNING**: Only use Phase 2 on systems you own or have explicit written permission to test.

- Web vulnerability scanning can trigger WAF/IDS alerts
- SSL/TLS testing may be logged by security teams
- CVE correlation is passive (safe for production use)
- Aggressive mode can cause service disruption

### Stealth Mode

When enabled:
- Slower scan rates (avoid threshold-based detection)
- Random delays between requests
- User-agent rotation
- Integration with existing evasion modules

### Data Protection

- Scan results may contain sensitive information (service versions, configurations)
- Store results securely
- Encrypt when transmitting over networks
- Follow data retention policies

---

## Troubleshooting

### Common Issues

**1. "No Phase 1 data loaded"**
- Load Phase 1 results via GUI "Load Phase 1 Results" button
- Or run Phase 1 first and use current results
- Or continue without Phase 1 data (manual target specification needed)

**2. "NVD API rate limit exceeded"**
- CVE correlation uses cached data when API is unavailable
- Wait 30 minutes and retry
- Consider using NVD API key for higher limits

**3. "Tool not available: nikto"**
- Install Nikto: `sudo apt-get install nikto` (Linux)
- Or download from: https://github.com/sullo/nikto
- Scanner will be skipped if not available

**4. "SSL connection failed"**
- Target may not support HTTPS
- Self-signed certificates may cause issues
- Check firewall/network connectivity

**5. "Scan tasks stuck at X%"**
- Check task timeout configuration
- Some targets may be slow to respond
- Consider using stealth mode with longer timeouts

### Debug Mode

Enable detailed logging:

```python
from loguru import logger
logger.add("phase2_debug.log", level="DEBUG")
```

### Tool Validation

Check which tools are available:

```python
from modules.nikto_scanner import NiktoScanner
from modules.xss_scanner import XSSScanner

nikto = NiktoScanner()
print(f"Nikto available: {nikto.is_available()}")

xss = XSSScanner()
print(f"XSS Scanner available: {xss.is_available()}")
```

---

## Future Enhancements

### Planned Features

1. **Additional Scanners**
   - OWASP ZAP integration
   - Burp Suite automation
   - Web application firewall (WAF) bypass testing
   - API security testing (REST, GraphQL, SOAP)

2. **ML-Based False Positive Reduction**
   - Train on historical scan results
   - Confidence scoring improvements
   - Automatic verification of findings

3. **Attack Path Analysis**
   - Graph-based vulnerability chaining
   - Multi-hop exploitation planning
   - Critical path identification

4. **Enhanced CVE Correlation**
   - ExploitDB integration
   - Metasploit module matching
   - CISA KEV (Known Exploited Vulnerabilities) tracking

5. **Distributed Scanning**
   - Multi-agent coordination
   - Load balancing across nodes
   - Aggregated result collection

---

## API Reference

### Phase2Orchestrator

```python
class Phase2Orchestrator:
    def __init__(self, config: Optional[Dict[str, Any]] = None)
    
    def load_phase1_results(self, phase1_data: Dict[str, Any]) -> None
    
    def create_scan_plan(self) -> List[ScanTask]
    
    async def execute_scan_plan(self, callback=None) -> Dict[str, Any]
    
    def save_results(self, output_dir: str = "./reports/phase2") -> str
```

### CVECorrelationEngine

```python
class CVECorrelationEngine:
    def __init__(self, cache_dir: str = "./data/cve_cache", cache_ttl: int = 86400)
    
    def correlate_service(self, service: str, version: str, 
                         vendor: Optional[str] = None) -> Dict[str, Any]
    
    def batch_correlate(self, services: List[Dict[str, str]]) -> List[Dict[str, Any]]
    
    def generate_vulnerabilities(self, correlation_result: Dict[str, Any], 
                                target: str) -> List[Dict[str, Any]]
```

### NiktoScanner

```python
class NiktoScanner(BaseTool):
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]
    
    def quick_scan(self, target: str) -> Dict[str, Any]
    
    def full_scan(self, target: str) -> Dict[str, Any]
    
    def stealth_scan(self, target: str) -> Dict[str, Any]
```

### XSSScanner

```python
class XSSScanner:
    def __init__(self, timeout: int = 10, max_payloads: int = 10)
    
    def scan_url(self, url: str, crawl: bool = False) -> Dict[str, Any]
```

### SSLTester

```python
class SSLTester:
    def __init__(self, timeout: int = 10)
    
    def test_url(self, url: str) -> Dict[str, Any]
```

---

## Change Log

### Version 1.0.0 (January 25, 2026)
- ✅ Initial implementation of Phase 2 orchestrator
- ✅ Nikto scanner integration
- ✅ XSS vulnerability scanner
- ✅ SSL/TLS security tester
- ✅ CVE correlation engine with NVD API
- ✅ GUI Phase 2 tab with real-time progress
- ✅ HTML/JSON report generation
- ✅ Phase 1 integration and attack surface analysis
- ✅ Parallel task execution with dependency management
- ✅ Comprehensive documentation

---

## Credits

**Development Team**: EsecAi Platform Development

**Integrated Tools**:
- Nikto - Web server scanner by Sullo
- SQLMap - SQL injection tool by Bernardo Damele & Miroslav Stampar
- NVD - National Vulnerability Database by NIST
- Python SSL module - Python Software Foundation

**Testing Environment**: DVWA, WebGoat, vulnerable VMs

---

## Support

For issues, questions, or contributions:
- Documentation: This file
- Example usage: [examples/phase2_example.py](examples/phase2_example.py)
- Issue tracker: GitHub repository
- Logging: Enable debug mode for detailed troubleshooting

---

**END OF PHASE 2 IMPLEMENTATION GUIDE**
