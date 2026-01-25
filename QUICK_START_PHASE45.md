# Quick Start Guide - Phase 4 & 5

## 🚀 Quick Start

### Run Complete Pentest (Phase 1-5)
```bash
python main.py --phase12345 --target corp.local
```

### Run Exploitation Only (Phase 1-3)
```bash
python main.py --phase123 --target 192.168.1.0/24
```

## 📋 Phase Overview

| Phase | Name | Purpose | Output |
|-------|------|---------|--------|
| 1 | Reconnaissance | Network scanning, OSINT | Hosts, services, subdomains |
| 2 | Vulnerability Scanning | CVE correlation, web scanning | Vulnerabilities with CVSS scores |
| 3 | Exploitation | LLM-driven exploit execution | Compromised hosts, shells |
| 4 | Post-Exploitation | Privilege escalation, credential harvesting | Root access, credentials, persistence |
| 5 | Lateral Movement | Network spreading, AD attacks | Domain Admin, DC compromise |

## ⚙️ Configuration Quick Reference

### Phase 4 Config
```python
{
    'privilege_escalation': {
        'enabled': True,
        'max_attempts': 3,
        'techniques': ['kernel_exploits', 'suid_binaries', 'sudo_abuse', 
                      'dll_hijacking', 'token_manipulation']
    },
    'credential_harvesting': {
        'enabled': True,
        'methods': ['mimikatz', 'browser_dump', 'memory_scrape', 'config_files']
    },
    'persistence': {
        'enabled': True,
        'stealth_mode': True,
        'max_mechanisms': 3
    }
}
```

### Phase 5 Config
```python
{
    'lateral_movement': {
        'enabled': True,
        'max_hops': 5,
        'techniques': ['pass_the_hash', 'pass_the_ticket', 'ssh', 'rdp', 
                      'winrm', 'psexec', 'wmi']
    },
    'active_directory': {
        'enabled': True,
        'attacks': ['kerberoasting', 'asrep_roasting', 'dcsync', 'golden_ticket']
    },
    'domain_dominance': {
        'target_dc': True,
        'bloodhound_analysis': True
    }
}
```

## 🔑 Key Features

### Phase 4: Post-Exploitation
- ✅ **Linux PrivEsc**: SUID, sudo, kernel exploits, capabilities, cron
- ✅ **Windows PrivEsc**: Token manipulation, DLL hijacking, kernel exploits
- ✅ **Credential Harvesting**: Mimikatz, browser dumps, memory scraping
- ✅ **Persistence**: SSH keys, registry, scheduled tasks, services

### Phase 5: Lateral Movement
- ✅ **Lateral Movement**: Pass-the-Hash, Pass-the-Ticket, SSH, RDP, WinRM, PSExec, WMI
- ✅ **AD Attacks**: Kerberoasting, DCSync, Golden Tickets, AS-REP Roasting
- ✅ **Network Topology**: NetworkX graphs, attack path analysis
- ✅ **BloodHound**: Data collection, graph analysis, crown jewels targeting

## 📊 Expected Results

### Phase 4 Output
```json
{
  "statistics": {
    "fully_compromised_hosts": 6,
    "total_credentials_harvested": 47,
    "persistence_mechanisms_installed": 12,
    "privilege_escalation_success_rate": 0.75
  }
}
```

### Phase 5 Output
```json
{
  "statistics": {
    "successful_lateral_movements": 23,
    "domain_admin_achieved": true,
    "domain_controllers_compromised": 2,
    "lateral_movement_success_rate": 0.77
  }
}
```

## 🛡️ Safety Modes

### Safe Mode (Default: ON)
```python
'safe_mode': True  # Prevents kernel exploits, destructive actions
```

### Stealth Mode
```python
'stealth_mode': True  # Minimal noise, anti-forensics
```

## 📁 File Locations

### Phase 4 Results
```
./reports/phase4/phase4_results_YYYYMMDD_HHMMSS.json
```

### Phase 5 Results
```
./reports/phase5/phase5_results_YYYYMMDD_HHMMSS.json
```

### Complete Pentest
```
./reports/complete_pentest_YYYYMMDD_HHMMSS.json
```

## 🔧 Programmatic Usage

```python
from core.phase4_orchestrator import Phase4Orchestrator
from core.phase5_orchestrator import Phase5Orchestrator
from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider

# Initialize LLM
provider = OpenAIProvider(api_key="sk-...", model="gpt-4")
orchestrator = LLMOrchestrator(provider)

# Run Phase 4
phase4 = Phase4Orchestrator(orchestrator, phase4_config)
results4 = await phase4.execute(target="192.168.1.100")

# Run Phase 5
phase5 = Phase5Orchestrator(orchestrator, phase5_config)
results5 = await phase5.execute(target="corp.local", phase4_results=results4)
```

## 🎯 Common Use Cases

### 1. Full Network Pentest
```bash
python main.py --phase12345 --target 192.168.1.0/24
```

### 2. Active Directory Assessment
```bash
python main.py --phase12345 --target corp.local
```

### 3. Single Host Deep Dive
```bash
python main.py --phase12345 --target 192.168.1.50
```

## ⚠️ Important Warnings

- ⚠️ **Requires written authorization**
- ⚠️ **Can crash systems (kernel exploits)**
- ⚠️ **Modifies system configuration**
- ⚠️ **Spreads across network**
- ⚠️ **Use safe_mode for initial testing**

## 📚 Documentation

- **Phase 4 Details**: `PHASE4_IMPLEMENTATION.md`
- **Phase 5 Details**: `PHASE5_IMPLEMENTATION.md`
- **Complete Summary**: `PHASE4_PHASE5_SUMMARY.md`

## 🐛 Troubleshooting

### Phase 4 Issues
```
Problem: Privilege escalation fails
Solution: Check OS detection, verify shell stability, increase max_attempts
```

### Phase 5 Issues
```
Problem: Lateral movement blocked
Solution: Verify credentials, check firewall rules (445, 5985, 3389), try alternative techniques
```

## 📞 Quick Help

```bash
# View all options
python main.py --help

# Check version
python main.py --version

# Test configuration
python main.py --test-config
```

---

**Ready to use! Start with `python main.py --phase12345 --target YOUR_TARGET`**
