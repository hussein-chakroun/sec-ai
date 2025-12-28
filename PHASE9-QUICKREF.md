# Phase 9: Adversary Simulation & Red Team Automation - Quick Reference

## Quick Start

```python
from core.phase9_engine import Phase9Engine
import asyncio

async def main():
    engine = Phase9Engine()
    results = await engine.run_full_assessment()

asyncio.run(main())
```

## Key Features

### 1. MITRE ATT&CK Integration ✅
- **Coverage Analysis**: Analyze your ATT&CK framework coverage
- **Technique Mapping**: Auto-map actions to ATT&CK techniques
- **Navigator Export**: Generate ATT&CK Navigator layers

### 2. Threat Actor Emulation 🎭
- **APT Groups**: APT28, APT29, Lazarus, APT38, APT41, FIN7
- **Realistic TTPs**: Use actual malware and tools from APT profiles
- **Campaign Timeline**: Replicate real-world attack timelines

### 3. Purple Team Operations 🟣
- **Telemetry Generation**: Create realistic security events
- **Detection Testing**: Validate detection rules
- **EDR Assessment**: Test EDR/XDR effectiveness
- **SIEM Integration**: Export to Elastic, Splunk, Sentinel

### 4. Continuous Simulation 🔄
- **Scheduled Campaigns**: Run attacks on schedule
- **Assume Breach**: Test post-compromise detection
- **Insider Threats**: Simulate malicious insiders
- **Supply Chain**: Test third-party compromise scenarios

## Common Commands

### Run Full Assessment
```python
from core.phase9_engine import Phase9Engine
engine = Phase9Engine()
results = await engine.run_full_assessment()
```

### Emulate Specific APT
```python
from adversary_simulation import ThreatActorEmulator
emulator = ThreatActorEmulator()
campaign = await emulator.emulate_actor("APT28")
```

### Purple Team Exercise
```python
from adversary_simulation import PurpleTeamCoordinator
coordinator = PurpleTeamCoordinator()
session = await coordinator.run_purple_team_exercise(
    technique_ids=["T1059", "T1003"],
    detection_rules=rules
)
```

### Assume Breach Scenario
```python
from adversary_simulation import ContinuousAdversarySimulator
simulator = ContinuousAdversarySimulator()
campaign = simulator.create_assume_breach_scenario(
    name="Compromised Account",
    initial_access="Phished credentials",
    privilege_level="user",
    target_assets=["DC01", "FS01"]
)
result = await simulator.run_campaign(campaign)
```

## APT Profiles Quick Reference

| APT Group | Country | Focus | Key Tools |
|-----------|---------|-------|-----------|
| APT28 (Fancy Bear) | Russia | Government/Military | XAgent, Sofacy, Mimikatz |
| APT29 (Cozy Bear) | Russia | Intelligence | CozyDuke, PowerDuke, SUNBURST |
| Lazarus | North Korea | Financial/Espionage | WannaCry, DTrack |
| APT38 | North Korea | Banking/SWIFT | DYEPACK, NESTEGG |
| APT41 | China | Healthcare/Telecom | HIGHNOON, LOWKEY, MESSAGETAP |
| FIN7 | Russia/Eastern Europe | Retail/Financial | Carbanak, GRIFFON |

## MITRE ATT&CK Tactics Quick Reference

1. **Reconnaissance** - T1595, T1592, T1589
2. **Resource Development** - T1583, T1587
3. **Initial Access** - T1190, T1566, T1078
4. **Execution** - T1059, T1106, T1053
5. **Persistence** - T1547, T1053, T1136
6. **Privilege Escalation** - T1068, T1134, T1078
7. **Defense Evasion** - T1070, T1055, T1027
8. **Credential Access** - T1003, T1110, T1056
9. **Discovery** - T1087, T1083, T1135
10. **Lateral Movement** - T1021, T1091
11. **Collection** - T1560, T1113, T1005
12. **Command & Control** - T1071, T1132, T1573
13. **Exfiltration** - T1041, T1048, T1567
14. **Impact** - T1486, T1490, T1489

## Campaign Types

### Scheduled Campaign
```python
campaign = simulator.create_scheduled_campaign(
    name="Weekly Test",
    schedule="0 2 * * 1",  # Cron format
    duration=timedelta(hours=2),
    techniques=["T1595", "T1592"],
    objectives=["Test recon detection"]
)
```

### Assume Breach
```python
campaign = simulator.create_assume_breach_scenario(
    name="Compromised User",
    initial_access="Phished creds",
    privilege_level="user",
    target_assets=["DC01"]
)
```

### Insider Threat
```python
campaign = simulator.create_insider_threat_scenario(
    name="Malicious Employee",
    insider_type="Disgruntled",
    access_level="privileged_user",
    motivation="Financial gain"
)
```

### Supply Chain
```python
campaign = simulator.create_supply_chain_attack_scenario(
    name="Trojanized Update",
    compromised_component="Monitoring Agent",
    target_organizations=["Org A", "Org B"]
)
```

## Telemetry Types

```python
from adversary_simulation import TelemetryGenerator
telem = TelemetryGenerator()

# Process creation
telem.generate_process_creation("T1059", "PowerShell", 
    "powershell.exe", "powershell.exe -Bypass")

# Network connection
telem.generate_network_connection("T1071", "C2 Beacon",
    "malware.exe", "192.168.1.100", 443)

# File creation
telem.generate_file_creation("T1105", "Download",
    "malware.exe", "C:\\Temp\\payload.exe")

# Registry modification
telem.generate_registry_modification("T1547", "Persistence",
    "malware.exe", "HKLM\\...\\Run", "C:\\malware.exe")

# Authentication
telem.generate_authentication_event("T1078", "Valid Account",
    success=True, user="admin", source_host="WS01", dest_host="DC01")
```

## Detection Rule Testing

```python
from adversary_simulation import DetectionValidator
validator = DetectionValidator()

rule = validator.create_detection_rule(
    rule_id="R001",
    name="Suspicious PowerShell",
    description="Detects bypass",
    severity="high",
    technique_ids=["T1059"],
    rule_type="sigma",
    rule_content="..."
)

results = await validator.test_rule(rule, telemetry_events)
print(f"Precision: {results['precision']:.2%}")
print(f"Recall: {results['recall']:.2%}")
```

## Output Files

```
reports/phase9/
├── phase9_assessment_*.json              # Main results
├── attack_navigator_layer.json           # ATT&CK viz
├── detection_validation.json             # Detection tests
├── threat_emulation/
│   └── threat_emulation_APT28_*.json
└── continuous_simulation/
    ├── campaign_*.json
    └── simulation_report_*.json
```

## Key Metrics

- **ATT&CK Coverage**: % of techniques tested
- **Detection Effectiveness**: EDR/XDR score (0-100)
- **True Positive Rate**: Correctly detected attacks
- **False Positive Rate**: Incorrectly flagged benign activity
- **Dwell Time**: Time from initial access to detection
- **Lateral Movement Success**: % of successful pivots

## Safety Tips

⚠️ **ALWAYS**:
- Get written authorization
- Coordinate with blue team
- Use test environments when possible
- Have kill switches ready
- Monitor system impact
- Preserve evidence/logs

❌ **NEVER**:
- Run without authorization
- Test in production unannounced
- Use destructive techniques without approval
- Exceed defined scope
- Ignore system stability issues

## Integration Points

```python
# With Phase 8 (Exfiltration)
from exfiltration import DNSExfiltrator
# Use in APT campaigns for data theft

# With Phase 7 (Cloud)
from cloud_security import AzureEnumerator
# Include cloud TTPs in campaigns

# With Phase 6 (Agents)
from agents import SwarmIntelligence
# Coordinate multi-host campaigns

# With Phase 4 (Evasion)
from evasion import ProcessHollowing
# Use evasion in APT emulation
```

## Quick Troubleshooting

| Issue | Solution |
|-------|----------|
| Campaign fails | Check target_env config |
| No detections | Verify telemetry generation |
| Low coverage | Add more techniques to campaign |
| High false positives | Tune detection rules |
| Slow execution | Reduce campaign duration |

## CLI Examples

```bash
# Run Phase 9 assessment
python -m core.phase9_engine

# Generate campaign report
python -c "from adversary_simulation import ContinuousAdversarySimulator; \
    sim = ContinuousAdversarySimulator(); \
    sim.generate_simulation_report()"

# Export ATT&CK Navigator layer
python -c "from adversary_simulation import MITREAttackMapper; \
    mapper = MITREAttackMapper(); \
    mapper.generate_navigator_layer('output.json')"
```

## Performance Tuning

```python
# Reduce campaign duration for faster testing
campaign.duration = timedelta(hours=1)

# Limit techniques for focused testing
campaign.techniques = ["T1059", "T1003", "T1021"]

# Adjust detection probability
# In continuous_simulation.py, modify:
detection_prob = 0.20  # Lower for less aggressive detection

# Parallel campaign execution
tasks = [simulator.run_campaign(c) for c in campaigns]
results = await asyncio.gather(*tasks)
```

## Resources

- **MITRE ATT&CK**: https://attack.mitre.org/
- **ATT&CK Navigator**: https://mitre-attack.github.io/attack-navigator/
- **Sigma Rules**: https://github.com/SigmaHQ/sigma
- **APT Groups**: https://attack.mitre.org/groups/
- **Purple Team**: https://www.sans.org/white-papers/purple-team/

## Version Info

- **Phase**: 9
- **Focus**: Adversary Simulation & Red Team Automation
- **Prerequisites**: Phases 1-8
- **Status**: Production Ready ✅
