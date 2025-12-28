# Phase 9: Adversary Simulation & Red Team Automation - Complete Guide

## Overview

Phase 9 implements advanced adversary simulation and red team automation capabilities, including:
- **MITRE ATT&CK Integration**: Map all actions to the ATT&CK framework and execute specific TTPs
- **Threat Actor Emulation**: Mimic nation-state actors (APT28, APT29, Lazarus, etc.)
- **Purple Team Capabilities**: Real-time telemetry generation and detection testing
- **Continuous Adversary Simulation**: Scheduled campaigns and assume-breach scenarios

## Table of Contents

1. [Installation](#installation)
2. [Core Components](#core-components)
3. [MITRE ATT&CK Integration](#mitre-attck-integration)
4. [Threat Actor Emulation](#threat-actor-emulation)
5. [Purple Team Operations](#purple-team-operations)
6. [Continuous Simulation](#continuous-simulation)
7. [Usage Examples](#usage-examples)
8. [Best Practices](#best-practices)

## Installation

### Prerequisites

```bash
# Install Phase 9 requirements
pip install -r requirements-phase9.txt
```

### Verify Installation

```python
from core.phase9_engine import Phase9Engine

# Initialize engine
engine = Phase9Engine()
print("Phase 9 Engine ready!")
```

## Core Components

### 1. MITRE ATT&CK Mapper

Maps security operations to MITRE ATT&CK framework:

```python
from adversary_simulation import MITREAttackMapper

mapper = MITREAttackMapper()

# Map action to techniques
techniques = mapper.map_action_to_attack(
    action="credential dumping with mimikatz",
    context={"tool": "mimikatz"}
)
# Returns: ['T1003', 'T1110']

# Get technique details
technique = mapper.get_technique("T1003")
print(f"Technique: {technique.name}")
print(f"Tactic: {technique.tactic}")

# Get coverage matrix
coverage = mapper.get_coverage_matrix()
```

### 2. Threat Actor Emulator

Emulate specific APT groups with realistic TTPs:

```python
from adversary_simulation import ThreatActorEmulator

emulator = ThreatActorEmulator()

# Get APT profile
profile = emulator.get_profile("APT28")
print(f"Attribution: {profile.attribution}")
print(f"Tools: {profile.preferred_tools}")

# Emulate APT campaign
campaign = await emulator.emulate_actor(
    actor_name="APT28",
    campaign_duration=timedelta(hours=24),
    target_environment={"domain": "corp.local"}
)
```

### 3. Purple Team Coordinator

Coordinate red and blue team activities:

```python
from adversary_simulation import PurpleTeamCoordinator

coordinator = PurpleTeamCoordinator()

# Run purple team exercise
session = await coordinator.run_purple_team_exercise(
    technique_ids=["T1059", "T1003", "T1071"],
    detection_rules=detection_rules,
    generate_telemetry=True
)

print(f"EDR Score: {session['edr_effectiveness']['score']}")
```

### 4. Continuous Adversary Simulator

Run ongoing attack simulations:

```python
from adversary_simulation import ContinuousAdversarySimulator

simulator = ContinuousAdversarySimulator()

# Create assume-breach scenario
campaign = simulator.create_assume_breach_scenario(
    name="Compromised User Account",
    initial_access="Phished credentials",
    privilege_level="user",
    target_assets=["DC01", "FS01"]
)

# Run campaign
result = await simulator.run_campaign(campaign)
```

## MITRE ATT&CK Integration

### Technique Mapping

Phase 9 automatically maps all actions to MITRE ATT&CK techniques:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Analyze coverage
coverage = engine.analyze_attack_coverage()

print(f"Overall Coverage: {coverage['overall_coverage']}%")
print(f"Techniques Executed: {coverage['executed_techniques']}")

# Generate ATT&CK Navigator layer
# Saved to: reports/phase9/attack_navigator_layer.json
```

### TTPs and Kill Chains

Pre-defined TTP sequences for common scenarios:

```python
from adversary_simulation import TTPs

# Standard kill chain
kill_chain = TTPs.killchain_sequence()

# Ransomware attack
ransomware = TTPs.ransomware_sequence()

# APT espionage
espionage = TTPs.apt_espionage_sequence()
```

### APT Emulation

Execute campaigns matching specific APT groups:

```python
from adversary_simulation import APTEmulator, MITREAttackMapper

mapper = MITREAttackMapper()
apt_emulator = APTEmulator(mapper)

# Emulate APT28 campaign
campaign = await apt_emulator.emulate_apt_campaign(
    apt_name="APT28",
    target_env={"domain": "target.local"}
)

print(f"Success Rate: {campaign['success_rate']}%")
print(f"Executed TTPs: {len(campaign['executed_ttps'])}")
```

## Threat Actor Emulation

### Supported APT Groups

Phase 9 includes profiles for major APT groups:

- **APT28** (Fancy Bear) - Russian GRU
- **APT29** (Cozy Bear) - Russian SVR
- **Lazarus Group** - North Korean RGB
- **APT38** - North Korean financial cybercrime
- **APT41** (Double Dragon) - Chinese dual-purpose
- **FIN7** (Carbanak) - Cybercriminal organization

### APT Profile Structure

Each APT profile includes:
- Attribution and country of origin
- Preferred tools and malware families
- Attack vectors and C2 infrastructure
- Known campaigns and targets
- Typical TTP sequences

### Emulation Example

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Emulate multiple APT groups
results = await engine.emulate_apt_groups(
    apt_groups=["APT28", "APT29", "Lazarus"],
    target_env={"domain": "corp.local"}
)

for result in results:
    print(f"APT: {result['actor']}")
    print(f"Phases: {len(result['timeline'])}")
    print(f"Tools: {result['tools_used']}")
```

## Purple Team Operations

### Telemetry Generation

Generate realistic security telemetry for testing:

```python
from adversary_simulation import TelemetryGenerator

telem_gen = TelemetryGenerator()

# Generate process creation event
event = telem_gen.generate_process_creation(
    technique_id="T1059",
    technique_name="PowerShell Execution",
    process="powershell.exe",
    command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile"
)

# Generate network connection
event = telem_gen.generate_network_connection(
    technique_id="T1071",
    technique_name="Application Layer Protocol",
    process="malware.exe",
    dest_ip="192.168.1.100",
    dest_port=443
)

# Export to SIEM format
elastic_events = telem_gen.export_to_siem_format("elastic")
splunk_events = telem_gen.export_to_siem_format("splunk")
sentinel_events = telem_gen.export_to_siem_format("sentinel")
```

### Detection Rule Testing

Test detection rules against generated telemetry:

```python
from adversary_simulation import DetectionValidator

validator = DetectionValidator()

# Create detection rule
rule = validator.create_detection_rule(
    rule_id="RULE001",
    name="Suspicious PowerShell",
    description="Detects bypass execution policy",
    severity="high",
    technique_ids=["T1059"],
    rule_type="sigma",
    rule_content="detection: selection: CommandLine|contains: 'bypass'"
)

# Test rule
results = await validator.test_rule(rule, telemetry_events)

print(f"Accuracy: {results['accuracy']:.2%}")
print(f"Precision: {results['precision']:.2%}")
print(f"Recall: {results['recall']:.2%}")
print(f"F1 Score: {results['f1_score']:.2%}")
```

### EDR/XDR Effectiveness Testing

Assess security controls effectiveness:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Run purple team exercise
purple_results = await engine.run_purple_team_exercise()

edr_effectiveness = purple_results['exercise']['edr_effectiveness']

print(f"EDR Score: {edr_effectiveness['score']}/100")
print(f"Rating: {edr_effectiveness['rating']}")
print(f"Detection Coverage: {edr_effectiveness['detection_coverage']:.1%}")
```

## Continuous Simulation

### Scheduled Campaigns

Schedule regular attack campaigns:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Schedule campaigns
campaigns = [
    {
        "name": "Weekly Reconnaissance",
        "schedule": "0 2 * * 1",  # Every Monday at 2 AM
        "duration_hours": 2,
        "techniques": ["T1595", "T1592", "T1589"],
        "objectives": ["Test detection of reconnaissance"]
    },
    {
        "name": "Monthly Full Kill Chain",
        "schedule": "0 0 1 * *",  # First day of each month
        "duration_hours": 8,
        "techniques": ["T1190", "T1059", "T1003", "T1021", "T1041"],
        "objectives": ["End-to-end attack simulation"]
    }
]

engine.schedule_continuous_campaigns(campaigns)

# Start continuous simulation
await engine.start_continuous_simulation(interval=timedelta(hours=24))
```

### Assume Breach Scenarios

Test post-compromise detection:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Run assume-breach scenarios
breach_results = await engine.run_assume_breach_scenarios({
    "domain": "corp.local",
    "critical_assets": ["DC01", "FS01", "DB01"]
})

for scenario in breach_results:
    print(f"Scenario: {scenario['name']}")
    print(f"Phases: {len(scenario['phases'])}")
    print(f"Success: {scenario['status']}")
```

### Insider Threat Simulation

Simulate malicious insider activity:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Simulate insider threat
insider_result = await engine.simulate_insider_threat()

print(f"Campaign: {insider_result['name']}")
print(f"Duration: {insider_result['duration_minutes']} minutes")
print(f"Techniques: {len(insider_result['techniques_executed'])}")
print(f"Detections: {len(insider_result.get('detections_triggered', []))}")
```

### Supply Chain Attack

Simulate supply chain compromise:

```python
from core.phase9_engine import Phase9Engine

engine = Phase9Engine()

# Simulate supply chain attack
supply_chain_result = await engine.simulate_supply_chain_attack()

print(f"Campaign: {supply_chain_result['name']}")
print(f"Vector: {supply_chain_result['type']}")
print(f"Phases: {len(supply_chain_result['phases'])}")
```

## Usage Examples

### Complete Phase 9 Assessment

```python
import asyncio
from core.phase9_engine import Phase9Engine

async def main():
    # Initialize engine
    engine = Phase9Engine({
        "output_dir": "reports/phase9"
    })
    
    # Run full assessment
    results = await engine.run_full_assessment({
        "domain": "corp.local",
        "critical_assets": ["DC01", "FS01", "DB01", "WEB01"],
        "security_controls": {
            "edr": True,
            "firewall": True,
            "siem": True
        }
    })
    
    # Review results
    print(f"\nATT&CK Coverage: {results['summary']['attack_coverage']:.1f}%")
    print(f"APT Emulations: {results['summary']['total_apt_emulations']}")
    print(f"Detection Score: {results['summary']['detection_effectiveness']:.1f}/100")
    
    print("\nRecommendations:")
    for rec in results['recommendations'][:5]:
        print(f"  • {rec}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Custom APT Campaign

```python
from adversary_simulation import ThreatActorEmulator
import asyncio

async def custom_apt_campaign():
    emulator = ThreatActorEmulator()
    
    # Emulate APT29 (Cozy Bear)
    campaign = await emulator.emulate_actor(
        actor_name="APT29",
        campaign_duration=timedelta(hours=12),
        target_environment={
            "domain": "target.corp",
            "critical_systems": ["mail.corp", "dc.corp"]
        }
    )
    
    print(f"Campaign: {campaign['actor']}")
    print(f"Duration: {campaign['profile']['active_since']}")
    print(f"Tools Used: {len(set(campaign['tools_used']))}")
    
    # Review timeline
    for activity in campaign['timeline']:
        print(f"  [{activity['timestamp']}] {activity['description']}")

asyncio.run(custom_apt_campaign())
```

### Purple Team Exercise

```python
from adversary_simulation import PurpleTeamCoordinator, DetectionValidator
import asyncio

async def purple_team_exercise():
    coordinator = PurpleTeamCoordinator()
    
    # Define detection rules
    rules = [
        coordinator.detection_validator.create_detection_rule(
            rule_id="CRED_DUMP",
            name="Credential Dumping Detection",
            description="Detects LSASS access",
            severity="critical",
            technique_ids=["T1003"],
            rule_type="sigma",
            rule_content="..."
        )
    ]
    
    # Run exercise
    session = await coordinator.run_purple_team_exercise(
        technique_ids=["T1003", "T1059", "T1021"],
        detection_rules=rules,
        generate_telemetry=True
    )
    
    # Review EDR effectiveness
    edr = session['edr_effectiveness']
    print(f"EDR Score: {edr['score']:.1f}/100")
    print(f"Rating: {edr['rating']}")
    
    # Review recommendations
    for rec in session['recommendations']:
        print(f"  • {rec}")

asyncio.run(purple_team_exercise())
```

## Best Practices

### 1. Coordination and Authorization

- **Get Written Authorization**: Always obtain written authorization before running adversary simulations
- **Coordinate with Blue Team**: Ensure blue team is aware of purple team exercises
- **Define Scope**: Clearly define what systems and networks are in scope
- **Set Boundaries**: Establish what techniques are off-limits

### 2. Safety and Control

- **Use Kill Switches**: Implement emergency stop mechanisms
- **Monitor Impact**: Continuously monitor system performance and availability
- **Limit Scope**: Start with limited scope and expand gradually
- **Backup Critical Data**: Ensure backups exist before destructive testing

### 3. Telemetry and Logging

- **Enable Comprehensive Logging**: Ensure all security controls are logging
- **Preserve Evidence**: Save all telemetry for post-exercise analysis
- **Timestamp Everything**: Accurate timestamps are critical for correlation
- **Export Formats**: Use standard formats (Sigma, ECS, etc.)

### 4. Detection Testing

- **Test Regularly**: Schedule regular purple team exercises
- **Measure Effectiveness**: Track detection rates over time
- **Tune Rules**: Use false positive/negative data to improve rules
- **Validate Changes**: Test detection rules after any changes

### 5. Continuous Improvement

- **Track Metrics**: Monitor ATT&CK coverage, detection rates, response times
- **Update Profiles**: Keep APT profiles current with latest intelligence
- **Learn from Results**: Use findings to improve defensive posture
- **Share Knowledge**: Document lessons learned and share with team

### 6. Reporting

- **Document Everything**: Maintain detailed records of all activities
- **Generate Reports**: Create comprehensive reports for stakeholders
- **Track Progress**: Show improvement over time
- **Provide Recommendations**: Include actionable recommendations

## Output and Reports

### Report Locations

```
reports/phase9/
├── phase9_assessment_YYYYMMDD_HHMMSS.json    # Main assessment results
├── attack_navigator_layer.json                # ATT&CK Navigator layer
├── detection_validation.json                  # Detection testing results
├── threat_emulation/
│   └── threat_emulation_APT28_*.json         # APT campaign reports
└── continuous_simulation/
    ├── campaign_*.json                        # Campaign results
    └── simulation_report_*.json               # Simulation summary
```

### ATT&CK Navigator

Import the generated ATT&CK Navigator layer:

1. Go to https://mitre-attack.github.io/attack-navigator/
2. Click "Open Existing Layer" → "Upload from local"
3. Select `attack_navigator_layer.json`
4. View your coverage visually

## Troubleshooting

### Common Issues

**Issue**: APT emulation fails
- Check target environment configuration
- Verify network connectivity
- Review logs for specific errors

**Issue**: Detection rules not triggering
- Verify telemetry is being generated
- Check rule syntax and logic
- Ensure SIEM is receiving events

**Issue**: Continuous simulation not running
- Check schedule syntax
- Verify campaign configuration
- Review system resources

## Integration with Previous Phases

Phase 9 builds on all previous phases:

- **Phase 1-3**: Basic reconnaissance and exploitation
- **Phase 4**: Evasion techniques used in APT campaigns
- **Phase 5**: Advanced exploitation for privilege escalation
- **Phase 6**: Agent coordination for complex campaigns
- **Phase 7**: Cloud targeting in modern APT scenarios
- **Phase 8**: Data exfiltration in final campaign stages

## Next Steps

After completing Phase 9:

1. Review ATT&CK coverage and identify gaps
2. Implement continuous simulation schedule
3. Establish regular purple team exercises
4. Update detection rules based on findings
5. Track metrics and measure improvement
6. Share results with security team

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Purple Team Exercise Guide: https://www.sans.org/white-papers/

## Support

For issues or questions:
- Check the main README.md
- Review logs in `logs/` directory
- Consult MITRE ATT&CK documentation
- Review APT profiles in source code
