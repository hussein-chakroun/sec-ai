"""
Phase 9 Example: Comprehensive Adversary Simulation
Demonstrates all Phase 9 capabilities
"""

import asyncio
from datetime import timedelta
from pathlib import Path

# Phase 9 imports
from core.phase9_engine import Phase9Engine
from adversary_simulation import (
    MITREAttackMapper,
    ThreatActorEmulator,
    PurpleTeamCoordinator,
    ContinuousAdversarySimulator,
    CampaignType
)


async def example_mitre_attack_coverage():
    """Example: Analyze MITRE ATT&CK coverage"""
    print("\n" + "="*80)
    print("EXAMPLE 1: MITRE ATT&CK Coverage Analysis")
    print("="*80)
    
    mapper = MITREAttackMapper()
    
    # Get coverage matrix
    coverage = mapper.get_coverage_matrix()
    
    print("\nATT&CK Coverage by Tactic:")
    for tactic, data in coverage.items():
        print(f"\n{tactic.upper()}")
        print(f"  Coverage: {data['coverage_percentage']:.1f}%")
        print(f"  Executed: {data['executed_techniques']}/{data['total_techniques']}")
    
    # Generate Navigator layer
    navigator_path = Path("examples/attack_navigator.json")
    mapper.generate_navigator_layer(navigator_path)
    print(f"\n✅ ATT&CK Navigator layer saved to: {navigator_path}")
    print("   Import at: https://mitre-attack.github.io/attack-navigator/")


async def example_apt_emulation():
    """Example: Emulate APT28 (Fancy Bear)"""
    print("\n" + "="*80)
    print("EXAMPLE 2: APT28 (Fancy Bear) Emulation")
    print("="*80)
    
    emulator = ThreatActorEmulator()
    
    # Get APT28 profile
    profile = emulator.get_profile("APT28")
    
    print(f"\nThreat Actor: {profile.name}")
    print(f"Aliases: {', '.join(profile.aliases)}")
    print(f"Attribution: {profile.attribution}")
    print(f"Country: {profile.country}")
    print(f"Active Since: {profile.active_since}")
    print(f"\nSophistication: {profile.sophistication}")
    print(f"Operational Security: {profile.operational_security}")
    
    print(f"\nPreferred Tools ({len(profile.preferred_tools)}):")
    for tool in profile.preferred_tools[:5]:
        print(f"  • {tool}")
    
    print(f"\nMalware Families ({len(profile.malware_families)}):")
    for malware in profile.malware_families[:5]:
        print(f"  • {malware}")
    
    # Emulate campaign
    print("\n🎯 Starting APT28 Campaign Emulation...")
    campaign = await emulator.emulate_actor(
        actor_name="APT28",
        campaign_duration=timedelta(minutes=5),
        target_environment={
            "domain": "target.corp",
            "critical_systems": ["mail.corp", "dc.corp", "fs.corp"]
        }
    )
    
    print(f"\n✅ Campaign Complete!")
    print(f"   Duration: {campaign['profile']['active_since']}")
    print(f"   Activities: {len(campaign['timeline'])}")
    print(f"   Unique Tools: {len(set(campaign['tools_used']))}")
    print(f"   Techniques: {len(set(campaign['techniques_used']))}")


async def example_purple_team():
    """Example: Purple team exercise with detection testing"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Purple Team Exercise")
    print("="*80)
    
    coordinator = PurpleTeamCoordinator()
    
    # Create detection rules
    print("\n📋 Creating Detection Rules...")
    
    rules = [
        coordinator.detection_validator.create_detection_rule(
            rule_id="PS001",
            name="Suspicious PowerShell Execution",
            description="Detects PowerShell with bypass flag",
            severity="high",
            technique_ids=["T1059"],
            rule_type="sigma",
            rule_content="CommandLine|contains: 'bypass'"
        ),
        coordinator.detection_validator.create_detection_rule(
            rule_id="CRED001",
            name="Credential Dumping Detection",
            description="Detects LSASS process access",
            severity="critical",
            technique_ids=["T1003"],
            rule_type="sigma",
            rule_content="TargetImage|endswith: 'lsass.exe'"
        ),
        coordinator.detection_validator.create_detection_rule(
            rule_id="NET001",
            name="Suspicious Network Connection",
            description="Detects connections to suspicious IPs",
            severity="medium",
            technique_ids=["T1071"],
            rule_type="sigma",
            rule_content="DestinationPort: 443"
        ),
    ]
    
    print(f"   ✓ Created {len(rules)} detection rules")
    
    # Generate telemetry
    print("\n📡 Generating Attack Telemetry...")
    telem = coordinator.telemetry_gen
    
    telem.generate_process_creation(
        "T1059", "PowerShell Execution",
        "powershell.exe",
        "powershell.exe -ExecutionPolicy Bypass -NoProfile"
    )
    
    telem.generate_process_creation(
        "T1003", "Credential Dumping",
        "rundll32.exe",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump"
    )
    
    telem.generate_network_connection(
        "T1071", "C2 Communication",
        "malware.exe",
        "192.168.1.100",
        443
    )
    
    print(f"   ✓ Generated {len(telem.events)} telemetry events")
    
    # Run purple team exercise
    print("\n🟣 Running Purple Team Exercise...")
    session = await coordinator.run_purple_team_exercise(
        technique_ids=["T1059", "T1003", "T1071"],
        detection_rules=rules,
        generate_telemetry=False  # Already generated
    )
    
    # Display results
    edr = session['edr_effectiveness']
    print(f"\n📊 EDR/XDR Effectiveness Assessment:")
    print(f"   Score: {edr['score']:.1f}/100")
    print(f"   Rating: {edr['rating']}")
    print(f"   Detection Coverage: {edr['detection_coverage']:.1%}")
    
    print(f"\n💡 Recommendations:")
    for rec in session['recommendations']:
        print(f"   • {rec}")


async def example_assume_breach():
    """Example: Assume breach scenario"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Assume Breach Scenario")
    print("="*80)
    
    simulator = ContinuousAdversarySimulator()
    
    # Create assume-breach scenario
    print("\n🎯 Creating Assume Breach Scenario...")
    campaign = simulator.create_assume_breach_scenario(
        name="Compromised Domain User Account",
        initial_access="Phished credentials via email",
        privilege_level="user",
        target_assets=["DC01.corp.local", "FS01.corp.local", "DB01.corp.local"],
        duration=timedelta(hours=4)
    )
    
    print(f"   ✓ Scenario created: {campaign.name}")
    print(f"   Initial Access: {campaign.initial_access}")
    print(f"   Starting Privilege: {campaign.privilege_level}")
    print(f"   Target Assets: {len(campaign.target_assets)}")
    
    # Run campaign
    print("\n⚔️  Executing Campaign...")
    result = await simulator.run_campaign(campaign)
    
    print(f"\n✅ Campaign Results:")
    print(f"   Status: {result['status']}")
    print(f"   Duration: {result.get('duration_minutes', 0):.1f} minutes")
    print(f"   Phases Completed: {len(result['phases'])}")
    print(f"   Techniques Executed: {len(result['techniques_executed'])}")
    
    if 'detections_triggered' in result:
        print(f"   Detections Triggered: {len(result['detections_triggered'])}")
    
    # Show phase breakdown
    print(f"\n📋 Phase Breakdown:")
    for phase in result['phases']:
        success = "✓" if phase.get('success', False) else "✗"
        print(f"   {success} {phase['phase']}: {len(phase['techniques'])} techniques")


async def example_insider_threat():
    """Example: Insider threat simulation"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Insider Threat Simulation")
    print("="*80)
    
    simulator = ContinuousAdversarySimulator()
    
    # Create insider threat scenario
    print("\n👤 Creating Insider Threat Scenario...")
    campaign = simulator.create_insider_threat_scenario(
        name="Disgruntled Employee - Data Exfiltration",
        insider_type="Malicious Employee",
        access_level="privileged_user",
        motivation="Financial gain - recruited by competitor",
        duration=timedelta(days=1)  # Simulated timeline
    )
    
    print(f"   ✓ Scenario: {campaign.name}")
    print(f"   Type: {campaign.results['insider_profile']['type']}")
    print(f"   Access Level: {campaign.results['insider_profile']['access_level']}")
    print(f"   Motivation: {campaign.results['insider_profile']['motivation']}")
    
    # Run campaign
    print("\n🕵️  Executing Insider Threat Simulation...")
    result = await simulator.run_campaign(campaign)
    
    print(f"\n✅ Simulation Results:")
    print(f"   Status: {result['status']}")
    print(f"   Duration: {result.get('duration_minutes', 0):.1f} minutes")
    print(f"   Activities: {len(result['techniques_executed'])}")
    
    # Analyze detection capability
    if 'detections_triggered' in result:
        detections = result['detections_triggered']
        print(f"\n🚨 Detections:")
        print(f"   Total Alerts: {len(detections)}")
        
        severity_counts = {}
        for detection in detections:
            sev = detection.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for sev, count in severity_counts.items():
            print(f"   {sev.capitalize()}: {count}")


async def example_supply_chain():
    """Example: Supply chain attack simulation"""
    print("\n" + "="*80)
    print("EXAMPLE 6: Supply Chain Attack Simulation")
    print("="*80)
    
    simulator = ContinuousAdversarySimulator()
    
    # Create supply chain attack
    print("\n🔗 Creating Supply Chain Attack Scenario...")
    campaign = simulator.create_supply_chain_attack_scenario(
        name="Trojanized Software Update - Monitoring Agent",
        compromised_component="Third-party monitoring agent",
        target_organizations=[
            "Financial Services Inc.",
            "Healthcare Corp",
            "Manufacturing Ltd.",
            "Retail Chain Co."
        ],
        duration=timedelta(hours=8)
    )
    
    details = campaign.results['supply_chain_details']
    print(f"   ✓ Scenario: {campaign.name}")
    print(f"   Compromised: {details['compromised_component']}")
    print(f"   Distribution: {details['distribution_method']}")
    print(f"   Target Organizations: {len(details['target_organizations'])}")
    
    # Run campaign
    print("\n🎪 Executing Supply Chain Attack...")
    result = await simulator.run_campaign(campaign)
    
    print(f"\n✅ Attack Results:")
    print(f"   Status: {result['status']}")
    print(f"   Duration: {result.get('duration_minutes', 0):.1f} minutes")
    print(f"   Attack Phases: {len(result['phases'])}")
    
    print(f"\n🎯 Supply Chain Impact:")
    print(f"   Initial Compromise: Successful")
    print(f"   Lateral Spread: Simulated across {len(details['target_organizations'])} orgs")
    print(f"   Techniques Used: {len(result['techniques_executed'])}")


async def example_full_assessment():
    """Example: Complete Phase 9 assessment"""
    print("\n" + "="*80)
    print("EXAMPLE 7: Complete Phase 9 Assessment")
    print("="*80)
    
    # Initialize engine
    engine = Phase9Engine({
        "output_dir": "examples/reports/phase9"
    })
    
    # Define target environment
    target_env = {
        "domain": "example.corp",
        "critical_assets": [
            "DC01.example.corp",
            "FS01.example.corp",
            "DB01.example.corp",
            "WEB01.example.corp",
            "MAIL01.example.corp"
        ],
        "user_count": 500,
        "admin_count": 10,
        "security_controls": {
            "edr": True,
            "firewall": True,
            "ids_ips": True,
            "siem": True,
            "dlp": True
        }
    }
    
    print("\n🚀 Starting Comprehensive Phase 9 Assessment...")
    print(f"   Target: {target_env['domain']}")
    print(f"   Assets: {len(target_env['critical_assets'])}")
    print(f"   Security Controls: {len([k for k, v in target_env['security_controls'].items() if v])}")
    
    # Run assessment
    results = await engine.run_full_assessment(target_env)
    
    # Display summary
    summary = results['summary']
    print(f"\n📊 Assessment Summary:")
    print(f"   ATT&CK Coverage: {summary['attack_coverage']:.1f}%")
    print(f"   APT Emulations: {summary['total_apt_emulations']}")
    print(f"   Techniques Tested: {summary['total_techniques_tested']}")
    print(f"   Detection Score: {summary['detection_effectiveness']:.1f}/100")
    
    print(f"\n💡 Top Recommendations:")
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f"   {i}. {rec}")
    
    print(f"\n✅ Full report saved to: {engine.output_dir}")


async def main():
    """Run all Phase 9 examples"""
    print("\n" + "="*80)
    print("PHASE 9 EXAMPLES: Adversary Simulation & Red Team Automation")
    print("="*80)
    
    # Example 1: MITRE ATT&CK Coverage
    await example_mitre_attack_coverage()
    
    # Example 2: APT Emulation
    await example_apt_emulation()
    
    # Example 3: Purple Team
    await example_purple_team()
    
    # Example 4: Assume Breach
    await example_assume_breach()
    
    # Example 5: Insider Threat
    await example_insider_threat()
    
    # Example 6: Supply Chain
    await example_supply_chain()
    
    # Example 7: Full Assessment
    # Uncomment to run full assessment (takes longer)
    # await example_full_assessment()
    
    print("\n" + "="*80)
    print("ALL EXAMPLES COMPLETE!")
    print("="*80)
    print("\n📚 For more information:")
    print("   • Full Guide: PHASE9-GUIDE.md")
    print("   • Quick Reference: PHASE9-QUICKREF.md")
    print("   • Summary: PHASE9-SUMMARY.md")
    print("\n🧪 Run tests: python test_phase9.py")


if __name__ == "__main__":
    asyncio.run(main())
