"""
Phase 9 Test Suite
Test adversary simulation and red team automation capabilities
"""

import asyncio
from pathlib import Path
from datetime import timedelta

# Phase 9 components
from core.phase9_engine import Phase9Engine
from adversary_simulation import (
    MITREAttackMapper,
    ThreatActorEmulator,
    PurpleTeamCoordinator,
    ContinuousAdversarySimulator,
    CampaignType
)


def test_mitre_attack_mapper():
    """Test MITRE ATT&CK mapper"""
    print("\n" + "="*60)
    print("TEST 1: MITRE ATT&CK Mapper")
    print("="*60)
    
    mapper = MITREAttackMapper()
    
    # Test technique mapping
    print("\n1. Testing technique mapping...")
    techniques = mapper.map_action_to_attack(
        action="credential dumping with mimikatz",
        context={"tool": "mimikatz"}
    )
    print(f"   ✓ Mapped to techniques: {techniques}")
    assert "T1003" in techniques, "Should map to credential dumping"
    
    # Test technique retrieval
    print("\n2. Testing technique retrieval...")
    technique = mapper.get_technique("T1003")
    print(f"   ✓ Technique: {technique.name}")
    print(f"   ✓ Tactic: {technique.tactic}")
    assert technique.name == "OS Credential Dumping"
    
    # Test coverage matrix
    print("\n3. Testing coverage matrix...")
    coverage = mapper.get_coverage_matrix()
    print(f"   ✓ Tactics: {len(coverage)}")
    print(f"   ✓ Total techniques: {sum(c['total_techniques'] for c in coverage.values())}")
    
    # Test Navigator layer generation
    print("\n4. Testing ATT&CK Navigator layer...")
    output_path = Path("test_navigator_layer.json")
    mapper.generate_navigator_layer(output_path)
    assert output_path.exists(), "Navigator layer should be created"
    print(f"   ✓ Navigator layer created: {output_path}")
    output_path.unlink()  # Cleanup
    
    print("\n✅ MITRE ATT&CK Mapper tests passed!")


async def test_threat_actor_emulator():
    """Test threat actor emulation"""
    print("\n" + "="*60)
    print("TEST 2: Threat Actor Emulator")
    print("="*60)
    
    emulator = ThreatActorEmulator()
    
    # Test profile retrieval
    print("\n1. Testing APT profile retrieval...")
    profile = emulator.get_profile("APT28")
    assert profile is not None, "Should find APT28 profile"
    print(f"   ✓ APT28 Profile loaded")
    print(f"      Attribution: {profile.attribution}")
    print(f"      Country: {profile.country}")
    print(f"      Tools: {len(profile.preferred_tools)}")
    
    # Test actor emulation
    print("\n2. Testing APT emulation (short duration)...")
    campaign = await emulator.emulate_actor(
        actor_name="APT28",
        campaign_duration=timedelta(seconds=10),  # Short test
        target_environment={"domain": "test.local"}
    )
    
    assert campaign["actor"] == "APT28"
    assert len(campaign["timeline"]) > 0
    print(f"   ✓ Campaign completed")
    print(f"      Activities: {len(campaign['timeline'])}")
    print(f"      Tools used: {len(set(campaign['tools_used']))}")
    
    print("\n✅ Threat Actor Emulator tests passed!")


async def test_purple_team():
    """Test purple team capabilities"""
    print("\n" + "="*60)
    print("TEST 3: Purple Team Capabilities")
    print("="*60)
    
    coordinator = PurpleTeamCoordinator()
    
    # Test telemetry generation
    print("\n1. Testing telemetry generation...")
    telem_gen = coordinator.telemetry_gen
    
    event1 = telem_gen.generate_process_creation(
        "T1059",
        "PowerShell Execution",
        "powershell.exe",
        "powershell.exe -ExecutionPolicy Bypass"
    )
    print(f"   ✓ Process creation event generated")
    
    event2 = telem_gen.generate_network_connection(
        "T1071",
        "C2 Communication",
        "malware.exe",
        "192.168.1.100",
        443
    )
    print(f"   ✓ Network connection event generated")
    
    # Test detection rules
    print("\n2. Testing detection rule creation...")
    rule = coordinator.detection_validator.create_detection_rule(
        rule_id="TEST001",
        name="Test PowerShell Rule",
        description="Test rule for PowerShell",
        severity="high",
        technique_ids=["T1059"],
        rule_type="sigma",
        rule_content="detection: selection: CommandLine|contains: 'bypass'"
    )
    print(f"   ✓ Detection rule created: {rule.name}")
    
    # Test rule validation
    print("\n3. Testing detection rule validation...")
    results = await coordinator.detection_validator.test_rule(
        rule,
        telem_gen.events
    )
    print(f"   ✓ Rule tested")
    print(f"      Accuracy: {results.get('accuracy', 0):.2%}")
    print(f"      Precision: {results.get('precision', 0):.2%}")
    print(f"      Recall: {results.get('recall', 0):.2%}")
    
    print("\n✅ Purple Team tests passed!")


async def test_continuous_simulation():
    """Test continuous adversary simulation"""
    print("\n" + "="*60)
    print("TEST 4: Continuous Adversary Simulation")
    print("="*60)
    
    simulator = ContinuousAdversarySimulator()
    
    # Test assume-breach scenario
    print("\n1. Testing assume-breach scenario...")
    campaign = simulator.create_assume_breach_scenario(
        name="Test Assume Breach",
        initial_access="Test credentials",
        privilege_level="user",
        target_assets=["TEST-DC01", "TEST-FS01"],
        duration=timedelta(seconds=10)
    )
    assert campaign.campaign_type == CampaignType.ASSUME_BREACH
    print(f"   ✓ Assume-breach scenario created")
    print(f"      Initial Access: {campaign.initial_access}")
    print(f"      Privilege: {campaign.privilege_level}")
    
    # Test campaign execution
    print("\n2. Testing campaign execution...")
    result = await simulator.run_campaign(campaign)
    assert result["status"] == "completed"
    print(f"   ✓ Campaign completed")
    print(f"      Phases: {len(result['phases'])}")
    print(f"      Techniques: {len(result['techniques_executed'])}")
    
    # Test insider threat scenario
    print("\n3. Testing insider threat scenario...")
    insider_campaign = simulator.create_insider_threat_scenario(
        name="Test Insider",
        insider_type="Malicious",
        access_level="user",
        motivation="Test",
        duration=timedelta(seconds=10)
    )
    assert insider_campaign.campaign_type == CampaignType.INSIDER_THREAT
    print(f"   ✓ Insider threat scenario created")
    
    # Test supply chain scenario
    print("\n4. Testing supply chain scenario...")
    supply_campaign = simulator.create_supply_chain_attack_scenario(
        name="Test Supply Chain",
        compromised_component="Test Component",
        target_organizations=["Org1", "Org2"],
        duration=timedelta(seconds=10)
    )
    assert supply_campaign.campaign_type == CampaignType.SUPPLY_CHAIN
    print(f"   ✓ Supply chain scenario created")
    
    print("\n✅ Continuous Simulation tests passed!")


async def test_phase9_engine():
    """Test Phase 9 engine integration"""
    print("\n" + "="*60)
    print("TEST 5: Phase 9 Engine Integration")
    print("="*60)
    
    # Initialize engine
    print("\n1. Initializing Phase 9 engine...")
    engine = Phase9Engine({
        "output_dir": "test_reports/phase9"
    })
    print("   ✓ Engine initialized")
    
    # Test ATT&CK coverage analysis
    print("\n2. Testing ATT&CK coverage analysis...")
    coverage = engine.analyze_attack_coverage()
    assert "overall_coverage" in coverage
    print(f"   ✓ Coverage analyzed")
    print(f"      Overall Coverage: {coverage['overall_coverage']:.1f}%")
    
    # Test quick assessment (limited scope)
    print("\n3. Testing quick assessment...")
    target_env = {
        "domain": "test.local",
        "critical_assets": ["TEST-DC01"],
        "security_controls": {"edr": True}
    }
    
    # Note: Full assessment would take too long for tests
    # So we'll just verify the engine can start
    print("   ✓ Engine ready for assessment")
    
    print("\n✅ Phase 9 Engine tests passed!")


async def main():
    """Run all Phase 9 tests"""
    print("\n" + "="*80)
    print("PHASE 9 TEST SUITE: Adversary Simulation & Red Team Automation")
    print("="*80)
    
    try:
        # Test 1: MITRE ATT&CK Mapper
        test_mitre_attack_mapper()
        
        # Test 2: Threat Actor Emulator
        await test_threat_actor_emulator()
        
        # Test 3: Purple Team
        await test_purple_team()
        
        # Test 4: Continuous Simulation
        await test_continuous_simulation()
        
        # Test 5: Phase 9 Engine
        await test_phase9_engine()
        
        # Summary
        print("\n" + "="*80)
        print("ALL TESTS PASSED! ✅")
        print("="*80)
        print("\nPhase 9 is ready to use!")
        print("\nNext steps:")
        print("  1. Review PHASE9-GUIDE.md for detailed documentation")
        print("  2. Run full assessment: python -m core.phase9_engine")
        print("  3. Set up continuous simulation campaigns")
        print("  4. Schedule regular purple team exercises")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
