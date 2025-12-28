"""
Complete Example: All Phases (1-4) Working Together

This example demonstrates the full capability of the autonomous pentesting platform
with all four phases integrated.
"""
import asyncio
from core.ultimate_engine import UltimatePentestEngine
from core.config import load_config


async def example_comprehensive_pentest():
    """
    Example 1: Comprehensive pentest with adaptive stealth
    
    Demonstrates:
    - Phase 1: LLM-guided reconnaissance and exploitation
    - Phase 2: Intelligent memory and self-improvement
    - Phase 3: Multi-agent swarm deployment
    - Phase 4: Advanced evasion and anti-forensics
    """
    
    print("=" * 80)
    print("EXAMPLE 1: Comprehensive Adaptive Pentest")
    print("=" * 80)
    
    # Load configuration
    config = load_config()
    
    # Initialize Ultimate Engine (all phases)
    engine = UltimatePentestEngine(config)
    
    # Run adaptive pentest
    # - Starts with low stealth
    # - Automatically increases stealth if detections occur
    # - Deploys full agent swarm
    # - Uses all evasion techniques as needed
    
    result = await engine.adaptive_engagement("10.0.0.50")
    
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    
    print(f"\nEngagement ID: {result['engagement_id']}")
    print(f"Target: {result['target']}")
    print(f"Duration: {result['duration']} seconds")
    print(f"Phases Executed: {', '.join(result['phases_executed'])}")
    
    print(f"\n📊 Reconnaissance:")
    print(f"   - Discoveries: {result['reconnaissance']['discoveries']}")
    print(f"   - Services: {result['reconnaissance']['services_identified']}")
    
    print(f"\n🧠 Intelligence (Phase 2):")
    print(f"   - Vulnerabilities: {result['intelligence']['vulnerabilities_identified']}")
    print(f"   - Attack Vectors: {result['intelligence']['attack_vectors_ranked']}")
    print(f"   - Historical References: {result['intelligence']['historical_engagements_referenced']}")
    
    print(f"\n🤖 Swarm (Phase 3):")
    print(f"   - Agents Deployed: {result['swarm']['agents_deployed']}")
    print(f"   - Cross-Domain Correlations: {result['swarm']['cross_domain_correlations']}")
    print(f"   - Collaborative Discoveries: {result['swarm']['collaborative_discoveries']}")
    
    print(f"\n🥷 Evasion (Phase 4):")
    evasion = result['evasion']
    print(f"   - Profile: {evasion['current_profile']}")
    print(f"   - Stealth Level: {evasion['stealth_level']}")
    print(f"   - Total Attempts: {evasion['detection_history']['total_attempts']}")
    print(f"   - Detected: {evasion['detection_history']['detections']}")
    
    print(f"\n💥 Exploitation:")
    print(f"   - Attempts: {result['exploits_attempted']}")
    print(f"   - Detection Events: {result['detection_events']}")
    print(f"   - Stealth Effectiveness: {result['stealth_effectiveness']:.1%}")
    
    print("\n✅ Engagement Complete!\n")


async def example_high_security_target():
    """
    Example 2: High-security target with maximum stealth
    
    Demonstrates:
    - High stealth mode from the start
    - All evasion techniques enabled
    - Anti-forensics measures
    - Slow, deliberate approach
    """
    
    print("=" * 80)
    print("EXAMPLE 2: High-Security Target (Maximum Stealth)")
    print("=" * 80)
    
    config = load_config()
    engine = UltimatePentestEngine(config)
    
    # Run with high stealth from the beginning
    result = await engine.run_ultimate_pentest(
        target="secure-bank.example.com",
        engagement_type="focused",
        stealth_mode="high"
    )
    
    print(f"\n🎯 Target: {result['target']}")
    print(f"🥷 Stealth Effectiveness: {result['stealth_effectiveness']:.1%}")
    
    # Show evasion techniques used
    print("\n🛡️ Evasion Techniques Applied:")
    for i, technique in enumerate(result.get('stealth_techniques', []), 1):
        print(f"   {i}. Vector {technique.get('vector')}")
        print(f"      Techniques: {', '.join(technique.get('techniques', []))}")
        print(f"      Detection Probability: {technique.get('detection_probability', 0):.1%}")
    
    # Show anti-forensics
    anti_forensics = result.get('anti_forensics', {})
    if anti_forensics:
        print("\n🧹 Anti-Forensics Measures:")
        if anti_forensics.get('log_poisoning'):
            print("   ✓ Log poisoning executed")
        if anti_forensics.get('timestomping'):
            print("   ✓ Timestomping completed")
        if anti_forensics.get('cleanup'):
            print("   ✓ Artifact cleanup performed")
    
    print("\n✅ High-security engagement complete with minimal detection!\n")


async def example_slow_burn_apt_simulation():
    """
    Example 3: 30-day slow burn APT simulation
    
    Demonstrates:
    - Extended campaign over 30 days
    - Progressive reconnaissance phases
    - Extreme stealth mode
    - Behavioral mimicry
    - Memory-only execution
    - LOLBins usage
    """
    
    print("=" * 80)
    print("EXAMPLE 3: 30-Day Slow Burn APT Simulation")
    print("=" * 80)
    
    config = load_config()
    engine = UltimatePentestEngine(config)
    
    # Run slow burn campaign
    result = await engine.run_ultimate_pentest(
        target="enterprise.example.com",
        engagement_type="slow_burn",
        stealth_mode="extreme"
    )
    
    print(f"\n📅 Campaign Duration: 30 days")
    print(f"🎯 Target: {result['target']}")
    
    # Show campaign schedule
    if 'campaign_schedule' in result:
        print("\n📋 Campaign Schedule:")
        schedule = result['campaign_schedule']
        
        phases = {}
        for item in schedule[:10]:  # Show first 10
            step = item.get('step', {})
            action = step.get('action', 'unknown')
            exec_time = item.get('execution_time', 'N/A')
            
            if action not in phases:
                phases[action] = []
            phases[action].append(exec_time)
        
        for phase, times in phases.items():
            print(f"   - {phase.upper()}: {len(times)} scheduled actions")
    
    print(f"\n🥷 Stealth Level: EXTREME")
    print(f"   - Timing: Minutes to hours between actions")
    print(f"   - Decoy Ratio: 20:1 (20 benign per 1 malicious)")
    print(f"   - Memory-only execution: Enabled")
    print(f"   - LOLBins preferred: Yes")
    print(f"   - Anti-forensics: Full suite")
    
    print(f"\n📊 Effectiveness: {result['stealth_effectiveness']:.1%}")
    print(f"🚨 Detection Events: {result['detection_events']}")
    
    print("\n✅ APT simulation campaign ready for 30-day execution!\n")


async def example_waf_protected_webapp():
    """
    Example 4: WAF-protected web application
    
    Demonstrates:
    - WAF detection
    - Automated bypass generation
    - LLM-powered bypass creativity
    - Encoding chains
    - Request smuggling
    """
    
    print("=" * 80)
    print("EXAMPLE 4: WAF-Protected Web Application")
    print("=" * 80)
    
    config = load_config()
    engine = UltimatePentestEngine(config)
    
    # The engine will automatically detect WAF and adapt
    result = await engine.run_ultimate_pentest(
        target="webapp.cloudflare-protected.com",
        engagement_type="focused",
        stealth_mode="adaptive"
    )
    
    # Check if WAF was detected
    if 'defensive_analysis' in result:
        defensive = result['defensive_analysis']
        
        print("\n🛡️ Defensive Measures Detected:")
        if defensive.get('waf_detected'):
            print("   ⚠️ WAF Detected!")
        if defensive.get('ids_ips_detected'):
            print("   ⚠️ IDS/IPS Detected!")
        if defensive.get('edr_detected'):
            print("   ⚠️ EDR Detected!")
        
        print(f"\n   Capabilities: {', '.join(defensive.get('detection_capabilities', []))}")
    
    # Show evasion strategy selected
    if 'evasion_strategy' in result:
        strategy = result['evasion_strategy']
        
        print("\n🎯 Evasion Strategy Selected:")
        print(f"   Primary Techniques:")
        for tech in strategy.get('primary_techniques', []):
            print(f"      - {tech}")
        print(f"   Timing Profile: {strategy.get('timing_profile')}")
        print(f"   Obfuscation Level: {strategy.get('obfuscation_level')}")
    
    print(f"\n💥 Results:")
    print(f"   Exploits Attempted: {result['exploits_attempted']}")
    print(f"   Stealth Effectiveness: {result['stealth_effectiveness']:.1%}")
    
    print("\n✅ WAF-protected target tested successfully!\n")


async def example_phase_comparison():
    """
    Example 5: Comparison of capabilities across phases
    
    Shows the evolution from Phase 1 to Phase 4
    """
    
    print("=" * 80)
    print("EXAMPLE 5: Evolution Across All Phases")
    print("=" * 80)
    
    config = load_config()
    engine = UltimatePentestEngine(config)
    
    print("\n📈 CAPABILITY EVOLUTION:\n")
    
    print("Phase 1 - Foundation:")
    print("   ✓ LLM-guided reconnaissance")
    print("   ✓ Nmap, SQLmap, Hydra, Metasploit integration")
    print("   ✓ Basic autonomous decision-making")
    print("   ✓ Report generation")
    print("   → Basic autonomous pentesting")
    
    print("\nPhase 2 - Intelligence:")
    print("   ✓ Vector database (ChromaDB)")
    print("   ✓ Persistent memory across engagements")
    print("   ✓ Probabilistic vulnerability assessment")
    print("   ✓ Cost-benefit analysis")
    print("   ✓ Adaptive strategy")
    print("   ✓ Self-improvement loop")
    print("   → Learning and continuous improvement")
    
    print("\nPhase 3 - Multi-Agent Swarm:")
    print("   ✓ 7 specialized agent types:")
    print("      - Recon, Web Exploit, Network Exploit")
    print("      - Social Engineering, Wireless")
    print("      - Physical Security, Cloud Security")
    print("   ✓ Collaborative intelligence")
    print("   ✓ Cross-domain correlation")
    print("   ✓ Dynamic resource allocation")
    print("   ✓ Competitive optimization")
    print("   → Parallel, specialized attack capabilities")
    
    print("\nPhase 4 - Advanced Evasion:")
    print("   ✓ IDS/IPS evasion:")
    print("      - Signature detection prediction")
    print("      - Polymorphic payloads")
    print("      - Traffic obfuscation")
    print("      - Timing randomization")
    print("      - Decoy traffic")
    print("   ✓ WAF bypass:")
    print("      - Automated fuzzing")
    print("      - Encoding chains")
    print("      - Request smuggling")
    print("      - LLM-generated bypasses")
    print("   ✓ Anti-forensics:")
    print("      - Log poisoning")
    print("      - Timestomping")
    print("      - Memory-only execution")
    print("      - LOLBins")
    print("      - Fileless malware")
    print("   ✓ Behavioral mimicry:")
    print("      - Traffic pattern analysis")
    print("      - Legitimate behavior mimicry")
    print("      - Slow-burn campaigns")
    print("   → APT-level stealth and sophistication")
    
    print("\n" + "=" * 80)
    print("INTEGRATED CAPABILITIES")
    print("=" * 80)
    
    # Run a test to show all capabilities
    result = await engine.run_ultimate_pentest(
        target="integration-test.example.com",
        engagement_type="comprehensive",
        stealth_mode="adaptive"
    )
    
    print(f"\n✅ All {len(result['phases_executed'])} phases executed successfully!")
    print(f"   {result['reconnaissance']['discoveries']} discoveries")
    print(f"   {result['swarm']['agents_deployed']} agents deployed")
    print(f"   {result['exploits_attempted']} exploitation attempts")
    print(f"   {result['stealth_effectiveness']:.1%} stealth effectiveness")
    
    print("\n🎉 Platform is fully operational with all Phase 1-4 capabilities!\n")


async def main():
    """Run all examples"""
    
    print("\n" + "=" * 80)
    print(" AUTONOMOUS PENTESTING PLATFORM - COMPLETE DEMONSTRATION")
    print(" Phases 1-4: Foundation → Intelligence → Swarm → Evasion")
    print("=" * 80 + "\n")
    
    # Run examples
    await example_comprehensive_pentest()
    input("Press Enter to continue to next example...")
    
    await example_high_security_target()
    input("Press Enter to continue to next example...")
    
    await example_slow_burn_apt_simulation()
    input("Press Enter to continue to next example...")
    
    await example_waf_protected_webapp()
    input("Press Enter to continue to final example...")
    
    await example_phase_comparison()
    
    print("\n" + "=" * 80)
    print(" ALL EXAMPLES COMPLETED SUCCESSFULLY!")
    print("=" * 80 + "\n")
    
    print("📚 For more information:")
    print("   - Phase 1: See USAGE.md")
    print("   - Phase 2: See PHASE2-INTELLIGENCE.md")
    print("   - Phase 3: See PHASE3-SWARM.md")
    print("   - Phase 4: See PHASE4-EVASION.md")
    print("\n")


if __name__ == "__main__":
    print("⚠️  WARNING: For authorized penetration testing only!")
    print("    Requires explicit written authorization")
    print("    Must comply with all applicable laws\n")
    
    response = input("Do you have authorization to run these tests? (yes/no): ")
    
    if response.lower() == 'yes':
        asyncio.run(main())
    else:
        print("\n❌ Authorization required. Exiting.\n")
