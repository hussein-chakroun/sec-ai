"""
Phase 10 Examples: Physical & Social Engineering Integration
Demonstration of OSINT weaponization, phishing, physical security, and deepfakes
"""

import asyncio
from pathlib import Path

from core.phase10_engine import Phase10Engine
from physical_social_engineering.osint_weaponization import (
    OSINTWeaponizer,
    LinkedInScraper
)
from physical_social_engineering.phishing_automation import (
    PhishingCampaignManager,
    PhishingType,
    PretextType
)
from physical_social_engineering.physical_security import (
    PhysicalSecurityAnalyzer,
    PhysicalLocation,
    BadgeSystem,
    SecurityCamera,
    LockSystem,
    SecurityLevel,
    AccessControlType
)
from physical_social_engineering.deepfake_integration import DeepfakeEngine


# Example 1: Basic OSINT Weaponization
async def example_1_osint_weaponization():
    """Example: Weaponize organization intelligence"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 1: OSINT WEAPONIZATION")
    print("=" * 80)
    
    osint = OSINTWeaponizer()
    
    # Weaponize target organization
    org_profile = await osint.weaponize_organization(
        company_name="Acme Corporation",
        domain="acme.com",
        max_profiles=25
    )
    
    # Display results
    print(f"\n📊 Intelligence gathered:")
    print(f"   Employees identified: {len(org_profile.employees)}")
    print(f"   Email patterns: {osint.email_identifier.discovered_patterns}")
    
    # Show org chart
    print(f"\n📈 Organizational structure:")
    for level, people in org_profile.org_chart.items():
        if level != "relationships" and isinstance(people, list):
            print(f"   {level}: {len(people)} employees")
    
    # Identify high-value targets
    scraper = LinkedInScraper()
    high_value = scraper.identify_high_value_targets(org_profile.employees, top_n=5)
    
    print(f"\n🎯 High-value targets:")
    for i, target in enumerate(high_value, 1):
        print(f"   {i}. {target.name} - {target.job_title}")
        print(f"      Email: {target.email}")
        print(f"      Vulnerability: {target.vulnerability_score:.1f}/100")


# Example 2: Automated Phishing Campaign
async def example_2_phishing_campaign():
    """Example: Create automated phishing campaign"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 2: AUTOMATED PHISHING CAMPAIGN")
    print("=" * 80)
    
    phishing = PhishingCampaignManager()
    
    # Define targets
    targets = [
        {"name": "John Doe", "email": "john.doe@acme.com", "title": "CFO", "company": "Acme Corp"},
        {"name": "Jane Smith", "email": "jane.smith@acme.com", "title": "IT Manager", "company": "Acme Corp"},
        {"name": "Bob Johnson", "email": "bob.johnson@acme.com", "title": "HR Director", "company": "Acme Corp"}
    ]
    
    # Create spear-phishing campaign
    campaign = await phishing.create_campaign(
        campaign_name="Executive_Credential_Harvest",
        targets=targets,
        campaign_type=PhishingType.SPEAR_PHISHING,
        pretext_type=PretextType.SECURITY_ALERT,
        duration_days=5
    )
    
    print(f"\n✅ Campaign created: {campaign.name}")
    print(f"   Type: {campaign.campaign_type.value}")
    print(f"   Pretext: {campaign.pretext_type.value}")
    print(f"   Targets: {len(targets)}")
    
    # Generate sample email
    from physical_social_engineering.phishing_automation import SpearPhishingGenerator
    generator = SpearPhishingGenerator()
    
    sample_email = generator.generate_email(
        target_name="John Doe",
        target_email="john.doe@acme.com",
        target_title="CFO",
        target_company="Acme Corp",
        pretext_type=PretextType.SECURITY_ALERT,
        urgency="critical"
    )
    
    print(f"\n📧 Sample phishing email:")
    print(f"   From: {sample_email.from_name} <{sample_email.from_address}>")
    print(f"   To: {sample_email.target_email}")
    print(f"   Subject: {sample_email.subject}")
    print(f"\n   Body preview:")
    print("   " + "\n   ".join(sample_email.body.split("\n")[:5]))


# Example 3: Physical Security Assessment
async def example_3_physical_security():
    """Example: Assess physical security controls"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 3: PHYSICAL SECURITY ASSESSMENT")
    print("=" * 80)
    
    analyzer = PhysicalSecurityAnalyzer()
    
    # Define facility
    location = PhysicalLocation(
        name="Acme Corporation Headquarters",
        address="123 Business Plaza, Tech City, CA 94000",
        facility_type="office",
        security_level=SecurityLevel.MEDIUM,
        access_controls=[
            AccessControlType.BADGE,
            AccessControlType.PIN,
            AccessControlType.GUARD
        ],
        operating_hours={},
        employee_count=250,
        security_guards=2,
        cameras=12,
        entry_points=3
    )
    
    # Define badge system
    badge_system = BadgeSystem(
        technology="RFID",
        frequency="125kHz",
        encryption=False,
        clone_difficulty="easy",
        vendor="HID ProxCard II"
    )
    
    # Define cameras
    cameras = [
        SecurityCamera(
            location="Main entrance",
            camera_type="fixed",
            resolution="1080p",
            field_of_view=90,
            night_vision=True,
            motion_detection=True,
            recording=True
        ),
        SecurityCamera(
            location="Parking lot",
            camera_type="PTZ",
            resolution="720p",
            field_of_view=360,
            night_vision=False,
            motion_detection=True,
            recording=True
        ),
        SecurityCamera(
            location="Back entrance",
            camera_type="fixed",
            resolution="720p",
            field_of_view=60,
            night_vision=False,
            motion_detection=False,
            recording=True
        )
    ]
    
    # Define locks
    locks = [
        LockSystem(lock_type="pin_pad", security_rating=4),
        LockSystem(lock_type="deadbolt", security_rating=6),
        LockSystem(lock_type="electronic", security_rating=5)
    ]
    
    # Run assessment
    assessment = await analyzer.analyze_facility(
        location=location,
        badge_system=badge_system,
        cameras=cameras,
        locks=locks
    )
    
    # Display results
    print(f"\n🏢 Facility: {location.name}")
    print(f"   Security level: {location.security_level.value}")
    
    print(f"\n🎫 Badge System Analysis:")
    badge_analysis = assessment.get("access_control_analysis", {})
    print(f"   Vulnerability rating: {badge_analysis.get('vulnerability_rating', 0)}/10")
    print(f"   Clone success probability: {badge_analysis.get('success_probability', 0):.0%}")
    
    print(f"\n🚪 Tailgating Opportunities:")
    for opp in assessment.get("tailgating_analysis", [])[:2]:
        print(f"   • {opp['entry_point']}: {opp['tailgating_difficulty']}")
        print(f"     Success rate: {opp['success_probability']:.0%}")
    
    print(f"\n📹 Camera Coverage:")
    camera_analysis = assessment.get("camera_analysis", {})
    blind_spots = camera_analysis.get("blind_spots", [])
    print(f"   Total cameras: {len(cameras)}")
    print(f"   Blind spots identified: {len(blind_spots)}")
    if blind_spots:
        for spot in blind_spots[:3]:
            print(f"      • {spot['location']}")
    
    print(f"\n⚠️  Total vulnerabilities: {len(assessment.get('overall_vulnerabilities', []))}")


# Example 4: Deepfake CEO Fraud Attack
async def example_4_deepfake_ceo_fraud():
    """Example: Plan CEO fraud attack using deepfakes"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 4: DEEPFAKE CEO FRAUD ATTACK")
    print("=" * 80)
    
    deepfake = DeepfakeEngine()
    
    # Plan comprehensive CEO fraud attack
    attack = await deepfake.create_comprehensive_attack(
        target_organization="Acme Corporation",
        executive_name="Sarah Williams",
        executive_title="Chief Executive Officer",
        victim_name="Robert Chen",
        victim_title="Chief Financial Officer",
        attack_goal="wire_transfer"
    )
    
    # Display attack plan
    print(f"\n🎭 CEO Fraud Attack Plan")
    print(f"   Impersonating: {attack['ceo_fraud_plan']['impersonated_executive']['name']}")
    print(f"   Target: {attack['ceo_fraud_plan']['target']['name']}")
    print(f"   Goal: {attack['attack_type']}")
    
    print(f"\n📊 Voice Quality:")
    voice_quality = attack['ceo_fraud_plan']['impersonated_executive']['voice_quality']
    print(f"   Quality level: {voice_quality}")
    
    print(f"\n📋 Attack Phases:")
    for phase in attack['ceo_fraud_plan']['attack_phases']:
        print(f"\n   Phase {phase['phase']}: {phase['name']}")
        print(f"   Method: {phase['method']}")
        print(f"   Timing: {phase['timing']}")
        print(f"   Objective: {phase['objective']}")
    
    print(f"\n🎯 Success Probability: {attack['overall_success_probability']:.0%}")
    print(f"   Timeline: {attack['timeline']}")
    print(f"   Detection risk: {attack.get('detection_risk', 'Unknown')}")


# Example 5: OSINT to Phishing Pipeline
async def example_5_osint_to_phishing():
    """Example: Use OSINT intelligence to create targeted phishing"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 5: OSINT → PHISHING PIPELINE")
    print("=" * 80)
    
    # Step 1: Gather OSINT
    print("\n📊 Step 1: Gathering OSINT...")
    osint = OSINTWeaponizer()
    org = await osint.weaponize_organization(
        company_name="TechStart Inc",
        domain="techstart.com",
        max_profiles=15
    )
    
    print(f"   ✓ Collected {len(org.employees)} employee profiles")
    
    # Step 2: Identify high-value targets
    print("\n🎯 Step 2: Identifying high-value targets...")
    scraper = LinkedInScraper()
    targets = scraper.identify_high_value_targets(org.employees, top_n=3)
    
    print(f"   ✓ Identified {len(targets)} high-value targets:")
    for target in targets:
        print(f"      • {target.name} - {target.job_title} (Score: {target.vulnerability_score:.1f})")
    
    # Step 3: Create personalized phishing campaign
    print("\n📧 Step 3: Creating personalized phishing campaign...")
    phishing = PhishingCampaignManager()
    
    campaign_targets = [
        {
            "name": t.name,
            "email": t.email,
            "title": t.job_title,
            "company": org.name
        }
        for t in targets
    ]
    
    campaign = await phishing.create_campaign(
        campaign_name="OSINT_Targeted_Phishing",
        targets=campaign_targets,
        campaign_type=PhishingType.SPEAR_PHISHING,
        pretext_type=PretextType.EXECUTIVE_REQUEST,
        duration_days=7
    )
    
    print(f"   ✓ Campaign created: {campaign.name}")
    print(f"   ✓ Highly personalized emails for {len(campaign_targets)} targets")


# Example 6: Physical Access + USB Drop
async def example_6_physical_usb_attack():
    """Example: Physical access with USB drop campaign"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 6: PHYSICAL ACCESS + USB DROP")
    print("=" * 80)
    
    analyzer = PhysicalSecurityAnalyzer()
    
    # Define location
    location = PhysicalLocation(
        name="Target Office",
        address="456 Corp Ave",
        facility_type="office",
        security_level=SecurityLevel.LOW,
        access_controls=[AccessControlType.BADGE],
        operating_hours={},
        employee_count=75,
        security_guards=1,
        cameras=4,
        entry_points=2
    )
    
    # Analyze tailgating opportunities
    print("\n🚪 Analyzing entry points...")
    tailgating_opps = analyzer.tailgating.analyze_entry_points(location)
    
    best_entry = max(tailgating_opps, key=lambda x: x["success_probability"])
    print(f"\n   Best entry point: {best_entry['entry_point']}")
    print(f"   Success probability: {best_entry['success_probability']:.0%}")
    print(f"   Recommended timing: {best_entry['recommended_time']}")
    
    # Plan USB drop campaign
    print("\n💾 Planning USB drop campaign...")
    usb_campaign = analyzer.usb_campaign.plan_campaign(
        target_location=location,
        usb_count=10,
        payload_type="credential_harvester"
    )
    
    print(f"   ✓ USB devices: {usb_campaign['usb_count']}")
    print(f"   ✓ Payload: {usb_campaign['payload_type']}")
    print(f"\n   Strategic drop locations:")
    for loc in usb_campaign['drop_locations'][:3]:
        print(f"      • {loc['location']}")
        print(f"        Pickup probability: {loc['pickup_probability']:.0%}")


# Example 7: Full Phase 10 Assessment
async def example_7_full_assessment():
    """Example: Complete Phase 10 assessment"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 7: FULL PHASE 10 ASSESSMENT")
    print("=" * 80)
    
    engine = Phase10Engine()
    
    # Run comprehensive assessment
    results = await engine.run_full_assessment(
        target_organization="GlobalTech Industries",
        target_domain="globaltech.com",
        target_address="789 Innovation Drive, Silicon Valley, CA",
        scope=['osint', 'phishing', 'physical', 'deepfake']
    )
    
    # Results are automatically printed by engine
    # Access specific results
    print("\n" + "=" * 80)
    print("KEY FINDINGS SUMMARY")
    print("=" * 80)
    
    # OSINT findings
    if "osint_weaponization" in results["phases"]:
        osint = results["phases"]["osint_weaponization"]
        print(f"\n🔍 OSINT Intelligence:")
        print(f"   • Employees mapped: {osint['total_employees_identified']}")
        print(f"   • High-value targets: {len(osint['high_value_targets'])}")
    
    # Phishing findings
    if "phishing_campaigns" in results["phases"]:
        phishing = results["phases"]["phishing_campaigns"]
        print(f"\n📧 Phishing Campaigns:")
        print(f"   • Campaigns planned: {phishing['total_campaigns']}")
        print(f"   • Total targets: {phishing['estimated_total_targets']}")
    
    # Physical findings
    if "physical_security" in results["phases"]:
        physical = results["phases"]["physical_security"]
        print(f"\n🏢 Physical Security:")
        print(f"   • Vulnerabilities: {physical['total_vulnerabilities']}")
        print(f"   • Badge vulnerability: {physical['badge_vulnerability_rating']}/10")
    
    # Deepfake findings
    if "deepfake_attacks" in results["phases"]:
        deepfake = results["phases"]["deepfake_attacks"]
        ceo_fraud = deepfake['ceo_fraud_attack']
        print(f"\n🎭 Deepfake Attacks:")
        print(f"   • CEO fraud success rate: {ceo_fraud['success_probability']:.0%}")
    
    # Integrated scenarios
    print(f"\n🎯 Integrated Attack Scenarios: {len(results['integrated_scenarios'])}")
    for scenario in results["integrated_scenarios"]:
        print(f"\n   • {scenario['name']}")
        print(f"     Phases: {len(scenario['phases'])}")
        print(f"     Success probability: {scenario['success_probability']:.0%}")
        print(f"     Impact: {scenario['impact']}")


# Example 8: Vishing Campaign
async def example_8_vishing_campaign():
    """Example: Generate vishing (voice phishing) campaign"""
    
    print("\n" + "=" * 80)
    print("EXAMPLE 8: VISHING CAMPAIGN")
    print("=" * 80)
    
    deepfake = DeepfakeEngine()
    
    # Define targets
    targets = [
        {"name": "Alice Johnson", "title": "IT Support Specialist"},
        {"name": "Mark Davis", "title": "HR Manager"},
        {"name": "Lisa Chen", "title": "Accounts Payable"}
    ]
    
    # Generate vishing campaign
    campaign = await deepfake.generate_vishing_campaign(
        executive_name="David Thompson",
        executive_title="Chief Information Security Officer",
        targets=targets,
        scenario="security_incident"
    )
    
    print(f"\n📞 Vishing Campaign: {campaign['campaign_name']}")
    print(f"   Impersonating: {campaign['impersonated_person']}")
    print(f"   Voice quality: {campaign['voice_quality']}")
    print(f"   Scenario: {campaign['scenario']}")
    print(f"   Targets: {campaign['total_targets']}")
    print(f"   Average success rate: {campaign['average_success_probability']:.0%}")
    
    # Show sample call
    if campaign['calls']:
        sample = campaign['calls'][0]
        print(f"\n   📝 Sample vishing call to {sample['target']}:")
        print(f"   Script preview: {sample['script'][:200]}...")


# Main execution
async def main():
    """Run all Phase 10 examples"""
    
    print("\n" + "=" * 80)
    print("PHASE 10: PHYSICAL & SOCIAL ENGINEERING EXAMPLES")
    print("=" * 80)
    print("\n⚠️  WARNING: These examples are for educational/authorized testing only!")
    print("   Always obtain written authorization before any assessment.")
    print("=" * 80)
    
    examples = [
        ("OSINT Weaponization", example_1_osint_weaponization),
        ("Phishing Campaign", example_2_phishing_campaign),
        ("Physical Security Assessment", example_3_physical_security),
        ("Deepfake CEO Fraud", example_4_deepfake_ceo_fraud),
        ("OSINT to Phishing Pipeline", example_5_osint_to_phishing),
        ("Physical + USB Drop", example_6_physical_usb_attack),
        ("Full Phase 10 Assessment", example_7_full_assessment),
        ("Vishing Campaign", example_8_vishing_campaign),
    ]
    
    print("\nAvailable examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"   {i}. {name}")
    
    print("\n   0. Run all examples")
    print("   q. Quit")
    
    choice = input("\nSelect example (0-8, q): ").strip()
    
    if choice.lower() == 'q':
        print("\nExiting...")
        return
    
    try:
        choice_num = int(choice)
        
        if choice_num == 0:
            # Run all examples
            for name, example_func in examples:
                print(f"\n\nRunning: {name}...")
                await example_func()
                await asyncio.sleep(1)
        elif 1 <= choice_num <= len(examples):
            # Run selected example
            name, example_func = examples[choice_num - 1]
            print(f"\n\nRunning: {name}...")
            await example_func()
        else:
            print("Invalid choice")
    
    except ValueError:
        print("Invalid input")
    
    print("\n" + "=" * 80)
    print("EXAMPLES COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
