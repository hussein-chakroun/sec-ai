"""
Phase 10 Engine: Physical & Social Engineering Integration
Orchestrates OSINT weaponization, phishing campaigns, physical security, and deepfake attacks
"""

import asyncio
import json
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

from physical_social_engineering.osint_weaponization import (
    OSINTWeaponizer,
    PersonProfile,
    OrganizationProfile
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
from physical_social_engineering.deepfake_integration import (
    DeepfakeEngine,
    QualityLevel
)


class Phase10Engine:
    """
    Main orchestration engine for Phase 10: Physical & Social Engineering
    
    Capabilities:
    - OSINT weaponization and intelligence gathering
    - Automated phishing campaign generation
    - Physical security assessment
    - Deepfake-powered social engineering
    - Integrated attack planning
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("assessments/phase10")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize all subsystems
        self.osint_weaponizer = OSINTWeaponizer(self.output_dir / "osint")
        self.phishing_manager = PhishingCampaignManager(self.output_dir / "phishing")
        self.physical_security = PhysicalSecurityAnalyzer(self.output_dir / "physical")
        self.deepfake_engine = DeepfakeEngine(self.output_dir / "deepfake")
        
        self.assessment_results: Dict = {}
        
    async def run_full_assessment(
        self,
        target_organization: str,
        target_domain: str,
        target_address: str = None,
        scope: List[str] = None
    ) -> Dict:
        """
        Run comprehensive Phase 10 assessment
        
        Args:
            target_organization: Name of target organization
            target_domain: Email domain
            target_address: Physical address (if applicable)
            scope: Assessment scope ['osint', 'phishing', 'physical', 'deepfake']
        
        Returns:
            Comprehensive assessment results
        """
        
        if scope is None:
            scope = ['osint', 'phishing', 'physical', 'deepfake']
        
        print("=" * 80)
        print("PHASE 10: PHYSICAL & SOCIAL ENGINEERING ASSESSMENT")
        print("=" * 80)
        print(f"\n🎯 Target Organization: {target_organization}")
        print(f"   Domain: {target_domain}")
        if target_address:
            print(f"   Location: {target_address}")
        print(f"   Scope: {', '.join(scope)}")
        print(f"\n⚠️  WARNING: Authorized testing only. Ensure proper authorization.")
        print("=" * 80)
        
        results = {
            "organization": target_organization,
            "domain": target_domain,
            "address": target_address,
            "assessment_scope": scope,
            "start_time": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: OSINT Weaponization
        if 'osint' in scope:
            print("\n" + "=" * 80)
            print("PHASE 1: OSINT WEAPONIZATION")
            print("=" * 80)
            
            osint_results = await self._run_osint_weaponization(
                target_organization,
                target_domain
            )
            results["phases"]["osint_weaponization"] = osint_results
        
        # Phase 2: Phishing Campaign Planning
        if 'phishing' in scope:
            print("\n" + "=" * 80)
            print("PHASE 2: PHISHING CAMPAIGN AUTOMATION")
            print("=" * 80)
            
            # Use OSINT results if available
            employee_targets = results.get("phases", {}).get("osint_weaponization", {}).get(
                "high_value_targets", []
            )
            
            phishing_results = await self._run_phishing_campaigns(
                target_organization,
                target_domain,
                employee_targets
            )
            results["phases"]["phishing_campaigns"] = phishing_results
        
        # Phase 3: Physical Security Assessment
        if 'physical' in scope:
            print("\n" + "=" * 80)
            print("PHASE 3: PHYSICAL SECURITY ANALYSIS")
            print("=" * 80)
            
            physical_results = await self._run_physical_security(
                target_organization,
                target_address
            )
            results["phases"]["physical_security"] = physical_results
        
        # Phase 4: Deepfake Integration
        if 'deepfake' in scope:
            print("\n" + "=" * 80)
            print("PHASE 4: DEEPFAKE SOCIAL ENGINEERING")
            print("=" * 80)
            
            # Use OSINT results to identify executives
            org_profile = results.get("phases", {}).get("osint_weaponization", {}).get(
                "organization_profile"
            )
            
            deepfake_results = await self._run_deepfake_attacks(
                target_organization,
                org_profile
            )
            results["phases"]["deepfake_attacks"] = deepfake_results
        
        # Generate integrated attack scenarios
        print("\n" + "=" * 80)
        print("INTEGRATED ATTACK SCENARIOS")
        print("=" * 80)
        
        integrated_scenarios = self._generate_integrated_scenarios(results)
        results["integrated_scenarios"] = integrated_scenarios
        
        # Complete assessment
        results["end_time"] = datetime.now().isoformat()
        results["status"] = "completed"
        
        # Save comprehensive report
        self._save_assessment(results)
        
        # Print summary
        self._print_summary(results)
        
        self.assessment_results = results
        return results
    
    async def _run_osint_weaponization(
        self,
        organization: str,
        domain: str
    ) -> Dict:
        """Run OSINT weaponization phase"""
        
        print("\n🔍 Running OSINT weaponization...")
        
        # Weaponize organization
        org_profile = await self.osint_weaponizer.weaponize_organization(
            company_name=organization,
            domain=domain,
            max_profiles=50
        )
        
        # Extract key intelligence
        employees = org_profile.employees
        org_chart = org_profile.org_chart
        
        # Identify high-value targets
        from physical_social_engineering.osint_weaponization import LinkedInScraper
        scraper = LinkedInScraper()
        high_value_targets = scraper.identify_high_value_targets(employees, top_n=10)
        
        results = {
            "total_employees_identified": len(employees),
            "org_chart_levels": {
                "c_level": len(org_chart.get("c_level", [])),
                "vp_level": len(org_chart.get("vp_level", [])),
                "directors": len(org_chart.get("director_level", [])),
                "managers": len(org_chart.get("manager_level", [])),
                "ics": len(org_chart.get("individual_contributors", []))
            },
            "email_patterns_discovered": len(self.osint_weaponizer.email_identifier.discovered_patterns),
            "high_value_targets": [
                {
                    "name": t.name,
                    "title": t.job_title,
                    "department": t.department,
                    "email": t.email,
                    "vulnerability_score": t.vulnerability_score
                }
                for t in high_value_targets
            ],
            "organization_profile": {
                "name": org_profile.name,
                "domain": org_profile.domain,
                "employee_count": len(employees)
            }
        }
        
        print(f"\n✅ OSINT Weaponization Complete")
        print(f"   Employees identified: {results['total_employees_identified']}")
        print(f"   High-value targets: {len(high_value_targets)}")
        
        return results
    
    async def _run_phishing_campaigns(
        self,
        organization: str,
        domain: str,
        employee_targets: List[Dict]
    ) -> Dict:
        """Run phishing campaign planning"""
        
        print("\n📧 Planning phishing campaigns...")
        
        campaigns = []
        
        # Campaign 1: Spear phishing against high-value targets
        if employee_targets:
            targets = [
                {
                    "name": t.get("name", "Unknown"),
                    "email": t.get("email", f"user@{domain}"),
                    "title": t.get("title", "Employee"),
                    "company": organization
                }
                for t in employee_targets[:5]
            ]
            
            spear_phish_campaign = await self.phishing_manager.create_campaign(
                campaign_name=f"SpearPhish_{organization}_HighValue",
                targets=targets,
                campaign_type=PhishingType.SPEAR_PHISHING,
                pretext_type=PretextType.IT_SUPPORT,
                duration_days=7
            )
            campaigns.append({
                "name": spear_phish_campaign.name,
                "type": spear_phish_campaign.campaign_type.value,
                "targets": len(targets),
                "pretext": spear_phish_campaign.pretext_type.value
            })
        
        # Campaign 2: Broad credential harvesting
        broad_targets = [
            {"name": f"Employee{i}", "email": f"employee{i}@{domain}", "company": organization}
            for i in range(1, 11)
        ]
        
        credential_campaign = await self.phishing_manager.create_campaign(
            campaign_name=f"CredentialHarvest_{organization}",
            targets=broad_targets,
            campaign_type=PhishingType.SPEAR_PHISHING,
            pretext_type=PretextType.SECURITY_ALERT,
            duration_days=5
        )
        campaigns.append({
            "name": credential_campaign.name,
            "type": credential_campaign.campaign_type.value,
            "targets": len(broad_targets),
            "pretext": credential_campaign.pretext_type.value
        })
        
        # Campaign 3: SMS phishing (smishing)
        smishing_campaign = await self.phishing_manager.create_campaign(
            campaign_name=f"Smishing_{organization}",
            targets=employee_targets[:3] if employee_targets else broad_targets[:3],
            campaign_type=PhishingType.SMISHING,
            pretext_type=PretextType.SECURITY_ALERT,
            duration_days=3
        )
        campaigns.append({
            "name": smishing_campaign.name,
            "type": smishing_campaign.campaign_type.value,
            "targets": 3,
            "pretext": smishing_campaign.pretext_type.value
        })
        
        results = {
            "total_campaigns": len(campaigns),
            "campaigns": campaigns,
            "estimated_total_targets": sum(c["targets"] for c in campaigns)
        }
        
        print(f"\n✅ Phishing Campaigns Planned")
        print(f"   Total campaigns: {results['total_campaigns']}")
        print(f"   Total targets: {results['estimated_total_targets']}")
        
        return results
    
    async def _run_physical_security(
        self,
        organization: str,
        address: Optional[str]
    ) -> Dict:
        """Run physical security assessment"""
        
        print("\n🏢 Assessing physical security...")
        
        # Create mock physical location
        location = PhysicalLocation(
            name=f"{organization} Headquarters",
            address=address or "Unknown",
            facility_type="office",
            security_level=SecurityLevel.MEDIUM,
            access_controls=[
                AccessControlType.BADGE,
                AccessControlType.GUARD
            ],
            operating_hours={
                "weekday": (datetime.strptime("08:00", "%H:%M").time(),
                           datetime.strptime("18:00", "%H:%M").time())
            },
            employee_count=100,
            security_guards=2,
            cameras=8,
            entry_points=3
        )
        
        # Create mock badge system
        badge_system = BadgeSystem(
            technology="RFID",
            frequency="125kHz",
            encryption=False,
            clone_difficulty="easy",
            vendor="HID ProxCard"
        )
        
        # Create mock cameras
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
                field_of_view=120,
                night_vision=False,
                motion_detection=False,
                recording=True
            )
        ]
        
        # Create mock locks
        locks = [
            LockSystem(
                lock_type="pin_pad",
                security_rating=4
            ),
            LockSystem(
                lock_type="deadbolt",
                security_rating=6
            )
        ]
        
        # Run assessment
        assessment = await self.physical_security.analyze_facility(
            location=location,
            badge_system=badge_system,
            cameras=cameras,
            locks=locks
        )
        
        results = {
            "facility_name": location.name,
            "security_level": location.security_level.value,
            "badge_vulnerability_rating": assessment.get("access_control_analysis", {}).get(
                "vulnerability_rating", 0
            ),
            "tailgating_opportunities": len(assessment.get("tailgating_analysis", [])),
            "camera_blind_spots": len(assessment.get("camera_analysis", {}).get("blind_spots", [])),
            "total_vulnerabilities": len(assessment.get("overall_vulnerabilities", [])),
            "attack_scenarios": len(assessment.get("attack_scenarios", []))
        }
        
        print(f"\n✅ Physical Security Assessment Complete")
        print(f"   Total vulnerabilities: {results['total_vulnerabilities']}")
        print(f"   Attack scenarios: {results['attack_scenarios']}")
        
        return results
    
    async def _run_deepfake_attacks(
        self,
        organization: str,
        org_profile: Optional[Dict]
    ) -> Dict:
        """Run deepfake attack planning"""
        
        print("\n🎭 Planning deepfake attacks...")
        
        # Identify CEO/executives
        if org_profile and org_profile.get("organization_profile"):
            # Use actual org data if available
            ceo_name = "John CEO"  # Would extract from org_profile
            ceo_title = "Chief Executive Officer"
        else:
            ceo_name = "Executive Leader"
            ceo_title = "CEO"
        
        # Identify victim (CFO, Finance Manager, etc.)
        victim_name = "Finance Manager"
        victim_title = "Senior Finance Manager"
        
        # Plan CEO fraud attack
        ceo_fraud_attack = await self.deepfake_engine.create_comprehensive_attack(
            target_organization=organization,
            executive_name=ceo_name,
            executive_title=ceo_title,
            victim_name=victim_name,
            victim_title=victim_title,
            attack_goal="wire_transfer"
        )
        
        # Plan vishing campaign
        vishing_targets = [
            {"name": "Employee 1", "title": "IT Support"},
            {"name": "Employee 2", "title": "HR Manager"},
            {"name": "Employee 3", "title": "Account Manager"}
        ]
        
        vishing_campaign = await self.deepfake_engine.generate_vishing_campaign(
            executive_name=ceo_name,
            executive_title=ceo_title,
            targets=vishing_targets,
            scenario="security_incident"
        )
        
        results = {
            "ceo_fraud_attack": {
                "impersonated_executive": ceo_name,
                "target_victim": victim_name,
                "attack_phases": len(ceo_fraud_attack.get("ceo_fraud_plan", {}).get("attack_phases", [])),
                "success_probability": ceo_fraud_attack.get("overall_success_probability", 0.0)
            },
            "vishing_campaign": {
                "scenario": vishing_campaign.get("scenario"),
                "total_targets": vishing_campaign.get("total_targets", 0),
                "average_success_rate": vishing_campaign.get("average_success_probability", 0.0)
            }
        }
        
        print(f"\n✅ Deepfake Attack Planning Complete")
        print(f"   CEO fraud success probability: {results['ceo_fraud_attack']['success_probability']:.0%}")
        print(f"   Vishing targets: {results['vishing_campaign']['total_targets']}")
        
        return results
    
    def _generate_integrated_scenarios(self, results: Dict) -> List[Dict]:
        """Generate integrated attack scenarios combining multiple techniques"""
        
        scenarios = []
        
        # Scenario 1: Full-spectrum social engineering
        scenarios.append({
            "name": "Full-Spectrum Social Engineering Attack",
            "description": "Multi-phase attack combining OSINT, phishing, physical access, and deepfakes",
            "phases": [
                {
                    "phase": 1,
                    "name": "OSINT Gathering",
                    "actions": [
                        "Collect employee profiles via LinkedIn",
                        "Map organizational structure",
                        "Identify high-value targets (executives, finance)",
                        "Discover email patterns and phone numbers"
                    ],
                    "duration": "2-3 days"
                },
                {
                    "phase": 2,
                    "name": "Phishing Campaign",
                    "actions": [
                        "Launch credential harvesting campaign",
                        "Target IT staff with fake security alerts",
                        "Harvest VPN/system credentials",
                        "Establish initial access"
                    ],
                    "duration": "3-5 days"
                },
                {
                    "phase": 3,
                    "name": "Physical Access",
                    "actions": [
                        "Clone employee badge via proximity reading",
                        "Tailgate during morning rush",
                        "Access building and plant rogue WiFi AP",
                        "USB drop campaign in common areas"
                    ],
                    "duration": "1 day"
                },
                {
                    "phase": 4,
                    "name": "Deepfake CEO Fraud",
                    "actions": [
                        "Clone CEO voice from public recordings",
                        "Call CFO with urgent wire transfer request",
                        "Follow up with spoofed email",
                        "Attempt fraudulent transfer"
                    ],
                    "duration": "1-2 days"
                }
            ],
            "success_probability": 0.70,
            "detection_difficulty": "High",
            "impact": "Critical - Full compromise + financial fraud"
        })
        
        # Scenario 2: Insider threat simulation
        scenarios.append({
            "name": "Insider Threat Simulation",
            "description": "Simulate malicious insider with social engineering techniques",
            "phases": [
                {
                    "phase": 1,
                    "name": "Credential Compromise",
                    "actions": [
                        "Phish employee credentials",
                        "Access as legitimate user"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Privilege Escalation",
                    "actions": [
                        "Use deepfake voice to request admin access from IT",
                        "Social engineer password reset",
                        "Gain elevated privileges"
                    ]
                },
                {
                    "phase": 3,
                    "name": "Data Exfiltration",
                    "actions": [
                        "Access sensitive data repositories",
                        "Exfiltrate via approved cloud services",
                        "Cover tracks"
                    ]
                }
            ],
            "success_probability": 0.60,
            "detection_difficulty": "Very High - Appears legitimate",
            "impact": "High - Data breach"
        })
        
        # Scenario 3: Supply chain compromise
        scenarios.append({
            "name": "Supply Chain Social Engineering",
            "description": "Compromise via vendor/partner impersonation",
            "phases": [
                {
                    "phase": 1,
                    "name": "Vendor Research",
                    "actions": [
                        "Identify key vendors via OSINT",
                        "Research vendor contacts and procedures"
                    ]
                },
                {
                    "phase": 2,
                    "name": "Vendor Impersonation",
                    "actions": [
                        "Phish as vendor requesting updated payment details",
                        "Use deepfake voice of vendor representative",
                        "Request credential updates or system access"
                    ]
                },
                {
                    "phase": 3,
                    "name": "Exploitation",
                    "actions": [
                        "Redirect payments to attacker account",
                        "Or: Gain system access via vendor portal",
                        "Pivot to internal network"
                    ]
                }
            ],
            "success_probability": 0.55,
            "detection_difficulty": "High",
            "impact": "Medium to High - Financial loss or system access"
        })
        
        print(f"\n📋 Generated {len(scenarios)} integrated attack scenarios")
        
        return scenarios
    
    def _save_assessment(self, results: Dict):
        """Save comprehensive assessment results"""
        
        output_file = self.output_dir / f"phase10_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Assessment saved: {output_file}")
    
    def _print_summary(self, results: Dict):
        """Print assessment summary"""
        
        print("\n" + "=" * 80)
        print("PHASE 10 ASSESSMENT SUMMARY")
        print("=" * 80)
        
        print(f"\n🎯 Organization: {results['organization']}")
        print(f"   Domain: {results['domain']}")
        
        # OSINT summary
        if "osint_weaponization" in results.get("phases", {}):
            osint = results["phases"]["osint_weaponization"]
            print(f"\n📊 OSINT Weaponization:")
            print(f"   Employees identified: {osint.get('total_employees_identified', 0)}")
            print(f"   High-value targets: {len(osint.get('high_value_targets', []))}")
            print(f"   Email patterns: {osint.get('email_patterns_discovered', 0)}")
        
        # Phishing summary
        if "phishing_campaigns" in results.get("phases", {}):
            phishing = results["phases"]["phishing_campaigns"]
            print(f"\n📧 Phishing Campaigns:")
            print(f"   Total campaigns: {phishing.get('total_campaigns', 0)}")
            print(f"   Total targets: {phishing.get('estimated_total_targets', 0)}")
        
        # Physical security summary
        if "physical_security" in results.get("phases", {}):
            physical = results["phases"]["physical_security"]
            print(f"\n🏢 Physical Security:")
            print(f"   Vulnerabilities found: {physical.get('total_vulnerabilities', 0)}")
            print(f"   Attack scenarios: {physical.get('attack_scenarios', 0)}")
            print(f"   Badge vulnerability: {physical.get('badge_vulnerability_rating', 0)}/10")
        
        # Deepfake summary
        if "deepfake_attacks" in results.get("phases", {}):
            deepfake = results["phases"]["deepfake_attacks"]
            ceo_fraud = deepfake.get("ceo_fraud_attack", {})
            print(f"\n🎭 Deepfake Attacks:")
            print(f"   CEO fraud success rate: {ceo_fraud.get('success_probability', 0):.0%}")
            print(f"   Vishing targets: {deepfake.get('vishing_campaign', {}).get('total_targets', 0)}")
        
        # Integrated scenarios
        scenarios = results.get("integrated_scenarios", [])
        print(f"\n🎯 Integrated Attack Scenarios: {len(scenarios)}")
        for i, scenario in enumerate(scenarios, 1):
            print(f"   {i}. {scenario['name']}")
            print(f"      Success probability: {scenario.get('success_probability', 0):.0%}")
            print(f"      Impact: {scenario.get('impact', 'Unknown')}")
        
        print("\n" + "=" * 80)
        print("✅ PHASE 10 ASSESSMENT COMPLETE")
        print("=" * 80)


# Standalone execution
async def main():
    """Example Phase 10 assessment"""
    
    engine = Phase10Engine()
    
    results = await engine.run_full_assessment(
        target_organization="Acme Corporation",
        target_domain="acme.com",
        target_address="123 Business St, Tech City, CA",
        scope=['osint', 'phishing', 'physical', 'deepfake']
    )
    
    return results


if __name__ == "__main__":
    asyncio.run(main())
