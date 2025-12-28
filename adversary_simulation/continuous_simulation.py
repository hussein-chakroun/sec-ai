"""
Continuous Adversary Simulation
Scheduled attack campaigns, assume breach scenarios, and ongoing testing
"""

import asyncio
import json
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import random


class CampaignType(Enum):
    """Types of attack campaigns"""
    SCHEDULED = "scheduled"
    ASSUME_BREACH = "assume_breach"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    RANSOMWARE = "ransomware"
    APT_ESPIONAGE = "apt_espionage"
    DATA_THEFT = "data_theft"


class CampaignStatus(Enum):
    """Campaign execution status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AttackCampaign:
    """Attack campaign definition"""
    campaign_id: str
    name: str
    campaign_type: CampaignType
    description: str
    schedule: str  # cron-like schedule
    duration: timedelta
    techniques: List[str]
    objectives: List[str]
    status: CampaignStatus = CampaignStatus.SCHEDULED
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: Dict = field(default_factory=dict)
    
    # Scenario-specific parameters
    initial_access: Optional[str] = None
    privilege_level: str = "user"
    target_assets: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)


class ContinuousAdversarySimulator:
    """
    Continuous adversary simulation engine
    Runs scheduled campaigns and assume-breach scenarios
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("reports/continuous_simulation")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.campaigns: List[AttackCampaign] = []
        self.active_campaigns: Dict[str, asyncio.Task] = {}
        self.campaign_history: List[Dict] = []
        
    def create_scheduled_campaign(
        self,
        name: str,
        schedule: str,
        duration: timedelta,
        techniques: List[str],
        objectives: List[str]
    ) -> AttackCampaign:
        """Create a scheduled attack campaign"""
        campaign = AttackCampaign(
            campaign_id=self._generate_campaign_id(),
            name=name,
            campaign_type=CampaignType.SCHEDULED,
            description=f"Scheduled campaign: {name}",
            schedule=schedule,
            duration=duration,
            techniques=techniques,
            objectives=objectives
        )
        
        self.campaigns.append(campaign)
        print(f"   📅 Created scheduled campaign: {name}")
        print(f"      Schedule: {schedule}")
        print(f"      Techniques: {len(techniques)}")
        
        return campaign
    
    def create_assume_breach_scenario(
        self,
        name: str,
        initial_access: str,
        privilege_level: str,
        target_assets: List[str],
        duration: timedelta = timedelta(hours=8)
    ) -> AttackCampaign:
        """
        Create an assume-breach scenario
        Starts from post-exploitation phase
        """
        # Assume breach techniques (skip initial access)
        techniques = [
            "T1087",  # Account Discovery
            "T1083",  # File and Directory Discovery
            "T1082",  # System Information Discovery
            "T1069",  # Permission Groups Discovery
            "T1057",  # Process Discovery
            "T1003",  # Credential Dumping
            "T1021",  # Remote Services
            "T1560",  # Archive Collected Data
            "T1041",  # Exfiltration Over C2
        ]
        
        campaign = AttackCampaign(
            campaign_id=self._generate_campaign_id(),
            name=name,
            campaign_type=CampaignType.ASSUME_BREACH,
            description=f"Assume breach scenario: {name}",
            schedule="manual",
            duration=duration,
            techniques=techniques,
            objectives=["Assess post-breach detection", "Test lateral movement controls"],
            initial_access=initial_access,
            privilege_level=privilege_level,
            target_assets=target_assets
        )
        
        self.campaigns.append(campaign)
        print(f"   🎯 Created assume-breach scenario: {name}")
        print(f"      Initial Access: {initial_access}")
        print(f"      Privilege Level: {privilege_level}")
        print(f"      Target Assets: {len(target_assets)}")
        
        return campaign
    
    def create_insider_threat_scenario(
        self,
        name: str,
        insider_type: str,
        access_level: str,
        motivation: str,
        duration: timedelta = timedelta(days=7)
    ) -> AttackCampaign:
        """
        Create insider threat simulation
        Simulates malicious or negligent insider
        """
        # Insider threat typically uses legitimate access
        techniques = [
            "T1078",  # Valid Accounts
            "T1005",  # Data from Local System
            "T1039",  # Data from Network Shared Drive
            "T1114",  # Email Collection
            "T1560",  # Archive Collected Data
            "T1048",  # Exfiltration Over Alternative Protocol
            "T1567",  # Exfiltration Over Web Service
            "T1070",  # Indicator Removal
        ]
        
        campaign = AttackCampaign(
            campaign_id=self._generate_campaign_id(),
            name=name,
            campaign_type=CampaignType.INSIDER_THREAT,
            description=f"Insider threat scenario: {insider_type}",
            schedule="manual",
            duration=duration,
            techniques=techniques,
            objectives=[
                "Test data loss prevention",
                "Assess user behavior analytics",
                "Validate insider threat detection"
            ],
            privilege_level=access_level,
            constraints=[
                "Use only legitimate credentials",
                "Access only authorized resources",
                "Simulate realistic insider behavior patterns"
            ]
        )
        
        campaign.results["insider_profile"] = {
            "type": insider_type,
            "motivation": motivation,
            "access_level": access_level
        }
        
        self.campaigns.append(campaign)
        print(f"   👤 Created insider threat scenario: {name}")
        print(f"      Type: {insider_type}")
        print(f"      Motivation: {motivation}")
        print(f"      Access Level: {access_level}")
        
        return campaign
    
    def create_supply_chain_attack_scenario(
        self,
        name: str,
        compromised_component: str,
        target_organizations: List[str],
        duration: timedelta = timedelta(days=30)
    ) -> AttackCampaign:
        """
        Create supply chain attack simulation
        Simulates compromise through trusted third party
        """
        techniques = [
            "T1195",  # Supply Chain Compromise
            "T1199",  # Trusted Relationship
            "T1550",  # Use Alternate Authentication Material
            "T1078",  # Valid Accounts
            "T1071",  # Application Layer Protocol
            "T1027",  # Obfuscated Files or Information
            "T1055",  # Process Injection
            "T1090",  # Proxy
            "T1041",  # Exfiltration Over C2
        ]
        
        campaign = AttackCampaign(
            campaign_id=self._generate_campaign_id(),
            name=name,
            campaign_type=CampaignType.SUPPLY_CHAIN,
            description=f"Supply chain attack via {compromised_component}",
            schedule="manual",
            duration=duration,
            techniques=techniques,
            objectives=[
                "Test supply chain security controls",
                "Assess third-party risk monitoring",
                "Validate software integrity checks"
            ],
            initial_access=f"Compromised {compromised_component}",
            target_assets=target_organizations
        )
        
        campaign.results["supply_chain_details"] = {
            "compromised_component": compromised_component,
            "distribution_method": "Software update",
            "target_organizations": target_organizations
        }
        
        self.campaigns.append(campaign)
        print(f"   🔗 Created supply chain attack scenario: {name}")
        print(f"      Compromised: {compromised_component}")
        print(f"      Targets: {len(target_organizations)} organizations")
        
        return campaign
    
    async def run_campaign(self, campaign: AttackCampaign) -> Dict:
        """Execute an attack campaign"""
        print(f"\n🎯 Starting Campaign: {campaign.name}")
        print(f"   Type: {campaign.campaign_type.value}")
        print(f"   Duration: {campaign.duration}")
        
        campaign.status = CampaignStatus.RUNNING
        campaign.start_time = datetime.now()
        
        results = {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "type": campaign.campaign_type.value,
            "start_time": campaign.start_time.isoformat(),
            "phases": [],
            "techniques_executed": [],
            "objectives_achieved": [],
            "detections_triggered": [],
            "metrics": {}
        }
        
        try:
            # Execute campaign based on type
            if campaign.campaign_type == CampaignType.ASSUME_BREACH:
                await self._execute_assume_breach(campaign, results)
            elif campaign.campaign_type == CampaignType.INSIDER_THREAT:
                await self._execute_insider_threat(campaign, results)
            elif campaign.campaign_type == CampaignType.SUPPLY_CHAIN:
                await self._execute_supply_chain(campaign, results)
            else:
                await self._execute_standard_campaign(campaign, results)
            
            campaign.status = CampaignStatus.COMPLETED
            results["status"] = "completed"
            
        except Exception as e:
            campaign.status = CampaignStatus.FAILED
            results["status"] = "failed"
            results["error"] = str(e)
            print(f"   ❌ Campaign failed: {e}")
        
        campaign.end_time = datetime.now()
        results["end_time"] = campaign.end_time.isoformat()
        results["duration_minutes"] = (campaign.end_time - campaign.start_time).total_seconds() / 60
        
        campaign.results = results
        self.campaign_history.append(results)
        
        self._save_campaign_results(campaign)
        self._print_campaign_summary(results)
        
        return results
    
    async def _execute_assume_breach(self, campaign: AttackCampaign, results: Dict):
        """Execute assume-breach scenario"""
        print(f"\n   🎯 Assume Breach Scenario")
        print(f"      Starting from: {campaign.initial_access}")
        print(f"      Privilege: {campaign.privilege_level}")
        
        # Phase 1: Discovery
        await self._execute_phase(
            "Discovery",
            ["T1087", "T1083", "T1082", "T1069"],
            campaign,
            results
        )
        
        # Phase 2: Credential Access
        if campaign.privilege_level == "user":
            await self._execute_phase(
                "Privilege Escalation",
                ["T1068", "T1134"],
                campaign,
                results
            )
        
        await self._execute_phase(
            "Credential Access",
            ["T1003", "T1056"],
            campaign,
            results
        )
        
        # Phase 3: Lateral Movement
        await self._execute_phase(
            "Lateral Movement",
            ["T1021", "T1570"],
            campaign,
            results
        )
        
        # Phase 4: Collection & Exfiltration
        await self._execute_phase(
            "Collection",
            ["T1560", "T1005"],
            campaign,
            results
        )
        
        await self._execute_phase(
            "Exfiltration",
            ["T1041", "T1048"],
            campaign,
            results
        )
    
    async def _execute_insider_threat(self, campaign: AttackCampaign, results: Dict):
        """Execute insider threat scenario"""
        print(f"\n   👤 Insider Threat Simulation")
        
        insider_profile = campaign.results.get("insider_profile", {})
        print(f"      Type: {insider_profile.get('type', 'Unknown')}")
        print(f"      Motivation: {insider_profile.get('motivation', 'Unknown')}")
        
        # Simulate realistic insider behavior over time
        # Day 1-3: Normal activity with occasional data access
        await self._execute_phase(
            "Baseline Activity",
            ["T1078"],
            campaign,
            results,
            description="Establish normal usage pattern"
        )
        
        # Day 4-5: Increased data access
        await self._execute_phase(
            "Escalated Access",
            ["T1005", "T1039", "T1114"],
            campaign,
            results,
            description="Access sensitive data"
        )
        
        # Day 6: Data collection and staging
        await self._execute_phase(
            "Data Staging",
            ["T1560"],
            campaign,
            results,
            description="Archive collected data"
        )
        
        # Day 7: Exfiltration
        await self._execute_phase(
            "Exfiltration",
            ["T1567", "T1048"],
            campaign,
            results,
            description="Exfiltrate data"
        )
        
        # Cleanup attempts
        await self._execute_phase(
            "Anti-Forensics",
            ["T1070"],
            campaign,
            results,
            description="Cover tracks"
        )
    
    async def _execute_supply_chain(self, campaign: AttackCampaign, results: Dict):
        """Execute supply chain attack scenario"""
        print(f"\n   🔗 Supply Chain Attack Simulation")
        
        supply_chain_details = campaign.results.get("supply_chain_details", {})
        print(f"      Vector: {supply_chain_details.get('compromised_component', 'Unknown')}")
        
        # Phase 1: Initial compromise via supply chain
        await self._execute_phase(
            "Supply Chain Compromise",
            ["T1195"],
            campaign,
            results,
            description="Deliver trojanized component"
        )
        
        # Phase 2: Establish foothold
        await self._execute_phase(
            "Execution",
            ["T1059", "T1106"],
            campaign,
            results,
            description="Execute malicious payload"
        )
        
        # Phase 3: Persistence and stealth
        await self._execute_phase(
            "Persistence",
            ["T1547", "T1053"],
            campaign,
            results,
            description="Maintain access"
        )
        
        await self._execute_phase(
            "Defense Evasion",
            ["T1027", "T1055"],
            campaign,
            results,
            description="Evade detection"
        )
        
        # Phase 4: Spread to other organizations
        await self._execute_phase(
            "Lateral Movement",
            ["T1199", "T1550"],
            campaign,
            results,
            description="Pivot to customer networks"
        )
        
        # Phase 5: Objectives
        await self._execute_phase(
            "Impact",
            ["T1485", "T1486"],
            campaign,
            results,
            description="Achieve campaign objectives"
        )
    
    async def _execute_standard_campaign(self, campaign: AttackCampaign, results: Dict):
        """Execute standard attack campaign"""
        print(f"\n   ⚔️  Standard Attack Campaign")
        
        # Execute kill chain
        phases = [
            ("Reconnaissance", ["T1595", "T1592"]),
            ("Initial Access", ["T1190", "T1566"]),
            ("Execution", ["T1059", "T1106"]),
            ("Persistence", ["T1547", "T1053"]),
            ("Privilege Escalation", ["T1068", "T1134"]),
            ("Defense Evasion", ["T1070", "T1055"]),
            ("Credential Access", ["T1003", "T1110"]),
            ("Discovery", ["T1087", "T1083"]),
            ("Lateral Movement", ["T1021"]),
            ("Collection", ["T1560", "T1005"]),
            ("Exfiltration", ["T1041", "T1048"])
        ]
        
        for phase_name, techniques in phases:
            # Only execute techniques that are in the campaign
            relevant_techniques = [t for t in techniques if t in campaign.techniques]
            if relevant_techniques:
                await self._execute_phase(
                    phase_name,
                    relevant_techniques,
                    campaign,
                    results
                )
    
    async def _execute_phase(
        self,
        phase_name: str,
        techniques: List[str],
        campaign: AttackCampaign,
        results: Dict,
        description: str = None
    ):
        """Execute a campaign phase"""
        print(f"\n      Phase: {phase_name}")
        if description:
            print(f"      {description}")
        
        phase_result = {
            "phase": phase_name,
            "description": description or phase_name,
            "start_time": datetime.now().isoformat(),
            "techniques": [],
            "success": True
        }
        
        for technique_id in techniques:
            success = await self._execute_technique(technique_id, campaign)
            
            phase_result["techniques"].append({
                "id": technique_id,
                "success": success,
                "timestamp": datetime.now().isoformat()
            })
            
            results["techniques_executed"].append(technique_id)
            
            if success:
                print(f"         ✓ {technique_id}")
            else:
                print(f"         ✗ {technique_id}")
                phase_result["success"] = False
            
            # Simulate realistic timing
            await asyncio.sleep(random.uniform(1, 3))
        
        phase_result["end_time"] = datetime.now().isoformat()
        results["phases"].append(phase_result)
    
    async def _execute_technique(self, technique_id: str, campaign: AttackCampaign) -> bool:
        """Execute a single technique"""
        # Simulate technique execution
        # In real implementation, would execute actual techniques
        await asyncio.sleep(0.5)
        
        # Simulate 80% success rate
        success = random.random() < 0.80
        
        # Simulate detection probability (20% for standard, 40% for assume-breach)
        detection_prob = 0.40 if campaign.campaign_type == CampaignType.ASSUME_BREACH else 0.20
        
        if random.random() < detection_prob:
            campaign.results.setdefault("detections_triggered", []).append({
                "technique": technique_id,
                "timestamp": datetime.now().isoformat(),
                "severity": random.choice(["low", "medium", "high"])
            })
        
        return success
    
    def _generate_campaign_id(self) -> str:
        """Generate unique campaign ID"""
        import hashlib
        return hashlib.md5(f"{datetime.now()}{random.random()}".encode()).hexdigest()[:12]
    
    def _save_campaign_results(self, campaign: AttackCampaign):
        """Save campaign results to file"""
        filename = f"campaign_{campaign.campaign_id}_{campaign.campaign_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(campaign.results, f, indent=2)
        
        print(f"\n   💾 Campaign results saved: {filepath}")
    
    def _print_campaign_summary(self, results: Dict):
        """Print campaign summary"""
        print(f"\n   📊 Campaign Summary")
        print(f"      Status: {results['status']}")
        print(f"      Duration: {results.get('duration_minutes', 0):.1f} minutes")
        print(f"      Phases Completed: {len(results['phases'])}")
        print(f"      Techniques Executed: {len(results['techniques_executed'])}")
        
        if "detections_triggered" in results:
            print(f"      Detections Triggered: {len(results['detections_triggered'])}")
        
        # Calculate phase success rate
        successful_phases = sum(1 for p in results['phases'] if p.get('success', False))
        total_phases = len(results['phases'])
        if total_phases > 0:
            print(f"      Phase Success Rate: {successful_phases}/{total_phases} ({successful_phases/total_phases*100:.1f}%)")
    
    async def run_continuous_simulation(self, interval: timedelta = timedelta(hours=24)):
        """Run continuous simulation with scheduled campaigns"""
        print(f"\n🔄 Starting Continuous Adversary Simulation")
        print(f"   Check Interval: {interval}")
        print(f"   Scheduled Campaigns: {len([c for c in self.campaigns if c.status == CampaignStatus.SCHEDULED])}")
        
        while True:
            # Check for scheduled campaigns
            for campaign in self.campaigns:
                if campaign.status == CampaignStatus.SCHEDULED:
                    # In real implementation, would check cron schedule
                    # For now, run if not already executed
                    if campaign.campaign_id not in self.active_campaigns:
                        print(f"\n   ⏰ Triggering scheduled campaign: {campaign.name}")
                        task = asyncio.create_task(self.run_campaign(campaign))
                        self.active_campaigns[campaign.campaign_id] = task
            
            # Clean up completed tasks
            completed = [
                cid for cid, task in self.active_campaigns.items()
                if task.done()
            ]
            
            for cid in completed:
                del self.active_campaigns[cid]
            
            # Wait before next check
            await asyncio.sleep(interval.total_seconds())
    
    def generate_simulation_report(self, output_path: Path = None) -> Dict:
        """Generate comprehensive simulation report"""
        if not output_path:
            output_path = self.output_dir / f"simulation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_campaigns": len(self.campaign_history),
            "campaign_types": {},
            "overall_metrics": {},
            "campaigns": self.campaign_history
        }
        
        # Aggregate metrics
        for campaign in self.campaign_history:
            ctype = campaign.get("type", "unknown")
            report["campaign_types"][ctype] = report["campaign_types"].get(ctype, 0) + 1
        
        if self.campaign_history:
            total_techniques = sum(len(c.get("techniques_executed", [])) for c in self.campaign_history)
            total_detections = sum(len(c.get("detections_triggered", [])) for c in self.campaign_history)
            
            report["overall_metrics"] = {
                "total_techniques_executed": total_techniques,
                "total_detections_triggered": total_detections,
                "detection_rate": (total_detections / total_techniques * 100) if total_techniques > 0 else 0,
                "average_campaign_duration": sum(c.get("duration_minutes", 0) for c in self.campaign_history) / len(self.campaign_history)
            }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n   📊 Simulation report saved: {output_path}")
        return report
