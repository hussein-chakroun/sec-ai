"""
Threat Actor Emulation
Mimic specific nation-state actors and use known malware families
"""

import asyncio
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import random


@dataclass
class APTProfile:
    """Advanced Persistent Threat Actor Profile"""
    name: str
    aliases: List[str]
    country: str
    attribution: str
    active_since: str
    motivation: List[str]
    targets: List[str]
    industries: List[str]
    regions: List[str]
    
    # Technical characteristics
    preferred_tools: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    c2_infrastructure: List[str] = field(default_factory=list)
    
    # Behavioral patterns
    typical_dwell_time: str = "90+ days"
    operation_tempo: str = "business_hours"
    sophistication: str = "high"
    operational_security: str = "high"
    
    # TTPs
    favorite_techniques: List[str] = field(default_factory=list)
    known_campaigns: List[str] = field(default_factory=list)


class ThreatActorEmulator:
    """
    Emulate specific threat actors with realistic behaviors
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("reports/threat_emulation")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.actor_profiles = self._load_actor_profiles()
        self.current_campaign = None
        
    def _load_actor_profiles(self) -> Dict[str, APTProfile]:
        """Load comprehensive threat actor profiles"""
        profiles = {}
        
        # APT28 / Fancy Bear
        profiles["APT28"] = APTProfile(
            name="APT28",
            aliases=["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"],
            country="Russia",
            attribution="GRU (Main Intelligence Directorate)",
            active_since="2007",
            motivation=["Espionage", "Intelligence Collection", "Political"],
            targets=["Government", "Military", "Defense", "Media", "Political"],
            industries=["Government", "Defense", "Aerospace", "Energy"],
            regions=["Europe", "North America", "Middle East"],
            preferred_tools=[
                "XAgent", "XTunnel", "Sofacy", "Chopstick", "GAMEFISH",
                "Mimikatz", "PowerShell Empire", "Cobalt Strike"
            ],
            malware_families=[
                "SOURFACE", "EVILTOSS", "CHOPSTICK", "ADVSTORESHELL",
                "GAMEFISH", "JHUHUGIT", "AZZY", "CANNON"
            ],
            attack_vectors=[
                "Spearphishing with malicious attachments",
                "Watering hole attacks",
                "Credential harvesting",
                "Zero-day exploits"
            ],
            c2_infrastructure=[
                "Compromised websites",
                "Bulletproof hosting",
                "Domain fronting",
                "Fast-flux DNS"
            ],
            typical_dwell_time="90-180 days",
            operation_tempo="business_hours_target_timezone",
            sophistication="very_high",
            operational_security="high",
            favorite_techniques=[
                "T1566.001", "T1059.001", "T1003.001", "T1021.001",
                "T1071.001", "T1041", "T1070.004"
            ],
            known_campaigns=[
                "Democratic National Committee (2016)",
                "World Anti-Doping Agency (2016)",
                "NotPetya attribution",
                "Olympic Destroyer"
            ]
        )
        
        # APT29 / Cozy Bear
        profiles["APT29"] = APTProfile(
            name="APT29",
            aliases=["Cozy Bear", "The Dukes", "CozyDuke", "NOBELIUM"],
            country="Russia",
            attribution="SVR (Foreign Intelligence Service)",
            active_since="2008",
            motivation=["Intelligence Collection", "Espionage"],
            targets=["Government", "Think Tanks", "Technology", "Healthcare"],
            industries=["Government", "Technology", "Research", "Healthcare"],
            regions=["North America", "Europe", "Asia"],
            preferred_tools=[
                "CozyDuke", "MiniDuke", "SeaDuke", "HammerDuke", "PowerDuke",
                "WellMess", "WellMail", "SolarWinds.Orion.Core.BusinessLayer.dll"
            ],
            malware_families=[
                "SUNBURST", "TEARDROP", "RAINDROP", "BEACON",
                "GoldMax", "Sibot", "GoldFinder", "SUNSPOT"
            ],
            attack_vectors=[
                "Supply chain compromise",
                "Spearphishing links",
                "Web application exploitation",
                "Cloud infrastructure targeting"
            ],
            c2_infrastructure=[
                "Legitimate cloud services (Azure, AWS)",
                "Compromised infrastructure",
                "Domain generation algorithms",
                "Steganography in images"
            ],
            typical_dwell_time="180-365+ days",
            operation_tempo="continuous_low_and_slow",
            sophistication="very_high",
            operational_security="very_high",
            favorite_techniques=[
                "T1195.002", "T1078", "T1550.001", "T1070.004",
                "T1027", "T1055", "T1071.001", "T1573.001"
            ],
            known_campaigns=[
                "SolarWinds Supply Chain (2020)",
                "DNC Breach (2016)",
                "COVID-19 vaccine research targeting",
                "Microsoft Exchange Server attacks"
            ]
        )
        
        # Lazarus Group
        profiles["Lazarus"] = APTProfile(
            name="Lazarus Group",
            aliases=["Guardians of Peace", "HIDDEN COBRA", "ZINC", "Labyrinth Chollima"],
            country="North Korea",
            attribution="Reconnaissance General Bureau",
            active_since="2009",
            motivation=["Financial Gain", "Espionage", "Destructive"],
            targets=["Financial", "Cryptocurrency", "Defense", "Media"],
            industries=["Banking", "Cryptocurrency", "Defense", "Entertainment"],
            regions=["Global"],
            preferred_tools=[
                "WannaCry", "DTrack", "BLINDINGCAN", "PowerRatankba",
                "ARTFULPIE", "HOTCROISSANT", "Volgmer", "KEYMARBLE"
            ],
            malware_families=[
                "HOPLIGHT", "SLICKSHOES", "CROWDEDFLOUNDER", "ELECTRICFISH",
                "BADCALL", "HARDRAIN", "NACHOCHEESE", "TYPEFRAME"
            ],
            attack_vectors=[
                "Spearphishing with weaponized documents",
                "Watering hole attacks",
                "Cryptocurrency exchange compromise",
                "ATM malware"
            ],
            c2_infrastructure=[
                "Compromised legitimate websites",
                "Free hosting services",
                "Social media platforms",
                "P2P networks"
            ],
            typical_dwell_time="30-90 days",
            operation_tempo="continuous",
            sophistication="high",
            operational_security="medium_high",
            favorite_techniques=[
                "T1566.001", "T1059.001", "T1070", "T1486",
                "T1567.002", "T1204.002", "T1027"
            ],
            known_campaigns=[
                "Sony Pictures Entertainment (2014)",
                "WannaCry Ransomware (2017)",
                "Bangladesh Bank Heist (2016)",
                "Cryptocurrency Exchange Hacks"
            ]
        )
        
        # APT38
        profiles["APT38"] = APTProfile(
            name="APT38",
            aliases=["Bluenoroff", "Stardust Chollima"],
            country="North Korea",
            attribution="Reconnaissance General Bureau",
            active_since="2014",
            motivation=["Financial Gain"],
            targets=["Banking", "Financial", "SWIFT"],
            industries=["Banking", "Financial Services", "Cryptocurrency"],
            regions=["Global"],
            preferred_tools=[
                "DYEPACK", "SHUTDOWNCK", "VIVACIOUSGIFT", "BOOTWRECK",
                "MAPMAKER", "NESTEGG", "CROWDEDFLOUNDER"
            ],
            malware_families=[
                "DYEPACK", "NESTEGG", "BOOTWRECK", "MAPMAKER",
                "WHITEOUT", "QUICKCAFE", "PEBBLEDASH"
            ],
            attack_vectors=[
                "Spearphishing banking employees",
                "SWIFT infrastructure compromise",
                "ATM cash-out operations",
                "Cryptocurrency theft"
            ],
            c2_infrastructure=[
                "Compromised web servers",
                "Free hosting services",
                "Encrypted communications"
            ],
            typical_dwell_time="90-180 days",
            operation_tempo="business_hours_target",
            sophistication="high",
            operational_security="high",
            favorite_techniques=[
                "T1190", "T1078", "T1136", "T1490",
                "T1048", "T1486"
            ],
            known_campaigns=[
                "Bangladesh Bank SWIFT Heist (2016)",
                "Banco de Chile Attack (2018)",
                "Indian Bank Compromises",
                "Mexican Bank Attacks"
            ]
        )
        
        # APT41 / Double Dragon
        profiles["APT41"] = APTProfile(
            name="APT41",
            aliases=["Double Dragon", "Barium", "Winnti"],
            country="China",
            attribution="Chinese MSS contractors",
            active_since="2012",
            motivation=["Espionage", "Financial Gain", "Dual Purpose"],
            targets=["Healthcare", "Telecom", "Gaming", "Education", "Government"],
            industries=["Healthcare", "Telecommunications", "Gaming", "Technology"],
            regions=["Global"],
            preferred_tools=[
                "HIGHNOON", "LOWKEY", "MESSAGETAP", "POISONPLUG",
                "DUSTPAN", "EVILSHOES", "SOGU", "HOMEUNIX"
            ],
            malware_families=[
                "WINNTI", "HIGHNOON", "LOWKEY", "POISONPLUG",
                "CROSSWALK", "BEACON", "DUSTPAN", "MESSAGETAP"
            ],
            attack_vectors=[
                "Web application exploitation",
                "Supply chain compromise",
                "SQL injection",
                "DLL hijacking"
            ],
            c2_infrastructure=[
                "Compromised legitimate websites",
                "Cloud infrastructure",
                "Fast-flux networks",
                "Domain fronting"
            ],
            typical_dwell_time="120-365+ days",
            operation_tempo="continuous",
            sophistication="very_high",
            operational_security="high",
            favorite_techniques=[
                "T1190", "T1505.003", "T1003", "T1560",
                "T1048", "T1195.002"
            ],
            known_campaigns=[
                "Healthcare Sector Targeting (2020)",
                "Gaming Industry Breaches",
                "Telecommunications Espionage",
                "COVID-19 Research Targeting"
            ]
        )
        
        # FIN7 / Carbanak
        profiles["FIN7"] = APTProfile(
            name="FIN7",
            aliases=["Carbanak Group", "Carbon Spider", "Anunak"],
            country="Russia/Eastern Europe",
            attribution="Cybercriminal organization",
            active_since="2013",
            motivation=["Financial Gain"],
            targets=["Retail", "Hospitality", "Financial"],
            industries=["Retail", "Hospitality", "Restaurant", "Financial"],
            regions=["North America", "Europe"],
            preferred_tools=[
                "Carbanak", "Cobalt Strike", "PowerShell Empire",
                "Mimikatz", "SQLRat", "GRIFFON", "DICELOADER"
            ],
            malware_families=[
                "Carbanak", "GRIFFON", "POWERSOURCE", "BOOSTWRITE",
                "PILLOWMINT", "DICELOADER", "TIRION"
            ],
            attack_vectors=[
                "Spearphishing with Office documents",
                "Point-of-sale malware",
                "Network reconnaissance",
                "Privilege escalation"
            ],
            c2_infrastructure=[
                "Legitimate cloud services",
                "Compromised websites",
                "DNS tunneling"
            ],
            typical_dwell_time="30-90 days",
            operation_tempo="business_hours",
            sophistication="high",
            operational_security="medium_high",
            favorite_techniques=[
                "T1566.001", "T1059.001", "T1003.001", "T1056.001",
                "T1132.001", "T1041"
            ],
            known_campaigns=[
                "Carbanak Campaign (2013-2018)",
                "Retail POS Breaches",
                "Restaurant Chain Compromises",
                "Hotel Chain Attacks"
            ]
        )
        
        return profiles
    
    def get_profile(self, actor_name: str) -> Optional[APTProfile]:
        """Get threat actor profile"""
        # Try exact match first
        if actor_name in self.actor_profiles:
            return self.actor_profiles[actor_name]
        
        # Try alias match
        for profile in self.actor_profiles.values():
            if actor_name in profile.aliases:
                return profile
        
        return None
    
    async def emulate_actor(
        self,
        actor_name: str,
        campaign_duration: timedelta = timedelta(hours=24),
        target_environment: Dict = None
    ) -> Dict:
        """
        Emulate a specific threat actor's behavior
        """
        profile = self.get_profile(actor_name)
        if not profile:
            raise ValueError(f"Unknown threat actor: {actor_name}")
        
        print(f"\n🎭 Emulating Threat Actor: {profile.name}")
        print(f"   Aliases: {', '.join(profile.aliases[:3])}")
        print(f"   Attribution: {profile.attribution} ({profile.country})")
        print(f"   Active Since: {profile.active_since}")
        print(f"   Sophistication: {profile.sophistication}")
        
        campaign = {
            "actor": profile.name,
            "start_time": datetime.now().isoformat(),
            "profile": self._profile_to_dict(profile),
            "timeline": [],
            "tools_used": [],
            "techniques_used": [],
            "indicators": [],
            "success_metrics": {}
        }
        
        self.current_campaign = campaign
        
        # Simulate campaign phases based on actor profile
        await self._execute_reconnaissance(profile, campaign)
        await self._execute_initial_access(profile, campaign)
        await self._execute_establishment(profile, campaign)
        await self._execute_escalation(profile, campaign)
        await self._execute_lateral_movement(profile, campaign)
        await self._execute_collection(profile, campaign)
        await self._execute_exfiltration(profile, campaign)
        
        # Calculate campaign metrics
        campaign["end_time"] = datetime.now().isoformat()
        campaign["success_metrics"] = self._calculate_success_metrics(campaign)
        
        # Save campaign report
        self._save_campaign_report(campaign)
        
        return campaign
    
    async def _execute_reconnaissance(self, profile: APTProfile, campaign: Dict):
        """Execute reconnaissance phase matching actor's profile"""
        print(f"\n   📡 Phase: Reconnaissance")
        
        # Simulate actor-specific reconnaissance
        if "Spearphishing" in str(profile.attack_vectors):
            await self._log_activity(
                campaign,
                "reconnaissance",
                "OSINT gathering from social media",
                ["LinkedIn profiles", "Corporate website", "Email patterns"]
            )
        
        if profile.sophistication in ["high", "very_high"]:
            await self._log_activity(
                campaign,
                "reconnaissance",
                "Technical reconnaissance via passive scanning",
                ["DNS enumeration", "SSL certificate analysis", "WHOIS data"]
            )
        
        await asyncio.sleep(2)
    
    async def _execute_initial_access(self, profile: APTProfile, campaign: Dict):
        """Execute initial access matching actor's preferred methods"""
        print(f"   🚪 Phase: Initial Access")
        
        # Use actor's preferred attack vector
        for vector in profile.attack_vectors[:2]:
            tool = random.choice(profile.preferred_tools) if profile.preferred_tools else "Custom tool"
            await self._log_activity(
                campaign,
                "initial_access",
                f"Attempting {vector}",
                [tool],
                techniques=["T1566", "T1190"]
            )
            await asyncio.sleep(1)
    
    async def _execute_establishment(self, profile: APTProfile, campaign: Dict):
        """Establish persistence and C2"""
        print(f"   ⚙️  Phase: Establishment")
        
        # Deploy actor-specific malware
        malware = random.choice(profile.malware_families) if profile.malware_families else "Custom implant"
        await self._log_activity(
            campaign,
            "execution",
            f"Deploy {malware}",
            [malware],
            techniques=["T1059", "T1106"]
        )
        
        # Establish C2 using actor's infrastructure preferences
        c2_method = random.choice(profile.c2_infrastructure) if profile.c2_infrastructure else "HTTPS"
        await self._log_activity(
            campaign,
            "command_and_control",
            f"Establish C2 via {c2_method}",
            ["C2 Framework"],
            techniques=["T1071", "T1573"]
        )
        
        await asyncio.sleep(2)
    
    async def _execute_escalation(self, profile: APTProfile, campaign: Dict):
        """Escalate privileges"""
        print(f"   ⬆️  Phase: Privilege Escalation")
        
        if "Mimikatz" in profile.preferred_tools:
            await self._log_activity(
                campaign,
                "privilege_escalation",
                "Credential dumping with Mimikatz",
                ["Mimikatz"],
                techniques=["T1003", "T1134"]
            )
        else:
            await self._log_activity(
                campaign,
                "privilege_escalation",
                "Exploit local vulnerability",
                ["Custom exploit"],
                techniques=["T1068"]
            )
        
        await asyncio.sleep(1)
    
    async def _execute_lateral_movement(self, profile: APTProfile, campaign: Dict):
        """Lateral movement across network"""
        print(f"   ➡️  Phase: Lateral Movement")
        
        await self._log_activity(
            campaign,
            "lateral_movement",
            "Move to additional hosts",
            ["PSExec", "WMI"],
            techniques=["T1021"]
        )
        
        await asyncio.sleep(2)
    
    async def _execute_collection(self, profile: APTProfile, campaign: Dict):
        """Collect data based on actor's objectives"""
        print(f"   📦 Phase: Collection")
        
        # Target data based on motivation
        if "Financial Gain" in profile.motivation:
            targets = ["Payment card data", "Banking credentials", "Cryptocurrency wallets"]
        elif "Espionage" in profile.motivation:
            targets = ["Intellectual property", "Strategic documents", "Email archives"]
        else:
            targets = ["Sensitive files", "Database dumps"]
        
        for target in targets[:2]:
            await self._log_activity(
                campaign,
                "collection",
                f"Collect {target}",
                ["Custom collector"],
                techniques=["T1005", "T1560"]
            )
            await asyncio.sleep(1)
    
    async def _execute_exfiltration(self, profile: APTProfile, campaign: Dict):
        """Exfiltrate data using actor's methods"""
        print(f"   📤 Phase: Exfiltration")
        
        c2_method = random.choice(profile.c2_infrastructure) if profile.c2_infrastructure else "HTTPS"
        await self._log_activity(
            campaign,
            "exfiltration",
            f"Exfiltrate via {c2_method}",
            ["Exfil tool"],
            techniques=["T1041", "T1048"]
        )
        
        await asyncio.sleep(1)
    
    async def _log_activity(
        self,
        campaign: Dict,
        phase: str,
        description: str,
        tools: List[str],
        techniques: List[str] = None
    ):
        """Log campaign activity"""
        activity = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "description": description,
            "tools": tools,
            "techniques": techniques or []
        }
        
        campaign["timeline"].append(activity)
        campaign["tools_used"].extend(tools)
        if techniques:
            campaign["techniques_used"].extend(techniques)
        
        print(f"      ✓ {description}")
        if tools:
            print(f"        Tools: {', '.join(tools)}")
    
    def _calculate_success_metrics(self, campaign: Dict) -> Dict:
        """Calculate campaign success metrics"""
        return {
            "total_phases": len(set(a["phase"] for a in campaign["timeline"])),
            "total_activities": len(campaign["timeline"]),
            "unique_tools": len(set(campaign["tools_used"])),
            "unique_techniques": len(set(campaign["techniques_used"])),
            "duration_minutes": (
                datetime.fromisoformat(campaign["end_time"]) -
                datetime.fromisoformat(campaign["start_time"])
            ).total_seconds() / 60
        }
    
    def _profile_to_dict(self, profile: APTProfile) -> Dict:
        """Convert profile to dictionary"""
        return {
            "name": profile.name,
            "aliases": profile.aliases,
            "country": profile.country,
            "attribution": profile.attribution,
            "active_since": profile.active_since,
            "motivation": profile.motivation,
            "sophistication": profile.sophistication,
            "operational_security": profile.operational_security
        }
    
    def _save_campaign_report(self, campaign: Dict):
        """Save campaign emulation report"""
        filename = f"threat_emulation_{campaign['actor']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(campaign, f, indent=2)
        
        print(f"\n   💾 Campaign report saved: {filepath}")
    
    def compare_with_real_campaign(self, campaign_data: Dict, known_campaign: str) -> Dict:
        """Compare emulated campaign with known real-world campaign"""
        comparison = {
            "emulated_campaign": campaign_data["actor"],
            "known_campaign": known_campaign,
            "similarity_score": 0,
            "matching_ttps": [],
            "missing_ttps": [],
            "additional_ttps": [],
            "recommendations": []
        }
        
        # This would compare against known campaign data
        # Placeholder for actual comparison logic
        
        return comparison
