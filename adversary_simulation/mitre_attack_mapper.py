"""
MITRE ATT&CK Framework Integration
Maps all actions to ATT&CK framework and executes specific TTPs
"""

import asyncio
import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import requests


@dataclass
class Technique:
    """MITRE ATT&CK Technique"""
    id: str
    name: str
    tactic: str
    description: str
    platforms: List[str]
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    mitigations: List[str] = field(default_factory=list)
    
    
@dataclass
class TTP:
    """Tactics, Techniques, and Procedures"""
    tactic: str
    technique: Technique
    procedure: str
    tools: List[str] = field(default_factory=list)
    executed: bool = False
    timestamp: Optional[datetime] = None
    evidence: List[str] = field(default_factory=list)


class MITREAttackMapper:
    """
    Maps security operations to MITRE ATT&CK framework
    Provides comprehensive ATT&CK matrix integration
    """
    
    def __init__(self, attack_data_path: Optional[Path] = None):
        self.attack_data_path = attack_data_path or Path("knowledge/mitre_attack")
        self.techniques: Dict[str, Technique] = {}
        self.tactics: Dict[str, List[str]] = {}
        self.executed_ttps: List[TTP] = []
        self.attack_matrix = self._load_attack_matrix()
        
    def _load_attack_matrix(self) -> Dict:
        """Load MITRE ATT&CK matrix data"""
        # Create comprehensive ATT&CK mapping
        matrix = {
            "reconnaissance": {
                "T1595": {
                    "name": "Active Scanning",
                    "description": "Adversaries may execute active reconnaissance scans",
                    "platforms": ["PRE"],
                    "data_sources": ["Network Traffic"]
                },
                "T1592": {
                    "name": "Gather Victim Host Information",
                    "description": "Adversaries may gather information about victim hosts",
                    "platforms": ["PRE"],
                    "data_sources": ["Internet Scan"]
                },
                "T1589": {
                    "name": "Gather Victim Identity Information",
                    "description": "Adversaries may gather information about victim identities",
                    "platforms": ["PRE"],
                    "data_sources": ["Social Media"]
                }
            },
            "resource_development": {
                "T1583": {
                    "name": "Acquire Infrastructure",
                    "description": "Adversaries may acquire infrastructure for operations",
                    "platforms": ["PRE"],
                    "data_sources": ["Internet Scan", "Domain Registration"]
                },
                "T1587": {
                    "name": "Develop Capabilities",
                    "description": "Adversaries may develop capabilities for operations",
                    "platforms": ["PRE"],
                    "data_sources": ["Malware Repository"]
                }
            },
            "initial_access": {
                "T1190": {
                    "name": "Exploit Public-Facing Application",
                    "description": "Adversaries may exploit vulnerabilities in public applications",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Application Log", "Network Traffic"]
                },
                "T1566": {
                    "name": "Phishing",
                    "description": "Adversaries may send phishing messages",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Email Gateway", "Application Log"]
                },
                "T1078": {
                    "name": "Valid Accounts",
                    "description": "Adversaries may obtain and abuse credentials",
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Authentication Logs", "Logon Session"]
                }
            },
            "execution": {
                "T1059": {
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command interpreters",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command"]
                },
                "T1106": {
                    "name": "Native API",
                    "description": "Adversaries may interact with Windows API",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Module"]
                },
                "T1053": {
                    "name": "Scheduled Task/Job",
                    "description": "Adversaries may abuse task scheduling",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Scheduled Job", "Process", "Command"]
                }
            },
            "persistence": {
                "T1547": {
                    "name": "Boot or Logon Autostart Execution",
                    "description": "Adversaries may configure autostart execution",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Windows Registry"]
                },
                "T1053": {
                    "name": "Scheduled Task/Job",
                    "description": "Adversaries may abuse task scheduling",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Scheduled Job", "Process"]
                },
                "T1136": {
                    "name": "Create Account",
                    "description": "Adversaries may create accounts",
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["User Account", "Command"]
                }
            },
            "privilege_escalation": {
                "T1068": {
                    "name": "Exploitation for Privilege Escalation",
                    "description": "Adversaries may exploit vulnerabilities for privilege escalation",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Application Log"]
                },
                "T1134": {
                    "name": "Access Token Manipulation",
                    "description": "Adversaries may modify access tokens",
                    "platforms": ["Windows"],
                    "data_sources": ["Process", "Command"]
                },
                "T1078": {
                    "name": "Valid Accounts",
                    "description": "Adversaries may obtain privileged accounts",
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Authentication Logs", "Logon Session"]
                }
            },
            "defense_evasion": {
                "T1070": {
                    "name": "Indicator Removal",
                    "description": "Adversaries may delete or modify artifacts",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Command"]
                },
                "T1055": {
                    "name": "Process Injection",
                    "description": "Adversaries may inject code into processes",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Module"]
                },
                "T1027": {
                    "name": "Obfuscated Files or Information",
                    "description": "Adversaries may obfuscate files or information",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Script"]
                }
            },
            "credential_access": {
                "T1003": {
                    "name": "OS Credential Dumping",
                    "description": "Adversaries may dump credentials",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command", "File"]
                },
                "T1110": {
                    "name": "Brute Force",
                    "description": "Adversaries may use brute force techniques",
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Authentication Logs", "Application Log"]
                },
                "T1056": {
                    "name": "Input Capture",
                    "description": "Adversaries may capture user input",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Driver"]
                }
            },
            "discovery": {
                "T1087": {
                    "name": "Account Discovery",
                    "description": "Adversaries may discover accounts",
                    "platforms": ["Windows", "Linux", "macOS", "Cloud"],
                    "data_sources": ["Process", "Command", "File"]
                },
                "T1083": {
                    "name": "File and Directory Discovery",
                    "description": "Adversaries may enumerate files and directories",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command", "File"]
                },
                "T1135": {
                    "name": "Network Share Discovery",
                    "description": "Adversaries may look for network shares",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command", "Network Traffic"]
                }
            },
            "lateral_movement": {
                "T1021": {
                    "name": "Remote Services",
                    "description": "Adversaries may use remote services",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "Logon Session", "Process"]
                },
                "T1091": {
                    "name": "Replication Through Removable Media",
                    "description": "Adversaries may move through removable media",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Drive"]
                }
            },
            "collection": {
                "T1560": {
                    "name": "Archive Collected Data",
                    "description": "Adversaries may archive collected data",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Command"]
                },
                "T1113": {
                    "name": "Screen Capture",
                    "description": "Adversaries may capture screen content",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command"]
                },
                "T1005": {
                    "name": "Data from Local System",
                    "description": "Adversaries may search local system sources",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Command"]
                }
            },
            "command_and_control": {
                "T1071": {
                    "name": "Application Layer Protocol",
                    "description": "Adversaries may use application layer protocols",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic"]
                },
                "T1132": {
                    "name": "Data Encoding",
                    "description": "Adversaries may encode data",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic"]
                },
                "T1573": {
                    "name": "Encrypted Channel",
                    "description": "Adversaries may use encrypted channels",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic"]
                }
            },
            "exfiltration": {
                "T1041": {
                    "name": "Exfiltration Over C2 Channel",
                    "description": "Adversaries may exfiltrate over C2 channel",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "Command"]
                },
                "T1048": {
                    "name": "Exfiltration Over Alternative Protocol",
                    "description": "Adversaries may exfiltrate over alternative protocols",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "File"]
                },
                "T1567": {
                    "name": "Exfiltration Over Web Service",
                    "description": "Adversaries may use web services for exfiltration",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Network Traffic", "File"]
                }
            },
            "impact": {
                "T1486": {
                    "name": "Data Encrypted for Impact",
                    "description": "Adversaries may encrypt data",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["File", "Process", "Command"]
                },
                "T1490": {
                    "name": "Inhibit System Recovery",
                    "description": "Adversaries may inhibit system recovery",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Command", "File"]
                },
                "T1489": {
                    "name": "Service Stop",
                    "description": "Adversaries may stop services",
                    "platforms": ["Windows", "Linux", "macOS"],
                    "data_sources": ["Process", "Service", "Command"]
                }
            }
        }
        
        # Load techniques into structured format
        for tactic, techniques in matrix.items():
            self.tactics[tactic] = list(techniques.keys())
            for tid, tdata in techniques.items():
                self.techniques[tid] = Technique(
                    id=tid,
                    name=tdata["name"],
                    tactic=tactic,
                    description=tdata["description"],
                    platforms=tdata["platforms"],
                    data_sources=tdata.get("data_sources", [])
                )
        
        return matrix
    
    def map_action_to_attack(self, action: str, context: Dict) -> List[str]:
        """Map an action to MITRE ATT&CK techniques"""
        mappings = []
        
        action_lower = action.lower()
        
        # Reconnaissance
        if any(k in action_lower for k in ['scan', 'enumerate', 'recon']):
            mappings.extend(['T1595', 'T1592'])
        
        # Initial Access
        if any(k in action_lower for k in ['exploit', 'phish', 'vulnerability']):
            mappings.extend(['T1190', 'T1566'])
        
        # Execution
        if any(k in action_lower for k in ['execute', 'command', 'script', 'powershell']):
            mappings.extend(['T1059', 'T1106'])
        
        # Persistence
        if any(k in action_lower for k in ['persist', 'autostart', 'scheduled']):
            mappings.extend(['T1547', 'T1053'])
        
        # Privilege Escalation
        if any(k in action_lower for k in ['escalate', 'privilege', 'token']):
            mappings.extend(['T1068', 'T1134'])
        
        # Defense Evasion
        if any(k in action_lower for k in ['evade', 'obfuscate', 'hide', 'inject']):
            mappings.extend(['T1070', 'T1055', 'T1027'])
        
        # Credential Access
        if any(k in action_lower for k in ['credential', 'dump', 'mimikatz', 'password']):
            mappings.extend(['T1003', 'T1110'])
        
        # Discovery
        if any(k in action_lower for k in ['discover', 'find', 'search']):
            mappings.extend(['T1087', 'T1083', 'T1135'])
        
        # Lateral Movement
        if any(k in action_lower for k in ['lateral', 'move', 'remote']):
            mappings.append('T1021')
        
        # Collection
        if any(k in action_lower for k in ['collect', 'archive', 'capture']):
            mappings.extend(['T1560', 'T1113', 'T1005'])
        
        # Command and Control
        if any(k in action_lower for k in ['c2', 'command', 'beacon']):
            mappings.extend(['T1071', 'T1573'])
        
        # Exfiltration
        if any(k in action_lower for k in ['exfil', 'steal', 'transmit']):
            mappings.extend(['T1041', 'T1048'])
        
        # Impact
        if any(k in action_lower for k in ['encrypt', 'ransom', 'destroy']):
            mappings.extend(['T1486', 'T1490'])
        
        return list(set(mappings))
    
    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get technique details by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Technique]:
        """Get all techniques for a specific tactic"""
        technique_ids = self.tactics.get(tactic, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def create_ttp(self, technique_id: str, procedure: str, tools: List[str] = None) -> Optional[TTP]:
        """Create a TTP from technique"""
        technique = self.get_technique(technique_id)
        if not technique:
            return None
        
        return TTP(
            tactic=technique.tactic,
            technique=technique,
            procedure=procedure,
            tools=tools or []
        )
    
    def record_ttp_execution(self, ttp: TTP, evidence: List[str] = None):
        """Record execution of a TTP"""
        ttp.executed = True
        ttp.timestamp = datetime.now()
        ttp.evidence = evidence or []
        self.executed_ttps.append(ttp)
    
    def get_coverage_matrix(self) -> Dict[str, Dict]:
        """Generate ATT&CK coverage matrix"""
        coverage = {}
        
        for tactic in self.tactics.keys():
            executed_count = sum(
                1 for ttp in self.executed_ttps
                if ttp.tactic == tactic
            )
            total_count = len(self.tactics[tactic])
            
            coverage[tactic] = {
                "total_techniques": total_count,
                "executed_techniques": executed_count,
                "coverage_percentage": (executed_count / total_count * 100) if total_count > 0 else 0,
                "techniques": [
                    {
                        "id": tid,
                        "name": self.techniques[tid].name,
                        "executed": any(ttp.technique.id == tid for ttp in self.executed_ttps)
                    }
                    for tid in self.tactics[tactic]
                ]
            }
        
        return coverage
    
    def generate_navigator_layer(self, output_path: Path):
        """Generate ATT&CK Navigator layer JSON"""
        techniques_list = []
        
        for ttp in self.executed_ttps:
            techniques_list.append({
                "techniqueID": ttp.technique.id,
                "tactic": ttp.tactic,
                "score": 1,
                "color": "#ff6666",
                "comment": f"Executed: {ttp.procedure}",
                "enabled": True,
                "metadata": [
                    {"name": "timestamp", "value": ttp.timestamp.isoformat() if ttp.timestamp else ""},
                    {"name": "tools", "value": ", ".join(ttp.tools)}
                ]
            })
        
        layer = {
            "name": "Red Team Campaign",
            "versions": {
                "attack": "13",
                "navigator": "4.8.0",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": "Executed TTPs from red team engagement",
            "techniques": techniques_list
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(layer, f, indent=2)
        
        return layer


class APTEmulator:
    """
    Emulate APT group behaviors and campaigns
    """
    
    def __init__(self, attack_mapper: MITREAttackMapper):
        self.attack_mapper = attack_mapper
        self.apt_profiles = self._load_apt_profiles()
    
    def _load_apt_profiles(self) -> Dict:
        """Load APT group profiles with their typical TTPs"""
        return {
            "APT28": {
                "name": "Fancy Bear",
                "country": "Russia",
                "description": "Russian military intelligence",
                "typical_ttps": [
                    ("T1566", "Spearphishing with malicious attachments"),
                    ("T1059", "PowerShell and command-line execution"),
                    ("T1003", "Credential dumping with Mimikatz"),
                    ("T1021", "Lateral movement via RDP and SMB"),
                    ("T1041", "Exfiltration over C2 channel")
                ],
                "tools": ["XAgent", "Sofacy", "Mimikatz", "PowerShell Empire"],
                "targets": ["Government", "Military", "Critical Infrastructure"]
            },
            "APT29": {
                "name": "Cozy Bear",
                "country": "Russia",
                "description": "Russian intelligence service",
                "typical_ttps": [
                    ("T1566", "Spearphishing links"),
                    ("T1059", "PowerShell execution"),
                    ("T1027", "Code obfuscation"),
                    ("T1055", "Process injection"),
                    ("T1071", "HTTP/HTTPS C2 communication")
                ],
                "tools": ["CozyDuke", "MiniDuke", "PowerDuke", "SeaDuke"],
                "targets": ["Government", "Think Tanks", "Technology"]
            },
            "Lazarus": {
                "name": "Lazarus Group",
                "country": "North Korea",
                "description": "North Korean state-sponsored",
                "typical_ttps": [
                    ("T1566", "Spearphishing with malicious documents"),
                    ("T1059", "Command and scripting interpreters"),
                    ("T1070", "Indicator removal on host"),
                    ("T1486", "Data encryption for ransom"),
                    ("T1567", "Exfiltration over web services")
                ],
                "tools": ["WannaCry", "DTrack", "BLINDINGCAN", "PowerRatankba"],
                "targets": ["Financial", "Cryptocurrency", "Defense"]
            },
            "APT38": {
                "name": "APT38",
                "country": "North Korea",
                "description": "North Korean financial cybercrime",
                "typical_ttps": [
                    ("T1190", "Exploit public-facing applications"),
                    ("T1078", "Valid account usage"),
                    ("T1136", "Account creation"),
                    ("T1490", "Inhibit system recovery"),
                    ("T1048", "Alternative protocol exfiltration")
                ],
                "tools": ["DYEPACK", "SHUTDOWNCK", "VIVACIOUSGIFT"],
                "targets": ["Financial", "SWIFT", "Banking"]
            },
            "APT41": {
                "name": "Double Dragon",
                "country": "China",
                "description": "Chinese state-sponsored espionage and crime",
                "typical_ttps": [
                    ("T1190", "Web application exploitation"),
                    ("T1505", "Web shell deployment"),
                    ("T1003", "Credential dumping"),
                    ("T1560", "Data archiving"),
                    ("T1048", "Exfiltration over alternative protocols")
                ],
                "tools": ["HIGHNOON", "LOWKEY", "MESSAGETAP", "POISONPLUG"],
                "targets": ["Healthcare", "Telecommunications", "Gaming"]
            }
        }
    
    async def emulate_apt_campaign(self, apt_name: str, target_env: Dict) -> Dict:
        """Emulate a full APT campaign"""
        if apt_name not in self.apt_profiles:
            raise ValueError(f"Unknown APT: {apt_name}")
        
        profile = self.apt_profiles[apt_name]
        campaign_results = {
            "apt": apt_name,
            "profile": profile,
            "executed_ttps": [],
            "timeline": [],
            "success_rate": 0
        }
        
        print(f"\n🎯 Emulating {profile['name']} ({apt_name}) Campaign")
        print(f"   Origin: {profile['country']}")
        print(f"   Description: {profile['description']}")
        
        successful_ttps = 0
        
        for technique_id, procedure in profile["typical_ttps"]:
            ttp = self.attack_mapper.create_ttp(
                technique_id,
                procedure,
                profile["tools"]
            )
            
            if ttp:
                # Simulate TTP execution
                success = await self._execute_ttp(ttp, target_env)
                
                if success:
                    self.attack_mapper.record_ttp_execution(
                        ttp,
                        evidence=[f"Simulated {apt_name} technique"]
                    )
                    successful_ttps += 1
                
                campaign_results["executed_ttps"].append({
                    "technique": ttp.technique.id,
                    "name": ttp.technique.name,
                    "procedure": procedure,
                    "success": success,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Simulate realistic timing between TTPs
                await asyncio.sleep(2)
        
        campaign_results["success_rate"] = (
            successful_ttps / len(profile["typical_ttps"]) * 100
        )
        
        return campaign_results
    
    async def _execute_ttp(self, ttp: TTP, target_env: Dict) -> bool:
        """Simulate execution of a TTP"""
        print(f"   ⚡ Executing {ttp.technique.id}: {ttp.technique.name}")
        print(f"      Procedure: {ttp.procedure}")
        
        # Simulated execution logic
        # In real implementation, would actually execute the technique
        await asyncio.sleep(1)
        
        # Simulate 85% success rate
        import random
        return random.random() < 0.85


class TTPs:
    """Helper class for common TTP patterns"""
    
    @staticmethod
    def killchain_sequence() -> List[Tuple[str, str]]:
        """Standard cyber kill chain TTP sequence"""
        return [
            ("T1595", "Active scanning for reconnaissance"),
            ("T1190", "Exploit public-facing application"),
            ("T1059", "Execute command interpreter"),
            ("T1547", "Establish persistence via autostart"),
            ("T1068", "Escalate privileges via exploit"),
            ("T1003", "Dump credentials"),
            ("T1087", "Discover accounts"),
            ("T1021", "Lateral movement via remote services"),
            ("T1560", "Archive collected data"),
            ("T1041", "Exfiltrate over C2 channel")
        ]
    
    @staticmethod
    def ransomware_sequence() -> List[Tuple[str, str]]:
        """Ransomware attack TTP sequence"""
        return [
            ("T1566", "Phishing for initial access"),
            ("T1059", "Execute malicious script"),
            ("T1547", "Establish persistence"),
            ("T1134", "Token manipulation for privilege escalation"),
            ("T1070", "Clear logs and indicators"),
            ("T1083", "File and directory discovery"),
            ("T1490", "Inhibit system recovery"),
            ("T1486", "Encrypt data for impact"),
            ("T1491", "Deface systems"),
            ("T1489", "Stop critical services")
        ]
    
    @staticmethod
    def apt_espionage_sequence() -> List[Tuple[str, str]]:
        """APT espionage campaign TTP sequence"""
        return [
            ("T1566", "Spearphishing attachment"),
            ("T1059", "PowerShell execution"),
            ("T1027", "Obfuscated payload"),
            ("T1055", "Process injection for stealth"),
            ("T1003", "Credential access"),
            ("T1087", "Account discovery"),
            ("T1083", "Sensitive file discovery"),
            ("T1560", "Archive collected intelligence"),
            ("T1071", "Application layer protocol C2"),
            ("T1048", "Exfiltration over alternative protocol")
        ]
