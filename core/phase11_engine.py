"""
Phase 11 Engine: IoT & Embedded Systems Security Testing
========================================================

Main orchestration engine for comprehensive IoT and embedded systems assessment.

Combines:
- IoT device discovery (Shodan, Censys, UPnP, firmware analysis)
- Embedded system analysis (UART/JTAG, firmware reverse engineering)
- ICS/SCADA exploitation (Modbus, DNP3, OPC, PLC manipulation)
- Wireless protocol exploitation (WiFi, Bluetooth, Zigbee, Z-Wave, LoRaWAN, 5G)

⚠️ CRITICAL AUTHORIZATION WARNING
==================================
This engine combines EXTREMELY POWERFUL and DANGEROUS capabilities:
- Can control industrial equipment
- Can disrupt critical infrastructure
- Can interfere with wireless spectrum
- Can cause physical damage and safety hazards

NEVER run without:
- Explicit written authorization
- Isolated test environment
- Safety system verification
- Emergency shutdown procedures
- Legal review and compliance

Unauthorized use is ILLEGAL and DANGEROUS.
"""

import asyncio
import logging
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from .iot_device_discovery import IoTDeviceDiscovery, IoTDevice
from .embedded_system_analysis import EmbeddedSystemAnalyzer, EmbeddedSystem, Architecture
from .ics_scada_exploitation import ICSExploiter, ICSDevice
from .wireless_protocol_exploitation import WirelessExploiter


logger = logging.getLogger(__name__)


class Phase11Engine:
    """
    Main orchestration engine for Phase 11: IoT & Embedded Systems.
    
    Runs comprehensive security assessment across all IoT attack surfaces:
    1. IoT Device Discovery
    2. Embedded System Analysis
    3. ICS/SCADA Exploitation
    4. Wireless Protocol Exploitation
    """
    
    def __init__(self, 
                 shodan_key: Optional[str] = None,
                 censys_id: Optional[str] = None,
                 censys_secret: Optional[str] = None):
        """
        Initialize Phase 11 engine.
        
        Args:
            shodan_key: Shodan API key (optional)
            censys_id: Censys API ID (optional)
            censys_secret: Censys API secret (optional)
        """
        self.iot_discovery = IoTDeviceDiscovery(shodan_key, censys_id, censys_secret)
        self.embedded_analyzer = EmbeddedSystemAnalyzer()
        self.ics_exploiter = ICSExploiter()
        self.wireless_exploiter = WirelessExploiter()
        
        logger.info("Phase 11 Engine initialized")
    
    async def run_full_assessment(self,
                                  target_network: Optional[str] = None,
                                  embedded_device: Optional[EmbeddedSystem] = None,
                                  firmware_path: Optional[str] = None,
                                  ics_network: Optional[str] = None,
                                  wireless_scan: bool = True) -> Dict[str, Any]:
        """
        Run comprehensive IoT & embedded systems security assessment.
        
        ⚠️ WARNING: This performs active security testing!
        Only run with explicit authorization.
        
        Args:
            target_network: Network to scan for IoT devices (CIDR notation)
            embedded_device: EmbeddedSystem object to analyze
            firmware_path: Path to firmware image to analyze
            ics_network: ICS/SCADA network to assess
            wireless_scan: Whether to perform wireless assessment
        
        Returns:
            Comprehensive assessment results dictionary
        """
        logger.critical("="*70)
        logger.critical("PHASE 11: IOT & EMBEDDED SYSTEMS SECURITY ASSESSMENT")
        logger.critical("="*70)
        logger.critical("⚠️  AUTHORIZATION VERIFICATION REQUIRED")
        logger.critical("⚠️  This assessment can affect physical systems")
        logger.critical("⚠️  Ensure proper authorization and safety measures")
        logger.critical("="*70)
        
        results = {
            "phase": "Phase 11: IoT & Embedded Systems",
            "assessment_time": datetime.now().isoformat(),
            "configuration": {
                "target_network": target_network,
                "ics_network": ics_network,
                "firmware_analysis": firmware_path is not None,
                "wireless_scan": wireless_scan,
            },
            "iot_discovery": None,
            "embedded_analysis": None,
            "ics_assessment": None,
            "wireless_assessment": None,
            "integrated_scenarios": [],
            "critical_findings": [],
            "risk_summary": {},
            "recommendations": [],
        }
        
        # Phase 1: IoT Device Discovery
        logger.info("\n" + "="*70)
        logger.info("PHASE 1: IoT DEVICE DISCOVERY")
        logger.info("="*70)
        results["iot_discovery"] = await self._run_iot_discovery(target_network, firmware_path)
        
        # Phase 2: Embedded System Analysis
        if embedded_device or firmware_path:
            logger.info("\n" + "="*70)
            logger.info("PHASE 2: EMBEDDED SYSTEM ANALYSIS")
            logger.info("="*70)
            results["embedded_analysis"] = await self._run_embedded_analysis(
                embedded_device, firmware_path
            )
        
        # Phase 3: ICS/SCADA Assessment
        if ics_network:
            logger.info("\n" + "="*70)
            logger.info("PHASE 3: ICS/SCADA SECURITY ASSESSMENT")
            logger.info("="*70)
            logger.critical("⚠️  CRITICAL: ICS systems control physical processes")
            logger.critical("⚠️  Ensure isolated test environment and safety measures")
            results["ics_assessment"] = await self._run_ics_assessment(ics_network)
        
        # Phase 4: Wireless Protocol Assessment
        if wireless_scan:
            logger.info("\n" + "="*70)
            logger.info("PHASE 4: WIRELESS PROTOCOL EXPLOITATION")
            logger.info("="*70)
            logger.warning("⚠️  Wireless testing may violate regulations")
            logger.warning("⚠️  Ensure proper authorization and RF shielding if needed")
            results["wireless_assessment"] = await self._run_wireless_assessment()
        
        # Phase 5: Generate Integrated Attack Scenarios
        logger.info("\n" + "="*70)
        logger.info("PHASE 5: INTEGRATED ATTACK SCENARIO GENERATION")
        logger.info("="*70)
        results["integrated_scenarios"] = self._generate_integrated_scenarios(results)
        
        # Generate risk summary
        results["risk_summary"] = self._calculate_risk_summary(results)
        
        # Identify critical findings
        results["critical_findings"] = self._identify_critical_findings(results)
        
        # Generate comprehensive recommendations
        results["recommendations"] = self._generate_comprehensive_recommendations(results)
        
        logger.info("\n" + "="*70)
        logger.info("PHASE 11 ASSESSMENT COMPLETE")
        logger.info(f"Critical Findings: {len(results['critical_findings'])}")
        logger.info(f"Overall Risk: {results['risk_summary'].get('overall_risk', 'UNKNOWN')}")
        logger.info("="*70)
        
        return results
    
    async def _run_iot_discovery(self, target_network: Optional[str], 
                                 firmware_path: Optional[str]) -> Dict[str, Any]:
        """Run IoT device discovery phase"""
        results = await self.iot_discovery.run_full_discovery(target_network)
        
        # Analyze firmware if provided
        if firmware_path:
            logger.info(f"Analyzing firmware: {firmware_path}")
            firmware_analysis = await self.iot_discovery.analyze_firmware(firmware_path)
            results["firmware_analysis"] = {
                "filename": firmware_analysis.filename if firmware_analysis else None,
                "architecture": firmware_analysis.architecture if firmware_analysis else None,
                "vulnerabilities": firmware_analysis.vulnerabilities if firmware_analysis else [],
                "hardcoded_credentials": firmware_analysis.hardcoded_credentials if firmware_analysis else [],
                "crypto_keys": firmware_analysis.crypto_keys if firmware_analysis else [],
                "backdoors": firmware_analysis.backdoors if firmware_analysis else [],
            } if firmware_analysis else None
        
        logger.info(f"IoT Discovery: {len(results['devices_found'])} devices found")
        return results
    
    async def _run_embedded_analysis(self, device: Optional[EmbeddedSystem],
                                     firmware_path: Optional[str]) -> Dict[str, Any]:
        """Run embedded system analysis phase"""
        # Create default device if not provided
        if not device and firmware_path:
            device = EmbeddedSystem(
                device_name="Analyzed Firmware",
                architecture=Architecture.ARM,
            )
        
        if not device:
            return {"error": "No device or firmware provided"}
        
        results = await self.embedded_analyzer.run_full_analysis(device, firmware_path)
        
        logger.info(f"Embedded Analysis: Risk level {results['overall_risk']}")
        return results
    
    async def _run_ics_assessment(self, ics_network: str) -> Dict[str, Any]:
        """Run ICS/SCADA assessment phase"""
        results = await self.ics_exploiter.run_full_assessment(ics_network)
        
        logger.warning(f"ICS Assessment: {len(results['devices_found'])} ICS devices found")
        logger.critical(f"Critical findings: {len(results['critical_findings'])}")
        
        return results
    
    async def _run_wireless_assessment(self) -> Dict[str, Any]:
        """Run wireless protocol exploitation phase"""
        results = await self.wireless_exploiter.run_full_assessment()
        
        total_devices = (
            len(results['wifi_networks']) +
            len(results['bluetooth_devices']) +
            len(results['zigbee_devices']) +
            len(results['zwave_devices']) +
            len(results['lorawan_devices'])
        )
        
        logger.info(f"Wireless Assessment: {total_devices} devices found across all protocols")
        return results
    
    def _generate_integrated_scenarios(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate integrated attack scenarios combining multiple techniques.
        
        Shows how IoT/embedded/ICS/wireless attacks can be chained together.
        """
        logger.info("Generating integrated attack scenarios...")
        
        scenarios = []
        
        # Scenario 1: Smart Building Compromise
        if results.get("iot_discovery") and results.get("wireless_assessment"):
            scenarios.append({
                "name": "Smart Building Complete Compromise",
                "description": "Multi-stage attack on smart building infrastructure",
                "phases": [
                    {
                        "phase": 1,
                        "action": "WiFi network compromise",
                        "method": "WPA2 handshake capture and offline cracking",
                        "outcome": "Network access obtained",
                    },
                    {
                        "phase": 2,
                        "action": "IoT device discovery",
                        "method": "UPnP scanning and Shodan correlation",
                        "outcome": "Smart locks, cameras, HVAC identified",
                    },
                    {
                        "phase": 3,
                        "action": "Zigbee network compromise",
                        "method": "Extract network key via insecure rejoin",
                        "outcome": "Control of smart lights, sensors",
                    },
                    {
                        "phase": 4,
                        "action": "Z-Wave lock exploitation",
                        "method": "Replay attack on S0-secured lock",
                        "outcome": "Physical access to building",
                    },
                ],
                "impact": "Complete building control - HVAC, lighting, access control",
                "difficulty": "MEDIUM",
                "detection_likelihood": "LOW",
            })
        
        # Scenario 2: Industrial Facility Attack
        if results.get("ics_assessment"):
            scenarios.append({
                "name": "Industrial Control System Sabotage",
                "description": "Targeted attack on ICS infrastructure",
                "phases": [
                    {
                        "phase": 1,
                        "action": "Network reconnaissance",
                        "method": "Modbus/DNP3 device scanning",
                        "outcome": "PLCs and SCADA systems identified",
                    },
                    {
                        "phase": 2,
                        "action": "HMI exploitation",
                        "method": "Default credentials and web vulnerabilities",
                        "outcome": "SCADA visualization access",
                    },
                    {
                        "phase": 3,
                        "action": "PLC program download",
                        "method": "Unauthenticated Modbus access",
                        "outcome": "Ladder logic extracted",
                    },
                    {
                        "phase": 4,
                        "action": "Logic modification",
                        "method": "Disable safety interlocks, modify setpoints",
                        "outcome": "Equipment damage or safety incident",
                    },
                ],
                "impact": "CRITICAL - Equipment damage, safety hazards, production outage",
                "difficulty": "MEDIUM",
                "detection_likelihood": "MEDIUM (if monitoring in place)",
            })
        
        # Scenario 3: Medical Device Attack
        if results.get("embedded_analysis") and results.get("wireless_assessment"):
            scenarios.append({
                "name": "Medical IoT Device Exploitation",
                "description": "Attack on wireless medical devices",
                "phases": [
                    {
                        "phase": 1,
                        "action": "Bluetooth device discovery",
                        "method": "BLE scanning for medical devices",
                        "outcome": "Insulin pumps, pacemakers, monitors found",
                    },
                    {
                        "phase": 2,
                        "action": "BIAS attack",
                        "method": "Impersonate paired device without key",
                        "outcome": "Unauthorized pairing established",
                    },
                    {
                        "phase": 3,
                        "action": "Firmware extraction",
                        "method": "BLE GATT service exploitation",
                        "outcome": "Firmware downloaded via wireless",
                    },
                    {
                        "phase": 4,
                        "action": "Command injection",
                        "method": "Send unauthorized commands to device",
                        "outcome": "Device parameter modification",
                    },
                ],
                "impact": "CRITICAL - Patient safety risk, medical device malfunction",
                "difficulty": "HIGH",
                "detection_likelihood": "LOW",
            })
        
        # Scenario 4: Smart City Infrastructure
        if results.get("iot_discovery") and results.get("wireless_assessment"):
            scenarios.append({
                "name": "Smart City Infrastructure Disruption",
                "description": "Large-scale IoT attack on city systems",
                "phases": [
                    {
                        "phase": 1,
                        "action": "LoRaWAN sensor discovery",
                        "method": "Scan for parking sensors, environmental monitors",
                        "outcome": "City IoT infrastructure mapped",
                    },
                    {
                        "phase": 2,
                        "action": "Traffic light controller access",
                        "method": "Default credentials on exposed web interface",
                        "outcome": "Traffic control access",
                    },
                    {
                        "phase": 3,
                        "action": "Camera system compromise",
                        "method": "Shodan + default credentials",
                        "outcome": "Surveillance camera access",
                    },
                    {
                        "phase": 4,
                        "action": "Coordinated disruption",
                        "method": "Modify traffic patterns, disable cameras, spoof sensors",
                        "outcome": "City-wide traffic chaos and safety risks",
                    },
                ],
                "impact": "HIGH - Public safety, traffic disruption, emergency response delays",
                "difficulty": "MEDIUM",
                "detection_likelihood": "HIGH (visible impact)",
            })
        
        logger.info(f"Generated {len(scenarios)} integrated attack scenarios")
        return scenarios
    
    def _calculate_risk_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk summary"""
        summary = {
            "overall_risk": "UNKNOWN",
            "risk_score": 0,
            "device_counts": {},
            "vulnerability_counts": {},
            "safety_critical_devices": 0,
        }
        
        risk_score = 0
        
        # Count IoT devices
        if results.get("iot_discovery"):
            iot_count = len(results["iot_discovery"].get("devices_found", []))
            summary["device_counts"]["iot_devices"] = iot_count
            risk_score += min(iot_count * 2, 20)
            
            high_risk_count = len(results["iot_discovery"].get("high_risk_devices", []))
            risk_score += high_risk_count * 5
        
        # Count ICS devices (very high risk)
        if results.get("ics_assessment"):
            ics_count = len(results["ics_assessment"].get("devices_found", []))
            summary["device_counts"]["ics_devices"] = ics_count
            risk_score += ics_count * 10  # ICS devices are high risk
            
            # Safety-critical devices
            safety_critical = sum(
                1 for dev in results["ics_assessment"].get("devices_found", [])
                if hasattr(dev, 'safety_level') and dev.safety_level.value >= "sil_2"
            )
            summary["safety_critical_devices"] = safety_critical
            risk_score += safety_critical * 20
        
        # Count wireless devices
        if results.get("wireless_assessment"):
            wireless = results["wireless_assessment"]
            wireless_count = (
                len(wireless.get("wifi_networks", [])) +
                len(wireless.get("bluetooth_devices", [])) +
                len(wireless.get("zigbee_devices", [])) +
                len(wireless.get("zwave_devices", []))
            )
            summary["device_counts"]["wireless_devices"] = wireless_count
            risk_score += min(wireless_count * 3, 30)
        
        # Count embedded system vulnerabilities
        if results.get("embedded_analysis"):
            embedded_vulns = len(results["embedded_analysis"].get("firmware_analysis", {}).get("vulnerabilities", []))
            summary["vulnerability_counts"]["embedded"] = embedded_vulns
            risk_score += min(embedded_vulns * 5, 25)
        
        summary["risk_score"] = min(risk_score, 100)
        
        # Determine overall risk level
        if risk_score >= 70:
            summary["overall_risk"] = "CRITICAL"
        elif risk_score >= 50:
            summary["overall_risk"] = "HIGH"
        elif risk_score >= 30:
            summary["overall_risk"] = "MEDIUM"
        else:
            summary["overall_risk"] = "LOW"
        
        return summary
    
    def _identify_critical_findings(self, results: Dict[str, Any]) -> List[str]:
        """Identify critical security findings"""
        findings = []
        
        # IoT findings
        if results.get("iot_discovery"):
            default_creds = results["iot_discovery"].get("default_credentials_found", [])
            for cred in default_creds:
                findings.append(
                    f"CRITICAL: IoT device {cred['device']} has default credentials: "
                    f"{cred['credentials']}"
                )
        
        # ICS findings
        if results.get("ics_assessment"):
            ics_findings = results["ics_assessment"].get("critical_findings", [])
            findings.extend(ics_findings)
        
        # Embedded findings
        if results.get("embedded_analysis"):
            if results["embedded_analysis"].get("uart_exploitation", {}).get("root_shell_obtained"):
                findings.append(
                    "CRITICAL: Root shell access via UART without authentication"
                )
            if results["embedded_analysis"].get("jtag_exploitation", {}).get("exploitable"):
                findings.append(
                    "CRITICAL: JTAG debug interface accessible - firmware extraction possible"
                )
        
        # Wireless findings
        if results.get("wireless_assessment"):
            wireless = results["wireless_assessment"]
            
            # Open WiFi networks
            for network in wireless.get("wifi_networks", []):
                if network.get("security") == "open":
                    findings.append(
                        f"CRITICAL: Open WiFi network '{network['ssid']}' - no encryption"
                    )
            
            # Bluetooth vulnerabilities
            for attack in wireless.get("bluetooth_attacks", []):
                if attack.get("success") and attack.get("attack") in ["KNOB", "BIAS"]:
                    findings.append(
                        f"CRITICAL: Bluetooth {attack['attack']} attack successful on "
                        f"{attack['target']}"
                    )
        
        return findings
    
    def _generate_comprehensive_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive security recommendations"""
        recommendations = [
            "=" * 70,
            "COMPREHENSIVE SECURITY RECOMMENDATIONS",
            "=" * 70,
            "",
            "🔴 CRITICAL PRIORITIES:",
            "",
        ]
        
        # Critical ICS recommendations
        if results.get("ics_assessment"):
            recommendations.extend([
                "ICS/SCADA SECURITY (CRITICAL):",
                "- Implement network segmentation (air-gap if possible)",
                "- Deploy ICS-specific firewalls and IDS/IPS",
                "- Enable authentication on ALL ICS protocols",
                "- Change default credentials immediately",
                "- Disable remote access to safety-critical systems",
                "- Implement hardware-based safety systems",
                "- Regular security audits by qualified ICS security professionals",
                "",
            ])
        
        # IoT recommendations
        if results.get("iot_discovery"):
            recommendations.extend([
                "IoT DEVICE SECURITY:",
                "- Update all firmware to latest versions",
                "- Change default passwords (use unique 20+ character passwords)",
                "- Disable UPnP on routers",
                "- Segment IoT devices on separate VLAN",
                "- Disable unused services and ports",
                "- Implement certificate-based authentication where possible",
                "",
            ])
        
        # Embedded system recommendations
        if results.get("embedded_analysis"):
            recommendations.extend([
                "EMBEDDED SYSTEM HARDENING:",
                "- Disable debug interfaces (UART, JTAG) in production",
                "- Blow JTAG protection fuses",
                "- Enable readout protection (RDP)",
                "- Implement secure boot with signature verification",
                "- Enable all compiler security features (NX, ASLR, stack canaries)",
                "- Remove hardcoded credentials from firmware",
                "- Encrypt sensitive data in flash",
                "",
            ])
        
        # Wireless recommendations
        if results.get("wireless_assessment"):
            recommendations.extend([
                "WIRELESS SECURITY:",
                "- Migrate to WPA3 for all WiFi networks",
                "- Use 20+ character WiFi passphrases",
                "- Disable WPS (WiFi Protected Setup)",
                "- Update Bluetooth devices to patch KNOB/BIAS",
                "- Use Zigbee install codes for secure commissioning",
                "- Upgrade Z-Wave to S2 security",
                "- Validate frame counters in LoRaWAN",
                "- Disable wireless when not needed",
                "",
            ])
        
        # General recommendations
        recommendations.extend([
            "GENERAL IoT/EMBEDDED SECURITY:",
            "- Implement defense-in-depth strategy",
            "- Regular vulnerability scanning and penetration testing",
            "- Security monitoring and logging",
            "- Incident response plan for IoT/ICS incidents",
            "- Security awareness training for all personnel",
            "- Vendor security requirements in procurement",
            "- Regular firmware and software updates",
            "",
            "COMPLIANCE & GOVERNANCE:",
            "- IEC 62443 for ICS security",
            "- NIST Cybersecurity Framework",
            "- IoT Security Foundation guidelines",
            "- Industry-specific regulations (NERC CIP for power, FDA for medical)",
            "",
            "=" * 70,
        ])
        
        return recommendations
    
    def save_report(self, results: Dict[str, Any], output_path: str) -> str:
        """Save assessment report to file"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Report saved to {output_file}")
        return str(output_file)
