"""
Physical Security Analysis
Assessment of physical security controls and attack vectors
"""

import asyncio
import json
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from enum import Enum


class SecurityLevel(Enum):
    """Security level classification"""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAXIMUM = "maximum"


class AccessControlType(Enum):
    """Types of access control"""
    BADGE = "badge"
    PIN = "pin"
    BIOMETRIC = "biometric"
    KEY_CARD = "key_card"
    PHYSICAL_KEY = "physical_key"
    GUARD = "security_guard"
    NONE = "none"


@dataclass
class PhysicalLocation:
    """Physical location/facility"""
    name: str
    address: str
    facility_type: str  # office, datacenter, warehouse, etc.
    security_level: SecurityLevel
    access_controls: List[AccessControlType]
    operating_hours: Dict[str, Tuple[time, time]]
    employee_count: int
    security_guards: int = 0
    cameras: int = 0
    entry_points: int = 1


@dataclass
class BadgeSystem:
    """Badge/access card system details"""
    technology: str  # RFID, HID, magnetic stripe
    frequency: Optional[str] = None  # 125kHz, 13.56MHz for RFID
    encryption: bool = False
    clone_difficulty: str = "easy"  # easy, medium, hard
    vendor: str = "Generic"


@dataclass
class SecurityCamera:
    """Security camera details"""
    location: str
    camera_type: str  # fixed, PTZ, dome
    resolution: str
    field_of_view: int  # degrees
    night_vision: bool
    motion_detection: bool
    recording: bool
    blind_spots: List[str] = field(default_factory=list)


@dataclass
class LockSystem:
    """Door lock system"""
    lock_type: str  # pin pad, deadbolt, electronic, biometric
    vulnerabilities: List[str] = field(default_factory=list)
    bypass_methods: List[str] = field(default_factory=list)
    security_rating: int = 5  # 1-10


@dataclass
class PhysicalVulnerability:
    """Physical security vulnerability"""
    vulnerability_type: str
    severity: str  # critical, high, medium, low
    location: str
    description: str
    exploitation_method: str
    mitigation: str
    detected_at: datetime = field(default_factory=datetime.now)


class BadgeCloningStrategy:
    """
    Badge cloning and duplication strategies
    Note: For authorized physical penetration testing only
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("physical_security/badge_cloning")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def analyze_badge_system(
        self,
        badge_system: BadgeSystem
    ) -> Dict:
        """Analyze badge system vulnerabilities"""
        
        print(f"\n🎫 Analyzing badge system: {badge_system.vendor}")
        print(f"   Technology: {badge_system.technology}")
        
        analysis = {
            "technology": badge_system.technology,
            "vendor": badge_system.vendor,
            "vulnerability_rating": 0,
            "cloning_methods": [],
            "required_equipment": [],
            "success_probability": 0.0,
            "detection_risk": ""
        }
        
        # Analyze based on technology
        if badge_system.technology == "RFID":
            analysis.update(self._analyze_rfid(badge_system))
        elif badge_system.technology == "HID":
            analysis.update(self._analyze_hid(badge_system))
        elif badge_system.technology == "magnetic_stripe":
            analysis.update(self._analyze_magstripe(badge_system))
        elif badge_system.technology == "NFC":
            analysis.update(self._analyze_nfc(badge_system))
        
        # Save analysis
        self._save_analysis(badge_system, analysis)
        
        return analysis
    
    def _analyze_rfid(self, badge: BadgeSystem) -> Dict:
        """Analyze RFID badge system"""
        
        freq = badge.frequency or "125kHz"
        
        if freq == "125kHz":
            # Low frequency - easier to clone
            return {
                "vulnerability_rating": 8,
                "cloning_methods": [
                    "Proxmark3 RFID cloner",
                    "HID ProxCard cloner",
                    "Physical card duplication"
                ],
                "required_equipment": [
                    "Proxmark3 device ($300)",
                    "LF RFID reader",
                    "Blank 125kHz cards",
                    "Laptop with software"
                ],
                "success_probability": 0.85,
                "detection_risk": "Low - passive reading, no logs",
                "attack_steps": [
                    "1. Proximity read of target badge (< 4 inches)",
                    "2. Clone card ID to blank card",
                    "3. Test cloned card on access point",
                    "4. Access granted"
                ]
            }
        
        elif freq == "13.56MHz":
            # High frequency - more difficult
            return {
                "vulnerability_rating": 5,
                "cloning_methods": [
                    "MIFARE Classic crack (if applicable)",
                    "Proxmark3 with HF antenna",
                    "Chameleon Mini emulation"
                ],
                "required_equipment": [
                    "Proxmark3 with HF support",
                    "Chameleon Mini",
                    "ACR122U reader",
                    "Cryptanalysis software"
                ],
                "success_probability": 0.6 if not badge.encryption else 0.3,
                "detection_risk": "Medium - may trigger anomaly detection",
                "attack_steps": [
                    "1. Read badge using HF reader",
                    "2. Decrypt keys if encrypted (MIFARE crypto1)",
                    "3. Clone or emulate badge",
                    "4. Present to reader"
                ]
            }
        
        return {"vulnerability_rating": 6, "success_probability": 0.7}
    
    def _analyze_hid(self, badge: BadgeSystem) -> Dict:
        """Analyze HID Prox/iCLASS systems"""
        return {
            "vulnerability_rating": 7,
            "cloning_methods": [
                "HID Prox card cloning",
                "iCLASS key diversification attack",
                "Man-in-the-middle relay"
            ],
            "required_equipment": [
                "HID card programmer",
                "Proxmark3",
                "iCLASS reader/writer"
            ],
            "success_probability": 0.75,
            "detection_risk": "Low to Medium",
            "notes": "iCLASS SE/Seos have stronger encryption"
        }
    
    def _analyze_magstripe(self, badge: BadgeSystem) -> Dict:
        """Analyze magnetic stripe systems"""
        return {
            "vulnerability_rating": 9,
            "cloning_methods": [
                "MSR605X magnetic stripe reader/writer",
                "Portable skimmer device",
                "Manual encoding"
            ],
            "required_equipment": [
                "Magnetic stripe reader/writer ($150)",
                "Blank cards",
                "Software (e.g., MSR Tools)"
            ],
            "success_probability": 0.95,
            "detection_risk": "Very Low",
            "attack_steps": [
                "1. Swipe target card on reader",
                "2. Capture track data",
                "3. Write to blank card",
                "4. Use cloned card"
            ],
            "notes": "Magnetic stripe is legacy tech - very vulnerable"
        }
    
    def _analyze_nfc(self, badge: BadgeSystem) -> Dict:
        """Analyze NFC badge systems"""
        return {
            "vulnerability_rating": 6,
            "cloning_methods": [
                "NFC reader app (smartphone)",
                "Proxmark3 NFC mode",
                "NFCGate relay attack"
            ],
            "required_equipment": [
                "NFC-enabled smartphone",
                "NFC Tools Pro app",
                "Blank NFC tags",
                "Optional: Proxmark3"
            ],
            "success_probability": 0.65,
            "detection_risk": "Medium",
            "notes": "Depends on NFC tag type and encryption"
        }
    
    def generate_cloning_procedure(
        self,
        badge_system: BadgeSystem,
        scenario: str = "office_access"
    ) -> Dict:
        """Generate step-by-step badge cloning procedure"""
        
        analysis = self.analyze_badge_system(badge_system)
        
        procedure = {
            "scenario": scenario,
            "objective": "Clone employee badge for unauthorized access",
            "phases": [
                {
                    "phase": "Reconnaissance",
                    "steps": [
                        "Identify badge system technology",
                        "Observe badge usage patterns",
                        "Identify target badge holder",
                        "Note reader locations"
                    ]
                },
                {
                    "phase": "Badge Acquisition",
                    "steps": [
                        "Social engineering approach to target",
                        "Proximity reading (< 4 inches for RFID)",
                        "Alternative: Tailgating to observe badge",
                        "Alternative: Dumpster diving for discarded badges"
                    ]
                },
                {
                    "phase": "Cloning",
                    "steps": analysis.get("attack_steps", [
                        "Read badge data",
                        "Write to blank card",
                        "Test functionality"
                    ])
                },
                {
                    "phase": "Access Testing",
                    "steps": [
                        "Test cloned badge during off-hours",
                        "Monitor for access logs/alerts",
                        "Proceed with authorized entry if successful"
                    ]
                }
            ],
            "equipment": analysis.get("required_equipment", []),
            "success_probability": analysis.get("success_probability", 0.5),
            "detection_risk": analysis.get("detection_risk", "Unknown")
        }
        
        return procedure
    
    def _save_analysis(self, badge_system: BadgeSystem, analysis: Dict):
        """Save badge analysis results"""
        output_file = self.output_dir / f"badge_analysis_{badge_system.vendor}_{datetime.now().strftime('%Y%m%d')}.json"
        
        with open(output_file, 'w') as f:
            json.dump({
                "badge_system": {
                    "technology": badge_system.technology,
                    "vendor": badge_system.vendor,
                    "frequency": badge_system.frequency,
                    "encrypted": badge_system.encryption
                },
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)


class TailgatingAnalyzer:
    """
    Analyze tailgating opportunities and social engineering access
    """
    
    def __init__(self):
        self.opportunities: List[Dict] = []
        
    def analyze_entry_points(
        self,
        location: PhysicalLocation
    ) -> List[Dict]:
        """Analyze tailgating opportunities at entry points"""
        
        print(f"\n🚪 Analyzing tailgating opportunities: {location.name}")
        
        opportunities = []
        
        # Analyze each entry point
        for i in range(location.entry_points):
            entry_name = f"Entrance {i+1}"
            
            opportunity = {
                "entry_point": entry_name,
                "security_level": location.security_level.value,
                "access_control": [ac.value for ac in location.access_controls],
                "guard_present": location.security_guards > 0,
                "camera_coverage": location.cameras > (i * 2),
                "tailgating_difficulty": "",
                "success_probability": 0.0,
                "recommended_time": "",
                "recommended_approach": []
            }
            
            # Calculate difficulty and success probability
            difficulty_score = 0
            
            if AccessControlType.GUARD in location.access_controls:
                difficulty_score += 4
            if AccessControlType.BIOMETRIC in location.access_controls:
                difficulty_score += 3
            if location.cameras > 5:
                difficulty_score += 2
            if location.security_level in [SecurityLevel.HIGH, SecurityLevel.MAXIMUM]:
                difficulty_score += 3
            
            if difficulty_score >= 8:
                opportunity["tailgating_difficulty"] = "Very Hard"
                opportunity["success_probability"] = 0.15
            elif difficulty_score >= 5:
                opportunity["tailgating_difficulty"] = "Hard"
                opportunity["success_probability"] = 0.35
            elif difficulty_score >= 3:
                opportunity["tailgating_difficulty"] = "Medium"
                opportunity["success_probability"] = 0.60
            else:
                opportunity["tailgating_difficulty"] = "Easy"
                opportunity["success_probability"] = 0.85
            
            # Recommended timing
            opportunity["recommended_time"] = self._recommend_timing(location)
            
            # Recommended approach
            opportunity["recommended_approach"] = self._recommend_approach(opportunity)
            
            opportunities.append(opportunity)
        
        self.opportunities.extend(opportunities)
        
        for opp in opportunities:
            print(f"   • {opp['entry_point']}: {opp['tailgating_difficulty']} "
                  f"(Success: {opp['success_probability']:.0%})")
        
        return opportunities
    
    def _recommend_timing(self, location: PhysicalLocation) -> str:
        """Recommend best time for tailgating"""
        timings = []
        
        # Peak hours when employees are rushing
        timings.append("8:00-9:00 AM (morning rush)")
        timings.append("12:00-1:00 PM (lunch return)")
        
        if location.security_guards < 2:
            timings.append("After 6:00 PM (reduced security)")
        
        return ", ".join(timings)
    
    def _recommend_approach(self, opportunity: Dict) -> List[str]:
        """Recommend tailgating approach strategies"""
        approaches = []
        
        # Universal approaches
        approaches.append("Carry boxes/packages (hands full excuse)")
        approaches.append("Follow closely behind employee")
        approaches.append("Pretend to be on phone call (distracted)")
        
        # Difficulty-specific
        if opportunity["tailgating_difficulty"] in ["Easy", "Medium"]:
            approaches.append("Smile and thank holder who holds door")
            approaches.append("Wear visitor badge from previous day")
        
        if opportunity["guard_present"]:
            approaches.append("Dress professionally (blend in)")
            approaches.append("Pretend to know employee ahead")
        
        if not opportunity["camera_coverage"]:
            approaches.append("Use side/back entrance")
        
        return approaches
    
    def generate_tailgating_scenario(
        self,
        location: PhysicalLocation,
        objective: str = "access server room"
    ) -> Dict:
        """Generate complete tailgating scenario"""
        
        opportunities = self.analyze_entry_points(location)
        best_opportunity = max(opportunities, key=lambda x: x["success_probability"])
        
        scenario = {
            "objective": objective,
            "target_location": location.name,
            "entry_point": best_opportunity["entry_point"],
            "execution_plan": {
                "preparation": [
                    "Research target company culture/dress code",
                    "Prepare prop (laptop bag, delivery package, etc.)",
                    "Scout entry points during business hours",
                    "Identify employee patterns"
                ],
                "execution": [
                    f"Arrive at {best_opportunity['recommended_time'].split(',')[0]}",
                    "Position near entry point",
                    "Wait for employee to approach",
                    "Follow employee through access control",
                    "Act natural - confident and belonging",
                    "If challenged: 'I'm new, forgot my badge at home'"
                ],
                "contingencies": [
                    "If stopped by guard: 'Meeting with [common name]'",
                    "If badge required: 'Visiting from [sister office]'",
                    "If questioned: Leave and try different entry/time"
                ]
            },
            "success_probability": best_opportunity["success_probability"],
            "risk_level": "Medium" if best_opportunity["guard_present"] else "Low"
        }
        
        return scenario


class CameraBlindSpotDetector:
    """
    Identify security camera blind spots
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("physical_security/camera_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def analyze_camera_coverage(
        self,
        location: PhysicalLocation,
        cameras: List[SecurityCamera]
    ) -> Dict:
        """Analyze camera coverage and identify blind spots"""
        
        print(f"\n📹 Analyzing camera coverage: {location.name}")
        print(f"   Total cameras: {len(cameras)}")
        
        analysis = {
            "total_cameras": len(cameras),
            "coverage_areas": [],
            "blind_spots": [],
            "vulnerable_zones": [],
            "evasion_routes": []
        }
        
        # Analyze each camera
        for camera in cameras:
            coverage = {
                "location": camera.location,
                "type": camera.camera_type,
                "fov": camera.field_of_view,
                "capabilities": {
                    "night_vision": camera.night_vision,
                    "motion_detection": camera.motion_detection,
                    "recording": camera.recording
                }
            }
            analysis["coverage_areas"].append(coverage)
        
        # Identify blind spots
        blind_spots = self._identify_blind_spots(cameras)
        analysis["blind_spots"] = blind_spots
        
        # Identify vulnerable zones
        vulnerable_zones = self._identify_vulnerable_zones(cameras)
        analysis["vulnerable_zones"] = vulnerable_zones
        
        # Generate evasion routes
        evasion_routes = self._generate_evasion_routes(blind_spots, vulnerable_zones)
        analysis["evasion_routes"] = evasion_routes
        
        print(f"   ✓ Identified {len(blind_spots)} blind spots")
        print(f"   ✓ Identified {len(vulnerable_zones)} vulnerable zones")
        print(f"   ✓ Generated {len(evasion_routes)} evasion routes")
        
        # Save analysis
        self._save_camera_analysis(location, analysis)
        
        return analysis
    
    def _identify_blind_spots(self, cameras: List[SecurityCamera]) -> List[Dict]:
        """Identify blind spots in camera coverage"""
        blind_spots = []
        
        # Common blind spot areas
        common_blind_spots = [
            "Directly below camera mount",
            "Behind support columns/pillars",
            "Corners with limited FOV overlap",
            "Areas blocked by furniture/equipment",
            "Stairwell landings",
            "Loading dock areas",
            "Parking garage corners"
        ]
        
        # Determine which exist based on camera coverage
        covered_locations = {cam.location.lower() for cam in cameras}
        
        for spot in common_blind_spots:
            # Simple heuristic: if not explicitly covered, it's a blind spot
            is_covered = any(
                loc_word in spot.lower()
                for loc_word in covered_locations
            )
            
            if not is_covered or len(cameras) < 5:
                blind_spots.append({
                    "location": spot,
                    "risk_level": random.choice(["Medium", "High"]),
                    "exploitation": f"Approach from {spot} to avoid detection"
                })
        
        return blind_spots
    
    def _identify_vulnerable_zones(self, cameras: List[SecurityCamera]) -> List[Dict]:
        """Identify zones with weak camera coverage"""
        vulnerable = []
        
        for camera in cameras:
            vulnerabilities = []
            
            # Check for known vulnerabilities
            if not camera.night_vision:
                vulnerabilities.append("No night vision - dark areas exploitable")
            
            if not camera.motion_detection:
                vulnerabilities.append("No motion detection - slow movement undetected")
            
            if not camera.recording:
                vulnerabilities.append("No recording - real-time monitoring only")
            
            if camera.field_of_view < 90:
                vulnerabilities.append("Narrow FOV - easy to stay out of frame")
            
            if vulnerabilities:
                vulnerable.append({
                    "camera_location": camera.location,
                    "vulnerabilities": vulnerabilities
                })
        
        return vulnerable
    
    def _generate_evasion_routes(
        self,
        blind_spots: List[Dict],
        vulnerable_zones: List[Dict]
    ) -> List[Dict]:
        """Generate routes to evade camera detection"""
        routes = []
        
        if blind_spots:
            routes.append({
                "route_name": "Blind Spot Exploitation Route",
                "waypoints": [spot["location"] for spot in blind_spots[:3]],
                "technique": "Move through identified blind spots",
                "success_probability": 0.75
            })
        
        if vulnerable_zones:
            routes.append({
                "route_name": "Vulnerable Zone Route",
                "waypoints": ["Entry"] + [z["camera_location"] for z in vulnerable_zones[:2]] + ["Target"],
                "technique": "Exploit camera weaknesses (e.g., no night vision after dark)",
                "success_probability": 0.60
            })
        
        # Universal evasion techniques
        routes.append({
            "route_name": "Head-Down Evasion",
            "waypoints": ["Any route"],
            "technique": "Keep head down, wear hat/hood to obscure face",
            "success_probability": 0.50
        })
        
        return routes
    
    def _save_camera_analysis(self, location: PhysicalLocation, analysis: Dict):
        """Save camera analysis"""
        output_file = self.output_dir / f"camera_analysis_{location.name}_{datetime.now().strftime('%Y%m%d')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(analysis, f, indent=2)


class LockVulnerabilityAssessor:
    """
    Assess lock vulnerabilities from images/descriptions
    """
    
    def __init__(self):
        self.assessments: List[Dict] = []
        
    def assess_lock(
        self,
        lock_system: LockSystem
    ) -> Dict:
        """Assess lock vulnerabilities and bypass methods"""
        
        print(f"\n🔐 Assessing lock: {lock_system.lock_type}")
        
        assessment = {
            "lock_type": lock_system.lock_type,
            "security_rating": lock_system.security_rating,
            "vulnerabilities": [],
            "bypass_methods": [],
            "required_tools": [],
            "skill_level": "",
            "time_estimate": ""
        }
        
        # Analyze based on lock type
        if lock_system.lock_type == "pin_pad":
            assessment.update(self._assess_pin_pad())
        elif lock_system.lock_type == "deadbolt":
            assessment.update(self._assess_deadbolt())
        elif lock_system.lock_type == "electronic":
            assessment.update(self._assess_electronic())
        elif lock_system.lock_type == "biometric":
            assessment.update(self._assess_biometric())
        elif lock_system.lock_type == "standard_key":
            assessment.update(self._assess_standard_key())
        
        self.assessments.append(assessment)
        
        print(f"   Security Rating: {assessment['security_rating']}/10")
        print(f"   Vulnerabilities: {len(assessment['vulnerabilities'])}")
        print(f"   Bypass Methods: {len(assessment['bypass_methods'])}")
        
        return assessment
    
    def _assess_pin_pad(self) -> Dict:
        """Assess PIN pad locks"""
        return {
            "vulnerabilities": [
                "Worn keys indicate common digits",
                "Thermal imaging shows recently pressed keys",
                "Shoulder surfing during code entry",
                "Default/weak PINs (1234, 0000)",
                "No lockout after failed attempts"
            ],
            "bypass_methods": [
                "Thermal imaging attack (within 60 seconds of use)",
                "Brute force common PINs",
                "Social engineering to obtain code",
                "Shimming door gap if poorly installed"
            ],
            "required_tools": [
                "FLIR thermal camera ($200-$5000)",
                "Lockpicking tools (if physical bypass available)",
                "Or: Social engineering (no tools)"
            ],
            "skill_level": "Beginner to Intermediate",
            "time_estimate": "1-30 minutes",
            "security_rating": 4
        }
    
    def _assess_deadbolt(self) -> Dict:
        """Assess deadbolt locks"""
        return {
            "vulnerabilities": [
                "Picking vulnerable if low-security cylinder",
                "Bumping attack possible",
                "Drilling attack on cheap locks",
                "Short throw (can be shimmed)",
                "Exposed screws (can be removed)"
            ],
            "bypass_methods": [
                "Lock picking (raking or single-pin picking)",
                "Bump key attack",
                "Drilling the cylinder",
                "Shimming if short throw",
                "Impressioning"
            ],
            "required_tools": [
                "Lock pick set ($20-$100)",
                "Bump keys ($10-$50)",
                "Drill and bits ($50+)",
                "Tension wrenches",
                "Shim tools"
            ],
            "skill_level": "Intermediate",
            "time_estimate": "2-20 minutes (depending on skill and lock quality)",
            "security_rating": 6
        }
    
    def _assess_electronic(self) -> Dict:
        """Assess electronic locks"""
        return {
            "vulnerabilities": [
                "Weak default credentials",
                "Unencrypted communication protocols",
                "Physical tampering detection absent",
                "Battery bypass possible",
                "Firmware vulnerabilities"
            ],
            "bypass_methods": [
                "Default credential attack",
                "Replay attack on RF signals",
                "Jamming/interference",
                "Physical battery/power bypass",
                "Exploit firmware vulnerabilities"
            ],
            "required_tools": [
                "SDR (Software Defined Radio) ($20-$300)",
                "Logic analyzer",
                "Multimeter",
                "Screwdrivers for physical access"
            ],
            "skill_level": "Advanced",
            "time_estimate": "10 minutes - 2 hours",
            "security_rating": 5
        }
    
    def _assess_biometric(self) -> Dict:
        """Assess biometric locks"""
        return {
            "vulnerabilities": [
                "Fingerprint spoofing with lifted prints",
                "Low-quality sensor vulnerable to fake",
                "Photo attack for facial recognition",
                "Iris scan vulnerable to photos/contacts",
                "Physical override keyhole"
            ],
            "bypass_methods": [
                "Fingerprint mold from lifted print",
                "High-res photo for facial recognition",
                "Thermal imaging to see recent fingerprints",
                "Pick physical backup keyhole",
                "Disassembly and direct wiring"
            ],
            "required_tools": [
                "Fingerprint lifting kit",
                "Gel/Play-Doh for molds",
                "High-res camera",
                "Lock picks (for backup)",
                "Electronics tools"
            ],
            "skill_level": "Advanced",
            "time_estimate": "30 minutes - several hours",
            "security_rating": 7
        }
    
    def _assess_standard_key(self) -> Dict:
        """Assess standard key locks"""
        return {
            "vulnerabilities": [
                "Simple pin tumbler design",
                "No security pins",
                "Wide keyway easy to pick",
                "Bumpable",
                "Can be impressioned"
            ],
            "bypass_methods": [
                "Lock picking (SPP or raking)",
                "Bump key",
                "Impressioning",
                "Decoder tools",
                "Key duplication from photo"
            ],
            "required_tools": [
                "Basic lock pick set ($15-$50)",
                "Bump keys",
                "Tension wrenches",
                "Impressioning blank and file"
            ],
            "skill_level": "Beginner to Intermediate",
            "time_estimate": "30 seconds - 10 minutes",
            "security_rating": 3
        }


class USBDropCampaign:
    """
    Plan and execute USB drop campaigns
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("physical_security/usb_drops")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def plan_campaign(
        self,
        target_location: PhysicalLocation,
        usb_count: int = 10,
        payload_type: str = "credential_harvester"
    ) -> Dict:
        """Plan USB drop campaign"""
        
        print(f"\n💾 Planning USB drop campaign")
        print(f"   Location: {target_location.name}")
        print(f"   USB devices: {usb_count}")
        print(f"   Payload: {payload_type}")
        
        campaign = {
            "target": target_location.name,
            "usb_count": usb_count,
            "payload_type": payload_type,
            "drop_locations": self._identify_drop_locations(target_location),
            "usb_configuration": self._configure_usb(payload_type),
            "social_engineering": self._usb_social_engineering(),
            "success_metrics": {
                "target_pickup_rate": "15-30%",
                "target_plugin_rate": "45-60% of pickups",
                "expected_compromises": int(usb_count * 0.15 * 0.5)
            }
        }
        
        # Save campaign plan
        self._save_campaign(campaign)
        
        return campaign
    
    def _identify_drop_locations(self, location: PhysicalLocation) -> List[Dict]:
        """Identify strategic USB drop locations"""
        locations = [
            {
                "location": "Parking lot (near employee vehicles)",
                "rationale": "High foot traffic, employees assume dropped by coworker",
                "pickup_probability": 0.30
            },
            {
                "location": "Reception/lobby area",
                "rationale": "Visible, appears to belong to visitor",
                "pickup_probability": 0.25
            },
            {
                "location": "Break room / Kitchen",
                "rationale": "Employees congregate, casual environment",
                "pickup_probability": 0.35
            },
            {
                "location": "Conference rooms",
                "rationale": "Before meeting, appears forgotten by attendee",
                "pickup_probability": 0.20
            },
            {
                "location": "Near printers/copy machines",
                "rationale": "Common area, plausible it belongs there",
                "pickup_probability": 0.25
            }
        ]
        
        return locations
    
    def _configure_usb(self, payload_type: str) -> Dict:
        """Configure USB payload"""
        payloads = {
            "credential_harvester": {
                "type": "HID Keyboard Emulation",
                "hardware": "USB Rubber Ducky / Bash Bunny",
                "payload_description": "Emulates keyboard, types PowerShell to harvest credentials",
                "execution_time": "< 5 seconds",
                "stealth_features": [
                    "Closes windows after execution",
                    "Clears run history",
                    "No visible indicators"
                ]
            },
            "reverse_shell": {
                "type": "Mass Storage + AutoRun",
                "hardware": "Custom USB with autorun.inf",
                "payload_description": "Establishes reverse shell on insertion",
                "execution_time": "< 10 seconds",
                "stealth_features": [
                    "Disguised as firmware update",
                    "Background execution",
                    "Persistence mechanism"
                ]
            },
            "network_implant": {
                "type": "Passive Network Tap",
                "hardware": "Packet Squirrel / LAN Turtle",
                "payload_description": "Creates covert network tunnel",
                "execution_time": "Continuous",
                "stealth_features": [
                    "Appears as network adapter",
                    "Passive monitoring",
                    "Remote access capability"
                ]
            }
        }
        
        return payloads.get(payload_type, payloads["credential_harvester"])
    
    def _usb_social_engineering(self) -> Dict:
        """Social engineering aspects of USB drops"""
        return {
            "labeling_strategies": [
                "\"Executive Salaries 2024 - CONFIDENTIAL\"",
                "\"Layoff List - DO NOT SHARE\"",
                "\"HR - Employee Complaints\"",
                "\"Q4 Bonus Structure\"",
                "\"IT Security Audit Results\"",
                "\"[CEO Name] - Personal\"",
                "\"Resume - [Common Name]\"",
                "\"Photos - Holiday Party\""
            ],
            "physical_appearance": [
                "Corporate branded USB (mimics company swag)",
                "Expensive-looking USB (curiosity factor)",
                "Worn/used appearance (trusted, not suspicious)",
                "Attached to keychain (appears personal)"
            ],
            "timing": [
                "Monday morning (weekend lost items)",
                "After company events (appears forgotten)",
                "During busy periods (less scrutiny)"
            ],
            "psychological_triggers": [
                "Curiosity (What's on it?)",
                "Helpfulness (Return to owner)",
                "Greed (Financial information)",
                "Fear (Layoff lists, security issues)"
            ]
        }
    
    def _save_campaign(self, campaign: Dict):
        """Save campaign plan"""
        output_file = self.output_dir / f"usb_campaign_{datetime.now().strftime('%Y%m%d')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(campaign, f, indent=2)
        
        print(f"   💾 Campaign saved: {output_file}")


class PhysicalSecurityAnalyzer:
    """
    Comprehensive physical security analysis engine
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("physical_security/assessments")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.badge_cloning = BadgeCloningStrategy(self.output_dir / "badge_cloning")
        self.tailgating = TailgatingAnalyzer()
        self.camera_analyzer = CameraBlindSpotDetector(self.output_dir / "cameras")
        self.lock_assessor = LockVulnerabilityAssessor()
        self.usb_campaign = USBDropCampaign(self.output_dir / "usb_drops")
        
        self.vulnerabilities: List[PhysicalVulnerability] = []
        
    async def analyze_facility(
        self,
        location: PhysicalLocation,
        badge_system: Optional[BadgeSystem] = None,
        cameras: Optional[List[SecurityCamera]] = None,
        locks: Optional[List[LockSystem]] = None
    ) -> Dict:
        """Comprehensive facility security analysis"""
        
        print(f"\n🏢 Analyzing Physical Security: {location.name}")
        print(f"   Address: {location.address}")
        print(f"   Security Level: {location.security_level.value}")
        
        analysis = {
            "location": location.name,
            "security_level": location.security_level.value,
            "access_control_analysis": {},
            "tailgating_analysis": {},
            "camera_analysis": {},
            "lock_analysis": [],
            "overall_vulnerabilities": [],
            "attack_scenarios": [],
            "recommendations": []
        }
        
        # Badge system analysis
        if badge_system:
            analysis["access_control_analysis"] = self.badge_cloning.analyze_badge_system(badge_system)
        
        # Tailgating analysis
        analysis["tailgating_analysis"] = self.tailgating.analyze_entry_points(location)
        
        # Camera coverage analysis
        if cameras:
            analysis["camera_analysis"] = self.camera_analyzer.analyze_camera_coverage(location, cameras)
        
        # Lock assessments
        if locks:
            for lock in locks:
                lock_assessment = self.lock_assessor.assess_lock(lock)
                analysis["lock_analysis"].append(lock_assessment)
        
        # Identify overall vulnerabilities
        vulnerabilities = self._identify_vulnerabilities(analysis)
        analysis["overall_vulnerabilities"] = vulnerabilities
        
        # Generate attack scenarios
        scenarios = self._generate_attack_scenarios(location, analysis)
        analysis["attack_scenarios"] = scenarios
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis)
        analysis["recommendations"] = recommendations
        
        # Save comprehensive report
        self._save_analysis(location, analysis)
        
        return analysis
    
    def _identify_vulnerabilities(self, analysis: Dict) -> List[Dict]:
        """Identify overall physical security vulnerabilities"""
        vulnerabilities = []
        
        # Badge cloning vulnerabilities
        if "access_control_analysis" in analysis:
            ac_analysis = analysis["access_control_analysis"]
            if ac_analysis.get("vulnerability_rating", 0) >= 7:
                vulnerabilities.append({
                    "type": "Badge Cloning",
                    "severity": "High",
                    "description": "Badge system highly vulnerable to cloning attacks",
                    "impact": "Unauthorized physical access to facility"
                })
        
        # Tailgating vulnerabilities
        for tailgate in analysis.get("tailgating_analysis", []):
            if tailgate.get("success_probability", 0) >= 0.6:
                vulnerabilities.append({
                    "type": "Tailgating",
                    "severity": "Medium",
                    "description": f"High tailgating success at {tailgate['entry_point']}",
                    "impact": "Unauthorized entry via social engineering"
                })
        
        # Camera blind spots
        blind_spots = analysis.get("camera_analysis", {}).get("blind_spots", [])
        if len(blind_spots) >= 3:
            vulnerabilities.append({
                "type": "Camera Blind Spots",
                "severity": "Medium",
                "description": f"{len(blind_spots)} blind spots identified in camera coverage",
                "impact": "Unmonitored areas allow covert movement"
            })
        
        # Weak locks
        for lock in analysis.get("lock_analysis", []):
            if lock.get("security_rating", 10) <= 4:
                vulnerabilities.append({
                    "type": "Weak Lock Security",
                    "severity": "High" if lock["security_rating"] <= 3 else "Medium",
                    "description": f"{lock['lock_type']} lock easily bypassable",
                    "impact": "Physical access to restricted areas"
                })
        
        return vulnerabilities
    
    def _generate_attack_scenarios(self, location: PhysicalLocation, analysis: Dict) -> List[Dict]:
        """Generate realistic attack scenarios"""
        scenarios = []
        
        # Scenario 1: Badge cloning + Tailgating
        scenarios.append({
            "name": "Sophisticated Entry Attack",
            "phases": [
                "Reconnaissance: Observe employee badge usage for 2-3 days",
                "Badge Acquisition: Clone badge via proximity reading in cafeteria",
                "Entry: Use cloned badge during peak hours (8:30 AM)",
                "Fallback: If badge fails, tailgate through same entrance",
                "Objective: Access server room or sensitive areas"
            ],
            "success_probability": 0.70,
            "detection_risk": "Medium"
        })
        
        # Scenario 2: USB drop campaign
        scenarios.append({
            "name": "USB Drop Campaign",
            "phases": [
                "Preparation: Create 10 weaponized USBs with enticing labels",
                "Distribution: Drop in parking lot and break room",
                "Waiting: Monitor for callback from payload",
                "Exploitation: Use initial access for lateral movement"
            ],
            "success_probability": 0.45,
            "detection_risk": "Low"
        })
        
        # Scenario 3: After-hours physical access
        if location.security_guards < 2:
            scenarios.append({
                "name": "After-Hours Intrusion",
                "phases": [
                    "Timing: Arrive after 8 PM when security is minimal",
                    "Entry: Exploit camera blind spots identified",
                    "Lock Bypass: Pick/shim weak locks on side entrance",
                    "Objective: Install rogue access point or exfiltrate data"
                ],
                "success_probability": 0.55,
                "detection_risk": "Medium"
            })
        
        return scenarios
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Access control recommendations
        if "access_control_analysis" in analysis:
            ac = analysis["access_control_analysis"]
            if ac.get("vulnerability_rating", 0) >= 7:
                recommendations.append(
                    "Upgrade to high-frequency (13.56MHz) encrypted badges (iCLASS SE or MIFARE DESFire)"
                )
                recommendations.append(
                    "Implement multi-factor authentication (badge + PIN/biometric)"
                )
        
        # Tailgating recommendations
        tailgate_success = [t.get("success_probability", 0) for t in analysis.get("tailgating_analysis", [])]
        if max(tailgate_success, default=0) >= 0.6:
            recommendations.append(
                "Install mantrap/turnstile systems at main entrances"
            )
            recommendations.append(
                "Increase security guard presence during peak hours"
            )
            recommendations.append(
                "Conduct employee awareness training on tailgating risks"
            )
        
        # Camera recommendations
        blind_spots = analysis.get("camera_analysis", {}).get("blind_spots", [])
        if len(blind_spots) >= 3:
            recommendations.append(
                f"Install additional cameras to cover {len(blind_spots)} identified blind spots"
            )
            recommendations.append(
                "Implement 360-degree cameras in critical areas"
            )
        
        # Lock recommendations
        weak_locks = [l for l in analysis.get("lock_analysis", []) if l.get("security_rating", 10) <= 4]
        if weak_locks:
            recommendations.append(
                "Replace weak locks with Grade 1 deadbolts or electronic access control"
            )
            recommendations.append(
                "Install alarm systems on critical doors"
            )
        
        # USB drop recommendations
        recommendations.append(
            "Implement USB device control policies (whitelist authorized devices)"
        )
        recommendations.append(
            "Conduct security awareness training on USB drop attacks"
        )
        
        return recommendations
    
    def _save_analysis(self, location: PhysicalLocation, analysis: Dict):
        """Save comprehensive analysis"""
        output_file = self.output_dir / f"physical_security_assessment_{location.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump({
                "facility": {
                    "name": location.name,
                    "address": location.address,
                    "type": location.facility_type,
                    "security_level": location.security_level.value
                },
                "analysis": analysis,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        
        print(f"\n   📄 Comprehensive analysis saved: {output_file}")
