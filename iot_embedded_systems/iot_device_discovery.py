"""
IoT Device Discovery Module
===========================

Automated discovery and reconnaissance of IoT devices using:
- Shodan/Censys integration for exposed device scanning
- UPnP exploitation for local network discovery
- Default credential testing
- Firmware extraction and analysis

⚠️ AUTHORIZATION REQUIRED: Only scan networks and devices you own or have permission to test.
"""

import asyncio
import logging
import re
import hashlib
import json
import binascii
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp
from pathlib import Path


logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Types of IoT devices"""
    CAMERA = "camera"
    ROUTER = "router"
    SMART_HOME = "smart_home"
    INDUSTRIAL = "industrial"
    MEDICAL = "medical"
    PRINTER = "printer"
    NAS = "nas"
    UNKNOWN = "unknown"


class FirmwareType(Enum):
    """Firmware file formats"""
    BIN = "bin"
    HEX = "hex"
    ELF = "elf"
    SQUASHFS = "squashfs"
    JFFS2 = "jffs2"
    CRAMFS = "cramfs"
    UBIFS = "ubifs"
    UNKNOWN = "unknown"


@dataclass
class IoTDevice:
    """Represents a discovered IoT device"""
    ip_address: str
    hostname: Optional[str] = None
    device_type: DeviceType = DeviceType.UNKNOWN
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    default_credentials: List[Tuple[str, str]] = field(default_factory=list)
    upnp_services: List[Dict[str, Any]] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.now)
    shodan_data: Optional[Dict] = None
    risk_score: float = 0.0


@dataclass
class FirmwareImage:
    """Represents extracted firmware"""
    filename: str
    file_hash: str
    file_type: FirmwareType
    size_bytes: int
    architecture: Optional[str] = None
    extracted_files: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    hardcoded_credentials: List[Tuple[str, str]] = field(default_factory=list)
    crypto_keys: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    backdoors: List[str] = field(default_factory=list)


class ShodanScanner:
    """
    Shodan integration for IoT device discovery.
    
    ⚠️ WARNING: Requires valid Shodan API key. Only search for devices you are authorized to test.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        
    async def search_devices(self, query: str, limit: int = 100) -> List[IoTDevice]:
        """
        Search for IoT devices using Shodan queries.
        
        Example queries:
        - "port:8080 country:US"
        - "webcam"
        - "default password"
        - "mqtt"
        """
        logger.info(f"Searching Shodan for: {query}")
        
        if not self.api_key:
            logger.warning("No Shodan API key provided - using simulated results")
            return self._simulate_shodan_search(query, limit)
        
        devices = []
        
        # In real implementation, would call Shodan API
        # For this example, we simulate the search
        devices = self._simulate_shodan_search(query, limit)
        
        logger.info(f"Found {len(devices)} devices matching query")
        return devices
    
    def _simulate_shodan_search(self, query: str, limit: int) -> List[IoTDevice]:
        """Simulate Shodan search results"""
        devices = []
        
        # Simulate finding various IoT devices
        device_templates = [
            {
                "ip": "192.168.1.100",
                "type": DeviceType.CAMERA,
                "manufacturer": "Hikvision",
                "model": "DS-2CD2032-I",
                "ports": [80, 554, 8000],
                "services": {80: "http", 554: "rtsp", 8000: "http-alt"},
                "vulns": ["CVE-2017-7921", "Default credentials"],
            },
            {
                "ip": "10.0.0.50",
                "type": DeviceType.ROUTER,
                "manufacturer": "TP-Link",
                "model": "Archer C7",
                "ports": [80, 443, 8080],
                "services": {80: "http", 443: "https", 8080: "http-proxy"},
                "vulns": ["CVE-2020-10882", "UPnP enabled"],
            },
            {
                "ip": "172.16.0.20",
                "type": DeviceType.SMART_HOME,
                "manufacturer": "Philips",
                "model": "Hue Bridge",
                "ports": [80, 443, 1900],
                "services": {80: "http", 443: "https", 1900: "upnp"},
                "vulns": ["Unauthenticated API"],
            },
            {
                "ip": "192.168.1.200",
                "type": DeviceType.INDUSTRIAL,
                "manufacturer": "Siemens",
                "model": "S7-1200",
                "ports": [102, 502],
                "services": {102: "s7comm", 502: "modbus"},
                "vulns": ["No authentication", "Default credentials"],
            },
        ]
        
        for i, template in enumerate(device_templates[:limit]):
            device = IoTDevice(
                ip_address=template["ip"],
                device_type=template["type"],
                manufacturer=template["manufacturer"],
                model=template["model"],
                open_ports=template["ports"],
                services=template["services"],
                vulnerabilities=template["vulns"],
                shodan_data={"query": query, "simulated": True}
            )
            
            # Calculate risk score
            device.risk_score = self._calculate_risk_score(device)
            devices.append(device)
        
        return devices
    
    def _calculate_risk_score(self, device: IoTDevice) -> float:
        """Calculate risk score (0-100) for a device"""
        score = 0.0
        
        # Open ports contribute to risk
        score += min(len(device.open_ports) * 5, 20)
        
        # Known vulnerabilities
        score += min(len(device.vulnerabilities) * 15, 40)
        
        # Default credentials
        score += min(len(device.default_credentials) * 20, 30)
        
        # Industrial devices are higher risk
        if device.device_type == DeviceType.INDUSTRIAL:
            score += 10
        
        return min(score, 100.0)


class CensysScanner:
    """
    Censys integration for IoT device discovery.
    
    Alternative to Shodan with focus on certificate and TLS analysis.
    """
    
    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id
        self.api_secret = api_secret
        self.base_url = "https://search.censys.io/api/v2"
    
    async def search_devices(self, query: str, limit: int = 100) -> List[IoTDevice]:
        """Search for devices using Censys"""
        logger.info(f"Searching Censys for: {query}")
        
        if not self.api_id or not self.api_secret:
            logger.warning("No Censys credentials - using simulated results")
            return self._simulate_censys_search(query, limit)
        
        return self._simulate_censys_search(query, limit)
    
    def _simulate_censys_search(self, query: str, limit: int) -> List[IoTDevice]:
        """Simulate Censys search results"""
        # Similar to Shodan but focus on certificate/TLS data
        devices = []
        
        device_templates = [
            {
                "ip": "203.0.113.100",
                "type": DeviceType.CAMERA,
                "manufacturer": "Dahua",
                "model": "IPC-HFW4431R-Z",
                "ports": [443, 554],
                "services": {443: "https", 554: "rtsp"},
                "cert_cn": "DVR",
                "cert_expired": True,
            },
            {
                "ip": "198.51.100.50",
                "type": DeviceType.NAS,
                "manufacturer": "Synology",
                "model": "DS218+",
                "ports": [443, 5000, 5001],
                "services": {443: "https", 5000: "http", 5001: "https"},
                "cert_cn": "synology.local",
                "cert_expired": False,
            },
        ]
        
        for template in device_templates[:limit]:
            device = IoTDevice(
                ip_address=template["ip"],
                device_type=template["type"],
                manufacturer=template["manufacturer"],
                model=template["model"],
                open_ports=template["ports"],
                services=template["services"],
                vulnerabilities=["Expired certificate"] if template.get("cert_expired") else []
            )
            devices.append(device)
        
        return devices


class UPnPExploiter:
    """
    UPnP (Universal Plug and Play) exploitation for local network device discovery.
    
    UPnP allows devices to open ports on routers without authentication - major security risk.
    """
    
    UPNP_MULTICAST = "239.255.255.250"
    UPNP_PORT = 1900
    
    async def discover_devices(self, timeout: float = 5.0) -> List[IoTDevice]:
        """
        Discover UPnP-enabled devices on local network.
        
        Sends SSDP (Simple Service Discovery Protocol) multicast packets.
        """
        logger.info("Discovering UPnP devices...")
        
        # Simulate UPnP discovery
        devices = self._simulate_upnp_discovery()
        
        logger.info(f"Found {len(devices)} UPnP devices")
        return devices
    
    def _simulate_upnp_discovery(self) -> List[IoTDevice]:
        """Simulate UPnP device discovery"""
        devices = []
        
        upnp_devices = [
            {
                "ip": "192.168.1.1",
                "type": DeviceType.ROUTER,
                "manufacturer": "Netgear",
                "model": "R7000",
                "services": [
                    {"type": "WANIPConnection", "control_url": "/ctl/IPConn"},
                    {"type": "WANCommonInterfaceConfig", "control_url": "/ctl/CmnIfCfg"},
                ],
            },
            {
                "ip": "192.168.1.150",
                "type": DeviceType.SMART_HOME,
                "manufacturer": "Samsung",
                "model": "SmartThings Hub",
                "services": [
                    {"type": "MediaRenderer", "control_url": "/dmr/control"},
                ],
            },
        ]
        
        for dev_data in upnp_devices:
            device = IoTDevice(
                ip_address=dev_data["ip"],
                device_type=dev_data["type"],
                manufacturer=dev_data["manufacturer"],
                model=dev_data["model"],
                upnp_services=dev_data["services"],
                vulnerabilities=["UPnP enabled - port forwarding risk"]
            )
            devices.append(device)
        
        return devices
    
    async def exploit_upnp(self, device: IoTDevice) -> Dict[str, Any]:
        """
        Attempt to exploit UPnP vulnerabilities.
        
        Common attacks:
        - Port forwarding without authentication
        - SOAP injection
        - Command injection via UPnP parameters
        """
        logger.warning(f"Attempting UPnP exploitation on {device.ip_address}")
        
        results = {
            "device": device.ip_address,
            "exploitable": False,
            "port_forwards_added": [],
            "vulnerabilities_found": [],
        }
        
        # Simulate checking for common UPnP vulnerabilities
        for service in device.upnp_services:
            if service["type"] == "WANIPConnection":
                # Simulate attempting to add port forward
                results["exploitable"] = True
                results["port_forwards_added"].append({
                    "external_port": 4444,
                    "internal_ip": "192.168.1.100",
                    "internal_port": 4444,
                    "protocol": "TCP",
                    "description": "Test forward"
                })
                results["vulnerabilities_found"].append(
                    "Unauthenticated port forwarding allowed"
                )
        
        return results


class DefaultCredentialDatabase:
    """
    Database of default credentials for IoT devices.
    
    Common default credentials are a major IoT security issue.
    """
    
    def __init__(self):
        self.credentials = self._load_default_credentials()
    
    def _load_default_credentials(self) -> Dict[str, List[Tuple[str, str]]]:
        """Load database of default credentials"""
        # Common default credentials by manufacturer/device
        return {
            "hikvision": [
                ("admin", "12345"),
                ("admin", "admin"),
                ("admin", "password"),
            ],
            "dahua": [
                ("admin", "admin"),
                ("admin", ""),
                ("888888", "888888"),
            ],
            "tp-link": [
                ("admin", "admin"),
                ("admin", "password"),
            ],
            "netgear": [
                ("admin", "password"),
                ("admin", "1234"),
            ],
            "d-link": [
                ("admin", ""),
                ("admin", "admin"),
            ],
            "siemens": [
                ("admin", "admin"),
                ("Administrator", ""),
            ],
            "schneider": [
                ("USER", "USER"),
                ("Administrator", "schneider"),
            ],
            "generic": [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "12345"),
                ("root", "root"),
                ("admin", ""),
                ("root", "password"),
            ],
        }
    
    def get_credentials(self, device: IoTDevice) -> List[Tuple[str, str]]:
        """Get potential default credentials for a device"""
        creds = []
        
        # Try manufacturer-specific credentials
        if device.manufacturer:
            manufacturer_key = device.manufacturer.lower()
            creds.extend(self.credentials.get(manufacturer_key, []))
        
        # Always try generic credentials
        creds.extend(self.credentials.get("generic", []))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_creds = []
        for cred in creds:
            if cred not in seen:
                seen.add(cred)
                unique_creds.append(cred)
        
        return unique_creds
    
    async def test_credentials(self, device: IoTDevice, port: int = 80) -> List[Tuple[str, str]]:
        """
        Test default credentials against a device.
        
        ⚠️ WARNING: Only test devices you are authorized to access.
        """
        logger.info(f"Testing default credentials on {device.ip_address}:{port}")
        
        potential_creds = self.get_credentials(device)
        working_creds = []
        
        # Simulate credential testing
        # In real implementation, would attempt HTTP/SSH/Telnet authentication
        for username, password in potential_creds[:3]:  # Test first 3
            # Simulate success rate based on device type
            if device.device_type == DeviceType.CAMERA:
                # Cameras often have default credentials
                if (username, password) in [("admin", "admin"), ("admin", "12345")]:
                    working_creds.append((username, password))
                    logger.warning(f"Found working credentials: {username}:{password}")
        
        device.default_credentials = working_creds
        return working_creds


class FirmwareExtractor:
    """
    Firmware extraction and analysis.
    
    Extracts and analyzes firmware images from IoT devices to find:
    - Hardcoded credentials
    - Crypto keys
    - Vulnerabilities
    - Backdoors
    """
    
    def __init__(self):
        self.extraction_tools = {
            "binwalk": "Firmware analysis tool",
            "firmware-mod-kit": "Firmware extraction toolkit",
            "jefferson": "JFFS2 filesystem extraction",
            "ubi_reader": "UBIFS extraction",
        }
    
    async def extract_firmware(self, firmware_path: str) -> Optional[FirmwareImage]:
        """
        Extract and analyze firmware image.
        
        Steps:
        1. Identify firmware type
        2. Extract filesystem
        3. Analyze binaries
        4. Search for credentials/keys
        5. Scan for known vulnerabilities
        """
        logger.info(f"Extracting firmware: {firmware_path}")
        
        # Calculate file hash
        file_hash = self._calculate_hash(firmware_path)
        
        # Detect firmware type
        firmware_type = self._detect_firmware_type(firmware_path)
        
        # Simulate firmware extraction
        firmware = FirmwareImage(
            filename=Path(firmware_path).name,
            file_hash=file_hash,
            file_type=firmware_type,
            size_bytes=1024 * 1024 * 16,  # 16 MB
            architecture="ARM",
        )
        
        # Simulate filesystem extraction
        firmware.extracted_files = self._simulate_extraction()
        
        # Analyze extracted files
        firmware.strings = self._extract_strings(firmware.extracted_files)
        firmware.hardcoded_credentials = self._find_credentials(firmware.strings)
        firmware.crypto_keys = self._find_crypto_keys(firmware.strings)
        firmware.backdoors = self._detect_backdoors(firmware.extracted_files)
        firmware.vulnerabilities = self._scan_vulnerabilities(firmware.extracted_files)
        
        logger.info(f"Firmware analysis complete - found {len(firmware.vulnerabilities)} vulnerabilities")
        return firmware
    
    def _calculate_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        # Simulate hash calculation
        return hashlib.sha256(filepath.encode()).hexdigest()[:16]
    
    def _detect_firmware_type(self, filepath: str) -> FirmwareType:
        """Detect firmware file type"""
        # In real implementation, would use magic bytes
        path = Path(filepath)
        
        if path.suffix == ".bin":
            return FirmwareType.BIN
        elif path.suffix == ".hex":
            return FirmwareType.HEX
        else:
            return FirmwareType.UNKNOWN
    
    def _simulate_extraction(self) -> List[str]:
        """Simulate firmware extraction"""
        return [
            "/etc/passwd",
            "/etc/shadow",
            "/bin/busybox",
            "/sbin/httpd",
            "/usr/bin/telnetd",
            "/var/www/html/index.html",
            "/etc/config/wireless",
            "/etc/config/network",
        ]
    
    def _extract_strings(self, files: List[str]) -> List[str]:
        """Extract interesting strings from files"""
        return [
            "admin:$1$abcd1234$xyz789",
            "root:password123",
            "API_KEY=sk_live_abcdef123456",
            "mongodb://localhost:27017/iot_db",
            "smtp_password=mail123",
            "wifi_psk=MySecretPassword",
        ]
    
    def _find_credentials(self, strings: List[str]) -> List[Tuple[str, str]]:
        """Find hardcoded credentials in strings"""
        credentials = []
        
        for string in strings:
            # Look for username:password patterns
            if ":" in string and not string.startswith("/"):
                parts = string.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    password = parts[1].split("/")[0]  # Remove any path suffix
                    if username and password and "$" not in password:
                        credentials.append((username, password))
        
        return credentials
    
    def _find_crypto_keys(self, strings: List[str]) -> List[str]:
        """Find cryptographic keys in strings"""
        keys = []
        
        for string in strings:
            # Look for API keys, tokens, etc.
            if any(keyword in string.lower() for keyword in ["api_key", "token", "secret", "key"]):
                if "=" in string:
                    key_value = string.split("=")[1]
                    keys.append(key_value)
        
        return keys
    
    def _detect_backdoors(self, files: List[str]) -> List[str]:
        """Detect potential backdoors"""
        backdoors = []
        
        # Check for telnet daemon
        if "/usr/bin/telnetd" in files:
            backdoors.append("Telnet daemon enabled - unencrypted remote access")
        
        # Check for debug interfaces
        suspicious_files = ["/bin/debug_shell", "/sbin/uart_console"]
        for file in suspicious_files:
            if file in files:
                backdoors.append(f"Suspicious debug interface: {file}")
        
        return backdoors
    
    def _scan_vulnerabilities(self, files: List[str]) -> List[str]:
        """Scan for known vulnerabilities"""
        vulns = []
        
        # Check for outdated/vulnerable binaries
        if "/bin/busybox" in files:
            vulns.append("BusyBox detected - check version for CVE-2021-42374")
        
        # Check for weak crypto
        if "/etc/config/wireless" in files:
            vulns.append("Wireless config found - may contain WEP/weak encryption")
        
        return vulns


class IoTDeviceDiscovery:
    """
    Main orchestrator for IoT device discovery.
    
    Combines multiple discovery techniques:
    - Shodan/Censys scanning
    - UPnP discovery
    - Default credential testing
    - Firmware analysis
    """
    
    def __init__(self, shodan_key: Optional[str] = None, censys_id: Optional[str] = None,
                 censys_secret: Optional[str] = None):
        self.shodan = ShodanScanner(shodan_key)
        self.censys = CensysScanner(censys_id, censys_secret)
        self.upnp = UPnPExploiter()
        self.cred_db = DefaultCredentialDatabase()
        self.firmware_extractor = FirmwareExtractor()
    
    async def run_full_discovery(self, target_network: Optional[str] = None) -> Dict[str, Any]:
        """
        Run comprehensive IoT device discovery.
        
        Args:
            target_network: Optional CIDR network to scan (e.g., "192.168.1.0/24")
        
        Returns:
            Dictionary with discovery results
        """
        logger.info("Starting comprehensive IoT device discovery")
        
        results = {
            "scan_time": datetime.now().isoformat(),
            "target_network": target_network,
            "devices_found": [],
            "high_risk_devices": [],
            "default_credentials_found": [],
            "upnp_vulnerabilities": [],
            "firmware_analysis": [],
        }
        
        # Phase 1: Shodan scanning
        logger.info("Phase 1: Shodan device discovery")
        shodan_devices = await self.shodan.search_devices("camera OR router OR iot", limit=10)
        results["devices_found"].extend(shodan_devices)
        
        # Phase 2: Censys scanning
        logger.info("Phase 2: Censys device discovery")
        censys_devices = await self.censys.search_devices("services.tls", limit=5)
        results["devices_found"].extend(censys_devices)
        
        # Phase 3: UPnP discovery (local network)
        logger.info("Phase 3: UPnP device discovery")
        upnp_devices = await self.upnp.discover_devices()
        results["devices_found"].extend(upnp_devices)
        
        # Phase 4: Test default credentials
        logger.info("Phase 4: Testing default credentials")
        for device in results["devices_found"]:
            working_creds = await self.cred_db.test_credentials(device)
            if working_creds:
                results["default_credentials_found"].append({
                    "device": device.ip_address,
                    "manufacturer": device.manufacturer,
                    "credentials": working_creds,
                })
        
        # Phase 5: UPnP exploitation
        logger.info("Phase 5: UPnP exploitation analysis")
        for device in upnp_devices:
            exploit_result = await self.upnp.exploit_upnp(device)
            if exploit_result["exploitable"]:
                results["upnp_vulnerabilities"].append(exploit_result)
        
        # Identify high-risk devices
        results["high_risk_devices"] = [
            {
                "ip": device.ip_address,
                "type": device.device_type.value,
                "manufacturer": device.manufacturer,
                "risk_score": device.risk_score,
                "vulnerabilities": device.vulnerabilities,
            }
            for device in results["devices_found"]
            if device.risk_score >= 60.0
        ]
        
        logger.info(f"Discovery complete - found {len(results['devices_found'])} devices, "
                   f"{len(results['high_risk_devices'])} high-risk")
        
        return results
    
    async def analyze_firmware(self, firmware_path: str) -> Optional[FirmwareImage]:
        """Analyze firmware image"""
        return await self.firmware_extractor.extract_firmware(firmware_path)
