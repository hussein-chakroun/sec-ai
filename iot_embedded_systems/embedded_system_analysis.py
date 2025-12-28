"""
Embedded System Analysis Module
===============================

Hardware-level security testing for embedded systems:
- UART/JTAG interface exploitation
- Firmware reverse engineering
- Binary vulnerability analysis
- Hardware debugging interface abuse

⚠️ AUTHORIZATION REQUIRED: Only test hardware you own or have permission to modify.
Physical access to debug interfaces may void warranties or damage equipment.
"""

import asyncio
import logging
import struct
import re
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


logger = logging.getLogger(__name__)


class InterfaceType(Enum):
    """Hardware debug interface types"""
    UART = "uart"
    JTAG = "jtag"
    SWD = "swd"
    I2C = "i2c"
    SPI = "spi"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """CPU architectures"""
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    X86 = "x86"
    X86_64 = "x86_64"
    RISCV = "riscv"
    AVR = "avr"
    UNKNOWN = "unknown"


class BinaryType(Enum):
    """Binary file types"""
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach-o"
    RAW = "raw"
    UNKNOWN = "unknown"


@dataclass
class DebugInterface:
    """Represents a hardware debug interface"""
    interface_type: InterfaceType
    pin_configuration: Dict[str, int]
    voltage: float
    baud_rate: Optional[int] = None  # For UART
    accessible: bool = False
    protected: bool = False
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class EmbeddedSystem:
    """Represents an embedded system under analysis"""
    device_name: str
    manufacturer: Optional[str] = None
    architecture: Architecture = Architecture.UNKNOWN
    flash_size_kb: int = 0
    ram_size_kb: int = 0
    debug_interfaces: List[DebugInterface] = field(default_factory=list)
    firmware_version: Optional[str] = None
    bootloader_version: Optional[str] = None
    security_features: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)


class UARTExploiter:
    """
    UART (Universal Asynchronous Receiver-Transmitter) exploitation.
    
    UART is commonly exposed on embedded systems for debugging.
    Often provides root shell access with no authentication.
    """
    
    COMMON_BAUD_RATES = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
    
    def __init__(self):
        self.discovered_interfaces = []
    
    async def discover_uart(self, device: EmbeddedSystem) -> List[DebugInterface]:
        """
        Discover UART interfaces on device.
        
        Steps:
        1. Identify potential UART pins (usually 3-4 pin headers)
        2. Measure voltage (typically 3.3V or 5V)
        3. Auto-detect baud rate
        4. Attempt to access bootloader/shell
        """
        logger.info(f"Discovering UART interfaces on {device.device_name}")
        
        interfaces = []
        
        # Simulate UART discovery
        uart_configs = [
            {
                "pins": {"TX": 1, "RX": 2, "GND": 3, "VCC": 4},
                "voltage": 3.3,
                "baud": 115200,
                "accessible": True,
                "protected": False,
            },
            {
                "pins": {"TX": 10, "RX": 11, "GND": 12},
                "voltage": 3.3,
                "baud": 9600,
                "accessible": True,
                "protected": True,  # Password protected
            },
        ]
        
        for config in uart_configs:
            interface = DebugInterface(
                interface_type=InterfaceType.UART,
                pin_configuration=config["pins"],
                voltage=config["voltage"],
                baud_rate=config["baud"],
                accessible=config["accessible"],
                protected=config["protected"],
            )
            
            # Analyze vulnerabilities
            if interface.accessible and not interface.protected:
                interface.vulnerabilities.append("Unauthenticated root shell access")
                interface.vulnerabilities.append("Bootloader interrupt possible")
            
            interfaces.append(interface)
            logger.info(f"Found UART at {interface.baud_rate} baud - "
                       f"Protected: {interface.protected}")
        
        device.debug_interfaces.extend(interfaces)
        return interfaces
    
    async def exploit_uart(self, interface: DebugInterface) -> Dict[str, Any]:
        """
        Exploit UART interface.
        
        Common attacks:
        - Interrupt boot process
        - Modify boot parameters
        - Drop to root shell
        - Extract firmware
        """
        logger.warning(f"Attempting UART exploitation at {interface.baud_rate} baud")
        
        results = {
            "interface": "UART",
            "baud_rate": interface.baud_rate,
            "exploitable": False,
            "root_shell_obtained": False,
            "bootloader_access": False,
            "firmware_extracted": False,
            "output": [],
        }
        
        if not interface.accessible:
            results["output"].append("Interface not accessible")
            return results
        
        if interface.protected:
            results["output"].append("Password protection detected")
            # Simulate brute force attempt
            results["output"].append("Attempting common passwords...")
            results["output"].append("Password cracked: 'root'")
            results["exploitable"] = True
        else:
            results["exploitable"] = True
        
        if results["exploitable"]:
            # Simulate boot interrupt
            results["output"].append("Sending interrupt signal...")
            results["output"].append("U-Boot > ")
            results["bootloader_access"] = True
            
            # Simulate bootloader commands
            results["output"].append("printenv")
            results["output"].append("bootargs=console=ttyS0,115200 root=/dev/mtdblock2")
            
            # Simulate firmware extraction
            results["output"].append("md.b 0x80000000 0x1000")
            results["firmware_extracted"] = True
            
            # Simulate dropping to shell
            results["output"].append("Starting kernel...")
            results["output"].append("# ")
            results["root_shell_obtained"] = True
        
        return results
    
    def auto_detect_baud_rate(self) -> Optional[int]:
        """
        Auto-detect UART baud rate.
        
        Methods:
        - Try common baud rates
        - Analyze timing of transitions
        - Look for readable ASCII characters
        """
        logger.info("Auto-detecting UART baud rate...")
        
        # Simulate trying different baud rates
        for baud in self.COMMON_BAUD_RATES:
            # In real implementation, would read from UART and check for valid data
            if baud == 115200:  # Simulate success
                logger.info(f"Baud rate detected: {baud}")
                return baud
        
        return None


class JTAGExploiter:
    """
    JTAG (Joint Test Action Group) exploitation.
    
    JTAG provides low-level CPU debug access - more powerful than UART.
    Can:
    - Dump/modify memory
    - Set breakpoints
    - Single-step execution
    - Bypass security features
    """
    
    JTAG_PINS = ["TDI", "TDO", "TCK", "TMS", "TRST"]
    
    async def discover_jtag(self, device: EmbeddedSystem) -> List[DebugInterface]:
        """
        Discover JTAG interfaces.
        
        JTAG uses 4-5 pins: TDI, TDO, TCK, TMS, (TRST optional)
        """
        logger.info(f"Discovering JTAG interfaces on {device.device_name}")
        
        interfaces = []
        
        # Simulate JTAG discovery
        jtag_config = {
            "pins": {"TDI": 20, "TDO": 21, "TCK": 22, "TMS": 23, "TRST": 24},
            "voltage": 3.3,
            "protected": False,  # Often not protected!
        }
        
        interface = DebugInterface(
            interface_type=InterfaceType.JTAG,
            pin_configuration=jtag_config["pins"],
            voltage=jtag_config["voltage"],
            accessible=True,
            protected=jtag_config["protected"],
        )
        
        if not interface.protected:
            interface.vulnerabilities.extend([
                "Full memory read/write access",
                "CPU debug capabilities",
                "Firmware extraction possible",
                "Security bypass via debug mode",
            ])
        
        interfaces.append(interface)
        device.debug_interfaces.extend(interfaces)
        
        logger.info(f"Found JTAG interface - Protected: {interface.protected}")
        return interfaces
    
    async def exploit_jtag(self, interface: DebugInterface, device: EmbeddedSystem) -> Dict[str, Any]:
        """
        Exploit JTAG interface.
        
        Attacks:
        - Dump flash memory
        - Extract firmware
        - Modify boot code
        - Disable security features
        - Debug running system
        """
        logger.warning("Attempting JTAG exploitation")
        
        results = {
            "interface": "JTAG",
            "exploitable": False,
            "cpu_halted": False,
            "memory_dumped": False,
            "firmware_extracted": False,
            "security_bypassed": False,
            "operations": [],
        }
        
        if not interface.accessible:
            results["operations"].append("Interface not accessible")
            return results
        
        if interface.protected:
            results["operations"].append("JTAG protection detected (fuses blown)")
            # Some chips allow bypass
            results["operations"].append("Attempting voltage glitching attack...")
            results["operations"].append("Protection bypassed!")
            results["security_bypassed"] = True
        
        results["exploitable"] = True
        
        # Simulate JTAG operations
        results["operations"].append("Connecting via OpenOCD...")
        results["operations"].append("TAP detected: ARM Cortex-M4")
        
        # Halt CPU
        results["operations"].append("Halting CPU...")
        results["cpu_halted"] = True
        
        # Dump memory
        results["operations"].append("Dumping flash memory (0x08000000 - 0x08100000)...")
        results["memory_dumped"] = True
        results["firmware_extracted"] = True
        
        # Read security features
        results["operations"].append("Reading option bytes...")
        results["operations"].append("RDP Level: 0 (No protection)")
        results["operations"].append("Write Protection: Disabled")
        
        return results


class FirmwareReverseEngineer:
    """
    Firmware reverse engineering and analysis.
    
    Analyzes firmware binaries to understand:
    - Code structure
    - Function entry points
    - String references
    - Crypto implementations
    - Vulnerability patterns
    """
    
    def __init__(self):
        self.disassemblers = {
            "ghidra": "NSA reverse engineering tool",
            "ida_pro": "Commercial disassembler",
            "radare2": "Open source reverse engineering framework",
            "binary_ninja": "Modern RE platform",
        }
    
    async def analyze_firmware(self, firmware_path: str, architecture: Architecture) -> Dict[str, Any]:
        """
        Reverse engineer firmware binary.
        
        Steps:
        1. Load binary
        2. Identify architecture
        3. Find entry points
        4. Disassemble code
        5. Identify functions
        6. Analyze for vulnerabilities
        """
        logger.info(f"Reverse engineering firmware: {firmware_path}")
        
        results = {
            "filename": Path(firmware_path).name,
            "architecture": architecture.value,
            "entry_point": 0,
            "functions_found": 0,
            "interesting_functions": [],
            "strings": [],
            "crypto_functions": [],
            "vulnerabilities": [],
            "analysis_notes": [],
        }
        
        # Simulate firmware loading
        results["entry_point"] = 0x08000000  # Common ARM reset vector
        results["analysis_notes"].append(f"Entry point: 0x{results['entry_point']:08x}")
        
        # Simulate function discovery
        interesting_funcs = [
            {"name": "crypto_init", "address": 0x08001234, "type": "crypto"},
            {"name": "http_server", "address": 0x08005678, "type": "network"},
            {"name": "auth_check", "address": 0x08009abc, "type": "security"},
            {"name": "strcpy", "address": 0x0800def0, "type": "dangerous"},
            {"name": "memcpy", "address": 0x0800def4, "type": "dangerous"},
        ]
        
        results["functions_found"] = len(interesting_funcs)
        results["interesting_functions"] = interesting_funcs
        
        # Simulate string extraction
        results["strings"] = [
            "admin:password123",
            "AES-128-CBC",
            "http://update.iotdevice.com",
            "telnetd",
            "root@localhost",
        ]
        
        # Identify crypto
        results["crypto_functions"] = [
            {"name": "AES_encrypt", "address": 0x08002000},
            {"name": "sha256_hash", "address": 0x08002100},
        ]
        
        # Vulnerability analysis
        results["vulnerabilities"] = self._analyze_vulnerabilities(interesting_funcs, results["strings"])
        
        logger.info(f"Analysis complete - found {len(results['vulnerabilities'])} vulnerabilities")
        return results
    
    def _analyze_vulnerabilities(self, functions: List[Dict], strings: List[str]) -> List[str]:
        """Analyze for common vulnerability patterns"""
        vulns = []
        
        # Check for dangerous functions
        dangerous_funcs = ["strcpy", "sprintf", "gets", "memcpy"]
        for func in functions:
            if any(df in func["name"] for df in dangerous_funcs):
                vulns.append(f"Buffer overflow risk: {func['name']} at 0x{func['address']:08x}")
        
        # Check for hardcoded credentials
        for string in strings:
            if ":" in string and any(word in string.lower() for word in ["admin", "root", "password"]):
                vulns.append(f"Hardcoded credential: {string}")
        
        # Check for insecure services
        insecure_services = ["telnetd", "ftpd", "httpd"]
        for string in strings:
            if any(svc in string for svc in insecure_services):
                vulns.append(f"Insecure service enabled: {string}")
        
        return vulns


class BinaryVulnerabilityAnalyzer:
    """
    Automated binary vulnerability analysis.
    
    Uses static and dynamic analysis to find:
    - Buffer overflows
    - Format string bugs
    - Integer overflows
    - Use-after-free
    - Race conditions
    """
    
    def __init__(self):
        self.analysis_tools = {
            "checksec": "Binary security features checker",
            "pwntools": "CTF and exploit development",
            "angr": "Binary analysis framework",
            "afl": "American Fuzzy Lop - fuzzer",
        }
    
    async def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary for vulnerabilities.
        
        Checks:
        - Security mitigations (NX, ASLR, PIE, Canary, RELRO)
        - Dangerous function calls
        - Common vulnerability patterns
        """
        logger.info(f"Analyzing binary: {binary_path}")
        
        results = {
            "binary": Path(binary_path).name,
            "security_features": {},
            "dangerous_functions": [],
            "vulnerabilities": [],
            "exploit_difficulty": "UNKNOWN",
        }
        
        # Check security features
        results["security_features"] = {
            "NX": False,  # No Execute - prevents code execution on stack
            "ASLR": False,  # Address Space Layout Randomization
            "PIE": False,  # Position Independent Executable
            "Canary": False,  # Stack canary
            "RELRO": "None",  # Relocation Read-Only
        }
        
        # Simulate detection of dangerous functions
        results["dangerous_functions"] = [
            {"name": "strcpy", "risk": "HIGH", "issue": "No bounds checking"},
            {"name": "sprintf", "risk": "HIGH", "issue": "Buffer overflow"},
            {"name": "gets", "risk": "CRITICAL", "issue": "Unbounded read"},
        ]
        
        # Identify vulnerabilities
        results["vulnerabilities"] = [
            {
                "type": "Buffer Overflow",
                "location": "http_request_handler",
                "severity": "HIGH",
                "description": "strcpy used without length validation",
            },
            {
                "type": "Format String",
                "location": "log_message",
                "severity": "MEDIUM",
                "description": "printf with user-controlled format string",
            },
        ]
        
        # Calculate exploit difficulty
        if not any(results["security_features"].values()):
            results["exploit_difficulty"] = "EASY"
        elif sum(results["security_features"].values()) <= 2:
            results["exploit_difficulty"] = "MEDIUM"
        else:
            results["exploit_difficulty"] = "HARD"
        
        logger.info(f"Binary analysis complete - {len(results['vulnerabilities'])} vulnerabilities, "
                   f"exploit difficulty: {results['exploit_difficulty']}")
        
        return results


class HardwareDebugInterface:
    """
    Generic hardware debug interface exploitation.
    
    Supports:
    - SWD (Serial Wire Debug) - ARM's 2-wire alternative to JTAG
    - I2C - Inter-Integrated Circuit
    - SPI - Serial Peripheral Interface
    """
    
    async def discover_interfaces(self, device: EmbeddedSystem) -> List[DebugInterface]:
        """Discover all hardware debug interfaces"""
        logger.info("Discovering hardware debug interfaces...")
        
        interfaces = []
        
        # SWD discovery
        swd = DebugInterface(
            interface_type=InterfaceType.SWD,
            pin_configuration={"SWDIO": 46, "SWCLK": 49},
            voltage=3.3,
            accessible=True,
            protected=False,
        )
        swd.vulnerabilities.append("SWD debug port accessible - firmware extraction possible")
        interfaces.append(swd)
        
        # I2C discovery (often for EEPROM access)
        i2c = DebugInterface(
            interface_type=InterfaceType.I2C,
            pin_configuration={"SDA": 30, "SCL": 31},
            voltage=3.3,
            accessible=True,
            protected=False,
        )
        i2c.vulnerabilities.append("I2C EEPROM accessible - may contain sensitive data")
        interfaces.append(i2c)
        
        # SPI discovery (often for flash memory)
        spi = DebugInterface(
            interface_type=InterfaceType.SPI,
            pin_configuration={"MOSI": 40, "MISO": 41, "SCK": 42, "CS": 43},
            voltage=3.3,
            accessible=True,
            protected=False,
        )
        spi.vulnerabilities.append("SPI flash accessible - full firmware dump possible")
        interfaces.append(spi)
        
        device.debug_interfaces.extend(interfaces)
        logger.info(f"Found {len(interfaces)} debug interfaces")
        
        return interfaces
    
    async def exploit_spi_flash(self) -> Dict[str, Any]:
        """
        Exploit SPI flash memory access.
        
        SPI flash often stores:
        - Firmware
        - Configuration
        - Credentials
        - Crypto keys
        """
        logger.warning("Attempting SPI flash extraction")
        
        results = {
            "interface": "SPI",
            "flash_size_mb": 16,
            "manufacturer": "Winbond",
            "model": "W25Q128",
            "firmware_extracted": False,
            "data_extracted": [],
        }
        
        # Simulate flash read
        results["firmware_extracted"] = True
        results["data_extracted"] = [
            "Firmware image (16 MB)",
            "WiFi credentials",
            "SSL private key",
            "Configuration database",
        ]
        
        return results


class EmbeddedSystemAnalyzer:
    """
    Main orchestrator for embedded system analysis.
    
    Combines:
    - UART exploitation
    - JTAG exploitation
    - Firmware reverse engineering
    - Binary vulnerability analysis
    - Hardware interface exploitation
    """
    
    def __init__(self):
        self.uart = UARTExploiter()
        self.jtag = JTAGExploiter()
        self.firmware_re = FirmwareReverseEngineer()
        self.binary_analyzer = BinaryVulnerabilityAnalyzer()
        self.hw_interface = HardwareDebugInterface()
    
    async def run_full_analysis(self, device: EmbeddedSystem, firmware_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run comprehensive embedded system security analysis.
        
        Args:
            device: EmbeddedSystem object to analyze
            firmware_path: Optional path to firmware binary
        
        Returns:
            Complete analysis results
        """
        logger.info(f"Starting comprehensive analysis of {device.device_name}")
        
        results = {
            "device": device.device_name,
            "manufacturer": device.manufacturer,
            "architecture": device.architecture.value,
            "analysis_time": datetime.now().isoformat(),
            "debug_interfaces": [],
            "uart_exploitation": None,
            "jtag_exploitation": None,
            "firmware_analysis": None,
            "binary_analysis": None,
            "hardware_interfaces": [],
            "overall_risk": "UNKNOWN",
            "recommendations": [],
        }
        
        # Phase 1: Discover debug interfaces
        logger.info("Phase 1: Debug interface discovery")
        uart_interfaces = await self.uart.discover_uart(device)
        jtag_interfaces = await self.jtag.discover_jtag(device)
        hw_interfaces = await self.hw_interface.discover_interfaces(device)
        
        results["debug_interfaces"] = [
            {
                "type": iface.interface_type.value,
                "accessible": iface.accessible,
                "protected": iface.protected,
                "vulnerabilities": iface.vulnerabilities,
            }
            for iface in device.debug_interfaces
        ]
        
        # Phase 2: Exploit UART
        logger.info("Phase 2: UART exploitation")
        if uart_interfaces:
            results["uart_exploitation"] = await self.uart.exploit_uart(uart_interfaces[0])
        
        # Phase 3: Exploit JTAG
        logger.info("Phase 3: JTAG exploitation")
        if jtag_interfaces:
            results["jtag_exploitation"] = await self.jtag.exploit_jtag(jtag_interfaces[0], device)
        
        # Phase 4: Firmware reverse engineering
        if firmware_path:
            logger.info("Phase 4: Firmware reverse engineering")
            results["firmware_analysis"] = await self.firmware_re.analyze_firmware(
                firmware_path, device.architecture
            )
            
            # Phase 5: Binary vulnerability analysis
            logger.info("Phase 5: Binary vulnerability analysis")
            results["binary_analysis"] = await self.binary_analyzer.analyze_binary(firmware_path)
        
        # Phase 6: Hardware interface exploitation
        logger.info("Phase 6: Hardware interface exploitation")
        spi_results = await self.hw_interface.exploit_spi_flash()
        results["hardware_interfaces"].append(spi_results)
        
        # Calculate overall risk
        results["overall_risk"] = self._calculate_risk(results)
        
        # Generate recommendations
        results["recommendations"] = self._generate_recommendations(results)
        
        logger.info(f"Analysis complete - Overall risk: {results['overall_risk']}")
        return results
    
    def _calculate_risk(self, results: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        risk_score = 0
        
        # Unprotected debug interfaces are high risk
        for iface in results["debug_interfaces"]:
            if iface["accessible"] and not iface["protected"]:
                risk_score += 30
        
        # UART/JTAG exploitation success
        if results["uart_exploitation"] and results["uart_exploitation"].get("exploitable"):
            risk_score += 25
        if results["jtag_exploitation"] and results["jtag_exploitation"].get("exploitable"):
            risk_score += 35
        
        # Firmware vulnerabilities
        if results["firmware_analysis"]:
            vuln_count = len(results["firmware_analysis"].get("vulnerabilities", []))
            risk_score += min(vuln_count * 5, 20)
        
        # Binary vulnerabilities
        if results["binary_analysis"]:
            if results["binary_analysis"]["exploit_difficulty"] == "EASY":
                risk_score += 20
        
        # Convert score to risk level
        if risk_score >= 70:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Debug interface recommendations
        for iface in results["debug_interfaces"]:
            if iface["accessible"] and not iface["protected"]:
                recommendations.append(
                    f"Disable or protect {iface['type'].upper()} interface before production"
                )
        
        # UART recommendations
        if results["uart_exploitation"] and results["uart_exploitation"].get("root_shell_obtained"):
            recommendations.append("Implement authentication for UART console access")
            recommendations.append("Disable UART in production builds")
        
        # JTAG recommendations
        if results["jtag_exploitation"] and results["jtag_exploitation"].get("exploitable"):
            recommendations.append("Blow JTAG protection fuses before shipping")
            recommendations.append("Enable readout protection (RDP)")
        
        # Firmware recommendations
        if results["firmware_analysis"]:
            vulns = results["firmware_analysis"].get("vulnerabilities", [])
            if any("hardcoded credential" in v.lower() for v in vulns):
                recommendations.append("Remove all hardcoded credentials from firmware")
            if any("telnet" in v.lower() for v in vulns):
                recommendations.append("Disable telnet - use SSH instead")
        
        # Binary security recommendations
        if results["binary_analysis"]:
            sec_features = results["binary_analysis"]["security_features"]
            if not sec_features.get("NX"):
                recommendations.append("Enable NX (No Execute) protection")
            if not sec_features.get("ASLR"):
                recommendations.append("Enable ASLR (Address Space Layout Randomization)")
            if not sec_features.get("Canary"):
                recommendations.append("Enable stack canaries")
        
        return recommendations
