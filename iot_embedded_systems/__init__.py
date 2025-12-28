"""
Phase 11: IoT & Embedded Systems Security Testing
================================================

Comprehensive security assessment for IoT devices, embedded systems,
industrial control systems, and wireless protocols.

Modules:
-------
- iot_device_discovery: Shodan/Censys integration, UPnP exploitation, firmware analysis
- embedded_system_analysis: UART/JTAG exploitation, firmware reverse engineering, binary analysis
- ics_scada_exploitation: Modbus/DNP3/OPC protocols, PLC manipulation, HMI vulnerabilities
- wireless_protocol_exploitation: WiFi/Bluetooth/Zigbee/Z-Wave/LoRaWAN/5G attacks

⚠️ WARNING: AUTHORIZED TESTING ONLY
====================================
These tools are designed for authorized security assessments of IoT and embedded systems.
Unauthorized testing of IoT devices, industrial control systems, or wireless networks
can cause:
- Physical damage to equipment
- Safety hazards in industrial environments
- Service disruptions to critical infrastructure
- Legal prosecution under computer fraud and CFAA laws
- Interference with licensed wireless spectrum (FCC violations)

ALWAYS:
- Obtain explicit written authorization before testing
- Verify ownership of all target devices
- Test in isolated lab environments when possible
- Respect wireless spectrum regulations
- Follow responsible disclosure for vulnerabilities
- Document safety system impacts in ICS environments
"""

from .iot_device_discovery import (
    IoTDeviceDiscovery,
    ShodanScanner,
    CensysScanner,
    UPnPExploiter,
    DefaultCredentialDatabase,
    FirmwareExtractor,
    IoTDevice,
    FirmwareImage
)

from .embedded_system_analysis import (
    EmbeddedSystemAnalyzer,
    UARTExploiter,
    JTAGExploiter,
    FirmwareReverseEngineer,
    BinaryVulnerabilityAnalyzer,
    HardwareDebugInterface,
    EmbeddedSystem,
    DebugInterface
)

from .ics_scada_exploitation import (
    ICSExploiter,
    ModbusExploiter,
    DNP3Exploiter,
    OPCExploiter,
    PLCManipulator,
    HMIVulnerabilityScanner,
    SafetySystemAnalyzer,
    ICSDevice,
    PLCProgram
)

from .wireless_protocol_exploitation import (
    WirelessExploiter,
    WiFiAttacker,
    BluetoothAttacker,
    ZigbeeExploiter,
    ZWaveExploiter,
    LoRaWANTester,
    CellularNetworkAttacker,
    WirelessDevice,
    WirelessNetwork
)

__all__ = [
    # IoT Device Discovery
    'IoTDeviceDiscovery',
    'ShodanScanner',
    'CensysScanner',
    'UPnPExploiter',
    'DefaultCredentialDatabase',
    'FirmwareExtractor',
    'IoTDevice',
    'FirmwareImage',
    
    # Embedded System Analysis
    'EmbeddedSystemAnalyzer',
    'UARTExploiter',
    'JTAGExploiter',
    'FirmwareReverseEngineer',
    'BinaryVulnerabilityAnalyzer',
    'HardwareDebugInterface',
    'EmbeddedSystem',
    'DebugInterface',
    
    # ICS/SCADA Exploitation
    'ICSExploiter',
    'ModbusExploiter',
    'DNP3Exploiter',
    'OPCExploiter',
    'PLCManipulator',
    'HMIVulnerabilityScanner',
    'SafetySystemAnalyzer',
    'ICSDevice',
    'PLCProgram',
    
    # Wireless Protocol Exploitation
    'WirelessExploiter',
    'WiFiAttacker',
    'BluetoothAttacker',
    'ZigbeeExploiter',
    'ZWaveExploiter',
    'LoRaWANTester',
    'CellularNetworkAttacker',
    'WirelessDevice',
    'WirelessNetwork',
]
