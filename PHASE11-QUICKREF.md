# Phase 11: IoT & Embedded Systems - Quick Reference

## Quick Start

```python
from core.phase11_engine import Phase11Engine
import asyncio

async def main():
    engine = Phase11Engine(
        shodan_key="your_key_here",  # Optional
    )
    
    results = await engine.run_full_assessment(
        target_network="192.168.1.0/24",
        ics_network="192.168.100.0/24",
        wireless_scan=True
    )
    
    print(f"Risk Level: {results['risk_summary']['overall_risk']}")
    print(f"Critical Findings: {len(results['critical_findings'])}")

asyncio.run(main())
```

## Module Quick Starts

### 1. IoT Device Discovery

```python
from iot_embedded_systems.iot_device_discovery import IoTDeviceDiscovery

discovery = IoTDeviceDiscovery(shodan_key="your_key")
results = await discovery.run_full_discovery("192.168.1.0/24")

print(f"Devices found: {len(results['devices_found'])}")
print(f"High-risk devices: {len(results['high_risk_devices'])}")
```

### 2. Embedded System Analysis

```python
from iot_embedded_systems.embedded_system_analysis import (
    EmbeddedSystemAnalyzer, EmbeddedSystem, Architecture
)

device = EmbeddedSystem(
    device_name="Smart Thermostat",
    architecture=Architecture.ARM,
)

analyzer = EmbeddedSystemAnalyzer()
results = await analyzer.run_full_analysis(device, "firmware.bin")

print(f"Overall Risk: {results['overall_risk']}")
```

### 3. ICS/SCADA Exploitation

```python
from iot_embedded_systems.ics_scada_exploitation import ICSExploiter

ics = ICSExploiter()
results = await ics.run_full_assessment("192.168.100.0/24")

print(f"ICS devices: {len(results['devices_found'])}")
print(f"Critical findings: {len(results['critical_findings'])}")
```

### 4. Wireless Protocol Exploitation

```python
from iot_embedded_systems.wireless_protocol_exploitation import WirelessExploiter

wireless = WirelessExploiter()
results = await wireless.run_full_assessment()

print(f"WiFi networks: {len(results['wifi_networks'])}")
print(f"Bluetooth devices: {len(results['bluetooth_devices'])}")
```

## Common Patterns

### Firmware Analysis

```python
from iot_embedded_systems.iot_device_discovery import FirmwareExtractor

extractor = FirmwareExtractor()
firmware = await extractor.extract_firmware("device_firmware.bin")

print(f"Hardcoded credentials: {firmware.hardcoded_credentials}")
print(f"Crypto keys found: {len(firmware.crypto_keys)}")
print(f"Vulnerabilities: {firmware.vulnerabilities}")
```

### WiFi Attack Chain

```python
from iot_embedded_systems.wireless_protocol_exploitation import WiFiAttacker

wifi = WiFiAttacker()

# 1. Scan networks
networks = await wifi.scan_wifi_networks()

# 2. Capture handshake
target = networks[0]
captured = await wifi.capture_handshake(target)

# 3. Crack password
if captured:
    password = await wifi.crack_wpa_password(target, "wordlist.txt")
    print(f"Password: {password}")
```

### Modbus Exploitation

```python
from iot_embedded_systems.ics_scada_exploitation import ModbusExploiter

modbus = ModbusExploiter()

# Scan for devices
devices = await modbus.scan_modbus_devices("192.168.100.0/24")

# Read coils
device = devices[0]
coils = await modbus.read_coils(device, start_address=0, count=10)

# Write coil (⚠️ AUTHORIZED TESTING ONLY)
await modbus.write_coil(device, address=1, value=True)
```

### Bluetooth Attack

```python
from iot_embedded_systems.wireless_protocol_exploitation import BluetoothAttacker

bt = BluetoothAttacker()

# Scan devices
devices = await bt.scan_bluetooth_devices()

# KNOB attack
device = devices[0]
result = await bt.knob_attack(device)

if result["vulnerable"]:
    print(f"Encryption key forced to {result['forced_key_length']} byte")
```

## Output Structure

### Phase 11 Assessment Output

```python
{
    "phase": "Phase 11: IoT & Embedded Systems",
    "assessment_time": "2025-12-28T...",
    "iot_discovery": {
        "devices_found": [...],
        "high_risk_devices": [...],
        "default_credentials_found": [...],
    },
    "embedded_analysis": {
        "overall_risk": "HIGH",
        "debug_interfaces": [...],
        "firmware_analysis": {...},
    },
    "ics_assessment": {
        "modbus_devices": [...],
        "dnp3_devices": [...],
        "critical_findings": [...],
    },
    "wireless_assessment": {
        "wifi_networks": [...],
        "bluetooth_devices": [...],
        "zigbee_devices": [...],
    },
    "integrated_scenarios": [...],
    "critical_findings": [...],
    "risk_summary": {
        "overall_risk": "CRITICAL",
        "risk_score": 85,
    },
    "recommendations": [...]
}
```

## Error Handling

```python
try:
    results = await engine.run_full_assessment(...)
except PermissionError:
    print("Insufficient permissions for hardware access")
except ConnectionError:
    print("Network unreachable")
except Exception as e:
    print(f"Error: {e}")
```

## Authorization Checks

```python
def verify_authorization():
    """
    Implement your authorization verification.
    Should confirm:
    - Written permission obtained
    - Test environment is isolated
    - Safety measures in place (for ICS)
    """
    authorized = input("Do you have written authorization? (yes/no): ")
    return authorized.lower() == "yes"

if verify_authorization():
    results = await engine.run_full_assessment(...)
else:
    print("Authorization required. Exiting.")
```

## Safety Checklist for ICS Testing

Before testing ICS/SCADA systems:

- [ ] Written authorization obtained
- [ ] Test environment is isolated/air-gapped
- [ ] Safety systems verified operational
- [ ] Emergency shutdown procedures in place
- [ ] Qualified personnel supervising
- [ ] Backup of PLC programs created
- [ ] Legal review completed
- [ ] Stakeholders notified

## Best Practices

1. **Always verify authorization** before any testing
2. **Start passive** (scanning) before active (exploitation)
3. **Test in isolated environments** when possible
4. **Document everything** - maintain detailed logs
5. **Responsible disclosure** for vulnerabilities found
6. **Respect regulations** - wireless, spectrum, telecommunications laws
7. **Safety first** - especially for ICS/medical devices
8. **Data handling** - protect any captured credentials/keys

## Legal Considerations

⚠️ **CRITICAL**: Phase 11 capabilities are subject to numerous laws:

- **Computer Fraud and Abuse Act (CFAA)** - US
- **Telecommunications Act** - FCC regulations on wireless
- **Critical Infrastructure Protection** - NERC CIP, etc.
- **Medical Device Regulations** - FDA, MDR
- **International regulations** - vary by country

Always consult legal counsel before testing.
