"""
Phase 11: IoT & Embedded Systems - Usage Examples
=================================================

Comprehensive examples demonstrating Phase 11 capabilities.

⚠️ AUTHORIZATION WARNING: All examples require explicit authorization.
Only run against systems you own or have written permission to test.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.phase11_engine import Phase11Engine
from iot_embedded_systems.iot_device_discovery import IoTDeviceDiscovery
from iot_embedded_systems.embedded_system_analysis import (
    EmbeddedSystemAnalyzer, EmbeddedSystem, Architecture
)
from iot_embedded_systems.ics_scada_exploitation import ICSExploiter
from iot_embedded_systems.wireless_protocol_exploitation import WirelessExploiter


print("=" * 70)
print("PHASE 11: IoT & EMBEDDED SYSTEMS - USAGE EXAMPLES")
print("=" * 70)
print("⚠️  WARNING: These examples perform active security testing!")
print("⚠️  Requires explicit authorization for all targets!")
print("=" * 70)
print()


async def example1_iot_device_discovery():
    """Example 1: IoT Device Discovery"""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: IoT Device Discovery")
    print("=" * 70)
    
    discovery = IoTDeviceDiscovery(
        shodan_key=None,  # Add your Shodan API key if available
    )
    
    print("Discovering IoT devices on network...")
    results = await discovery.run_full_discovery(target_network="192.168.1.0/24")
    
    print(f"\n✓ Devices found: {len(results['devices_found'])}")
    print(f"✓ High-risk devices: {len(results['high_risk_devices'])}")
    print(f"✓ Default credentials found: {len(results['default_credentials_found'])}")
    
    # Display high-risk devices
    if results['high_risk_devices']:
        print("\n🔴 High-Risk Devices:")
        for device in results['high_risk_devices'][:3]:
            print(f"  - {device['ip']} ({device['type']})")
            print(f"    Risk Score: {device['risk_score']:.1f}")
            print(f"    Vulnerabilities: {', '.join(device['vulnerabilities'][:2])}")


async def example2_embedded_system_analysis():
    """Example 2: Embedded System Analysis"""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Embedded System Analysis")
    print("=" * 70)
    
    # Create device profile
    device = EmbeddedSystem(
        device_name="Smart Thermostat",
        manufacturer="Generic IoT Corp",
        architecture=Architecture.ARM,
        flash_size_kb=1024,
        ram_size_kb=256,
    )
    
    analyzer = EmbeddedSystemAnalyzer()
    
    print(f"Analyzing embedded device: {device.device_name}")
    print(f"Architecture: {device.architecture.value}")
    
    results = await analyzer.run_full_analysis(device)
    
    print(f"\n✓ Debug interfaces found: {len(results['debug_interfaces'])}")
    print(f"✓ Overall risk: {results['overall_risk']}")
    
    # Display vulnerabilities
    if results['debug_interfaces']:
        print("\n🔴 Debug Interface Vulnerabilities:")
        for iface in results['debug_interfaces'][:3]:
            print(f"  - {iface['type'].upper()}")
            print(f"    Accessible: {iface['accessible']}")
            print(f"    Protected: {iface['protected']}")
            if iface['vulnerabilities']:
                print(f"    Issue: {iface['vulnerabilities'][0]}")


async def example3_ics_scada_assessment():
    """Example 3: ICS/SCADA Security Assessment"""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: ICS/SCADA Security Assessment")
    print("=" * 70)
    print("⚠️  CRITICAL: ICS systems control physical processes!")
    print("⚠️  Only test isolated lab environments with safety measures!")
    print()
    
    ics = ICSExploiter()
    
    print("Scanning for ICS/SCADA devices...")
    results = await ics.run_full_assessment("192.168.100.0/24")
    
    print(f"\n✓ Modbus devices: {len(results['modbus_devices'])}")
    print(f"✓ DNP3 devices: {len(results['dnp3_devices'])}")
    print(f"✓ OPC servers: {len(results['opc_servers'])}")
    print(f"✓ Critical findings: {len(results['critical_findings'])}")
    
    # Display critical findings
    if results['critical_findings']:
        print("\n🔴 Critical Findings:")
        for finding in results['critical_findings'][:3]:
            print(f"  - {finding}")


async def example4_wireless_exploitation():
    """Example 4: Wireless Protocol Exploitation"""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Wireless Protocol Exploitation")
    print("=" * 70)
    print("⚠️  WARNING: Wireless testing may violate regulations!")
    print("⚠️  Use only in RF-shielded environment or with authorization!")
    print()
    
    wireless = WirelessExploiter()
    
    print("Scanning wireless protocols...")
    results = await wireless.run_full_assessment()
    
    print(f"\n✓ WiFi networks: {len(results['wifi_networks'])}")
    print(f"✓ Bluetooth devices: {len(results['bluetooth_devices'])}")
    print(f"✓ Zigbee devices: {len(results['zigbee_devices'])}")
    print(f"✓ Z-Wave devices: {len(results['zwave_devices'])}")
    print(f"✓ LoRaWAN devices: {len(results['lorawan_devices'])}")
    
    # Display WiFi vulnerabilities
    if results['wifi_networks']:
        print("\n🔴 WiFi Network Vulnerabilities:")
        for network in results['wifi_networks'][:3]:
            print(f"  - {network['ssid']}")
            print(f"    Security: {network['security']}")
            print(f"    Signal: {network['signal']} dBm")
            if network['vulnerabilities']:
                print(f"    Issue: {network['vulnerabilities'][0]}")


async def example5_firmware_analysis():
    """Example 5: Firmware Analysis"""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Firmware Analysis")
    print("=" * 70)
    
    discovery = IoTDeviceDiscovery()
    
    # Note: Use actual firmware file path
    firmware_path = "sample_firmware.bin"
    
    print(f"Analyzing firmware: {firmware_path}")
    firmware = await discovery.analyze_firmware(firmware_path)
    
    if firmware:
        print(f"\n✓ Architecture: {firmware.architecture}")
        print(f"✓ File type: {firmware.file_type.value}")
        print(f"✓ Size: {firmware.size_bytes / 1024:.1f} KB")
        print(f"✓ Hardcoded credentials: {len(firmware.hardcoded_credentials)}")
        print(f"✓ Crypto keys found: {len(firmware.crypto_keys)}")
        print(f"✓ Vulnerabilities: {len(firmware.vulnerabilities)}")
        
        if firmware.hardcoded_credentials:
            print("\n🔴 Hardcoded Credentials:")
            for username, password in firmware.hardcoded_credentials[:3]:
                print(f"  - {username}:{password}")


async def example6_wifi_attack_chain():
    """Example 6: WiFi Attack Chain"""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: WiFi Attack Chain (WPA2 Cracking)")
    print("=" * 70)
    print("⚠️  Only test networks you own!")
    print()
    
    from iot_embedded_systems.wireless_protocol_exploitation import WiFiAttacker
    
    wifi = WiFiAttacker()
    
    # Step 1: Scan networks
    print("Step 1: Scanning WiFi networks...")
    networks = await wifi.scan_wifi_networks()
    
    # Find WPA2 network
    wpa2_networks = [n for n in networks if n.security.value == "wpa2"]
    
    if wpa2_networks:
        target = wpa2_networks[0]
        print(f"✓ Target: {target.ssid} ({target.security.value})")
        
        # Step 2: Capture handshake
        print("\nStep 2: Capturing WPA2 handshake...")
        captured = await wifi.capture_handshake(target)
        
        if captured:
            print("✓ Handshake captured!")
            
            # Step 3: Crack password
            print("\nStep 3: Cracking password (dictionary attack)...")
            password = await wifi.crack_wpa_password(target, "wordlist.txt")
            
            if password:
                print(f"✓ Password cracked: {password}")


async def example7_bluetooth_attack():
    """Example 7: Bluetooth KNOB/BIAS Attacks"""
    print("\n" + "=" * 70)
    print("EXAMPLE 7: Bluetooth KNOB/BIAS Attacks")
    print("=" * 70)
    
    from iot_embedded_systems.wireless_protocol_exploitation import BluetoothAttacker
    
    bt = BluetoothAttacker()
    
    # Scan for devices
    print("Scanning for Bluetooth devices...")
    devices = await bt.scan_bluetooth_devices()
    
    if devices:
        device = devices[0]
        print(f"\n✓ Target: {device.device_name}")
        print(f"  MAC: {device.mac_address}")
        print(f"  Version: {device.bluetooth_version.value}")
        
        # Try KNOB attack
        print("\nAttempting KNOB attack...")
        knob_result = await bt.knob_attack(device)
        
        if knob_result['vulnerable']:
            print(f"✓ Device is vulnerable to KNOB!")
            print(f"  Encryption key forced to {knob_result['forced_key_length']} byte")
        
        # Try BIAS attack
        print("\nAttempting BIAS attack...")
        bias_result = await bt.bias_attack(device, "target_mac_here")
        
        if bias_result['vulnerable']:
            print(f"✓ Device is vulnerable to BIAS!")
            if bias_result['impersonation_successful']:
                print("  Impersonation successful!")


async def example8_full_phase11_assessment():
    """Example 8: Full Phase 11 Assessment"""
    print("\n" + "=" * 70)
    print("EXAMPLE 8: Complete Phase 11 Assessment")
    print("=" * 70)
    print("Running comprehensive IoT & embedded systems assessment...")
    print()
    
    engine = Phase11Engine()
    
    results = await engine.run_full_assessment(
        target_network="192.168.1.0/24",
        ics_network="192.168.100.0/24",
        wireless_scan=True
    )
    
    print("\n" + "=" * 70)
    print("ASSESSMENT SUMMARY")
    print("=" * 70)
    
    # Overall risk
    risk = results['risk_summary']
    print(f"\n🎯 Overall Risk: {risk['overall_risk']}")
    print(f"   Risk Score: {risk['risk_score']}/100")
    
    # Device counts
    if 'device_counts' in risk:
        print(f"\n📊 Device Inventory:")
        for device_type, count in risk['device_counts'].items():
            print(f"   {device_type}: {count}")
    
    # Critical findings
    print(f"\n🔴 Critical Findings: {len(results['critical_findings'])}")
    for finding in results['critical_findings'][:5]:
        print(f"   - {finding}")
    
    # Integrated scenarios
    if results['integrated_scenarios']:
        print(f"\n🎯 Attack Scenarios Generated: {len(results['integrated_scenarios'])}")
        for scenario in results['integrated_scenarios'][:2]:
            print(f"\n   {scenario['name']}:")
            print(f"   Impact: {scenario['impact']}")
            print(f"   Phases: {len(scenario['phases'])}")
    
    # Top recommendations
    print(f"\n📋 Top Recommendations:")
    for rec in results['recommendations'][:5]:
        if rec.strip() and not rec.startswith("="):
            print(f"   {rec}")
    
    # Save report
    report_path = "phase11_assessment_report.json"
    engine.save_report(results, report_path)
    print(f"\n✓ Full report saved to: {report_path}")


async def main():
    """Main example runner"""
    examples = {
        "1": ("IoT Device Discovery", example1_iot_device_discovery),
        "2": ("Embedded System Analysis", example2_embedded_system_analysis),
        "3": ("ICS/SCADA Assessment", example3_ics_scada_assessment),
        "4": ("Wireless Exploitation", example4_wireless_exploitation),
        "5": ("Firmware Analysis", example5_firmware_analysis),
        "6": ("WiFi Attack Chain", example6_wifi_attack_chain),
        "7": ("Bluetooth Attacks", example7_bluetooth_attack),
        "8": ("Full Phase 11 Assessment", example8_full_phase11_assessment),
    }
    
    print("\nAvailable Examples:")
    for num, (name, _) in examples.items():
        print(f"  {num}. {name}")
    print("  A. Run all examples")
    print("  Q. Quit")
    
    choice = input("\nSelect example (1-8, A, Q): ").strip().upper()
    
    if choice == 'Q':
        print("Exiting...")
        return
    elif choice == 'A':
        for num, (name, func) in examples.items():
            await func()
    elif choice in examples:
        _, func = examples[choice]
        await func()
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    print("\n⚠️  AUTHORIZATION VERIFICATION")
    print("=" * 70)
    authorized = input("Do you have written authorization for testing? (yes/no): ").strip().lower()
    
    if authorized == "yes":
        print("✓ Authorization confirmed. Proceeding with examples...\n")
        asyncio.run(main())
    else:
        print("❌ Authorization required. Exiting.")
        sys.exit(1)
