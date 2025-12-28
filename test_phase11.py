"""
Phase 11: IoT & Embedded Systems - Test Suite
=============================================

Comprehensive tests for Phase 11 modules.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from iot_embedded_systems.iot_device_discovery import (
    IoTDeviceDiscovery, ShodanScanner, UPnPExploiter, 
    DefaultCredentialDatabase, FirmwareExtractor
)
from iot_embedded_systems.embedded_system_analysis import (
    EmbeddedSystemAnalyzer, UARTExploiter, JTAGExploiter,
    EmbeddedSystem, Architecture
)
from iot_embedded_systems.ics_scada_exploitation import (
    ICSExploiter, ModbusExploiter, DNP3Exploiter, OPCExploiter
)
from iot_embedded_systems.wireless_protocol_exploitation import (
    WirelessExploiter, WiFiAttacker, BluetoothAttacker
)
from core.phase11_engine import Phase11Engine


class TestIoTDeviceDiscovery:
    """Test IoT device discovery module"""
    
    @pytest.mark.asyncio
    async def test_shodan_scanner(self):
        """Test Shodan device scanning"""
        scanner = ShodanScanner()
        devices = await scanner.search_devices("camera", limit=5)
        
        assert len(devices) > 0
        assert all(hasattr(d, 'ip_address') for d in devices)
        assert all(hasattr(d, 'vulnerabilities') for d in devices)
    
    @pytest.mark.asyncio
    async def test_upnp_discovery(self):
        """Test UPnP device discovery"""
        exploiter = UPnPExploiter()
        devices = await exploiter.discover_devices()
        
        assert isinstance(devices, list)
        for device in devices:
            assert hasattr(device, 'upnp_services')
    
    @pytest.mark.asyncio
    async def test_default_credentials(self):
        """Test default credential database"""
        from iot_embedded_systems.iot_device_discovery import IoTDevice, DeviceType
        
        db = DefaultCredentialDatabase()
        device = IoTDevice(
            ip_address="192.168.1.1",
            device_type=DeviceType.CAMERA,
            manufacturer="Hikvision"
        )
        
        creds = db.get_credentials(device)
        assert len(creds) > 0
        assert all(isinstance(c, tuple) and len(c) == 2 for c in creds)
    
    @pytest.mark.asyncio
    async def test_firmware_extraction(self):
        """Test firmware extraction"""
        extractor = FirmwareExtractor()
        firmware = await extractor.extract_firmware("test_firmware.bin")
        
        assert firmware is not None
        assert hasattr(firmware, 'file_type')
        assert hasattr(firmware, 'extracted_files')


class TestEmbeddedSystemAnalysis:
    """Test embedded system analysis module"""
    
    @pytest.mark.asyncio
    async def test_uart_discovery(self):
        """Test UART interface discovery"""
        device = EmbeddedSystem(
            device_name="Test Device",
            architecture=Architecture.ARM
        )
        
        uart = UARTExploiter()
        interfaces = await uart.discover_uart(device)
        
        assert isinstance(interfaces, list)
        assert len(device.debug_interfaces) > 0
    
    @pytest.mark.asyncio
    async def test_jtag_discovery(self):
        """Test JTAG interface discovery"""
        device = EmbeddedSystem(
            device_name="Test Device",
            architecture=Architecture.ARM
        )
        
        jtag = JTAGExploiter()
        interfaces = await jtag.discover_jtag(device)
        
        assert isinstance(interfaces, list)
        for iface in interfaces:
            assert hasattr(iface, 'interface_type')
            assert hasattr(iface, 'vulnerabilities')
    
    @pytest.mark.asyncio
    async def test_full_embedded_analysis(self):
        """Test full embedded system analysis"""
        device = EmbeddedSystem(
            device_name="Smart Thermostat",
            architecture=Architecture.ARM,
            flash_size_kb=1024,
            ram_size_kb=256
        )
        
        analyzer = EmbeddedSystemAnalyzer()
        results = await analyzer.run_full_analysis(device)
        
        assert 'overall_risk' in results
        assert 'debug_interfaces' in results
        assert 'recommendations' in results


class TestICSExploitation:
    """Test ICS/SCADA exploitation module"""
    
    @pytest.mark.asyncio
    async def test_modbus_scanner(self):
        """Test Modbus device scanning"""
        modbus = ModbusExploiter()
        devices = await modbus.scan_modbus_devices("192.168.100.0/24")
        
        assert isinstance(devices, list)
        for device in devices:
            assert hasattr(device, 'protocol')
            assert hasattr(device, 'safety_level')
    
    @pytest.mark.asyncio
    async def test_modbus_read(self):
        """Test Modbus read operations"""
        from iot_embedded_systems.ics_scada_exploitation import ICSDevice, ICSProtocol
        
        modbus = ModbusExploiter()
        device = ICSDevice(
            ip_address="192.168.100.10",
            protocol=ICSProtocol.MODBUS
        )
        
        coils = await modbus.read_coils(device, 0, 10)
        assert isinstance(coils, dict)
        assert len(coils) == 10
    
    @pytest.mark.asyncio
    async def test_dnp3_scanner(self):
        """Test DNP3 device scanning"""
        dnp3 = DNP3Exploiter()
        devices = await dnp3.scan_dnp3_devices("192.168.200.0/24")
        
        assert isinstance(devices, list)
    
    @pytest.mark.asyncio
    async def test_ics_full_assessment(self):
        """Test full ICS assessment"""
        ics = ICSExploiter()
        results = await ics.run_full_assessment("192.168.100.0/24")
        
        assert 'modbus_devices' in results
        assert 'critical_findings' in results
        assert 'recommendations' in results


class TestWirelessExploitation:
    """Test wireless protocol exploitation module"""
    
    @pytest.mark.asyncio
    async def test_wifi_scanner(self):
        """Test WiFi network scanning"""
        wifi = WiFiAttacker()
        networks = await wifi.scan_wifi_networks()
        
        assert isinstance(networks, list)
        assert len(networks) > 0
        
        for network in networks:
            assert hasattr(network, 'ssid')
            assert hasattr(network, 'security')
            assert hasattr(network, 'vulnerabilities')
    
    @pytest.mark.asyncio
    async def test_bluetooth_scanner(self):
        """Test Bluetooth device scanning"""
        bt = BluetoothAttacker()
        devices = await bt.scan_bluetooth_devices()
        
        assert isinstance(devices, list)
        for device in devices:
            assert hasattr(device, 'mac_address')
            assert hasattr(device, 'bluetooth_version')
    
    @pytest.mark.asyncio
    async def test_wifi_handshake_capture(self):
        """Test WiFi handshake capture"""
        from iot_embedded_systems.wireless_protocol_exploitation import WirelessNetwork, WiFiSecurity
        
        wifi = WiFiAttacker()
        network = WirelessNetwork(
            ssid="TestNetwork",
            bssid="00:11:22:33:44:55",
            channel=6,
            frequency=2437,
            signal_strength=-50,
            protocol=None,
            security=WiFiSecurity.WPA2,
            clients=["client1", "client2"]
        )
        
        result = await wifi.capture_handshake(network)
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_bluetooth_knob_attack(self):
        """Test Bluetooth KNOB attack"""
        from iot_embedded_systems.wireless_protocol_exploitation import (
            WirelessDevice, BluetoothVersion, WirelessProtocol
        )
        
        bt = BluetoothAttacker()
        device = WirelessDevice(
            mac_address="00:1A:7D:DA:71:13",
            device_name="Test Device",
            protocol=WirelessProtocol.BLUETOOTH,
            bluetooth_version=BluetoothVersion.BT_5_0
        )
        
        result = await bt.knob_attack(device)
        assert 'vulnerable' in result
        assert 'encryption_key_length' in result
    
    @pytest.mark.asyncio
    async def test_wireless_full_assessment(self):
        """Test full wireless assessment"""
        wireless = WirelessExploiter()
        results = await wireless.run_full_assessment()
        
        assert 'wifi_networks' in results
        assert 'bluetooth_devices' in results
        assert 'recommendations' in results


class TestPhase11Engine:
    """Test Phase 11 orchestration engine"""
    
    @pytest.mark.asyncio
    async def test_engine_initialization(self):
        """Test engine initialization"""
        engine = Phase11Engine()
        
        assert engine.iot_discovery is not None
        assert engine.embedded_analyzer is not None
        assert engine.ics_exploiter is not None
        assert engine.wireless_exploiter is not None
    
    @pytest.mark.asyncio
    async def test_full_assessment(self):
        """Test full Phase 11 assessment"""
        engine = Phase11Engine()
        
        results = await engine.run_full_assessment(
            target_network="192.168.1.0/24",
            wireless_scan=True
        )
        
        assert 'phase' in results
        assert results['phase'] == "Phase 11: IoT & Embedded Systems"
        assert 'iot_discovery' in results
        assert 'wireless_assessment' in results
        assert 'risk_summary' in results
        assert 'critical_findings' in results
        assert 'recommendations' in results
    
    @pytest.mark.asyncio
    async def test_integrated_scenarios(self):
        """Test integrated scenario generation"""
        engine = Phase11Engine()
        
        results = await engine.run_full_assessment(wireless_scan=True)
        scenarios = results.get('integrated_scenarios', [])
        
        assert isinstance(scenarios, list)
        for scenario in scenarios:
            assert 'name' in scenario
            assert 'phases' in scenario
            assert 'impact' in scenario
    
    @pytest.mark.asyncio
    async def test_risk_calculation(self):
        """Test risk summary calculation"""
        engine = Phase11Engine()
        
        results = await engine.run_full_assessment()
        risk_summary = results['risk_summary']
        
        assert 'overall_risk' in risk_summary
        assert risk_summary['overall_risk'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        assert 'risk_score' in risk_summary
        assert 0 <= risk_summary['risk_score'] <= 100


class TestIntegration:
    """Integration tests across modules"""
    
    @pytest.mark.asyncio
    async def test_iot_to_wireless_integration(self):
        """Test IoT discovery integration with wireless"""
        iot_discovery = IoTDeviceDiscovery()
        wireless = WirelessExploiter()
        
        # Discover IoT devices
        iot_results = await iot_discovery.run_full_discovery()
        
        # Scan wireless
        wireless_results = await wireless.run_full_assessment()
        
        # Verify both completed
        assert len(iot_results['devices_found']) > 0
        assert len(wireless_results['wifi_networks']) > 0
    
    @pytest.mark.asyncio
    async def test_embedded_to_ics_integration(self):
        """Test embedded analysis integration with ICS"""
        device = EmbeddedSystem(
            device_name="PLC Controller",
            architecture=Architecture.ARM
        )
        
        embedded_analyzer = EmbeddedSystemAnalyzer()
        ics_exploiter = ICSExploiter()
        
        # Analyze embedded system
        embedded_results = await embedded_analyzer.run_full_analysis(device)
        
        # Scan for ICS devices
        ics_results = await ics_exploiter.run_full_assessment("192.168.100.0/24")
        
        # Verify both completed
        assert 'overall_risk' in embedded_results
        assert len(ics_results['devices_found']) > 0


# Pytest configuration
@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
