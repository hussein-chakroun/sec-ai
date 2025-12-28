"""
Phase 7 Installation and Integration Test
"""

import sys
import asyncio
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_active_directory_imports():
    """Test Active Directory module imports"""
    try:
        logger.info("Testing Active Directory imports...")
        
        from active_directory.bloodhound_analyzer import BloodHoundAnalyzer
        from active_directory.kerberos_attacks import KerberosAttacks
        from active_directory.dcsync import DCSyncAttack
        from active_directory.ntlm_relay import NTLMRelay
        from active_directory.gpo_abuse import GPOAbuse
        
        logger.info("✓ All Active Directory modules imported successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Active Directory import failed: {e}")
        return False


async def test_lateral_movement_imports():
    """Test Lateral Movement module imports"""
    try:
        logger.info("Testing Lateral Movement imports...")
        
        from lateral_movement.smb_exploitation import SMBExploitation
        from lateral_movement.rdp_hijacking import RDPHijacking
        from lateral_movement.ssh_lateral import SSHLateral
        from lateral_movement.database_hopping import DatabaseHopping
        from lateral_movement.container_escape import ContainerEscape
        from lateral_movement.cloud_metadata_abuse import CloudMetadataAbuse
        
        logger.info("✓ All Lateral Movement modules imported successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Lateral Movement import failed: {e}")
        return False


async def test_privilege_escalation_imports():
    """Test Privilege Escalation module imports"""
    try:
        logger.info("Testing Privilege Escalation imports...")
        
        from privilege_escalation.kernel_exploit_db import KernelExploitDatabase
        from privilege_escalation.misconfiguration_enum import MisconfigurationEnumerator
        from privilege_escalation.token_manipulation import TokenManipulator
        from privilege_escalation.process_injection import ProcessInjector
        from privilege_escalation.dll_hijacking import DLLHijacker
        
        logger.info("✓ All Privilege Escalation modules imported successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Privilege Escalation import failed: {e}")
        return False


async def test_pivoting_imports():
    """Test Pivoting module imports"""
    try:
        logger.info("Testing Pivoting imports...")
        
        from pivoting.port_forwarding import PortForwarder
        from pivoting.socks_proxy import SOCKSProxy
        from pivoting.vpn_establishment import VPNEstablisher
        from pivoting.route_manipulation import RouteManipulator
        from pivoting.ssh_tunneling import SSHTunneling
        
        logger.info("✓ All Pivoting modules imported successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Pivoting import failed: {e}")
        return False


async def test_phase7_engine():
    """Test Phase 7 engine"""
    try:
        logger.info("Testing Phase 7 Engine...")
        
        from core.phase7_engine import Phase7Engine
        
        # Initialize engine
        engine = Phase7Engine(domain='test.local', os_type='windows')
        
        logger.info(f"  - Domain: {engine.domain}")
        logger.info(f"  - OS Type: {engine.os_type}")
        logger.info(f"  - Compromised hosts: {len(engine.compromised_hosts)}")
        
        # Test report generation
        report = await engine.generate_phase7_report()
        logger.info(f"  - Report generated: {report['phase']}")
        
        logger.info("✓ Phase 7 Engine operational")
        return True
    except Exception as e:
        logger.error(f"✗ Phase 7 Engine failed: {e}")
        return False


async def test_active_directory_functionality():
    """Test Active Directory module functionality"""
    try:
        logger.info("Testing Active Directory functionality...")
        
        from active_directory.kerberos_attacks import KerberosAttacks
        from active_directory.gpo_abuse import GPOAbuse
        
        # Test Kerberos module
        kerb = KerberosAttacks('test.local')
        logger.info("  - Kerberos module initialized")
        
        # Test GPO abuse
        gpo = GPOAbuse('test.local')
        logger.info("  - GPO abuse module initialized")
        
        logger.info("✓ Active Directory modules functional")
        return True
    except Exception as e:
        logger.error(f"✗ Active Directory functionality failed: {e}")
        return False


async def test_privilege_escalation_functionality():
    """Test Privilege Escalation functionality"""
    try:
        logger.info("Testing Privilege Escalation functionality...")
        
        from privilege_escalation.kernel_exploit_db import KernelExploitDatabase
        
        # Test kernel exploit database
        exploits_db = KernelExploitDatabase()
        logger.info(f"  - Loaded {len(exploits_db.exploits)} kernel exploits")
        
        # Find exploits for Windows 10
        windows_exploits = await exploits_db.find_exploits_for_system('Windows', '10')
        logger.info(f"  - Found {len(windows_exploits)} Windows 10 exploits")
        
        # Find exploits for Linux
        linux_exploits = await exploits_db.find_exploits_for_system('Linux', 'Ubuntu 20.04')
        logger.info(f"  - Found {len(linux_exploits)} Ubuntu 20.04 exploits")
        
        logger.info("✓ Privilege Escalation modules functional")
        return True
    except Exception as e:
        logger.error(f"✗ Privilege Escalation functionality failed: {e}")
        return False


async def test_lateral_movement_functionality():
    """Test Lateral Movement functionality"""
    try:
        logger.info("Testing Lateral Movement functionality...")
        
        from lateral_movement.smb_exploitation import SMBExploitation
        from lateral_movement.ssh_lateral import SSHLateral
        
        # Test SMB module
        smb = SMBExploitation()
        logger.info("  - SMB exploitation module initialized")
        
        # Test SSH module
        ssh = SSHLateral()
        logger.info("  - SSH lateral movement module initialized")
        
        logger.info("✓ Lateral Movement modules functional")
        return True
    except Exception as e:
        logger.error(f"✗ Lateral Movement functionality failed: {e}")
        return False


async def test_pivoting_functionality():
    """Test Pivoting functionality"""
    try:
        logger.info("Testing Pivoting functionality...")
        
        from pivoting.port_forwarding import PortForwarder
        from pivoting.socks_proxy import SOCKSProxy
        
        # Test port forwarder
        pf = PortForwarder()
        active_forwards = pf.list_active_forwards()
        logger.info(f"  - Port forwarder initialized ({len(active_forwards)} active)")
        
        # Test SOCKS proxy
        socks = SOCKSProxy()
        active_proxies = socks.get_active_proxies()
        logger.info(f"  - SOCKS proxy initialized ({len(active_proxies)} active)")
        
        logger.info("✓ Pivoting modules functional")
        return True
    except Exception as e:
        logger.error(f"✗ Pivoting functionality failed: {e}")
        return False


async def run_all_tests():
    """Run all Phase 7 tests"""
    logger.info("=" * 60)
    logger.info("Phase 7: Lateral Movement & Domain Dominance - Test Suite")
    logger.info("=" * 60)
    
    results = []
    
    # Import tests
    results.append(await test_active_directory_imports())
    results.append(await test_lateral_movement_imports())
    results.append(await test_privilege_escalation_imports())
    results.append(await test_pivoting_imports())
    
    # Functionality tests
    results.append(await test_active_directory_functionality())
    results.append(await test_privilege_escalation_functionality())
    results.append(await test_lateral_movement_functionality())
    results.append(await test_pivoting_functionality())
    
    # Engine test
    results.append(await test_phase7_engine())
    
    # Summary
    logger.info("=" * 60)
    passed = sum(results)
    total = len(results)
    logger.info(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        logger.info("✓ All Phase 7 tests passed!")
        logger.info("\nPhase 7 modules created:")
        logger.info("  - Active Directory: 5 modules")
        logger.info("  - Lateral Movement: 6 modules")
        logger.info("  - Privilege Escalation: 5 modules")
        logger.info("  - Pivoting: 5 modules")
        logger.info("  - Total: 21 modules + orchestrator")
        return 0
    else:
        logger.error(f"✗ {total - passed} tests failed")
        return 1
    
    logger.info("=" * 60)


if __name__ == '__main__':
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
