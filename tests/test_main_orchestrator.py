#!/usr/bin/env python3
"""
Test Main Orchestrator
Quick validation script for the Main Orchestrator
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import MainOrchestrator, OrchestratorConfig
from loguru import logger


async def test_orchestrator_initialization():
    """Test that orchestrator can be initialized"""
    logger.info("Test 1: Orchestrator Initialization")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            llm_model="gpt-4-turbo-preview",
            enabled_phases=[1],  # Only phase 1 for quick test
            enable_memory=False,  # Disable for faster init
            enable_learning=False,
            enable_agents=False
        )
        
        orchestrator = MainOrchestrator(config)
        logger.success("✅ Orchestrator initialized successfully")
        
        return True
    except Exception as e:
        logger.error(f"❌ Initialization failed: {e}")
        return False


async def test_configuration():
    """Test configuration options"""
    logger.info("\nTest 2: Configuration Options")
    
    try:
        # Test various configurations
        configs = [
            OrchestratorConfig(llm_provider="openai", enabled_phases=[1, 2]),
            OrchestratorConfig(llm_provider="openai", enabled_phases=[1, 2, 3], stop_at_phase=2),
            OrchestratorConfig(llm_provider="openai", execution_mode="autonomous"),
            OrchestratorConfig(llm_provider="openai", enable_memory=True, enable_learning=True)
        ]
        
        for i, config in enumerate(configs, 1):
            orchestrator = MainOrchestrator(config)
            logger.info(f"   Config {i}: ✅")
        
        logger.success("✅ All configurations valid")
        return True
    except Exception as e:
        logger.error(f"❌ Configuration test failed: {e}")
        return False


async def test_status_monitoring():
    """Test status monitoring"""
    logger.info("\nTest 3: Status Monitoring")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            enabled_phases=[1],
            enable_memory=False,
            enable_learning=False,
            enable_agents=False
        )
        
        orchestrator = MainOrchestrator(config)
        
        # Get status
        status = orchestrator.get_status()
        
        required_keys = ['status', 'current_phase', 'progress_percentage', 'elapsed_time', 'stats']
        for key in required_keys:
            assert key in status, f"Missing key: {key}"
        
        logger.info(f"   Status: {status['status']}")
        logger.info(f"   Phase: {status['current_phase']}")
        logger.info(f"   Progress: {status['progress_percentage']:.1f}%")
        
        logger.success("✅ Status monitoring works")
        return True
    except Exception as e:
        logger.error(f"❌ Status monitoring failed: {e}")
        return False


async def test_phase_integration():
    """Test phase integration bridge integration"""
    logger.info("\nTest 4: Phase Integration")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            enabled_phases=[1, 2, 3],
            enable_memory=False,
            enable_learning=False,
            enable_agents=False
        )
        
        orchestrator = MainOrchestrator(config)
        
        # Check phase bridge exists
        assert hasattr(orchestrator, 'phase_bridge'), "Phase bridge not initialized"
        assert orchestrator.phase_bridge is not None, "Phase bridge is None"
        
        logger.info(f"   Phase bridge initialized")
        logger.info(f"   Enabled phases: {config.enabled_phases}")
        
        logger.success("✅ Phase integration works")
        return True
    except Exception as e:
        logger.error(f"❌ Phase integration failed: {e}")
        return False


async def test_results_structure():
    """Test results structure"""
    logger.info("\nTest 5: Results Structure")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            enabled_phases=[1],
            enable_memory=False,
            enable_learning=False,
            enable_agents=False
        )
        
        orchestrator = MainOrchestrator(config)
        
        # Check initial results structure
        assert hasattr(orchestrator, 'results'), "Results not initialized"
        assert 'metadata' in orchestrator.results, "Missing metadata"
        assert 'phases' in orchestrator.results, "Missing phases"
        assert 'overall_stats' in orchestrator.results, "Missing overall_stats"
        assert 'timeline' in orchestrator.results, "Missing timeline"
        
        logger.info(f"   Metadata: ✅")
        logger.info(f"   Phases: ✅")
        logger.info(f"   Stats: ✅")
        logger.info(f"   Timeline: ✅")
        
        logger.success("✅ Results structure correct")
        return True
    except Exception as e:
        logger.error(f"❌ Results structure test failed: {e}")
        return False


async def test_control_methods():
    """Test control methods (pause, resume, stop)"""
    logger.info("\nTest 6: Control Methods")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            enabled_phases=[1],
            enable_memory=False,
            enable_learning=False,
            enable_agents=False
        )
        
        orchestrator = MainOrchestrator(config)
        
        # Test pause
        await orchestrator.pause()
        assert orchestrator.progress.status == "paused", "Pause failed"
        logger.info(f"   Pause: ✅")
        
        # Test resume
        await orchestrator.resume()
        assert orchestrator.progress.status == "running", "Resume failed"
        logger.info(f"   Resume: ✅")
        
        # Test stop
        results = await orchestrator.stop()
        assert orchestrator.progress.status == "stopped", "Stop failed"
        assert isinstance(results, dict), "Stop should return results dict"
        logger.info(f"   Stop: ✅")
        
        logger.success("✅ Control methods work")
        return True
    except Exception as e:
        logger.error(f"❌ Control methods test failed: {e}")
        return False


async def test_config_to_dict():
    """Test configuration serialization"""
    logger.info("\nTest 7: Configuration Serialization")
    
    try:
        config = OrchestratorConfig(
            llm_provider="openai",
            enabled_phases=[1, 2, 3],
            enable_memory=True,
            enable_learning=True,
            enable_agents=True
        )
        
        orchestrator = MainOrchestrator(config)
        config_dict = orchestrator._config_to_dict()
        
        assert isinstance(config_dict, dict), "Config dict should be dict"
        assert 'llm_provider' in config_dict, "Missing llm_provider"
        assert 'enabled_phases' in config_dict, "Missing enabled_phases"
        
        logger.info(f"   Serialization: ✅")
        logger.info(f"   Config keys: {list(config_dict.keys())}")
        
        logger.success("✅ Configuration serialization works")
        return True
    except Exception as e:
        logger.error(f"❌ Configuration serialization failed: {e}")
        return False


async def run_all_tests():
    """Run all tests"""
    logger.info("=" * 80)
    logger.info("MAIN ORCHESTRATOR - TEST SUITE")
    logger.info("=" * 80)
    
    tests = [
        test_orchestrator_initialization,
        test_configuration,
        test_status_monitoring,
        test_phase_integration,
        test_results_structure,
        test_control_methods,
        test_config_to_dict
    ]
    
    results = []
    for test in tests:
        result = await test()
        results.append(result)
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    
    passed = sum(results)
    total = len(results)
    
    logger.info(f"Passed: {passed}/{total}")
    logger.info(f"Failed: {total - passed}/{total}")
    
    if passed == total:
        logger.success("\n✅ ALL TESTS PASSED!")
        return 0
    else:
        logger.error(f"\n❌ {total - passed} TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
