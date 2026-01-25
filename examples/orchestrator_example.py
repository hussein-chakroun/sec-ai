#!/usr/bin/env python3
"""
Main Orchestrator Usage Examples
Demonstrates how to use the Main Orchestrator for autonomous penetration testing
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import MainOrchestrator, OrchestratorConfig, run_autonomous_pentest


async def example_1_quick_autonomous_pentest():
    """
    Example 1: Quick autonomous pentest with all features enabled
    This is the simplest way to run a complete pentest
    """
    print("=" * 80)
    print("Example 1: Quick Autonomous Pentest")
    print("=" * 80)
    
    target = "192.168.1.100"  # Replace with your target
    
    # Quick start - runs complete pentest with all features
    results = await run_autonomous_pentest(
        target=target,
        llm_provider="openai",
        llm_model="gpt-4-turbo-preview",
        enable_all_features=True
    )
    
    print(f"\n✅ Pentest complete!")
    print(f"Phases completed: {results['overall_stats']['phases_completed']}/5")
    print(f"Hosts compromised: {results['overall_stats']['hosts_compromised']}")
    print(f"Credentials harvested: {results['overall_stats']['credentials_harvested']}")


async def example_2_custom_configuration():
    """
    Example 2: Custom orchestrator configuration
    Shows how to customize the orchestrator behavior
    """
    print("\n" + "=" * 80)
    print("Example 2: Custom Configuration")
    print("=" * 80)
    
    # Create custom configuration
    config = OrchestratorConfig(
        # LLM Settings
        llm_provider="openai",
        llm_model="gpt-4-turbo-preview",
        
        # Execution Mode
        execution_mode="autonomous",  # autonomous, guided, manual
        max_iterations=100,
        
        # Phase Control
        enabled_phases=[1, 2, 3],  # Only run phases 1-3
        auto_progress=True,
        stop_at_phase=3,  # Stop after exploitation
        
        # Memory & Learning
        enable_memory=True,
        enable_learning=True,
        enable_agents=True,
        enable_rl=False,  # Reinforcement Learning (experimental)
        
        # Output & Reporting
        output_dir="./custom_reports",
        save_intermediate=True,
        verbose=True,
        
        # Safety & Controls
        max_concurrent_tasks=5,
        
        # Advanced Features
        enable_autonomous_research=True,
        enable_adaptive_strategy=True,
        enable_self_improvement=True
    )
    
    # Create orchestrator
    orchestrator = MainOrchestrator(config)
    
    # Run pentest
    target = "example.com"
    results = await orchestrator.run_complete_pentest(target)
    
    print(f"\n✅ Custom pentest complete!")
    print(f"Stopped at phase: {config.stop_at_phase}")


async def example_3_phased_execution():
    """
    Example 3: Run specific phases only
    Shows how to control which phases execute
    """
    print("\n" + "=" * 80)
    print("Example 3: Phased Execution")
    print("=" * 80)
    
    # Only reconnaissance and scanning
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2],  # Only recon and vuln scanning
        auto_progress=True,
        enable_memory=False,  # Faster without memory
        enable_learning=False
    )
    
    orchestrator = MainOrchestrator(config)
    results = await orchestrator.run_complete_pentest("192.168.1.0/24")
    
    print(f"\n✅ Reconnaissance and scanning complete!")
    print(f"Hosts discovered: {results['overall_stats']['hosts_discovered']}")
    print(f"Vulnerabilities found: {results['overall_stats']['vulnerabilities_found']}")


async def example_4_monitoring_progress():
    """
    Example 4: Monitor orchestration progress in real-time
    Shows how to track progress during execution
    """
    print("\n" + "=" * 80)
    print("Example 4: Progress Monitoring")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3],
        verbose=True
    )
    
    orchestrator = MainOrchestrator(config)
    
    # Start pentest in background
    pentest_task = asyncio.create_task(
        orchestrator.run_complete_pentest("192.168.1.100")
    )
    
    # Monitor progress
    while not pentest_task.done():
        status = orchestrator.get_status()
        print(f"\rPhase {status['current_phase']}/5 - {status['progress_percentage']:.1f}% - "
              f"Elapsed: {status['elapsed_time']:.1f}s", end="")
        await asyncio.sleep(2)
    
    results = await pentest_task
    print(f"\n\n✅ Pentest complete!")


async def example_5_pause_resume():
    """
    Example 5: Pause and resume orchestration
    Shows orchestration control capabilities
    """
    print("\n" + "=" * 80)
    print("Example 5: Pause/Resume Control")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3, 4, 5]
    )
    
    orchestrator = MainOrchestrator(config)
    
    # Start pentest
    pentest_task = asyncio.create_task(
        orchestrator.run_complete_pentest("192.168.1.100")
    )
    
    # Wait a bit
    await asyncio.sleep(30)
    
    # Pause
    await orchestrator.pause()
    print("⏸️  Orchestration paused")
    
    # Wait
    await asyncio.sleep(10)
    
    # Resume
    await orchestrator.resume()
    print("▶️  Orchestration resumed")
    
    # Wait for completion
    results = await pentest_task
    print(f"\n✅ Pentest complete!")


async def example_6_multi_target():
    """
    Example 6: Multi-target pentesting
    Shows how to test multiple targets
    """
    print("\n" + "=" * 80)
    print("Example 6: Multi-Target Pentesting")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3]
    )
    
    targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    
    orchestrator = MainOrchestrator(config)
    
    all_results = []
    for target in targets:
        print(f"\n🎯 Testing target: {target}")
        results = await orchestrator.run_complete_pentest(
            target=target,
            scope=targets  # Full scope for lateral movement
        )
        all_results.append(results)
    
    print(f"\n✅ All targets tested!")
    print(f"Total targets: {len(targets)}")


async def example_7_memory_and_learning():
    """
    Example 7: Memory and learning systems
    Shows how the orchestrator learns from previous engagements
    """
    print("\n" + "=" * 80)
    print("Example 7: Memory & Learning")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3],
        enable_memory=True,
        enable_learning=True,
        enable_self_improvement=True
    )
    
    orchestrator = MainOrchestrator(config)
    
    # First engagement - learns from results
    print("Running first engagement...")
    results1 = await orchestrator.run_complete_pentest("target1.example.com")
    
    # Second engagement - uses learned knowledge
    print("\nRunning second engagement with learned knowledge...")
    results2 = await orchestrator.run_complete_pentest("target2.example.com")
    
    print(f"\n✅ Learning enabled - orchestrator improves over time!")


async def example_8_agent_swarm():
    """
    Example 8: Agent swarm intelligence
    Shows distributed task execution with multiple agents
    """
    print("\n" + "=" * 80)
    print("Example 8: Agent Swarm Intelligence")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3],
        enable_agents=True,
        max_concurrent_tasks=20  # Allow many concurrent tasks
    )
    
    orchestrator = MainOrchestrator(config)
    results = await orchestrator.run_complete_pentest("192.168.1.0/24")
    
    print(f"\n✅ Swarm intelligence - parallel task execution!")


async def example_9_autonomous_research():
    """
    Example 9: Autonomous research and intelligence gathering
    Shows pre-engagement intelligence capabilities
    """
    print("\n" + "=" * 80)
    print("Example 9: Autonomous Research")
    print("=" * 80)
    
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3],
        enable_autonomous_research=True,  # Enable autonomous research
        enable_adaptive_strategy=True     # Enable adaptive strategy planning
    )
    
    orchestrator = MainOrchestrator(config)
    results = await orchestrator.run_complete_pentest("target.example.com")
    
    # Show research results
    if 'pre_engagement_research' in results:
        research = results['pre_engagement_research']
        print(f"\n📚 Pre-engagement research:")
        print(f"   Sources found: {len(research.get('sources', []))}")
    
    if 'attack_strategy' in results:
        print(f"\n🧠 Adaptive attack strategy planned")
    
    print(f"\n✅ Autonomous research enhanced the engagement!")


async def example_10_complete_enterprise():
    """
    Example 10: Complete enterprise penetration test
    Full-featured example with all capabilities
    """
    print("\n" + "=" * 80)
    print("Example 10: Complete Enterprise Pentest")
    print("=" * 80)
    
    config = OrchestratorConfig(
        # LLM Configuration
        llm_provider="openai",
        llm_model="gpt-4-turbo-preview",
        
        # Complete workflow
        execution_mode="autonomous",
        enabled_phases=[1, 2, 3, 4, 5],  # All phases
        auto_progress=True,
        
        # All features enabled
        enable_memory=True,
        enable_learning=True,
        enable_agents=True,
        enable_autonomous_research=True,
        enable_adaptive_strategy=True,
        enable_self_improvement=True,
        
        # Enterprise settings
        max_concurrent_tasks=15,
        output_dir="./enterprise_reports",
        save_intermediate=True,
        verbose=True
    )
    
    orchestrator = MainOrchestrator(config)
    
    # Enterprise target with scope
    results = await orchestrator.run_complete_pentest(
        target="primary-server.corp.local",
        scope=[
            "192.168.1.0/24",      # Internal network
            "10.0.0.0/16",         # Corporate network
            "*.corp.local"         # Domain wildcard
        ]
    )
    
    print(f"\n" + "=" * 80)
    print("ENTERPRISE PENTEST SUMMARY")
    print("=" * 80)
    
    stats = results['overall_stats']
    print(f"Duration: {stats['total_duration']:.2f}s")
    print(f"Phases completed: {stats['phases_completed']}/5")
    print(f"Hosts discovered: {stats['hosts_discovered']}")
    print(f"Vulnerabilities: {stats['vulnerabilities_found']}")
    print(f"Compromised hosts: {stats['hosts_compromised']}")
    print(f"Credentials: {stats['credentials_harvested']}")
    
    if 'executive_summary' in results:
        print(f"\nExecutive Summary:")
        print(results['executive_summary'])
    
    print(f"\n✅ Enterprise pentest complete!")


async def main():
    """Run all examples"""
    print("MAIN ORCHESTRATOR - USAGE EXAMPLES")
    print("=" * 80)
    print("\nSelect an example to run:")
    print("1. Quick Autonomous Pentest")
    print("2. Custom Configuration")
    print("3. Phased Execution")
    print("4. Progress Monitoring")
    print("5. Pause/Resume Control")
    print("6. Multi-Target Testing")
    print("7. Memory & Learning")
    print("8. Agent Swarm Intelligence")
    print("9. Autonomous Research")
    print("10. Complete Enterprise Pentest")
    print("0. Run ALL examples (demo mode)")
    
    choice = input("\nEnter choice (0-10): ").strip()
    
    examples = {
        "1": example_1_quick_autonomous_pentest,
        "2": example_2_custom_configuration,
        "3": example_3_phased_execution,
        "4": example_4_monitoring_progress,
        "5": example_5_pause_resume,
        "6": example_6_multi_target,
        "7": example_7_memory_and_learning,
        "8": example_8_agent_swarm,
        "9": example_9_autonomous_research,
        "10": example_10_complete_enterprise
    }
    
    if choice == "0":
        # Run all examples in sequence (with dummy targets)
        print("\n⚠️  Running all examples with dummy targets...")
        for example_func in examples.values():
            try:
                await example_func()
            except Exception as e:
                print(f"Example failed: {e}")
    elif choice in examples:
        await examples[choice]()
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())
