#!/usr/bin/env python3
"""
EsecAi - AI-Powered Security Testing Platform
Main Entry Point
"""
import sys
import argparse
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from gui import main as gui_main
from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
from core.pentest_engine import PentestEngine
from core.config import config
from reports import ReportGenerator
from loguru import logger

# Phase engines
from core.phase12_engine import Phase12Engine
from core.phase_integration_bridge import PhaseIntegrationBridge, run_automated_pentest
from core.main_orchestrator import MainOrchestrator, OrchestratorConfig, run_autonomous_pentest


def run_cli(args):
    """Run in CLI mode"""
    logger.info("Starting CLI mode")
    
    # Initialize LLM provider
    api_key = config.openai_api_key if config.llm_provider == "openai" else config.anthropic_api_key
    
    if not api_key:
        logger.error("No API key found. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env")
        return 1
    
    if config.llm_provider == "openai":
        provider = OpenAIProvider(api_key, config.llm_model)
    else:
        provider = AnthropicProvider(api_key, config.llm_model)
    
    # Initialize orchestrator with low context mode if configured
    orchestrator = LLMOrchestrator(
        provider,
        low_context_mode=config.low_context_mode,
        chunk_size=config.low_context_chunk_size
    )
    engine = PentestEngine(orchestrator)
    
    if config.low_context_mode:
        logger.warning("Low context mode enabled - processing will take longer but use less memory")
    
    # Check tools
    logger.info("Checking installed tools...")
    tools_status = engine.check_tools()
    for tool, installed in tools_status.items():
        status = "✅" if installed else "❌"
        logger.info(f"{status} {tool}")
    
    # Run pentest
    logger.info(f"Starting pentest against {args.target}")
    results = engine.run_pentest(args.target, args.max_iterations)
    
    # Generate reports
    logger.info("Generating reports...")
    report_gen = ReportGenerator(config.report_output_dir)
    files = report_gen.generate_report(results, formats=args.formats)
    
    logger.info("Reports generated:")
    for fmt, path in files.items():
        logger.info(f"  {fmt}: {path}")
    
    logger.info("Pentest completed successfully!")
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="EsecAi - AI-Powered Security Testing Platform"
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch GUI interface (default)"
    )
    
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run in CLI mode"
    )
    
    parser.add_argument(
        "--target",
        type=str,
        help="Target for CLI mode (IP, domain, or URL)"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum iterations for autonomous scanning (default: 10)"
    )
    
    parser.add_argument(
        "--formats",
        nargs="+",
        default=["json", "html"],
        choices=["json", "html", "txt"],
        help="Report formats (default: json html)"
    )
    
    parser.add_argument(
        "--phase12",
        action="store_true",
        help="Run Phase 12: AI-Powered Adaptive Exploitation"
    )
    
    parser.add_argument(
        "--phase",
        type=int,
        choices=[1, 2, 3, 4, 5, 12],
        help="Run specific phase (1=Recon, 2=Vuln Scan, 3=Exploitation, 4=Post-Exploitation, 5=Lateral Movement, 12=AI Adaptive)"
    )
    
    parser.add_argument(
        "--phase123",
        action="store_true",
        help="Run Phase 1→2→3 automated pentest workflow (Recon→Vuln Scan→Exploitation)"
    )
    
    parser.add_argument(
        "--phase12345",
        action="store_true",
        help="Run complete Phase 1→2→3→4→5 automated pentest workflow (Full Pentest + Post-Exploitation + Lateral Movement)"
    )
    
    parser.add_argument(
        "--orchestrator",
        action="store_true",
        help="Use Main Orchestrator for complete autonomous pentesting with advanced AI features"
    )
    
    parser.add_argument(
        "--enable-all",
        action="store_true",
        help="Enable all advanced features (memory, learning, agents, autonomous research)"
    )
    
    args = parser.parse_args()
    
    # Determine mode
    if args.cli or args.phase12 or args.phase or args.phase123 or args.phase12345 or args.orchestrator:
        if not args.target:
            parser.error("--target is required in CLI mode")
        
        # Check for Main Orchestrator mode
        if args.orchestrator:
            logger.info("Using Main Orchestrator - Advanced Autonomous Pentesting")
            return asyncio.run(run_main_orchestrator(args))
        
        # Check for Phase 1→2→3→4→5 complete workflow
        if args.phase12345:
            logger.info("Running Phase 1→2→3→4→5: Complete Automated Pentest + Post-Exploitation + Lateral Movement")
            return asyncio.run(run_phase12345_workflow(args))
        
        # Check for Phase 1→2→3 workflow
        if args.phase123:
            logger.info("Running Phase 1→2→3: Complete Automated Pentest")
            return asyncio.run(run_phase123_workflow(args))
        
        # Check for Phase 4 or 5
        if args.phase == 4:
            logger.info("Running Phase 4: Post-Exploitation & Privilege Escalation")
            logger.warning("Phase 4 requires Phase 3 results. Use --phase12345 for complete workflow.")
            return 1
        
        if args.phase == 5:
            logger.info("Running Phase 5: Lateral Movement & Domain Dominance")
            logger.warning("Phase 5 requires Phase 4 results. Use --phase12345 for complete workflow.")
            return 1
        
        # Check for Phase 3
        if args.phase == 3:
            logger.info("Running Phase 3: Intelligent Exploitation")
            logger.warning("Phase 3 requires Phase 1 & 2 results. Use --phase123 for complete workflow.")
            return 1
        
        # Check for Phase 12
        if args.phase12 or args.phase == 12:
            logger.info("Running Phase 12: AI-Powered Adaptive Exploitation")
            return asyncio.run(run_phase12(args))
        
        return run_cli(args)
    else:
        # Default to GUI
        gui_main()
        return 0


async def run_phase123_workflow(args):
    """Run complete Phase 1→2→3 automated pentest workflow"""
    logger.info("=" * 80)
    logger.info("STARTING COMPLETE AUTOMATED PENETRATION TEST")
    logger.info(f"Target: {args.target}")
    logger.info("=" * 80)
    
    # Initialize LLM provider
    api_key = config.openai_api_key if config.llm_provider == "openai" else config.anthropic_api_key
    
    if not api_key:
        logger.error("No API key found. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env")
        return 1
    
    if config.llm_provider == "openai":
        from core.llm_orchestrator import OpenAIProvider
        provider = OpenAIProvider(api_key, config.llm_model)
    else:
        from core.llm_orchestrator import AnthropicProvider
        provider = AnthropicProvider(api_key, config.llm_model)
    
    orchestrator = LLMOrchestrator(
        provider,
        low_context_mode=config.low_context_mode,
        chunk_size=config.low_context_chunk_size
    )
    
    # Configuration for all phases
    pentest_config = {
        'auto_progress': True,
        'save_intermediate': True,
        'output_dir': './reports',
        'phase1': {
            'scan_mode': 'balanced',  # quick, balanced, deep
            'enable_osint': True,
            'enable_subdomain_enum': True
        },
        'phase2': {
            'scan_mode': 'balanced',  # quick, balanced, deep, aggressive
            'enable_cve_correlation': True,
            'severity_threshold': 'medium'  # Only scan medium+ vulns
        },
        'phase3': {
            'max_attempts_per_vuln': 3,
            'exploit_timeout': 300,
            'safe_mode': True,
            'aggressive_mode': False,
            'require_confirmation': False
        }
    }
    
    # Run automated pentest
    try:
        results = await run_automated_pentest(
            args.target,
            orchestrator,
            pentest_config
        )
        
        # Display executive summary
        logger.info("=" * 80)
        logger.info("PENETRATION TEST COMPLETE - EXECUTIVE SUMMARY")
        logger.info("=" * 80)
        
        summary = results.get('executive_summary', {})
        pentest_summary = results.get('pentest_summary', {})
        
        logger.info(f"Duration: {pentest_summary.get('duration_formatted', 'N/A')}")
        logger.info(f"Phases Completed: {pentest_summary.get('phases_completed', 0)}/3")
        logger.info(f"Status: {pentest_summary.get('status', 'unknown').upper()}")
        logger.info("")
        logger.info("FINDINGS:")
        logger.info(f"  • Targets Scanned: {summary.get('targets_scanned', 0)}")
        logger.info(f"  • Services Discovered: {summary.get('services_discovered', 0)}")
        logger.info(f"  • Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
        logger.info(f"  • Critical Vulnerabilities: {summary.get('critical_vulnerabilities', 0)}")
        logger.info(f"  • High Vulnerabilities: {summary.get('high_vulnerabilities', 0)}")
        logger.info(f"  • Successful Exploits: {summary.get('successful_exploits', 0)}")
        logger.info(f"  • Shells Obtained: {summary.get('shells_obtained', 0)}")
        logger.info(f"  • Compromised Hosts: {len(summary.get('compromised_hosts', []))}")
        logger.info("")
        
        risk_level = summary.get('risk_level', 'unknown').upper()
        risk_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
        }
        color = risk_colors.get(risk_level, '')
        reset = '\033[0m'
        
        logger.info(f"OVERALL RISK LEVEL: {color}{risk_level}{reset}")
        logger.info("=" * 80)
        
        # Generate reports
        if args.formats:
            logger.info("Generating detailed reports...")
            report_gen = ReportGenerator(config.report_output_dir)
            files = report_gen.generate_report(results, formats=args.formats)
            
            logger.info("Reports generated:")
            for fmt, path in files.items():
                logger.info(f"  {fmt}: {path}")
        
        logger.success("Automated penetration test completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"Automated pentest failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


async def run_phase12345_workflow(args):
    """Run complete Phase 1→2→3→4→5 automated pentest workflow"""
    logger.info("=" * 80)
    logger.info("STARTING COMPLETE AUTOMATED PENETRATION TEST")
    logger.info("Phase 1: Reconnaissance → Phase 2: Vulnerability Scanning")
    logger.info("→ Phase 3: Exploitation → Phase 4: Post-Exploitation")
    logger.info("→ Phase 5: Lateral Movement & Domain Dominance")
    logger.info(f"Target: {args.target}")
    logger.info("=" * 80)
    
    # Initialize LLM provider
    api_key = config.openai_api_key if config.llm_provider == "openai" else config.anthropic_api_key
    
    if not api_key:
        logger.error("No API key found. Please set OPENAI_API_KEY or ANTHROPIC_API_KEY in .env")
        return 1
    
    if config.llm_provider == "openai":
        from core.llm_orchestrator import OpenAIProvider
        provider = OpenAIProvider(api_key, config.llm_model)
    else:
        from core.llm_orchestrator import AnthropicProvider
        provider = AnthropicProvider(api_key, config.llm_model)
    
    orchestrator = LLMOrchestrator(
        provider,
        low_context_mode=config.low_context_mode,
        chunk_size=config.low_context_chunk_size
    )
    
    # Configuration for all phases
    pentest_config = {
        'auto_progress': True,
        'save_intermediate': True,
        'output_dir': './reports',
        'phase1': {
            'scan_mode': 'balanced',  # quick, balanced, deep
            'enable_osint': True,
            'enable_subdomain_enum': True
        },
        'phase2': {
            'scan_mode': 'balanced',  # quick, balanced, deep, aggressive
            'enable_cve_correlation': True,
            'severity_threshold': 'medium'  # Only scan medium+ vulns
        },
        'phase3': {
            'max_attempts_per_vuln': 3,
            'exploit_timeout': 300,
            'safe_mode': True,
            'aggressive_mode': False,
            'require_confirmation': False
        },
        'phase4': {
            'privilege_escalation': {
                'enabled': True,
                'max_attempts': 3,
                'techniques': ['kernel_exploits', 'suid_binaries', 'sudo_abuse', 'dll_hijacking', 'token_manipulation']
            },
            'credential_harvesting': {
                'enabled': True,
                'methods': ['mimikatz', 'browser_dump', 'memory_scrape', 'config_files']
            },
            'persistence': {
                'enabled': True,
                'stealth_mode': True,
                'max_mechanisms': 3
            }
        },
        'phase5': {
            'lateral_movement': {
                'enabled': True,
                'max_hops': 5,
                'techniques': ['pass_the_hash', 'pass_the_ticket', 'ssh', 'rdp', 'winrm', 'psexec', 'wmi']
            },
            'active_directory': {
                'enabled': True,
                'attacks': ['kerberoasting', 'asrep_roasting', 'dcsync', 'golden_ticket']
            },
            'domain_dominance': {
                'target_dc': True,
                'bloodhound_analysis': True
            }
        }
    }
    
    # Initialize integration bridge
    bridge = PhaseIntegrationBridge(orchestrator, pentest_config)
    
    # Run complete pentest (all 5 phases)
    try:
        results = await bridge.run_complete_pentest(
            args.target,
            phase1_config=pentest_config.get('phase1'),
            phase2_config=pentest_config.get('phase2'),
            phase3_config=pentest_config.get('phase3'),
            phase4_config=pentest_config.get('phase4'),
            phase5_config=pentest_config.get('phase5'),
            stop_at_phase=5  # Run all 5 phases
        )
        
        # Display executive summary
        logger.info("=" * 80)
        logger.info("PENETRATION TEST COMPLETE - EXECUTIVE SUMMARY")
        logger.info("=" * 80)
        
        summary = results.get('executive_summary', {})
        pentest_summary = results.get('pentest_summary', {})
        
        logger.info(f"Duration: {pentest_summary.get('duration_formatted', 'N/A')}")
        logger.info(f"Phases Completed: {pentest_summary.get('phases_completed', 0)}/5")
        logger.info(f"Status: {pentest_summary.get('status', 'unknown').upper()}")
        logger.info("")
        
        logger.info("PHASE 1-2: RECONNAISSANCE & VULNERABILITY SCANNING")
        logger.info(f"  • Targets Scanned: {summary.get('targets_scanned', 0)}")
        logger.info(f"  • Services Discovered: {summary.get('services_discovered', 0)}")
        logger.info(f"  • Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
        logger.info(f"  • Critical Vulnerabilities: {summary.get('critical_vulnerabilities', 0)}")
        logger.info(f"  • High Vulnerabilities: {summary.get('high_vulnerabilities', 0)}")
        logger.info("")
        
        logger.info("PHASE 3: EXPLOITATION")
        logger.info(f"  • Successful Exploits: {summary.get('successful_exploits', 0)}")
        logger.info(f"  • Shells Obtained: {summary.get('shells_obtained', 0)}")
        logger.info(f"  • Initially Compromised Hosts: {len(summary.get('compromised_hosts', []))}")
        logger.info("")
        
        logger.info("PHASE 4: POST-EXPLOITATION")
        logger.info(f"  • Fully Compromised Hosts: {summary.get('fully_compromised_hosts', 0)}")
        logger.info(f"  • Credentials Harvested: {summary.get('credentials_harvested', 0)}")
        logger.info(f"  • Persistence Mechanisms Installed: {summary.get('persistence_installed', 0)}")
        logger.info("")
        
        logger.info("PHASE 5: LATERAL MOVEMENT & DOMAIN DOMINANCE")
        logger.info(f"  • Lateral Movements: {summary.get('lateral_movements', 0)}")
        logger.info(f"  • Domain Admin Achieved: {'YES ⚠️' if summary.get('domain_admin_achieved') else 'NO'}")
        logger.info(f"  • Domain Controllers Compromised: {summary.get('domain_controllers_compromised', 0)}")
        logger.info("")
        
        risk_level = summary.get('risk_level', 'unknown').upper()
        risk_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[92m',       # Green
        }
        color = risk_colors.get(risk_level, '')
        reset = '\033[0m'
        
        logger.info(f"OVERALL RISK LEVEL: {color}{risk_level}{reset}")
        logger.info("=" * 80)
        
        # Generate reports
        if args.formats:
            logger.info("Generating detailed reports...")
            report_gen = ReportGenerator(config.report_output_dir)
            files = report_gen.generate_report(results, formats=args.formats)
            
            logger.info("Reports generated:")
            for fmt, path in files.items():
                logger.info(f"  {fmt}: {path}")
        
        logger.success("Complete automated penetration test (Phase 1-5) completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"Complete pentest failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


async def run_main_orchestrator(args):
    """Run Main Orchestrator for complete autonomous pentesting"""
    logger.info("=" * 80)
    logger.info("MAIN ORCHESTRATOR - ADVANCED AUTONOMOUS PENETRATION TESTING")
    logger.info("=" * 80)
    logger.info(f"Target: {args.target}")
    logger.info(f"Advanced Features: {'ENABLED' if args.enable_all else 'STANDARD'}")
    logger.info("=" * 80)
    
    try:
        # Create orchestrator configuration
        orch_config = OrchestratorConfig(
            llm_provider=config.llm_provider,
            llm_model=config.llm_model,
            execution_mode="autonomous",
            enabled_phases=[1, 2, 3, 4, 5],
            auto_progress=True,
            enable_memory=args.enable_all or config.enable_memory if hasattr(config, 'enable_memory') else True,
            enable_learning=args.enable_all or config.enable_learning if hasattr(config, 'enable_learning') else True,
            enable_agents=args.enable_all or config.enable_agents if hasattr(config, 'enable_agents') else True,
            enable_autonomous_research=args.enable_all,
            enable_adaptive_strategy=args.enable_all,
            enable_self_improvement=args.enable_all,
            output_dir=config.report_output_dir,
            save_intermediate=True,
            verbose=True,
            max_concurrent_tasks=config.max_concurrent_tasks if hasattr(config, 'max_concurrent_tasks') else 10
        )
        
        # Create orchestrator
        orchestrator = MainOrchestrator(orch_config)
        
        # Run complete pentest
        results = await orchestrator.run_complete_pentest(args.target)
        
        # Display results
        logger.info("")
        logger.info("=" * 80)
        logger.info("MAIN ORCHESTRATOR - EXECUTION COMPLETE")
        logger.info("=" * 80)
        
        overall_stats = results.get('overall_stats', {})
        
        logger.info(f"Total Duration: {overall_stats.get('total_duration', 0):.2f}s")
        logger.info(f"Phases Completed: {overall_stats.get('phases_completed', 0)}/5")
        logger.info("")
        logger.info("FINDINGS:")
        logger.info(f"  • Hosts Discovered: {overall_stats.get('hosts_discovered', 0)}")
        logger.info(f"  • Vulnerabilities Found: {overall_stats.get('vulnerabilities_found', 0)}")
        logger.info(f"  • Successful Exploits: {overall_stats.get('exploits_successful', 0)}")
        logger.info(f"  • Hosts Compromised: {overall_stats.get('hosts_compromised', 0)}")
        logger.info(f"  • Credentials Harvested: {overall_stats.get('credentials_harvested', 0)}")
        logger.info("")
        
        # Display executive summary if available
        if 'executive_summary' in results:
            logger.info("EXECUTIVE SUMMARY:")
            logger.info(results['executive_summary'])
        
        logger.info("=" * 80)
        
        # Generate reports
        if args.formats:
            logger.info("\nGenerating detailed reports...")
            report_gen = ReportGenerator(config.report_output_dir)
            files = report_gen.generate_report(results, formats=args.formats)
            
            logger.info("Reports generated:")
            for fmt, path in files.items():
                logger.info(f"  {fmt}: {path}")
        
        logger.success("\n✅ Main Orchestrator execution completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"❌ Main Orchestrator failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


async def run_phase12(args):
    """Run Phase 12: AI-Powered Adaptive Exploitation"""
    logger.info("Initializing Phase 12 Engine")
    
    config_phase12 = {
        'rl_config': {
            'enabled': True,
            'learning_rate': 0.1,
            'discount_factor': 0.95
        },
        'evolution_config': {
            'enabled': True,
            'population_size': 100,
            'generations': 50
        },
        'poisoning_config': {
            'enabled': True
        },
        'evasion_config': {
            'enabled': True
        },
        'inversion_config': {
            'enabled': True
        },
        'prompt_config': {
            'enabled': True
        },
        'jailbreak_config': {
            'enabled': True
        },
        'cve_config': {
            'enabled': True,
            'severity_threshold': 7.0,
            'days_back': 30
        },
        'intel_config': {
            'enabled': True
        }
    }
    
    engine = Phase12Engine(config_phase12)
    
    options = {
        'enable_rl_exploitation': True,
        'enable_adversarial_ml': True,
        'enable_nlp_exploitation': True,
        'enable_autonomous_research': True,
        'ql_episodes': 1000,
        'population_size': 100,
        'generations': 50,
        'mutation_rate': 0.1,
        'poisoning_ratio': 0.1,
        'perturbation_budget': 0.05,
        'evasion_method': 'fgsm',
        'jailbreak_iterations': 100,
        'severity_threshold': 7.0
    }
    
    logger.info(f"Starting Phase 12 assessment on {args.target}")
    results = await engine.execute(args.target, options)
    
    logger.info("Phase 12 completed successfully")
    logger.info(f"Risk Level: {results['summary']['risk_level'].upper()}")
    logger.info(f"ML Vulnerabilities: {results['summary']['ml_vulnerabilities']}")
    logger.info(f"NLP Vulnerabilities: {results['summary']['nlp_vulnerabilities']}")
    logger.info(f"Research Findings: {results['summary']['research_findings']}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
