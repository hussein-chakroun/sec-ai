#!/usr/bin/env python3
"""
SEC-AI - Autonomous Pentesting Platform
Main Entry Point
"""
import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from gui import main as gui_main
from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
from core.pentest_engine import PentestEngine
from core.config import config
from reports import ReportGenerator
from loguru import logger


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
    
    orchestrator = LLMOrchestrator(provider)
    engine = PentestEngine(orchestrator)
    
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
        description="SEC-AI - Autonomous Pentesting Platform"
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
    
    args = parser.parse_args()
    
    # Determine mode
    if args.cli:
        if not args.target:
            parser.error("--target is required in CLI mode")
        return run_cli(args)
    else:
        # Default to GUI
        gui_main()
        return 0


if __name__ == "__main__":
    sys.exit(main())
