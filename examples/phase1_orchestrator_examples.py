"""
Phase 1 Orchestrator - Quick Start Examples
"""
import asyncio
from core.phase1_orchestrator import Phase1Orchestrator


async def example_basic_scan():
    """Example: Basic reconnaissance scan"""
    print("=" * 80)
    print("EXAMPLE 1: Basic Reconnaissance")
    print("=" * 80)
    
    orchestrator = Phase1Orchestrator(
        target="example.com",
        recon_mode='quick'
    )
    
    # Set progress callback
    orchestrator.set_progress_callback(lambda msg: print(f"  {msg}"))
    
    results = await orchestrator.execute(
        selected_tools=['dns', 'whois'],
        osint_tools=[],
        crawler_config=None
    )
    
    print("\nResults:")
    print(f"  Risk Level: {results['summary']['risk_level']}")
    print(f"  Completed Tasks: {results['progress']['completed']}/{results['progress']['total_tasks']}")


async def example_full_scan():
    """Example: Full Phase 1 with OSINT and web crawler"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Full Phase 1 Reconnaissance")
    print("=" * 80)
    
    orchestrator = Phase1Orchestrator(
        target="example.com",
        recon_mode='balanced'
    )
    
    orchestrator.set_progress_callback(lambda msg: print(f"  {msg}"))
    
    results = await orchestrator.execute(
        selected_tools=['nmap', 'dns', 'whois', 'subdomain', 'service', 'os'],
        osint_tools=['haveibeenpwned'],
        crawler_config={
            'max_depth': 3,
            'max_pages': 50,
            'evasive': True  # Enable IDS/IPS evasion
        }
    )
    
    print("\nResults:")
    print(f"  Risk Level: {results['summary']['risk_level']}")
    print(f"  Attack Surface Score: {results['summary']['attack_surface_score']}")
    print(f"  High Risk Findings: {results['summary']['high_risk_findings']}")
    
    # Display correlations
    attack_surface = results['correlations']['attack_surface']
    print(f"\nAttack Surface:")
    print(f"  Open Ports: {attack_surface['open_ports']}")
    print(f"  Web Forms: {attack_surface['web_forms']}")
    print(f"  Subdomains: {attack_surface['subdomains']}")
    
    # Display recommendations
    print(f"\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  {rec}")


async def example_stealth_scan():
    """Example: Stealth scan with maximum evasion"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Stealth Reconnaissance")
    print("=" * 80)
    
    orchestrator = Phase1Orchestrator(
        target="example.com",
        recon_mode='stealth'  # Slowest but most evasive
    )
    
    orchestrator.set_progress_callback(lambda msg: print(f"  {msg}"))
    
    results = await orchestrator.execute(
        selected_tools=['dns', 'whois', 'subdomain'],
        osint_tools=[],
        crawler_config={
            'max_depth': 2,
            'max_pages': 25,
            'evasive': True
        }
    )
    
    print(f"\nCompleted in stealth mode")
    print(f"  Tasks: {results['progress']['completed']}/{results['progress']['total_tasks']}")


async def example_correlation_analysis():
    """Example: Focus on data correlation"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Data Correlation Analysis")
    print("=" * 80)
    
    orchestrator = Phase1Orchestrator(
        target="example.com",
        recon_mode='balanced'
    )
    
    results = await orchestrator.execute(
        selected_tools=['nmap', 'dns'],
        osint_tools=['haveibeenpwned'],
        crawler_config={
            'max_depth': 3,
            'max_pages': 50,
            'evasive': True
        }
    )
    
    correlations = results['correlations']
    
    print("\nPort-Service Correlations:")
    for correlation in correlations.get('ports_and_services', []):
        print(f"  Port {correlation['port']}: {correlation['service']} - {correlation['web_technologies']}")
    
    print("\nEmail-Breach Correlations:")
    for correlation in correlations.get('emails_and_breaches', []):
        print(f"  {correlation['email']}: {correlation['breach_count']} breaches (Severity: {correlation['severity']})")
    
    print("\nTechnology-Vulnerability Correlations:")
    for correlation in correlations.get('technologies_and_vulnerabilities', []):
        print(f"  {correlation['technology']} v{correlation.get('version', 'unknown')}: {correlation['recommendation']}")


if __name__ == "__main__":
    # Run examples
    print("Phase 1 Orchestrator - Usage Examples\n")
    
    # Example 1: Basic scan
    asyncio.run(example_basic_scan())
    
    # Example 2: Full scan (commented out - takes longer)
    # asyncio.run(example_full_scan())
    
    # Example 3: Stealth scan
    # asyncio.run(example_stealth_scan())
    
    # Example 4: Correlation analysis
    # asyncio.run(example_correlation_analysis())
    
    print("\n" + "=" * 80)
    print("Examples complete!")
    print("Uncomment other examples to try them.")
    print("=" * 80)
