"""
Phase 2 Example Usage Script
Demonstrates Phase 2 vulnerability scanning capabilities
"""
import asyncio
import json
from pathlib import Path


async def example_standalone_phase2():
    """Example: Run Phase 2 independently with manual target specification"""
    print("=" * 80)
    print("Example 1: Standalone Phase 2 Scan (Without Phase 1)")
    print("=" * 80)
    
    from core.phase2_orchestrator import Phase2Orchestrator
    
    # Create mock Phase 1 data (simulating reconnaissance results)
    mock_phase1_data = {
        'target': 'example.local',
        'nmap_scan': {
            'hosts': [
                {
                    'ip': '192.168.1.100',
                    'ports': [
                        {'port': 80, 'service': 'http', 'state': 'open', 'version': 'Apache/2.4.41'},
                        {'port': 443, 'service': 'https', 'state': 'open', 'version': 'Apache/2.4.41'},
                        {'port': 22, 'service': 'ssh', 'state': 'open', 'version': 'OpenSSH 7.9p1'},
                        {'port': 3306, 'service': 'mysql', 'state': 'open', 'version': 'MySQL 5.7.30'},
                    ]
                }
            ]
        },
        'dns_enumeration': {
            'domains': ['example.local'],
            'subdomains': ['www.example.local', 'api.example.local']
        }
    }
    
    # Configure Phase 2
    config = {
        'scan_mode': 'balanced',
        'stealth_mode': False,
        'enable_web_scanning': True,
        'enable_cve_matching': True,
        'enable_ssl_testing': True,
        'max_parallel_tasks': 5
    }
    
    # Create orchestrator
    orchestrator = Phase2Orchestrator(config)
    
    # Load Phase 1 data
    print("\n[*] Loading Phase 1 reconnaissance data...")
    orchestrator.load_phase1_results(mock_phase1_data)
    
    # Create scan plan
    print("[*] Creating scan plan...")
    scan_plan = orchestrator.create_scan_plan()
    print(f"[+] Created {len(scan_plan)} scan tasks")
    
    for task in scan_plan[:5]:  # Show first 5 tasks
        print(f"    - {task.task_type}: {task.target} (Priority: {task.priority})")
    
    # Execute scan
    print("\n[*] Executing vulnerability scan...")
    results = await orchestrator.execute_scan_plan()
    
    # Display results
    print("\n" + "=" * 80)
    print("SCAN RESULTS")
    print("=" * 80)
    
    vuln_summary = results['vulnerability_summary']
    print(f"Total Vulnerabilities: {vuln_summary['total']}")
    print(f"  🔴 Critical: {vuln_summary['critical']}")
    print(f"  🟠 High: {vuln_summary['high']}")
    print(f"  🟡 Medium: {vuln_summary['medium']}")
    print(f"  🟢 Low: {vuln_summary['low']}")
    
    # Show sample vulnerabilities
    if results['vulnerabilities']:
        print("\nTop Vulnerabilities:")
        for vuln in results['vulnerabilities'][:3]:
            print(f"\n  [{vuln['severity'].upper()}] {vuln['title']}")
            print(f"  Target: {vuln['affected_target']}")
            if vuln.get('cvss_score'):
                print(f"  CVSS: {vuln['cvss_score']}")
    
    # Save results
    output_file = orchestrator.save_results()
    print(f"\n[+] Results saved to: {output_file}")
    
    return results


async def example_phase1_to_phase2_workflow():
    """Example: Complete Phase 1 → Phase 2 workflow"""
    print("\n" + "=" * 80)
    print("Example 2: Phase 1 → Phase 2 Integration")
    print("=" * 80)
    
    # This example assumes you have Phase 1 results saved
    # If not, you would run Phase 1 first
    
    from core.phase2_orchestrator import Phase2Orchestrator
    
    # Load existing Phase 1 results
    phase1_file = Path("reports/phase1/recon_results_latest.json")
    
    if not phase1_file.exists():
        print(f"[!] Phase 1 results not found at {phase1_file}")
        print("[!] Run Phase 1 first or use Example 1 with mock data")
        return None
    
    print(f"[*] Loading Phase 1 results from {phase1_file}...")
    with open(phase1_file, 'r') as f:
        phase1_data = json.load(f)
    
    # Configure Phase 2 for deep scan
    config = {
        'scan_mode': 'deep',
        'stealth_mode': True,  # Use stealth techniques
        'enable_web_scanning': True,
        'enable_cve_matching': True,
        'enable_ssl_testing': True,
        'enable_network_vuln': True,
        'max_parallel_tasks': 3  # Lower for stealth
    }
    
    # Run Phase 2
    orchestrator = Phase2Orchestrator(config)
    orchestrator.load_phase1_results(phase1_data)
    orchestrator.create_scan_plan()
    
    print("[*] Starting deep vulnerability scan in stealth mode...")
    results = await orchestrator.execute_scan_plan()
    
    # Display critical findings
    critical_vulns = [v for v in results['vulnerabilities'] if v['severity'] == 'critical']
    
    if critical_vulns:
        print("\n⚠️  CRITICAL VULNERABILITIES FOUND!")
        print("=" * 80)
        for vuln in critical_vulns:
            print(f"\n🔴 {vuln['title']}")
            print(f"   ID: {vuln['vuln_id']}")
            print(f"   Target: {vuln['affected_target']}")
            print(f"   CVSS: {vuln.get('cvss_score', 'N/A')}")
            if vuln.get('exploit_available'):
                print(f"   ⚡ EXPLOIT AVAILABLE!")
            print(f"   Remediation: {vuln.get('remediation', 'See vendor advisory')}")
    
    return results


async def example_cve_correlation():
    """Example: CVE correlation for specific services"""
    print("\n" + "=" * 80)
    print("Example 3: CVE Correlation")
    print("=" * 80)
    
    from modules.cve_correlation import CVECorrelationEngine
    
    engine = CVECorrelationEngine()
    
    # Example services to check
    services = [
        {'service': 'apache', 'version': '2.4.41', 'vendor': 'apache'},
        {'service': 'openssh', 'version': '7.9p1', 'vendor': 'openbsd'},
        {'service': 'mysql', 'version': '5.7.30', 'vendor': 'oracle'},
    ]
    
    print("\n[*] Correlating CVEs for discovered services...")
    
    for svc in services:
        print(f"\n[*] Checking {svc['service']} {svc['version']}...")
        
        result = engine.correlate_service(
            service=svc['service'],
            version=svc['version'],
            vendor=svc.get('vendor')
        )
        
        print(f"    Found {result['total_cves']} CVEs")
        if result['critical_count'] > 0:
            print(f"    🔴 {result['critical_count']} Critical")
        if result['high_count'] > 0:
            print(f"    🟠 {result['high_count']} High")
        if result['exploits_available'] > 0:
            print(f"    ⚡ {result['exploits_available']} with exploits")
        
        # Show sample CVEs
        for cve in result['cves'][:2]:
            print(f"\n    - {cve['cve_id']}: {cve['cvss_severity']}")
            print(f"      CVSS: {cve['cvss_score']}")
            if cve.get('exploit_available'):
                print(f"      Exploit: {', '.join(cve['exploit_references'][:1])}")


async def example_individual_scanners():
    """Example: Using individual scanners directly"""
    print("\n" + "=" * 80)
    print("Example 4: Individual Scanner Usage")
    print("=" * 80)
    
    # XSS Scanner
    print("\n[*] XSS Scanner Example:")
    from modules.xss_scanner import XSSScanner
    
    xss_scanner = XSSScanner(timeout=5, max_payloads=5)
    
    # This would test a real URL - here we'll just show the API
    print("    API: xss_scanner.scan_url(url, crawl=True)")
    print("    Returns: {'vulnerabilities': [...], 'tested_parameters': N, ...}")
    
    # SSL Tester
    print("\n[*] SSL/TLS Tester Example:")
    from modules.ssl_tester import SSLTester
    
    ssl_tester = SSLTester(timeout=5)
    
    print("    API: ssl_tester.test_url('https://example.com')")
    print("    Returns: {'security_score': 85, 'vulnerabilities': [...], ...}")
    
    # Nikto Scanner
    print("\n[*] Nikto Scanner Example:")
    from modules.nikto_scanner import NiktoScanner
    
    nikto = NiktoScanner()
    
    if nikto.is_available():
        print("    ✅ Nikto is available")
        print("    API: nikto.quick_scan(target)")
        print("         nikto.full_scan(target)")
        print("         nikto.stealth_scan(target)")
    else:
        print("    ❌ Nikto not installed")
        print("    Install: sudo apt-get install nikto")


async def example_custom_scan_configuration():
    """Example: Custom scan configuration"""
    print("\n" + "=" * 80)
    print("Example 5: Custom Scan Configuration")
    print("=" * 80)
    
    from core.phase2_orchestrator import Phase2Orchestrator
    
    # Aggressive scan configuration
    aggressive_config = {
        'scan_mode': 'aggressive',
        'stealth_mode': False,
        'max_parallel_tasks': 15,
        'timeout_per_task': 600,  # 10 minutes
        'enable_web_scanning': True,
        'enable_cve_matching': True,
        'enable_network_vuln': True,
        'enable_ssl_testing': True,
        'enable_default_creds': True,
    }
    
    print("[*] Aggressive Scan Configuration:")
    for key, value in aggressive_config.items():
        print(f"    {key}: {value}")
    
    # Stealth scan configuration
    stealth_config = {
        'scan_mode': 'balanced',
        'stealth_mode': True,
        'max_parallel_tasks': 2,  # Low concurrency
        'timeout_per_task': 900,  # Longer timeouts
        'enable_web_scanning': True,
        'enable_cve_matching': True,  # Passive, always safe
        'enable_network_vuln': False,  # Skip noisy scans
        'enable_ssl_testing': True,
        'enable_default_creds': False,
    }
    
    print("\n[*] Stealth Scan Configuration:")
    for key, value in stealth_config.items():
        print(f"    {key}: {value}")
    
    print("\n[+] Use orchestrator = Phase2Orchestrator(config) with either config")


async def main():
    """Run all examples"""
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                     PHASE 2 - VULNERABILITY SCANNING                         ║
    ║                           Example Usage Script                               ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Example 1: Standalone Phase 2 with mock data
        await example_standalone_phase2()
        
        # Example 2: Phase 1 → Phase 2 workflow (if Phase 1 results exist)
        # Uncomment to run if you have Phase 1 results
        # await example_phase1_to_phase2_workflow()
        
        # Example 3: CVE Correlation
        await example_cve_correlation()
        
        # Example 4: Individual scanners
        await example_individual_scanners()
        
        # Example 5: Custom configurations
        await example_custom_scan_configuration()
        
        print("\n" + "=" * 80)
        print("✅ All examples completed!")
        print("=" * 80)
        print("\nNext Steps:")
        print("1. Review PHASE2_IMPLEMENTATION.md for detailed documentation")
        print("2. Run Phase 1 reconnaissance to gather targets")
        print("3. Execute Phase 2 vulnerability scan")
        print("4. Export results and proceed to exploitation (Phase 3+)")
        print("\nFor GUI usage: python main.py (Phase 2 tab)")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())
