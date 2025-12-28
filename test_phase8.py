"""
Phase 8: Data Exfiltration & Impact Analysis - Test Suite
"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.phase8_engine import Phase8Engine
from data_discovery import SensitiveDataScanner, PIIDetector, DatabaseAnalyzer
from impact_analysis import BusinessImpactCalculator, CrownJewelIdentifier
from compliance import GDPRAnalyzer, HIPAAAnalyzer, PCIDSSAnalyzer, ComplianceReporter


def print_header(title):
    """Print section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)


def test_sensitive_data_scanner():
    """Test sensitive data scanner"""
    print_header("TEST: Sensitive Data Scanner")
    
    scanner = SensitiveDataScanner()
    
    # Create test file
    test_dir = Path("test_data_phase8")
    test_dir.mkdir(exist_ok=True)
    
    test_file = test_dir / "credentials.txt"
    test_file.write_text("""
    Database Configuration:
    username: admin
    password: SuperSecret123!
    api_key: AKIAIOSFODNN7EXAMPLE
    credit_card: 4532-1234-5678-9010
    
    Personal Information:
    SSN: 123-45-6789
    Email: john.doe@example.com
    """)
    
    # Scan directory
    discoveries = scanner.scan_directory(str(test_dir), max_files=100)
    
    print(f"[+] Discovered {len(discoveries)} sensitive files")
    
    # Generate report
    report = scanner.generate_report()
    print(f"[+] Critical files: {report['by_sensitivity']['critical']}")
    print(f"[+] High sensitivity files: {report['by_sensitivity']['high']}")
    
    # Cleanup
    test_file.unlink()
    test_dir.rmdir()
    
    return len(discoveries) > 0


def test_pii_detector():
    """Test PII detector"""
    print_header("TEST: PII Detector")
    
    detector = PIIDetector()
    
    test_text = """
    Customer Records:
    Name: John Smith
    SSN: 123-45-6789
    Email: john.smith@example.com
    Phone: (555) 123-4567
    Credit Card: 4532-1234-5678-9010
    Date of Birth: 01/15/1985
    """
    
    matches = detector.scan_text(test_text, "test_document")
    
    print(f"[+] Found {len(matches)} PII matches")
    
    stats = detector.get_statistics()
    print(f"[+] PII types detected: {stats['unique_types']}")
    
    for pii_type, info in stats['by_type'].items():
        print(f"    - {pii_type}: {info['count']} matches (avg confidence: {info['avg_confidence']:.2f})")
    
    return len(matches) > 0


def test_business_impact_calculator():
    """Test business impact calculator"""
    print_header("TEST: Business Impact Calculator")
    
    calculator = BusinessImpactCalculator(organization_size='medium')
    
    # Test data breach impact
    breach_impact = calculator.calculate_data_breach_impact(
        records_exposed=50000,
        data_types=['pii', 'financial'],
        detection_time_days=45
    )
    
    print(f"[+] Breach Impact Assessment:")
    print(f"    Severity: {breach_impact.severity}")
    print(f"    Financial Impact: ${breach_impact.financial_impact_usd:,.2f}")
    print(f"    Recovery Time: {breach_impact.recovery_time_hours} hours")
    print(f"    Operational Impact: {breach_impact.operational_impact}")
    print(f"    Regulatory Impact: {breach_impact.regulatory_impact}")
    
    # Test ransomware impact
    ransomware_impact = calculator.calculate_ransomware_impact(
        encrypted_systems=50,
        critical_systems=5,
        downtime_hours=72
    )
    
    print(f"\n[+] Ransomware Impact Assessment:")
    print(f"    Severity: {ransomware_impact.severity}")
    print(f"    Financial Impact: ${ransomware_impact.financial_impact_usd:,.2f}")
    print(f"    Recovery Time: {ransomware_impact.recovery_time_hours} hours")
    
    # Test IP theft impact
    ip_impact = calculator.calculate_ip_theft_impact(
        ip_types=['source_code', 'trade_secret'],
        competitive_advantage_lost=True
    )
    
    print(f"\n[+] IP Theft Impact Assessment:")
    print(f"    Severity: {ip_impact.severity}")
    print(f"    Financial Impact: ${ip_impact.financial_impact_usd:,.2f}")
    
    return True


def test_crown_jewel_identifier():
    """Test crown jewel identifier"""
    print_header("TEST: Crown Jewel Identifier")
    
    identifier = CrownJewelIdentifier()
    
    # Mock database data
    test_databases = [
        {
            'name': 'customer_database',
            'sensitive_tables': ['users', 'payments', 'credit_cards', 'addresses'],
            'record_counts': {'users': 100000, 'payments': 50000},
            'columns': ['email', 'password_hash', 'credit_card_number']
        },
        {
            'name': 'analytics_database',
            'sensitive_tables': ['events'],
            'record_counts': {'events': 1000000},
            'columns': ['user_id', 'event_type']
        }
    ]
    
    crown_jewels = identifier.identify_data_crown_jewels(test_databases)
    
    print(f"[+] Identified {len(crown_jewels)} crown jewel assets")
    
    for jewel in crown_jewels:
        print(f"    - {jewel.name}: Score {jewel.value_score}/100 ({jewel.sensitivity})")
    
    # Generate protection priority
    priority_list = identifier.generate_protection_priority()
    
    print(f"\n[+] Protection Priority List:")
    for item in priority_list[:3]:
        print(f"    {item['priority']}. {item['asset']} (Score: {item['score']})")
    
    return len(crown_jewels) > 0


def test_gdpr_analyzer():
    """Test GDPR analyzer"""
    print_header("TEST: GDPR Compliance Analyzer")
    
    analyzer = GDPRAnalyzer()
    
    # Test data breach analysis
    violations = analyzer.analyze_data_breach(
        pii_records=25000,
        special_categories=True,
        encryption=False,
        notification_time_hours=96
    )
    
    print(f"[+] Found {len(violations)} GDPR violations")
    
    for violation in violations:
        print(f"    - {violation.article}: {violation.description}")
        print(f"      Severity: {violation.severity}")
        print(f"      Potential Fine: €{violation.potential_fine_eur:,.2f}")
    
    # Generate report
    report = analyzer.generate_report()
    
    print(f"\n[+] GDPR Report Summary:")
    print(f"    Total Violations: {report['total_violations']}")
    print(f"    Potential Fines: €{report['potential_fines_eur']:,.2f}")
    print(f"    Critical Violations: {report['severity_breakdown']['critical']}")
    
    return len(violations) > 0


def test_compliance_reporter():
    """Test compliance reporter"""
    print_header("TEST: Compliance Reporter")
    
    reporter = ComplianceReporter()
    
    breach_details = {
        'pii_records': 30000,
        'phi_records': 5000,
        'card_records': 1200,
        'encrypted': False,
        'special_categories': True,
        'notification_hours': 80,
        'notification_days': 4,
        'network_segmented': False
    }
    
    summary = reporter.analyze_breach_compliance(breach_details)
    
    print(f"\n[+] Compliance Summary:")
    print(f"    Regulations Violated: {', '.join(summary['regulations_violated']).upper()}")
    print(f"    Total Potential Fines: ${summary['total_potential_fines_usd']:,.2f}")
    print(f"    Overall Severity: {summary['severity']}")
    
    for regulation, report in summary['reports'].items():
        print(f"\n    {regulation.upper()}:")
        print(f"      Violations: {report['total_violations']}")
        if 'potential_fines_eur' in report:
            print(f"      Fines: €{report['potential_fines_eur']:,.2f}")
        else:
            print(f"      Fines: ${report['potential_fines_usd']:,.2f}")
    
    return len(summary['regulations_violated']) > 0


async def test_phase8_engine():
    """Test Phase 8 engine"""
    print_header("TEST: Phase 8 Engine Integration")
    
    # Create test configuration
    config = {
        'data_discovery': {
            'enabled': True,
            'scan_directories': [],
            'scan_pii': False,
            'analyze_databases': False,
            'enumerate_cloud': False,
            'scan_repositories': False
        },
        'exfiltration': {
            'enabled': False,
            'authorized': False
        },
        'impact_analysis': {
            'enabled': True,
            'simulate_breach': True,
            'breach_records': 10000,
            'data_types': ['pii', 'financial'],
            'detection_days': 30,
            'simulate_ransomware': True,
            'total_systems': 50,
            'critical_systems': ['database', 'payment']
        },
        'compliance': {
            'enabled': True,
            'pii_records': 10000,
            'card_records': 500,
            'encrypted': False,
            'notification_hours': 100
        }
    }
    
    engine = Phase8Engine(output_dir="reports/test_phase8")
    
    print("[*] Running Phase 8 assessment...")
    results = await engine.run_full_assessment(config)
    
    print("\n[+] Phase 8 Assessment Results:")
    
    if 'impact_analysis' in results:
        ia = results['impact_analysis']
        if 'breach_impact' in ia:
            print(f"    Breach Impact: ${ia['breach_impact']['financial_impact_usd']:,.2f}")
        if 'ransomware' in ia:
            print(f"    Ransomware Impact: ${ia['ransomware']['impact']['financial_impact_usd']:,.2f}")
    
    if 'compliance' in results:
        comp = results['compliance']
        if 'total_potential_fines_usd' in comp:
            print(f"    Compliance Fines: ${comp['total_potential_fines_usd']:,.2f}")
    
    return True


def run_all_tests():
    """Run all Phase 8 tests"""
    print("\n" + "="*60)
    print("  PHASE 8: DATA EXFILTRATION & IMPACT ANALYSIS")
    print("  Test Suite")
    print("="*60)
    
    tests = [
        ("Sensitive Data Scanner", test_sensitive_data_scanner),
        ("PII Detector", test_pii_detector),
        ("Business Impact Calculator", test_business_impact_calculator),
        ("Crown Jewel Identifier", test_crown_jewel_identifier),
        ("GDPR Analyzer", test_gdpr_analyzer),
        ("Compliance Reporter", test_compliance_reporter),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
            print(f"\n[{'✓' if result else '✗'}] {test_name}: {'PASSED' if result else 'FAILED'}")
        except Exception as e:
            print(f"\n[✗] {test_name}: FAILED - {str(e)}")
            results.append((test_name, False))
    
    # Run async test
    try:
        result = asyncio.run(test_phase8_engine())
        results.append(("Phase 8 Engine", result))
        print(f"\n[{'✓' if result else '✗'}] Phase 8 Engine: {'PASSED' if result else 'FAILED'}")
    except Exception as e:
        print(f"\n[✗] Phase 8 Engine: FAILED - {str(e)}")
        results.append(("Phase 8 Engine", False))
    
    # Summary
    print("\n" + "="*60)
    print("  TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\nTests Passed: {passed}/{total}")
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    print("\n" + "="*60)
    
    return passed == total


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
