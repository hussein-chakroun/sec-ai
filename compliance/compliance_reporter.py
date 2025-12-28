"""
Compliance Reporter
Unified compliance reporting across regulations
"""

import json
from typing import Dict, List
from .gdpr_analyzer import GDPRAnalyzer
from .hipaa_analyzer import HIPAAAnalyzer
from .pci_dss_analyzer import PCIDSSAnalyzer

class ComplianceReporter:
    """
    Unified compliance reporting
    """
    
    def __init__(self):
        self.gdpr = GDPRAnalyzer()
        self.hipaa = HIPAAAnalyzer()
        self.pci_dss = PCIDSSAnalyzer()
    
    def analyze_breach_compliance(self, breach_details: Dict) -> Dict:
        """
        Analyze compliance implications of a breach
        """
        print("[*] Analyzing compliance implications...")
        
        reports = {}
        
        # GDPR analysis
        if breach_details.get('pii_records', 0) > 0:
            self.gdpr.analyze_data_breach(
                pii_records=breach_details.get('pii_records', 0),
                special_categories=breach_details.get('special_categories', False),
                encryption=breach_details.get('encrypted', False),
                notification_time_hours=breach_details.get('notification_hours', 0)
            )
            reports['gdpr'] = self.gdpr.generate_report()
        
        # HIPAA analysis
        if breach_details.get('phi_records', 0) > 0:
            self.hipaa.analyze_phi_breach(
                records=breach_details.get('phi_records', 0),
                encrypted=breach_details.get('encrypted', False),
                breach_notification_days=breach_details.get('notification_days', 0)
            )
            reports['hipaa'] = self.hipaa.generate_report()
        
        # PCI-DSS analysis
        if breach_details.get('card_records', 0) > 0:
            self.pci_dss.analyze_cardholder_data_breach(
                card_records=breach_details.get('card_records', 0),
                encrypted=breach_details.get('encrypted', False),
                network_segmented=breach_details.get('network_segmented', False)
            )
            reports['pci_dss'] = self.pci_dss.generate_report()
        
        # Calculate total exposure
        total_fines = 0
        if 'gdpr' in reports:
            total_fines += reports['gdpr']['potential_fines_usd']
        if 'hipaa' in reports:
            total_fines += reports['hipaa']['potential_fines_usd']
        if 'pci_dss' in reports:
            total_fines += reports['pci_dss']['potential_fines_usd']
        
        summary = {
            'total_potential_fines_usd': total_fines,
            'regulations_violated': list(reports.keys()),
            'severity': 'critical' if total_fines > 10000000 else 'high',
            'reports': reports
        }
        
        print(f"\n[!] Compliance Analysis Complete:")
        print(f"    Regulations: {', '.join(reports.keys()).upper()}")
        print(f"    Total potential fines: ${total_fines:,.2f}")
        
        return summary
    
    def export_comprehensive_report(self, summary: Dict, output_file: str):
        """Export comprehensive compliance report"""
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"[+] Compliance report exported to: {output_file}")
