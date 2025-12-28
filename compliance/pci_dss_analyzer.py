"""
PCI-DSS Compliance Analyzer
"""

from typing import Dict, List
from dataclasses import dataclass, asdict

@dataclass
class PCIDSSViolation:
    """PCI-DSS violation"""
    requirement: str
    description: str
    severity: str
    potential_fine_usd: float
    remediation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class PCIDSSAnalyzer:
    """Analyzes PCI-DSS compliance"""
    
    def __init__(self):
        self.violations = []
    
    def analyze_cardholder_data_breach(self, card_records: int, 
                                      encrypted: bool,
                                      network_segmented: bool) -> List[PCIDSSViolation]:
        """Analyze cardholder data breach"""
        
        # Requirement 3 - Protect stored cardholder data
        if not encrypted:
            violation = PCIDSSViolation(
                requirement='Requirement 3.4',
                description='Cardholder data not encrypted',
                severity='critical',
                potential_fine_usd=self._calculate_fine(card_records),
                remediation='Encrypt all stored cardholder data'
            )
            self.violations.append(violation)
        
        # Requirement 1 - Network segmentation
        if not network_segmented:
            violation = PCIDSSViolation(
                requirement='Requirement 1.3',
                description='Inadequate network segmentation',
                severity='high',
                potential_fine_usd=500000,
                remediation='Implement network segmentation for cardholder data environment'
            )
            self.violations.append(violation)
        
        return self.violations
    
    def _calculate_fine(self, records: int) -> float:
        """Calculate PCI-DSS fines"""
        # Fines from card brands + potential lawsuits
        base_fine = 50000  # Monthly fine
        per_record = 90  # Average cost per compromised card
        
        return base_fine + (records * per_record)
    
    def generate_report(self) -> Dict:
        """Generate PCI-DSS report"""
        return {
            'regulation': 'PCI-DSS',
            'total_violations': len(self.violations),
            'potential_fines_usd': sum(v.potential_fine_usd for v in self.violations),
            'violations': [v.to_dict() for v in self.violations]
        }
