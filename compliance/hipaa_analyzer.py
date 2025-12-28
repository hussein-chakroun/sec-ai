"""
HIPAA Compliance Analyzer
"""

from typing import Dict, List
from dataclasses import dataclass, asdict

@dataclass
class HIPAAViolation:
    """HIPAA violation"""
    rule: str
    description: str
    severity: str
    potential_fine_usd: float
    remediation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class HIPAAAnalyzer:
    """Analyzes HIPAA compliance"""
    
    def __init__(self):
        self.violations = []
    
    def analyze_phi_breach(self, records: int, encrypted: bool, 
                          breach_notification_days: int = 0) -> List[HIPAAViolation]:
        """Analyze PHI breach"""
        
        # Security Rule - Encryption
        if not encrypted:
            violation = HIPAAViolation(
                rule='Security Rule §164.312(a)(2)(iv)',
                description='PHI not encrypted at rest',
                severity='critical',
                potential_fine_usd=self._calculate_fine(records, True),
                remediation='Implement encryption for all ePHI'
            )
            self.violations.append(violation)
        
        # Breach Notification Rule - 60 days
        if breach_notification_days > 60:
            violation = HIPAAViolation(
                rule='Breach Notification Rule §164.404',
                description='Failed to notify individuals within 60 days',
                severity='high',
                potential_fine_usd=50000 * min(records, 100),
                remediation='Establish breach notification procedures'
            )
            self.violations.append(violation)
        
        return self.violations
    
    def _calculate_fine(self, records: int, willful_neglect: bool) -> float:
        """Calculate HIPAA fines"""
        if willful_neglect:
            per_violation = 50000
            max_annual = 1500000
        else:
            per_violation = 25000
            max_annual = 1500000
        
        return min(records * per_violation, max_annual)
    
    def generate_report(self) -> Dict:
        """Generate HIPAA report"""
        return {
            'regulation': 'HIPAA',
            'total_violations': len(self.violations),
            'potential_fines_usd': sum(v.potential_fine_usd for v in self.violations),
            'violations': [v.to_dict() for v in self.violations]
        }
