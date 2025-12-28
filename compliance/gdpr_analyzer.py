"""
GDPR Compliance Analyzer
Assesses GDPR violations and compliance gaps
"""

from typing import Dict, List
from dataclasses import dataclass, asdict
import json

@dataclass
class GDPRViolation:
    """GDPR violation finding"""
    article: str
    description: str
    severity: str  # critical, high, medium, low
    affected_data: str
    potential_fine_eur: float
    remediation: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class GDPRAnalyzer:
    """
    Analyzes GDPR compliance and violations
    """
    
    def __init__(self):
        self.violations = []
        
        # GDPR Articles and requirements
        self.requirements = {
            'Article 5': 'Principles relating to processing of personal data',
            'Article 6': 'Lawfulness of processing',
            'Article 9': 'Processing of special categories of personal data',
            'Article 13': 'Information to be provided (transparency)',
            'Article 15': 'Right of access by data subject',
            'Article 17': 'Right to erasure (right to be forgotten)',
            'Article 25': 'Data protection by design and by default',
            'Article 30': 'Records of processing activities',
            'Article 32': 'Security of processing',
            'Article 33': 'Notification of data breach to supervisory authority',
            'Article 34': 'Communication of data breach to data subject'
        }
    
    def analyze_data_breach(self, 
                           pii_records: int,
                           special_categories: bool = False,
                           encryption: bool = False,
                           notification_time_hours: int = 0) -> List[GDPRViolation]:
        """
        Analyze GDPR implications of data breach
        """
        print(f"[*] Analyzing GDPR implications of data breach")
        print(f"    PII records: {pii_records}")
        print(f"    Special categories: {special_categories}")
        print(f"    Encrypted: {encryption}")
        
        # Article 32 - Security of processing
        if not encryption:
            violation = GDPRViolation(
                article='Article 32',
                description='Inadequate security measures - data not encrypted',
                severity='critical',
                affected_data=f'{pii_records} PII records',
                potential_fine_eur=self._calculate_fine(pii_records, True),
                remediation='Implement encryption at rest and in transit'
            )
            self.violations.append(violation)
        
        # Article 33 - Notification to supervisory authority (72 hours)
        if notification_time_hours == 0 or notification_time_hours > 72:
            violation = GDPRViolation(
                article='Article 33',
                description='Failure to notify supervisory authority within 72 hours',
                severity='high',
                affected_data=f'{pii_records} PII records',
                potential_fine_eur=self._calculate_fine(pii_records, False) * 0.5,
                remediation='Establish breach notification procedures'
            )
            self.violations.append(violation)
        
        # Article 34 - Notification to data subjects
        if pii_records > 0:
            violation = GDPRViolation(
                article='Article 34',
                description='Requirement to notify affected data subjects',
                severity='high' if pii_records > 1000 else 'medium',
                affected_data=f'{pii_records} data subjects',
                potential_fine_eur=self._calculate_fine(pii_records, False) * 0.3,
                remediation='Notify all affected individuals without undue delay'
            )
            self.violations.append(violation)
        
        # Article 9 - Special categories
        if special_categories:
            violation = GDPRViolation(
                article='Article 9',
                description='Breach of special category personal data (health, biometric, etc.)',
                severity='critical',
                affected_data='Special category data',
                potential_fine_eur=self._calculate_fine(pii_records, True) * 1.5,
                remediation='Enhanced protection measures required for special categories'
            )
            self.violations.append(violation)
        
        print(f"[!] Found {len(self.violations)} GDPR violations")
        
        return self.violations
    
    def analyze_data_processing(self,
                               purpose_specified: bool,
                               consent_obtained: bool,
                               data_minimization: bool,
                               retention_policy: bool) -> List[GDPRViolation]:
        """
        Analyze data processing practices
        """
        # Article 5 - Principles
        if not purpose_specified:
            violation = GDPRViolation(
                article='Article 5(1)(b)',
                description='Purpose limitation - purpose not specified',
                severity='high',
                affected_data='All processing activities',
                potential_fine_eur=5000000,
                remediation='Document specific, explicit and legitimate purposes'
            )
            self.violations.append(violation)
        
        if not data_minimization:
            violation = GDPRViolation(
                article='Article 5(1)(c)',
                description='Data minimization - collecting excessive data',
                severity='medium',
                affected_data='All collected data',
                potential_fine_eur=2000000,
                remediation='Collect only data necessary for specified purposes'
            )
            self.violations.append(violation)
        
        if not retention_policy:
            violation = GDPRViolation(
                article='Article 5(1)(e)',
                description='Storage limitation - no retention policy',
                severity='medium',
                affected_data='All stored data',
                potential_fine_eur=2000000,
                remediation='Implement data retention and deletion policies'
            )
            self.violations.append(violation)
        
        # Article 6 - Lawful basis
        if not consent_obtained:
            violation = GDPRViolation(
                article='Article 6',
                description='No lawful basis for processing (consent not obtained)',
                severity='critical',
                affected_data='All processing activities',
                potential_fine_eur=10000000,
                remediation='Obtain valid consent or establish other lawful basis'
            )
            self.violations.append(violation)
        
        return self.violations
    
    def analyze_data_subject_rights(self,
                                   access_request_capability: bool,
                                   erasure_capability: bool,
                                   portability_capability: bool) -> List[GDPRViolation]:
        """
        Analyze data subject rights implementation
        """
        # Article 15 - Right of access
        if not access_request_capability:
            violation = GDPRViolation(
                article='Article 15',
                description='No mechanism for data subject access requests',
                severity='high',
                affected_data='All data subjects',
                potential_fine_eur=3000000,
                remediation='Implement data subject access request (DSAR) procedures'
            )
            self.violations.append(violation)
        
        # Article 17 - Right to erasure
        if not erasure_capability:
            violation = GDPRViolation(
                article='Article 17',
                description='Cannot fulfill right to erasure requests',
                severity='high',
                affected_data='All data subjects',
                potential_fine_eur=3000000,
                remediation='Implement data deletion capabilities'
            )
            self.violations.append(violation)
        
        # Article 20 - Right to data portability
        if not portability_capability:
            violation = GDPRViolation(
                article='Article 20',
                description='No data portability mechanism',
                severity='medium',
                affected_data='All data subjects',
                potential_fine_eur=1000000,
                remediation='Enable data export in structured, machine-readable format'
            )
            self.violations.append(violation)
        
        return self.violations
    
    def _calculate_fine(self, records: int, severe: bool) -> float:
        """
        Calculate potential GDPR fine
        GDPR: Up to €20M or 4% of global annual turnover (whichever is higher)
        """
        # Base fine calculation (simplified)
        base_fine = records * 50  # €50 per record (conservative estimate)
        
        # Severity multiplier
        if severe:
            base_fine *= 2
        
        # Cap at typical maximum
        max_fine = 20000000  # €20M
        
        return min(base_fine, max_fine)
    
    def generate_report(self) -> Dict:
        """Generate GDPR compliance report"""
        total_fines = sum(v.potential_fine_eur for v in self.violations)
        
        report = {
            'regulation': 'GDPR',
            'total_violations': len(self.violations),
            'potential_fines_eur': total_fines,
            'potential_fines_usd': total_fines * 1.1,  # Approximate conversion
            'severity_breakdown': {
                'critical': sum(1 for v in self.violations if v.severity == 'critical'),
                'high': sum(1 for v in self.violations if v.severity == 'high'),
                'medium': sum(1 for v in self.violations if v.severity == 'medium'),
                'low': sum(1 for v in self.violations if v.severity == 'low')
            },
            'violations': [v.to_dict() for v in self.violations],
            'recommendations': self._get_priority_recommendations()
        }
        
        return report
    
    def _get_priority_recommendations(self) -> List[str]:
        """Get prioritized remediation recommendations"""
        critical_violations = [v for v in self.violations if v.severity == 'critical']
        
        recommendations = []
        for violation in critical_violations[:5]:  # Top 5
            recommendations.append(f"{violation.article}: {violation.remediation}")
        
        return recommendations
    
    def export_report(self, output_file: str):
        """Export GDPR report"""
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] GDPR compliance report exported to: {output_file}")
        print(f"    Total violations: {report['total_violations']}")
        print(f"    Potential fines: €{report['potential_fines_eur']:,.2f}")
