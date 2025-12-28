"""
Business Impact Calculator
Calculate financial and operational impact of data exposure
"""

from typing import Dict, List
from dataclasses import dataclass, asdict
import json

@dataclass
class ImpactAssessment:
    """Impact assessment result"""
    severity: str  # critical, high, medium, low
    financial_impact_usd: float
    operational_impact: str
    reputational_impact: str
    regulatory_impact: str
    recovery_time_hours: float
    affected_systems: List[str]
    affected_data: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class BusinessImpactCalculator:
    """
    Calculates business impact of security incidents
    """
    
    def __init__(self, organization_size: str = 'medium'):
        """
        Args:
            organization_size: small, medium, large, enterprise
        """
        self.org_size = organization_size
        
        # Cost multipliers by organization size
        self.size_multipliers = {
            'small': 1.0,
            'medium': 5.0,
            'large': 25.0,
            'enterprise': 100.0
        }
        
        # Base costs (USD)
        self.base_costs = {
            'data_breach_per_record': 150,  # Industry average
            'downtime_per_hour': 5000,
            'incident_response': 50000,
            'legal_fees': 100000,
            'regulatory_fine_base': 250000,
            'reputation_damage': 500000,
            'customer_notification': 10000
        }
    
    def calculate_data_breach_impact(self, 
                                    records_exposed: int,
                                    data_types: List[str],
                                    detection_time_days: int = 30) -> ImpactAssessment:
        """
        Calculate impact of data breach
        """
        multiplier = self.size_multipliers[self.org_size]
        
        # Calculate base financial impact
        financial_impact = records_exposed * self.base_costs['data_breach_per_record']
        
        # Adjust for data sensitivity
        sensitivity_multiplier = self._calculate_sensitivity_multiplier(data_types)
        financial_impact *= sensitivity_multiplier
        
        # Add incident response costs
        financial_impact += self.base_costs['incident_response'] * multiplier
        
        # Add legal and regulatory costs
        if 'pii' in data_types or 'financial' in data_types:
            financial_impact += self.base_costs['legal_fees'] * multiplier
            financial_impact += self.base_costs['regulatory_fine_base'] * multiplier
        
        # Add customer notification costs
        if records_exposed > 1000:
            financial_impact += self.base_costs['customer_notification'] * multiplier
        
        # Reputation damage
        if records_exposed > 10000:
            financial_impact += self.base_costs['reputation_damage'] * multiplier
        
        # Determine severity
        severity = self._calculate_severity(records_exposed, data_types)
        
        # Estimate recovery time
        recovery_time = self._estimate_recovery_time(records_exposed, detection_time_days)
        
        assessment = ImpactAssessment(
            severity=severity,
            financial_impact_usd=financial_impact,
            operational_impact=self._describe_operational_impact(records_exposed),
            reputational_impact=self._describe_reputational_impact(records_exposed),
            regulatory_impact=self._describe_regulatory_impact(data_types),
            recovery_time_hours=recovery_time,
            affected_systems=['database', 'application', 'backup'],
            affected_data=data_types
        )
        
        return assessment
    
    def calculate_ransomware_impact(self,
                                   encrypted_systems: int,
                                   critical_systems: int,
                                   downtime_hours: float) -> ImpactAssessment:
        """
        Calculate ransomware attack impact
        """
        multiplier = self.size_multipliers[self.org_size]
        
        # Downtime costs
        financial_impact = downtime_hours * self.base_costs['downtime_per_hour'] * multiplier
        
        # System restoration costs
        restoration_cost_per_system = 10000 * multiplier
        financial_impact += encrypted_systems * restoration_cost_per_system
        
        # Critical system multiplier
        if critical_systems > 0:
            financial_impact *= (1 + (critical_systems * 0.5))
        
        # Incident response
        financial_impact += self.base_costs['incident_response'] * multiplier * 2
        
        # Potential ransom (estimate only - should NOT pay)
        estimated_ransom = encrypted_systems * 50000
        
        severity = 'critical' if critical_systems > 0 else 'high'
        
        assessment = ImpactAssessment(
            severity=severity,
            financial_impact_usd=financial_impact,
            operational_impact=f"Complete disruption: {downtime_hours} hours downtime",
            reputational_impact="Severe - public ransomware attack",
            regulatory_impact="Breach notification required",
            recovery_time_hours=downtime_hours + (encrypted_systems * 4),
            affected_systems=[f"system_{i}" for i in range(encrypted_systems)],
            affected_data=['encrypted_files']
        )
        
        return assessment
    
    def calculate_service_disruption_impact(self,
                                           affected_services: List[str],
                                           downtime_hours: float,
                                           users_affected: int) -> ImpactAssessment:
        """
        Calculate service disruption impact
        """
        multiplier = self.size_multipliers[self.org_size]
        
        # Base downtime cost
        financial_impact = downtime_hours * self.base_costs['downtime_per_hour'] * multiplier
        
        # User impact multiplier
        if users_affected > 1000:
            financial_impact *= 2
        if users_affected > 10000:
            financial_impact *= 3
        
        # Service criticality
        critical_services = ['payment', 'authentication', 'database', 'production']
        is_critical = any(svc in ' '.join(affected_services).lower() for svc in critical_services)
        
        if is_critical:
            financial_impact *= 2
            severity = 'critical'
        else:
            severity = 'high' if downtime_hours > 24 else 'medium'
        
        assessment = ImpactAssessment(
            severity=severity,
            financial_impact_usd=financial_impact,
            operational_impact=f"{len(affected_services)} services down, {users_affected} users affected",
            reputational_impact="Service reliability concerns",
            regulatory_impact="Possible SLA violations",
            recovery_time_hours=downtime_hours,
            affected_systems=affected_services,
            affected_data=['service_data']
        )
        
        return assessment
    
    def calculate_ip_theft_impact(self,
                                  ip_types: List[str],
                                  competitive_advantage_lost: bool = True) -> ImpactAssessment:
        """
        Calculate intellectual property theft impact
        """
        multiplier = self.size_multipliers[self.org_size]
        
        # Base IP value
        ip_values = {
            'source_code': 500000,
            'trade_secret': 1000000,
            'patent': 2000000,
            'customer_list': 250000,
            'business_strategy': 750000,
            'research_data': 1500000
        }
        
        financial_impact = 0
        for ip_type in ip_types:
            financial_impact += ip_values.get(ip_type, 100000)
        
        financial_impact *= multiplier
        
        # Competitive advantage multiplier
        if competitive_advantage_lost:
            financial_impact *= 2
        
        # Legal costs
        financial_impact += self.base_costs['legal_fees'] * multiplier * 2
        
        assessment = ImpactAssessment(
            severity='critical',
            financial_impact_usd=financial_impact,
            operational_impact="Loss of competitive advantage",
            reputational_impact="Critical - IP theft public disclosure",
            regulatory_impact="Trade secret litigation likely",
            recovery_time_hours=0,  # Cannot recover stolen IP
            affected_systems=['repositories', 'file_shares', 'databases'],
            affected_data=ip_types
        )
        
        return assessment
    
    def _calculate_sensitivity_multiplier(self, data_types: List[str]) -> float:
        """Calculate multiplier based on data sensitivity"""
        multipliers = {
            'pii': 2.0,
            'financial': 2.5,
            'health': 3.0,
            'authentication': 2.0,
            'trade_secret': 3.5,
            'government': 2.5
        }
        
        max_multiplier = 1.0
        for data_type in data_types:
            if data_type in multipliers:
                max_multiplier = max(max_multiplier, multipliers[data_type])
        
        return max_multiplier
    
    def _calculate_severity(self, records: int, data_types: List[str]) -> str:
        """Calculate overall severity"""
        if records > 100000 or 'health' in data_types or 'trade_secret' in data_types:
            return 'critical'
        elif records > 10000 or 'pii' in data_types or 'financial' in data_types:
            return 'high'
        elif records > 1000:
            return 'medium'
        else:
            return 'low'
    
    def _estimate_recovery_time(self, records: int, detection_days: int) -> float:
        """Estimate recovery time in hours"""
        base_time = 24  # Base 24 hours
        
        # Add time based on scale
        if records > 100000:
            base_time += 720  # +30 days
        elif records > 10000:
            base_time += 168  # +7 days
        elif records > 1000:
            base_time += 72   # +3 days
        
        # Late detection increases recovery time
        if detection_days > 30:
            base_time *= 2
        
        return base_time
    
    def _describe_operational_impact(self, records: int) -> str:
        """Describe operational impact"""
        if records > 100000:
            return "Severe disruption - major incident response required"
        elif records > 10000:
            return "Significant disruption - full incident response"
        elif records > 1000:
            return "Moderate disruption - limited incident response"
        else:
            return "Minor disruption - standard procedures"
    
    def _describe_reputational_impact(self, records: int) -> str:
        """Describe reputational impact"""
        if records > 100000:
            return "Severe - national media coverage, customer exodus"
        elif records > 10000:
            return "High - industry press, customer concerns"
        elif records > 1000:
            return "Moderate - local press, some customer impact"
        else:
            return "Low - minimal public awareness"
    
    def _describe_regulatory_impact(self, data_types: List[str]) -> str:
        """Describe regulatory impact"""
        impacts = []
        
        if 'pii' in data_types:
            impacts.append("GDPR/CCPA notification required")
        if 'health' in data_types:
            impacts.append("HIPAA breach notification")
        if 'financial' in data_types:
            impacts.append("PCI-DSS incident response, possible fines")
        if 'government' in data_types:
            impacts.append("Government breach reporting")
        
        return '; '.join(impacts) if impacts else "Minimal regulatory impact"
    
    def generate_impact_report(self, assessments: List[ImpactAssessment]) -> Dict:
        """Generate comprehensive impact report"""
        total_financial = sum(a.financial_impact_usd for a in assessments)
        total_recovery_time = sum(a.recovery_time_hours for a in assessments)
        
        report = {
            'total_incidents': len(assessments),
            'total_financial_impact_usd': total_financial,
            'total_recovery_time_hours': total_recovery_time,
            'severity_breakdown': {
                'critical': sum(1 for a in assessments if a.severity == 'critical'),
                'high': sum(1 for a in assessments if a.severity == 'high'),
                'medium': sum(1 for a in assessments if a.severity == 'medium'),
                'low': sum(1 for a in assessments if a.severity == 'low')
            },
            'assessments': [a.to_dict() for a in assessments]
        }
        
        return report
    
    def export_report(self, report: Dict, output_file: str):
        """Export impact report"""
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Impact report exported to: {output_file}")
