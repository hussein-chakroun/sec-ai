"""
Crown Jewel Identifier
Identifies and prioritizes critical assets and data
"""

from typing import Dict, List
from dataclasses import dataclass, asdict
import json

@dataclass
class CrownJewel:
    """Critical asset"""
    name: str
    type: str  # data, system, service, intellectual_property
    value_score: float  # 0-100
    sensitivity: str  # critical, high, medium, low
    dependencies: List[str]
    protection_level: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class CrownJewelIdentifier:
    """Identifies organization's most critical assets"""
    
    def __init__(self):
        self.crown_jewels = []
        
        # Scoring criteria weights
        self.weights = {
            'business_criticality': 0.4,
            'data_sensitivity': 0.3,
            'revenue_impact': 0.2,
            'regulatory_impact': 0.1
        }
    
    def identify_data_crown_jewels(self, databases: List[Dict]) -> List[CrownJewel]:
        """Identify critical data assets"""
        for db in databases:
            score = self._score_database(db)
            
            if score >= 75:
                jewel = CrownJewel(
                    name=db['name'],
                    type='data',
                    value_score=score,
                    sensitivity='critical',
                    dependencies=db.get('dependent_systems', []),
                    protection_level=db.get('protection', 'unknown')
                )
                self.crown_jewels.append(jewel)
                print(f"[!] Crown Jewel identified: {jewel.name} (score: {score})")
        
        return self.crown_jewels
    
    def identify_system_crown_jewels(self, systems: List[Dict]) -> List[CrownJewel]:
        """Identify critical systems"""
        critical_keywords = ['payment', 'authentication', 'production', 'database', 'core']
        
        for system in systems:
            is_critical = any(kw in system['name'].lower() for kw in critical_keywords)
            
            if is_critical:
                score = 90
                jewel = CrownJewel(
                    name=system['name'],
                    type='system',
                    value_score=score,
                    sensitivity='critical',
                    dependencies=system.get('dependencies', []),
                    protection_level=system.get('protection', 'unknown')
                )
                self.crown_jewels.append(jewel)
        
        return self.crown_jewels
    
    def _score_database(self, db: Dict) -> float:
        """Score a database's criticality"""
        score = 50.0  # Base score
        
        # Check for sensitive tables
        sensitive_tables = db.get('sensitive_tables', [])
        if len(sensitive_tables) > 10:
            score += 20
        elif len(sensitive_tables) > 5:
            score += 10
        
        # Check record counts
        total_records = sum(db.get('record_counts', {}).values())
        if total_records > 1000000:
            score += 20
        elif total_records > 100000:
            score += 10
        
        # Check for PII/financial data
        has_pii = any('pii' in str(col).lower() for col in db.get('columns', []))
        has_financial = any('financial' in str(col).lower() for col in db.get('columns', []))
        
        if has_pii:
            score += 10
        if has_financial:
            score += 10
        
        return min(score, 100)
    
    def generate_protection_priority(self) -> List[Dict]:
        """Generate prioritized protection list"""
        sorted_jewels = sorted(self.crown_jewels, key=lambda x: x.value_score, reverse=True)
        
        return [
            {
                'priority': i + 1,
                'asset': jewel.name,
                'type': jewel.type,
                'score': jewel.value_score,
                'recommendations': self._get_recommendations(jewel)
            }
            for i, jewel in enumerate(sorted_jewels)
        ]
    
    def _get_recommendations(self, jewel: CrownJewel) -> List[str]:
        """Get protection recommendations"""
        recs = []
        
        if jewel.sensitivity == 'critical':
            recs.append("Implement multi-factor authentication")
            recs.append("Enable encryption at rest and in transit")
            recs.append("Implement strict access controls")
            recs.append("Enable comprehensive audit logging")
            recs.append("Perform regular security assessments")
        
        return recs
