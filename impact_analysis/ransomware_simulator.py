"""
Ransomware Impact Simulator
Simulates ransomware attack impact
"""

from typing import Dict, List
import random

class RansomwareImpactSimulator:
    """Simulates ransomware attack scenarios"""
    
    def __init__(self):
        self.infected_systems = []
        self.encryption_rate = 100  # MB/s
    
    def simulate_attack(self, entry_point: str, total_systems: int, 
                       critical_systems: List[str]) -> Dict:
        """Simulate ransomware spread"""
        print(f"[*] Simulating ransomware attack from: {entry_point}")
        
        # Lateral movement simulation
        infected = set([entry_point])
        spread_probability = 0.7
        
        for _ in range(total_systems):
            if random.random() < spread_probability:
                system = f"system_{len(infected)}"
                infected.add(system)
        
        # Check critical system impact
        critical_infected = len([s for s in infected if s in critical_systems])
        
        # Calculate downtime
        recovery_time_per_system = 4  # hours
        total_recovery = len(infected) * recovery_time_per_system
        
        result = {
            'total_systems': total_systems,
            'infected_systems': len(infected),
            'critical_systems_infected': critical_infected,
            'infection_percentage': (len(infected) / total_systems) * 100,
            'estimated_downtime_hours': total_recovery,
            'estimated_data_loss_gb': len(infected) * 50,  # 50GB average per system
            'severity': 'critical' if critical_infected > 0 else 'high'
        }
        
        print(f"[!] Simulation complete:")
        print(f"    Infected: {result['infected_systems']}/{total_systems} systems")
        print(f"    Critical systems: {critical_infected}")
        print(f"    Downtime: {total_recovery} hours")
        
        return result
    
    def estimate_ransom_demand(self, company_size: str, data_value: str = 'medium') -> Dict:
        """Estimate ransom demand"""
        base_ransoms = {
            'small': 50000,
            'medium': 250000,
            'large': 1000000,
            'enterprise': 5000000
        }
        
        value_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 2.0,
            'critical': 4.0
        }
        
        base = base_ransoms.get(company_size, 100000)
        multiplier = value_multipliers.get(data_value, 1.0)
        
        estimated_ransom = base * multiplier
        
        return {
            'estimated_ransom_usd': estimated_ransom,
            'negotiated_estimate_usd': estimated_ransom * 0.7,  # Typical negotiation
            'recommendation': 'DO NOT PAY - No guarantee of decryption, funds criminals'
        }
