"""
Impact Analysis Module
Calculate and simulate the impact of security compromises
"""

from .business_impact import BusinessImpactCalculator
from .crown_jewels import CrownJewelIdentifier
from .data_flow_mapper import DataFlowMapper
from .ransomware_simulator import RansomwareImpactSimulator

__all__ = [
    'BusinessImpactCalculator',
    'CrownJewelIdentifier',
    'DataFlowMapper',
    'RansomwareImpactSimulator'
]
