"""
Evasion Package - Phase 4
Advanced Evasion & Stealth capabilities
"""
from evasion.evasion_engine import EvasionEngine
from evasion.ids_evasion import (
    SignatureDetectionPredictor,
    PolymorphicPayloadGenerator,
    TrafficObfuscator,
    TimingRandomizer,
    DecoyTrafficGenerator,
    ProtocolManipulator
)
from evasion.waf_bypass import WAFBypassEngine
from evasion.anti_forensics import (
    LogPoisoner,
    TimestompOperations,
    MemoryOnlyExecution,
    LOLBinsExecution,
    FilelessMalwareDeployment
)
from evasion.behavioral_mimicry import (
    BehaviorAnalyzer,
    TrafficMimicker,
    SlowBurnAttacker,
    BehaviorBlender
)

__all__ = [
    'EvasionEngine',
    'SignatureDetectionPredictor',
    'PolymorphicPayloadGenerator',
    'TrafficObfuscator',
    'TimingRandomizer',
    'DecoyTrafficGenerator',
    'ProtocolManipulator',
    'WAFBypassEngine',
    'LogPoisoner',
    'TimestompOperations',
    'MemoryOnlyExecution',
    'LOLBinsExecution',
    'FilelessMalwareDeployment',
    'BehaviorAnalyzer',
    'TrafficMimicker',
    'SlowBurnAttacker',
    'BehaviorBlender'
]
