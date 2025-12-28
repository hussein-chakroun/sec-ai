"""
Adversary Simulation & Red Team Automation
Phase 9: Advanced threat actor emulation and purple team capabilities
"""

from .mitre_attack_mapper import MITREAttackMapper, TTPs, APTEmulator
from .threat_actor_emulator import ThreatActorEmulator, APTProfile
from .purple_team import PurpleTeamCoordinator, TelemetryGenerator, DetectionValidator
from .continuous_simulation import ContinuousAdversarySimulator, AttackCampaign

__all__ = [
    'MITREAttackMapper',
    'TTPs',
    'APTEmulator',
    'ThreatActorEmulator',
    'APTProfile',
    'PurpleTeamCoordinator',
    'TelemetryGenerator',
    'DetectionValidator',
    'ContinuousAdversarySimulator',
    'AttackCampaign'
]
