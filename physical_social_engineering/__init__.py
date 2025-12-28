"""
Physical & Social Engineering Integration
Phase 10: Advanced social engineering and physical security testing
"""

from .osint_weaponization import (
    OSINTWeaponizer,
    LinkedInScraper,
    EmailPatternIdentifier,
    SocialMediaProfiler,
    RelationshipMapper
)

from .phishing_automation import (
    PhishingCampaignManager,
    SpearPhishingGenerator,
    CredentialHarvester,
    MaliciousDocumentGenerator,
    SmishingEngine,
    VishingScriptGenerator
)

from .physical_security import (
    PhysicalSecurityAnalyzer,
    BadgeCloningStrategy,
    TailgatingAnalyzer,
    CameraBlindSpotDetector,
    LockVulnerabilityAssessor,
    USBDropCampaign
)

from .deepfake_integration import (
    DeepfakeEngine,
    VoiceCloningSystem,
    VideoManipulator,
    CEOFraudAutomation
)

__all__ = [
    'OSINTWeaponizer',
    'LinkedInScraper',
    'EmailPatternIdentifier',
    'SocialMediaProfiler',
    'RelationshipMapper',
    'PhishingCampaignManager',
    'SpearPhishingGenerator',
    'CredentialHarvester',
    'MaliciousDocumentGenerator',
    'SmishingEngine',
    'VishingScriptGenerator',
    'PhysicalSecurityAnalyzer',
    'BadgeCloningStrategy',
    'TailgatingAnalyzer',
    'CameraBlindSpotDetector',
    'LockVulnerabilityAssessor',
    'USBDropCampaign',
    'DeepfakeEngine',
    'VoiceCloningSystem',
    'VideoManipulator',
    'CEOFraudAutomation'
]
