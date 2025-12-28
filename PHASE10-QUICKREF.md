# Phase 10 Quick Reference

## Installation

```bash
pip install -r requirements-phase10.txt
```

## Quick Start

```python
import asyncio
from core.phase10_engine import Phase10Engine

async def main():
    engine = Phase10Engine()
    results = await engine.run_full_assessment(
        target_organization="Acme Corp",
        target_domain="acme.com",
        scope=['osint', 'phishing', 'physical', 'deepfake']
    )

asyncio.run(main())
```

## Module Imports

```python
# OSINT
from physical_social_engineering.osint_weaponization import (
    OSINTWeaponizer, PersonProfile, OrganizationProfile
)

# Phishing
from physical_social_engineering.phishing_automation import (
    PhishingCampaignManager, PhishingType, PretextType
)

# Physical Security
from physical_social_engineering.physical_security import (
    PhysicalSecurityAnalyzer, BadgeSystem, SecurityLevel
)

# Deepfake
from physical_social_engineering.deepfake_integration import (
    DeepfakeEngine, QualityLevel
)
```

## OSINT Weaponization

```python
osint = OSINTWeaponizer()

# Weaponize organization
org = await osint.weaponize_organization(
    company_name="Target Corp",
    domain="targetcorp.com",
    max_profiles=100
)

# Results
print(f"Employees: {len(org.employees)}")
print(f"Email patterns: {org.email_patterns}")
print(f"Org chart: {org.org_chart}")
```

**Key Classes:**
- `OSINTWeaponizer` - Main orchestrator
- `LinkedInScraper` - Employee enumeration
- `EmailPatternIdentifier` - Email pattern discovery
- `SocialMediaProfiler` - Social media analysis
- `RelationshipMapper` - Relationship graphing

## Phishing Campaigns

```python
phishing = PhishingCampaignManager()

# Create campaign
campaign = await phishing.create_campaign(
    campaign_name="Test_Campaign",
    targets=[{"name": "User", "email": "user@example.com"}],
    campaign_type=PhishingType.SPEAR_PHISHING,
    pretext_type=PretextType.IT_SUPPORT
)
```

**Phishing Types:**
- `SPEAR_PHISHING` - Targeted emails
- `WHALING` - Executive targeting
- `SMISHING` - SMS phishing
- `VISHING` - Voice phishing
- `CLONE_PHISHING` - Email cloning

**Pretext Types:**
- `IT_SUPPORT` - Password reset, account issues
- `HR_NOTIFICATION` - Benefits, payroll
- `EXECUTIVE_REQUEST` - CEO/CFO requests
- `SECURITY_ALERT` - Account compromise
- `DOCUMENT_SHARE` - SharePoint, file sharing
- `VENDOR_INVOICE` - Payment requests

**Key Classes:**
- `SpearPhishingGenerator` - Email generation
- `CredentialHarvester` - Harvesting pages
- `MaliciousDocumentGenerator` - Weaponized docs
- `SmishingEngine` - SMS messages
- `VishingScriptGenerator` - Call scripts

## Physical Security

```python
analyzer = PhysicalSecurityAnalyzer()

# Create location
location = PhysicalLocation(
    name="HQ",
    address="123 Main St",
    security_level=SecurityLevel.MEDIUM,
    access_controls=[AccessControlType.BADGE],
    cameras=10,
    entry_points=3
)

# Analyze
assessment = await analyzer.analyze_facility(
    location=location,
    badge_system=badge_system,
    cameras=cameras,
    locks=locks
)
```

**Security Levels:**
- `MINIMAL` - Basic security
- `LOW` - Light controls
- `MEDIUM` - Standard controls
- `HIGH` - Enhanced security
- `MAXIMUM` - Maximum security

**Access Control Types:**
- `BADGE` - RFID/HID badges
- `PIN` - PIN pads
- `BIOMETRIC` - Fingerprint, iris
- `KEY_CARD` - Magnetic stripe
- `PHYSICAL_KEY` - Traditional keys
- `GUARD` - Security guards

**Key Classes:**
- `BadgeCloningStrategy` - Badge analysis
- `TailgatingAnalyzer` - Entry point analysis
- `CameraBlindSpotDetector` - Camera coverage
- `LockVulnerabilityAssessor` - Lock assessment
- `USBDropCampaign` - USB drop planning

## Badge Cloning

```python
from physical_social_engineering.physical_security import (
    BadgeCloningStrategy, BadgeSystem
)

cloning = BadgeCloningStrategy()

badge = BadgeSystem(
    technology="RFID",
    frequency="125kHz",
    encryption=False,
    vendor="HID ProxCard"
)

analysis = cloning.analyze_badge_system(badge)
print(f"Vulnerability: {analysis['vulnerability_rating']}/10")
print(f"Success probability: {analysis['success_probability']:.0%}")
```

## Camera Analysis

```python
from physical_social_engineering.physical_security import (
    CameraBlindSpotDetector, SecurityCamera
)

detector = CameraBlindSpotDetector()

cameras = [
    SecurityCamera(
        location="Main entrance",
        camera_type="fixed",
        field_of_view=90,
        night_vision=True
    )
]

analysis = detector.analyze_camera_coverage(location, cameras)
print(f"Blind spots: {len(analysis['blind_spots'])}")
print(f"Evasion routes: {len(analysis['evasion_routes'])}")
```

## Deepfake Attacks

```python
deepfake = DeepfakeEngine()

# CEO fraud
attack = await deepfake.create_comprehensive_attack(
    target_organization="Acme Corp",
    executive_name="Jane CEO",
    executive_title="CEO",
    victim_name="Bob CFO",
    victim_title="CFO",
    attack_goal="wire_transfer"
)

print(f"Success rate: {attack['overall_success_probability']:.0%}")
```

**Quality Levels:**
- `LOW` - Detectable
- `MEDIUM` - Convincing
- `HIGH` - Very convincing
- `PERFECT` - Indistinguishable

**Key Classes:**
- `VoiceCloningSystem` - Voice synthesis
- `VideoManipulator` - Video deepfakes
- `CEOFraudAutomation` - BEC attacks

## Voice Cloning

```python
voice_cloner = deepfake.voice_cloner

# Create profile
profile = await voice_cloner.create_voice_profile(
    person_name="Executive Name",
    person_title="CEO"
)

# Generate audio
audio = await voice_cloner.generate_voice_clone(
    profile=profile,
    script="Your script here"
)
```

## Vishing Campaign

```python
# Generate vishing campaign
campaign = await deepfake.generate_vishing_campaign(
    executive_name="Jane Smith",
    executive_title="CEO",
    targets=[
        {"name": "Employee 1", "title": "IT Support"},
        {"name": "Employee 2", "title": "Finance"}
    ],
    scenario="security_incident"
)
```

## Assessment Scopes

```python
# Full assessment
results = await engine.run_full_assessment(
    target_organization="Acme",
    target_domain="acme.com",
    scope=['osint', 'phishing', 'physical', 'deepfake']
)

# OSINT only
results = await engine.run_full_assessment(
    target_organization="Acme",
    target_domain="acme.com",
    scope=['osint']
)

# Phishing + Deepfake
results = await engine.run_full_assessment(
    target_organization="Acme",
    target_domain="acme.com",
    scope=['phishing', 'deepfake']
)
```

## Common Patterns

### OSINT → Phishing Chain

```python
# 1. Gather intelligence
org = await osint.weaponize_organization("Co", "co.com")

# 2. Identify targets
from physical_social_engineering.osint_weaponization import LinkedInScraper
scraper = LinkedInScraper()
targets = scraper.identify_high_value_targets(org.employees, 5)

# 3. Create phishing campaign
campaign = await phishing.create_campaign(
    campaign_name="Targeted",
    targets=[{"name": t.name, "email": t.email} for t in targets],
    campaign_type=PhishingType.SPEAR_PHISHING,
    pretext_type=PretextType.EXECUTIVE_REQUEST
)
```

### Physical + USB Drop

```python
# 1. Assess physical security
assessment = await analyzer.analyze_facility(location)

# 2. Plan USB drop
usb_campaign = analyzer.usb_campaign.plan_campaign(
    target_location=location,
    usb_count=10,
    payload_type="credential_harvester"
)
```

### CEO Fraud Attack

```python
# 1. Create voice profile
voice_profile = await deepfake.voice_cloner.create_voice_profile(
    "CEO Name", "CEO"
)

# 2. Generate vishing audio
audio = deepfake.voice_cloner.generate_vishing_audio(
    profile=voice_profile,
    scenario="ceo_urgent_request",
    target_name="CFO Name"
)
```

## Output Files

```
assessments/phase10/
├── osint/
│   └── weaponized_intel_[org]_[date].json
├── phishing/
│   ├── campaigns/[campaign]_[date].json
│   └── harvester/[type]_[org]_[date].html
├── physical/
│   └── assessments/physical_security_[loc]_[date].json
├── deepfake/
│   └── ceo_fraud/ceo_fraud_plan_[id].json
└── phase10_assessment_[date].json
```

## Results Structure

```python
results = {
    "organization": "Acme Corp",
    "domain": "acme.com",
    "phases": {
        "osint_weaponization": {
            "total_employees_identified": 50,
            "high_value_targets": [...],
            "email_patterns_discovered": 3
        },
        "phishing_campaigns": {
            "total_campaigns": 3,
            "estimated_total_targets": 25
        },
        "physical_security": {
            "total_vulnerabilities": 12,
            "attack_scenarios": 3
        },
        "deepfake_attacks": {
            "ceo_fraud_attack": {...},
            "vishing_campaign": {...}
        }
    },
    "integrated_scenarios": [...]
}
```

## Error Handling

```python
try:
    results = await engine.run_full_assessment(...)
except Exception as e:
    print(f"Assessment failed: {e}")
```

## Authorization Check

**Before any assessment:**

```python
# ⚠️ REQUIRED: Verify authorization
authorization_confirmed = input("Do you have written authorization? (yes/no): ")
if authorization_confirmed.lower() != 'yes':
    print("❌ Authorization required. Exiting.")
    exit(1)

# Proceed with assessment
results = await engine.run_full_assessment(...)
```

## Key Warnings

1. **Always get written authorization**
2. **Never test without permission**
3. **Respect privacy laws (GDPR, etc.)**
4. **Don't log real credentials**
5. **Mark deepfakes as synthetic**
6. **Coordinate physical access with security**
7. **Report findings responsibly**

## See Also

- [PHASE10-GUIDE.md](PHASE10-GUIDE.md) - Full documentation
- [PHASE10-SUMMARY.md](PHASE10-SUMMARY.md) - Architecture overview
- [test_phase10.py](test_phase10.py) - Test examples
