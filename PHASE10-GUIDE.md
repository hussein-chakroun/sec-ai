# Phase 10: Physical & Social Engineering Integration

## Overview

Phase 10 implements comprehensive physical and social engineering capabilities, integrating:

1. **OSINT Weaponization** - Intelligence gathering and targeting
2. **Automated Phishing** - Spear-phishing, smishing, vishing campaigns  
3. **Physical Security Analysis** - Badge cloning, tailgating, camera analysis
4. **Deepfake Integration** - Voice cloning, video manipulation, CEO fraud

## ⚠️ Critical Warning

**AUTHORIZATION REQUIRED**: All Phase 10 capabilities are for **authorized security testing only**. Unauthorized use of these techniques is illegal and unethical.

- **Social engineering** without authorization is fraud
- **Badge cloning** without authorization is illegal access
- **Deepfakes** for fraud are criminal offenses
- **Phishing** without consent is cybercrime

**Always obtain written authorization before any Phase 10 assessment.**

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
    
    # Run comprehensive assessment
    results = await engine.run_full_assessment(
        target_organization="Acme Corporation",
        target_domain="acme.com",
        target_address="123 Business St, City, State",
        scope=['osint', 'phishing', 'physical', 'deepfake']
    )
    
    print(f"Assessment complete: {results['status']}")

asyncio.run(main())
```

## Module Capabilities

### 1. OSINT Weaponization

Gather and weaponize publicly available intelligence:

```python
from physical_social_engineering.osint_weaponization import OSINTWeaponizer

osint = OSINTWeaponizer()

# Weaponize organization intelligence
org_profile = await osint.weaponize_organization(
    company_name="Target Corp",
    domain="targetcorp.com",
    max_profiles=100
)

# Access results
print(f"Employees found: {len(org_profile.employees)}")
print(f"Email patterns: {org_profile.email_patterns}")
print(f"Org chart: {org_profile.org_chart}")
```

**Capabilities:**
- LinkedIn employee enumeration
- Organizational chart mapping
- Email pattern identification
- Social media profiling
- Relationship mapping
- High-value target identification

### 2. Phishing Campaign Automation

Generate and manage sophisticated phishing campaigns:

```python
from physical_social_engineering.phishing_automation import (
    PhishingCampaignManager,
    PhishingType,
    PretextType
)

phishing = PhishingCampaignManager()

# Create spear-phishing campaign
campaign = await phishing.create_campaign(
    campaign_name="Q4_IT_Security_Test",
    targets=[
        {"name": "John Doe", "email": "jdoe@target.com", "title": "CFO"}
    ],
    campaign_type=PhishingType.SPEAR_PHISHING,
    pretext_type=PretextType.IT_SUPPORT,
    duration_days=7
)
```

**Campaign Types:**
- Spear Phishing (targeted emails)
- Whaling (executive targeting)
- Smishing (SMS phishing)
- Vishing (voice phishing)
- Clone Phishing

**Pretext Types:**
- IT Support
- HR Notifications
- Executive Requests
- Security Alerts
- Document Sharing
- Vendor Invoices

**Features:**
- Personalized email generation
- Credential harvesting pages
- Malicious document generation
- SMS phishing messages
- Vishing call scripts

### 3. Physical Security Analysis

Assess physical security controls:

```python
from physical_social_engineering.physical_security import (
    PhysicalSecurityAnalyzer,
    PhysicalLocation,
    BadgeSystem,
    SecurityLevel
)

analyzer = PhysicalSecurityAnalyzer()

# Define facility
location = PhysicalLocation(
    name="Corporate HQ",
    address="123 Main St",
    facility_type="office",
    security_level=SecurityLevel.MEDIUM,
    access_controls=[AccessControlType.BADGE, AccessControlType.GUARD],
    employee_count=500,
    security_guards=3,
    cameras=15,
    entry_points=4
)

# Analyze security
assessment = await analyzer.analyze_facility(
    location=location,
    badge_system=badge_system,
    cameras=camera_list,
    locks=lock_list
)
```

**Analysis Capabilities:**

**Badge Cloning:**
- RFID system analysis (125kHz, 13.56MHz)
- HID Prox/iCLASS vulnerabilities
- Magnetic stripe weaknesses
- Cloning procedure generation

**Tailgating Analysis:**
- Entry point vulnerability assessment
- Success probability calculation
- Timing recommendations
- Social engineering approaches

**Camera Analysis:**
- Blind spot identification
- Coverage gap detection
- Evasion route generation
- Camera capability assessment

**Lock Assessment:**
- Pin pad vulnerabilities
- Deadbolt bypass methods
- Electronic lock weaknesses
- Biometric system analysis

**USB Drop Campaigns:**
- Strategic location identification
- Payload configuration
- Social engineering labels
- Success probability estimation

### 4. Deepfake Integration

AI-powered impersonation attacks:

```python
from physical_social_engineering.deepfake_integration import DeepfakeEngine

deepfake = DeepfakeEngine()

# Plan CEO fraud attack
attack = await deepfake.create_comprehensive_attack(
    target_organization="Acme Corp",
    executive_name="Jane CEO",
    executive_title="Chief Executive Officer",
    victim_name="Bob CFO",
    victim_title="Chief Financial Officer",
    attack_goal="wire_transfer"
)
```

**Voice Cloning:**
- Voice profile creation from public audio
- Voice characteristic analysis
- Vishing audio generation
- Quality level assessment

**Video Manipulation:**
- Video profile creation
- Deepfake video generation
- Face swapping
- Lip-sync generation

**CEO Fraud Automation:**
- Multi-phase attack planning
- Email + voice + video coordination
- Wire transfer social engineering
- Whaling attack scenarios

## Integrated Attack Scenarios

Phase 10 generates comprehensive, multi-technique attack scenarios:

### Scenario 1: Full-Spectrum Social Engineering

1. **OSINT Phase**: Gather employee profiles, map org structure
2. **Phishing Phase**: Credential harvesting campaigns
3. **Physical Phase**: Badge cloning, tailgating, USB drops
4. **Deepfake Phase**: CEO fraud voice call

### Scenario 2: Insider Threat Simulation

1. Credential compromise via phishing
2. Deepfake voice for privilege escalation
3. Data exfiltration as insider

### Scenario 3: Supply Chain Compromise

1. Vendor research via OSINT
2. Vendor impersonation phishing
3. Payment redirection or system access

## Usage Examples

### Example 1: OSINT + Spear Phishing

```python
async def osint_phishing_campaign():
    osint = OSINTWeaponizer()
    phishing = PhishingCampaignManager()
    
    # Gather intelligence
    org = await osint.weaponize_organization("Target Co", "target.com")
    
    # Get high-value targets
    from physical_social_engineering.osint_weaponization import LinkedInScraper
    scraper = LinkedInScraper()
    targets = scraper.identify_high_value_targets(org.employees, 5)
    
    # Create targeted phishing campaign
    campaign_targets = [
        {
            "name": t.name,
            "email": t.email,
            "title": t.job_title,
            "company": "Target Co"
        }
        for t in targets
    ]
    
    campaign = await phishing.create_campaign(
        campaign_name="Executive_Phishing",
        targets=campaign_targets,
        campaign_type=PhishingType.SPEAR_PHISHING,
        pretext_type=PretextType.EXECUTIVE_REQUEST
    )
```

### Example 2: Physical Security + USB Drop

```python
async def physical_assessment_usb():
    analyzer = PhysicalSecurityAnalyzer()
    
    # Assess facility
    location = PhysicalLocation(...)
    assessment = await analyzer.analyze_facility(location)
    
    # Plan USB drop based on assessment
    usb_campaign = analyzer.usb_campaign.plan_campaign(
        target_location=location,
        usb_count=10,
        payload_type="credential_harvester"
    )
    
    print(f"USB drop locations: {usb_campaign['drop_locations']}")
```

### Example 3: CEO Fraud with Deepfakes

```python
async def ceo_fraud_attack():
    deepfake = DeepfakeEngine()
    
    # Create voice profile
    voice_profile = await deepfake.voice_cloner.create_voice_profile(
        person_name="Jane Smith",
        person_title="CEO"
    )
    
    # Generate vishing audio
    audio_script = """
    Hi Bob, this is Jane. I'm in a board meeting but need your help 
    with an urgent wire transfer. Can you process $500,000 to 
    Anderson Capital today? I'll email the details. Thanks.
    """
    
    audio_file = await deepfake.voice_cloner.generate_voice_clone(
        profile=voice_profile,
        script=audio_script
    )
    
    print(f"Generated deepfake audio: {audio_file}")
```

## Assessment Workflow

### Full Phase 10 Assessment

```python
async def complete_assessment():
    engine = Phase10Engine()
    
    # Comprehensive assessment
    results = await engine.run_full_assessment(
        target_organization="Acme Corporation",
        target_domain="acme.com",
        target_address="123 Business St",
        scope=['osint', 'phishing', 'physical', 'deepfake']
    )
    
    # Results structure
    # results['phases']['osint_weaponization']
    # results['phases']['phishing_campaigns']
    # results['phases']['physical_security']
    # results['phases']['deepfake_attacks']
    # results['integrated_scenarios']
```

### Selective Assessment

```python
# OSINT only
results = await engine.run_full_assessment(
    target_organization="Acme Corp",
    target_domain="acme.com",
    scope=['osint']
)

# Phishing + Deepfake
results = await engine.run_full_assessment(
    target_organization="Acme Corp",
    target_domain="acme.com",
    scope=['phishing', 'deepfake']
)
```

## Output and Reporting

All Phase 10 assessments generate comprehensive JSON reports:

```
assessments/phase10/
├── osint/
│   ├── weaponized_intel_AcmeCorp_20240115.json
│   ├── linkedin/
│   └── social_media/
├── phishing/
│   ├── campaigns/
│   │   └── SpearPhish_AcmeCorp_HighValue_20240115.json
│   ├── harvester/
│   │   └── office365_AcmeCorp_20240115.html
│   └── documents/
├── physical/
│   ├── assessments/
│   │   └── physical_security_assessment_HQ_20240115.json
│   ├── badge_cloning/
│   ├── cameras/
│   └── usb_drops/
├── deepfake/
│   ├── voice/
│   ├── video/
│   └── ceo_fraud/
│       └── ceo_fraud_plan_20240115.json
└── phase10_assessment_20240115_143022.json
```

## Security Considerations

### Legal Considerations

1. **Written Authorization**: Always required
2. **Scope Definition**: Clearly defined boundaries
3. **Data Handling**: Secure storage and disposal
4. **Compliance**: GDPR, privacy laws, computer fraud laws

### Ethical Guidelines

1. **Harm Prevention**: Never cause actual harm
2. **Data Privacy**: Respect personal information
3. **Professional Conduct**: Maintain ethical standards
4. **Disclosure**: Report findings responsibly

### Technical Safeguards

1. **Test Environment**: Use isolated test environments when possible
2. **Credential Harvesting**: Never log actual credentials
3. **Deepfakes**: Clearly mark as synthetic
4. **Physical Access**: Coordinate with security teams

## Troubleshooting

### OSINT Collection Fails

```python
# Reduce profile count
org = await osint.weaponize_organization(
    company_name="Target",
    domain="target.com",
    max_profiles=20  # Reduce from default
)
```

### Phishing Campaign Errors

```python
# Validate email formats
from email_validator import validate_email

for target in targets:
    try:
        validate_email(target['email'])
    except:
        print(f"Invalid email: {target['email']}")
```

### Deepfake Quality Issues

```python
# Check profile quality
if voice_profile.quality_level == QualityLevel.LOW:
    print("Warning: Low quality voice profile")
    print(f"Samples needed: {len(voice_profile.audio_samples)}")
    # Need 3+ samples for MEDIUM, 5+ for HIGH
```

## Integration with Other Phases

Phase 10 integrates with:

- **Phase 6**: AI-driven reconnaissance feeds OSINT
- **Phase 7**: Evasion techniques apply to phishing
- **Phase 8**: Exploit development for USB payloads
- **Phase 9**: Adversary simulation uses social engineering

## Best Practices

1. **Start with OSINT**: Build intelligence foundation first
2. **Targeted Phishing**: Use OSINT to personalize attacks
3. **Physical Coordination**: Coordinate with facility security
4. **Deepfake Testing**: Verify quality before deployment
5. **Comprehensive Reporting**: Document all findings
6. **Remediation Focus**: Provide actionable recommendations

## Advanced Topics

### Custom Phishing Templates

```python
# Add custom email template
custom_template = {
    "subject": "Custom Subject - {company}",
    "from_name": "Custom Sender",
    "from_address": "sender@example.com",
    "body": "Custom email body with {name} personalization",
    "landing_url": "https://harvester.local/custom"
}

generator.email_templates[PretextType.CUSTOM] = custom_template
```

### Badge Cloning Hardware

```python
# Analyze specific RFID frequency
badge = BadgeSystem(
    technology="RFID",
    frequency="13.56MHz",  # HID iCLASS
    encryption=True,  # iCLASS SE
    vendor="HID iCLASS"
)

analysis = cloning.analyze_badge_system(badge)
# Returns difficulty rating and required equipment
```

### Voice Profile Enhancement

```python
# Add more audio sources for better quality
voice_profile = await voice_cloner.create_voice_profile(
    person_name="Executive",
    person_title="CEO",
    audio_sources=[
        "earnings_call_q1.mp3",
        "earnings_call_q2.mp3",
        "conference_keynote.mp3",
        "podcast_interview.mp3",
        "webinar_presentation.mp3"
    ]
)
# 5+ sources = HIGH quality
```

## See Also

- [PHASE10-QUICKREF.md](PHASE10-QUICKREF.md) - Quick reference guide
- [PHASE10-SUMMARY.md](PHASE10-SUMMARY.md) - Architecture summary
- [test_phase10.py](test_phase10.py) - Test suite
- [examples/phase10_examples.py](examples/phase10_examples.py) - Usage examples

## Support

For questions or issues:
1. Review documentation
2. Check test examples
3. Verify authorization requirements
4. Consult with legal/compliance teams
