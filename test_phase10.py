"""
Phase 10 Test Suite
Tests for Physical & Social Engineering Integration
"""

import asyncio
import pytest
from pathlib import Path

from core.phase10_engine import Phase10Engine
from physical_social_engineering.osint_weaponization import (
    OSINTWeaponizer,
    LinkedInScraper,
    EmailPatternIdentifier,
    SocialMediaProfiler,
    RelationshipMapper
)
from physical_social_engineering.phishing_automation import (
    PhishingCampaignManager,
    SpearPhishingGenerator,
    CredentialHarvester,
    SmishingEngine,
    VishingScriptGenerator,
    PhishingType,
    PretextType
)
from physical_social_engineering.physical_security import (
    PhysicalSecurityAnalyzer,
    BadgeCloningStrategy,
    TailgatingAnalyzer,
    CameraBlindSpotDetector,
    LockVulnerabilityAssessor,
    USBDropCampaign,
    PhysicalLocation,
    BadgeSystem,
    SecurityCamera,
    LockSystem,
    SecurityLevel,
    AccessControlType
)
from physical_social_engineering.deepfake_integration import (
    DeepfakeEngine,
    VoiceCloningSystem,
    VideoManipulator,
    CEOFraudAutomation,
    QualityLevel
)


class TestOSINTWeaponization:
    """Test OSINT weaponization capabilities"""
    
    @pytest.mark.asyncio
    async def test_osint_weaponizer_init(self):
        """Test OSINT weaponizer initialization"""
        osint = OSINTWeaponizer()
        assert osint.linkedin_scraper is not None
        assert osint.email_identifier is not None
        assert osint.social_profiler is not None
        assert osint.relationship_mapper is not None
    
    @pytest.mark.asyncio
    async def test_weaponize_organization(self):
        """Test organization weaponization"""
        osint = OSINTWeaponizer()
        
        org_profile = await osint.weaponize_organization(
            company_name="Test Corp",
            domain="testcorp.com",
            max_profiles=10
        )
        
        assert org_profile is not None
        assert org_profile.name == "Test Corp"
        assert org_profile.domain == "testcorp.com"
        assert len(org_profile.employees) > 0
        assert len(org_profile.employees) <= 10
    
    @pytest.mark.asyncio
    async def test_linkedin_scraper(self):
        """Test LinkedIn scraping"""
        scraper = LinkedInScraper()
        
        profiles = await scraper.gather_company_employees(
            company_name="Test Corp",
            max_profiles=5
        )
        
        assert len(profiles) > 0
        assert len(profiles) <= 5
        assert all(p.name for p in profiles)
        assert all(p.job_title for p in profiles)
    
    @pytest.mark.asyncio
    async def test_email_pattern_identification(self):
        """Test email pattern discovery"""
        identifier = EmailPatternIdentifier()
        
        patterns = await identifier.identify_patterns(
            domain="testcorp.com",
            known_emails=["john.doe@testcorp.com"]
        )
        
        assert len(patterns) > 0
        assert any("{first}.{last}" in p for p in patterns)
    
    @pytest.mark.asyncio
    async def test_high_value_target_identification(self):
        """Test high-value target identification"""
        scraper = LinkedInScraper()
        
        profiles = await scraper.gather_company_employees("Test", 20)
        targets = scraper.identify_high_value_targets(profiles, top_n=5)
        
        assert len(targets) <= 5
        assert all(t.vulnerability_score > 0 for t in targets)


class TestPhishingAutomation:
    """Test phishing automation capabilities"""
    
    @pytest.mark.asyncio
    async def test_phishing_campaign_manager_init(self):
        """Test campaign manager initialization"""
        manager = PhishingCampaignManager()
        assert manager.email_generator is not None
        assert manager.credential_harvester is not None
        assert manager.doc_generator is not None
    
    @pytest.mark.asyncio
    async def test_spear_phishing_generation(self):
        """Test spear phishing email generation"""
        generator = SpearPhishingGenerator()
        
        email = generator.generate_email(
            target_name="John Doe",
            target_email="john.doe@test.com",
            target_title="CFO",
            target_company="Test Corp",
            pretext_type=PretextType.IT_SUPPORT,
            urgency="high"
        )
        
        assert email is not None
        assert "John" in email.body or "Doe" in email.body
        assert email.target_email == "john.doe@test.com"
        assert "URGENT" in email.subject
    
    @pytest.mark.asyncio
    async def test_credential_harvester_generation(self):
        """Test harvesting page generation"""
        harvester = CredentialHarvester()
        
        page_path = harvester.generate_login_page(
            company_name="Test Corp",
            page_type="office365"
        )
        
        assert Path(page_path).exists()
        assert ".html" in page_path
    
    @pytest.mark.asyncio
    async def test_smishing_generation(self):
        """Test SMS phishing generation"""
        smishing = SmishingEngine()
        
        sms = smishing.generate_sms(
            target_name="John Doe",
            target_phone="+1-555-0100",
            pretext_type=PretextType.SECURITY_ALERT
        )
        
        assert sms is not None
        assert sms.target_phone == "+1-555-0100"
        assert len(sms.message) > 0
    
    @pytest.mark.asyncio
    async def test_vishing_script_generation(self):
        """Test vishing script generation"""
        vishing = VishingScriptGenerator()
        
        script = vishing.generate_script(
            target_name="John Doe",
            target_title="CFO",
            pretext_type=PretextType.IT_SUPPORT
        )
        
        assert script is not None
        assert len(script.body) > 0
        assert len(script.objection_handlers) > 0


class TestPhysicalSecurity:
    """Test physical security assessment"""
    
    @pytest.mark.asyncio
    async def test_physical_security_analyzer_init(self):
        """Test analyzer initialization"""
        analyzer = PhysicalSecurityAnalyzer()
        assert analyzer.badge_cloning is not None
        assert analyzer.tailgating is not None
        assert analyzer.camera_analyzer is not None
    
    @pytest.mark.asyncio
    async def test_badge_cloning_analysis(self):
        """Test badge system analysis"""
        cloning = BadgeCloningStrategy()
        
        badge = BadgeSystem(
            technology="RFID",
            frequency="125kHz",
            encryption=False,
            vendor="HID ProxCard"
        )
        
        analysis = cloning.analyze_badge_system(badge)
        
        assert analysis is not None
        assert analysis["vulnerability_rating"] > 0
        assert analysis["success_probability"] > 0
        assert len(analysis["cloning_methods"]) > 0
    
    @pytest.mark.asyncio
    async def test_tailgating_analysis(self):
        """Test tailgating analysis"""
        analyzer = TailgatingAnalyzer()
        
        location = PhysicalLocation(
            name="Test HQ",
            address="123 Test St",
            facility_type="office",
            security_level=SecurityLevel.MEDIUM,
            access_controls=[AccessControlType.BADGE],
            operating_hours={},
            employee_count=100,
            entry_points=2
        )
        
        opportunities = analyzer.analyze_entry_points(location)
        
        assert len(opportunities) > 0
        assert all(o["success_probability"] > 0 for o in opportunities)
    
    @pytest.mark.asyncio
    async def test_camera_blind_spot_detection(self):
        """Test camera blind spot detection"""
        detector = CameraBlindSpotDetector()
        
        location = PhysicalLocation(
            name="Test Site",
            address="123 Test",
            facility_type="office",
            security_level=SecurityLevel.MEDIUM,
            access_controls=[],
            operating_hours={},
            employee_count=50
        )
        
        cameras = [
            SecurityCamera(
                location="Main entrance",
                camera_type="fixed",
                resolution="1080p",
                field_of_view=90,
                night_vision=True,
                motion_detection=True,
                recording=True
            )
        ]
        
        analysis = detector.analyze_camera_coverage(location, cameras)
        
        assert "blind_spots" in analysis
        assert "evasion_routes" in analysis
    
    @pytest.mark.asyncio
    async def test_usb_drop_campaign(self):
        """Test USB drop campaign planning"""
        usb_campaign = USBDropCampaign()
        
        location = PhysicalLocation(
            name="Office",
            address="123 St",
            facility_type="office",
            security_level=SecurityLevel.LOW,
            access_controls=[],
            operating_hours={},
            employee_count=100
        )
        
        campaign = usb_campaign.plan_campaign(
            target_location=location,
            usb_count=10,
            payload_type="credential_harvester"
        )
        
        assert campaign is not None
        assert campaign["usb_count"] == 10
        assert len(campaign["drop_locations"]) > 0


class TestDeepfakeIntegration:
    """Test deepfake integration"""
    
    @pytest.mark.asyncio
    async def test_voice_cloning_system_init(self):
        """Test voice cloning initialization"""
        voice_cloner = VoiceCloningSystem()
        assert voice_cloner is not None
    
    @pytest.mark.asyncio
    async def test_voice_profile_creation(self):
        """Test voice profile creation"""
        voice_cloner = VoiceCloningSystem()
        
        profile = await voice_cloner.create_voice_profile(
            person_name="John CEO",
            person_title="Chief Executive Officer"
        )
        
        assert profile is not None
        assert profile.person_name == "John CEO"
        assert len(profile.audio_samples) > 0
        assert profile.quality_level in QualityLevel
    
    @pytest.mark.asyncio
    async def test_voice_clone_generation(self):
        """Test voice clone generation"""
        voice_cloner = VoiceCloningSystem()
        
        profile = await voice_cloner.create_voice_profile("Test CEO", "CEO")
        
        audio_path = await voice_cloner.generate_voice_clone(
            profile=profile,
            script="This is a test message"
        )
        
        assert audio_path is not None
        assert ".mp3" in audio_path
    
    @pytest.mark.asyncio
    async def test_video_manipulator_init(self):
        """Test video manipulator initialization"""
        video_manip = VideoManipulator()
        assert video_manip is not None
    
    @pytest.mark.asyncio
    async def test_video_profile_creation(self):
        """Test video profile creation"""
        video_manip = VideoManipulator()
        
        profile = await video_manip.create_video_profile(
            person_name="Jane CEO",
            person_title="CEO"
        )
        
        assert profile is not None
        assert len(profile.video_samples) > 0
        assert len(profile.image_samples) > 0
    
    @pytest.mark.asyncio
    async def test_ceo_fraud_automation(self):
        """Test CEO fraud planning"""
        voice_cloner = VoiceCloningSystem()
        video_manip = VideoManipulator()
        ceo_fraud = CEOFraudAutomation(voice_cloner, video_manip)
        
        attack_plan = await ceo_fraud.plan_ceo_fraud_attack(
            ceo_name="John CEO",
            ceo_title="CEO",
            target_employee="Bob CFO",
            target_title="CFO",
            attack_goal="wire_transfer"
        )
        
        assert attack_plan is not None
        assert attack_plan["goal"] == "wire_transfer"
        assert len(attack_plan["attack_phases"]) > 0
        assert attack_plan["success_probability"] > 0


class TestPhase10Engine:
    """Test Phase 10 orchestration engine"""
    
    @pytest.mark.asyncio
    async def test_engine_initialization(self):
        """Test engine initialization"""
        engine = Phase10Engine()
        assert engine.osint_weaponizer is not None
        assert engine.phishing_manager is not None
        assert engine.physical_security is not None
        assert engine.deepfake_engine is not None
    
    @pytest.mark.asyncio
    async def test_osint_only_assessment(self):
        """Test OSINT-only assessment"""
        engine = Phase10Engine()
        
        results = await engine.run_full_assessment(
            target_organization="Test Corp",
            target_domain="test.com",
            scope=['osint']
        )
        
        assert results is not None
        assert "osint_weaponization" in results["phases"]
        assert results["status"] == "completed"
    
    @pytest.mark.asyncio
    async def test_phishing_only_assessment(self):
        """Test phishing-only assessment"""
        engine = Phase10Engine()
        
        results = await engine.run_full_assessment(
            target_organization="Test Corp",
            target_domain="test.com",
            scope=['phishing']
        )
        
        assert results is not None
        assert "phishing_campaigns" in results["phases"]
    
    @pytest.mark.asyncio
    async def test_full_assessment(self):
        """Test full Phase 10 assessment"""
        engine = Phase10Engine()
        
        results = await engine.run_full_assessment(
            target_organization="Test Corporation",
            target_domain="testcorp.com",
            target_address="123 Business St",
            scope=['osint', 'phishing', 'physical', 'deepfake']
        )
        
        assert results is not None
        assert results["organization"] == "Test Corporation"
        assert results["domain"] == "testcorp.com"
        assert results["status"] == "completed"
        
        # Check all phases
        assert "osint_weaponization" in results["phases"]
        assert "phishing_campaigns" in results["phases"]
        assert "physical_security" in results["phases"]
        assert "deepfake_attacks" in results["phases"]
        
        # Check integrated scenarios
        assert "integrated_scenarios" in results
        assert len(results["integrated_scenarios"]) > 0


class TestIntegration:
    """Integration tests for combined techniques"""
    
    @pytest.mark.asyncio
    async def test_osint_to_phishing_chain(self):
        """Test OSINT → Phishing integration"""
        osint = OSINTWeaponizer()
        phishing = PhishingCampaignManager()
        
        # Gather OSINT
        org = await osint.weaponize_organization("Test", "test.com", 10)
        
        # Use OSINT for phishing
        from physical_social_engineering.osint_weaponization import LinkedInScraper
        scraper = LinkedInScraper()
        targets = scraper.identify_high_value_targets(org.employees, 3)
        
        campaign_targets = [
            {
                "name": t.name,
                "email": t.email,
                "title": t.job_title,
                "company": "Test"
            }
            for t in targets
        ]
        
        campaign = await phishing.create_campaign(
            campaign_name="OSINT_Phishing",
            targets=campaign_targets,
            campaign_type=PhishingType.SPEAR_PHISHING,
            pretext_type=PretextType.IT_SUPPORT
        )
        
        assert campaign is not None
    
    @pytest.mark.asyncio
    async def test_full_spectrum_attack(self):
        """Test full-spectrum attack scenario"""
        engine = Phase10Engine()
        
        # Run comprehensive assessment
        results = await engine.run_full_assessment(
            target_organization="Target Corp",
            target_domain="target.com",
            scope=['osint', 'phishing', 'physical', 'deepfake']
        )
        
        # Verify integrated scenarios include multi-phase attacks
        scenarios = results["integrated_scenarios"]
        assert any("Full-Spectrum" in s["name"] for s in scenarios)
        
        # Check scenario has multiple phases
        full_spectrum = next(s for s in scenarios if "Full-Spectrum" in s["name"])
        assert len(full_spectrum["phases"]) >= 3


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
