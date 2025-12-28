"""
OSINT Weaponization
Comprehensive intelligence gathering for social engineering
"""

import asyncio
import json
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import random
import hashlib


@dataclass
class PersonProfile:
    """Individual person profile from OSINT"""
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    company: Optional[str] = None
    location: Optional[str] = None
    linkedin_url: Optional[str] = None
    twitter_handle: Optional[str] = None
    facebook_profile: Optional[str] = None
    instagram_handle: Optional[str] = None
    skills: List[str] = field(default_factory=list)
    interests: List[str] = field(default_factory=list)
    connections: List[str] = field(default_factory=list)
    education: List[Dict] = field(default_factory=list)
    work_history: List[Dict] = field(default_factory=list)
    personal_info: Dict = field(default_factory=dict)
    vulnerability_score: float = 0.0


@dataclass
class OrganizationProfile:
    """Organization profile from OSINT"""
    name: str
    domain: str
    industry: str
    size: str
    locations: List[str] = field(default_factory=list)
    employees: List[PersonProfile] = field(default_factory=list)
    org_chart: Dict = field(default_factory=dict)
    email_patterns: List[str] = field(default_factory=list)
    phone_patterns: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    social_media: Dict = field(default_factory=dict)
    recent_news: List[Dict] = field(default_factory=list)


class LinkedInScraper:
    """
    LinkedIn data gathering for organizational intelligence
    Note: Respects LinkedIn ToS - use only for authorized testing
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("intelligence/linkedin")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_collected: List[PersonProfile] = []
        
    async def gather_company_employees(
        self,
        company_name: str,
        max_profiles: int = 100
    ) -> List[PersonProfile]:
        """Gather employee profiles from LinkedIn"""
        print(f"\n   🔍 Gathering LinkedIn profiles for: {company_name}")
        
        # Simulated LinkedIn scraping (actual implementation would use APIs or authorized methods)
        profiles = []
        
        # Simulate finding employees
        departments = ["Engineering", "Sales", "Marketing", "HR", "Finance", "Operations"]
        titles = {
            "Engineering": ["Software Engineer", "Senior Engineer", "Engineering Manager", "CTO"],
            "Sales": ["Sales Rep", "Account Executive", "Sales Manager", "VP Sales"],
            "Marketing": ["Marketing Specialist", "Content Manager", "CMO"],
            "HR": ["HR Specialist", "HR Manager", "CHRO"],
            "Finance": ["Accountant", "Financial Analyst", "CFO"],
            "Operations": ["Operations Manager", "COO"]
        }
        
        num_profiles = min(max_profiles, random.randint(20, 50))
        
        for i in range(num_profiles):
            dept = random.choice(departments)
            title = random.choice(titles[dept])
            
            profile = PersonProfile(
                name=self._generate_name(),
                email=None,  # Will be inferred
                job_title=title,
                department=dept,
                company=company_name,
                linkedin_url=f"https://linkedin.com/in/{self._generate_slug()}",
                skills=self._generate_skills(dept),
                connections=[]
            )
            
            # Calculate vulnerability score
            profile.vulnerability_score = self._calculate_vulnerability_score(profile)
            
            profiles.append(profile)
            self.profiles_collected.append(profile)
        
        print(f"   ✓ Collected {len(profiles)} employee profiles")
        
        return profiles
    
    async def build_org_chart(
        self,
        profiles: List[PersonProfile]
    ) -> Dict:
        """Build organizational hierarchy from profiles"""
        print(f"\n   📊 Building organizational chart...")
        
        org_chart = {
            "c_level": [],
            "vp_level": [],
            "director_level": [],
            "manager_level": [],
            "individual_contributors": []
        }
        
        for profile in profiles:
            title_lower = profile.job_title.lower()
            
            if any(t in title_lower for t in ['ceo', 'cto', 'cfo', 'coo', 'cmo', 'chro']):
                org_chart["c_level"].append(profile)
            elif 'vp' in title_lower or 'vice president' in title_lower:
                org_chart["vp_level"].append(profile)
            elif 'director' in title_lower:
                org_chart["director_level"].append(profile)
            elif 'manager' in title_lower:
                org_chart["manager_level"].append(profile)
            else:
                org_chart["individual_contributors"].append(profile)
        
        print(f"   ✓ Org chart built:")
        print(f"      C-Level: {len(org_chart['c_level'])}")
        print(f"      VP Level: {len(org_chart['vp_level'])}")
        print(f"      Directors: {len(org_chart['director_level'])}")
        print(f"      Managers: {len(org_chart['manager_level'])}")
        print(f"      ICs: {len(org_chart['individual_contributors'])}")
        
        return org_chart
    
    def identify_high_value_targets(
        self,
        profiles: List[PersonProfile],
        top_n: int = 10
    ) -> List[PersonProfile]:
        """Identify high-value targets for social engineering"""
        # Sort by vulnerability score and position
        scored_profiles = []
        
        for profile in profiles:
            score = profile.vulnerability_score
            
            # Boost score for high-level positions
            title_lower = profile.job_title.lower()
            if any(t in title_lower for t in ['ceo', 'cto', 'cfo']):
                score += 30
            elif 'vp' in title_lower:
                score += 20
            elif 'director' in title_lower:
                score += 15
            elif 'manager' in title_lower:
                score += 10
            
            scored_profiles.append((score, profile))
        
        scored_profiles.sort(reverse=True, key=lambda x: x[0])
        
        return [p for _, p in scored_profiles[:top_n]]
    
    def _calculate_vulnerability_score(self, profile: PersonProfile) -> float:
        """Calculate social engineering vulnerability score"""
        score = 0.0
        
        # More connections = more trusting
        if profile.connections:
            score += min(len(profile.connections) / 50, 20)
        
        # Publicly shared skills indicate openness
        score += min(len(profile.skills) * 2, 20)
        
        # Public social media presence
        if profile.twitter_handle:
            score += 15
        if profile.facebook_profile:
            score += 15
        if profile.instagram_handle:
            score += 10
        
        # Random variation
        score += random.uniform(0, 20)
        
        return min(score, 100)
    
    def _generate_name(self) -> str:
        """Generate realistic name"""
        first_names = ["John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa"]
        last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
        return f"{random.choice(first_names)} {random.choice(last_names)}"
    
    def _generate_slug(self) -> str:
        """Generate LinkedIn slug"""
        return f"user-{hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}"
    
    def _generate_skills(self, department: str) -> List[str]:
        """Generate realistic skills for department"""
        skill_sets = {
            "Engineering": ["Python", "Java", "AWS", "Docker", "Kubernetes"],
            "Sales": ["Salesforce", "Negotiation", "Account Management"],
            "Marketing": ["Content Marketing", "SEO", "Social Media", "Analytics"],
            "HR": ["Recruiting", "Employee Relations", "HRIS"],
            "Finance": ["Excel", "Financial Analysis", "Accounting"],
            "Operations": ["Project Management", "Process Improvement"]
        }
        
        base_skills = skill_sets.get(department, ["Communication", "Teamwork"])
        return random.sample(base_skills, min(3, len(base_skills)))


class EmailPatternIdentifier:
    """
    Identify and validate email patterns for an organization
    """
    
    def __init__(self):
        self.discovered_patterns: List[str] = []
        self.validated_emails: List[str] = []
        
    async def identify_patterns(
        self,
        domain: str,
        known_emails: List[str] = None
    ) -> List[str]:
        """Identify email patterns from known emails"""
        print(f"\n   📧 Identifying email patterns for: {domain}")
        
        patterns = []
        
        # Common email patterns
        common_patterns = [
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{f}{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}@{domain}",
            "{last}@{domain}"
        ]
        
        if known_emails:
            # Analyze known emails to determine pattern
            for email in known_emails:
                local_part = email.split('@')[0]
                patterns.append(self._infer_pattern(local_part))
        else:
            # Use common patterns
            patterns = common_patterns
        
        self.discovered_patterns = list(set(patterns))
        
        print(f"   ✓ Identified {len(self.discovered_patterns)} email patterns")
        for pattern in self.discovered_patterns[:3]:
            print(f"      • {pattern}")
        
        return self.discovered_patterns
    
    def generate_email(
        self,
        first_name: str,
        last_name: str,
        domain: str,
        pattern: str = None
    ) -> str:
        """Generate email address using pattern"""
        if not pattern and self.discovered_patterns:
            pattern = self.discovered_patterns[0]
        elif not pattern:
            pattern = "{first}.{last}@{domain}"
        
        email = pattern.format(
            first=first_name.lower(),
            last=last_name.lower(),
            f=first_name[0].lower(),
            l=last_name[0].lower(),
            domain=domain
        )
        
        return email
    
    def enrich_profiles_with_emails(
        self,
        profiles: List[PersonProfile],
        domain: str
    ) -> List[PersonProfile]:
        """Add email addresses to profiles"""
        print(f"\n   ✉️  Enriching profiles with email addresses...")
        
        for profile in profiles:
            if not profile.email and profile.name:
                parts = profile.name.split()
                if len(parts) >= 2:
                    profile.email = self.generate_email(
                        parts[0], parts[-1], domain
                    )
        
        enriched_count = sum(1 for p in profiles if p.email)
        print(f"   ✓ Enriched {enriched_count}/{len(profiles)} profiles")
        
        return profiles
    
    def _infer_pattern(self, local_part: str) -> str:
        """Infer email pattern from local part"""
        if '.' in local_part:
            return "{first}.{last}@{domain}"
        elif '_' in local_part:
            return "{first}_{last}@{domain}"
        else:
            return "{first}{last}@{domain}"


class SocialMediaProfiler:
    """
    Aggregate social media intelligence
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("intelligence/social_media")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    async def profile_individual(
        self,
        person: PersonProfile
    ) -> Dict:
        """Gather social media intelligence on individual"""
        print(f"\n   📱 Profiling: {person.name}")
        
        intel = {
            "name": person.name,
            "platforms": {},
            "interests": [],
            "recent_activity": [],
            "connections": [],
            "vulnerability_indicators": []
        }
        
        # Simulate social media intelligence gathering
        if person.twitter_handle:
            intel["platforms"]["twitter"] = await self._profile_twitter(person)
        
        if person.facebook_profile:
            intel["platforms"]["facebook"] = await self._profile_facebook(person)
        
        if person.instagram_handle:
            intel["platforms"]["instagram"] = await self._profile_instagram(person)
        
        # Identify vulnerability indicators
        intel["vulnerability_indicators"] = self._identify_vulnerabilities(intel)
        
        return intel
    
    async def _profile_twitter(self, person: PersonProfile) -> Dict:
        """Profile Twitter account"""
        await asyncio.sleep(0.1)  # Simulate API call
        
        return {
            "handle": person.twitter_handle,
            "follower_count": random.randint(50, 5000),
            "tweet_frequency": random.choice(["high", "medium", "low"]),
            "topics": random.sample(
                ["tech", "business", "sports", "politics", "travel"],
                k=random.randint(2, 4)
            ),
            "engagement_level": random.choice(["high", "medium", "low"])
        }
    
    async def _profile_facebook(self, person: PersonProfile) -> Dict:
        """Profile Facebook account"""
        await asyncio.sleep(0.1)
        
        return {
            "privacy_level": random.choice(["public", "friends", "private"]),
            "post_frequency": random.choice(["daily", "weekly", "rarely"]),
            "shares_location": random.choice([True, False]),
            "shares_family_info": random.choice([True, False])
        }
    
    async def _profile_instagram(self, person: PersonProfile) -> Dict:
        """Profile Instagram account"""
        await asyncio.sleep(0.1)
        
        return {
            "handle": person.instagram_handle,
            "follower_count": random.randint(100, 10000),
            "post_count": random.randint(50, 500),
            "shares_location": random.choice([True, False]),
            "account_type": random.choice(["public", "private"])
        }
    
    def _identify_vulnerabilities(self, intel: Dict) -> List[str]:
        """Identify social engineering vulnerability indicators"""
        vulnerabilities = []
        
        for platform, data in intel["platforms"].items():
            if platform == "facebook":
                if data.get("privacy_level") == "public":
                    vulnerabilities.append("Public Facebook profile")
                if data.get("shares_family_info"):
                    vulnerabilities.append("Shares family information publicly")
                if data.get("shares_location"):
                    vulnerabilities.append("Shares location data")
            
            elif platform == "twitter":
                if data.get("engagement_level") == "high":
                    vulnerabilities.append("High Twitter engagement (responsive)")
                    
            elif platform == "instagram":
                if data.get("account_type") == "public":
                    vulnerabilities.append("Public Instagram account")
        
        return vulnerabilities


class RelationshipMapper:
    """
    Map relationships and social connections
    """
    
    def __init__(self):
        self.relationship_graph: Dict[str, Set[str]] = {}
        
    def build_relationship_graph(
        self,
        profiles: List[PersonProfile]
    ) -> Dict:
        """Build relationship graph from profiles"""
        print(f"\n   🕸️  Building relationship graph...")
        
        # Initialize graph
        for profile in profiles:
            self.relationship_graph[profile.name] = set()
        
        # Add connections (simulated)
        for profile in profiles:
            # Same department connections
            dept_colleagues = [
                p.name for p in profiles
                if p.department == profile.department and p.name != profile.name
            ]
            if dept_colleagues:
                connections = random.sample(
                    dept_colleagues,
                    min(3, len(dept_colleagues))
                )
                self.relationship_graph[profile.name].update(connections)
        
        total_connections = sum(len(conns) for conns in self.relationship_graph.values())
        print(f"   ✓ Mapped {total_connections} relationships")
        
        return self.relationship_graph
    
    def find_path_to_target(
        self,
        start_person: str,
        target_person: str,
        max_hops: int = 3
    ) -> Optional[List[str]]:
        """Find social path from start to target"""
        # BFS to find shortest path
        if start_person not in self.relationship_graph:
            return None
        
        queue = [(start_person, [start_person])]
        visited = {start_person}
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_hops:
                continue
            
            if current == target_person:
                return path
            
            for neighbor in self.relationship_graph.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None
    
    def identify_influencers(
        self,
        min_connections: int = 5
    ) -> List[Tuple[str, int]]:
        """Identify influential people by connection count"""
        influencers = [
            (person, len(connections))
            for person, connections in self.relationship_graph.items()
            if len(connections) >= min_connections
        ]
        
        influencers.sort(key=lambda x: x[1], reverse=True)
        return influencers


class OSINTWeaponizer:
    """
    Comprehensive OSINT weaponization engine
    Orchestrates all OSINT gathering and analysis
    """
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("intelligence/weaponized_osint")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.linkedin_scraper = LinkedInScraper(self.output_dir / "linkedin")
        self.email_identifier = EmailPatternIdentifier()
        self.social_profiler = SocialMediaProfiler(self.output_dir / "social_media")
        self.relationship_mapper = RelationshipMapper()
        
        self.organization_profile: Optional[OrganizationProfile] = None
        
    async def weaponize_organization(
        self,
        company_name: str,
        domain: str,
        max_profiles: int = 100
    ) -> OrganizationProfile:
        """Complete OSINT weaponization of an organization"""
        print(f"\n🎯 Weaponizing OSINT for: {company_name}")
        print(f"   Domain: {domain}")
        
        # Initialize organization profile
        org_profile = OrganizationProfile(
            name=company_name,
            domain=domain,
            industry="Technology",  # Would be determined from OSINT
            size=f"{random.randint(100, 1000)}+ employees"
        )
        
        # Step 1: LinkedIn scraping
        employees = await self.linkedin_scraper.gather_company_employees(
            company_name,
            max_profiles
        )
        org_profile.employees = employees
        
        # Step 2: Email pattern identification
        await self.email_identifier.identify_patterns(domain)
        self.email_identifier.enrich_profiles_with_emails(employees, domain)
        
        # Step 3: Build org chart
        org_profile.org_chart = await self.linkedin_scraper.build_org_chart(employees)
        
        # Step 4: Social media profiling (selective)
        high_value_targets = self.linkedin_scraper.identify_high_value_targets(employees, 10)
        
        print(f"\n   🎯 High-Value Targets Identified: {len(high_value_targets)}")
        for i, target in enumerate(high_value_targets[:5], 1):
            print(f"      {i}. {target.name} - {target.job_title} (Score: {target.vulnerability_score:.1f})")
        
        # Step 5: Relationship mapping
        org_profile.org_chart["relationships"] = self.relationship_mapper.build_relationship_graph(employees)
        
        # Step 6: Identify attack paths
        attack_recommendations = self._generate_attack_recommendations(
            org_profile,
            high_value_targets
        )
        
        # Save results
        self._save_intelligence(org_profile, attack_recommendations)
        
        self.organization_profile = org_profile
        
        return org_profile
    
    def _generate_attack_recommendations(
        self,
        org_profile: OrganizationProfile,
        high_value_targets: List[PersonProfile]
    ) -> Dict:
        """Generate social engineering attack recommendations"""
        recommendations = {
            "spear_phishing_targets": [],
            "pretexting_scenarios": [],
            "relationship_exploitation": [],
            "physical_tailgating": []
        }
        
        # Spear phishing targets
        for target in high_value_targets[:5]:
            recommendations["spear_phishing_targets"].append({
                "name": target.name,
                "email": target.email,
                "title": target.job_title,
                "department": target.department,
                "vulnerability_score": target.vulnerability_score,
                "recommended_pretext": self._suggest_pretext(target)
            })
        
        # Pretexting scenarios
        recommendations["pretexting_scenarios"] = [
            "IT support password reset",
            "HR benefits enrollment",
            "Executive assistant scheduling",
            "Vendor credential verification",
            "Security audit compliance"
        ]
        
        return recommendations
    
    def _suggest_pretext(self, target: PersonProfile) -> str:
        """Suggest pretexting scenario for target"""
        dept = target.department
        
        pretexts = {
            "Engineering": "GitHub repository access issue",
            "Sales": "CRM system upgrade notification",
            "Marketing": "Campaign analytics report",
            "HR": "Benefits enrollment deadline",
            "Finance": "Expense report approval needed"
        }
        
        return pretexts.get(dept, "IT support request")
    
    def _save_intelligence(
        self,
        org_profile: OrganizationProfile,
        recommendations: Dict
    ):
        """Save weaponized intelligence"""
        output_file = self.output_dir / f"weaponized_intel_{org_profile.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        data = {
            "organization": org_profile.name,
            "domain": org_profile.domain,
            "total_employees": len(org_profile.employees),
            "email_patterns": self.email_identifier.discovered_patterns,
            "org_chart_summary": {
                level: len(people) if isinstance(people, list) else 0
                for level, people in org_profile.org_chart.items()
                if level != "relationships"
            },
            "attack_recommendations": recommendations,
            "generated_at": datetime.now().isoformat()
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n   💾 Intelligence saved: {output_file}")
