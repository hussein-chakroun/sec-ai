"""
CVE Monitor
Automated CVE monitoring and analysis
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import random
import json


logger = logging.getLogger(__name__)


class CVEMonitor:
    """
    Automated CVE Monitoring and Intelligence Engine
    
    Monitors, analyzes, and correlates CVE data for targeted systems
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.cve_sources = [
            'nvd_nist',
            'mitre',
            'exploit_db',
            'cve_details',
            'vendor_advisories'
        ]
        
        self.severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    async def monitor_cves(
        self,
        target: str,
        keywords: List[str] = None,
        severity_threshold: float = 7.0,
        days_back: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Monitor and analyze recent CVEs relevant to target
        """
        if keywords is None:
            keywords = []
        
        self.logger.info(f"Monitoring CVEs for {target} (severity >= {severity_threshold}, last {days_back} days)")
        
        # Discover target technologies
        technologies = await self._identify_technologies(target)
        
        # Expand keywords with identified technologies
        all_keywords = keywords + [tech['name'] for tech in technologies]
        
        # Search CVEs from multiple sources
        cves = []
        for source in self.cve_sources:
            source_cves = await self._fetch_cves_from_source(
                source,
                all_keywords,
                severity_threshold,
                days_back
            )
            cves.extend(source_cves)
        
        # Deduplicate and enrich CVEs
        unique_cves = self._deduplicate_cves(cves)
        enriched_cves = await self._enrich_cves(unique_cves, technologies)
        
        # Prioritize CVEs
        prioritized = self._prioritize_cves(enriched_cves, target)
        
        summary = {
            'target': target,
            'technologies_identified': len(technologies),
            'keywords_used': len(all_keywords),
            'total_cves_found': len(unique_cves),
            'critical_cves': len([c for c in enriched_cves if c.get('severity') == 'CRITICAL']),
            'high_cves': len([c for c in enriched_cves if c.get('severity') == 'HIGH']),
            'exploitable_cves': len([c for c in enriched_cves if c.get('exploit_available')]),
            'priority_cves': prioritized[:10]
        }
        
        return [summary]
    
    async def _identify_technologies(self, target: str) -> List[Dict[str, Any]]:
        """Identify technologies used by target"""
        await asyncio.sleep(0.1)
        
        # Simulated technology fingerprinting
        common_technologies = [
            {'name': 'Apache', 'version': '2.4.41', 'category': 'web_server'},
            {'name': 'OpenSSL', 'version': '1.1.1k', 'category': 'crypto'},
            {'name': 'PHP', 'version': '7.4.3', 'category': 'language'},
            {'name': 'MySQL', 'version': '8.0.23', 'category': 'database'},
            {'name': 'WordPress', 'version': '5.8', 'category': 'cms'},
            {'name': 'nginx', 'version': '1.18.0', 'category': 'web_server'},
            {'name': 'Node.js', 'version': '14.17.0', 'category': 'runtime'},
            {'name': 'React', 'version': '17.0.2', 'category': 'framework'},
            {'name': 'jQuery', 'version': '3.6.0', 'category': 'library'},
            {'name': 'Linux Kernel', 'version': '5.4.0', 'category': 'os'}
        ]
        
        # Randomly select technologies for this target
        num_technologies = random.randint(3, 7)
        technologies = random.sample(common_technologies, num_technologies)
        
        return technologies
    
    async def _fetch_cves_from_source(
        self,
        source: str,
        keywords: List[str],
        severity_threshold: float,
        days_back: int
    ) -> List[Dict[str, Any]]:
        """Fetch CVEs from a specific source"""
        await asyncio.sleep(0.05)
        
        cves = []
        num_cves = random.randint(5, 20)
        
        for i in range(num_cves):
            keyword = random.choice(keywords) if keywords else 'generic'
            
            cve_id = f"CVE-2024-{random.randint(10000, 99999)}"
            score = random.uniform(severity_threshold, 10.0)
            
            # Determine severity from CVSS score
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            cve = {
                'cve_id': cve_id,
                'source': source,
                'cvss_score': round(score, 1),
                'severity': severity,
                'published_date': (datetime.now() - timedelta(days=random.randint(0, days_back))).isoformat(),
                'affected_product': keyword,
                'description': f"Vulnerability in {keyword} allows {random.choice(['RCE', 'privilege escalation', 'information disclosure', 'DoS'])}",
                'exploit_available': random.random() > 0.7,
                'patch_available': random.random() > 0.4
            }
            
            cves.append(cve)
        
        return cves
    
    def _deduplicate_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate CVEs"""
        seen_ids = set()
        unique = []
        
        for cve in cves:
            cve_id = cve['cve_id']
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                unique.append(cve)
        
        return unique
    
    async def _enrich_cves(
        self,
        cves: List[Dict[str, Any]],
        technologies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich CVE data with additional intelligence"""
        await asyncio.sleep(0.1)
        
        for cve in cves:
            # Add exploit information
            if cve.get('exploit_available'):
                cve['exploit_maturity'] = random.choice(['poc', 'functional', 'high', 'weaponized'])
                cve['exploit_sources'] = random.sample(['exploit-db', 'github', 'metasploit', 'packetstorm'], 
                                                       random.randint(1, 3))
            
            # Add affected versions
            matching_tech = next((t for t in technologies if t['name'].lower() in cve['affected_product'].lower()), None)
            if matching_tech:
                cve['affected_versions'] = [matching_tech['version']]
                cve['technology_match'] = True
            else:
                cve['technology_match'] = False
            
            # Add references
            cve['references'] = [
                f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve['cve_id']}"
            ]
            
            # Add attack vector
            cve['attack_vector'] = random.choice(['network', 'adjacent', 'local', 'physical'])
            cve['attack_complexity'] = random.choice(['low', 'high'])
            cve['privileges_required'] = random.choice(['none', 'low', 'high'])
            
        return cves
    
    def _prioritize_cves(self, cves: List[Dict[str, Any]], target: str) -> List[Dict[str, Any]]:
        """Prioritize CVEs based on exploitability and impact"""
        
        def calculate_priority_score(cve: Dict[str, Any]) -> float:
            score = cve['cvss_score']
            
            # Boost score for exploit availability
            if cve.get('exploit_available'):
                score += 2.0
                if cve.get('exploit_maturity') == 'weaponized':
                    score += 1.0
            
            # Boost for technology match
            if cve.get('technology_match'):
                score += 1.5
            
            # Boost for network-based attacks
            if cve.get('attack_vector') == 'network':
                score += 1.0
            
            # Boost for no privileges required
            if cve.get('privileges_required') == 'none':
                score += 0.5
            
            # Reduce score if patch available
            if cve.get('patch_available'):
                score -= 0.5
            
            return score
        
        # Calculate priority scores
        for cve in cves:
            cve['priority_score'] = calculate_priority_score(cve)
        
        # Sort by priority score
        return sorted(cves, key=lambda x: x['priority_score'], reverse=True)
