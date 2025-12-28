"""
Knowledge Base for CVEs, Exploits, and Pentesting Techniques
"""
from typing import Dict, Any, List, Optional
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta
from loguru import logger
import time


class KnowledgeBase:
    """Central knowledge base for pentesting information"""
    
    def __init__(self, data_dir: str = "./data/knowledge"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.cve_cache = self.data_dir / "cves.json"
        self.exploit_db = self.data_dir / "exploits.json"
        self.techniques_db = self.data_dir / "techniques.json"
        
        self._load_databases()
        
        logger.info("Knowledge base initialized")
    
    def _load_databases(self):
        """Load local databases"""
        self.cves = self._load_json(self.cve_cache, {})
        self.exploits = self._load_json(self.exploit_db, {})
        self.techniques = self._load_json(self.techniques_db, self._get_default_techniques())
    
    def _load_json(self, filepath: Path, default: Any) -> Any:
        """Load JSON file"""
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
        return default
    
    def _save_json(self, filepath: Path, data: Any):
        """Save JSON file"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _get_default_techniques(self) -> Dict[str, Any]:
        """Get default pentesting techniques"""
        return {
            "network_discovery": {
                "name": "Network Discovery",
                "description": "Identify live hosts and network topology",
                "tools": ["nmap", "netdiscover", "arp-scan"],
                "mitre_id": "T1046",
                "success_rate": 0.95,
                "stealth_level": "medium",
                "parameters": {
                    "nmap": ["-sn", "-T4"]
                }
            },
            "service_enumeration": {
                "name": "Service Enumeration",
                "description": "Identify running services and versions",
                "tools": ["nmap", "masscan"],
                "mitre_id": "T1046",
                "success_rate": 0.90,
                "stealth_level": "medium",
                "parameters": {
                    "nmap": ["-sV", "-sC"]
                }
            },
            "sql_injection": {
                "name": "SQL Injection Testing",
                "description": "Test for SQL injection vulnerabilities",
                "tools": ["sqlmap", "burp"],
                "mitre_id": "T1190",
                "success_rate": 0.35,
                "stealth_level": "low",
                "parameters": {
                    "sqlmap": ["--batch", "--level=1", "--risk=1"]
                }
            },
            "password_brute_force": {
                "name": "Password Brute Force",
                "description": "Attempt to crack passwords",
                "tools": ["hydra", "medusa", "ncrack"],
                "mitre_id": "T1110",
                "success_rate": 0.25,
                "stealth_level": "low",
                "parameters": {
                    "hydra": ["-t", "4", "-V"]
                }
            },
            "smb_enumeration": {
                "name": "SMB Enumeration",
                "description": "Enumerate SMB shares and users",
                "tools": ["enum4linux", "smbclient", "nmap"],
                "mitre_id": "T1135",
                "success_rate": 0.70,
                "stealth_level": "medium"
            }
        }
    
    def search_cve(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search CVE database"""
        # Try to fetch from NVD API
        results = self._fetch_nvd_cves(query, limit)
        
        if results:
            # Cache results
            for cve in results:
                self.cves[cve['id']] = cve
            self._save_json(self.cve_cache, self.cves)
        
        return results
    
    def _fetch_nvd_cves(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API"""
        try:
            # NVD API 2.0
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": query,
                "resultsPerPage": limit
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                results = []
                for item in data.get('vulnerabilities', [])[:limit]:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    
                    # Extract metrics
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
                    
                    results.append({
                        'id': cve_id,
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'published': cve.get('published', ''),
                        'cvss_score': cvss_v3.get('cvssData', {}).get('baseScore', 0),
                        'severity': cvss_v3.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                        'vector': cvss_v3.get('cvssData', {}).get('vectorString', ''),
                        'references': [ref.get('url', '') for ref in cve.get('references', [])]
                    })
                
                logger.info(f"Fetched {len(results)} CVEs for query: {query}")
                return results
            
        except Exception as e:
            logger.warning(f"Failed to fetch CVEs from NVD: {e}")
        
        # Fallback to cache
        return self._search_cached_cves(query, limit)
    
    def _search_cached_cves(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search cached CVEs"""
        query_lower = query.lower()
        results = []
        
        for cve_id, cve_data in self.cves.items():
            if query_lower in cve_data.get('description', '').lower():
                results.append(cve_data)
                if len(results) >= limit:
                    break
        
        return results
    
    def get_exploit_for_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get exploit information for CVE"""
        # Check local database
        if cve_id in self.exploits:
            return self.exploits[cve_id]
        
        # Try to find in ExploitDB (simplified - would need actual API)
        return self._search_exploit_db(cve_id)
    
    def _search_exploit_db(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Search exploit database"""
        # This is a placeholder - in production, integrate with actual exploit DBs
        # like ExploitDB API, Metasploit modules, etc.
        
        exploit_mapping = {
            "CVE-2017-0144": {  # EternalBlue
                "name": "EternalBlue SMB Exploit",
                "type": "remote",
                "platform": "windows",
                "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
                "description": "Remote code execution via SMB vulnerability",
                "reliability": 0.85
            },
            "CVE-2014-0160": {  # Heartbleed
                "name": "Heartbleed SSL/TLS",
                "type": "information_disclosure",
                "platform": "multi",
                "metasploit_module": "auxiliary/scanner/ssl/openssl_heartbleed",
                "description": "Memory disclosure in OpenSSL",
                "reliability": 0.95
            }
        }
        
        if cve_id in exploit_mapping:
            self.exploits[cve_id] = exploit_mapping[cve_id]
            self._save_json(self.exploit_db, self.exploits)
            return exploit_mapping[cve_id]
        
        return None
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get pentesting technique"""
        return self.techniques.get(technique_id)
    
    def get_techniques_for_context(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get relevant techniques based on context"""
        services = context.get('services', [])
        os_type = context.get('os', '').lower()
        
        relevant = []
        
        for tech_id, tech_data in self.techniques.items():
            # Match based on context
            if 'http' in services or 'web' in services:
                if tech_id in ['sql_injection', 'xss', 'csrf']:
                    relevant.append({**tech_data, 'id': tech_id})
            
            if 'ssh' in services:
                if tech_id == 'password_brute_force':
                    relevant.append({**tech_data, 'id': tech_id})
            
            if 'smb' in services or 'windows' in os_type:
                if tech_id == 'smb_enumeration':
                    relevant.append({**tech_data, 'id': tech_id})
            
            # Always include network discovery and service enumeration
            if tech_id in ['network_discovery', 'service_enumeration']:
                relevant.append({**tech_data, 'id': tech_id})
        
        # Sort by success rate
        relevant.sort(key=lambda x: x.get('success_rate', 0), reverse=True)
        
        return relevant
    
    def add_custom_technique(self, technique_id: str, technique_data: Dict[str, Any]):
        """Add custom technique to knowledge base"""
        self.techniques[technique_id] = technique_data
        self._save_json(self.techniques_db, self.techniques)
        logger.info(f"Added custom technique: {technique_id}")
    
    def update_technique_success_rate(self, technique_id: str, new_rate: float):
        """Update technique success rate based on learning"""
        if technique_id in self.techniques:
            old_rate = self.techniques[technique_id].get('success_rate', 0.5)
            # Weighted average (70% old, 30% new)
            self.techniques[technique_id]['success_rate'] = (old_rate * 0.7) + (new_rate * 0.3)
            self._save_json(self.techniques_db, self.techniques)
            logger.info(f"Updated {technique_id} success rate: {old_rate:.2f} -> {self.techniques[technique_id]['success_rate']:.2f}")
    
    def get_wordlist_suggestions(self, context: Dict[str, Any]) -> List[str]:
        """Generate custom wordlist based on context"""
        wordlist = set()
        
        # Add target-specific words
        target = context.get('target', '')
        if target:
            parts = target.replace('.', ' ').replace('-', ' ').split()
            wordlist.update(parts)
        
        # Add organization name variations
        org = context.get('organization', '')
        if org:
            wordlist.add(org.lower())
            wordlist.add(org.upper())
            wordlist.add(org.title())
        
        # Add technology-specific defaults
        technologies = context.get('technologies', [])
        for tech in technologies:
            if 'wordpress' in tech.lower():
                wordlist.update(['admin', 'wp-admin', 'administrator'])
            if 'apache' in tech.lower():
                wordlist.update(['apache', 'httpd', 'www-data'])
        
        # Add common passwords
        wordlist.update(['admin', 'password', 'password123', '123456', 'admin123'])
        
        return sorted(list(wordlist))
    
    def get_evasion_techniques(self, defensive_mechanisms: List[str]) -> List[Dict[str, Any]]:
        """Get evasion techniques based on detected defenses"""
        evasion = []
        
        if 'ids' in defensive_mechanisms or 'ips' in defensive_mechanisms:
            evasion.append({
                'technique': 'packet_fragmentation',
                'description': 'Fragment packets to evade IDS/IPS',
                'nmap_flags': ['-f'],
                'effectiveness': 0.6
            })
            evasion.append({
                'technique': 'timing_delays',
                'description': 'Add delays between packets',
                'nmap_flags': ['-T', '1'],
                'effectiveness': 0.7
            })
        
        if 'firewall' in defensive_mechanisms:
            evasion.append({
                'technique': 'source_port_manipulation',
                'description': 'Use common source ports',
                'nmap_flags': ['-g', '53'],
                'effectiveness': 0.5
            })
        
        if 'waf' in defensive_mechanisms:
            evasion.append({
                'technique': 'payload_encoding',
                'description': 'Encode payloads to evade WAF',
                'sqlmap_flags': ['--tamper=space2comment'],
                'effectiveness': 0.6
            })
        
        return evasion
    
    def get_stats(self) -> Dict[str, int]:
        """Get knowledge base statistics"""
        return {
            'cached_cves': len(self.cves),
            'known_exploits': len(self.exploits),
            'techniques': len(self.techniques)
        }
