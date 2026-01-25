"""
CVE Correlation Engine
Matches discovered services against known CVEs and exploits
"""
import re
import requests
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger
from datetime import datetime, timedelta
import json
from pathlib import Path
import time


class CVECorrelationEngine:
    """
    Correlates discovered services with CVE database
    Identifies known vulnerabilities based on service versions
    """
    
    # NVD API Configuration
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # CVSSv3 Severity Mapping
    SEVERITY_MAP = {
        'CRITICAL': {'min': 9.0, 'max': 10.0},
        'HIGH': {'min': 7.0, 'max': 8.9},
        'MEDIUM': {'min': 4.0, 'max': 6.9},
        'LOW': {'min': 0.1, 'max': 3.9},
        'NONE': {'min': 0.0, 'max': 0.0}
    }
    
    def __init__(self, cache_dir: str = "./data/cve_cache", cache_ttl: int = 86400):
        """
        Initialize CVE correlation engine
        
        Args:
            cache_dir: Directory for caching CVE data
            cache_ttl: Cache time-to-live in seconds (default: 24 hours)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = cache_ttl
        
        # Load knowledge base integration
        try:
            from knowledge.knowledge_base import KnowledgeBase
            self.kb = KnowledgeBase()
        except Exception:
            self.kb = None
            logger.warning("Knowledge base not available")
        
        logger.info("CVE Correlation Engine initialized")
    
    def correlate_service(self, service: str, version: str, 
                         vendor: Optional[str] = None) -> Dict[str, Any]:
        """
        Correlate a service/version with known CVEs
        
        Args:
            service: Service name (e.g., 'apache', 'openssh', 'mysql')
            version: Version string (e.g., '2.4.41', '7.9p1')
            vendor: Optional vendor name (e.g., 'apache', 'openbsd')
            
        Returns:
            Dictionary containing:
                - cves: List of relevant CVEs
                - total_cves: Count of CVEs found
                - critical_count: Number of critical CVEs
                - high_count: Number of high severity CVEs
                - exploits_available: Count of CVEs with known exploits
        """
        logger.info(f"Correlating CVEs for {service} {version}")
        
        results = {
            'service': service,
            'version': version,
            'vendor': vendor,
            'cves': [],
            'total_cves': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'exploits_available': 0,
            'query_time': datetime.now().isoformat()
        }
        
        # Build search query
        search_query = self._build_search_query(service, version, vendor)
        
        # Search CVE database
        cves = self._search_cves(search_query)
        
        # Filter and score CVEs by relevance
        relevant_cves = self._filter_relevant_cves(cves, service, version)
        
        # Enrich with exploit information
        enriched_cves = self._enrich_with_exploits(relevant_cves)
        
        results['cves'] = enriched_cves
        results['total_cves'] = len(enriched_cves)
        
        # Calculate statistics
        for cve in enriched_cves:
            severity = cve.get('severity', '').upper()
            if severity == 'CRITICAL':
                results['critical_count'] += 1
            elif severity == 'HIGH':
                results['high_count'] += 1
            elif severity == 'MEDIUM':
                results['medium_count'] += 1
            elif severity == 'LOW':
                results['low_count'] += 1
            
            if cve.get('exploit_available'):
                results['exploits_available'] += 1
        
        logger.info(f"Found {results['total_cves']} CVEs ({results['critical_count']} critical, "
                   f"{results['high_count']} high, {results['exploits_available']} with exploits)")
        
        return results
    
    def _build_search_query(self, service: str, version: str, 
                           vendor: Optional[str] = None) -> str:
        """Build search query for CVE database"""
        # Normalize service name
        service = service.lower().strip()
        
        # Common service name mappings
        service_mappings = {
            'http': 'apache',
            'https': 'apache',
            'ssh': 'openssh',
            'ftp': 'vsftpd',
            'smb': 'samba',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'mssql': 'microsoft sql server',
            'mongodb': 'mongodb',
            'redis': 'redis',
            'nginx': 'nginx',
            'apache': 'apache',
            'iis': 'microsoft iis'
        }
        
        service_name = service_mappings.get(service, service)
        
        # Build query
        if vendor:
            query = f"{vendor} {service_name} {version}"
        else:
            query = f"{service_name} {version}"
        
        return query
    
    def _search_cves(self, query: str) -> List[Dict[str, Any]]:
        """Search CVE database with caching"""
        # Check cache first
        cache_key = self._get_cache_key(query)
        cached = self._load_from_cache(cache_key)
        
        if cached:
            logger.debug(f"Using cached CVE data for: {query}")
            return cached
        
        # Fetch from NVD API
        cves = self._fetch_from_nvd(query)
        
        # Cache results
        if cves:
            self._save_to_cache(cache_key, cves)
        
        return cves
    
    def _fetch_from_nvd(self, query: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API"""
        try:
            params = {
                'keywordSearch': query,
                'resultsPerPage': max_results
            }
            
            logger.debug(f"Querying NVD API: {query}")
            response = requests.get(self.NVD_API_BASE, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                cves = []
                for item in data.get('vulnerabilities', []):
                    cve_data = item.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    # Extract metrics (prefer CVSSv3)
                    metrics = cve_data.get('metrics', {})
                    cvss_v31 = metrics.get('cvssMetricV31', [])
                    cvss_v30 = metrics.get('cvssMetricV30', [])
                    cvss_v2 = metrics.get('cvssMetricV2', [])
                    
                    # Get primary metric
                    cvss_metric = None
                    if cvss_v31:
                        cvss_metric = cvss_v31[0]
                        cvss_version = '3.1'
                    elif cvss_v30:
                        cvss_metric = cvss_v30[0]
                        cvss_version = '3.0'
                    elif cvss_v2:
                        cvss_metric = cvss_v2[0]
                        cvss_version = '2.0'
                    
                    cvss_data = cvss_metric.get('cvssData', {}) if cvss_metric else {}
                    
                    # Get description
                    descriptions = cve_data.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Get references
                    references = cve_data.get('references', [])
                    ref_urls = [ref.get('url', '') for ref in references]
                    
                    cves.append({
                        'cve_id': cve_id,
                        'description': description,
                        'published_date': cve_data.get('published', ''),
                        'last_modified': cve_data.get('lastModified', ''),
                        'cvss_version': cvss_version if cvss_metric else None,
                        'cvss_score': cvss_data.get('baseScore', 0.0),
                        'cvss_severity': cvss_data.get('baseSeverity', 'UNKNOWN'),
                        'cvss_vector': cvss_data.get('vectorString', ''),
                        'exploitability_score': cvss_metric.get('exploitabilityScore', 0.0) if cvss_metric else 0.0,
                        'impact_score': cvss_metric.get('impactScore', 0.0) if cvss_metric else 0.0,
                        'references': ref_urls,
                        'cwe_ids': [w.get('value', '') for w in cve_data.get('weaknesses', [{}])[0].get('description', [])]
                    })
                
                logger.info(f"Fetched {len(cves)} CVEs from NVD")
                return cves
                
            elif response.status_code == 403:
                logger.warning("NVD API rate limit exceeded. Using cached data only.")
                return []
            else:
                logger.warning(f"NVD API returned status {response.status_code}")
                return []
                
        except requests.RequestException as e:
            logger.error(f"Error fetching CVEs from NVD: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing NVD response: {e}")
            return []
    
    def _filter_relevant_cves(self, cves: List[Dict[str, Any]], 
                             service: str, version: str) -> List[Dict[str, Any]]:
        """Filter CVEs to only include relevant ones for the service/version"""
        relevant = []
        
        for cve in cves:
            # Calculate relevance score
            relevance = self._calculate_relevance(cve, service, version)
            
            if relevance > 0.3:  # Threshold for relevance
                cve['relevance_score'] = relevance
                relevant.append(cve)
        
        # Sort by relevance and severity
        relevant.sort(
            key=lambda x: (x.get('cvss_score', 0), x.get('relevance_score', 0)),
            reverse=True
        )
        
        return relevant
    
    def _calculate_relevance(self, cve: Dict[str, Any], 
                            service: str, version: str) -> float:
        """Calculate how relevant a CVE is to the service/version"""
        relevance = 0.0
        
        description = cve.get('description', '').lower()
        service_lower = service.lower()
        version_lower = version.lower()
        
        # Exact service name match
        if service_lower in description:
            relevance += 0.5
        
        # Version mentioned
        if version_lower in description:
            relevance += 0.3
        
        # Generic version patterns (e.g., "before 2.4.50")
        version_patterns = [
            r'before\s+[\d.]+',
            r'prior\s+to\s+[\d.]+',
            r'through\s+[\d.]+',
            r'versions?\s+[\d.]+',
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, description):
                relevance += 0.2
                break
        
        return min(relevance, 1.0)
    
    def _enrich_with_exploits(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich CVE data with exploit information"""
        for cve in cves:
            # Check references for exploit indicators
            exploit_keywords = ['exploit', 'poc', 'proof-of-concept', 'metasploit', 'exploit-db']
            
            exploit_refs = []
            for ref in cve.get('references', []):
                ref_lower = ref.lower()
                if any(keyword in ref_lower for keyword in exploit_keywords):
                    exploit_refs.append(ref)
            
            cve['exploit_available'] = len(exploit_refs) > 0
            cve['exploit_references'] = exploit_refs
        
        return cves
    
    def _get_cache_key(self, query: str) -> str:
        """Generate cache key from query"""
        # Sanitize query for filename
        safe_query = re.sub(r'[^\w\s-]', '', query).strip().replace(' ', '_')
        return f"cve_{safe_query}.json"
    
    def _load_from_cache(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Load CVE data from cache if available and fresh"""
        cache_file = self.cache_dir / cache_key
        
        if not cache_file.exists():
            return None
        
        # Check if cache is fresh
        file_age = time.time() - cache_file.stat().st_mtime
        if file_age > self.cache_ttl:
            logger.debug(f"Cache expired for {cache_key}")
            return None
        
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error loading cache: {e}")
            return None
    
    def _save_to_cache(self, cache_key: str, data: List[Dict[str, Any]]) -> None:
        """Save CVE data to cache"""
        cache_file = self.cache_dir / cache_key
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Error saving to cache: {e}")
    
    def batch_correlate(self, services: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Correlate multiple services in batch
        
        Args:
            services: List of dicts with 'service', 'version', optional 'vendor'
            
        Returns:
            List of correlation results
        """
        results = []
        
        for svc in services:
            result = self.correlate_service(
                service=svc.get('service', ''),
                version=svc.get('version', ''),
                vendor=svc.get('vendor')
            )
            results.append(result)
            
            # Rate limiting to avoid API throttling
            time.sleep(0.5)
        
        return results
    
    def generate_vulnerabilities(self, correlation_result: Dict[str, Any], 
                                target: str) -> List[Dict[str, Any]]:
        """
        Convert CVE correlation results to vulnerability findings format
        
        Args:
            correlation_result: Result from correlate_service()
            target: Target identifier (IP:port or URL)
            
        Returns:
            List of vulnerability dictionaries compatible with Phase2Orchestrator
        """
        vulnerabilities = []
        
        service = correlation_result.get('service', '')
        version = correlation_result.get('version', '')
        
        for cve_data in correlation_result.get('cves', []):
            vuln = {
                'vuln_id': cve_data.get('cve_id', ''),
                'title': f"{cve_data.get('cve_id')} in {service} {version}",
                'severity': cve_data.get('cvss_severity', 'UNKNOWN').lower(),
                'cvss_score': cve_data.get('cvss_score', 0.0),
                'description': cve_data.get('description', ''),
                'affected_target': target,
                'affected_service': service,
                'affected_version': version,
                'exploit_available': cve_data.get('exploit_available', False),
                'exploit_references': cve_data.get('exploit_references', []),
                'tool_source': 'cve_matcher',
                'confidence': cve_data.get('relevance_score', 0.8),
                'evidence': [
                    f"Service: {service} {version}",
                    f"CVSS Score: {cve_data.get('cvss_score')}",
                    f"CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}"
                ],
                'remediation': f"Update {service} to a patched version. "
                              f"See references: {', '.join(cve_data.get('references', [])[:2])}"
            }
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities


# Convenience function
def correlate_service_version(service: str, version: str, vendor: Optional[str] = None) -> Dict[str, Any]:
    """
    Quick function to correlate a service version with CVEs
    
    Args:
        service: Service name
        version: Version string
        vendor: Optional vendor name
        
    Returns:
        Correlation results
    """
    engine = CVECorrelationEngine()
    return engine.correlate_service(service, version, vendor)
