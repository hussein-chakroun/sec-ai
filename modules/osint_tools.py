"""
OSINT (Open Source Intelligence) Tools Module
Integrates multiple OSINT frameworks and services
"""
import subprocess
import requests
import json
import re
from typing import Dict, Any, List, Optional
from loguru import logger
from .base_tool import BaseTool


class HaveIBeenPwnedChecker:
    """Have I Been Pwned API integration for email breach checking"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            "User-Agent": "Security-Assessment-Tool"
        }
        if api_key:
            self.headers["hibp-api-key"] = api_key
    
    def check_email(self, email: str) -> Dict[str, Any]:
        """Check if email has been in data breaches"""
        logger.info(f"Checking email breach status: {email}")
        
        results = {
            "email": email,
            "breached": False,
            "breaches": [],
            "breach_count": 0,
            "pastes": [],
            "paste_count": 0
        }
        
        try:
            # Check breaches
            breach_url = f"{self.base_url}/breachedaccount/{email}"
            response = requests.get(breach_url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                results["breached"] = True
                results["breaches"] = breaches
                results["breach_count"] = len(breaches)
                logger.warning(f"Email {email} found in {len(breaches)} breaches")
            elif response.status_code == 404:
                logger.info(f"Email {email} not found in breaches")
            else:
                logger.warning(f"HIBP API returned status {response.status_code}")
            
            # Check pastes (if API key provided)
            if self.api_key:
                paste_url = f"{self.base_url}/pasteaccount/{email}"
                paste_response = requests.get(paste_url, headers=self.headers, timeout=10)
                
                if paste_response.status_code == 200:
                    pastes = paste_response.json()
                    results["pastes"] = pastes
                    results["paste_count"] = len(pastes)
                    logger.warning(f"Email {email} found in {len(pastes)} pastes")
        
        except requests.RequestException as e:
            logger.error(f"HIBP check failed: {e}")
            results["error"] = str(e)
        
        return results
    
    def check_multiple_emails(self, emails: List[str]) -> Dict[str, Any]:
        """Check multiple emails for breaches"""
        logger.info(f"Checking {len(emails)} emails")
        
        results = {
            "emails_checked": len(emails),
            "breached_emails": [],
            "clean_emails": [],
            "total_breaches": 0,
            "details": {}
        }
        
        for email in emails:
            email_result = self.check_email(email)
            results["details"][email] = email_result
            
            if email_result.get("breached"):
                results["breached_emails"].append(email)
                results["total_breaches"] += email_result.get("breach_count", 0)
            else:
                results["clean_emails"].append(email)
        
        return results


class SpiderFootScanner(BaseTool):
    """SpiderFoot OSINT automation tool wrapper"""
    
    def get_default_command(self) -> str:
        return "spiderfoot"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse SpiderFoot output"""
        return {
            "raw_output": output,
            "findings": self._extract_findings(output)
        }
    
    def _extract_findings(self, output: str) -> List[str]:
        """Extract findings from output"""
        findings = []
        for line in output.split('\n'):
            if any(keyword in line.lower() for keyword in ['found', 'discovered', 'identified']):
                findings.append(line.strip())
        return findings
    
    def scan_target(self, target: str, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run SpiderFoot scan on target
        
        Args:
            target: Domain or IP to scan
            modules: Specific modules to run (None = all modules)
        """
        logger.info(f"Starting SpiderFoot scan on {target}")
        
        args = ["-s", target]
        
        if modules:
            args.extend(["-m", ",".join(modules)])
        else:
            # Common useful modules
            args.extend(["-m", "sfp_dnsresolve,sfp_emails,sfp_names,sfp_social,sfp_whois"])
        
        # Output format
        args.extend(["-o", "json"])
        
        return self.execute(args)
    
    def check_installation(self) -> bool:
        """Check if SpiderFoot is installed"""
        try:
            subprocess.run([self.tool_path, "-h"], capture_output=True, timeout=5)
            return True
        except:
            return False


class IntelligenceXAPI:
    """Intelligence X API integration for deep web/dark web searches"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://2.intelx.io"
        self.headers = {
            "x-key": api_key if api_key else "",
            "User-Agent": "Security-Assessment-Tool"
        }
    
    def search(self, query: str, search_type: str = "domain") -> Dict[str, Any]:
        """
        Search Intelligence X
        
        Args:
            query: Search term (domain, email, IP, etc.)
            search_type: Type of search (domain, email, ip, url, etc.)
        """
        logger.info(f"Intelligence X search: {query} (type: {search_type})")
        
        if not self.api_key:
            return {
                "error": "No API key provided",
                "available": False,
                "message": "Intelligence X requires API key"
            }
        
        results = {
            "query": query,
            "type": search_type,
            "results": [],
            "count": 0
        }
        
        try:
            # Initiate search
            search_url = f"{self.base_url}/intelligent/search"
            payload = {
                "term": query,
                "maxresults": 100,
                "media": 0,
                "sort": 4,
                "terminate": []
            }
            
            response = requests.post(search_url, json=payload, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                results["results"] = data.get("selectors", [])
                results["count"] = len(results["results"])
                logger.info(f"Found {results['count']} results")
            else:
                logger.warning(f"Intelligence X returned status {response.status_code}")
                results["error"] = f"API returned {response.status_code}"
        
        except requests.RequestException as e:
            logger.error(f"Intelligence X search failed: {e}")
            results["error"] = str(e)
        
        return results


class MaltegoTransform:
    """Maltego transform execution wrapper"""
    
    def __init__(self):
        self.maltego_path = self._find_maltego()
    
    def _find_maltego(self) -> Optional[str]:
        """Find Maltego installation"""
        # Common Maltego paths
        paths = [
            "maltego",
            "/usr/bin/maltego",
            "C:\\Program Files\\Maltego\\maltego.exe",
            "C:\\Program Files (x86)\\Maltego\\maltego.exe"
        ]
        
        for path in paths:
            try:
                subprocess.run([path, "--version"], capture_output=True, timeout=5)
                return path
            except:
                continue
        
        return None
    
    def is_available(self) -> bool:
        """Check if Maltego is available"""
        return self.maltego_path is not None
    
    def run_transform(self, entity_type: str, entity_value: str, transform: str) -> Dict[str, Any]:
        """
        Run Maltego transform
        
        Args:
            entity_type: Type of entity (domain, email, person, etc.)
            entity_value: Value of entity
            transform: Transform to run
        """
        if not self.is_available():
            return {
                "error": "Maltego not installed",
                "available": False
            }
        
        logger.info(f"Running Maltego transform: {transform} on {entity_value}")
        
        # Note: Maltego CLI requires proper configuration
        # This is a placeholder for integration
        return {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "transform": transform,
            "message": "Maltego transforms require GUI or API configuration",
            "recommendation": "Use Maltego GUI for manual transforms"
        }


class OSINTFrameworkCollector:
    """OSINT Framework - Collection of OSINT resources and tools"""
    
    def __init__(self):
        self.categories = {
            "username": ["Namechk", "KnowEm", "WhatsMyName"],
            "email": ["Hunter.io", "Email-Format", "Clearbit"],
            "domain": ["Whois", "DNS", "Subdomain Finder"],
            "ip": ["Shodan", "Censys", "IP Location"],
            "social_media": ["Social-Searcher", "Hootsuite", "Mention"],
            "people": ["Pipl", "Spokeo", "BeenVerified"],
            "company": ["Crunchbase", "LinkedIn", "ZoomInfo"]
        }
    
    def get_tools_for_category(self, category: str) -> List[str]:
        """Get recommended tools for category"""
        return self.categories.get(category, [])
    
    def generate_recommendations(self, target_type: str, target_value: str) -> Dict[str, Any]:
        """Generate OSINT recommendations based on target type"""
        logger.info(f"Generating OSINT recommendations for {target_type}: {target_value}")
        
        recommendations = {
            "target_type": target_type,
            "target_value": target_value,
            "recommended_tools": [],
            "manual_checks": [],
            "automated_available": []
        }
        
        if target_type == "domain":
            recommendations["recommended_tools"] = [
                "WHOIS lookup",
                "DNS enumeration",
                "SSL certificate transparency logs",
                "Subdomain enumeration",
                "Historical DNS records",
                "Website screenshots (archive.org)"
            ]
            recommendations["manual_checks"] = [
                f"https://whois.domaintools.com/{target_value}",
                f"https://crt.sh/?q=%25.{target_value}",
                f"https://web.archive.org/web/*/{target_value}"
            ]
        
        elif target_type == "email":
            recommendations["recommended_tools"] = [
                "Have I Been Pwned",
                "Email format validation",
                "Domain verification",
                "Social media association",
                "Breach databases"
            ]
            recommendations["automated_available"] = ["Have I Been Pwned API"]
        
        elif target_type == "person":
            recommendations["recommended_tools"] = [
                "Social media search",
                "Public records",
                "Professional networks (LinkedIn)",
                "Username enumeration",
                "Photo reverse search"
            ]
        
        elif target_type == "company":
            recommendations["recommended_tools"] = [
                "Business registration search",
                "Financial records",
                "Employee enumeration",
                "Technology stack analysis",
                "News and media mentions"
            ]
        
        return recommendations


class OSINTSuite:
    """
    Comprehensive OSINT suite combining multiple tools and services
    """
    
    def __init__(self, hibp_api_key: Optional[str] = None, intelx_api_key: Optional[str] = None):
        self.hibp = HaveIBeenPwnedChecker(hibp_api_key)
        self.spiderfoot = SpiderFootScanner()
        self.intelx = IntelligenceXAPI(intelx_api_key)
        self.maltego = MaltegoTransform()
        self.framework = OSINTFrameworkCollector()
    
    def perform_osint(self, target: str, target_type: str = "domain", 
                     tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive OSINT on target
        
        Args:
            target: Target to investigate (domain, email, IP, etc.)
            target_type: Type of target (domain, email, ip, person, company)
            tools: List of tools to use (None = all available)
        
        Returns:
            Dictionary containing OSINT results from all tools
        """
        logger.info(f"Starting OSINT investigation on {target} (type: {target_type})")
        
        results = {
            "target": target,
            "target_type": target_type,
            "osint_results": {},
            "emails_found": [],
            "social_media": [],
            "data_leaks": [],
            "recommendations": {}
        }
        
        # Default to all available tools
        if tools is None:
            tools = ['hibp', 'spiderfoot', 'intelx', 'framework']
        
        try:
            # Have I Been Pwned (for emails)
            if 'hibp' in tools and target_type == "email":
                logger.info("Running Have I Been Pwned check...")
                results['osint_results']['hibp'] = self.hibp.check_email(target)
            
            # SpiderFoot
            if 'spiderfoot' in tools and self.spiderfoot.check_installation():
                logger.info("Running SpiderFoot scan...")
                results['osint_results']['spiderfoot'] = self.spiderfoot.scan_target(target)
            
            # Intelligence X
            if 'intelx' in tools:
                logger.info("Running Intelligence X search...")
                results['osint_results']['intelx'] = self.intelx.search(target, target_type)
            
            # OSINT Framework Recommendations
            if 'framework' in tools:
                logger.info("Generating OSINT framework recommendations...")
                results['recommendations'] = self.framework.generate_recommendations(
                    target_type, target
                )
            
            # Maltego (availability check)
            if 'maltego' in tools:
                results['osint_results']['maltego'] = {
                    "available": self.maltego.is_available(),
                    "message": "Use Maltego GUI for interactive transforms" if self.maltego.is_available() 
                              else "Maltego not installed"
                }
            
            logger.info("OSINT investigation completed")
        
        except Exception as e:
            logger.error(f"OSINT investigation error: {e}")
            results['error'] = str(e)
        
        return results
    
    def check_emails_from_list(self, emails: List[str]) -> Dict[str, Any]:
        """Check multiple emails for breaches"""
        return self.hibp.check_multiple_emails(emails)
