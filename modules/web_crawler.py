"""
Web Crawler and Information Gatherer with IDS/IPS Evasion
Crawls websites to extract emails, links, metadata, technologies, and potential vulnerabilities
Includes advanced evasion techniques to avoid detection
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
from typing import Dict, Any, List, Set, Optional
from loguru import logger
import time
import random
from collections import defaultdict


class EvasiveCrawlerConfig:
    """Configuration for evasive web crawling"""
    
    # Rotate between multiple realistic user agents
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    ]
    
    # Realistic referer patterns
    REFERERS = [
        'https://www.google.com/',
        'https://www.bing.com/',
        'https://duckduckgo.com/',
        'https://search.yahoo.com/',
        '',  # No referer sometimes
    ]
    
    # Accept language variations
    ACCEPT_LANGUAGES = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'en-US,en;q=0.9,es;q=0.8',
        'en-CA,en;q=0.9',
    ]
    
    # Request timing (min, max in seconds)
    REQUEST_DELAY_RANGE = (1.0, 4.0)
    
    # Use random timing jitter
    ENABLE_JITTER = True
    
    # Session cookies to appear as a real browser
    MAINTAIN_COOKIES = True
    
    # Follow redirects like a real browser
    FOLLOW_REDIRECTS = True
    
    # Maximum redirects to follow
    MAX_REDIRECTS = 5


class WebCrawler:
    """
    Intelligent web crawler for information gathering with IDS/IPS evasion
    Extracts emails, links, forms, technologies, and metadata
    """
    
    def __init__(self, max_depth: int = 3, max_pages: int = 50, timeout: int = 10, evasive: bool = True):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.evasive = evasive
        self.visited_urls = set()
        self.session = requests.Session()
        
        # Configure session for evasion
        if self.evasive:
            self._configure_evasive_session()
        else:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
        
        self.last_request_time = 0
    
    def _configure_evasive_session(self):
        """Configure session with evasion techniques"""
        # Initial headers with random user agent
        self.session.headers.update({
            'User-Agent': random.choice(EvasiveCrawlerConfig.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(EvasiveCrawlerConfig.ACCEPT_LANGUAGES),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        })
        
        if EvasiveCrawlerConfig.MAINTAIN_COOKIES:
            self.session.cookies.update({
                'session_id': f'sess_{random.randint(100000, 999999)}',
            })
    
    def _rotate_headers(self, url: str):
        """Rotate headers for each request to appear more human"""
        if not self.evasive:
            return
        
        # Rotate user agent occasionally (not every request)
        if random.random() < 0.3:  # 30% chance
            self.session.headers['User-Agent'] = random.choice(EvasiveCrawlerConfig.USER_AGENTS)
        
        # Rotate accept language occasionally
        if random.random() < 0.2:  # 20% chance
            self.session.headers['Accept-Language'] = random.choice(EvasiveCrawlerConfig.ACCEPT_LANGUAGES)
        
        # Add realistic referer
        referer = random.choice(EvasiveCrawlerConfig.REFERERS)
        if referer:
            self.session.headers['Referer'] = referer
        elif 'Referer' in self.session.headers:
            del self.session.headers['Referer']
    
    def _apply_timing_evasion(self):
        """Apply random delays to mimic human browsing"""
        if not self.evasive:
            return
        
        # Calculate delay
        current_time = time.time()
        min_delay, max_delay = EvasiveCrawlerConfig.REQUEST_DELAY_RANGE
        
        base_delay = random.uniform(min_delay, max_delay)
        
        # Add jitter
        if EvasiveCrawlerConfig.ENABLE_JITTER:
            jitter = random.uniform(-0.5, 0.5)
            base_delay += jitter
        
        # Ensure minimum delay between requests
        elapsed = current_time - self.last_request_time
        if elapsed < base_delay:
            sleep_time = base_delay - elapsed
            logger.debug(f"Timing evasion: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def crawl(self, start_url: str) -> Dict[str, Any]:
        """
        Crawl website starting from start_url
        
        Returns:
            Dictionary containing all gathered information
        """
        logger.info(f"Starting crawl of {start_url}")
        
        results = {
            "start_url": start_url,
            "pages_crawled": 0,
            "emails": set(),
            "phone_numbers": set(),
            "social_media": defaultdict(set),
            "subdomains": set(),
            "external_links": set(),
            "internal_links": set(),
            "forms": [],
            "technologies": set(),
            "metadata": {},
            "comments": [],
            "javascript_files": set(),
            "css_files": set(),
            "images": set(),
            "documents": set(),
            "potential_vulnerabilities": []
        }
        
        # Parse base domain
        parsed_url = urlparse(start_url)
        base_domain = parsed_url.netloc
        
        # Start crawling
        self._crawl_recursive(start_url, base_domain, 0, results)
        
        # Convert sets to lists for JSON serialization
        results["emails"] = list(results["emails"])
        results["phone_numbers"] = list(results["phone_numbers"])
        results["social_media"] = {k: list(v) for k, v in results["social_media"].items()}
        results["subdomains"] = list(results["subdomains"])
        results["external_links"] = list(results["external_links"])
        results["internal_links"] = list(results["internal_links"])
        results["technologies"] = list(results["technologies"])
        results["javascript_files"] = list(results["javascript_files"])
        results["css_files"] = list(results["css_files"])
        results["images"] = list(results["images"])
        results["documents"] = list(results["documents"])
        
        logger.info(f"Crawl complete: {results['pages_crawled']} pages, "
                   f"{len(results['emails'])} emails found")
        
        return results
    
    def _crawl_recursive(self, url: str, base_domain: str, depth: int, results: Dict[str, Any]):
        """Recursively crawl pages"""
        
        # Stop conditions
        if depth > self.max_depth:
            return
        if results["pages_crawled"] >= self.max_pages:
            return
        if url in self.visited_urls:
            return
        
        # Mark as visited
        self.visited_urls.add(url)
        results["pages_crawled"] += 1
        
        try:
            # Apply evasion techniques
            self._rotate_headers(url)
            self._apply_timing_evasion()
            
            # Make request
            logger.debug(f"Crawling: {url} (depth: {depth})")
            response = self.session.get(url, timeout=self.timeout, allow_redirects=EvasiveCrawlerConfig.FOLLOW_REDIRECTS)
            
            if response.status_code != 200:
                logger.warning(f"Non-200 status code {response.status_code} for {url}")
                return
            logger.debug(f"Crawling: {url} (depth: {depth})")
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            if response.status_code != 200:
                return
            
            # Only process HTML
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract information
            self._extract_emails(response.text, results)
            self._extract_phone_numbers(response.text, results)
            self._extract_social_media(soup, results)
            self._extract_links(soup, url, base_domain, results)
            self._extract_forms(soup, url, results)
            self._extract_technologies(response, soup, results)
            self._extract_metadata(soup, results)
            self._extract_comments(soup, results)
            self._extract_resources(soup, url, results)
            self._detect_vulnerabilities(soup, url, results)
            
            # Crawl internal links
            for link in list(results["internal_links"]):
                if link not in self.visited_urls:
                    self._crawl_recursive(link, base_domain, depth + 1, results)
                    time.sleep(0.5)  # Be polite
        
        except requests.RequestException as e:
            logger.warning(f"Failed to crawl {url}: {e}")
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
    
    def _extract_emails(self, text: str, results: Dict[str, Any]):
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, text)
        for email in emails:
            # Filter out common false positives
            if not any(x in email.lower() for x in ['example.com', 'test.com', 'yoursite.com']):
                results["emails"].add(email.lower())
    
    def _extract_phone_numbers(self, text: str, results: Dict[str, Any]):
        """Extract phone numbers"""
        # Common phone patterns
        patterns = [
            r'\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',  # US format
            r'\+?\d{1,3}[\s.-]?\(?\d{2,3}\)?[\s.-]?\d{3,4}[\s.-]?\d{4}',  # International
        ]
        
        for pattern in patterns:
            numbers = re.findall(pattern, text)
            results["phone_numbers"].update(numbers)
    
    def _extract_social_media(self, soup: BeautifulSoup, results: Dict[str, Any]):
        """Extract social media links"""
        social_platforms = {
            'facebook': r'facebook\.com',
            'twitter': r'twitter\.com|x\.com',
            'linkedin': r'linkedin\.com',
            'instagram': r'instagram\.com',
            'youtube': r'youtube\.com',
            'github': r'github\.com',
            'tiktok': r'tiktok\.com'
        }
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            for platform, pattern in social_platforms.items():
                if re.search(pattern, href, re.I):
                    results["social_media"][platform].add(href)
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str, base_domain: str, 
                      results: Dict[str, Any]):
        """Extract and categorize links"""
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(current_url, href)
            parsed = urlparse(absolute_url)
            
            # Skip non-http(s) links
            if parsed.scheme not in ['http', 'https']:
                continue
            
            # Categorize link
            if parsed.netloc == base_domain:
                results["internal_links"].add(absolute_url)
            elif base_domain in parsed.netloc:
                results["subdomains"].add(parsed.netloc)
                results["internal_links"].add(absolute_url)
            else:
                results["external_links"].add(absolute_url)
    
    def _extract_forms(self, soup: BeautifulSoup, url: str, results: Dict[str, Any]):
        """Extract forms and their details"""
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                "url": url,
                "action": form.get('action', ''),
                "method": form.get('method', 'get').upper(),
                "inputs": [],
                "has_file_upload": False,
                "has_password": False
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                
                form_data["inputs"].append({
                    "name": input_name,
                    "type": input_type
                })
                
                if input_type == 'file':
                    form_data["has_file_upload"] = True
                if input_type == 'password':
                    form_data["has_password"] = True
            
            results["forms"].append(form_data)
    
    def _extract_technologies(self, response: requests.Response, soup: BeautifulSoup, 
                            results: Dict[str, Any]):
        """Detect technologies used"""
        
        # Check headers
        headers = response.headers
        
        if 'Server' in headers:
            results["technologies"].add(f"Server: {headers['Server']}")
        
        if 'X-Powered-By' in headers:
            results["technologies"].add(f"Powered-By: {headers['X-Powered-By']}")
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                results["technologies"].add(f"Generator: {meta.get('content', '')}")
        
        # Check for common frameworks/CMS
        html = str(soup)
        
        frameworks = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'sites/all'],
            'React': ['react', 'react-dom'],
            'Angular': ['ng-app', 'angular'],
            'Vue.js': ['vue', 'v-bind'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }
        
        for framework, indicators in frameworks.items():
            if any(indicator in html.lower() for indicator in indicators):
                results["technologies"].add(framework)
    
    def _extract_metadata(self, soup: BeautifulSoup, results: Dict[str, Any]):
        """Extract metadata"""
        
        # Title
        title = soup.find('title')
        if title:
            results["metadata"]["title"] = title.string
        
        # Meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                results["metadata"][name] = content
    
    def _extract_comments(self, soup: BeautifulSoup, results: Dict[str, Any]):
        """Extract HTML comments"""
        from bs4 import Comment
        
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        
        for comment in comments:
            comment_text = str(comment).strip()
            if len(comment_text) > 10:  # Filter out empty/short comments
                results["comments"].append(comment_text)
    
    def _extract_resources(self, soup: BeautifulSoup, current_url: str, results: Dict[str, Any]):
        """Extract JavaScript, CSS, images, and documents"""
        
        # JavaScript files
        for script in soup.find_all('script', src=True):
            js_url = urljoin(current_url, script['src'])
            results["javascript_files"].add(js_url)
        
        # CSS files
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                css_url = urljoin(current_url, link['href'])
                results["css_files"].add(css_url)
        
        # Images
        for img in soup.find_all('img', src=True):
            img_url = urljoin(current_url, img['src'])
            results["images"].add(img_url)
        
        # Documents
        document_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar']
        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if any(href.endswith(ext) for ext in document_extensions):
                doc_url = urljoin(current_url, link['href'])
                results["documents"].add(doc_url)
    
    def _detect_vulnerabilities(self, soup: BeautifulSoup, url: str, results: Dict[str, Any]):
        """Detect potential vulnerabilities"""
        
        # Check for forms without CSRF protection
        for form in soup.find_all('form'):
            has_csrf = any(
                input_tag.get('name', '').lower() in ['csrf', 'token', '_token', 'csrf_token']
                for input_tag in form.find_all('input')
            )
            
            if not has_csrf and form.get('method', 'get').upper() == 'POST':
                results["potential_vulnerabilities"].append({
                    "type": "Missing CSRF Token",
                    "url": url,
                    "severity": "Medium",
                    "description": "Form appears to lack CSRF protection"
                })
        
        # Check for HTTP forms on HTTPS pages
        if urlparse(url).scheme == 'https':
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action.startswith('http://'):
                    results["potential_vulnerabilities"].append({
                        "type": "Mixed Content",
                        "url": url,
                        "severity": "Medium",
                        "description": "HTTPS page with HTTP form action"
                    })
        
        # Check for potential XSS in comments
        for comment in soup.find_all(string=lambda text: isinstance(text, str)):
            if '<script' in str(comment).lower() or 'javascript:' in str(comment).lower():
                results["potential_vulnerabilities"].append({
                    "type": "Potential XSS in Comments",
                    "url": url,
                    "severity": "Low",
                    "description": "JavaScript code found in HTML comments"
                })
        
        # Check for exposed directories
        common_exposures = ['/admin', '/backup', '/.git', '/.env', '/config']
        for exposure in common_exposures:
            if exposure in url.lower():
                results["potential_vulnerabilities"].append({
                    "type": "Exposed Directory",
                    "url": url,
                    "severity": "High",
                    "description": f"Potentially exposed directory: {exposure}"
                })


class InformationGatherer:
    """
    Combines web crawler with additional information gathering techniques
    """
    
    def __init__(self, max_depth: int = 3, max_pages: int = 50):
        self.crawler = WebCrawler(max_depth, max_pages)
    
    def gather_information(self, target_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive information gathering on target
        
        Args:
            target_url: Website URL to analyze
        
        Returns:
            Dictionary containing all gathered information
        """
        logger.info(f"Starting information gathering for {target_url}")
        
        # Crawl website
        crawl_results = self.crawler.crawl(target_url)
        
        # Additional analysis
        analysis = {
            "summary": self._generate_summary(crawl_results),
            "security_issues": self._analyze_security(crawl_results),
            "attack_surface": self._analyze_attack_surface(crawl_results),
            "osint_targets": self._identify_osint_targets(crawl_results)
        }
        
        crawl_results["analysis"] = analysis
        
        return crawl_results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of findings"""
        return {
            "total_pages": results["pages_crawled"],
            "total_emails": len(results["emails"]),
            "total_forms": len(results["forms"]),
            "total_vulnerabilities": len(results["potential_vulnerabilities"]),
            "technologies_detected": len(results["technologies"]),
            "external_domains": len(results["external_links"])
        }
    
    def _analyze_security(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security posture"""
        security = {
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "informational": []
        }
        
        # Categorize vulnerabilities by severity
        for vuln in results["potential_vulnerabilities"]:
            severity = vuln.get("severity", "Low")
            if severity == "High":
                security["high_risk"].append(vuln)
            elif severity == "Medium":
                security["medium_risk"].append(vuln)
            else:
                security["low_risk"].append(vuln)
        
        # Additional checks
        if results["emails"]:
            security["informational"].append({
                "type": "Email Exposure",
                "description": f"Found {len(results['emails'])} email addresses on website"
            })
        
        if results["comments"]:
            security["informational"].append({
                "type": "HTML Comments",
                "description": f"Found {len(results['comments'])} HTML comments (may contain sensitive info)"
            })
        
        return security
    
    def _analyze_attack_surface(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack surface"""
        return {
            "entry_points": len(results["forms"]),
            "file_uploads": sum(1 for form in results["forms"] if form.get("has_file_upload")),
            "login_forms": sum(1 for form in results["forms"] if form.get("has_password")),
            "javascript_files": len(results["javascript_files"]),
            "subdomains_found": len(results["subdomains"]),
            "external_dependencies": len(results["external_links"])
        }
    
    def _identify_osint_targets(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Identify targets for OSINT investigation"""
        return {
            "emails_for_breach_check": results["emails"],
            "domains_for_investigation": list(results["subdomains"]),
            "social_media_profiles": results["social_media"],
            "technologies_for_cve_search": list(results["technologies"])
        }
