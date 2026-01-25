"""
XSS (Cross-Site Scripting) Vulnerability Scanner
Detects reflected, stored, and DOM-based XSS vulnerabilities
"""
import re
import requests
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from bs4 import BeautifulSoup
import time


class XSSScanner:
    """XSS vulnerability scanner"""
    
    # Common XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "\"onmouseover=alert('XSS')>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
    ]
    
    # Encoded variants
    ENCODED_PAYLOADS = [
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    ]
    
    # Detection patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?alert.*?</script>",
        r"<img[^>]*onerror\s*=",
        r"<svg[^>]*onload\s*=",
        r"javascript:\s*alert",
        r"on\w+\s*=\s*['\"]?\s*alert",
    ]
    
    def __init__(self, timeout: int = 10, max_payloads: int = 10):
        self.timeout = timeout
        self.max_payloads = max_payloads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_url(self, url: str, crawl: bool = False) -> Dict[str, Any]:
        """
        Scan URL for XSS vulnerabilities
        
        Args:
            url: Target URL to scan
            crawl: Whether to crawl and test discovered forms
            
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting XSS scan on {url}")
        
        results = {
            "target": url,
            "vulnerabilities": [],
            "tested_parameters": 0,
            "forms_tested": 0,
            "urls_tested": 0,
            "payloads_tested": 0
        }
        
        try:
            # Test URL parameters
            self._test_url_parameters(url, results)
            
            # Test forms if crawling enabled
            if crawl:
                self._test_forms(url, results)
            
        except Exception as e:
            logger.error(f"XSS scan error: {e}")
            results['error'] = str(e)
        
        logger.info(f"XSS scan complete - Found {len(results['vulnerabilities'])} vulnerabilities")
        
        return results
    
    def _test_url_parameters(self, url: str, results: Dict[str, Any]) -> None:
        """Test URL parameters for XSS"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param_name in params.keys():
            logger.debug(f"Testing parameter: {param_name}")
            results['tested_parameters'] += 1
            
            # Test with various payloads
            for i, payload in enumerate(self.XSS_PAYLOADS[:self.max_payloads]):
                results['payloads_tested'] += 1
                
                # Build test URL
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{base_url}?{urllib.parse.urlencode(test_params, doseq=True)}"
                
                # Send request
                try:
                    response = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                    
                    # Check if payload is reflected
                    if self._is_vulnerable(payload, response.text):
                        vuln = {
                            'vuln_id': f'XSS-URL-{len(results["vulnerabilities"]) + 1}',
                            'title': f'Reflected XSS in URL parameter: {param_name}',
                            'severity': 'high',
                            'description': f'The parameter "{param_name}" is vulnerable to reflected XSS. '
                                         f'User input is reflected in the response without proper sanitization.',
                            'affected_target': url,
                            'affected_service': 'web',
                            'exploit_available': True,
                            'tool_source': 'xss_scanner',
                            'confidence': 0.9,
                            'evidence': [
                                f'Parameter: {param_name}',
                                f'Payload: {payload}',
                                f'Test URL: {test_url}',
                                f'Response contains unescaped payload'
                            ],
                            'remediation': 'Implement proper input validation and output encoding. '
                                          'Use context-aware output encoding (HTML entity encoding for HTML context, '
                                          'JavaScript encoding for JavaScript context, etc.). '
                                          'Consider using Content Security Policy (CSP) headers.'
                        }
                        
                        results['vulnerabilities'].append(vuln)
                        logger.warning(f"XSS vulnerability found in parameter: {param_name}")
                        break  # Found vulnerability, no need to test more payloads
                    
                    # Rate limiting
                    time.sleep(0.1)
                    
                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue
        
        results['urls_tested'] += 1
    
    def _test_forms(self, url: str, results: Dict[str, Any]) -> None:
        """Discover and test forms for XSS"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                results['forms_tested'] += 1
                self._test_form(url, form, results)
                
        except Exception as e:
            logger.debug(f"Form testing error: {e}")
    
    def _test_form(self, base_url: str, form, results: Dict[str, Any]) -> None:
        """Test individual form for XSS"""
        try:
            # Get form details
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Build form URL
            if action.startswith('http'):
                form_url = action
            elif action.startswith('/'):
                parsed = urllib.parse.urlparse(base_url)
                form_url = f"{parsed.scheme}://{parsed.netloc}{action}"
            else:
                form_url = urllib.parse.urljoin(base_url, action)
            
            # Get form inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            
            for input_field in inputs:
                name = input_field.get('name')
                if not name:
                    continue
                
                input_type = input_field.get('type', 'text').lower()
                
                # Skip submit buttons, etc.
                if input_type in ['submit', 'button', 'image', 'reset']:
                    continue
                
                # Default value
                form_data[name] = input_field.get('value', 'test')
            
            # Test each input field
            for field_name in form_data.keys():
                results['tested_parameters'] += 1
                
                for payload in self.XSS_PAYLOADS[:self.max_payloads]:
                    results['payloads_tested'] += 1
                    
                    # Inject payload
                    test_data = form_data.copy()
                    test_data[field_name] = payload
                    
                    # Send request
                    try:
                        if method == 'post':
                            response = self.session.post(form_url, data=test_data, timeout=self.timeout)
                        else:
                            response = self.session.get(form_url, params=test_data, timeout=self.timeout)
                        
                        # Check for vulnerability
                        if self._is_vulnerable(payload, response.text):
                            vuln = {
                                'vuln_id': f'XSS-FORM-{len(results["vulnerabilities"]) + 1}',
                                'title': f'XSS in form field: {field_name}',
                                'severity': 'high',
                                'description': f'The form field "{field_name}" is vulnerable to XSS. '
                                             f'User input is not properly sanitized.',
                                'affected_target': base_url,
                                'affected_service': 'web',
                                'exploit_available': True,
                                'tool_source': 'xss_scanner',
                                'confidence': 0.9,
                                'evidence': [
                                    f'Form URL: {form_url}',
                                    f'Method: {method.upper()}',
                                    f'Field: {field_name}',
                                    f'Payload: {payload}'
                                ],
                                'remediation': 'Implement input validation and output encoding. '
                                              'Use parameterized queries and avoid directly inserting user input into HTML.'
                            }
                            
                            results['vulnerabilities'].append(vuln)
                            logger.warning(f"XSS vulnerability found in form field: {field_name}")
                            break
                        
                        time.sleep(0.1)
                        
                    except requests.RequestException as e:
                        logger.debug(f"Form test request failed: {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"Form parsing error: {e}")
    
    def _is_vulnerable(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected without proper encoding"""
        # Check for exact payload match (unescaped)
        if payload in response_text:
            return True
        
        # Check for partial matches using regex patterns
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def is_available(self) -> bool:
        """Check if scanner is available (always true for Python-based scanner)"""
        return True
