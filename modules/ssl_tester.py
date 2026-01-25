"""
SSL/TLS Security Tester
Tests SSL/TLS configurations for vulnerabilities and weak cipher suites
"""
import ssl
import socket
from typing import Dict, Any, List, Optional
from loguru import logger
import urllib.parse
from datetime import datetime


class SSLTester:
    """SSL/TLS security configuration tester"""
    
    # Weak/insecure protocol versions
    WEAK_PROTOCOLS = {
        'SSLv2': ssl.PROTOCOL_SSLv23,  # SSLv2 is deprecated
        'SSLv3': ssl.PROTOCOL_SSLv23,  # SSLv3 is vulnerable (POODLE)
        'TLSv1.0': ssl.PROTOCOL_TLSv1,  # TLS 1.0 is deprecated
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,  # TLS 1.1 is deprecated
    }
    
    # Secure protocol versions
    SECURE_PROTOCOLS = {
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        'TLSv1.3': ssl.PROTOCOL_TLS,  # TLS 1.3 (most secure)
    }
    
    # Known weak cipher suites (partial list)
    WEAK_CIPHERS = [
        'NULL', 'aNULL', 'eNULL',  # No encryption
        'EXPORT', 'EXP',  # Export-grade (weak)
        'DES', 'MD5',  # Weak algorithms
        'RC4',  # Broken
        'ADH', 'AECDH',  # Anonymous (no authentication)
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def test_url(self, url: str) -> Dict[str, Any]:
        """
        Test SSL/TLS configuration for a URL
        
        Args:
            url: Target URL (https://example.com)
            
        Returns:
            Dictionary with test results and vulnerabilities
        """
        logger.info(f"Starting SSL/TLS test on {url}")
        
        results = {
            "target": url,
            "vulnerabilities": [],
            "certificate_info": {},
            "protocol_support": {},
            "cipher_suites": [],
            "security_score": 100,  # Start with perfect score, deduct for issues
            "issues": []
        }
        
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        if not hostname:
            results['error'] = "Invalid URL"
            return results
        
        try:
            # Test certificate
            self._test_certificate(hostname, port, results)
            
            # Test protocol versions
            self._test_protocols(hostname, port, results)
            
            # Test cipher suites
            self._test_ciphers(hostname, port, results)
            
            # Generate vulnerability findings
            self._generate_vulnerabilities(results)
            
        except Exception as e:
            logger.error(f"SSL/TLS test error: {e}")
            results['error'] = str(e)
        
        logger.info(f"SSL/TLS test complete - Security score: {results['security_score']}/100")
        
        return results
    
    def _test_certificate(self, hostname: str, port: int, results: Dict[str, Any]) -> None:
        """Test SSL certificate"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    results['certificate_info'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        results['issues'].append('Certificate has expired')
                        results['security_score'] -= 50
                    elif days_until_expiry < 30:
                        results['issues'].append(f'Certificate expires soon ({days_until_expiry} days)')
                        results['security_score'] -= 10
                    
                    results['certificate_info']['days_until_expiry'] = days_until_expiry
                    
        except ssl.SSLError as e:
            logger.warning(f"SSL certificate error: {e}")
            results['issues'].append(f'Certificate error: {str(e)}')
            results['security_score'] -= 30
        except Exception as e:
            logger.debug(f"Certificate test error: {e}")
    
    def _test_protocols(self, hostname: str, port: int, results: Dict[str, Any]) -> None:
        """Test supported SSL/TLS protocol versions"""
        logger.debug("Testing protocol versions...")
        
        # Test weak protocols
        for proto_name, proto_const in self.WEAK_PROTOCOLS.items():
            try:
                supported = self._test_protocol(hostname, port, proto_const)
                results['protocol_support'][proto_name] = supported
                
                if supported:
                    results['issues'].append(f'Weak protocol supported: {proto_name}')
                    
                    # Severe vulnerabilities for SSLv2/SSLv3
                    if proto_name in ['SSLv2', 'SSLv3']:
                        results['security_score'] -= 40
                    else:
                        results['security_score'] -= 20
                        
            except Exception:
                results['protocol_support'][proto_name] = False
        
        # Test secure protocols
        for proto_name, proto_const in self.SECURE_PROTOCOLS.items():
            try:
                supported = self._test_protocol(hostname, port, proto_const)
                results['protocol_support'][proto_name] = supported
                
                if not supported and proto_name == 'TLSv1.2':
                    results['issues'].append('TLS 1.2 not supported')
                    results['security_score'] -= 15
                    
            except Exception:
                results['protocol_support'][proto_name] = False
    
    def _test_protocol(self, hostname: str, port: int, protocol) -> bool:
        """Test if a specific protocol version is supported"""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
                    
        except (ssl.SSLError, socket.error, OSError):
            return False
    
    def _test_ciphers(self, hostname: str, port: int, results: Dict[str, Any]) -> None:
        """Test cipher suites"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        results['cipher_suites'].append({
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        })
                        
                        # Check for weak ciphers
                        cipher_name = cipher[0]
                        for weak_cipher in self.WEAK_CIPHERS:
                            if weak_cipher in cipher_name:
                                results['issues'].append(f'Weak cipher in use: {cipher_name}')
                                results['security_score'] -= 25
                                break
                        
                        # Check for low bit encryption
                        if cipher[2] < 128:
                            results['issues'].append(f'Low encryption strength: {cipher[2]} bits')
                            results['security_score'] -= 20
                            
        except Exception as e:
            logger.debug(f"Cipher test error: {e}")
    
    def _generate_vulnerabilities(self, results: Dict[str, Any]) -> None:
        """Generate vulnerability findings from test results"""
        # SSL/TLS protocol vulnerabilities
        for proto, supported in results['protocol_support'].items():
            if supported and proto in self.WEAK_PROTOCOLS:
                severity = 'critical' if proto in ['SSLv2', 'SSLv3'] else 'high'
                
                vuln = {
                    'vuln_id': f'SSL-PROTO-{proto}',
                    'title': f'Insecure SSL/TLS Protocol Supported: {proto}',
                    'severity': severity,
                    'cvss_score': 7.5 if severity == 'critical' else 5.9,
                    'description': f'The server supports the deprecated and insecure {proto} protocol, '
                                 f'which is vulnerable to various attacks.',
                    'affected_target': results['target'],
                    'affected_service': 'HTTPS',
                    'tool_source': 'ssl_tester',
                    'confidence': 1.0,
                    'evidence': [f'Protocol {proto} is enabled and accepting connections'],
                    'remediation': f'Disable {proto} support. Configure the server to only allow TLS 1.2 and TLS 1.3.'
                }
                
                # Add CVE references for known vulnerabilities
                if proto == 'SSLv3':
                    vuln['vuln_id'] = 'CVE-2014-3566'  # POODLE
                    vuln['exploit_available'] = True
                    vuln['exploit_references'] = ['https://www.openssl.org/~bodo/ssl-poodle.pdf']
                
                results['vulnerabilities'].append(vuln)
        
        # Certificate issues
        if 'Certificate has expired' in results['issues']:
            results['vulnerabilities'].append({
                'vuln_id': 'SSL-CERT-EXPIRED',
                'title': 'SSL Certificate Has Expired',
                'severity': 'high',
                'cvss_score': 7.4,
                'description': 'The SSL/TLS certificate has expired, which will cause browser warnings '
                             'and may prevent users from accessing the site.',
                'affected_target': results['target'],
                'affected_service': 'HTTPS',
                'tool_source': 'ssl_tester',
                'confidence': 1.0,
                'evidence': results['issues'],
                'remediation': 'Renew the SSL certificate immediately.'
            })
        
        # Weak ciphers
        weak_cipher_issues = [issue for issue in results['issues'] if 'Weak cipher' in issue]
        if weak_cipher_issues:
            results['vulnerabilities'].append({
                'vuln_id': 'SSL-WEAK-CIPHER',
                'title': 'Weak Cipher Suites Enabled',
                'severity': 'medium',
                'cvss_score': 5.3,
                'description': 'The server supports weak cipher suites that may be vulnerable to attacks.',
                'affected_target': results['target'],
                'affected_service': 'HTTPS',
                'tool_source': 'ssl_tester',
                'confidence': 0.9,
                'evidence': weak_cipher_issues,
                'remediation': 'Disable weak cipher suites. Use only modern, secure ciphers with forward secrecy.'
            })
    
    def is_available(self) -> bool:
        """Check if SSL tester is available (always true for built-in Python ssl module)"""
        return True
