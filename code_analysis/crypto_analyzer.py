"""
Cryptographic Weakness Analyzer
Detects weak cryptographic implementations
"""

import logging
from typing import Dict, List, Any
import re

logger = logging.getLogger(__name__)


class CryptoWeaknessAnalyzer:
    """
    Analyzes code for cryptographic weaknesses and misconfigurations
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.weak_algorithms = self._load_weak_algorithms()
        
    async def analyze(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Analyze code for cryptographic weaknesses
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Detected cryptographic weaknesses
        """
        logger.info(f"Analyzing cryptographic usage in {language} code")
        
        weaknesses = []
        
        # Detect weak algorithms
        weaknesses.extend(self._detect_weak_algorithms(code, language))
        
        # Detect weak key sizes
        weaknesses.extend(self._detect_weak_key_sizes(code, language))
        
        # Detect hardcoded keys/secrets
        weaknesses.extend(self._detect_hardcoded_secrets(code, language))
        
        # Detect insecure modes
        weaknesses.extend(self._detect_insecure_modes(code, language))
        
        # Detect weak random number generation
        weaknesses.extend(self._detect_weak_random(code, language))
        
        logger.info(f"Found {len(weaknesses)} cryptographic weaknesses")
        
        return weaknesses
    
    def _detect_weak_algorithms(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect use of weak cryptographic algorithms"""
        
        weaknesses = []
        
        for algo_type, algos in self.weak_algorithms.items():
            for algo, info in algos.items():
                patterns = info.get('patterns', {}).get(language, [])
                
                for pattern in patterns:
                    matches = re.finditer(pattern, code, re.IGNORECASE)
                    
                    for match in matches:
                        weaknesses.append({
                            'type': 'weak_algorithm',
                            'algorithm': algo,
                            'category': algo_type,
                            'severity': info['severity'],
                            'line': code[:match.start()].count('\n') + 1,
                            'code': match.group(),
                            'description': info['description'],
                            'remediation': info['remediation']
                        })
        
        return weaknesses
    
    def _detect_weak_key_sizes(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect weak key sizes"""
        
        weaknesses = []
        
        if language == 'python':
            # RSA key size
            rsa_matches = re.finditer(r'RSA\.generate\((\d+)\)', code)
            for match in rsa_matches:
                key_size = int(match.group(1))
                if key_size < 2048:
                    weaknesses.append({
                        'type': 'weak_key_size',
                        'algorithm': 'RSA',
                        'key_size': key_size,
                        'severity': 'high',
                        'line': code[:match.start()].count('\n') + 1,
                        'description': f'RSA key size {key_size} bits is insufficient (minimum 2048)',
                        'remediation': 'Use at least 2048-bit RSA keys'
                    })
            
            # AES key size
            aes_matches = re.finditer(r'AES\.new\([^,]+,\s*AES\.\w+,?\s*([^)]*)\)', code)
            for match in aes_matches:
                # Check if key is explicitly small
                if '128' in match.group() or '64' in match.group():
                    weaknesses.append({
                        'type': 'weak_key_size',
                        'algorithm': 'AES',
                        'severity': 'medium',
                        'description': 'AES-128 is acceptable but AES-256 is recommended',
                        'remediation': 'Consider using AES-256 for better security'
                    })
        
        elif language == 'java':
            # KeyGenerator key size
            keygen_matches = re.finditer(r'keyGen\.init\((\d+)\)', code)
            for match in keygen_matches:
                key_size = int(match.group(1))
                if key_size < 128:
                    weaknesses.append({
                        'type': 'weak_key_size',
                        'key_size': key_size,
                        'severity': 'critical',
                        'description': f'Key size {key_size} bits is cryptographically weak'
                    })
        
        return weaknesses
    
    def _detect_hardcoded_secrets(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect hardcoded cryptographic keys and secrets"""
        
        weaknesses = []
        
        # Patterns for hardcoded secrets
        patterns = [
            (r'(password|passwd|pwd|secret|key)\s*=\s*["\']([^"\']{8,})["\']', 'Hardcoded password/key'),
            (r'api[_-]?key\s*=\s*["\']([^"\']+)["\']', 'Hardcoded API key'),
            (r'token\s*=\s*["\']([^"\']{20,})["\']', 'Hardcoded token'),
            (r'["\'][a-zA-Z0-9]{32,}["\']', 'Potential hardcoded secret (32+ chars)'),
        ]
        
        for pattern, description in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            
            for match in matches:
                # Skip common false positives
                matched_text = match.group()
                if any(fp in matched_text.lower() for fp in ['example', 'test', 'dummy', 'placeholder']):
                    continue
                
                weaknesses.append({
                    'type': 'hardcoded_secret',
                    'severity': 'critical',
                    'line': code[:match.start()].count('\n') + 1,
                    'description': description,
                    'remediation': 'Use environment variables or secure key management system'
                })
        
        return weaknesses
    
    def _detect_insecure_modes(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect insecure cipher modes"""
        
        weaknesses = []
        
        if language == 'python':
            # ECB mode (insecure)
            if 'AES.MODE_ECB' in code:
                weaknesses.append({
                    'type': 'insecure_mode',
                    'mode': 'ECB',
                    'severity': 'high',
                    'description': 'ECB mode is insecure - identical plaintext blocks produce identical ciphertext',
                    'remediation': 'Use CBC, GCM, or CTR mode with proper IV'
                })
            
            # CBC without IV
            cbc_matches = re.finditer(r'AES\.new\([^)]*MODE_CBC[^)]*\)', code)
            for match in matches:
                if 'iv=' not in match.group().lower():
                    weaknesses.append({
                        'type': 'missing_iv',
                        'severity': 'high',
                        'description': 'CBC mode without explicit IV',
                        'remediation': 'Always provide a random IV for CBC mode'
                    })
        
        elif language == 'java':
            # Check cipher transformations
            cipher_matches = re.finditer(r'Cipher\.getInstance\(["\']([^"\']+)["\']\)', code)
            for match in cipher_matches:
                transformation = match.group(1)
                
                if '/ECB/' in transformation:
                    weaknesses.append({
                        'type': 'insecure_mode',
                        'mode': 'ECB',
                        'severity': 'high',
                        'description': 'ECB mode is cryptographically weak'
                    })
                
                # No mode/padding specified (defaults to ECB)
                if transformation.count('/') == 0:
                    weaknesses.append({
                        'type': 'default_mode',
                        'severity': 'high',
                        'description': f'Cipher transformation "{transformation}" uses default mode (often ECB)',
                        'remediation': 'Explicitly specify mode and padding'
                    })
        
        return weaknesses
    
    def _detect_weak_random(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect weak random number generation for crypto"""
        
        weaknesses = []
        
        if language == 'python':
            # Using random module for crypto
            crypto_contexts = ['key', 'password', 'token', 'salt', 'iv', 'nonce']
            
            for context in crypto_contexts:
                pattern = f'{context}.*random\\.(randint|choice|random)'
                if re.search(pattern, code, re.IGNORECASE):
                    weaknesses.append({
                        'type': 'weak_random',
                        'severity': 'critical',
                        'context': context,
                        'description': f'Using weak random.{context} for cryptographic {context}',
                        'remediation': 'Use secrets module or os.urandom() for cryptographic randomness'
                    })
        
        elif language == 'java':
            # Using java.util.Random for crypto
            if 'new Random()' in code and any(ctx in code for ctx in ['key', 'password', 'token']):
                weaknesses.append({
                    'type': 'weak_random',
                    'severity': 'critical',
                    'description': 'Using java.util.Random for cryptographic purposes',
                    'remediation': 'Use SecureRandom instead'
                })
        
        elif language == 'javascript':
            # Using Math.random() for crypto
            if 'Math.random()' in code and any(ctx in code for ctx in ['key', 'password', 'token']):
                weaknesses.append({
                    'type': 'weak_random',
                    'severity': 'critical',
                    'description': 'Using Math.random() for security-sensitive values',
                    'remediation': 'Use crypto.randomBytes() or crypto.getRandomValues()'
                })
        
        return weaknesses
    
    def _load_weak_algorithms(self) -> Dict[str, Dict[str, Any]]:
        """Load database of weak cryptographic algorithms"""
        
        return {
            'hash': {
                'MD5': {
                    'severity': 'high',
                    'description': 'MD5 is cryptographically broken - collision attacks exist',
                    'remediation': 'Use SHA-256 or SHA-3',
                    'patterns': {
                        'python': [r'hashlib\.md5\(', r'Crypto\.Hash\.MD5'],
                        'java': [r'MessageDigest\.getInstance\(["\']MD5["\']\)'],
                        'javascript': [r'crypto\.createHash\(["\']md5["\']\)']
                    }
                },
                'SHA1': {
                    'severity': 'medium',
                    'description': 'SHA-1 is deprecated - collision attacks demonstrated',
                    'remediation': 'Use SHA-256 or SHA-3',
                    'patterns': {
                        'python': [r'hashlib\.sha1\(', r'Crypto\.Hash\.SHA1'],
                        'java': [r'MessageDigest\.getInstance\(["\']SHA-1["\']\)'],
                        'javascript': [r'crypto\.createHash\(["\']sha1["\']\)']
                    }
                }
            },
            'cipher': {
                'DES': {
                    'severity': 'critical',
                    'description': 'DES has 56-bit key - easily brute-forced',
                    'remediation': 'Use AES-256',
                    'patterns': {
                        'python': [r'Crypto\.Cipher\.DES'],
                        'java': [r'Cipher\.getInstance\(["\'][^"\']*DES[^"\']*["\']\)'],
                    }
                },
                '3DES': {
                    'severity': 'medium',
                    'description': '3DES is deprecated and slow',
                    'remediation': 'Use AES-256',
                    'patterns': {
                        'python': [r'Crypto\.Cipher\.DES3'],
                        'java': [r'Cipher\.getInstance\(["\'][^"\']*DESede[^"\']*["\']\)'],
                    }
                },
                'RC4': {
                    'severity': 'critical',
                    'description': 'RC4 has multiple known weaknesses',
                    'remediation': 'Use AES-GCM',
                    'patterns': {
                        'python': [r'Crypto\.Cipher\.ARC4'],
                        'java': [r'Cipher\.getInstance\(["\'][^"\']*RC4[^"\']*["\']\)'],
                    }
                }
            }
        }
