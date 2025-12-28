"""
Deserialization Vulnerability Scanner
Detects insecure deserialization patterns
"""

import logging
from typing import Dict, List, Any
import re

logger = logging.getLogger(__name__)


class DeserializationScanner:
    """
    Scans for insecure deserialization vulnerabilities
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.patterns = self._load_patterns()
        
    async def scan(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Scan for deserialization vulnerabilities
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Detected vulnerabilities
        """
        logger.info(f"Scanning for deserialization vulnerabilities in {language}")
        
        vulnerabilities = []
        
        # Pattern-based detection
        vulnerabilities.extend(self._pattern_scan(code, language))
        
        # Check for unsafe configurations
        vulnerabilities.extend(self._check_configurations(code, language))
        
        # Check for user-controlled input to deserialization
        vulnerabilities.extend(self._check_user_input(code, language))
        
        logger.info(f"Found {len(vulnerabilities)} deserialization issues")
        
        return vulnerabilities
    
    def _pattern_scan(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Pattern-based scanning"""
        
        vulnerabilities = []
        patterns = self.patterns.get(language, [])
        
        for pattern_info in patterns:
            matches = re.finditer(pattern_info['regex'], code)
            
            for match in matches:
                vulnerabilities.append({
                    'type': 'insecure_deserialization',
                    'function': pattern_info['function'],
                    'severity': pattern_info['severity'],
                    'line': code[:match.start()].count('\n') + 1,
                    'code': match.group()[:100],
                    'description': pattern_info['description'],
                    'remediation': pattern_info['remediation']
                })
        
        return vulnerabilities
    
    def _check_configurations(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for unsafe deserialization configurations"""
        
        vulnerabilities = []
        
        if language == 'java':
            # Check for ObjectInputStream without validation
            if 'ObjectInputStream' in code:
                # Check if readObject is overridden with validation
                if 'readObject' in code:
                    # Look for validation in custom readObject
                    if not re.search(r'if\s*\([^)]*instanceof[^)]*\)', code):
                        vulnerabilities.append({
                            'type': 'missing_validation',
                            'severity': 'high',
                            'description': 'ObjectInputStream without type validation in readObject',
                            'remediation': 'Implement type checking in custom readObject method'
                        })
                else:
                    vulnerabilities.append({
                        'type': 'unsafe_deserialization',
                        'severity': 'critical',
                        'description': 'ObjectInputStream used without custom readObject validation',
                        'remediation': 'Implement look-ahead deserialization or use safe alternatives'
                    })
        
        elif language == 'python':
            # Check for pickle without restrictions
            if 'pickle.loads' in code or 'pickle.load' in code:
                # Check if Unpickler is restricted
                if 'Unpickler' not in code:
                    vulnerabilities.append({
                        'type': 'unrestricted_pickle',
                        'severity': 'critical',
                        'description': 'Pickle deserialization without Unpickler restrictions',
                        'remediation': 'Use restricted Unpickler or switch to JSON'
                    })
        
        elif language == 'php':
            # unserialize() without validation
            if 'unserialize(' in code:
                # Check for allowed_classes option (PHP 7+)
                if not re.search(r'unserialize\([^,]+,\s*\[', code):
                    vulnerabilities.append({
                        'type': 'unrestricted_unserialize',
                        'severity': 'critical',
                        'description': 'unserialize() without allowed_classes restriction',
                        'remediation': 'Use allowed_classes option or JSON instead'
                    })
        
        return vulnerabilities
    
    def _check_user_input(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check if user input flows to deserialization"""
        
        vulnerabilities = []
        
        # Common user input sources
        input_sources = {
            'python': ['request.GET', 'request.POST', 'request.data', 'request.json', 'input('],
            'java': ['request.getParameter', 'request.getInputStream', '@RequestBody'],
            'javascript': ['req.body', 'req.query', 'req.params'],
            'php': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']
        }
        
        # Deserialization functions
        deser_functions = {
            'python': ['pickle.loads', 'pickle.load', 'yaml.load', 'marshal.loads'],
            'java': ['readObject(', 'readUnshared('],
            'javascript': ['JSON.parse', 'deserialize'],
            'php': ['unserialize(']
        }
        
        sources = input_sources.get(language, [])
        functions = deser_functions.get(language, [])
        
        for source in sources:
            for func in functions:
                # Check if input source is used with deserialization function
                # This is a simple check - could be more sophisticated with data flow analysis
                source_pos = code.find(source)
                func_pos = code.find(func)
                
                if source_pos != -1 and func_pos != -1:
                    # Check if they're reasonably close (same function/block)
                    if abs(source_pos - func_pos) < 1000:  # Within 1000 chars
                        vulnerabilities.append({
                            'type': 'user_input_deserialization',
                            'severity': 'critical',
                            'source': source,
                            'function': func,
                            'description': f'User input from {source} may flow to {func}',
                            'remediation': 'Validate and sanitize input, use safe formats like JSON'
                        })
        
        return vulnerabilities
    
    def _load_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load deserialization vulnerability patterns"""
        
        return {
            'python': [
                {
                    'function': 'pickle.loads',
                    'regex': r'pickle\.loads?\s*\(',
                    'severity': 'critical',
                    'description': 'Pickle deserialization can execute arbitrary code',
                    'remediation': 'Use JSON or implement restricted Unpickler'
                },
                {
                    'function': 'yaml.load',
                    'regex': r'yaml\.load\s*\([^,)]+\)',  # Without Loader argument
                    'severity': 'critical',
                    'description': 'yaml.load() without Loader is unsafe',
                    'remediation': 'Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)'
                },
                {
                    'function': 'marshal.loads',
                    'regex': r'marshal\.loads?\s*\(',
                    'severity': 'high',
                    'description': 'Marshal deserialization from untrusted data is dangerous',
                    'remediation': 'Only use marshal for trusted data'
                }
            ],
            'java': [
                {
                    'function': 'ObjectInputStream.readObject',
                    'regex': r'ObjectInputStream[^;]*readObject\s*\(\)',
                    'severity': 'critical',
                    'description': 'Java deserialization can lead to RCE',
                    'remediation': 'Implement SerialKiller or ValidatingObjectInputStream'
                },
                {
                    'function': 'XMLDecoder.readObject',
                    'regex': r'XMLDecoder[^;]*readObject\s*\(\)',
                    'severity': 'critical',
                    'description': 'XMLDecoder deserialization is unsafe',
                    'remediation': 'Use safer XML parsing methods'
                },
                {
                    'function': 'XStream',
                    'regex': r'new\s+XStream\s*\(',
                    'severity': 'high',
                    'description': 'XStream deserialization without security framework',
                    'remediation': 'Configure XStream security settings'
                }
            ],
            'javascript': [
                {
                    'function': 'node-serialize',
                    'regex': r'require\(["\']node-serialize["\']\)',
                    'severity': 'critical',
                    'description': 'node-serialize has known RCE vulnerabilities',
                    'remediation': 'Use JSON.parse() or safer alternatives'
                },
                {
                    'function': 'eval',
                    'regex': r'\beval\s*\(',
                    'severity': 'critical',
                    'description': 'eval() can execute arbitrary code',
                    'remediation': 'Never use eval() with user input'
                }
            ],
            'php': [
                {
                    'function': 'unserialize',
                    'regex': r'\bunserialize\s*\(',
                    'severity': 'critical',
                    'description': 'PHP unserialize() can lead to object injection',
                    'remediation': 'Use JSON or restrict allowed_classes'
                }
            ],
            'csharp': [
                {
                    'function': 'BinaryFormatter',
                    'regex': r'new\s+BinaryFormatter\s*\(',
                    'severity': 'critical',
                    'description': 'BinaryFormatter is inherently insecure',
                    'remediation': 'Use JSON.NET or protobuf'
                },
                {
                    'function': 'JavaScriptSerializer',
                    'regex': r'JavaScriptSerializer[^;]*Deserialize',
                    'severity': 'high',
                    'description': 'JavaScriptSerializer can be exploited',
                    'remediation': 'Use JSON.NET with proper configuration'
                }
            ]
        }
