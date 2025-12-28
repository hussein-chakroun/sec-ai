"""
Logic Flaw Detector
Detects business logic and application logic vulnerabilities
"""

import logging
from typing import Dict, List, Any
import re

logger = logging.getLogger(__name__)


class LogicFlawDetector:
    """
    Detects logic flaws in application code
    Focuses on business logic vulnerabilities
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.patterns = self._load_logic_patterns()
        
    async def detect_flaws(self, code: str, language: str, 
                          context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Detect logic flaws in code
        
        Args:
            code: Source code
            language: Programming language
            context: Additional context
            
        Returns:
            Detected logic flaws
        """
        logger.info(f"Detecting logic flaws in {language} code")
        
        flaws = []
        
        # Pattern-based detection
        pattern_flaws = self._pattern_based_detection(code, language)
        flaws.extend(pattern_flaws)
        
        # LLM-based detection if available
        if self.llm_client:
            llm_flaws = await self._llm_based_detection(code, language, context)
            flaws.extend(llm_flaws)
        
        logger.info(f"Found {len(flaws)} logic flaws")
        
        return flaws
    
    def _pattern_based_detection(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Pattern-based logic flaw detection"""
        
        flaws = []
        patterns = self.patterns.get(language, {})
        
        for flaw_type, pattern_info in patterns.items():
            matches = re.finditer(pattern_info['regex'], code, re.MULTILINE)
            
            for match in matches:
                flaws.append({
                    'type': flaw_type,
                    'severity': pattern_info['severity'],
                    'line': code[:match.start()].count('\n') + 1,
                    'code': match.group(),
                    'description': pattern_info['description']
                })
        
        return flaws
    
    async def _llm_based_detection(self, code: str, language: str,
                                   context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """LLM-based logic flaw detection"""
        
        prompt = f"""
Analyze this {language} code for logic flaws and business logic vulnerabilities:

```{language}
{code}
```

Look for:
1. Authentication/Authorization bypasses
2. Price/quantity manipulation vulnerabilities
3. Race conditions in critical operations
4. Missing input validation allowing business logic bypass
5. Incorrect state transitions
6. Time-of-check/time-of-use (TOCTOU) issues
7. Logic errors in conditionals
8. Missing or incorrect access controls

Provide specific findings with line numbers and severity.
"""
        
        try:
            response = await self.llm_client.generate(prompt)
            flaws = self._parse_llm_findings(response)
            return flaws
        except Exception as e:
            logger.warning(f"LLM detection failed: {e}")
            return []
    
    def _parse_llm_findings(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response for logic flaws"""
        
        flaws = []
        
        # Parse structured response
        for line in response.split('\n'):
            if line.strip().startswith('-'):
                flaws.append({
                    'type': 'logic_flaw',
                    'severity': 'medium',
                    'description': line.strip()[1:].strip()
                })
        
        return flaws
    
    def _load_logic_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load logic flaw patterns"""
        
        return {
            'python': {
                'price_manipulation': {
                    'regex': r'price\s*=\s*request\.(GET|POST|args|form)\[',
                    'severity': 'high',
                    'description': 'Price taken directly from user input without validation'
                },
                'auth_bypass': {
                    'regex': r'if\s+.*user.*==\s*["\']admin["\']',
                    'severity': 'high',
                    'description': 'Simple string comparison for admin check - bypassable'
                },
                'missing_auth_check': {
                    'regex': r'@app\.route.*\n(?!.*@login_required)def ',
                    'severity': 'medium',
                    'description': 'Route without authentication decorator'
                },
                'toctou': {
                    'regex': r'os\.path\.exists\([^)]+\)[^{]*open\(',
                    'severity': 'medium',
                    'description': 'TOCTOU: checking file exists before opening'
                },
                'weak_random': {
                    'regex': r'random\.(randint|choice|random)',
                    'severity': 'medium',
                    'description': 'Using weak random for security-sensitive operation'
                }
            },
            'javascript': {
                'client_side_auth': {
                    'regex': r'if\s*\(\s*isAdmin\s*\)',
                    'severity': 'high',
                    'description': 'Client-side authorization check - easily bypassed'
                },
                'price_manipulation': {
                    'regex': r'(price|amount|total)\s*=\s*req\.(body|query)\.',
                    'severity': 'high',
                    'description': 'Price/amount from request without server-side validation'
                },
                'jwt_weak': {
                    'regex': r'jwt\.sign\([^,]+,\s*["\'][^"\']{1,8}["\']',
                    'severity': 'high',
                    'description': 'JWT signed with weak secret key'
                },
                'mass_assignment': {
                    'regex': r'User\.create\(req\.body\)',
                    'severity': 'high',
                    'description': 'Mass assignment vulnerability - user controls all fields'
                }
            },
            'java': {
                'auth_bypass': {
                    'regex': r'if\s*\(\s*user\.getRole\(\)\.equals\(["\']admin["\']\)',
                    'severity': 'high',
                    'description': 'Simple role check - may be bypassable'
                },
                'missing_access_control': {
                    'regex': r'@RequestMapping.*\n(?!.*@PreAuthorize).*public ',
                    'severity': 'medium',
                    'description': 'Endpoint without access control annotation'
                },
                'race_condition': {
                    'regex': r'if\s*\([^)]*balance[^)]*\)[^{]*balance\s*[-+]=',
                    'severity': 'high',
                    'description': 'Race condition in balance check and update'
                }
            }
        }
    
    def check_state_machine(self, code: str, states: List[str], 
                           transitions: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Check state machine implementation for logic errors
        
        Args:
            code: State machine code
            states: Valid states
            transitions: Valid state transitions
            
        Returns:
            State machine violations
        """
        logger.info("Checking state machine logic")
        
        violations = []
        
        # Look for direct state assignments that bypass validation
        for line_num, line in enumerate(code.split('\n'), 1):
            if re.search(r'state\s*=\s*["\']?\w+["\']?', line):
                # Check if this is in a validation function
                if 'def ' not in line and 'function ' not in line:
                    violations.append({
                        'type': 'invalid_state_transition',
                        'line': line_num,
                        'description': 'Direct state assignment bypassing transition logic',
                        'severity': 'high'
                    })
        
        return violations
