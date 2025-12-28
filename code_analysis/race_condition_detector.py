"""
Race Condition Detector
Detects race conditions and concurrency issues
"""

import logging
from typing import Dict, List, Any, Set
import re

logger = logging.getLogger(__name__)


class RaceConditionDetector:
    """
    Detects race conditions and TOCTOU vulnerabilities
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        
    async def detect_race_conditions(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Detect race conditions in code
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Detected race conditions
        """
        logger.info(f"Detecting race conditions in {language} code")
        
        race_conditions = []
        
        # Check-then-act patterns
        race_conditions.extend(self._find_check_then_act(code, language))
        
        # Double-checked locking
        race_conditions.extend(self._find_double_checked_locking(code, language))
        
        # Shared resource access without synchronization
        race_conditions.extend(self._find_unsynchronized_access(code, language))
        
        # TOCTOU file operations
        race_conditions.extend(self._find_toctou_file_ops(code, language))
        
        logger.info(f"Found {len(race_conditions)} potential race conditions")
        
        return race_conditions
    
    def _find_check_then_act(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find check-then-act race conditions"""
        
        race_conditions = []
        lines = code.split('\n')
        
        for i in range(len(lines) - 1):
            line = lines[i].strip()
            next_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
            
            # Look for check followed by action
            if language == 'python':
                # if balance > amount: balance -= amount
                if re.match(r'if\s+.*>\s*', line) and '-=' in next_line:
                    race_conditions.append({
                        'type': 'check_then_act',
                        'line': i + 1,
                        'severity': 'high',
                        'description': 'Check-then-act pattern without synchronization',
                        'code': f"{line}\n{next_line}"
                    })
                
                # if os.path.exists(...): open(...)
                if 'exists' in line and 'open(' in next_line:
                    race_conditions.append({
                        'type': 'toctou',
                        'line': i + 1,
                        'severity': 'medium',
                        'description': 'TOCTOU: File existence check before use',
                        'code': f"{line}\n{next_line}"
                    })
            
            elif language in ['java', 'javascript']:
                # Similar patterns for Java/JavaScript
                if re.match(r'if\s*\([^)]*>\s*', line) and ('--' in next_line or '-=' in next_line):
                    race_conditions.append({
                        'type': 'check_then_act',
                        'line': i + 1,
                        'severity': 'high',
                        'description': 'Check-then-act race condition',
                        'code': f"{line}\n{next_line}"
                    })
        
        return race_conditions
    
    def _find_double_checked_locking(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find double-checked locking anti-pattern"""
        
        race_conditions = []
        
        if language == 'java':
            # Pattern: if (instance == null) { synchronized { if (instance == null) { instance = new } } }
            pattern = r'if\s*\([^)]*==\s*null\)[^{]*\{[^}]*synchronized[^}]*\{[^}]*if\s*\([^)]*==\s*null\)'
            
            matches = re.finditer(pattern, code, re.DOTALL)
            for match in matches:
                # Check if variable is volatile
                var_name = re.search(r'if\s*\((\w+)\s*==\s*null\)', match.group())
                if var_name:
                    var = var_name.group(1)
                    if f'volatile {var}' not in code and f'volatile\n{var}' not in code:
                        race_conditions.append({
                            'type': 'double_checked_locking',
                            'severity': 'high',
                            'description': 'Double-checked locking without volatile',
                            'code': match.group()[:200]
                        })
        
        return race_conditions
    
    def _find_unsynchronized_access(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find unsynchronized access to shared resources"""
        
        race_conditions = []
        
        # Look for global/class variables modified in multiple places
        if language == 'python':
            # Find global variable modifications
            global_writes = re.findall(r'global\s+(\w+)', code)
            
            for var in set(global_writes):
                # Count how many times it's modified
                modifications = len(re.findall(rf'{var}\s*[-+*/]=', code))
                
                if modifications > 1:
                    # Check if threading/multiprocessing is used
                    if 'threading' in code or 'multiprocessing' in code:
                        # Check for locks
                        if f'lock.acquire()' not in code and 'with lock:' not in code:
                            race_conditions.append({
                                'type': 'unsynchronized_access',
                                'severity': 'high',
                                'description': f'Global variable "{var}" modified without synchronization',
                                'variable': var
                            })
        
        elif language == 'java':
            # Find instance variables not marked volatile or synchronized
            instance_vars = re.findall(r'private\s+(?!final)(?!volatile)(\w+)\s+(\w+);', code)
            
            for type_name, var_name in instance_vars:
                # Check if accessed in synchronized block
                if var_name in code:
                    modifications = code.count(f'{var_name} =')
                    if modifications > 1:
                        if 'synchronized' not in code:
                            race_conditions.append({
                                'type': 'unsynchronized_access',
                                'severity': 'medium',
                                'description': f'Instance variable "{var_name}" may have race condition',
                                'variable': var_name
                            })
        
        return race_conditions
    
    def _find_toctou_file_ops(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find TOCTOU vulnerabilities in file operations"""
        
        race_conditions = []
        lines = code.split('\n')
        
        # Track file checks and uses
        file_checks = {}  # line -> file variable
        file_uses = {}    # line -> file variable
        
        for i, line in enumerate(lines):
            # File existence checks
            if language == 'python':
                check_match = re.search(r'os\.path\.exists\(["\']?([^"\')\s]+)', line)
                if check_match:
                    file_checks[i] = check_match.group(1)
                
                # File opens
                open_match = re.search(r'open\(["\']?([^"\')\s]+)', line)
                if open_match:
                    file_uses[i] = open_match.group(1)
            
            elif language in ['c', 'cpp']:
                # access() followed by open()
                if 'access(' in line:
                    file_checks[i] = 'file'
                if 'open(' in line or 'fopen(' in line:
                    file_uses[i] = 'file'
        
        # Look for check followed by use within reasonable distance
        for check_line, check_file in file_checks.items():
            for use_line, use_file in file_uses.items():
                if 0 < use_line - check_line < 10:  # Within 10 lines
                    if check_file == use_file or check_file == 'file':
                        race_conditions.append({
                            'type': 'toctou_file',
                            'severity': 'high',
                            'line': check_line + 1,
                            'description': f'TOCTOU: File checked at line {check_line+1}, used at {use_line+1}',
                            'file': check_file
                        })
                        break
        
        return race_conditions
    
    async def analyze_concurrency_patterns(self, code: str, 
                                          language: str) -> Dict[str, Any]:
        """
        Analyze concurrency patterns and safety
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Concurrency analysis
        """
        logger.info("Analyzing concurrency patterns")
        
        analysis = {
            'uses_threading': False,
            'synchronization_primitives': [],
            'potential_deadlocks': [],
            'race_conditions': []
        }
        
        # Check if threading/concurrency is used
        if language == 'python':
            analysis['uses_threading'] = ('threading' in code or 
                                         'multiprocessing' in code or
                                         'asyncio' in code)
            
            # Find synchronization primitives
            if 'Lock()' in code:
                analysis['synchronization_primitives'].append('Lock')
            if 'RLock()' in code:
                analysis['synchronization_primitives'].append('RLock')
            if 'Semaphore' in code:
                analysis['synchronization_primitives'].append('Semaphore')
                
        elif language == 'java':
            analysis['uses_threading'] = ('Thread' in code or 
                                         'Runnable' in code or
                                         'ExecutorService' in code)
            
            if 'synchronized' in code:
                analysis['synchronization_primitives'].append('synchronized')
            if 'ReentrantLock' in code:
                analysis['synchronization_primitives'].append('ReentrantLock')
        
        # Detect race conditions
        analysis['race_conditions'] = await self.detect_race_conditions(code, language)
        
        # Detect potential deadlocks
        analysis['potential_deadlocks'] = self._detect_deadlocks(code, language)
        
        return analysis
    
    def _detect_deadlocks(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect potential deadlock situations"""
        
        deadlocks = []
        
        if language == 'python':
            # Look for nested lock acquisitions
            lock_pattern = r'(\w+)\.acquire\(\)'
            lock_acquisitions = re.findall(lock_pattern, code)
            
            # Check for multiple locks acquired in same scope
            if len(set(lock_acquisitions)) > 1:
                deadlocks.append({
                    'type': 'potential_deadlock',
                    'severity': 'medium',
                    'description': 'Multiple locks acquired - potential for deadlock',
                    'locks': list(set(lock_acquisitions))
                })
        
        elif language == 'java':
            # Look for nested synchronized blocks
            synchronized_blocks = re.findall(r'synchronized\s*\(([^)]+)\)', code)
            
            if len(synchronized_blocks) > 1:
                deadlocks.append({
                    'type': 'potential_deadlock',
                    'severity': 'medium',
                    'description': 'Multiple synchronized blocks - check lock ordering',
                    'objects': synchronized_blocks
                })
        
        return deadlocks
