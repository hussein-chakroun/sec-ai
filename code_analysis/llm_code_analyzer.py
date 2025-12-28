"""
LLM-Powered Code Analysis Module
Uses LLM to analyze code for logic flaws and vulnerabilities
"""

import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)


class LLMCodeAnalyzer:
    """
    LLM-powered code analysis for deep vulnerability detection
    Finds logic flaws, business logic issues, and subtle bugs
    """
    
    def __init__(self, llm_client):
        self.llm_client = llm_client
        self.analysis_cache = {}
        
    async def analyze_code(self, code: str, language: str, 
                          context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze code using LLM
        
        Args:
            code: Source code to analyze
            language: Programming language
            context: Additional context about the code
            
        Returns:
            Analysis results
        """
        logger.info(f"LLM analysis of {language} code ({len(code)} chars)")
        
        results = {
            'vulnerabilities': [],
            'logic_flaws': [],
            'code_smells': [],
            'recommendations': []
        }
        
        try:
            # Analyze in chunks if code is large
            if len(code) > 10000:
                results = await self._analyze_large_code(code, language, context)
            else:
                results = await self._analyze_code_chunk(code, language, context)
            
            logger.info(f"LLM analysis complete: {len(results['vulnerabilities'])} vulnerabilities, "
                       f"{len(results['logic_flaws'])} logic flaws")
            
            return results
            
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return {'error': str(e)}
    
    async def _analyze_code_chunk(self, code: str, language: str,
                                  context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze a single chunk of code"""
        
        prompt = self._build_analysis_prompt(code, language, context)
        
        try:
            response = await self.llm_client.generate(prompt)
            results = self._parse_llm_response(response)
            return results
            
        except Exception as e:
            logger.error(f"LLM request failed: {e}")
            return {'vulnerabilities': [], 'logic_flaws': [], 'code_smells': []}
    
    async def _analyze_large_code(self, code: str, language: str,
                                 context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze large codebase in chunks"""
        
        # Split into functions/classes
        chunks = self._split_code(code, language)
        
        # Analyze chunks in parallel
        tasks = []
        for chunk in chunks[:10]:  # Limit to 10 chunks
            task = self._analyze_code_chunk(chunk, language, context)
            tasks.append(task)
        
        chunk_results = await asyncio.gather(*tasks)
        
        # Merge results
        merged = {
            'vulnerabilities': [],
            'logic_flaws': [],
            'code_smells': [],
            'recommendations': []
        }
        
        for result in chunk_results:
            for key in merged:
                merged[key].extend(result.get(key, []))
        
        return merged
    
    def _build_analysis_prompt(self, code: str, language: str,
                               context: Dict[str, Any] = None) -> str:
        """Build prompt for LLM code analysis"""
        
        context_str = ""
        if context:
            context_str = f"\nContext: {context.get('description', '')}"
            if context.get('framework'):
                context_str += f"\nFramework: {context['framework']}"
        
        prompt = f"""
Analyze the following {language} code for security vulnerabilities, logic flaws, and code quality issues.
{context_str}

Code:
```{language}
{code}
```

Provide a detailed analysis including:

1. **Security Vulnerabilities**: Identify any security issues like injection flaws, authentication bypasses, etc.
2. **Logic Flaws**: Business logic errors, race conditions, incorrect state management
3. **Code Smells**: Poor coding practices, maintainability issues
4. **Recommendations**: Specific suggestions for fixes

Format your response as:

VULNERABILITIES:
- [Type] [Severity] [Line number if applicable]: Description
- ...

LOGIC_FLAWS:
- [Issue]: Description and impact
- ...

CODE_SMELLS:
- [Pattern]: Description
- ...

RECOMMENDATIONS:
1. Recommendation 1
2. Recommendation 2
...
"""
        
        return prompt
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured results"""
        
        results = {
            'vulnerabilities': [],
            'logic_flaws': [],
            'code_smells': [],
            'recommendations': []
        }
        
        current_section = None
        
        for line in response.split('\n'):
            line = line.strip()
            
            if line.startswith('VULNERABILITIES:'):
                current_section = 'vulnerabilities'
            elif line.startswith('LOGIC_FLAWS:'):
                current_section = 'logic_flaws'
            elif line.startswith('CODE_SMELLS:'):
                current_section = 'code_smells'
            elif line.startswith('RECOMMENDATIONS:'):
                current_section = 'recommendations'
            elif line.startswith('-') and current_section:
                item = line[1:].strip()
                results[current_section].append(item)
            elif line and current_section == 'recommendations' and line[0].isdigit():
                results[current_section].append(line)
        
        return results
    
    def _split_code(self, code: str, language: str) -> List[str]:
        """Split code into logical chunks (functions, classes)"""
        
        chunks = []
        
        if language == 'python':
            # Split by function/class definitions
            current_chunk = []
            indent_level = 0
            
            for line in code.split('\n'):
                if line.startswith('def ') or line.startswith('class '):
                    if current_chunk:
                        chunks.append('\n'.join(current_chunk))
                    current_chunk = [line]
                    indent_level = len(line) - len(line.lstrip())
                else:
                    current_chunk.append(line)
            
            if current_chunk:
                chunks.append('\n'.join(current_chunk))
                
        elif language in ['javascript', 'typescript']:
            # Split by function declarations
            import re
            functions = re.split(r'\n(?=function |const \w+ = (?:async )?(?:function|\())', code)
            chunks = functions
            
        else:
            # Default: split by lines (crude but works)
            lines = code.split('\n')
            chunk_size = 100
            for i in range(0, len(lines), chunk_size):
                chunks.append('\n'.join(lines[i:i+chunk_size]))
        
        return chunks
    
    async def find_business_logic_flaws(self, code: str, 
                                       business_rules: List[str]) -> List[Dict[str, Any]]:
        """
        Find business logic vulnerabilities
        
        Args:
            code: Application code
            business_rules: List of business rules to check
            
        Returns:
            Business logic flaws
        """
        logger.info(f"Analyzing business logic with {len(business_rules)} rules")
        
        prompt = f"""
Analyze this code for business logic vulnerabilities.

Business Rules:
{chr(10).join(f"- {rule}" for rule in business_rules)}

Code:
```
{code}
```

Identify violations of business rules, logic errors, and potential exploits.
Focus on:
- Authentication/authorization bypasses
- Price manipulation
- Quantity/amount tampering
- State machine violations
- Race conditions in transactions
- Missing validation

Provide specific findings with line numbers.
"""
        
        try:
            response = await self.llm_client.generate(prompt)
            flaws = self._parse_business_logic_response(response)
            
            logger.info(f"Found {len(flaws)} business logic issues")
            return flaws
            
        except Exception as e:
            logger.error(f"Business logic analysis failed: {e}")
            return []
    
    def _parse_business_logic_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse business logic analysis response"""
        
        flaws = []
        
        # Simple parsing - would be more sophisticated in practice
        for line in response.split('\n'):
            if line.strip().startswith('-'):
                flaws.append({
                    'description': line.strip()[1:].strip(),
                    'type': 'business_logic',
                    'severity': 'medium'
                })
        
        return flaws
    
    async def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze entire file
        
        Args:
            file_path: Path to source file
            
        Returns:
            Analysis results
        """
        logger.info(f"Analyzing file: {file_path}")
        
        try:
            path = Path(file_path)
            code = path.read_text(errors='ignore')
            
            # Detect language
            ext = path.suffix.lower()
            language_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.java': 'java',
                '.c': 'c',
                '.cpp': 'cpp',
                '.go': 'go',
                '.rs': 'rust',
                '.php': 'php'
            }
            
            language = language_map.get(ext, 'unknown')
            
            results = await self.analyze_code(code, language, {
                'file': str(path),
                'description': f'Analysis of {path.name}'
            })
            
            results['file'] = str(path)
            results['language'] = language
            
            return results
            
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            return {'error': str(e), 'file': file_path}
    
    async def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """
        Analyze entire project
        
        Args:
            project_path: Path to project directory
            
        Returns:
            Project-wide analysis results
        """
        logger.info(f"Analyzing project: {project_path}")
        
        results = {
            'project': project_path,
            'files_analyzed': 0,
            'total_vulnerabilities': 0,
            'files': []
        }
        
        try:
            project_dir = Path(project_path)
            
            # Find source files
            source_extensions = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rs', '.php']
            source_files = []
            
            for ext in source_extensions:
                source_files.extend(project_dir.rglob(f'*{ext}'))
            
            # Limit to reasonable number
            source_files = source_files[:20]
            
            # Analyze files
            for file_path in source_files:
                file_results = await self.analyze_file(str(file_path))
                results['files'].append(file_results)
                results['files_analyzed'] += 1
                results['total_vulnerabilities'] += len(file_results.get('vulnerabilities', []))
            
            logger.info(f"Project analysis complete: {results['files_analyzed']} files, "
                       f"{results['total_vulnerabilities']} vulnerabilities")
            
            return results
            
        except Exception as e:
            logger.error(f"Project analysis failed: {e}")
            return {'error': str(e), 'project': project_path}
