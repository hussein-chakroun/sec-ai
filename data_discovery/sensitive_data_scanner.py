"""
Sensitive Data Scanner
Keyword-based sensitive file identification and classification
"""

import os
import re
import json
import magic
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
import hashlib
import mimetypes

@dataclass
class SensitiveFile:
    """Represents a sensitive file discovery"""
    path: str
    file_type: str
    sensitivity_level: str  # critical, high, medium, low
    matched_keywords: List[str]
    file_size: int
    hash_md5: str
    hash_sha256: str
    last_modified: float
    owner: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


class SensitiveDataScanner:
    """
    Intelligent scanner for sensitive data discovery
    """
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        
        # Keyword categories for sensitive data
        self.keyword_patterns = {
            'financial': [
                r'\b(credit[_\s]?card|visa|mastercard|amex)\b',
                r'\b(bank[_\s]?account|routing[_\s]?number|swift)\b',
                r'\b(invoice|payment|transaction|billing)\b',
                r'\b(salary|payroll|compensation)\b',
                r'\b(financial[_\s]?statement|balance[_\s]?sheet)\b'
            ],
            'credentials': [
                r'\b(password|passwd|pwd)\b',
                r'\b(api[_\s]?key|secret[_\s]?key|access[_\s]?token)\b',
                r'\b(private[_\s]?key|ssh[_\s]?key)\b',
                r'\b(authentication|credentials)\b',
                r'(BEGIN (RSA |DSA |EC )?PRIVATE KEY)',
            ],
            'pii': [
                r'\b(social[_\s]?security|ssn)\b',
                r'\b(driver[_\s]?license|passport)\b',
                r'\b(date[_\s]?of[_\s]?birth|dob)\b',
                r'\b(medical[_\s]?record|health[_\s]?information)\b',
                r'\b(personal[_\s]?data|personally[_\s]?identifiable)\b'
            ],
            'intellectual_property': [
                r'\b(patent|trademark|copyright)\b',
                r'\b(proprietary|confidential|trade[_\s]?secret)\b',
                r'\b(source[_\s]?code|algorithm)\b',
                r'\b(research[_\s]?data|experimental)\b',
                r'\b(prototype|blueprint|design[_\s]?document)\b'
            ],
            'legal': [
                r'\b(contract|agreement|nda)\b',
                r'\b(non[_\s]?disclosure|confidentiality)\b',
                r'\b(lawsuit|litigation|legal)\b',
                r'\b(merger|acquisition|m&a)\b',
                r'\b(compliance|regulatory)\b'
            ],
            'security': [
                r'\b(vulnerability|exploit|penetration[_\s]?test)\b',
                r'\b(incident[_\s]?response|security[_\s]?breach)\b',
                r'\b(firewall|encryption|certificate)\b',
                r'\b(audit[_\s]?log|access[_\s]?control)\b',
                r'\b(threat[_\s]?intelligence|ioc)\b'
            ]
        }
        
        # High-value file extensions
        self.sensitive_extensions = {
            'critical': ['.key', '.pem', '.p12', '.pfx', '.jks', '.keystore'],
            'high': ['.sql', '.db', '.sqlite', '.mdb', '.accdb', '.dbf'],
            'medium': ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt', '.pptx'],
            'low': ['.txt', '.csv', '.json', '.xml', '.yaml', '.yml']
        }
        
        # File paths that often contain sensitive data
        self.sensitive_paths = [
            '/config/', '/conf/', '/.aws/', '/.ssh/', '/.gnupg/',
            '/backup/', '/backups/', '/credentials/', '/secrets/',
            '/private/', '/confidential/', '/hr/', '/finance/',
            '/legal/', '/contracts/', '/personal/'
        ]
        
        self.discoveries = []
        
    def scan_directory(self, root_path: str, max_depth: int = 5, 
                      max_files: int = 10000) -> List[SensitiveFile]:
        """
        Recursively scan directory for sensitive files
        """
        print(f"[*] Scanning directory: {root_path}")
        files_scanned = 0
        
        for root, dirs, files in os.walk(root_path):
            # Check depth
            depth = root[len(root_path):].count(os.sep)
            if depth > max_depth:
                continue
                
            # Check if we've hit max files
            if files_scanned >= max_files:
                print(f"[!] Reached maximum file limit ({max_files})")
                break
                
            for filename in files:
                try:
                    filepath = os.path.join(root, filename)
                    result = self.analyze_file(filepath)
                    
                    if result:
                        self.discoveries.append(result)
                        print(f"[+] Found sensitive file: {filepath}")
                        print(f"    Level: {result.sensitivity_level}")
                        print(f"    Keywords: {', '.join(result.matched_keywords[:3])}")
                    
                    files_scanned += 1
                    
                except Exception as e:
                    print(f"[!] Error scanning {filepath}: {str(e)}")
                    continue
        
        print(f"\n[*] Scan complete: {files_scanned} files analyzed")
        print(f"[*] Sensitive files found: {len(self.discoveries)}")
        
        return self.discoveries
    
    def analyze_file(self, filepath: str) -> Optional[SensitiveFile]:
        """
        Analyze a single file for sensitive content
        """
        try:
            # Get file metadata
            stat = os.stat(filepath)
            file_size = stat.st_size
            
            # Skip very large files (>50MB)
            if file_size > 50 * 1024 * 1024:
                return None
            
            # Get file hashes
            md5_hash, sha256_hash = self._hash_file(filepath)
            
            # Determine file type
            file_type = self._get_file_type(filepath)
            
            # Check extension sensitivity
            ext_sensitivity = self._check_extension_sensitivity(filepath)
            
            # Check path sensitivity
            path_sensitivity = self._check_path_sensitivity(filepath)
            
            # Scan file content
            matched_keywords = self._scan_content(filepath, file_type)
            
            # Determine overall sensitivity level
            sensitivity_level = self._calculate_sensitivity(
                ext_sensitivity, path_sensitivity, matched_keywords
            )
            
            # Only return if sensitive
            if sensitivity_level != 'none':
                return SensitiveFile(
                    path=filepath,
                    file_type=file_type,
                    sensitivity_level=sensitivity_level,
                    matched_keywords=matched_keywords,
                    file_size=file_size,
                    hash_md5=md5_hash,
                    hash_sha256=sha256_hash,
                    last_modified=stat.st_mtime
                )
            
            return None
            
        except Exception as e:
            return None
    
    def _hash_file(self, filepath: str) -> tuple:
        """Calculate MD5 and SHA256 hashes"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                    sha256.update(chunk)
            
            return md5.hexdigest(), sha256.hexdigest()
        except:
            return 'unknown', 'unknown'
    
    def _get_file_type(self, filepath: str) -> str:
        """Determine file type"""
        try:
            mime = magic.from_file(filepath, mime=True)
            return mime
        except:
            # Fallback to extension-based detection
            mime_type, _ = mimetypes.guess_type(filepath)
            return mime_type or 'unknown'
    
    def _check_extension_sensitivity(self, filepath: str) -> str:
        """Check file extension against sensitive lists"""
        ext = os.path.splitext(filepath)[1].lower()
        
        for level, extensions in self.sensitive_extensions.items():
            if ext in extensions:
                return level
        
        return 'none'
    
    def _check_path_sensitivity(self, filepath: str) -> bool:
        """Check if file path contains sensitive indicators"""
        filepath_lower = filepath.lower().replace('\\', '/')
        
        for sensitive_path in self.sensitive_paths:
            if sensitive_path in filepath_lower:
                return True
        
        return False
    
    def _scan_content(self, filepath: str, file_type: str) -> List[str]:
        """Scan file content for sensitive keywords"""
        matched_keywords = []
        
        # Only scan text-based files
        if not self._is_text_file(file_type):
            return matched_keywords
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100000)  # Read first 100KB
                
                for category, patterns in self.keyword_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            matched_keywords.append(category)
                            break  # One match per category
        except:
            pass
        
        return matched_keywords
    
    def _is_text_file(self, file_type: str) -> bool:
        """Check if file is text-based"""
        text_types = ['text/', 'application/json', 'application/xml', 
                     'application/javascript', 'application/sql']
        
        return any(file_type.startswith(t) for t in text_types)
    
    def _calculate_sensitivity(self, ext_sensitivity: str, 
                              path_sensitivity: bool, 
                              matched_keywords: List[str]) -> str:
        """Calculate overall sensitivity level"""
        score = 0
        
        # Extension scoring
        ext_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
        score += ext_scores.get(ext_sensitivity, 0)
        
        # Path scoring
        if path_sensitivity:
            score += 2
        
        # Keyword scoring
        if 'credentials' in matched_keywords or 'security' in matched_keywords:
            score += 3
        elif 'financial' in matched_keywords or 'pii' in matched_keywords:
            score += 2
        elif matched_keywords:
            score += 1
        
        # Determine level
        if score >= 5:
            return 'critical'
        elif score >= 3:
            return 'high'
        elif score >= 1:
            return 'medium'
        else:
            return 'none'
    
    def generate_report(self) -> Dict:
        """Generate summary report of discoveries"""
        report = {
            'total_files': len(self.discoveries),
            'by_sensitivity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'by_category': {},
            'total_size_mb': 0,
            'files': []
        }
        
        for discovery in self.discoveries:
            # Count by sensitivity
            report['by_sensitivity'][discovery.sensitivity_level] += 1
            
            # Count by category
            for keyword in discovery.matched_keywords:
                report['by_category'][keyword] = report['by_category'].get(keyword, 0) + 1
            
            # Calculate total size
            report['total_size_mb'] += discovery.file_size / (1024 * 1024)
            
            # Add to files list
            report['files'].append(discovery.to_dict())
        
        return report
    
    def export_results(self, output_file: str):
        """Export results to JSON file"""
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Results exported to: {output_file}")
    
    async def llm_classify_file(self, filepath: str, content_sample: str) -> Dict:
        """Use LLM to classify file sensitivity"""
        if not self.llm_client:
            return {'classification': 'unknown', 'confidence': 0}
        
        prompt = f"""
        Analyze this file and determine if it contains sensitive data:
        
        File: {filepath}
        Content Sample:
        {content_sample[:2000]}
        
        Classify as: critical, high, medium, low, or none
        Identify what type of sensitive data it contains.
        
        Respond in JSON format:
        {{
            "sensitivity": "level",
            "data_types": ["type1", "type2"],
            "justification": "explanation"
        }}
        """
        
        try:
            response = await self.llm_client.generate(prompt)
            return json.loads(response)
        except:
            return {'classification': 'unknown', 'confidence': 0}
