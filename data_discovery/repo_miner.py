"""
Repository Miner
Source code repository analysis and secret detection
"""

import os
import re
import json
import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class SecretMatch:
    """Detected secret in repository"""
    file_path: str
    line_number: int
    secret_type: str
    matched_pattern: str
    context: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class RepositoryMiner:
    """
    Analyzes source code repositories for secrets and sensitive information
    """
    
    def __init__(self):
        # Secret detection patterns
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
            'github_pat': r'ghp_[0-9a-zA-Z]{36}',
            'slack_token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}',
            'slack_webhook': r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9a-zA-Z]{24}',
            'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
            'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'heroku_api_key': r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'stripe_api_key': r'sk_live_[0-9a-zA-Z]{24}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'private_key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            'generic_secret': r'[s|S][e|E][c|C][r|R][e|E][t|T].*[\'"][0-9a-zA-Z]{32,45}[\'"]',
            'generic_password': r'[p|P][a|A][s|S][s|S][w|W][o|O][r|R][d|D].*[\'"][^\'\"]{8,}[\'"]',
            'jwt_token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'connection_string': r'(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@[^/]+',
            'api_key_header': r'[a|A][p|P][i|I][_-]?[k|K][e|E][y|Y].*[\'"][0-9a-zA-Z]{32,}[\'"]',
        }
        
        # Files/directories to exclude
        self.exclude_patterns = [
            r'\.git/',
            r'node_modules/',
            r'__pycache__/',
            r'\.venv/',
            r'venv/',
            r'dist/',
            r'build/',
            r'\.min\.js$',
            r'\.bundle\.js$'
        ]
        
        self.secrets = []
        self.repo_info = {}
    
    def analyze_repository(self, repo_path: str) -> List[SecretMatch]:
        """
        Analyze Git repository for secrets
        """
        print(f"[*] Analyzing repository: {repo_path}")
        
        # Get repository info
        self.repo_info = self._get_repo_info(repo_path)
        
        # Scan files
        for root, dirs, files in os.walk(repo_path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                
                if not self._is_excluded(filepath):
                    self._scan_file(filepath, repo_path)
        
        print(f"\n[*] Repository scan complete")
        print(f"[!] Found {len(self.secrets)} potential secrets")
        
        return self.secrets
    
    def analyze_git_history(self, repo_path: str, max_commits: int = 100) -> List[SecretMatch]:
        """
        Scan Git history for secrets (dangerous!)
        """
        print(f"[*] Analyzing Git history: {repo_path}")
        
        try:
            # Get list of commits
            result = subprocess.run(
                ['git', '-C', repo_path, 'log', '--pretty=format:%H', f'-{max_commits}'],
                capture_output=True,
                text=True
            )
            
            commits = result.stdout.strip().split('\n')
            
            for commit in commits:
                # Get commit diff
                diff_result = subprocess.run(
                    ['git', '-C', repo_path, 'show', commit],
                    capture_output=True,
                    text=True
                )
                
                diff_text = diff_result.stdout
                
                # Scan diff for secrets
                self._scan_text(diff_text, f"git:{commit[:8]}")
            
            print(f"[*] Git history scan complete")
            
        except Exception as e:
            print(f"[!] Error scanning Git history: {str(e)}")
        
        return self.secrets
    
    def _get_repo_info(self, repo_path: str) -> Dict:
        """
        Get repository metadata
        """
        info = {
            'path': repo_path,
            'is_git': os.path.exists(os.path.join(repo_path, '.git'))
        }
        
        if info['is_git']:
            try:
                # Get remote URL
                result = subprocess.run(
                    ['git', '-C', repo_path, 'config', '--get', 'remote.origin.url'],
                    capture_output=True,
                    text=True
                )
                info['remote_url'] = result.stdout.strip()
                
                # Get current branch
                result = subprocess.run(
                    ['git', '-C', repo_path, 'branch', '--show-current'],
                    capture_output=True,
                    text=True
                )
                info['branch'] = result.stdout.strip()
                
                # Get last commit
                result = subprocess.run(
                    ['git', '-C', repo_path, 'log', '-1', '--pretty=format:%H %s'],
                    capture_output=True,
                    text=True
                )
                info['last_commit'] = result.stdout.strip()
                
            except Exception as e:
                print(f"[!] Error getting Git info: {str(e)}")
        
        return info
    
    def _is_excluded(self, path: str) -> bool:
        """
        Check if path should be excluded
        """
        path_normalized = path.replace('\\', '/')
        
        for pattern in self.exclude_patterns:
            if re.search(pattern, path_normalized):
                return True
        
        return False
    
    def _scan_file(self, filepath: str, repo_root: str):
        """
        Scan single file for secrets
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    for secret_type, pattern in self.secret_patterns.items():
                        matches = re.finditer(pattern, line)
                        
                        for match in matches:
                            # Get context (surrounding lines)
                            start = max(0, line_num - 2)
                            end = min(len(lines), line_num + 2)
                            context = ''.join(lines[start:end])
                            
                            # Create relative path
                            rel_path = os.path.relpath(filepath, repo_root)
                            
                            secret = SecretMatch(
                                file_path=rel_path,
                                line_number=line_num,
                                secret_type=secret_type,
                                matched_pattern=match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                                context=context.strip()
                            )
                            
                            self.secrets.append(secret)
                            
                            print(f"[!] Secret found in {rel_path}:{line_num}")
                            print(f"    Type: {secret_type}")
        
        except Exception as e:
            pass  # Skip files that can't be read
    
    def _scan_text(self, text: str, source: str):
        """
        Scan text for secrets
        """
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern in self.secret_patterns.items():
                matches = re.finditer(pattern, line)
                
                for match in matches:
                    secret = SecretMatch(
                        file_path=source,
                        line_number=line_num,
                        secret_type=secret_type,
                        matched_pattern=match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                        context=line.strip()
                    )
                    
                    self.secrets.append(secret)
    
    def analyze_dependencies(self, repo_path: str) -> Dict:
        """
        Analyze dependencies for vulnerabilities
        """
        vulnerabilities = {
            'python': [],
            'javascript': [],
            'ruby': [],
            'java': []
        }
        
        # Python dependencies
        requirements_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'Pipfile',
            'setup.py'
        ]
        
        for req_file in requirements_files:
            req_path = os.path.join(repo_path, req_file)
            if os.path.exists(req_path):
                print(f"[*] Found Python dependencies: {req_file}")
                # Could integrate with safety or snyk here
        
        # JavaScript dependencies
        if os.path.exists(os.path.join(repo_path, 'package.json')):
            print(f"[*] Found JavaScript dependencies: package.json")
            # Could integrate with npm audit
        
        return vulnerabilities
    
    def generate_report(self) -> Dict:
        """
        Generate repository analysis report
        """
        report = {
            'repository': self.repo_info,
            'total_secrets': len(self.secrets),
            'by_type': {},
            'by_file': {},
            'secrets': []
        }
        
        for secret in self.secrets:
            # Count by type
            report['by_type'][secret.secret_type] = report['by_type'].get(secret.secret_type, 0) + 1
            
            # Count by file
            report['by_file'][secret.file_path] = report['by_file'].get(secret.file_path, 0) + 1
            
            # Add to list
            report['secrets'].append(secret.to_dict())
        
        return report
    
    def export_results(self, output_file: str):
        """
        Export results to JSON
        """
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Repository analysis exported to: {output_file}")
    
    def get_high_severity_secrets(self) -> List[SecretMatch]:
        """
        Get high-severity secrets (credentials, keys)
        """
        high_severity_types = [
            'aws_access_key',
            'aws_secret_key',
            'private_key',
            'github_token',
            'github_pat',
            'stripe_api_key',
            'connection_string'
        ]
        
        return [s for s in self.secrets if s.secret_type in high_severity_types]
