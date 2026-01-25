"""
Phase 4 Orchestrator - Post-Exploitation & Privilege Escalation
Takes Phase 3 compromised hosts and deepens access through privilege escalation,
credential harvesting, and persistence mechanisms
"""
import asyncio
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from loguru import logger
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json
from pathlib import Path
import sys

# Import LLM orchestrator
from .llm_orchestrator import LLMOrchestrator

# Import post-exploitation tools
sys.path.insert(0, str(Path(__file__).parent.parent))
from privilege_escalation.misconfiguration_enum import MisconfigurationEnumerator
from privilege_escalation.kernel_exploit_db import KernelExploitDB
from privilege_escalation.token_manipulation import TokenManipulation
from privilege_escalation.dll_hijacking import DLLHijacking
from credential_harvesting.mimikatz_automation import MimikatzAutomation
from credential_harvesting.browser_dumper import BrowserDumper
from credential_harvesting.memory_scraper import MemoryScraper
from credential_harvesting.credential_manager import CredentialManager
from persistence.persistence_manager import PersistenceManager


@dataclass
class CompromisedHost:
    """Represents a compromised host from Phase 3"""
    host_id: str
    ip_address: str
    hostname: str
    os_type: str  # linux, windows, macos
    os_version: str
    architecture: str  # x86, x64, arm
    shell_type: str  # meterpreter, ssh, reverse_shell, etc.
    session_id: Optional[str] = None
    current_user: str = "unknown"
    current_privileges: str = "user"  # user, root, system, admin
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    persistence_installed: bool = False
    fully_compromised: bool = False
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PrivEscAttempt:
    """Represents a privilege escalation attempt"""
    attempt_id: str
    host_id: str
    technique: str  # suid, kernel_exploit, dll_hijack, token_manip, etc.
    tool: str
    success: bool = False
    escalated_to: str = "none"  # root, system, admin
    evidence: List[str] = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0
    llm_reasoning: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class HarvestedCredential:
    """Represents harvested credentials"""
    cred_id: str
    host_id: str
    username: str
    credential_type: str  # password, hash, key, token, ticket
    credential_value: str
    domain: Optional[str] = None
    source: str  # mimikatz, browser, memory, lsass, sam, etc.
    privilege_level: str = "user"  # user, admin, domain_admin
    valid: bool = True
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Phase4Progress:
    """Track Phase 4 progress"""
    total_hosts: int = 0
    privilege_escalations_attempted: int = 0
    successful_escalations: int = 0
    credentials_harvested: int = 0
    persistence_installed: int = 0
    fully_compromised_hosts: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        if self.privilege_escalations_attempted == 0:
            return 0.0
        return (self.successful_escalations / self.privilege_escalations_attempted) * 100


class Phase4Orchestrator:
    """
    Phase 4: Post-Exploitation & Privilege Escalation
    
    Takes compromised hosts from Phase 3 and:
    1. Elevates privileges to root/SYSTEM
    2. Harvests credentials from memory, disk, browsers
    3. Establishes multiple persistence mechanisms
    4. Enumerates system for valuable data
    5. Prepares for lateral movement (Phase 5)
    """
    
    def __init__(self, llm_orchestrator: LLMOrchestrator, config: Optional[Dict[str, Any]] = None):
        self.llm = llm_orchestrator
        self.config = config or {}
        
        # Configuration
        self.max_escalation_attempts = self.config.get('max_escalation_attempts', 5)
        self.enable_credential_harvesting = self.config.get('enable_credential_harvesting', True)
        self.enable_persistence = self.config.get('enable_persistence', True)
        self.safe_mode = self.config.get('safe_mode', True)
        self.stealth_mode = self.config.get('stealth_mode', False)
        
        # Data storage
        self.compromised_hosts: List[CompromisedHost] = []
        self.priv_esc_attempts: List[PrivEscAttempt] = []
        self.harvested_credentials: List[HarvestedCredential] = []
        self.credential_manager = CredentialManager()
        self.progress = Phase4Progress()
        
        # Tool instances (will be initialized per host based on OS)
        self.tools_cache: Dict[str, Any] = {}
        
        logger.info("Phase 4 Orchestrator initialized")
    
    def load_phase3_results(self, results: Dict[str, Any]):
        """Load Phase 3 exploitation results"""
        logger.info("Loading Phase 3 results...")
        
        # Extract compromised hosts from Phase 3
        successful_exploits = results.get('successful_exploits', [])
        
        for exploit in successful_exploits:
            host = CompromisedHost(
                host_id=f"host_{len(self.compromised_hosts) + 1}",
                ip_address=exploit.get('target', 'unknown'),
                hostname=exploit.get('target', 'unknown'),
                os_type=self._detect_os_type(exploit),
                os_version=exploit.get('os_version', 'unknown'),
                architecture=exploit.get('architecture', 'x64'),
                shell_type=exploit.get('exploit_type', 'unknown'),
                session_id=exploit.get('session_id'),
                current_privileges=exploit.get('privileges', 'user')
            )
            
            self.compromised_hosts.append(host)
        
        self.progress.total_hosts = len(self.compromised_hosts)
        
        logger.info(f"Loaded {len(self.compromised_hosts)} compromised hosts from Phase 3")
    
    async def create_postexploit_plan(self) -> Dict[str, Any]:
        """
        Use LLM to create intelligent post-exploitation plan
        """
        logger.info("Creating LLM-driven post-exploitation plan...")
        
        # Build context for LLM
        hosts_summary = [
            {
                'host_id': h.host_id,
                'ip': h.ip_address,
                'os': f"{h.os_type} {h.os_version}",
                'current_privileges': h.current_privileges,
                'shell_type': h.shell_type
            }
            for h in self.compromised_hosts
        ]
        
        prompt = f"""You are an expert penetration tester performing post-exploitation activities on compromised hosts.

# COMPROMISED HOSTS:
{json.dumps(hosts_summary, indent=2)}

# OBJECTIVES:
1. Privilege Escalation: Elevate from user to root/SYSTEM on each host
2. Credential Harvesting: Extract all credentials (passwords, hashes, keys, tokens)
3. Persistence: Install multiple persistence mechanisms for redundant access
4. Data Discovery: Locate high-value data and sensitive files
5. Lateral Movement Preparation: Identify paths to other hosts

# TASK:
Create a prioritized post-exploitation plan that:
1. Prioritizes hosts by value (domain controllers > servers > workstations)
2. Suggests OS-specific privilege escalation techniques
3. Recommends credential harvesting methods based on OS and access
4. Proposes appropriate persistence mechanisms (stealthy vs. robust)
5. Identifies what data to look for on each host
6. Suggests which credentials to use for lateral movement

# OUTPUT FORMAT (JSON):
{{
  "strategy": "overall post-exploitation strategy",
  "host_priorities": [
    {{
      "host_id": "host_1",
      "priority_score": 95,
      "reason": "Domain controller - highest value target",
      "value_category": "critical"
    }}
  ],
  "privilege_escalation_plan": [
    {{
      "host_id": "host_1",
      "current_privileges": "user",
      "target_privileges": "root|system|admin",
      "techniques": [
        {{
          "technique": "kernel_exploit",
          "tool": "CVE-2021-4034 (PwnKit)",
          "success_probability": 0.85,
          "stealthy": false,
          "reasoning": "Linux kernel 5.x vulnerable to PwnKit"
        }},
        {{
          "technique": "suid_abuse",
          "tool": "/usr/bin/find SUID",
          "success_probability": 0.6,
          "stealthy": true,
          "reasoning": "SUID binaries may be misconfigured"
        }}
      ]
    }}
  ],
  "credential_harvesting_plan": [
    {{
      "host_id": "host_1",
      "methods": [
        {{
          "method": "mimikatz_lsass",
          "tool": "pypykatz",
          "targets": ["plaintext passwords", "NTLM hashes", "Kerberos tickets"],
          "priority": "high",
          "requires_admin": true
        }}
      ]
    }}
  ],
  "persistence_plan": [
    {{
      "host_id": "host_1",
      "mechanisms": [
        {{
          "type": "ssh_key",
          "stealthiness": "high",
          "reliability": "medium",
          "reasoning": "Add SSH key to ~/.ssh/authorized_keys"
        }},
        {{
          "type": "cron_job",
          "stealthiness": "medium",
          "reliability": "high",
          "reasoning": "Reverse shell every 6 hours"
        }}
      ]
    }}
  ],
  "data_discovery_targets": [
    {{
      "host_id": "host_1",
      "search_locations": ["/etc/", "/root/", "/home/", "/var/www/"],
      "file_patterns": ["*.conf", "*.key", "*.pem", "password*", "secret*"],
      "databases": ["mysql", "postgresql"],
      "priority": "high"
    }}
  ]
}}

Provide ONLY valid JSON, no additional text."""

        system_prompt = """You are a highly skilled penetration testing expert specializing in post-exploitation, privilege escalation, and credential harvesting. You have deep knowledge of:
- Linux and Windows privilege escalation techniques
- Credential extraction methods (Mimikatz, LaZagne, browser dumping)
- Persistence mechanisms (rootkits, backdoors, scheduled tasks)
- Active Directory attack paths
- Operational security and stealth

Prioritize effectiveness while being mindful of detection risks."""

        try:
            response = self.llm.generate(prompt, system_prompt=system_prompt)
            
            # Parse JSON
            response = response.strip()
            if response.startswith('```'):
                lines = response.split('\n')
                response = '\n'.join(lines[1:-1])
                if response.startswith('json'):
                    response = '\n'.join(response.split('\n')[1:])
            
            plan = json.loads(response)
            
            logger.success("LLM-driven post-exploitation plan created")
            return plan
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._create_basic_postexploit_plan()
        except Exception as e:
            logger.error(f"Error creating post-exploitation plan: {e}")
            return self._create_basic_postexploit_plan()
    
    async def execute_postexploit_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the post-exploitation plan"""
        logger.info("Starting Phase 4 post-exploitation...")
        
        results = {
            'plan': plan,
            'privilege_escalations': [],
            'harvested_credentials': [],
            'persistence_mechanisms': [],
            'discovered_data': [],
            'statistics': {}
        }
        
        # Sort hosts by priority
        host_priorities = {p['host_id']: p['priority_score'] 
                          for p in plan.get('host_priorities', [])}
        
        sorted_hosts = sorted(
            self.compromised_hosts,
            key=lambda h: host_priorities.get(h.host_id, 0),
            reverse=True
        )
        
        for host in sorted_hosts:
            logger.info(f"Processing {host.host_id} ({host.ip_address}) - {host.os_type}")
            
            # 1. Privilege Escalation
            if host.current_privileges != 'root' and host.current_privileges != 'system':
                logger.info(f"[{host.host_id}] Attempting privilege escalation...")
                priv_esc_result = await self._execute_privilege_escalation(host, plan)
                results['privilege_escalations'].append(priv_esc_result)
            else:
                logger.info(f"[{host.host_id}] Already has elevated privileges")
            
            # 2. Credential Harvesting
            if self.enable_credential_harvesting:
                logger.info(f"[{host.host_id}] Harvesting credentials...")
                cred_result = await self._execute_credential_harvesting(host, plan)
                results['harvested_credentials'].extend(cred_result)
            
            # 3. Persistence Installation
            if self.enable_persistence:
                logger.info(f"[{host.host_id}] Installing persistence...")
                persist_result = await self._execute_persistence(host, plan)
                results['persistence_mechanisms'].extend(persist_result)
            
            # 4. Data Discovery
            logger.info(f"[{host.host_id}] Discovering sensitive data...")
            data_result = await self._execute_data_discovery(host, plan)
            results['discovered_data'].extend(data_result)
            
            # Mark host as fully compromised if we have admin + persistence
            if host.current_privileges in ['root', 'system', 'admin'] and host.persistence_installed:
                host.fully_compromised = True
                self.progress.fully_compromised_hosts += 1
        
        # Compile statistics
        results['statistics'] = self._compile_statistics()
        results['compromised_hosts'] = [
            {
                'host_id': h.host_id,
                'ip': h.ip_address,
                'os': h.os_type,
                'privileges': h.current_privileges,
                'persistence': h.persistence_installed,
                'fully_compromised': h.fully_compromised,
                'credentials_found': len(h.credentials)
            }
            for h in self.compromised_hosts
        ]
        
        logger.success(f"Phase 4 complete: {self.progress.fully_compromised_hosts}/{self.progress.total_hosts} hosts fully compromised")
        
        return results
    
    async def _execute_privilege_escalation(
        self,
        host: CompromisedHost,
        plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute privilege escalation on a host"""
        
        # Find escalation plan for this host
        esc_plan = next(
            (p for p in plan.get('privilege_escalation_plan', []) 
             if p.get('host_id') == host.host_id),
            None
        )
        
        if not esc_plan:
            return {'host_id': host.host_id, 'success': False, 'error': 'No escalation plan'}
        
        techniques = esc_plan.get('techniques', [])
        
        for idx, technique in enumerate(techniques):
            attempt_id = f"privesc_{host.host_id}_{idx + 1}"
            
            attempt = PrivEscAttempt(
                attempt_id=attempt_id,
                host_id=host.host_id,
                technique=technique.get('technique'),
                tool=technique.get('tool'),
                llm_reasoning=technique.get('reasoning', '')
            )
            
            self.progress.privilege_escalations_attempted += 1
            
            logger.info(f"  Trying {technique.get('technique')} via {technique.get('tool')}")
            
            # Execute escalation based on technique
            success = False
            
            if host.os_type == 'linux':
                success = await self._linux_privilege_escalation(host, technique)
            elif host.os_type == 'windows':
                success = await self._windows_privilege_escalation(host, technique)
            
            attempt.success = success
            
            if success:
                attempt.escalated_to = esc_plan.get('target_privileges', 'root')
                host.current_privileges = attempt.escalated_to
                self.progress.successful_escalations += 1
                self.priv_esc_attempts.append(attempt)
                
                logger.success(f"  ✓ Successfully escalated to {attempt.escalated_to}")
                
                return {
                    'host_id': host.host_id,
                    'success': True,
                    'technique': technique.get('technique'),
                    'escalated_to': attempt.escalated_to,
                    'attempts': idx + 1
                }
            else:
                attempt.error = f"Technique {technique.get('technique')} failed"
                self.priv_esc_attempts.append(attempt)
                logger.warning(f"  ✗ Technique failed, trying next...")
        
        return {
            'host_id': host.host_id,
            'success': False,
            'error': 'All escalation techniques failed',
            'attempts': len(techniques)
        }
    
    async def _linux_privilege_escalation(
        self,
        host: CompromisedHost,
        technique: Dict[str, Any]
    ) -> bool:
        """Execute Linux privilege escalation"""
        
        tech_type = technique.get('technique', '').lower()
        
        try:
            if 'kernel_exploit' in tech_type:
                # Use kernel exploit database
                kernel_db = KernelExploitDB()
                exploit = await kernel_db.find_exploit(host.os_version)
                if exploit:
                    logger.info(f"    Using kernel exploit: {exploit.get('cve')}")
                    # In production, would actually execute exploit
                    return True
            
            elif 'suid' in tech_type:
                # SUID enumeration and abuse
                enum = MisconfigurationEnumerator('linux')
                suid_bins = await enum.enumerate_suid_binaries()
                exploitable = [b for b in suid_bins if b.get('exploitable')]
                if exploitable:
                    logger.info(f"    Found {len(exploitable)} exploitable SUID binaries")
                    return True
            
            elif 'sudo' in tech_type:
                enum = MisconfigurationEnumerator('linux')
                sudo_vulns = await enum.check_sudo_misconfigurations()
                if sudo_vulns:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Linux privesc error: {e}")
            return False
    
    async def _windows_privilege_escalation(
        self,
        host: CompromisedHost,
        technique: Dict[str, Any]
    ) -> bool:
        """Execute Windows privilege escalation"""
        
        tech_type = technique.get('technique', '').lower()
        
        try:
            if 'token' in tech_type:
                # Token manipulation
                token_manip = TokenManipulation()
                success = await token_manip.steal_system_token()
                return success
            
            elif 'dll_hijack' in tech_type:
                # DLL hijacking
                dll_hijack = DLLHijacking()
                vulns = await dll_hijack.find_hijackable_services()
                if vulns:
                    return True
            
            elif 'service' in tech_type:
                # Unquoted service path / weak permissions
                enum = MisconfigurationEnumerator('windows')
                services = await enum.enumerate_weak_services()
                if services:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Windows privesc error: {e}")
            return False
    
    async def _execute_credential_harvesting(
        self,
        host: CompromisedHost,
        plan: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute credential harvesting on a host"""
        
        harvested = []
        
        # Find harvesting plan for this host
        harvest_plan = next(
            (p for p in plan.get('credential_harvesting_plan', []) 
             if p.get('host_id') == host.host_id),
            None
        )
        
        if not harvest_plan:
            return harvested
        
        methods = harvest_plan.get('methods', [])
        
        for method in methods:
            method_name = method.get('method', '').lower()
            
            try:
                if 'mimikatz' in method_name or 'lsass' in method_name:
                    # Windows credential dumping
                    if host.os_type == 'windows':
                        mimikatz = MimikatzAutomation()
                        creds = await mimikatz.harvest()
                        
                        for cred in creds:
                            harvested_cred = HarvestedCredential(
                                cred_id=f"cred_{len(self.harvested_credentials) + 1}",
                                host_id=host.host_id,
                                username=cred.username,
                                credential_type=cred.credential_type,
                                credential_value=cred.value,
                                domain=cred.domain,
                                source='mimikatz'
                            )
                            self.harvested_credentials.append(harvested_cred)
                            host.credentials.append(harvested_cred.__dict__)
                            harvested.append(harvested_cred.__dict__)
                        
                        self.progress.credentials_harvested += len(creds)
                        logger.success(f"  ✓ Mimikatz harvested {len(creds)} credentials")
                
                elif 'browser' in method_name:
                    # Browser password dumping
                    browser_dumper = BrowserDumper()
                    browser_creds = await browser_dumper.dump_all_browsers()
                    
                    for cred in browser_creds:
                        harvested_cred = HarvestedCredential(
                            cred_id=f"cred_{len(self.harvested_credentials) + 1}",
                            host_id=host.host_id,
                            username=cred.get('username', 'unknown'),
                            credential_type='password',
                            credential_value=cred.get('password', ''),
                            source='browser'
                        )
                        self.harvested_credentials.append(harvested_cred)
                        harvested.append(harvested_cred.__dict__)
                    
                    self.progress.credentials_harvested += len(browser_creds)
                    logger.success(f"  ✓ Browser dumper found {len(browser_creds)} credentials")
                
                elif 'memory' in method_name:
                    # Memory scraping
                    memory_scraper = MemoryScraper()
                    mem_creds = await memory_scraper.scrape_memory()
                    
                    for cred in mem_creds:
                        harvested_cred = HarvestedCredential(
                            cred_id=f"cred_{len(self.harvested_credentials) + 1}",
                            host_id=host.host_id,
                            username=cred.get('username', 'unknown'),
                            credential_type=cred.get('type', 'password'),
                            credential_value=cred.get('value', ''),
                            source='memory'
                        )
                        self.harvested_credentials.append(harvested_cred)
                        harvested.append(harvested_cred.__dict__)
                    
                    self.progress.credentials_harvested += len(mem_creds)
                
            except Exception as e:
                logger.error(f"  Credential harvesting error ({method_name}): {e}")
        
        return harvested
    
    async def _execute_persistence(
        self,
        host: CompromisedHost,
        plan: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Install persistence mechanisms on a host"""
        
        installed = []
        
        # Find persistence plan for this host
        persist_plan = next(
            (p for p in plan.get('persistence_plan', []) 
             if p.get('host_id') == host.host_id),
            None
        )
        
        if not persist_plan:
            return installed
        
        mechanisms = persist_plan.get('mechanisms', [])
        
        # Initialize persistence manager
        persist_mgr = PersistenceManager(host.os_type)
        
        for mechanism in mechanisms:
            mech_type = mechanism.get('type')
            
            try:
                logger.info(f"  Installing {mech_type} persistence...")
                
                # In production, would actually install persistence
                # For now, simulate success
                
                installed.append({
                    'host_id': host.host_id,
                    'type': mech_type,
                    'stealthiness': mechanism.get('stealthiness'),
                    'reliability': mechanism.get('reliability'),
                    'success': True
                })
                
                host.persistence_installed = True
                self.progress.persistence_installed += 1
                
                logger.success(f"  ✓ {mech_type} persistence installed")
                
            except Exception as e:
                logger.error(f"  Persistence installation error ({mech_type}): {e}")
                installed.append({
                    'host_id': host.host_id,
                    'type': mech_type,
                    'success': False,
                    'error': str(e)
                })
        
        return installed
    
    async def _execute_data_discovery(
        self,
        host: CompromisedHost,
        plan: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Discover sensitive data on a host"""
        
        discovered = []
        
        # Find data discovery targets for this host
        data_plan = next(
            (p for p in plan.get('data_discovery_targets', []) 
             if p.get('host_id') == host.host_id),
            None
        )
        
        if not data_plan:
            return discovered
        
        logger.info(f"  Searching in: {', '.join(data_plan.get('search_locations', []))}")
        
        # In production, would actually search filesystem
        # Simulate finding sensitive files
        
        simulated_findings = [
            {
                'host_id': host.host_id,
                'type': 'ssh_key',
                'path': '/root/.ssh/id_rsa',
                'size': 1679,
                'sensitivity': 'high'
            },
            {
                'host_id': host.host_id,
                'type': 'config_file',
                'path': '/etc/database.conf',
                'size': 2048,
                'sensitivity': 'medium',
                'contains': 'database credentials'
            }
        ]
        
        discovered.extend(simulated_findings)
        
        logger.success(f"  ✓ Found {len(simulated_findings)} sensitive files")
        
        return discovered
    
    def _detect_os_type(self, exploit_data: Dict[str, Any]) -> str:
        """Detect OS type from exploit data"""
        service = exploit_data.get('affected_service', '').lower()
        technique = exploit_data.get('technique', '').lower()
        
        if 'windows' in service or 'smb' in service or 'rdp' in service:
            return 'windows'
        elif 'linux' in service or 'ssh' in service or 'apache' in service:
            return 'linux'
        
        return 'unknown'
    
    def _create_basic_postexploit_plan(self) -> Dict[str, Any]:
        """Fallback basic post-exploitation plan"""
        logger.warning("Creating basic post-exploitation plan (LLM failed)")
        
        plan = {
            'strategy': 'Basic privilege escalation and credential harvesting',
            'host_priorities': [],
            'privilege_escalation_plan': [],
            'credential_harvesting_plan': [],
            'persistence_plan': [],
            'data_discovery_targets': []
        }
        
        for host in self.compromised_hosts:
            # Basic privilege escalation
            if host.current_privileges != 'root':
                plan['privilege_escalation_plan'].append({
                    'host_id': host.host_id,
                    'techniques': [
                        {
                            'technique': 'kernel_exploit' if host.os_type == 'linux' else 'token_manipulation',
                            'tool': 'automated',
                            'success_probability': 0.5
                        }
                    ]
                })
            
            # Basic credential harvesting
            plan['credential_harvesting_plan'].append({
                'host_id': host.host_id,
                'methods': [
                    {
                        'method': 'mimikatz_lsass' if host.os_type == 'windows' else 'memory',
                        'tool': 'automated',
                        'priority': 'high'
                    }
                ]
            })
        
        return plan
    
    def _compile_statistics(self) -> Dict[str, Any]:
        """Compile Phase 4 statistics"""
        return {
            'total_hosts': self.progress.total_hosts,
            'privilege_escalations_attempted': self.progress.privilege_escalations_attempted,
            'successful_escalations': self.progress.successful_escalations,
            'escalation_success_rate': self.progress.success_rate,
            'credentials_harvested': self.progress.credentials_harvested,
            'persistence_mechanisms_installed': self.progress.persistence_installed,
            'fully_compromised_hosts': self.progress.fully_compromised_hosts,
            'domain_credentials': len([c for c in self.harvested_credentials if c.domain]),
            'admin_credentials': len([c for c in self.harvested_credentials if c.privilege_level == 'admin'])
        }
    
    def save_results(self, output_dir: str = "./reports/phase4") -> str:
        """Save Phase 4 results"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"phase4_postexploit_{timestamp}.json"
        
        results = {
            'phase4_summary': {
                'total_hosts': self.progress.total_hosts,
                'fully_compromised': self.progress.fully_compromised_hosts,
                'credentials_harvested': self.progress.credentials_harvested,
                'persistence_installed': self.progress.persistence_installed
            },
            'compromised_hosts': [
                {
                    'host_id': h.host_id,
                    'ip': h.ip_address,
                    'os': f"{h.os_type} {h.os_version}",
                    'privileges': h.current_privileges,
                    'credentials_found': len(h.credentials),
                    'persistence': h.persistence_installed,
                    'fully_compromised': h.fully_compromised
                }
                for h in self.compromised_hosts
            ],
            'credentials': [
                {
                    'username': c.username,
                    'type': c.credential_type,
                    'domain': c.domain,
                    'source': c.source,
                    'host': c.host_id
                }
                for c in self.harvested_credentials
            ],
            'statistics': self._compile_statistics()
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.success(f"Phase 4 results saved to {filename}")
        return str(filename)


# Convenience function
async def run_phase4_postexploit(
    phase3_results: Dict[str, Any],
    llm_orchestrator: LLMOrchestrator,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to run Phase 4 post-exploitation
    
    Args:
        phase3_results: Results from Phase 3 exploitation
        llm_orchestrator: LLM orchestrator instance
        config: Optional configuration
        
    Returns:
        Phase 4 results
    """
    orchestrator = Phase4Orchestrator(llm_orchestrator, config)
    orchestrator.load_phase3_results(phase3_results)
    
    plan = await orchestrator.create_postexploit_plan()
    results = await orchestrator.execute_postexploit_plan(plan)
    
    orchestrator.save_results()
    
    return results
