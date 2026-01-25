"""
Phase 2 Orchestrator - Advanced Scanning & Vulnerability Assessment
Bridges reconnaissance (Phase 1) and exploitation (Phase 3+) with intelligent vulnerability detection
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


@dataclass
class VulnerabilityFinding:
    """Represents a discovered vulnerability"""
    vuln_id: str  # CVE-ID or custom identifier
    title: str
    severity: str  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    description: str = ""
    affected_target: str = ""
    affected_service: str = ""
    affected_version: str = ""
    exploit_available: bool = False
    exploit_references: List[str] = field(default_factory=list)
    remediation: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    tool_source: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'description': self.description,
            'affected_target': self.affected_target,
            'affected_service': self.affected_service,
            'affected_version': self.affected_version,
            'exploit_available': self.exploit_available,
            'exploit_references': self.exploit_references,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'tool_source': self.tool_source,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ScanTask:
    """Represents a vulnerability scanning task"""
    task_id: str
    task_type: str  # web_scan, cve_match, network_vuln, ssl_test, etc.
    target: str
    tool: str
    priority: int = 5  # 1-10, higher = more urgent
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # Task IDs that must complete first
    status: str = "pending"  # pending, running, completed, failed, skipped
    result: Optional[Any] = None
    error: Optional[str] = None
    duration: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class Phase2Progress:
    """Track Phase 2 scanning progress"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    vulnerabilities_found: int = 0
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    
    @property
    def percentage(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100
    
    @property
    def eta_seconds(self) -> Optional[float]:
        if self.completed_tasks == 0:
            return None
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        avg_time_per_task = elapsed / self.completed_tasks
        remaining_tasks = self.total_tasks - self.completed_tasks
        
        return avg_time_per_task * remaining_tasks
    
    @property
    def eta_formatted(self) -> str:
        eta = self.eta_seconds
        if eta is None:
            return "Calculating..."
        
        if eta < 60:
            return f"{int(eta)}s"
        elif eta < 3600:
            return f"{int(eta / 60)}m {int(eta % 60)}s"
        else:
            hours = int(eta / 3600)
            minutes = int((eta % 3600) / 60)
            return f"{hours}h {minutes}m"


class Phase2Orchestrator:
    """
    Orchestrates Phase 2: Advanced Scanning & Vulnerability Assessment
    
    Workflow:
    1. Consumes Phase 1 reconnaissance data
    2. Analyzes attack surface and creates scan plan
    3. Executes web vulnerability scans (SQLi, XSS, etc.)
    4. Performs CVE correlation against discovered services
    5. Conducts network vulnerability assessments
    6. Prioritizes findings based on severity and exploitability
    7. Prepares actionable targets for Phase 3+ exploitation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.progress = Phase2Progress()
        self.scan_tasks: List[ScanTask] = []
        self.vulnerabilities: List[VulnerabilityFinding] = []
        self.phase1_data: Optional[Dict[str, Any]] = None
        self.attack_surface: Dict[str, Any] = {}
        
        # Configure scanning modes
        self.scan_mode = self.config.get('scan_mode', 'balanced')  # quick, balanced, deep, aggressive
        self.stealth_mode = self.config.get('stealth_mode', False)
        self.max_parallel_tasks = self.config.get('max_parallel_tasks', 5)
        self.timeout_per_task = self.config.get('timeout_per_task', 300)  # 5 minutes default
        
        # Tool configuration
        self.enable_web_scanning = self.config.get('enable_web_scanning', True)
        self.enable_cve_matching = self.config.get('enable_cve_matching', True)
        self.enable_network_vuln = self.config.get('enable_network_vuln', True)
        self.enable_ssl_testing = self.config.get('enable_ssl_testing', True)
        self.enable_default_creds = self.config.get('enable_default_creds', True)
        
        # Import modules (lazy loading)
        self._tools_loaded = False
        self._sqlmap = None
        self._nikto = None
        self._cve_matcher = None
        self._ssl_tester = None
        
        logger.info(f"Phase 2 Orchestrator initialized - Mode: {self.scan_mode}, Stealth: {self.stealth_mode}")
    
    def load_phase1_results(self, phase1_data: Dict[str, Any]) -> None:
        """Load and process Phase 1 reconnaissance results"""
        logger.info("Loading Phase 1 reconnaissance data...")
        self.phase1_data = phase1_data
        
        # Extract key information
        self._extract_targets()
        self._analyze_attack_surface()
        
        logger.success(f"Phase 1 data loaded - Found {len(self.attack_surface.get('web_targets', []))} web targets, "
                      f"{len(self.attack_surface.get('network_services', []))} network services")
    
    def _extract_targets(self) -> None:
        """Extract actionable targets from Phase 1 data"""
        self.attack_surface = {
            'web_targets': [],
            'network_services': [],
            'hosts': [],
            'domains': [],
            'subdomains': []
        }
        
        if not self.phase1_data:
            return
        
        # Extract web targets (HTTP/HTTPS services)
        nmap_results = self.phase1_data.get('nmap_scan', {})
        if isinstance(nmap_results, dict):
            hosts = nmap_results.get('hosts', [])
            for host in hosts:
                host_ip = host.get('ip', '')
                ports = host.get('ports', [])
                
                if host_ip:
                    self.attack_surface['hosts'].append(host_ip)
                
                for port_info in ports:
                    port = port_info.get('port')
                    service = port_info.get('service', '').lower()
                    state = port_info.get('state', '')
                    version = port_info.get('version', '')
                    
                    if state != 'open':
                        continue
                    
                    # Web services
                    if service in ['http', 'https', 'ssl/http'] or port in [80, 443, 8080, 8443]:
                        protocol = 'https' if service == 'https' or port in [443, 8443] else 'http'
                        url = f"{protocol}://{host_ip}:{port}"
                        self.attack_surface['web_targets'].append({
                            'url': url,
                            'ip': host_ip,
                            'port': port,
                            'service': service,
                            'version': version
                        })
                    
                    # Other network services
                    else:
                        self.attack_surface['network_services'].append({
                            'ip': host_ip,
                            'port': port,
                            'service': service,
                            'version': version,
                            'state': state
                        })
        
        # Extract domains and subdomains
        dns_results = self.phase1_data.get('dns_enumeration', {})
        if isinstance(dns_results, dict):
            self.attack_surface['domains'] = dns_results.get('domains', [])
            self.attack_surface['subdomains'] = dns_results.get('subdomains', [])
            
            # Add web targets from domains
            for domain in self.attack_surface['domains'] + self.attack_surface['subdomains']:
                for protocol in ['https', 'http']:
                    self.attack_surface['web_targets'].append({
                        'url': f"{protocol}://{domain}",
                        'domain': domain,
                        'service': protocol
                    })
    
    def _analyze_attack_surface(self) -> None:
        """Analyze attack surface to prioritize targets"""
        logger.info("Analyzing attack surface...")
        
        # Prioritize targets based on:
        # 1. Service type (web apps > databases > other services)
        # 2. Version information availability
        # 3. Known vulnerable versions
        # 4. Default configurations
        
        analysis = {
            'high_priority_targets': [],
            'medium_priority_targets': [],
            'low_priority_targets': [],
            'statistics': {
                'total_web_targets': len(self.attack_surface.get('web_targets', [])),
                'total_network_services': len(self.attack_surface.get('network_services', [])),
                'services_with_versions': 0,
                'potentially_vulnerable': 0
            }
        }
        
        # Analyze network services
        for service in self.attack_surface.get('network_services', []):
            if service.get('version'):
                analysis['statistics']['services_with_versions'] += 1
                # High priority if database or critical service
                if service.get('service') in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis', 'ssh', 'ftp', 'smb']:
                    analysis['high_priority_targets'].append(service)
                else:
                    analysis['medium_priority_targets'].append(service)
            else:
                analysis['low_priority_targets'].append(service)
        
        # All web targets are high priority
        analysis['high_priority_targets'].extend(self.attack_surface.get('web_targets', []))
        
        self.attack_surface['analysis'] = analysis
        
        logger.info(f"Attack surface analysis complete - "
                   f"High priority: {len(analysis['high_priority_targets'])}, "
                   f"Medium: {len(analysis['medium_priority_targets'])}, "
                   f"Low: {len(analysis['low_priority_targets'])}")
    
    def create_scan_plan(self) -> List[ScanTask]:
        """Create intelligent scan plan based on attack surface"""
        logger.info("Creating scan plan...")
        tasks = []
        task_counter = 0
        
        # Web vulnerability scanning tasks
        if self.enable_web_scanning:
            for web_target in self.attack_surface.get('web_targets', []):
                # SQLMap scan
                task_counter += 1
                tasks.append(ScanTask(
                    task_id=f"web_sqli_{task_counter}",
                    task_type="web_sqli",
                    target=web_target['url'],
                    tool="sqlmap",
                    priority=8,
                    params={'crawl_depth': 2 if self.scan_mode == 'deep' else 1}
                ))
                
                # Nikto web server scan
                task_counter += 1
                tasks.append(ScanTask(
                    task_id=f"web_nikto_{task_counter}",
                    task_type="web_scan",
                    target=web_target['url'],
                    tool="nikto",
                    priority=7
                ))
                
                # XSS scanning
                task_counter += 1
                tasks.append(ScanTask(
                    task_id=f"web_xss_{task_counter}",
                    task_type="web_xss",
                    target=web_target['url'],
                    tool="xss_scanner",
                    priority=7
                ))
        
        # CVE matching for services with versions
        if self.enable_cve_matching:
            for service in self.attack_surface.get('network_services', []):
                if service.get('version'):
                    task_counter += 1
                    tasks.append(ScanTask(
                        task_id=f"cve_match_{task_counter}",
                        task_type="cve_correlation",
                        target=f"{service['ip']}:{service['port']}",
                        tool="cve_matcher",
                        priority=9,
                        params={
                            'service': service.get('service'),
                            'version': service.get('version')
                        }
                    ))
        
        # SSL/TLS testing
        if self.enable_ssl_testing:
            for web_target in self.attack_surface.get('web_targets', []):
                if web_target.get('url', '').startswith('https'):
                    task_counter += 1
                    tasks.append(ScanTask(
                        task_id=f"ssl_test_{task_counter}",
                        task_type="ssl_analysis",
                        target=web_target['url'],
                        tool="ssl_tester",
                        priority=6
                    ))
        
        # Network vulnerability scans
        if self.enable_network_vuln:
            for service in self.attack_surface.get('network_services', []):
                # Focus on common vulnerable services
                if service.get('service') in ['smb', 'ssh', 'ftp', 'mysql', 'postgresql', 'mongodb', 'redis']:
                    task_counter += 1
                    tasks.append(ScanTask(
                        task_id=f"net_vuln_{task_counter}",
                        task_type="network_vulnerability",
                        target=f"{service['ip']}:{service['port']}",
                        tool="nmap_vuln_scripts",
                        priority=7,
                        params={'service': service.get('service')}
                    ))
        
        # Sort by priority (descending)
        tasks.sort(key=lambda x: x.priority, reverse=True)
        
        self.scan_tasks = tasks
        self.progress.total_tasks = len(tasks)
        
        logger.success(f"Scan plan created - {len(tasks)} tasks planned")
        return tasks
    
    async def execute_scan_plan(self, callback=None) -> Dict[str, Any]:
        """Execute the scan plan with parallel task execution"""
        logger.info("Starting Phase 2 vulnerability scanning...")
        self.progress.start_time = datetime.now()
        
        # Load tools
        await self._load_tools()
        
        # Execute tasks in priority order with parallelization
        pending_tasks = [task for task in self.scan_tasks if task.status == "pending"]
        running_tasks: List[asyncio.Task] = []
        
        while pending_tasks or running_tasks:
            # Start new tasks up to max_parallel_tasks
            while len(running_tasks) < self.max_parallel_tasks and pending_tasks:
                # Get highest priority task that has dependencies met
                task_to_run = None
                for task in pending_tasks:
                    deps_met = all(
                        any(t.task_id == dep_id and t.status == "completed" 
                            for t in self.scan_tasks)
                        for dep_id in task.dependencies
                    ) if task.dependencies else True
                    
                    if deps_met:
                        task_to_run = task
                        break
                
                if not task_to_run:
                    break
                
                pending_tasks.remove(task_to_run)
                task_to_run.status = "running"
                task_to_run.start_time = datetime.now()
                
                # Create async task
                async_task = asyncio.create_task(self._execute_scan_task(task_to_run))
                running_tasks.append(async_task)
                
                logger.info(f"Started task: {task_to_run.task_id} ({task_to_run.task_type}) - Priority: {task_to_run.priority}")
            
            # Wait for at least one task to complete
            if running_tasks:
                done, running_tasks = await asyncio.wait(
                    running_tasks,
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=1.0
                )
                
                for completed_task in done:
                    try:
                        await completed_task
                    except Exception as e:
                        logger.error(f"Task execution error: {e}")
                
                # Update progress callback
                if callback:
                    callback(self.progress)
            else:
                # No tasks running and no pending tasks with met dependencies
                if pending_tasks:
                    logger.warning(f"{len(pending_tasks)} tasks have unmet dependencies")
                break
        
        # Compile results
        results = self._compile_results()
        
        logger.success(f"Phase 2 scanning complete - Found {self.progress.vulnerabilities_found} vulnerabilities "
                      f"({self.progress.critical_vulns} critical, {self.progress.high_vulns} high)")
        
        return results
    
    async def _execute_scan_task(self, task: ScanTask) -> None:
        """Execute a single scan task"""
        try:
            # Route to appropriate scanner based on task type
            if task.task_type == "web_sqli":
                result = await self._run_sqlmap(task)
            elif task.task_type == "web_scan":
                result = await self._run_nikto(task)
            elif task.task_type == "web_xss":
                result = await self._run_xss_scanner(task)
            elif task.task_type == "cve_correlation":
                result = await self._run_cve_matcher(task)
            elif task.task_type == "ssl_analysis":
                result = await self._run_ssl_tester(task)
            elif task.task_type == "network_vulnerability":
                result = await self._run_network_vuln_scanner(task)
            else:
                logger.warning(f"Unknown task type: {task.task_type}")
                task.status = "skipped"
                self.progress.skipped_tasks += 1
                return
            
            task.result = result
            task.status = "completed"
            task.end_time = datetime.now()
            task.duration = (task.end_time - task.start_time).total_seconds()
            self.progress.completed_tasks += 1
            
            # Extract vulnerabilities from result
            if result and result.get('vulnerabilities'):
                for vuln in result['vulnerabilities']:
                    self._add_vulnerability(vuln)
            
            logger.success(f"Completed: {task.task_id} in {task.duration:.1f}s")
            
        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}")
            task.status = "failed"
            task.error = str(e)
            task.end_time = datetime.now()
            self.progress.failed_tasks += 1
    
    def _add_vulnerability(self, vuln_data: Dict[str, Any]) -> None:
        """Add a vulnerability finding and update statistics"""
        vuln = VulnerabilityFinding(
            vuln_id=vuln_data.get('vuln_id', f'VULN-{len(self.vulnerabilities) + 1}'),
            title=vuln_data.get('title', 'Unknown Vulnerability'),
            severity=vuln_data.get('severity', 'info').lower(),
            cvss_score=vuln_data.get('cvss_score'),
            description=vuln_data.get('description', ''),
            affected_target=vuln_data.get('affected_target', ''),
            affected_service=vuln_data.get('affected_service', ''),
            affected_version=vuln_data.get('affected_version', ''),
            exploit_available=vuln_data.get('exploit_available', False),
            exploit_references=vuln_data.get('exploit_references', []),
            remediation=vuln_data.get('remediation', ''),
            confidence=vuln_data.get('confidence', 1.0),
            evidence=vuln_data.get('evidence', []),
            tool_source=vuln_data.get('tool_source', '')
        )
        
        self.vulnerabilities.append(vuln)
        self.progress.vulnerabilities_found += 1
        
        # Update severity counters
        if vuln.severity == 'critical':
            self.progress.critical_vulns += 1
        elif vuln.severity == 'high':
            self.progress.high_vulns += 1
        elif vuln.severity == 'medium':
            self.progress.medium_vulns += 1
        elif vuln.severity == 'low':
            self.progress.low_vulns += 1
    
    async def _load_tools(self) -> None:
        """Lazy load scanning tools"""
        if self._tools_loaded:
            return
        
        try:
            # Import scanning modules
            from modules.sqlmap_scanner import SQLMapScanner
            from modules.nikto_scanner import NiktoScanner
            from modules.xss_scanner import XSSScanner
            from modules.cve_correlation import CVECorrelationEngine
            from modules.ssl_tester import SSLTester
            
            self._sqlmap = SQLMapScanner()
            self._nikto = NiktoScanner()
            self._xss_scanner = XSSScanner()
            self._cve_matcher = CVECorrelationEngine()
            self._ssl_tester = SSLTester()
            
            logger.info("Scanning tools loaded successfully")
            self._tools_loaded = True
            
        except Exception as e:
            logger.warning(f"Some tools could not be loaded: {e}")
            self._tools_loaded = True  # Continue with available tools
    
    async def _run_sqlmap(self, task: ScanTask) -> Dict[str, Any]:
        """Run SQLMap SQL injection scanner"""
        if not self._sqlmap:
            return {'tool': 'sqlmap', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
        
        logger.info(f"Running SQLMap on {task.target}")
        
        try:
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._sqlmap.scan(
                    task.target,
                    {'batch': True, 'level': 1, 'risk': 1, 'crawl': task.params.get('crawl_depth', 1)}
        if not self._nikto:
            return {'tool': 'nikto', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
        
        logger.info(f"Running Nikto on {task.target}")
        
        try:
            loop = asyncio.get_event_loop()
            
            # Choose scan type based on stealth mode
            if self.stealth_mode:
                scan_func = lambda: self._nikto.stealth_scan(task.target)
            else:
                scan_func = lambda: self._nikto.quick_scan(task.target)
            
            result = await loop.run_in_executor(None, scan_func)
            
            return {
                'tool': 'nikto',
                'target': task.target,
                'vulnerabilities': result.get('vulnerabilities', []),
                'raw_result': result,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"Nikto error: {e}")
            return {'tool': 'nikto', 'target': task.target, 'vulnerabilities': [], 'error': str(e), 'status': 'failed'            'title': 'SQL Injection Vulnerability',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'description': f'SQL injection found in {task.target}. '
                                 f'Injection types: {", ".join(result.get("injection_type", []))}',
                    'affected_target': task.target,
                    'affected_service': 'web',
                    'exploit_available': True,
                    'tool_source': 'sqlmap',
                    'confidence': 1.0,
                    'evidence': result.get('payloads', [])[:5],
                    'remediation': 'Use parameterized queries/prepared statements. Implement input validation and WAF.'
                })
            
            return {
                'tool': 'sqlmap',
                'target': task.target,
                'vulnerabilities': vulnerabilities,
                'raw_result': result,
                'status': 'completed'
            }
            
        if not self._xss_scanner:
            return {'tool': 'xss_scanner', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
        
        logger.info(f"Running XSS scanner on {task.target}")
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._xss_scanner.scan_url(task.target, crawl=(self.scan_mode in ['deep', 'aggressive']))
            )
            
            return {
                'tool': 'xss_scanner',
                'target': task.target,
                'vulnerabilities': result.get('vulnerabilities', []),
                'raw_result': result,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"XSS scanner error: {e}")
            return {'tool': 'xss_scanner', 'target': task.target, 'vulnerabilities': [], 'error': str(e), 'status': 'failed'
        return {
            'tool': 'nikto',
            'target': task.target,
            'vulnerabilities': [],
            'status': 'completed'
        }
    
    asynif not self._cve_matcher:
            return {'tool': 'cve_matcher', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
        
        logger.info(f"Running CVE matcher for {task.target}")
        
        try:
            service = task.params.get('service', '')
            version = task.params.get('version', '')
            vendor = task.params.get('vendor')
            
            if not service or not version:
                return {'tool': 'cve_matcher', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._cve_matcher.correlate_service(service, version, vendor)
            )
            
            # Generate vulnerability findings
            vulnerabilities = self._cve_matcher.generate_vulnerabilities(result, task.target)
            
            return {
                'tool': 'cve_matcher',
                'target': task.target,
                'vulnerabilities': vulnerabilities,
                'raw_result': result,
        if not self._ssl_tester:
            return {'tool': 'ssl_tester', 'target': task.target, 'vulnerabilities': [], 'status': 'skipped'}
        
        logger.info(f"Running SSL/TLS test on {task.target}")
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._ssl_tester.test_url(task.target)
            )
            
            return {
                'tool': 'ssl_tester',
                'target': task.target,
                'vulnerabilities': result.get('vulnerabilities', []),
                'raw_result': result,
                'status': 'completed'
            }
            
        except Exception as e:
            logger.error(f"SSL tester error: {e}")
            return {'tool': 'ssl_tester', 'target': task.target, 'vulnerabilities': [], 'error': str(e), 'status': 'failed'c def _run_cve_matcher(self, task: ScanTask) -> Dict[str, Any]:
        """Run CVE correlation against service versions"""
        logger.info(f"Running CVE matcher for {task.target}")
        await asyncio.sleep(0.2)
        
        # This will use the CVE correlation engine (to be implemented)
        return {
            'tool': 'cve_matcher',
            'target': task.target,
            'vulnerabilities': [],
            'status': 'completed'
        }
    
    async def _run_ssl_tester(self, task: ScanTask) -> Dict[str, Any]:
        """Run SSL/TLS security tester"""
        logger.info(f"Running SSL/TLS test on {task.target}")
        await asyncio.sleep(0.4)
        
        return {
            'tool': 'ssl_tester',
            'target': task.target,
            'vulnerabilities': [],
            'status': 'completed'
        }
    
    async def _run_network_vuln_scanner(self, task: ScanTask) -> Dict[str, Any]:
        """Run network vulnerability scanner"""
        logger.info(f"Running network vulnerability scan on {task.target}")
        await asyncio.sleep(0.6)
        
        return {
            'tool': 'nmap_vuln',
            'target': task.target,
            'vulnerabilities': [],
            'status': 'completed'
        }
    
    def _compile_results(self) -> Dict[str, Any]:
        """Compile all scan results into structured format"""
        # Sort vulnerabilities by severity and CVSS score
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: (
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(v.severity, 0),
                v.cvss_score or 0.0
            ),
            reverse=True
        )
        
        results = {
            'scan_summary': {
                'total_tasks': self.progress.total_tasks,
                'completed_tasks': self.progress.completed_tasks,
                'failed_tasks': self.progress.failed_tasks,
                'skipped_tasks': self.progress.skipped_tasks,
                'scan_duration': (datetime.now() - self.progress.start_time).total_seconds(),
                'scan_mode': self.scan_mode
            },
            'vulnerability_summary': {
                'total': self.progress.vulnerabilities_found,
                'critical': self.progress.critical_vulns,
                'high': self.progress.high_vulns,
                'medium': self.progress.medium_vulns,
                'low': self.progress.low_vulns
            },
            'vulnerabilities': [v.to_dict() for v in sorted_vulns],
            'attack_surface': self.attack_surface,
            'scan_tasks': [
                {
                    'task_id': t.task_id,
                    'type': t.task_type,
                    'target': t.target,
                    'status': t.status,
                    'duration': t.duration
                }
                for t in self.scan_tasks
            ],
            'recommendations': self._generate_recommendations(sorted_vulns)
        }
        
        return results
    
    def _generate_recommendations(self, vulnerabilities: List[VulnerabilityFinding]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation recommendations"""
        recommendations = []
        
        # Group by affected target
        target_vulns = defaultdict(list)
        for vuln in vulnerabilities:
            target_vulns[vuln.affected_target].append(vuln)
        
        # Create recommendations for each target
        for target, vulns in target_vulns.items():
            critical_count = sum(1 for v in vulns if v.severity == 'critical')
            high_count = sum(1 for v in vulns if v.severity == 'high')
            
            if critical_count > 0:
                recommendations.append({
                    'priority': 'critical',
                    'target': target,
                    'message': f'URGENT: {critical_count} critical vulnerabilities found. Immediate remediation required.',
                    'affected_vulns': [v.vuln_id for v in vulns if v.severity == 'critical']
                })
            
            if high_count > 0:
                recommendations.append({
                    'priority': 'high',
                    'target': target,
                    'message': f'{high_count} high-severity vulnerabilities found. Remediate within 48 hours.',
                    'affected_vulns': [v.vuln_id for v in vulns if v.severity == 'high']
                })
        
        return recommendations
    
    def save_results(self, output_dir: str = "./reports/phase2") -> str:
        """Save scan results to file"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"phase2_scan_{timestamp}.json"
        
        results = self._compile_results()
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.success(f"Results saved to {filename}")
        return str(filename)
    
    def export_for_phase3(self) -> Dict[str, Any]:
        """
        Export Phase 2 results in format optimized for Phase 3 exploitation
        
        Returns:
            Dictionary containing vulnerability data ready for exploitation
        """
        logger.info("Exporting Phase 2 results for Phase 3 exploitation")
        
        results = self._compile_results()
        
        # Enhance vulnerability data with exploitation context
        exploitable_vulns = []
        for vuln in results.get('vulnerabilities', []):
            # Only include vulnerabilities with medium+ severity
            if vuln.get('severity') not in ['critical', 'high', 'medium']:
                continue
            
            enhanced_vuln = vuln.copy()
            
            # Add exploitation metadata
            enhanced_vuln['exploitation_priority'] = self._calculate_exploitation_priority(vuln)
            enhanced_vuln['recommended_tools'] = self._recommend_exploitation_tools(vuln)
            enhanced_vuln['attack_vector'] = self._determine_attack_vector(vuln)
            
            exploitable_vulns.append(enhanced_vuln)
        
        # Sort by exploitation priority
        exploitable_vulns.sort(
            key=lambda v: v.get('exploitation_priority', 0),
            reverse=True
        )
        
        export_data = {
            'vulnerabilities': exploitable_vulns,
            'targets': list(set(v.get('affected_target') for v in exploitable_vulns)),
            'summary': {
                'total_exploitable': len(exploitable_vulns),
                'critical_vulns': len([v for v in exploitable_vulns if v.get('severity') == 'critical']),
                'high_vulns': len([v for v in exploitable_vulns if v.get('severity') == 'high']),
                'medium_vulns': len([v for v in exploitable_vulns if v.get('severity') == 'medium']),
                'with_public_exploits': len([v for v in exploitable_vulns if v.get('exploit_available')])
            },
            'attack_surface': results.get('attack_surface', {}),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.success(f"Exported {len(exploitable_vulns)} exploitable vulnerabilities for Phase 3")
        return export_data
    
    def _calculate_exploitation_priority(self, vuln: Dict[str, Any]) -> int:
        """Calculate exploitation priority score (0-100)"""
        priority = 0
        
        # Severity weighting
        severity_scores = {'critical': 40, 'high': 30, 'medium': 15, 'low': 5}
        priority += severity_scores.get(vuln.get('severity'), 0)
        
        # CVSS score weighting
        cvss = vuln.get('cvss_score', 0.0)
        if cvss:
            priority += int(cvss * 3)  # Max 30 points
        
        # Exploit availability
        if vuln.get('exploit_available'):
            priority += 20
        
        # Confidence weighting
        confidence = vuln.get('confidence', 1.0)
        priority = int(priority * confidence)
        
        return min(priority, 100)
    
    def _recommend_exploitation_tools(self, vuln: Dict[str, Any]) -> List[str]:
        """Recommend exploitation tools based on vulnerability"""
        tools = []
        
        vuln_id = vuln.get('vuln_id', '').lower()
        title = vuln.get('title', '').lower()
        service = vuln.get('affected_service', '').lower()
        
        # Metasploit for known CVEs with exploits
        if vuln.get('exploit_available') and 'cve-' in vuln_id:
            tools.append('metasploit')
        
        # Service-specific tools
        if 'sql' in title or 'sql' in service:
            tools.append('sqlmap')
        elif 'web' in service or 'http' in service:
            tools.append('burpsuite')
            tools.append('nikto')
        elif 'ssh' in service:
            tools.append('hydra')
            tools.append('medusa')
        elif 'smb' in service or 'windows' in service:
            tools.append('metasploit')
            tools.append('crackmapexec')
        elif 'ftp' in service:
            tools.append('hydra')
        
        # Custom exploit generator for buffer overflows, etc.
        if any(term in title for term in ['overflow', 'injection', 'deserialization']):
            tools.append('custom_exploit_generator')
        
        # Default to metasploit if no specific tool
        if not tools:
            tools.append('metasploit')
        
        return tools
    
    def _determine_attack_vector(self, vuln: Dict[str, Any]) -> str:
        """Determine attack vector (network, local, adjacent, physical)"""
        service = vuln.get('affected_service', '').lower()
        title = vuln.get('title', '').lower()
        
        # Network-based
        if any(term in service for term in ['http', 'ssh', 'ftp', 'smb', 'rdp', 'telnet']):
            return 'network'
        
        # Remote code execution implies network
        if any(term in title for term in ['remote', 'rce', 'network']):
            return 'network'
        
        # Local exploitation
        if any(term in title for term in ['local', 'privilege escalation', 'kernel']):
            return 'local'
        
        # Adjacent network
        if any(term in title for term in ['wifi', 'bluetooth', 'wireless']):
            return 'adjacent'
        
        # Default to network
        return 'network'


# Convenience function for quick execution
async def run_phase2_scan(phase1_results: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function to run Phase 2 scan
    
    Args:
        phase1_results: Results from Phase 1 reconnaissance
        config: Optional configuration dictionary
        
    Returns:
        Dictionary containing all scan results
    """
    orchestrator = Phase2Orchestrator(config)
    orchestrator.load_phase1_results(phase1_results)
    orchestrator.create_scan_plan()
    results = await orchestrator.execute_scan_plan()
    orchestrator.save_results()
    
    return results
