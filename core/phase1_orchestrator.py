"""
Phase 1 Orchestrator - Intelligent Reconnaissance & OSINT Coordination
Manages the complete Phase 1 workflow with parallel execution, error recovery, and data correlation
"""
import asyncio
import time
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json


@dataclass
class TaskResult:
    """Result from a reconnaissance task"""
    task_name: str
    status: str  # success, failed, skipped
    data: Any
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Phase1Progress:
    """Track Phase 1 progress"""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    estimated_completion: Optional[datetime] = None
    
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


class ToolValidator:
    """Validates and auto-installs required tools"""
    
    TOOLS = {
        'nmap': {
            'command': 'nmap',
            'test_args': ['--version'],
            'install_cmd_linux': 'sudo apt-get install -y nmap',
            'install_cmd_windows': 'winget install nmap',
            'required': True
        },
        'dnsenum': {
            'command': 'dnsenum',
            'test_args': ['--help'],
            'install_cmd_linux': 'sudo apt-get install -y dnsenum',
            'install_cmd_windows': None,  # Manual install
            'required': False
        },
        'whois': {
            'command': 'whois',
            'test_args': ['--version'],
            'install_cmd_linux': 'sudo apt-get install -y whois',
            'install_cmd_windows': None,
            'required': False
        },
        'subfinder': {
            'command': 'subfinder',
            'test_args': ['-version'],
            'install_cmd_linux': 'GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'install_cmd_windows': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'required': False
        },
        'spiderfoot': {
            'command': 'spiderfoot',
            'test_args': ['-h'],
            'install_cmd_linux': 'pip install spiderfoot',
            'install_cmd_windows': 'pip install spiderfoot',
            'required': False
        }
    }
    
    def __init__(self):
        self.available_tools: Set[str] = set()
        self.unavailable_tools: Set[str] = set()
        self._cache_validated = False
    
    async def validate_all(self) -> Dict[str, bool]:
        """Validate all tools"""
        if self._cache_validated:
            return {tool: tool in self.available_tools for tool in self.TOOLS}
        
        results = {}
        tasks = [self.validate_tool(tool_name) for tool_name in self.TOOLS]
        validations = await asyncio.gather(*tasks, return_exceptions=True)
        
        for tool_name, available in zip(self.TOOLS.keys(), validations):
            if isinstance(available, Exception):
                available = False
            results[tool_name] = available
            
            if available:
                self.available_tools.add(tool_name)
            else:
                self.unavailable_tools.add(tool_name)
        
        self._cache_validated = True
        return results
    
    async def validate_tool(self, tool_name: str) -> bool:
        """Validate single tool"""
        if tool_name not in self.TOOLS:
            return False
        
        tool_config = self.TOOLS[tool_name]
        
        try:
            process = await asyncio.create_subprocess_exec(
                tool_config['command'],
                *tool_config['test_args'],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.wait(), timeout=5.0)
            return process.returncode == 0 or process.returncode == 1  # Some tools return 1 for --help
        except (FileNotFoundError, asyncio.TimeoutError):
            return False
        except Exception as e:
            logger.debug(f"Tool validation error for {tool_name}: {e}")
            return False
    
    async def auto_install_tool(self, tool_name: str) -> bool:
        """Attempt to auto-install a tool"""
        if tool_name not in self.TOOLS:
            return False
        
        tool_config = self.TOOLS[tool_name]
        
        import platform
        system = platform.system().lower()
        
        install_cmd = None
        if 'linux' in system:
            install_cmd = tool_config.get('install_cmd_linux')
        elif 'windows' in system:
            install_cmd = tool_config.get('install_cmd_windows')
        
        if not install_cmd:
            logger.warning(f"No auto-install available for {tool_name} on {system}")
            return False
        
        try:
            logger.info(f"Attempting to install {tool_name}...")
            process = await asyncio.create_subprocess_shell(
                install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            
            # Verify installation
            return await self.validate_tool(tool_name)
        except Exception as e:
            logger.error(f"Failed to install {tool_name}: {e}")
            return False


class ResultCache:
    """Cache for DNS, WHOIS, and other slow operations"""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Any] = {}
        self.timestamps: Dict[str, datetime] = {}
        self.ttl_seconds = ttl_seconds
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key not in self.cache:
            return None
        
        if key in self.timestamps:
            age = (datetime.now() - self.timestamps[key]).total_seconds()
            if age > self.ttl_seconds:
                # Expired
                del self.cache[key]
                del self.timestamps[key]
                return None
        
        return self.cache[key]
    
    def set(self, key: str, value: Any):
        """Set cached value"""
        self.cache[key] = value
        self.timestamps[key] = datetime.now()
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
        self.timestamps.clear()


class DataCorrelationEngine:
    """Correlates data from multiple reconnaissance sources"""
    
    def __init__(self):
        self.knowledge_graph = defaultdict(dict)
        self.correlations = []
    
    def add_data(self, source: str, data: Dict[str, Any]):
        """Add data from a source"""
        self.knowledge_graph[source] = data
    
    def correlate(self) -> Dict[str, Any]:
        """Correlate all gathered data"""
        correlations = {
            'ports_and_services': self._correlate_ports_services(),
            'domains_and_ips': self._correlate_domains_ips(),
            'emails_and_breaches': self._correlate_emails_breaches(),
            'technologies_and_vulnerabilities': self._correlate_tech_vulns(),
            'subdomains_and_services': self._correlate_subdomains_services(),
            'whois_and_dns': self._correlate_whois_dns(),
            'attack_surface': self._calculate_attack_surface(),
            'risk_score': self._calculate_risk_score()
        }
        
        return correlations
    
    def _correlate_ports_services(self) -> List[Dict[str, Any]]:
        """Correlate open ports with identified services"""
        correlations = []
        
        # Get port scan results
        nmap_data = self.knowledge_graph.get('nmap', {})
        web_crawl_data = self.knowledge_graph.get('web_crawler', {})
        
        open_ports = nmap_data.get('open_ports', [])
        technologies = web_crawl_data.get('technologies', [])
        
        for port_info in open_ports:
            port = port_info.get('port')
            service = port_info.get('service')
            version = port_info.get('version', '')
            
            # Cross-reference with web technologies
            matching_tech = [tech for tech in technologies if service.lower() in tech.lower()]
            
            if matching_tech:
                correlations.append({
                    'type': 'port_service_match',
                    'port': port,
                    'service': service,
                    'version': version,
                    'web_technologies': matching_tech,
                    'confidence': 'high'
                })
        
        return correlations
    
    def _correlate_domains_ips(self) -> List[Dict[str, Any]]:
        """Correlate domains with IP addresses"""
        correlations = []
        
        dns_data = self.knowledge_graph.get('dns', {})
        whois_data = self.knowledge_graph.get('whois', {})
        subdomain_data = self.knowledge_graph.get('subdomains', {})
        
        # Link subdomains to main domain
        main_domain = whois_data.get('domain', '')
        subdomains = subdomain_data.get('subdomains', [])
        
        if main_domain and subdomains:
            correlations.append({
                'type': 'domain_hierarchy',
                'main_domain': main_domain,
                'subdomains': subdomains,
                'total_subdomains': len(subdomains),
                'confidence': 'high'
            })
        
        return correlations
    
    def _correlate_emails_breaches(self) -> List[Dict[str, Any]]:
        """Correlate found emails with breach data"""
        correlations = []
        
        crawl_data = self.knowledge_graph.get('web_crawler', {})
        breach_data = self.knowledge_graph.get('breach_check', {})
        
        emails = crawl_data.get('emails', [])
        breached_emails = breach_data.get('breached_emails', [])
        
        for email in emails:
            if email in breached_emails:
                breach_details = breach_data.get('details', {}).get(email, {})
                correlations.append({
                    'type': 'email_breach',
                    'email': email,
                    'breach_count': breach_details.get('breach_count', 0),
                    'severity': 'high' if breach_details.get('breach_count', 0) > 2 else 'medium',
                    'confidence': 'confirmed'
                })
        
        return correlations
    
    def _correlate_tech_vulns(self) -> List[Dict[str, Any]]:
        """Correlate detected technologies with known vulnerabilities"""
        correlations = []
        
        crawl_data = self.knowledge_graph.get('web_crawler', {})
        vuln_data = crawl_data.get('potential_vulnerabilities', [])
        technologies = crawl_data.get('technologies', [])
        
        for tech in technologies:
            # Check for outdated versions
            if any(keyword in tech.lower() for keyword in ['wordpress', 'joomla', 'drupal']):
                # Extract version if present
                import re
                version_match = re.search(r'(\d+\.\d+)', tech)
                if version_match:
                    correlations.append({
                        'type': 'technology_version',
                        'technology': tech,
                        'version': version_match.group(1),
                        'recommendation': 'Check for CVEs and update to latest version',
                        'severity': 'medium'
                    })
        
        return correlations
    
    def _correlate_subdomains_services(self) -> List[Dict[str, Any]]:
        """Correlate subdomains with running services"""
        correlations = []
        
        subdomain_data = self.knowledge_graph.get('subdomains', {})
        nmap_data = self.knowledge_graph.get('nmap', {})
        
        subdomains = subdomain_data.get('subdomains', [])
        
        # For each subdomain, note what we know about it
        for subdomain in subdomains:
            correlations.append({
                'type': 'subdomain_mapping',
                'subdomain': subdomain,
                'status': 'discovered',
                'next_action': 'port_scan_recommended'
            })
        
        return correlations
    
    def _correlate_whois_dns(self) -> Dict[str, Any]:
        """Correlate WHOIS and DNS data"""
        whois_data = self.knowledge_graph.get('whois', {})
        dns_data = self.knowledge_graph.get('dns', {})
        
        correlation = {
            'registrar': whois_data.get('registrar'),
            'nameservers': whois_data.get('name_servers', []),
            'creation_date': whois_data.get('creation_date'),
            'dns_records': dns_data.get('dns_records', ''),
            'consistency': 'checking'
        }
        
        return correlation
    
    def _calculate_attack_surface(self) -> Dict[str, Any]:
        """Calculate overall attack surface"""
        nmap_data = self.knowledge_graph.get('nmap', {})
        crawl_data = self.knowledge_graph.get('web_crawler', {})
        subdomain_data = self.knowledge_graph.get('subdomains', {})
        
        attack_surface = {
            'open_ports': len(nmap_data.get('open_ports', [])),
            'web_forms': len(crawl_data.get('forms', [])),
            'file_uploads': sum(1 for form in crawl_data.get('forms', []) if form.get('has_file_upload')),
            'subdomains': len(subdomain_data.get('subdomains', [])),
            'external_dependencies': len(crawl_data.get('external_links', [])),
            'potential_vulnerabilities': len(crawl_data.get('potential_vulnerabilities', [])),
            'technologies_exposed': len(crawl_data.get('technologies', [])),
            'emails_exposed': len(crawl_data.get('emails', []))
        }
        
        # Calculate total surface score
        attack_surface['surface_score'] = (
            attack_surface['open_ports'] * 5 +
            attack_surface['web_forms'] * 3 +
            attack_surface['file_uploads'] * 10 +
            attack_surface['subdomains'] * 2 +
            attack_surface['potential_vulnerabilities'] * 15
        )
        
        return attack_surface
    
    def _calculate_risk_score(self) -> Dict[str, Any]:
        """Calculate overall risk score"""
        attack_surface = self._calculate_attack_surface()
        breach_data = self.knowledge_graph.get('breach_check', {})
        crawl_data = self.knowledge_graph.get('web_crawler', {})
        
        risk_factors = {
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0,
            'total_risk_score': 0
        }
        
        # Count vulnerabilities by severity
        for vuln in crawl_data.get('potential_vulnerabilities', []):
            severity = vuln.get('severity', 'Low').lower()
            if severity == 'high':
                risk_factors['high_risk_count'] += 1
                risk_factors['total_risk_score'] += 10
            elif severity == 'medium':
                risk_factors['medium_risk_count'] += 1
                risk_factors['total_risk_score'] += 5
            else:
                risk_factors['low_risk_count'] += 1
                risk_factors['total_risk_score'] += 1
        
        # Add breach risk
        breached_count = len(breach_data.get('breached_emails', []))
        if breached_count > 0:
            risk_factors['total_risk_score'] += breached_count * 8
        
        # Add attack surface risk
        risk_factors['total_risk_score'] += attack_surface['surface_score'] // 10
        
        # Categorize overall risk
        total = risk_factors['total_risk_score']
        if total > 100:
            risk_factors['risk_level'] = 'CRITICAL'
        elif total > 50:
            risk_factors['risk_level'] = 'HIGH'
        elif total > 20:
            risk_factors['risk_level'] = 'MEDIUM'
        else:
            risk_factors['risk_level'] = 'LOW'
        
        return risk_factors


class Phase1Orchestrator:
    """
    Orchestrates Phase 1 reconnaissance workflow
    - Parallel task execution
    - Error recovery and retry logic
    - Progress tracking with ETA
    - Data correlation
    - Tool validation
    """
    
    def __init__(self, target: str, recon_mode: str = 'balanced'):
        self.target = target
        self.recon_mode = recon_mode
        self.progress = Phase1Progress()
        self.results: Dict[str, TaskResult] = {}
        self.tool_validator = ToolValidator()
        self.cache = ResultCache()
        self.correlation_engine = DataCorrelationEngine()
        self.progress_callback = None
        
        # Retry configuration
        self.max_retries = 3
        self.retry_delay = 2.0  # seconds
    
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, message: str):
        """Update progress and call callback"""
        if self.progress_callback:
            self.progress_callback(message)
    
    async def execute(self, selected_tools: List[str], 
                     osint_tools: List[str] = None,
                     crawler_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Execute Phase 1 reconnaissance
        
        Args:
            selected_tools: List of reconnaissance tools to use
            osint_tools: List of OSINT tools to use
            crawler_config: Web crawler configuration
        
        Returns:
            Complete Phase 1 results with correlations
        """
        logger.info(f"Starting Phase 1 orchestration for target: {self.target}")
        self.progress.start_time = datetime.now()
        
        try:
            # Step 1: Validate tools
            self._update_progress("🔍 Validating tools...")
            await self._validate_and_install_tools(selected_tools + (osint_tools or []))
            
            # Step 2: Plan execution
            execution_plan = self._plan_execution(selected_tools, osint_tools, crawler_config)
            self.progress.total_tasks = len(execution_plan)
            
            # Step 3: Execute reconnaissance (parallel where possible)
            self._update_progress("🚀 Executing reconnaissance tasks...")
            await self._execute_plan(execution_plan)
            
            # Step 4: Correlate results
            self._update_progress("🔗 Correlating data...")
            correlations = await self._correlate_results()
            
            # Step 5: Generate final report
            self._update_progress("📊 Generating report...")
            final_report = self._generate_phase1_report(correlations)
            
            logger.info(f"Phase 1 completed: {self.progress.completed_tasks}/{self.progress.total_tasks} tasks")
            
            return final_report
        
        except Exception as e:
            logger.error(f"Phase 1 orchestration failed: {e}")
            raise
    
    async def _validate_and_install_tools(self, tools: List[str]):
        """Validate and auto-install required tools"""
        validation_results = await self.tool_validator.validate_all()
        
        missing_required = []
        missing_optional = []
        
        for tool in tools:
            if tool not in validation_results:
                continue
            
            if not validation_results[tool]:
                tool_config = self.tool_validator.TOOLS.get(tool, {})
                if tool_config.get('required'):
                    missing_required.append(tool)
                else:
                    missing_optional.append(tool)
        
        # Auto-install missing tools
        for tool in missing_required + missing_optional:
            self._update_progress(f"📦 Installing {tool}...")
            success = await self.tool_validator.auto_install_tool(tool)
            
            if success:
                logger.info(f"Successfully installed {tool}")
                self._update_progress(f"✅ {tool} installed")
            else:
                if tool in missing_required:
                    logger.error(f"Failed to install required tool: {tool}")
                    self._update_progress(f"❌ Failed to install {tool} (required)")
                else:
                    logger.warning(f"Failed to install optional tool: {tool}")
                    self._update_progress(f"⚠️  {tool} unavailable, will skip")
    
    def _plan_execution(self, recon_tools: List[str], 
                       osint_tools: List[str], 
                       crawler_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Plan execution order and parallelization"""
        plan = []
        
        # Phase 1a: Basic reconnaissance (can run in parallel)
        parallel_group_1 = []
        
        if 'dns' in recon_tools:
            parallel_group_1.append({
                'name': 'dns_enumeration',
                'function': 'run_dns_enumeration',
                'parallel_group': 1,
                'cacheable': True
            })
        
        if 'whois' in recon_tools:
            parallel_group_1.append({
                'name': 'whois_lookup',
                'function': 'run_whois',
                'parallel_group': 1,
                'cacheable': True
            })
        
        if 'subdomain' in recon_tools:
            parallel_group_1.append({
                'name': 'subdomain_enumeration',
                'function': 'run_subdomain_enum',
                'parallel_group': 1,
                'cacheable': False
            })
        
        plan.extend(parallel_group_1)
        
        # Phase 1b: Port scanning (depends on DNS but can run alone)
        if 'nmap' in recon_tools or 'port' in recon_tools:
            plan.append({
                'name': 'port_scan',
                'function': 'run_port_scan',
                'parallel_group': 2,
                'cacheable': False
            })
        
        # Phase 1c: Service enumeration (depends on port scan)
        if 'service' in recon_tools:
            plan.append({
                'name': 'service_enumeration',
                'function': 'run_service_enum',
                'parallel_group': 3,
                'depends_on': ['port_scan'],
                'cacheable': False
            })
        
        # Phase 1d: OS detection (can run with service enum)
        if 'os' in recon_tools:
            plan.append({
                'name': 'os_detection',
                'function': 'run_os_detection',
                'parallel_group': 3,
                'cacheable': False
            })
        
        # Phase 2: OSINT (can run in parallel with Phase 1)
        if crawler_config:
            plan.append({
                'name': 'web_crawler',
                'function': 'run_web_crawler',
                'config': crawler_config,
                'parallel_group': 1,  # Can start with Phase 1
                'cacheable': False
            })
        
        if osint_tools:
            if 'spiderfoot' in osint_tools:
                plan.append({
                    'name': 'spiderfoot',
                    'function': 'run_spiderfoot',
                    'parallel_group': 4,
                    'cacheable': False
                })
            
            if 'haveibeenpwned' in osint_tools:
                plan.append({
                    'name': 'breach_check',
                    'function': 'run_breach_check',
                    'parallel_group': 5,
                    'depends_on': ['web_crawler'],  # Needs emails from crawler
                    'cacheable': True
                })
        
        return plan
    
    async def _execute_plan(self, plan: List[Dict[str, Any]]):
        """Execute plan with parallel execution and error recovery"""
        # Group tasks by parallel group
        groups = defaultdict(list)
        for task in plan:
            groups[task['parallel_group']].append(task)
        
        # Execute groups in order
        for group_id in sorted(groups.keys()):
            group_tasks = groups[group_id]
            
            # Execute tasks in this group in parallel
            tasks = [
                self._execute_task_with_retry(task)
                for task in group_tasks
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for task, result in zip(group_tasks, results):
                if isinstance(result, Exception):
                    logger.error(f"Task {task['name']} failed: {result}")
                    self.progress.failed_tasks += 1
                    self._update_progress(f"❌ {task['name']} failed: {str(result)}")
                else:
                    self.progress.completed_tasks += 1
    
    async def _execute_task_with_retry(self, task: Dict[str, Any]) -> TaskResult:
        """Execute task with retry logic"""
        task_name = task['name']
        function_name = task['function']
        
        for attempt in range(self.max_retries):
            try:
                self._update_progress(f"⏳ Running {task_name}...")
                
                # Check cache first
                if task.get('cacheable'):
                    cache_key = f"{task_name}:{self.target}"
                    cached_result = self.cache.get(cache_key)
                    if cached_result:
                        logger.info(f"Using cached result for {task_name}")
                        self._update_progress(f"💾 {task_name} (cached)")
                        return cached_result
                
                # Execute task
                start_time = time.time()
                result = await self._call_task_function(function_name, task)
                duration = time.time() - start_time
                
                task_result = TaskResult(
                    task_name=task_name,
                    status='success',
                    data=result,
                    duration=duration
                )
                
                # Cache if applicable
                if task.get('cacheable'):
                    cache_key = f"{task_name}:{self.target}"
                    self.cache.set(cache_key, task_result)
                
                # Add to correlation engine
                self.correlation_engine.add_data(task_name, result)
                
                # Store result
                self.results[task_name] = task_result
                
                self._update_progress(f"✅ {task_name} completed ({duration:.1f}s)")
                
                return task_result
            
            except Exception as e:
                logger.warning(f"Task {task_name} attempt {attempt + 1} failed: {e}")
                
                if attempt < self.max_retries - 1:
                    # Retry with exponential backoff
                    delay = self.retry_delay * (2 ** attempt)
                    self._update_progress(f"⚠️  {task_name} failed, retrying in {delay:.1f}s...")
                    await asyncio.sleep(delay)
                else:
                    # Final failure
                    error_result = TaskResult(
                        task_name=task_name,
                        status='failed',
                        data=None,
                        error=str(e)
                    )
                    self.results[task_name] = error_result
                    self._update_progress(f"❌ {task_name} failed after {self.max_retries} attempts")
                    
                    # Continue with other tasks instead of failing completely
                    logger.error(f"Task {task_name} permanently failed, continuing with other tasks")
                    raise
    
    async def _call_task_function(self, function_name: str, task: Dict[str, Any]) -> Any:
        """Call the appropriate task function"""
        # Import modules here to avoid circular imports
        from modules.reconnaissance_suite import ReconnaissanceSuite, ReconnaissanceMode
        from modules.web_crawler import InformationGatherer
        from modules.osint_tools import OSINTSuite
        
        suite = ReconnaissanceSuite()
        
        # Map mode to ReconnaissanceMode
        mode_map = {
            'quick': ReconnaissanceMode.QUICK,
            'balanced': ReconnaissanceMode.BALANCED,
            'deep': ReconnaissanceMode.DEEP,
            'stealth': ReconnaissanceMode.STEALTH
        }
        mode = mode_map.get(self.recon_mode, ReconnaissanceMode.BALANCED)
        
        if function_name == 'run_dns_enumeration':
            return suite.dns_recon.enumerate_dns(self.target, mode)
        elif function_name == 'run_whois':
            return suite.whois.lookup(self.target)
        elif function_name == 'run_subdomain_enum':
            return suite.subdomain_enum.enumerate(self.target, mode)
        elif function_name == 'run_port_scan':
            return suite.port_scanner.scan_ports(self.target, mode)
        elif function_name == 'run_service_enum':
            return suite.service_enum.enumerate_services(self.target, mode=mode)
        elif function_name == 'run_os_detection':
            return suite.os_detector.detect_os(self.target, mode)
        elif function_name == 'run_web_crawler':
            config = task.get('config', {})
            gatherer = InformationGatherer(
                config.get('max_depth', 3),
                config.get('max_pages', 50)
            )
            target_url = self.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f'https://{target_url}'
            return gatherer.gather_information(target_url)
        elif function_name == 'run_spiderfoot':
            # Placeholder for SpiderFoot
            return {'status': 'completed', 'findings': []}
        elif function_name == 'run_breach_check':
            # Get emails from web crawler
            crawler_result = self.results.get('web_crawler')
            if crawler_result and crawler_result.status == 'success':
                emails = crawler_result.data.get('emails', [])
                if emails:
                    osint_suite = OSINTSuite()
                    return osint_suite.check_emails_from_list(emails)
            return {'emails_checked': 0, 'breached_emails': [], 'clean_emails': []}
        else:
            raise ValueError(f"Unknown function: {function_name}")
    
    async def _correlate_results(self) -> Dict[str, Any]:
        """Correlate all results"""
        return self.correlation_engine.correlate()
    
    def _generate_phase1_report(self, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final Phase 1 report"""
        return {
            'target': self.target,
            'mode': self.recon_mode,
            'timestamp': datetime.now().isoformat(),
            'progress': {
                'total_tasks': self.progress.total_tasks,
                'completed': self.progress.completed_tasks,
                'failed': self.progress.failed_tasks,
                'percentage': self.progress.percentage
            },
            'task_results': {
                name: {
                    'status': result.status,
                    'duration': result.duration,
                    'error': result.error,
                    'data': result.data
                }
                for name, result in self.results.items()
            },
            'correlations': correlations,
            'summary': self._generate_summary(correlations),
            'recommendations': self._generate_recommendations(correlations)
        }
    
    def _generate_summary(self, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        attack_surface = correlations.get('attack_surface', {})
        risk_score = correlations.get('risk_score', {})
        
        return {
            'attack_surface_score': attack_surface.get('surface_score', 0),
            'risk_level': risk_score.get('risk_level', 'UNKNOWN'),
            'total_risk_score': risk_score.get('total_risk_score', 0),
            'high_risk_findings': risk_score.get('high_risk_count', 0),
            'medium_risk_findings': risk_score.get('medium_risk_count', 0),
            'low_risk_findings': risk_score.get('low_risk_count', 0)
        }
    
    def _generate_recommendations(self, correlations: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        attack_surface = correlations.get('attack_surface', {})
        risk_score = correlations.get('risk_score', {})
        
        # High-level recommendations
        if risk_score.get('risk_level') in ['HIGH', 'CRITICAL']:
            recommendations.append("🔴 CRITICAL: Immediate security review required")
        
        if attack_surface.get('open_ports', 0) > 10:
            recommendations.append("⚠️  Reduce attack surface: Close unnecessary ports")
        
        if attack_surface.get('potential_vulnerabilities', 0) > 0:
            recommendations.append("🔧 Address identified vulnerabilities immediately")
        
        if attack_surface.get('emails_exposed', 0) > 5:
            recommendations.append("📧 Consider implementing email obfuscation")
        
        if attack_surface.get('file_uploads', 0) > 0:
            recommendations.append("📤 Review file upload security controls")
        
        # Next phase recommendations
        recommendations.append("➡️  Proceed to Phase 2: Advanced Scanning & Vulnerability Assessment")
        
        return recommendations
