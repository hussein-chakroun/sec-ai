"""
Main Orchestrator - Central Coordination System
Orchestrates all 5 phases, LLM decision-making, memory systems, and agent coordination
for complete autonomous penetration testing
"""
import asyncio
import time
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import json
import sys

# Import core systems
from .llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
from .enhanced_orchestrator import EnhancedLLMOrchestrator
from .phase_integration_bridge import PhaseIntegrationBridge
from .config import config

# Import phase orchestrators
from .phase1_orchestrator import Phase1Orchestrator
from .phase2_orchestrator import Phase2Orchestrator
from .phase3_orchestrator import Phase3Orchestrator
from .phase4_orchestrator import Phase4Orchestrator
from .phase5_orchestrator import Phase5Orchestrator

# Import advanced systems
sys.path.insert(0, str(Path(__file__).parent.parent))
from memory import VectorDatabase, PersistentMemory
from knowledge import KnowledgeBase
from learning import SelfImprovementEngine
from agents import SwarmIntelligence
from autonomous_research import IntelligenceGatherer
from reinforcement_learning import RLAgent


@dataclass
class OrchestratorConfig:
    """Configuration for Main Orchestrator"""
    # LLM Settings
    llm_provider: str = "openai"  # openai or anthropic
    llm_model: str = "gpt-4-turbo-preview"
    api_key: Optional[str] = None
    
    # Execution Mode
    execution_mode: str = "autonomous"  # autonomous, guided, manual
    max_iterations: int = 100
    
    # Phase Control
    enabled_phases: List[int] = field(default_factory=lambda: [1, 2, 3, 4, 5])
    auto_progress: bool = True  # Auto progress between phases
    stop_at_phase: Optional[int] = None  # Stop at specific phase
    
    # Memory & Learning
    enable_memory: bool = True
    enable_learning: bool = True
    enable_agents: bool = True
    enable_rl: bool = False  # Reinforcement Learning (experimental)
    
    # Output & Reporting
    output_dir: str = "./reports"
    save_intermediate: bool = True
    verbose: bool = True
    
    # Safety & Controls
    max_concurrent_tasks: int = 10
    timeout_per_phase: Optional[int] = None  # seconds
    require_approval: List[str] = field(default_factory=list)  # Actions requiring approval
    
    # Advanced Features
    enable_autonomous_research: bool = True
    enable_adaptive_strategy: bool = True
    enable_self_improvement: bool = True


@dataclass
class OrchestrationProgress:
    """Track overall orchestration progress"""
    start_time: datetime = field(default_factory=datetime.now)
    current_phase: int = 0
    total_phases: int = 5
    
    # Phase completion
    phase1_complete: bool = False
    phase2_complete: bool = False
    phase3_complete: bool = False
    phase4_complete: bool = False
    phase5_complete: bool = False
    
    # Statistics
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    
    # Findings
    hosts_discovered: int = 0
    vulnerabilities_found: int = 0
    exploits_successful: int = 0
    hosts_compromised: int = 0
    credentials_harvested: int = 0
    
    # Status
    status: str = "initializing"  # initializing, running, paused, completed, failed
    
    @property
    def percentage(self) -> float:
        completed = sum([
            self.phase1_complete,
            self.phase2_complete,
            self.phase3_complete,
            self.phase4_complete,
            self.phase5_complete
        ])
        return (completed / self.total_phases) * 100
    
    @property
    def elapsed_time(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()


class MainOrchestrator:
    """
    Main Orchestrator - Central coordination system for all penetration testing operations
    
    Coordinates:
    - 5 Phase workflow (Recon → Scan → Exploit → Post-Exploit → Lateral Movement)
    - LLM decision-making and strategy
    - Memory and learning systems
    - Agent swarm intelligence
    - Autonomous research and adaptation
    """
    
    def __init__(self, config: Optional[OrchestratorConfig] = None):
        """
        Initialize Main Orchestrator
        
        Args:
            config: Orchestrator configuration
        """
        self.config = config or OrchestratorConfig()
        self.progress = OrchestrationProgress()
        
        logger.info("=" * 80)
        logger.info("MAIN ORCHESTRATOR - INITIALIZING")
        logger.info("=" * 80)
        
        # Initialize LLM Provider
        self._initialize_llm()
        
        # Initialize Memory & Learning Systems
        if self.config.enable_memory:
            self._initialize_memory_systems()
        
        # Initialize Agent Systems
        if self.config.enable_agents:
            self._initialize_agent_systems()
        
        # Initialize Phase Integration Bridge
        self.phase_bridge = PhaseIntegrationBridge(
            llm_orchestrator=self.llm_orchestrator,
            config={
                'auto_progress': self.config.auto_progress,
                'save_intermediate': self.config.save_intermediate,
                'output_dir': self.config.output_dir
            }
        )
        
        # Results storage
        self.results: Dict[str, Any] = {
            'metadata': {
                'orchestrator_version': '1.0.0',
                'start_time': datetime.now().isoformat(),
                'config': self._config_to_dict()
            },
            'phases': {},
            'overall_stats': {},
            'timeline': []
        }
        
        logger.info("✅ Main Orchestrator initialized successfully")
        logger.info(f"   LLM Provider: {self.config.llm_provider}")
        logger.info(f"   Model: {self.config.llm_model}")
        logger.info(f"   Memory: {'Enabled' if self.config.enable_memory else 'Disabled'}")
        logger.info(f"   Agents: {'Enabled' if self.config.enable_agents else 'Disabled'}")
        logger.info(f"   Enabled Phases: {self.config.enabled_phases}")
    
    def _initialize_llm(self):
        """Initialize LLM provider and orchestrators"""
        logger.info("Initializing LLM systems...")
        
        # Get API key
        api_key = self.config.api_key
        if not api_key:
            if self.config.llm_provider == "openai":
                api_key = config.openai_api_key
            else:
                api_key = config.anthropic_api_key
        
        if not api_key:
            raise ValueError(f"No API key found for {self.config.llm_provider}")
        
        # Create provider
        if self.config.llm_provider == "openai":
            provider = OpenAIProvider(api_key, self.config.llm_model)
        else:
            provider = AnthropicProvider(api_key, self.config.llm_model)
        
        # Create orchestrators
        if self.config.enable_memory:
            self.llm_orchestrator = EnhancedLLMOrchestrator(
                provider,
                enable_memory=True
            )
        else:
            self.llm_orchestrator = LLMOrchestrator(provider)
        
        logger.info(f"✅ LLM initialized: {self.config.llm_provider}/{self.config.llm_model}")
    
    def _initialize_memory_systems(self):
        """Initialize memory and learning systems"""
        logger.info("Initializing memory & learning systems...")
        
        self.vector_db = VectorDatabase()
        self.persistent_memory = PersistentMemory()
        self.knowledge_base = KnowledgeBase()
        
        if self.config.enable_learning:
            self.learning_engine = SelfImprovementEngine(
                self.persistent_memory,
                self.knowledge_base
            )
            self.learning_engine.train_from_history()
        
        logger.info("✅ Memory systems initialized")
    
    def _initialize_agent_systems(self):
        """Initialize agent swarm intelligence"""
        logger.info("Initializing agent systems...")
        
        self.swarm = SwarmIntelligence(
            llm_orchestrator=self.llm_orchestrator,
            max_agents=self.config.max_concurrent_tasks
        )
        
        if self.config.enable_autonomous_research:
            self.intelligence_gatherer = IntelligenceGatherer(
                llm_orchestrator=self.llm_orchestrator
            )
        
        logger.info("✅ Agent systems initialized")
    
    async def run_complete_pentest(
        self,
        target: str,
        scope: Optional[List[str]] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run complete autonomous penetration test
        
        Args:
            target: Primary target (IP, domain, or URL)
            scope: Additional targets/scope (optional)
            custom_config: Custom phase configurations
            
        Returns:
            Complete results from all phases
        """
        logger.info("=" * 80)
        logger.info("STARTING COMPLETE AUTONOMOUS PENETRATION TEST")
        logger.info("=" * 80)
        logger.info(f"Target: {target}")
        logger.info(f"Scope: {scope or 'Single target'}")
        logger.info(f"Mode: {self.config.execution_mode}")
        logger.info("=" * 80)
        
        self.progress.status = "running"
        self.results['target'] = target
        self.results['scope'] = scope or [target]
        
        try:
            # Pre-engagement intelligence gathering
            if self.config.enable_autonomous_research:
                logger.info("\n🔍 Conducting pre-engagement intelligence gathering...")
                await self._pre_engagement_research(target)
            
            # Adaptive strategy planning
            if self.config.enable_adaptive_strategy:
                logger.info("\n🧠 Planning adaptive attack strategy...")
                strategy = await self._plan_attack_strategy(target)
                self.results['attack_strategy'] = strategy
            
            # Run phases sequentially with LLM-guided decisions
            for phase_num in self.config.enabled_phases:
                if self.config.stop_at_phase and phase_num > self.config.stop_at_phase:
                    logger.info(f"Stopping at phase {self.config.stop_at_phase} as configured")
                    break
                
                await self._run_phase(phase_num, target, custom_config)
                
                # Check if we should continue
                if not self.config.auto_progress:
                    if not await self._request_phase_approval(phase_num):
                        logger.warning(f"User declined to proceed after Phase {phase_num}")
                        break
            
            # Post-engagement analysis
            logger.info("\n📊 Conducting post-engagement analysis...")
            await self._post_engagement_analysis()
            
            # Self-improvement
            if self.config.enable_self_improvement:
                logger.info("\n🎓 Learning from engagement results...")
                await self._learn_from_engagement()
            
            self.progress.status = "completed"
            logger.info("\n" + "=" * 80)
            logger.info("✅ PENETRATION TEST COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            
            return self._compile_final_results()
            
        except Exception as e:
            logger.error(f"❌ Orchestration failed: {e}")
            self.progress.status = "failed"
            self.results['error'] = str(e)
            raise
    
    async def _run_phase(
        self,
        phase_num: int,
        target: str,
        custom_config: Optional[Dict[str, Any]] = None
    ):
        """
        Run a specific phase with LLM guidance
        
        Args:
            phase_num: Phase number (1-5)
            target: Target
            custom_config: Custom configuration
        """
        self.progress.current_phase = phase_num
        phase_start = time.time()
        
        logger.info("\n" + "=" * 80)
        logger.info(f"PHASE {phase_num}: {self._get_phase_name(phase_num)}")
        logger.info("=" * 80)
        
        try:
            # Get phase-specific config
            phase_config = custom_config.get(f'phase{phase_num}', {}) if custom_config else {}
            
            # Run phase using integration bridge
            if phase_num == 1:
                results = await self.phase_bridge.run_phase1(target, phase_config)
                self.progress.phase1_complete = True
                self.progress.hosts_discovered = len(results.get('discovered_hosts', []))
                
            elif phase_num == 2:
                if not self.progress.phase1_complete:
                    raise ValueError("Phase 1 must complete before Phase 2")
                results = await self.phase_bridge.run_phase2(
                    self.phase_bridge.phase1_results,
                    phase_config
                )
                self.progress.phase2_complete = True
                self.progress.vulnerabilities_found = len(results.get('vulnerabilities', []))
                
            elif phase_num == 3:
                if not self.progress.phase2_complete:
                    raise ValueError("Phase 2 must complete before Phase 3")
                results = await self.phase_bridge.run_phase3(
                    self.phase_bridge.phase1_results,
                    self.phase_bridge.phase2_results,
                    phase_config
                )
                self.progress.phase3_complete = True
                self.progress.exploits_successful = results.get('successful_exploits', 0)
                self.progress.hosts_compromised = len(results.get('compromised_hosts', []))
                
            elif phase_num == 4:
                if not self.progress.phase3_complete:
                    raise ValueError("Phase 3 must complete before Phase 4")
                results = await self.phase_bridge.run_phase4(
                    self.phase_bridge.phase3_results,
                    phase_config
                )
                self.progress.phase4_complete = True
                self.progress.credentials_harvested = len(results.get('harvested_credentials', []))
                
            elif phase_num == 5:
                if not self.progress.phase4_complete:
                    raise ValueError("Phase 4 must complete before Phase 5")
                results = await self.phase_bridge.run_phase5(
                    self.phase_bridge.phase3_results,
                    self.phase_bridge.phase4_results,
                    phase_config
                )
                self.progress.phase5_complete = True
            
            else:
                raise ValueError(f"Invalid phase number: {phase_num}")
            
            # Store results
            phase_duration = time.time() - phase_start
            self.results['phases'][f'phase{phase_num}'] = {
                'results': results,
                'duration': phase_duration,
                'completed_at': datetime.now().isoformat()
            }
            
            # Add to timeline
            self.results['timeline'].append({
                'phase': phase_num,
                'phase_name': self._get_phase_name(phase_num),
                'timestamp': datetime.now().isoformat(),
                'duration': phase_duration,
                'status': 'completed'
            })
            
            logger.info(f"✅ Phase {phase_num} completed in {phase_duration:.2f}s")
            
            # LLM analysis of phase results
            if phase_num < 5:
                await self._analyze_phase_results(phase_num, results)
            
        except Exception as e:
            logger.error(f"❌ Phase {phase_num} failed: {e}")
            self.results['timeline'].append({
                'phase': phase_num,
                'phase_name': self._get_phase_name(phase_num),
                'timestamp': datetime.now().isoformat(),
                'status': 'failed',
                'error': str(e)
            })
            raise
    
    async def _pre_engagement_research(self, target: str):
        """Conduct pre-engagement intelligence gathering"""
        if not hasattr(self, 'intelligence_gatherer'):
            return
        
        research = await self.intelligence_gatherer.gather_target_intelligence(target)
        self.results['pre_engagement_research'] = research
        logger.info(f"   Found {len(research.get('sources', []))} intelligence sources")
    
    async def _plan_attack_strategy(self, target: str) -> Dict[str, Any]:
        """Use LLM to plan adaptive attack strategy"""
        prompt = f"""
        You are planning a penetration test against target: {target}
        
        Based on the target, recommend:
        1. Initial reconnaissance approach (passive vs active)
        2. Priority vulnerabilities to look for
        3. Exploitation strategy (stealthy vs aggressive)
        4. Post-exploitation objectives
        5. Lateral movement tactics
        
        Provide a strategic plan in JSON format.
        """
        
        response = self.llm_orchestrator.provider.generate(
            prompt,
            system_prompt="You are an expert penetration testing strategist."
        )
        
        try:
            strategy = json.loads(response)
        except:
            strategy = {'raw_analysis': response}
        
        logger.info("   Attack strategy planned")
        return strategy
    
    async def _analyze_phase_results(self, phase_num: int, results: Dict[str, Any]):
        """Use LLM to analyze phase results and guide next steps"""
        prompt = f"""
        Phase {phase_num} ({self._get_phase_name(phase_num)}) has completed.
        
        Results summary:
        {json.dumps(results, indent=2, default=str)[:2000]}
        
        Analyze these results and provide:
        1. Key findings
        2. Risk assessment
        3. Recommended next steps for Phase {phase_num + 1}
        4. Potential attack vectors to prioritize
        
        Provide analysis in JSON format.
        """
        
        analysis = self.llm_orchestrator.provider.generate(
            prompt,
            system_prompt="You are an expert penetration tester analyzing engagement results."
        )
        
        self.results['phases'][f'phase{phase_num}']['llm_analysis'] = analysis
        logger.info(f"   LLM analysis completed for Phase {phase_num}")
    
    async def _post_engagement_analysis(self):
        """Final analysis and reporting"""
        total_duration = self.progress.elapsed_time
        
        self.results['overall_stats'] = {
            'total_duration': total_duration,
            'phases_completed': sum([
                self.progress.phase1_complete,
                self.progress.phase2_complete,
                self.progress.phase3_complete,
                self.progress.phase4_complete,
                self.progress.phase5_complete
            ]),
            'hosts_discovered': self.progress.hosts_discovered,
            'vulnerabilities_found': self.progress.vulnerabilities_found,
            'exploits_successful': self.progress.exploits_successful,
            'hosts_compromised': self.progress.hosts_compromised,
            'credentials_harvested': self.progress.credentials_harvested
        }
        
        # LLM executive summary
        summary_prompt = f"""
        Generate an executive summary for this penetration test:
        
        {json.dumps(self.results['overall_stats'], indent=2)}
        
        Include:
        1. Overall assessment
        2. Critical findings
        3. Business impact
        4. Remediation priorities
        """
        
        executive_summary = self.llm_orchestrator.provider.generate(
            summary_prompt,
            system_prompt="You are a senior security consultant writing an executive summary."
        )
        
        self.results['executive_summary'] = executive_summary
    
    async def _learn_from_engagement(self):
        """Apply self-improvement based on engagement results"""
        if not self.config.enable_learning or not hasattr(self, 'learning_engine'):
            return
        
        # Store engagement in memory
        if hasattr(self, 'persistent_memory'):
            self.persistent_memory.store_engagement(self.results)
        
        # Learn patterns
        self.learning_engine.learn_from_engagement(self.results)
        logger.info("   Learning complete - knowledge base updated")
    
    async def _request_phase_approval(self, completed_phase: int) -> bool:
        """Request approval to proceed to next phase"""
        logger.info(f"\n⏸️  Phase {completed_phase} complete. Awaiting approval to proceed...")
        # In automated mode, always approve
        if self.config.execution_mode == "autonomous":
            return True
        # In guided/manual mode, implement approval mechanism
        # This could be input(), GUI callback, or API endpoint
        return True
    
    def _get_phase_name(self, phase_num: int) -> str:
        """Get human-readable phase name"""
        names = {
            1: "RECONNAISSANCE & OSINT",
            2: "VULNERABILITY SCANNING",
            3: "EXPLOITATION",
            4: "POST-EXPLOITATION & PRIVILEGE ESCALATION",
            5: "LATERAL MOVEMENT & DOMAIN DOMINANCE"
        }
        return names.get(phase_num, f"Phase {phase_num}")
    
    def _compile_final_results(self) -> Dict[str, Any]:
        """Compile final results"""
        self.results['metadata']['end_time'] = datetime.now().isoformat()
        self.results['metadata']['total_duration'] = self.progress.elapsed_time
        
        # Save to file
        if self.config.save_intermediate:
            output_path = Path(self.config.output_dir) / f"pentest_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            logger.info(f"📄 Results saved to: {output_path}")
        
        return self.results
    
    def _config_to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'llm_provider': self.config.llm_provider,
            'llm_model': self.config.llm_model,
            'execution_mode': self.config.execution_mode,
            'enabled_phases': self.config.enabled_phases,
            'memory_enabled': self.config.enable_memory,
            'learning_enabled': self.config.enable_learning,
            'agents_enabled': self.config.enable_agents
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current orchestration status"""
        return {
            'status': self.progress.status,
            'current_phase': self.progress.current_phase,
            'progress_percentage': self.progress.percentage,
            'elapsed_time': self.progress.elapsed_time,
            'stats': {
                'hosts_discovered': self.progress.hosts_discovered,
                'vulnerabilities_found': self.progress.vulnerabilities_found,
                'exploits_successful': self.progress.exploits_successful,
                'hosts_compromised': self.progress.hosts_compromised,
                'credentials_harvested': self.progress.credentials_harvested
            }
        }
    
    async def pause(self):
        """Pause orchestration"""
        logger.warning("⏸️  Orchestration paused")
        self.progress.status = "paused"
    
    async def resume(self):
        """Resume orchestration"""
        logger.info("▶️  Orchestration resumed")
        self.progress.status = "running"
    
    async def stop(self):
        """Stop orchestration"""
        logger.warning("⏹️  Orchestration stopped")
        self.progress.status = "stopped"
        return self._compile_final_results()


# Convenience functions
async def run_autonomous_pentest(
    target: str,
    llm_provider: str = "openai",
    llm_model: str = "gpt-4-turbo-preview",
    api_key: Optional[str] = None,
    enable_all_features: bool = True
) -> Dict[str, Any]:
    """
    Quick start function for autonomous penetration testing
    
    Args:
        target: Target to test
        llm_provider: LLM provider (openai or anthropic)
        llm_model: Model to use
        api_key: API key (optional, will use env var if not provided)
        enable_all_features: Enable all advanced features
        
    Returns:
        Complete pentest results
    """
    config = OrchestratorConfig(
        llm_provider=llm_provider,
        llm_model=llm_model,
        api_key=api_key,
        execution_mode="autonomous",
        enable_memory=enable_all_features,
        enable_learning=enable_all_features,
        enable_agents=enable_all_features,
        enable_autonomous_research=enable_all_features,
        enable_adaptive_strategy=enable_all_features,
        enable_self_improvement=enable_all_features
    )
    
    orchestrator = MainOrchestrator(config)
    return await orchestrator.run_complete_pentest(target)


def create_orchestrator(
    llm_provider: str = "openai",
    llm_model: str = "gpt-4-turbo-preview",
    **kwargs
) -> MainOrchestrator:
    """
    Create and configure a main orchestrator
    
    Args:
        llm_provider: LLM provider
        llm_model: Model to use
        **kwargs: Additional configuration options
        
    Returns:
        Configured MainOrchestrator instance
    """
    config = OrchestratorConfig(
        llm_provider=llm_provider,
        llm_model=llm_model,
        **kwargs
    )
    return MainOrchestrator(config)
