"""
Enhanced Pentest Engine - Phase 2 & 3
Integrates learning, memory, and multi-agent capabilities
"""
import asyncio
from typing import Dict, Any, List, Optional
from loguru import logger
from datetime import datetime

from core.llm_orchestrator import LLMOrchestrator
from core.memory_system import MemoryStore
from core.vector_knowledge import VectorKnowledgeBase
from core.decision_engine import ProbabilisticReasoner, CostBenefitAnalyzer, AdaptiveStrategy
from core.self_improvement import SelfImprovementEngine
from agents import AgentCoordinator, AgentSwarmFactory, SwarmIntelligence, DynamicResourceAllocator
from modules import NmapScanner, SQLMapScanner, HydraCracker, MetasploitFramework


class EnhancedPentestEngine:
    """
    Advanced pentesting engine with:
    - Vector knowledge base
    - Persistent memory
    - Probabilistic reasoning
    - Self-improvement
    - Multi-agent swarm intelligence
    """
    
    def __init__(self, orchestrator: LLMOrchestrator, enable_swarm: bool = True):
        self.orchestrator = orchestrator
        
        # Phase 2 Components
        self.memory = MemoryStore()
        self.knowledge_base = VectorKnowledgeBase()
        self.reasoner = ProbabilisticReasoner(self.memory, self.knowledge_base)
        self.cost_analyzer = CostBenefitAnalyzer(self.memory)
        self.adaptive_strategy = AdaptiveStrategy(self.memory, self.knowledge_base)
        self.self_improver = SelfImprovementEngine(self.memory)
        
        # Phase 3 Components (optional)
        self.enable_swarm = enable_swarm
        if enable_swarm:
            self.agent_coordinator = AgentCoordinator()
            self.swarm_intelligence = SwarmIntelligence(self.agent_coordinator)
            self.resource_allocator = DynamicResourceAllocator(self.agent_coordinator)
            self._init_swarm()
        
        # Phase 1 Tools
        self.nmap = NmapScanner()
        self.sqlmap = SQLMapScanner()
        self.hydra = HydraCracker()
        self.metasploit = MetasploitFramework()
        
        self.scan_results = []
        self.target = None
        self.context = {}
        
        logger.info("Enhanced Pentest Engine initialized (Phase 2 & 3)")
    
    def _init_swarm(self):
        """Initialize agent swarm"""
        swarms = AgentSwarmFactory.create_full_swarm(self.agent_coordinator.coordinator_id)
        
        for swarm_type, agents in swarms.items():
            for agent in agents:
                self.agent_coordinator.register_agent(agent)
                asyncio.create_task(agent.run())
        
        logger.info(f"Initialized swarm with {len(self.agent_coordinator.agents)} agents")
    
    async def run_enhanced_pentest(self, target: str, max_iterations: int = 15,
                                  use_swarm: bool = True) -> Dict[str, Any]:
        """Run enhanced penetration test with all features"""
        
        self.target = target
        self.scan_results = []
        start_time = datetime.now()
        
        logger.info(f"Starting enhanced pentest against {target}")
        
        # Load target profile from memory
        target_profile = self.memory.get_target_profile(target)
        if target_profile:
            logger.info(f"Found existing profile for {target}")
            self.context['target_profile'] = target_profile
            
            # Predict defensive measures
            predicted_defenses = self.adaptive_strategy.predict_defensive_measures(target_profile)
            logger.info(f"Predicted defenses: {predicted_defenses}")
            self.context['predicted_defenses'] = predicted_defenses
        
        # Phase 1: Initial Analysis with LLM
        logger.info("Phase 1: AI-powered target analysis")
        analysis = self.orchestrator.analyze_target(target)
        self.context["initial_analysis"] = analysis
        
        # Phase 2: Reconnaissance (with swarm if enabled)
        logger.info("Phase 2: Multi-source reconnaissance")
        if use_swarm and self.enable_swarm:
            recon_result = await self._swarm_reconnaissance()
        else:
            recon_result = self._traditional_reconnaissance()
        
        self.scan_results.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "reconnaissance",
            "result": recon_result
        })
        
        # Update context with discoveries
        if recon_result.get('success'):
            parsed = recon_result.get('parsed', {})
            self.context['open_ports'] = parsed.get('open_ports', [])
            self.context['services'] = parsed.get('services', [])
        
        # Phase 3: Probabilistic Attack Vector Analysis
        logger.info("Phase 3: Probabilistic attack vector ranking")
        attack_vectors = self.reasoner.rank_attack_vectors(
            recon_result,
            self.context
        )
        
        logger.info(f"Identified {len(attack_vectors)} attack vectors")
        for i, av in enumerate(attack_vectors[:5]):
            logger.info(f"  {i+1}. {av['service']}:{av['port']} (score: {av['score']:.2f})")
        
        # Phase 4: Adaptive Iterative Testing
        logger.info("Phase 4: Adaptive exploitation")
        iteration = 0
        
        while iteration < max_iterations and attack_vectors:
            iteration += 1
            logger.info(f"Iteration {iteration}/{max_iterations}")
            
            # Select best attack vector
            current_vector = attack_vectors[0]
            
            # Cost-benefit analysis
            approaches = self._generate_approaches(current_vector)
            analyzed_approaches = self.cost_analyzer.compare_approaches(
                approaches,
                self.context
            )
            
            # Select approach with best ROI
            best_approach = analyzed_approaches[0]
            
            if best_approach['analysis']['recommendation'] == 'skip':
                logger.info("Cost-benefit analysis recommends skipping")
                attack_vectors.pop(0)
                continue
            
            # Execute approach
            try:
                result = await self._execute_approach(best_approach)
                
                # Record response for adaptive strategy
                self.adaptive_strategy.record_response(
                    {"approach": best_approach},
                    result
                )
                
                # Check for defensive patterns
                defensive_pattern = self.adaptive_strategy.detect_defensive_pattern()
                if defensive_pattern:
                    logger.warning(f"Defensive pattern detected: {defensive_pattern['type']}")
                    # Adapt strategy
                    current_strategy = {"approach": best_approach}
                    adapted = self.adaptive_strategy.adapt_strategy(current_strategy)
                    if adapted.get('switch_tool'):
                        attack_vectors.pop(0)
                        continue
                
                # Store result
                self.scan_results.append({
                    "timestamp": datetime.now().isoformat(),
                    "phase": f"iteration_{iteration}",
                    "attack_vector": current_vector,
                    "approach": best_approach,
                    "result": result
                })
                
                # Learn from outcome
                success = result.get('success', False)
                self.memory.record_technique_outcome(
                    technique=best_approach['tool'],
                    target_type=self.context.get('target_type', 'unknown'),
                    success=success,
                    context={"attack_vector": current_vector}
                )
                
                if not success:
                    # Analyze failure and improve
                    failure_analysis = self.self_improver.analyze_failure(
                        tool=best_approach['tool'],
                        parameters=best_approach.get('parameters', {}),
                        error=result.get('stderr', ''),
                        context=self.context
                    )
                    logger.info(f"Failure analysis: {failure_analysis['category']}")
                
                # Remove used vector
                attack_vectors.pop(0)
                
                # Re-rank remaining vectors if we learned something
                if success:
                    attack_vectors = self.reasoner.rank_attack_vectors(
                        {"parsed": {"open_ports": self.context.get('open_ports', [])}},
                        self.context
                    )
                
            except Exception as e:
                logger.error(f"Error in iteration {iteration}: {e}")
                attack_vectors.pop(0)
        
        # Phase 5: Generate Intelligent Report
        logger.info("Phase 5: Generating comprehensive report")
        recommendations = self.orchestrator.generate_recommendations(self.scan_results)
        
        # Get improvement suggestions
        improvement_suggestions = self.self_improver.get_improvement_suggestions()
        
        # Store engagement in memory
        final_results = {
            "target": target,
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_iterations": iteration,
            "scan_results": self.scan_results,
            "attack_vectors_analyzed": len(attack_vectors),
            "recommendations": recommendations,
            "improvement_suggestions": improvement_suggestions,
            "context": self.context,
            "swarm_used": use_swarm and self.enable_swarm
        }
        
        self.memory.store_engagement(target, final_results)
        
        # Persist knowledge
        self.knowledge_base.persist()
        
        logger.info("Enhanced pentest completed")
        
        # Get statistics
        stats = {
            "memory_stats": self.memory.get_memory_statistics(),
            "knowledge_stats": self.knowledge_base.get_statistics()
        }
        
        if self.enable_swarm:
            stats["swarm_stats"] = self.agent_coordinator.get_swarm_status()
        
        final_results["statistics"] = stats
        
        return final_results
    
    async def _swarm_reconnaissance(self) -> Dict[str, Any]:
        """Parallel reconnaissance using agent swarm"""
        logger.info("Deploying reconnaissance swarm")
        
        # Create recon tasks
        tasks = [
            {"type": "recon", "target": self.target, "source": "dns"},
            {"type": "recon", "target": self.target, "source": "whois"},
            {"type": "recon", "target": self.target, "source": "osint"},
        ]
        
        # Assign to swarm
        for task in tasks:
            await self.agent_coordinator.assign_task(task, priority=10)
        
        # Wait for results (simplified)
        await asyncio.sleep(5)
        
        # Aggregate discoveries
        all_discoveries = self.agent_coordinator.discoveries
        
        # Also run traditional nmap scan
        nmap_result = self.nmap.service_scan(self.target)
        
        # Combine results
        combined_result = {
            **nmap_result,
            "swarm_discoveries": all_discoveries,
            "sources": ["nmap", "swarm"]
        }
        
        return combined_result
    
    def _traditional_reconnaissance(self) -> Dict[str, Any]:
        """Traditional single-threaded reconnaissance"""
        return self.nmap.service_scan(self.target)
    
    def _generate_approaches(self, attack_vector: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate possible approaches for an attack vector"""
        service = attack_vector['service']
        port = attack_vector['port']
        
        approaches = []
        
        # Nmap detailed scan
        approaches.append({
            "option_id": "nmap_detailed",
            "tool": "nmap",
            "parameters": {"scan_type": "vuln", "port": port},
            "potential_value": 0.7
        })
        
        # Service-specific approaches
        if 'http' in service.lower():
            approaches.append({
                "option_id": "sqlmap",
                "tool": "sqlmap",
                "parameters": {"action": "test", "url": f"http://{self.target}:{port}"},
                "potential_value": 0.8
            })
        
        if 'ssh' in service.lower():
            approaches.append({
                "option_id": "hydra_ssh",
                "tool": "hydra",
                "parameters": {"service": "ssh", "port": port},
                "potential_value": 0.6
            })
        
        return approaches
    
    async def _execute_approach(self, approach: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an approach"""
        tool = approach['tool']
        parameters = approach.get('parameters', {})
        
        # Use traditional tools from Phase 1
        if tool == "nmap":
            return self.nmap.custom_scan(self.target, ["-p", str(parameters.get('port'))])
        elif tool == "sqlmap":
            return self.sqlmap.test_url(parameters.get('url'))
        elif tool == "hydra":
            # Simplified - in real implementation would use proper credentials
            return {"success": False, "reason": "no_credentials"}
        else:
            return {"success": False, "reason": "unknown_tool"}
