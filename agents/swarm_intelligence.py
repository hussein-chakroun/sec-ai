"""
Agent Coordination and Swarm Intelligence - Phase 3
"""
import asyncio
from typing import Dict, Any, List, Optional
from loguru import logger
from datetime import datetime
from collections import defaultdict

from .base_agent import AgentCoordinator, BaseAgent, AgentRole, AgentState
from .specialized_agents import AgentSwarmFactory


class SwarmIntelligence:
    """Collaborative intelligence system for agent swarms"""
    
    def __init__(self, coordinator: AgentCoordinator):
        self.coordinator = coordinator
        self.collective_knowledge = {}
        self.correlation_engine = CorrelationEngine()
        logger.info("Swarm Intelligence initialized")
    
    async def share_discovery(self, agent_id: str, discovery: Dict[str, Any]):
        """Share discovery across swarm"""
        await self.coordinator.broadcast_discovery(discovery, agent_id)
        
        # Correlate with existing discoveries
        correlations = self.correlation_engine.find_correlations(
            discovery,
            self.coordinator.discoveries
        )
        
        if correlations:
            logger.info(f"Found {len(correlations)} correlations for discovery")
            # Broadcast correlations
            for correlation in correlations:
                await self.coordinator.broadcast_discovery({
                    "type": "correlation",
                    "correlation": correlation
                }, "swarm_intelligence")
    
    async def collective_decision(self, options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Make collective decision through agent consensus"""
        
        votes = {}
        for option in options:
            consensus = await self.coordinator.request_consensus(option)
            votes[option['option_id']] = consensus
        
        # Select option with highest approval
        best_option = max(votes.items(), key=lambda x: x[1]['approval_rate'])
        
        logger.info(f"Collective decision: {best_option[0]} with {best_option[1]['approval_rate']:.2%} approval")
        
        return {
            "selected_option": best_option[0],
            "approval_rate": best_option[1]['approval_rate'],
            "consensus_reached": best_option[1]['consensus'],
            "all_votes": votes
        }
    
    async def competitive_optimization(self, attack_vector: Dict[str, Any], 
                                     num_agents: int = 5) -> Dict[str, Any]:
        """Multiple agents compete for best exploitation path"""
        
        task = {
            "type": "competitive",
            "attack_vector": attack_vector,
            "task_id": f"comp_{datetime.now().timestamp()}"
        }
        
        # Assign to multiple agents
        agent_ids = []
        for _ in range(num_agents):
            agent_id = await self.coordinator.assign_task(task, priority=8)
            if agent_id:
                agent_ids.append(agent_id)
        
        # Wait for results
        results = await self._collect_competitive_results(task["task_id"], num_agents)
        
        # Select best result
        if results:
            best_result = max(results, key=lambda r: r.get('score', 0))
            logger.info(f"Competitive optimization winner: {best_result.get('agent_id')}")
            return best_result
        
        return {"success": False, "reason": "no_results"}
    
    async def _collect_competitive_results(self, task_id: str, 
                                          expected_count: int,
                                          timeout: float = 30.0) -> List[Dict]:
        """Collect results from competitive agents"""
        results = []
        start_time = datetime.now()
        
        while len(results) < expected_count:
            if (datetime.now() - start_time).total_seconds() > timeout:
                break
            await asyncio.sleep(0.5)
            # In real implementation, check for completed tasks
        
        return results


class CorrelationEngine:
    """Correlate discoveries across different domains"""
    
    def __init__(self):
        self.correlations = []
    
    def find_correlations(self, discovery: Dict[str, Any],
                         past_discoveries: List[Dict]) -> List[Dict[str, Any]]:
        """Find correlations between discoveries"""
        correlations = []
        
        discovery_type = discovery.get("discovery", {}).get("type")
        
        for past in past_discoveries:
            past_type = past.get("discovery", {}).get("type")
            
            # Web vuln + network access = deeper access
            if discovery_type == "web_vulnerability" and past_type == "network_access":
                correlations.append({
                    "type": "pivot_opportunity",
                    "description": "Web vulnerability can be used with network access for deeper compromise",
                    "severity": "high",
                    "discoveries": [discovery, past]
                })
            
            # Credentials + service = exploitation
            elif discovery_type == "credentials" and past_type == "open_service":
                correlations.append({
                    "type": "credential_reuse",
                    "description": "Discovered credentials may work on identified services",
                    "severity": "medium",
                    "discoveries": [discovery, past]
                })
            
            # Cloud misconfiguration + data exposure
            elif discovery_type == "cloud_misconfiguration" and past_type == "data_location":
                correlations.append({
                    "type": "data_exposure",
                    "description": "Cloud misconfiguration exposes sensitive data",
                    "severity": "critical",
                    "discoveries": [discovery, past]
                })
        
        return correlations


class DynamicResourceAllocator:
    """Dynamically allocate agents based on attack surface"""
    
    def __init__(self, coordinator: AgentCoordinator):
        self.coordinator = coordinator
        self.resource_history = []
        logger.info("Dynamic Resource Allocator initialized")
    
    async def analyze_attack_surface(self, scan_results: Dict[str, Any]) -> Dict[str, int]:
        """Analyze attack surface and recommend agent allocation"""
        
        allocation = defaultdict(int)
        
        # Analyze discovered services
        open_ports = scan_results.get('parsed', {}).get('open_ports', [])
        services = [p.get('service') for p in open_ports]
        
        # Web services
        web_services = ['http', 'https', 'apache', 'nginx']
        web_count = sum(1 for s in services if any(w in s.lower() for w in web_services))
        if web_count > 0:
            allocation[AgentRole.WEB_EXPLOIT] = min(web_count * 2, 10)
        
        # Network services
        network_services = ['smb', 'rdp', 'ssh', 'telnet']
        network_count = sum(1 for s in services if any(n in s.lower() for n in network_services))
        if network_count > 0:
            allocation[AgentRole.NETWORK_EXPLOIT] = min(network_count, 5)
        
        # Always allocate recon
        allocation[AgentRole.RECON] = 5
        
        logger.info(f"Recommended allocation: {dict(allocation)}")
        return dict(allocation)
    
    async def scale_resources(self, allocation: Dict[AgentRole, int]):
        """Scale agent swarm based on allocation"""
        
        current_counts = defaultdict(int)
        for agent in self.coordinator.agents.values():
            current_counts[agent.role] += 1
        
        for role, target_count in allocation.items():
            current = current_counts[role]
            
            if target_count > current:
                # Scale up
                to_add = target_count - current
                logger.info(f"Scaling up {role.value}: adding {to_add} agents")
                
                # Create factory based on role
                if role == AgentRole.RECON:
                    new_agents = AgentSwarmFactory.create_recon_swarm(
                        self.coordinator.coordinator_id,
                        to_add
                    )
                elif role == AgentRole.WEB_EXPLOIT:
                    # Create general web agents
                    from .specialized_agents import WebExploitAgent
                    new_agents = [
                        WebExploitAgent(f"web_agent_{i}", "general", 
                                      self.coordinator.coordinator_id)
                        for i in range(to_add)
                    ]
                elif role == AgentRole.NETWORK_EXPLOIT:
                    new_agents = AgentSwarmFactory.create_network_swarm(
                        self.coordinator.coordinator_id,
                        to_add
                    )
                else:
                    continue
                
                # Register and start agents
                for agent in new_agents:
                    self.coordinator.register_agent(agent)
                    asyncio.create_task(agent.run())
            
            elif target_count < current:
                # Scale down (remove idle agents)
                logger.info(f"Scaling down {role.value}: removing {current - target_count} agents")
                # Implementation for graceful shutdown
    
    async def load_balance(self, tasks: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Load balance tasks across agents"""
        
        task_assignments = defaultdict(list)
        
        # Group tasks by type
        tasks_by_type = defaultdict(list)
        for task in tasks:
            tasks_by_type[task.get('type')].append(task)
        
        # Distribute tasks
        for task_type, task_list in tasks_by_type.items():
            # Find capable agents
            capable = [
                agent for agent in self.coordinator.agents.values()
                if agent.can_handle_task(task_list[0]) and 
                   agent.state == AgentState.IDLE
            ]
            
            if not capable:
                logger.warning(f"No capable agents for {task_type}")
                continue
            
            # Round-robin distribution
            for i, task in enumerate(task_list):
                agent = capable[i % len(capable)]
                task_assignments[agent.agent_id].append(task['task_id'])
                await self.coordinator.assign_task(task)
        
        return dict(task_assignments)
    
    def prioritize_dead_ends(self, results: List[Dict[str, Any]]) -> List[str]:
        """Identify and deprioritize dead-end attack vectors"""
        
        dead_ends = []
        
        for result in results:
            # Check for repeated failures
            if not result.get('success', False):
                agent_id = result.get('agent_id')
                task_type = result.get('task_type')
                
                # Check history
                recent_failures = [
                    r for r in results[-10:]
                    if r.get('agent_id') == agent_id and not r.get('success')
                ]
                
                if len(recent_failures) >= 3:
                    dead_ends.append(task_type)
                    logger.info(f"Identified dead end: {task_type}")
        
        return list(set(dead_ends))
