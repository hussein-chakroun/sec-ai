"""
Multi-Agent Architecture - Phase 3
Base classes and coordination for agent swarms
"""
from typing import Dict, Any, List, Optional, Callable
from abc import ABC, abstractmethod
from loguru import logger
import asyncio
from datetime import datetime
import uuid
from enum import Enum


class AgentRole(Enum):
    """Agent role types"""
    RECON = "reconnaissance"
    WEB_EXPLOIT = "web_exploitation"
    NETWORK_EXPLOIT = "network_exploitation"
    SOCIAL_ENGINEER = "social_engineering"
    WIRELESS = "wireless_security"
    PHYSICAL = "physical_security"
    CLOUD = "cloud_security"
    COORDINATOR = "coordinator"


class AgentState(Enum):
    """Agent states"""
    IDLE = "idle"
    WORKING = "working"
    WAITING = "waiting"
    COMPLETE = "complete"
    FAILED = "failed"


class Message:
    """Inter-agent message"""
    
    def __init__(self, sender_id: str, receiver_id: str, message_type: str,
                 content: Dict[str, Any], priority: int = 5):
        self.id = str(uuid.uuid4())
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_type = message_type
        self.content = content
        self.priority = priority
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "message_type": self.message_type,
            "content": self.content,
            "priority": self.priority,
            "timestamp": self.timestamp
        }


class BaseAgent(ABC):
    """Base class for all agents"""
    
    def __init__(self, agent_id: str, role: AgentRole, coordinator_id: str = None):
        self.agent_id = agent_id
        self.role = role
        self.coordinator_id = coordinator_id
        self.state = AgentState.IDLE
        self.knowledge = {}
        self.discoveries = []
        self.message_queue = asyncio.Queue()
        self.performance_metrics = {
            "tasks_completed": 0,
            "success_count": 0,
            "failure_count": 0,
            "avg_execution_time": 0
        }
        logger.info(f"Agent {agent_id} initialized with role {role.value}")
    
    @abstractmethod
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute assigned task"""
        pass
    
    @abstractmethod
    def can_handle_task(self, task: Dict[str, Any]) -> bool:
        """Check if agent can handle this task"""
        pass
    
    async def run(self):
        """Main agent loop"""
        logger.info(f"Agent {self.agent_id} starting")
        self.state = AgentState.IDLE
        
        while True:
            try:
                # Process messages
                if not self.message_queue.empty():
                    message = await self.message_queue.get()
                    await self.handle_message(message)
                
                await asyncio.sleep(0.1)
                
            except asyncio.CancelledError:
                logger.info(f"Agent {self.agent_id} stopped")
                break
            except Exception as e:
                logger.error(f"Agent {self.agent_id} error: {e}")
                self.state = AgentState.FAILED
    
    async def handle_message(self, message: Message):
        """Handle incoming message"""
        logger.debug(f"Agent {self.agent_id} received message type {message.message_type}")
        
        if message.message_type == "task":
            await self.execute_task_with_tracking(message.content)
        
        elif message.message_type == "discovery":
            self.process_discovery(message.content)
        
        elif message.message_type == "status_request":
            await self.send_status_update()
        
        elif message.message_type == "terminate":
            self.state = AgentState.COMPLETE
    
    async def execute_task_with_tracking(self, task: Dict[str, Any]):
        """Execute task with performance tracking"""
        start_time = datetime.now()
        self.state = AgentState.WORKING
        
        try:
            result = await self.execute_task(task)
            
            self.performance_metrics["tasks_completed"] += 1
            if result.get("success", False):
                self.performance_metrics["success_count"] += 1
            else:
                self.performance_metrics["failure_count"] += 1
            
            # Update average execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            n = self.performance_metrics["tasks_completed"]
            current_avg = self.performance_metrics["avg_execution_time"]
            self.performance_metrics["avg_execution_time"] = (
                (current_avg * (n - 1) + execution_time) / n
            )
            
            # Send result to coordinator
            if self.coordinator_id:
                await self.send_message(
                    receiver_id=self.coordinator_id,
                    message_type="task_result",
                    content={
                        "task_id": task.get("task_id"),
                        "result": result,
                        "agent_id": self.agent_id
                    }
                )
            
            self.state = AgentState.IDLE
            
        except Exception as e:
            logger.error(f"Agent {self.agent_id} task failed: {e}")
            self.performance_metrics["failure_count"] += 1
            self.state = AgentState.FAILED
    
    async def send_message(self, receiver_id: str, message_type: str,
                          content: Dict[str, Any], priority: int = 5):
        """Send message to another agent"""
        message = Message(
            sender_id=self.agent_id,
            receiver_id=receiver_id,
            message_type=message_type,
            content=content,
            priority=priority
        )
        
        # In a real system, this would go through a message broker
        logger.debug(f"Agent {self.agent_id} sending {message_type} to {receiver_id}")
        
        return message
    
    def process_discovery(self, discovery: Dict[str, Any]):
        """Process discovery from another agent"""
        self.discoveries.append({
            "timestamp": datetime.now().isoformat(),
            "discovery": discovery
        })
        logger.info(f"Agent {self.agent_id} received discovery: {discovery.get('type')}")
    
    async def send_status_update(self):
        """Send status update to coordinator"""
        if self.coordinator_id:
            await self.send_message(
                receiver_id=self.coordinator_id,
                message_type="status_update",
                content={
                    "agent_id": self.agent_id,
                    "state": self.state.value,
                    "metrics": self.performance_metrics,
                    "discoveries_count": len(self.discoveries)
                }
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "state": self.state.value,
            "discoveries": len(self.discoveries),
            "performance": self.performance_metrics
        }


class AgentCoordinator:
    """Coordinates multiple agents"""
    
    def __init__(self, coordinator_id: str = "main_coordinator"):
        self.coordinator_id = coordinator_id
        self.agents: Dict[str, BaseAgent] = {}
        self.task_queue = asyncio.PriorityQueue()
        self.shared_knowledge = {}
        self.discoveries = []
        self.active_tasks = {}
        logger.info(f"Agent Coordinator {coordinator_id} initialized")
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent"""
        self.agents[agent.agent_id] = agent
        logger.info(f"Registered agent {agent.agent_id} with role {agent.role.value}")
    
    async def assign_task(self, task: Dict[str, Any], priority: int = 5):
        """Assign task to appropriate agent"""
        task_id = task.get("task_id", str(uuid.uuid4()))
        task["task_id"] = task_id
        
        # Find capable agents
        capable_agents = [
            agent for agent in self.agents.values()
            if agent.can_handle_task(task) and agent.state == AgentState.IDLE
        ]
        
        if not capable_agents:
            logger.warning(f"No capable agents for task {task_id}")
            await self.task_queue.put((priority, task))
            return None
        
        # Select best agent based on performance
        best_agent = max(
            capable_agents,
            key=lambda a: a.performance_metrics["success_count"] /
                         max(a.performance_metrics["tasks_completed"], 1)
        )
        
        # Send task to agent
        message = Message(
            sender_id=self.coordinator_id,
            receiver_id=best_agent.agent_id,
            message_type="task",
            content=task,
            priority=priority
        )
        
        await best_agent.message_queue.put(message)
        self.active_tasks[task_id] = {
            "task": task,
            "agent_id": best_agent.agent_id,
            "started_at": datetime.now().isoformat()
        }
        
        logger.info(f"Assigned task {task_id} to agent {best_agent.agent_id}")
        return best_agent.agent_id
    
    async def broadcast_discovery(self, discovery: Dict[str, Any], sender_id: str):
        """Broadcast discovery to all agents"""
        self.discoveries.append({
            "sender": sender_id,
            "discovery": discovery,
            "timestamp": datetime.now().isoformat()
        })
        
        # Update shared knowledge
        discovery_type = discovery.get("type")
        if discovery_type not in self.shared_knowledge:
            self.shared_knowledge[discovery_type] = []
        self.shared_knowledge[discovery_type].append(discovery)
        
        # Broadcast to all agents except sender
        for agent_id, agent in self.agents.items():
            if agent_id != sender_id:
                message = Message(
                    sender_id=self.coordinator_id,
                    receiver_id=agent_id,
                    message_type="discovery",
                    content=discovery
                )
                await agent.message_queue.put(message)
        
        logger.info(f"Broadcasted discovery from {sender_id}: {discovery_type}")
    
    async def request_consensus(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        """Request consensus from agents on a decision"""
        votes = {}
        
        # Request votes from all agents
        for agent_id, agent in self.agents.items():
            message = Message(
                sender_id=self.coordinator_id,
                receiver_id=agent_id,
                message_type="vote_request",
                content=decision
            )
            await agent.message_queue.put(message)
        
        # Wait for votes (with timeout)
        try:
            await asyncio.wait_for(
                self._collect_votes(votes, len(self.agents)),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.warning("Consensus vote timeout")
        
        # Tally votes
        approve_count = sum(1 for v in votes.values() if v.get("approve", False))
        total_votes = len(votes)
        
        consensus_reached = approve_count / total_votes > 0.66 if total_votes > 0 else False
        
        return {
            "decision": decision,
            "votes": votes,
            "consensus": consensus_reached,
            "approval_rate": approve_count / total_votes if total_votes > 0 else 0
        }
    
    async def _collect_votes(self, votes: Dict, expected_count: int):
        """Collect votes from agents"""
        while len(votes) < expected_count:
            await asyncio.sleep(0.1)
    
    def get_swarm_status(self) -> Dict[str, Any]:
        """Get status of entire swarm"""
        agent_statuses = {
            agent_id: agent.get_status()
            for agent_id, agent in self.agents.items()
        }
        
        total_discoveries = sum(
            agent.get_status()["discoveries"]
            for agent in self.agents.values()
        )
        
        return {
            "coordinator_id": self.coordinator_id,
            "total_agents": len(self.agents),
            "active_agents": sum(
                1 for a in self.agents.values()
                if a.state == AgentState.WORKING
            ),
            "idle_agents": sum(
                1 for a in self.agents.values()
                if a.state == AgentState.IDLE
            ),
            "total_discoveries": total_discoveries,
            "active_tasks": len(self.active_tasks),
            "agents": agent_statuses
        }
    
    async def scale_swarm(self, role: AgentRole, count: int, 
                         agent_factory: Callable) -> List[str]:
        """Dynamically scale swarm by adding agents"""
        new_agent_ids = []
        
        for i in range(count):
            agent_id = f"{role.value}_agent_{len(self.agents) + i + 1}"
            agent = agent_factory(agent_id, role, self.coordinator_id)
            self.register_agent(agent)
            new_agent_ids.append(agent_id)
            
            # Start agent
            asyncio.create_task(agent.run())
        
        logger.info(f"Scaled swarm: added {count} {role.value} agents")
        return new_agent_ids
