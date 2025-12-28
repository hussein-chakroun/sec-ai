"""
Agents module initialization
"""
from .base_agent import BaseAgent, AgentCoordinator, AgentRole, AgentState, Message
from .specialized_agents import (
    ReconAgent, WebExploitAgent, NetworkExploitAgent,
    SocialEngineerAgent, WirelessAgent, PhysicalSecurityAgent,
    CloudSecurityAgent, AgentSwarmFactory
)
from .swarm_intelligence import SwarmIntelligence, CorrelationEngine, DynamicResourceAllocator

__all__ = [
    'BaseAgent', 'AgentCoordinator', 'AgentRole', 'AgentState', 'Message',
    'ReconAgent', 'WebExploitAgent', 'NetworkExploitAgent',
    'SocialEngineerAgent', 'WirelessAgent', 'PhysicalSecurityAgent',
    'CloudSecurityAgent', 'AgentSwarmFactory',
    'SwarmIntelligence', 'CorrelationEngine', 'DynamicResourceAllocator'
]
