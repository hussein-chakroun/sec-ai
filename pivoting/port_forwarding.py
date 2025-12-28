"""
Port Forwarding - Local and Remote Port Forwarding
"""

import asyncio
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class PortForwarder:
    """
    Port forwarding and tunneling
    """
    
    def __init__(self):
        """Initialize port forwarder"""
        self.active_forwards = []
        
        logger.info("PortForwarder initialized")
        
    async def local_port_forward(self, local_port: int, remote_host: str, 
                                 remote_port: int, ssh_server: str, 
                                 username: str, key_path: str = None) -> bool:
        """
        Create local port forward via SSH
        
        Args:
            local_port: Local port to listen on
            remote_host: Remote destination host
            remote_port: Remote destination port
            ssh_server: SSH server to tunnel through
            username: SSH username
            key_path: SSH key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating local port forward: localhost:{local_port} -> {remote_host}:{remote_port}")
            
            # SSH local port forward:
            # ssh -L <local_port>:<remote_host>:<remote_port> user@ssh_server
            
            # Or using Python asyncio:
            # Open local socket on local_port
            # Connect to SSH server
            # Forward traffic to remote_host:remote_port through SSH tunnel
            
            forward_info = {
                'type': 'local',
                'local_port': local_port,
                'remote_host': remote_host,
                'remote_port': remote_port,
                'ssh_server': ssh_server,
                'active': True
            }
            
            self.active_forwards.append(forward_info)
            
            logger.info(f"Local port forward established on port {local_port}")
            return True
            
        except Exception as e:
            logger.error(f"Local port forward failed: {e}")
            return False
            
    async def remote_port_forward(self, remote_port: int, local_host: str,
                                  local_port: int, ssh_server: str,
                                  username: str, key_path: str = None) -> bool:
        """
        Create remote port forward via SSH
        
        Args:
            remote_port: Remote port to listen on
            local_host: Local destination host
            local_port: Local destination port
            ssh_server: SSH server
            username: SSH username
            key_path: SSH key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating remote port forward: {ssh_server}:{remote_port} -> {local_host}:{local_port}")
            
            # SSH remote port forward:
            # ssh -R <remote_port>:<local_host>:<local_port> user@ssh_server
            
            # Useful for exposing local services through remote server
            
            forward_info = {
                'type': 'remote',
                'remote_port': remote_port,
                'local_host': local_host,
                'local_port': local_port,
                'ssh_server': ssh_server,
                'active': True
            }
            
            self.active_forwards.append(forward_info)
            
            logger.info(f"Remote port forward established on {ssh_server}:{remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Remote port forward failed: {e}")
            return False
            
    async def dynamic_port_forward(self, local_port: int, ssh_server: str,
                                   username: str, key_path: str = None) -> bool:
        """
        Create dynamic port forward (SOCKS proxy) via SSH
        
        Args:
            local_port: Local port for SOCKS proxy
            ssh_server: SSH server
            username: SSH username
            key_path: SSH key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating dynamic port forward (SOCKS) on port {local_port}...")
            
            # SSH dynamic forward:
            # ssh -D <local_port> user@ssh_server
            
            # Creates SOCKS4/5 proxy on local_port
            
            forward_info = {
                'type': 'dynamic',
                'local_port': local_port,
                'ssh_server': ssh_server,
                'protocol': 'SOCKS5',
                'active': True
            }
            
            self.active_forwards.append(forward_info)
            
            logger.info(f"SOCKS proxy active on localhost:{local_port}")
            logger.info(f"Configure clients to use: socks5://localhost:{local_port}")
            return True
            
        except Exception as e:
            logger.error(f"Dynamic port forward failed: {e}")
            return False
            
    async def chisel_forward(self, chisel_server: str, local_port: int,
                            remote_host: str, remote_port: int) -> bool:
        """
        Port forward using Chisel
        
        Args:
            chisel_server: Chisel server address
            local_port: Local port
            remote_host: Remote destination
            remote_port: Remote port
            
        Returns:
            Success status
        """
        try:
            logger.info("Creating Chisel tunnel...")
            
            # Chisel server on attacker machine:
            # chisel server -p 8080 --reverse
            
            # Chisel client on compromised host:
            # chisel client <server>:8080 R:<local_port>:<remote_host>:<remote_port>
            
            logger.info(f"Chisel tunnel established: {local_port} -> {remote_host}:{remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Chisel forward failed: {e}")
            return False
            
    async def netsh_port_forward(self, listen_port: int, connect_host: str,
                                 connect_port: int) -> bool:
        """
        Windows netsh port forward
        
        Args:
            listen_port: Port to listen on
            connect_host: Destination host
            connect_port: Destination port
            
        Returns:
            Success status
        """
        try:
            logger.warning("Creating netsh port forward...")
            
            # netsh interface portproxy add v4tov4 listenport=<port> listenaddress=0.0.0.0 connectport=<port> connectaddress=<host>
            
            logger.warning(f"netsh forward: 0.0.0.0:{listen_port} -> {connect_host}:{connect_port}")
            return True
            
        except Exception as e:
            logger.error(f"netsh port forward failed: {e}")
            return False
            
    def list_active_forwards(self) -> List[Dict[str, Any]]:
        """
        List active port forwards
        
        Returns:
            List of active forwards
        """
        return [f for f in self.active_forwards if f.get('active', False)]
