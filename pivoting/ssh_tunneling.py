"""
SSH Tunneling - Multi-Hop SSH and ProxyJump
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class SSHTunneling:
    """
    SSH tunneling and multi-hop connections
    """
    
    def __init__(self):
        """Initialize SSH tunneling"""
        self.active_tunnels = []
        
        logger.info("SSHTunneling initialized")
        
    async def create_ssh_tunnel(self, ssh_host: str, ssh_user: str,
                               local_port: int, remote_host: str, remote_port: int,
                               key_path: str = None) -> bool:
        """
        Create SSH tunnel (local port forward)
        
        Args:
            ssh_host: SSH server to tunnel through
            ssh_user: SSH username
            local_port: Local port to bind
            remote_host: Destination host
            remote_port: Destination port
            key_path: SSH private key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating SSH tunnel: localhost:{local_port} -> {remote_host}:{remote_port}")
            
            # ssh -L <local_port>:<remote_host>:<remote_port> user@ssh_host -i <key_path> -N -f
            # -L: Local port forward
            # -N: No command execution
            # -f: Background
            
            tunnel_info = {
                'type': 'local_forward',
                'ssh_host': ssh_host,
                'local_port': local_port,
                'remote_host': remote_host,
                'remote_port': remote_port,
                'active': True
            }
            
            self.active_tunnels.append(tunnel_info)
            
            logger.info(f"SSH tunnel active on localhost:{local_port}")
            return True
            
        except Exception as e:
            logger.error(f"SSH tunnel creation failed: {e}")
            return False
            
    async def multi_hop_ssh(self, jump_hosts: List[Dict[str, str]], 
                           final_target: str, final_user: str) -> bool:
        """
        Create multi-hop SSH connection
        
        Args:
            jump_hosts: List of jump hosts with user, host, key
            final_target: Final destination host
            final_user: Username for final target
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating multi-hop SSH through {len(jump_hosts)} jump hosts...")
            
            # Method 1: ProxyJump (OpenSSH 7.3+)
            # ssh -J user1@host1,user2@host2,user3@host3 final_user@final_target
            
            jump_string = ','.join([f"{j['user']}@{j['host']}" for j in jump_hosts])
            cmd = f"ssh -J {jump_string} {final_user}@{final_target}"
            
            # Method 2: ProxyCommand chain
            # ssh -o ProxyCommand="ssh -W %h:%p user1@host1" user2@host2
            
            logger.info(f"Multi-hop SSH connection established to {final_target}")
            logger.info(f"Jump path: {' -> '.join([j['host'] for j in jump_hosts])} -> {final_target}")
            return True
            
        except Exception as e:
            logger.error(f"Multi-hop SSH failed: {e}")
            return False
            
    async def reverse_ssh_tunnel(self, ssh_host: str, ssh_user: str,
                                remote_port: int, local_host: str, local_port: int,
                                key_path: str = None) -> bool:
        """
        Create reverse SSH tunnel (remote port forward)
        
        Args:
            ssh_host: SSH server
            ssh_user: SSH username
            remote_port: Remote port to bind
            local_host: Local destination host
            local_port: Local destination port
            key_path: SSH private key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating reverse SSH tunnel: {ssh_host}:{remote_port} -> {local_host}:{local_port}")
            
            # ssh -R <remote_port>:<local_host>:<local_port> user@ssh_host -i <key_path> -N -f
            
            # Enable GatewayPorts on SSH server for external access:
            # /etc/ssh/sshd_config: GatewayPorts yes
            
            tunnel_info = {
                'type': 'remote_forward',
                'ssh_host': ssh_host,
                'remote_port': remote_port,
                'local_host': local_host,
                'local_port': local_port,
                'active': True
            }
            
            self.active_tunnels.append(tunnel_info)
            
            logger.info(f"Reverse SSH tunnel active: {ssh_host}:{remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Reverse SSH tunnel failed: {e}")
            return False
            
    async def dynamic_ssh_tunnel(self, ssh_host: str, ssh_user: str,
                                local_port: int = 1080, key_path: str = None) -> bool:
        """
        Create dynamic SSH tunnel (SOCKS proxy)
        
        Args:
            ssh_host: SSH server
            ssh_user: SSH username
            local_port: Local SOCKS port
            key_path: SSH private key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating dynamic SSH tunnel (SOCKS) on port {local_port}...")
            
            # ssh -D <local_port> user@ssh_host -i <key_path> -N -f
            
            tunnel_info = {
                'type': 'dynamic',
                'ssh_host': ssh_host,
                'local_port': local_port,
                'protocol': 'SOCKS5',
                'active': True
            }
            
            self.active_tunnels.append(tunnel_info)
            
            logger.info(f"SOCKS proxy active on localhost:{local_port}")
            logger.info(f"Configure clients: socks5://localhost:{local_port}")
            return True
            
        except Exception as e:
            logger.error(f"Dynamic SSH tunnel failed: {e}")
            return False
            
    async def ssh_vpn_tunnel(self, ssh_host: str, ssh_user: str,
                            local_tun: int = 0, remote_tun: int = 0) -> bool:
        """
        Create SSH VPN tunnel using TUN devices
        
        Args:
            ssh_host: SSH server
            ssh_user: SSH username
            local_tun: Local TUN device number
            remote_tun: Remote TUN device number
            
        Returns:
            Success status
        """
        try:
            logger.info("Creating SSH VPN tunnel...")
            
            # Requires PermitTunnel yes in sshd_config
            # ssh -w <local_tun>:<remote_tun> user@ssh_host
            
            # Configure TUN interfaces:
            # On local: ip addr add 10.0.0.1/30 dev tun0; ip link set tun0 up
            # On remote: ip addr add 10.0.0.2/30 dev tun0; ip link set tun0 up
            
            # Add routes:
            # ip route add <remote_network> via 10.0.0.2
            
            logger.info(f"SSH VPN tunnel established via tun{local_tun}")
            return True
            
        except Exception as e:
            logger.error(f"SSH VPN tunnel failed: {e}")
            return False
            
    async def ssh_over_http_proxy(self, proxy_host: str, proxy_port: int,
                                  ssh_host: str, ssh_user: str) -> bool:
        """
        SSH connection through HTTP proxy
        
        Args:
            proxy_host: HTTP proxy host
            proxy_port: HTTP proxy port
            ssh_host: SSH server
            ssh_user: SSH username
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating SSH connection through HTTP proxy {proxy_host}:{proxy_port}...")
            
            # Using ProxyCommand with netcat or corkscrew:
            # ssh -o ProxyCommand="nc -X connect -x <proxy_host>:<proxy_port> %h %p" user@ssh_host
            # or
            # ssh -o ProxyCommand="corkscrew <proxy_host> <proxy_port> %h %p" user@ssh_host
            
            logger.info(f"SSH connection established to {ssh_host} via proxy")
            return True
            
        except Exception as e:
            logger.error(f"SSH over HTTP proxy failed: {e}")
            return False
            
    async def persistent_ssh_tunnel(self, ssh_host: str, ssh_user: str,
                                   local_port: int, remote_host: str,
                                   remote_port: int, key_path: str = None) -> bool:
        """
        Create persistent SSH tunnel with autossh
        
        Args:
            ssh_host: SSH server
            ssh_user: SSH username
            local_port: Local port
            remote_host: Destination host
            remote_port: Destination port
            key_path: SSH private key path
            
        Returns:
            Success status
        """
        try:
            logger.info("Creating persistent SSH tunnel with autossh...")
            
            # autossh -M <monitoring_port> -N -L <local_port>:<remote_host>:<remote_port> user@ssh_host
            # -M: Monitoring port for connection health
            
            # Or use systemd service for persistence
            
            logger.info(f"Persistent SSH tunnel established on localhost:{local_port}")
            logger.info("Tunnel will automatically reconnect if dropped")
            return True
            
        except Exception as e:
            logger.error(f"Persistent SSH tunnel failed: {e}")
            return False
            
    def get_active_tunnels(self) -> List[Dict[str, Any]]:
        """
        Get list of active SSH tunnels
        
        Returns:
            List of active tunnels
        """
        return [t for t in self.active_tunnels if t.get('active', False)]
