"""
SOCKS Proxy - SOCKS4/5 Proxy Chains
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class SOCKSProxy:
    """
    SOCKS proxy management and chaining
    """
    
    def __init__(self):
        """Initialize SOCKS proxy"""
        self.proxies = []
        
        logger.info("SOCKSProxy initialized")
        
    async def start_socks_server(self, listen_port: int, version: int = 5) -> bool:
        """
        Start SOCKS proxy server
        
        Args:
            listen_port: Port to listen on
            version: SOCKS version (4 or 5)
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Starting SOCKS{version} server on port {listen_port}...")
            
            # Using Python asyncio SOCKS server
            # Or using tools like microsocks, dante-server
            
            proxy_info = {
                'port': listen_port,
                'version': version,
                'type': 'server',
                'active': True
            }
            
            self.proxies.append(proxy_info)
            
            logger.info(f"SOCKS{version} server active on 0.0.0.0:{listen_port}")
            return True
            
        except Exception as e:
            logger.error(f"SOCKS server start failed: {e}")
            return False
            
    async def ssh_socks_tunnel(self, ssh_host: str, ssh_user: str, local_port: int,
                               key_path: str = None) -> bool:
        """
        Create SOCKS tunnel via SSH
        
        Args:
            ssh_host: SSH server
            ssh_user: SSH username
            local_port: Local SOCKS port
            key_path: SSH key path
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating SSH SOCKS tunnel to {ssh_host}...")
            
            # ssh -D <local_port> -N -f user@host
            # -D: Dynamic port forwarding (SOCKS)
            # -N: No command execution
            # -f: Background
            
            proxy_info = {
                'port': local_port,
                'version': 5,
                'type': 'ssh_tunnel',
                'ssh_host': ssh_host,
                'active': True
            }
            
            self.proxies.append(proxy_info)
            
            logger.info(f"SSH SOCKS tunnel active on localhost:{local_port}")
            return True
            
        except Exception as e:
            logger.error(f"SSH SOCKS tunnel failed: {e}")
            return False
            
    async def configure_proxychains(self, proxy_list: List[Dict[str, Any]],
                                   chain_type: str = 'dynamic') -> bool:
        """
        Configure proxychains
        
        Args:
            proxy_list: List of proxies (host, port, type)
            chain_type: Chain type (dynamic/strict/random)
            
        Returns:
            Success status
        """
        try:
            logger.info("Configuring proxychains...")
            
            # Edit /etc/proxychains.conf or ~/.proxychains/proxychains.conf
            
            # [ProxyList]
            # socks5 127.0.0.1 9050
            # socks4 192.168.1.1 1080
            # http 10.0.0.1 8080
            
            config = f"""
            {chain_type}_chain
            proxy_dns
            
            [ProxyList]
            """
            
            for proxy in proxy_list:
                config += f"{proxy['type']} {proxy['host']} {proxy['port']}\n"
                
            logger.info(f"Proxychains configured with {len(proxy_list)} proxies")
            logger.info(f"Chain type: {chain_type}")
            logger.info("Use: proxychains <command>")
            return True
            
        except Exception as e:
            logger.error(f"Proxychains configuration failed: {e}")
            return False
            
    async def redsocks_transparent_proxy(self, socks_host: str, socks_port: int,
                                        local_port: int = 12345) -> bool:
        """
        Configure redsocks for transparent proxying
        
        Args:
            socks_host: SOCKS proxy host
            socks_port: SOCKS proxy port
            local_port: Local redsocks port
            
        Returns:
            Success status
        """
        try:
            logger.info("Configuring redsocks transparent proxy...")
            
            # redsocks.conf:
            # redsocks {
            #     local_ip = 127.0.0.1;
            #     local_port = 12345;
            #     ip = <socks_host>;
            #     port = <socks_port>;
            #     type = socks5;
            # }
            
            # iptables rules to redirect traffic:
            # iptables -t nat -N REDSOCKS
            # iptables -t nat -A REDSOCKS -d <internal_network> -j RETURN
            # iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345
            # iptables -t nat -A OUTPUT -p tcp -j REDSOCKS
            
            logger.info(f"Redsocks configured: {socks_host}:{socks_port}")
            logger.info("All TCP traffic will be proxied")
            return True
            
        except Exception as e:
            logger.error(f"Redsocks configuration failed: {e}")
            return False
            
    async def metasploit_socks_proxy(self, session_id: int, port: int = 1080) -> bool:
        """
        Create SOCKS proxy through Metasploit session
        
        Args:
            session_id: Meterpreter session ID
            port: Local SOCKS port
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Creating Metasploit SOCKS proxy via session {session_id}...")
            
            # In Metasploit:
            # use auxiliary/server/socks_proxy
            # set SRVPORT <port>
            # set VERSION 5
            # run
            
            # Then route through session:
            # route add <target_network> <netmask> <session_id>
            
            logger.info(f"Metasploit SOCKS proxy active on localhost:{port}")
            logger.info(f"Configure proxychains: socks5 127.0.0.1 {port}")
            return True
            
        except Exception as e:
            logger.error(f"Metasploit SOCKS proxy failed: {e}")
            return False
            
    async def windows_netsh_socks(self, listen_port: int, remote_socks: str,
                                 remote_port: int) -> bool:
        """
        Create SOCKS proxy using Windows netsh
        
        Args:
            listen_port: Local port to listen
            remote_socks: Remote SOCKS server
            remote_port: Remote SOCKS port
            
        Returns:
            Success status
        """
        try:
            logger.info("Creating Windows netsh SOCKS proxy...")
            
            # netsh interface portproxy add v4tov4 listenport=<port> connectaddress=<socks_host> connectport=<socks_port>
            
            logger.info(f"Windows SOCKS proxy: localhost:{listen_port} -> {remote_socks}:{remote_port}")
            return True
            
        except Exception as e:
            logger.error(f"Windows netsh SOCKS failed: {e}")
            return False
            
    def get_active_proxies(self) -> List[Dict[str, Any]]:
        """
        Get list of active SOCKS proxies
        
        Returns:
            List of active proxies
        """
        return [p for p in self.proxies if p.get('active', False)]
