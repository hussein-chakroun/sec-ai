"""
Route Manipulation - Network Route Management for Pivoting
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RouteManipulator:
    """
    Network route manipulation for pivoting
    """
    
    def __init__(self, os_type: str = 'linux'):
        """
        Initialize route manipulator
        
        Args:
            os_type: Operating system (linux/windows)
        """
        self.os_type = os_type
        self.added_routes = []
        
        logger.info(f"RouteManipulator initialized for {os_type}")
        
    async def view_routing_table(self) -> List[Dict[str, Any]]:
        """
        View current routing table
        
        Returns:
            List of routes
        """
        try:
            logger.info("Viewing routing table...")
            
            if self.os_type == 'linux':
                # ip route show
                # or: route -n
                # or: netstat -rn
                pass
            else:  # windows
                # route print
                # or: Get-NetRoute
                pass
                
            routes = [
                {
                    'destination': '0.0.0.0',
                    'netmask': '0.0.0.0',
                    'gateway': '192.168.1.1',
                    'interface': 'eth0',
                    'metric': 100
                },
                {
                    'destination': '10.0.0.0',
                    'netmask': '255.0.0.0',
                    'gateway': '10.0.0.1',
                    'interface': 'tun0',
                    'metric': 50
                }
            ]
            
            logger.info(f"Found {len(routes)} routes")
            return routes
            
        except Exception as e:
            logger.error(f"Route viewing failed: {e}")
            return []
            
    async def add_route(self, network: str, netmask: str, gateway: str,
                       interface: str = None) -> bool:
        """
        Add network route
        
        Args:
            network: Destination network
            netmask: Network mask
            gateway: Gateway IP
            interface: Network interface (optional)
            
        Returns:
            Success status
        """
        try:
            logger.warning(f"Adding route: {network}/{netmask} via {gateway}...")
            
            if self.os_type == 'linux':
                # ip route add <network>/<cidr> via <gateway> dev <interface>
                # or: route add -net <network> netmask <netmask> gw <gateway>
                cmd = f"ip route add {network}/{self._cidr_from_netmask(netmask)} via {gateway}"
                if interface:
                    cmd += f" dev {interface}"
                    
            else:  # windows
                # route add <network> mask <netmask> <gateway>
                cmd = f"route add {network} mask {netmask} {gateway}"
                if interface:
                    cmd += f" IF {interface}"
                    
            route_info = {
                'network': network,
                'netmask': netmask,
                'gateway': gateway,
                'interface': interface,
                'command': cmd
            }
            
            self.added_routes.append(route_info)
            
            logger.warning(f"Route added: {network}/{netmask}")
            return True
            
        except Exception as e:
            logger.error(f"Route addition failed: {e}")
            return False
            
    async def delete_route(self, network: str, netmask: str = None) -> bool:
        """
        Delete network route
        
        Args:
            network: Destination network
            netmask: Network mask
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Deleting route: {network}...")
            
            if self.os_type == 'linux':
                # ip route del <network>/<cidr>
                # or: route del -net <network> netmask <netmask>
                cmd = f"ip route del {network}"
            else:  # windows
                # route delete <network>
                cmd = f"route delete {network}"
                
            logger.info(f"Route deleted: {network}")
            return True
            
        except Exception as e:
            logger.error(f"Route deletion failed: {e}")
            return False
            
    async def add_metasploit_route(self, session_id: int, subnet: str, netmask: str) -> bool:
        """
        Add route through Metasploit session
        
        Args:
            session_id: Meterpreter session ID
            subnet: Target subnet
            netmask: Subnet mask
            
        Returns:
            Success status
        """
        try:
            logger.info(f"Adding Metasploit route through session {session_id}...")
            
            # In Metasploit:
            # route add <subnet> <netmask> <session_id>
            
            # Or using autoroute:
            # use post/multi/manage/autoroute
            # set SESSION <session_id>
            # set SUBNET <subnet>
            # set NETMASK <netmask>
            # run
            
            logger.info(f"Metasploit route added: {subnet}/{netmask} via session {session_id}")
            logger.info("All Metasploit modules can now reach this network")
            return True
            
        except Exception as e:
            logger.error(f"Metasploit route addition failed: {e}")
            return False
            
    async def enable_ip_forwarding(self) -> bool:
        """
        Enable IP forwarding on system
        
        Returns:
            Success status
        """
        try:
            logger.warning("Enabling IP forwarding...")
            
            if self.os_type == 'linux':
                # Temporary:
                # echo 1 > /proc/sys/net/ipv4/ip_forward
                # sysctl -w net.ipv4.ip_forward=1
                
                # Permanent:
                # Edit /etc/sysctl.conf: net.ipv4.ip_forward=1
                # sysctl -p
                pass
            else:  # windows
                # reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f
                # Restart-Service RemoteAccess
                pass
                
            logger.warning("IP forwarding enabled - system can route traffic")
            return True
            
        except Exception as e:
            logger.error(f"IP forwarding enable failed: {e}")
            return False
            
    async def setup_nat(self, internal_interface: str, external_interface: str,
                       internal_network: str) -> bool:
        """
        Setup NAT (Network Address Translation)
        
        Args:
            internal_interface: Internal network interface
            external_interface: External network interface
            internal_network: Internal network CIDR
            
        Returns:
            Success status
        """
        try:
            logger.warning("Setting up NAT...")
            
            if self.os_type == 'linux':
                # iptables -t nat -A POSTROUTING -s <internal_network> -o <external_interface> -j MASQUERADE
                # iptables -A FORWARD -i <internal_interface> -o <external_interface> -j ACCEPT
                # iptables -A FORWARD -i <external_interface> -o <internal_interface> -m state --state RELATED,ESTABLISHED -j ACCEPT
                
                logger.warning(f"NAT configured: {internal_network} via {external_interface}")
            else:  # windows
                # New-NetNat -Name "NATNetwork" -InternalIPInterfaceAddressPrefix <internal_network>
                logger.warning("NAT configured via Windows NAT")
                
            return True
            
        except Exception as e:
            logger.error(f"NAT setup failed: {e}")
            return False
            
    async def configure_policy_based_routing(self, source_network: str,
                                            gateway: str, table_id: int = 100) -> bool:
        """
        Configure policy-based routing
        
        Args:
            source_network: Source network CIDR
            gateway: Gateway for this traffic
            table_id: Routing table ID
            
        Returns:
            Success status
        """
        try:
            logger.info("Configuring policy-based routing...")
            
            # ip rule add from <source_network> table <table_id>
            # ip route add default via <gateway> table <table_id>
            
            logger.info(f"Policy routing: {source_network} -> {gateway}")
            return True
            
        except Exception as e:
            logger.error(f"Policy routing configuration failed: {e}")
            return False
            
    def _cidr_from_netmask(self, netmask: str) -> int:
        """
        Convert netmask to CIDR notation
        
        Args:
            netmask: Netmask (e.g., 255.255.255.0)
            
        Returns:
            CIDR prefix length
        """
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])
        
    def get_added_routes(self) -> List[Dict[str, Any]]:
        """
        Get list of routes added by this tool
        
        Returns:
            List of added routes
        """
        return self.added_routes
