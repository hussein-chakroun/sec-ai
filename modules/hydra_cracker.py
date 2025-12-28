"""
Hydra Password Cracker Module
"""
import re
from typing import Dict, Any, List
from .base_tool import BaseTool
from loguru import logger


class HydraCracker(BaseTool):
    """Hydra password cracker wrapper"""
    
    def get_default_command(self) -> str:
        return "hydra"
    
    def get_install_command(self, platform: str, package_manager: str) -> str:
        """Get platform-specific installation command for Hydra"""
        if platform == "linux":
            if package_manager in ["apt", "apt-get"]:
                return "hydra"
            elif package_manager in ["yum", "dnf"]:
                return "hydra"
            elif package_manager == "pacman":
                return "hydra"
        elif platform == "darwin":
            return "hydra"
        elif platform == "windows":
            return "hydra"  # Available via chocolatey
        
        return None
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output"""
        results = {
            "credentials_found": [],
            "attempts": 0,
            "success": False,
            "raw_output": output
        }
        
        # Parse found credentials
        # Format: [port][protocol] host: login   password: pass
        cred_pattern = r"\[(\d+)\]\[(\w+)\]\s+host:\s+([\w\.-]+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
        credentials = re.findall(cred_pattern, output)
        
        for port, protocol, host, login, password in credentials:
            results["credentials_found"].append({
                "port": port,
                "protocol": protocol,
                "host": host,
                "username": login,
                "password": password
            })
        
        results["success"] = len(results["credentials_found"]) > 0
        
        # Parse attempt count
        attempt_pattern = r"(\d+) valid passwords found"
        attempt_match = re.search(attempt_pattern, output)
        if attempt_match:
            results["attempts"] = int(attempt_match.group(1))
        
        return results
    
    def crack_ssh(self, target: str, username: str = None, userlist: str = None, 
                  password: str = None, passlist: str = None, port: int = 22) -> Dict[str, Any]:
        """Crack SSH credentials"""
        logger.info(f"Starting SSH password cracking on {target}")
        
        args = ["-s", str(port), target, "ssh"]
        
        if username:
            args.extend(["-l", username])
        elif userlist:
            args.extend(["-L", userlist])
        else:
            raise ValueError("Either username or userlist must be provided")
        
        if password:
            args.extend(["-p", password])
        elif passlist:
            args.extend(["-P", passlist])
        else:
            raise ValueError("Either password or passlist must be provided")
        
        return self.execute(args)
    
    def crack_ftp(self, target: str, username: str = None, userlist: str = None,
                  password: str = None, passlist: str = None, port: int = 21) -> Dict[str, Any]:
        """Crack FTP credentials"""
        logger.info(f"Starting FTP password cracking on {target}")
        
        args = ["-s", str(port), target, "ftp"]
        
        if username:
            args.extend(["-l", username])
        elif userlist:
            args.extend(["-L", userlist])
        
        if password:
            args.extend(["-p", password])
        elif passlist:
            args.extend(["-P", passlist])
        
        return self.execute(args)
    
    def crack_http_form(self, target: str, path: str, form_params: str,
                       username: str = None, userlist: str = None,
                       password: str = None, passlist: str = None) -> Dict[str, Any]:
        """Crack HTTP form credentials"""
        logger.info(f"Starting HTTP form password cracking on {target}")
        
        args = [target, "http-post-form", f"{path}:{form_params}"]
        
        if username:
            args.extend(["-l", username])
        elif userlist:
            args.extend(["-L", userlist])
        
        if password:
            args.extend(["-p", password])
        elif passlist:
            args.extend(["-P", passlist])
        
        return self.execute(args)
    
    def custom_attack(self, target: str, service: str, flags: List[str]) -> Dict[str, Any]:
        """Execute custom hydra attack"""
        logger.info(f"Starting custom Hydra attack on {target}")
        return self.execute([target, service] + flags)
