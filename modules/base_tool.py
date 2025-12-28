"""
Base Tool Module
"""
import subprocess
import shlex
import platform
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from loguru import logger
import asyncio


class ToolExecutionError(Exception):
    """Custom exception for tool execution errors"""
    pass


class BaseTool(ABC):
    """Abstract base class for pentesting tools"""
    
    def __init__(self, tool_path: Optional[str] = None, timeout: int = 600):
        self.tool_path = tool_path or self.get_default_command()
        self.timeout = timeout
        self.last_output = ""
        self.last_error = ""
    
    @abstractmethod
    def get_default_command(self) -> str:
        """Get default command name"""
        pass
    
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured format"""
        pass
    
    def execute(self, args: List[str], sudo: bool = False) -> Dict[str, Any]:
        """Execute tool with given arguments"""
        command = [self.tool_path] + args
        
        if sudo:
            command = ["sudo"] + command
        
        logger.info(f"Executing: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            self.last_output = result.stdout
            self.last_error = result.stderr
            
            if result.returncode != 0:
                logger.warning(f"Tool returned non-zero exit code: {result.returncode}")
                logger.warning(f"stderr: {result.stderr}")
            
            return {
                "success": result.returncode == 0,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "parsed": self.parse_output(result.stdout)
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Tool execution timed out after {self.timeout} seconds")
            raise ToolExecutionError(f"Execution timed out after {self.timeout} seconds")
        
        except FileNotFoundError:
            logger.error(f"Tool not found: {self.tool_path}")
            raise ToolExecutionError(f"Tool not found: {self.tool_path}. Please install it.")
        
        except Exception as e:
            logger.error(f"Unexpected error executing tool: {e}")
            raise ToolExecutionError(f"Unexpected error: {str(e)}")
    
    async def execute_async(self, args: List[str], sudo: bool = False) -> Dict[str, Any]:
        """Execute tool asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.execute, args, sudo)
    
    def check_installed(self) -> bool:
        """Check if tool is installed"""
        try:
            result = subprocess.run(
                [self.tool_path, "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def get_install_command(self) -> Optional[List[str]]:
        """Get installation command for this tool (platform-specific)"""
        import platform
        system = platform.system().lower()
        
        tool_name = self.get_default_command()
        
        # Installation commands by platform
        if system == "linux":
            # Detect package manager
            if self._command_exists("apt-get"):
                return ["sudo", "apt-get", "install", "-y", tool_name]
            elif self._command_exists("yum"):
                return ["sudo", "yum", "install", "-y", tool_name]
            elif self._command_exists("dnf"):
                return ["sudo", "dnf", "install", "-y", tool_name]
            elif self._command_exists("pacman"):
                return ["sudo", "pacman", "-S", "--noconfirm", tool_name]
        
        elif system == "darwin":  # macOS
            if self._command_exists("brew"):
                return ["brew", "install", tool_name]
        
        elif system == "windows":
            # Try chocolatey or scoop
            if self._command_exists("choco"):
                return ["choco", "install", "-y", tool_name]
            elif self._command_exists("scoop"):
                return ["scoop", "install", tool_name]
        
        return None
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(
                ["which", command] if platform.system() != "Windows" else ["where", command],
                capture_output=True,
                timeout=2
            )
            return True
        except:
            return False
    
    def attempt_install(self) -> bool:
        """Attempt to install the tool automatically"""
        install_cmd = self.get_install_command()
        
        if not install_cmd:
            logger.warning(f"No automatic installation method available for {self.tool_path}")
            return False
        
        logger.info(f"Attempting to install {self.tool_path}: {' '.join(install_cmd)}")
        
        try:
            result = subprocess.run(
                install_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for installation
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully installed {self.tool_path}")
                return True
            else:
                logger.error(f"Installation failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Installation timed out")
            return False
        except Exception as e:
            logger.error(f"Installation error: {e}")
            return False
