"""
Nmap Scanner Module
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from .base_tool import BaseTool
from loguru import logger


class NmapScanner(BaseTool):
    """Nmap network scanner wrapper"""
    
    def get_default_command(self) -> str:
        return "nmap"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        results = {
            "hosts": [],
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "raw_output": output
        }
        
        # Parse hosts
        host_pattern = r"Nmap scan report for ([\w\.-]+) \(([\d\.]+)\)"
        hosts = re.findall(host_pattern, output)
        results["hosts"] = [{"hostname": h[0], "ip": h[1]} for h in hosts]
        
        # Parse open ports
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+([\w\-]+)(?:\s+(.+))?"
        ports = re.findall(port_pattern, output)
        
        for port, protocol, service, version in ports:
            port_info = {
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "version": version.strip() if version else ""
            }
            results["open_ports"].append(port_info)
            results["services"].append(service)
        
        # Parse OS detection
        os_pattern = r"OS details: (.+)"
        os_match = re.search(os_pattern, output)
        if os_match:
            results["os_detection"] = os_match.group(1)
        
        return results
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform a quick scan"""
        logger.info(f"Starting quick scan on {target}")
        return self.execute(["-F", target])
    
    def service_scan(self, target: str) -> Dict[str, Any]:
        """Scan with service version detection"""
        logger.info(f"Starting service scan on {target}")
        return self.execute(["-sV", "-sC", target])
    
    def full_scan(self, target: str, os_detection: bool = True) -> Dict[str, Any]:
        """Perform comprehensive scan"""
        logger.info(f"Starting full scan on {target}")
        args = ["-sV", "-sC", "-p-", target]
        if os_detection:
            args.insert(0, "-O")
        return self.execute(args, sudo=os_detection)
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Scan for vulnerabilities using NSE scripts"""
        logger.info(f"Starting vulnerability scan on {target}")
        return self.execute(["--script", "vuln", target])
    
    def custom_scan(self, target: str, flags: List[str]) -> Dict[str, Any]:
        """Execute custom nmap scan"""
        logger.info(f"Starting custom scan on {target} with flags: {flags}")
        return self.execute(flags + [target])
