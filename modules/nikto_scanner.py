"""
Nikto Web Server Scanner Module
Scans web servers for known vulnerabilities, misconfigurations, and security issues
"""
import re
import subprocess
from typing import Dict, Any, List, Optional
from .base_tool import BaseTool
from loguru import logger


class NiktoScanner(BaseTool):
    """Nikto web vulnerability scanner wrapper"""
    
    def get_default_command(self) -> str:
        return "nikto"
    
    def get_install_command(self) -> List[str]:
        """Nikto installation commands"""
        import platform
        system = platform.system().lower()
        
        if system == "linux":
            if self._command_exists("apt-get"):
                return ["sudo", "apt-get", "install", "-y", "nikto"]
            elif self._command_exists("yum"):
                return ["sudo", "yum", "install", "-y", "nikto"]
            elif self._command_exists("pacman"):
                return ["sudo", "pacman", "-S", "--noconfirm", "nikto"]
        
        elif system == "darwin":
            if self._command_exists("brew"):
                return ["brew", "install", "nikto"]
        
        # Fallback: Git clone
        logger.info("Please install Nikto manually from: https://github.com/sullo/nikto")
        return []
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run Nikto scan on target
        
        Args:
            target: Target URL or IP address
            options: Additional scan options
                - port: Custom port (default: auto-detect from URL)
                - ssl: Force SSL mode (default: auto-detect)
                - tuning: Scan tuning (1-9, x for all)
                - timeout: Request timeout in seconds
                - evasion: IDS evasion techniques
                - format: Output format (html, xml, csv, txt)
                
        Returns:
            Dictionary with scan results and vulnerabilities
        """
        if not self.is_available():
            logger.error("Nikto is not available")
            return {"error": "Nikto not installed"}
        
        options = options or {}
        
        # Build command
        cmd = [self.command, "-host", target]
        
        # Add options
        if options.get('port'):
            cmd.extend(["-port", str(options['port'])])
        
        if options.get('ssl'):
            cmd.append("-ssl")
        
        if options.get('tuning'):
            cmd.extend(["-Tuning", str(options['tuning'])])
        
        if options.get('timeout'):
            cmd.extend(["-timeout", str(options['timeout'])])
        
        if options.get('evasion'):
            cmd.extend(["-evasion", str(options['evasion'])])
        
        # Output format
        output_format = options.get('format', 'txt')
        if output_format != 'txt':
            cmd.extend(["-Format", output_format])
        
        # No interactive prompts
        cmd.append("-nointeractive")
        
        # Execute scan
        logger.info(f"Running Nikto scan on {target}")
        output = self.execute(cmd)
        
        # Parse results
        results = self.parse_output(output)
        results['target'] = target
        results['command'] = ' '.join(cmd)
        
        return results
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse Nikto scan output
        
        Returns:
            Dictionary containing:
                - vulnerabilities: List of found vulnerabilities
                - server_info: Server information
                - findings_count: Number of findings
                - osvdb_ids: List of OSVDB IDs found
        """
        results = {
            "vulnerabilities": [],
            "server_info": {},
            "findings_count": 0,
            "osvdb_ids": [],
            "raw_output": output
        }
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Parse server information
            if line.startswith("+ Server:"):
                results['server_info']['server'] = line.split(":", 1)[1].strip()
            
            elif line.startswith("+ Start Time:"):
                results['server_info']['start_time'] = line.split(":", 1)[1].strip()
            
            elif line.startswith("+ Target IP:"):
                results['server_info']['target_ip'] = line.split(":", 1)[1].strip()
            
            elif line.startswith("+ Target Port:"):
                results['server_info']['target_port'] = line.split(":", 1)[1].strip()
            
            # Parse findings (lines starting with +)
            elif line.startswith("+ ") and not any(x in line for x in ["Server:", "Start Time:", "Target"]):
                # Extract OSVDB ID if present
                osvdb_match = re.search(r'OSVDB-(\d+)', line)
                osvdb_id = osvdb_match.group(1) if osvdb_match else None
                
                if osvdb_id:
                    results['osvdb_ids'].append(osvdb_id)
                
                # Determine severity based on keywords
                severity = "info"
                if any(keyword in line.lower() for keyword in ['vulnerable', 'exploit', 'critical', 'severe']):
                    severity = "high"
                elif any(keyword in line.lower() for keyword in ['weak', 'exposed', 'disclosed', 'default']):
                    severity = "medium"
                elif any(keyword in line.lower() for keyword in ['missing', 'deprecated', 'outdated']):
                    severity = "low"
                
                # Create vulnerability entry
                vuln = {
                    'vuln_id': f"OSVDB-{osvdb_id}" if osvdb_id else f"NIKTO-{results['findings_count'] + 1}",
                    'title': line[2:].strip(),  # Remove "+ " prefix
                    'description': line[2:].strip(),
                    'severity': severity,
                    'tool_source': 'nikto',
                    'evidence': [line],
                    'confidence': 0.8
                }
                
                results['vulnerabilities'].append(vuln)
                results['findings_count'] += 1
        
        logger.info(f"Nikto scan complete - Found {results['findings_count']} findings")
        
        return results
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Run a quick Nikto scan with minimal tuning"""
        return self.scan(target, {'tuning': '1'})
    
    def full_scan(self, target: str) -> Dict[str, Any]:
        """Run a comprehensive Nikto scan"""
        return self.scan(target, {'tuning': 'x'})
    
    def stealth_scan(self, target: str) -> Dict[str, Any]:
        """Run Nikto with IDS evasion techniques"""
        return self.scan(target, {
            'evasion': '1',  # Random URI encoding
            'timeout': 10
        })
