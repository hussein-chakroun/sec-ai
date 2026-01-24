"""
Reconnaissance Suite - Comprehensive Phase 1 Tools
Includes multiple reconnaissance tools with speed vs depth options
"""
import subprocess
import json
from typing import Dict, Any, List, Optional
from loguru import logger
from .nmap_scanner import NmapScanner
from .base_tool import BaseTool


class ReconnaissanceMode:
    """Reconnaissance scanning modes"""
    QUICK = "quick"           # Fast scans, basic info
    BALANCED = "balanced"     # Moderate depth
    DEEP = "deep"            # Comprehensive, time-intensive
    STEALTH = "stealth"      # Slow but evasive


class DNSRecon(BaseTool):
    """DNS reconnaissance tool wrapper"""
    
    def get_default_command(self) -> str:
        return "dnsenum" if self._check_command_exists("dnsenum") else "nslookup"
    
    def _check_command_exists(self, command: str) -> bool:
        """Check if command exists"""
        try:
            subprocess.run([command, "--help"], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse DNS output"""
        return {
            "dns_records": output,
            "raw_output": output
        }
    
    def enumerate_dns(self, domain: str, mode: str = ReconnaissanceMode.BALANCED) -> Dict[str, Any]:
        """Enumerate DNS records"""
        logger.info(f"DNS enumeration for {domain} in {mode} mode")
        
        if "dnsenum" in self.tool_path:
            args = [domain]
            if mode == ReconnaissanceMode.QUICK:
                args.insert(0, "--quick")
            elif mode == ReconnaissanceMode.DEEP:
                args.extend(["--threads", "10", "--enum"])
        else:
            args = [domain]
        
        return self.execute(args)


class WhoisLookup(BaseTool):
    """WHOIS information gathering"""
    
    def get_default_command(self) -> str:
        return "whois"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output"""
        return {
            "registrar": self._extract_field(output, "Registrar:"),
            "creation_date": self._extract_field(output, "Creation Date:"),
            "expiration_date": self._extract_field(output, "Expiration Date:"),
            "name_servers": self._extract_nameservers(output),
            "raw_output": output
        }
    
    def _extract_field(self, output: str, field: str) -> Optional[str]:
        """Extract field from WHOIS output"""
        for line in output.split('\n'):
            if field in line:
                return line.split(field)[1].strip()
        return None
    
    def _extract_nameservers(self, output: str) -> List[str]:
        """Extract nameservers"""
        nameservers = []
        for line in output.split('\n'):
            if "Name Server:" in line or "name server:" in line:
                ns = line.split(":")[-1].strip()
                if ns:
                    nameservers.append(ns)
        return nameservers
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        logger.info(f"WHOIS lookup for {domain}")
        return self.execute([domain])


class SubdomainEnumerator(BaseTool):
    """Subdomain enumeration tool"""
    
    def get_default_command(self) -> str:
        # Try multiple tools in order of preference
        for tool in ["subfinder", "sublist3r", "amass"]:
            if self._check_command_exists(tool):
                return tool
        return "nslookup"  # Fallback
    
    def _check_command_exists(self, command: str) -> bool:
        """Check if command exists"""
        try:
            subprocess.run([command, "--help"], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse subdomain enumeration output"""
        subdomains = []
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                subdomains.append(line)
        
        return {
            "subdomains": subdomains,
            "count": len(subdomains),
            "raw_output": output
        }
    
    def enumerate(self, domain: str, mode: str = ReconnaissanceMode.BALANCED) -> Dict[str, Any]:
        """Enumerate subdomains"""
        logger.info(f"Subdomain enumeration for {domain} in {mode} mode")
        
        args = []
        if "subfinder" in self.tool_path:
            args = ["-d", domain, "-silent"]
            if mode == ReconnaissanceMode.DEEP:
                args.extend(["-all", "-recursive"])
        elif "sublist3r" in self.tool_path:
            args = ["-d", domain]
            if mode == ReconnaissanceMode.DEEP:
                args.extend(["-b", "-t", "10"])  # Bruteforce with threads
        elif "amass" in self.tool_path:
            args = ["enum", "-d", domain]
            if mode == ReconnaissanceMode.DEEP:
                args.extend(["-active", "-brute"])
        else:
            # Fallback basic enumeration
            args = [f"www.{domain}"]
        
        return self.execute(args)


class PortScanner(BaseTool):
    """Advanced port scanning with multiple techniques"""
    
    def get_default_command(self) -> str:
        return "nmap"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse port scan output"""
        # Use NmapScanner's parser
        scanner = NmapScanner()
        return scanner.parse_output(output)
    
    def scan_ports(self, target: str, mode: str = ReconnaissanceMode.BALANCED) -> Dict[str, Any]:
        """Scan ports based on mode"""
        logger.info(f"Port scanning {target} in {mode} mode")
        
        if mode == ReconnaissanceMode.QUICK:
            # Top 100 ports, no service detection
            args = ["-F", "-T4", target]
        elif mode == ReconnaissanceMode.BALANCED:
            # Top 1000 ports with basic service detection
            args = ["-sV", "-T4", target]
        elif mode == ReconnaissanceMode.DEEP:
            # All ports with comprehensive service and OS detection
            args = ["-sV", "-sC", "-O", "-p-", "-T4", target]
        elif mode == ReconnaissanceMode.STEALTH:
            # Stealth scan with timing adjustments
            args = ["-sS", "-sV", "-T2", "-f", target]
        else:
            args = ["-sV", target]
        
        return self.execute(args, sudo=(mode == ReconnaissanceMode.DEEP or mode == ReconnaissanceMode.STEALTH))


class ServiceEnumerator(BaseTool):
    """Service version and banner grabbing"""
    
    def get_default_command(self) -> str:
        return "nmap"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse service enumeration output"""
        scanner = NmapScanner()
        return scanner.parse_output(output)
    
    def enumerate_services(self, target: str, ports: Optional[str] = None, mode: str = ReconnaissanceMode.BALANCED) -> Dict[str, Any]:
        """Enumerate services with version detection"""
        logger.info(f"Service enumeration for {target} in {mode} mode")
        
        args = ["-sV"]
        
        if mode == ReconnaissanceMode.QUICK:
            args.extend(["-T4", "--version-intensity", "0"])
        elif mode == ReconnaissanceMode.BALANCED:
            args.extend(["-T4", "--version-intensity", "5"])
        elif mode == ReconnaissanceMode.DEEP:
            args.extend(["-sC", "-A", "--version-intensity", "9"])
        
        if ports:
            args.extend(["-p", ports])
        
        args.append(target)
        return self.execute(args)


class OSDetector(BaseTool):
    """Operating system detection"""
    
    def get_default_command(self) -> str:
        return "nmap"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse OS detection output"""
        scanner = NmapScanner()
        return scanner.parse_output(output)
    
    def detect_os(self, target: str, mode: str = ReconnaissanceMode.BALANCED) -> Dict[str, Any]:
        """Detect operating system"""
        logger.info(f"OS detection for {target} in {mode} mode")
        
        args = ["-O"]
        
        if mode == ReconnaissanceMode.DEEP:
            args.extend(["--osscan-guess", "--max-os-tries", "5"])
        
        args.append(target)
        return self.execute(args, sudo=True)


class ReconnaissanceSuite:
    """
    Comprehensive reconnaissance suite combining multiple tools
    Supports different scanning modes: quick, balanced, deep, stealth
    """
    
    def __init__(self):
        self.nmap_scanner = NmapScanner()
        self.dns_recon = DNSRecon()
        self.whois = WhoisLookup()
        self.subdomain_enum = SubdomainEnumerator()
        self.port_scanner = PortScanner()
        self.service_enum = ServiceEnumerator()
        self.os_detector = OSDetector()
    
    def perform_reconnaissance(self, target: str, mode: str = ReconnaissanceMode.BALANCED, 
                             tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance
        
        Args:
            target: Target IP, domain, or URL
            mode: Scanning mode (quick, balanced, deep, stealth)
            tools: List of tools to use. If None, uses all available tools.
                   Options: ['dns', 'whois', 'subdomain', 'port', 'service', 'os', 'nmap']
        
        Returns:
            Dictionary containing results from all reconnaissance activities
        """
        logger.info(f"Starting reconnaissance on {target} in {mode} mode")
        
        results = {
            "target": target,
            "mode": mode,
            "results": {},
            "summary": {}
        }
        
        # Default to all tools if none specified
        if tools is None:
            tools = ['dns', 'whois', 'subdomain', 'port', 'service', 'os']
        
        # Determine if target is domain or IP
        is_domain = not target.replace('.', '').replace(':', '').isdigit()
        
        try:
            # DNS Reconnaissance
            if 'dns' in tools and is_domain:
                logger.info("Running DNS reconnaissance...")
                results['results']['dns'] = self.dns_recon.enumerate_dns(target, mode)
            
            # WHOIS Lookup
            if 'whois' in tools and is_domain:
                logger.info("Running WHOIS lookup...")
                results['results']['whois'] = self.whois.lookup(target)
            
            # Subdomain Enumeration
            if 'subdomain' in tools and is_domain:
                logger.info("Running subdomain enumeration...")
                results['results']['subdomains'] = self.subdomain_enum.enumerate(target, mode)
            
            # Port Scanning
            if 'port' in tools or 'nmap' in tools:
                logger.info("Running port scan...")
                results['results']['ports'] = self.port_scanner.scan_ports(target, mode)
            
            # Service Enumeration
            if 'service' in tools and mode != ReconnaissanceMode.QUICK:
                logger.info("Running service enumeration...")
                results['results']['services'] = self.service_enum.enumerate_services(target, mode=mode)
            
            # OS Detection
            if 'os' in tools and mode in [ReconnaissanceMode.BALANCED, ReconnaissanceMode.DEEP]:
                logger.info("Running OS detection...")
                results['results']['os_detection'] = self.os_detector.detect_os(target, mode)
            
            # Generate summary
            results['summary'] = self._generate_summary(results['results'])
            
            logger.info("Reconnaissance completed successfully")
            
        except Exception as e:
            logger.error(f"Reconnaissance error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of reconnaissance results"""
        summary = {
            "open_ports_count": 0,
            "services_found": [],
            "subdomains_count": 0,
            "os_detected": None
        }
        
        # Count open ports
        if 'ports' in results and 'open_ports' in results['ports']:
            summary['open_ports_count'] = len(results['ports']['open_ports'])
            summary['services_found'] = results['ports'].get('services', [])
        
        # Count subdomains
        if 'subdomains' in results:
            summary['subdomains_count'] = results['subdomains'].get('count', 0)
        
        # OS detection
        if 'os_detection' in results:
            summary['os_detected'] = results['os_detection'].get('os_detection')
        
        return summary
    
    def quick_scan(self, target: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform quick reconnaissance scan"""
        return self.perform_reconnaissance(target, ReconnaissanceMode.QUICK, tools)
    
    def balanced_scan(self, target: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform balanced reconnaissance scan"""
        return self.perform_reconnaissance(target, ReconnaissanceMode.BALANCED, tools)
    
    def deep_scan(self, target: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform deep reconnaissance scan"""
        return self.perform_reconnaissance(target, ReconnaissanceMode.DEEP, tools)
    
    def stealth_scan(self, target: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform stealth reconnaissance scan"""
        return self.perform_reconnaissance(target, ReconnaissanceMode.STEALTH, tools)
