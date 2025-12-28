"""
SQLMap Module
"""
import re
from typing import Dict, Any, List
from .base_tool import BaseTool
from loguru import logger


class SQLMapScanner(BaseTool):
    """SQLMap SQL injection scanner wrapper"""
    
    def get_default_command(self) -> str:
        return "sqlmap"    
    def get_install_command(self) -> List[str]:
        """SQLMap is typically installed via git or package manager"""
        import platform
        system = platform.system().lower()
        
        if system == "linux":
            # SQLMap is often available in repos
            if self._command_exists("apt-get"):
                return ["sudo", "apt-get", "install", "-y", "sqlmap"]
            elif self._command_exists("yum"):
                return ["sudo", "yum", "install", "-y", "sqlmap"]
            elif self._command_exists("pacman"):
                return ["sudo", "pacman", "-S", "--noconfirm", "sqlmap"]
        
        elif system == "darwin":
            if self._command_exists("brew"):
                return ["brew", "install", "sqlmap"]
        
        # Fallback: Try pip installation
        return ["pip", "install", "sqlmap-python"]    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output"""
        results = {
            "vulnerable": False,
            "injection_type": [],
            "database": None,
            "tables": [],
            "payloads": [],
            "raw_output": output
        }
        
        # Check if vulnerable
        if "is vulnerable" in output.lower():
            results["vulnerable"] = True
        
        # Parse injection types
        injection_patterns = [
            r"Type: ([\w\s]+)",
            r"Title: (.+)",
        ]
        
        for pattern in injection_patterns:
            matches = re.findall(pattern, output)
            results["injection_type"].extend(matches)
        
        # Parse database name
        db_pattern = r"current database: '(.+?)'"
        db_match = re.search(db_pattern, output)
        if db_match:
            results["database"] = db_match.group(1)
        
        # Parse tables
        table_pattern = r"Database: .+?\[(\d+) tables?\]"
        tables_match = re.findall(r"\[\*\] (.+)", output)
        results["tables"] = tables_match
        
        return results
    
    def test_url(self, url: str, data: str = None, cookie: str = None) -> Dict[str, Any]:
        """Test URL for SQL injection"""
        logger.info(f"Testing URL for SQLi: {url}")
        args = ["--batch", "-u", url]
        
        if data:
            args.extend(["--data", data])
        if cookie:
            args.extend(["--cookie", cookie])
        
        return self.execute(args)
    
    def dump_database(self, url: str, database: str = None, table: str = None) -> Dict[str, Any]:
        """Dump database contents"""
        logger.info(f"Dumping database from {url}")
        args = ["--batch", "-u", url]
        
        if database:
            args.extend(["-D", database])
        if table:
            args.extend(["-T", table, "--dump"])
        else:
            args.append("--dump-all")
        
        return self.execute(args)
    
    def get_dbs(self, url: str) -> Dict[str, Any]:
        """Enumerate databases"""
        logger.info(f"Enumerating databases from {url}")
        return self.execute(["--batch", "-u", url, "--dbs"])
    
    def get_tables(self, url: str, database: str) -> Dict[str, Any]:
        """Enumerate tables in database"""
        logger.info(f"Enumerating tables from {database}")
        return self.execute(["--batch", "-u", url, "-D", database, "--tables"])
    
    def custom_scan(self, url: str, flags: List[str]) -> Dict[str, Any]:
        """Execute custom sqlmap scan"""
        logger.info(f"Starting custom SQLMap scan on {url}")
        return self.execute(["--batch", "-u", url] + flags)
