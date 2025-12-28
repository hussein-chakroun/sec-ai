"""
Credential Manager - Automated Credential Harvesting
Coordinates multiple credential extraction techniques
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class Credential:
    """Represents a harvested credential"""
    
    def __init__(self, username: str, password: str = None, hash_value: str = None,
                 domain: str = None, credential_type: str = 'plaintext', source: str = None):
        self.username = username
        self.password = password
        self.hash_value = hash_value
        self.domain = domain
        self.credential_type = credential_type  # plaintext, ntlm, sha256, etc.
        self.source = source
        self.timestamp = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'username': self.username,
            'password': self.password,
            'hash': self.hash_value,
            'domain': self.domain,
            'type': self.credential_type,
            'source': self.source,
            'timestamp': self.timestamp.isoformat()
        }


class CredentialManager:
    """
    Manages credential harvesting operations
    Coordinates multiple extraction techniques and deduplicates results
    """
    
    def __init__(self, os_type: str = 'windows'):
        """
        Initialize credential manager
        
        Args:
            os_type: Operating system type
        """
        self.os_type = os_type
        self.credentials: List[Credential] = []
        self.harvesters: Dict[str, 'CredentialHarvester'] = {}
        self.unique_credentials: Set[str] = set()
        
        logger.info(f"CredentialManager initialized for {os_type}")
        
    def register_harvester(self, name: str, harvester: 'CredentialHarvester'):
        """Register a credential harvester"""
        self.harvesters[name] = harvester
        logger.info(f"Registered harvester: {name}")
        
    async def harvest_all(self) -> List[Credential]:
        """
        Run all registered harvesters
        
        Returns:
            List of harvested credentials
        """
        logger.info("Starting comprehensive credential harvest...")
        
        tasks = []
        for name, harvester in self.harvesters.items():
            tasks.append(self._run_harvester(name, harvester))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results
        all_creds = []
        for result in results:
            if isinstance(result, list):
                all_creds.extend(result)
                
        # Add unique credentials
        for cred in all_creds:
            self._add_credential(cred)
            
        logger.info(f"Harvested {len(self.credentials)} unique credentials")
        return self.credentials
        
    async def _run_harvester(self, name: str, harvester: 'CredentialHarvester') -> List[Credential]:
        """Run a single harvester"""
        try:
            logger.info(f"Running harvester: {name}")
            creds = await harvester.harvest()
            logger.info(f"{name} harvested {len(creds)} credentials")
            return creds
        except Exception as e:
            logger.error(f"Harvester {name} failed: {e}")
            return []
            
    def _add_credential(self, cred: Credential):
        """Add credential with deduplication"""
        # Create unique key
        if cred.password:
            key = f"{cred.username}:{cred.password}:{cred.domain}"
        elif cred.hash_value:
            key = f"{cred.username}:{cred.hash_value}:{cred.domain}"
        else:
            key = f"{cred.username}:{cred.domain}"
            
        if key not in self.unique_credentials:
            self.credentials.append(cred)
            self.unique_credentials.add(key)
            
    async def harvest_specific(self, harvester_name: str) -> List[Credential]:
        """
        Run specific harvester
        
        Args:
            harvester_name: Name of harvester to run
            
        Returns:
            List of credentials
        """
        if harvester_name not in self.harvesters:
            logger.error(f"Unknown harvester: {harvester_name}")
            return []
            
        harvester = self.harvesters[harvester_name]
        creds = await self._run_harvester(harvester_name, harvester)
        
        for cred in creds:
            self._add_credential(cred)
            
        return creds
        
    def get_credentials_by_type(self, cred_type: str) -> List[Credential]:
        """Get credentials of specific type"""
        return [c for c in self.credentials if c.credential_type == cred_type]
        
    def get_credentials_by_source(self, source: str) -> List[Credential]:
        """Get credentials from specific source"""
        return [c for c in self.credentials if c.source == source]
        
    def get_domain_credentials(self, domain: str) -> List[Credential]:
        """Get credentials for specific domain"""
        return [c for c in self.credentials if c.domain == domain]
        
    async def export_credentials(self, filepath: Path, format: str = 'json'):
        """
        Export credentials to file
        
        Args:
            filepath: Output file path
            format: Export format (json, csv, hashcat)
        """
        try:
            if format == 'json':
                data = [c.to_dict() for c in self.credentials]
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
                    
            elif format == 'csv':
                import csv
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Username', 'Password', 'Hash', 'Domain', 'Type', 'Source', 'Timestamp'])
                    
                    for cred in self.credentials:
                        writer.writerow([
                            cred.username,
                            cred.password or '',
                            cred.hash_value or '',
                            cred.domain or '',
                            cred.credential_type,
                            cred.source,
                            cred.timestamp.isoformat()
                        ])
                        
            elif format == 'hashcat':
                # Export hashes in hashcat format
                with open(filepath, 'w') as f:
                    for cred in self.credentials:
                        if cred.hash_value:
                            # Format: username:hash
                            f.write(f"{cred.username}:{cred.hash_value}\n")
                            
            logger.info(f"Exported {len(self.credentials)} credentials to {filepath}")
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            
    async def crack_hashes(self, wordlist: Path, hash_type: str = 'ntlm') -> Dict[str, str]:
        """
        Attempt to crack password hashes
        
        Args:
            wordlist: Path to wordlist
            hash_type: Hash type (ntlm, sha256, etc.)
            
        Returns:
            Dictionary mapping username to cracked password
        """
        logger.info(f"Attempting to crack {hash_type} hashes...")
        
        cracked = {}
        
        # Get credentials with hashes
        hash_creds = [c for c in self.credentials if c.hash_value and c.credential_type == hash_type]
        
        logger.info(f"Found {len(hash_creds)} {hash_type} hashes to crack")
        
        # In real implementation, would use hashcat or john
        # This is a simulation
        
        return cracked
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get credential harvesting statistics"""
        stats = {
            'total_credentials': len(self.credentials),
            'unique_users': len(set(c.username for c in self.credentials)),
            'by_type': {},
            'by_source': {},
            'by_domain': {},
            'with_plaintext': len([c for c in self.credentials if c.password]),
            'with_hash': len([c for c in self.credentials if c.hash_value])
        }
        
        # Count by type
        for cred in self.credentials:
            stats['by_type'][cred.credential_type] = stats['by_type'].get(cred.credential_type, 0) + 1
            
            if cred.source:
                stats['by_source'][cred.source] = stats['by_source'].get(cred.source, 0) + 1
                
            if cred.domain:
                stats['by_domain'][cred.domain] = stats['by_domain'].get(cred.domain, 0) + 1
                
        return stats


class CredentialHarvester:
    """Base class for credential harvesters"""
    
    def __init__(self, name: str):
        self.name = name
        
    async def harvest(self) -> List[Credential]:
        """Harvest credentials"""
        raise NotImplementedError
