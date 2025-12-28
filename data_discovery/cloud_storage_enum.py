"""
Cloud Storage Enumerator
Discovers and analyzes cloud storage buckets and containers
"""

import re
import json
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import aiohttp

@dataclass
class CloudBucket:
    """Cloud storage bucket information"""
    provider: str
    name: str
    url: str
    accessible: bool
    public: bool
    files_count: int
    total_size: int
    sensitive_files: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class CloudStorageEnumerator:
    """
    Enumerates and analyzes cloud storage (AWS S3, Azure Blob, GCP Storage)
    """
    
    def __init__(self):
        self.buckets = []
        
        # Common bucket name patterns
        self.name_patterns = [
            '{company}',
            '{company}-backup',
            '{company}-data',
            '{company}-files',
            '{company}-assets',
            '{company}-logs',
            '{company}-prod',
            '{company}-dev',
            '{company}-staging',
            '{company}-private',
            '{company}-public',
            '{company}-web',
            '{company}-app'
        ]
    
    async def enumerate_s3_buckets(self, company_name: str, 
                                   variations: List[str] = None) -> List[CloudBucket]:
        """
        Enumerate potential AWS S3 buckets
        """
        print(f"[*] Enumerating S3 buckets for: {company_name}")
        
        if not variations:
            variations = self._generate_variations(company_name)
        
        tasks = []
        for bucket_name in variations:
            tasks.append(self._check_s3_bucket(bucket_name))
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.buckets.append(result)
                print(f"[+] Found S3 bucket: {result.name}")
        
        return [b for b in self.buckets if b.provider == 's3']
    
    async def _check_s3_bucket(self, bucket_name: str) -> Optional[CloudBucket]:
        """
        Check if S3 bucket exists and is accessible
        """
        url = f"https://{bucket_name}.s3.amazonaws.com"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    accessible = response.status != 404
                    public = response.status == 200
                    
                    if accessible:
                        files = []
                        total_size = 0
                        
                        if public:
                            # Try to list objects
                            try:
                                text = await response.text()
                                # Parse XML response
                                files = self._parse_s3_listing(text)
                                total_size = sum(f.get('size', 0) for f in files)
                            except:
                                pass
                        
                        return CloudBucket(
                            provider='s3',
                            name=bucket_name,
                            url=url,
                            accessible=accessible,
                            public=public,
                            files_count=len(files),
                            total_size=total_size,
                            sensitive_files=[f['key'] for f in files if self._is_sensitive_filename(f.get('key', ''))]
                        )
        except:
            pass
        
        return None
    
    async def enumerate_azure_containers(self, account_name: str, 
                                        container_variations: List[str] = None) -> List[CloudBucket]:
        """
        Enumerate Azure Blob Storage containers
        """
        print(f"[*] Enumerating Azure containers for: {account_name}")
        
        if not container_variations:
            container_variations = self._generate_variations(account_name)
        
        tasks = []
        for container_name in container_variations:
            tasks.append(self._check_azure_container(account_name, container_name))
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.buckets.append(result)
                print(f"[+] Found Azure container: {result.name}")
        
        return [b for b in self.buckets if b.provider == 'azure']
    
    async def _check_azure_container(self, account_name: str, 
                                    container_name: str) -> Optional[CloudBucket]:
        """
        Check if Azure container exists and is accessible
        """
        url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    accessible = response.status != 404
                    public = response.status == 200
                    
                    if accessible:
                        files = []
                        total_size = 0
                        
                        if public:
                            try:
                                text = await response.text()
                                files = self._parse_azure_listing(text)
                                total_size = sum(f.get('size', 0) for f in files)
                            except:
                                pass
                        
                        return CloudBucket(
                            provider='azure',
                            name=f"{account_name}/{container_name}",
                            url=url.split('?')[0],
                            accessible=accessible,
                            public=public,
                            files_count=len(files),
                            total_size=total_size,
                            sensitive_files=[f['name'] for f in files if self._is_sensitive_filename(f.get('name', ''))]
                        )
        except:
            pass
        
        return None
    
    async def enumerate_gcp_buckets(self, project_name: str, 
                                   variations: List[str] = None) -> List[CloudBucket]:
        """
        Enumerate GCP Storage buckets
        """
        print(f"[*] Enumerating GCP buckets for: {project_name}")
        
        if not variations:
            variations = self._generate_variations(project_name)
        
        tasks = []
        for bucket_name in variations:
            tasks.append(self._check_gcp_bucket(bucket_name))
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                self.buckets.append(result)
                print(f"[+] Found GCP bucket: {result.name}")
        
        return [b for b in self.buckets if b.provider == 'gcp']
    
    async def _check_gcp_bucket(self, bucket_name: str) -> Optional[CloudBucket]:
        """
        Check if GCP bucket exists and is accessible
        """
        url = f"https://storage.googleapis.com/{bucket_name}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    accessible = response.status != 404
                    public = response.status == 200
                    
                    if accessible:
                        files = []
                        total_size = 0
                        
                        if public:
                            try:
                                text = await response.text()
                                files = self._parse_gcp_listing(text)
                                total_size = sum(f.get('size', 0) for f in files)
                            except:
                                pass
                        
                        return CloudBucket(
                            provider='gcp',
                            name=bucket_name,
                            url=url,
                            accessible=accessible,
                            public=public,
                            files_count=len(files),
                            total_size=total_size,
                            sensitive_files=[f['name'] for f in files if self._is_sensitive_filename(f.get('name', ''))]
                        )
        except:
            pass
        
        return None
    
    def _generate_variations(self, base_name: str) -> List[str]:
        """
        Generate bucket name variations
        """
        variations = []
        base_clean = base_name.lower().replace(' ', '-')
        
        for pattern in self.name_patterns:
            variations.append(pattern.format(company=base_clean))
        
        # Add common prefixes/suffixes
        for prefix in ['www', 'api', 'cdn', 'static', 'media']:
            variations.append(f"{prefix}-{base_clean}")
            variations.append(f"{base_clean}-{prefix}")
        
        # Add year variations
        for year in ['2023', '2024', '2025']:
            variations.append(f"{base_clean}-{year}")
        
        return list(set(variations))  # Remove duplicates
    
    def _is_sensitive_filename(self, filename: str) -> bool:
        """
        Check if filename suggests sensitive content
        """
        sensitive_patterns = [
            r'.*password.*', r'.*credential.*', r'.*secret.*',
            r'.*private.*', r'.*confidential.*', r'.*backup.*',
            r'.*\.key$', r'.*\.pem$', r'.*\.p12$',
            r'.*\.sql$', r'.*\.db$', r'.*\.sqlite$',
            r'.*config.*', r'.*\.env$'
        ]
        
        filename_lower = filename.lower()
        
        for pattern in sensitive_patterns:
            if re.match(pattern, filename_lower):
                return True
        
        return False
    
    def _parse_s3_listing(self, xml_text: str) -> List[Dict]:
        """
        Parse S3 XML listing
        """
        import xml.etree.ElementTree as ET
        
        files = []
        try:
            root = ET.fromstring(xml_text)
            
            for content in root.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Contents'):
                key = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Key')
                size = content.find('{http://s3.amazonaws.com/doc/2006-03-01/}Size')
                
                if key is not None:
                    files.append({
                        'key': key.text,
                        'size': int(size.text) if size is not None else 0
                    })
        except:
            pass
        
        return files
    
    def _parse_azure_listing(self, xml_text: str) -> List[Dict]:
        """
        Parse Azure XML listing
        """
        import xml.etree.ElementTree as ET
        
        files = []
        try:
            root = ET.fromstring(xml_text)
            
            for blob in root.findall('.//Blob'):
                name = blob.find('Name')
                properties = blob.find('Properties')
                size = properties.find('Content-Length') if properties is not None else None
                
                if name is not None:
                    files.append({
                        'name': name.text,
                        'size': int(size.text) if size is not None else 0
                    })
        except:
            pass
        
        return files
    
    def _parse_gcp_listing(self, xml_text: str) -> List[Dict]:
        """
        Parse GCP XML listing
        """
        # GCP uses similar format to S3
        return self._parse_s3_listing(xml_text)
    
    def generate_report(self) -> Dict:
        """
        Generate cloud storage enumeration report
        """
        report = {
            'total_buckets': len(self.buckets),
            'accessible_buckets': sum(1 for b in self.buckets if b.accessible),
            'public_buckets': sum(1 for b in self.buckets if b.public),
            'by_provider': {},
            'sensitive_exposure': 0,
            'total_files': 0,
            'total_size_gb': 0,
            'buckets': []
        }
        
        for bucket in self.buckets:
            # Count by provider
            report['by_provider'][bucket.provider] = report['by_provider'].get(bucket.provider, 0) + 1
            
            # Aggregate stats
            if bucket.sensitive_files:
                report['sensitive_exposure'] += len(bucket.sensitive_files)
            report['total_files'] += bucket.files_count
            report['total_size_gb'] += bucket.total_size / (1024**3)
            
            # Add to list
            report['buckets'].append(bucket.to_dict())
        
        return report
    
    def export_results(self, output_file: str):
        """Export results to JSON"""
        report = self.generate_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Cloud storage enumeration exported to: {output_file}")
