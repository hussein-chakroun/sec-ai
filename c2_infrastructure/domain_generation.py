"""
Domain Generation Algorithm (DGA) - Resilient C2 Domain Resolution
Generates pseudo-random domains for C2 communication to evade blocking
"""

import hashlib
import logging
from typing import List, Optional
from datetime import datetime, timedelta
import random
import string

logger = logging.getLogger(__name__)


class DomainGenerationAlgorithm:
    """
    Domain Generation Algorithm for resilient C2
    Generates domains based on date seeds for synchronization between C2 and implant
    """
    
    def __init__(self, seed: Optional[str] = None, tlds: Optional[List[str]] = None):
        """
        Initialize DGA
        
        Args:
            seed: Seed string for domain generation (shared secret)
            tlds: List of TLDs to use
        """
        self.seed = seed or "default_seed_change_me"
        self.tlds = tlds or ['.com', '.net', '.org', '.info', '.biz']
        
        # DGA configuration
        self.domain_length_min = 8
        self.domain_length_max = 20
        self.domains_per_day = 100
        
        logger.info("DomainGenerationAlgorithm initialized")
        
    def generate_domains(self, date: Optional[datetime] = None, count: Optional[int] = None) -> List[str]:
        """
        Generate DGA domains for a specific date
        
        Args:
            date: Date to generate domains for (default: today)
            count: Number of domains to generate (default: domains_per_day)
            
        Returns:
            List of generated domain names
        """
        if date is None:
            date = datetime.now()
            
        if count is None:
            count = self.domains_per_day
            
        # Create date-based seed
        date_str = date.strftime('%Y-%m-%d')
        date_seed = f"{self.seed}_{date_str}"
        
        domains = []
        
        for i in range(count):
            # Create unique seed for this domain
            domain_seed = f"{date_seed}_{i}"
            
            # Generate domain using hash
            domain = self._generate_domain(domain_seed)
            domains.append(domain)
            
        logger.info(f"Generated {len(domains)} DGA domains for {date_str}")
        return domains
        
    def _generate_domain(self, seed: str) -> str:
        """Generate a single domain from seed"""
        # Hash the seed
        hash_obj = hashlib.md5(seed.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Use hash to determine domain length
        length = (int(hash_hex[:2], 16) % (self.domain_length_max - self.domain_length_min)) + self.domain_length_min
        
        # Generate domain name from hash
        domain = ""
        for i in range(length):
            # Use hash bytes to select characters
            byte_val = int(hash_hex[(i*2) % len(hash_hex):(i*2) % len(hash_hex) + 2], 16)
            char = chr(ord('a') + (byte_val % 26))
            domain += char
            
        # Select TLD based on hash
        tld_index = int(hash_hex[-2:], 16) % len(self.tlds)
        tld = self.tlds[tld_index]
        
        return domain + tld
        
    def generate_domains_range(self, start_date: datetime, end_date: datetime) -> List[str]:
        """
        Generate domains for a date range
        
        Args:
            start_date: Start date
            end_date: End date
            
        Returns:
            List of all domains for the date range
        """
        all_domains = []
        current_date = start_date
        
        while current_date <= end_date:
            domains = self.generate_domains(current_date)
            all_domains.extend(domains)
            current_date += timedelta(days=1)
            
        logger.info(f"Generated {len(all_domains)} domains for date range")
        return all_domains
        
    def get_current_domains(self, count: int = 10) -> List[str]:
        """Get current active domains"""
        return self.generate_domains(datetime.now(), count)
        
    def get_backup_domains(self, days_ahead: int = 7, count_per_day: int = 10) -> List[str]:
        """
        Get backup domains for future dates
        
        Args:
            days_ahead: Number of days to generate ahead
            count_per_day: Domains per day
            
        Returns:
            List of backup domains
        """
        backup = []
        
        for i in range(1, days_ahead + 1):
            future_date = datetime.now() + timedelta(days=i)
            domains = self.generate_domains(future_date, count_per_day)
            backup.extend(domains)
            
        logger.info(f"Generated {len(backup)} backup domains")
        return backup


class WordBasedDGA:
    """
    Word-based DGA for more legitimate-looking domains
    Uses dictionary words to avoid detection
    """
    
    def __init__(self, seed: Optional[str] = None, wordlist: Optional[List[str]] = None):
        self.seed = seed or "default_seed"
        
        # Default word list (in real use, load from file)
        self.wordlist = wordlist or [
            'global', 'secure', 'cloud', 'data', 'tech', 'cyber', 'net',
            'digital', 'smart', 'systems', 'solutions', 'enterprise',
            'services', 'network', 'portal', 'gateway', 'platform'
        ]
        
        self.tlds = ['.com', '.net', '.org', '.io', '.tech']
        
    def generate_domains(self, date: Optional[datetime] = None, count: int = 50) -> List[str]:
        """Generate word-based domains"""
        if date is None:
            date = datetime.now()
            
        date_str = date.strftime('%Y-%m-%d')
        date_seed = f"{self.seed}_{date_str}"
        
        domains = []
        
        for i in range(count):
            domain_seed = f"{date_seed}_{i}"
            domain = self._generate_word_domain(domain_seed)
            domains.append(domain)
            
        logger.info(f"Generated {len(domains)} word-based DGA domains")
        return domains
        
    def _generate_word_domain(self, seed: str) -> str:
        """Generate a word-based domain"""
        # Hash seed
        hash_obj = hashlib.sha256(seed.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Select 2-3 words
        word_count = (int(hash_hex[:2], 16) % 2) + 2
        words = []
        
        for i in range(word_count):
            idx = int(hash_hex[i*4:(i+1)*4], 16) % len(self.wordlist)
            words.append(self.wordlist[idx])
            
        # Optionally add number
        if int(hash_hex[-2:], 16) % 3 == 0:
            num = int(hash_hex[-4:-2], 16) % 100
            words.append(str(num))
            
        # Join with hyphen or nothing
        separator = '-' if int(hash_hex[10:12], 16) % 2 == 0 else ''
        domain = separator.join(words)
        
        # Select TLD
        tld_idx = int(hash_hex[-6:-4], 16) % len(self.tlds)
        tld = self.tlds[tld_idx]
        
        return domain + tld


class TimeBasedDGA:
    """
    Time-based DGA that changes domains hourly
    For very resilient C2
    """
    
    def __init__(self, seed: str = "time_seed"):
        self.seed = seed
        self.tlds = ['.com', '.net', '.org']
        
    def generate_domains(self, timestamp: Optional[datetime] = None, count: int = 10) -> List[str]:
        """Generate domains for specific hour"""
        if timestamp is None:
            timestamp = datetime.now()
            
        # Round to hour
        hour_timestamp = timestamp.replace(minute=0, second=0, microsecond=0)
        hour_str = hour_timestamp.strftime('%Y%m%d%H')
        
        domains = []
        
        for i in range(count):
            seed = f"{self.seed}_{hour_str}_{i}"
            hash_obj = hashlib.sha256(seed.encode())
            hash_hex = hash_obj.hexdigest()
            
            # Generate 12-16 character domain
            length = 12 + (int(hash_hex[:2], 16) % 5)
            domain = ""
            
            for j in range(length):
                byte_val = int(hash_hex[(j*2) % len(hash_hex):(j*2+2) % len(hash_hex)], 16)
                domain += chr(ord('a') + (byte_val % 26))
                
            tld = self.tlds[int(hash_hex[-2:], 16) % len(self.tlds)]
            domains.append(domain + tld)
            
        logger.info(f"Generated {len(domains)} time-based DGA domains for {hour_str}")
        return domains
        
    def get_current_domains(self) -> List[str]:
        """Get domains for current hour"""
        return self.generate_domains(datetime.now())
        
    def get_next_hour_domains(self) -> List[str]:
        """Get domains for next hour"""
        next_hour = datetime.now() + timedelta(hours=1)
        return self.generate_domains(next_hour)


class HybridDGA:
    """
    Hybrid DGA combining multiple techniques
    Most resilient approach
    """
    
    def __init__(self, seed: str = "hybrid_seed"):
        self.hash_dga = DomainGenerationAlgorithm(seed)
        self.word_dga = WordBasedDGA(seed)
        self.time_dga = TimeBasedDGA(seed)
        
    def generate_domains(self, count: int = 100) -> List[str]:
        """Generate domains using all techniques"""
        domains = []
        
        # Mix of techniques
        domains.extend(self.hash_dga.generate_domains(count=count // 3))
        domains.extend(self.word_dga.generate_domains(count=count // 3))
        domains.extend(self.time_dga.generate_domains(count=count // 3))
        
        # Shuffle to mix techniques
        random.shuffle(domains)
        
        logger.info(f"Generated {len(domains)} hybrid DGA domains")
        return domains[:count]
