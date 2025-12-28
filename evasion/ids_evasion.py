"""
IDS/IPS Evasion Module - Phase 4
Machine learning-based detection prediction and evasion
"""
import random
import time
from typing import Dict, Any, List, Optional
from loguru import logger
import numpy as np
from datetime import datetime, timedelta


class SignatureDetectionPredictor:
    """ML model to predict signature-based detection"""
    
    def __init__(self):
        self.signature_patterns = self._load_known_signatures()
        self.detection_history = []
        logger.info("Signature Detection Predictor initialized")
    
    def _load_known_signatures(self) -> Dict[str, List[str]]:
        """Load known IDS/IPS signatures"""
        return {
            "nmap": [
                "rapid_port_scan",
                "sequential_ports",
                "os_detection_probes",
                "version_detection"
            ],
            "sqlmap": [
                "union_based_sqli",
                "error_based_sqli",
                "time_based_sqli",
                "sqlmap_user_agent"
            ],
            "metasploit": [
                "shellcode_patterns",
                "known_exploit_signatures",
                "meterpreter_traffic"
            ],
            "web_attacks": [
                "xss_patterns",
                "lfi_traversal",
                "command_injection",
                "xxe_entity"
            ]
        }
    
    def predict_detection_probability(self, tool: str, payload: str, 
                                     context: Dict[str, Any]) -> float:
        """Predict probability of detection"""
        
        base_probability = 0.5
        
        # Check for known signatures
        tool_signatures = self.signature_patterns.get(tool, [])
        matches = sum(1 for sig in tool_signatures if sig.lower() in payload.lower())
        
        if matches > 0:
            base_probability += 0.2 * matches
        
        # Adjust for target defenses
        defensive_measures = context.get('predicted_defenses', [])
        if 'ids' in str(defensive_measures).lower():
            base_probability += 0.3
        if 'ips' in str(defensive_measures).lower():
            base_probability += 0.4
        
        # Adjust for timing
        if context.get('rapid_scanning', False):
            base_probability += 0.2
        
        # Adjust for past detections
        recent_detections = len([
            d for d in self.detection_history[-10:]
            if d['detected']
        ])
        base_probability += recent_detections * 0.05
        
        return min(base_probability, 0.95)
    
    def record_detection(self, tool: str, payload: str, detected: bool):
        """Record detection outcome for learning"""
        self.detection_history.append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool,
            "payload": payload[:100],
            "detected": detected
        })
    
    def suggest_evasion_technique(self, tool: str, 
                                  detection_probability: float) -> Dict[str, Any]:
        """Suggest evasion technique based on detection probability"""
        
        if detection_probability < 0.3:
            return {
                "technique": "none",
                "reason": "Low detection risk"
            }
        
        elif detection_probability < 0.6:
            return {
                "technique": "timing_randomization",
                "parameters": {
                    "delay_range": (2, 5),
                    "jitter": 0.3
                }
            }
        
        elif detection_probability < 0.8:
            return {
                "technique": "payload_obfuscation",
                "parameters": {
                    "encoding": "base64",
                    "fragmentation": True
                }
            }
        
        else:
            return {
                "technique": "polymorphic_payload",
                "parameters": {
                    "mutation_rate": 0.7,
                    "decoy_traffic": True
                }
            }


class PolymorphicPayloadGenerator:
    """Generate polymorphic payloads to evade signatures"""
    
    def __init__(self):
        self.mutation_techniques = [
            "variable_renaming",
            "instruction_reordering",
            "garbage_insertion",
            "encoding_chains",
            "nop_sledding"
        ]
        logger.info("Polymorphic Payload Generator initialized")
    
    def generate_variant(self, original_payload: str, 
                        mutation_rate: float = 0.5) -> str:
        """Generate polymorphic variant of payload"""
        
        payload = original_payload
        
        # Apply random mutations
        num_mutations = int(len(self.mutation_techniques) * mutation_rate)
        selected_techniques = random.sample(self.mutation_techniques, num_mutations)
        
        for technique in selected_techniques:
            payload = self._apply_mutation(payload, technique)
        
        logger.debug(f"Generated variant using: {selected_techniques}")
        return payload
    
    def _apply_mutation(self, payload: str, technique: str) -> str:
        """Apply specific mutation technique"""
        
        if technique == "variable_renaming":
            # Replace common variable names
            replacements = {
                "cmd": f"var_{random.randint(1000, 9999)}",
                "exec": f"fn_{random.randint(1000, 9999)}",
                "system": f"sys_{random.randint(1000, 9999)}"
            }
            for old, new in replacements.items():
                payload = payload.replace(old, new)
        
        elif technique == "instruction_reordering":
            # Shuffle non-critical instructions (simplified)
            lines = payload.split(';')
            if len(lines) > 2:
                middle = lines[1:-1]
                random.shuffle(middle)
                payload = lines[0] + ';' + ';'.join(middle) + ';' + lines[-1]
        
        elif technique == "garbage_insertion":
            # Insert benign garbage code
            garbage = [
                "/* comment */",
                "var _unused = 0;",
                "// benign comment"
            ]
            payload += random.choice(garbage)
        
        elif technique == "encoding_chains":
            # Apply encoding (simplified)
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            payload = f"eval(atob('{encoded}'))"
        
        elif technique == "nop_sledding":
            # Add NOP-equivalent operations
            nops = ["\x90" * random.randint(5, 15)]
            payload = random.choice(nops) + payload
        
        return payload
    
    def generate_multiple_variants(self, payload: str, count: int = 5) -> List[str]:
        """Generate multiple unique variants"""
        variants = []
        for _ in range(count):
            variant = self.generate_variant(payload, random.uniform(0.3, 0.8))
            variants.append(variant)
        return variants


class TrafficObfuscator:
    """Obfuscate and encrypt traffic"""
    
    def __init__(self):
        self.obfuscation_methods = [
            "base64",
            "url_encode",
            "hex_encode",
            "rot13",
            "compression"
        ]
        logger.info("Traffic Obfuscator initialized")
    
    def obfuscate(self, data: str, method: str = "auto") -> Dict[str, Any]:
        """Obfuscate data"""
        
        if method == "auto":
            method = random.choice(self.obfuscation_methods)
        
        obfuscated = data
        
        if method == "base64":
            import base64
            obfuscated = base64.b64encode(data.encode()).decode()
        
        elif method == "url_encode":
            import urllib.parse
            obfuscated = urllib.parse.quote(data)
        
        elif method == "hex_encode":
            obfuscated = data.encode().hex()
        
        elif method == "rot13":
            obfuscated = data.translate(
                str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                )
            )
        
        elif method == "compression":
            import zlib
            import base64
            compressed = zlib.compress(data.encode())
            obfuscated = base64.b64encode(compressed).decode()
        
        return {
            "original": data,
            "obfuscated": obfuscated,
            "method": method,
            "reversible": True
        }
    
    def chain_obfuscation(self, data: str, chain_length: int = 3) -> Dict[str, Any]:
        """Apply chain of obfuscation methods"""
        
        result = data
        methods_used = []
        
        for _ in range(chain_length):
            method = random.choice(self.obfuscation_methods)
            obfuscated_result = self.obfuscate(result, method)
            result = obfuscated_result['obfuscated']
            methods_used.append(method)
        
        return {
            "original": data,
            "obfuscated": result,
            "methods_chain": methods_used,
            "reversible": True
        }


class TimingRandomizer:
    """Statistical timing randomization"""
    
    def __init__(self):
        self.timing_profiles = {
            "aggressive": {"mean": 0.5, "std": 0.2},
            "normal": {"mean": 2.0, "std": 0.5},
            "stealthy": {"mean": 5.0, "std": 1.5},
            "glacial": {"mean": 30.0, "std": 10.0}
        }
        logger.info("Timing Randomizer initialized")
    
    def get_delay(self, profile: str = "normal") -> float:
        """Get randomized delay based on profile"""
        
        params = self.timing_profiles.get(profile, self.timing_profiles["normal"])
        
        # Generate delay using normal distribution
        delay = np.random.normal(params["mean"], params["std"])
        
        # Ensure positive delay
        delay = max(delay, 0.1)
        
        return delay
    
    def wait(self, profile: str = "normal"):
        """Wait with randomized timing"""
        delay = self.get_delay(profile)
        logger.debug(f"Waiting {delay:.2f}s ({profile} profile)")
        time.sleep(delay)
    
    def generate_request_schedule(self, num_requests: int, 
                                  profile: str = "normal",
                                  time_window: int = 3600) -> List[float]:
        """Generate schedule for requests over time window"""
        
        # Generate delays
        delays = [self.get_delay(profile) for _ in range(num_requests)]
        
        # Convert to timestamps
        current_time = 0
        schedule = []
        
        for delay in delays:
            current_time += delay
            if current_time < time_window:
                schedule.append(current_time)
        
        logger.info(f"Generated schedule for {len(schedule)} requests over {time_window}s")
        return schedule


class DecoyTrafficGenerator:
    """Generate decoy/benign traffic to blend attacks"""
    
    def __init__(self):
        self.benign_patterns = [
            "user_agent_rotation",
            "normal_browsing",
            "api_calls",
            "static_resources",
            "health_checks"
        ]
        logger.info("Decoy Traffic Generator initialized")
    
    def generate_decoy_request(self, pattern: str = "normal_browsing") -> Dict[str, Any]:
        """Generate a benign-looking request"""
        
        if pattern == "normal_browsing":
            paths = ["/", "/about", "/contact", "/products", "/blog"]
            return {
                "method": "GET",
                "path": random.choice(paths),
                "user_agent": self._random_user_agent(),
                "referrer": "https://www.google.com"
            }
        
        elif pattern == "static_resources":
            resources = ["/css/style.css", "/js/app.js", "/images/logo.png"]
            return {
                "method": "GET",
                "path": random.choice(resources),
                "user_agent": self._random_user_agent()
            }
        
        elif pattern == "api_calls":
            endpoints = ["/api/status", "/api/version", "/api/health"]
            return {
                "method": "GET",
                "path": random.choice(endpoints),
                "user_agent": "API Client/1.0"
            }
        
        return {
            "method": "GET",
            "path": "/",
            "user_agent": self._random_user_agent()
        }
    
    def _random_user_agent(self) -> str:
        """Get random realistic user agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        return random.choice(agents)
    
    def generate_decoy_traffic(self, malicious_request: Dict[str, Any],
                              decoy_ratio: int = 5) -> List[Dict[str, Any]]:
        """Generate decoy traffic around malicious request"""
        
        traffic = []
        
        # Add benign requests before
        for _ in range(decoy_ratio):
            traffic.append(self.generate_decoy_request())
        
        # Add malicious request
        traffic.append(malicious_request)
        
        # Add benign requests after
        for _ in range(decoy_ratio):
            traffic.append(self.generate_decoy_request())
        
        # Shuffle to avoid obvious pattern
        random.shuffle(traffic)
        
        logger.info(f"Generated {len(traffic)} requests ({decoy_ratio}:1 decoy ratio)")
        return traffic


class ProtocolManipulator:
    """Protocol manipulation and fragmentation"""
    
    def __init__(self):
        logger.info("Protocol Manipulator initialized")
    
    def fragment_payload(self, payload: str, fragment_size: int = 10) -> List[str]:
        """Fragment payload into smaller chunks"""
        
        fragments = []
        for i in range(0, len(payload), fragment_size):
            fragments.append(payload[i:i+fragment_size])
        
        logger.info(f"Fragmented payload into {len(fragments)} chunks")
        return fragments
    
    def manipulate_http_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Manipulate HTTP headers to evade detection"""
        
        manipulated = headers.copy()
        
        # Add uncommon but valid headers
        manipulated['X-Forwarded-For'] = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        manipulated['X-Real-IP'] = f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # Randomize header order (some IDS check this)
        # In real implementation, would reorder during sending
        
        # Case manipulation
        if random.random() > 0.5:
            manipulated['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            manipulated['content-type'] = 'application/x-www-form-urlencoded'
        
        return manipulated
    
    def tcp_segmentation(self, data: bytes, segment_size: int = 100) -> List[bytes]:
        """Segment TCP data"""
        
        segments = []
        for i in range(0, len(data), segment_size):
            segments.append(data[i:i+segment_size])
        
        return segments
