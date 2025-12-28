"""
Behavioral Mimicry Module - Phase 4
Analyze and mimic legitimate user behavior patterns
"""
import random
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from loguru import logger
from collections import defaultdict
import numpy as np


class BehaviorAnalyzer:
    """Analyze legitimate user behavior patterns"""
    
    def __init__(self):
        self.user_patterns = defaultdict(list)
        self.traffic_baselines = {}
        logger.info("Behavior Analyzer initialized")
    
    def analyze_traffic_patterns(self, traffic_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze normal traffic patterns"""
        
        patterns = {
            "request_frequency": [],
            "request_paths": defaultdict(int),
            "user_agents": defaultdict(int),
            "request_sizes": [],
            "response_times": [],
            "time_distribution": defaultdict(int)
        }
        
        for log in traffic_logs:
            # Request frequency (requests per minute)
            timestamp = log.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            hour = timestamp.hour
            patterns["time_distribution"][hour] += 1
            
            # Path analysis
            path = log.get('path', '/')
            patterns["request_paths"][path] += 1
            
            # User agent analysis
            ua = log.get('user_agent', '')
            patterns["user_agents"][ua] += 1
            
            # Size analysis
            size = log.get('request_size', 0)
            patterns["request_sizes"].append(size)
            
            # Response time
            resp_time = log.get('response_time', 0)
            patterns["response_times"].append(resp_time)
        
        # Calculate statistics
        analysis = {
            "avg_request_size": np.mean(patterns["request_sizes"]) if patterns["request_sizes"] else 0,
            "std_request_size": np.std(patterns["request_sizes"]) if patterns["request_sizes"] else 0,
            "avg_response_time": np.mean(patterns["response_times"]) if patterns["response_times"] else 0,
            "peak_hours": self._get_peak_hours(patterns["time_distribution"]),
            "common_paths": self._get_top_n(patterns["request_paths"], 10),
            "common_user_agents": self._get_top_n(patterns["user_agents"], 5)
        }
        
        self.traffic_baselines = analysis
        logger.info(f"Analyzed {len(traffic_logs)} traffic logs")
        
        return analysis
    
    def _get_peak_hours(self, time_dist: Dict[int, int]) -> List[int]:
        """Get peak traffic hours"""
        sorted_hours = sorted(time_dist.items(), key=lambda x: x[1], reverse=True)
        return [hour for hour, _ in sorted_hours[:3]]
    
    def _get_top_n(self, counter: Dict, n: int) -> List[Tuple[str, int]]:
        """Get top N items from counter"""
        sorted_items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        return sorted_items[:n]
    
    def detect_anomalies(self, new_traffic: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalous behavior"""
        
        anomalies = []
        
        for log in new_traffic:
            anomaly_score = 0
            reasons = []
            
            # Check request size
            size = log.get('request_size', 0)
            avg_size = self.traffic_baselines.get('avg_request_size', 0)
            std_size = self.traffic_baselines.get('std_request_size', 1)
            
            if abs(size - avg_size) > 3 * std_size:
                anomaly_score += 0.3
                reasons.append("unusual_request_size")
            
            # Check timing
            timestamp = log.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            
            peak_hours = self.traffic_baselines.get('peak_hours', [])
            if timestamp.hour not in peak_hours:
                anomaly_score += 0.2
                reasons.append("off_peak_access")
            
            # Check user agent
            ua = log.get('user_agent', '')
            common_uas = [ua for ua, _ in self.traffic_baselines.get('common_user_agents', [])]
            if ua not in common_uas:
                anomaly_score += 0.3
                reasons.append("unusual_user_agent")
            
            # Check path
            path = log.get('path', '/')
            common_paths = [p for p, _ in self.traffic_baselines.get('common_paths', [])]
            if path not in common_paths:
                anomaly_score += 0.2
                reasons.append("unusual_path")
            
            if anomaly_score > 0.5:
                anomalies.append({
                    "log": log,
                    "anomaly_score": anomaly_score,
                    "reasons": reasons
                })
        
        logger.info(f"Detected {len(anomalies)} anomalies in {len(new_traffic)} requests")
        return anomalies


class TrafficMimicker:
    """Mimic normal traffic patterns"""
    
    def __init__(self, behavior_analyzer: BehaviorAnalyzer):
        self.analyzer = behavior_analyzer
        logger.info("Traffic Mimicker initialized")
    
    def generate_legitimate_request(self) -> Dict[str, Any]:
        """Generate a request that looks legitimate"""
        
        baselines = self.analyzer.traffic_baselines
        
        # Select common path
        common_paths = baselines.get('common_paths', [('/', 1)])
        paths = [p for p, _ in common_paths]
        path = random.choice(paths) if paths else '/'
        
        # Select common user agent
        common_uas = baselines.get('common_user_agents', [('Mozilla/5.0', 1)])
        uas = [ua for ua, _ in common_uas]
        user_agent = random.choice(uas) if uas else 'Mozilla/5.0'
        
        # Generate size based on normal distribution
        avg_size = baselines.get('avg_request_size', 1000)
        std_size = baselines.get('std_request_size', 200)
        size = int(np.random.normal(avg_size, std_size))
        size = max(size, 0)
        
        # Time during peak hours
        peak_hours = baselines.get('peak_hours', [9, 14, 16])
        hour = random.choice(peak_hours)
        
        now = datetime.now()
        timestamp = now.replace(hour=hour, minute=random.randint(0, 59))
        
        return {
            "method": "GET",
            "path": path,
            "user_agent": user_agent,
            "request_size": size,
            "timestamp": timestamp.isoformat(),
            "is_legitimate": True
        }
    
    def blend_malicious_with_legitimate(self, malicious_request: Dict[str, Any],
                                       num_legitimate: int = 10) -> List[Dict[str, Any]]:
        """Blend malicious request with legitimate traffic"""
        
        traffic = []
        
        # Add legitimate requests before
        for _ in range(num_legitimate // 2):
            traffic.append(self.generate_legitimate_request())
        
        # Add malicious request
        # Modify to look more legitimate
        blended = self._make_malicious_look_legitimate(malicious_request)
        traffic.append(blended)
        
        # Add legitimate requests after
        for _ in range(num_legitimate - num_legitimate // 2):
            traffic.append(self.generate_legitimate_request())
        
        # Shuffle slightly but keep general order
        # (don't want malicious request always in exact middle)
        import random
        mid = len(traffic) // 2
        window = traffic[max(0, mid-2):min(len(traffic), mid+3)]
        random.shuffle(window)
        traffic[max(0, mid-2):min(len(traffic), mid+3)] = window
        
        logger.info(f"Blended 1 malicious request with {num_legitimate} legitimate ones")
        return traffic
    
    def _make_malicious_look_legitimate(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Modify malicious request to blend in"""
        
        baselines = self.analyzer.traffic_baselines
        
        # Use common user agent
        common_uas = baselines.get('common_user_agents', [])
        if common_uas:
            request['user_agent'] = common_uas[0][0]
        
        # Adjust timing to peak hours
        peak_hours = baselines.get('peak_hours', [9, 14, 16])
        hour = random.choice(peak_hours)
        now = datetime.now()
        request['timestamp'] = now.replace(hour=hour, minute=random.randint(0, 59)).isoformat()
        
        # Add referrer to look like user navigation
        request['referrer'] = 'https://www.google.com/'
        
        # Mark as modified
        request['_blended'] = True
        
        return request


class SlowBurnAttacker:
    """Execute attacks slowly over extended periods"""
    
    def __init__(self):
        self.attack_schedule = []
        logger.info("Slow Burn Attacker initialized")
    
    def create_extended_campaign(self, attack_steps: List[Dict[str, Any]],
                                duration_days: int = 30) -> List[Dict[str, Any]]:
        """Create attack campaign over extended period"""
        
        schedule = []
        
        # Distribute steps over duration
        total_seconds = duration_days * 24 * 3600
        interval = total_seconds / len(attack_steps)
        
        current_time = datetime.now()
        
        for i, step in enumerate(attack_steps):
            # Add random jitter
            jitter = random.uniform(-interval * 0.3, interval * 0.3)
            execution_time = current_time + timedelta(seconds=i * interval + jitter)
            
            schedule.append({
                "step": step,
                "execution_time": execution_time,
                "step_number": i + 1,
                "total_steps": len(attack_steps)
            })
        
        self.attack_schedule = schedule
        logger.info(f"Created {duration_days}-day campaign with {len(attack_steps)} steps")
        
        return schedule
    
    def get_next_action(self) -> Optional[Dict[str, Any]]:
        """Get next action to execute"""
        
        now = datetime.now()
        
        for action in self.attack_schedule:
            if action['execution_time'] <= now and not action.get('executed', False):
                action['executed'] = True
                logger.info(f"Executing step {action['step_number']}/{action['total_steps']}")
                return action
        
        return None
    
    def calculate_optimal_timing(self, detection_probability: float) -> float:
        """Calculate optimal delay based on detection risk"""
        
        # Higher detection risk = longer delays
        if detection_probability < 0.3:
            # Low risk: 1-5 minutes
            return random.uniform(60, 300)
        elif detection_probability < 0.6:
            # Medium risk: 1-6 hours
            return random.uniform(3600, 21600)
        elif detection_probability < 0.8:
            # High risk: 6-24 hours
            return random.uniform(21600, 86400)
        else:
            # Very high risk: 1-7 days
            return random.uniform(86400, 604800)
    
    def progressive_reconnaissance(self, target: str, 
                                  total_duration_days: int = 14) -> List[Dict[str, Any]]:
        """Progressive reconnaissance over time"""
        
        recon_phases = [
            {"phase": "passive_osint", "duration_ratio": 0.3},
            {"phase": "light_scanning", "duration_ratio": 0.2},
            {"phase": "service_enumeration", "duration_ratio": 0.2},
            {"phase": "deep_scanning", "duration_ratio": 0.3}
        ]
        
        schedule = []
        current_time = datetime.now()
        
        for phase in recon_phases:
            phase_duration = total_duration_days * phase["duration_ratio"]
            
            schedule.append({
                "target": target,
                "phase": phase["phase"],
                "start_time": current_time,
                "end_time": current_time + timedelta(days=phase_duration),
                "intensity": "low"
            })
            
            current_time += timedelta(days=phase_duration)
        
        logger.info(f"Created {total_duration_days}-day progressive recon plan")
        return schedule


class BehaviorBlender:
    """High-level behavior blending orchestrator"""
    
    def __init__(self):
        self.analyzer = BehaviorAnalyzer()
        self.mimicker = None
        self.slow_burn = SlowBurnAttacker()
        logger.info("Behavior Blender initialized")
    
    def initialize_from_traffic(self, traffic_logs: List[Dict[str, Any]]):
        """Initialize from legitimate traffic"""
        self.analyzer.analyze_traffic_patterns(traffic_logs)
        self.mimicker = TrafficMimicker(self.analyzer)
        logger.info("Initialized from traffic baseline")
    
    def execute_stealthy_attack(self, attack_requests: List[Dict[str, Any]],
                               stealth_level: str = "high") -> List[Dict[str, Any]]:
        """Execute attack with stealth considerations"""
        
        if not self.mimicker:
            logger.error("Must initialize from traffic first")
            return attack_requests
        
        # Determine blend ratio based on stealth level
        blend_ratios = {
            "low": 2,      # 2 legitimate per malicious
            "medium": 5,   # 5 legitimate per malicious
            "high": 10,    # 10 legitimate per malicious
            "extreme": 20  # 20 legitimate per malicious
        }
        
        blend_ratio = blend_ratios.get(stealth_level, 10)
        
        # Blend each attack request
        all_traffic = []
        
        for attack_req in attack_requests:
            blended = self.mimicker.blend_malicious_with_legitimate(
                attack_req, 
                num_legitimate=blend_ratio
            )
            all_traffic.extend(blended)
        
        logger.info(f"Blended {len(attack_requests)} attacks with {len(all_traffic)} total requests")
        return all_traffic
    
    def adaptive_stealth(self, detection_events: List[Dict[str, Any]]) -> str:
        """Adapt stealth level based on detection events"""
        
        recent_detections = len([
            e for e in detection_events
            if (datetime.now() - datetime.fromisoformat(e.get('timestamp', datetime.now().isoformat()))).days < 1
        ])
        
        if recent_detections == 0:
            return "low"
        elif recent_detections < 3:
            return "medium"
        elif recent_detections < 7:
            return "high"
        else:
            return "extreme"
