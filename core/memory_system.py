"""
Persistent Memory System - Phase 2
Manages long-term memory across engagements
"""
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime, timedelta
from loguru import logger
import hashlib
from collections import defaultdict


class MemoryStore:
    """Long-term memory system for pentesting AI"""
    
    def __init__(self, memory_dir: str = "./data/memory"):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        
        self.engagements_file = self.memory_dir / "engagements.json"
        self.targets_file = self.memory_dir / "target_profiles.json"
        self.techniques_file = self.memory_dir / "technique_stats.json"
        self.patterns_file = self.memory_dir / "learned_patterns.json"
        
        # Load existing memory
        self.engagements = self._load_json(self.engagements_file, {})
        self.target_profiles = self._load_json(self.targets_file, {})
        self.technique_stats = self._load_json(self.techniques_file, {})
        self.learned_patterns = self._load_json(self.patterns_file, {})
        
        logger.info("Memory store initialized")
    
    def _load_json(self, filepath: Path, default: Any) -> Any:
        """Load JSON file or return default"""
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
        return default
    
    def _save_json(self, filepath: Path, data: Any):
        """Save data to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _get_target_hash(self, target: str) -> str:
        """Get consistent hash for target"""
        return hashlib.sha256(target.encode()).hexdigest()[:16]
    
    def store_engagement(self, target: str, results: Dict[str, Any]):
        """Store engagement results"""
        engagement_id = f"{self._get_target_hash(target)}_{datetime.now().timestamp()}"
        
        self.engagements[engagement_id] = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "success_metrics": self._calculate_success_metrics(results)
        }
        
        self._save_json(self.engagements_file, self.engagements)
        logger.info(f"Stored engagement: {engagement_id}")
        
        # Update target profile
        self._update_target_profile(target, results)
    
    def _calculate_success_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate success metrics from results"""
        scan_results = results.get('scan_results', [])
        
        total_scans = len(scan_results)
        successful_scans = sum(
            1 for s in scan_results 
            if s.get('result', {}).get('success', False)
        )
        
        vulnerabilities_found = sum(
            len(s.get('result', {}).get('parsed', {}).get('open_ports', []))
            for s in scan_results
        )
        
        return {
            "total_scans": total_scans,
            "successful_scans": successful_scans,
            "success_rate": successful_scans / total_scans if total_scans > 0 else 0,
            "vulnerabilities_found": vulnerabilities_found,
            "tools_used": list(set(s['tool'] for s in scan_results))
        }
    
    def _update_target_profile(self, target: str, results: Dict[str, Any]):
        """Update or create target profile"""
        target_hash = self._get_target_hash(target)
        
        if target_hash not in self.target_profiles:
            self.target_profiles[target_hash] = {
                "target": target,
                "first_seen": datetime.now().isoformat(),
                "engagement_count": 0,
                "technology_stack": set(),
                "known_vulnerabilities": [],
                "defensive_measures": set(),
                "success_patterns": []
            }
        
        profile = self.target_profiles[target_hash]
        profile["engagement_count"] += 1
        profile["last_seen"] = datetime.now().isoformat()
        
        # Extract technology stack
        for scan in results.get('scan_results', []):
            services = scan.get('result', {}).get('parsed', {}).get('services', [])
            profile["technology_stack"].update(services)
        
        # Convert sets to lists for JSON serialization
        profile["technology_stack"] = list(profile["technology_stack"])
        profile["defensive_measures"] = list(profile.get("defensive_measures", set()))
        
        self._save_json(self.targets_file, self.target_profiles)
    
    def get_target_profile(self, target: str) -> Optional[Dict[str, Any]]:
        """Get profile for a target"""
        target_hash = self._get_target_hash(target)
        return self.target_profiles.get(target_hash)
    
    def record_technique_outcome(self, technique: str, target_type: str, 
                                success: bool, context: Dict[str, Any]):
        """Record outcome of a technique"""
        if technique not in self.technique_stats:
            self.technique_stats[technique] = {
                "total_attempts": 0,
                "successful_attempts": 0,
                "by_target_type": defaultdict(lambda: {"total": 0, "success": 0}),
                "contexts": []
            }
        
        stats = self.technique_stats[technique]
        stats["total_attempts"] += 1
        
        if success:
            stats["successful_attempts"] += 1
        
        # Track by target type
        if target_type not in stats["by_target_type"]:
            stats["by_target_type"][target_type] = {"total": 0, "success": 0}
        
        stats["by_target_type"][target_type]["total"] += 1
        if success:
            stats["by_target_type"][target_type]["success"] += 1
        
        # Store context
        stats["contexts"].append({
            "timestamp": datetime.now().isoformat(),
            "success": success,
            "context": context
        })
        
        # Keep only recent contexts
        stats["contexts"] = stats["contexts"][-100:]
        
        self._save_json(self.techniques_file, self.technique_stats)
    
    def get_technique_stats(self, technique: str, target_type: str = None) -> Dict[str, Any]:
        """Get statistics for a technique"""
        if technique not in self.technique_stats:
            return {
                "success_rate": 0.5,  # Default
                "confidence": 0.0,
                "total_attempts": 0
            }
        
        stats = self.technique_stats[technique]
        
        if target_type and target_type in stats["by_target_type"]:
            type_stats = stats["by_target_type"][target_type]
            total = type_stats["total"]
            success = type_stats["success"]
        else:
            total = stats["total_attempts"]
            success = stats["successful_attempts"]
        
        return {
            "success_rate": success / total if total > 0 else 0.5,
            "confidence": min(total / 100, 1.0),  # Confidence increases with attempts
            "total_attempts": total,
            "successful_attempts": success
        }
    
    def learn_pattern(self, pattern_id: str, description: str, 
                     conditions: List[str], outcome: str):
        """Learn a new pattern"""
        self.learned_patterns[pattern_id] = {
            "description": description,
            "conditions": conditions,
            "outcome": outcome,
            "learned_at": datetime.now().isoformat(),
            "confidence": 0.5,
            "occurrences": 1
        }
        
        self._save_json(self.patterns_file, self.learned_patterns)
        logger.info(f"Learned new pattern: {pattern_id}")
    
    def reinforce_pattern(self, pattern_id: str, success: bool):
        """Reinforce or weaken a pattern based on outcome"""
        if pattern_id not in self.learned_patterns:
            return
        
        pattern = self.learned_patterns[pattern_id]
        pattern["occurrences"] += 1
        
        # Update confidence using exponential moving average
        alpha = 0.1
        current_confidence = pattern["confidence"]
        new_signal = 1.0 if success else 0.0
        
        pattern["confidence"] = (1 - alpha) * current_confidence + alpha * new_signal
        pattern["last_seen"] = datetime.now().isoformat()
        
        self._save_json(self.patterns_file, self.learned_patterns)
    
    def get_matching_patterns(self, conditions: List[str], 
                             min_confidence: float = 0.6) -> List[Dict]:
        """Get patterns matching current conditions"""
        matching = []
        
        for pattern_id, pattern in self.learned_patterns.items():
            # Check if conditions overlap
            pattern_conditions = set(pattern["conditions"])
            current_conditions = set(conditions)
            
            overlap = len(pattern_conditions & current_conditions)
            
            if overlap > 0 and pattern["confidence"] >= min_confidence:
                matching.append({
                    "pattern_id": pattern_id,
                    "pattern": pattern,
                    "match_score": overlap / len(pattern_conditions)
                })
        
        # Sort by match score and confidence
        matching.sort(
            key=lambda x: (x["match_score"], x["pattern"]["confidence"]),
            reverse=True
        )
        
        return matching
    
    def get_recent_engagements(self, days: int = 30) -> List[Dict]:
        """Get recent engagements"""
        cutoff = datetime.now() - timedelta(days=days)
        
        recent = []
        for eng_id, engagement in self.engagements.items():
            eng_time = datetime.fromisoformat(engagement["timestamp"])
            if eng_time > cutoff:
                recent.append({
                    "id": eng_id,
                    **engagement
                })
        
        return sorted(recent, key=lambda x: x["timestamp"], reverse=True)
    
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get memory system statistics"""
        return {
            "total_engagements": len(self.engagements),
            "tracked_targets": len(self.target_profiles),
            "tracked_techniques": len(self.technique_stats),
            "learned_patterns": len(self.learned_patterns),
            "high_confidence_patterns": len([
                p for p in self.learned_patterns.values()
                if p["confidence"] > 0.7
            ])
        }
