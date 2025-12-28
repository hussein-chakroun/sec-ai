"""
Self-Improvement Loop - Phase 2
Analyzes failures and optimizes approach
"""
from typing import Dict, Any, List, Optional
from loguru import logger
from collections import defaultdict
import json
from datetime import datetime

from .memory_system import MemoryStore


class SelfImprovementEngine:
    """Engine for analyzing failures and improving performance"""
    
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.failure_analysis = defaultdict(list)
        self.optimization_history = []
        logger.info("Self-Improvement Engine initialized")
    
    def analyze_failure(self, tool: str, parameters: Dict[str, Any],
                       error: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze why an exploit/scan failed"""
        
        failure_record = {
            "tool": tool,
            "parameters": parameters,
            "error": error,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
        
        self.failure_analysis[tool].append(failure_record)
        
        # Categorize failure
        category = self._categorize_failure(error)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            tool, parameters, category, context
        )
        
        # Store in memory
        self.memory.record_technique_outcome(
            technique=tool,
            target_type=context.get('target_type', 'unknown'),
            success=False,
            context={
                "error_category": category,
                "parameters": parameters
            }
        )
        
        return {
            "category": category,
            "recommendations": recommendations,
            "adjusted_parameters": self._adjust_parameters(tool, parameters, category)
        }
    
    def _categorize_failure(self, error: str) -> str:
        """Categorize the type of failure"""
        error_lower = error.lower()
        
        if 'timeout' in error_lower:
            return 'timeout'
        elif 'permission' in error_lower or 'denied' in error_lower:
            return 'permissions'
        elif 'connection' in error_lower or 'refused' in error_lower:
            return 'connection'
        elif 'not found' in error_lower or '404' in error_lower:
            return 'not_found'
        elif 'blocked' in error_lower or 'forbidden' in error_lower:
            return 'blocked'
        else:
            return 'unknown'
    
    def _generate_recommendations(self, tool: str, parameters: Dict[str, Any],
                                 category: str, context: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on failure analysis"""
        recommendations = []
        
        if category == 'timeout':
            recommendations.append(f"Increase timeout for {tool}")
            recommendations.append("Consider network connectivity issues")
            recommendations.append("Try with reduced scope or simpler parameters")
        
        elif category == 'permissions':
            recommendations.append(f"Run {tool} with elevated privileges")
            recommendations.append("Check tool installation and permissions")
        
        elif category == 'connection':
            recommendations.append("Verify target is reachable")
            recommendations.append("Check firewall rules")
            recommendations.append("Consider using different network route")
        
        elif category == 'blocked':
            recommendations.append("Defensive measure detected")
            recommendations.append("Try stealth options")
            recommendations.append("Reduce request rate")
            recommendations.append("Consider IP rotation")
        
        return recommendations
    
    def _adjust_parameters(self, tool: str, parameters: Dict[str, Any],
                          category: str) -> Dict[str, Any]:
        """Automatically adjust parameters based on failure"""
        adjusted = parameters.copy()
        
        if tool == 'nmap':
            if category == 'timeout':
                adjusted['timing'] = 'T2'  # Slower timing
            elif category == 'blocked':
                adjusted['stealth'] = True
                adjusted['fragmentation'] = True
        
        elif tool == 'sqlmap':
            if category == 'timeout':
                adjusted['threads'] = 1
                adjusted['delay'] = 2
            elif category == 'blocked':
                adjusted['random_agent'] = True
                adjusted['tamper'] = 'space2comment'
        
        elif tool == 'hydra':
            if category == 'blocked':
                adjusted['tasks'] = 1  # Single thread
                adjusted['wait'] = 5   # Longer wait
        
        return adjusted
    
    def ab_test_approaches(self, approach_a: Dict[str, Any],
                          approach_b: Dict[str, Any],
                          iterations: int = 10) -> Dict[str, Any]:
        """A/B test different approaches"""
        
        test_id = f"ab_test_{datetime.now().timestamp()}"
        
        test_record = {
            "test_id": test_id,
            "approach_a": approach_a,
            "approach_b": approach_b,
            "iterations": iterations,
            "results_a": [],
            "results_b": [],
            "started_at": datetime.now().isoformat()
        }
        
        logger.info(f"Starting A/B test: {approach_a.get('name')} vs {approach_b.get('name')}")
        
        self.optimization_history.append(test_record)
        
        return {
            "test_id": test_id,
            "status": "initiated",
            "monitor_key": test_id
        }
    
    def record_ab_result(self, test_id: str, approach: str, 
                        success: bool, metrics: Dict[str, Any]):
        """Record result of A/B test iteration"""
        
        for test in self.optimization_history:
            if test['test_id'] == test_id:
                if approach == 'a':
                    test['results_a'].append({
                        "success": success,
                        "metrics": metrics,
                        "timestamp": datetime.now().isoformat()
                    })
                else:
                    test['results_b'].append({
                        "success": success,
                        "metrics": metrics,
                        "timestamp": datetime.now().isoformat()
                    })
                break
    
    def analyze_ab_test(self, test_id: str) -> Dict[str, Any]:
        """Analyze A/B test results"""
        
        test = next((t for t in self.optimization_history if t['test_id'] == test_id), None)
        
        if not test:
            return {"error": "Test not found"}
        
        results_a = test['results_a']
        results_b = test['results_b']
        
        if not results_a or not results_b:
            return {"status": "insufficient_data"}
        
        # Calculate success rates
        success_rate_a = sum(1 for r in results_a if r['success']) / len(results_a)
        success_rate_b = sum(1 for r in results_b if r['success']) / len(results_b)
        
        # Calculate average time
        avg_time_a = sum(r['metrics'].get('time', 0) for r in results_a) / len(results_a)
        avg_time_b = sum(r['metrics'].get('time', 0) for r in results_b) / len(results_b)
        
        # Determine winner
        score_a = success_rate_a - (avg_time_a / 100)  # Penalize slower approaches
        score_b = success_rate_b - (avg_time_b / 100)
        
        winner = 'a' if score_a > score_b else 'b'
        confidence = abs(score_a - score_b)
        
        return {
            "test_id": test_id,
            "approach_a": test['approach_a']['name'],
            "approach_b": test['approach_b']['name'],
            "success_rate_a": success_rate_a,
            "success_rate_b": success_rate_b,
            "avg_time_a": avg_time_a,
            "avg_time_b": avg_time_b,
            "winner": winner,
            "confidence": confidence,
            "recommendation": test[f'approach_{winner}']
        }
    
    def build_custom_wordlist(self, target: str, reconnaissance_data: Dict[str, Any]) -> List[str]:
        """Build custom wordlist from target reconnaissance"""
        
        wordlist = set()
        
        # Extract from domain
        if '.' in target:
            parts = target.replace('.', ' ').replace('-', ' ').split()
            wordlist.update(parts)
        
        # Extract from services
        services = reconnaissance_data.get('services', [])
        wordlist.update(services)
        
        # Extract from page content
        page_content = reconnaissance_data.get('page_content', '')
        if page_content:
            # Extract common patterns
            words = page_content.lower().split()
            # Add words longer than 4 characters
            wordlist.update(w for w in words if len(w) > 4 and w.isalpha())
        
        # Add common mutations
        base_words = list(wordlist)[:20]  # Top 20 words
        for word in base_words:
            wordlist.add(word + '123')
            wordlist.add(word + '2024')
            wordlist.add(word + '!')
        
        logger.info(f"Built custom wordlist with {len(wordlist)} entries")
        
        return list(wordlist)
    
    def optimize_timing(self, tool: str, target_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize timing based on past detections"""
        
        defensive_measures = target_profile.get('defensive_measures', [])
        
        # Get historical detection data
        past_engagements = self.memory.get_recent_engagements(days=90)
        detected_count = sum(
            1 for eng in past_engagements
            if eng.get('results', {}).get('detected', False)
        )
        
        detection_rate = detected_count / len(past_engagements) if past_engagements else 0
        
        timing = {
            "delay_between_requests": 1.0,
            "randomize_delay": True,
            "timing_template": "normal"
        }
        
        # Adjust based on detection risk
        if detection_rate > 0.3:
            timing['delay_between_requests'] = 3.0
            timing['timing_template'] = 'stealthy'
            logger.info("High detection rate, using stealthy timing")
        
        # Adjust for specific defensive measures
        if 'ids' in defensive_measures:
            timing['delay_between_requests'] *= 2
            timing['randomize_delay'] = True
        
        if 'rate_limiting' in defensive_measures:
            timing['delay_between_requests'] *= 1.5
        
        return timing
    
    def get_improvement_suggestions(self) -> List[Dict[str, Any]]:
        """Get suggestions for improvement based on failure analysis"""
        
        suggestions = []
        
        # Analyze failure patterns
        for tool, failures in self.failure_analysis.items():
            if len(failures) >= 3:
                recent_failures = failures[-5:]
                
                # Check if same error repeating
                error_categories = [self._categorize_failure(f['error']) for f in recent_failures]
                most_common = max(set(error_categories), key=error_categories.count)
                
                if error_categories.count(most_common) >= 3:
                    suggestions.append({
                        "tool": tool,
                        "issue": f"Repeated {most_common} failures",
                        "suggestion": f"Review {tool} configuration and parameters",
                        "priority": "high"
                    })
        
        # Analyze optimization opportunities
        stats = self.memory.get_memory_statistics()
        
        if stats['total_engagements'] < 10:
            suggestions.append({
                "area": "learning",
                "suggestion": "Need more engagements to build effective patterns",
                "priority": "medium"
            })
        
        return suggestions
