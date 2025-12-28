"""
Self-Improvement and Learning System
"""
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import numpy as np
from sklearn.linear_model import LogisticRegression
from loguru import logger
import json


class SelfImprovementEngine:
    """Engine for continuous learning and self-improvement"""
    
    def __init__(self, memory_system, knowledge_base):
        self.memory = memory_system
        self.knowledge = knowledge_base
        
        # Learning models
        self.technique_predictor = LogisticRegression()
        self.is_trained = False
        
        # Performance tracking
        self.performance_history = []
        
        logger.info("Self-improvement engine initialized")
    
    def analyze_failure(self, context: Dict[str, Any], technique: str,
                       tool: str, parameters: Dict, error: str) -> Dict[str, Any]:
        """Analyze why a technique/exploit failed"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'technique': technique,
            'tool': tool,
            'parameters': parameters,
            'error': error,
            'context': context,
            'failure_type': self._classify_failure(error),
            'suggested_adjustments': []
        }
        
        # Determine failure cause
        failure_type = analysis['failure_type']
        
        if failure_type == 'timeout':
            analysis['suggested_adjustments'].append({
                'parameter': 'timeout',
                'adjustment': 'increase',
                'new_value': parameters.get('timeout', 600) * 1.5,
                'reasoning': 'Operation timed out, increase timeout'
            })
        
        elif failure_type == 'authentication':
            analysis['suggested_adjustments'].append({
                'parameter': 'wordlist',
                'adjustment': 'expand',
                'new_value': 'use_target_specific',
                'reasoning': 'Authentication failed, try target-specific wordlist'
            })
            analysis['suggested_adjustments'].append({
                'parameter': 'threads',
                'adjustment': 'decrease',
                'new_value': max(1, parameters.get('threads', 4) // 2),
                'reasoning': 'Reduce threads to avoid detection/blocking'
            })
        
        elif failure_type == 'detection':
            analysis['suggested_adjustments'].append({
                'parameter': 'stealth',
                'adjustment': 'increase',
                'new_value': 'use_evasion_techniques',
                'reasoning': 'Detected by security mechanisms, increase stealth'
            })
            analysis['suggested_adjustments'].append({
                'parameter': 'timing',
                'adjustment': 'slower',
                'new_value': 'T1',  # Slowest nmap timing
                'reasoning': 'Use slower scan timing'
            })
        
        elif failure_type == 'false_positive':
            analysis['suggested_adjustments'].append({
                'parameter': 'validation',
                'adjustment': 'increase',
                'new_value': 'double_check',
                'reasoning': 'False positive detected, add validation'
            })
        
        elif failure_type == 'target_not_vulnerable':
            analysis['suggested_adjustments'].append({
                'parameter': 'strategy',
                'adjustment': 'pivot',
                'new_value': 'try_alternative_technique',
                'reasoning': 'Target not vulnerable to this technique'
            })
        
        # Store learning event
        self.memory.store_learning_event(
            event_type='exploit_failure',
            context=context,
            analysis=json.dumps(analysis),
            adjustments=analysis['suggested_adjustments']
        )
        
        logger.info(f"Analyzed failure: {failure_type}, {len(analysis['suggested_adjustments'])} adjustments suggested")
        
        return analysis
    
    def _classify_failure(self, error: str) -> str:
        """Classify the type of failure"""
        error_lower = error.lower()
        
        if 'timeout' in error_lower or 'timed out' in error_lower:
            return 'timeout'
        elif 'authentication' in error_lower or 'login' in error_lower or 'credentials' in error_lower:
            return 'authentication'
        elif 'blocked' in error_lower or 'banned' in error_lower or 'detected' in error_lower:
            return 'detection'
        elif 'not vulnerable' in error_lower or 'no injection' in error_lower:
            return 'target_not_vulnerable'
        elif 'false positive' in error_lower:
            return 'false_positive'
        else:
            return 'unknown'
    
    def optimize_parameters(self, technique: str, tool: str, 
                          historical_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Optimize parameters based on historical performance"""
        if not historical_results:
            return self.knowledge.get_technique(technique).get('parameters', {}).get(tool, {})
        
        # Analyze successful attempts
        successful = [r for r in historical_results if r.get('success')]
        
        if not successful:
            # All failed, try more conservative parameters
            return self._get_conservative_parameters(technique, tool)
        
        # Extract common parameters from successful attempts
        param_frequency = {}
        for result in successful:
            params = result.get('parameters', {})
            for key, value in params.items():
                if key not in param_frequency:
                    param_frequency[key] = {}
                value_str = str(value)
                param_frequency[key][value_str] = param_frequency[key].get(value_str, 0) + 1
        
        # Select most common successful parameters
        optimized = {}
        for param, values in param_frequency.items():
            most_common = max(values.items(), key=lambda x: x[1])
            optimized[param] = most_common[0]
        
        logger.info(f"Optimized parameters for {technique}/{tool}")
        return optimized
    
    def _get_conservative_parameters(self, technique: str, tool: str) -> Dict[str, Any]:
        """Get conservative parameters for stealth"""
        conservative = {
            'nmap': {
                'timing': 'T1',  # Slowest
                'max_rate': 100,
                'scan_delay': '1s'
            },
            'hydra': {
                'threads': 1,
                'wait_time': 5
            },
            'sqlmap': {
                'level': 1,
                'risk': 1,
                'threads': 1
            }
        }
        
        return conservative.get(tool, {})
    
    def predict_vulnerability_likelihood(self, target_context: Dict[str, Any],
                                        vulnerability_type: str) -> float:
        """Predict likelihood of vulnerability existing"""
        # Get similar past engagements
        similar = self.memory.get_similar_engagements(
            target_context.get('technologies', []),
            limit=10
        )
        
        if not similar:
            return 0.5  # Unknown, assume 50%
        
        # Calculate probability based on similar targets
        found_count = sum(
            1 for eng in similar
            if vulnerability_type in eng.get('vulnerabilities', [])
        )
        
        probability = found_count / len(similar)
        
        # Adjust based on technology versions
        if 'versions' in target_context:
            # Check CVE database for known vulnerabilities
            for tech, version in target_context.get('versions', {}).items():
                cves = self.knowledge.search_cve(f"{tech} {version}", limit=5)
                if cves:
                    probability = min(1.0, probability + 0.2)  # Boost if CVEs exist
        
        logger.debug(f"Vulnerability likelihood for {vulnerability_type}: {probability:.2f}")
        return probability
    
    def cost_benefit_analysis(self, technique: str, tool: str,
                             context: Dict[str, Any]) -> Dict[str, float]:
        """Analyze cost vs benefit of a testing approach"""
        # Get technique data
        tech_data = self.knowledge.get_technique(technique) or {}
        
        # Cost factors
        stealth_cost = 1.0 - tech_data.get('stealth_level_numeric', 0.5)  # Lower stealth = higher cost
        time_cost = tech_data.get('avg_execution_time', 300) / 600  # Normalize to 0-1
        detection_risk = self._calculate_detection_risk(technique, context)
        
        total_cost = (stealth_cost * 0.4) + (time_cost * 0.3) + (detection_risk * 0.3)
        
        # Benefit factors
        success_probability = self.memory.get_technique_success_rate(technique, tool)
        vuln_likelihood = self.predict_vulnerability_likelihood(context, technique)
        impact = tech_data.get('impact_score', 0.5)
        
        total_benefit = (success_probability * 0.4) + (vuln_likelihood * 0.4) + (impact * 0.2)
        
        # Calculate ROI
        roi = total_benefit / (total_cost + 0.01)  # Avoid division by zero
        
        analysis = {
            'cost': total_cost,
            'benefit': total_benefit,
            'roi': roi,
            'recommendation': 'execute' if roi > 1.0 else 'skip',
            'confidence': min(total_benefit, 1.0)
        }
        
        logger.debug(f"Cost-benefit for {technique}: ROI={roi:.2f}")
        return analysis
    
    def _calculate_detection_risk(self, technique: str, context: Dict[str, Any]) -> float:
        """Calculate risk of detection"""
        base_risk = 0.3
        
        # Increase risk if defensive mechanisms detected
        defensive_mechanisms = context.get('defensive_mechanisms', [])
        if 'ids' in defensive_mechanisms or 'ips' in defensive_mechanisms:
            base_risk += 0.3
        if 'waf' in defensive_mechanisms:
            base_risk += 0.2
        if 'firewall' in defensive_mechanisms:
            base_risk += 0.1
        
        # Check past detection events
        detection_events = self.memory.get_learning_events('detection', limit=10)
        if detection_events:
            recent_detections = sum(
                1 for e in detection_events
                if e.get('context', {}).get('technique') == technique
            )
            base_risk += (recent_detections / 10) * 0.2
        
        return min(base_risk, 1.0)
    
    def adaptive_strategy(self, current_results: List[Dict[str, Any]],
                         target_context: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt strategy based on target responses"""
        strategy = {
            'approach': 'balanced',
            'techniques': [],
            'parameters': {},
            'reasoning': []
        }
        
        # Analyze current results
        if not current_results:
            strategy['approach'] = 'reconnaissance'
            strategy['reasoning'].append("No data yet, start with reconnaissance")
            return strategy
        
        # Check for defensive responses
        detected_defenses = self._detect_defensive_measures(current_results)
        
        if detected_defenses:
            strategy['approach'] = 'stealth'
            strategy['reasoning'].append(f"Detected defenses: {', '.join(detected_defenses)}")
            
            # Get evasion techniques
            evasion = self.knowledge.get_evasion_techniques(detected_defenses)
            for ev in evasion:
                strategy['techniques'].append(ev['technique'])
                strategy['parameters'][ev['technique']] = {
                    k: v for k, v in ev.items()
                    if k not in ['technique', 'description', 'effectiveness']
                }
        
        # Check success rate
        successful = [r for r in current_results if r.get('result', {}).get('success')]
        success_rate = len(successful) / len(current_results)
        
        if success_rate < 0.3:
            strategy['approach'] = 'pivot'
            strategy['reasoning'].append(f"Low success rate ({success_rate:.1%}), trying different approach")
            
            # Suggest alternative techniques
            used_techniques = set(r.get('tool') for r in current_results)
            all_techniques = list(self.knowledge.techniques.keys())
            unused = [t for t in all_techniques if t not in used_techniques]
            
            if unused:
                # Recommend highest success rate unused technique
                best = max(
                    unused,
                    key=lambda t: self.knowledge.techniques[t].get('success_rate', 0)
                )
                strategy['techniques'].append(best)
        
        elif success_rate > 0.7:
            strategy['approach'] = 'exploit'
            strategy['reasoning'].append(f"High success rate ({success_rate:.1%}), escalate to exploitation")
        
        return strategy
    
    def _detect_defensive_measures(self, results: List[Dict[str, Any]]) -> List[str]:
        """Detect defensive measures from results"""
        defenses = []
        
        for result in results:
            error = result.get('result', {}).get('stderr', '').lower()
            stdout = result.get('result', {}).get('stdout', '').lower()
            
            if 'blocked' in error or 'filtered' in stdout:
                defenses.append('firewall')
            if 'waf' in error or 'web application firewall' in error:
                defenses.append('waf')
            if 'rate limit' in error or 'too many requests' in error:
                defenses.append('rate_limiting')
            if 'banned' in error or 'blacklist' in error:
                defenses.append('ids')
        
        return list(set(defenses))
    
    def build_custom_wordlist(self, target_context: Dict[str, Any],
                             scan_results: List[Dict[str, Any]]) -> List[str]:
        """Build custom wordlist from target reconnaissance"""
        wordlist = set()
        
        # Get suggestions from knowledge base
        kb_suggestions = self.knowledge.get_wordlist_suggestions(target_context)
        wordlist.update(kb_suggestions)
        
        # Extract from scan results
        for result in scan_results:
            parsed = result.get('result', {}).get('parsed', {})
            
            # Extract from service banners
            services = parsed.get('services', [])
            for service in services:
                if isinstance(service, str):
                    words = service.lower().split()
                    wordlist.update(words)
            
            # Extract from HTTP responses
            if 'http' in parsed:
                headers = parsed.get('http', {}).get('headers', {})
                for key, value in headers.items():
                    wordlist.add(key.lower())
                    if isinstance(value, str):
                        wordlist.update(value.lower().split())
        
        # Add mutations
        base_words = list(wordlist)
        for word in base_words[:20]:  # Limit mutations
            wordlist.add(word + '123')
            wordlist.add(word + '!')
            wordlist.add(word.upper())
            wordlist.add(word.capitalize())
        
        return sorted(list(wordlist))
    
    def train_from_history(self):
        """Train models from historical data"""
        # Get technique usage history
        stats = self.memory.get_stats()
        
        if stats['total_techniques'] < 10:
            logger.warning("Not enough data to train, need at least 10 samples")
            return False
        
        # This is a simplified version - in production would use more sophisticated ML
        logger.info("Training models from historical data...")
        
        # Update knowledge base success rates
        for technique_id in self.knowledge.techniques.keys():
            success_rate = self.memory.get_technique_success_rate(technique_id)
            if success_rate > 0:
                self.knowledge.update_technique_success_rate(technique_id, success_rate)
        
        self.is_trained = True
        logger.info("Training complete")
        return True
