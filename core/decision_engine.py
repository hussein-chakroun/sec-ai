"""
Enhanced Decision Engine - Phase 2
Probabilistic reasoning and adaptive strategy
"""
from typing import Dict, Any, List, Optional, Tuple
from loguru import logger
import random
from datetime import datetime
from collections import defaultdict

from .memory_system import MemoryStore
from .vector_knowledge import VectorKnowledgeBase


class ProbabilisticReasoner:
    """Probabilistic reasoning for vulnerability assessment"""
    
    def __init__(self, memory: MemoryStore, knowledge_base: VectorKnowledgeBase):
        self.memory = memory
        self.kb = knowledge_base
        logger.info("Probabilistic Reasoner initialized")
    
    def estimate_vulnerability_probability(self, service: str, version: str, 
                                          context: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate probability of vulnerability existing"""
        
        # Search for known exploits
        query = f"{service} {version} vulnerability"
        similar_exploits = self.kb.search_similar_exploits(query, n_results=10)
        
        # Get historical data
        target_profile = context.get('target_profile', {})
        tech_stack = target_profile.get('technology_stack', [])
        
        # Base probability from CVE database
        cve_probability = min(len(similar_exploits) / 10, 0.9)
        
        # Adjust for version specificity
        exact_version_match = any(
            version in exp['document'] 
            for exp in similar_exploits
        )
        version_factor = 1.2 if exact_version_match else 0.8
        
        # Adjust for target history
        known_vulns = target_profile.get('known_vulnerabilities', [])
        history_factor = 1.1 if service in str(known_vulns) else 1.0
        
        # Calculate final probability
        probability = cve_probability * version_factor * history_factor
        probability = min(max(probability, 0.0), 1.0)
        
        # Estimate severity
        severity_scores = [
            exp['metadata'].get('cvss_score', 5.0)
            for exp in similar_exploits
        ]
        avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 5.0
        
        return {
            "service": service,
            "version": version,
            "probability": probability,
            "confidence": len(similar_exploits) / 10,
            "estimated_severity": avg_severity,
            "similar_exploits_count": len(similar_exploits),
            "reasoning": self._explain_reasoning(
                cve_probability, version_factor, history_factor, similar_exploits
            )
        }
    
    def _explain_reasoning(self, cve_prob: float, version_factor: float,
                          history_factor: float, exploits: List) -> str:
        """Generate explanation for probability estimate"""
        explanation = []
        
        if cve_prob > 0.5:
            explanation.append(f"Found {len(exploits)} similar known exploits")
        
        if version_factor > 1.0:
            explanation.append("Exact version match in CVE database")
        
        if history_factor > 1.0:
            explanation.append("Service previously found vulnerable on this target")
        
        return "; ".join(explanation) if explanation else "Limited historical data"
    
    def rank_attack_vectors(self, scan_results: Dict[str, Any],
                           context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Rank potential attack vectors by probability of success"""
        
        open_ports = scan_results.get('parsed', {}).get('open_ports', [])
        
        attack_vectors = []
        
        for port_info in open_ports:
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')
            port = port_info.get('port')
            
            # Estimate vulnerability
            vuln_estimate = self.estimate_vulnerability_probability(
                service, version, context
            )
            
            # Get technique success rates
            techniques = self._get_applicable_techniques(service)
            avg_success_rate = sum(t['success_rate'] for t in techniques) / len(techniques) if techniques else 0.5
            
            # Calculate overall score
            score = (vuln_estimate['probability'] * 0.6 + 
                    avg_success_rate * 0.4)
            
            attack_vectors.append({
                "port": port,
                "service": service,
                "version": version,
                "score": score,
                "vulnerability_probability": vuln_estimate['probability'],
                "estimated_severity": vuln_estimate['estimated_severity'],
                "applicable_techniques": techniques,
                "reasoning": vuln_estimate['reasoning']
            })
        
        # Sort by score
        attack_vectors.sort(key=lambda x: x['score'], reverse=True)
        
        return attack_vectors
    
    def _get_applicable_techniques(self, service: str) -> List[Dict[str, Any]]:
        """Get applicable techniques for a service"""
        techniques_query = f"attack {service}"
        similar_techniques = self.kb.search_techniques(techniques_query, n_results=5)
        
        results = []
        for tech in similar_techniques:
            stats = self.memory.get_technique_stats(tech['id'])
            results.append({
                "id": tech['id'],
                "name": tech['document'][:100],
                "success_rate": stats['success_rate'],
                "confidence": stats['confidence']
            })
        
        return results


class CostBenefitAnalyzer:
    """Analyze cost-benefit of different testing approaches"""
    
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        logger.info("Cost-Benefit Analyzer initialized")
    
    def analyze_approach(self, approach: Dict[str, Any], 
                        context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cost-benefit of an approach"""
        
        tool = approach.get('tool', 'unknown')
        target_type = context.get('target_type', 'unknown')
        
        # Get historical performance
        stats = self.memory.get_technique_stats(tool, target_type)
        
        # Estimate costs
        time_cost = self._estimate_time_cost(tool, approach.get('parameters', {}))
        resource_cost = self._estimate_resource_cost(tool)
        detection_risk = self._estimate_detection_risk(tool, context)
        
        # Estimate benefits
        expected_value = stats['success_rate'] * approach.get('potential_value', 1.0)
        
        # Calculate ROI
        total_cost = time_cost + resource_cost + (detection_risk * 2)
        roi = (expected_value - total_cost) / max(total_cost, 0.1)
        
        return {
            "tool": tool,
            "expected_success_rate": stats['success_rate'],
            "confidence": stats['confidence'],
            "time_cost": time_cost,
            "resource_cost": resource_cost,
            "detection_risk": detection_risk,
            "expected_value": expected_value,
            "roi": roi,
            "recommendation": "proceed" if roi > 0.3 else "skip"
        }
    
    def _estimate_time_cost(self, tool: str, parameters: Dict) -> float:
        """Estimate time cost (normalized 0-1)"""
        time_costs = {
            "nmap": 0.2,
            "sqlmap": 0.6,
            "hydra": 0.8,
            "metasploit": 0.5
        }
        return time_costs.get(tool, 0.5)
    
    def _estimate_resource_cost(self, tool: str) -> float:
        """Estimate computational resource cost"""
        resource_costs = {
            "nmap": 0.1,
            "sqlmap": 0.4,
            "hydra": 0.7,
            "metasploit": 0.3
        }
        return resource_costs.get(tool, 0.3)
    
    def _estimate_detection_risk(self, tool: str, context: Dict) -> float:
        """Estimate risk of detection"""
        base_risk = {
            "nmap": 0.3,
            "sqlmap": 0.6,
            "hydra": 0.9,
            "metasploit": 0.7
        }.get(tool, 0.5)
        
        # Adjust for known defensive measures
        target_profile = context.get('target_profile', {})
        defensive_measures = target_profile.get('defensive_measures', [])
        
        if 'ids' in str(defensive_measures).lower():
            base_risk *= 1.3
        if 'waf' in str(defensive_measures).lower():
            base_risk *= 1.2
        
        return min(base_risk, 1.0)
    
    def compare_approaches(self, approaches: List[Dict[str, Any]],
                          context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Compare multiple approaches and rank them"""
        
        analyzed = []
        for approach in approaches:
            analysis = self.analyze_approach(approach, context)
            analyzed.append({
                **approach,
                "analysis": analysis
            })
        
        # Sort by ROI
        analyzed.sort(key=lambda x: x['analysis']['roi'], reverse=True)
        
        return analyzed


class AdaptiveStrategy:
    """Adaptive strategy based on target responses"""
    
    def __init__(self, memory: MemoryStore, knowledge_base: VectorKnowledgeBase):
        self.memory = memory
        self.kb = knowledge_base
        self.response_history = []
        logger.info("Adaptive Strategy initialized")
    
    def record_response(self, action: Dict[str, Any], response: Dict[str, Any]):
        """Record target response to an action"""
        self.response_history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "response": response,
            "success": response.get('success', False)
        })
    
    def detect_defensive_pattern(self) -> Optional[Dict[str, Any]]:
        """Detect defensive patterns from responses"""
        
        if len(self.response_history) < 3:
            return None
        
        recent = self.response_history[-5:]
        
        # Check for rate limiting
        failures = [r for r in recent if not r['success']]
        if len(failures) >= 3:
            return {
                "type": "rate_limiting",
                "confidence": 0.7,
                "recommendation": "slow_down",
                "suggested_delay": 5.0
            }
        
        # Check for blocking
        consecutive_failures = 0
        for r in reversed(self.response_history):
            if not r['success']:
                consecutive_failures += 1
            else:
                break
        
        if consecutive_failures >= 4:
            return {
                "type": "blocking",
                "confidence": 0.8,
                "recommendation": "change_approach",
                "reason": f"{consecutive_failures} consecutive failures"
            }
        
        return None
    
    def adapt_strategy(self, current_strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt strategy based on responses"""
        
        defensive_pattern = self.detect_defensive_pattern()
        
        if not defensive_pattern:
            return current_strategy
        
        adapted = current_strategy.copy()
        
        if defensive_pattern['type'] == 'rate_limiting':
            # Slow down
            adapted['delay_between_requests'] = defensive_pattern['suggested_delay']
            adapted['concurrency'] = 1
            logger.info("Detected rate limiting, slowing down")
        
        elif defensive_pattern['type'] == 'blocking':
            # Change approach
            adapted['switch_tool'] = True
            adapted['use_evasion'] = True
            logger.info("Detected blocking, changing approach")
        
        return adapted
    
    def predict_defensive_measures(self, target_profile: Dict[str, Any]) -> List[str]:
        """Predict defensive measures before encountering them"""
        
        predictions = []
        
        tech_stack = target_profile.get('technology_stack', [])
        
        # Predict based on technology stack
        if any('apache' in s.lower() for s in tech_stack):
            predictions.append('mod_security')
        
        if any('nginx' in s.lower() for s in tech_stack):
            predictions.append('rate_limiting')
        
        if any('cloudflare' in str(target_profile).lower()):
            predictions.append('waf')
            predictions.append('ddos_protection')
        
        # Search for similar targets
        target_desc = f"Target with {', '.join(tech_stack[:3])}"
        similar_engagements = self.kb.search_similar_engagements(target_desc, n_results=3)
        
        for eng in similar_engagements:
            defensive = eng['metadata'].get('defensive_measures', [])
            predictions.extend(defensive)
        
        return list(set(predictions))
