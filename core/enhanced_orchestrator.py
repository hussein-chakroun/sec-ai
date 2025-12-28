"""
Enhanced LLM Orchestrator with Memory - Phase 2
"""
from typing import Dict, Any, List, Optional
from core.llm_orchestrator import LLMOrchestrator as BaseOrchestrator
from memory import VectorDatabase, PersistentMemory
from knowledge import KnowledgeBase
from learning import SelfImprovementEngine, PatternRecognizer
from loguru import logger
import json


class EnhancedLLMOrchestrator(BaseOrchestrator):
    """LLM Orchestrator with memory and learning capabilities"""
    
    def __init__(self, provider, enable_memory: bool = True):
        super().__init__(provider)
        
        self.enable_memory = enable_memory
        
        if enable_memory:
            # Initialize memory systems
            self.vector_db = VectorDatabase()
            self.persistent_memory = PersistentMemory()
            self.knowledge_base = KnowledgeBase()
            
            # Initialize learning systems
            self.learning_engine = SelfImprovementEngine(
                self.persistent_memory,
                self.knowledge_base
            )
            self.pattern_recognizer = PatternRecognizer()
            
            # Train from historical data
            self.learning_engine.train_from_history()
            
            logger.info("Enhanced LLM Orchestrator initialized with memory and learning")
        else:
            logger.info("Enhanced LLM Orchestrator initialized without memory")
    
    def analyze_target_with_memory(self, target: str) -> Dict[str, Any]:
        """Analyze target using memory of past engagements"""
        # Get base analysis
        base_analysis = self.analyze_target(target)
        
        if not self.enable_memory:
            return base_analysis
        
        # Search for similar past engagements
        technologies = base_analysis.get('technologies', [])
        similar_engagements = self.vector_db.search_similar_engagements(
            target,
            technologies,
            n_results=5
        )
        
        # Enhance analysis with historical knowledge
        enhanced_analysis = {
            **base_analysis,
            'similar_past_engagements': similar_engagements,
            'learned_patterns': [],
            'recommended_techniques': []
        }
        
        # Get relevant techniques from knowledge base
        context = {
            'services': base_analysis.get('services', []),
            'os': base_analysis.get('os', ''),
            'technologies': technologies
        }
        
        recommended_techniques = self.knowledge_base.get_techniques_for_context(context)
        enhanced_analysis['recommended_techniques'] = recommended_techniques[:5]
        
        # Search for relevant CVEs
        for tech in technologies[:3]:  # Limit to avoid API spam
            cves = self.knowledge_base.search_cve(tech, limit=3)
            if cves:
                enhanced_analysis.setdefault('potential_cves', []).extend(cves)
        
        logger.info(f"Enhanced analysis with {len(similar_engagements)} similar engagements")
        
        return enhanced_analysis
    
    def decide_next_action_with_learning(self, scan_results: Dict[str, Any],
                                        context: Optional[Dict] = None) -> Dict[str, Any]:
        """Decide next action using learning and cost-benefit analysis"""
        # Get base decision
        base_decision = self.decide_next_action(scan_results, context)
        
        if not self.enable_memory:
            return base_decision
        
        # Recognize patterns in current results
        all_results = context.get('all_scan_results', []) if context else []
        if all_results:
            vulnerability_patterns = self.pattern_recognizer.recognize_vulnerability_patterns(all_results)
            defensive_patterns = self.pattern_recognizer.recognize_defensive_patterns(all_results)
            
            context = context or {}
            context['vulnerability_patterns'] = vulnerability_patterns
            context['defensive_patterns'] = defensive_patterns
        
        # Perform cost-benefit analysis
        tool = base_decision.get('tool', '')
        if tool and tool != 'none':
            cba = self.learning_engine.cost_benefit_analysis(
                tool,
                tool,  # Using same for simplicity
                context or {}
            )
            
            base_decision['cost_benefit_analysis'] = cba
            
            # Override decision if ROI is too low
            if cba['roi'] < 0.5:
                base_decision['reasoning'] += f" However, cost-benefit analysis shows low ROI ({cba['roi']:.2f}). Consider alternative."
                base_decision['alternative_suggested'] = True
        
        # Get adaptive strategy
        if all_results:
            adaptive_strategy = self.learning_engine.adaptive_strategy(
                all_results,
                context or {}
            )
            base_decision['adaptive_strategy'] = adaptive_strategy
            
            if adaptive_strategy['approach'] == 'stealth':
                base_decision['parameters'] = base_decision.get('parameters', {})
                base_decision['parameters']['stealth_mode'] = True
                base_decision['parameters'].update(adaptive_strategy.get('parameters', {}))
        
        # Predict vulnerability likelihood
        if context and 'technologies' in context:
            vuln_likelihood = self.learning_engine.predict_vulnerability_likelihood(
                context,
                tool
            )
            base_decision['vulnerability_likelihood'] = vuln_likelihood
        
        return base_decision
    
    def generate_recommendations_with_memory(self, all_results: List[Dict]) -> Dict[str, Any]:
        """Generate recommendations using historical knowledge"""
        # Get base recommendations
        base_recommendations = self.generate_recommendations(all_results)
        
        if not self.enable_memory:
            return base_recommendations
        
        # Recognize success patterns
        success_patterns = self.pattern_recognizer.recognize_success_patterns(all_results)
        
        # Enhance recommendations
        enhanced_recommendations = {
            **base_recommendations,
            'success_patterns': success_patterns,
            'lessons_learned': [],
            'future_recommendations': []
        }
        
        # Analyze failures and generate lessons
        failures = [r for r in all_results if not r.get('result', {}).get('success', True)]
        for failure in failures:
            analysis = self.learning_engine.analyze_failure(
                context=failure.get('decision', {}).get('context', {}),
                technique=failure.get('tool', ''),
                tool=failure.get('tool', ''),
                parameters=failure.get('decision', {}).get('parameters', {}),
                error=failure.get('result', {}).get('stderr', 'Unknown error')
            )
            enhanced_recommendations['lessons_learned'].append(analysis)
        
        # Generate future recommendations
        target_context = {
            'technologies': [],
            'services': []
        }
        
        # Extract context from results
        for result in all_results:
            parsed = result.get('result', {}).get('parsed', {})
            if 'services' in parsed:
                target_context['services'].extend(parsed['services'])
        
        # Get techniques that haven't been tried yet
        used_techniques = set(r.get('tool') for r in all_results)
        all_techniques = self.knowledge_base.get_techniques_for_context(target_context)
        
        unused_promising = [
            t for t in all_techniques
            if t.get('id') not in used_techniques and t.get('success_rate', 0) > 0.6
        ]
        
        enhanced_recommendations['future_recommendations'] = unused_promising[:3]
        
        return enhanced_recommendations
    
    def store_engagement(self, engagement_id: str, engagement_data: Dict[str, Any]):
        """Store engagement in memory"""
        if not self.enable_memory:
            return
        
        # Store in vector database for semantic search
        self.vector_db.add_engagement(engagement_id, engagement_data)
        
        # Store in persistent memory for structured queries
        self.persistent_memory.store_engagement(engagement_data)
        
        # Persist to disk
        self.vector_db.persist()
        
        logger.info(f"Stored engagement {engagement_id} in memory")
    
    def build_target_profile(self, target_id: str, all_results: List[Dict]) -> Dict[str, Any]:
        """Build and store target profile"""
        if not self.enable_memory:
            return {}
        
        # Extract information from results
        technologies = set()
        vulnerabilities = []
        defensive_mechanisms = []
        
        for result in all_results:
            parsed = result.get('result', {}).get('parsed', {})
            
            # Extract technologies
            if 'services' in parsed:
                technologies.update(parsed['services'])
            
            # Extract vulnerabilities
            if parsed.get('vulnerable'):
                vulnerabilities.append({
                    'type': result.get('tool'),
                    'details': parsed
                })
        
        # Recognize defensive patterns
        defensive_patterns = self.pattern_recognizer.recognize_defensive_patterns(all_results)
        if defensive_patterns.get('firewall'):
            defensive_mechanisms.append('firewall')
        if defensive_patterns.get('waf'):
            defensive_mechanisms.append('waf')
        if defensive_patterns.get('ids_ips'):
            defensive_mechanisms.append('ids/ips')
        
        profile = {
            'id': target_id,
            'technologies': list(technologies),
            'common_vulnerabilities': vulnerabilities,
            'defensive_mechanisms': defensive_mechanisms,
            'security_posture': self._assess_security_posture(vulnerabilities, defensive_mechanisms)
        }
        
        # Store profile
        self.persistent_memory.store_target_profile(profile)
        
        logger.info(f"Built and stored target profile for {target_id}")
        
        return profile
    
    def _assess_security_posture(self, vulnerabilities: List, defensive_mechanisms: List) -> str:
        """Assess overall security posture"""
        vuln_score = len(vulnerabilities)
        defense_score = len(defensive_mechanisms)
        
        if vuln_score > 5 and defense_score < 2:
            return 'weak'
        elif vuln_score < 2 and defense_score > 3:
            return 'strong'
        else:
            return 'moderate'
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory system statistics"""
        if not self.enable_memory:
            return {'enabled': False}
        
        return {
            'enabled': True,
            'vector_db': self.vector_db.get_engagement_stats(),
            'persistent_memory': self.persistent_memory.get_stats(),
            'knowledge_base': self.knowledge_base.get_stats(),
            'learning_trained': self.learning_engine.is_trained
        }
    
    def close(self):
        """Clean up resources"""
        if self.enable_memory:
            self.vector_db.persist()
            self.persistent_memory.close()
        
        logger.info("Enhanced LLM Orchestrator closed")
