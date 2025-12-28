# Phase 12: AI-Powered Adaptive Exploitation - Quick Reference

## Quick Start

```python
from core.phase12_engine import Phase12Engine

config = {'rl_config': {}, 'poisoning_config': {}, 'prompt_config': {}, 'cve_config': {}}
engine = Phase12Engine(config)
results = await engine.execute("target.com")
```

---

## Module 1: Reinforcement Learning

### Q-Learning Exploitation
```python
results = await engine.execute(target, {
    'enable_rl_exploitation': True,
    'ql_episodes': 1000,
    'learning_rate': 0.1,
    'discount_factor': 0.95
})
```

### Payload Evolution
```python
results = await engine.execute(target, {
    'enable_rl_exploitation': True,
    'population_size': 100,
    'generations': 50,
    'mutation_rate': 0.1
})
```

**Key Metrics:**
- `best_reward`: Highest reward achieved
- `convergence`: Whether RL has converged
- `q_table_size`: Number of state-action pairs learned

---

## Module 2: Adversarial ML

### Model Poisoning
```python
results = await engine.execute(target, {
    'enable_adversarial_ml': True,
    'poisoning_ratio': 0.1,
    'attack_type': 'label_flip'  # or 'feature_manipulation', 'clean_label'
})
```

### Evasion Attacks
```python
results = await engine.execute(target, {
    'enable_adversarial_ml': True,
    'perturbation_budget': 0.05,
    'evasion_method': 'fgsm'  # or 'pgd', 'carlini_wagner', 'deepfool'
})
```

### Model Inversion
```python
results = await engine.execute(target, {
    'enable_adversarial_ml': True,
    'inversion_queries': 10000,
    'optimization_steps': 1000
})
```

**Attack Methods:**
- `fgsm` - Fast, single-step
- `pgd` - Iterative, more powerful
- `carlini_wagner` - Optimized, stealthy
- `deepfool` - Minimal perturbation
- `boundary_attack` - Black-box
- `zoo` - Gradient-free

---

## Module 3: Natural Language Exploitation

### Prompt Injection
```python
results = await engine.execute(target, {
    'enable_nlp_exploitation': True,
    'injection_types': ['direct', 'indirect', 'context_overflow']
})
```

**Injection Types:**
- `direct` - Straightforward override
- `indirect` - Embedded in context
- `context_overflow` - Buffer-style attacks
- `multi_language` - Language-specific
- `role_manipulation` - Persona attacks
- `delimiter_injection` - Parser exploitation

### LLM Jailbreaking
```python
results = await engine.execute(target, {
    'enable_nlp_exploitation': True,
    'jailbreak_techniques': ['dan', 'role_play', 'token_smuggling'],
    'jailbreak_iterations': 100
})
```

**Techniques:**
- `dan` - "Do Anything Now"
- `role_play` - Fictional scenarios
- `token_smuggling` - Encoding tricks
- `context_manipulation` - Exploiting context
- `instruction_hierarchy` - Override prompts
- `multi_step` - Sequential jailbreaks

### Training Data Extraction
```python
results = await engine.execute(target, {
    'enable_nlp_exploitation': True,
    'extraction_methods': ['membership_inference', 'verbatim_extraction'],
    'extraction_queries': 5000
})
```

---

## Module 4: Autonomous Research

### CVE Monitoring
```python
results = await engine.execute(target, {
    'enable_autonomous_research': True,
    'severity_threshold': 7.0,
    'cve_days_back': 30
})
```

### Exploit Collection
```python
results = await engine.execute(target, {
    'enable_autonomous_research': True,
    'exploit_repos': ['exploit-db', 'github', 'packetstorm'],
    'verify_exploits': True
})
```

### Social Media Intelligence
```python
results = await engine.execute(target, {
    'enable_autonomous_research': True,
    'platforms': ['twitter', 'mastodon'],
    'sentiment_analysis': True
})
```

### Dark Web Monitoring
```python
results = await engine.execute(target, {
    'enable_autonomous_research': True,
    'categories': ['exploits', 'credentials', 'databases'],
    'safety_level': 'passive'
})
```

---

## Common Options

### Full Assessment
```python
options = {
    'enable_rl_exploitation': True,
    'enable_adversarial_ml': True,
    'enable_nlp_exploitation': True,
    'enable_autonomous_research': True,
    
    # RL options
    'ql_episodes': 1000,
    'population_size': 100,
    'generations': 50,
    
    # Adversarial ML options
    'poisoning_ratio': 0.1,
    'perturbation_budget': 0.05,
    'evasion_method': 'pgd',
    
    # NLP options
    'injection_types': ['direct', 'indirect'],
    'jailbreak_techniques': ['dan', 'role_play'],
    'jailbreak_iterations': 100,
    
    # Research options
    'severity_threshold': 7.0,
    'cve_days_back': 30
}

results = await engine.execute("target.com", options)
```

---

## Result Structure

```python
{
    'target': 'target.com',
    'timestamp': '2024-...',
    'phase': 'Phase 12 - AI-Powered Adaptive Exploitation',
    
    'modules': {
        'rl_exploitation': {
            'q_learning': [...],
            'neural_strategies': [...],
            'evolved_payloads': [...],
            'adaptive_strategies': [...]
        },
        'adversarial_ml': {
            'model_poisoning': [...],
            'evasion_attacks': [...],
            'model_inversion': [...],
            'backdoor_insertion': [...]
        },
        'nlp_exploitation': {
            'prompt_injection': [...],
            'llm_jailbreaking': [...],
            'social_engineering_bots': [...],
            'data_extraction': [...]
        },
        'autonomous_research': {
            'cve_monitoring': [...],
            'security_blogs': [...],
            'exploit_pocs': [...],
            'social_intel': [...],
            'darkweb_intel': [...]
        }
    },
    
    'summary': {
        'total_techniques': 0,
        'successful_exploits': 0,
        'ml_vulnerabilities': 0,
        'nlp_vulnerabilities': 0,
        'research_findings': 0,
        'risk_level': 'medium'
    },
    
    'recommendations': [...]
}
```

---

## Testing

```bash
# Run Phase 12 tests
python test_phase12.py

# Run specific module tests
python -c "
import asyncio
from core.phase12_engine import Phase12Engine

async def test():
    engine = Phase12Engine({})
    results = await engine.execute('test.com', {
        'enable_rl_exploitation': True
    })
    print(results['summary'])

asyncio.run(test())
"
```

---

## Performance Tips

### Reinforcement Learning
- Start with 100-500 episodes for testing
- Use 1000+ episodes for production
- Monitor convergence to avoid over-training

### Adversarial ML
- Lower perturbation budgets are stealthier
- PGD is more effective than FGSM but slower
- C&W produces minimal perturbations

### Natural Language
- Try simple injections first
- Combine multiple techniques for better results
- Monitor for rate limiting

### Autonomous Research
- Filter by severity ≥7.0 for critical issues
- Verify exploits before use
- Update threat intelligence regularly

---

## Error Handling

```python
try:
    results = await engine.execute(target, options)
except Exception as e:
    logger.error(f"Phase 12 error: {e}")
    # Check specific module errors
    if 'modules' in results:
        for module, data in results['modules'].items():
            if 'error' in data:
                logger.error(f"{module} error: {data['error']}")
```

---

## Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ql_episodes` | 1000 | Q-learning training episodes |
| `learning_rate` | 0.1 | RL learning rate |
| `discount_factor` | 0.95 | Future reward discount |
| `population_size` | 100 | GA population size |
| `generations` | 50 | GA generations |
| `mutation_rate` | 0.1 | GA mutation rate |
| `poisoning_ratio` | 0.1 | Data poisoning percentage |
| `perturbation_budget` | 0.05 | Max adversarial perturbation |
| `inversion_queries` | 10000 | Model inversion queries |
| `jailbreak_iterations` | 100 | Jailbreak attempts |
| `severity_threshold` | 7.0 | Minimum CVE severity |
| `cve_days_back` | 30 | CVE lookback period |

---

## Quick Commands

```bash
# Full Phase 12 scan
python -m core.phase12_engine

# Test Phase 12
python test_phase12.py

# View results
cat reports/phase12/phase12_results_*.json | jq .summary
```

---

## Cheat Sheet

### RL Exploitation
```python
# Q-learning
await engine._reinforcement_learning_exploitation(target, {
    'ql_episodes': 1000
})

# Payload evolution
from reinforcement_learning.payload_evolver import PayloadEvolver
evolver = PayloadEvolver({})
await evolver.evolve_payloads(target, payload_type='xss')
```

### Adversarial ML
```python
# Poisoning
from adversarial_ml.model_poisoner import ModelPoisoner
poisoner = ModelPoisoner({})
await poisoner.poison_models(target, poisoning_ratio=0.1)

# Evasion
from adversarial_ml.evasion_engine import EvasionEngine
evader = EvasionEngine({})
await evader.evade_ml_security(target, attack_method='fgsm')
```

### NLP Exploitation
```python
# Prompt injection
from natural_language_exploitation.prompt_injector import PromptInjector
injector = PromptInjector({})
await injector.inject_prompts(target, injection_types=['direct'])

# Jailbreaking
from natural_language_exploitation.llm_jailbreaker import LLMJailbreaker
jailbreaker = LLMJailbreaker({})
await jailbreaker.jailbreak_llm(target, techniques=['dan'])
```

### Autonomous Research
```python
# CVE monitoring
from autonomous_research.cve_monitor import CVEMonitor
monitor = CVEMonitor({})
await monitor.monitor_cves(target, severity_threshold=7.0)

# Intelligence gathering
from autonomous_research.intelligence_gatherer import IntelligenceGatherer
intel = IntelligenceGatherer({})
await intel.collect_exploits(target, repositories=['exploit-db'])
```

---

## Notes

- Always obtain authorization before testing
- RL/ML operations can be resource-intensive
- Monitor rate limits for API calls
- Some techniques require significant compute time
- Results saved to `reports/phase12/`

---

*See PHASE12-GUIDE.md for detailed documentation*
