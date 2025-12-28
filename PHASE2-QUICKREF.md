# SEC-AI Phase 2 - Quick Reference

## 🚀 Quick Start

```bash
# Install Phase 2
pip install -r requirements-phase2.txt

# Run with memory enabled (default)
python main.py --cli --target example.com
```

## 📚 Key Imports

```python
# Memory Systems
from memory import VectorDatabase, PersistentMemory

# Knowledge Base
from knowledge import KnowledgeBase

# Learning Systems
from learning import SelfImprovementEngine, PatternRecognizer

# Enhanced Orchestrator
from core.enhanced_orchestrator import EnhancedLLMOrchestrator
```

## 🧠 Memory Operations

### Vector Database
```python
from memory import VectorDatabase

vdb = VectorDatabase()

# Search similar engagements
similar = vdb.search_similar_engagements(
    target="example.com",
    technologies=["nginx", "php"],
    n_results=5
)

# Search vulnerabilities
vulns = vdb.search_vulnerabilities("nginx", n_results=10)

# Get stats
stats = vdb.get_engagement_stats()
```

### Persistent Memory
```python
from memory import PersistentMemory

pm = PersistentMemory()

# Get technique success rate
success_rate = pm.get_technique_success_rate("sql_injection", "sqlmap")

# Get similar engagements
similar = pm.get_similar_engagements(
    technologies=["apache", "mysql"],
    limit=5
)

# Get target profile
profile = pm.get_target_profile("example.com")

# Get stats
stats = pm.get_stats()
```

## 📖 Knowledge Base Operations

```python
from knowledge import KnowledgeBase

kb = KnowledgeBase()

# Search CVEs
cves = kb.search_cve("apache 2.4", limit=10)

# Get exploit for CVE
exploit = kb.get_exploit_for_cve("CVE-2017-0144")

# Get techniques for context
context = {
    'services': ['http', 'ssh'],
    'os': 'linux',
    'technologies': ['apache']
}
techniques = kb.get_techniques_for_context(context)

# Generate wordlist
wordlist = kb.get_wordlist_suggestions(context)

# Get evasion techniques
evasion = kb.get_evasion_techniques(['ids', 'waf'])
```

## 🎓 Learning Operations

### Self-Improvement Engine
```python
from learning import SelfImprovementEngine
from memory import PersistentMemory
from knowledge import KnowledgeBase

engine = SelfImprovementEngine(
    PersistentMemory(),
    KnowledgeBase()
)

# Analyze failure
analysis = engine.analyze_failure(
    context={'target': 'example.com'},
    technique='sql_injection',
    tool='sqlmap',
    parameters={'--level': 1},
    error='not injectable'
)

# Predict vulnerability
likelihood = engine.predict_vulnerability_likelihood(
    target_context={'technologies': ['wordpress']},
    vulnerability_type='sql_injection'
)

# Cost-benefit analysis
cba = engine.cost_benefit_analysis(
    technique='password_brute_force',
    tool='hydra',
    context=context
)

# Adaptive strategy
strategy = engine.adaptive_strategy(
    current_results=scan_results,
    target_context=context
)

# Build custom wordlist
wordlist = engine.build_custom_wordlist(
    target_context=context,
    scan_results=results
)

# Train from history
engine.train_from_history()
```

### Pattern Recognition
```python
from learning import PatternRecognizer

pr = PatternRecognizer()

# Recognize vulnerability patterns
vuln_patterns = pr.recognize_vulnerability_patterns(scan_results)

# Recognize defensive patterns
defensive = pr.recognize_defensive_patterns(scan_results)

# Recognize success patterns
success = pr.recognize_success_patterns(historical_data)

# Detect anomalies
anomalies = pr.detect_anomalies(current_data, baseline)

# Calculate similarity
similarity = pr.similarity_score(target1, target2)
```

## 🎯 Enhanced Orchestrator

```python
from core.enhanced_orchestrator import EnhancedLLMOrchestrator
from core.llm_orchestrator import OpenAIProvider

# Initialize
provider = OpenAIProvider(api_key, model)
orch = EnhancedLLMOrchestrator(provider, enable_memory=True)

# Analyze target with memory
analysis = orch.analyze_target_with_memory("example.com")

# Decide next action with learning
decision = orch.decide_next_action_with_learning(
    scan_results=latest_results,
    context=engagement_context
)

# Generate recommendations with memory
recommendations = orch.generate_recommendations_with_memory(
    all_results=all_scan_results
)

# Store engagement
orch.store_engagement(engagement_id, engagement_data)

# Build target profile
profile = orch.build_target_profile(target_id, all_results)

# Get memory stats
stats = orch.get_memory_stats()

# Close (cleanup)
orch.close()
```

## ⚙️ Configuration

### Enable/Disable Features
```yaml
# config/config.yaml

memory:
  enabled: true  # Toggle memory system

learning:
  enabled: true  # Toggle learning
  auto_train: true  # Auto-train on startup
  min_samples_for_training: 10

pattern_recognition:
  enabled: true  # Toggle pattern recognition
  
self_improvement:
  enabled: true  # Toggle self-improvement
  analyze_failures: true
  optimize_parameters: true
```

## 📊 Common Patterns

### Pattern 1: Check Memory Before Pentest
```python
# Get context from memory
similar_targets = vdb.search_similar_engagements(
    target="example.com",
    technologies=detected_technologies
)

# Learn from similar targets
if similar_targets:
    for target in similar_targets:
        print(f"Past engagement: {target['metadata']}")
        print(f"Success techniques: {target['metadata']['successful_techniques']}")
```

### Pattern 2: Adaptive Technique Selection
```python
# Get recommended techniques
techniques = kb.get_techniques_for_context(context)

# Filter by success rate
proven_techniques = [
    t for t in techniques
    if pm.get_technique_success_rate(t['id']) > 0.7
]

# Use most successful
best_technique = max(proven_techniques, key=lambda t: t['success_rate'])
```

### Pattern 3: Failure Recovery
```python
# If technique fails
if not result['success']:
    # Analyze failure
    analysis = engine.analyze_failure(
        context, technique, tool, params, error
    )
    
    # Apply suggested adjustments
    for adjustment in analysis['suggested_adjustments']:
        if adjustment['parameter'] == 'timeout':
            params['timeout'] = adjustment['new_value']
        elif adjustment['parameter'] == 'stealth':
            params['timing'] = 'T1'  # Slowest
    
    # Retry with optimized parameters
    result = retry_with_params(params)
```

### Pattern 4: Building Wordlist
```python
# Get suggestions from multiple sources
kb_suggestions = kb.get_wordlist_suggestions(context)
custom_suggestions = engine.build_custom_wordlist(context, scan_results)

# Combine and deduplicate
wordlist = list(set(kb_suggestions + custom_suggestions))

# Save for hydra
with open('custom_wordlist.txt', 'w') as f:
    f.write('\n'.join(wordlist))
```

### Pattern 5: Evasion Strategy
```python
# Detect defenses
defensive = pr.recognize_defensive_patterns(scan_results)

# Get evasion techniques
if defensive['waf']:
    evasion = kb.get_evasion_techniques(['waf'])
    for ev in evasion:
        if 'sqlmap_flags' in ev:
            sqlmap_params.extend(ev['sqlmap_flags'])
```

## 🔧 Maintenance Commands

```bash
# View memory stats
python -c "
from memory import PersistentMemory
pm = PersistentMemory()
print(pm.get_stats())
"

# Clear all memory
rm -rf data/vectordb data/memory.db data/knowledge

# Backup memory
tar -czf memory-backup.tar.gz data/

# Restore memory
tar -xzf memory-backup.tar.gz

# Force retrain
python -c "
from memory import PersistentMemory
from knowledge import KnowledgeBase
from learning import SelfImprovementEngine
engine = SelfImprovementEngine(PersistentMemory(), KnowledgeBase())
engine.train_from_history()
"
```

## 📈 Monitoring

### Check Learning Progress
```python
from memory import PersistentMemory

pm = PersistentMemory()
stats = pm.get_stats()

print(f"Engagements: {stats['total_engagements']}")
print(f"Techniques tried: {stats['total_techniques']}")
print(f"Learning events: {stats['learning_events']}")

# Get success rate trend
technique = "sql_injection"
rate = pm.get_technique_success_rate(technique)
print(f"{technique} success rate: {rate:.1%}")
```

### View Learning Events
```python
from memory import PersistentMemory

pm = PersistentMemory()
events = pm.get_learning_events(event_type='exploit_failure', limit=10)

for event in events:
    print(f"{event['timestamp']}: {event['analysis']}")
```

## 🐛 Debugging

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check database connections
from memory import VectorDatabase, PersistentMemory

try:
    vdb = VectorDatabase()
    print("✅ Vector DB OK")
except Exception as e:
    print(f"❌ Vector DB Error: {e}")

try:
    pm = PersistentMemory()
    print("✅ Persistent Memory OK")
except Exception as e:
    print(f"❌ Persistent Memory Error: {e}")

# Check knowledge base
from knowledge import KnowledgeBase

try:
    kb = KnowledgeBase()
    print("✅ Knowledge Base OK")
    print(f"Stats: {kb.get_stats()}")
except Exception as e:
    print(f"❌ Knowledge Base Error: {e}")
```

## 💡 Pro Tips

1. **Let it learn**: Run 10+ engagements before expecting optimal decisions
2. **Check similar targets**: Always review similar past engagements first
3. **Trust cost-benefit**: If ROI < 1.0, seriously consider skipping
4. **Review failures**: Learning events show why things failed
5. **Build profiles**: Target profiles improve over multiple engagements
6. **Custom wordlists**: Always generate before password attacks
7. **Monitor defenses**: Pattern recognition spots IDS/WAF early
8. **Backup memory**: Your learned knowledge is valuable
9. **Train regularly**: Run `train_from_history()` monthly
10. **Optimize storage**: Clean old engagements after 6 months

## 🎯 Performance Tuning

```yaml
# config/config.yaml

# For faster but less accurate
memory:
  enabled: true
learning:
  min_samples_for_training: 5  # Lower threshold

# For better learning
learning:
  min_samples_for_training: 20  # More data
  success_rate_threshold: 0.8  # Higher bar

# For resource-constrained systems
memory:
  enabled: false  # Disable memory
  
# For stealth focus
self_improvement:
  analyze_failures: true
  adaptive_strategy: true  # Always adapt
```

---

**Quick Reference Complete!** 🎉

For detailed documentation, see:
- [USAGE-PHASE2.md](USAGE-PHASE2.md) - Complete usage guide
- [PHASE2-SUMMARY.md](PHASE2-SUMMARY.md) - Technical overview
- [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md) - Upgrade instructions
