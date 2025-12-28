# SEC-AI Phase 2 - Usage Guide

## Phase 2: Intelligent Context & Memory

This guide covers the new capabilities added in Phase 2.

## 🆕 What's New in Phase 2

### 1. Vector Database Integration
- Semantic search across all pentesting knowledge
- Find similar past engagements automatically
- Store CVEs, exploits, and techniques with embeddings

### 2. Persistent Memory
- Remember every engagement permanently
- Track technique success rates over time
- Build organizational security profiles
- Learn from failures and successes

### 3. Self-Improvement Loop
- Automatically analyze why exploits failed
- Optimize tool parameters based on experience
- Generate custom wordlists from target data
- Adapt timing and evasion techniques

### 4. Enhanced Decision Making
- Probabilistic vulnerability prediction
- Cost-benefit analysis for each action
- Adaptive strategy based on target responses
- Defensive mechanism detection and evasion

## Installation

### Additional Dependencies

```bash
# Install Phase 2 requirements
pip install -r requirements-phase2.txt
```

This adds:
- `chromadb` - Vector database
- `sentence-transformers` - Text embeddings
- `scikit-learn` - Machine learning
- `fuzzywuzzy` - Fuzzy string matching
- Additional ML and analysis libraries

### Configuration

Edit `config/config.yaml`:

```yaml
memory:
  enabled: true  # Enable memory system
  vector_db_path: "./data/vectordb"
  persistent_db_path: "./data/memory.db"

learning:
  enabled: true  # Enable self-improvement
  auto_train: true
  min_samples_for_training: 10
```

## Using Memory Features

### Automatic Learning

Memory is automatically enabled. The system will:

1. **Store Every Engagement**
   - All scan results
   - Successful techniques
   - Failed attempts
   - Target characteristics

2. **Learn from Experience**
   - Update technique success rates
   - Build target profiles
   - Recognize patterns
   - Optimize parameters

3. **Apply Knowledge**
   - Search similar past targets
   - Predict vulnerability likelihood
   - Recommend proven techniques
   - Avoid past mistakes

### Manual Memory Queries

You can query the memory system programmatically:

```python
from memory import VectorDatabase, PersistentMemory

# Initialize
vector_db = VectorDatabase()
persistent_memory = PersistentMemory()

# Search similar engagements
similar = vector_db.search_similar_engagements(
    target="example.com",
    technologies=["nginx", "php", "mysql"],
    n_results=5
)

# Get technique success rate
success_rate = persistent_memory.get_technique_success_rate("sql_injection", "sqlmap")

# Search CVEs
from knowledge import KnowledgeBase
kb = KnowledgeBase()
cves = kb.search_cve("nginx 1.14", limit=10)
```

## Knowledge Base Features

### CVE Integration

The system automatically searches for CVEs when it detects services:

```python
# Automatic in pentest workflow
# When nmap detects "Apache 2.4.29", system:
# 1. Searches NVD for Apache 2.4.29 CVEs
# 2. Stores CVEs in knowledge base
# 3. Maps CVEs to exploits
# 4. Recommends exploitation approach
```

### Technique Recommendations

Get relevant techniques based on context:

```python
from knowledge import KnowledgeBase

kb = KnowledgeBase()

context = {
    'services': ['http', 'ssh', 'mysql'],
    'os': 'linux',
    'technologies': ['apache', 'php']
}

techniques = kb.get_techniques_for_context(context)
# Returns: sql_injection, password_brute_force, etc.
```

### Custom Wordlists

Automatically build target-specific wordlists:

```python
from learning import SelfImprovementEngine

engine = SelfImprovementEngine(memory, knowledge_base)

context = {
    'target': 'acmecorp.com',
    'organization': 'ACME Corp',
    'technologies': ['wordpress']
}

wordlist = engine.build_custom_wordlist(context, scan_results)
# Returns: ['acme', 'acmecorp', 'admin', 'wp-admin', ...]
```

## Self-Improvement Features

### Failure Analysis

When an exploit fails, the system analyzes why:

```python
# Automatic in pentest workflow
# System detects failure and:
# 1. Classifies failure type (timeout, authentication, detection)
# 2. Suggests parameter adjustments
# 3. Stores learning event
# 4. Updates future recommendations
```

Example failure analysis output:

```json
{
  "failure_type": "detection",
  "suggested_adjustments": [
    {
      "parameter": "stealth",
      "adjustment": "increase",
      "new_value": "use_evasion_techniques",
      "reasoning": "Detected by security mechanisms"
    },
    {
      "parameter": "timing",
      "adjustment": "slower",
      "new_value": "T1",
      "reasoning": "Use slower scan timing"
    }
  ]
}
```

### Parameter Optimization

Learn optimal parameters from experience:

```python
# System tracks:
# - Which parameters led to success
# - Which led to detection
# - Which were most efficient

# Next attempt uses optimized parameters
optimized = engine.optimize_parameters(
    technique="sql_injection",
    tool="sqlmap",
    historical_results=past_attempts
)
```

### Adaptive Strategy

System adapts approach based on target responses:

```python
# Automatic adaptation:
# - Detects firewall -> Increases stealth
# - Low success rate -> Pivots to different techniques
# - High success rate -> Escalates to exploitation
# - Detects IDS/IPS -> Uses evasion techniques

strategy = engine.adaptive_strategy(
    current_results=scan_history,
    target_context=context
)
```

## Pattern Recognition

### Vulnerability Patterns

Recognize common vulnerability patterns:

```python
from learning import PatternRecognizer

recognizer = PatternRecognizer()

patterns = recognizer.recognize_vulnerability_patterns(scan_results)

# Example patterns found:
# - Port 445 open (SMB - high risk)
# - Outdated Apache 2.4.7 (known CVEs)
# - MySQL 5.5 (end of life)
```

### Defensive Patterns

Detect defensive mechanisms:

```python
defensive = recognizer.recognize_defensive_patterns(scan_results)

# Returns:
{
  'firewall': True,
  'waf': True,
  'ids_ips': False,
  'rate_limiting': True,
  'patterns': ['filtered_ports', 'waf_detection']
}
```

### Success Patterns

Learn what works:

```python
success_patterns = recognizer.recognize_success_patterns(historical_data)

# Returns techniques with high success rates and their common features:
{
  'technique': 'service_enumeration',
  'success_rate': 0.92,
  'common_features': {
    'common_technologies': ['apache', 'nginx'],
    'common_ports': [80, 443, 8080]
  }
}
```

## Probabilistic Decision Making

### Vulnerability Likelihood Prediction

Predict if a vulnerability exists:

```python
from learning import SelfImprovementEngine

likelihood = engine.predict_vulnerability_likelihood(
    target_context={'technologies': ['wordpress', 'php7.2']},
    vulnerability_type='sql_injection'
)

# Returns 0.0 to 1.0 probability based on:
# - Similar past targets
# - Known CVEs
# - Technology versions
# - Historical success rates
```

### Cost-Benefit Analysis

Evaluate if a technique is worth trying:

```python
analysis = engine.cost_benefit_analysis(
    technique='password_brute_force',
    tool='hydra',
    context=current_context
)

# Returns:
{
  'cost': 0.65,  # Time + stealth + detection risk
  'benefit': 0.42,  # Success probability + impact
  'roi': 0.64,  # Benefit/cost ratio
  'recommendation': 'skip'  # execute or skip
}
```

## GUI Enhancements (Phase 2)

The GUI automatically shows Phase 2 features:

### Memory Tab
- View stored engagements
- Browse knowledge base
- See success rates
- Review learning events

### Analytics Tab
- Pattern visualizations
- Success rate trends
- Vulnerability predictions
- Cost-benefit charts

### Learning Tab
- Failure analyses
- Parameter optimizations
- Custom wordlists
- Adaptive strategies

## Advanced Usage Examples

### Example 1: Using Memory for Similar Targets

```python
from core.enhanced_orchestrator import EnhancedLLMOrchestrator
from core.llm_orchestrator import OpenAIProvider

# Initialize
provider = OpenAIProvider(api_key, model)
orchestrator = EnhancedLLMOrchestrator(provider, enable_memory=True)

# Analyze with memory
analysis = orchestrator.analyze_target_with_memory("example.com")

# Shows:
# - Similar past engagements
# - Recommended techniques based on history
# - Potential CVEs
# - Success probability estimates
```

### Example 2: Learning from Failures

```python
# After a failed SQL injection attempt
analysis = engine.analyze_failure(
    context={'target': 'example.com', 'technologies': ['mysql']},
    technique='sql_injection',
    tool='sqlmap',
    parameters={'--level': 1, '--risk': 1},
    error='[CRITICAL] all tested parameters appear to be not injectable'
)

# System suggests:
# - Try higher --level and --risk
# - Use different injection techniques
# - Check for WAF
# - Try manual injection
```

### Example 3: Building Target Profile

```python
# After full engagement
profile = orchestrator.build_target_profile(
    target_id='example.com',
    all_results=scan_results
)

# Stores:
# - Technologies detected
# - Common vulnerabilities
# - Defensive mechanisms
# - Security posture assessment
# - For future reference
```

## Performance & Storage

### Storage Requirements

Phase 2 adds data storage:

- **Vector Database**: ~100MB per 1000 engagements
- **Persistent Memory**: ~50MB per 1000 engagements
- **Knowledge Base**: ~10MB (cached CVEs/exploits)

### Performance Impact

- First run: ~2-5 seconds to initialize databases
- Subsequent runs: ~0.5 seconds to load
- Memory search: ~0.1 seconds per query
- CVE lookup: ~1-2 seconds (with API rate limiting)

## Maintenance

### Clearing Memory

```bash
# Clear all stored data
rm -rf data/vectordb data/memory.db data/knowledge

# Will rebuild on next run
```

### Backing Up Data

```bash
# Backup memory databases
tar -czf sec-ai-memory-backup-$(date +%Y%m%d).tar.gz data/

# Restore
tar -xzf sec-ai-memory-backup-20251228.tar.gz
```

### Training Updates

```bash
# Force retrain from all historical data
python -c "
from memory import PersistentMemory
from knowledge import KnowledgeBase
from learning import SelfImprovementEngine

memory = PersistentMemory()
kb = KnowledgeBase()
engine = SelfImprovementEngine(memory, kb)
engine.train_from_history()
"
```

## Troubleshooting

### "ChromaDB not initialized"
```bash
pip install -r requirements-phase2.txt
```

### "Not enough data to train"
- Run at least 10 engagements
- System will work without training, just without learning benefits

### "CVE API rate limited"
- NVD API has rate limits
- System uses cached CVEs when available
- Wait 6 seconds between requests (automatic)

### Memory database locked
```bash
# Close all SEC-AI instances
pkill -f "python.*sec-ai"

# Remove lock file
rm data/memory.db-journal
```

## Best Practices

1. **Let it Learn**: Run multiple engagements to build memory
2. **Review Patterns**: Check learned patterns for accuracy
3. **Verify Recommendations**: Don't blindly trust predictions
4. **Backup Regularly**: Memory is valuable, back it up
5. **Monitor Storage**: Clean old data periodically

## Next Steps

With Phase 2 complete, you have:
- ✅ Intelligent memory and learning
- ✅ Probabilistic decision making
- ✅ Self-improvement capabilities
- ✅ Knowledge base integration

Ready for Phase 3: Advanced Exploitation!
