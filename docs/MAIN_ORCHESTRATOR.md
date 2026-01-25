# Main Orchestrator - Complete Autonomous Penetration Testing

The Main Orchestrator is the central coordination system for EsecAi, managing all 5 phases of penetration testing with advanced AI-driven decision making.

## Overview

The Main Orchestrator coordinates:
- **Phase 1**: Reconnaissance & OSINT
- **Phase 2**: Vulnerability Scanning
- **Phase 3**: Exploitation
- **Phase 4**: Post-Exploitation & Privilege Escalation
- **Phase 5**: Lateral Movement & Domain Dominance

## Key Features

### 🤖 AI-Driven Decision Making
- LLM-powered strategic planning
- Adaptive attack strategies based on target analysis
- Real-time decision making during exploitation
- Post-engagement analysis and reporting

### 🧠 Memory & Learning Systems
- Vector database for storing engagement history
- Pattern recognition across engagements
- Self-improvement through learning
- Knowledge base integration

### 🐝 Agent Swarm Intelligence
- Distributed task execution
- Parallel scanning and exploitation
- Coordinated multi-target attacks
- Autonomous research capabilities

### 🔄 Complete Workflow Management
- Seamless phase-to-phase transitions
- Intelligent result correlation
- Automated progress tracking
- Comprehensive reporting

## Quick Start

### Basic Usage

```python
from core import run_autonomous_pentest

# Simple autonomous pentest
results = await run_autonomous_pentest(
    target="192.168.1.100",
    llm_provider="openai",
    enable_all_features=True
)
```

### Command Line

```bash
# Full autonomous pentest with all features
python main.py --orchestrator --target 192.168.1.100 --enable-all

# Standard workflow (phases 1-5)
python main.py --phase12345 --target 192.168.1.100

# Custom phase selection
python main.py --orchestrator --target example.com
```

## Configuration

### OrchestratorConfig

```python
from core import MainOrchestrator, OrchestratorConfig

config = OrchestratorConfig(
    # LLM Settings
    llm_provider="openai",           # openai or anthropic
    llm_model="gpt-4-turbo-preview",
    api_key=None,                    # Optional, uses env var
    
    # Execution Mode
    execution_mode="autonomous",     # autonomous, guided, manual
    max_iterations=100,
    
    # Phase Control
    enabled_phases=[1, 2, 3, 4, 5], # Phases to execute
    auto_progress=True,              # Auto progress between phases
    stop_at_phase=None,              # Stop at specific phase
    
    # Memory & Learning
    enable_memory=True,              # Vector database & memory
    enable_learning=True,            # Self-improvement
    enable_agents=True,              # Agent swarm
    enable_rl=False,                 # Reinforcement learning
    
    # Output & Reporting
    output_dir="./reports",
    save_intermediate=True,
    verbose=True,
    
    # Advanced Features
    enable_autonomous_research=True,
    enable_adaptive_strategy=True,
    enable_self_improvement=True
)

orchestrator = MainOrchestrator(config)
```

## Usage Examples

### Example 1: Quick Autonomous Pentest

```python
import asyncio
from core import run_autonomous_pentest

async def quick_pentest():
    results = await run_autonomous_pentest(
        target="192.168.1.100",
        llm_provider="openai",
        enable_all_features=True
    )
    
    print(f"Phases completed: {results['overall_stats']['phases_completed']}/5")
    print(f"Hosts compromised: {results['overall_stats']['hosts_compromised']}")

asyncio.run(quick_pentest())
```

### Example 2: Custom Configuration

```python
from core import MainOrchestrator, OrchestratorConfig

config = OrchestratorConfig(
    llm_provider="openai",
    enabled_phases=[1, 2, 3],  # Only reconnaissance, scanning, and exploitation
    stop_at_phase=3,
    enable_memory=True,
    enable_learning=True
)

orchestrator = MainOrchestrator(config)
results = await orchestrator.run_complete_pentest("example.com")
```

### Example 3: Progress Monitoring

```python
orchestrator = MainOrchestrator(config)

# Start pentest
task = asyncio.create_task(orchestrator.run_complete_pentest("target.com"))

# Monitor progress
while not task.done():
    status = orchestrator.get_status()
    print(f"Phase {status['current_phase']}/5 - {status['progress_percentage']:.1f}%")
    await asyncio.sleep(2)

results = await task
```

### Example 4: Multi-Target Testing

```python
targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

orchestrator = MainOrchestrator(config)

for target in targets:
    results = await orchestrator.run_complete_pentest(
        target=target,
        scope=targets  # Full scope for lateral movement
    )
```

### Example 5: Pause/Resume Control

```python
orchestrator = MainOrchestrator(config)

# Start pentest
task = asyncio.create_task(orchestrator.run_complete_pentest("target.com"))

# Pause after some time
await asyncio.sleep(30)
await orchestrator.pause()

# Resume later
await asyncio.sleep(10)
await orchestrator.resume()

results = await task
```

## Architecture

```
Main Orchestrator
├── LLM Orchestrator (Decision Making)
│   ├── OpenAI Provider
│   └── Anthropic Provider
│
├── Phase Integration Bridge
│   ├── Phase 1 Orchestrator (Reconnaissance)
│   ├── Phase 2 Orchestrator (Vulnerability Scanning)
│   ├── Phase 3 Orchestrator (Exploitation)
│   ├── Phase 4 Orchestrator (Post-Exploitation)
│   └── Phase 5 Orchestrator (Lateral Movement)
│
├── Memory Systems
│   ├── Vector Database
│   ├── Persistent Memory
│   └── Knowledge Base
│
├── Learning Systems
│   ├── Self-Improvement Engine
│   └── Pattern Recognizer
│
└── Agent Systems
    ├── Swarm Intelligence
    └── Intelligence Gatherer
```

## Results Structure

```python
{
    'metadata': {
        'orchestrator_version': '1.0.0',
        'start_time': '2026-01-25T10:00:00',
        'end_time': '2026-01-25T12:30:00',
        'total_duration': 9000.0,
        'config': {...}
    },
    'target': '192.168.1.100',
    'scope': ['192.168.1.0/24'],
    'pre_engagement_research': {...},
    'attack_strategy': {...},
    'phases': {
        'phase1': {
            'results': {...},
            'duration': 300.0,
            'completed_at': '2026-01-25T10:05:00',
            'llm_analysis': '...'
        },
        'phase2': {...},
        'phase3': {...},
        'phase4': {...},
        'phase5': {...}
    },
    'overall_stats': {
        'total_duration': 9000.0,
        'phases_completed': 5,
        'hosts_discovered': 45,
        'vulnerabilities_found': 127,
        'exploits_successful': 12,
        'hosts_compromised': 8,
        'credentials_harvested': 34
    },
    'executive_summary': '...',
    'timeline': [...]
}
```

## Status Monitoring

```python
status = orchestrator.get_status()

# Returns:
{
    'status': 'running',              # initializing, running, paused, completed, failed
    'current_phase': 3,
    'progress_percentage': 60.0,
    'elapsed_time': 1800.0,
    'stats': {
        'hosts_discovered': 45,
        'vulnerabilities_found': 127,
        'exploits_successful': 12,
        'hosts_compromised': 8,
        'credentials_harvested': 34
    }
}
```

## Advanced Features

### Autonomous Research
Pre-engagement intelligence gathering:
- OSINT collection
- Threat intelligence correlation
- Historical vulnerability research
- CVE monitoring

### Adaptive Strategy
LLM-driven strategy planning:
- Target-specific attack planning
- Risk-based prioritization
- Evasion technique selection
- Resource optimization

### Self-Improvement
Learning from engagements:
- Pattern recognition
- Technique effectiveness tracking
- Knowledge base updates
- Strategy refinement

### Memory Systems
Persistent knowledge:
- Previous engagement history
- Successful attack patterns
- Tool effectiveness metrics
- Target fingerprints

## Control Methods

### Pause/Resume

```python
await orchestrator.pause()   # Pause execution
await orchestrator.resume()  # Resume execution
await orchestrator.stop()    # Stop and return results
```

### Phase Control

```python
# Run specific phases only
config = OrchestratorConfig(
    enabled_phases=[1, 2],  # Only recon and scanning
    stop_at_phase=2         # Stop after phase 2
)
```

## Error Handling

```python
try:
    results = await orchestrator.run_complete_pentest(target)
except Exception as e:
    logger.error(f"Orchestration failed: {e}")
    
    # Get partial results
    partial_results = orchestrator._compile_final_results()
```

## Best Practices

1. **Start Small**: Begin with phases 1-2 for reconnaissance before full exploitation
2. **Enable Memory**: Use memory systems to improve over time
3. **Monitor Progress**: Track status during long engagements
4. **Configure Scope**: Define clear target scope to prevent scope creep
5. **Save Intermediate**: Always save intermediate results for recovery
6. **Use Agents**: Enable agent swarm for faster parallel execution
7. **Review Strategy**: Check LLM-generated strategy before auto-progression

## Performance Tips

- Use `max_concurrent_tasks` to control parallelism
- Disable memory/learning for faster one-off tests
- Set `stop_at_phase` to avoid unnecessary phases
- Use `execution_mode="guided"` for manual control points
- Enable `save_intermediate` for long engagements

## Security Considerations

⚠️ **WARNING**: This tool performs actual attacks and can compromise systems.

- Only use on authorized targets
- Configure appropriate `require_approval` actions
- Review LLM decisions in sensitive environments
- Use `safe_mode` in production environments
- Monitor and log all actions
- Follow ethical hacking guidelines

## Troubleshooting

### Common Issues

**LLM API errors**
```python
# Check API key configuration
config = OrchestratorConfig(
    api_key="your-api-key-here"  # Explicit API key
)
```

**Memory issues with large scans**
```python
# Disable memory for large scans
config = OrchestratorConfig(
    enable_memory=False,
    enable_learning=False
)
```

**Timeout issues**
```python
# Increase timeout settings
config = OrchestratorConfig(
    timeout_per_phase=3600  # 1 hour per phase
)
```

## Integration

### With Existing Systems

```python
# Use with existing LLM provider
from core.llm_orchestrator import OpenAIProvider

provider = OpenAIProvider(api_key, model)
orchestrator = MainOrchestrator(config)
orchestrator.llm_orchestrator.provider = provider
```

### With Custom Phases

```python
# Extend phase integration bridge
from core.phase_integration_bridge import PhaseIntegrationBridge

class CustomBridge(PhaseIntegrationBridge):
    async def run_custom_phase(self, results):
        # Custom phase implementation
        pass
```

## See Also

- [Phase Integration Bridge](./phase_integration_bridge.py)
- [LLM Orchestrator](./llm_orchestrator.py)
- [Usage Examples](../examples/orchestrator_example.py)
- [Phase 1-5 Documentation](../)

## License

MIT License - See LICENSE file for details
