# Quick Start Guide - Main Orchestrator

Get started with the Main Orchestrator in 5 minutes!

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/sec-ai.git
cd sec-ai

# Install dependencies
pip install -r requirements.txt

# Set up API key
export OPENAI_API_KEY="your-api-key-here"
# OR
export ANTHROPIC_API_KEY="your-api-key-here"
```

## 1. Simplest Usage - Command Line

Run a complete autonomous pentest:

```bash
python main.py --orchestrator --target 192.168.1.100 --enable-all
```

That's it! The orchestrator will:
- ✅ Run all 5 phases automatically
- ✅ Use LLM for intelligent decision making
- ✅ Enable memory and learning
- ✅ Deploy agent swarm for parallel execution
- ✅ Generate comprehensive reports

## 2. Quick Python Script

Create a file `my_pentest.py`:

```python
import asyncio
from core import run_autonomous_pentest

async def main():
    results = await run_autonomous_pentest(
        target="192.168.1.100",
        llm_provider="openai",
        enable_all_features=True
    )
    
    print(f"✅ Pentest complete!")
    print(f"Compromised hosts: {results['overall_stats']['hosts_compromised']}")

asyncio.run(main())
```

Run it:
```bash
python my_pentest.py
```

## 3. Specific Phases Only

Want to run just reconnaissance and scanning?

```bash
python main.py --orchestrator --target example.com
```

Then edit the configuration:

```python
from core import MainOrchestrator, OrchestratorConfig

config = OrchestratorConfig(
    llm_provider="openai",
    enabled_phases=[1, 2],  # Only recon and scanning
    stop_at_phase=2
)

orchestrator = MainOrchestrator(config)
results = await orchestrator.run_complete_pentest("example.com")
```

## 4. Monitor Progress

```python
from core import MainOrchestrator, OrchestratorConfig
import asyncio

async def pentest_with_monitoring():
    config = OrchestratorConfig(
        llm_provider="openai",
        enabled_phases=[1, 2, 3]
    )
    
    orchestrator = MainOrchestrator(config)
    
    # Start pentest
    task = asyncio.create_task(
        orchestrator.run_complete_pentest("192.168.1.100")
    )
    
    # Monitor progress
    while not task.done():
        status = orchestrator.get_status()
        print(f"Phase {status['current_phase']}/5 - "
              f"{status['progress_percentage']:.1f}% - "
              f"Hosts compromised: {status['stats']['hosts_compromised']}")
        await asyncio.sleep(5)
    
    results = await task
    print("✅ Complete!")

asyncio.run(pentest_with_monitoring())
```

## 5. Custom Configuration

```python
from core import MainOrchestrator, OrchestratorConfig

config = OrchestratorConfig(
    # Which LLM to use
    llm_provider="openai",
    llm_model="gpt-4-turbo-preview",
    
    # Which phases to run
    enabled_phases=[1, 2, 3, 4, 5],
    
    # Features
    enable_memory=True,      # Remember previous engagements
    enable_learning=True,    # Learn from results
    enable_agents=True,      # Use agent swarm
    
    # Output
    output_dir="./my_reports",
    save_intermediate=True
)

orchestrator = MainOrchestrator(config)
results = await orchestrator.run_complete_pentest("target.com")
```

## Common Use Cases

### Use Case 1: Quick Network Scan

Just want to find vulnerabilities?

```bash
# Phases 1-2 only (recon + scanning)
python main.py --orchestrator --target 192.168.1.0/24
```

### Use Case 2: Full Pentest

Complete penetration test with exploitation:

```bash
# All 5 phases
python main.py --phase12345 --target 192.168.1.100
```

### Use Case 3: Learning Mode

Test and improve over time:

```python
config = OrchestratorConfig(
    llm_provider="openai",
    enable_memory=True,
    enable_learning=True,
    enable_self_improvement=True
)

# First test - learns patterns
results1 = await orchestrator.run_complete_pentest("target1.com")

# Second test - uses learned knowledge
results2 = await orchestrator.run_complete_pentest("target2.com")
```

### Use Case 4: Multi-Target Campaign

Test multiple targets:

```python
targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

orchestrator = MainOrchestrator(config)

for target in targets:
    results = await orchestrator.run_complete_pentest(
        target=target,
        scope=targets  # For lateral movement
    )
```

## Output

The orchestrator generates:

1. **JSON Results** - `./reports/pentest_results_TIMESTAMP.json`
2. **Executive Summary** - LLM-generated summary
3. **Phase Reports** - Detailed results per phase
4. **Timeline** - Complete execution timeline

Example output structure:
```json
{
  "overall_stats": {
    "hosts_discovered": 45,
    "vulnerabilities_found": 127,
    "exploits_successful": 12,
    "hosts_compromised": 8,
    "credentials_harvested": 34
  },
  "executive_summary": "...",
  "phases": {
    "phase1": {...},
    "phase2": {...},
    "phase3": {...}
  }
}
```

## Command Line Options

```bash
# Basic usage
python main.py --orchestrator --target TARGET

# With all features
python main.py --orchestrator --target TARGET --enable-all

# Specific phases
python main.py --phase12345 --target TARGET

# With custom output
python main.py --orchestrator --target TARGET --formats json html txt
```

## Environment Variables

```bash
# Required: API key
export OPENAI_API_KEY="sk-..."
# OR
export ANTHROPIC_API_KEY="sk-ant-..."

# Optional: Configuration
export LLM_PROVIDER="openai"
export LLM_MODEL="gpt-4-turbo-preview"
```

## Troubleshooting

### "No API key found"
Set your API key:
```bash
export OPENAI_API_KEY="your-key-here"
```

### "Import error"
Install dependencies:
```bash
pip install -r requirements.txt
```

### "Phase failed"
Check tool installation:
```bash
python main.py --cli --target 192.168.1.100
# Will show which tools are missing
```

## Next Steps

1. ✅ **Read the docs**: [MAIN_ORCHESTRATOR.md](../docs/MAIN_ORCHESTRATOR.md)
2. ✅ **Try examples**: [orchestrator_example.py](../examples/orchestrator_example.py)
3. ✅ **Run tests**: `python tests/test_main_orchestrator.py`
4. ✅ **Customize**: Modify `OrchestratorConfig` for your needs

## Safety Tips

⚠️ **Important**:
- Only test authorized targets
- Use in controlled environments
- Review LLM decisions
- Follow ethical hacking guidelines
- Save logs for compliance

## Getting Help

- 📖 Documentation: `docs/MAIN_ORCHESTRATOR.md`
- 💡 Examples: `examples/orchestrator_example.py`
- 🐛 Issues: GitHub Issues
- 💬 Discussions: GitHub Discussions

## Quick Reference

```python
# Import
from core import MainOrchestrator, OrchestratorConfig, run_autonomous_pentest

# Quick start
results = await run_autonomous_pentest(target="IP", enable_all_features=True)

# Custom config
config = OrchestratorConfig(llm_provider="openai", enabled_phases=[1,2,3])
orchestrator = MainOrchestrator(config)
results = await orchestrator.run_complete_pentest("target")

# Monitor
status = orchestrator.get_status()

# Control
await orchestrator.pause()
await orchestrator.resume()
await orchestrator.stop()
```

Happy pentesting! 🎯
