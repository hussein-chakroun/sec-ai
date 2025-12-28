# SEC-AI Phase 1 - Technical Architecture

## Overview

SEC-AI is an autonomous penetration testing platform that leverages Large Language Models (LLMs) to make intelligent decisions during security assessments. Phase 1 implements the foundation layer with basic autonomous capabilities.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        GUI Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Main Window │  │  Config Tab  │  │  Tools Tab   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                   Core Engine Layer                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           PentestEngine (Orchestrator)               │   │
│  │  - Manages workflow                                  │   │
│  │  - Coordinates tools                                 │   │
│  │  - Maintains context                                 │   │
│  └────────────┬────────────────────────┬────────────────┘   │
│               │                        │                     │
│  ┌────────────┴────────────┐  ┌───────┴──────────────┐     │
│  │   LLM Orchestrator      │  │  Report Generator    │     │
│  │  - Decision making      │  │  - JSON reports      │     │
│  │  - Strategy planning    │  │  - HTML reports      │     │
│  │  - Analysis             │  │  - Text reports      │     │
│  └─────────────────────────┘  └──────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                    LLM Provider Layer                        │
│  ┌──────────────────┐           ┌──────────────────┐        │
│  │  OpenAI Provider │           │ Anthropic Provider│        │
│  │  - GPT-4 Turbo   │           │  - Claude 3 Opus │        │
│  │  - Tool calling  │           │  - Tool calling  │        │
│  └──────────────────┘           └──────────────────┘        │
└─────────────────────────────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                   Tool Execution Layer                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Nmap   │  │  SQLMap  │  │  Hydra   │  │Metasploit│   │
│  │ Scanner  │  │ Scanner  │  │ Cracker  │  │Framework │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│       │             │             │             │           │
│  ┌────┴─────────────┴─────────────┴─────────────┴────┐     │
│  │            BaseTool (Abstract)                     │     │
│  │  - Command execution                              │     │
│  │  - Output parsing                                 │     │
│  │  - Error handling                                 │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. GUI Layer

**Location**: `gui/main_window.py`

**Responsibilities**:
- User interface for Linux desktop
- Target configuration
- Progress monitoring
- Report viewing

**Technologies**:
- PyQt5 for native Linux UI
- Multi-threaded execution (QThread)
- Real-time output streaming

**Key Features**:
- Tabbed interface (Pentest, Config, Tools)
- Background worker threads
- Progress indication
- Report export

### 2. Core Engine Layer

#### PentestEngine
**Location**: `core/pentest_engine.py`

**Responsibilities**:
- Main orchestration logic
- Workflow management
- Context maintenance
- Tool coordination

**Key Methods**:
- `run_pentest()`: Main autonomous loop
- `check_tools()`: Verify tool availability
- `_execute_tool()`: Tool execution router

**Workflow**:
1. Target analysis
2. Initial reconnaissance
3. Iterative autonomous scanning
4. Report generation

#### LLM Orchestrator
**Location**: `core/llm_orchestrator.py`

**Responsibilities**:
- AI decision making
- Strategy planning
- Result analysis
- Recommendation generation

**Key Methods**:
- `analyze_target()`: Initial target analysis
- `decide_next_action()`: Determine next step
- `generate_recommendations()`: Final report

**Provider Support**:
- OpenAI (GPT-4 Turbo)
- Anthropic (Claude 3 Opus)
- Extensible for other providers

### 3. Tool Execution Layer

#### BaseTool
**Location**: `modules/base_tool.py`

**Features**:
- Abstract base class for all tools
- Standardized execution interface
- Output parsing framework
- Error handling
- Timeout management

#### Nmap Scanner
**Location**: `modules/nmap_scanner.py`

**Capabilities**:
- Quick scan
- Service version detection
- Full port scan
- Vulnerability scanning (NSE)
- OS detection

**Output Parsing**:
- Open ports extraction
- Service identification
- Version detection
- OS fingerprinting

#### SQLMap Scanner
**Location**: `modules/sqlmap_scanner.py`

**Capabilities**:
- SQL injection testing
- Database enumeration
- Table dumping
- Custom payload injection

**Output Parsing**:
- Vulnerability detection
- Injection type identification
- Database structure

#### Hydra Cracker
**Location**: `modules/hydra_cracker.py`

**Capabilities**:
- SSH brute force
- FTP cracking
- HTTP form attacks
- Multi-protocol support

**Output Parsing**:
- Credential extraction
- Success rate analysis

#### Metasploit Framework
**Location**: `modules/metasploit_framework.py`

**Capabilities**:
- Exploit search
- Exploit execution
- Auxiliary modules
- Vulnerability checking

**Output Parsing**:
- Session detection
- Exploit success tracking
- Module usage logging

### 4. Report Generation

**Location**: `reports/report_generator.py`

**Formats**:
1. **JSON**: Structured data for automation
2. **HTML**: Rich formatted reports
3. **TXT**: Plain text for simple parsing

**Features**:
- Templated HTML generation (Jinja2)
- Severity color coding
- Scan timeline
- Recommendations section

## Data Flow

### 1. Initialization
```
User → GUI → Config → LLM Provider → PentestEngine
```

### 2. Pentest Execution
```
GUI Input → PentestEngine → LLM Orchestrator → Decision
                 ↓                                  ↓
           Tool Modules ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
                 ↓
           Parse Output → Store Results → Context Update
                                    ↓
                              LLM Analysis → Next Decision
```

### 3. Report Generation
```
Results → Report Generator → [JSON, HTML, TXT] → User
```

## Configuration Management

**Location**: `core/config.py`

**Sources**:
1. `.env` file (API keys, secrets)
2. `config/config.yaml` (application settings)
3. Environment variables

**Key Configurations**:
- LLM provider and model
- Tool paths and timeouts
- Scan behavior
- Report formats
- Logging levels

## Security Considerations

### 1. Safe Execution
- Subprocess isolation
- Timeout enforcement
- Resource limits
- Safe mode by default

### 2. Credential Management
- Environment variables for secrets
- No hardcoded credentials
- API key masking in logs

### 3. Authorization
- Explicit user confirmation
- Legal disclaimer
- Scope boundaries
- Action logging

### 4. Error Handling
- Graceful degradation
- Detailed logging
- User feedback
- Recovery mechanisms

## Extensibility

### Adding New Tools

1. Create new module in `modules/`
2. Inherit from `BaseTool`
3. Implement required methods:
   - `get_default_command()`
   - `parse_output()`
4. Add tool-specific methods
5. Register in `PentestEngine._execute_tool()`

Example:
```python
class NewTool(BaseTool):
    def get_default_command(self) -> str:
        return "newtool"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        # Custom parsing logic
        return {"findings": []}
```

### Adding New LLM Providers

1. Inherit from `BaseLLMProvider`
2. Implement:
   - `generate()`
   - `generate_with_tools()`
3. Add provider selection in config

### Custom Report Formats

1. Add format method in `ReportGenerator`
2. Implement template/formatting
3. Add to `generate_report()` formats

## Performance Optimization

### 1. Async Execution
- Tool execution in threads
- Non-blocking UI
- Parallel scanning capability

### 2. Caching
- LLM conversation history
- Tool output caching
- Context preservation

### 3. Resource Management
- Configurable timeouts
- Max concurrent scans
- Memory-efficient parsing

## Logging and Debugging

**Location**: `logs/sec-ai.log`

**Levels**:
- INFO: General operation
- WARNING: Non-critical issues
- ERROR: Failures and exceptions
- DEBUG: Detailed execution (dev mode)

**Features**:
- Rotation (10 MB)
- Retention (10 days)
- Structured logging with loguru

## Testing Strategy

### Unit Tests
- Tool parsers
- LLM orchestrator
- Report generation

### Integration Tests
- End-to-end pentest workflow
- Tool execution
- Report generation

### Mock Testing
- LLM responses
- Tool outputs
- Network interactions

## Known Limitations (Phase 1)

1. **Sequential Execution**: Tools run one at a time
2. **Basic Parsing**: Simple regex-based parsing
3. **Limited Exploit DB**: No custom exploit development
4. **Single Target**: One target at a time
5. **No Stealth**: No evasion techniques

## Future Enhancements (Phase 2+)

1. Advanced exploitation engine
2. Custom payload generation
3. Multi-target support
4. Stealth and evasion
5. Machine learning for pattern recognition
6. Collaborative multi-agent system
7. Integration with vulnerability databases
8. Real-time collaboration features

## Dependencies

### Core
- Python 3.9+
- openai >= 1.0.0
- anthropic >= 0.18.0
- python-dotenv

### GUI
- PyQt5 >= 5.15.0

### Tools
- nmap (system package)
- sqlmap (system package)
- hydra (system package)
- metasploit-framework (system package)

### Utilities
- jinja2 (templates)
- loguru (logging)
- pyyaml (config)
- rich (formatting)

## Deployment

### Development
```bash
./install.sh
source venv/bin/activate
python main.py
```

### Production
- Use virtual environment
- Configure secrets via .env
- Run with appropriate privileges
- Monitor logs
- Regular updates

## Conclusion

Phase 1 provides a solid foundation for autonomous penetration testing with:
- ✅ LLM-driven decision making
- ✅ Multiple tool integration
- ✅ Intelligent workflow management
- ✅ Comprehensive reporting
- ✅ User-friendly GUI
- ✅ Extensible architecture

The modular design allows for easy enhancement and scaling to more advanced capabilities in future phases.
