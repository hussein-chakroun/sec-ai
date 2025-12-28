# Contributing to SEC-AI

Thank you for your interest in contributing to SEC-AI! This document provides guidelines for contributing to the project.

## 🎯 Areas for Contribution

### 1. Tool Integrations
- Add new pentesting tools (Burp Suite, Nikto, etc.)
- Enhance existing tool wrappers
- Improve output parsers

### 2. LLM Enhancements
- Add new LLM providers (Llama, Mistral, etc.)
- Improve prompting strategies
- Optimize token usage

### 3. GUI Improvements
- Enhanced visualizations
- Real-time graphs
- Better UX/UI

### 4. Core Features
- Parallel scanning
- Stealth techniques
- Advanced decision logic
- Custom exploit modules

### 5. Documentation
- Usage examples
- Video tutorials
- API documentation
- Architecture diagrams

## 🚀 Getting Started

### Development Setup

1. Fork the repository
2. Clone your fork:
```bash
git clone https://github.com/YOUR_USERNAME/sec-ai.git
cd sec-ai
```

3. Create a development branch:
```bash
git checkout -b feature/your-feature-name
```

4. Install in development mode:
```bash
./install.sh
source venv/bin/activate
pip install -e .
```

### Development Environment

- Python 3.9+
- Linux (Ubuntu/Debian recommended)
- VS Code or PyCharm (recommended)
- Git

## 📝 Coding Standards

### Python Style
- Follow PEP 8
- Use type hints
- Write docstrings for all functions/classes
- Maximum line length: 100 characters

Example:
```python
def analyze_target(self, target: str) -> Dict[str, Any]:
    """
    Analyze target and determine scanning strategy.
    
    Args:
        target: IP address, domain, or URL to analyze
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        ValueError: If target format is invalid
    """
    pass
```

### Code Organization
- Keep modules focused and single-purpose
- Use inheritance appropriately (BaseTool pattern)
- Separate concerns (business logic vs UI)
- Write testable code

### Logging
- Use loguru for logging
- Appropriate log levels:
  - DEBUG: Development info
  - INFO: Normal operations
  - WARNING: Unexpected but handled
  - ERROR: Failures

Example:
```python
from loguru import logger

logger.info(f"Starting scan on {target}")
logger.warning(f"Tool returned non-zero exit code: {code}")
logger.error(f"Failed to execute: {error}")
```

## 🧪 Testing

### Running Tests
```bash
# Installation test
python test_installation.py

# Unit tests (when available)
pytest tests/

# Integration tests
pytest tests/integration/
```

### Writing Tests
- Test all new features
- Include edge cases
- Mock external dependencies
- Use pytest framework

Example:
```python
def test_nmap_parser():
    """Test nmap output parsing"""
    scanner = NmapScanner()
    output = """
    Nmap scan report for example.com (93.184.216.34)
    22/tcp open ssh OpenSSH 7.4
    """
    
    result = scanner.parse_output(output)
    assert len(result['open_ports']) == 1
    assert result['open_ports'][0]['port'] == 22
```

## 📦 Adding New Features

### Adding a New Tool

1. Create module in `modules/`:
```python
from .base_tool import BaseTool

class NewTool(BaseTool):
    def get_default_command(self) -> str:
        return "newtool"
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        # Implement parsing
        return {"findings": []}
```

2. Add to `modules/__init__.py`
3. Register in `PentestEngine._execute_tool()`
4. Update documentation

### Adding a New LLM Provider

1. Create provider class:
```python
from core.llm_orchestrator import BaseLLMProvider

class NewProvider(BaseLLMProvider):
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        # Implement generation
        pass
    
    def generate_with_tools(self, prompt: str, tools: List[Dict], 
                           system_prompt: str = None) -> Dict:
        # Implement tool calling
        pass
```

2. Add to orchestrator imports
3. Update configuration options
4. Document usage

## 🔍 Pull Request Process

### Before Submitting

1. Test your changes thoroughly
2. Update documentation
3. Add docstrings
4. Check code style
5. Update CHANGELOG (if exists)

### PR Guidelines

1. **Title**: Clear, descriptive title
   - ✅ "Add Nikto scanner integration"
   - ❌ "Update stuff"

2. **Description**: Include:
   - What changed
   - Why it changed
   - How to test
   - Related issues

3. **Commits**: 
   - Atomic commits
   - Clear commit messages
   - Reference issues when applicable

Example:
```
Add Nikto web scanner integration

- Created NiktoScanner class in modules/
- Implemented output parsing
- Added tests
- Updated documentation

Closes #123
```

### Review Process

1. Automated checks must pass
2. Code review by maintainers
3. Address feedback
4. Merge when approved

## 🐛 Bug Reports

### How to Report

1. Check existing issues
2. Use issue template
3. Include:
   - OS and Python version
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs/screenshots
   - Minimal reproduction example

Example:
```markdown
**Environment**
- OS: Ubuntu 22.04
- Python: 3.10.5
- SEC-AI: Phase 1

**Bug Description**
Nmap scan fails with timeout error

**Steps to Reproduce**
1. Launch GUI
2. Enter target: 192.168.1.1
3. Click Start Pentest
4. Error appears after 30 seconds

**Expected Behavior**
Scan should complete successfully

**Actual Behavior**
TimeoutError: Execution timed out after 30 seconds

**Logs**
[Attach relevant logs]
```

## 💡 Feature Requests

### How to Request

1. Check existing requests
2. Describe the feature clearly
3. Explain use case
4. Propose implementation (optional)

## 📄 Documentation

### Where to Document

- Code: Docstrings
- Usage: USAGE.md
- Architecture: ARCHITECTURE.md
- API: In-code comments
- Examples: README.md

### Documentation Style

- Clear and concise
- Include examples
- Use proper formatting
- Keep updated

## 🔒 Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@yourproject.com
2. Provide detailed description
3. Include reproduction steps
4. Suggest fix if possible

### Security Guidelines

- Never commit API keys
- Sanitize user input
- Validate all data
- Use secure defaults
- Follow principle of least privilege

## 🎓 Learning Resources

### Penetration Testing
- OWASP Testing Guide
- Metasploit Unleashed
- Nmap Documentation

### Python Development
- Python Documentation
- Real Python
- PyPI Package Index

### AI/LLM
- OpenAI API Documentation
- Anthropic Claude Documentation
- Prompt Engineering Guide

## 📞 Communication

### Channels
- GitHub Issues: Bug reports, feature requests
- GitHub Discussions: Questions, ideas
- Pull Requests: Code contributions

### Code of Conduct
- Be respectful
- Be constructive
- Help others
- Follow guidelines

## 🏆 Recognition

Contributors will be:
- Added to CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

## ❓ Questions?

- Check documentation first
- Search existing issues
- Ask in discussions
- Contact maintainers

## 📋 Checklist for Contributors

- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests added/passing
- [ ] Commits are clean
- [ ] PR description is clear
- [ ] No sensitive data committed
- [ ] Legal/license compliance

Thank you for contributing to SEC-AI! 🚀
