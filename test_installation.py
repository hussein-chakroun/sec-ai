"""
Quick test script to verify installation
"""
import sys
from pathlib import Path

def test_imports():
    """Test if all modules can be imported"""
    print("Testing imports...")
    
    try:
        from core.llm_orchestrator import LLMOrchestrator, OpenAIProvider, AnthropicProvider
        print("✅ Core modules")
    except ImportError as e:
        print(f"❌ Core modules: {e}")
        return False
    
    try:
        from modules import NmapScanner, SQLMapScanner, HydraCracker, MetasploitFramework
        print("✅ Tool modules")
    except ImportError as e:
        print(f"❌ Tool modules: {e}")
        return False
    
    try:
        from reports import ReportGenerator
        print("✅ Report modules")
    except ImportError as e:
        print(f"❌ Report modules: {e}")
        return False
    
    try:
        from gui import MainWindow
        print("✅ GUI modules")
    except ImportError as e:
        print(f"❌ GUI modules: {e}")
        return False
    
    return True


def test_dependencies():
    """Test if dependencies are installed"""
    print("\nTesting dependencies...")
    
    required = [
        'openai',
        'anthropic',
        'PyQt5',
        'jinja2',
        'loguru',
        'yaml',
        'dotenv'
    ]
    
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing.append(package)
    
    return len(missing) == 0


def test_tools():
    """Test if pentesting tools are available"""
    print("\nTesting pentesting tools...")
    
    import subprocess
    
    tools = {
        'nmap': '--version',
        'sqlmap': '--version',
        'hydra': '-h',
        'msfconsole': '--version'
    }
    
    available = []
    
    for tool, flag in tools.items():
        try:
            result = subprocess.run(
                [tool, flag],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0 or tool == 'hydra':  # hydra returns non-zero for -h
                print(f"✅ {tool}")
                available.append(tool)
            else:
                print(f"❌ {tool} (not working properly)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"❌ {tool} (not found)")
    
    return len(available) > 0


def test_config():
    """Test configuration"""
    print("\nTesting configuration...")
    
    env_file = Path('.env')
    config_file = Path('config/config.yaml')
    
    if env_file.exists():
        print("✅ .env file exists")
    else:
        print("⚠️  .env file not found (use .env.example)")
    
    if config_file.exists():
        print("✅ config.yaml exists")
    else:
        print("❌ config.yaml not found")
        return False
    
    return True


def main():
    """Run all tests"""
    print("="*60)
    print("SEC-AI Installation Test")
    print("="*60)
    print()
    
    tests = [
        ("Imports", test_imports),
        ("Dependencies", test_dependencies),
        ("Tools", test_tools),
        ("Configuration", test_config)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} test failed with error: {e}")
            results.append((name, False))
        print()
    
    # Summary
    print("="*60)
    print("Test Summary")
    print("="*60)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name}: {status}")
    
    all_passed = all(r for _, r in results)
    
    print()
    if all_passed:
        print("✅ All tests passed! Ready to use.")
    else:
        print("⚠️  Some tests failed. Check the output above.")
        print("\nNext steps:")
        print("1. Install missing dependencies: pip install -r requirements.txt")
        print("2. Install pentesting tools: sudo apt install nmap sqlmap hydra metasploit-framework")
        print("3. Create .env file from .env.example")
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
