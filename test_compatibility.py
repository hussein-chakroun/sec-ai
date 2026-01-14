#!/usr/bin/env python3
"""
Test Python and library compatibility for SEC-AI.
This script verifies that all critical libraries can be imported.
"""

import sys
import importlib
import platform


def test_python_version():
    """Check Python version."""
    version = sys.version_info
    print(f"\n{'='*60}")
    print(f"Python Version: {version.major}.{version.minor}.{version.micro}")
    print(f"{'='*60}")
    
    if version.major == 3 and version.minor >= 11:
        print("✓ Python version compatible (3.11+)")
        if version.minor >= 12:
            print("✓ Using Python 3.12+ (RECOMMENDED)")
        return True
    else:
        print("✗ Python 3.11+ required")
        return False


def test_platform():
    """Check platform."""
    system = platform.system()
    machine = platform.machine()
    print(f"\n{'='*60}")
    print(f"Platform: {system} ({machine})")
    print(f"{'='*60}")
    
    if system in ["Linux", "Windows", "Darwin"]:
        print(f"✓ Platform supported: {system}")
        return True
    else:
        print(f"⚠ Platform may have limited support: {system}")
        return True


def test_critical_imports():
    """Test critical library imports."""
    print(f"\n{'='*60}")
    print("Testing Critical Libraries")
    print(f"{'='*60}")
    
    # Grouped by category
    libraries = {
        "AI/LLM": ["openai", "anthropic"],
        "Data Science": ["numpy", "pandas", "sklearn"],
        "ML/Embeddings": ["sentence_transformers"],
        "Network": ["requests", "aiohttp", "scapy"],
        "Security": ["cryptography", "pycryptodome"],
        "Database": ["sqlalchemy", "redis"],
        "GUI": ["PyQt5"],
        "Binary Analysis": ["capstone", "pefile", "pyelftools"],
        "Utilities": ["colorama", "rich", "tqdm"],
    }
    
    failed = []
    total = 0
    
    for category, libs in libraries.items():
        print(f"\n{category}:")
        for lib in libs:
            total += 1
            # Handle special import names
            import_name = lib
            if lib == "sklearn":
                import_name = "sklearn"
            elif lib == "pycryptodome":
                import_name = "Crypto"
            elif lib == "sentence_transformers":
                import_name = "sentence_transformers"
                
            try:
                importlib.import_module(import_name)
                print(f"  ✓ {lib}")
            except ImportError as e:
                print(f"  ✗ {lib}: {e}")
                failed.append(lib)
    
    print(f"\n{'='*60}")
    print(f"Results: {total - len(failed)}/{total} libraries loaded successfully")
    print(f"{'='*60}")
    
    if failed:
        print(f"\nFailed imports ({len(failed)}):")
        for lib in failed:
            print(f"  - {lib}")
        print("\nTo install missing libraries:")
        print("  pip install -r requirements.txt")
    
    return len(failed) == 0


def test_optional_imports():
    """Test optional security tool imports."""
    print(f"\n{'='*60}")
    print("Testing Optional Security Tools")
    print(f"{'='*60}")
    
    optional_libs = [
        ("angr", "Binary symbolic execution"),
        ("frida", "Dynamic instrumentation"),
        ("pwntools", "Exploit development"),
        ("impacket", "Network protocol tools"),
        ("volatility3", "Memory forensics"),
    ]
    
    available = []
    
    for lib, description in optional_libs:
        try:
            importlib.import_module(lib)
            print(f"  ✓ {lib:<20} - {description}")
            available.append(lib)
        except ImportError:
            print(f"  ○ {lib:<20} - {description} (not installed)")
    
    print(f"\n{len(available)}/{len(optional_libs)} optional tools available")
    return True


def main():
    """Run all compatibility tests."""
    print("\n" + "="*60)
    print("SEC-AI COMPATIBILITY TEST")
    print("="*60)
    
    results = []
    results.append(("Python Version", test_python_version()))
    results.append(("Platform", test_platform()))
    results.append(("Critical Libraries", test_critical_imports()))
    results.append(("Optional Tools", test_optional_imports()))
    
    print(f"\n{'='*60}")
    print("FINAL RESULTS")
    print(f"{'='*60}")
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{name:<25} {status}")
    
    print(f"{'='*60}")
    
    if all(r[1] for r in results[:3]):  # Check critical tests only
        print("\n✓ ALL CRITICAL CHECKS PASSED!")
        print("Your environment is ready for SEC-AI.")
        return 0
    else:
        print("\n✗ SOME CRITICAL CHECKS FAILED")
        print("Please install missing dependencies:")
        print("  pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
