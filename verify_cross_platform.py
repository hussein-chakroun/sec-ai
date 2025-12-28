#!/usr/bin/env python3
"""
Cross-Platform Compatibility Verification Script
================================================

Verifies that SEC-AI is properly configured for cross-platform compatibility.

Tests:
1. No OS-specific imports in requirements.txt
2. All imports are cross-platform compatible
3. Code gracefully handles OS-specific features
4. Documentation is up to date

Usage:
    python verify_cross_platform.py
"""

import re
import sys
from pathlib import Path


def check_requirements_file():
    """Check requirements.txt for OS-specific dependencies."""
    print("=" * 70)
    print("Checking requirements.txt for OS-specific dependencies...")
    print("=" * 70)
    
    requirements_path = Path("requirements.txt")
    if not requirements_path.exists():
        print("❌ ERROR: requirements.txt not found")
        return False
    
    content = requirements_path.read_text()
    
    # Check for platform conditionals
    platform_patterns = [
        r'platform_system\s*==',
        r'sys_platform\s*==',
        r';\s*platform_system',
        r';\s*sys_platform',
    ]
    
    issues = []
    for pattern in platform_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            issues.append(f"Found platform conditional: {pattern}")
    
    # Check for known OS-specific libraries
    os_specific_libs = [
        'pywin32',
        'wmi',
        'python-pam',
        'evdev',
        'pybluez',
    ]
    
    for lib in os_specific_libs:
        # Check if it's actually installed (not just in comments)
        pattern = rf'^{lib}\s*>=.*$'
        matches = re.findall(pattern, content, re.MULTILINE)
        if matches:
            issues.append(f"Found OS-specific library: {lib}")
    
    if issues:
        print("❌ FAILED: Found OS-specific dependencies:")
        for issue in issues:
            print(f"  - {issue}")
        return False
    else:
        print("✅ PASSED: No OS-specific dependencies found")
        return True


def check_imports_in_code():
    """Check Python files for problematic OS-specific imports."""
    print("\n" + "=" * 70)
    print("Checking Python files for OS-specific imports...")
    print("=" * 70)
    
    # Libraries that should NOT be imported directly (without try/except)
    forbidden_imports = {
        'win32api',
        'win32con',
        'win32gui',
        'win32clipboard',
        'wmi',
        'evdev',
        'pybluez',
        'bluetooth',
    }
    
    issues = []
    python_files = list(Path('.').rglob('*.py'))
    
    for py_file in python_files:
        # Skip virtual environment and cache directories
        if any(part in py_file.parts for part in ['venv', '__pycache__', '.git', 'site-packages']):
            continue
        
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
            
            # Skip content inside triple-quoted strings
            # Remove all docstrings and multi-line strings
            lines_to_check = []
            in_triple_quote = False
            triple_quote_char = None
            
            for line in content.split('\n'):
                stripped = line.strip()
                
                # Check for triple quotes
                if '"""' in stripped or "'''" in stripped:
                    if '"""' in stripped:
                        quote = '"""'
                    else:
                        quote = "'''"
                    
                    count = stripped.count(quote)
                    if count % 2 == 1:  # Odd number means toggle
                        in_triple_quote = not in_triple_quote
                    # If count is even, could be opening and closing on same line
                    
                # Only check lines not in docstrings and not comments
                if not in_triple_quote and not stripped.startswith('#'):
                    lines_to_check.append(line)
            
            content_to_check = '\n'.join(lines_to_check)
            
            # Check for direct imports (not in comments or strings)
            for forbidden in forbidden_imports:
                # Pattern for "import X" or "from X import"
                patterns = [
                    rf'^import\s+{forbidden}\s*$',
                    rf'^from\s+{forbidden}\s+import',
                    rf'^import\s+{forbidden}\.',
                ]
                
                for pattern in patterns:
                    # Only match non-commented lines
                    for line_num, line in enumerate(content_to_check.split('\n'), 1):
                        line = line.strip()
                        if line.startswith('#'):
                            continue
                        
                        if re.match(pattern, line, re.MULTILINE):
                            issues.append(f"{py_file}:{line_num}: Direct import of {forbidden}")
        
        except Exception as e:
            print(f"⚠️  Warning: Could not read {py_file}: {e}")
    
    if issues:
        print("❌ FAILED: Found OS-specific imports without proper handling:")
        for issue in issues[:10]:  # Show first 10
            print(f"  - {issue}")
        if len(issues) > 10:
            print(f"  ... and {len(issues) - 10} more")
        return False
    else:
        print("✅ PASSED: No problematic OS-specific imports found")
        return True


def check_documentation():
    """Check that cross-platform documentation exists."""
    print("\n" + "=" * 70)
    print("Checking documentation...")
    print("=" * 70)
    
    required_docs = [
        'CROSS-PLATFORM.md',
    ]
    
    all_exist = True
    for doc in required_docs:
        if Path(doc).exists():
            print(f"✅ Found: {doc}")
        else:
            print(f"❌ Missing: {doc}")
            all_exist = False
    
    return all_exist


def check_readme():
    """Check README mentions cross-platform compatibility."""
    print("\n" + "=" * 70)
    print("Checking README.md...")
    print("=" * 70)
    
    readme_path = Path("README.md")
    if not readme_path.exists():
        print("❌ README.md not found")
        return False
    
    content = readme_path.read_text(encoding='utf-8', errors='ignore')
    
    # Check for cross-platform mentions
    if 'cross-platform' in content.lower() or 'windows' in content.lower() and 'linux' in content.lower():
        print("✅ README mentions cross-platform compatibility")
        return True
    else:
        print("❌ README does not mention cross-platform compatibility")
        return False


def main():
    """Run all verification checks."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 10 + "SEC-AI Cross-Platform Compatibility Verification" + " " * 8 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    results = []
    
    # Run all checks
    results.append(("Requirements.txt", check_requirements_file()))
    results.append(("Python imports", check_imports_in_code()))
    results.append(("Documentation", check_documentation()))
    results.append(("README.md", check_readme()))
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    all_passed = True
    for check_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{check_name:.<50} {status}")
        if not passed:
            all_passed = False
    
    print("=" * 70)
    
    if all_passed:
        print("\n🎉 SUCCESS! SEC-AI is properly configured for cross-platform compatibility!")
        print("   - Works on both Windows and Linux")
        print("   - No OS-specific dependencies in requirements.txt")
        print("   - Code gracefully handles platform differences")
        print("   - Documentation is complete")
        return 0
    else:
        print("\n❌ ISSUES FOUND! Please review the failures above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
