#!/usr/bin/env python3
"""
Quick test to verify GUI loads correctly with all 12 phases
"""

def test_gui_import():
    """Test that GUI can be imported"""
    try:
        from gui.main_window import MainWindow
        print("✅ GUI module imported successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to import GUI: {e}")
        return False


def test_phase_count():
    """Test that all 12 phases are defined"""
    try:
        from gui.main_window import MainWindow
        
        # Create instance without showing
        import sys
        from PyQt5.QtWidgets import QApplication
        
        app = QApplication(sys.argv)
        window = MainWindow()
        
        # Check phase count
        phase_count = len(window.enabled_phases)
        expected_count = 12
        
        if phase_count == expected_count:
            print(f"✅ All {expected_count} phases configured")
            print(f"   Phases: {', '.join(window.enabled_phases.keys())}")
            return True
        else:
            print(f"❌ Expected {expected_count} phases, found {phase_count}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to check phases: {e}")
        return False


def test_tab_creation_methods():
    """Test that all tab creation methods exist"""
    try:
        from gui.main_window import MainWindow
        
        required_methods = [
            'create_pentest_tab',
            'create_phase_selection_tab',
            'create_config_tab',
            'create_discovery_tab',
            'create_exfiltration_tab',
            'create_impact_tab',
            'create_compliance_tab',
            'create_adversary_simulation_tab',
            'create_physical_social_tab',
            'create_iot_embedded_tab',
            'create_ai_adaptive_tab',
            'create_tools_tab',
        ]
        
        missing_methods = []
        for method_name in required_methods:
            if not hasattr(MainWindow, method_name):
                missing_methods.append(method_name)
        
        if not missing_methods:
            print(f"✅ All {len(required_methods)} tab creation methods exist")
            return True
        else:
            print(f"❌ Missing methods: {', '.join(missing_methods)}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to check methods: {e}")
        return False


def test_action_methods():
    """Test that phase action methods exist"""
    try:
        from gui.main_window import MainWindow
        
        required_methods = [
            'start_adversary_simulation',
            'start_social_engineering',
            'start_iot_assessment',
            'start_ai_exploitation',
        ]
        
        missing_methods = []
        for method_name in required_methods:
            if not hasattr(MainWindow, method_name):
                missing_methods.append(method_name)
        
        if not missing_methods:
            print(f"✅ All {len(required_methods)} action methods exist")
            return True
        else:
            print(f"❌ Missing methods: {', '.join(missing_methods)}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to check action methods: {e}")
        return False


def main():
    """Run all GUI tests"""
    print("="*60)
    print("SEC-AI GUI Test Suite - Phase 1-12 Verification")
    print("="*60)
    
    tests = [
        ("GUI Import", test_gui_import),
        ("Phase Count", test_phase_count),
        ("Tab Creation Methods", test_tab_creation_methods),
        ("Action Methods", test_action_methods),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
    
    print("="*60)
    print(f"Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ All GUI tests passed! The UI is ready for all 12 phases.")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed. Please review errors above.")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
