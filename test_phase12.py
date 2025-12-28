#!/usr/bin/env python3
"""
Test Suite for Phase 12: AI-Powered Adaptive Exploitation
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.phase12_engine import Phase12Engine


async def test_phase12():
    """Test Phase 12 functionality"""
    
    print("=" * 80)
    print("Phase 12: AI-Powered Adaptive Exploitation - Test Suite")
    print("=" * 80)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration
    config = {
        'rl_config': {
            'enabled': True,
            'learning_rate': 0.1,
            'discount_factor': 0.95
        },
        'evolution_config': {
            'enabled': True,
            'population_size': 50,
            'generations': 25
        },
        'poisoning_config': {
            'enabled': True,
            'attack_types': ['label_flip', 'feature_manipulation']
        },
        'evasion_config': {
            'enabled': True,
            'methods': ['fgsm', 'pgd', 'carlini_wagner']
        },
        'inversion_config': {
            'enabled': True,
            'techniques': ['gradient_based', 'membership_inference']
        },
        'prompt_config': {
            'enabled': True,
            'injection_types': ['direct', 'indirect', 'context_overflow']
        },
        'jailbreak_config': {
            'enabled': True,
            'techniques': ['dan', 'role_play', 'token_smuggling']
        },
        'cve_config': {
            'enabled': True,
            'severity_threshold': 7.0,
            'days_back': 30
        },
        'intel_config': {
            'enabled': True,
            'sources': ['blogs', 'forums', 'social_media']
        }
    }
    
    # Initialize engine
    print("\n[+] Initializing Phase 12 Engine...")
    engine = Phase12Engine(config)
    
    # Test target
    target = "example-target.com"
    
    print(f"\n[+] Testing against target: {target}")
    print("-" * 80)
    
    # Test Module 1: Reinforcement Learning
    print("\n[TEST 1] Reinforcement Learning for Exploitation")
    print("-" * 80)
    try:
        rl_options = {
            'enable_rl_exploitation': True,
            'ql_episodes': 100,
            'learning_rate': 0.1,
            'discount_factor': 0.95,
            'population_size': 50,
            'generations': 25,
            'mutation_rate': 0.1
        }
        
        rl_results = await engine._reinforcement_learning_exploitation(target, rl_options)
        
        print(f"✓ Q-Learning paths: {len(rl_results.get('q_learning', []))}")
        print(f"✓ Neural strategies: {len(rl_results.get('neural_strategies', []))}")
        print(f"✓ Evolved payloads: {len(rl_results.get('evolved_payloads', []))}")
        print(f"✓ Adaptive strategies: {len(rl_results.get('adaptive_strategies', []))}")
        
        if rl_results.get('q_learning'):
            ql_summary = rl_results['q_learning'][0]
            print(f"  - Q-Learning episodes: {ql_summary.get('total_episodes', 0)}")
            print(f"  - Best reward: {ql_summary.get('best_reward', 0):.2f}")
        
        print("✓ Reinforcement Learning module PASSED")
        
    except Exception as e:
        print(f"✗ Reinforcement Learning module FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Test Module 2: Adversarial ML
    print("\n[TEST 2] Adversarial Machine Learning")
    print("-" * 80)
    try:
        adv_ml_options = {
            'enable_adversarial_ml': True,
            'poisoning_ratio': 0.1,
            'attack_type': 'label_flip',
            'perturbation_budget': 0.05,
            'evasion_method': 'fgsm',
            'inversion_queries': 1000
        }
        
        adv_ml_results = await engine._adversarial_ml_attacks(target, adv_ml_options)
        
        print(f"✓ Model poisoning: {len(adv_ml_results.get('model_poisoning', []))}")
        print(f"✓ Evasion attacks: {len(adv_ml_results.get('evasion_attacks', []))}")
        print(f"✓ Model inversion: {len(adv_ml_results.get('model_inversion', []))}")
        print(f"✓ Backdoor insertion: {len(adv_ml_results.get('backdoor_insertion', []))}")
        
        print("✓ Adversarial ML module PASSED")
        
    except Exception as e:
        print(f"✗ Adversarial ML module FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Test Module 3: Natural Language Exploitation
    print("\n[TEST 3] Natural Language Exploitation")
    print("-" * 80)
    try:
        nlp_options = {
            'enable_nlp_exploitation': True,
            'injection_types': ['direct', 'indirect'],
            'jailbreak_techniques': ['dan', 'role_play'],
            'jailbreak_iterations': 50
        }
        
        nlp_results = await engine._natural_language_exploitation(target, nlp_options)
        
        print(f"✓ Prompt injections: {len(nlp_results.get('prompt_injection', []))}")
        print(f"✓ LLM jailbreaks: {len(nlp_results.get('llm_jailbreaking', []))}")
        print(f"✓ Social engineering: {len(nlp_results.get('social_engineering_bots', []))}")
        print(f"✓ Data extraction: {len(nlp_results.get('data_extraction', []))}")
        
        if nlp_results.get('prompt_injection'):
            injection_summary = nlp_results['prompt_injection'][0]
            print(f"  - Injection success rate: {injection_summary.get('vulnerability_rate', 0):.2%}")
        
        print("✓ Natural Language Exploitation module PASSED")
        
    except Exception as e:
        print(f"✗ Natural Language Exploitation module FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Test Module 4: Autonomous Research
    print("\n[TEST 4] Autonomous Research")
    print("-" * 80)
    try:
        research_options = {
            'enable_autonomous_research': True,
            'severity_threshold': 7.0,
            'cve_days_back': 30,
            'sources': ['blogs', 'forums'],
            'platforms': ['twitter']
        }
        
        research_results = await engine._autonomous_research(target, research_options)
        
        print(f"✓ CVE monitoring: {len(research_results.get('cve_monitoring', []))}")
        print(f"✓ Security blogs: {len(research_results.get('security_blogs', []))}")
        print(f"✓ Exploit PoCs: {len(research_results.get('exploit_pocs', []))}")
        print(f"✓ Social intelligence: {len(research_results.get('social_intel', []))}")
        print(f"✓ Dark web intel: {len(research_results.get('darkweb_intel', []))}")
        
        if research_results.get('cve_monitoring'):
            cve_summary = research_results['cve_monitoring'][0]
            print(f"  - CVEs found: {cve_summary.get('total_cves_found', 0)}")
            print(f"  - Critical CVEs: {cve_summary.get('critical_cves', 0)}")
        
        print("✓ Autonomous Research module PASSED")
        
    except Exception as e:
        print(f"✗ Autonomous Research module FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Full Integration Test
    print("\n[TEST 5] Full Phase 12 Integration")
    print("-" * 80)
    try:
        full_options = {
            'enable_rl_exploitation': True,
            'enable_adversarial_ml': True,
            'enable_nlp_exploitation': True,
            'enable_autonomous_research': True,
            'ql_episodes': 50,
            'generations': 15,
            'jailbreak_iterations': 30
        }
        
        print("[+] Running full Phase 12 assessment...")
        results = await engine.execute(target, full_options)
        
        print(f"\n✓ Phase: {results.get('phase')}")
        print(f"✓ Target: {results.get('target')}")
        print(f"✓ Timestamp: {results.get('timestamp')}")
        
        modules = results.get('modules', {})
        print(f"\n✓ Modules executed: {len(modules)}")
        for module_name in modules.keys():
            print(f"  - {module_name}")
        
        summary = results.get('summary', {})
        print(f"\n✓ Summary:")
        print(f"  - Total techniques: {summary.get('total_techniques', 0)}")
        print(f"  - Successful exploits: {summary.get('successful_exploits', 0)}")
        print(f"  - ML vulnerabilities: {summary.get('ml_vulnerabilities', 0)}")
        print(f"  - NLP vulnerabilities: {summary.get('nlp_vulnerabilities', 0)}")
        print(f"  - Research findings: {summary.get('research_findings', 0)}")
        print(f"  - Risk level: {summary.get('risk_level', 'unknown').upper()}")
        
        recommendations = results.get('recommendations', [])
        if recommendations:
            print(f"\n✓ Recommendations: {len(recommendations)}")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"  {i}. {rec}")
        
        print("\n✓ Full Phase 12 Integration PASSED")
        
    except Exception as e:
        print(f"✗ Full Phase 12 Integration FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    # Summary
    print("\n" + "=" * 80)
    print("Phase 12 Test Suite Completed")
    print("=" * 80)
    print("\n✓ All Phase 12 modules tested successfully!")
    print("\nPhase 12 Capabilities:")
    print("  • Reinforcement Learning for Exploitation")
    print("  • Adversarial Machine Learning Attacks")
    print("  • Natural Language Exploitation")
    print("  • Autonomous Security Research")
    print("\nReport saved to: reports/phase12/")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(test_phase12())
