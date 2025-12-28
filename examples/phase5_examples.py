"""
Phase 5 Usage Examples
Demonstrates various capabilities of the Zero-Day Discovery & Exploit Development engine
"""

import asyncio
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


async def example_binary_fuzzing():
    """Example: Fuzz a binary application"""
    from fuzzing.fuzzing_orchestrator import FuzzingOrchestrator
    
    # Initialize fuzzing orchestrator
    orchestrator = FuzzingOrchestrator(llm_client=None)
    
    # Define target
    target = {
        'type': 'binary',
        'name': 'vulnerable_app',
        'path': '/path/to/vulnerable_binary',
        'input_format': 'file',  # or 'stdin', 'network'
        'corpus_path': '/path/to/seed/corpus'
    }
    
    # Configure fuzzing campaign
    config = {
        'timeout': 3600,  # 1 hour
        'enable_cmplog': True,
        'enable_power_schedule': True,
        'enable_symbolic_execution': True,
        'enable_taint_analysis': True,
        'memory_limit': '200M'
    }
    
    # Start campaign
    logger.info("Starting fuzzing campaign...")
    campaign_id = await orchestrator.start_campaign(target, config)
    
    # Monitor progress
    await asyncio.sleep(60)  # Wait a bit
    status = orchestrator.get_campaign_status(campaign_id)
    
    logger.info(f"Campaign status: {status['status']}")
    logger.info(f"Crashes found: {len(status.get('findings', []))}")
    
    return status


async def example_code_analysis():
    """Example: Analyze source code for vulnerabilities"""
    from code_analysis.llm_code_analyzer import LLMCodeAnalyzer
    from code_analysis.logic_flaw_detector import LogicFlawDetector
    from code_analysis.crypto_analyzer import CryptoWeaknessAnalyzer
    
    # Sample vulnerable code
    code = """
import pickle
import hashlib

def process_user_data(user_input):
    # Insecure deserialization
    data = pickle.loads(user_input)
    
    # Weak cryptography
    hash_value = hashlib.md5(data.encode()).hexdigest()
    
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {data['id']}"
    
    # Hardcoded secret
    api_key = "sk_live_51234567890abcdef"
    
    return query, hash_value
"""
    
    # LLM-powered analysis (requires LLM client)
    # analyzer = LLMCodeAnalyzer(llm_client)
    # results = await analyzer.analyze_code(code, 'python')
    
    # Logic flaw detection
    logic_detector = LogicFlawDetector(llm_client=None)
    logic_flaws = await logic_detector.detect_flaws(code, 'python')
    
    logger.info("Logic flaws found:")
    for flaw in logic_flaws:
        logger.info(f"  - {flaw['type']}: {flaw['description']}")
    
    # Crypto analysis
    crypto_analyzer = CryptoWeaknessAnalyzer(llm_client=None)
    crypto_issues = await crypto_analyzer.analyze(code, 'python')
    
    logger.info("Cryptographic weaknesses:")
    for issue in crypto_issues:
        logger.info(f"  - {issue['type']}: {issue['description']}")
    
    return logic_flaws, crypto_issues


async def example_exploit_generation():
    """Example: Generate exploit for a buffer overflow"""
    from exploit_dev.exploit_generator import ExploitGenerator
    from exploit_dev.rop_chain_builder import ROPChainBuilder
    
    # Vulnerability information
    vuln_info = {
        'type': 'buffer_overflow',
        'offset': 264,  # Bytes to overwrite return address
        'binary_path': '/path/to/vulnerable_binary',
        'security_features': {
            'nx': True,   # NX/DEP enabled
            'pie': False,  # No PIE
            'canary': False,  # No stack canary
            'relro': False
        },
        'architecture': 'x86_64',
        'os': 'linux'
    }
    
    # Generate exploit
    generator = ExploitGenerator({
        'architecture': 'x86_64',
        'os': 'linux'
    })
    
    exploit = await generator.generate_exploit(vuln_info)
    
    if exploit:
        logger.info(f"Exploit generated: {exploit['type']}")
        logger.info(f"Payload size: {len(exploit['payload'])} bytes")
        logger.info("Exploit steps:")
        for step in exploit['steps']:
            logger.info(f"  - {step}")
        
        # Save exploit
        output_file = Path('exploits') / f"exploit_{exploit['type']}.bin"
        output_file.parent.mkdir(exist_ok=True)
        output_file.write_bytes(exploit['payload'])
        logger.info(f"Exploit saved to {output_file}")
    
    return exploit


async def example_reverse_engineering():
    """Example: Reverse engineer a binary"""
    from vulnerability_research.reverse_engineer import ReverseEngineer
    
    binary_path = '/path/to/binary'
    
    # Initialize reverse engineer
    re_tool = ReverseEngineer({
        'tool': 'radare2'  # or 'ghidra'
    })
    
    # Analyze binary
    logger.info(f"Analyzing binary: {binary_path}")
    analysis = await re_tool.analyze(binary_path)
    
    logger.info(f"Functions found: {len(analysis.get('functions', []))}")
    logger.info(f"Strings found: {len(analysis.get('strings', []))}")
    logger.info(f"Interesting code patterns: {len(analysis.get('interesting_code', []))}")
    
    # Find vulnerable functions
    vulnerable_funcs = await re_tool.find_vulnerable_functions(binary_path)
    
    logger.info("Potentially vulnerable functions:")
    for func in vulnerable_funcs[:5]:  # Top 5
        logger.info(f"  - {func['function']} (risk: {func['risk_score']})")
        logger.info(f"    Reasons: {', '.join(func['reasons'])}")
    
    return analysis, vulnerable_funcs


async def example_api_security_testing():
    """Example: Test API security"""
    from vulnerability_research.api_fuzzer import APISecurityFuzzer
    
    # OpenAPI specification
    api_spec = {
        'paths': {
            '/api/users/{id}': {
                'get': {
                    'parameters': [
                        {'name': 'id', 'in': 'path', 'required': True}
                    ],
                    'security': [{'bearerAuth': []}]
                },
                'delete': {
                    'parameters': [
                        {'name': 'id', 'in': 'path', 'required': True}
                    ],
                    'security': [{'bearerAuth': []}]
                }
            },
            '/api/products': {
                'post': {
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'properties': {
                                        'name': {'type': 'string'},
                                        'price': {'type': 'number'}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    # Initialize API fuzzer
    fuzzer = APISecurityFuzzer({})
    
    # Fuzz API
    logger.info("Fuzzing API endpoints...")
    results = await fuzzer.fuzz_api(api_spec, 'https://api.example.com')
    
    logger.info(f"Endpoints tested: {results['endpoints_tested']}")
    logger.info(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
    
    for vuln in results['vulnerabilities']:
        logger.info(f"  - {vuln['type']} at {vuln['endpoint']} (severity: {vuln['severity']})")
    
    return results


async def example_full_assessment():
    """Example: Complete Phase 5 assessment"""
    from core.phase5_engine import Phase5Engine
    
    # Initialize Phase 5 engine
    engine = Phase5Engine(
        llm_client=None,  # Provide your LLM client
        config={
            'fuzzing_timeout': 1800,  # 30 minutes
            'enable_fuzzing': True,
            'enable_symbolic_execution': True,
            'exploit_gen': {
                'architecture': 'x86_64',
                'os': 'linux'
            }
        }
    )
    
    # Define comprehensive target
    target = {
        'type': 'binary',
        'name': 'web_server',
        'path': '/path/to/web_server',
        'source_path': '/path/to/source',  # Optional
        'language': 'c',
        'architecture': 'x86_64',
        'os': 'linux',
        'security_features': {
            'nx': True,
            'pie': True,
            'canary': True
        }
    }
    
    # Run full assessment
    logger.info("Starting Phase 5 full assessment...")
    results = await engine.full_assessment(target)
    
    # Display summary
    summary = results['summary']
    logger.info("Assessment complete!")
    logger.info(f"Risk level: {summary['risk_level'].upper()}")
    logger.info(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    logger.info(f"Exploits generated: {summary['exploits_generated']}")
    logger.info(f"Phases completed: {', '.join(results['phases_completed'])}")
    
    logger.info("\nSeverity breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            logger.info(f"  {severity.capitalize()}: {count}")
    
    logger.info(f"\nResults saved to: reports/phase5/")
    
    return results


async def example_exploit_chain():
    """Example: Build multi-stage exploit chain"""
    from exploit_dev.exploit_chain import ExploitChainConstructor
    
    # Multiple vulnerabilities to chain
    vulnerabilities = [
        {
            'type': 'information_disclosure',
            'description': 'Memory leak reveals stack address',
            'severity': 'medium'
        },
        {
            'type': 'buffer_overflow',
            'description': 'Stack buffer overflow in input handler',
            'severity': 'high',
            'offset': 264
        },
        {
            'type': 'privilege_escalation',
            'description': 'Kernel vulnerability for root access',
            'severity': 'critical'
        }
    ]
    
    # Build exploit chain
    constructor = ExploitChainConstructor({
        'architecture': 'x86_64',
        'os': 'linux'
    })
    
    chain = await constructor.construct_chain(vulnerabilities)
    
    logger.info("Exploit chain constructed:")
    logger.info(f"Stages: {len(chain['stages'])}")
    logger.info(f"Overall impact: {chain['impact']}")
    logger.info(f"Reliability: {chain['reliability']}")
    
    logger.info("\nChain visualization:")
    viz = constructor.visualize_chain(chain)
    print(viz)
    
    return chain


async def main():
    """Run all examples"""
    
    print("=" * 60)
    print("Phase 5: Zero-Day Discovery & Exploit Development Examples")
    print("=" * 60)
    print()
    
    # Select examples to run
    examples = {
        '1': ('Binary Fuzzing', example_binary_fuzzing),
        '2': ('Code Analysis', example_code_analysis),
        '3': ('Exploit Generation', example_exploit_generation),
        '4': ('Reverse Engineering', example_reverse_engineering),
        '5': ('API Security Testing', example_api_security_testing),
        '6': ('Full Assessment', example_full_assessment),
        '7': ('Exploit Chain', example_exploit_chain),
    }
    
    print("Available examples:")
    for key, (name, _) in examples.items():
        print(f"  {key}. {name}")
    print()
    
    # For demonstration, run code analysis example
    logger.info("Running Code Analysis example...")
    print()
    
    try:
        await example_code_analysis()
    except Exception as e:
        logger.error(f"Example failed: {e}")
        logger.info("Note: Some examples require proper paths and tools to be installed")
    
    print()
    print("=" * 60)
    print("Examples complete!")
    print("See PHASE5-GUIDE.md for full documentation")
    print("=" * 60)


if __name__ == '__main__':
    asyncio.run(main())
