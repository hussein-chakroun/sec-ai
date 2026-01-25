"""
Phase Integration Bridge
Seamlessly connects Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5 workflow
"""
import asyncio
from typing import Dict, Any, Optional
from loguru import logger
from pathlib import Path
import json
from datetime import datetime

from .phase1_orchestrator import Phase1Orchestrator
from .phase2_orchestrator import Phase2Orchestrator
from .phase3_orchestrator import Phase3Orchestrator
from .phase4_orchestrator import Phase4Orchestrator
from .phase5_orchestrator import Phase5Orchestrator
from .llm_orchestrator import LLMOrchestrator


class PhaseIntegrationBridge:
    """
    Manages the complete workflow from reconnaissance to domain dominance
    Phase 1 (Recon) → Phase 2 (Vuln Scan) → Phase 3 (Exploitation) → 
    Phase 4 (Post-Exploit) → Phase 5 (Lateral Movement)
    """
    
    def __init__(
        self,
        llm_orchestrator: LLMOrchestrator,
        config: Optional[Dict[str, Any]] = None
    ):
        self.llm = llm_orchestrator
        self.config = config or {}
        
        # Phase orchestrators
        self.phase1: Optional[Phase1Orchestrator] = None
        self.phase2: Optional[Phase2Orchestrator] = None
        self.phase3: Optional[Phase3Orchestrator] = None
        self.phase4: Optional[Phase4Orchestrator] = None
        self.phase5: Optional[Phase5Orchestrator] = None
        
        # Results storage
        self.phase1_results: Optional[Dict[str, Any]] = None
        self.phase2_results: Optional[Dict[str, Any]] = None
        self.phase3_results: Optional[Dict[str, Any]] = None
        self.phase4_results: Optional[Dict[str, Any]] = None
        self.phase5_results: Optional[Dict[str, Any]] = None
        
        # Configuration
        self.auto_progress = self.config.get('auto_progress', True)
        self.save_intermediate = self.config.get('save_intermediate', True)
        self.output_dir = self.config.get('output_dir', './reports')
        
        logger.info("Phase Integration Bridge initialized")
    
    async def run_complete_pentest(
        self,
        target: str,
        phase1_config: Optional[Dict[str, Any]] = None,
        phase2_config: Optional[Dict[str, Any]] = None,
        phase3_config: Optional[Dict[str, Any]] = None,
        phase4_config: Optional[Dict[str, Any]] = None,
        phase5_config: Optional[Dict[str, Any]] = None,
        stop_at_phase: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Run complete penetration test: Phase 1 → 2 → 3 → 4 → 5
        
        Args:
            target: Target IP/domain/URL
            phase1_config: Phase 1 configuration
            phase2_config: Phase 2 configuration
            phase3_config: Phase 3 configuration
            phase4_config: Phase 4 configuration
            phase5_config: Phase 5 configuration
            stop_at_phase: Optional phase number to stop at (1-5)
            
        Returns:
            Complete results from all phases
        """
        logger.info(f"Starting complete penetration test against {target}")
        start_time = datetime.now()
        
        # Phase 1: Reconnaissance
        logger.info("=" * 60)
        logger.info("PHASE 1: RECONNAISSANCE & INFORMATION GATHERING")
        logger.info("=" * 60)
        
        self.phase1_results = await self.run_phase1(target, phase1_config)
        
        if self.save_intermediate:
            self._save_phase_results(1, self.phase1_results)
        
        if stop_at_phase == 1:
            return self._compile_final_results(start_time, stopped_at_phase=1)
        
        # Check if we should continue to Phase 2
        if not self._should_continue_to_phase2():
            logger.warning("Insufficient reconnaissance data. Stopping before Phase 2.")
            return self._compile_final_results(start_time, stopped_at_phase=1)
        
        # Phase 2: Vulnerability Scanning
        logger.info("=" * 60)
        logger.info("PHASE 2: VULNERABILITY ASSESSMENT")
        logger.info("=" * 60)
        
        self.phase2_results = await self.run_phase2(self.phase1_results, phase2_config)
        
        if self.save_intermediate:
            self._save_phase_results(2, self.phase2_results)
        
        if stop_at_phase == 2:
            return self._compile_final_results(start_time, stopped_at_phase=2)
        
        # Check if we should continue to Phase 3
        if not self._should_continue_to_phase3():
            logger.warning("No exploitable vulnerabilities found. Stopping before Phase 3.")
            return self._compile_final_results(start_time, stopped_at_phase=2)
        
        # Phase 3: Exploitation
        logger.info("=" * 60)
        logger.info("PHASE 3: INTELLIGENT EXPLOITATION")
        logger.info("=" * 60)
        
        self.phase3_results = await self.run_phase3(
            self.phase1_results,
            self.phase2_results,
            phase3_config
        )
        
        if self.save_intermediate:
            self._save_phase_results(3, self.phase3_results)
        
        if stop_at_phase == 3:
            return self._compile_final_results(start_time, stopped_at_phase=3)
        
        # Check if we should continue to Phase 4
        if not self._should_continue_to_phase4():
            logger.warning("No compromised hosts. Stopping before Phase 4.")
            return self._compile_final_results(start_time, stopped_at_phase=3)
        
        # Phase 4: Post-Exploitation & Privilege Escalation
        logger.info("=" * 60)
        logger.info("PHASE 4: POST-EXPLOITATION & PRIVILEGE ESCALATION")
        logger.info("=" * 60)
        
        self.phase4_results = await self.run_phase4(self.phase3_results, phase4_config)
        
        if self.save_intermediate:
            self._save_phase_results(4, self.phase4_results)
        
        if stop_at_phase == 4:
            return self._compile_final_results(start_time, stopped_at_phase=4)
        
        # Check if we should continue to Phase 5
        if not self._should_continue_to_phase5():
            logger.warning("Insufficient hosts/credentials for lateral movement. Stopping before Phase 5.")
            return self._compile_final_results(start_time, stopped_at_phase=4)
        
        # Phase 5: Lateral Movement & Domain Dominance
        logger.info("=" * 60)
        logger.info("PHASE 5: LATERAL MOVEMENT & DOMAIN DOMINANCE")
        logger.info("=" * 60)
        
        self.phase5_results = await self.run_phase5(self.phase4_results, phase5_config)
        
        if self.save_intermediate:
            self._save_phase_results(5, self.phase5_results)
        
        # Compile final results
        final_results = self._compile_final_results(start_time, stopped_at_phase=5)
        
        logger.success("Complete penetration test finished successfully!")
        return final_results
    
    async def run_phase1(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Phase 1: Reconnaissance"""
        logger.info(f"Starting Phase 1 reconnaissance for {target}")
        
        phase1_config = {**(config or {}), **(self.config.get('phase1', {}))}
        
        self.phase1 = Phase1Orchestrator(phase1_config)
        self.phase1.add_target(target)
        
        # Create and execute reconnaissance plan
        self.phase1.create_recon_plan()
        results = await self.phase1.execute_recon_plan()
        
        logger.success(f"Phase 1 complete: {len(results.get('hosts', []))} hosts discovered")
        return results
    
    async def run_phase2(
        self,
        phase1_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Phase 2: Vulnerability Scanning"""
        logger.info("Starting Phase 2 vulnerability assessment")
        
        phase2_config = {**(config or {}), **(self.config.get('phase2', {}))}
        
        self.phase2 = Phase2Orchestrator(phase2_config)
        self.phase2.load_phase1_results(phase1_results)
        
        # Create and execute scan plan
        self.phase2.create_scan_plan()
        results = await self.phase2.execute_scan_plan()
        
        # Export optimized data for Phase 3
        phase2_export = self.phase2.export_for_phase3()
        
        logger.success(
            f"Phase 2 complete: {phase2_export['summary']['total_exploitable']} "
            f"exploitable vulnerabilities found"
        )
        
        # Return both full results and Phase 3 export
        results['phase3_export'] = phase2_export
        return results
    
    async def run_phase3(
        self,
        phase1_results: Dict[str, Any],
        phase2_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Phase 3: Exploitation"""
        logger.info("Starting Phase 3 intelligent exploitation")
        
        phase3_config = {**(config or {}), **(self.config.get('phase3', {}))}
        
        self.phase3 = Phase3Orchestrator(self.llm, phase3_config)
        self.phase3.load_phase1_results(phase1_results)
        
        # Load Phase 2 export if available, otherwise full results
        phase2_export = phase2_results.get('phase3_export', phase2_results)
        self.phase3.load_phase2_results(phase2_export)
        
        # Create LLM-driven exploitation plan
        exploitation_plan = await self.phase3.create_exploitation_plan()
        
        logger.info(f"LLM created exploitation plan with {len(exploitation_plan.get('exploit_sequence', []))} targets")
        
        # Execute exploitation
        results = await self.phase3.execute_exploitation_plan(exploitation_plan)
        
        logger.success(
            f"Phase 3 complete: {results.get('statistics', {}).get('successful_exploits', 0)} "
            f"successful exploits, {results.get('statistics', {}).get('shells_obtained', 0)} shells obtained"
        )
        
        return results
    
    async def run_phase4(
        self,
        phase3_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Phase 4: Post-Exploitation & Privilege Escalation"""
        logger.info("Starting Phase 4 post-exploitation")
        
        phase4_config = {**(config or {}), **(self.config.get('phase4', {}))}
        
        self.phase4 = Phase4Orchestrator(self.llm, phase4_config)
        self.phase4.load_phase3_results(phase3_results)
        
        # Create LLM-driven post-exploitation plan
        postexploit_plan = await self.phase4.create_postexploit_plan()
        
        logger.info(f"LLM created post-exploitation plan for {len(self.phase4.compromised_hosts)} hosts")
        
        # Execute post-exploitation
        results = await self.phase4.execute_postexploit_plan(postexploit_plan)
        
        logger.success(
            f"Phase 4 complete: {results.get('statistics', {}).get('fully_compromised_hosts', 0)} "
            f"fully compromised hosts, {results.get('statistics', {}).get('credentials_harvested', 0)} credentials harvested"
        )
        
        return results
    
    async def run_phase5(
        self,
        phase4_results: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run Phase 5: Lateral Movement & Domain Dominance"""
        logger.info("Starting Phase 5 lateral movement")
        
        phase5_config = {**(config or {}), **(self.config.get('phase5', {}))}
        
        self.phase5 = Phase5Orchestrator(self.llm, phase5_config)
        self.phase5.load_phase4_results(phase4_results)
        
        # Create LLM-driven lateral movement plan
        lateral_plan = await self.phase5.create_lateral_movement_plan()
        
        logger.info(f"LLM created lateral movement plan")
        
        # Execute lateral movement
        results = await self.phase5.execute_lateral_movement_plan(lateral_plan)
        
        logger.success(
            f"Phase 5 complete: {results.get('statistics', {}).get('total_compromised_hosts', 0)} "
            f"total hosts compromised, Domain Admin: {results.get('statistics', {}).get('domain_admin_achieved', False)}"
        )
        
        return results
    
    def _should_continue_to_phase2(self) -> bool:
        """Determine if sufficient data exists to run Phase 2"""
        if not self.phase1_results:
            return False
        
        # Check if we discovered any hosts/services
        hosts = self.phase1_results.get('hosts', [])
        services = self.phase1_results.get('services', [])
        
        if not hosts and not services:
            logger.warning("No hosts or services discovered in Phase 1")
            return False
        
        return True
    
    def _should_continue_to_phase3(self) -> bool:
        """Determine if exploitable vulnerabilities exist for Phase 3"""
        if not self.phase2_results:
            return False
        
        # Check Phase 3 export
        phase3_export = self.phase2_results.get('phase3_export', {})
        exploitable_count = phase3_export.get('summary', {}).get('total_exploitable', 0)
        
        if exploitable_count == 0:
            logger.warning("No exploitable vulnerabilities found in Phase 2")
            
            # Ask LLM if we should still attempt Phase 3
            if self.llm and self.auto_progress:
                decision = self._ask_llm_to_continue()
                return decision
            
            return False
        
        logger.info(f"Found {exploitable_count} exploitable vulnerabilities, proceeding to Phase 3")
        return True
    
    def _should_continue_to_phase4(self) -> bool:
        """Determine if we have compromised hosts for Phase 4"""
        if not self.phase3_results:
            return False
        
        successful_exploits = self.phase3_results.get('statistics', {}).get('successful_exploits', 0)
        
        if successful_exploits == 0:
            logger.warning("No successful exploits in Phase 3, cannot proceed to Phase 4")
            return False
        
        logger.info(f"Phase 3 compromised {successful_exploits} hosts, proceeding to Phase 4")
        return True
    
    def _should_continue_to_phase5(self) -> bool:
        """Determine if we have sufficient hosts/credentials for Phase 5"""
        if not self.phase4_results:
            return False
        
        stats = self.phase4_results.get('statistics', {})
        fully_compromised = stats.get('fully_compromised_hosts', 0)
        credentials = stats.get('credentials_harvested', 0)
        
        if fully_compromised == 0 and credentials == 0:
            logger.warning("No fully compromised hosts or credentials, cannot proceed to Phase 5")
            return False
        
        logger.info(f"Phase 4: {fully_compromised} fully compromised hosts, {credentials} credentials, proceeding to Phase 5")
        return True
    
    def _ask_llm_to_continue(self) -> bool:
        """Ask LLM if we should attempt Phase 3 despite no obvious exploits"""
        prompt = f"""
Phase 2 vulnerability scan found no obvious exploitable vulnerabilities with public exploits.

Phase 2 Summary:
{json.dumps(self.phase2_results.get('vulnerability_summary', {}), indent=2)}

Should we still attempt Phase 3 exploitation? Consider:
1. Manual exploitation techniques
2. Configuration issues that could be exploited
3. Chained vulnerabilities
4. Zero-day potential

Respond with JSON: {{"continue": true/false, "reasoning": "explanation"}}
"""
        
        try:
            response = self.llm.generate(prompt)
            
            # Parse response
            response = response.strip()
            if response.startswith('```'):
                lines = response.split('\n')
                response = '\n'.join(lines[1:-1])
            
            decision = json.loads(response)
            
            logger.info(f"LLM decision: {'Continue' if decision.get('continue') else 'Stop'}")
            logger.info(f"Reasoning: {decision.get('reasoning')}")
            
            return decision.get('continue', False)
            
        except Exception as e:
            logger.error(f"Failed to get LLM decision: {e}")
            return False
    
    def _compile_final_results(
        self,
        start_time: datetime,
        stopped_at_phase: int
    ) -> Dict[str, Any]:
        """Compile final results from all phases"""
        duration = (datetime.now() - start_time).total_seconds()
        
        final_results = {
            'pentest_summary': {
                'start_time': start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': duration,
                'duration_formatted': self._format_duration(duration),
                'phases_completed': stopped_at_phase,
                'status': 'complete' if stopped_at_phase == 5 else 'partial'
            },
            'phase1_results': self.phase1_results,
            'phase2_results': self.phase2_results,
            'phase3_results': self.phase3_results,
            'phase4_results': self.phase4_results,
            'phase5_results': self.phase5_results,
            'executive_summary': self._create_executive_summary()
        }
        
        return final_results
    
    def _create_executive_summary(self) -> Dict[str, Any]:
        """Create executive summary of entire pentest"""
        summary = {
            'targets_scanned': 0,
            'services_discovered': 0,
            'vulnerabilities_found': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'successful_exploits': 0,
            'shells_obtained': 0,
            'compromised_hosts': [],
            'fully_compromised_hosts': 0,
            'credentials_harvested': 0,
            'persistence_installed': 0,
            'lateral_movements': 0,
            'domain_admin_achieved': False,
            'domain_controllers_compromised': 0,
            'risk_level': 'unknown'
        }
        
        # Phase 1 data
        if self.phase1_results:
            summary['targets_scanned'] = len(self.phase1_results.get('hosts', []))
            summary['services_discovered'] = len(self.phase1_results.get('services', []))
        
        # Phase 2 data
        if self.phase2_results:
            vuln_summary = self.phase2_results.get('vulnerability_summary', {})
            summary['vulnerabilities_found'] = vuln_summary.get('total', 0)
            summary['critical_vulnerabilities'] = vuln_summary.get('critical', 0)
            summary['high_vulnerabilities'] = vuln_summary.get('high', 0)
        
        # Phase 3 data
        if self.phase3_results:
            stats = self.phase3_results.get('statistics', {})
            summary['successful_exploits'] = stats.get('successful_exploits', 0)
            summary['shells_obtained'] = stats.get('shells_obtained', 0)
            summary['compromised_hosts'] = self.phase3_results.get('compromised_hosts', [])
        
        # Phase 4 data
        if self.phase4_results:
            stats = self.phase4_results.get('statistics', {})
            summary['fully_compromised_hosts'] = stats.get('fully_compromised_hosts', 0)
            summary['credentials_harvested'] = stats.get('total_credentials_harvested', 0)
            summary['persistence_installed'] = stats.get('persistence_mechanisms_installed', 0)
        
        # Phase 5 data
        if self.phase5_results:
            stats = self.phase5_results.get('statistics', {})
            summary['lateral_movements'] = stats.get('successful_lateral_movements', 0)
            summary['domain_admin_achieved'] = stats.get('domain_admin_achieved', False)
            summary['domain_controllers_compromised'] = stats.get('domain_controllers_compromised', 0)
        
        # Determine overall risk level
        summary['risk_level'] = self._calculate_risk_level(summary)
        
        return summary
    
    def _calculate_risk_level(self, summary: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        # Critical if domain admin achieved or domain controllers compromised
        if summary.get('domain_admin_achieved') or summary.get('domain_controllers_compromised', 0) > 0:
            return 'critical'
        
        # Critical if lateral movement successful or persistence installed
        if summary.get('lateral_movements', 0) > 0 or summary.get('persistence_installed', 0) > 0:
            return 'critical'
        
        # Critical if any successful exploits or critical vulns
        if summary['successful_exploits'] > 0 or summary['critical_vulnerabilities'] > 0:
            return 'critical'
        
        # High if high vulns exist
        if summary['high_vulnerabilities'] > 0:
            return 'high'
        
        # Medium if any vulnerabilities
        if summary['vulnerabilities_found'] > 0:
            return 'medium'
        
        # Low otherwise
        return 'low'
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"
    
    def _save_phase_results(self, phase: int, results: Dict[str, Any]):
        """Save intermediate phase results"""
        output_path = Path(self.output_dir) / f"phase{phase}"
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = output_path / f"phase{phase}_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Phase {phase} results saved to {filename}")
    
    def save_final_results(self, results: Dict[str, Any], filename: Optional[str] = None):
        """Save final complete results"""
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"complete_pentest_{timestamp}.json"
        
        filepath = output_path / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.success(f"Final results saved to {filepath}")
        return str(filepath)


# Convenience function
async def run_automated_pentest(
    target: str,
    llm_orchestrator: LLMOrchestrator,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run automated Phase 1 → 2 → 3 pentest
    
    Args:
        target: Target IP/domain/URL
        llm_orchestrator: LLM orchestrator instance
        config: Optional configuration
        
    Returns:
        Complete pentest results
    """
    bridge = PhaseIntegrationBridge(llm_orchestrator, config)
    results = await bridge.run_complete_pentest(target)
    bridge.save_final_results(results)
    return results
