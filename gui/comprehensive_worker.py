"""
Comprehensive Worker for Multi-Phase Orchestration
Handles execution of multiple phases with detailed logging and result saving
"""
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
from typing import Dict, Any, List, Optional
from loguru import logger
import json
import os
from pathlib import Path
from datetime import datetime


class ComprehensiveWorker(QThread):
    """Worker thread for comprehensive multi-phase orchestration"""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)  # For detailed logging
    phase_started = pyqtSignal(int, str)  # phase_num, phase_name
    phase_completed = pyqtSignal(int, dict)  # phase_num, results
    step_update = pyqtSignal(str, str)  # step_name, step_description
    
    def __init__(self, target: str, enabled_phases: List[int], 
                 iterations: int = 10, config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.target = target
        self.enabled_phases = sorted(enabled_phases)
        self.iterations = iterations
        self.config = config or {}
        self.results_dir = Path("./phase_results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Session ID for this run
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Phase results storage
        self.phase_results = {}
        
    def run(self):
        """Execute all enabled phases"""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.progress.emit(f"🚀 Starting comprehensive pentest session: {self.session_id}")
            self.progress.emit(f"🎯 Target: {self.target}")
            self.progress.emit(f"📋 Enabled Phases: {', '.join([f'Phase {p}' for p in self.enabled_phases])}")
            self.progress.emit(f"🔄 Max Iterations: {self.iterations}")
            self.progress.emit("="*80)
            
            # Execute phases sequentially
            for phase_num in self.enabled_phases:
                try:
                    self.progress.emit(f"\n{'='*80}")
                    result = loop.run_until_complete(
                        self.execute_phase(phase_num)
                    )
                    
                    if result:
                        self.phase_results[phase_num] = result
                        self.save_phase_result(phase_num, result)
                        self.phase_completed.emit(phase_num, result)
                        self.progress.emit(f"✅ Phase {phase_num} completed successfully")
                    else:
                        self.progress.emit(f"⚠️ Phase {phase_num} returned no results")
                        
                except Exception as e:
                    error_msg = f"❌ Phase {phase_num} failed: {str(e)}"
                    self.progress.emit(error_msg)
                    logger.error(f"Phase {phase_num} error: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    
                    # Decide whether to continue or stop
                    if phase_num in [1, 2]:  # Critical phases
                        self.error.emit(f"Critical phase {phase_num} failed. Stopping execution.")
                        loop.close()
                        return
            
            # Cleanup
            loop.close()
            
            # Emit final results
            final_results = {
                'session_id': self.session_id,
                'target': self.target,
                'enabled_phases': self.enabled_phases,
                'phase_results': self.phase_results,
                'timestamp': datetime.now().isoformat()
            }
            
            self.save_session_summary(final_results)
            self.finished.emit(final_results)
            
        except Exception as e:
            logger.error(f"Comprehensive worker error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.error.emit(str(e))
    
    async def execute_phase(self, phase_num: int) -> Dict[str, Any]:
        """Execute a specific phase"""
        phase_name = self.get_phase_name(phase_num)
        self.phase_started.emit(phase_num, phase_name)
        self.progress.emit(f"\n🔷 PHASE {phase_num}: {phase_name}")
        self.progress.emit(f"{'='*80}")
        
        if phase_num == 1:
            return await self.execute_phase1()
        elif phase_num == 2:
            return await self.execute_phase2()
        elif phase_num == 3:
            return await self.execute_phase3()
        elif phase_num == 4:
            return await self.execute_phase4()
        elif phase_num == 5:
            return await self.execute_phase5()
        else:
            self.progress.emit(f"⚠️ Phase {phase_num} not implemented yet")
            return {}
    
    async def execute_phase1(self) -> Dict[str, Any]:
        """Execute Phase 1: Reconnaissance"""
        from core.phase1_orchestrator import Phase1Orchestrator
        
        self.step_update.emit("Initialization", "Setting up Phase 1 Orchestrator")
        self.progress.emit("📡 Step 1: Initializing reconnaissance orchestrator...")
        
        orchestrator = Phase1Orchestrator(self.target, mode="balanced")
        orchestrator.set_progress_callback(self.emit_step_progress)
        
        # Default tools
        recon_tools = ['nmap', 'dns', 'whois', 'subdomain', 'service']
        
        self.progress.emit(f"🛠️ Step 2: Configuring tools: {', '.join(recon_tools)}")
        self.step_update.emit("Tool Configuration", f"Using: {', '.join(recon_tools)}")
        
        self.progress.emit("🔍 Step 3: Starting reconnaissance scan...")
        self.step_update.emit("Scanning", "Performing network reconnaissance")
        
        results = await orchestrator.execute(
            selected_tools=recon_tools,
            osint_tools=[]
        )
        
        self.progress.emit(f"📊 Step 4: Analysis complete")
        self.progress.emit(f"   - Hosts discovered: {len(results.get('hosts', []))}")
        self.progress.emit(f"   - Open ports found: {results.get('total_ports', 0)}")
        self.progress.emit(f"   - Services identified: {len(results.get('services', []))}")
        
        return results
    
    async def execute_phase2(self) -> Dict[str, Any]:
        """Execute Phase 2: Vulnerability Scanning"""
        from core.phase2_orchestrator import Phase2Orchestrator
        
        self.step_update.emit("Initialization", "Setting up Phase 2 Orchestrator")
        self.progress.emit("🔎 Step 1: Initializing vulnerability scanner...")
        
        # Get Phase 1 results
        if 1 not in self.phase_results:
            self.progress.emit("⚠️ Phase 1 results not found, attempting to load from file...")
            phase1_results = self.load_phase_result(1)
            if not phase1_results:
                raise Exception("Phase 2 requires Phase 1 results")
        else:
            phase1_results = self.phase_results[1]
        
        orchestrator = Phase2Orchestrator(self.target, phase1_results)
        orchestrator.set_progress_callback(self.emit_step_progress)
        
        self.progress.emit("🔍 Step 2: Analyzing Phase 1 results for vulnerabilities...")
        self.step_update.emit("Analysis", "Processing reconnaissance data")
        
        self.progress.emit("🎯 Step 3: Running vulnerability scans...")
        self.step_update.emit("Scanning", "Detecting vulnerabilities")
        
        results = await orchestrator.execute()
        
        self.progress.emit(f"📊 Step 4: Vulnerability analysis complete")
        self.progress.emit(f"   - Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        self.progress.emit(f"   - Critical: {results.get('critical_count', 0)}")
        self.progress.emit(f"   - High: {results.get('high_count', 0)}")
        
        return results
    
    async def execute_phase3(self) -> Dict[str, Any]:
        """Execute Phase 3: Exploitation"""
        from core.phase3_orchestrator import Phase3Orchestrator
        
        self.step_update.emit("Initialization", "Setting up Phase 3 Orchestrator")
        self.progress.emit("💥 Step 1: Initializing exploitation engine...")
        
        # Get Phase 2 results
        if 2 not in self.phase_results:
            self.progress.emit("⚠️ Phase 2 results not found, attempting to load from file...")
            phase2_results = self.load_phase_result(2)
            if not phase2_results:
                raise Exception("Phase 3 requires Phase 2 results")
        else:
            phase2_results = self.phase_results[2]
        
        orchestrator = Phase3Orchestrator(self.target, phase2_results)
        orchestrator.set_progress_callback(self.emit_step_progress)
        
        self.progress.emit("🔍 Step 2: Analyzing vulnerabilities for exploitation...")
        self.step_update.emit("Analysis", "Selecting exploitation targets")
        
        self.progress.emit("🎯 Step 3: Executing exploits...")
        self.step_update.emit("Exploitation", "Attempting to compromise targets")
        
        results = await orchestrator.execute()
        
        self.progress.emit(f"📊 Step 4: Exploitation complete")
        self.progress.emit(f"   - Exploits attempted: {results.get('attempts', 0)}")
        self.progress.emit(f"   - Successful: {results.get('successful', 0)}")
        self.progress.emit(f"   - Hosts compromised: {len(results.get('compromised_hosts', []))}")
        
        return results
    
    async def execute_phase4(self) -> Dict[str, Any]:
        """Execute Phase 4: Post-Exploitation"""
        from core.phase4_orchestrator import Phase4Orchestrator
        
        self.step_update.emit("Initialization", "Setting up Phase 4 Orchestrator")
        self.progress.emit("🔓 Step 1: Initializing post-exploitation engine...")
        
        # Get Phase 3 results
        if 3 not in self.phase_results:
            self.progress.emit("⚠️ Phase 3 results not found, attempting to load from file...")
            phase3_results = self.load_phase_result(3)
            if not phase3_results:
                raise Exception("Phase 4 requires Phase 3 results")
        else:
            phase3_results = self.phase_results[3]
        
        orchestrator = Phase4Orchestrator(self.target, phase3_results)
        orchestrator.set_progress_callback(self.emit_step_progress)
        
        self.progress.emit("🔍 Step 2: Analyzing compromised hosts...")
        self.step_update.emit("Analysis", "Identifying post-exploitation targets")
        
        self.progress.emit("🎯 Step 3: Privilege escalation and credential harvesting...")
        self.step_update.emit("Post-Exploitation", "Escalating privileges")
        
        results = await orchestrator.execute()
        
        self.progress.emit(f"📊 Step 4: Post-exploitation complete")
        self.progress.emit(f"   - Privilege escalations: {results.get('privesc_count', 0)}")
        self.progress.emit(f"   - Credentials harvested: {len(results.get('credentials', []))}")
        self.progress.emit(f"   - Persistence installed: {results.get('persistence_count', 0)}")
        
        return results
    
    async def execute_phase5(self) -> Dict[str, Any]:
        """Execute Phase 5: Lateral Movement"""
        from core.phase5_orchestrator import Phase5Orchestrator
        
        self.step_update.emit("Initialization", "Setting up Phase 5 Orchestrator")
        self.progress.emit("🌐 Step 1: Initializing lateral movement engine...")
        
        # Get Phase 4 results
        if 4 not in self.phase_results:
            self.progress.emit("⚠️ Phase 4 results not found, attempting to load from file...")
            phase4_results = self.load_phase_result(4)
            if not phase4_results:
                raise Exception("Phase 5 requires Phase 4 results")
        else:
            phase4_results = self.phase_results[4]
        
        orchestrator = Phase5Orchestrator(self.target, phase4_results)
        orchestrator.set_progress_callback(self.emit_step_progress)
        
        self.progress.emit("🔍 Step 2: Analyzing network for lateral movement opportunities...")
        self.step_update.emit("Analysis", "Mapping network topology")
        
        self.progress.emit("🎯 Step 3: Performing lateral movement...")
        self.step_update.emit("Lateral Movement", "Moving across the network")
        
        results = await orchestrator.execute()
        
        self.progress.emit(f"📊 Step 4: Lateral movement complete")
        self.progress.emit(f"   - New hosts compromised: {len(results.get('new_hosts', []))}")
        self.progress.emit(f"   - AD attacks successful: {results.get('ad_attacks', 0)}")
        self.progress.emit(f"   - Network penetration: {results.get('penetration_percentage', 0)}%")
        
        return results
    
    def emit_step_progress(self, message: str):
        """Emit progress from orchestrators"""
        self.progress.emit(f"   {message}")
    
    def get_phase_name(self, phase_num: int) -> str:
        """Get human-readable phase name"""
        phase_names = {
            1: "Reconnaissance & Information Gathering",
            2: "Vulnerability Scanning & Analysis",
            3: "Exploitation & System Compromise",
            4: "Post-Exploitation & Privilege Escalation",
            5: "Lateral Movement & Domain Dominance",
            12: "AI Adaptive Exploitation"
        }
        return phase_names.get(phase_num, f"Phase {phase_num}")
    
    def save_phase_result(self, phase_num: int, results: Dict[str, Any]):
        """Save phase results to file"""
        try:
            phase_file = self.results_dir / f"phase{phase_num}_{self.session_id}.json"
            
            save_data = {
                'phase': phase_num,
                'phase_name': self.get_phase_name(phase_num),
                'target': self.target,
                'session_id': self.session_id,
                'timestamp': datetime.now().isoformat(),
                'results': results
            }
            
            with open(phase_file, 'w') as f:
                json.dump(save_data, f, indent=2, default=str)
            
            self.progress.emit(f"💾 Phase {phase_num} results saved to: {phase_file}")
            logger.info(f"Phase {phase_num} results saved to {phase_file}")
            
        except Exception as e:
            logger.error(f"Failed to save Phase {phase_num} results: {e}")
            self.progress.emit(f"⚠️ Warning: Could not save Phase {phase_num} results: {e}")
    
    def load_phase_result(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Load phase results from file"""
        try:
            # Try to find the most recent result for this phase
            pattern = f"phase{phase_num}_*.json"
            files = sorted(self.results_dir.glob(pattern), reverse=True)
            
            if files:
                latest_file = files[0]
                self.progress.emit(f"📂 Loading Phase {phase_num} from: {latest_file}")
                
                with open(latest_file, 'r') as f:
                    data = json.load(f)
                
                return data.get('results', {})
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to load Phase {phase_num} results: {e}")
            return None
    
    def save_session_summary(self, results: Dict[str, Any]):
        """Save overall session summary"""
        try:
            summary_file = self.results_dir / f"session_{self.session_id}.json"
            
            with open(summary_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.progress.emit(f"\n{'='*80}")
            self.progress.emit(f"💾 Session summary saved to: {summary_file}")
            logger.info(f"Session summary saved to {summary_file}")
            
        except Exception as e:
            logger.error(f"Failed to save session summary: {e}")
            self.progress.emit(f"⚠️ Warning: Could not save session summary: {e}")
