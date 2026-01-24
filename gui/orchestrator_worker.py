"""
GUI Worker for Phase 1 Orchestrator
Provides async execution of Phase 1 reconnaissance with progress updates
"""
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
from typing import Dict, Any, List
from loguru import logger


class Phase1OrchestratorWorker(QThread):
    """Worker thread for Phase 1 orchestration"""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    
    def __init__(self, target: str, mode: str, recon_tools: List[str], 
                 osint_tools: List[str] = None, crawler_config: Dict[str, Any] = None):
        super().__init__()
        self.target = target
        self.mode = mode
        self.recon_tools = recon_tools
        self.osint_tools = osint_tools or []
        self.crawler_config = crawler_config
    
    def run(self):
        """Execute Phase 1 orchestration"""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Import orchestrator
            from core.phase1_orchestrator import Phase1Orchestrator
            
            # Create orchestrator
            orchestrator = Phase1Orchestrator(self.target, self.mode)
            
            # Set progress callback
            orchestrator.set_progress_callback(self.emit_progress)
            
            # Execute Phase 1
            self.progress.emit(f"🎯 Starting Phase 1 for {self.target}")
            results = loop.run_until_complete(
                orchestrator.execute(
                    selected_tools=self.recon_tools,
                    osint_tools=self.osint_tools,
                    crawler_config=self.crawler_config
                )
            )
            
            # Cleanup
            loop.close()
            
            # Emit results
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Phase 1 orchestration error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.error.emit(str(e))
    
    def emit_progress(self, message: str):
        """Emit progress signal"""
        self.progress.emit(message)
