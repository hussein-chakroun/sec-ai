"""
Honggfuzz Integration
Provides feedback-driven fuzzing with hardware-based coverage
"""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any
import json

logger = logging.getLogger(__name__)


class HonggfuzzFuzzer:
    """Honggfuzz wrapper with hardware-assisted fuzzing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.honggfuzz_path = config.get('honggfuzz_path', 'honggfuzz')
        self.work_dir = Path(config.get('work_dir', 'honggfuzz_work'))
        
    async def fuzz(self, target_binary: str, corpus: List[bytes],
                   timeout: int = 3600) -> Dict[str, Any]:
        """
        Run Honggfuzz fuzzing campaign
        
        Args:
            target_binary: Path to target binary
            corpus: Initial test corpus
            timeout: Fuzzing timeout in seconds
            
        Returns:
            Fuzzing results
        """
        logger.info(f"Starting Honggfuzz: {target_binary}")
        
        # Setup directories
        input_dir = self.work_dir / 'input'
        workspace = self.work_dir / 'workspace'
        crashes_dir = workspace / 'crashes'
        
        input_dir.mkdir(parents=True, exist_ok=True)
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Write corpus
        self._write_corpus(input_dir, corpus)
        
        # Build command
        cmd = self._build_command(target_binary, input_dir, workspace)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Run with timeout
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.info("Honggfuzz timeout reached")
                process.terminate()
                await process.wait()
            
            # Collect results
            results = await self._collect_results(crashes_dir, workspace)
            return results
            
        except Exception as e:
            logger.error(f"Honggfuzz error: {e}")
            return {'crashes': [], 'coverage': {}, 'executions': 0, 'error': str(e)}
    
    def _write_corpus(self, input_dir: Path, corpus: List[bytes]):
        """Write fuzzing corpus"""
        for i, data in enumerate(corpus):
            (input_dir / f'seed_{i}').write_bytes(data)
    
    def _build_command(self, target_binary: str, input_dir: Path, 
                      workspace: Path) -> List[str]:
        """Build Honggfuzz command"""
        cmd = [
            self.honggfuzz_path,
            '--input', str(input_dir),
            '--workspace', str(workspace),
        ]
        
        # Number of fuzzing threads
        threads = self.config.get('threads', 4)
        cmd.extend(['--threads', str(threads)])
        
        # Enable persistent mode for performance
        if self.config.get('persistent_mode', True):
            cmd.append('--persistent')
        
        # Timeout per execution
        timeout = self.config.get('exec_timeout', 10)
        cmd.extend(['--timeout', str(timeout)])
        
        # Enable sanitizers if available
        if self.config.get('enable_sanitizers', True):
            cmd.append('--sanitizers')
        
        # Dictionary
        dict_path = self.config.get('dictionary_path')
        if dict_path and Path(dict_path).exists():
            cmd.extend(['--dict', dict_path])
        
        # Target binary
        cmd.append('--')
        cmd.append(target_binary)
        cmd.append('___FILE___')
        
        return cmd
    
    async def _collect_results(self, crashes_dir: Path, workspace: Path) -> Dict[str, Any]:
        """Collect Honggfuzz results"""
        results = {
            'crashes': [],
            'coverage': {},
            'executions': 0
        }
        
        # Read crash files
        if crashes_dir.exists():
            for crash_file in crashes_dir.iterdir():
                if crash_file.is_file():
                    try:
                        crash_data = crash_file.read_bytes()
                        results['crashes'].append({
                            'file': crash_file.name,
                            'size': len(crash_data),
                            'data': crash_data.hex()[:200]
                        })
                    except Exception as e:
                        logger.warning(f"Failed to read crash: {e}")
        
        # Parse coverage data if available
        cov_file = workspace / 'coverage.txt'
        if cov_file.exists():
            try:
                results['coverage'] = self._parse_coverage(cov_file)
            except Exception as e:
                logger.warning(f"Failed to parse coverage: {e}")
        
        logger.info(f"Honggfuzz: {len(results['crashes'])} crashes found")
        
        return results
    
    def _parse_coverage(self, cov_file: Path) -> Dict[str, Any]:
        """Parse coverage information"""
        coverage = {'edges': 0, 'blocks': 0}
        
        try:
            content = cov_file.read_text()
            # Parse coverage metrics from file
            # Format depends on Honggfuzz output
            for line in content.split('\n'):
                if 'edge' in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit():
                            coverage['edges'] = int(part)
                            break
        except Exception as e:
            logger.warning(f"Coverage parsing error: {e}")
        
        return coverage
