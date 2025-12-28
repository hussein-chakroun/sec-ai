"""
LibFuzzer Integration
In-process coverage-guided fuzzing
"""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any
import tempfile

logger = logging.getLogger(__name__)


class LibFuzzer:
    """LibFuzzer wrapper for in-process fuzzing"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.work_dir = Path(config.get('work_dir', 'libfuzzer_work'))
        
    async def fuzz(self, target_binary: str, corpus: List[bytes],
                   timeout: int = 3600) -> Dict[str, Any]:
        """
        Run LibFuzzer campaign
        
        Args:
            target_binary: Path to LibFuzzer target
            corpus: Initial corpus
            timeout: Fuzzing timeout
            
        Returns:
            Fuzzing results
        """
        logger.info(f"Starting LibFuzzer: {target_binary}")
        
        # Setup corpus directory
        corpus_dir = self.work_dir / 'corpus'
        corpus_dir.mkdir(parents=True, exist_ok=True)
        
        # Write corpus
        for i, data in enumerate(corpus):
            (corpus_dir / f'seed_{i}').write_bytes(data)
        
        # Build command
        cmd = self._build_command(target_binary, corpus_dir, timeout)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse output
            results = self._parse_output(stdout.decode(), stderr.decode(), corpus_dir)
            return results
            
        except Exception as e:
            logger.error(f"LibFuzzer error: {e}")
            return {'crashes': [], 'coverage': {}, 'executions': 0, 'error': str(e)}
    
    def _build_command(self, target_binary: str, corpus_dir: Path, 
                      timeout: int) -> List[str]:
        """Build LibFuzzer command"""
        cmd = [target_binary, str(corpus_dir)]
        
        # Max time to run
        cmd.append(f'-max_total_time={timeout}')
        
        # Jobs (parallel workers)
        jobs = self.config.get('jobs', 4)
        cmd.append(f'-jobs={jobs}')
        
        # Max length of test input
        max_len = self.config.get('max_len', 4096)
        cmd.append(f'-max_len={max_len}')
        
        # Print coverage stats
        cmd.append('-print_coverage=1')
        
        # Print final stats
        cmd.append('-print_final_stats=1')
        
        # Dictionary
        dict_path = self.config.get('dictionary_path')
        if dict_path and Path(dict_path).exists():
            cmd.append(f'-dict={dict_path}')
        
        return cmd
    
    def _parse_output(self, stdout: str, stderr: str, corpus_dir: Path) -> Dict[str, Any]:
        """Parse LibFuzzer output"""
        results = {
            'crashes': [],
            'coverage': {},
            'executions': 0
        }
        
        output = stdout + stderr
        
        # Parse execution count
        for line in output.split('\n'):
            if 'exec/s:' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if 'exec/s' in part and i > 0:
                        try:
                            # Total execs is typically shown earlier
                            pass
                        except:
                            pass
            
            # Look for crash artifacts
            if 'crash-' in line or 'leak-' in line or 'timeout-' in line:
                # Extract artifact filename
                for word in line.split():
                    if 'crash-' in word or 'leak-' in word or 'timeout-' in word:
                        artifact_path = Path(word.strip())
                        if artifact_path.exists():
                            try:
                                data = artifact_path.read_bytes()
                                results['crashes'].append({
                                    'file': artifact_path.name,
                                    'size': len(data),
                                    'data': data.hex()[:200]
                                })
                            except:
                                pass
            
            # Parse coverage
            if 'cov:' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.startswith('cov:'):
                        try:
                            cov_value = int(part.split(':')[1])
                            results['coverage']['features'] = cov_value
                        except:
                            pass
        
        # Count corpus size
        if corpus_dir.exists():
            results['corpus_size'] = len(list(corpus_dir.iterdir()))
        
        logger.info(f"LibFuzzer: {len(results['crashes'])} crashes, "
                   f"coverage: {results['coverage'].get('features', 0)}")
        
        return results
