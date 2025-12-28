"""
AFL++ Fuzzer Integration
Provides coverage-guided fuzzing using AFL++
"""

import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import shutil

logger = logging.getLogger(__name__)


class AFLFuzzer:
    """AFL++ fuzzer wrapper with advanced features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.afl_path = config.get('afl_path', 'afl-fuzz')
        self.work_dir = Path(config.get('work_dir', 'fuzzing_work'))
        self.crashes = []
        self.total_execs = 0
        
    async def fuzz(self, target_binary: str, corpus: List[bytes], 
                   timeout: int = 3600) -> Dict[str, Any]:
        """
        Run AFL++ fuzzing campaign
        
        Args:
            target_binary: Path to target binary
            corpus: Initial test corpus
            timeout: Fuzzing timeout in seconds
            
        Returns:
            Fuzzing results including crashes and coverage
        """
        logger.info(f"Starting AFL++ fuzzing: {target_binary}")
        
        # Setup directories
        input_dir = self.work_dir / 'input'
        output_dir = self.work_dir / 'output'
        crashes_dir = output_dir / 'default' / 'crashes'
        
        self._setup_directories(input_dir, output_dir)
        self._write_corpus(input_dir, corpus)
        
        # Build AFL command
        cmd = self._build_afl_command(target_binary, input_dir, output_dir)
        
        # Run AFL++ with timeout
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait with timeout
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                logger.info("AFL++ fuzzing timeout reached")
                process.terminate()
                await process.wait()
            
            # Collect results
            results = await self._collect_results(crashes_dir, output_dir)
            
            return results
            
        except Exception as e:
            logger.error(f"AFL++ fuzzing error: {e}")
            return {
                'crashes': [],
                'coverage': {},
                'executions': 0,
                'error': str(e)
            }
    
    def _setup_directories(self, input_dir: Path, output_dir: Path):
        """Setup fuzzing directories"""
        input_dir.mkdir(parents=True, exist_ok=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Clear old output
        if output_dir.exists():
            for item in output_dir.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
    
    def _write_corpus(self, input_dir: Path, corpus: List[bytes]):
        """Write initial corpus to disk"""
        for i, data in enumerate(corpus):
            (input_dir / f'seed_{i}').write_bytes(data)
    
    def _build_afl_command(self, target_binary: str, input_dir: Path, 
                          output_dir: Path) -> List[str]:
        """Build AFL++ command with optimal settings"""
        cmd = [
            self.afl_path,
            '-i', str(input_dir),
            '-o', str(output_dir),
        ]
        
        # Add power schedules for better coverage
        if self.config.get('use_power_schedule', True):
            cmd.extend(['-p', 'explore'])
        
        # Enable CMPLOG for better magic byte handling
        if self.config.get('enable_cmplog', True):
            cmd.extend(['-c', '0'])
        
        # Add dictionary if available
        dict_path = self.config.get('dictionary_path')
        if dict_path and Path(dict_path).exists():
            cmd.extend(['-x', dict_path])
        
        # Memory limit
        mem_limit = self.config.get('memory_limit', '200M')
        cmd.extend(['-m', mem_limit])
        
        # Timeout for each execution
        timeout = self.config.get('exec_timeout', '1000+')
        cmd.extend(['-t', timeout])
        
        # Target binary and arguments
        cmd.append('--')
        cmd.append(target_binary)
        
        # Add input placeholder
        cmd.append('@@')
        
        return cmd
    
    async def _collect_results(self, crashes_dir: Path, output_dir: Path) -> Dict[str, Any]:
        """Collect fuzzing results"""
        results = {
            'crashes': [],
            'coverage': {},
            'executions': 0,
            'unique_crashes': 0
        }
        
        # Parse stats file
        stats_file = output_dir / 'default' / 'fuzzer_stats'
        if stats_file.exists():
            stats = self._parse_stats(stats_file)
            results['executions'] = stats.get('execs_done', 0)
            results['coverage'] = {
                'bitmap_cvg': stats.get('bitmap_cvg', '0%'),
                'paths_total': stats.get('paths_total', 0)
            }
        
        # Collect crashes
        if crashes_dir.exists():
            for crash_file in crashes_dir.glob('id:*'):
                try:
                    crash_data = crash_file.read_bytes()
                    results['crashes'].append({
                        'file': crash_file.name,
                        'size': len(crash_data),
                        'data': crash_data.hex()[:200]  # First 200 hex chars
                    })
                except Exception as e:
                    logger.warning(f"Failed to read crash file {crash_file}: {e}")
        
        results['unique_crashes'] = len(results['crashes'])
        
        logger.info(f"AFL++ results: {results['executions']} execs, "
                   f"{results['unique_crashes']} unique crashes")
        
        return results
    
    def _parse_stats(self, stats_file: Path) -> Dict[str, Any]:
        """Parse AFL stats file"""
        stats = {}
        
        try:
            content = stats_file.read_text()
            for line in content.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Convert numeric values
                    try:
                        if value.isdigit():
                            value = int(value)
                        elif value.replace('.', '').isdigit():
                            value = float(value)
                    except:
                        pass
                    
                    stats[key] = value
        except Exception as e:
            logger.warning(f"Failed to parse stats: {e}")
        
        return stats
    
    def minimize_crash(self, crash_data: bytes, target_binary: str) -> bytes:
        """
        Minimize a crash test case using afl-tmin
        
        Args:
            crash_data: Original crash input
            target_binary: Target binary path
            
        Returns:
            Minimized crash input
        """
        logger.info("Minimizing crash test case")
        
        # Write crash to temp file
        temp_dir = self.work_dir / 'temp'
        temp_dir.mkdir(exist_ok=True)
        
        crash_file = temp_dir / 'crash_original'
        crash_file.write_bytes(crash_data)
        
        minimized_file = temp_dir / 'crash_minimized'
        
        # Run afl-tmin
        cmd = [
            'afl-tmin',
            '-i', str(crash_file),
            '-o', str(minimized_file),
            '--',
            target_binary,
            '@@'
        ]
        
        try:
            subprocess.run(cmd, timeout=300, capture_output=True)
            
            if minimized_file.exists():
                minimized = minimized_file.read_bytes()
                logger.info(f"Minimized crash: {len(crash_data)} -> {len(minimized)} bytes")
                return minimized
        except Exception as e:
            logger.warning(f"Crash minimization failed: {e}")
        
        return crash_data
