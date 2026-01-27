"""
Pattern Recognition System
"""
from typing import Dict, Any, List, Tuple
import re
from collections import Counter
from thefuzz import fuzz
from loguru import logger


class PatternRecognizer:
    """Recognize patterns in pentesting data"""
    
    def __init__(self):
        self.learned_patterns = {
            'vulnerabilities': [],
            'defensive_patterns': [],
            'success_patterns': []
        }
        
        logger.info("Pattern recognizer initialized")
    
    def recognize_vulnerability_patterns(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recognize vulnerability patterns from scan results"""
        patterns = []
        
        # Port patterns
        open_ports = []
        for result in scan_results:
            parsed = result.get('result', {}).get('parsed', {})
            ports = parsed.get('open_ports', [])
            open_ports.extend([p['port'] for p in ports if isinstance(p, dict)])
        
        if open_ports:
            port_freq = Counter(open_ports)
            for port, count in port_freq.most_common(5):
                patterns.append({
                    'type': 'port_pattern',
                    'port': port,
                    'frequency': count,
                    'risk': self._assess_port_risk(port)
                })
        
        # Service version patterns
        service_versions = []
        for result in scan_results:
            parsed = result.get('result', {}).get('parsed', {})
            for port_info in parsed.get('open_ports', []):
                if isinstance(port_info, dict) and port_info.get('version'):
                    service_versions.append({
                        'service': port_info.get('service', ''),
                        'version': port_info.get('version', '')
                    })
        
        # Look for outdated versions
        for sv in service_versions:
            if self._is_potentially_vulnerable(sv['service'], sv['version']):
                patterns.append({
                    'type': 'outdated_service',
                    'service': sv['service'],
                    'version': sv['version'],
                    'risk': 'high'
                })
        
        logger.info(f"Recognized {len(patterns)} vulnerability patterns")
        return patterns
    
    def _assess_port_risk(self, port: int) -> str:
        """Assess risk level of open port"""
        high_risk_ports = {
            23: 'telnet',  # Unencrypted
            21: 'ftp',     # Often misconfigured
            445: 'smb',    # Common exploit target
            3389: 'rdp',   # Brute force target
            1433: 'mssql', # Database
            3306: 'mysql'  # Database
        }
        
        if port in high_risk_ports:
            return 'high'
        elif port < 1024:
            return 'medium'
        else:
            return 'low'
    
    def _is_potentially_vulnerable(self, service: str, version: str) -> bool:
        """Check if service/version is potentially vulnerable"""
        # This is simplified - in production, check against CVE database
        vulnerable_keywords = ['old', 'outdated', '0.', '1.', '2.']
        
        version_lower = version.lower()
        for keyword in vulnerable_keywords:
            if keyword in version_lower:
                return True
        
        return False
    
    def recognize_defensive_patterns(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Recognize defensive mechanism patterns"""
        defenses = {
            'firewall': False,
            'ids_ips': False,
            'waf': False,
            'rate_limiting': False,
            'patterns': []
        }
        
        # Analyze error patterns
        errors = []
        for result in results:
            stderr = result.get('result', {}).get('stderr', '')
            if stderr:
                errors.append(stderr.lower())
        
        # Look for defensive indicators
        for error in errors:
            if 'filtered' in error or 'blocked' in error:
                defenses['firewall'] = True
                defenses['patterns'].append('filtered_ports')
            
            if 'rate limit' in error or 'too many' in error:
                defenses['rate_limiting'] = True
                defenses['patterns'].append('rate_limiting')
            
            if 'waf' in error or 'mod_security' in error:
                defenses['waf'] = True
                defenses['patterns'].append('waf_detection')
        
        # Analyze timing patterns
        response_times = []
        for result in results:
            exec_time = result.get('execution_time', 0)
            if exec_time > 0:
                response_times.append(exec_time)
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            if avg_time > 10:  # Suspiciously slow
                defenses['patterns'].append('slow_response_potential_honeypot')
        
        logger.info(f"Recognized defensive patterns: {defenses['patterns']}")
        return defenses
    
    def recognize_success_patterns(self, historical_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recognize patterns that lead to success"""
        patterns = []
        
        # Group by technique and analyze success
        technique_results = {}
        for data in historical_data:
            technique = data.get('technique', 'unknown')
            success = data.get('success', False)
            
            if technique not in technique_results:
                technique_results[technique] = {'success': 0, 'total': 0, 'contexts': []}
            
            technique_results[technique]['total'] += 1
            if success:
                technique_results[technique]['success'] += 1
                technique_results[technique]['contexts'].append(data.get('context', {}))
        
        # Find successful patterns
        for technique, results in technique_results.items():
            if results['total'] >= 3:  # Minimum sample size
                success_rate = results['success'] / results['total']
                
                if success_rate > 0.7:  # High success rate
                    # Analyze common context features
                    common_features = self._find_common_features(results['contexts'])
                    
                    patterns.append({
                        'technique': technique,
                        'success_rate': success_rate,
                        'sample_size': results['total'],
                        'common_features': common_features,
                        'recommendation': 'prioritize'
                    })
        
        logger.info(f"Recognized {len(patterns)} success patterns")
        return patterns
    
    def _find_common_features(self, contexts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Find common features across contexts"""
        if not contexts:
            return {}
        
        common = {}
        
        # Find common technologies
        all_techs = []
        for ctx in contexts:
            all_techs.extend(ctx.get('technologies', []))
        
        if all_techs:
            tech_freq = Counter(all_techs)
            common['common_technologies'] = [
                tech for tech, count in tech_freq.most_common(3)
                if count > len(contexts) * 0.5
            ]
        
        # Find common ports
        all_ports = []
        for ctx in contexts:
            all_ports.extend(ctx.get('open_ports', []))
        
        if all_ports:
            port_freq = Counter(all_ports)
            common['common_ports'] = [
                port for port, count in port_freq.most_common(3)
                if count > len(contexts) * 0.5
            ]
        
        return common
    
    def detect_anomalies(self, current_data: Dict[str, Any],
                        historical_baseline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies compared to baseline"""
        anomalies = []
        
        if not historical_baseline:
            return anomalies
        
        # Check execution time anomalies
        current_time = current_data.get('execution_time', 0)
        baseline_times = [d.get('execution_time', 0) for d in historical_baseline if d.get('execution_time')]
        
        if baseline_times and current_time > 0:
            avg_time = sum(baseline_times) / len(baseline_times)
            if current_time > avg_time * 2:
                anomalies.append({
                    'type': 'execution_time',
                    'severity': 'medium',
                    'message': f'Execution time ({current_time}s) significantly higher than baseline ({avg_time:.1f}s)',
                    'possible_cause': 'rate_limiting_or_detection'
                })
        
        # Check result size anomalies
        current_output_size = len(str(current_data.get('output', '')))
        baseline_sizes = [len(str(d.get('output', ''))) for d in historical_baseline]
        
        if baseline_sizes and current_output_size > 0:
            avg_size = sum(baseline_sizes) / len(baseline_sizes)
            if current_output_size < avg_size * 0.1:
                anomalies.append({
                    'type': 'output_size',
                    'severity': 'high',
                    'message': 'Output significantly smaller than expected',
                    'possible_cause': 'blocking_or_filtering'
                })
        
        logger.debug(f"Detected {len(anomalies)} anomalies")
        return anomalies
    
    def similarity_score(self, target1: Dict[str, Any], target2: Dict[str, Any]) -> float:
        """Calculate similarity between two targets"""
        score = 0.0
        factors = 0
        
        # Technology overlap
        tech1 = set(target1.get('technologies', []))
        tech2 = set(target2.get('technologies', []))
        if tech1 and tech2:
            tech_overlap = len(tech1 & tech2) / len(tech1 | tech2)
            score += tech_overlap
            factors += 1
        
        # Port overlap
        ports1 = set(target1.get('open_ports', []))
        ports2 = set(target2.get('open_ports', []))
        if ports1 and ports2:
            port_overlap = len(ports1 & ports2) / len(ports1 | ports2)
            score += port_overlap
            factors += 1
        
        # OS similarity
        os1 = target1.get('os', '').lower()
        os2 = target2.get('os', '').lower()
        if os1 and os2:
            os_sim = fuzz.ratio(os1, os2) / 100.0
            score += os_sim
            factors += 1
        
        return score / factors if factors > 0 else 0.0
