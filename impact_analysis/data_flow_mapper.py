"""
Data Flow Mapper
Maps data flows and dependencies across systems
"""

from typing import Dict, List, Set
import json

class DataFlowMapper:
    """Maps data flows between systems"""
    
    def __init__(self):
        self.nodes = {}  # System/data store nodes
        self.edges = []  # Data flows
    
    def add_node(self, node_id: str, node_type: str, metadata: Dict = None):
        """Add a system or data store"""
        self.nodes[node_id] = {
            'type': node_type,
            'metadata': metadata or {},
            'incoming': [],
            'outgoing': []
        }
    
    def add_flow(self, source: str, destination: str, data_type: str, sensitivity: str = 'medium'):
        """Add a data flow"""
        flow = {
            'source': source,
            'destination': destination,
            'data_type': data_type,
            'sensitivity': sensitivity
        }
        
        self.edges.append(flow)
        
        if source in self.nodes:
            self.nodes[source]['outgoing'].append(destination)
        if destination in self.nodes:
            self.nodes[destination]['incoming'].append(source)
    
    def find_critical_paths(self) -> List[List[str]]:
        """Find critical data paths"""
        critical_paths = []
        
        # Find nodes handling sensitive data
        sensitive_nodes = [
            node_id for node_id, data in self.nodes.items()
            if data['metadata'].get('sensitivity') == 'critical'
        ]
        
        # Trace paths from/to sensitive nodes
        for node in sensitive_nodes:
            paths = self._trace_paths(node, max_depth=5)
            critical_paths.extend(paths)
        
        return critical_paths
    
    def _trace_paths(self, start_node: str, max_depth: int = 5) -> List[List[str]]:
        """Trace all paths from a node"""
        paths = []
        
        def dfs(current, path, depth):
            if depth > max_depth:
                return
            
            path = path + [current]
            
            if current not in self.nodes:
                return
            
            outgoing = self.nodes[current]['outgoing']
            
            if not outgoing:
                paths.append(path)
            else:
                for next_node in outgoing:
                    if next_node not in path:  # Avoid cycles
                        dfs(next_node, path, depth + 1)
        
        dfs(start_node, [], 0)
        return paths
    
    def analyze_dependencies(self, node_id: str) -> Dict:
        """Analyze dependencies for a node"""
        if node_id not in self.nodes:
            return {}
        
        return {
            'node': node_id,
            'direct_dependencies': self.nodes[node_id]['incoming'],
            'direct_dependents': self.nodes[node_id]['outgoing'],
            'transitive_dependencies': self._get_transitive_deps(node_id),
            'impact_radius': len(self._get_all_affected(node_id))
        }
    
    def _get_transitive_deps(self, node_id: str, visited: Set = None) -> List[str]:
        """Get all transitive dependencies"""
        if visited is None:
            visited = set()
        
        if node_id in visited or node_id not in self.nodes:
            return []
        
        visited.add(node_id)
        deps = []
        
        for dep in self.nodes[node_id]['incoming']:
            deps.append(dep)
            deps.extend(self._get_transitive_deps(dep, visited))
        
        return list(set(deps))
    
    def _get_all_affected(self, node_id: str, visited: Set = None) -> List[str]:
        """Get all nodes affected if this node is compromised"""
        if visited is None:
            visited = set()
        
        if node_id in visited or node_id not in self.nodes:
            return []
        
        visited.add(node_id)
        affected = []
        
        for dep in self.nodes[node_id]['outgoing']:
            affected.append(dep)
            affected.extend(self._get_all_affected(dep, visited))
        
        return list(set(affected))
    
    def export_graph(self, output_file: str):
        """Export graph to JSON"""
        graph = {
            'nodes': [{'id': k, **v} for k, v in self.nodes.items()],
            'edges': self.edges
        }
        
        with open(output_file, 'w') as f:
            json.dump(graph, f, indent=2)
        
        print(f"[+] Data flow graph exported to: {output_file}")
