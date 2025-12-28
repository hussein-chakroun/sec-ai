"""
Vector Database Manager - Phase 2
Manages knowledge storage and retrieval using vector embeddings
"""
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger
import json
from datetime import datetime


class VectorKnowledgeBase:
    """Vector database for storing and retrieving pentesting knowledge"""
    
    def __init__(self, persist_directory: str = "./data/vector_db"):
        self.persist_dir = Path(persist_directory)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB
        self.client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory=str(self.persist_dir)
        ))
        
        # Initialize embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Collections
        self.exploits_collection = self._get_or_create_collection("exploits")
        self.engagements_collection = self._get_or_create_collection("engagements")
        self.techniques_collection = self._get_or_create_collection("techniques")
        self.patterns_collection = self._get_or_create_collection("patterns")
        
        logger.info("Vector Knowledge Base initialized")
    
    def _get_or_create_collection(self, name: str):
        """Get or create a collection"""
        try:
            return self.client.get_collection(name)
        except:
            return self.client.create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )
    
    def add_exploit(self, cve_id: str, description: str, metadata: Dict[str, Any]):
        """Add exploit knowledge to database"""
        self.exploits_collection.add(
            documents=[description],
            metadatas=[{
                "cve_id": cve_id,
                "timestamp": datetime.now().isoformat(),
                **metadata
            }],
            ids=[cve_id]
        )
        logger.info(f"Added exploit: {cve_id}")
    
    def add_engagement(self, engagement_id: str, target: str, results: Dict[str, Any], 
                      success_rate: float):
        """Store past engagement for learning"""
        document = f"""
        Target: {target}
        Success Rate: {success_rate}
        Findings: {json.dumps(results.get('findings', []))}
        Techniques Used: {json.dumps(results.get('techniques', []))}
        Tools Used: {json.dumps(results.get('tools', []))}
        """
        
        self.engagements_collection.add(
            documents=[document],
            metadatas=[{
                "engagement_id": engagement_id,
                "target": target,
                "success_rate": success_rate,
                "timestamp": datetime.now().isoformat(),
                "target_type": results.get('target_type', 'unknown')
            }],
            ids=[engagement_id]
        )
        logger.info(f"Stored engagement: {engagement_id}")
    
    def add_technique(self, technique_id: str, name: str, description: str, 
                     success_rate: float, metadata: Dict[str, Any]):
        """Store technique with success metrics"""
        self.techniques_collection.add(
            documents=[f"{name}: {description}"],
            metadatas=[{
                "technique_id": technique_id,
                "success_rate": success_rate,
                "timestamp": datetime.now().isoformat(),
                **metadata
            }],
            ids=[technique_id]
        )
        logger.info(f"Added technique: {technique_id}")
    
    def add_pattern(self, pattern_id: str, pattern_description: str, 
                   context: Dict[str, Any]):
        """Store recognized patterns"""
        self.patterns_collection.add(
            documents=[pattern_description],
            metadatas=[{
                "pattern_id": pattern_id,
                "timestamp": datetime.now().isoformat(),
                **context
            }],
            ids=[pattern_id]
        )
        logger.info(f"Added pattern: {pattern_id}")
    
    def search_similar_exploits(self, query: str, n_results: int = 5) -> List[Dict]:
        """Search for similar exploits using semantic search"""
        results = self.exploits_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        
        return self._format_results(results)
    
    def search_similar_engagements(self, target_description: str, 
                                   n_results: int = 3) -> List[Dict]:
        """Find similar past engagements"""
        results = self.engagements_collection.query(
            query_texts=[target_description],
            n_results=n_results
        )
        
        return self._format_results(results)
    
    def search_techniques(self, context: str, min_success_rate: float = 0.5,
                         n_results: int = 10) -> List[Dict]:
        """Search for techniques relevant to context"""
        results = self.techniques_collection.query(
            query_texts=[context],
            n_results=n_results * 2  # Get more to filter
        )
        
        formatted = self._format_results(results)
        
        # Filter by success rate
        filtered = [
            r for r in formatted 
            if r['metadata'].get('success_rate', 0) >= min_success_rate
        ]
        
        return filtered[:n_results]
    
    def search_patterns(self, description: str, n_results: int = 5) -> List[Dict]:
        """Search for similar patterns"""
        results = self.patterns_collection.query(
            query_texts=[description],
            n_results=n_results
        )
        
        return self._format_results(results)
    
    def _format_results(self, results: Dict) -> List[Dict]:
        """Format ChromaDB results"""
        if not results['ids'] or not results['ids'][0]:
            return []
        
        formatted = []
        for i in range(len(results['ids'][0])):
            formatted.append({
                'id': results['ids'][0][i],
                'document': results['documents'][0][i] if results['documents'] else None,
                'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                'distance': results['distances'][0][i] if results.get('distances') else None
            })
        
        return formatted
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        return {
            "exploits": self.exploits_collection.count(),
            "engagements": self.engagements_collection.count(),
            "techniques": self.techniques_collection.count(),
            "patterns": self.patterns_collection.count()
        }
    
    def persist(self):
        """Persist all collections to disk"""
        self.client.persist()
        logger.info("Knowledge base persisted to disk")


class KnowledgeLoader:
    """Load CVE and exploit data into knowledge base"""
    
    def __init__(self, knowledge_base: VectorKnowledgeBase):
        self.kb = knowledge_base
    
    def load_cve_database(self, cve_file: Path):
        """Load CVE database from JSON file"""
        logger.info(f"Loading CVE database from {cve_file}")
        
        if not cve_file.exists():
            logger.warning(f"CVE file not found: {cve_file}")
            return
        
        with open(cve_file, 'r') as f:
            cves = json.load(f)
        
        for cve in cves:
            self.kb.add_exploit(
                cve_id=cve['id'],
                description=cve['description'],
                metadata={
                    'severity': cve.get('severity', 'unknown'),
                    'cvss_score': cve.get('cvss_score', 0),
                    'published_date': cve.get('published_date'),
                    'affected_products': json.dumps(cve.get('affected_products', []))
                }
            )
        
        logger.info(f"Loaded {len(cves)} CVEs")
    
    def load_techniques_database(self, techniques_file: Path):
        """Load attack techniques (MITRE ATT&CK, etc.)"""
        logger.info(f"Loading techniques from {techniques_file}")
        
        if not techniques_file.exists():
            logger.warning(f"Techniques file not found: {techniques_file}")
            return
        
        with open(techniques_file, 'r') as f:
            techniques = json.load(f)
        
        for tech in techniques:
            self.kb.add_technique(
                technique_id=tech['id'],
                name=tech['name'],
                description=tech['description'],
                success_rate=tech.get('success_rate', 0.5),
                metadata={
                    'tactic': tech.get('tactic'),
                    'platform': tech.get('platform'),
                    'permissions_required': tech.get('permissions_required')
                }
            )
        
        logger.info(f"Loaded {len(techniques)} techniques")
