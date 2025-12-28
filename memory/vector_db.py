"""
Vector Database for storing and retrieving pentesting knowledge
"""
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from loguru import logger
from pathlib import Path
import json


class VectorDatabase:
    """Vector database for semantic search of pentesting knowledge"""
    
    def __init__(self, persist_dir: str = "./data/vectordb"):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB with persistence
        self.client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory=str(self.persist_dir)
        ))
        
        # Initialize embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Create collections
        self.engagements = self._get_or_create_collection("engagements")
        self.vulnerabilities = self._get_or_create_collection("vulnerabilities")
        self.techniques = self._get_or_create_collection("techniques")
        self.exploits = self._get_or_create_collection("exploits")
        
        logger.info(f"Vector database initialized at {persist_dir}")
    
    def _get_or_create_collection(self, name: str):
        """Get or create a collection"""
        try:
            return self.client.get_collection(name)
        except:
            return self.client.create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )
    
    def add_engagement(self, engagement_id: str, data: Dict[str, Any]):
        """Store engagement data"""
        # Create searchable text
        text = f"""
        Target: {data.get('target', '')}
        Technologies: {', '.join(data.get('technologies', []))}
        Vulnerabilities: {', '.join(data.get('vulnerabilities', []))}
        Successful Techniques: {', '.join(data.get('successful_techniques', []))}
        Failed Techniques: {', '.join(data.get('failed_techniques', []))}
        """
        
        self.engagements.add(
            documents=[text],
            metadatas=[data],
            ids=[engagement_id]
        )
        
        logger.info(f"Added engagement {engagement_id} to vector DB")
    
    def add_vulnerability(self, vuln_id: str, cve_id: str, description: str, 
                         metadata: Dict[str, Any]):
        """Store vulnerability information"""
        text = f"""
        CVE: {cve_id}
        Description: {description}
        CVSS: {metadata.get('cvss', 'N/A')}
        Affected: {metadata.get('affected_products', '')}
        """
        
        metadata['cve_id'] = cve_id
        
        self.vulnerabilities.add(
            documents=[text],
            metadatas=[metadata],
            ids=[vuln_id]
        )
        
        logger.debug(f"Added vulnerability {cve_id}")
    
    def add_technique(self, technique_id: str, name: str, description: str,
                     metadata: Dict[str, Any]):
        """Store pentesting technique"""
        text = f"""
        Technique: {name}
        Description: {description}
        Tools: {', '.join(metadata.get('tools', []))}
        Success Rate: {metadata.get('success_rate', 'N/A')}
        """
        
        self.techniques.add(
            documents=[text],
            metadatas=[metadata],
            ids=[technique_id]
        )
        
        logger.debug(f"Added technique {technique_id}")
    
    def add_exploit(self, exploit_id: str, name: str, description: str,
                   metadata: Dict[str, Any]):
        """Store exploit information"""
        text = f"""
        Exploit: {name}
        Description: {description}
        Target: {metadata.get('target', '')}
        Type: {metadata.get('type', '')}
        """
        
        self.exploits.add(
            documents=[text],
            metadatas=[metadata],
            ids=[exploit_id]
        )
        
        logger.debug(f"Added exploit {exploit_id}")
    
    def search_similar_engagements(self, target: str, technologies: List[str],
                                  n_results: int = 5) -> List[Dict[str, Any]]:
        """Find similar past engagements"""
        query = f"Target with {', '.join(technologies)}"
        
        results = self.engagements.query(
            query_texts=[query],
            n_results=n_results
        )
        
        if results['ids'] and results['ids'][0]:
            return [
                {
                    'id': id_,
                    'metadata': meta,
                    'distance': dist
                }
                for id_, meta, dist in zip(
                    results['ids'][0],
                    results['metadatas'][0],
                    results['distances'][0]
                )
            ]
        
        return []
    
    def search_vulnerabilities(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for relevant vulnerabilities"""
        results = self.vulnerabilities.query(
            query_texts=[query],
            n_results=n_results
        )
        
        if results['ids'] and results['ids'][0]:
            return [
                {
                    'id': id_,
                    'metadata': meta,
                    'distance': dist
                }
                for id_, meta, dist in zip(
                    results['ids'][0],
                    results['metadatas'][0],
                    results['distances'][0]
                )
            ]
        
        return []
    
    def search_techniques(self, context: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find relevant pentesting techniques"""
        results = self.techniques.query(
            query_texts=[context],
            n_results=n_results
        )
        
        if results['ids'] and results['ids'][0]:
            return [
                {
                    'id': id_,
                    'metadata': meta,
                    'distance': dist
                }
                for id_, meta, dist in zip(
                    results['ids'][0],
                    results['metadatas'][0],
                    results['distances'][0]
                )
            ]
        
        return []
    
    def search_exploits(self, vulnerability: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Find relevant exploits"""
        results = self.exploits.query(
            query_texts=[vulnerability],
            n_results=n_results
        )
        
        if results['ids'] and results['ids'][0]:
            return [
                {
                    'id': id_,
                    'metadata': meta,
                    'distance': dist
                }
                for id_, meta, dist in zip(
                    results['ids'][0],
                    results['metadatas'][0],
                    results['distances'][0]
                )
            ]
        
        return []
    
    def get_engagement_stats(self) -> Dict[str, int]:
        """Get database statistics"""
        return {
            'engagements': self.engagements.count(),
            'vulnerabilities': self.vulnerabilities.count(),
            'techniques': self.techniques.count(),
            'exploits': self.exploits.count()
        }
    
    def persist(self):
        """Persist database to disk"""
        self.client.persist()
        logger.info("Vector database persisted to disk")
