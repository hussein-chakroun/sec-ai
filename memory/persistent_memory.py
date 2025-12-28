"""
Persistent Memory System for long-term learning
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from loguru import logger

Base = declarative_base()


class Engagement(Base):
    """Engagement record"""
    __tablename__ = 'engagements'
    
    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    status = Column(String)
    technologies = Column(JSON)
    vulnerabilities_found = Column(JSON)
    successful_techniques = Column(JSON)
    failed_techniques = Column(JSON)
    metadata = Column(JSON)


class Technique(Base):
    """Technique usage record"""
    __tablename__ = 'techniques'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    engagement_id = Column(String, nullable=False)
    technique_name = Column(String, nullable=False)
    tool = Column(String)
    parameters = Column(JSON)
    success = Column(Integer)  # 1=success, 0=fail
    timestamp = Column(DateTime, default=datetime.now)
    execution_time = Column(Float)
    metadata = Column(JSON)


class TargetProfile(Base):
    """Target organization profile"""
    __tablename__ = 'target_profiles'
    
    id = Column(String, primary_key=True)
    organization = Column(String)
    ip_ranges = Column(JSON)
    technologies = Column(JSON)
    security_posture = Column(String)
    defensive_mechanisms = Column(JSON)
    common_vulnerabilities = Column(JSON)
    last_updated = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)


class LearningEvent(Base):
    """Learning events from self-improvement"""
    __tablename__ = 'learning_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String)  # exploit_failure, detection, success, etc.
    context = Column(JSON)
    analysis = Column(Text)
    adjustments = Column(JSON)
    timestamp = Column(DateTime, default=datetime.now)


class PersistentMemory:
    """Persistent memory system with SQL backend"""
    
    def __init__(self, db_path: str = "./data/memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create engine and session
        self.engine = create_engine(f'sqlite:///{self.db_path}')
        Base.metadata.create_all(self.engine)
        
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        
        logger.info(f"Persistent memory initialized at {db_path}")
    
    def store_engagement(self, engagement_data: Dict[str, Any]) -> str:
        """Store engagement record"""
        engagement = Engagement(
            id=engagement_data['id'],
            target=engagement_data['target'],
            start_time=datetime.fromisoformat(engagement_data['start_time']),
            end_time=datetime.fromisoformat(engagement_data.get('end_time', engagement_data['start_time'])),
            status=engagement_data.get('status', 'completed'),
            technologies=engagement_data.get('technologies', []),
            vulnerabilities_found=engagement_data.get('vulnerabilities', []),
            successful_techniques=engagement_data.get('successful_techniques', []),
            failed_techniques=engagement_data.get('failed_techniques', []),
            metadata=engagement_data.get('metadata', {})
        )
        
        self.session.merge(engagement)
        self.session.commit()
        
        logger.info(f"Stored engagement {engagement_data['id']}")
        return engagement_data['id']
    
    def store_technique_usage(self, engagement_id: str, technique: str, tool: str,
                             parameters: Dict, success: bool, execution_time: float,
                             metadata: Dict = None):
        """Store technique usage"""
        record = Technique(
            engagement_id=engagement_id,
            technique_name=technique,
            tool=tool,
            parameters=parameters,
            success=1 if success else 0,
            execution_time=execution_time,
            metadata=metadata or {}
        )
        
        self.session.add(record)
        self.session.commit()
        
        logger.debug(f"Stored technique usage: {technique}")
    
    def get_technique_success_rate(self, technique: str, tool: Optional[str] = None) -> float:
        """Calculate success rate for a technique"""
        query = self.session.query(Technique).filter(
            Technique.technique_name == technique
        )
        
        if tool:
            query = query.filter(Technique.tool == tool)
        
        records = query.all()
        
        if not records:
            return 0.5  # Unknown, assume 50%
        
        successes = sum(1 for r in records if r.success == 1)
        return successes / len(records)
    
    def get_similar_engagements(self, technologies: List[str], limit: int = 5) -> List[Dict]:
        """Get engagements with similar technology stacks"""
        engagements = self.session.query(Engagement).all()
        
        # Score by technology overlap
        scored = []
        for eng in engagements:
            overlap = len(set(technologies) & set(eng.technologies or []))
            if overlap > 0:
                scored.append((overlap, eng))
        
        scored.sort(reverse=True, key=lambda x: x[0])
        
        return [
            {
                'id': eng.id,
                'target': eng.target,
                'technologies': eng.technologies,
                'vulnerabilities': eng.vulnerabilities_found,
                'successful_techniques': eng.successful_techniques,
                'similarity_score': score
            }
            for score, eng in scored[:limit]
        ]
    
    def store_target_profile(self, profile_data: Dict[str, Any]):
        """Store or update target profile"""
        profile = TargetProfile(
            id=profile_data['id'],
            organization=profile_data.get('organization', ''),
            ip_ranges=profile_data.get('ip_ranges', []),
            technologies=profile_data.get('technologies', []),
            security_posture=profile_data.get('security_posture', 'unknown'),
            defensive_mechanisms=profile_data.get('defensive_mechanisms', []),
            common_vulnerabilities=profile_data.get('common_vulnerabilities', []),
            last_updated=datetime.now(),
            metadata=profile_data.get('metadata', {})
        )
        
        self.session.merge(profile)
        self.session.commit()
        
        logger.info(f"Stored target profile {profile_data['id']}")
    
    def get_target_profile(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get target profile"""
        profile = self.session.query(TargetProfile).filter(
            TargetProfile.id == target_id
        ).first()
        
        if not profile:
            return None
        
        return {
            'id': profile.id,
            'organization': profile.organization,
            'ip_ranges': profile.ip_ranges,
            'technologies': profile.technologies,
            'security_posture': profile.security_posture,
            'defensive_mechanisms': profile.defensive_mechanisms,
            'common_vulnerabilities': profile.common_vulnerabilities,
            'last_updated': profile.last_updated.isoformat()
        }
    
    def store_learning_event(self, event_type: str, context: Dict, 
                           analysis: str, adjustments: Dict):
        """Store learning event"""
        event = LearningEvent(
            event_type=event_type,
            context=context,
            analysis=analysis,
            adjustments=adjustments
        )
        
        self.session.add(event)
        self.session.commit()
        
        logger.info(f"Stored learning event: {event_type}")
    
    def get_learning_events(self, event_type: Optional[str] = None,
                           limit: int = 100) -> List[Dict]:
        """Get learning events"""
        query = self.session.query(LearningEvent)
        
        if event_type:
            query = query.filter(LearningEvent.event_type == event_type)
        
        events = query.order_by(LearningEvent.timestamp.desc()).limit(limit).all()
        
        return [
            {
                'id': e.id,
                'event_type': e.event_type,
                'context': e.context,
                'analysis': e.analysis,
                'adjustments': e.adjustments,
                'timestamp': e.timestamp.isoformat()
            }
            for e in events
        ]
    
    def get_stats(self) -> Dict[str, int]:
        """Get memory statistics"""
        return {
            'total_engagements': self.session.query(Engagement).count(),
            'total_techniques': self.session.query(Technique).count(),
            'target_profiles': self.session.query(TargetProfile).count(),
            'learning_events': self.session.query(LearningEvent).count()
        }
    
    def close(self):
        """Close session"""
        self.session.close()
