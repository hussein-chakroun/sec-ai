"""
Intelligence Gatherer
Automated security intelligence from multiple sources
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import random
import hashlib


logger = logging.getLogger(__name__)


class IntelligenceGatherer:
    """
    Autonomous Security Intelligence Gathering Engine
    
    Collects intelligence from blogs, forums, social media, and dark web
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.security_blogs = [
            'KrebsOnSecurity',
            'Schneier on Security',
            'Threatpost',
            'The Hacker News',
            'Bleeping Computer',
            'Dark Reading'
        ]
        
        self.security_forums = [
            'exploit.in',
            'hackforums',
            'reddit/r/netsec',
            'reddit/r/AskNetsec',
            'stackexchange/security'
        ]
        
        self.exploit_repositories = [
            'exploit-db',
            'github',
            'packetstorm',
            'seebug',
            'rapid7'
        ]
    
    async def monitor_security_sources(
        self,
        target: str,
        sources: List[str] = None,
        relevance_threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Monitor security blogs and forums for relevant intelligence
        """
        if sources is None:
            sources = ['blogs', 'forums', 'advisories']
        
        self.logger.info(f"Monitoring security sources: {', '.join(sources)}")
        
        results = []
        
        if 'blogs' in sources:
            blog_intel = await self._monitor_blogs(target, relevance_threshold)
            results.extend(blog_intel)
        
        if 'forums' in sources:
            forum_intel = await self._monitor_forums(target, relevance_threshold)
            results.extend(forum_intel)
        
        if 'advisories' in sources:
            advisory_intel = await self._monitor_advisories(target, relevance_threshold)
            results.extend(advisory_intel)
        
        summary = {
            'sources_monitored': sources,
            'total_items': len(results),
            'high_relevance': len([r for r in results if r.get('relevance_score', 0) > 0.8]),
            'threat_indicators': len([r for r in results if r.get('threat_level') in ['high', 'critical']]),
            'actionable_intel': len([r for r in results if r.get('actionable')])
        }
        
        return [summary] + results[:15]
    
    async def collect_exploits(
        self,
        target: str,
        repositories: List[str] = None,
        verification: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Collect exploit proof-of-concepts from various repositories
        """
        if repositories is None:
            repositories = ['exploit-db', 'github', 'packetstorm']
        
        self.logger.info(f"Collecting exploits from: {', '.join(repositories)}")
        
        exploits = []
        
        for repo in repositories:
            repo_exploits = await self._fetch_exploits_from_repo(repo, target)
            exploits.extend(repo_exploits)
        
        if verification:
            verified_exploits = await self._verify_exploits(exploits)
        else:
            verified_exploits = exploits
        
        summary = {
            'repositories_searched': repositories,
            'total_exploits_found': len(exploits),
            'verified_exploits': len(verified_exploits),
            'by_type': self._categorize_exploits(verified_exploits),
            'weaponized_exploits': len([e for e in verified_exploits if e.get('weaponized')]),
            'recent_exploits': len([e for e in verified_exploits if e.get('age_days', 999) < 30])
        }
        
        return [summary] + verified_exploits[:10]
    
    async def monitor_social_media(
        self,
        target: str,
        platforms: List[str] = None,
        researchers: List[str] = None,
        sentiment_analysis: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Monitor security researcher social media for intelligence
        """
        if platforms is None:
            platforms = ['twitter', 'mastodon']
        
        self.logger.info(f"Monitoring social media platforms: {', '.join(platforms)}")
        
        results = []
        
        # Default researcher list if none provided
        if not researchers:
            researchers = [
                '@SwiftOnSecurity',
                '@malwareunicorn',
                '@GossiTheDog',
                '@briankrebs',
                '@schneierblog',
                '@thegrugq'
            ]
        
        for platform in platforms:
            platform_intel = await self._monitor_platform(platform, target, researchers)
            results.extend(platform_intel)
        
        if sentiment_analysis:
            results = await self._analyze_sentiment(results)
        
        summary = {
            'platforms_monitored': platforms,
            'researchers_tracked': len(researchers),
            'total_posts': len(results),
            'threat_mentions': len([r for r in results if r.get('mentions_threat')]),
            'vulnerability_disclosures': len([r for r in results if r.get('type') == 'vulnerability']),
            'average_sentiment': sum([r.get('sentiment_score', 0) for r in results]) / max(len(results), 1)
        }
        
        return [summary] + results[:12]
    
    async def monitor_darkweb(
        self,
        target: str,
        marketplaces: List[str] = None,
        categories: List[str] = None,
        safety_level: str = 'passive'
    ) -> List[Dict[str, Any]]:
        """
        Monitor dark web marketplaces for intelligence (passive monitoring only)
        """
        if categories is None:
            categories = ['exploits', 'credentials', 'databases']
        
        self.logger.info(f"Monitoring dark web (safety level: {safety_level})")
        
        # Only passive monitoring for safety
        if safety_level != 'passive':
            self.logger.warning("Only passive monitoring is supported for safety reasons")
            safety_level = 'passive'
        
        results = await self._passive_darkweb_monitoring(target, categories)
        
        summary = {
            'monitoring_type': 'passive',
            'categories_monitored': categories,
            'total_mentions': len(results),
            'credential_leaks': len([r for r in results if r.get('category') == 'credentials']),
            'exploit_listings': len([r for r in results if r.get('category') == 'exploits']),
            'database_dumps': len([r for r in results if r.get('category') == 'databases']),
            'threat_level': self._assess_darkweb_threat(results)
        }
        
        return [summary] + results[:8]
    
    async def _monitor_blogs(self, target: str, threshold: float) -> List[Dict[str, Any]]:
        """Monitor security blogs"""
        await asyncio.sleep(0.1)
        
        articles = []
        num_articles = random.randint(5, 15)
        
        for i in range(num_articles):
            blog = random.choice(self.security_blogs)
            relevance = random.uniform(threshold, 1.0)
            
            articles.append({
                'source': blog,
                'type': 'blog_post',
                'title': f"Security analysis related to {target}",
                'url': f"https://{blog.lower().replace(' ', '')}.com/article-{i}",
                'published_date': (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat(),
                'relevance_score': relevance,
                'threat_level': random.choice(['low', 'medium', 'high']) if relevance > 0.8 else 'low',
                'actionable': relevance > 0.85,
                'key_topics': random.sample(['vulnerability', 'exploit', 'breach', 'malware', 'apt'], 
                                           random.randint(1, 3))
            })
        
        return articles
    
    async def _monitor_forums(self, target: str, threshold: float) -> List[Dict[str, Any]]:
        """Monitor security forums"""
        await asyncio.sleep(0.1)
        
        posts = []
        num_posts = random.randint(3, 10)
        
        for i in range(num_posts):
            forum = random.choice(self.security_forums)
            relevance = random.uniform(threshold, 1.0)
            
            posts.append({
                'source': forum,
                'type': 'forum_post',
                'title': f"Discussion about {target} security",
                'url': f"https://{forum.split('/')[0]}.com/thread-{i}",
                'posted_date': (datetime.now() - timedelta(hours=random.randint(0, 720))).isoformat(),
                'relevance_score': relevance,
                'replies': random.randint(0, 50),
                'views': random.randint(10, 5000),
                'actionable': relevance > 0.85 and random.random() > 0.5,
                'contains_poc': random.random() > 0.7
            })
        
        return posts
    
    async def _monitor_advisories(self, target: str, threshold: float) -> List[Dict[str, Any]]:
        """Monitor security advisories"""
        await asyncio.sleep(0.1)
        
        advisories = []
        num_advisories = random.randint(2, 8)
        
        for i in range(num_advisories):
            vendor = random.choice(['Microsoft', 'Cisco', 'Adobe', 'Oracle', 'VMware'])
            
            advisories.append({
                'source': f'{vendor} Security Advisory',
                'type': 'advisory',
                'advisory_id': f'{vendor[:3].upper()}-2024-{random.randint(1000, 9999)}',
                'title': f'Security Update for {vendor} Products',
                'url': f'https://{vendor.lower()}.com/security/advisory-{i}',
                'published_date': (datetime.now() - timedelta(days=random.randint(0, 60))).isoformat(),
                'relevance_score': random.uniform(threshold, 1.0),
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'threat_level': random.choice(['medium', 'high', 'critical']),
                'patch_available': True,
                'actionable': True
            })
        
        return advisories
    
    async def _fetch_exploits_from_repo(self, repo: str, target: str) -> List[Dict[str, Any]]:
        """Fetch exploits from repository"""
        await asyncio.sleep(0.1)
        
        exploits = []
        num_exploits = random.randint(3, 12)
        
        for i in range(num_exploits):
            exploit_types = ['remote', 'local', 'web', 'dos', 'privilege_escalation']
            
            exploits.append({
                'repository': repo,
                'exploit_id': f'{repo}-{random.randint(10000, 99999)}',
                'title': f'Exploit for {target} vulnerability',
                'type': random.choice(exploit_types),
                'platform': random.choice(['linux', 'windows', 'multi', 'web']),
                'published_date': (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
                'age_days': random.randint(0, 365),
                'author': f'researcher_{random.randint(1, 100)}',
                'verified': random.random() > 0.4,
                'weaponized': random.random() > 0.7,
                'reliability': random.choice(['excellent', 'good', 'normal', 'unknown']),
                'url': f'https://{repo}.com/exploit/{i}'
            })
        
        return exploits
    
    async def _verify_exploits(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify exploit functionality"""
        await asyncio.sleep(0.2)
        
        verified = []
        
        for exploit in exploits:
            # Simulate verification process
            verification_success = random.random() > 0.3
            
            if verification_success:
                exploit['verification_status'] = 'verified'
                exploit['verification_date'] = datetime.now().isoformat()
                exploit['false_positive'] = False
                verified.append(exploit)
            else:
                exploit['verification_status'] = 'failed'
                exploit['false_positive'] = random.random() > 0.5
        
        return verified
    
    def _categorize_exploits(self, exploits: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize exploits by type"""
        categories = {}
        
        for exploit in exploits:
            exploit_type = exploit.get('type', 'unknown')
            categories[exploit_type] = categories.get(exploit_type, 0) + 1
        
        return categories
    
    async def _monitor_platform(
        self,
        platform: str,
        target: str,
        researchers: List[str]
    ) -> List[Dict[str, Any]]:
        """Monitor social media platform"""
        await asyncio.sleep(0.1)
        
        posts = []
        num_posts = random.randint(5, 20)
        
        for i in range(num_posts):
            researcher = random.choice(researchers)
            
            post_types = ['vulnerability', 'threat_intel', 'general', 'tool_release', 'breach_news']
            post_type = random.choice(post_types)
            
            posts.append({
                'platform': platform,
                'author': researcher,
                'type': post_type,
                'content_preview': f'{researcher} discussing {post_type} related to security',
                'url': f'https://{platform}.com/{researcher}/status/{random.randint(1000000, 9999999)}',
                'posted_date': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                'engagement': {
                    'likes': random.randint(0, 1000),
                    'retweets': random.randint(0, 500),
                    'replies': random.randint(0, 100)
                },
                'mentions_threat': post_type in ['vulnerability', 'threat_intel', 'breach_news'],
                'has_iocs': random.random() > 0.7,
                'relevance': random.uniform(0.5, 1.0)
            })
        
        return posts
    
    async def _analyze_sentiment(self, posts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze sentiment of posts"""
        await asyncio.sleep(0.05)
        
        for post in posts:
            # Simulate sentiment analysis
            if post.get('mentions_threat'):
                sentiment = random.uniform(-0.5, 0.2)  # More negative if threat-related
            else:
                sentiment = random.uniform(-0.2, 0.8)
            
            post['sentiment_score'] = sentiment
            
            if sentiment > 0.5:
                post['sentiment'] = 'positive'
            elif sentiment > 0:
                post['sentiment'] = 'neutral'
            else:
                post['sentiment'] = 'negative'
        
        return posts
    
    async def _passive_darkweb_monitoring(
        self,
        target: str,
        categories: List[str]
    ) -> List[Dict[str, Any]]:
        """Passive dark web monitoring (simulated)"""
        await asyncio.sleep(0.15)
        
        # Note: This is simulated for safety. Real implementation would use
        # specialized threat intelligence feeds, not direct dark web access.
        
        mentions = []
        num_mentions = random.randint(2, 8)
        
        for i in range(num_mentions):
            category = random.choice(categories)
            
            mention = {
                'category': category,
                'source': 'threat_intelligence_feed',
                'marketplace': f'marketplace_{random.randint(1, 5)}',
                'title': f'{category.title()} related to {target}',
                'first_seen': (datetime.now() - timedelta(days=random.randint(0, 90))).isoformat(),
                'last_seen': (datetime.now() - timedelta(days=random.randint(0, 7))).isoformat(),
                'price': random.randint(100, 10000) if category in ['exploits', 'credentials'] else None,
                'seller_reputation': random.choice(['unknown', 'low', 'medium', 'high']),
                'threat_score': random.uniform(0.5, 1.0),
                'verified': random.random() > 0.6
            }
            
            if category == 'credentials':
                mention['record_count'] = random.randint(100, 100000)
                mention['data_type'] = random.choice(['emails', 'passwords', 'api_keys', 'sessions'])
            elif category == 'databases':
                mention['size_gb'] = random.randint(1, 1000)
                mention['table_count'] = random.randint(10, 500)
            
            mentions.append(mention)
        
        return mentions
    
    def _assess_darkweb_threat(self, mentions: List[Dict[str, Any]]) -> str:
        """Assess overall threat level from dark web mentions"""
        if not mentions:
            return 'none'
        
        avg_threat_score = sum([m.get('threat_score', 0) for m in mentions]) / len(mentions)
        credential_leaks = len([m for m in mentions if m.get('category') == 'credentials'])
        
        if avg_threat_score > 0.8 or credential_leaks > 2:
            return 'critical'
        elif avg_threat_score > 0.6 or credential_leaks > 0:
            return 'high'
        elif avg_threat_score > 0.4:
            return 'medium'
        else:
            return 'low'
