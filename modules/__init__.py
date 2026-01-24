"""
Pentesting modules initialization
"""
from .nmap_scanner import NmapScanner
from .sqlmap_scanner import SQLMapScanner
from .hydra_cracker import HydraCracker
from .metasploit_framework import MetasploitFramework, MSFVenom
from .reconnaissance_suite import (
    ReconnaissanceSuite,
    ReconnaissanceMode,
    DNSRecon,
    WhoisLookup,
    SubdomainEnumerator,
    PortScanner,
    ServiceEnumerator,
    OSDetector
)
from .osint_tools import (
    OSINTSuite,
    HaveIBeenPwnedChecker,
    SpiderFootScanner,
    IntelligenceXAPI,
    MaltegoTransform,
    OSINTFrameworkCollector
)
from .web_crawler import (
    WebCrawler,
    InformationGatherer
)

__all__ = [
    'NmapScanner',
    'SQLMapScanner', 
    'HydraCracker',
    'MetasploitFramework',
    'MSFVenom',
    'ReconnaissanceSuite',
    'ReconnaissanceMode',
    'DNSRecon',
    'WhoisLookup',
    'SubdomainEnumerator',
    'PortScanner',
    'ServiceEnumerator',
    'OSDetector',
    'OSINTSuite',
    'HaveIBeenPwnedChecker',
    'SpiderFootScanner',
    'IntelligenceXAPI',
    'MaltegoTransform',
    'OSINTFrameworkCollector',
    'WebCrawler',
    'InformationGatherer'
]
