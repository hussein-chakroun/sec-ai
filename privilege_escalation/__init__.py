"""
Privilege Escalation Module
Automated privilege escalation techniques
"""

from .kernel_exploit_db import KernelExploitDatabase
from .misconfiguration_enum import MisconfigurationEnumerator
from .token_manipulation import TokenManipulator
from .process_injection import ProcessInjector
from .dll_hijacking import DLLHijacker

__all__ = [
    'KernelExploitDatabase',
    'MisconfigurationEnumerator',
    'TokenManipulator',
    'ProcessInjector',
    'DLLHijacker',
]
