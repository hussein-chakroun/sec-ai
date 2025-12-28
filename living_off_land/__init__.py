"""
Living Off The Land Module
Native OS tool abuse and fileless techniques
"""

from .lolbas_manager import LOLBASManager
from .windows_lol import WindowsLOL
from .linux_lol import LinuxLOL
from .fileless_executor import FilelessExecutor

__all__ = [
    'LOLBASManager',
    'WindowsLOL',
    'LinuxLOL',
    'FilelessExecutor'
]
