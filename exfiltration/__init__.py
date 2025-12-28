"""
Exfiltration Module
Data exfiltration techniques for penetration testing
"""

from .dns_exfil import DNSExfiltrator
from .steganography import SteganographyExfil
from .protocol_mimicry import ProtocolMimicry
from .slow_trickle import SlowTrickleExfil
from .multi_channel import MultiChannelExfil

__all__ = [
    'DNSExfiltrator',
    'SteganographyExfil',
    'ProtocolMimicry',
    'SlowTrickleExfil',
    'MultiChannelExfil'
]
