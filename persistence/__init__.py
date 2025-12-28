"""
Persistence Mechanisms Module
Advanced persistence techniques
"""

from .persistence_manager import PersistenceManager
from .bootkit import BootkitDeployer
from .firmware import FirmwareImplant
from .uefi import UEFIPersistence, HypervisorPersistence
from .supply_chain import SupplyChainInsertion

__all__ = [
    'PersistenceManager',
    'BootkitDeployer',
    'FirmwareImplant',
    'UEFIPersistence',
    'HypervisorPersistence',
    'SupplyChainInsertion'
]
