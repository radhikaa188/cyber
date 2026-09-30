"""Core package for MemoryMapper Lite."""
from core.acquisition import AcquisitionManager, BaseAcquisition
from core.chain_of_custody import ChainOfCustody
from core.evidence_integrity import EvidenceIntegrity
from core.evidence_manager import CaseEvidence, EvidenceManager
from core.hasher import Hasher
from core.metadata import CaseMetadata
from core.system_detector import SystemDetector

__all__ = [
    "AcquisitionManager",
    "BaseAcquisition",
    "ChainOfCustody",
    "EvidenceIntegrity",
    "CaseEvidence",
    "EvidenceManager",
    "Hasher",
    "CaseMetadata",
    "SystemDetector",
]
