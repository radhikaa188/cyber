"""Analysis interface and standardized schema for MemoryMapper Lite.

Defines base analyzer contract and structured result containers for DFIR findings.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ForensicAnalysisResult:
    """Standard container for memory forensics findings."""
    analyzer_name: str
    status: str  # 'SUCCESS', 'PARTIAL', 'NOT AVAILABLE', 'FAILED'
    os_detected: str = "Unknown"
    dump_path: str = ""
    dump_size_bytes: int = 0
    signatures_found: List[str] = field(default_factory=list)
    processes: List[Dict[str, Any]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)
    extracted_strings: Dict[str, List[str]] = field(default_factory=dict)
    summary_notes: str = ""
    errors_and_limitations: List[str] = field(default_factory=list)
    analysis_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts result object to clean JSON-serializable dictionary."""
        return asdict(self)


class BaseAnalyzer(ABC):
    """Abstract interface for memory forensic analyzers."""

    @abstractmethod
    def analyze(self, dump_file_path: Path | str) -> ForensicAnalysisResult:
        """Performs analysis on a memory dump file and returns structured results."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the forensic analyzer engine."""
        pass
