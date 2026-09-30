"""Evidence directory and artifact management for MemoryMapper Lite.

Manages evidence folders, standardized file naming, chain of custody records,
manifest discovery, and overwrite prevention.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from config.config import EVIDENCE_DIR
from core.chain_of_custody import ChainOfCustody
from core.metadata import CaseMetadata
from utils.logger import logger
from utils.validators import validate_case_folder


class CaseEvidence:
    """Represents a single evidence case bundle."""

    def __init__(self, case_dir: Path):
        self.case_dir = case_dir
        self.case_id = case_dir.name
        self.metadata_file = case_dir / "metadata.json"
        self.manifest_file = case_dir / "evidence_manifest.json"
        self.custody_file = case_dir / "chain_of_custody.json"
        self.hash_file = case_dir / "hash.txt"
        self.report_json_file = case_dir / "forensic_report.json"
        self.dump_file: Optional[Path] = self._locate_dump_file()

    def _locate_dump_file(self) -> Optional[Path]:
        """Locates the memory dump or test image in the case folder."""
        for candidate in ["memory.raw", "memory_dump.raw", "demo_memory.raw", "memory.bin", "memory.dmp"]:
            p = self.case_dir / candidate
            if p.exists():
                return p
        # Check manifest or metadata
        if self.manifest_file.exists():
            try:
                import json
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    df = data.get("original_filename")
                    if df:
                        p = self.case_dir / df
                        if p.exists():
                            return p
            except Exception:
                pass
        for f in self.case_dir.glob("*"):
            if f.suffix.lower() in [".raw", ".bin", ".dmp", ".mem", ".img"]:
                return f
        return None

    def get_metadata(self) -> Optional[Dict]:
        """Loads and returns the case metadata if present."""
        if self.metadata_file.exists():
            return CaseMetadata.load_metadata(self.metadata_file)
        return None

    def get_manifest(self) -> Optional[Dict]:
        """Loads and returns the evidence manifest if present."""
        if self.manifest_file.exists():
            try:
                import json
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    def get_custody(self) -> ChainOfCustody:
        """Returns ChainOfCustody manager for this case."""
        return ChainOfCustody(self.case_dir)


class EvidenceManager:
    """Creates, validates, and manages case evidence directories with overwrite protection."""

    @staticmethod
    def generate_case_id(prefix: str = "CASE") -> str:
        """Generates a timestamped case ID: CASE_YYYYMMDD_HHMMSS."""
        now = datetime.now()
        return f"{prefix}_{now.strftime('%Y%m%d_%H%M%S')}"

    @staticmethod
    def create_case_folder(case_id: Optional[str] = None) -> Path:
        """
        Creates a new unique case evidence directory.
        Implements strict duplicate/overwrite prevention.
        """
        if not case_id:
            case_id = EvidenceManager.generate_case_id()

        case_path = EVIDENCE_DIR / case_id

        # Overwrite prevention: if folder exists, append disambiguation suffix
        counter = 1
        base_path = case_path
        while case_path.exists():
            case_path = EVIDENCE_DIR / f"{base_path.name}_{counter:02d}"
            counter += 1

        case_path.mkdir(parents=True, exist_ok=False)
        logger.info(f"Created secure evidence case directory: {case_path}")
        return case_path

    @staticmethod
    def list_all_cases() -> List[CaseEvidence]:
        """Discovers and returns all existing case folders sorted newest first."""
        cases: List[CaseEvidence] = []
        if not EVIDENCE_DIR.exists():
            return cases

        for child in sorted(EVIDENCE_DIR.iterdir(), reverse=True):
            if child.is_dir():
                cases.append(CaseEvidence(child))
        return cases

    @staticmethod
    def get_latest_case() -> Optional[CaseEvidence]:
        """Returns the most recent valid case, or None."""
        cases = EvidenceManager.list_all_cases()
        return cases[0] if cases else None

    @staticmethod
    def get_case_by_id(case_id: str) -> Optional[CaseEvidence]:
        """Finds a case by exact or partial case ID."""
        for case in EvidenceManager.list_all_cases():
            if case.case_id.lower() == case_id.lower() or case.case_id.lower().startswith(case_id.lower()):
                return case
        return None
