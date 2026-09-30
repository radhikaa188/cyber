"""Common abstraction and controller for memory acquisition in MemoryMapper Lite.

Delegates execution to OS-specific acquisition drivers or Demo mode,
records Chain of Custody events, seals evidence with SHA-256, applies
read-only protection, and generates the evidence manifest.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from core.chain_of_custody import ChainOfCustody
from core.evidence_integrity import EvidenceIntegrity
from core.evidence_manager import EvidenceManager
from core.hasher import Hasher
from core.metadata import CaseMetadata
from core.system_detector import SystemDetector
from utils.logger import logger


class BaseAcquisition(ABC):
    """Abstract Base Class for OS-specific memory acquisition modules."""

    @abstractmethod
    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifies if required tools, drivers, and permissions are met."""
        pass

    @abstractmethod
    def acquire(self, target_dump_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Performs memory acquisition.
        
        Returns:
            (Success: bool, Message: str, ExecutionDetails: dict)
        """
        pass

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name of the underlying acquisition utility."""
        pass


class AcquisitionManager:
    """Orchestrates memory acquisition workflow, evidence packaging, hashing, and metadata."""

    def __init__(self, acquisition_driver: BaseAcquisition, mode: str = "REAL"):
        self.driver = acquisition_driver
        self.mode = mode  # 'REAL' or 'DEMO'

    def run_workflow(self, custom_case_id: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Executes full acquisition pipeline:
        1. System check & Prerequisite validation
        2. Case directory creation
        3. Real/Demo RAM acquisition
        4. SHA-256 computation and preservation
        5. Evidence manifest & Chain of Custody initialization
        6. Apply OS-level read-only protection to original evidence
        7. Metadata record generation
        """
        system_info = SystemDetector.get_system_summary()
        case_id = custom_case_id or EvidenceManager.generate_case_id(
            prefix="DEMO_CASE" if self.mode == "DEMO" else "CASE"
        )
        evidence_id = f"EVD_{case_id.replace('CASE_', '').replace('DEMO_CASE_', '')}"
        
        logger.info(f"Starting acquisition workflow [{self.mode}] for Case: {case_id}")
        start_time = datetime.now().isoformat()

        # Step 1: Check prerequisites
        ready, prereq_msg = self.driver.check_prerequisites()
        if not ready:
            err = f"Prerequisite check failed: {prereq_msg}"
            logger.error(err)
            return False, err, {"case_id": case_id, "status": "FAILED"}

        # Step 2: Create evidence folder
        case_dir = EvidenceManager.create_case_folder(case_id)
        coc = ChainOfCustody(case_dir)

        # Log Acquisition Start
        coc.add_event(
            event_type="ACQUISITION_INITIALIZED",
            evidence_id=evidence_id,
            description=f"Acquisition pipeline started in mode [{self.mode}] using {self.driver.tool_name}.",
            status="INITIALIZED",
            details={"mode": self.mode, "os": system_info["os_name"], "tool": self.driver.tool_name},
        )

        dump_filename = "demo_memory.raw" if self.mode == "DEMO" else "memory.raw"
        dump_path = case_dir / dump_filename

        # Step 3: Run acquisition
        logger.info(f"Writing memory dump to {dump_path}...")
        success, acq_msg, details = self.driver.acquire(dump_path)
        end_time = datetime.now().isoformat()

        if not success:
            logger.error(f"Acquisition failed: {acq_msg}")
            coc.add_event(
                event_type="ACQUISITION_FAILED",
                evidence_id=evidence_id,
                description=f"RAM acquisition failed: {acq_msg}",
                status="FAILED",
                details=details,
            )
            # Write failure metadata
            meta = CaseMetadata.create_metadata_record(
                case_id=case_id,
                os_name=system_info["os_name"],
                architecture=system_info["architecture"],
                python_version=system_info["python_version"],
                dump_file_name=dump_filename,
                dump_size_bytes=0,
                sha256="N/A",
                acquisition_status="FAILED",
                acquisition_mode=self.mode,
                acquisition_start=start_time,
                acquisition_end=end_time,
                is_admin=system_info["is_admin"],
                tool_used=self.driver.tool_name,
                additional_info={"error": acq_msg, **details},
            )
            CaseMetadata.save_metadata(meta, case_dir / "metadata.json")
            return False, acq_msg, meta

        # Record successful acquisition
        dump_size = dump_path.stat().st_size
        coc.add_event(
            event_type="MEMORY_ACQUIRED",
            evidence_id=evidence_id,
            description=f"Physical RAM image acquired ({dump_size:,} bytes) at {dump_path.name}.",
            status="SUCCESS",
            details={"file_name": dump_filename, "size_bytes": dump_size},
        )

        # Step 4: Calculate SHA-256 & save hash file
        try:
            sha256_hash = Hasher.save_hash_file(dump_path, case_dir / "hash.txt")
            coc.add_event(
                event_type="HASH_GENERATED",
                evidence_id=evidence_id,
                description=f"Cryptographic SHA-256 seal computed: {sha256_hash}",
                status="SUCCESS",
                details={"sha256": sha256_hash, "algorithm": "SHA-256"},
            )
        except Exception as e:
            err = f"Failed to compute SHA-256 for acquired image: {e}"
            logger.error(err)
            return False, err, {}

        # Step 5: Create Evidence Manifest
        manifest = EvidenceIntegrity.create_evidence_manifest(
            case_dir=case_dir,
            case_id=case_id,
            evidence_id=evidence_id,
            original_filename=dump_filename,
            acquisition_start=start_time,
            acquisition_end=end_time,
            file_size=dump_size,
            sha256_hash=sha256_hash,
            operating_system=system_info["os_name"],
            architecture=system_info["architecture"],
            acquisition_method=self.driver.tool_name,
            acquisition_status="SUCCESS",
            acquisition_mode=self.mode,
        )
        coc.add_event(
            event_type="EVIDENCE_MANIFEST_CREATED",
            evidence_id=evidence_id,
            description="Official evidence manifest created (evidence_manifest.json).",
            status="SUCCESS",
        )

        # Step 6: Apply OS-level read-only protection
        protected = EvidenceIntegrity.apply_read_only_protection(dump_path)
        if protected:
            coc.add_event(
                event_type="EVIDENCE_PROTECTED",
                evidence_id=evidence_id,
                description="OS-level read-only file attribute applied to prevent accidental alteration.",
                status="PROTECTED",
            )

        # Step 7: Save complete metadata record
        meta = CaseMetadata.create_metadata_record(
            case_id=case_id,
            os_name=system_info["os_name"],
            architecture=system_info["architecture"],
            python_version=system_info["python_version"],
            dump_file_name=dump_filename,
            dump_size_bytes=dump_size,
            sha256=sha256_hash,
            acquisition_status="SUCCESS",
            acquisition_mode=self.mode,
            acquisition_start=start_time,
            acquisition_end=end_time,
            is_admin=system_info["is_admin"],
            tool_used=self.driver.tool_name,
            additional_info=details,
        )
        CaseMetadata.save_metadata(meta, case_dir / "metadata.json")

        logger.info(f"Acquisition pipeline completed successfully for Case: {case_id}")
        return True, "Acquisition, cryptographic sealing, and evidence manifest complete.", meta
