"""Evidence Integrity and Protection module for MemoryMapper Lite.

Manages evidence manifests, software-level read-only protection,
non-destructive working copies for analysis, and verifiable integrity checks.
"""

import json
import os
import shutil
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from config.config import WORKSPACE_DIR
from core.chain_of_custody import ChainOfCustody
from core.hasher import Hasher
from utils.logger import logger
from utils.validators import validate_file_exists


class EvidenceIntegrity:
    """Provides evidence manifest creation, write protection, and working-copy management."""

    @staticmethod
    def create_evidence_manifest(
        case_dir: Path | str,
        case_id: str,
        evidence_id: str,
        original_filename: str,
        acquisition_start: str,
        acquisition_end: str,
        file_size: int,
        sha256_hash: str,
        operating_system: str,
        architecture: str,
        acquisition_method: str,
        acquisition_status: str,
        acquisition_mode: str = "REAL",
    ) -> Dict[str, Any]:
        """Creates and saves the official evidence_manifest.json record."""
        manifest_path = Path(case_dir) / "evidence_manifest.json"

        manifest_data = {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "original_filename": original_filename,
            "acquisition_mode": acquisition_mode,  # 'REAL' or 'DEMO'
            "acquisition_start_timestamp": acquisition_start,
            "acquisition_completion_timestamp": acquisition_end,
            "file_size_bytes": file_size,
            "sha256_hash": sha256_hash,
            "operating_system": operating_system,
            "architecture": architecture,
            "acquisition_method": acquisition_method,
            "acquisition_status": acquisition_status,
            "protection_status": "READ_ONLY_APPLIED",
            "manifest_created_at": datetime.now().isoformat(),
            "notes": (
                "Original memory evidence sealed. SHA-256 hash serves as the mathematical baseline "
                "to detect any subsequent modification or tampering."
            ),
        }

        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=4)
            logger.info(f"Evidence manifest created at: {manifest_path}")
        except Exception as e:
            logger.error(f"Failed to write evidence manifest: {e}")

        return manifest_data

    @staticmethod
    def load_manifest(case_dir: Path | str) -> Optional[Dict[str, Any]]:
        """Loads and parses the evidence_manifest.json if present."""
        path = Path(case_dir) / "evidence_manifest.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading evidence manifest: {e}")
            return None

    @staticmethod
    def apply_read_only_protection(file_path: Path | str) -> bool:
        """
        Applies OS-level read-only file attribute to prevent casual overwriting.
        Note: Software-level read-only provides basic protection from accidental changes,
        though users with root/admin access can alter file attributes.
        """
        path = Path(file_path)
        if not path.exists():
            return False

        try:
            # Set read-only permission (S_IREAD)
            current_mode = os.stat(path).st_mode
            os.chmod(path, stat.S_IREAD)
            logger.info(f"Applied read-only protection attribute to original evidence: {path.name}")
            return True
        except Exception as e:
            logger.warning(f"Could not set read-only attribute on {path}: {e}")
            return False

    @staticmethod
    def create_analysis_working_copy(original_dump_path: Path | str, case_id: str) -> Tuple[bool, Optional[Path], str]:
        """
        Copies the original evidence to the analysis_workspace so that
        forensic examination tools operate exclusively on a working replica,
        preserving the original primary evidence untouched.
        """
        orig = Path(original_dump_path)
        valid, msg = validate_file_exists(orig)
        if not valid:
            return False, None, f"Original evidence invalid: {msg}"

        case_workspace = WORKSPACE_DIR / case_id
        case_workspace.mkdir(parents=True, exist_ok=True)
        working_copy_path = case_workspace / f"working_copy_{orig.name}"

        try:
            # If working copy already exists and matches, reuse
            if working_copy_path.exists() and working_copy_path.stat().st_size == orig.stat().st_size:
                logger.info(f"Using existing analysis working copy: {working_copy_path}")
                return True, working_copy_path, "Reusing existing working copy."

            logger.info(f"Creating non-destructive analysis working copy: {orig.name} -> {working_copy_path}")
            shutil.copy2(orig, working_copy_path)

            # Ensure working copy is writable for forensic tool operations if needed
            os.chmod(working_copy_path, stat.S_IREAD | stat.S_IWRITE)

            return True, working_copy_path, "Working copy created successfully."
        except Exception as e:
            err = f"Failed to create analysis working copy: {e}"
            logger.error(err)
            return False, None, err

    @staticmethod
    def verify_case_integrity(case_dir: Path | str) -> Tuple[str, str, str, str]:
        """
        Performs full cryptographic verification of evidence against recorded baseline.
        
        Returns:
            (Status: 'INTEGRITY VERIFIED' | 'TAMPERING DETECTED' | 'ERROR',
             CurrentHash, ExpectedHash, Details)
        """
        case_path = Path(case_dir)
        manifest = EvidenceIntegrity.load_manifest(case_path)
        coc = ChainOfCustody(case_path)

        # Locate target file
        dump_candidates = [
            case_path / "memory.raw",
            case_path / "memory_dump.raw",
            case_path / "demo_memory.raw",
        ]
        target_file = None
        if manifest and manifest.get("original_filename"):
            cand = case_path / manifest["original_filename"]
            if cand.exists():
                target_file = cand

        if not target_file:
            for c in dump_candidates:
                if c.exists():
                    target_file = c
                    break

        if not target_file or not target_file.exists():
            msg = "Evidence file not found in case folder."
            coc.add_event(
                event_type="INTEGRITY_CHECK_FAILED",
                evidence_id=manifest.get("evidence_id", case_path.name) if manifest else case_path.name,
                description=msg,
                status="FAILED",
            )
            return "ERROR", "N/A", "N/A", msg

        # Read expected hash from manifest, fallback to metadata.json or hash.txt
        expected_hash = None
        if manifest and manifest.get("sha256_hash"):
            expected_hash = manifest["sha256_hash"]
        
        if not expected_hash:
            meta_path = case_path / "metadata.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        expected_hash = meta.get("sha256")
                except Exception:
                    pass

        if not expected_hash:
            hash_txt = case_path / "hash.txt"
            expected_hash = Hasher.read_stored_hash(hash_txt)

        if not expected_hash or expected_hash == "N/A":
            msg = "No reference SHA-256 baseline hash found."
            return "ERROR", "N/A", "N/A", msg

        # Calculate current hash
        try:
            current_hash = Hasher.calculate_sha256(target_file).lower()
            expected_clean = expected_hash.strip().lower()
            ev_id = manifest.get("evidence_id", case_path.name) if manifest else case_path.name

            if current_hash == expected_clean:
                status_str = "INTEGRITY VERIFIED"
                desc = f"Evidence SHA-256 matches baseline ({current_hash[:16]}...). No modification detected."
                coc.add_event(
                    event_type="EVIDENCE_INTEGRITY_VERIFIED",
                    evidence_id=ev_id,
                    description=desc,
                    status="VALID",
                    details={"calculated_hash": current_hash, "baseline_hash": expected_clean},
                )
                return status_str, current_hash, expected_clean, desc
            else:
                status_str = "TAMPERING DETECTED"
                desc = (
                    f"CRITICAL WARNING: Evidence hash mismatch! Current hash ({current_hash[:16]}...) "
                    f"differs from baseline ({expected_clean[:16]}...). File has been modified after acquisition."
                )
                coc.add_event(
                    event_type="EVIDENCE_TAMPERING_DETECTED",
                    evidence_id=ev_id,
                    description=desc,
                    status="TAMPERED",
                    details={"calculated_hash": current_hash, "baseline_hash": expected_clean},
                )
                return status_str, current_hash, expected_clean, desc
        except Exception as e:
            err = f"Verification error: {e}"
            return "ERROR", str(e), str(expected_hash), err
