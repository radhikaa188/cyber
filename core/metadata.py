"""Evidence metadata management for MemoryMapper Lite.

Structures, validates, serializes, and deserializes metadata.json records
for each memory acquisition case.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from utils.logger import logger


class CaseMetadata:
    """Handles case metadata schema creation, saving, and loading."""

    @staticmethod
    def create_metadata_record(
        case_id: str,
        os_name: str,
        architecture: str,
        python_version: str,
        dump_file_name: str,
        dump_size_bytes: int,
        sha256: str,
        acquisition_status: str,
        acquisition_mode: str,
        acquisition_start: str,
        acquisition_end: str,
        is_admin: bool,
        tool_used: str,
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Builds standardized metadata dictionary."""
        record = {
            "case_id": case_id,
            "timestamp": acquisition_start,
            "acquisition_start": acquisition_start,
            "acquisition_end": acquisition_end,
            "os": os_name,
            "architecture": architecture,
            "python_version": python_version,
            "dump_file": dump_file_name,
            "dump_size_bytes": dump_size_bytes,
            "sha256": sha256,
            "acquisition_status": acquisition_status,
            "acquisition_mode": acquisition_mode,  # 'REAL' or 'DEMO'
            "is_admin": is_admin,
            "tool_used": tool_used,
            "additional_info": additional_info or {},
        }
        return record

    @staticmethod
    def save_metadata(metadata_dict: Dict[str, Any], output_path: Path | str) -> None:
        """Saves metadata dict to metadata.json."""
        path = Path(output_path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(metadata_dict, f, indent=4)
        logger.info(f"Saved metadata record to {path}")

    @staticmethod
    def load_metadata(file_path: Path | str) -> Dict[str, Any]:
        """Loads and parses metadata.json."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Metadata file not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
