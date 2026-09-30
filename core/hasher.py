"""Cryptographic hashing and evidence integrity module for MemoryMapper Lite.

Calculates and verifies SHA-256 hashes for memory dumps and digital artifacts
to ensure forensic chain of custody and data integrity.
"""

import hashlib
from pathlib import Path
from typing import Optional, Tuple
from config.config import HASH_CHUNK_SIZE
from utils.logger import logger
from utils.validators import validate_file_exists


class Hasher:
    """Provides SHA-256 computation, verification, and file persistence."""

    @staticmethod
    def calculate_sha256(file_path: Path | str) -> str:
        """Calculates SHA-256 hash of a file using streaming chunks."""
        path = Path(file_path)
        valid, msg = validate_file_exists(path)
        if not valid:
            raise FileNotFoundError(f"Cannot hash file: {msg}")

        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                sha256_hash.update(chunk)
        
        computed_hash = sha256_hash.hexdigest()
        logger.debug(f"Computed SHA-256 for {path.name}: {computed_hash}")
        return computed_hash

    @staticmethod
    def save_hash_file(file_path: Path | str, output_hash_file: Path | str) -> str:
        """Calculates SHA-256 and writes it to a designated hash.txt file."""
        path = Path(file_path)
        out_path = Path(output_hash_file)
        
        digest = Hasher.calculate_sha256(path)
        
        content = (
            f"SHA-256 Evidence Integrity Record\n"
            f"Target File : {path.name}\n"
            f"File Size   : {path.stat().st_size} bytes\n"
            f"SHA-256     : {digest}\n"
        )
        
        out_path.write_text(content, encoding="utf-8")
        logger.info(f"Saved SHA-256 hash to {out_path}")
        return digest

    @staticmethod
    def read_stored_hash(hash_file_path: Path | str) -> Optional[str]:
        """Reads the recorded SHA-256 hash from a hash.txt file."""
        path = Path(hash_file_path)
        if not path.exists():
            return None
        
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "SHA-256" in line and ":" in line:
                parts = line.split(":", 1)
                candidate = parts[1].strip()
                if len(candidate) == 64 and all(c in "0123456789abcdefABCDEF" for c in candidate):
                    return candidate.lower()
        return None

    @staticmethod
    def verify_integrity(target_file: Path | str, expected_hash: str) -> Tuple[str, str, str]:
        """
        Verifies whether target file matches the expected hash.
        
        Returns:
            Tuple of (Status: 'VALID' | 'MODIFIED' | 'ERROR', CurrentHash, ExpectedHash)
        """
        try:
            current_hash = Hasher.calculate_sha256(target_file).lower()
            expected_clean = expected_hash.strip().lower()

            if current_hash == expected_clean:
                logger.info(f"Integrity check SUCCESS for {target_file}: VALID")
                return "VALID", current_hash, expected_clean
            else:
                logger.warning(f"Integrity check FAILED for {target_file}: MODIFIED! Current={current_hash}, Expected={expected_clean}")
                return "MODIFIED", current_hash, expected_clean
        except Exception as e:
            logger.error(f"Error during integrity verification: {e}")
            return "ERROR", str(e), expected_hash
