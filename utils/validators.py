"""Validation utilities for MemoryMapper Lite."""

import os
from pathlib import Path
from typing import Optional, Tuple


def validate_file_exists(file_path: Path | str) -> Tuple[bool, str]:
    """Check if a file exists and is a non-empty regular file."""
    if not file_path:
        return False, "File path is empty or None."
    
    path = Path(file_path)
    if not path.exists():
        return False, f"File does not exist: {path}"
    if not path.is_file():
        return False, f"Path is not a regular file: {path}"
    
    try:
        size = path.stat().st_size
        if size == 0:
            return False, f"File is empty (0 bytes): {path}"
    except Exception as e:
        return False, f"Cannot read file size: {e}"

    return True, "File is valid."


def validate_directory_exists(dir_path: Path | str) -> Tuple[bool, str]:
    """Check if a directory exists and is accessible."""
    if not dir_path:
        return False, "Directory path is empty."
    
    path = Path(dir_path)
    if not path.exists():
        return False, f"Directory does not exist: {path}"
    if not path.is_dir():
        return False, f"Path is not a directory: {path}"

    return True, "Directory is valid."


def validate_case_folder(case_path: Path | str) -> Tuple[bool, str]:
    """Validates that a case directory contains expected evidence artifacts."""
    valid_dir, msg = validate_directory_exists(case_path)
    if not valid_dir:
        return False, msg

    path = Path(case_path)
    meta_path = path / "metadata.json"
    if not meta_path.exists():
        return False, f"Missing metadata.json in case folder: {path}"

    return True, "Case folder is valid."


def sanitize_filename(filename: str) -> str:
    """Sanitizes user input for filenames to prevent path traversal."""
    cleaned = filename.replace("/", "_").replace("\\", "_").replace("..", "_")
    clean = "".join(c for c in cleaned if c.isalnum() or c in ("-", "_", "."))
    clean = clean.lstrip(".")
    return clean or "unnamed_case"
