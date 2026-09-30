"""Logging utility for MemoryMapper Lite."""

import logging
import sys
from pathlib import Path
from config.config import LOG_FILE


def setup_logger(name: str = "MemoryMapper") -> logging.Logger:
    """Configures and returns a logger instance writing to both file and console."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(logging.INFO)

        # File Handler
        try:
            file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] (%(module)s:%(lineno)d): %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"[!] Warning: Could not initialize file logging: {e}", file=sys.stderr)

        # Console Handler (terse / clean)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter("[%(levelname)s] %(message)s")
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger


logger = setup_logger()
