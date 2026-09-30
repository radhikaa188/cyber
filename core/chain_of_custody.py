"""Chain of Custody and Audit Logging module for MemoryMapper Lite.

Tracks every interaction, acquisition event, hash computation, verification check,
and analysis action performed on forensic evidence items to maintain a strict,
verifiable audit trail (ISO/IEC 27037).
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from utils.logger import logger


class ChainOfCustody:
    """Manages the chronological record of evidence custody and verification events."""

    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.log_file = self.case_dir / "chain_of_custody.json"
        self._events: List[Dict[str, Any]] = self._load_events()

    def _load_events(self) -> List[Dict[str, Any]]:
        """Loads existing custody events from disk or initializes an empty list."""
        if self.log_file.exists():
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return data
                    elif isinstance(data, dict) and "events" in data:
                        return data["events"]
            except Exception as e:
                logger.error(f"Error loading chain of custody log: {e}")
        return []

    def _save_events(self) -> None:
        """Persists the event chain to chain_of_custody.json."""
        try:
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(self._events, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to persist chain of custody event log: {e}")

    def add_event(
        self,
        event_type: str,
        evidence_id: str,
        description: str,
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Appends a new immutable audit record to the chain of custody."""
        event_number = len(self._events) + 1
        event_id = f"EVT-{event_number:03d}"
        now_iso = datetime.now().isoformat()

        event_record = {
            "event_id": event_id,
            "timestamp": now_iso,
            "event": event_type,
            "evidence_id": evidence_id,
            "description": description,
            "status": status,
            "details": details or {},
        }

        self._events.append(event_record)
        self._save_events()
        logger.info(f"Chain of Custody [{event_id}]: {event_type} - {description} ({status})")
        return event_record

    def get_events(self) -> List[Dict[str, Any]]:
        """Returns the full chronological list of custody events."""
        return self._events

    def get_summary_text(self) -> str:
        """Returns a human-readable CLI summary of the custody trail."""
        if not self._events:
            return "No chain-of-custody events recorded for this case."

        lines = [
            f"{'Event ID':<9} {'Timestamp':<25} {'Event Type':<25} {'Status':<12}",
            "-" * 75,
        ]
        for ev in self._events:
            lines.append(
                f"{ev.get('event_id', 'N/A'):<9} "
                f"{ev.get('timestamp', 'N/A')[:19]:<25} "
                f"{ev.get('event', 'N/A'):<25} "
                f"{ev.get('status', 'N/A'):<12}"
            )
            desc = ev.get('description', '')
            if desc:
                lines.append(f"  -> Description: {desc}")
        lines.append("-" * 75)
        return "\n".join(lines)
