"""
Storage-focused operations for alert rules and configurations.

This module provides data persistence functionality for alert rules
and other configuration data. Uses file-based storage.

Note: Saved search functionality has been removed as part of tool consolidation.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from ...utils.logging import get_logger

logger = get_logger(__name__)

# Storage directory
STORAGE_DIR = Path.home() / ".syslog-mcp"
ALERT_RULES_FILE = STORAGE_DIR / "alert_rules.json"


def ensure_storage_dir() -> None:
    """Ensure storage directory exists."""
    STORAGE_DIR.mkdir(exist_ok=True)


def get_exports_directory() -> Path:
    """Get the exports directory, creating it if necessary."""
    exports_dir = os.getenv("SYSLOG_EXPORTS", "/tmp/syslog-exports")
    exports_path = Path(exports_dir)

    # Create directory if it doesn't exist
    try:
        exports_path.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Export directory ready: {exports_path}")
        return exports_path
    except Exception as e:
        logger.error(f"Failed to create exports directory {exports_path}: {e}")
        # Fallback to /tmp
        fallback_path = Path("/tmp/syslog-exports")
        fallback_path.mkdir(parents=True, exist_ok=True)
        logger.warning(f"Using fallback export directory: {fallback_path}")
        return fallback_path


def generate_export_filename(
    query: str | None = None,
    device: str | None = None,
    format_type: str = "json"
) -> str:
    """Generate a unique filename for export."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H%M%S")

    # Create a descriptive filename
    parts = ["syslog_export"]

    if device:
        # Sanitize device name for filename
        safe_device = "".join(c for c in device if c.isalnum() or c in "-_")[:20]
        parts.append(safe_device)

    if query:
        # Sanitize query for filename
        safe_query = "".join(c for c in query if c.isalnum() or c in "-_")[:15]
        parts.append(safe_query)

    parts.append(timestamp)

    # Validate format
    if format_type.lower() not in ["json", "csv"]:
        format_type = "json"

    filename = "_".join(parts) + f".{format_type.lower()}"
    return filename


def export_logs_query(
    query: str | None = None,
    device: str | None = None,
    level: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    format_type: str = "json"
) -> dict[str, Any]:
    """Generate export query parameters with file path."""

    # Validate format
    if format_type.lower() not in ["json", "csv"]:
        logger.warning(f"Invalid format '{format_type}', defaulting to 'json'")
        format_type = "json"

    # Generate export file path
    exports_dir = get_exports_directory()
    filename = generate_export_filename(query, device, format_type)
    export_path = exports_dir / filename

    export_config = {
        "query_params": {
            "query": query,
            "device": device,
            "level": level,
            "start_time": start_time,
            "end_time": end_time
        },
        "export_format": format_type.lower(),
        "export_path": str(export_path),
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "max_records": 10000  # Safety limit
    }

    return export_config


def load_alert_rules() -> dict[str, Any]:
    """Load alert rules from file."""
    ensure_storage_dir()

    if not ALERT_RULES_FILE.exists():
        return {"rules": {}, "created_at": datetime.utcnow().isoformat()}

    try:
        with open(ALERT_RULES_FILE) as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {"rules": {}, "created_at": datetime.utcnow().isoformat()}
    except Exception as e:
        logger.error(f"Error loading alert rules: {e}")
        return {"rules": {}, "created_at": datetime.utcnow().isoformat()}


def save_alert_rules_data(data: dict[str, Any]) -> bool:
    """Save alert rules data to file."""
    ensure_storage_dir()

    try:
        data["updated_at"] = datetime.utcnow().isoformat()
        with open(ALERT_RULES_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving alert rules: {e}")
        return False


def create_alert_rule(
    name: str,
    query: str,
    threshold: int,
    time_window: int,
    severity: str = "medium",
    description: str | None = None
) -> dict[str, Any]:
    """Create a new alert rule."""

    data = load_alert_rules()

    rule_entry = {
        "name": name,
        "query": query,
        "threshold": threshold,
        "time_window_minutes": time_window,
        "severity": severity,
        "description": description or "",
        "enabled": True,
        "created_at": datetime.utcnow().isoformat(),
        "last_triggered": None,
        "trigger_count": 0
    }

    data["rules"][name] = rule_entry

    if save_alert_rules_data(data):
        return {"success": True, "rule": rule_entry}
    else:
        return {"success": False, "error": "Failed to save alert rule"}


__all__ = [
    "export_logs_query",
    "get_exports_directory",
    "generate_export_filename",
    "create_alert_rule",
    "load_alert_rules"
]
