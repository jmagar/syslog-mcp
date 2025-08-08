"""
Storage-focused operations for saved searches and configurations.

This module provides data persistence functionality for saved searches,
alert rules, and other configuration data. Uses file-based storage.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...utils.logging import get_logger

logger = get_logger(__name__)

# Storage directory
STORAGE_DIR = Path.home() / ".syslog-mcp"
SAVED_SEARCHES_FILE = STORAGE_DIR / "saved_searches.json"
ALERT_RULES_FILE = STORAGE_DIR / "alert_rules.json"


def ensure_storage_dir():
    """Ensure storage directory exists."""
    STORAGE_DIR.mkdir(exist_ok=True)


def load_saved_searches() -> Dict[str, Any]:
    """Load saved searches from file."""
    ensure_storage_dir()
    
    if not SAVED_SEARCHES_FILE.exists():
        return {"searches": {}, "created_at": datetime.utcnow().isoformat()}
    
    try:
        with open(SAVED_SEARCHES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading saved searches: {e}")
        return {"searches": {}, "created_at": datetime.utcnow().isoformat()}


def save_searches_data(data: Dict[str, Any]) -> bool:
    """Save searches data to file."""
    ensure_storage_dir()
    
    try:
        data["updated_at"] = datetime.utcnow().isoformat()
        with open(SAVED_SEARCHES_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving searches data: {e}")
        return False


def add_saved_search(
    name: str,
    query: str,
    description: Optional[str] = None,
    search_type: str = "general",
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Add a new saved search."""
    
    data = load_saved_searches()
    
    search_entry = {
        "name": name,
        "query": query,
        "description": description or "",
        "search_type": search_type,
        "filters": filters or {},
        "created_at": datetime.utcnow().isoformat(),
        "last_used": None,
        "usage_count": 0
    }
    
    data["searches"][name] = search_entry
    
    if save_searches_data(data):
        return {"success": True, "search": search_entry}
    else:
        return {"success": False, "error": "Failed to save search"}


def get_saved_searches() -> Dict[str, Any]:
    """Get all saved searches."""
    return load_saved_searches()


def get_saved_search(name: str) -> Optional[Dict[str, Any]]:
    """Get a specific saved search by name."""
    data = load_saved_searches()
    return data["searches"].get(name)


def update_search_usage(name: str) -> bool:
    """Update usage statistics for a saved search."""
    data = load_saved_searches()
    
    if name in data["searches"]:
        data["searches"][name]["last_used"] = datetime.utcnow().isoformat()
        data["searches"][name]["usage_count"] += 1
        return save_searches_data(data)
    
    return False


def delete_saved_search(name: str) -> bool:
    """Delete a saved search."""
    data = load_saved_searches()
    
    if name in data["searches"]:
        del data["searches"][name]
        return save_searches_data(data)
    
    return False


def export_logs_query(
    query: Optional[str] = None,
    device: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    format_type: str = "json"
) -> Dict[str, Any]:
    """Generate export query parameters."""
    
    export_config = {
        "query_params": {
            "query": query,
            "device": device,
            "level": level,
            "start_time": start_time,
            "end_time": end_time
        },
        "export_format": format_type,
        "timestamp": datetime.utcnow().isoformat(),
        "max_records": 10000  # Safety limit
    }
    
    return export_config


def load_alert_rules() -> Dict[str, Any]:
    """Load alert rules from file."""
    ensure_storage_dir()
    
    if not ALERT_RULES_FILE.exists():
        return {"rules": {}, "created_at": datetime.utcnow().isoformat()}
    
    try:
        with open(ALERT_RULES_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading alert rules: {e}")
        return {"rules": {}, "created_at": datetime.utcnow().isoformat()}


def save_alert_rules_data(data: Dict[str, Any]) -> bool:
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
    description: Optional[str] = None
) -> Dict[str, Any]:
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
    "add_saved_search",
    "get_saved_searches", 
    "get_saved_search",
    "update_search_usage",
    "delete_saved_search",
    "export_logs_query",
    "create_alert_rule",
    "load_alert_rules"
]