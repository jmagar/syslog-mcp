"""
Report generation analysis logic.

This module provides pure business logic for generating comprehensive reports,
including daily summaries and export functionality.
No data access or presentation logic - just analysis.
"""

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from ...utils.logging import get_logger

logger = get_logger(__name__)


def safe_int(value: Any, default: int = 0) -> int:
    """Safely convert any value to int with a default fallback."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def analyze_daily_report_data(
    device_summary: dict[str, Any],
    auth_summary: dict[str, Any],
    security_summary: dict[str, Any],
    error_summary: dict[str, Any],
    target_date: str | None = None
) -> dict[str, Any]:
    """Analyze data for daily report generation."""

    report_date = target_date or datetime.utcnow().strftime("%Y-%m-%d")

    # Executive Summary
    executive_summary = {
        "report_date": report_date,
        "total_events": 0,
        "total_devices": 0,
        "security_incidents": 0,
        "system_errors": 0,
        "overall_health": "unknown"
    }

    # Process device summary
    device_stats = {
        "active_devices": 0,
        "inactive_devices": 0,
        "devices_with_errors": 0,
        "top_active_devices": []
    }

    if device_summary.get("total_events"):
        executive_summary["total_events"] += device_summary["total_events"]
        device_stats["active_devices"] = len(device_summary.get("active_devices", []))

    # Process authentication summary
    auth_stats = {
        "total_failed_auths": 0,
        "unique_attacking_ips": 0,
        "targeted_accounts": 0,
        "auth_success_rate": 100.0
    }

    if auth_summary.get("total_attacks"):
        executive_summary["security_incidents"] += auth_summary["total_attacks"]
        auth_stats["total_failed_auths"] = auth_summary["total_attacks"]
        auth_stats["unique_attacking_ips"] = len(auth_summary.get("attacking_ips", []))

    # Process security summary
    security_stats = {
        "suspicious_activities": 0,
        "security_alerts": 0,
        "threat_level": "low"
    }

    if security_summary.get("suspicious_events"):
        executive_summary["security_incidents"] += security_summary["suspicious_events"]
        security_stats["suspicious_activities"] = security_summary["suspicious_events"]

    # Process error summary
    error_stats = {
        "total_errors": 0,
        "critical_errors": 0,
        "error_categories": {},
        "top_error_sources": []
    }

    if error_summary.get("total_errors"):
        executive_summary["system_errors"] = error_summary["total_errors"]
        error_stats["total_errors"] = error_summary["total_errors"]

        # Categorize errors by severity
        for error in error_summary.get("error_breakdown", []):
            if error.get("level") == "critical":
                error_stats["critical_errors"] += error.get("count", 0)

    # Calculate overall health score
    health_score = calculate_health_score(
        safe_int(executive_summary["total_events"]),
        safe_int(executive_summary["security_incidents"]),
        safe_int(executive_summary["system_errors"]),
        safe_int(device_stats["active_devices"])
    )

    executive_summary["health_score"] = health_score
    executive_summary["overall_health"] = get_health_status(health_score)

    # Generate insights and recommendations
    insights = generate_daily_insights(
        executive_summary,
        device_stats,
        auth_stats,
        security_stats,
        error_stats
    )

    recommendations = generate_daily_recommendations(
        executive_summary,
        insights
    )

    return {
        "report_metadata": {
            "report_date": report_date,
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": "daily_summary",
            "data_sources": ["device_health", "authentication", "security", "errors"]
        },
        "executive_summary": executive_summary,
        "device_statistics": device_stats,
        "authentication_statistics": auth_stats,
        "security_statistics": security_stats,
        "error_statistics": error_stats,
        "insights": insights,
        "recommendations": recommendations,
        "health_assessment": {
            "overall_score": health_score,
            "status": get_health_status(health_score),
            "trend": "stable"  # Could be enhanced with historical data
        }
    }


def analyze_export_data(
    raw_logs: list[dict[str, Any]],
    export_config: dict[str, Any]
) -> dict[str, Any]:
    """Analyze data for export functionality."""

    total_logs = len(raw_logs)

    # Analyze log distribution
    device_distribution: Counter[str] = Counter()
    level_distribution: Counter[str] = Counter()
    program_distribution: Counter[str] = Counter()
    time_distribution: defaultdict[str, int] = defaultdict(int)

    for log_entry in raw_logs:
        device_distribution[log_entry.get("device", "unknown")] += 1
        level_distribution[log_entry.get("level", "unknown")] += 1
        program_distribution[log_entry.get("program", "unknown")] += 1

        # Time distribution (by hour)
        timestamp = log_entry.get("timestamp", "")
        if timestamp:
            try:
                hour_key = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:00")
                time_distribution[hour_key] += 1
            except (ValueError, TypeError):
                pass

    return {
        "export_metadata": {
            "total_records": total_logs,
            "export_format": export_config.get("export_format", "json"),
            "exported_at": datetime.utcnow().isoformat(),
            "query_parameters": export_config.get("query_params", {})
        },
        "data_summary": {
            "unique_devices": len(device_distribution),
            "unique_programs": len(program_distribution),
            "log_levels": dict(level_distribution.most_common()),
            "time_span_hours": len(time_distribution),
            "top_devices": dict(device_distribution.most_common(10)),
            "top_programs": dict(program_distribution.most_common(10))
        },
        "export_quality": {
            "completeness": "high" if total_logs > 0 else "none",
            "data_coverage": "full" if total_logs < export_config.get("max_records", 10000) else "limited"
        }
    }


def write_logs_to_json(raw_logs: list[dict[str, Any]], export_path: str) -> dict[str, Any]:
    """Write logs to JSON file."""
    try:
        export_data = {
            "export_metadata": {
                "exported_at": datetime.utcnow().isoformat(),
                "total_records": len(raw_logs),
                "format": "json"
            },
            "logs": raw_logs
        }

        with Path(export_path).open('w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        # Get file size
        file_size = Path(export_path).stat().st_size

        return {
            "success": True,
            "records_written": len(raw_logs),
            "file_size_bytes": file_size,
            "file_path": export_path
        }

    except Exception as e:
        logger.error(f"Failed to write JSON export: {e}")
        return {
            "success": False,
            "error": str(e),
            "file_path": export_path
        }


def write_logs_to_csv(raw_logs: list[dict[str, Any]], export_path: str) -> dict[str, Any]:
    """Write logs to CSV file."""
    try:
        if not raw_logs:
            return {
                "success": False,
                "error": "No logs to export",
                "file_path": export_path
            }

        # Determine all possible fieldnames from the logs
        fieldnames_set: set[str] = set()
        for log in raw_logs:
            fieldnames_set.update(log.keys())

        # Sort fieldnames for consistent column order
        fieldnames = sorted(fieldnames_set)

        with Path(export_path).open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for log_entry in raw_logs:
                # Ensure all fields are present (fill missing with empty string)
                row = {field: log_entry.get(field, '') for field in fieldnames}
                writer.writerow(row)

        # Get file size
        file_size = Path(export_path).stat().st_size

        return {
            "success": True,
            "records_written": len(raw_logs),
            "file_size_bytes": file_size,
            "columns": len(fieldnames),
            "file_path": export_path
        }

    except Exception as e:
        logger.error(f"Failed to write CSV export: {e}")
        return {
            "success": False,
            "error": str(e),
            "file_path": export_path
        }


def export_logs_to_file(
    raw_logs: list[dict[str, Any]],
    export_config: dict[str, Any]
) -> dict[str, Any]:
    """Export logs to file in specified format."""

    export_path = export_config.get("export_path")
    export_format = export_config.get("export_format", "json").lower()

    if not export_path:
        return {
            "success": False,
            "error": "No export path specified",
            "analysis_data": analyze_export_data(raw_logs, export_config)
        }

    logger.info(f"Exporting {len(raw_logs)} logs to {export_path} in {export_format} format")

    # Write file based on format
    if export_format == "json":
        write_result = write_logs_to_json(raw_logs, export_path)
    elif export_format == "csv":
        write_result = write_logs_to_csv(raw_logs, export_path)
    else:
        return {
            "success": False,
            "error": f"Unsupported export format: {export_format}",
            "analysis_data": analyze_export_data(raw_logs, export_config)
        }

    # Combine write result with analysis data
    analysis_data = analyze_export_data(raw_logs, export_config)

    return {
        **write_result,
        "analysis_data": analysis_data
    }


def calculate_health_score(
    total_events: int,
    security_incidents: int,
    system_errors: int,
    active_devices: int
) -> float:
    """Calculate overall system health score (0-100)."""

    base_score = 100.0

    # Deduct for security incidents
    if total_events > 0:
        security_ratio = security_incidents / total_events
        base_score -= min(security_ratio * 50, 40)  # Max 40 point deduction

    # Deduct for system errors
    if total_events > 0:
        error_ratio = system_errors / total_events
        base_score -= min(error_ratio * 30, 30)  # Max 30 point deduction

    # Boost for active devices (shows healthy activity)
    if active_devices > 0:
        base_score = min(base_score + (active_devices * 2), 100)

    return max(base_score, 0.0)


def get_health_status(health_score: float) -> str:
    """Convert health score to status."""

    if health_score >= 80:
        return "excellent"
    elif health_score >= 60:
        return "good"
    elif health_score >= 40:
        return "fair"
    elif health_score >= 20:
        return "poor"
    else:
        return "critical"


def generate_daily_insights(
    executive_summary: dict[str, Any],
    device_stats: dict[str, Any],
    auth_stats: dict[str, Any],
    security_stats: dict[str, Any],
    error_stats: dict[str, Any]
) -> list[str]:
    """Generate insights for daily report."""

    insights = []

    # Overall activity insights
    total_events = executive_summary.get("total_events", 0)
    if total_events == 0:
        insights.append("No system activity detected - potential monitoring issues")
    elif total_events > 100000:
        insights.append(f"High system activity with {total_events:,} total events")

    # Security insights
    security_incidents = executive_summary.get("security_incidents", 0)
    if security_incidents > 0:
        insights.append(f"{security_incidents} security incidents detected requiring attention")

    if auth_stats.get("unique_attacking_ips", 0) > 10:
        insights.append("High number of unique attacking IPs suggests coordinated attack")

    # System health insights
    if error_stats.get("critical_errors", 0) > 0:
        insights.append(f"{error_stats['critical_errors']} critical system errors need immediate attention")

    # Device insights
    active_devices = device_stats.get("active_devices", 0)
    if active_devices == 0:
        insights.append("No active devices detected - check monitoring coverage")

    return insights


def generate_daily_recommendations(
    executive_summary: dict[str, Any],
    insights: list[str]
) -> list[str]:
    """Generate recommendations for daily report."""

    recommendations = []

    health_score = executive_summary.get("health_score", 0)

    if health_score < 50:
        recommendations.append("Immediate attention required - multiple system issues detected")
    elif health_score < 70:
        recommendations.append("Review and address identified security and error issues")

    security_incidents = executive_summary.get("security_incidents", 0)
    if security_incidents > 0:
        recommendations.append("Investigate and respond to security incidents")
        recommendations.append("Review and update security monitoring rules")

    system_errors = executive_summary.get("system_errors", 0)
    if system_errors > 100:
        recommendations.append("Investigate high error rates and implement fixes")

    if not recommendations:
        recommendations.append("System appears healthy - maintain current monitoring practices")

    return recommendations


__all__ = [
    "analyze_daily_report_data",
    "analyze_export_data"
]
