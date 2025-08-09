"""
Error pattern analysis logic.

This module provides pure business logic for analyzing error patterns and troubleshooting,
including error classification and resolution recommendations.
No data access or presentation logic - just analysis.
"""

from typing import Any
from collections import defaultdict

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_error_patterns_data(
    es_response: dict[str, Any],
    device: str | None = None,
    hours: int = 24,
    severity: str | None = None
) -> dict[str, Any]:
    """Analyze error patterns data from Elasticsearch response."""

    total_errors = es_response["hits"]["total"]["value"]
    aggs = es_response.get("aggregations", {})

    # Process error patterns
    error_patterns = []
    if "error_patterns" in aggs:
        for bucket in aggs["error_patterns"]["buckets"]:
            pattern = bucket["key"]
            count = bucket["doc_count"]
            error_patterns.append({
                "pattern": pattern,
                "count": count,
                "severity": _classify_error_severity(pattern, count, hours),
                "resolution_priority": _get_resolution_priority(pattern, count)
            })

    # Process affected services
    affected_services = []
    if "affected_services" in aggs:
        for bucket in aggs["affected_services"]["buckets"]:
            service = bucket["key"]
            count = bucket["doc_count"]
            affected_services.append({
                "service": service,
                "error_count": count,
                "impact_level": _assess_service_impact(service, count, total_errors)
            })

    # Process affected devices
    affected_devices = []
    if "affected_devices" in aggs:
        for bucket in aggs["affected_devices"]["buckets"]:
            device_name = bucket["key"]
            count = bucket["doc_count"]
            affected_devices.append({
                "device": device_name,
                "error_count": count,
                "percentage": round((count / total_errors) * 100, 1) if total_errors > 0 else 0
            })

    # Process severity breakdown
    severity_breakdown = {}
    if "severity_breakdown" in aggs:
        for bucket in aggs["severity_breakdown"]["buckets"]:
            level = bucket["key"]
            count = bucket["doc_count"]
            severity_breakdown[level] = count

    # Process error timeline
    error_timeline = []
    if "error_timeline" in aggs:
        for bucket in aggs["error_timeline"]["buckets"]:
            error_timeline.append({
                "timestamp": bucket["key_as_string"],
                "error_count": bucket["doc_count"]
            })

    # Process peak error periods
    peak_periods = []
    if "peak_error_periods" in aggs:
        for bucket in aggs["peak_error_periods"]["buckets"]:
            peak_periods.append({
                "timestamp": bucket["key_as_string"],
                "error_count": bucket["doc_count"]
            })
    peak_periods.sort(key=lambda x: x["error_count"], reverse=True)

    # Process sample errors by service
    sample_errors_by_service = {}
    if "sample_errors" in aggs:
        for bucket in aggs["sample_errors"]["buckets"]:
            service = bucket["key"]
            sample_errors = []

            if "sample_messages" in bucket:
                for hit in bucket["sample_messages"]["hits"]["hits"]:
                    source = hit["_source"]
                    sample_errors.append({
                        "timestamp": source.get("timestamp"),
                        "device": source.get("device"),
                        "message": source.get("message"),
                        "level": source.get("level")
                    })

            sample_errors_by_service[service] = sample_errors

    # Calculate error trends
    error_trends = _analyze_error_trends(error_timeline, hours)

    # Analyze detailed error patterns
    detailed_patterns = _analyze_detailed_error_patterns(error_patterns, sample_errors_by_service)

    # Generate troubleshooting insights
    troubleshooting_insights = _generate_troubleshooting_insights(
        error_patterns, affected_services, sample_errors_by_service
    )

    return {
        "total_errors": total_errors,
        "error_patterns": error_patterns,
        "affected_services": affected_services,
        "affected_devices": affected_devices,
        "severity_breakdown": severity_breakdown,
        "error_timeline": error_timeline,
        "peak_periods": peak_periods[:5],  # Top 5 peak periods
        "sample_errors_by_service": sample_errors_by_service,
        "error_trends": error_trends,
        "detailed_patterns": detailed_patterns,
        "troubleshooting_insights": troubleshooting_insights,
        "analysis_parameters": {
            "device": device,
            "hours": hours,
            "severity": severity
        }
    }


def analyze_error_message_patterns(error_list: list[dict]) -> dict[str, Any]:
    """Analyze patterns in error messages."""

    # Group errors by pattern
    pattern_groups = defaultdict(list)

    for error in error_list:
        message = error.get("message", "").lower()
        pattern = _classify_error_message_pattern(message)
        pattern_groups[pattern].append(error)

    # Calculate pattern statistics
    pattern_stats = []
    for pattern, errors in pattern_groups.items():
        pattern_stats.append({
            "pattern": pattern,
            "count": len(errors),
            "severity": _get_pattern_severity(pattern),
            "latest_occurrence": max(errors, key=lambda x: x.get("timestamp", ""))["timestamp"] if errors else None,
            "affected_programs": list({e.get("program", "unknown") for e in errors}),
            "sample_messages": [e.get("message", "") for e in errors[:3]]
        })

    pattern_stats.sort(key=lambda x: x["count"], reverse=True)

    # Identify recurring issues
    recurring_issues = [p for p in pattern_stats if p["count"] > 2]

    # Calculate pattern diversity
    total_errors = sum(p["count"] for p in pattern_stats)
    pattern_diversity = len(pattern_stats) / total_errors if total_errors > 0 else 0

    return {
        "pattern_statistics": pattern_stats,
        "recurring_issues": recurring_issues,
        "pattern_diversity": round(pattern_diversity, 3),
        "most_common_pattern": pattern_stats[0]["pattern"] if pattern_stats else None
    }


def _classify_error_severity(pattern: str, count: int, hours: int) -> str:
    """Classify error severity based on pattern and frequency."""

    frequency = count / hours if hours > 0 else 0

    # Pattern-based severity
    if any(keyword in pattern.lower() for keyword in ["hardware", "disk", "memory", "cpu"]):
        return "HIGH" if frequency > 1 else "MEDIUM"
    elif any(keyword in pattern.lower() for keyword in ["network", "connection", "timeout"]):
        return "HIGH" if frequency > 2 else "MEDIUM"
    elif any(keyword in pattern.lower() for keyword in ["service", "daemon", "failed to start"]):
        return "MEDIUM" if frequency > 0.5 else "LOW"
    elif any(keyword in pattern.lower() for keyword in ["authentication", "permission", "denied"]):
        return "HIGH" if frequency > 5 else "MEDIUM"
    else:
        return "MEDIUM" if frequency > 3 else "LOW"


def _get_resolution_priority(pattern: str, count: int) -> int:
    """Get resolution priority (1-5, 1 being highest priority)."""

    # High priority patterns
    if any(keyword in pattern.lower() for keyword in ["critical", "hardware", "disk full", "memory"]):
        return 1
    elif any(keyword in pattern.lower() for keyword in ["service", "daemon", "failed", "network"]):
        return 2 if count > 10 else 3
    elif any(keyword in pattern.lower() for keyword in ["authentication", "security", "permission"]):
        return 2 if count > 20 else 3
    else:
        return 4 if count > 5 else 5


def _assess_service_impact(service: str, error_count: int, total_errors: int) -> str:
    """Assess the impact level of service errors."""

    percentage = (error_count / total_errors) * 100 if total_errors > 0 else 0

    # Service-specific impact assessment
    critical_services = ["kernel", "systemd", "sshd", "network"]
    if any(service.lower().startswith(s) for s in critical_services):
        return "HIGH" if percentage > 20 else "MEDIUM"

    if percentage > 50:
        return "HIGH"
    elif percentage > 25:
        return "MEDIUM"
    else:
        return "LOW"


def _analyze_error_trends(error_timeline: list[dict], hours: int) -> dict[str, Any]:
    """Analyze error trends over time."""

    if not error_timeline:
        return {"trend": "STABLE", "trend_percentage": 0, "peak_periods": []}

    # Calculate trend over time
    error_counts = [period.get("error_count", 0) for period in error_timeline]

    if len(error_counts) < 2:
        return {"trend": "STABLE", "trend_percentage": 0, "peak_periods": []}

    # Simple trend calculation (compare first half to second half)
    mid_point = len(error_counts) // 2
    first_half_avg = sum(error_counts[:mid_point]) / mid_point if mid_point > 0 else 0
    second_half_avg = sum(error_counts[mid_point:]) / (len(error_counts) - mid_point)

    if second_half_avg > first_half_avg * 1.2:
        trend = "INCREASING"
        trend_percentage = ((second_half_avg - first_half_avg) / first_half_avg) * 100 if first_half_avg > 0 else 100
    elif second_half_avg < first_half_avg * 0.8:
        trend = "DECREASING"
        trend_percentage = ((first_half_avg - second_half_avg) / first_half_avg) * 100 if first_half_avg > 0 else 0
    else:
        trend = "STABLE"
        trend_percentage = 0

    # Identify peak periods
    avg_errors = sum(error_counts) / len(error_counts)
    peak_periods = [
        {
            "timestamp": period["timestamp"],
            "error_count": period.get("error_count", 0)
        }
        for period in error_timeline
        if period.get("error_count", 0) > avg_errors * 1.5
    ]

    return {
        "trend": trend,
        "trend_percentage": round(trend_percentage, 1),
        "peak_periods": peak_periods[:5],
        "average_errors_per_hour": round(avg_errors, 1),
        "total_periods": len(error_timeline)
    }


def _analyze_detailed_error_patterns(
    error_patterns: list[dict],
    sample_errors: dict[str, list]
) -> dict[str, Any]:
    """Analyze detailed error patterns for deeper insights."""

    pattern_insights = {}

    for pattern_data in error_patterns:
        pattern_name = pattern_data["pattern"]
        count = pattern_data["count"]

        # Extract service name from pattern if available
        service = None
        if "(" in pattern_name and ")" in pattern_name:
            service = pattern_name.split("(")[-1].replace(")", "").strip()

        insights = {
            "frequency_analysis": _analyze_pattern_frequency(count, pattern_data.get("severity", "LOW")),
            "affected_services": [service] if service else [],
            "common_causes": _identify_common_causes(pattern_name),
            "resolution_steps": _get_resolution_steps(pattern_name),
            "prevention_measures": _get_prevention_measures(pattern_name)
        }

        # Add sample messages if available for the service
        if service and service in sample_errors:
            insights["sample_messages"] = [
                msg.get("message", "") for msg in sample_errors[service][:2]
            ]

        pattern_insights[pattern_name] = insights

    return pattern_insights


def _generate_troubleshooting_insights(
    error_patterns: list[dict],
    affected_services: list[dict],
    sample_errors: dict[str, list]
) -> list[dict[str, str]]:
    """Generate actionable troubleshooting insights."""

    insights = []

    # Pattern-based insights
    for pattern in error_patterns[:3]:  # Top 3 patterns
        if pattern["severity"] in ["HIGH", "CRITICAL"]:
            insight = {
                "type": "ERROR_PATTERN",
                "title": f"High-priority {pattern['pattern']}",
                "description": f"Detected {pattern['count']} occurrences of {pattern['pattern']}",
                "action": _get_pattern_troubleshooting_action(pattern["pattern"])
            }
            insights.append(insight)

    # Service-based insights
    for service in affected_services[:2]:  # Top 2 affected services
        if service["impact_level"] == "HIGH":
            insight = {
                "type": "SERVICE_IMPACT",
                "title": f"Service Issues: {service['service']}",
                "description": f"{service['service']} has {service['error_count']} errors",
                "action": f"Check {service['service']} service status and configuration"
            }
            insights.append(insight)

    return insights[:4]  # Limit to 4 insights


def _classify_error_message_pattern(message: str) -> str:
    """Classify error message into a pattern category."""

    msg_lower = message.lower()

    if any(keyword in msg_lower for keyword in ["usb", "hardware", "device"]):
        return "Hardware Issues"
    elif any(keyword in msg_lower for keyword in ["network", "connection", "timeout", "tcp"]):
        return "Network Issues"
    elif any(keyword in msg_lower for keyword in ["auth", "permission", "denied", "login"]):
        return "Authentication Issues"
    elif any(keyword in msg_lower for keyword in ["disk", "filesystem", "mount", "space"]):
        return "Filesystem Issues"
    elif any(keyword in msg_lower for keyword in ["service", "daemon", "failed to start", "systemd"]):
        return "Service Issues"
    elif any(keyword in msg_lower for keyword in ["memory", "cpu", "resource", "load"]):
        return "Resource Issues"
    elif any(keyword in msg_lower for keyword in ["kernel", "panic", "oops", "bug"]):
        return "Kernel Issues"
    else:
        return "Other Issues"


def _get_pattern_severity(pattern: str) -> str:
    """Get severity level for an error pattern."""

    high_severity = ["Hardware Issues", "Kernel Issues", "Filesystem Issues"]
    medium_severity = ["Service Issues", "Network Issues", "Resource Issues"]

    if pattern in high_severity:
        return "HIGH"
    elif pattern in medium_severity:
        return "MEDIUM"
    else:
        return "LOW"


def _analyze_pattern_frequency(count: int, severity: str) -> dict[str, Any]:
    """Analyze pattern frequency and provide insights."""

    if count > 100:
        frequency_level = "VERY_HIGH"
        description = "Extremely frequent occurrence - immediate attention required"
    elif count > 50:
        frequency_level = "HIGH"
        description = "High frequency occurrence - requires investigation"
    elif count > 20:
        frequency_level = "MODERATE"
        description = "Moderate frequency - monitor for trends"
    elif count > 5:
        frequency_level = "LOW"
        description = "Low frequency occurrence - investigate if recurring"
    else:
        frequency_level = "RARE"
        description = "Rare occurrence - may be isolated incident"

    return {
        "frequency_level": frequency_level,
        "count": count,
        "description": description,
        "urgency": _calculate_urgency(frequency_level, severity)
    }


def _calculate_urgency(frequency_level: str, severity: str) -> str:
    """Calculate urgency based on frequency and severity."""

    urgency_matrix = {
        ("VERY_HIGH", "HIGH"): "CRITICAL",
        ("VERY_HIGH", "MEDIUM"): "HIGH",
        ("VERY_HIGH", "LOW"): "MEDIUM",
        ("HIGH", "HIGH"): "HIGH",
        ("HIGH", "MEDIUM"): "MEDIUM",
        ("HIGH", "LOW"): "LOW",
        ("MODERATE", "HIGH"): "MEDIUM",
        ("MODERATE", "MEDIUM"): "LOW",
        ("LOW", "HIGH"): "LOW",
    }

    return urgency_matrix.get((frequency_level, severity), "LOW")


def _identify_common_causes(pattern: str) -> list[str]:
    """Identify common causes for error patterns."""

    causes = {
        "Hardware Issues": [
            "Faulty hardware components",
            "Driver compatibility issues",
            "Power supply problems",
            "Cable/connection issues"
        ],
        "Network Issues": [
            "Network connectivity problems",
            "DNS resolution failures",
            "Firewall blocking connections",
            "Service unavailability"
        ],
        "Service Issues": [
            "Service configuration errors",
            "Missing dependencies",
            "Resource constraints",
            "Permission issues"
        ],
        "Filesystem Issues": [
            "Disk space exhaustion",
            "File permission problems",
            "Corrupted filesystem",
            "Mount point issues"
        ]
    }

    for pattern_type, pattern_causes in causes.items():
        if pattern_type in pattern:
            return pattern_causes

    return ["Configuration issues", "Resource constraints", "External dependencies"]


def _get_resolution_steps(pattern: str) -> list[str]:
    """Get resolution steps for error patterns."""

    steps = {
        "Hardware Issues": [
            "Check hardware connections and cables",
            "Review dmesg and hardware logs",
            "Test hardware components individually",
            "Update device drivers if needed"
        ],
        "Network Issues": [
            "Test network connectivity",
            "Check DNS resolution",
            "Verify firewall rules",
            "Review network service configuration"
        ],
        "Service Issues": [
            "Check service status and logs",
            "Verify service configuration",
            "Restart affected services",
            "Check for resource constraints"
        ],
        "Filesystem Issues": [
            "Check disk space availability",
            "Verify mount points and permissions",
            "Run filesystem checks if safe",
            "Review filesystem logs"
        ]
    }

    for pattern_type, pattern_steps in steps.items():
        if pattern_type in pattern:
            return pattern_steps

    return ["Review system logs", "Check configuration", "Restart affected services"]


def _get_prevention_measures(pattern: str) -> list[str]:
    """Get prevention measures for error patterns."""

    measures = {
        "Hardware Issues": [
            "Regular hardware health monitoring",
            "Preventive maintenance schedules",
            "Environmental monitoring (temperature, power)",
            "Hardware redundancy where possible"
        ],
        "Network Issues": [
            "Network monitoring and alerting",
            "Redundant network connections",
            "Regular connectivity testing",
            "Network configuration backups"
        ],
        "Service Issues": [
            "Service monitoring and health checks",
            "Configuration management and versioning",
            "Resource monitoring and alerting",
            "Regular service updates and patches"
        ],
        "Filesystem Issues": [
            "Disk space monitoring and alerts",
            "Regular filesystem maintenance",
            "Backup and recovery procedures",
            "Storage capacity planning"
        ]
    }

    for pattern_type, pattern_measures in measures.items():
        if pattern_type in pattern:
            return pattern_measures

    return ["Regular system monitoring", "Configuration management", "Preventive maintenance"]


def _get_pattern_troubleshooting_action(pattern: str) -> str:
    """Get specific troubleshooting action for error pattern."""

    actions = {
        "Hardware Issues": "Check hardware connections, run diagnostics, review dmesg output",
        "Network Issues": "Verify network connectivity, check firewall rules, test DNS resolution",
        "Authentication Issues": "Review user accounts, check password policies, examine auth logs",
        "Filesystem Issues": "Check disk space, verify mount points, run filesystem check",
        "Service Issues": "Restart affected services, check service configuration, review dependencies",
        "Resource Issues": "Monitor system resources, check for memory leaks, review process usage",
        "Kernel Issues": "Check for kernel updates, review hardware compatibility, examine system logs"
    }

    return actions.get(pattern, "Review logs and system configuration")
