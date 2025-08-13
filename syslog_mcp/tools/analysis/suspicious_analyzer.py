"""
Suspicious activity analysis logic.

This module provides pure business logic for analyzing suspicious activity data,
including pattern detection and risk assessment.
No data access or presentation logic - just analysis.
"""

from typing import Any

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_suspicious_activity_data(
    es_response: dict[str, Any],
    device: str | None = None,
    hours: int = 24,
    sensitivity: str = "medium"
) -> dict[str, Any]:
    """Analyze suspicious activity data from Elasticsearch response."""

    total_events = es_response["hits"]["total"]["value"]
    aggs = es_response.get("aggregations", {})

    # Process suspicious patterns
    suspicious_patterns = []
    if "suspicious_patterns" in aggs:
        for bucket in aggs["suspicious_patterns"]["buckets"]:
            pattern = bucket["key"]
            count = bucket["doc_count"]
            suspicious_patterns.append({
                "pattern": pattern,
                "count": count,
                "severity": _assess_pattern_severity(pattern, count, hours)
            })

    # Process off-hours activity
    off_hours_data = {}
    if "off_hours_activity" in aggs:
        off_hours_count = aggs["off_hours_activity"]["doc_count"]
        off_hours_data = {
            "count": off_hours_count,
            "percentage": (off_hours_count / total_events * 100) if total_events > 0 else 0,
            "hourly_breakdown": []
        }

        if "by_hour" in aggs["off_hours_activity"]:
            for bucket in aggs["off_hours_activity"]["by_hour"]["buckets"]:
                off_hours_data["hourly_breakdown"].append({
                    "hour": bucket["key_as_string"],
                    "count": bucket["doc_count"]
                })

    # Process devices with suspicious activity
    suspicious_devices = []
    if "devices_with_activity" in aggs:
        for bucket in aggs["devices_with_activity"]["buckets"]:
            device_name = bucket["key"]
            count = bucket["doc_count"]
            suspicious_devices.append({
                "device": device_name,
                "event_count": count,
                "risk_score": _calculate_device_risk_score(count, total_events)
            })

    # Process timeline
    activity_timeline = []
    if "timeline" in aggs:
        for bucket in aggs["timeline"]["buckets"]:
            activity_timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })

    # Extract sample events
    sample_events = []
    for hit in es_response["hits"]["hits"]:
        source = hit["_source"]
        sample_events.append({
            "timestamp": source.get("timestamp"),
            "device": source.get("hostname"),
            "message": source.get("message"),
            "program": source.get("program"),
            "level": source.get("severity"),
            "suspicion_reason": _identify_suspicion_reason(source.get("message", ""))
        })

    # Calculate overall risk assessment
    overall_risk = _calculate_overall_suspicion_risk(
        total_events, suspicious_patterns, off_hours_data, hours, sensitivity
    )

    # Analyze pattern trends
    pattern_analysis = _analyze_suspicious_patterns(suspicious_patterns, activity_timeline)

    return {
        "total_events": total_events,
        "suspicious_patterns": suspicious_patterns,
        "off_hours_activity": off_hours_data,
        "suspicious_devices": suspicious_devices,
        "activity_timeline": activity_timeline,
        "sample_events": sample_events,
        "overall_risk_assessment": overall_risk,
        "pattern_analysis": pattern_analysis,
        "analysis_parameters": {
            "device": device,
            "hours": hours,
            "sensitivity": sensitivity
        }
    }


def _assess_pattern_severity(pattern: str, count: int, hours: int) -> str:
    """Assess severity of suspicious activity pattern."""
    frequency = count / hours

    # Pattern-specific thresholds
    if "Privilege Escalation" in pattern:
        return "HIGH" if frequency > 0.5 else "MEDIUM"
    elif "Network Tools" in pattern or "Network Downloads" in pattern:
        return "HIGH" if frequency > 1 else "MEDIUM"
    elif "File Manipulation" in pattern:
        return "MEDIUM" if frequency > 2 else "LOW"
    elif "System Anomalies" in pattern:
        return "HIGH" if frequency > 5 else "MEDIUM"
    else:
        return "LOW"


def _calculate_device_risk_score(device_events: int, total_events: int) -> float:
    """Calculate risk score for a device based on suspicious activity."""
    if total_events == 0:
        return 0.0

    percentage = (device_events / total_events) * 100

    if percentage > 50:
        return 9.0
    elif percentage > 30:
        return 7.0
    elif percentage > 15:
        return 5.0
    elif percentage > 5:
        return 3.0
    else:
        return 1.0


def _identify_suspicion_reason(message: str) -> str:
    """Identify why a log message is considered suspicious."""
    msg_lower = message.lower()

    if any(term in msg_lower for term in ["sudo", "su ", "privilege"]):
        return "Privilege escalation detected"
    elif any(term in msg_lower for term in ["wget", "curl", "download"]):
        return "Network download activity"
    elif any(term in msg_lower for term in ["nc ", "netcat", "socket"]):
        return "Network tool usage"
    elif any(term in msg_lower for term in ["/tmp/", "chmod +x", "executable"]):
        return "Suspicious file operations"
    elif any(term in msg_lower for term in ["failed", "error", "critical"]):
        return "System error or failure"
    else:
        return "General suspicious pattern"


def _calculate_overall_suspicion_risk(
    total_events: int,
    patterns: list[dict[str, Any]],
    off_hours: dict[str, Any],
    hours: int,
    sensitivity: str
) -> dict[str, Any]:
    """Calculate overall suspicion risk assessment."""

    risk_score = 0.0
    risk_factors = []

    # Event frequency risk
    events_per_hour = total_events / hours if hours > 0 else 0
    if events_per_hour > 20:
        risk_score += 3.0
        risk_factors.append("High suspicious event frequency")
    elif events_per_hour > 10:
        risk_score += 2.0
        risk_factors.append("Moderate suspicious event frequency")

    # Pattern severity risk
    high_severity_patterns = sum(1 for p in patterns if p.get("severity") == "HIGH")
    if high_severity_patterns > 0:
        risk_score += high_severity_patterns * 2.0
        risk_factors.append(f"{high_severity_patterns} high-severity suspicious patterns")

    # Off-hours activity risk
    if off_hours.get("percentage", 0) > 30:
        risk_score += 2.0
        risk_factors.append("Significant off-hours activity")

    # Sensitivity adjustment
    sensitivity_multiplier = {"low": 0.7, "medium": 1.0, "high": 1.3}.get(sensitivity, 1.0)
    risk_score *= sensitivity_multiplier

    # Risk level classification
    if risk_score > 8:
        risk_level = "CRITICAL"
    elif risk_score > 6:
        risk_level = "HIGH"
    elif risk_score > 4:
        risk_level = "MEDIUM"
    elif risk_score > 2:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return {
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "recommendation": _get_risk_recommendation(risk_level),
        "immediate_actions": _get_immediate_actions(risk_level, risk_factors)
    }


def _analyze_suspicious_patterns(
    patterns: list[dict[str, Any]],
    timeline: list[dict[str, Any]]
) -> dict[str, Any]:
    """Analyze suspicious activity patterns for insights."""

    if not patterns:
        return {"pattern_diversity": 0, "dominant_pattern": None, "trend_analysis": "No patterns detected"}

    # Calculate pattern diversity
    total_events = sum(p["count"] for p in patterns)
    pattern_diversity = len(patterns) / total_events if total_events > 0 else 0

    # Identify dominant pattern
    dominant_pattern = max(patterns, key=lambda x: x["count"])

    # Analyze timeline trends
    trend_analysis = "Stable activity"
    if timeline and len(timeline) > 4:
        recent_activity = sum(t["count"] for t in timeline[-2:])  # Last 2 periods
        earlier_activity = sum(t["count"] for t in timeline[:2])  # First 2 periods

        if recent_activity > earlier_activity * 1.5:
            trend_analysis = "Increasing suspicious activity"
        elif recent_activity < earlier_activity * 0.5:
            trend_analysis = "Decreasing suspicious activity"

    # Calculate pattern concentration
    pattern_concentration = _calculate_pattern_concentration(patterns)

    return {
        "pattern_diversity": round(pattern_diversity, 3),
        "dominant_pattern": {
            "name": dominant_pattern["pattern"],
            "count": dominant_pattern["count"],
            "percentage": round((dominant_pattern["count"] / total_events) * 100, 1)
        },
        "trend_analysis": trend_analysis,
        "pattern_concentration": pattern_concentration,
        "risk_indicators": _identify_pattern_risk_indicators(patterns)
    }


def _calculate_pattern_concentration(patterns: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate how concentrated the suspicious activity is across patterns."""

    if not patterns:
        return {"score": 0, "description": "No patterns"}

    total_events = sum(p["count"] for p in patterns)
    top_pattern_count = max(p["count"] for p in patterns)

    concentration_score = (top_pattern_count / total_events) if total_events > 0 else 0

    if concentration_score > 0.7:
        description = "Highly concentrated - single pattern dominates"
    elif concentration_score > 0.4:
        description = "Moderately concentrated - few patterns dominate"
    else:
        description = "Distributed - activity spread across multiple patterns"

    return {
        "score": round(concentration_score, 2),
        "description": description,
        "dominant_pattern_percentage": round(concentration_score * 100, 1)
    }


def _identify_pattern_risk_indicators(patterns: list[dict[str, Any]]) -> dict[str, Any]:
    """Identify key risk indicators from suspicious patterns."""

    indicators = {
        "privilege_escalation_detected": False,
        "network_tools_used": False,
        "file_manipulation_detected": False,
        "system_anomalies_present": False,
        "high_frequency_attacks": False
    }

    for pattern in patterns:
        pattern_name = pattern["pattern"].lower()
        count = pattern["count"]

        if "privilege escalation" in pattern_name:
            indicators["privilege_escalation_detected"] = True
        if "network" in pattern_name:
            indicators["network_tools_used"] = True
        if "file manipulation" in pattern_name:
            indicators["file_manipulation_detected"] = True
        if "system anomalies" in pattern_name:
            indicators["system_anomalies_present"] = True

        if count > 20:  # High frequency threshold
            indicators["high_frequency_attacks"] = True

    # Calculate overall indicator score
    active_indicators = sum(1 for indicator in indicators.values() if indicator)
    indicator_score = active_indicators / len(indicators)

    return {
        "indicators": indicators,
        "active_indicators": active_indicators,
        "indicator_score": round(indicator_score, 2),
        "risk_summary": _generate_indicator_risk_summary(indicators)
    }


def _generate_indicator_risk_summary(indicators: dict[str, bool]) -> str:
    """Generate risk summary based on active indicators."""

    active = [key.replace("_", " ").title() for key, value in indicators.items() if value]

    if len(active) == 0:
        return "No significant risk indicators detected"
    elif len(active) == 1:
        return f"Single risk indicator: {active[0]}"
    elif len(active) <= 2:
        return f"Multiple risk indicators: {', '.join(active)}"
    else:
        return f"Numerous risk indicators detected: {len(active)} different types"


def _get_risk_recommendation(risk_level: str) -> str:
    """Get recommendation based on risk level."""
    recommendations = {
        "CRITICAL": "Immediate investigation required - potential active attack",
        "HIGH": "Urgent review needed - implement additional monitoring",
        "MEDIUM": "Investigate suspicious patterns - consider preventive measures",
        "LOW": "Continue monitoring - review logs periodically",
        "MINIMAL": "Normal activity detected - maintain current security posture"
    }
    return recommendations.get(risk_level, "Continue monitoring")


def _get_immediate_actions(risk_level: str, risk_factors: list[str]) -> list[str]:
    """Get immediate actions based on risk level and factors."""

    actions = []

    if risk_level in ["CRITICAL", "HIGH"]:
        actions.extend([
            "Isolate or closely monitor affected devices",
            "Review recent system changes and user activities",
            "Check for signs of data exfiltration or system compromise"
        ])

    # Factor-specific actions
    if any("privilege" in factor.lower() for factor in risk_factors):
        actions.append("Review and audit privileged account usage")

    if any("off-hours" in factor.lower() for factor in risk_factors):
        actions.append("Investigate off-hours activity - verify legitimate business need")

    if any("frequency" in factor.lower() for factor in risk_factors):
        actions.append("Implement rate limiting or alerting for suspicious activity")

    if not actions:
        actions.append("Continue regular monitoring and log analysis")

    return actions[:5]  # Limit to 5 actions
