"""
Device health analysis logic.

This module provides pure business logic for analyzing device health data,
including status assessment and health scoring.
No data access or presentation logic - just analysis.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import defaultdict

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_device_health_data(
    es_response: Dict[str, Any],
    device_name: str,
    hours: int = 24
) -> Dict[str, Any]:
    """Analyze device health data from Elasticsearch response."""
    
    total_logs = es_response["hits"]["total"]["value"]
    aggs = es_response.get("aggregations", {})
    
    # Process severity distribution
    severity_distribution = {}
    if "severity_distribution" in aggs:
        for bucket in aggs["severity_distribution"]["buckets"]:
            level = bucket["key"]
            count = bucket["doc_count"]
            severity_distribution[level] = count
    
    # Process facility distribution  
    facility_distribution = {}
    if "facility_distribution" in aggs:
        for bucket in aggs["facility_distribution"]["buckets"]:
            facility = bucket["key"]
            count = bucket["doc_count"]
            facility_distribution[facility] = count
    
    # Process top programs
    top_programs = []
    if "top_programs" in aggs:
        for bucket in aggs["top_programs"]["buckets"]:
            program = bucket["key"]
            count = bucket["doc_count"]
            top_programs.append({
                "program": program,
                "log_count": count
            })
    
    # Process recent errors
    recent_errors = []
    if "recent_errors" in aggs and "latest_errors" in aggs["recent_errors"]:
        for hit in aggs["recent_errors"]["latest_errors"]["hits"]["hits"]:
            source = hit["_source"]
            recent_errors.append({
                "timestamp": source.get("timestamp"),
                "message": source.get("message"),
                "program": source.get("program"),
                "level": source.get("level")
            })
    
    # Process recent warnings
    recent_warnings = []
    if "recent_warnings" in aggs and "latest_warnings" in aggs["recent_warnings"]:
        for hit in aggs["recent_warnings"]["latest_warnings"]["hits"]["hits"]:
            source = hit["_source"]
            recent_warnings.append({
                "timestamp": source.get("timestamp"),
                "message": source.get("message"),
                "program": source.get("program"),
                "level": source.get("level")
            })
    
    # Process activity timeline
    activity_timeline = []
    if "activity_timeline" in aggs:
        for bucket in aggs["activity_timeline"]["buckets"]:
            activity_timeline.append({
                "timestamp": bucket["key_as_string"],
                "log_count": bucket["doc_count"]
            })
    
    # Get last activity timestamp
    last_seen = None
    if "last_activity" in aggs and aggs["last_activity"]["hits"]["hits"]:
        last_activity_hit = aggs["last_activity"]["hits"]["hits"][0]
        last_seen = last_activity_hit["_source"]["timestamp"]
    
    # Calculate health metrics
    error_count = severity_distribution.get("error", 0) + severity_distribution.get("critical", 0)
    warning_count = severity_distribution.get("warning", 0) + severity_distribution.get("warn", 0)
    
    # Determine device status
    device_status = _determine_device_status(
        total_logs, error_count, warning_count, last_seen, hours
    )
    
    # Analyze system components
    component_analysis = _analyze_system_components(top_programs, recent_errors)
    
    # Calculate health score
    health_score = _calculate_device_health_score(
        total_logs, error_count, warning_count, activity_timeline, hours
    )
    
    return {
        "device_name": device_name,
        "total_logs": total_logs,
        "severity_distribution": severity_distribution,
        "facility_distribution": facility_distribution,
        "top_programs": top_programs,
        "recent_errors": recent_errors,
        "recent_warnings": recent_warnings,
        "activity_timeline": activity_timeline,
        "last_seen": last_seen,
        "device_status": device_status,
        "error_count": error_count,
        "warning_count": warning_count,
        "hours": hours,
        "component_analysis": component_analysis,
        "health_score": health_score,
        "recommendations": _generate_device_recommendations(device_status, component_analysis)
    }


def _determine_device_status(
    total_logs: int,
    error_count: int,
    warning_count: int,
    last_seen: Optional[str],
    hours: int
) -> str:
    """Determine overall device status based on metrics."""
    
    if total_logs == 0:
        return "no_activity"
    
    # Check if device is recently active
    if last_seen:
        try:
            last_activity = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            time_since_last = datetime.now(last_activity.tzinfo) - last_activity
            
            if time_since_last > timedelta(hours=2):
                return "warning"  # No recent activity
        except ValueError as e:
            logger.warning(f"Failed to parse timestamp '{last_seen}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing timestamp '{last_seen}': {e}")
    
    # Calculate error rates
    error_rate = (error_count / total_logs) * 100 if total_logs > 0 else 0
    warning_rate = (warning_count / total_logs) * 100 if total_logs > 0 else 0
    
    # Determine status based on error rates
    if error_count > 0 and error_rate > 5:
        return "critical"
    elif error_count > 0 or warning_rate > 10:
        return "warning"
    else:
        return "healthy"


def _analyze_system_components(
    top_programs: List[Dict],
    recent_errors: List[Dict]
) -> Dict[str, Any]:
    """Analyze system components and their health."""
    
    # Categorize programs by type
    component_categories = {
        "system": ["kernel", "systemd", "init", "udev"],
        "network": ["sshd", "nginx", "apache", "dhcp"],
        "security": ["fail2ban", "iptables", "sudo", "pam"],
        "storage": ["mount", "umount", "fsck", "lvm"],
        "application": []  # Everything else goes here
    }
    
    categorized_components = defaultdict(list)
    
    for program in top_programs:
        prog_name = program["program"].lower()
        
        # Find category
        category = "application"
        for cat, keywords in component_categories.items():
            if any(keyword in prog_name for keyword in keywords):
                category = cat
                break
        
        categorized_components[category].append({
            "program": program["program"],
            "log_count": program["log_count"],
            "health_status": _assess_component_health(program["program"], recent_errors)
        })
    
    # Calculate category health scores
    category_health = {}
    for category, components in categorized_components.items():
        healthy = sum(1 for c in components if c["health_status"] == "healthy")
        total = len(components)
        category_health[category] = {
            "healthy_components": healthy,
            "total_components": total,
            "health_percentage": round((healthy / total) * 100, 1) if total > 0 else 100
        }
    
    return {
        "categorized_components": dict(categorized_components),
        "category_health": category_health,
        "most_active_components": top_programs[:5]
    }


def _calculate_device_health_score(
    total_logs: int,
    error_count: int,
    warning_count: int,
    activity_timeline: List[Dict],
    hours: int
) -> Dict[str, Any]:
    """Calculate comprehensive device health score."""
    
    health_score = 100.0
    score_factors = []
    
    # Error rate impact
    if total_logs > 0:
        error_rate = (error_count / total_logs) * 100
        warning_rate = (warning_count / total_logs) * 100
        
        if error_rate > 0:
            error_penalty = min(error_rate * 10, 40)  # Max 40 point penalty
            health_score -= error_penalty
            score_factors.append(f"Error rate penalty: -{error_penalty:.1f} ({error_rate:.1f}% error rate)")
        
        if warning_rate > 5:
            warning_penalty = min((warning_rate - 5) * 2, 20)  # Max 20 point penalty
            health_score -= warning_penalty
            score_factors.append(f"Warning rate penalty: -{warning_penalty:.1f} ({warning_rate:.1f}% warning rate)")
    
    # Activity consistency impact
    if activity_timeline:
        activity_variance = _calculate_activity_variance(activity_timeline)
        if activity_variance > 0.5:
            variance_penalty = min(activity_variance * 10, 15)  # Max 15 point penalty
            health_score -= variance_penalty
            score_factors.append(f"Activity inconsistency penalty: -{variance_penalty:.1f}")
    
    # Recent activity impact
    recent_activity = sum(period["log_count"] for period in activity_timeline[-3:]) if len(activity_timeline) >= 3 else 0
    expected_recent = (total_logs / hours) * 3 if hours > 0 else 0  # Expected logs in last 3 hours
    
    if recent_activity < expected_recent * 0.5:
        activity_penalty = 10
        health_score -= activity_penalty
        score_factors.append(f"Low recent activity penalty: -{activity_penalty}")
    
    health_score = max(health_score, 0)  # Ensure score doesn't go below 0
    
    # Determine health grade
    if health_score >= 90:
        health_grade = "EXCELLENT"
    elif health_score >= 80:
        health_grade = "GOOD"
    elif health_score >= 70:
        health_grade = "FAIR"
    elif health_score >= 60:
        health_grade = "POOR"
    else:
        health_grade = "CRITICAL"
    
    return {
        "score": round(health_score, 1),
        "grade": health_grade,
        "score_factors": score_factors,
        "max_score": 100.0
    }


def _generate_device_recommendations(
    device_status: str,
    component_analysis: Dict[str, Any]
) -> List[str]:
    """Generate actionable recommendations for device health."""
    
    recommendations = []
    
    # Status-based recommendations
    if device_status == "critical":
        recommendations.append("URGENT: Investigate critical errors immediately")
        recommendations.append("Consider device restart if errors persist")
    elif device_status == "warning":
        recommendations.append("Review recent warnings and errors")
        recommendations.append("Monitor device activity closely")
    elif device_status == "no_activity":
        recommendations.append("Check device connectivity and power")
        recommendations.append("Verify logging service is running")
    
    # Component-based recommendations
    category_health = component_analysis.get("category_health", {})
    for category, health in category_health.items():
        if health["health_percentage"] < 70:
            recommendations.append(f"Review {category} components - {health['health_percentage']:.1f}% healthy")
    
    # General maintenance recommendations
    if not recommendations:  # If no issues found
        recommendations.extend([
            "Continue regular monitoring",
            "Consider log rotation if needed",
            "Review system updates availability"
        ])
    
    return recommendations[:5]  # Limit to top 5 recommendations


def _assess_component_health(program: str, recent_errors: List[Dict]) -> str:
    """Assess health status of a system component."""
    
    program_errors = [e for e in recent_errors if e.get("program") == program]
    
    if len(program_errors) == 0:
        return "healthy"
    elif len(program_errors) <= 2:
        return "warning"
    else:
        return "error"


def _calculate_activity_variance(timeline: List[Dict]) -> float:
    """Calculate variance in activity levels."""
    
    if not timeline:
        return 0.0
    
    counts = [period.get("log_count", 0) for period in timeline]
    mean = sum(counts) / len(counts)
    
    if mean == 0:
        return 0.0
    
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    return variance / (mean ** 2)  # Coefficient of variation