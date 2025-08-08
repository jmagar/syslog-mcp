"""
Authentication-focused analysis logic.

This module provides pure business logic for analyzing authentication data,
including failed authentication analysis and authentication timeline analysis.
No data access or presentation logic - just analysis.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import re
from collections import defaultdict

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_failed_authentication_data(
    es_response: Dict[str, Any],
    device_name: Optional[str] = None,
    hours: int = 24
) -> Dict[str, Any]:
    """Analyze failed authentication data from Elasticsearch response."""
    
    # Extract basic metrics
    total_attacks = es_response["hits"]["total"]["value"]
    
    # Extract aggregation data
    aggs = es_response.get("aggregations", {})
    
    # Process attacking IPs
    attacking_ips = []
    if "attacking_ips" in aggs:
        for bucket in aggs["attacking_ips"]["buckets"]:
            ip = bucket["key"]
            count = bucket["doc_count"]
            if ip != "unknown":
                attacking_ips.append((ip, count))
    
    # Process targeted devices
    targeted_devices = []
    if "targeted_devices" in aggs:
        for bucket in aggs["targeted_devices"]["buckets"]:
            device = bucket["key"]
            count = bucket["doc_count"]
            targeted_devices.append((device, count))
    
    # Process failed users
    failed_users = []
    if "failed_users" in aggs:
        for bucket in aggs["failed_users"]["buckets"]:
            user = bucket["key"]
            count = bucket["doc_count"]
            if user != "unknown":
                failed_users.append((user, count))
    
    # Process attack methods
    attack_methods = []
    if "attack_methods" in aggs:
        for bucket in aggs["attack_methods"]["buckets"]:
            method = bucket["key"]
            count = bucket["doc_count"]
            attack_methods.append((method, count))
    
    # Process timeline
    attack_timeline = []
    if "attack_timeline" in aggs:
        for bucket in aggs["attack_timeline"]["buckets"]:
            timestamp = bucket["key_as_string"]
            count = bucket["doc_count"]
            attack_timeline.append((timestamp, count))
    
    # Extract sample attacks from hits
    sample_attacks = []
    for hit in es_response["hits"]["hits"]:
        source = hit["_source"]
        sample_attacks.append({
            "timestamp": source.get("timestamp"),
            "device": source.get("device"),
            "message": source.get("message"),
            "program": source.get("program"),
            "level": source.get("level")
        })
    
    return {
        "total_attacks": total_attacks,
        "attacking_ips": attacking_ips,
        "targeted_devices": targeted_devices, 
        "failed_users": failed_users,
        "attack_methods": attack_methods,
        "attack_timeline": attack_timeline,
        "sample_attacks": sample_attacks,
        "device_name": device_name,
        "hours": hours
    }


def analyze_authentication_timeline_data(
    es_response: Dict[str, Any],
    device: Optional[str] = None,
    hours: int = 24,
    interval: str = "1h"
) -> Dict[str, Any]:
    """Analyze authentication timeline data from Elasticsearch response."""
    
    total_events = es_response["hits"]["total"]["value"]
    aggs = es_response.get("aggregations", {})
    
    # Process main timeline - look for authentication events in the base query results
    auth_timeline = []
    success_count = 0
    failure_count = 0
    
    # Extract sample authentication events from hits
    auth_events = []
    for hit in es_response["hits"]["hits"]:
        source = hit["_source"]
        message = source.get("message", "").lower()
        
        # Classify authentication event type
        event_type = "other"
        if any(term in message for term in ["failed password", "invalid user", "authentication failure"]):
            event_type = "failure"
            failure_count += 1
        elif any(term in message for term in ["accepted", "session opened", "login successful"]):
            event_type = "success"
            success_count += 1
        
        auth_events.append({
            "timestamp": source.get("timestamp"),
            "device": source.get("device"),
            "message": source.get("message"),
            "program": source.get("program"),
            "event_type": event_type,
            "user": _extract_username_from_message(source.get("message", "")),
            "source_ip": _extract_ip_from_message(source.get("message", ""))
        })
    
    # Process timeline aggregation if available
    if "auth_timeline" in aggs and "buckets" in aggs["auth_timeline"]:
        for bucket in aggs["auth_timeline"]["buckets"]:
            auth_timeline.append({
                "timestamp": bucket["key_as_string"],
                "total_events": bucket["doc_count"]
            })
    
    # Calculate authentication patterns
    auth_patterns = _analyze_auth_patterns(auth_events)
    
    # Identify peak periods
    peak_periods = _identify_peak_auth_periods(auth_timeline)
    
    # Calculate success/failure rates
    total_classified = success_count + failure_count
    success_rate = (success_count / total_classified * 100) if total_classified > 0 else 0
    failure_rate = (failure_count / total_classified * 100) if total_classified > 0 else 0
    
    # Assess security risk
    security_assessment = _assess_auth_security_risk(
        failure_rate, total_events, peak_periods, auth_patterns
    )
    
    return {
        "total_auth_events": total_events,
        "success_count": success_count,
        "failure_count": failure_count,
        "success_rate": success_rate,
        "failure_rate": failure_rate,
        "auth_timeline": auth_timeline,
        "auth_events": auth_events[:50],  # Limit sample events
        "auth_patterns": auth_patterns,
        "peak_periods": peak_periods,
        "security_assessment": security_assessment,
        "analysis_parameters": {
            "device": device,
            "hours": hours,
            "interval": interval
        }
    }


def _analyze_auth_patterns(auth_events: List[Dict]) -> Dict[str, Any]:
    """Analyze patterns in authentication events."""
    
    user_patterns = defaultdict(lambda: {"success": 0, "failure": 0})
    ip_patterns = defaultdict(lambda: {"success": 0, "failure": 0})
    time_patterns = defaultdict(lambda: {"success": 0, "failure": 0})
    
    for event in auth_events:
        user = event.get("user", "unknown")
        ip = event.get("source_ip", "unknown")
        event_type = event.get("event_type", "other")
        
        if event_type in ["success", "failure"]:
            user_patterns[user][event_type] += 1
            ip_patterns[ip][event_type] += 1
            
            # Extract hour for time pattern analysis
            timestamp = event.get("timestamp", "")
            if timestamp:
                try:
                    hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
                    time_patterns[hour][event_type] += 1
                except:
                    pass
    
    # Find most targeted users
    targeted_users = sorted(
        [(user, data["failure"]) for user, data in user_patterns.items()],
        key=lambda x: x[1], reverse=True
    )[:10]
    
    # Find most aggressive IPs
    aggressive_ips = sorted(
        [(ip, data["failure"]) for ip, data in ip_patterns.items() if ip != "unknown"],
        key=lambda x: x[1], reverse=True
    )[:10]
    
    # Find peak failure hours
    peak_hours = sorted(
        [(hour, data["failure"]) for hour, data in time_patterns.items()],
        key=lambda x: x[1], reverse=True
    )[:5]
    
    return {
        "targeted_users": targeted_users,
        "aggressive_ips": aggressive_ips,
        "peak_failure_hours": peak_hours,
        "total_unique_users": len(user_patterns),
        "total_unique_ips": len([ip for ip in ip_patterns.keys() if ip != "unknown"])
    }


def _identify_peak_auth_periods(timeline: List[Dict]) -> List[Dict]:
    """Identify peak authentication periods from timeline data."""
    if not timeline:
        return []
    
    # Calculate average activity
    total_events = sum(period.get("total_events", 0) for period in timeline)
    avg_events = total_events / len(timeline) if timeline else 0
    
    # Find periods with activity > 150% of average
    peaks = []
    for period in timeline:
        events = period.get("total_events", 0)
        if events > avg_events * 1.5:
            peaks.append({
                "timestamp": period["timestamp"],
                "events": events,
                "intensity": round(events / avg_events, 1) if avg_events > 0 else 0
            })
    
    return sorted(peaks, key=lambda x: x["events"], reverse=True)[:5]


def _assess_auth_security_risk(
    failure_rate: float,
    total_events: int,
    peak_periods: List[Dict],
    patterns: Dict[str, Any]
) -> Dict[str, Any]:
    """Assess overall authentication security risk."""
    
    risk_score = 0.0
    security_issues = []
    
    # High failure rate risk
    if failure_rate > 50:
        risk_score += 4.0
        security_issues.append(f"Very high authentication failure rate ({failure_rate:.1f}%)")
    elif failure_rate > 25:
        risk_score += 2.0
        security_issues.append(f"High authentication failure rate ({failure_rate:.1f}%)")
    
    # High volume risk
    if total_events > 1000:
        risk_score += 2.0
        security_issues.append("High volume of authentication attempts")
    
    # Peak activity risk
    if peak_periods and len(peak_periods) > 2:
        risk_score += 1.0
        security_issues.append("Multiple peak attack periods detected")
    
    # Aggressive IP risk
    aggressive_ips = patterns.get("aggressive_ips", [])
    if aggressive_ips and aggressive_ips[0][1] > 100:
        risk_score += 3.0
        security_issues.append(f"Highly aggressive IP detected ({aggressive_ips[0][1]} failures)")
    
    # Risk level
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
        "security_issues": security_issues,
        "recommendations": _get_auth_security_recommendations(risk_level, security_issues)
    }


def _extract_username_from_message(message: str) -> str:
    """Extract username from authentication log message."""
    # Common patterns for SSH authentication logs
    patterns = [
        r"Failed password for (\w+) from",
        r"Invalid user (\w+) from",
        r"Accepted .+ for (\w+) from",
        r"session opened for user (\w+)",
        r"user (\w+):"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)
    
    return "unknown"


def _extract_ip_from_message(message: str) -> str:
    """Extract IP address from log message."""
    ip_pattern = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    match = re.search(ip_pattern, message)
    return match.group(1) if match else "unknown"


def _get_auth_security_recommendations(risk_level: str, issues: List[str]) -> List[str]:
    """Get authentication security recommendations."""
    base_recommendations = [
        "Monitor authentication logs regularly",
        "Implement account lockout policies",
        "Use strong password requirements",
        "Enable multi-factor authentication where possible"
    ]
    
    if risk_level in ["CRITICAL", "HIGH"]:
        base_recommendations.extend([
            "Implement IP-based blocking for aggressive sources",
            "Consider changing SSH port from default (22)",
            "Review and strengthen access controls immediately"
        ])
    
    if any("aggressive IP" in issue for issue in issues):
        base_recommendations.append("Block or rate-limit identified aggressive IP addresses")
    
    if any("failure rate" in issue for issue in issues):
        base_recommendations.append("Implement stricter authentication policies")
    
    return base_recommendations[:6]  # Limit to top 6 recommendations