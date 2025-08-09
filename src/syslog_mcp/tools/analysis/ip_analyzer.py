"""
IP reputation analysis logic.

This module provides pure business logic for analyzing IP reputation data,
including threat assessment and geographic analysis.
No data access or presentation logic - just analysis.
"""

from typing import Any

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_ip_reputation_data(
    es_response: dict[str, Any],
    ip_address: str | None = None,
    hours: int = 24,
    min_attempts: int = 5,
    top_ips: int = 20
) -> dict[str, Any]:
    """Analyze IP reputation data from Elasticsearch response."""
    
    aggs = es_response.get("aggregations", {})
    
    # Process IP analysis data
    ip_reputation_data = []
    total_attempts = 0
    
    if "ip_analysis" in aggs:
        for bucket in aggs["ip_analysis"]["buckets"]:
            ip = bucket["key"]
            attempts = bucket["doc_count"]
            
            if ip == "unknown":
                continue
            
            # Filter by specific IP if provided
            if ip_address and ip != ip_address:
                continue
                
            # Filter by minimum attempts threshold
            if attempts < min_attempts:
                continue
                
            total_attempts += attempts
            
            # Extract sub-aggregations for this IP
            ip_data = {
                "ip": ip,
                "attempts": attempts,
                "attack_patterns": [],
                "targeted_services": [],
                "activity_timeline": [],
                "sample_logs": []
            }
            
            # Attack patterns
            if "attack_patterns" in bucket:
                for pattern_bucket in bucket["attack_patterns"]["buckets"]:
                    ip_data["attack_patterns"].append({
                        "pattern": pattern_bucket["key"],
                        "count": pattern_bucket["doc_count"]
                    })
            
            # Targeted services
            if "targeted_services" in bucket:
                for service_bucket in bucket["targeted_services"]["buckets"]:
                    ip_data["targeted_services"].append({
                        "service": service_bucket["key"],
                        "count": service_bucket["doc_count"]
                    })
            
            # Activity timeline
            if "activity_timeline" in bucket:
                for time_bucket in bucket["activity_timeline"]["buckets"]:
                    ip_data["activity_timeline"].append({
                        "timestamp": time_bucket["key_as_string"],
                        "count": time_bucket["doc_count"]
                    })
            
            # Sample logs
            if "sample_logs" in bucket and "hits" in bucket["sample_logs"]:
                for hit in bucket["sample_logs"]["hits"]["hits"]:
                    source = hit["_source"]
                    ip_data["sample_logs"].append({
                        "timestamp": source.get("timestamp"),
                        "device": source.get("device"),
                        "message": source.get("message"),
                        "program": source.get("program")
                    })
            
            ip_reputation_data.append(ip_data)
    
    # Process geographic distribution
    geographic_data = []
    if "geographic_distribution" in aggs:
        for bucket in aggs["geographic_distribution"]["buckets"]:
            region = bucket["key"]
            count = bucket["doc_count"]
            if region != "Unknown":
                geographic_data.append({
                    "region": region,
                    "count": count
                })
    
    # Calculate reputation scores for each IP
    for ip_data in ip_reputation_data:
        ip_data["reputation_score"] = _calculate_ip_reputation_score(
            ip_data["attempts"], 
            ip_data["attack_patterns"],
            hours
        )
        ip_data["threat_level"] = _get_threat_level(ip_data["reputation_score"])
        ip_data["risk_analysis"] = _analyze_ip_risk_factors(ip_data)
    
    # Sort by reputation score (highest risk first)
    ip_reputation_data.sort(key=lambda x: x["reputation_score"], reverse=True)
    
    return {
        "ip_reputation_data": ip_reputation_data[:top_ips],
        "geographic_data": geographic_data,
        "total_attempts": total_attempts,
        "analysis_period_hours": hours,
        "min_attempts_threshold": min_attempts,
        "specific_ip": ip_address,
        "threat_summary": _generate_threat_summary(ip_reputation_data[:top_ips])
    }


def _calculate_ip_reputation_score(attempts: int, attack_patterns: list[dict], hours: int) -> float:
    """Calculate reputation score for an IP address (0-100, higher = more dangerous)."""
    base_score = min(attempts / hours * 2, 50)  # Base score from frequency
    
    pattern_multiplier = 1.0
    for pattern in attack_patterns:
        if pattern["pattern"] == "Brute Force":
            pattern_multiplier += 0.3
        elif pattern["pattern"] == "User Scanning":
            pattern_multiplier += 0.2
        elif pattern["pattern"] == "Connection Probing":
            pattern_multiplier += 0.1
    
    final_score = min(base_score * pattern_multiplier, 100)
    return round(final_score, 1)


def _get_threat_level(score: float) -> str:
    """Convert reputation score to threat level."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def _analyze_ip_risk_factors(ip_data: dict[str, Any]) -> dict[str, Any]:
    """Analyze specific risk factors for an IP address."""
    
    risk_factors = []
    risk_indicators = {
        "high_volume": False,
        "brute_force": False,
        "user_enumeration": False,
        "service_scanning": False,
        "persistent_attacks": False
    }
    
    # High volume attacks
    if ip_data["attempts"] > 100:
        risk_factors.append(f"High attack volume ({ip_data['attempts']} attempts)")
        risk_indicators["high_volume"] = True
    
    # Attack pattern analysis
    for pattern in ip_data["attack_patterns"]:
        if pattern["pattern"] == "Brute Force" and pattern["count"] > 20:
            risk_factors.append(f"Brute force attacks ({pattern['count']} attempts)")
            risk_indicators["brute_force"] = True
        elif pattern["pattern"] == "User Scanning" and pattern["count"] > 10:
            risk_factors.append(f"Username enumeration ({pattern['count']} attempts)")
            risk_indicators["user_enumeration"] = True
        elif pattern["pattern"] == "Connection Probing":
            risk_factors.append("Service scanning/probing detected")
            risk_indicators["service_scanning"] = True
    
    # Timeline persistence analysis
    timeline_data = ip_data.get("activity_timeline", [])
    if timeline_data and len([t for t in timeline_data if t["count"] > 0]) > 12:  # Active for >12 hours
        risk_factors.append("Persistent attack pattern over extended period")
        risk_indicators["persistent_attacks"] = True
    
    # Service targeting analysis
    targeted_services = ip_data.get("targeted_services", [])
    if len(targeted_services) > 3:
        service_names = [s["service"] for s in targeted_services[:3]]
        risk_factors.append(f"Multiple service targeting: {', '.join(service_names)}")
    
    return {
        "risk_factors": risk_factors,
        "risk_indicators": risk_indicators,
        "overall_risk_score": _calculate_overall_ip_risk(risk_indicators, ip_data["attempts"])
    }


def _calculate_overall_ip_risk(indicators: dict[str, bool], attempts: int) -> float:
    """Calculate overall risk score based on indicators."""
    
    base_risk = min(attempts / 50, 5.0)  # Base risk from volume
    
    indicator_weights = {
        "high_volume": 2.0,
        "brute_force": 2.5,
        "user_enumeration": 2.0,
        "service_scanning": 1.5,
        "persistent_attacks": 3.0
    }
    
    indicator_risk = sum(weight for indicator, weight in indicator_weights.items() if indicators.get(indicator, False))
    
    total_risk = min(base_risk + indicator_risk, 10.0)
    return round(total_risk, 1)


def _generate_threat_summary(ip_data_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate overall threat summary from IP reputation data."""
    
    if not ip_data_list:
        return {
            "total_malicious_ips": 0,
            "highest_threat_level": "NONE",
            "total_attack_attempts": 0,
            "geographic_diversity": 0,
            "key_threats": []
        }
    
    # Count by threat level
    threat_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    total_attempts = 0
    key_threats = []
    
    for ip_data in ip_data_list:
        threat_level = ip_data.get("threat_level", "MINIMAL")
        threat_counts[threat_level] += 1
        total_attempts += ip_data.get("attempts", 0)
        
        # Collect key threats (CRITICAL and HIGH)
        if threat_level in ["CRITICAL", "HIGH"]:
            key_threats.append({
                "ip": ip_data["ip"],
                "threat_level": threat_level,
                "attempts": ip_data["attempts"],
                "primary_attack": ip_data["attack_patterns"][0]["pattern"] if ip_data["attack_patterns"] else "Unknown"
            })
    
    # Determine highest threat level
    highest_threat = "MINIMAL"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if threat_counts[level] > 0:
            highest_threat = level
            break
    
    return {
        "total_malicious_ips": len(ip_data_list),
        "threat_level_distribution": threat_counts,
        "highest_threat_level": highest_threat,
        "total_attack_attempts": total_attempts,
        "key_threats": key_threats[:5],  # Top 5 key threats
        "recommendations": _get_threat_mitigation_recommendations(highest_threat, key_threats)
    }


def _get_threat_mitigation_recommendations(highest_threat: str, key_threats: list[dict]) -> list[str]:
    """Get recommendations for threat mitigation based on analysis."""
    
    recommendations = []
    
    if highest_threat == "CRITICAL":
        recommendations.extend([
            "IMMEDIATE ACTION: Block critical threat IPs at firewall level",
            "Implement emergency rate limiting for authentication attempts",
            "Consider temporarily disabling external SSH access if possible"
        ])
    elif highest_threat == "HIGH":
        recommendations.extend([
            "Block high-threat IPs and implement fail2ban rules",
            "Enable enhanced logging for authentication attempts",
            "Review and strengthen password policies"
        ])
    
    # Specific threat-based recommendations
    if key_threats:
        brute_force_ips = [t for t in key_threats if "brute force" in t.get("primary_attack", "").lower()]
        if brute_force_ips:
            recommendations.append(f"Focus on brute force protection - {len(brute_force_ips)} IPs detected")
        
        scanning_ips = [t for t in key_threats if "scanning" in t.get("primary_attack", "").lower()]
        if scanning_ips:
            recommendations.append(f"Implement service discovery protection - {len(scanning_ips)} scanning IPs")
    
    # General recommendations
    recommendations.extend([
        "Monitor IP reputation feeds and blacklists",
        "Implement geographic IP filtering if appropriate",
        "Regular review of authentication logs and failed attempts"
    ])
    
    return recommendations[:6]  # Limit to 6 recommendations
