"""
System performance analysis logic.

This module provides pure business logic for analyzing system performance data,
including activity patterns, stability metrics, and performance insights.
No data access or presentation logic - just analysis.
"""

from typing import Any, Dict, List, Optional

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_system_performance_data(
    activity_timeline: List[Dict],
    error_timeline: List[Dict],
    hours: int
) -> Dict[str, Any]:
    """Analyze system performance data from timeline information."""
    
    # Calculate activity statistics
    activity_stats = _calculate_activity_statistics(activity_timeline)
    
    # Identify activity anomalies
    activity_anomalies = _identify_activity_anomalies(activity_timeline)
    
    # Calculate error rate trends
    error_trends = _analyze_error_trends(error_timeline, hours)
    
    # Identify correlation between activity and errors
    activity_error_correlation = _analyze_activity_error_correlation(
        activity_timeline, error_timeline
    )
    
    # Calculate system stability metrics
    stability_metrics = _calculate_stability_metrics(
        activity_timeline, error_timeline, hours
    )
    
    # Generate performance insights
    performance_insights = _generate_performance_insights(
        activity_stats, activity_anomalies, error_trends, stability_metrics
    )
    
    return {
        "activity_statistics": activity_stats,
        "activity_anomalies": activity_anomalies,
        "error_trends": error_trends,
        "activity_error_correlation": activity_error_correlation,
        "stability_metrics": stability_metrics,
        "performance_insights": performance_insights,
        "analysis_period_hours": hours
    }


def _calculate_activity_statistics(timeline: List[Dict]) -> Dict[str, Any]:
    """Calculate basic activity statistics."""
    
    if not timeline:
        return {"mean": 0, "max": 0, "min": 0, "total": 0, "periods": 0}
    
    counts = [period.get("log_count", 0) for period in timeline]
    
    return {
        "mean": round(sum(counts) / len(counts), 1),
        "max": max(counts),
        "min": min(counts),
        "total": sum(counts),
        "periods": len(counts)
    }


def _identify_activity_anomalies(timeline: List[Dict]) -> List[Dict]:
    """Identify unusual activity patterns."""
    
    if len(timeline) < 3:
        return []
    
    counts = [period.get("log_count", 0) for period in timeline]
    mean = sum(counts) / len(counts)
    
    anomalies = []
    for period in timeline:
        count = period.get("log_count", 0)
        
        # Detect spikes (> 3x mean) or drops (< 0.1x mean, but not zero)
        if count > mean * 3:
            anomalies.append({
                "type": "SPIKE",
                "timestamp": period["timestamp"],
                "count": count,
                "factor": round(count / mean, 1) if mean > 0 else 0
            })
        elif count < mean * 0.1 and count > 0:
            anomalies.append({
                "type": "DROP",
                "timestamp": period["timestamp"], 
                "count": count,
                "factor": round(count / mean, 1) if mean > 0 else 0
            })
    
    return anomalies


def _analyze_error_trends(error_timeline: List[Dict], hours: int) -> Dict[str, Any]:
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


def _analyze_activity_error_correlation(
    activity_timeline: List[Dict],
    error_timeline: List[Dict]
) -> Dict[str, Any]:
    """Analyze correlation between activity levels and error rates."""
    
    if not activity_timeline or not error_timeline:
        return {"correlation": "INSUFFICIENT_DATA"}
    
    # Align timelines (simplified - assumes same intervals)
    min_length = min(len(activity_timeline), len(error_timeline))
    activity_counts = [activity_timeline[i].get("log_count", 0) for i in range(min_length)]
    error_counts = [error_timeline[i].get("error_count", 0) for i in range(min_length)]
    
    # Simple correlation analysis
    activity_average = sum(activity_counts) / len(activity_counts) if len(activity_counts) > 0 else 0
    high_activity_periods = sum(1 for count in activity_counts if count > activity_average)
    high_error_periods = sum(1 for count in error_counts if count > 0)
    
    if high_activity_periods > 0:
        correlation_ratio = high_error_periods / high_activity_periods
        
        if correlation_ratio > 0.7:
            return {"correlation": "HIGH", "ratio": round(correlation_ratio, 2)}
        elif correlation_ratio > 0.3:
            return {"correlation": "MODERATE", "ratio": round(correlation_ratio, 2)}
        else:
            return {"correlation": "LOW", "ratio": round(correlation_ratio, 2)}
    
    return {"correlation": "INSUFFICIENT_DATA"}


def _calculate_stability_metrics(
    activity_timeline: List[Dict],
    error_timeline: List[Dict],
    hours: int
) -> Dict[str, Any]:
    """Calculate system stability metrics."""
    
    if not activity_timeline:
        return {"stability_score": 0, "uptime_percentage": 0}
    
    # Calculate periods with activity (proxy for uptime)
    active_periods = sum(1 for period in activity_timeline if period.get("log_count", 0) > 0)
    total_periods = len(activity_timeline)
    uptime_percentage = (active_periods / total_periods) * 100 if total_periods > 0 else 0
    
    # Calculate error-free periods
    error_free_periods = 0
    if error_timeline:
        error_free_periods = sum(1 for period in error_timeline if period.get("error_count", 0) == 0)
        total_error_periods = len(error_timeline)
        error_free_percentage = (error_free_periods / total_error_periods) * 100 if total_error_periods > 0 else 100
    else:
        error_free_percentage = 100
    
    # Calculate overall stability score
    stability_score = (uptime_percentage * 0.6) + (error_free_percentage * 0.4)
    
    # Calculate additional stability metrics
    consistency_score = _calculate_consistency_score(activity_timeline)
    reliability_score = _calculate_reliability_score(error_timeline, hours)
    
    return {
        "stability_score": round(stability_score, 1),
        "uptime_percentage": round(uptime_percentage, 1),
        "error_free_percentage": round(error_free_percentage, 1),
        "consistency_score": consistency_score,
        "reliability_score": reliability_score,
        "active_periods": active_periods,
        "total_periods": total_periods
    }


def _calculate_consistency_score(activity_timeline: List[Dict]) -> Dict[str, Any]:
    """Calculate consistency score based on activity variance."""
    
    if not activity_timeline:
        return {"score": 0, "grade": "UNKNOWN"}
    
    counts = [period.get("log_count", 0) for period in activity_timeline]
    mean = sum(counts) / len(counts) if counts else 0
    
    if mean == 0:
        return {"score": 100, "grade": "STABLE", "description": "No activity detected"}
    
    # Calculate coefficient of variation
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std_dev = variance ** 0.5
    cv = (std_dev / mean) * 100
    
    # Convert to consistency score (lower variance = higher consistency)
    consistency_score = max(0, 100 - cv)
    
    if consistency_score >= 80:
        grade = "EXCELLENT"
        description = "Very consistent activity patterns"
    elif consistency_score >= 60:
        grade = "GOOD"
        description = "Generally consistent with minor variations"
    elif consistency_score >= 40:
        grade = "FAIR"
        description = "Moderate consistency with some variations"
    else:
        grade = "POOR"
        description = "High variability in activity patterns"
    
    return {
        "score": round(consistency_score, 1),
        "grade": grade,
        "description": description,
        "coefficient_of_variation": round(cv, 1)
    }


def _calculate_reliability_score(error_timeline: List[Dict], hours: int) -> Dict[str, Any]:
    """Calculate reliability score based on error frequency and distribution."""
    
    if not error_timeline:
        return {"score": 100, "grade": "EXCELLENT", "description": "No errors detected"}
    
    error_counts = [period.get("error_count", 0) for period in error_timeline]
    total_errors = sum(error_counts)
    
    if total_errors == 0:
        return {"score": 100, "grade": "EXCELLENT", "description": "Error-free operation"}
    
    # Calculate error rate per hour
    error_rate = total_errors / hours if hours > 0 else 0
    
    # Calculate reliability score based on error rate
    if error_rate <= 1:
        reliability_score = 95
        grade = "EXCELLENT"
        description = "Very low error rate"
    elif error_rate <= 5:
        reliability_score = 85
        grade = "GOOD"
        description = "Low error rate"
    elif error_rate <= 10:
        reliability_score = 70
        grade = "FAIR"
        description = "Moderate error rate"
    elif error_rate <= 20:
        reliability_score = 50
        grade = "POOR"
        description = "High error rate"
    else:
        reliability_score = 25
        grade = "CRITICAL"
        description = "Very high error rate"
    
    # Adjust for error distribution (penalize concentrated error periods)
    max_errors_in_period = max(error_counts)
    avg_errors = total_errors / len(error_counts)
    
    if max_errors_in_period > avg_errors * 3:  # High concentration penalty
        reliability_score -= 10
        description += " with concentrated error periods"
    
    reliability_score = max(0, reliability_score)
    
    return {
        "score": round(reliability_score, 1),
        "grade": grade,
        "description": description,
        "error_rate_per_hour": round(error_rate, 1),
        "total_errors": total_errors
    }


def _generate_performance_insights(
    activity_stats: Dict,
    anomalies: List[Dict],
    error_trends: Dict,
    stability_metrics: Dict
) -> List[str]:
    """Generate performance insights and recommendations."""
    
    insights = []
    
    # Activity insights
    if activity_stats.get("max", 0) > activity_stats.get("mean", 0) * 5:
        insights.append(f"High activity spikes detected - peak {activity_stats['max']} vs avg {activity_stats['mean']}")
    
    # Anomaly insights
    if len(anomalies) > 2:
        spike_count = sum(1 for a in anomalies if a["type"] == "SPIKE")
        drop_count = sum(1 for a in anomalies if a["type"] == "DROP")
        
        if spike_count > 0:
            insights.append(f"Activity instability detected - {spike_count} significant spikes")
        
        if drop_count > 0:
            insights.append(f"Activity drops detected - {drop_count} significant decreases")
    
    # Error trend insights
    if error_trends.get("trend") == "INCREASING":
        insights.append(f"Error rate increasing by {error_trends.get('trend_percentage', 0):.1f}%")
    elif error_trends.get("trend") == "DECREASING":
        insights.append(f"Error rate decreasing by {error_trends.get('trend_percentage', 0):.1f}%")
    
    # Stability insights
    stability_score = stability_metrics.get("stability_score", 0)
    if stability_score < 80:
        insights.append(f"System stability concerns - {stability_score:.1f}% stability score")
    
    # Consistency insights
    consistency = stability_metrics.get("consistency_score", {})
    if consistency.get("score", 0) < 60:
        insights.append(f"Activity patterns inconsistent - {consistency.get('description', 'high variability')}")
    
    # Reliability insights
    reliability = stability_metrics.get("reliability_score", {})
    if reliability.get("score", 0) < 70:
        insights.append(f"Reliability concerns - {reliability.get('description', 'high error rate')}")
    
    if not insights:
        insights.append("System performance appears stable with no significant issues detected")
    
    return insights


def analyze_resource_utilization_patterns(
    activity_timeline: List[Dict],
    hours: int
) -> Dict[str, Any]:
    """Analyze resource utilization patterns from activity data."""
    
    if not activity_timeline:
        return {"utilization_score": 0, "pattern_analysis": "No data available"}
    
    counts = [period.get("log_count", 0) for period in activity_timeline]
    total_activity = sum(counts)
    max_activity = max(counts)
    avg_activity = total_activity / len(counts)
    
    # Calculate utilization score (how efficiently resources are used)
    if max_activity > 0:
        utilization_efficiency = avg_activity / max_activity
        utilization_score = utilization_efficiency * 100
    else:
        utilization_efficiency = 0
        utilization_score = 0
    
    # Analyze activity patterns
    peak_periods = sum(1 for count in counts if count > avg_activity * 1.5)
    idle_periods = sum(1 for count in counts if count < avg_activity * 0.3)
    
    pattern_analysis = {
        "peak_utilization_periods": peak_periods,
        "low_utilization_periods": idle_periods,
        "average_utilization": round(avg_activity, 1),
        "peak_utilization": max_activity,
        "utilization_efficiency": round(utilization_efficiency, 3) if max_activity > 0 else 0
    }
    
    # Generate utilization insights
    if utilization_score > 80:
        utilization_grade = "EXCELLENT"
        utilization_insight = "Efficient resource utilization with consistent activity"
    elif utilization_score > 60:
        utilization_grade = "GOOD"
        utilization_insight = "Good resource utilization with minor inefficiencies"
    elif utilization_score > 40:
        utilization_grade = "FAIR"
        utilization_insight = "Moderate resource utilization with room for improvement"
    else:
        utilization_grade = "POOR"
        utilization_insight = "Poor resource utilization with significant waste"
    
    return {
        "utilization_score": round(utilization_score, 1),
        "utilization_grade": utilization_grade,
        "utilization_insight": utilization_insight,
        "pattern_analysis": pattern_analysis,
        "recommendations": _get_utilization_recommendations(utilization_score, pattern_analysis, len(counts))
    }


def _get_utilization_recommendations(score: float, pattern_analysis: Dict, total_periods: int = 0) -> List[str]:
    """Get recommendations for improving resource utilization."""
    
    recommendations = []
    
    if score < 60:
        recommendations.append("Consider optimizing resource allocation to reduce waste")
        recommendations.append("Investigate causes of low utilization periods")
    
    peak_periods = pattern_analysis.get("peak_utilization_periods", 0)
    if peak_periods > 0 and total_periods > 0 and peak_periods > total_periods * 0.3:  # More than 30% peak periods
        recommendations.append("Consider load balancing to distribute peak activity")
    
    idle_periods = pattern_analysis.get("low_utilization_periods", 0)
    if idle_periods > 5:
        recommendations.append("Review system configuration for idle period optimization")
    
    if not recommendations:
        recommendations.append("Resource utilization appears optimal")
    
    return recommendations