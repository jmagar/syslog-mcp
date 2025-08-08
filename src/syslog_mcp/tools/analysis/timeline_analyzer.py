"""
Timeline analysis logic.

This module provides pure business logic for analyzing timeline-based data,
including authentication patterns, activity trends, and temporal insights.
No data access or presentation logic - just analysis.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_authentication_timeline_data(
    es_response: Dict[str, Any],
    hours: int,
    interval: str = "1h"
) -> Dict[str, Any]:
    """Analyze authentication timeline data from Elasticsearch response."""
    
    aggs = es_response.get("aggregations", {})
    
    # Process timeline buckets
    timeline_data = []
    if "auth_timeline" in aggs:
        for bucket in aggs["auth_timeline"]["buckets"]:
            timestamp = bucket["key_as_string"]
            total_attempts = bucket["doc_count"]
            
            # Get success/failure breakdown
            successful_attempts = 0
            failed_attempts = 0
            
            if "auth_status" in bucket:
                for status_bucket in bucket["auth_status"]["buckets"]:
                    count = status_bucket["doc_count"]
                    if "success" in status_bucket["key"].lower():
                        successful_attempts = count
                    else:
                        failed_attempts = count
            
            timeline_data.append({
                "timestamp": timestamp,
                "total_attempts": total_attempts,
                "successful_attempts": successful_attempts,
                "failed_attempts": failed_attempts,
                "success_rate": round((successful_attempts / total_attempts) * 100, 1) if total_attempts > 0 else 0
            })
    
    # Analyze timeline patterns
    timeline_patterns = _analyze_timeline_patterns(timeline_data, hours, interval)
    
    # Identify peak periods
    peak_periods = _identify_peak_authentication_periods(timeline_data)
    
    # Calculate overall metrics
    total_attempts = sum(period["total_attempts"] for period in timeline_data)
    total_successful = sum(period["successful_attempts"] for period in timeline_data)
    total_failed = sum(period["failed_attempts"] for period in timeline_data)
    
    overall_success_rate = round((total_successful / total_attempts) * 100, 1) if total_attempts > 0 else 0
    
    # Analyze authentication trends
    auth_trends = _analyze_authentication_trends(timeline_data)
    
    # Generate insights
    timeline_insights = _generate_timeline_insights(timeline_patterns, auth_trends, peak_periods)
    
    return {
        "timeline_data": timeline_data,
        "timeline_patterns": timeline_patterns,
        "peak_periods": peak_periods[:5],  # Top 5 peak periods
        "total_attempts": total_attempts,
        "total_successful": total_successful,
        "total_failed": total_failed,
        "overall_success_rate": overall_success_rate,
        "auth_trends": auth_trends,
        "timeline_insights": timeline_insights,
        "analysis_parameters": {
            "hours": hours,
            "interval": interval
        }
    }


def analyze_activity_timeline_data(
    timeline_buckets: List[Dict],
    hours: int,
    interval: str = "1h"
) -> Dict[str, Any]:
    """Analyze activity timeline patterns."""
    
    if not timeline_buckets:
        return {"activity_level": "no_data", "patterns": []}
    
    # Process timeline data
    activity_data = []
    for bucket in timeline_buckets:
        activity_data.append({
            "timestamp": bucket["key_as_string"],
            "log_count": bucket["doc_count"]
        })
    
    # Calculate activity metrics
    activity_metrics = _calculate_activity_metrics(activity_data)
    
    # Identify activity patterns
    activity_patterns = _identify_activity_patterns(activity_data, hours)
    
    # Detect anomalies
    activity_anomalies = _detect_activity_anomalies(activity_data)
    
    # Calculate consistency score
    consistency_score = _calculate_activity_consistency(activity_data)
    
    return {
        "activity_data": activity_data,
        "activity_metrics": activity_metrics,
        "activity_patterns": activity_patterns,
        "activity_anomalies": activity_anomalies,
        "consistency_score": consistency_score,
        "analysis_period": {"hours": hours, "interval": interval}
    }


def analyze_temporal_patterns(
    timeline_data: List[Dict],
    pattern_type: str = "general"
) -> Dict[str, Any]:
    """Analyze temporal patterns in timeline data."""
    
    if not timeline_data:
        return {"patterns": [], "insights": []}
    
    # Extract temporal features
    temporal_features = _extract_temporal_features(timeline_data)
    
    # Identify cyclical patterns
    cyclical_patterns = _identify_cyclical_patterns(timeline_data, pattern_type)
    
    # Detect temporal anomalies
    temporal_anomalies = _detect_temporal_anomalies(timeline_data)
    
    # Calculate pattern strength
    pattern_strength = _calculate_pattern_strength(cyclical_patterns)
    
    # Generate temporal insights
    temporal_insights = _generate_temporal_insights(
        temporal_features, cyclical_patterns, temporal_anomalies
    )
    
    return {
        "temporal_features": temporal_features,
        "cyclical_patterns": cyclical_patterns,
        "temporal_anomalies": temporal_anomalies,
        "pattern_strength": pattern_strength,
        "temporal_insights": temporal_insights
    }


def _analyze_timeline_patterns(
    timeline_data: List[Dict],
    hours: int,
    interval: str
) -> Dict[str, Any]:
    """Analyze patterns in timeline data."""
    
    if not timeline_data:
        return {"pattern_type": "no_data"}
    
    # Calculate baseline activity
    total_periods = len(timeline_data)
    avg_attempts_per_period = sum(p["total_attempts"] for p in timeline_data) / total_periods if total_periods > 0 else 0
    
    # Identify high-activity periods
    high_activity_threshold = avg_attempts_per_period * 1.5
    high_activity_periods = [p for p in timeline_data if p["total_attempts"] > high_activity_threshold]
    
    # Identify low-activity periods
    low_activity_threshold = avg_attempts_per_period * 0.5
    low_activity_periods = [p for p in timeline_data if p["total_attempts"] < low_activity_threshold]
    
    # Calculate activity variance
    variance = sum((p["total_attempts"] - avg_attempts_per_period) ** 2 for p in timeline_data) / total_periods if total_periods > 0 else 0
    std_deviation = variance ** 0.5
    
    # Determine pattern type
    if std_deviation < avg_attempts_per_period * 0.3:
        pattern_type = "CONSISTENT"
    elif len(high_activity_periods) > total_periods * 0.3:
        pattern_type = "BURST_HEAVY"
    elif len(low_activity_periods) > total_periods * 0.3:
        pattern_type = "SPARSE"
    else:
        pattern_type = "VARIABLE"
    
    return {
        "pattern_type": pattern_type,
        "average_attempts_per_period": round(avg_attempts_per_period, 1),
        "high_activity_periods": len(high_activity_periods),
        "low_activity_periods": len(low_activity_periods),
        "variance": round(variance, 2),
        "standard_deviation": round(std_deviation, 2),
        "total_periods": total_periods
    }


def _identify_peak_authentication_periods(timeline_data: List[Dict]) -> List[Dict]:
    """Identify peak authentication periods."""
    
    if not timeline_data:
        return []
    
    # Sort by total attempts (descending)
    sorted_periods = sorted(timeline_data, key=lambda x: x["total_attempts"], reverse=True)
    
    # Get top periods with significant activity
    avg_attempts = sum(p["total_attempts"] for p in timeline_data) / len(timeline_data)
    peak_threshold = max(avg_attempts * 1.5, 10)  # At least 1.5x average or 10 attempts
    
    peak_periods = []
    for period in sorted_periods[:10]:  # Consider top 10 periods
        if period["total_attempts"] >= peak_threshold:
            peak_periods.append({
                "timestamp": period["timestamp"],
                "total_attempts": period["total_attempts"],
                "failed_attempts": period["failed_attempts"],
                "success_rate": period["success_rate"],
                "intensity": round(period["total_attempts"] / avg_attempts, 1) if avg_attempts > 0 else 0
            })
    
    return peak_periods


def _analyze_authentication_trends(timeline_data: List[Dict]) -> Dict[str, Any]:
    """Analyze authentication trends over time."""
    
    if len(timeline_data) < 2:
        return {"trend": "INSUFFICIENT_DATA"}
    
    # Calculate trends for different metrics
    attempts_trend = _calculate_trend([p["total_attempts"] for p in timeline_data])
    failures_trend = _calculate_trend([p["failed_attempts"] for p in timeline_data])
    success_rate_trend = _calculate_trend([p["success_rate"] for p in timeline_data])
    
    # Determine overall trend direction
    if attempts_trend["direction"] == "INCREASING" and failures_trend["direction"] == "INCREASING":
        overall_trend = "DEGRADING"
        trend_description = "Increasing authentication attempts with rising failure rate"
    elif attempts_trend["direction"] == "INCREASING" and success_rate_trend["direction"] == "INCREASING":
        overall_trend = "IMPROVING"
        trend_description = "Increasing authentication activity with improving success rate"
    elif attempts_trend["direction"] == "DECREASING":
        overall_trend = "DECLINING"
        trend_description = "Decreasing authentication activity"
    else:
        overall_trend = "STABLE"
        trend_description = "Stable authentication patterns"
    
    return {
        "overall_trend": overall_trend,
        "trend_description": trend_description,
        "attempts_trend": attempts_trend,
        "failures_trend": failures_trend,
        "success_rate_trend": success_rate_trend
    }


def _calculate_activity_metrics(activity_data: List[Dict]) -> Dict[str, Any]:
    """Calculate basic activity metrics."""
    
    if not activity_data:
        return {"total_activity": 0, "average_activity": 0}
    
    counts = [period["log_count"] for period in activity_data]
    total_activity = sum(counts)
    average_activity = total_activity / len(counts)
    max_activity = max(counts)
    min_activity = min(counts)
    
    # Calculate activity distribution
    variance = sum((count - average_activity) ** 2 for count in counts) / len(counts)
    std_deviation = variance ** 0.5
    
    return {
        "total_activity": total_activity,
        "average_activity": round(average_activity, 1),
        "max_activity": max_activity,
        "min_activity": min_activity,
        "standard_deviation": round(std_deviation, 2),
        "coefficient_of_variation": round(std_deviation / average_activity, 2) if average_activity > 0 else 0
    }


def _identify_activity_patterns(activity_data: List[Dict], hours: int) -> List[Dict]:
    """Identify patterns in activity data."""
    
    patterns = []
    
    if not activity_data:
        return patterns
    
    counts = [period["log_count"] for period in activity_data]
    avg_count = sum(counts) / len(counts)
    
    # Identify spikes
    spike_threshold = avg_count * 2
    spikes = [
        {"timestamp": period["timestamp"], "count": period["log_count"], "type": "SPIKE"}
        for period in activity_data
        if period["log_count"] > spike_threshold
    ]
    patterns.extend(spikes)
    
    # Identify quiet periods
    quiet_threshold = avg_count * 0.3
    quiet_periods = [
        {"timestamp": period["timestamp"], "count": period["log_count"], "type": "QUIET"}
        for period in activity_data
        if period["log_count"] < quiet_threshold and period["log_count"] > 0
    ]
    patterns.extend(quiet_periods)
    
    return patterns


def _detect_activity_anomalies(activity_data: List[Dict]) -> List[Dict]:
    """Detect anomalies in activity data."""
    
    if len(activity_data) < 5:
        return []
    
    counts = [period["log_count"] for period in activity_data]
    mean = sum(counts) / len(counts)
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std_dev = variance ** 0.5
    
    anomalies = []
    
    # Use 2-sigma rule for anomaly detection
    lower_bound = mean - (2 * std_dev)
    upper_bound = mean + (2 * std_dev)
    
    for period in activity_data:
        count = period["log_count"]
        if count < lower_bound or count > upper_bound:
            anomaly_type = "HIGH" if count > upper_bound else "LOW"
            anomalies.append({
                "timestamp": period["timestamp"],
                "count": count,
                "type": anomaly_type,
                "deviation": round(abs(count - mean) / std_dev, 1) if std_dev > 0 else 0
            })
    
    return anomalies


def _calculate_activity_consistency(activity_data: List[Dict]) -> Dict[str, Any]:
    """Calculate consistency score for activity data."""
    
    if not activity_data:
        return {"score": 0, "grade": "NO_DATA"}
    
    counts = [period["log_count"] for period in activity_data]
    mean = sum(counts) / len(counts)
    
    if mean == 0:
        return {"score": 100, "grade": "STABLE", "description": "No activity variation"}
    
    # Calculate coefficient of variation
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std_dev = variance ** 0.5
    cv = (std_dev / mean) * 100
    
    # Convert to consistency score (lower CV = higher consistency)
    consistency_score = max(0, 100 - cv)
    
    if consistency_score >= 85:
        grade = "EXCELLENT"
        description = "Very consistent activity levels"
    elif consistency_score >= 70:
        grade = "GOOD"
        description = "Generally consistent activity"
    elif consistency_score >= 50:
        grade = "FAIR"
        description = "Moderate consistency"
    else:
        grade = "POOR"
        description = "Highly variable activity"
    
    return {
        "score": round(consistency_score, 1),
        "grade": grade,
        "description": description,
        "coefficient_of_variation": round(cv, 1)
    }


def _extract_temporal_features(timeline_data: List[Dict]) -> Dict[str, Any]:
    """Extract temporal features from timeline data."""
    
    features = {
        "duration_hours": 0,
        "data_points": len(timeline_data),
        "time_coverage": 0
    }
    
    if len(timeline_data) >= 2:
        # Calculate time span
        first_timestamp = timeline_data[0]["timestamp"]
        last_timestamp = timeline_data[-1]["timestamp"]
        
        try:
            first_dt = datetime.fromisoformat(first_timestamp.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(last_timestamp.replace("Z", "+00:00"))
            duration = last_dt - first_dt
            features["duration_hours"] = round(duration.total_seconds() / 3600, 1)
        except:
            pass
    
    return features


def _identify_cyclical_patterns(timeline_data: List[Dict], pattern_type: str) -> List[Dict]:
    """Identify cyclical patterns in timeline data."""
    
    # This is a simplified implementation
    # In a real system, you might use FFT or other signal processing techniques
    
    patterns = []
    
    if len(timeline_data) < 24:  # Need at least 24 data points for daily pattern
        return patterns
    
    # Look for daily patterns (assuming hourly data)
    if pattern_type in ["authentication", "general"]:
        daily_pattern = _detect_daily_pattern(timeline_data)
        if daily_pattern:
            patterns.append(daily_pattern)
    
    return patterns


def _detect_daily_pattern(timeline_data: List[Dict]) -> Optional[Dict]:
    """Detect daily patterns in timeline data."""
    
    # Group data by hour of day
    hourly_activity = defaultdict(list)
    
    for period in timeline_data:
        try:
            dt = datetime.fromisoformat(period["timestamp"].replace("Z", "+00:00"))
            hour = dt.hour
            activity = period.get("total_attempts", period.get("log_count", 0))
            hourly_activity[hour].append(activity)
        except:
            continue
    
    if len(hourly_activity) < 12:  # Need data for at least half the day
        return None
    
    # Calculate average activity per hour
    hourly_averages = {}
    for hour, activities in hourly_activity.items():
        hourly_averages[hour] = sum(activities) / len(activities)
    
    # Find peak and quiet hours
    sorted_hours = sorted(hourly_averages.items(), key=lambda x: x[1], reverse=True)
    peak_hours = [hour for hour, avg in sorted_hours[:3]]
    quiet_hours = [hour for hour, avg in sorted_hours[-3:]]
    
    return {
        "pattern_type": "DAILY",
        "peak_hours": peak_hours,
        "quiet_hours": quiet_hours,
        "hourly_averages": hourly_averages
    }


def _detect_temporal_anomalies(timeline_data: List[Dict]) -> List[Dict]:
    """Detect temporal anomalies in timeline data."""
    
    anomalies = []
    
    # Look for gaps in timeline
    if len(timeline_data) >= 2:
        expected_interval = _estimate_interval(timeline_data[:5])  # Use first 5 points
        
        for i in range(1, len(timeline_data)):
            try:
                prev_dt = datetime.fromisoformat(timeline_data[i-1]["timestamp"].replace("Z", "+00:00"))
                curr_dt = datetime.fromisoformat(timeline_data[i]["timestamp"].replace("Z", "+00:00"))
                actual_interval = (curr_dt - prev_dt).total_seconds() / 60  # minutes
                
                if actual_interval > expected_interval * 1.5:  # 50% longer than expected
                    anomalies.append({
                        "type": "TIME_GAP",
                        "timestamp": timeline_data[i]["timestamp"],
                        "gap_minutes": round(actual_interval, 1)
                    })
            except:
                continue
    
    return anomalies


def _estimate_interval(timeline_sample: List[Dict]) -> float:
    """Estimate the expected interval between timeline points in minutes."""
    
    if len(timeline_sample) < 2:
        return 60.0  # Default to 1 hour
    
    intervals = []
    for i in range(1, len(timeline_sample)):
        try:
            prev_dt = datetime.fromisoformat(timeline_sample[i-1]["timestamp"].replace("Z", "+00:00"))
            curr_dt = datetime.fromisoformat(timeline_sample[i]["timestamp"].replace("Z", "+00:00"))
            interval = (curr_dt - prev_dt).total_seconds() / 60
            intervals.append(interval)
        except:
            continue
    
    return sum(intervals) / len(intervals) if intervals else 60.0


def _calculate_pattern_strength(patterns: List[Dict]) -> Dict[str, Any]:
    """Calculate the strength of identified patterns."""
    
    if not patterns:
        return {"strength": "NONE", "confidence": 0}
    
    # Simple scoring based on number of patterns found
    pattern_count = len(patterns)
    
    if pattern_count >= 3:
        strength = "STRONG"
        confidence = 85
    elif pattern_count >= 2:
        strength = "MODERATE"
        confidence = 65
    else:
        strength = "WEAK"
        confidence = 40
    
    return {
        "strength": strength,
        "confidence": confidence,
        "pattern_count": pattern_count
    }


def _calculate_trend(values: List[float]) -> Dict[str, Any]:
    """Calculate trend direction and strength for a series of values."""
    
    if len(values) < 2:
        return {"direction": "INSUFFICIENT_DATA", "strength": 0}
    
    # Simple linear trend calculation
    n = len(values)
    x_sum = sum(range(n))
    y_sum = sum(values)
    xy_sum = sum(i * values[i] for i in range(n))
    x_squared_sum = sum(i ** 2 for i in range(n))
    
    if n * x_squared_sum == x_sum ** 2:  # Avoid division by zero
        return {"direction": "STABLE", "strength": 0}
    
    slope = (n * xy_sum - x_sum * y_sum) / (n * x_squared_sum - x_sum ** 2)
    
    # Determine direction and strength
    if abs(slope) < 0.1:
        direction = "STABLE"
        strength = 0
    elif slope > 0:
        direction = "INCREASING"
        strength = min(abs(slope) * 10, 100)  # Scale to 0-100
    else:
        direction = "DECREASING"
        strength = min(abs(slope) * 10, 100)
    
    return {
        "direction": direction,
        "strength": round(strength, 1),
        "slope": round(slope, 4)
    }


def _generate_timeline_insights(
    patterns: Dict[str, Any],
    trends: Dict[str, Any],
    peak_periods: List[Dict]
) -> List[str]:
    """Generate insights from timeline analysis."""
    
    insights = []
    
    # Pattern insights
    pattern_type = patterns.get("pattern_type", "UNKNOWN")
    if pattern_type == "BURST_HEAVY":
        insights.append("Authentication activity shows burst patterns with high-intensity periods")
    elif pattern_type == "SPARSE":
        insights.append("Authentication activity is generally sparse with many low-activity periods")
    elif pattern_type == "CONSISTENT":
        insights.append("Authentication activity shows consistent, stable patterns")
    
    # Trend insights
    overall_trend = trends.get("overall_trend", "UNKNOWN")
    if overall_trend == "DEGRADING":
        insights.append("Authentication patterns are degrading with increasing failure rates")
    elif overall_trend == "IMPROVING":
        insights.append("Authentication activity is improving with better success rates")
    elif overall_trend == "DECLINING":
        insights.append("Overall authentication activity is declining")
    
    # Peak period insights
    if len(peak_periods) > 3:
        insights.append(f"Multiple peak periods detected - system experiencing {len(peak_periods)} high-activity periods")
    
    return insights


def _generate_temporal_insights(
    temporal_features: Dict,
    cyclical_patterns: List[Dict],
    temporal_anomalies: List[Dict]
) -> List[str]:
    """Generate insights from temporal analysis."""
    
    insights = []
    
    # Duration insights
    duration = temporal_features.get("duration_hours", 0)
    if duration > 48:
        insights.append(f"Long-term analysis covering {duration:.1f} hours of data")
    
    # Pattern insights
    for pattern in cyclical_patterns:
        if pattern["pattern_type"] == "DAILY":
            peak_hours = pattern["peak_hours"]
            insights.append(f"Daily pattern detected with peak activity at hours: {', '.join(map(str, peak_hours))}")
    
    # Anomaly insights
    if len(temporal_anomalies) > 0:
        gap_anomalies = [a for a in temporal_anomalies if a["type"] == "TIME_GAP"]
        if gap_anomalies:
            insights.append(f"Timeline gaps detected - {len(gap_anomalies)} periods with missing data")
    
    return insights