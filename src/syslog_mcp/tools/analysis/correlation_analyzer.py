"""
Correlation analysis logic.

This module provides pure business logic for analyzing log correlations,
including pattern detection and event relationship analysis.
No data access or presentation logic - just analysis.
"""

import math
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ...utils.logging import get_logger

logger = get_logger(__name__)


def analyze_search_correlate_data(
    es_response: Dict[str, Any],
    primary_query: str,
    correlation_fields: List[str],
    time_window: int = 60,
    hours: int = 24
) -> Dict[str, Any]:
    """Analyze search correlation data from Elasticsearch response."""
    
    # Extract basic metrics
    total_events = es_response["hits"]["total"]["value"]
    raw_events = es_response["hits"]["hits"]
    
    # Extract aggregation data
    aggs = es_response.get("aggregations", {})
    
    # Analyze event timeline
    timeline_data = []
    timeline_stats = {"peak_activity": 0, "peak_time": None, "total_windows": 0}
    
    if "event_timeline" in aggs:
        for bucket in aggs["event_timeline"]["buckets"]:
            timestamp = bucket["key_as_string"]
            count = bucket["doc_count"]
            timeline_data.append({
                "timestamp": timestamp,
                "event_count": count,
                "time_window_seconds": time_window
            })
            
            if count > timeline_stats["peak_activity"]:
                timeline_stats["peak_activity"] = count
                timeline_stats["peak_time"] = timestamp
                
        timeline_stats["total_windows"] = len(timeline_data)
    
    # Analyze correlations by field
    field_correlations = {}
    correlation_strength = {}
    
    for field in correlation_fields:
        field_key = field.replace(".", "_")
        agg_key = f"correlation_by_{field_key}"
        
        if agg_key in aggs:
            field_data = []
            field_timeline = {}
            
            for bucket in aggs[agg_key]["buckets"]:
                field_value = bucket["key"]
                field_count = bucket["doc_count"]
                
                # Get sample events for this field value
                sample_events = []
                if "sample_events" in bucket and "hits" in bucket["sample_events"]:
                    for hit in bucket["sample_events"]["hits"]["hits"]:
                        sample_events.append({
                            "timestamp": hit["_source"]["timestamp"],
                            "device": hit["_source"]["device"],
                            "message": hit["_source"]["message"][:100] + "..." if len(hit["_source"]["message"]) > 100 else hit["_source"]["message"],
                            "program": hit["_source"]["program"],
                            "level": hit["_source"]["level"]
                        })
                
                # Analyze timeline for this field value
                timeline_buckets = bucket.get("timeline", {}).get("buckets", [])
                field_timeline[field_value] = [
                    {"timestamp": b["key_as_string"], "count": b["doc_count"]} 
                    for b in timeline_buckets
                ]
                
                field_data.append({
                    "value": field_value,
                    "event_count": field_count,
                    "percentage": round((field_count / total_events) * 100, 2) if total_events > 0 else 0,
                    "sample_events": sample_events,
                    "timeline_points": len(timeline_buckets)
                })
            
            # Sort by event count
            field_data.sort(key=lambda x: x["event_count"], reverse=True)
            field_correlations[field] = field_data
            
            # Calculate correlation strength
            if field_data:
                # Shannon entropy for diversity measure
                total_field_events = sum(item["event_count"] for item in field_data)
                if total_field_events > 0:
                    entropy = -sum(
                        (count/total_field_events) * math.log2(count/total_field_events)
                        for count in [item["event_count"] for item in field_data]
                        if count > 0
                    )
                    
                    correlation_strength[field] = {
                        "diversity_score": entropy,
                        "concentration_ratio": field_data[0]["event_count"] / total_field_events if total_field_events > 0 else 0,
                        "unique_values": len(field_data),
                        "top_value": field_data[0]["value"],
                        "top_percentage": field_data[0]["percentage"]
                    }
    
    # Analyze correlation matrix patterns
    correlation_patterns = []
    correlation_matrix_strength = 0
    
    if "correlation_matrix" in aggs:
        pattern_counts = {}
        for bucket in aggs["correlation_matrix"]["buckets"]:
            pattern = bucket["key"]
            count = bucket["doc_count"]
            if pattern and "|" in pattern:  # Valid correlation pattern
                pattern_counts[pattern] = count
        
        # Sort patterns by frequency
        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
        
        for pattern, count in sorted_patterns[:10]:  # Top 10 patterns
            components = pattern.split("|")
            correlation_patterns.append({
                "pattern": pattern,
                "event_count": count,
                "percentage": round((count / total_events) * 100, 2) if total_events > 0 else 0,
                "components": [comp for comp in components if comp],
                "pattern_strength": count / total_events if total_events > 0 else 0
            })
        
        # Calculate overall correlation matrix strength
        if correlation_patterns:
            correlation_matrix_strength = sum(p["pattern_strength"] for p in correlation_patterns[:5])
    
    # Generate insights and recommendations
    insights = []
    recommendations = []
    
    # Timeline insights
    if timeline_stats["peak_activity"] > 0:
        avg_activity = total_events / timeline_stats["total_windows"] if timeline_stats["total_windows"] > 0 else 0
        if timeline_stats["peak_activity"] > avg_activity * 3:
            insights.append(f"Significant activity spike detected at {timeline_stats['peak_time']} with {timeline_stats['peak_activity']} events")
            recommendations.append("Investigate the cause of the activity spike for potential security incidents")
    
    # Field correlation insights
    for field, strength_data in correlation_strength.items():
        if strength_data["concentration_ratio"] > 0.7:
            insights.append(f"High concentration in {field}: {strength_data['top_percentage']}% of events from '{strength_data['top_value']}'")
            recommendations.append(f"Review {field} '{strength_data['top_value']}' for potential issues or misconfigurations")
        elif strength_data["unique_values"] > 20:
            insights.append(f"High diversity in {field} with {strength_data['unique_values']} unique values")
    
    # Pattern insights
    if correlation_patterns:
        top_pattern = correlation_patterns[0]
        if top_pattern["percentage"] > 30:
            insights.append(f"Dominant pattern detected: {top_pattern['percentage']}% of events follow pattern '{top_pattern['pattern']}'")
            recommendations.append("Investigate the dominant pattern for operational or security implications")
    
    return {
        "query_info": {
            "primary_query": primary_query,
            "correlation_fields": correlation_fields,
            "time_window_seconds": time_window,
            "analysis_hours": hours,
            "total_events": total_events
        },
        "timeline_analysis": {
            "data": timeline_data,
            "statistics": timeline_stats
        },
        "field_correlations": field_correlations,
        "correlation_strength": correlation_strength,
        "correlation_patterns": correlation_patterns,
        "correlation_matrix_strength": round(correlation_matrix_strength, 4),
        "insights": insights,
        "recommendations": recommendations,
        "sample_events": [
            {
                "timestamp": hit["_source"]["timestamp"],
                "device": hit["_source"]["device"],
                "message": hit["_source"]["message"][:150] + "..." if len(hit["_source"]["message"]) > 150 else hit["_source"]["message"],
                "program": hit["_source"]["program"],
                "level": hit["_source"]["level"]
            }
            for hit in raw_events[:5]  # Top 5 sample events
        ],
        "analysis_metadata": {
            "analyzed_at": datetime.utcnow().isoformat(),
            "correlation_fields_count": len(correlation_fields),
            "total_correlation_patterns": len(correlation_patterns),
            "analysis_quality": "high" if total_events > 100 else "medium" if total_events > 10 else "low"
        }
    }


__all__ = ["analyze_search_correlate_data"]