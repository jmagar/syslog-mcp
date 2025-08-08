"""
Search tools MCP interface layer.

This module provides thin orchestration between MCP tools and the
search components (data access + analysis + presentation).
"""

from typing import Any, Dict, List, Optional

from ..data_access.search_queries import (
    query_logs_by_timerange,
    query_full_text_search,
    query_general_log_search,
    query_search_correlate
)
from ..presentation.summary_formatters import (
    format_search_results_summary,
    format_search_correlate_summary
)
from ..analysis.correlation_analyzer import analyze_search_correlate_data
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def search_by_timerange(
    client,
    start_time: str,
    end_time: str,
    device: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 100
) -> str:
    """Search logs within time range - thin orchestration layer."""
    
    try:
        # Data Access Layer - get raw data from Elasticsearch
        search_results = await query_logs_by_timerange(
            es_client=client,
            start_time=start_time,
            end_time=end_time,
            device=device,
            query=query,
            limit=limit
        )
        
        # Add metadata for presentation
        search_results.update({
            "search_query": query,
            "time_range": {
                "start_time": start_time,
                "end_time": end_time
            }
        })
        
        # Presentation Layer - pure formatting
        return format_search_results_summary(search_results, search_type="timerange")
        
    except Exception as e:
        logger.error(f"Time range search error: {e}")
        return f"Error searching logs in time range: {str(e)}"


async def full_text_search(
    client,
    query: str,
    device: Optional[str] = None,
    hours: int = 24,
    limit: int = 50,
    search_type: str = "phrase"
) -> str:
    """Full text search across log messages - thin orchestration layer."""
    
    try:
        # Data Access Layer - get raw data from Elasticsearch
        search_results = await query_full_text_search(
            es_client=client,
            search_query=query,
            device=device,
            hours=hours,
            limit=limit,
            search_type=search_type
        )
        
        # Add metadata for presentation
        search_results.update({
            "search_query": query,
            "search_parameters": {
                "device": device,
                "hours": hours,
                "search_type": search_type
            }
        })
        
        # Presentation Layer - pure formatting
        return format_search_results_summary(search_results, search_type="fulltext")
        
    except Exception as e:
        logger.error(f"Full text search error: {e}")
        return f"Error performing full text search: {str(e)}"


async def search_logs(
    client,
    query: Optional[str] = None,
    device: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    sort_field: str = "timestamp",
    sort_order: str = "desc"
) -> str:
    """General log search - thin orchestration layer."""
    
    try:
        # Data Access Layer - get raw data from Elasticsearch
        search_results = await query_general_log_search(
            es_client=client,
            query=query,
            device=device,
            level=level,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
            sort_field=sort_field,
            sort_order=sort_order
        )
        
        # Add metadata for presentation
        search_results.update({
            "search_query": query,
            "search_parameters": {
                "device": device,
                "level": level,
                "time_range": {
                    "start_time": start_time,
                    "end_time": end_time
                } if start_time and end_time else None
            }
        })
        
        # Presentation Layer - pure formatting
        return format_search_results_summary(search_results, search_type="general")
        
    except Exception as e:
        logger.error(f"General search error: {e}")
        return f"Error searching logs: {str(e)}"


async def search_correlate(
    client,
    primary_query: str,
    correlation_fields: str,
    time_window: int = 60,
    device: Optional[str] = None,
    hours: int = 24,
    limit: int = 100
) -> str:
    """Search for correlations between log events - thin orchestration layer."""
    
    try:
        # Parse correlation fields (comma-separated string to list)
        fields_list = [field.strip() for field in correlation_fields.split(",") if field.strip()]
        if not fields_list:
            return "Error: No correlation fields specified. Provide comma-separated field names (e.g., 'device,program,level')"
        
        # Data Access Layer - get raw data from Elasticsearch
        search_results = await query_search_correlate(
            es_client=client,
            primary_query=primary_query,
            correlation_fields=fields_list,
            time_window=time_window,
            device=device,
            hours=hours,
            limit=limit
        )
        
        # Analysis Layer - pure business logic
        analysis_data = analyze_search_correlate_data(
            es_response=search_results,
            primary_query=primary_query,
            correlation_fields=fields_list,
            time_window=time_window,
            hours=hours
        )
        
        # Presentation Layer - pure formatting
        return format_search_correlate_summary(analysis_data)
        
    except Exception as e:
        logger.error(f"Search correlation error: {e}")
        return f"Error performing correlation search: {str(e)}"