"""
Device tools MCP interface layer.

This module provides thin orchestration between MCP tools and the
device analysis components (data access + analysis + presentation).
"""

from typing import Any, Dict, List, Optional

from ..data_access.device_queries import (
    query_device_health_summary,
    query_error_analysis
)
from ..analysis.device_analyzer import (
    analyze_device_health_data,
    analyze_error_patterns_data
)
from ..presentation.summary_formatters import (
    format_device_summary,
    format_error_analysis_summary
)
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def get_device_summary(
    client,
    device: str,
    hours: int = 24
) -> str:
    """Get device health summary - thin orchestration layer."""
    
    try:
        # Data Access Layer - get raw data from Elasticsearch  
        es_response = await query_device_health_summary(
            es_client=client,
            device_name=device,
            hours=hours
        )
        
        # Analysis Layer - pure business logic
        analysis_data = analyze_device_health_data(
            es_response=es_response,
            device_name=device,
            hours=hours
        )
        
        # Presentation Layer - pure formatting
        return format_device_summary(analysis_data)
        
    except Exception as e:
        logger.error(f"Device summary error: {e}")
        return f"Error analyzing device {device}: {str(e)}"


async def get_error_analysis(
    client,
    device: Optional[str] = None,
    hours: int = 24,
    severity: Optional[str] = None,
    top_errors: int = 15
) -> str:
    """Get system error analysis - thin orchestration layer."""
    
    try:
        # Data Access Layer - get raw data from Elasticsearch
        es_response = await query_error_analysis(
            es_client=client,
            device=device,
            hours=hours,
            severity=severity,
            top_errors=top_errors
        )
        
        # Analysis Layer - pure business logic
        analysis_data = analyze_error_patterns_data(
            es_response=es_response,
            device=device,
            hours=hours,
            severity=severity
        )
        
        # Presentation Layer - pure formatting
        return format_error_analysis_summary(analysis_data)
        
    except Exception as e:
        logger.error(f"Error analysis error: {e}")
        return f"Error analyzing system errors: {str(e)}"