"""
Security tools MCP interface layer.

This module provides thin orchestration between MCP tools and the
security analysis components (data access + analysis + presentation).
"""

from ...services.elasticsearch_client import ElasticsearchClient
from ...utils.logging import get_logger
from ..analysis.security_analyzer import (
    analyze_failed_authentication_data,
    analyze_suspicious_activity_data,
)
from ..data_access.security_queries import (
    query_failed_auth_attempts,
    query_suspicious_activity,
)
from ..presentation.summary_formatters import (
    format_auth_timeline_summary,
    format_failed_auth_summary,
    format_suspicious_activity_summary,
)

logger = get_logger(__name__)


async def get_failed_auth_summary(
    client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    top_ips: int = 10
) -> str:
    """Get failed authentication summary - thin orchestration layer."""

    try:
        # Data Access Layer - get raw data from Elasticsearch
        es_response = await query_failed_auth_attempts(
            es_client=client,
            device=device,
            hours=hours,
            top_ips=top_ips
        )

        # Analysis Layer - pure business logic
        analysis_data = analyze_failed_authentication_data(
            es_response=es_response,
            device_name=device,
            hours=hours,
            top_ips=top_ips
        )

        # Presentation Layer - pure formatting
        return format_failed_auth_summary(analysis_data)

    except Exception as e:
        logger.error(f"Failed auth summary error: {e}")
        return f"Error analyzing failed authentication attempts: {str(e)}"


async def get_suspicious_activity(
    client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    sensitivity: str = "medium"
) -> str:
    """Get suspicious activity analysis - thin orchestration layer."""

    try:
        # Data Access Layer - get raw data from Elasticsearch
        es_response = await query_suspicious_activity(
            es_client=client,
            device=device,
            hours=hours,
            sensitivity=sensitivity
        )

        # Analysis Layer - pure business logic
        analysis_data = analyze_suspicious_activity_data(
            es_response=es_response,
            device=device,
            hours=hours,
            sensitivity=sensitivity
        )

        # Presentation Layer - pure formatting
        return format_suspicious_activity_summary(analysis_data)

    except Exception as e:
        logger.error(f"Suspicious activity analysis error: {e}")
        return f"Error analyzing suspicious activity: {str(e)}"


async def get_auth_timeline(
    client: ElasticsearchClient,
    device: str | None = None,
    hours: int = 24,
    interval: str = "1h"
) -> str:
    """Get authentication timeline analysis - thin orchestration layer."""

    try:
        # Data Access Layer - get raw data from Elasticsearch
        from ..data_access.security_queries import query_authentication_timeline
        es_response = await query_authentication_timeline(
            es_client=client,
            device=device,
            hours=hours,
            interval=interval
        )

        # Analysis Layer - pure business logic
        from ..analysis.timeline_analyzer import analyze_authentication_timeline_data
        analysis_data = analyze_authentication_timeline_data(
            es_response=es_response,
            device=device,
            hours=hours,
            interval=interval
        )

        # Presentation Layer - pure formatting
        return format_auth_timeline_summary(analysis_data)

    except Exception as e:
        logger.error(f"Auth timeline analysis error: {e}")
        return f"Error analyzing authentication timeline: {str(e)}"


