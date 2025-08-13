"""
Consolidated tool interfaces for unified MCP tools.

This module provides unified interfaces that route to existing analysis functions
based on mode parameters, maintaining the ultra-focused modular architecture
while creating cleaner user interfaces.
"""

from typing import Any

from ...services.elasticsearch_client import ElasticsearchClient
from ...utils.logging import get_logger
from .device_tools import get_device_summary, get_error_analysis
from .search_tools import (
    full_text_search,
    search_by_timerange,
    search_correlate,
    search_logs,
)

# Import existing interface functions
from .security_tools import (
    get_auth_timeline,
    get_failed_auth_summary,
    get_suspicious_activity,
)
from .utility_tools import (
    alert_rules_interface,
    check_alerts_interface,
    create_alert_rule_interface,
    generate_daily_report_interface,
    test_gotify_interface,
)

logger = get_logger(__name__)


async def syslog_sec_interface(
    es_client: ElasticsearchClient,
    mode: str,
    device: str | None = None,
    hours: int = 24,
    **kwargs: Any
) -> str:
    """
    Unified security analysis interface.

    Args:
        es_client: Elasticsearch client
        mode: Analysis mode - "auth_summary", "suspicious_activity", "auth_timeline"
        device: Optional device filter
        hours: Time range in hours
        **kwargs: Additional mode-specific parameters
    """

    logger.info(f"Security analysis mode: {mode}", extra={"device": device, "hours": hours})

    if mode == "auth_summary":
        top_ips = kwargs.get("top_ips", 10)
        return await get_failed_auth_summary(
            es_client, device=device, hours=hours, top_ips=top_ips
        )

    elif mode == "suspicious_activity":
        sensitivity = kwargs.get("sensitivity", "medium")
        return await get_suspicious_activity(
            es_client, device=device, hours=hours, sensitivity=sensitivity
        )

    elif mode == "auth_timeline":
        interval = kwargs.get("interval", "1h")
        return await get_auth_timeline(
            es_client, device=device, hours=hours, interval=interval
        )

    else:
        raise ValueError(f"Invalid security analysis mode: {mode}. Valid modes: auth_summary, suspicious_activity, auth_timeline")


async def syslog_reports_interface(
    es_client: ElasticsearchClient,
    mode: str,
    device: str | None = None,
    hours: int = 24,
    **kwargs: Any
) -> str:
    """
    Unified reporting interface.

    Args:
        es_client: Elasticsearch client
        mode: Report mode - "summary", "analysis", "daily"
        device: Device name (required for summary/analysis modes)
        hours: Time range in hours
        **kwargs: Additional mode-specific parameters
    """

    logger.info(f"Report mode: {mode}", extra={"device": device, "hours": hours})

    if mode == "summary":
        if not device:
            raise ValueError("Device parameter is required for summary mode")
        return await get_device_summary(es_client, device, hours)

    elif mode == "analysis":
        if not device:
            raise ValueError("Device parameter is required for analysis mode")
        severity = kwargs.get("severity", None)
        top_errors = kwargs.get("top_errors", 15)
        return await get_error_analysis(
            es_client, device=device, hours=hours, severity=severity, top_errors=top_errors
        )

    elif mode == "daily":
        target_date = kwargs.get("target_date", None)
        return await generate_daily_report_interface(es_client, target_date=target_date)

    else:
        raise ValueError(f"Invalid report mode: {mode}. Valid modes: summary, analysis, daily")


async def syslog_alerts_interface(
    es_client: ElasticsearchClient,
    mode: str,
    **kwargs: Any
) -> str:
    """
    Unified alert management interface.

    Args:
        es_client: Elasticsearch client
        mode: Alert mode - "create", "list", "check", "test"
        **kwargs: Mode-specific parameters
    """

    logger.info(f"Alert mode: {mode}")

    if mode == "create":
        # Extract parameters for alert creation
        name = kwargs.get("name")
        query = kwargs.get("query")
        threshold = kwargs.get("threshold")
        time_window = kwargs.get("time_window", 60)
        severity = kwargs.get("severity", "medium")
        description = kwargs.get("description", None)

        if not all([name, query]):
            raise ValueError("Alert creation requires: name and query parameters")

        # threshold is now always provided with a default value, but validate it
        if threshold is None:
            raise ValueError("Threshold is required")
        try:
            threshold = int(threshold)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Threshold must be a valid integer, got: {threshold}") from e

        # Convert time_window to integer if it's a string
        try:
            time_window = int(time_window)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Time window must be a valid integer, got: {time_window}") from e

        # Ensure name and query are strings
        if not isinstance(name, str) or not isinstance(query, str):
            raise ValueError("Name and query must be strings")

        return await create_alert_rule_interface(
            es_client, name=name, query=query, threshold=threshold,
            time_window=time_window, severity=severity, description=description
        )

    elif mode == "list":
        return await alert_rules_interface(es_client)

    elif mode == "check":
        return await check_alerts_interface(es_client)

    elif mode == "test":
        return await test_gotify_interface(es_client)

    else:
        raise ValueError(f"Invalid alert mode: {mode}. Valid modes: create, list, check, test")


async def syslog_search_interface(
    es_client: ElasticsearchClient,
    mode: str | None = None,
    query: str | None = None,
    **kwargs: Any
) -> str:
    """
    Unified search interface.

    Args:
        es_client: Elasticsearch client
        mode: Search mode - None (default), "timerange", "full_text", "correlate"
        query: Search query
        **kwargs: Mode-specific parameters
    """

    logger.info(f"Search mode: {mode or 'default'}", extra={"query": query})

    if mode is None or mode == "default":
        # Default search_logs functionality
        device = kwargs.get("device", None)
        level = kwargs.get("level", None)
        start_time = kwargs.get("start_time", None)
        end_time = kwargs.get("end_time", None)
        hours = kwargs.get("hours", 24)
        limit = kwargs.get("limit", 100)
        offset = kwargs.get("offset", 0)
        sort_field = kwargs.get("sort_field", "timestamp")
        sort_order = kwargs.get("sort_order", "desc")

        return await search_logs(
            es_client, query=query, device=device, level=level,
            start_time=start_time, end_time=end_time, hours=hours, limit=limit,
            offset=offset, sort_field=sort_field, sort_order=sort_order
        )

    elif mode == "timerange":
        start_time = kwargs.get("start_time")
        end_time = kwargs.get("end_time")
        device = kwargs.get("device", None)
        limit = kwargs.get("limit", 100)

        if not all([start_time, end_time]):
            raise ValueError("Timerange search requires start_time and end_time parameters")

        # Ensure start_time and end_time are strings
        if not isinstance(start_time, str) or not isinstance(end_time, str):
            raise ValueError("start_time and end_time must be strings")

        return await search_by_timerange(
            es_client, start_time=start_time, end_time=end_time,
            query=query, device=device, limit=limit
        )

    elif mode == "full_text":
        hours = kwargs.get("hours", 24)
        device = kwargs.get("device", None)
        search_type = kwargs.get("search_type", "phrase")
        limit = kwargs.get("limit", 50)

        if not query:
            raise ValueError("Full-text search requires a query parameter")

        return await full_text_search(
            es_client, query=query, hours=hours, device=device,
            search_type=search_type, limit=limit
        )

    elif mode == "correlate":
        correlation_fields = kwargs.get("correlation_fields")
        hours = kwargs.get("hours", 24)
        device = kwargs.get("device", None)
        time_window = kwargs.get("time_window", 60)
        limit = kwargs.get("limit", 100)

        if not all([query, correlation_fields]):
            raise ValueError("Correlation search requires query and correlation_fields parameters")

        # Ensure query and correlation_fields are strings
        if not isinstance(query, str) or not isinstance(correlation_fields, str):
            raise ValueError("query and correlation_fields must be strings")

        return await search_correlate(
            es_client, primary_query=query, correlation_fields=correlation_fields,
            hours=hours, device=device, time_window=time_window, limit=limit
        )

    else:
        raise ValueError(f"Invalid search mode: {mode}. Valid modes: default, timerange, full_text, correlate")


__all__ = [
    "syslog_sec_interface",
    "syslog_reports_interface",
    "syslog_alerts_interface",
    "syslog_search_interface"
]
