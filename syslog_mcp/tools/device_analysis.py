"""
Consolidated MCP tools registry.

This module provides 5 unified MCP tools that replace the original 16 tools,
maintaining ultra-focused modular architecture while creating cleaner interfaces.
"""


from fastmcp import FastMCP

from ..services.elasticsearch_client import ElasticsearchClient
from ..utils.logging import get_logger, log_mcp_request, log_mcp_response

# Import consolidated interfaces
from .interface.consolidated_tools import (
    syslog_alerts_interface,
    syslog_reports_interface,
    syslog_search_interface,
    syslog_sec_interface,
)
from .interface.utility_tools import export_logs_interface, syslog_tail_interface

logger = get_logger(__name__)


def register_device_analysis_tools(mcp: FastMCP) -> None:
    """Register all consolidated MCP tools."""

    @mcp.tool()
    async def syslog_sec(
        mode: str,
        device: str | None = None,
        hours: int = 24,
        top_ips: int = 10,
        sensitivity: str = "medium",
        interval: str = "1h"
    ) -> str:
        """
        Unified security analysis tool.

        Args:
            mode: Analysis mode - "auth_summary", "suspicious_activity", "auth_timeline"
            device: Optional device filter
            hours: Time range in hours (default: 24)
            top_ips: Number of top attacking IPs to show (auth_summary mode)
            sensitivity: Detection sensitivity - "low", "medium", "high" (suspicious_activity mode)
            interval: Timeline interval - "30m", "1h", "2h" (auth_timeline mode)

        Examples:
            syslog_sec auth_summary Ubuntu-Server-1
            syslog_sec suspicious_activity --sensitivity=high
            syslog_sec auth_timeline --interval=30m
        """
        log_mcp_request("syslog_sec", {
            "mode": mode, "device": device, "hours": hours,
            "top_ips": top_ips, "sensitivity": sensitivity, "interval": interval
        })

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await syslog_sec_interface(
                es_client, mode=mode, device=device, hours=hours,
                top_ips=top_ips, sensitivity=sensitivity, interval=interval
            )

            log_mcp_response("syslog_sec", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_sec", False, error=str(e))
            return f"Security analysis error ({mode}): {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def syslog_reports(
        mode: str,
        device: str | None = None,
        hours: int = 24,
        severity: str | None = None,
        top_errors: int = 15,
        target_date: str | None = None
    ) -> str:
        """
        Unified system reporting tool.

        Args:
            mode: Report mode - "summary", "analysis", "daily"
            device: Device name (required for summary/analysis modes)
            hours: Time range in hours (default: 24)
            severity: Error severity filter for analysis mode
            top_errors: Number of top errors to show (analysis mode)
            target_date: Target date for daily report (YYYY-MM-DD format)

        Examples:
            syslog_reports summary TOOTIE
            syslog_reports analysis DOOK --severity=error
            syslog_reports daily --target_date=2025-01-15
        """
        log_mcp_request("syslog_reports", {
            "mode": mode, "device": device, "hours": hours,
            "severity": severity, "top_errors": top_errors, "target_date": target_date
        })

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await syslog_reports_interface(
                es_client, mode=mode, device=device, hours=hours,
                severity=severity, top_errors=top_errors, target_date=target_date
            )

            log_mcp_response("syslog_reports", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_reports", False, error=str(e))
            return f"Report generation error ({mode}): {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def syslog_alerts(
        mode: str,
        name: str | None = None,
        query: str | None = None,
        threshold: int = 10,
        time_window: int = 60,
        severity: str = "medium",
        description: str | None = None
    ) -> str:
        """
        Unified alert management tool.

        Args:
            mode: Alert mode - "create", "list", "check", "test"
            name: Alert rule name (create mode)
            query: Alert query (create mode)
            threshold: Alert threshold (create mode)
            time_window: Time window in minutes (create mode, default: 60)
            severity: Alert severity - "low", "medium", "high", "critical" (create mode)
            description: Alert description (create mode)

        Examples:
            syslog_alerts create --name="High Error Rate" --query="level:error" --threshold=100
            syslog_alerts list
            syslog_alerts check
            syslog_alerts test
        """
        log_mcp_request("syslog_alerts", {
            "mode": mode, "name": name, "query": query, "threshold": threshold,
            "time_window": time_window, "severity": severity, "description": description
        })

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await syslog_alerts_interface(
                es_client, mode=mode, name=name, query=query, threshold=threshold,
                time_window=time_window, severity=severity, description=description
            )

            log_mcp_response("syslog_alerts", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_alerts", False, error=str(e))
            return f"Alert management error ({mode}): {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def syslog_search(
        query: str | None = None,
        mode: str | None = None,
        device: str | None = None,
        level: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        hours: int = 24,
        limit: int = 100,
        offset: int = 0,
        sort_field: str = "timestamp",
        sort_order: str = "desc",
        search_type: str = "phrase",
        correlation_fields: str | None = None,
        time_window: int = 60
    ) -> str:
        """
        Unified search tool with multiple search strategies.

        Args:
            query: Search query
            mode: Search mode - None (default), "timerange", "full_text", "correlate"
            device: Device filter
            level: Log level filter
            start_time: Start time (ISO format, timerange mode)
            end_time: End time (ISO format, timerange mode)
            hours: Time range in hours (default: 24)
            limit: Maximum results (default: 100)
            offset: Results offset for pagination (default: 0)
            sort_field: Sort field (default: "timestamp")
            sort_order: Sort order - "asc", "desc" (default: "desc")
            search_type: Search type - "phrase", "fuzzy", "wildcard" (full_text mode)
            correlation_fields: Correlation fields (correlate mode)
            time_window: Correlation time window in seconds (correlate mode)

        Examples:
            syslog_search --query="error database"
            syslog_search timerange --start_time="2025-01-15T00:00:00Z" --end_time="2025-01-15T23:59:59Z"
            syslog_search full_text --query="connection timeout" --search_type=fuzzy
            syslog_search correlate --query="error database" --correlation_fields="device,program"
        """
        log_mcp_request("syslog_search", {
            "query": query, "mode": mode, "device": device, "level": level,
            "start_time": start_time, "end_time": end_time, "hours": hours,
            "limit": limit, "search_type": search_type, "correlation_fields": correlation_fields
        })

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await syslog_search_interface(
                es_client, mode=mode, query=query, device=device, level=level,
                start_time=start_time, end_time=end_time, hours=hours,
                limit=limit, offset=offset, sort_field=sort_field, sort_order=sort_order,
                search_type=search_type, correlation_fields=correlation_fields,
                time_window=time_window
            )

            log_mcp_response("syslog_search", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_search", False, error=str(e))
            return f"Search error ({mode or 'default'}): {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def syslog_export(
        query: str | None = None,
        device: str | None = None,
        level: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        format_type: str = "json",
        limit: int = 1000
    ) -> str:
        """
        Export logs matching specified criteria.

        Args:
            query: Search query filter
            device: Device filter
            level: Log level filter
            start_time: Start time (ISO format)
            end_time: End time (ISO format)
            format_type: Export format - "json", "csv" (default: "json")
            limit: Maximum logs to export (default: 1000)

        Examples:
            syslog_export --query="level:error" --format_type=json
            syslog_export --device=web-server-01 --start_time="2025-01-15T00:00:00Z"
        """
        log_mcp_request("syslog_export", {
            "query": query, "device": device, "level": level,
            "start_time": start_time, "end_time": end_time,
            "format_type": format_type, "limit": limit
        })

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await export_logs_interface(
                es_client, query=query, device=device, level=level,
                start_time=start_time, end_time=end_time,
                format_type=format_type, limit=limit
            )

            log_mcp_response("syslog_export", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_export", False, error=str(e))
            return f"Export error: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def syslog_tail(
        device: str,
        lines: int = 50
    ) -> str:
        """
        Display recent log entries for a device (like 'tail -f' for logs).

        Args:
            device: Device name to get recent logs from (required)
            lines: Number of recent lines to display (default: 50)

        Examples:
            syslog_tail TOOTIE
            syslog_tail web-server-01 --lines=100
        """
        log_mcp_request("syslog_tail", {"device": device, "lines": lines})

        try:
            es_client = ElasticsearchClient()
            await es_client.connect()

            result = await syslog_tail_interface(es_client, device=device, lines=lines)

            log_mcp_response("syslog_tail", True)
            return result
        except Exception as e:
            log_mcp_response("syslog_tail", False, error=str(e))
            return f"Tail error for device '{device}': {str(e)}"
        finally:
            await es_client.disconnect()


# Export consolidated tools
__all__ = [
    "register_device_analysis_tools"
]
