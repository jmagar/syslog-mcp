"""
Device analysis tools registry.

This module serves as a simple registry that imports and re-exports
all device analysis tools from the new modular structure.
This maintains backward compatibility while using the ultra-focused architecture.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Import from interface layer (thin orchestration)
from .interface.security_tools import (
    get_failed_auth_summary,
    get_suspicious_activity,
    get_auth_timeline,
    get_ip_reputation
)
from .interface.device_tools import (
    get_device_summary,
    get_error_analysis
)
from .interface.search_tools import (
    search_by_timerange,
    full_text_search,
    search_logs,
    search_correlate
)
from .interface.utility_tools import (
    get_saved_searches_list,
    add_new_saved_search,
    generate_daily_report,
    export_logs,
    create_new_alert_rule,
    get_alert_rules_list,
    check_alerts_now,
    test_gotify_connection
)
from ..services.elasticsearch_client import ElasticsearchClient
from ..utils.logging import get_logger, log_mcp_request, log_mcp_response

logger = get_logger(__name__)


def register_device_analysis_tools(mcp: FastMCP) -> None:
    """Register all device analysis MCP tools."""
    
    @mcp.tool()
    async def get_device_summary_tool(device: str, hours: int = 24) -> str:
        """Get comprehensive device health summary with status, activity, and recommendations."""
        log_mcp_request("get_device_summary", {"device": device, "hours": hours})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_device_summary(es_client, device, hours)
            log_mcp_response("get_device_summary", True)
            return result
        except Exception as e:
            log_mcp_response("get_device_summary", False, error=str(e))
            return f"Error analyzing device {device}: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def failed_auth_summary_tool(
        device: Optional[str] = None,
        hours: int = 24,
        top_ips: int = 10
    ) -> str:
        """Analyze failed authentication attempts with IP analysis and attack patterns."""
        log_mcp_request("failed_auth_summary", {"device": device, "hours": hours, "top_ips": top_ips})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_failed_auth_summary(es_client, device, hours, top_ips)
            log_mcp_response("failed_auth_summary", True)
            return result
        except Exception as e:
            log_mcp_response("failed_auth_summary", False, error=str(e))
            return f"Error analyzing failed authentication attempts: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def suspicious_activity_tool(
        device: Optional[str] = None,
        hours: int = 24,
        sensitivity: str = "medium"
    ) -> str:
        """Detect suspicious activity patterns beyond authentication failures."""
        log_mcp_request("suspicious_activity", {"device": device, "hours": hours, "sensitivity": sensitivity})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_suspicious_activity(es_client, device, hours, sensitivity)
            log_mcp_response("suspicious_activity", True)
            return result
        except Exception as e:
            log_mcp_response("suspicious_activity", False, error=str(e))
            return f"Error analyzing suspicious activity: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def auth_timeline_tool(
        device: Optional[str] = None,
        hours: int = 24,
        interval: str = "1h"
    ) -> str:
        """Create timeline visualization of authentication events with trend analysis."""
        log_mcp_request("auth_timeline", {"device": device, "hours": hours, "interval": interval})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_auth_timeline(es_client, device, hours, interval)
            log_mcp_response("auth_timeline", True)
            return result
        except Exception as e:
            log_mcp_response("auth_timeline", False, error=str(e))
            return f"Error analyzing authentication timeline: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def ip_reputation_tool(
        ip_address: Optional[str] = None,
        hours: int = 24,
        min_attempts: int = 5,
        top_ips: int = 20
    ) -> str:
        """Analyze IP reputation and activity patterns for threat assessment."""
        log_mcp_request("ip_reputation", {"ip_address": ip_address, "hours": hours, "min_attempts": min_attempts})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_ip_reputation(es_client, ip_address, hours, min_attempts, top_ips)
            log_mcp_response("ip_reputation", True)
            return result
        except Exception as e:
            log_mcp_response("ip_reputation", False, error=str(e))
            return f"Error analyzing IP reputation: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def error_analysis_tool(
        device: Optional[str] = None,
        hours: int = 24,
        severity: Optional[str] = None,
        top_errors: int = 15
    ) -> str:
        """Analyze system errors with troubleshooting insights and resolution recommendations."""
        log_mcp_request("error_analysis", {"device": device, "hours": hours, "severity": severity})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await get_error_analysis(es_client, device, hours, severity, top_errors)
            log_mcp_response("error_analysis", True)
            return result
        except Exception as e:
            log_mcp_response("error_analysis", False, error=str(e))
            return f"Error analyzing system errors: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def search_by_timerange_tool(
        start_time: str,
        end_time: str,
        device: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 100
    ) -> str:
        """Search logs within specific time range with optional filtering."""
        log_mcp_request("search_by_timerange", {"start_time": start_time, "end_time": end_time, "device": device, "query": query})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await search_by_timerange(es_client, start_time, end_time, device, query, limit)
            log_mcp_response("search_by_timerange", True)
            return result
        except Exception as e:
            log_mcp_response("search_by_timerange", False, error=str(e))
            return f"Error searching logs by time range: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def full_text_search_tool(
        query: str,
        device: Optional[str] = None,
        hours: int = 24,
        limit: int = 50,
        search_type: str = "phrase"
    ) -> str:
        """Advanced full-text search across log messages with ranking and relevance."""
        log_mcp_request("full_text_search", {"query": query, "device": device, "hours": hours, "search_type": search_type})
        
        try:
            es_client = ElasticsearchClient()
            await es_client.connect()
            result = await full_text_search(es_client, query, device, hours, limit, search_type)
            log_mcp_response("full_text_search", True)
            return result
        except Exception as e:
            log_mcp_response("full_text_search", False, error=str(e))
            return f"Error performing full text search: {str(e)}"
        finally:
            await es_client.disconnect()
    
    @mcp.tool()
    async def search_correlate_tool(
        primary_query: str, 
        correlation_fields: str,
        time_window: int = 60,
        device: str = None,
        hours: int = 24,
        limit: int = 100
    ) -> str:
        """Search for correlations between log events based on specified fields."""
        log_mcp_request("search_correlate", {
            "primary_query": primary_query, 
            "correlation_fields": correlation_fields,
            "time_window": time_window,
            "device": device,
            "hours": hours,
            "limit": limit
        })
        
        es_client = ElasticsearchClient()
        try:
            await es_client.connect()
            result = await search_correlate(es_client, primary_query, correlation_fields, time_window, device, hours, limit)
            log_mcp_response("search_correlate", True)
            return result
        except Exception as e:
            log_mcp_response("search_correlate", False, error=str(e))
            return f"Error performing correlation search: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def saved_searches_tool() -> str:
        """Get all saved searches with usage statistics."""
        log_mcp_request("saved_searches", {})
        
        es_client = ElasticsearchClient()
        try:
            result = await get_saved_searches_list(es_client)
            log_mcp_response("saved_searches", True)
            return result
        except Exception as e:
            log_mcp_response("saved_searches", False, error=str(e))
            return f"Error retrieving saved searches: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def add_saved_search_tool(
        name: str,
        query: str,
        description: str = None,
        search_type: str = "general"
    ) -> str:
        """Save a search query for future use."""
        log_mcp_request("add_saved_search", {
            "name": name,
            "query": query,
            "description": description,
            "search_type": search_type
        })
        
        es_client = ElasticsearchClient()
        try:
            result = await add_new_saved_search(es_client, name, query, description, search_type)
            log_mcp_response("add_saved_search", True)
            return result
        except Exception as e:
            log_mcp_response("add_saved_search", False, error=str(e))
            return f"Error saving search: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def generate_daily_report_tool(target_date: str = None) -> str:
        """Generate comprehensive daily system report."""
        log_mcp_request("generate_daily_report", {"target_date": target_date})
        
        es_client = ElasticsearchClient()
        try:
            await es_client.connect()
            result = await generate_daily_report(es_client, target_date)
            log_mcp_response("generate_daily_report", True)
            return result
        except Exception as e:
            log_mcp_response("generate_daily_report", False, error=str(e))
            return f"Error generating daily report: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def export_logs_tool(
        query: str = None,
        device: str = None,
        level: str = None,
        start_time: str = None,
        end_time: str = None,
        format_type: str = "json",
        limit: int = 1000
    ) -> str:
        """Export logs matching specified criteria."""
        log_mcp_request("export_logs", {
            "query": query,
            "device": device,
            "level": level,
            "start_time": start_time,
            "end_time": end_time,
            "format_type": format_type,
            "limit": limit
        })
        
        es_client = ElasticsearchClient()
        try:
            await es_client.connect()
            result = await export_logs(es_client, query, device, level, start_time, end_time, format_type, limit)
            log_mcp_response("export_logs", True)
            return result
        except Exception as e:
            log_mcp_response("export_logs", False, error=str(e))
            return f"Error exporting logs: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def create_alert_rule_tool(
        name: str,
        query: str,
        threshold: int,
        time_window: int = 60,
        severity: str = "medium",
        description: str = None
    ) -> str:
        """Create a new alert rule for monitoring."""
        log_mcp_request("create_alert_rule", {
            "name": name,
            "query": query,
            "threshold": threshold,
            "time_window": time_window,
            "severity": severity,
            "description": description
        })
        
        es_client = ElasticsearchClient()
        try:
            result = await create_new_alert_rule(es_client, name, query, threshold, time_window, severity, description)
            log_mcp_response("create_alert_rule", True)
            return result
        except Exception as e:
            log_mcp_response("create_alert_rule", False, error=str(e))
            return f"Error creating alert rule: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def alert_rules_tool() -> str:
        """Get all configured alert rules."""
        log_mcp_request("alert_rules", {})
        
        es_client = ElasticsearchClient()
        try:
            result = await get_alert_rules_list(es_client)
            log_mcp_response("alert_rules", True)
            return result
        except Exception as e:
            log_mcp_response("alert_rules", False, error=str(e))
            return f"Error retrieving alert rules: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def check_alerts_tool() -> str:
        """Check all alert rules now and send notifications if triggered."""
        log_mcp_request("check_alerts", {})
        
        es_client = ElasticsearchClient()
        try:
            result = await check_alerts_now(es_client)
            log_mcp_response("check_alerts", True)
            return result
        except Exception as e:
            log_mcp_response("check_alerts", False, error=str(e))
            return f"Error checking alerts: {str(e)}"
        finally:
            await es_client.disconnect()

    @mcp.tool()
    async def test_gotify_tool() -> str:
        """Test Gotify server connection and send a test notification."""
        log_mcp_request("test_gotify", {})
        
        es_client = ElasticsearchClient()
        try:
            result = await test_gotify_connection(es_client)
            log_mcp_response("test_gotify", True)
            return result
        except Exception as e:
            log_mcp_response("test_gotify", False, error=str(e))
            return f"Error testing Gotify: {str(e)}"
        finally:
            await es_client.disconnect()


# Re-export all tools for backward compatibility
__all__ = [
    # Registration function
    "register_device_analysis_tools",
    # Security analysis tools
    "get_failed_auth_summary",
    "get_suspicious_activity", 
    "get_auth_timeline",
    "get_ip_reputation",
    # Device health tools
    "get_device_summary",
    "get_error_analysis",
    # Search tools
    "search_by_timerange",
    "full_text_search",
    "search_logs"
]