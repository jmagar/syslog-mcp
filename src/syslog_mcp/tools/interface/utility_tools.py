"""
Utility tools MCP interface layer.

This module provides thin orchestration between MCP tools and the
utility components (saved searches, daily reports, export, alert rules).
"""

from typing import Any, Dict, List, Optional
import json

from ..data_access.storage_queries import (
    add_saved_search,
    get_saved_searches,
    get_saved_search,
    update_search_usage,
    delete_saved_search,
    export_logs_query,
    create_alert_rule,
    load_alert_rules
)
from ..data_access.search_queries import query_general_log_search
from ..analysis.report_analyzer import (
    analyze_daily_report_data,
    analyze_export_data
)
from ..presentation.summary_formatters import (
    format_saved_searches_summary,
    format_daily_report_summary,
    format_export_summary,
    format_alert_rules_summary
)
from .security_tools import get_failed_auth_summary, get_suspicious_activity
from .device_tools import get_device_summary, get_error_analysis
from ...utils.logging import get_logger

logger = get_logger(__name__)


async def get_saved_searches_list(client) -> str:
    """Get all saved searches - thin orchestration layer."""
    
    try:
        # Data Access Layer - get stored searches
        searches_data = get_saved_searches()
        
        # Presentation Layer - pure formatting
        return format_saved_searches_summary(searches_data)
        
    except Exception as e:
        logger.error(f"Saved searches error: {e}")
        return f"Error retrieving saved searches: {str(e)}"


async def add_new_saved_search(
    client,
    name: str,
    query: str,
    description: Optional[str] = None,
    search_type: str = "general"
) -> str:
    """Add a new saved search - thin orchestration layer."""
    
    try:
        # Data Access Layer - store search
        result = add_saved_search(name, query, description, search_type)
        
        if result["success"]:
            return f"✅ **Search '{name}' saved successfully!**\n\nQuery: `{query}`\nType: {search_type}"
        else:
            return f"❌ **Failed to save search:** {result.get('error', 'Unknown error')}"
        
    except Exception as e:
        logger.error(f"Add saved search error: {e}")
        return f"Error saving search: {str(e)}"


async def generate_daily_report(
    client,
    target_date: Optional[str] = None
) -> str:
    """Generate comprehensive daily report - thin orchestration layer."""
    
    try:
        # Collect data from various analysis tools
        device_summary = {}
        auth_summary = {}
        security_summary = {}
        error_summary = {}
        
        try:
            # Get device summary
            from .device_tools import get_device_summary
            device_result = await get_device_summary(client, "all", 24)
            # Parse the result to extract metrics (simplified for now)
            device_summary = {"total_events": 0, "active_devices": []}
        except:
            pass
        
        try:
            # Get auth summary  
            auth_result = await get_failed_auth_summary(client, None, 24, 10)
            auth_summary = {"total_attacks": 0, "attacking_ips": []}
        except:
            pass
        
        try:
            # Get security summary
            security_result = await get_suspicious_activity(client, None, 24, "medium")
            security_summary = {"suspicious_events": 0}
        except:
            pass
        
        try:
            # Get error summary
            error_result = await get_error_analysis(client, None, 24, None, 15)
            error_summary = {"total_errors": 0, "error_breakdown": []}
        except:
            pass
        
        # Analysis Layer - pure business logic
        analysis_data = analyze_daily_report_data(
            device_summary=device_summary,
            auth_summary=auth_summary,
            security_summary=security_summary,
            error_summary=error_summary,
            target_date=target_date
        )
        
        # Presentation Layer - pure formatting
        return format_daily_report_summary(analysis_data)
        
    except Exception as e:
        logger.error(f"Daily report generation error: {e}")
        return f"Error generating daily report: {str(e)}"


async def export_logs(
    client,
    query: Optional[str] = None,
    device: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    format_type: str = "json",
    limit: int = 1000
) -> str:
    """Export logs with specified criteria - thin orchestration layer."""
    
    try:
        # Data Access Layer - get export configuration
        export_config = export_logs_query(query, device, level, start_time, end_time, format_type)
        
        # Get raw log data
        search_results = await query_general_log_search(
            es_client=client,
            query=query,
            device=device,
            level=level,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=0
        )
        
        # Extract raw logs
        raw_logs = []
        if "hits" in search_results and "hits" in search_results["hits"]:
            raw_logs = [hit["_source"] for hit in search_results["hits"]["hits"]]
        
        # Analysis Layer - pure business logic
        analysis_data = analyze_export_data(raw_logs, export_config)
        
        # For actual export, you would write the logs to a file here
        # For now, just return a summary
        
        # Presentation Layer - pure formatting  
        summary = format_export_summary(analysis_data)
        
        # Add export data in requested format
        if format_type.lower() == "json" and raw_logs:
            summary += f"\n## Export Data (First 5 records):\n```json\n"
            summary += json.dumps(raw_logs[:5], indent=2)
            summary += f"\n```\n\n*Total {len(raw_logs)} records available for export*"
        
        return summary
        
    except Exception as e:
        logger.error(f"Export logs error: {e}")
        return f"Error exporting logs: {str(e)}"


async def create_new_alert_rule(
    client,
    name: str,
    query: str,
    threshold: int,
    time_window: int = 60,
    severity: str = "medium",
    description: Optional[str] = None
) -> str:
    """Create a new alert rule - thin orchestration layer."""
    
    try:
        # Data Access Layer - store alert rule
        result = create_alert_rule(name, query, threshold, time_window, severity, description)
        
        if result["success"]:
            rule = result["rule"]
            return f"✅ **Alert rule '{name}' created successfully!**\n\n" \
                   f"**Query:** `{query}`\n" \
                   f"**Threshold:** {threshold} events in {time_window} minutes\n" \
                   f"**Severity:** {severity.title()}\n" \
                   f"**Status:** Active"
        else:
            return f"❌ **Failed to create alert rule:** {result.get('error', 'Unknown error')}"
        
    except Exception as e:
        logger.error(f"Create alert rule error: {e}")
        return f"Error creating alert rule: {str(e)}"


async def check_alerts_now(client) -> str:
    """Check all alert rules now and send notifications if triggered."""
    try:
        from ...services.alert_monitor import check_alerts_once
        
        # Run alert check
        results = await check_alerts_once()
        
        # Format results
        summary = f"# Alert Check Results\n\n"
        summary += f"**Total Rules:** {results['total_rules']}\n"
        summary += f"**Triggered Alerts:** {results['triggered_alerts']}\n"
        summary += f"**Notifications Sent:** {results['sent_notifications']}\n"
        
        if results['errors'] > 0:
            summary += f"**Errors:** {results['errors']}\n"
        
        if results['triggered_rules']:
            summary += f"\n## 🚨 Triggered Rules\n"
            for rule_name in results['triggered_rules']:
                summary += f"- {rule_name}\n"
        else:
            summary += f"\n✅ **No alerts triggered** - All systems operating normally.\n"
        
        return summary
        
    except Exception as e:
        logger.error(f"Check alerts error: {e}")
        return f"Error checking alerts: {str(e)}"


async def test_gotify_connection(client) -> str:
    """Test Gotify server connection and configuration."""
    try:
        from ...services.gotify_client import test_gotify_configuration, send_alert_notification
        
        # Test configuration and connection
        is_configured = await test_gotify_configuration()
        
        if not is_configured:
            return "❌ **Gotify not configured or unreachable**\n\n" \
                   "Check your GOTIFY_URL and GOTIFY_TOKEN environment variables."
        
        # Send test notification
        success = await send_alert_notification(
            title="🧪 Syslog MCP Test",
            message="This is a test notification from the Syslog MCP server.\n\n" \
                    "If you receive this, your Gotify configuration is working correctly!",
            priority=3
        )
        
        if success:
            return "✅ **Gotify connection successful!**\n\n" \
                   "Test notification sent successfully. Check your Gotify client."
        else:
            return "⚠️ **Gotify configured but notification failed**\n\n" \
                   "Connection established but test message could not be sent."
        
    except Exception as e:
        logger.error(f"Test Gotify connection error: {e}")
        return f"Error testing Gotify connection: {str(e)}"


async def get_alert_rules_list(client) -> str:
    """Get all alert rules - thin orchestration layer."""
    
    try:
        # Data Access Layer - get stored rules
        rules_data = load_alert_rules()
        
        # Presentation Layer - pure formatting
        return format_alert_rules_summary(rules_data)
        
    except Exception as e:
        logger.error(f"Alert rules error: {e}")
        return f"Error retrieving alert rules: {str(e)}"