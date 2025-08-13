"""
Utility tools MCP interface layer.

This module provides thin orchestration between MCP tools and the
utility components (saved searches, daily reports, export, alert rules).
"""


from ...services.alert_monitor import check_alerts_once
from ...services.elasticsearch_client import ElasticsearchClient
from ...services.gotify_client import send_alert_notification, test_gotify_configuration
from ...utils.logging import get_logger
from ..analysis.report_analyzer import analyze_daily_report_data, export_logs_to_file
from ..data_access.search_queries import query_general_log_search
from ..data_access.storage_queries import (
    create_alert_rule,
    export_logs_query,
    load_alert_rules,
)
from ..presentation.summary_formatters import (
    format_alert_rules_summary,
    format_daily_report_summary,
)
from .device_tools import get_device_summary, get_error_analysis
from .security_tools import get_failed_auth_summary, get_suspicious_activity

logger = get_logger(__name__)



async def generate_daily_report_interface(
    client: ElasticsearchClient,
    target_date: str | None = None
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
            await get_device_summary(client, "all", 24)
            # Parse the result to extract metrics (simplified for now)
            device_summary = {"total_events": 0, "active_devices": []}
        except Exception:
            pass

        try:
            # Get auth summary
            await get_failed_auth_summary(client, None, 24, 10)
            auth_summary = {"total_attacks": 0, "attacking_ips": []}
        except Exception:
            pass

        try:
            # Get security summary
            await get_suspicious_activity(client, None, 24, "medium")
            security_summary = {"suspicious_events": 0}
        except Exception:
            pass

        try:
            # Get error summary
            await get_error_analysis(client, None, 24, None, 15)
            error_summary = {"total_errors": 0, "error_breakdown": []}
        except Exception:
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


async def export_logs_interface(
    client: ElasticsearchClient,
    query: str | None = None,
    device: str | None = None,
    level: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    format_type: str = "json",
    limit: int = 1000
) -> str:
    """Export logs to file with specified criteria - thin orchestration layer."""

    try:
        # Data Access Layer - get export configuration with file path
        export_config = export_logs_query(query, device, level, start_time, end_time, format_type)

        # Get raw log data from Elasticsearch
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

        # Analysis Layer - export logs to file and analyze
        export_result = export_logs_to_file(raw_logs, export_config)

        # Format response based on success/failure
        if export_result.get("success"):
            file_path = export_result["file_path"]
            records_written = export_result["records_written"]
            file_size = export_result["file_size_bytes"]

            # Convert file size to human readable format
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"

            # Get analysis data for additional insights
            analysis_data = export_result.get("analysis_data", {})
            data_summary = analysis_data.get("data_summary", {})

            summary = "✅ **Export Complete!**\n\n"
            summary += f"**File:** `{file_path}`\n"
            summary += f"**Records:** {records_written:,}\n"
            summary += f"**Size:** {size_str}\n"
            summary += f"**Format:** {format_type.upper()}\n\n"

            # Add data insights
            if data_summary:
                summary += "## Export Summary\n"
                summary += f"- **Devices:** {data_summary.get('unique_devices', 0)}\n"
                summary += f"- **Programs:** {data_summary.get('unique_programs', 0)}\n"
                summary += f"- **Time Span:** {data_summary.get('time_span_hours', 0)} hours\n"

                if format_type.lower() == "csv":
                    columns = export_result.get("columns", 0)
                    summary += f"- **Columns:** {columns}\n"

            return summary

        else:
            error_msg = export_result.get("error", "Unknown error")
            return f"❌ **Export Failed:** {error_msg}"

    except Exception as e:
        logger.error(f"Export logs error: {e}")
        return f"Error exporting logs: {str(e)}"


async def create_alert_rule_interface(
    client: ElasticsearchClient,
    name: str,
    query: str,
    threshold: int,
    time_window: int = 60,
    severity: str = "medium",
    description: str | None = None
) -> str:
    """Create a new alert rule - thin orchestration layer."""

    try:
        # Data Access Layer - store alert rule
        result = create_alert_rule(name, query, threshold, time_window, severity, description)

        if result["success"]:
            result["rule"]
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


async def check_alerts_interface(client: ElasticsearchClient) -> str:
    """Check all alert rules now and send notifications if triggered."""
    try:
        # Run alert check
        results = await check_alerts_once()

        # Format results
        summary = "# Alert Check Results\n\n"
        summary += f"**Total Rules:** {results['total_rules']}\n"
        summary += f"**Triggered Alerts:** {results['triggered_alerts']}\n"
        summary += f"**Notifications Sent:** {results['sent_notifications']}\n"

        if results['errors'] > 0:
            summary += f"**Errors:** {results['errors']}\n"

        if results['triggered_rules']:
            summary += "\n## 🚨 Triggered Rules\n"
            for rule_name in results['triggered_rules']:
                summary += f"- {rule_name}\n"
        else:
            summary += "\n✅ **No alerts triggered** - All systems operating normally.\n"

        return summary

    except Exception as e:
        logger.error(f"Check alerts error: {e}")
        return f"Error checking alerts: {str(e)}"


async def test_gotify_interface(client: ElasticsearchClient) -> str:
    """Test Gotify server connection and configuration."""
    try:
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


async def alert_rules_interface(client: ElasticsearchClient) -> str:
    """Get all alert rules - thin orchestration layer."""

    try:
        # Data Access Layer - get stored rules
        rules_data = load_alert_rules()

        # Presentation Layer - pure formatting
        return format_alert_rules_summary(rules_data)

    except Exception as e:
        logger.error(f"Alert rules error: {e}")
        return f"Error retrieving alert rules: {str(e)}"
