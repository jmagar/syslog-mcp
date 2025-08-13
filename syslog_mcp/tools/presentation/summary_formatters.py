"""
Summary formatting functions for syslog analysis results.

This module provides pure presentation logic for formatting analysis results
into user-friendly markdown summaries. No business logic or data access.
"""

from datetime import datetime
from typing import Any

from ...utils.logging import get_logger

logger = get_logger(__name__)

# Threat level threshold constants (0-100 scale)
THREAT_CRITICAL = 80  # 80+ = Critical threat requiring immediate action
THREAT_HIGH = 60      # 60-79 = High threat requiring prompt attention
THREAT_MEDIUM = 40    # 40-59 = Medium threat requiring monitoring
THREAT_LOW = 0        # 0-39 = Low threat level


def format_device_summary(analysis_data: dict[str, Any]) -> str:
    """Format device analysis data into markdown summary."""

    device_name = analysis_data.get("device_name", "Unknown Device")
    total_logs = analysis_data.get("total_logs", 0)
    hours = analysis_data.get("hours", 24)
    device_status = analysis_data.get("device_status", "unknown")

    # Create header
    markdown = f"# Device Summary: {device_name}\n\n"

    # Add status indicator
    status_emoji = {
        "healthy": "✅",
        "warning": "⚠️",
        "critical": "🚨",
        "no_activity": "❓"
    }.get(device_status, "❓")

    markdown += f"**Status:** {status_emoji} {device_status.title()}\n"
    markdown += f"**Analysis Period:** Last {hours} hours\n"
    markdown += f"**Total Log Entries:** {total_logs:,}\n\n"

    # Activity Overview
    markdown += "## Activity Overview\n\n"

    if total_logs == 0:
        markdown += "⚠️ **No activity detected** - Device may be offline or logging service may be down.\n\n"
        return markdown

    # Severity breakdown
    severity_dist = analysis_data.get("severity_distribution", {})
    if severity_dist:
        markdown += "### Log Severity Distribution\n\n"
        for level, count in severity_dist.items():
            percentage = (count / total_logs) * 100 if total_logs > 0 else 0
            markdown += f"- **{level.title()}:** {count:,} ({percentage:.1f}%)\n"
        markdown += "\n"

    # Recent issues
    error_count = analysis_data.get("error_count", 0)
    warning_count = analysis_data.get("warning_count", 0)

    if error_count > 0 or warning_count > 0:
        markdown += "## Recent Issues\n\n"
        if error_count > 0:
            markdown += f"🚨 **{error_count} errors** detected in the last {hours} hours\n"
        if warning_count > 0:
            markdown += f"⚠️ **{warning_count} warnings** detected in the last {hours} hours\n"
        markdown += "\n"

    # Health score
    health_score = analysis_data.get("health_score", {})
    if health_score:
        score = health_score.get("score", 0)
        grade = health_score.get("grade", "UNKNOWN")
        markdown += f"## Health Score: {score}/100 ({grade})\n\n"

        score_factors = health_score.get("score_factors", [])
        if score_factors:
            markdown += "**Score Factors:**\n"
            for factor in score_factors:
                markdown += f"- {factor}\n"
            markdown += "\n"

    # Top programs
    top_programs = analysis_data.get("top_programs", [])
    if top_programs:
        markdown += "## Most Active Services\n\n"
        for i, program in enumerate(top_programs[:5], 1):
            prog_name = program.get("program", "unknown")
            log_count = program.get("log_count", 0)
            percentage = (log_count / total_logs) * 100 if total_logs > 0 else 0
            markdown += f"{i}. **{prog_name}** - {log_count:,} logs ({percentage:.1f}%)\n"
        markdown += "\n"

    # Recent errors
    recent_errors = analysis_data.get("recent_errors", [])
    if recent_errors:
        markdown += "## Recent Errors\n\n"
        for error in recent_errors[:3]:  # Show top 3
            timestamp = error.get("timestamp", "Unknown")
            message = error.get("message", "No message")
            program = error.get("program", "unknown")
            markdown += f"- **{timestamp}** [{program}]: {message[:100]}...\n"
        markdown += "\n"

    # Recommendations
    recommendations = analysis_data.get("recommendations", [])
    if recommendations:
        markdown += "## Recommendations\n\n"
        for i, rec in enumerate(recommendations, 1):
            markdown += f"{i}. {rec}\n"
        markdown += "\n"

    markdown += f"---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


def format_failed_auth_summary(analysis_data: dict[str, Any]) -> str:
    """Format failed authentication analysis data into markdown summary."""

    total_attempts = analysis_data.get("total_attempts", 0)
    hours = analysis_data.get("hours", 24)
    device = analysis_data.get("device")

    # Create header
    title = "Failed Authentication Summary"
    if device:
        title += f" - {device}"
    markdown = f"# {title}\n\n"

    markdown += f"**Analysis Period:** Last {hours} hours\n"
    markdown += f"**Total Failed Attempts:** {total_attempts:,}\n\n"

    if total_attempts == 0:
        markdown += "✅ **No failed authentication attempts detected** - System appears secure.\n\n"
        return markdown

    # Attack intensity
    attempts_per_hour = total_attempts / hours if hours > 0 else 0
    if attempts_per_hour > 50:
        intensity = "🚨 **CRITICAL**"
    elif attempts_per_hour > 20:
        intensity = "⚠️ **HIGH**"
    elif attempts_per_hour > 5:
        intensity = "🔶 **MODERATE**"
    else:
        intensity = "🔵 **LOW**"

    markdown += f"**Attack Intensity:** {intensity} ({attempts_per_hour:.1f} attempts/hour)\n\n"

    # Top attacking IPs
    top_ips = analysis_data.get("top_attacking_ips", [])
    if top_ips:
        markdown += "## Top Attacking IP Addresses\n\n"
        for i, ip_data in enumerate(top_ips[:10], 1):
            ip = ip_data.get("ip", "unknown")
            attempts = ip_data.get("attempts", 0)
            percentage = (attempts / total_attempts) * 100 if total_attempts > 0 else 0
            markdown += f"{i}. **{ip}** - {attempts:,} attempts ({percentage:.1f}%)\n"
        markdown += "\n"

    # Most targeted usernames
    targeted_users = analysis_data.get("most_targeted_users", [])
    if targeted_users:
        markdown += "## Most Targeted Usernames\n\n"
        for user_data in targeted_users[:5]:
            username = user_data.get("username", "unknown")
            attempts = user_data.get("attempts", 0)
            percentage = (attempts / total_attempts) * 100 if total_attempts > 0 else 0
            markdown += f"- **{username}** - {attempts:,} attempts ({percentage:.1f}%)\n"
        markdown += "\n"

    # Attack patterns
    attack_patterns = analysis_data.get("attack_patterns", {})
    if attack_patterns:
        markdown += "## Attack Pattern Analysis\n\n"

        pattern_type = attack_patterns.get("primary_pattern", "UNKNOWN")
        if pattern_type == "DISTRIBUTED":
            markdown += "🌐 **Distributed Attack Pattern** - Multiple IPs with coordinated attempts\n"
        elif pattern_type == "CONCENTRATED":
            markdown += "🎯 **Concentrated Attack Pattern** - High-volume attempts from few IPs\n"
        elif pattern_type == "SCANNING":
            markdown += "🔍 **Scanning Pattern** - Low-volume attempts from many IPs\n"

        geographic_info = attack_patterns.get("geographic_distribution", [])
        if geographic_info:
            markdown += "\n**Geographic Distribution:**\n"
            for geo in geographic_info[:5]:
                country = geo.get("country", "Unknown")
                attempts = geo.get("attempts", 0)
                markdown += f"- {country}: {attempts:,} attempts\n"

        markdown += "\n"

    # Sample attack attempts
    sample_attempts = analysis_data.get("sample_attacks", [])
    if sample_attempts:
        markdown += "## Sample Attack Attempts\n\n"
        for attempt in sample_attempts[:3]:
            timestamp = attempt.get("timestamp", "Unknown")
            ip = attempt.get("source_ip", "unknown")
            username = attempt.get("username", "unknown")
            method = attempt.get("method", "unknown")
            markdown += f"- **{timestamp}** - IP: {ip}, User: {username}, Method: {method}\n"
        markdown += "\n"

    # Security recommendations
    recommendations = analysis_data.get("security_recommendations", [])
    if recommendations:
        markdown += "## Security Recommendations\n\n"
        for i, rec in enumerate(recommendations, 1):
            markdown += f"{i}. {rec}\n"
        markdown += "\n"

    markdown += f"---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


def format_suspicious_activity_summary(analysis_data: dict[str, Any]) -> str:
    """Format suspicious activity analysis data into markdown summary."""

    total_events = analysis_data.get("total_suspicious_events", 0)
    hours = analysis_data.get("hours", 24)
    device = analysis_data.get("device")

    # Create header
    title = "Suspicious Activity Analysis"
    if device:
        title += f" - {device}"
    markdown = f"# {title}\n\n"

    markdown += f"**Analysis Period:** Last {hours} hours\n"
    markdown += f"**Suspicious Events Detected:** {total_events:,}\n\n"

    if total_events == 0:
        markdown += "✅ **No suspicious activity detected** - System appears to be operating normally.\n\n"
        return markdown

    # Risk assessment
    risk_level = analysis_data.get("risk_assessment", {}).get("level", "UNKNOWN")
    risk_emoji = {
        "CRITICAL": "🚨",
        "HIGH": "⚠️",
        "MEDIUM": "🔶",
        "LOW": "🔵"
    }.get(risk_level, "❓")

    markdown += f"**Risk Level:** {risk_emoji} {risk_level}\n\n"

    # Suspicious patterns
    patterns = analysis_data.get("suspicious_patterns", [])
    if patterns:
        markdown += "## Suspicious Patterns Detected\n\n"
        for pattern in patterns[:5]:
            pattern_type = pattern.get("type", "Unknown")
            severity = pattern.get("severity", "UNKNOWN")
            count = pattern.get("count", 0)
            description = pattern.get("description", "No description")

            severity_emoji = {
                "HIGH": "🚨",
                "MEDIUM": "⚠️",
                "LOW": "🔍"
            }.get(severity, "❓")

            markdown += f"### {severity_emoji} {pattern_type}\n"
            markdown += f"**Events:** {count:,} | **Severity:** {severity}\n"
            markdown += f"{description}\n\n"

    # Off-hours activity
    off_hours = analysis_data.get("off_hours_activity", {})
    if off_hours and off_hours.get("events", 0) > 0:
        markdown += "## Off-Hours Activity\n\n"
        events = off_hours.get("events", 0)
        percentage = off_hours.get("percentage", 0)
        markdown += f"🌙 **{events:,} suspicious events** occurred during off-hours ({percentage:.1f}% of total)\n"

        off_hours_patterns = off_hours.get("patterns", [])
        if off_hours_patterns:
            markdown += "\n**Off-hours patterns:**\n"
            for pattern in off_hours_patterns[:3]:
                markdown += f"- {pattern}\n"
        markdown += "\n"

    # Privilege escalation
    privilege_events = analysis_data.get("privilege_escalation", {})
    if privilege_events and privilege_events.get("events", 0) > 0:
        markdown += "## Privilege Escalation Attempts\n\n"
        events = privilege_events.get("events", 0)
        markdown += f"🔓 **{events:,} privilege escalation attempts** detected\n"

        escalation_methods = privilege_events.get("methods", [])
        if escalation_methods:
            markdown += "\n**Methods detected:**\n"
            for method in escalation_methods:
                markdown += f"- {method}\n"
        markdown += "\n"

    # Network anomalies
    network_anomalies = analysis_data.get("network_anomalies", {})
    if network_anomalies and network_anomalies.get("events", 0) > 0:
        markdown += "## Network Anomalies\n\n"
        events = network_anomalies.get("events", 0)
        markdown += f"🌐 **{events:,} network anomalies** detected\n"

        anomaly_types = network_anomalies.get("types", [])
        if anomaly_types:
            markdown += "\n**Anomaly types:**\n"
            for anomaly_type in anomaly_types:
                markdown += f"- {anomaly_type}\n"
        markdown += "\n"

    # Sample events
    sample_events = analysis_data.get("sample_events", [])
    if sample_events:
        markdown += "## Sample Suspicious Events\n\n"
        for event in sample_events[:5]:
            timestamp = event.get("timestamp", "Unknown")
            event_type = event.get("type", "unknown")
            description = event.get("description", "No description")
            source = event.get("source", "unknown")
            markdown += f"- **{timestamp}** [{event_type}] from {source}: {description}\n"
        markdown += "\n"

    # Security recommendations
    recommendations = analysis_data.get("security_recommendations", [])
    if recommendations:
        markdown += "## Security Recommendations\n\n"
        for i, rec in enumerate(recommendations, 1):
            markdown += f"{i}. {rec}\n"
        markdown += "\n"

    markdown += f"---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


def format_auth_timeline_summary(analysis_data: dict[str, Any]) -> str:
    """Format authentication timeline analysis data into markdown summary."""

    total_attempts = analysis_data.get("total_attempts", 0)
    hours = analysis_data.get("hours", 24)
    interval = analysis_data.get("analysis_parameters", {}).get("interval", "1h")

    markdown = "# Authentication Timeline Analysis\n\n"
    markdown += f"**Analysis Period:** Last {hours} hours\n"
    markdown += f"**Time Interval:** {interval}\n"
    markdown += f"**Total Authentication Attempts:** {total_attempts:,}\n\n"

    if total_attempts == 0:
        markdown += "ℹ️ **No authentication attempts detected** during the analysis period.\n\n"
        return markdown

    # Overall success rate
    total_successful = analysis_data.get("total_successful", 0)
    overall_success_rate = analysis_data.get("overall_success_rate", 0)

    success_emoji = "✅" if overall_success_rate > 90 else "⚠️" if overall_success_rate > 70 else "🚨"
    markdown += f"**Overall Success Rate:** {success_emoji} {overall_success_rate:.1f}% ({total_successful:,}/{total_attempts:,})\n\n"

    # Timeline visualization
    timeline_data = analysis_data.get("timeline_data", [])
    if timeline_data:
        markdown += "## Authentication Activity Timeline\n\n"
        markdown += "```\n"
        markdown += "Time Period          | Attempts | Success | Failed | Success %\n"
        markdown += "--------------------|----------|---------|--------|----------\n"

        for period in timeline_data[-12:]:  # Show last 12 periods
            timestamp = period.get("timestamp", "Unknown")
            total = period.get("total_attempts", 0)
            success = period.get("successful_attempts", 0)
            failed = period.get("failed_attempts", 0)
            success_rate = period.get("success_rate", 0)

            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%m-%d %H:%M")
            except:
                time_str = timestamp[:16]

            markdown += f"{time_str:19} | {total:8} | {success:7} | {failed:6} | {success_rate:7.1f}%\n"

        markdown += "```\n\n"

    # Peak periods
    peak_periods = analysis_data.get("peak_periods", [])
    if peak_periods:
        markdown += "## Peak Activity Periods\n\n"
        for i, peak in enumerate(peak_periods[:5], 1):
            timestamp = peak.get("timestamp", "Unknown")
            attempts = peak.get("total_attempts", 0)
            failed = peak.get("failed_attempts", 0)
            success_rate = peak.get("success_rate", 0)
            intensity = peak.get("intensity", 0)

            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                time_str = timestamp

            markdown += f"{i}. **{time_str}** - {attempts:,} attempts ({failed:,} failed, {success_rate:.1f}% success, {intensity}x intensity)\n"
        markdown += "\n"

    # Authentication trends
    auth_trends = analysis_data.get("auth_trends", {})
    if auth_trends:
        overall_trend = auth_trends.get("overall_trend", "UNKNOWN")
        trend_description = auth_trends.get("trend_description", "No description")

        markdown += "## Authentication Trends\n\n"

        trend_emoji = {
            "IMPROVING": "📈",
            "DEGRADING": "📉",
            "DECLINING": "📉",
            "STABLE": "➡️"
        }.get(overall_trend, "❓")

        markdown += f"{trend_emoji} **{overall_trend}**: {trend_description}\n\n"

        # Individual trend details
        attempts_trend = auth_trends.get("attempts_trend", {})
        failures_trend = auth_trends.get("failures_trend", {})

        if attempts_trend.get("direction") != "INSUFFICIENT_DATA":
            direction = attempts_trend.get("direction", "STABLE")
            strength = attempts_trend.get("strength", 0)
            markdown += f"- **Attempts Trend:** {direction} (strength: {strength:.1f})\n"

        if failures_trend.get("direction") != "INSUFFICIENT_DATA":
            direction = failures_trend.get("direction", "STABLE")
            strength = failures_trend.get("strength", 0)
            markdown += f"- **Failures Trend:** {direction} (strength: {strength:.1f})\n"

        markdown += "\n"

    # Timeline insights
    timeline_insights = analysis_data.get("timeline_insights", [])
    if timeline_insights:
        markdown += "## Timeline Insights\n\n"
        for insight in timeline_insights:
            markdown += f"- {insight}\n"
        markdown += "\n"

    markdown += f"---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown




def format_error_analysis_summary(analysis_data: dict[str, Any]) -> str:
    """Format error analysis data into markdown summary."""

    total_errors = analysis_data.get("total_errors", 0)
    hours = analysis_data.get("hours", 24)
    device = analysis_data.get("analysis_parameters", {}).get("device")
    severity = analysis_data.get("analysis_parameters", {}).get("severity")

    # Create header
    title = "System Error Analysis"
    if device:
        title += f" - {device}"
    markdown = f"# {title}\n\n"

    markdown += f"**Analysis Period:** Last {hours} hours\n"
    if severity:
        markdown += f"**Severity Filter:** {severity.upper()}\n"
    markdown += f"**Total Errors:** {total_errors:,}\n\n"

    if total_errors == 0:
        markdown += "✅ **No errors detected** - System appears to be operating normally.\n\n"
        return markdown

    # Error rate assessment
    errors_per_hour = total_errors / hours if hours > 0 else 0
    if errors_per_hour > 20:
        rate_assessment = "🚨 **CRITICAL** - Very high error rate"
    elif errors_per_hour > 10:
        rate_assessment = "⚠️ **HIGH** - High error rate requiring attention"
    elif errors_per_hour > 5:
        rate_assessment = "🔶 **MODERATE** - Moderate error rate"
    else:
        rate_assessment = "🔵 **LOW** - Low error rate"

    markdown += f"**Error Rate:** {rate_assessment} ({errors_per_hour:.1f} errors/hour)\n\n"

    # Top error patterns
    error_patterns = analysis_data.get("error_patterns", [])
    if error_patterns:
        markdown += "## Top Error Patterns\n\n"
        for i, pattern in enumerate(error_patterns[:5], 1):
            pattern_name = pattern.get("pattern", "Unknown")
            count = pattern.get("count", 0)
            severity_level = pattern.get("severity", "UNKNOWN")
            priority = pattern.get("resolution_priority", 5)

            severity_emoji = {
                "HIGH": "🚨",
                "MEDIUM": "⚠️",
                "LOW": "🔍"
            }.get(severity_level, "❓")

            percentage = (count / total_errors) * 100 if total_errors > 0 else 0
            priority_text = {1: "URGENT", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "MINIMAL"}.get(priority, "UNKNOWN")

            markdown += f"{i}. {severity_emoji} **{pattern_name}**\n"
            markdown += f"   - Occurrences: {count:,} ({percentage:.1f}%)\n"
            markdown += f"   - Priority: {priority_text}\n\n"

    # Affected services
    affected_services = analysis_data.get("affected_services", [])
    if affected_services:
        markdown += "## Most Affected Services\n\n"
        for service in affected_services[:5]:
            service_name = service.get("service", "unknown")
            error_count = service.get("error_count", 0)
            impact_level = service.get("impact_level", "UNKNOWN")

            impact_emoji = {
                "HIGH": "🚨",
                "MEDIUM": "⚠️",
                "LOW": "🔍"
            }.get(impact_level, "❓")

            percentage = (error_count / total_errors) * 100 if total_errors > 0 else 0
            markdown += f"- {impact_emoji} **{service_name}** - {error_count:,} errors ({percentage:.1f}%), {impact_level} impact\n"
        markdown += "\n"

    # Severity breakdown
    severity_breakdown = analysis_data.get("severity_breakdown", {})
    if severity_breakdown:
        markdown += "## Error Severity Breakdown\n\n"
        for level, count in sorted(severity_breakdown.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_errors) * 100 if total_errors > 0 else 0
            level_emoji = {
                "critical": "🚨",
                "error": "❌",
                "warning": "⚠️",
                "warn": "⚠️"
            }.get(level.lower(), "❓")

            markdown += f"- {level_emoji} **{level.title()}:** {count:,} ({percentage:.1f}%)\n"
        markdown += "\n"

    # Error timeline/trends
    error_trends = analysis_data.get("error_trends", {})
    if error_trends:
        trend = error_trends.get("trend", "STABLE")
        trend_percentage = error_trends.get("trend_percentage", 0)

        markdown += "## Error Trends\n\n"

        if trend == "INCREASING":
            markdown += f"📈 **Error rate is increasing** by {trend_percentage:.1f}% - Requires immediate attention\n"
        elif trend == "DECREASING":
            markdown += f"📉 **Error rate is decreasing** by {trend_percentage:.1f}% - Positive trend\n"
        else:
            markdown += "➡️ **Error rate is stable** - No significant trend detected\n"
        markdown += "\n"

    # Peak error periods
    peak_periods = analysis_data.get("peak_periods", [])
    if peak_periods:
        markdown += "## Peak Error Periods\n\n"
        for period in peak_periods[:3]:
            timestamp = period.get("timestamp", "Unknown")
            error_count = period.get("error_count", 0)

            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                time_str = timestamp

            markdown += f"- **{time_str}** - {error_count:,} errors\n"
        markdown += "\n"

    # Troubleshooting insights
    troubleshooting_insights = analysis_data.get("troubleshooting_insights", [])
    if troubleshooting_insights:
        markdown += "## Troubleshooting Insights\n\n"
        for insight in troubleshooting_insights:
            insight_type = insight.get("type", "GENERAL")
            title = insight.get("title", "Unknown")
            description = insight.get("description", "No description")
            action = insight.get("action", "No action specified")

            type_emoji = {
                "ERROR_PATTERN": "🔍",
                "SERVICE_IMPACT": "⚙️",
                "SYSTEM_HEALTH": "🏥"
            }.get(insight_type, "💡")

            markdown += f"### {type_emoji} {title}\n"
            markdown += f"{description}\n"
            markdown += f"**Recommended Action:** {action}\n\n"

    markdown += f"---\n*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


def format_search_results_summary(
    search_results: dict[str, Any],
    search_type: str = "general"
) -> str:
    """Format search results into markdown summary."""

    total_hits = search_results.get("total_hits", 0)
    search_query = search_results.get("search_query", "")
    time_range = search_results.get("time_range", {})

    # Create header based on search type
    if search_type == "timerange":
        title = "Time Range Search Results"
    elif search_type == "fulltext":
        title = "Full-Text Search Results"
    else:
        title = "Search Results"

    markdown = f"# {title}\n\n"

    if search_query:
        markdown += f"**Search Query:** `{search_query}`\n"

    if time_range:
        start_time = time_range.get("start_time", "")
        end_time = time_range.get("end_time", "")
        markdown += f"**Time Range:** {start_time} to {end_time}\n"

    markdown += f"**Total Matches:** {total_hits:,}\n\n"

    if total_hits == 0:
        markdown += "ℹ️ **No results found** - Try adjusting your search criteria.\n\n"
        return markdown

    # Search results
    logs = search_results.get("logs", [])
    if logs:
        markdown += "## Search Results\n\n"

        # Show results in table format for better readability
        if search_type == "timerange":
            markdown += "| Timestamp | Device | Level | Program | Message |\n"
            markdown += "|-----------|--------|-------|---------|----------|\n"
        else:
            markdown += "| Timestamp | Device | Message |\n"
            markdown += "|-----------|--------|---------|\n"

        for log in logs[:20]:  # Show top 20 results
            timestamp = log.get("timestamp", "Unknown")
            device = log.get("device", "unknown")
            level = log.get("level", "")
            program = log.get("program", "")
            message = log.get("message", "")

            # Truncate long messages
            if len(message) > 80:
                message = message[:77] + "..."

            # Escape pipe characters for markdown table
            message = message.replace("|", "\\|")
            device = device.replace("|", "\\|")
            program = program.replace("|", "\\|")

            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = dt.strftime("%m-%d %H:%M")
            except:
                time_str = timestamp[:16] if timestamp else "Unknown"

            if search_type == "timerange":
                markdown += f"| {time_str} | {device} | {level} | {program} | {message} |\n"
            else:
                markdown += f"| {time_str} | {device} | {message} |\n"

        markdown += "\n"

        if total_hits > 20:
            remaining = total_hits - 20
            markdown += f"*... and {remaining:,} more results*\n\n"

    # Device distribution
    device_distribution = search_results.get("device_distribution", [])
    if device_distribution:
        markdown += "## Results by Device\n\n"
        for device_data in device_distribution[:5]:
            device = device_data.get("device", "unknown")
            count = device_data.get("count", 0)
            percentage = (count / total_hits) * 100 if total_hits > 0 else 0
            markdown += f"- **{device}:** {count:,} results ({percentage:.1f}%)\n"
        markdown += "\n"

    # Search performance
    execution_time = search_results.get("execution_time_ms", 0)
    if execution_time > 0:
        markdown += f"*Search completed in {execution_time}ms*\n\n"

    markdown += f"---\n*Search completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


def format_search_correlate_summary(analysis_data: dict[str, Any]) -> str:
    """Format search correlation analysis into readable summary."""

    query_info = analysis_data.get("query_info", {})
    timeline_analysis = analysis_data.get("timeline_analysis", {})
    field_correlations = analysis_data.get("field_correlations", {})
    correlation_patterns = analysis_data.get("correlation_patterns", [])
    insights = analysis_data.get("insights", [])
    recommendations = analysis_data.get("recommendations", [])
    sample_events = analysis_data.get("sample_events", [])

    # Header
    markdown = "# Search Correlation Analysis\n\n"
    markdown += f"**Primary Query:** `{query_info.get('primary_query', 'N/A')}`\n"
    markdown += f"**Analysis Period:** Last {query_info.get('analysis_hours', 24)} hours\n"
    markdown += f"**Total Events Found:** {query_info.get('total_events', 0):,}\n"
    markdown += f"**Time Window:** {query_info.get('time_window_seconds', 60)}s\n"
    markdown += f"**Correlation Fields:** {', '.join(query_info.get('correlation_fields', []))}\n\n"

    # Executive Summary
    total_events = query_info.get('total_events', 0)
    if total_events == 0:
        markdown += "ℹ️ **No events found** matching the search criteria.\n\n"
        return markdown

    # Timeline Analysis
    timeline_data = timeline_analysis.get("data", [])
    timeline_stats = timeline_analysis.get("statistics", {})

    if timeline_data:
        markdown += "## Timeline Analysis\n\n"
        markdown += f"**Peak Activity:** {timeline_stats.get('peak_activity', 0)} events at {timeline_stats.get('peak_time', 'N/A')}\n"
        markdown += f"**Total Time Windows:** {timeline_stats.get('total_windows', 0)}\n"
        avg_per_window = total_events / timeline_stats.get('total_windows', 1) if timeline_stats.get('total_windows', 0) > 0 else 0
        markdown += f"**Average per Window:** {avg_per_window:.1f} events\n\n"

    # Field Correlations
    if field_correlations:
        markdown += "## Field Correlations\n\n"
        for field, field_data in field_correlations.items():
            markdown += f"### {field.title()}\n"
            for item in field_data[:5]:  # Top 5 values per field
                markdown += f"- **{item['value']}:** {item['event_count']:,} events ({item['percentage']}%)\n"
            markdown += "\n"

    # Correlation Patterns
    if correlation_patterns:
        markdown += "## Correlation Patterns\n\n"
        markdown += f"**Matrix Strength:** {analysis_data.get('correlation_matrix_strength', 0):.4f}\n\n"
        for i, pattern in enumerate(correlation_patterns[:5], 1):
            components_str = " → ".join(pattern['components'])
            markdown += f"**{i}.** `{components_str}`\n"
            markdown += f"   - **Events:** {pattern['event_count']:,} ({pattern['percentage']}%)\n"
            markdown += f"   - **Strength:** {pattern['pattern_strength']:.4f}\n\n"

    # Key Insights
    if insights:
        markdown += "## 🔍 Key Insights\n\n"
        for insight in insights:
            markdown += f"- {insight}\n"
        markdown += "\n"

    # Recommendations
    if recommendations:
        markdown += "## 💡 Recommendations\n\n"
        for rec in recommendations:
            markdown += f"- {rec}\n"
        markdown += "\n"

    # Sample Events
    if sample_events:
        markdown += "## Sample Events\n\n"
        for event in sample_events[:3]:
            timestamp = event.get('timestamp', 'N/A')
            device = event.get('device', 'unknown')
            message = event.get('message', 'N/A')
            program = event.get('program', 'N/A')

            markdown += f"**{timestamp}** | {device} | {program}\n"
            markdown += f"```\n{message}\n```\n\n"

    # Analysis Quality
    quality = analysis_data.get("analysis_metadata", {}).get("analysis_quality", "unknown")
    quality_emoji = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(quality, "⚪")
    markdown += f"---\n*Analysis Quality: {quality_emoji} {quality.title()}*\n"
    markdown += f"*Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"

    return markdown


# Saved search functionality removed as part of tool consolidation


def format_daily_report_summary(analysis_data: dict[str, Any]) -> str:
    """Format daily report analysis into readable summary."""

    metadata = analysis_data.get("report_metadata", {})
    executive = analysis_data.get("executive_summary", {})
    device_stats = analysis_data.get("device_statistics", {})
    auth_stats = analysis_data.get("authentication_statistics", {})
    security_stats = analysis_data.get("security_statistics", {})
    error_stats = analysis_data.get("error_statistics", {})
    insights = analysis_data.get("insights", [])
    recommendations = analysis_data.get("recommendations", [])
    health = analysis_data.get("health_assessment", {})

    # Header
    markdown = f"# Daily System Report - {metadata.get('report_date', 'N/A')}\n\n"

    # Executive Summary
    health_emoji = {"excellent": "🟢", "good": "🟡", "fair": "🟠", "poor": "🔴", "critical": "🚨"}.get(health.get("status", "unknown"), "⚪")
    markdown += f"**Overall Health:** {health_emoji} {health.get('status', 'Unknown').title()} ({health.get('overall_score', 0):.1f}/100)\n"
    markdown += f"**Total Events:** {executive.get('total_events', 0):,}\n"
    markdown += f"**Security Incidents:** {executive.get('security_incidents', 0)}\n"
    markdown += f"**System Errors:** {executive.get('system_errors', 0)}\n\n"

    # Device Statistics
    markdown += "## 📱 Device Statistics\n"
    markdown += f"- **Active Devices:** {device_stats.get('active_devices', 0)}\n"
    markdown += f"- **Devices with Errors:** {device_stats.get('devices_with_errors', 0)}\n\n"

    # Authentication Statistics
    if auth_stats.get('total_failed_auths', 0) > 0:
        markdown += "## 🔐 Authentication Summary\n"
        markdown += f"- **Failed Attempts:** {auth_stats.get('total_failed_auths', 0)}\n"
        markdown += f"- **Attacking IPs:** {auth_stats.get('unique_attacking_ips', 0)}\n\n"

    # Security Statistics
    if security_stats.get('suspicious_activities', 0) > 0:
        markdown += "## 🛡️ Security Summary\n"
        markdown += f"- **Suspicious Activities:** {security_stats.get('suspicious_activities', 0)}\n"
        markdown += f"- **Threat Level:** {security_stats.get('threat_level', 'low').title()}\n\n"

    # Error Statistics
    if error_stats.get('total_errors', 0) > 0:
        markdown += "## ⚠️ Error Summary\n"
        markdown += f"- **Total Errors:** {error_stats.get('total_errors', 0)}\n"
        markdown += f"- **Critical Errors:** {error_stats.get('critical_errors', 0)}\n\n"

    # Key Insights
    if insights:
        markdown += "## 🔍 Key Insights\n"
        for insight in insights:
            markdown += f"- {insight}\n"
        markdown += "\n"

    # Recommendations
    if recommendations:
        markdown += "## 💡 Recommendations\n"
        for rec in recommendations:
            markdown += f"- {rec}\n"
        markdown += "\n"

    markdown += f"---\n*Report generated at {metadata.get('generated_at', 'N/A')}*\n"
    return markdown


def format_export_summary(analysis_data: dict[str, Any]) -> str:
    """Format log export analysis into readable summary."""

    metadata = analysis_data.get("export_metadata", {})
    summary = analysis_data.get("data_summary", {})
    quality = analysis_data.get("export_quality", {})

    markdown = "# Log Export Summary\n\n"
    markdown += f"**Total Records:** {metadata.get('total_records', 0):,}\n"
    markdown += f"**Export Format:** {metadata.get('export_format', 'json').upper()}\n"
    markdown += f"**Export Quality:** {quality.get('completeness', 'unknown').title()}\n\n"

    if summary.get('unique_devices', 0) > 0:
        markdown += "## Data Overview\n"
        markdown += f"- **Devices:** {summary.get('unique_devices', 0)}\n"
        markdown += f"- **Programs:** {summary.get('unique_programs', 0)}\n"
        markdown += f"- **Time Span:** {summary.get('time_span_hours', 0)} hours\n\n"

        # Top devices and programs
        if summary.get('top_devices'):
            markdown += "### Top Devices\n"
            for device, count in list(summary['top_devices'].items())[:5]:
                markdown += f"- **{device}:** {count:,} logs\n"
            markdown += "\n"

    if metadata.get('total_records', 0) == 0:
        markdown += "ℹ️ **No data exported** - check your search criteria.\n\n"

    markdown += f"---\n*Export completed at {metadata.get('exported_at', 'N/A')}*\n"
    return markdown


def format_alert_rules_summary(rules_data: dict[str, Any]) -> str:
    """Format alert rules data into readable summary."""

    rules = rules_data.get("rules", {})

    markdown = "# Alert Rules\n\n"

    if not rules:
        markdown += "🔔 **No alert rules configured.**\n\n"
        markdown += "Use `create_alert_rule` to set up monitoring alerts.\n"
        return markdown

    markdown += f"**Total Alert Rules:** {len(rules)}\n\n"

    # Separate enabled and disabled rules
    enabled_rules = {k: v for k, v in rules.items() if v.get("enabled", True)}
    disabled_rules = {k: v for k, v in rules.items() if not v.get("enabled", True)}

    if enabled_rules:
        markdown += f"## ✅ Active Rules ({len(enabled_rules)})\n\n"
        for name, rule_data in enabled_rules.items():
            severity_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(rule_data.get("severity", "medium"), "⚪")
            markdown += f"### {severity_emoji} {name}\n"
            markdown += f"**Query:** `{rule_data.get('query', 'N/A')}`\n"
            markdown += f"**Threshold:** {rule_data.get('threshold', 0)} events in {rule_data.get('time_window_minutes', 0)} minutes\n"
            markdown += f"**Severity:** {rule_data.get('severity', 'medium').title()}\n"

            if rule_data.get('description'):
                markdown += f"**Description:** {rule_data['description']}\n"

            trigger_count = rule_data.get('trigger_count', 0)
            if trigger_count > 0:
                markdown += f"**Triggered:** {trigger_count} times\n"
                if rule_data.get('last_triggered'):
                    markdown += f"**Last Trigger:** {rule_data['last_triggered']}\n"

            markdown += "\n"

    if disabled_rules:
        markdown += f"## ❌ Disabled Rules ({len(disabled_rules)})\n\n"
        for name, rule_data in disabled_rules.items():
            markdown += f"- **{name}:** {rule_data.get('description', 'No description')}\n"
        markdown += "\n"

    markdown += f"---\n*Rules loaded at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n"
    return markdown


def _get_threat_level(threat_score: float) -> str:
    """Convert numeric threat score to threat level."""

    if threat_score >= THREAT_CRITICAL:
        return "CRITICAL"
    elif threat_score >= THREAT_HIGH:
        return "HIGH"
    elif threat_score >= THREAT_MEDIUM:
        return "MEDIUM"
    else:
        return "LOW"
