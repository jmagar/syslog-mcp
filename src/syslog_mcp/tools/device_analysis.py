"""
Device analysis tools for monitoring and understanding device activity patterns.

This module provides tools for analyzing device-specific log data including
activity summaries, program usage, error patterns, and health monitoring.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from ..models.query import LogSearchQuery, TimeRange, SearchFilter, SortOrder
from ..models.response import LogSearchResult, ResponseStatus
from ..services.elasticsearch_client import ElasticsearchClient
from ..utils.logging import get_logger, log_mcp_request, log_mcp_response
from ..exceptions import (
    ElasticsearchConnectionError, 
    ElasticsearchQueryError,
    ElasticsearchTimeoutError
)

logger = get_logger(__name__)


def _generate_device_analysis_summary(
    device_name: str,
    total_logs: int,
    severity_dist: Dict[str, int],
    facility_dist: Dict[str, int],
    top_programs: List[Dict[str, Any]],
    recent_errors: List[Dict[str, Any]],
    activity_timeline: List[Dict[str, Any]],
    last_seen: Optional[str],
    status: str,
    error_count: int,
    warning_count: int,
    hours: int
) -> str:
    """Generate a human-readable analysis summary with supporting log evidence."""
    
    # Status emoji mapping
    status_emoji = {
        "healthy": "🟢",
        "warning": "🟡", 
        "critical": "🔴",
        "no_activity": "⚫"
    }
    
    # Build the summary
    lines = []
    lines.append(f"# 📊 DEVICE ANALYSIS: {device_name}")
    lines.append(f"**Analysis Period:** Last {hours} hours")
    lines.append("")
    
    # Overall status
    emoji = status_emoji.get(status, "❓")
    lines.append(f"## {emoji} OVERALL STATUS: {status.upper()}")
    lines.append(f"**Total Activity:** {total_logs:,} log entries")
    
    if last_seen:
        lines.append(f"**Last Activity:** {last_seen}")
    lines.append("")
    
    # Activity analysis with timeline anomalies
    lines.append("## 📈 ACTIVITY ANALYSIS")
    
    # Check for unusual activity patterns
    if activity_timeline:
        log_counts = [entry["log_count"] for entry in activity_timeline if entry["log_count"] > 0]
        if log_counts:
            avg_activity = sum(log_counts) / len(log_counts)
            max_activity = max(log_counts)
            
            # Detect spikes (more than 2x average)
            spikes = []
            zero_periods = []
            
            for entry in activity_timeline:
                if entry["log_count"] > avg_activity * 2:
                    spikes.append(entry)
                elif entry["log_count"] == 0:
                    zero_periods.append(entry)
            
            if spikes:
                lines.append("### ⚠️ UNUSUAL ACTIVITY DETECTED")
                for spike in spikes[:3]:  # Show top 3 spikes
                    timestamp = spike["timestamp"].split("T")[1][:5]  # Extract HH:MM
                    lines.append(f"- **{timestamp} UTC:** {spike['log_count']:,} logs (vs avg {avg_activity:.0f})")
                lines.append("")
            
            if zero_periods and len(zero_periods) > 2:
                lines.append("### 🚨 ACTIVITY GAPS")
                lines.append(f"- **{len(zero_periods)} hours** with no log activity")
                if zero_periods:
                    first_gap = zero_periods[0]["timestamp"].split("T")[1][:5]
                    lines.append(f"- Gap started around **{first_gap} UTC**")
                lines.append("")
    
    # Service analysis
    lines.append("## 💻 PRIMARY SERVICES")
    if top_programs:
        for i, prog in enumerate(top_programs[:5]):
            service = prog["program"]
            count = prog["log_count"]
            percentage = (count / total_logs) * 100
            
            # Add service explanation
            service_desc = _get_service_description(service)
            lines.append(f"**{i+1}. {service}** ({count:,} logs, {percentage:.1f}%)")
            if service_desc:
                lines.append(f"   *{service_desc}*")
        lines.append("")
    
    # Error analysis with examples
    if error_count > 0 or warning_count > 0:
        lines.append("## 🚨 ISSUES DETECTED")
        lines.append(f"**Errors:** {error_count} | **Warnings:** {warning_count}")
        lines.append("")
        
        if recent_errors:
            # Group errors by type/pattern
            error_patterns = {}
            for error in recent_errors[:10]:
                msg = error["message"]
                # Simple pattern detection
                if "usb" in msg.lower():
                    error_patterns.setdefault("USB Hardware Issues", []).append(error)
                elif "ssh" in msg.lower() or "auth" in msg.lower():
                    error_patterns.setdefault("Authentication Issues", []).append(error)
                elif "network" in msg.lower() or "connection" in msg.lower():
                    error_patterns.setdefault("Network Issues", []).append(error)
                else:
                    error_patterns.setdefault("Other Issues", []).append(error)
            
            for pattern_name, errors in error_patterns.items():
                lines.append(f"### {pattern_name}")
                lines.append(f"**Count:** {len(errors)} recent occurrences")
                
                # Show example log entries
                for error in errors[:2]:  # Show up to 2 examples
                    timestamp = error["timestamp"].split("T")[1][:8]  # HH:MM:SS
                    program = error["program"]
                    message = error["message"][:100] + "..." if len(error["message"]) > 100 else error["message"]
                    lines.append(f"```")
                    lines.append(f"{timestamp} {program}: {message}")
                    lines.append(f"```")
                lines.append("")
    
    # Security assessment for auth-heavy devices
    auth_logs = facility_dist.get("auth", 0) + facility_dist.get("authpriv", 0)
    if auth_logs > total_logs * 0.5:  # More than 50% auth logs
        lines.append("## 🔐 SECURITY NOTES")
        lines.append(f"**High Authentication Activity:** {auth_logs:,} auth-related logs ({(auth_logs/total_logs)*100:.1f}%)")
        
        # Look for SSH patterns
        ssh_programs = [p for p in top_programs if "ssh" in p["program"].lower()]
        if ssh_programs:
            ssh_count = ssh_programs[0]["log_count"]
            lines.append(f"**SSH Activity:** {ssh_count:,} SSH-related events")
            lines.append("*Recommendation: Review for failed authentication attempts*")
        lines.append("")
    
    # Recommendations
    lines.append("## 🔍 RECOMMENDATIONS")
    recommendations = []
    
    if spikes:
        recommendations.append("Investigate unusual activity spikes - possible attack or system malfunction")
    
    if zero_periods and len(zero_periods) > 2:
        recommendations.append("Check device connectivity - extended periods with no logs")
    
    if "usb" in " ".join([e["message"].lower() for e in recent_errors[:5]]):
        recommendations.append("Replace or disconnect failing USB device causing kernel errors")
    
    if auth_logs > total_logs * 0.7:
        recommendations.append("Review authentication logs for brute force attempts")
    
    if not recommendations:
        recommendations.append("Continue monitoring - no immediate issues detected")
    
    for i, rec in enumerate(recommendations[:5], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def _get_service_description(service_name: str) -> str:
    """Get human-readable description of service/program names."""
    descriptions = {
        "sshd-session": "SSH connection sessions",
        "sshd": "SSH daemon (secure shell)",
        "kernel": "Linux kernel messages",
        "sudo": "Privilege escalation commands", 
        "crond": "Scheduled task daemon",
        "cron": "Scheduled tasks",
        "systemd": "System service manager",
        "webgui": "Web interface",
        "move": "File/data movement operations",
        "shfs": "Shared filesystem operations",
        "plugin-manager": "Plugin/extension management",
        "monitor_nchan": "Channel monitoring service"
    }
    return descriptions.get(service_name, "")


def _generate_failed_auth_summary(
    device_name: Optional[str],
    hours: int,
    total_attacks: int,
    attacking_ips: List[tuple],
    targeted_devices: List[tuple],
    failed_users: List[tuple],
    attack_methods: List[tuple],
    attack_timeline: List[tuple],
    sample_attacks: List[Dict[str, Any]]
) -> str:
    """Generate a human-readable failed authentication analysis summary."""
    
    lines = []
    lines.append("# 🚨 FAILED AUTHENTICATION ANALYSIS")
    
    if device_name:
        lines.append(f"**Target Device:** {device_name}")
    else:
        lines.append("**Scope:** All devices")
        
    lines.append(f"**Analysis Period:** Last {hours} hours")
    lines.append("")
    
    # Overall statistics
    if total_attacks == 0:
        lines.append("## ✅ NO FAILED AUTHENTICATION ATTEMPTS")
        lines.append("No suspicious authentication activity detected in the specified time period.")
        return "\n".join(lines)
    
    lines.append(f"## 📊 ATTACK OVERVIEW")
    lines.append(f"**Total Failed Attempts:** {total_attacks:,}")
    
    # Calculate attack intensity
    attacks_per_hour = total_attacks / hours
    if attacks_per_hour > 100:
        intensity = "🔴 **CRITICAL** - Heavy attack in progress"
    elif attacks_per_hour > 20:
        intensity = "🟡 **HIGH** - Active brute force attempts"
    elif attacks_per_hour > 5:
        intensity = "🟠 **MODERATE** - Ongoing probing"
    else:
        intensity = "🟢 **LOW** - Minimal activity"
        
    lines.append(f"**Attack Intensity:** {intensity} ({attacks_per_hour:.1f} attempts/hour)")
    lines.append("")
    
    # Top attacking IPs
    if attacking_ips:
        lines.append("## 🌐 TOP ATTACKING IP ADDRESSES")
        for i, (ip, count) in enumerate(attacking_ips[:10], 1):
            if ip != "unknown":
                percentage = (count / total_attacks) * 100
                lines.append(f"**{i}. {ip}** - {count:,} attempts ({percentage:.1f}%)")
        lines.append("")
    
    # Most targeted devices
    if not device_name and targeted_devices:
        lines.append("## 🎯 MOST TARGETED DEVICES")
        for i, (device, count) in enumerate(targeted_devices[:5], 1):
            percentage = (count / total_attacks) * 100
            lines.append(f"**{i}. {device}** - {count:,} attempts ({percentage:.1f}%)")
        lines.append("")
    
    # Failed usernames
    if failed_users:
        lines.append("## 👤 TARGETED USERNAMES")
        valid_users = [(user, count) for user, count in failed_users if user != "unknown"]
        for i, (user, count) in enumerate(valid_users[:10], 1):
            percentage = (count / total_attacks) * 100
            lines.append(f"**{i}. {user}** - {count:,} attempts ({percentage:.1f}%)")
        lines.append("")
    
    # Attack methods
    if attack_methods:
        lines.append("## 🔓 ATTACK METHODS")
        for i, (method, count) in enumerate(attack_methods[:5], 1):
            percentage = (count / total_attacks) * 100
            lines.append(f"**{i}. {method}** - {count:,} attempts ({percentage:.1f}%)")
        lines.append("")
    
    # Timeline analysis
    if attack_timeline:
        lines.append("## ⏱️ ATTACK TIMELINE")
        
        # Find peak activity periods
        timeline_data = [(timestamp, count) for timestamp, count in attack_timeline if count > 0]
        if timeline_data:
            max_attacks = max(count for _, count in timeline_data)
            peaks = [(ts, count) for ts, count in timeline_data if count >= max_attacks * 0.7]
            
            if peaks:
                lines.append("### 📈 PEAK ATTACK PERIODS")
                for timestamp, count in peaks[:5]:
                    hour = timestamp.split("T")[1][:5]  # Extract HH:MM
                    lines.append(f"- **{hour} UTC:** {count:,} failed attempts")
                lines.append("")
    
    # Sample attack logs
    if sample_attacks:
        lines.append("## 📝 RECENT ATTACK SAMPLES")
        
        # Group samples by attack type for better organization
        password_attacks = []
        invalid_users = []
        other_attacks = []
        
        for attack in sample_attacks[:15]:
            msg = attack["message"]
            if "Failed password" in msg:
                password_attacks.append(attack)
            elif "Invalid user" in msg:
                invalid_users.append(attack)
            else:
                other_attacks.append(attack)
        
        # Show password brute force examples
        if password_attacks:
            lines.append("### 🔑 Password Brute Force Attempts")
            for attack in password_attacks[:3]:
                timestamp = attack["timestamp"].split("T")[1][:8]  # HH:MM:SS
                device = attack["device"]
                message = attack["message"][:150] + "..." if len(attack["message"]) > 150 else attack["message"]
                lines.append("```")
                lines.append(f"{timestamp} {device}: {message}")
                lines.append("```")
            lines.append("")
        
        # Show invalid user examples
        if invalid_users:
            lines.append("### 👻 Invalid Username Probes")
            for attack in invalid_users[:3]:
                timestamp = attack["timestamp"].split("T")[1][:8]  # HH:MM:SS
                device = attack["device"]
                message = attack["message"][:150] + "..." if len(attack["message"]) > 150 else attack["message"]
                lines.append("```")
                lines.append(f"{timestamp} {device}: {message}")
                lines.append("```")
            lines.append("")
        
        # Show other attack types
        if other_attacks:
            lines.append("### 🔍 Other Attack Attempts")
            for attack in other_attacks[:2]:
                timestamp = attack["timestamp"].split("T")[1][:8]  # HH:MM:SS
                device = attack["device"]
                message = attack["message"][:150] + "..." if len(attack["message"]) > 150 else attack["message"]
                lines.append("```")
                lines.append(f"{timestamp} {device}: {message}")
                lines.append("```")
            lines.append("")
    
    # Recommendations
    lines.append("## 🛡️ SECURITY RECOMMENDATIONS")
    recommendations = []
    
    if total_attacks > 1000:
        recommendations.append("**URGENT:** Implement IP-based blocking/rate limiting - very high attack volume")
    elif total_attacks > 100:
        recommendations.append("Consider implementing fail2ban or similar IP blocking solution")
    
    if attacking_ips and len(attacking_ips) < 5:
        recommendations.append("Few attack sources detected - consider blocking specific IPs")
    elif attacking_ips and len(attacking_ips) > 20:
        recommendations.append("Distributed attack detected - implement geographic IP filtering")
    
    # Check for common usernames being attacked
    common_targets = ["root", "admin", "administrator", "user", "ubuntu", "centos"]
    if any(user in common_targets for user, _ in failed_users[:5]):
        recommendations.append("Disable/rename default accounts (root, admin, etc.) if possible")
    
    if attacks_per_hour > 50:
        recommendations.append("Change SSH to non-standard port (not 22)")
        recommendations.append("Implement SSH key-only authentication")
    
    recommendations.append("Monitor logs regularly for new attack patterns")
    recommendations.append("Consider implementing multi-factor authentication")
    
    for i, rec in enumerate(recommendations[:6], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


class DeviceSummaryParameters(BaseModel):
    """Parameters for the get_device_summary MCP tool."""
    
    device: str = Field(
        ...,
        description="Device name to analyze"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )


class FailedAuthParameters(BaseModel):
    """Parameters for the failed_auth_summary MCP tool."""
    
    device: Optional[str] = Field(
        None,
        description="Specific device to analyze (optional, analyzes all devices if not specified)"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )
    
    top_ips: int = Field(
        10,
        ge=1,
        le=50,
        description="Number of top attacking IPs to show (default: 10)"
    )


class SuspiciousActivityParameters(BaseModel):
    """Parameters for the suspicious_activity MCP tool."""
    
    device: Optional[str] = Field(
        None,
        description="Specific device to analyze (optional, analyzes all devices if not specified)"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )
    
    sensitivity: str = Field(
        "medium",
        pattern="^(low|medium|high)$",
        description="Detection sensitivity level (low, medium, high)"
    )


class AuthTimelineParameters(BaseModel):
    """Parameters for the auth_timeline MCP tool."""
    
    device: Optional[str] = Field(
        None,
        description="Specific device to analyze (optional, analyzes all devices if not specified)"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )
    
    interval: str = Field(
        "1h",
        pattern="^(1m|5m|15m|30m|1h|2h|4h|6h|12h|1d)$",
        description="Time interval for timeline buckets (1m, 5m, 15m, 30m, 1h, 2h, 4h, 6h, 12h, 1d)"
    )


class IpReputationParameters(BaseModel):
    """Parameters for the ip_reputation MCP tool."""
    
    ip_address: Optional[str] = Field(
        None,
        description="Specific IP address to analyze (optional, analyzes top IPs if not specified)"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )
    
    top_count: int = Field(
        20,
        ge=1,
        le=100,
        description="Number of top IPs to analyze (1-100, default: 20)"
    )


class ErrorAnalysisParameters(BaseModel):
    """Parameters for the error_analysis MCP tool."""
    
    device: Optional[str] = Field(
        None,
        description="Specific device to analyze (optional, analyzes all devices if not specified)"
    )
    
    hours: int = Field(
        24,
        ge=1,
        le=168,  # Max 1 week
        description="Number of hours to analyze (default: 24)"
    )
    
    severity: Optional[str] = Field(
        None,
        pattern="^(debug|info|notice|warning|warn|error|err|critical|crit|alert|emergency)$",
        description="Filter by specific severity level (optional)"
    )


class TimeRangeSearchParameters(BaseModel):
    """Parameters for the search_by_timerange MCP tool."""
    
    start_time: str = Field(
        ...,
        description="Start time in ISO format (e.g., 2023-12-01T10:00:00Z)"
    )
    
    end_time: str = Field(
        ...,
        description="End time in ISO format (e.g., 2023-12-01T12:00:00Z)"
    )
    
    device: Optional[str] = Field(
        None,
        description="Specific device to search (optional)"
    )
    
    query: Optional[str] = Field(
        None,
        description="Text query to search for (optional)"
    )
    
    limit: int = Field(
        100,
        ge=1,
        le=1000,
        description="Maximum number of results to return (1-1000, default: 100)"
    )


def _generate_auth_timeline_summary(
    device_name: Optional[str],
    hours: int,
    interval: str,
    timeline_data: List[Dict[str, Any]],
    auth_patterns: List[Dict[str, Any]],
    peak_periods: List[Dict[str, Any]],
    total_auth_events: int
) -> str:
    """Generate a human-readable authentication timeline summary."""
    
    lines = []
    lines.append("# 📅 AUTHENTICATION TIMELINE ANALYSIS")
    
    if device_name:
        lines.append(f"**Target Device:** {device_name}")
    else:
        lines.append("**Scope:** All devices")
        
    lines.append(f"**Analysis Period:** Last {hours} hours")
    lines.append(f"**Time Interval:** {interval}")
    lines.append("")
    
    if total_auth_events == 0:
        lines.append("## ✅ NO AUTHENTICATION ACTIVITY")
        lines.append("No authentication events found in the specified time period.")
        return "\n".join(lines)
    
    lines.append(f"## 📊 TIMELINE OVERVIEW")
    lines.append(f"**Total Authentication Events:** {total_auth_events:,}")
    
    # Calculate average activity
    non_zero_periods = [p for p in timeline_data if p["count"] > 0]
    if non_zero_periods:
        avg_activity = sum(p["count"] for p in non_zero_periods) / len(non_zero_periods)
        lines.append(f"**Average Activity:** {avg_activity:.1f} events per {interval}")
    lines.append("")
    
    # Peak periods analysis
    if peak_periods:
        lines.append("## 🔥 PEAK ACTIVITY PERIODS")
        for period in peak_periods[:5]:
            timestamp_raw = period["timestamp"]
            timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else timestamp_raw
            count = period["count"]
            lines.append(f"- **{timestamp} UTC:** {count:,} authentication events")
        lines.append("")
    
    # Authentication patterns
    if auth_patterns:
        lines.append("## 🔐 AUTHENTICATION PATTERNS")
        for pattern in auth_patterns[:5]:
            pattern_type = pattern["type"]
            count = pattern["count"]
            percentage = (count / total_auth_events) * 100
            lines.append(f"**{pattern_type}:** {count:,} events ({percentage:.1f}%)")
        lines.append("")
    
    # Timeline visualization (simple text chart)
    if len(timeline_data) <= 24:  # Only show chart for reasonable number of periods
        lines.append("## 📈 ACTIVITY TIMELINE")
        max_count = max(p["count"] for p in timeline_data) if timeline_data else 0
        if max_count > 0:
            for period in timeline_data[-12:]:  # Show last 12 periods
                timestamp_raw = period["timestamp"]
                timestamp = timestamp_raw.split("T")[1][:5] if "T" in timestamp_raw else timestamp_raw[-5:]
                count = period["count"]
                bar_length = int((count / max_count) * 20) if max_count > 0 else 0
                bar = "█" * bar_length + "░" * (20 - bar_length)
                lines.append(f"{timestamp}: {bar} {count:,}")
        lines.append("")
    
    return "\n".join(lines)


def _generate_ip_reputation_summary(
    ip_address: Optional[str],
    hours: int,
    ip_analysis: List[Dict[str, Any]],
    geographic_data: List[Dict[str, Any]],
    attack_patterns: List[Dict[str, Any]],
    total_requests: int
) -> str:
    """Generate a human-readable IP reputation analysis summary."""
    
    lines = []
    lines.append("# 🌐 IP REPUTATION ANALYSIS")
    
    if ip_address:
        lines.append(f"**Target IP:** {ip_address}")
    else:
        lines.append("**Scope:** Top suspicious IPs")
        
    lines.append(f"**Analysis Period:** Last {hours} hours")
    lines.append("")
    
    if total_requests == 0:
        lines.append("## ✅ NO SUSPICIOUS IP ACTIVITY")
        lines.append("No suspicious IP activity detected in the specified time period.")
        return "\n".join(lines)
    
    lines.append(f"## 📊 IP ACTIVITY OVERVIEW")
    lines.append(f"**Total Requests from Analyzed IPs:** {total_requests:,}")
    lines.append("")
    
    # IP analysis
    if ip_analysis:
        lines.append("## 🎯 TOP SUSPICIOUS IPs")
        for i, ip_data in enumerate(ip_analysis[:10], 1):
            ip = ip_data["ip"]
            count = ip_data["count"]
            risk_level = ip_data.get("risk_level", "medium")
            country = ip_data.get("country", "unknown")
            
            risk_emoji = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
            lines.append(f"**{i}. {ip}** {risk_emoji}")
            lines.append(f"   - **Requests:** {count:,}")
            lines.append(f"   - **Country:** {country}")
            lines.append(f"   - **Risk Level:** {risk_level}")
            
            # Add context about why it's suspicious
            if count > 1000:
                lines.append(f"   - *⚠️ High volume activity - potential bot/scanner*")
            elif "Failed" in str(ip_data.get("sample_activity", "")):
                lines.append(f"   - *⚠️ Authentication failures detected*")
                
        lines.append("")
    
    # Geographic analysis
    if geographic_data:
        lines.append("## 🗺️ GEOGRAPHIC DISTRIBUTION")
        for geo in geographic_data[:8]:
            country = geo["country"]
            count = geo["count"]
            percentage = (count / total_requests) * 100
            lines.append(f"- **{country}:** {count:,} requests ({percentage:.1f}%)")
        lines.append("")
    
    # Attack patterns
    if attack_patterns:
        lines.append("## 🚨 ATTACK PATTERNS")
        for pattern in attack_patterns[:5]:
            pattern_type = pattern["type"]
            count = pattern["count"]
            description = pattern.get("description", "")
            lines.append(f"**{pattern_type}:** {count:,} occurrences")
            if description:
                lines.append(f"   *{description}*")
        lines.append("")
    
    # Recommendations
    lines.append("## 🛡️ IP SECURITY RECOMMENDATIONS")
    recommendations = []
    
    high_risk_ips = [ip for ip in ip_analysis if ip.get("risk_level") == "high"]
    if high_risk_ips:
        recommendations.append(f"**URGENT:** Block {len(high_risk_ips)} high-risk IP addresses immediately")
    
    if total_requests > 10000:
        recommendations.append("Implement rate limiting - very high request volume detected")
    
    suspicious_countries = [g["country"] for g in geographic_data if g["count"] > total_requests * 0.1]
    if suspicious_countries:
        recommendations.append(f"Consider geo-blocking traffic from: {', '.join(suspicious_countries[:3])}")
    
    recommendations.append("Monitor these IPs for continued malicious activity")
    recommendations.append("Update firewall rules based on analysis")
    recommendations.append("Consider implementing CAPTCHA for suspicious IPs")
    
    for i, rec in enumerate(recommendations[:6], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def _generate_error_analysis_summary(
    device_name: Optional[str],
    hours: int,
    severity: Optional[str],
    error_patterns: List[Dict[str, Any]],
    error_timeline: List[Dict[str, Any]],
    affected_services: List[Dict[str, Any]],
    total_errors: int
) -> str:
    """Generate a human-readable error analysis summary."""
    
    lines = []
    lines.append("# ⚠️ ERROR ANALYSIS REPORT")
    
    if device_name:
        lines.append(f"**Target Device:** {device_name}")
    else:
        lines.append("**Scope:** All devices")
        
    lines.append(f"**Analysis Period:** Last {hours} hours")
    if severity:
        lines.append(f"**Severity Filter:** {severity.upper()}")
    lines.append("")
    
    if total_errors == 0:
        lines.append("## ✅ NO ERRORS DETECTED")
        lines.append("No error events found matching the specified criteria.")
        return "\n".join(lines)
    
    lines.append(f"## 📊 ERROR OVERVIEW")
    lines.append(f"**Total Error Events:** {total_errors:,}")
    
    # Calculate error rate
    error_rate = total_errors / hours
    if error_rate > 100:
        severity_level = "🔴 **CRITICAL** - Very high error rate"
    elif error_rate > 20:
        severity_level = "🟡 **HIGH** - Elevated error rate"
    else:
        severity_level = "🟢 **NORMAL** - Acceptable error rate"
    
    lines.append(f"**Error Rate:** {severity_level} ({error_rate:.1f} errors/hour)")
    lines.append("")
    
    # Error patterns
    if error_patterns:
        lines.append("## 🔍 TOP ERROR PATTERNS")
        for i, pattern in enumerate(error_patterns[:8], 1):
            error_type = pattern["type"]
            count = pattern["count"]
            percentage = (count / total_errors) * 100
            sample_msg = pattern.get("sample_message", "")[:80]
            
            lines.append(f"**{i}. {error_type}** - {count:,} occurrences ({percentage:.1f}%)")
            if sample_msg:
                lines.append(f"   *Sample: {sample_msg}...*")
                
        lines.append("")
    
    # Affected services
    if affected_services:
        lines.append("## ⚙️ AFFECTED SERVICES")
        for service in affected_services[:6]:
            service_name = service["service"]
            count = service["count"]
            lines.append(f"- **{service_name}:** {count:,} errors")
        lines.append("")
    
    # Error timeline peaks
    if error_timeline:
        peak_errors = sorted(error_timeline, key=lambda x: x["count"], reverse=True)[:5]
        if peak_errors and peak_errors[0]["count"] > 0:
            lines.append("## 📈 ERROR TIMELINE PEAKS")
            for peak in peak_errors:
                timestamp_raw = peak["timestamp"]
                timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
                count = peak["count"]
                lines.append(f"- **{timestamp} UTC:** {count:,} errors")
            lines.append("")
    
    # Recommendations
    lines.append("## 🔧 ERROR RESOLUTION RECOMMENDATIONS")
    recommendations = []
    
    if error_rate > 50:
        recommendations.append("**URGENT:** Investigate critical system issues - extremely high error rate")
    elif error_rate > 20:
        recommendations.append("Review system health - elevated error rate detected")
    
    critical_services = [s for s in affected_services if s["count"] > total_errors * 0.2]
    if critical_services:
        service_names = [s["service"] for s in critical_services[:3]]
        recommendations.append(f"Focus on these high-error services: {', '.join(service_names)}")
    
    if "systemd" in [s["service"] for s in affected_services[:5]]:
        recommendations.append("Check system service configurations and dependencies")
    
    if any("network" in p["type"].lower() for p in error_patterns[:3]):
        recommendations.append("Investigate network connectivity and configuration issues")
    
    recommendations.append("Monitor error trends and implement automated alerting")
    recommendations.append("Review application logs for additional context")
    
    for i, rec in enumerate(recommendations[:6], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def _generate_suspicious_activity_summary(
    device_name: Optional[str],
    hours: int,
    total_suspicious: int,
    unusual_commands: List[Dict[str, Any]],
    off_hours_activity: List[Dict[str, Any]],
    privilege_escalations: List[Dict[str, Any]],
    network_anomalies: List[Dict[str, Any]],
    file_system_activity: List[Dict[str, Any]],
    service_anomalies: List[Dict[str, Any]],
    sample_events: List[Dict[str, Any]],
    sensitivity: str
) -> str:
    """Generate a human-readable suspicious activity analysis summary."""
    
    lines = []
    lines.append("# 🔍 SUSPICIOUS ACTIVITY ANALYSIS")
    
    if device_name:
        lines.append(f"**Target Device:** {device_name}")
    else:
        lines.append("**Scope:** All devices")
        
    lines.append(f"**Analysis Period:** Last {hours} hours")
    lines.append(f"**Detection Sensitivity:** {sensitivity.upper()}")
    lines.append("")
    
    # Overall statistics
    if total_suspicious == 0:
        lines.append("## ✅ NO SUSPICIOUS ACTIVITY DETECTED")
        lines.append("No unusual activity patterns detected with current sensitivity settings.")
        lines.append("")
        lines.append("💡 **Tip:** Try increasing sensitivity to 'high' for more detailed analysis")
        return "\n".join(lines)
    
    lines.append(f"## 📊 ACTIVITY OVERVIEW")
    lines.append(f"**Total Suspicious Events:** {total_suspicious:,}")
    
    # Threat level assessment
    if total_suspicious > 100:
        threat_level = "🔴 **HIGH** - Multiple suspicious patterns detected"
    elif total_suspicious > 20:
        threat_level = "🟡 **MEDIUM** - Some unusual activity detected"  
    else:
        threat_level = "🟢 **LOW** - Minimal suspicious activity"
        
    lines.append(f"**Threat Level:** {threat_level}")
    lines.append("")
    
    # Unusual commands section
    if unusual_commands:
        lines.append("## 💻 UNUSUAL COMMAND EXECUTION")
        lines.append(f"**Detected:** {len(unusual_commands)} suspicious command patterns")
        
        for i, cmd in enumerate(unusual_commands[:5], 1):
            command = cmd["command"]
            count = cmd["count"]
            risk = cmd.get("risk_level", "medium")
            lines.append(f"**{i}. {command}** - {count} executions (Risk: {risk})")
            
            # Add context about why it's suspicious
            if "rm -rf" in command:
                lines.append("   *⚠️ Dangerous file deletion command*")
            elif "chmod 777" in command:
                lines.append("   *⚠️ Dangerous permission changes*")
            elif "nc " in command or "netcat" in command:
                lines.append("   *⚠️ Network tool usage - potential backdoor*")
            elif "wget" in command or "curl" in command:
                lines.append("   *⚠️ File download activity*")
                
        lines.append("")
    
    # Off-hours activity
    if off_hours_activity:
        lines.append("## 🌙 OFF-HOURS ACTIVITY")
        lines.append(f"**Detected:** {len(off_hours_activity)} unusual timing patterns")
        
        for activity in off_hours_activity[:3]:
            timestamp_raw = activity["timestamp"]
            if "T" in timestamp_raw:
                timestamp = timestamp_raw.split("T")[1][:5]  # HH:MM
            else:
                timestamp = "unknown"
            program = activity["program"]
            count = activity["count"]
            lines.append(f"- **{timestamp} UTC:** {program} ({count} events)")
            
        lines.append("")
    
    # Privilege escalations
    if privilege_escalations:
        lines.append("## 🔐 PRIVILEGE ESCALATION ATTEMPTS")
        lines.append(f"**Detected:** {len(privilege_escalations)} escalation events")
        
        for escalation in privilege_escalations[:3]:
            timestamp_raw = escalation["timestamp"]
            if "T" in timestamp_raw:
                timestamp = timestamp_raw.split("T")[1][:8]  # HH:MM:SS
            else:
                timestamp = "unknown"
            user = escalation.get("user", "unknown")
            command = escalation.get("command", escalation["message"][:50])
            lines.append(f"- **{timestamp}:** User '{user}' - {command}...")
            
        lines.append("")
    
    # Network anomalies
    if network_anomalies:
        lines.append("## 🌐 NETWORK ANOMALIES")
        lines.append(f"**Detected:** {len(network_anomalies)} unusual network patterns")
        
        for anomaly in network_anomalies[:3]:
            pattern_type = anomaly.get("type", "unknown")
            count = anomaly["count"]
            description = anomaly.get("description", "")
            lines.append(f"- **{pattern_type}:** {count} occurrences - {description}")
            
        lines.append("")
    
    # File system activity
    if file_system_activity:
        lines.append("## 📁 SUSPICIOUS FILE SYSTEM ACTIVITY")
        lines.append(f"**Detected:** {len(file_system_activity)} unusual file operations")
        
        for fs_activity in file_system_activity[:3]:
            activity_type = fs_activity.get("type", "unknown")
            path = fs_activity.get("path", "unknown")
            count = fs_activity["count"]
            lines.append(f"- **{activity_type}:** {path} ({count} operations)")
            
        lines.append("")
    
    # Service anomalies
    if service_anomalies:
        lines.append("## ⚙️ SERVICE ANOMALIES")
        lines.append(f"**Detected:** {len(service_anomalies)} unusual service behavior")
        
        for service in service_anomalies[:3]:
            service_name = service["service"]
            anomaly_type = service.get("anomaly", "unusual activity")
            count = service["count"]
            lines.append(f"- **{service_name}:** {anomaly_type} ({count} events)")
            
        lines.append("")
    
    # Sample events with context
    if sample_events:
        lines.append("## 📝 SAMPLE SUSPICIOUS EVENTS")
        
        # Group by type for better organization
        high_risk = [e for e in sample_events if e.get("risk", "medium") == "high"]
        medium_risk = [e for e in sample_events if e.get("risk", "medium") == "medium"]
        
        if high_risk:
            lines.append("### 🚨 High Risk Events")
            for event in high_risk[:3]:
                timestamp_raw = event["timestamp"]
                timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
                device = event.get("device", "unknown")
                message = event["message"][:120] + "..." if len(event["message"]) > 120 else event["message"]
                lines.append("```")
                lines.append(f"{timestamp} {device}: {message}")
                lines.append("```")
            lines.append("")
            
        if medium_risk:
            lines.append("### ⚠️ Medium Risk Events")
            for event in medium_risk[:2]:
                timestamp_raw = event["timestamp"]
                timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
                device = event.get("device", "unknown")  
                message = event["message"][:120] + "..." if len(event["message"]) > 120 else event["message"]
                lines.append("```")
                lines.append(f"{timestamp} {device}: {message}")
                lines.append("```")
            lines.append("")
    
    # Recommendations
    lines.append("## 🛡️ SECURITY RECOMMENDATIONS")
    recommendations = []
    
    if unusual_commands:
        recommendations.append("Review and audit unusual command executions - verify legitimate business purpose")
        
    if off_hours_activity:
        recommendations.append("Investigate off-hours activity - confirm authorized personnel or automated processes")
        
    if privilege_escalations:
        recommendations.append("**HIGH PRIORITY:** Review all privilege escalation attempts immediately")
        
    if network_anomalies:
        recommendations.append("Analyze network traffic patterns - check for data exfiltration or command & control")
        
    if file_system_activity:
        recommendations.append("Monitor file system changes - implement file integrity monitoring")
        
    if service_anomalies:
        recommendations.append("Check service configurations and logs for signs of tampering")
    
    # General recommendations based on threat level
    if total_suspicious > 50:
        recommendations.append("Enable enhanced logging and monitoring")
        recommendations.append("Consider implementing SIEM alerting for these patterns")
        
    recommendations.append("Correlate events with user activity and business operations")
    recommendations.append("Update security policies based on identified threats")
    
    for i, rec in enumerate(recommendations[:7], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def _generate_timerange_search_summary(
    start_time: str,
    end_time: str,
    device: Optional[str],
    query: Optional[str],
    limit: int,
    total_results: int,
    log_entries: List[Dict[str, Any]],
    device_breakdown: List[Dict[str, Any]],
    hourly_activity: List[Dict[str, Any]],
    message_patterns: List[Dict[str, Any]],
    time_diff: Any
) -> str:
    """Generate a human-readable time range search summary."""
    
    lines = []
    lines.append("# 🕒 TIME RANGE LOG SEARCH")
    lines.append("")
    lines.append(f"**Search Period:** {start_time} to {end_time}")
    lines.append(f"**Duration:** {time_diff.total_seconds() / 3600:.1f} hours ({time_diff.days} days)")
    if device:
        lines.append(f"**Device Filter:** {device}")
    else:
        lines.append("**Scope:** All devices")
    if query:
        lines.append(f"**Text Filter:** \"{query}\"")
    lines.append(f"**Results Limit:** {limit}")
    lines.append("")
    
    if total_results == 0:
        lines.append("## 📭 NO MATCHING ENTRIES")
        lines.append("No log entries found matching the specified criteria.")
        lines.append("")
        lines.append("### 💡 Search Tips")
        lines.append("- Try expanding the time range")
        lines.append("- Remove or modify text filters")
        lines.append("- Check device name spelling")
        lines.append("- Use broader search terms")
        return "\n".join(lines)
    
    lines.append("## 📊 SEARCH RESULTS OVERVIEW")
    lines.append(f"**Total Matching Entries:** {total_results:,}")
    lines.append(f"**Displaying:** {len(log_entries):,} entries (most recent first)")
    
    if total_results > limit:
        lines.append(f"**Note:** Showing top {limit} most recent entries out of {total_results:,} total matches")
    
    # Activity rate
    activity_rate = total_results / (time_diff.total_seconds() / 3600)
    if activity_rate > 100:
        activity_level = "🔴 **VERY HIGH**"
    elif activity_rate > 20:
        activity_level = "🟡 **MODERATE**"
    else:
        activity_level = "🟢 **NORMAL**"
        
    lines.append(f"**Activity Rate:** {activity_level} ({activity_rate:.1f} entries/hour)")
    lines.append("")
    
    # Device breakdown
    if device_breakdown:
        lines.append("## 💻 DEVICE ACTIVITY BREAKDOWN")
        for i, dev in enumerate(device_breakdown[:8], 1):
            device_name = dev["key"]
            count = dev["doc_count"]
            percentage = (count / total_results) * 100
            lines.append(f"**{i}. {device_name}** - {count:,} entries ({percentage:.1f}%)")
        lines.append("")
    
    # Message patterns
    if message_patterns:
        lines.append("## 🔍 MESSAGE PATTERNS")
        for pattern in message_patterns[:6]:
            pattern_type = pattern["key"]
            count = pattern["doc_count"]
            percentage = (count / total_results) * 100
            lines.append(f"- **{pattern_type}:** {count:,} entries ({percentage:.1f}%)")
        lines.append("")
    
    # Activity timeline peaks
    if hourly_activity:
        peak_hours = sorted(hourly_activity, key=lambda x: x["doc_count"], reverse=True)[:5]
        if peak_hours and peak_hours[0]["doc_count"] > 0:
            lines.append("## 📈 PEAK ACTIVITY PERIODS")
            for peak in peak_hours:
                timestamp_raw = peak["key_as_string"]
                timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
                count = peak["doc_count"]
                lines.append(f"- **{timestamp} UTC:** {count:,} entries")
            lines.append("")
    
    # Recent log entries
    if log_entries:
        lines.append("## 📝 LOG ENTRIES (Most Recent First)")
        for i, entry in enumerate(log_entries[:15], 1):
            timestamp_raw = entry["timestamp"]
            timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
            device_name = entry["device"]
            level = entry.get("level", "info").upper()
            message = entry["message"]
            
            # Level emoji
            level_emoji = {"ERROR": "🔴", "WARN": "🟡", "WARNING": "🟡", "INFO": "🔵", "DEBUG": "⚪"}.get(level, "⚪")
            
            lines.append(f"**{i}.** `{timestamp}` {level_emoji} **{device_name}** [{level}]")
            lines.append(f"   {message}")
            lines.append("")
        
        if len(log_entries) > 15:
            lines.append(f"*... and {len(log_entries) - 15} more entries*")
            lines.append("")
    
    # Search performance tips
    lines.append("## ⚡ SEARCH OPTIMIZATION")
    recommendations = []
    
    if total_results > 10000:
        recommendations.append("Consider narrowing time range - very large result set")
    if activity_rate > 200:
        recommendations.append("High activity period detected - consider filtering by device or message type")
    if query and len(query) < 4:
        recommendations.append("Use longer search terms for more precise results")
    if not query and total_results > 1000:
        recommendations.append("Add text filters to focus search results")
    
    recommendations.append("Use specific devices or error keywords to filter results")
    recommendations.append("Combine with text search for targeted investigation")
    
    for i, rec in enumerate(recommendations[:5], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def _generate_full_text_search_summary(
    query: str,
    device: Optional[str],
    hours: int,
    limit: int,
    search_type: str,
    total_results: int,
    max_score: float,
    search_results: List[Dict[str, Any]],
    device_matches: List[Dict[str, Any]],
    time_distribution: List[Dict[str, Any]],
    related_terms: List[Dict[str, Any]],
    message_stats: Dict[str, Any]
) -> str:
    """Generate a human-readable full-text search summary."""
    
    lines = []
    lines.append("# 🔍 FULL-TEXT SEARCH RESULTS")
    lines.append("")
    lines.append(f"**Search Query:** \"{query}\"")
    lines.append(f"**Search Type:** {search_type.title()}")
    lines.append(f"**Time Window:** Last {hours} hours")
    if device:
        lines.append(f"**Device Filter:** {device}")
    else:
        lines.append("**Scope:** All devices")
    lines.append(f"**Results Limit:** {limit}")
    lines.append("")
    
    if total_results == 0:
        lines.append("## ❌ NO MATCHES FOUND")
        lines.append(f"No log entries found matching \"{query}\" in the specified time period.")
        lines.append("")
        lines.append("### 💡 Search Suggestions")
        lines.append("- Try different search terms or synonyms")
        lines.append("- Use 'fuzzy' search type for approximate matches")
        lines.append("- Use 'wildcard' search with * for partial matches")
        lines.append("- Expand the time window")
        lines.append("- Remove device filters")
        return "\n".join(lines)
    
    lines.append("## 📊 SEARCH PERFORMANCE")
    lines.append(f"**Total Matches:** {total_results:,}")
    lines.append(f"**Displaying:** {len(search_results)} results (highest relevance first)")
    lines.append(f"**Max Relevance Score:** {max_score:.2f}")
    
    if total_results > limit:
        lines.append(f"**Note:** Showing top {limit} most relevant results out of {total_results:,} total matches")
    
    # Search effectiveness
    match_rate = (total_results / hours) if hours > 0 else 0
    if match_rate > 50:
        effectiveness = "🔥 **VERY COMMON** - High frequency term"
    elif match_rate > 10:
        effectiveness = "🟡 **FREQUENT** - Regular occurrence"
    elif match_rate > 1:
        effectiveness = "🟢 **MODERATE** - Occasional occurrence"
    else:
        effectiveness = "🔵 **RARE** - Infrequent term"
        
    lines.append(f"**Search Effectiveness:** {effectiveness} ({match_rate:.1f} matches/hour)")
    lines.append("")
    
    # Device distribution
    if device_matches:
        lines.append("## 💻 DEVICES WITH MATCHES")
        for i, dev in enumerate(device_matches[:8], 1):
            device_name = dev["key"]
            count = dev["doc_count"]
            percentage = (count / total_results) * 100
            lines.append(f"**{i}. {device_name}** - {count:,} matches ({percentage:.1f}%)")
        lines.append("")
    
    # Time distribution
    if time_distribution:
        peak_times = sorted(time_distribution, key=lambda x: x["doc_count"], reverse=True)[:5]
        if peak_times:
            lines.append("## ⏰ TEMPORAL DISTRIBUTION")
            for peak in peak_times:
                timestamp_raw = peak["key_as_string"]
                timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
                count = peak["doc_count"]
                lines.append(f"- **{timestamp} UTC:** {count:,} matches")
            lines.append("")
    
    # Related terms
    if related_terms:
        lines.append("## 🔗 RELATED TERMS FOUND")
        for term in related_terms[:8]:
            term_text = term["key"]
            score = term.get("score", 0)
            lines.append(f"- **{term_text}** (relevance: {score:.2f})")
        lines.append("")
    
    # Top matching results
    if search_results:
        lines.append("## 🎯 TOP MATCHING LOG ENTRIES")
        for i, result in enumerate(search_results[:10], 1):
            timestamp_raw = result["timestamp"]
            timestamp = timestamp_raw.split("T")[1][:8] if "T" in timestamp_raw else "unknown"
            device_name = result["device"]
            level = result.get("level", "info").upper()
            message = result["message"]
            score = result["score"]
            highlight = result.get("highlight", "")
            
            # Level emoji
            level_emoji = {"ERROR": "🔴", "WARN": "🟡", "WARNING": "🟡", "INFO": "🔵", "DEBUG": "⚪"}.get(level, "⚪")
            
            # Relevance stars
            stars = "⭐" * min(5, int(score / max(max_score / 5, 1))) if max_score > 0 else ""
            
            lines.append(f"**{i}.** `{timestamp}` {level_emoji} **{device_name}** [{level}] {stars}")
            lines.append(f"   **Score:** {score:.2f}")
            
            if highlight and highlight != message:
                lines.append(f"   **Highlighted:** {highlight[:150]}...")
            else:
                lines.append(f"   {message}")
            lines.append("")
        
        if len(search_results) > 10:
            lines.append(f"*... and {len(search_results) - 10} more matches*")
            lines.append("")
    
    # Message statistics
    if message_stats:
        avg_length = message_stats.get("avg", 0)
        max_length = message_stats.get("max", 0)
        min_length = message_stats.get("min", 0)
        
        lines.append("## 📏 MESSAGE STATISTICS")
        lines.append(f"- **Average Length:** {avg_length:.0f} characters")
        lines.append(f"- **Longest Message:** {max_length} characters")
        lines.append(f"- **Shortest Message:** {min_length} characters")
        lines.append("")
    
    # Search optimization recommendations
    lines.append("## 🚀 SEARCH OPTIMIZATION TIPS")
    recommendations = []
    
    if search_type == "phrase" and total_results == 0:
        recommendations.append("Try 'fuzzy' search for typo-tolerant matching")
    if search_type == "phrase" and total_results > 1000:
        recommendations.append("Use exact phrases for more precise results")
    if max_score < 5 and total_results > 0:
        recommendations.append("Consider refining search terms for higher relevance")
    if total_results > 10000:
        recommendations.append("Add device or time filters to narrow results")
    
    search_tips = {
        "phrase": "Use quotes for exact phrase matching: \"error message\"",
        "fuzzy": "Handles typos automatically - good for uncertain spelling",
        "wildcard": "Use * for partial matches: \"fail*\" matches \"failed\", \"failure\"",
        "regex": "Advanced pattern matching - use carefully for complex searches"
    }
    
    recommendations.append(f"Current mode ({search_type}): {search_tips.get(search_type, 'Standard text search')}")
    recommendations.append("Combine with device filters for targeted investigation")
    recommendations.append("Use time range searches for incident analysis")
    
    for i, rec in enumerate(recommendations[:6], 1):
        lines.append(f"{i}. {rec}")
    
    return "\n".join(lines)


def register_device_analysis_tools(mcp: FastMCP) -> None:
    """Register all device analysis MCP tools."""
    
    @mcp.tool()
    async def get_device_summary(
        device: str,
        hours: int = 24
    ) -> str:
        """
        Get comprehensive summary of a device's recent activity.
        
        Provides a human-readable analysis including activity patterns,
        security concerns, hardware issues, and actionable recommendations
        with supporting log evidence.
        
        Args:
            device: Device name to analyze
            hours: Number of hours to analyze (1-168, default: 24)
            
        Returns:
            Formatted markdown text containing:
            - Overall device status and activity summary
            - Unusual activity detection (spikes, gaps)
            - Primary services analysis with explanations
            - Issues detected with log examples
            - Security assessment for auth-heavy devices
            - Actionable recommendations
        """
        request_args = {
            "device": device,
            "hours": hours
        }
        log_mcp_request("get_device_summary", request_args)
        
        try:
            # Validate parameters
            params = DeviceSummaryParameters(device=device, hours=hours)
            
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=params.hours)
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Build aggregation query for comprehensive device analysis
                agg_query = {
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"hostname.keyword": params.device}},
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": 0,  # We only want aggregations
                    "aggs": {
                        # Severity level distribution
                        "severity_distribution": {
                            "terms": {
                                "field": "severity.keyword",
                                "size": 10
                            }
                        },
                        # Top programs
                        "top_programs": {
                            "terms": {
                                "field": "program.keyword",
                                "size": 10
                            }
                        },
                        # Facility distribution
                        "facility_distribution": {
                            "terms": {
                                "field": "facility.keyword",
                                "size": 10
                            }
                        },
                        # Activity timeline (hourly buckets)
                        "activity_timeline": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": "1h",
                                "min_doc_count": 0,
                                "extended_bounds": {
                                    "min": start_time.isoformat(),
                                    "max": end_time.isoformat()
                                }
                            }
                        },
                        # Recent errors (last 50 error/warning messages)
                        "recent_errors": {
                            "filter": {
                                "terms": {
                                    "severity.keyword": ["error", "warning", "err", "warn"]
                                }
                            },
                            "aggs": {
                                "error_samples": {
                                    "top_hits": {
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                        "size": 20,
                                        "_source": ["timestamp", "program", "message", "severity"]
                                    }
                                }
                            }
                        },
                        # Most recent log entry
                        "latest_entry": {
                            "top_hits": {
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "size": 1,
                                "_source": ["timestamp", "program", "message"]
                            }
                        }
                    }
                }
                
                # Execute aggregation query
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=agg_query,
                    timeout="30s"
                )
                
                # Parse aggregation results
                aggs = response.get("aggregations", {})
                total_logs = response["hits"]["total"]["value"]
                
                # Extract severity distribution
                severity_buckets = aggs.get("severity_distribution", {}).get("buckets", [])
                severity_dist = {bucket["key"]: bucket["doc_count"] for bucket in severity_buckets}
                
                # Extract top programs
                program_buckets = aggs.get("top_programs", {}).get("buckets", [])
                top_programs = [
                    {"program": bucket["key"], "log_count": bucket["doc_count"]}
                    for bucket in program_buckets
                ]
                
                # Extract facility distribution
                facility_buckets = aggs.get("facility_distribution", {}).get("buckets", [])
                facility_dist = {bucket["key"]: bucket["doc_count"] for bucket in facility_buckets}
                
                # Extract activity timeline
                timeline_buckets = aggs.get("activity_timeline", {}).get("buckets", [])
                activity_timeline = [
                    {
                        "timestamp": bucket["key_as_string"],
                        "log_count": bucket["doc_count"]
                    }
                    for bucket in timeline_buckets
                ]
                
                # Extract recent errors
                error_hits = aggs.get("recent_errors", {}).get("error_samples", {}).get("hits", {}).get("hits", [])
                recent_errors = [
                    {
                        "timestamp": hit["_source"]["timestamp"],
                        "program": hit["_source"].get("program", "unknown"),
                        "severity": hit["_source"].get("severity", "unknown"),
                        "message": hit["_source"]["message"][:200] + "..." if len(hit["_source"]["message"]) > 200 else hit["_source"]["message"]
                    }
                    for hit in error_hits
                ]
                
                # Get most recent log entry
                latest_hits = aggs.get("latest_entry", {}).get("hits", {}).get("hits", [])
                last_seen = None
                if latest_hits:
                    last_seen = latest_hits[0]["_source"]["timestamp"]
                
                # Assess device status based on recent activity and errors
                error_count = sum(count for level, count in severity_dist.items() 
                                if level.lower() in ['error', 'err', 'critical', 'crit'])
                warning_count = sum(count for level, count in severity_dist.items() 
                                  if level.lower() in ['warning', 'warn'])
                
                if error_count > 50:
                    status = "critical"
                elif error_count > 10 or warning_count > 100:
                    status = "warning" 
                elif total_logs == 0:
                    status = "no_activity"
                else:
                    status = "healthy"
                
                # Generate human-readable summary with log evidence
                summary = _generate_device_analysis_summary(
                    params.device, 
                    total_logs, 
                    severity_dist, 
                    facility_dist,
                    top_programs, 
                    recent_errors, 
                    activity_timeline, 
                    last_seen, 
                    status,
                    error_count,
                    warning_count,
                    params.hours
                )
                
                # Return the summary directly as a string for clean display
                result = summary
                
                log_mcp_response("get_device_summary", True, {
                    "device": params.device,
                    "total_logs": total_logs,
                    "status": status
                })
                
                return result
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\n\nFailed to connect to Elasticsearch: {e.message}\n\nDevice: {device}"
            log_mcp_response("get_device_summary", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\n\nElasticsearch query failed: {e.message}\n\nDevice: {device}"
            log_mcp_response("get_device_summary", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\n\nUnexpected error occurred: {str(e)}\n\nDevice: {device}\nPlease check server logs for details."
            logger.error("Error in get_device_summary", extra={
                "error": str(e),
                "device": device,
                "hours": hours
            }, exc_info=True)
            log_mcp_response("get_device_summary", False, error=error_msg)
            return error_msg
    
    @mcp.tool()
    async def failed_auth_summary(
        device: Optional[str] = None,
        hours: int = 24,
        top_ips: int = 10
    ) -> str:
        """
        Track failed SSH/login attempts by source IP, user, and device.
        
        Provides analysis of authentication failures including attack patterns,
        geographic distribution, and targeted accounts with supporting log evidence.
        
        Args:
            device: Specific device to analyze (optional, analyzes all devices if not specified)
            hours: Number of hours to analyze (1-168, default: 24)
            top_ips: Number of top attacking IPs to show (1-50, default: 10)
            
        Returns:
            Formatted markdown text containing:
            - Failed authentication attempt statistics
            - Top attacking IP addresses with attempt counts
            - Most targeted usernames/accounts
            - Attack patterns and timing analysis
            - Geographic distribution if detectable
            - Sample log entries showing attack methods
        """
        request_args = {
            "device": device,
            "hours": hours,
            "top_ips": top_ips
        }
        log_mcp_request("failed_auth_summary", request_args)
        
        try:
            # Validate parameters
            params = FailedAuthParameters(device=device, hours=hours, top_ips=top_ips)
            
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=params.hours)
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Build query for failed authentication attempts
                base_query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "query_string": {
                                        "query": "(\"Failed password\" OR \"authentication failure\" OR \"Invalid user\" OR \"Failed publickey\" OR \"Connection closed by authenticating user\" OR \"Bad protocol version\" OR \"Unable to negotiate\") AND (ssh OR sshd OR auth)",
                                        "default_field": "message"
                                    }
                                }
                            ],
                            "filter": [
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
                
                # Add device filter if specified
                if params.device:
                    base_query["query"]["bool"]["filter"].append({
                        "term": {"hostname.keyword": params.device}
                    })
                
                # Add aggregations for analysis
                auth_query = {
                    **base_query,
                    "size": 0,
                    "aggs": {
                        # Top attacking IPs
                        "attacking_ips": {
                            "terms": {
                                "script": {
                                    "source": """
                                        String msg = doc['message.keyword'].value;
                                        Matcher m = /from\\s+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})/.matcher(msg);
                                        if (m.find()) {
                                            return m.group(1);
                                        }
                                        return 'unknown';
                                    """,
                                    "lang": "painless"
                                },
                                "size": params.top_ips
                            }
                        },
                        # Most targeted devices
                        "targeted_devices": {
                            "terms": {
                                "field": "hostname.keyword",
                                "size": 10
                            }
                        },
                        # Failed usernames
                        "failed_users": {
                            "terms": {
                                "script": {
                                    "source": """
                                        String msg = doc['message.keyword'].value;
                                        Matcher m = /(for|user)\\s+(\\w+)\\s+from/.matcher(msg);
                                        if (m.find()) {
                                            return m.group(2);
                                        }
                                        m = /Invalid user\\s+(\\w+)/.matcher(msg);
                                        if (m.find()) {
                                            return m.group(1);
                                        }
                                        return 'unknown';
                                    """,
                                    "lang": "painless"
                                },
                                "size": 15
                            }
                        },
                        # Attack timeline (hourly)
                        "attack_timeline": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": "1h",
                                "min_doc_count": 0,
                                "extended_bounds": {
                                    "min": start_time.isoformat(),
                                    "max": end_time.isoformat()
                                }
                            }
                        },
                        # Attack methods
                        "attack_methods": {
                            "terms": {
                                "script": {
                                    "source": """
                                        String msg = doc['message.keyword'].value;
                                        if (msg.contains('Failed password')) return 'Password Brute Force';
                                        if (msg.contains('Invalid user')) return 'Invalid Username';
                                        if (msg.contains('Failed publickey')) return 'SSH Key Attack';
                                        if (msg.contains('authentication failure')) return 'Auth Failure';
                                        if (msg.contains('Connection closed by authenticating')) return 'Connection Closed';
                                        return 'Other';
                                    """,
                                    "lang": "painless"
                                },
                                "size": 10
                            }
                        },
                        # Sample logs for evidence
                        "sample_attacks": {
                            "top_hits": {
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "size": 20,
                                "_source": ["timestamp", "hostname", "message", "program"]
                            }
                        }
                    }
                }
                
                # Execute aggregation query
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=auth_query,
                    timeout="30s"
                )
                
                # Parse results
                aggs = response.get("aggregations", {})
                total_attacks = response["hits"]["total"]["value"]
                
                # Extract data
                attacking_ips = [(b["key"], b["doc_count"]) for b in aggs.get("attacking_ips", {}).get("buckets", [])]
                targeted_devices = [(b["key"], b["doc_count"]) for b in aggs.get("targeted_devices", {}).get("buckets", [])]
                failed_users = [(b["key"], b["doc_count"]) for b in aggs.get("failed_users", {}).get("buckets", [])]
                attack_methods = [(b["key"], b["doc_count"]) for b in aggs.get("attack_methods", {}).get("buckets", [])]
                
                timeline_buckets = aggs.get("attack_timeline", {}).get("buckets", [])
                attack_timeline = [(b["key_as_string"], b["doc_count"]) for b in timeline_buckets]
                
                sample_hits = aggs.get("sample_attacks", {}).get("hits", {}).get("hits", [])
                sample_attacks = [
                    {
                        "timestamp": h["_source"]["timestamp"],
                        "device": h["_source"].get("hostname", "unknown"),
                        "program": h["_source"].get("program", "unknown"),
                        "message": h["_source"]["message"]
                    }
                    for h in sample_hits
                ]
                
                # Generate human-readable summary
                summary = _generate_failed_auth_summary(
                    params.device,
                    params.hours,
                    total_attacks,
                    attacking_ips,
                    targeted_devices,
                    failed_users,
                    attack_methods,
                    attack_timeline,
                    sample_attacks
                )
                
                log_mcp_response("failed_auth_summary", True, {
                    "device": params.device,
                    "total_attacks": total_attacks,
                    "top_attacker_count": len(attacking_ips)
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\n\nFailed to connect to Elasticsearch: {e.message}\n\nDevice: {device or 'ALL'}"
            log_mcp_response("failed_auth_summary", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\n\nElasticsearch query failed: {e.message}\n\nDevice: {device or 'ALL'}"
            log_mcp_response("failed_auth_summary", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\n\nUnexpected error occurred: {str(e)}\n\nDevice: {device or 'ALL'}\nPlease check server logs for details."
            logger.error("Error in failed_auth_summary", extra={
                "error": str(e),
                "device": device,
                "hours": hours
            }, exc_info=True)
            log_mcp_response("failed_auth_summary", False, error=error_msg)
            return error_msg
    
    @mcp.tool()
    async def suspicious_activity(
        device: Optional[str] = None,
        hours: int = 24,
        sensitivity: str = "medium"
    ) -> str:
        """
        Detect suspicious activity patterns beyond authentication failures.
        
        Analyzes system logs for unusual command executions, off-hours activity,
        privilege escalations, network anomalies, and other potentially malicious behavior.
        
        Args:
            device: Specific device to analyze (optional, analyzes all devices if not specified)
            hours: Number of hours to analyze (1-168, default: 24)
            sensitivity: Detection sensitivity level - low, medium, high (default: medium)
            
        Returns:
            Formatted markdown text containing:
            - Unusual command execution patterns
            - Off-hours activity detection
            - Privilege escalation attempts
            - Network anomalies and suspicious connections
            - File system manipulation attempts
            - Service anomalies and configuration changes
            - Risk assessment and security recommendations
        """
        request_args = {
            "device": device,
            "hours": hours,
            "sensitivity": sensitivity
        }
        log_mcp_request("suspicious_activity", request_args)
        
        try:
            # Validate parameters
            params = SuspiciousActivityParameters(device=device, hours=hours, sensitivity=sensitivity)
            
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=params.hours)
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Base query structure
                base_query = {
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
                
                # Add device filter if specified
                if params.device:
                    base_query["query"]["bool"]["filter"].append({
                        "term": {"hostname.keyword": params.device}
                    })
                
                # Set sensitivity thresholds
                if params.sensitivity == "high":
                    min_occurrences = 1
                    time_threshold_hour = 2  # 2 AM - 6 AM is off-hours
                    max_off_hours_hour = 6
                elif params.sensitivity == "low":
                    min_occurrences = 10
                    time_threshold_hour = 0  # Midnight - 5 AM is off-hours
                    max_off_hours_hour = 5
                else:  # medium
                    min_occurrences = 3
                    time_threshold_hour = 1  # 1 AM - 6 AM is off-hours  
                    max_off_hours_hour = 6
                
                # Build comprehensive suspicious activity query
                suspicious_query = {
                    **base_query,
                    "size": 0,
                    "aggs": {
                        # Unusual commands detection
                        "unusual_commands": {
                            "filter": {
                                "query_string": {
                                    "query": "(rm\\ -rf OR chmod\\ 777 OR nc\\ OR netcat OR wget OR curl OR base64 OR python\\ -c OR perl\\ -e OR bash\\ -c OR sh\\ -c) AND NOT (update OR install OR package)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "command_patterns": {
                                    "terms": {
                                        "script": {
                                            "source": """
                                                String msg = doc['message.keyword'].value;
                                                if (msg.contains('rm -rf')) return 'rm -rf (dangerous deletion)';
                                                if (msg.contains('chmod 777')) return 'chmod 777 (insecure permissions)';
                                                if (msg.contains('nc ') || msg.contains('netcat')) return 'netcat (network tool)';
                                                if (msg.contains('wget') || msg.contains('curl')) return 'download tool (wget/curl)';
                                                if (msg.contains('base64')) return 'base64 encoding';
                                                if (msg.contains('python -c')) return 'python one-liner';
                                                if (msg.contains('bash -c') || msg.contains('sh -c')) return 'shell command execution';
                                                return 'other suspicious command';
                                            """,
                                            "lang": "painless"
                                        },
                                        "size": 10,
                                        "min_doc_count": min_occurrences
                                    }
                                }
                            }
                        },
                        
                        # Off-hours activity (1 AM - 6 AM UTC)
                        "off_hours_activity": {
                            "filter": {
                                "script": {
                                    "script": {
                                        "source": f"""
                                            def hour = doc['timestamp'].value.getHour();
                                            return hour >= {time_threshold_hour} && hour <= {max_off_hours_hour};
                                        """,
                                        "lang": "painless"
                                    }
                                }
                            },
                            "aggs": {
                                "programs": {
                                    "terms": {
                                        "field": "program.keyword",
                                        "size": 10
                                    }
                                },
                                "sample_events": {
                                    "top_hits": {
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                        "size": 5,
                                        "_source": ["timestamp", "hostname", "program", "message"]
                                    }
                                }
                            }
                        },
                        
                        # Privilege escalation attempts
                        "privilege_escalations": {
                            "filter": {
                                "query_string": {
                                    "query": "(sudo OR su\\ - OR authentication\\ failure OR pam_unix OR setuid OR setgid) AND NOT (session\\ opened OR session\\ closed)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "escalation_events": {
                                    "top_hits": {
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                        "size": 10,
                                        "_source": ["timestamp", "hostname", "program", "message"]
                                    }
                                }
                            }
                        },
                        
                        # Network anomalies (unusual ports, connections)
                        "network_anomalies": {
                            "filter": {
                                "query_string": {
                                    "query": "(port OR connection OR bind OR listen OR socket) AND (unusual OR failed OR denied OR refused)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "network_patterns": {
                                    "terms": {
                                        "script": {
                                            "source": """
                                                String msg = doc['message.keyword'].value.toLowerCase();
                                                if (msg.contains('connection refused')) return 'connection_refused';
                                                if (msg.contains('port') && msg.contains('denied')) return 'port_denied';
                                                if (msg.contains('bind') && msg.contains('failed')) return 'bind_failed';
                                                if (msg.contains('unusual') && msg.contains('connection')) return 'unusual_connection';
                                                return 'other_network_anomaly';
                                            """,
                                            "lang": "painless"
                                        },
                                        "size": 10
                                    }
                                }
                            }
                        },
                        
                        # File system suspicious activity
                        "file_system_activity": {
                            "filter": {
                                "query_string": {
                                    "query": "(etc OR passwd OR shadow OR hosts OR cron OR init.d OR systemd) AND (modified OR changed OR created OR deleted)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "fs_patterns": {
                                    "terms": {
                                        "script": {
                                            "source": """
                                                String msg = doc['message.keyword'].value.toLowerCase();
                                                if (msg.contains('/etc/passwd')) return '/etc/passwd manipulation';
                                                if (msg.contains('/etc/shadow')) return '/etc/shadow manipulation';
                                                if (msg.contains('/etc/hosts')) return '/etc/hosts manipulation';
                                                if (msg.contains('cron')) return 'cron job manipulation';
                                                if (msg.contains('/etc/')) return 'system config changes';
                                                return 'other filesystem activity';
                                            """,
                                            "lang": "painless"
                                        },
                                        "size": 10
                                    }
                                }
                            }
                        },
                        
                        # Service anomalies
                        "service_anomalies": {
                            "filter": {
                                "query_string": {
                                    "query": "(systemd OR service OR daemon) AND (failed OR error OR stopped OR crashed OR restart)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "service_patterns": {
                                    "terms": {
                                        "field": "program.keyword",
                                        "size": 10
                                    }
                                }
                            }
                        },
                        
                        # Sample suspicious events
                        "sample_suspicious": {
                            "filter": {
                                "query_string": {
                                    "query": "(error OR warning OR failed OR denied OR suspicious OR unusual OR unauthorized OR attack OR intrusion OR malware OR virus)",
                                    "default_field": "message"
                                }
                            },
                            "aggs": {
                                "sample_events": {
                                    "top_hits": {
                                        "sort": [{"timestamp": {"order": "desc"}}],
                                        "size": 15,
                                        "_source": ["timestamp", "hostname", "program", "message", "severity"]
                                    }
                                }
                            }
                        }
                    }
                }
                
                # Execute the query
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=suspicious_query,
                    timeout="60s"  # Longer timeout for complex aggregations
                )
                
                # Parse results
                aggs = response.get("aggregations", {})
                
                # Extract unusual commands
                unusual_commands = []
                cmd_buckets = aggs.get("unusual_commands", {}).get("command_patterns", {}).get("buckets", [])
                for bucket in cmd_buckets:
                    risk_level = "high" if any(danger in bucket["key"] for danger in ["rm -rf", "chmod 777"]) else "medium"
                    unusual_commands.append({
                        "command": bucket["key"],
                        "count": bucket["doc_count"],
                        "risk_level": risk_level
                    })
                
                # Extract off-hours activity
                off_hours_activity = []
                off_hours_programs = aggs.get("off_hours_activity", {}).get("programs", {}).get("buckets", [])
                off_hours_samples = aggs.get("off_hours_activity", {}).get("sample_events", {}).get("hits", {}).get("hits", [])
                
                for bucket in off_hours_programs[:5]:
                    # Find sample for this program
                    sample = next((h["_source"] for h in off_hours_samples if h["_source"].get("program") == bucket["key"]), {})
                    off_hours_activity.append({
                        "program": bucket["key"],
                        "count": bucket["doc_count"],
                        "timestamp": sample.get("timestamp", "unknown")
                    })
                
                # Extract privilege escalations
                privilege_escalations = []
                priv_hits = aggs.get("privilege_escalations", {}).get("escalation_events", {}).get("hits", {}).get("hits", [])
                for hit in priv_hits:
                    src = hit["_source"]
                    privilege_escalations.append({
                        "timestamp": src["timestamp"],
                        "device": src.get("hostname", "unknown"),
                        "program": src.get("program", "unknown"),
                        "message": src["message"],
                        "user": "unknown"  # Could extract from message with regex if needed
                    })
                
                # Extract network anomalies
                network_anomalies = []
                net_buckets = aggs.get("network_anomalies", {}).get("network_patterns", {}).get("buckets", [])
                for bucket in net_buckets:
                    anomaly_type = bucket["key"].replace("_", " ").title()
                    description = ""
                    if "refused" in bucket["key"]:
                        description = "Connections being refused - potential service issues or blocking"
                    elif "denied" in bucket["key"]:
                        description = "Port access denied - potential firewall or security policy"
                        
                    network_anomalies.append({
                        "type": anomaly_type,
                        "count": bucket["doc_count"],
                        "description": description
                    })
                
                # Extract file system activity
                file_system_activity = []
                fs_buckets = aggs.get("file_system_activity", {}).get("fs_patterns", {}).get("buckets", [])
                for bucket in fs_buckets:
                    fs_type = bucket["key"]
                    path = "system files" if "/etc/" in fs_type else fs_type
                    file_system_activity.append({
                        "type": fs_type,
                        "path": path,
                        "count": bucket["doc_count"]
                    })
                
                # Extract service anomalies  
                service_anomalies = []
                service_buckets = aggs.get("service_anomalies", {}).get("service_patterns", {}).get("buckets", [])
                for bucket in service_buckets:
                    service_anomalies.append({
                        "service": bucket["key"],
                        "count": bucket["doc_count"],
                        "anomaly": "service failures or errors"
                    })
                
                # Extract sample events
                sample_events = []
                sample_hits = aggs.get("sample_suspicious", {}).get("sample_events", {}).get("hits", {}).get("hits", [])
                for hit in sample_hits:
                    src = hit["_source"]
                    # Assess risk level based on message content
                    msg_lower = src["message"].lower()
                    risk = "high" if any(keyword in msg_lower for keyword in ["attack", "intrusion", "malware", "unauthorized"]) else "medium"
                    
                    sample_events.append({
                        "timestamp": src["timestamp"],
                        "device": src.get("hostname", "unknown"),
                        "program": src.get("program", "unknown"),
                        "message": src["message"],
                        "risk": risk
                    })
                
                # Calculate total suspicious events
                total_suspicious = (len(unusual_commands) + len(off_hours_activity) + 
                                 len(privilege_escalations) + len(network_anomalies) + 
                                 len(file_system_activity) + len(service_anomalies))
                
                # Generate human-readable summary
                summary = _generate_suspicious_activity_summary(
                    params.device,
                    params.hours,
                    total_suspicious,
                    unusual_commands,
                    off_hours_activity,
                    privilege_escalations,
                    network_anomalies,
                    file_system_activity,
                    service_anomalies,
                    sample_events,
                    params.sensitivity
                )
                
                log_mcp_response("suspicious_activity", True, {
                    "device": params.device,
                    "total_suspicious": total_suspicious,
                    "sensitivity": params.sensitivity
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("suspicious_activity", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("suspicious_activity", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nDevice: {device or 'ALL'}\\nPlease check server logs for details."
            logger.error("Error in suspicious_activity", extra={
                "error": str(e),
                "device": device,
                "hours": hours,
                "sensitivity": sensitivity
            }, exc_info=True)
            log_mcp_response("suspicious_activity", False, error=error_msg)
            return error_msg
    
    @mcp.tool()
    async def auth_timeline(
        device: Optional[str] = None,
        hours: int = 24,
        interval: str = "1h"
    ) -> str:
        """
        Create a timeline visualization of authentication events.
        
        Analyzes authentication activity over time to identify patterns,
        peak periods, and potential security incidents with trend analysis.
        
        Args:
            device: Specific device to analyze (optional, analyzes all devices if not specified)
            hours: Number of hours to analyze (1-168, default: 24)
            interval: Time interval for timeline buckets (1m, 5m, 15m, 30m, 1h, 2h, 4h, 6h, 12h, 1d)
            
        Returns:
            Formatted markdown text containing:
            - Authentication event timeline with visual representation
            - Peak activity period identification
            - Authentication pattern analysis (success vs failure rates)
            - Trend analysis and anomaly detection
            - Security insights and recommendations
        """
        request_args = {
            "device": device,
            "hours": hours,
            "interval": interval
        }
        log_mcp_request("auth_timeline", request_args)
        
        try:
            # Validate parameters
            params = AuthTimelineParameters(device=device, hours=hours, interval=interval)
            
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=params.hours)
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Build authentication timeline query
                timeline_query = {
                    "query": {
                        "bool": {
                            "must": [
                                {
                                    "query_string": {
                                        "query": "(auth OR authentication OR login OR ssh OR sshd OR Failed OR Accepted OR session)",
                                        "default_field": "message"
                                    }
                                }
                            ],
                            "filter": [
                                {
                                    "range": {
                                        "timestamp": {
                                            "gte": start_time.isoformat(),
                                            "lte": end_time.isoformat()
                                        }
                                    }
                                }
                            ]
                        }
                    },
                    "size": 0,
                    "aggs": {
                        # Timeline aggregation
                        "auth_timeline": {
                            "date_histogram": {
                                "field": "timestamp",
                                "calendar_interval": params.interval,
                                "min_doc_count": 0,
                                "extended_bounds": {
                                    "min": start_time.isoformat(),
                                    "max": end_time.isoformat()
                                }
                            }
                        },
                        
                        # Authentication patterns
                        "auth_patterns": {
                            "terms": {
                                "script": {
                                    "source": """
                                        String msg = doc['message.keyword'].value;
                                        if (msg.contains('Failed password') || msg.contains('authentication failure')) return 'Failed Authentication';
                                        if (msg.contains('Accepted password') || msg.contains('session opened')) return 'Successful Authentication';
                                        if (msg.contains('session closed') || msg.contains('Disconnected')) return 'Session Termination';
                                        if (msg.contains('Invalid user')) return 'Invalid User Attempt';
                                        if (msg.contains('Connection closed')) return 'Connection Closed';
                                        return 'Other Auth Event';
                                    """,
                                    "lang": "painless"
                                },
                                "size": 10
                            }
                        }
                    }
                }
                
                # Add device filter if specified
                if params.device:
                    timeline_query["query"]["bool"]["filter"].append({
                        "term": {"hostname.keyword": params.device}
                    })
                
                # Execute the query
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=timeline_query,
                    timeout="30s"
                )
                
                # Parse timeline results
                aggs = response.get("aggregations", {})
                total_auth_events = response["hits"]["total"]["value"]
                
                # Extract timeline data
                timeline_buckets = aggs.get("auth_timeline", {}).get("buckets", [])
                timeline_data = [
                    {
                        "timestamp": bucket["key_as_string"],
                        "count": bucket["doc_count"]
                    }
                    for bucket in timeline_buckets
                ]
                
                # Extract authentication patterns
                pattern_buckets = aggs.get("auth_patterns", {}).get("buckets", [])
                auth_patterns = [
                    {
                        "type": bucket["key"],
                        "count": bucket["doc_count"]
                    }
                    for bucket in pattern_buckets
                ]
                
                # Identify peak periods (periods with >150% of average activity)
                non_zero_periods = [p for p in timeline_data if p["count"] > 0]
                if non_zero_periods:
                    avg_activity = sum(p["count"] for p in non_zero_periods) / len(non_zero_periods)
                    peak_periods = [p for p in timeline_data if p["count"] > avg_activity * 1.5]
                    peak_periods.sort(key=lambda x: x["count"], reverse=True)
                else:
                    peak_periods = []
                
                # Generate summary
                summary = _generate_auth_timeline_summary(
                    params.device,
                    params.hours,
                    params.interval,
                    timeline_data,
                    auth_patterns,
                    peak_periods,
                    total_auth_events
                )
                
                log_mcp_response("auth_timeline", True, {
                    "device": params.device,
                    "total_auth_events": total_auth_events,
                    "peak_periods": len(peak_periods)
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("auth_timeline", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("auth_timeline", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nDevice: {device or 'ALL'}\\nPlease check server logs for details."
            logger.error("Error in auth_timeline", extra={
                "error": str(e),
                "device": device,
                "hours": hours,
                "interval": interval
            }, exc_info=True)
            log_mcp_response("auth_timeline", False, error=error_msg)
            return error_msg

    @mcp.tool()
    async def ip_reputation(
        ip_address: Optional[str] = None,
        hours: int = 24,
        min_attempts: int = 5,
        top_ips: int = 20
    ) -> str:
        """
        Analyze IP reputation and activity patterns for threat assessment.

        Provides comprehensive analysis of IP addresses interacting with your systems,
        including geographic distribution, attack patterns, and reputation scoring.

        Args:
            ip_address: Specific IP to analyze (optional, analyzes top IPs if not specified)
            hours: Number of hours to analyze (1-168, default: 24)
            min_attempts: Minimum attempts to consider an IP significant (default: 5)
            top_ips: Number of top IPs to analyze if no specific IP provided (default: 20)
            
        Returns:
            Formatted markdown text containing:
            - IP reputation analysis and threat scoring
            - Geographic distribution and country analysis
            - Attack pattern identification (brute force, scanning, etc.)
            - Activity timeline and frequency analysis
            - Comparison with known threat intelligence
            - Targeted services and accounts analysis
            - Recommendation for blocking/monitoring
            - Sample log entries showing attack methods
        """
        request_args = {
            "ip_address": ip_address,
            "hours": hours,
            "min_attempts": min_attempts,
            "top_ips": top_ips
        }
        log_mcp_request("ip_reputation", request_args)
        
        try:
            # Validate parameters
            params = IpReputationParameters(
                ip_address=ip_address,
                hours=hours,
                min_attempts=min_attempts,
                top_ips=top_ips
            )
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Calculate time range
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=params.hours)
                
                    # Build base query
                base_query = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            }
                        ],
                        "should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "invalid user"}},
                            {"match_phrase": {"message": "Connection closed"}},
                            {"match_phrase": {"message": "refused connect"}},
                            {"match_phrase": {"message": "port scan"}},
                            {"match_phrase": {"message": "blocked"}},
                            {"wildcard": {"message": "*[0-9].[0-9].[0-9].[0-9]*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
                
                # If specific IP provided, filter for it
                if params.ip_address:
                    base_query["bool"]["must"].append({
                        "wildcard": {"message": f"*{params.ip_address}*"}
                    })
                
                # Build aggregation for IP analysis
                agg_query = {
                "query": base_query,
                "size": 0,
                "aggs": {
                    "ip_analysis": {
                        "terms": {
                            "script": {
                                "source": r"""
                                    String msg = doc['message.keyword'].value;
                                    Matcher matcher = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.matcher(msg);
                                    return matcher.find() ? matcher.group(1) : 'unknown';
                                """
                            },
                            "size": top_ips,
                            "min_doc_count": min_attempts
                        },
                        "aggs": {
                            "activity_timeline": {
                                "date_histogram": {
                                    "field": "timestamp",
                                    "fixed_interval": "1h",
                                    "min_doc_count": 0
                                }
                            },
                            "attack_types": {
                                "filters": {
                                    "filters": {
                                        "failed_auth": {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"message": "Failed password"}},
                                                    {"match_phrase": {"message": "authentication failure"}},
                                                    {"match_phrase": {"message": "invalid user"}}
                                                ]
                                            }
                                        },
                                        "connection_issues": {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"message": "Connection closed"}},
                                                    {"match_phrase": {"message": "refused connect"}},
                                                    {"match_phrase": {"message": "timeout"}}
                                                ]
                                            }
                                        },
                                        "scanning": {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"message": "port scan"}},
                                                    {"match_phrase": {"message": "probe"}},
                                                    {"match_phrase": {"message": "blocked"}}
                                                ]
                                            }
                                        }
                                    }
                                }
                            },
                            "targeted_accounts": {
                                "terms": {
                                    "script": {
                                        "source": """
                                            String msg = doc['message.keyword'].value.toLowerCase();
                                            if (msg.contains('user ')) {
                                                int start = msg.indexOf('user ') + 5;
                                                int end = msg.indexOf(' ', start);
                                                if (end == -1) end = msg.length();
                                                return msg.substring(start, Math.min(end, start + 20));
                                            }
                                            return 'unknown';
                                        """
                                    },
                                    "size": 10
                                }
                            },
                            "devices_targeted": {
                                "terms": {
                                    "field": "device.keyword",
                                    "size": 10
                                }
                            },
                            "sample_attacks": {
                                "top_hits": {
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "size": 5,
                                    "_source": ["timestamp", "device", "message"]
                                }
                            }
                        }
                    },
                    "total_unique_ips": {
                        "cardinality": {
                            "script": {
                                "source": r"""
                                    String msg = doc['message.keyword'].value;
                                    Matcher matcher = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.matcher(msg);
                                    return matcher.find() ? matcher.group(1) : 'unknown';
                                """
                            }
                        }
                    }
                }
                    }
            
                logger.debug(f"Executing IP reputation query: {agg_query}")
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=agg_query,
                    timeout="30s"
                )
                
                # Extract data from response
                aggs = response.get("aggregations", {})
                ip_buckets = aggs.get("ip_analysis", {}).get("buckets", [])
                total_unique_ips = aggs.get("total_unique_ips", {}).get("value", 0)
                
                # Process IP data
                ip_data = []
                for bucket in ip_buckets:
                    ip = bucket["key"]
                    if ip == "unknown":
                        continue
                        
                    total_attempts = bucket["doc_count"]
                    attack_types = bucket.get("attack_types", {}).get("buckets", {})
                    targeted_accounts = bucket.get("targeted_accounts", {}).get("buckets", [])
                    devices_targeted = bucket.get("devices_targeted", {}).get("buckets", [])
                    sample_attacks = bucket.get("sample_attacks", {}).get("hits", {}).get("hits", [])
                    
                    ip_data.append({
                        "ip": ip,
                        "total_attempts": total_attempts,
                        "failed_auth": attack_types.get("failed_auth", {}).get("doc_count", 0),
                        "connection_issues": attack_types.get("connection_issues", {}).get("doc_count", 0),
                        "scanning": attack_types.get("scanning", {}).get("doc_count", 0),
                        "targeted_accounts": [acc["key"] for acc in targeted_accounts[:5] if acc["key"] != "unknown"],
                        "devices_targeted": [dev["key"] for dev in devices_targeted[:5]],
                        "sample_attacks": [
                            {
                                "timestamp": hit["_source"]["timestamp"],
                                "device": hit["_source"]["device"],
                                "message": hit["_source"]["message"][:100]
                            }
                            for hit in sample_attacks
                        ]
                    })
                
                # Generate summary
                summary = _generate_ip_reputation_summary(
                    ip_address,
                    hours,
                    min_attempts,
                    ip_data,
                    total_unique_ips,
                    response["hits"]["total"]["value"] if "hits" in response else 0
                )
                
                log_mcp_response("ip_reputation", True, {
                    "analyzed_ips": len(ip_data),
                    "total_unique_ips": total_unique_ips,
                    "target_ip": ip_address or "all",
                    "total_events": response["hits"]["total"]["value"] if "hits" in response else 0
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nIP: {ip_address or 'ALL'}"
            log_mcp_response("ip_reputation", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nIP: {ip_address or 'ALL'}"
            log_mcp_response("ip_reputation", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nIP: {ip_address or 'ALL'}\\nPlease check server logs for details."
            logger.error("Error in ip_reputation", extra={
                "error": str(e),
                "ip_address": ip_address,
                "hours": hours,
                "min_attempts": min_attempts,
                "top_ips": top_ips
            }, exc_info=True)
            log_mcp_response("ip_reputation", False, error=error_msg)
            return error_msg

    @mcp.tool()
    async def error_analysis(
        device: Optional[str] = None,
        hours: int = 24,
        severity: Optional[str] = None,
        top_errors: int = 15
    ) -> str:
        """
        Analyze system errors and provide troubleshooting insights.

        Identifies error patterns, affected services, resolution recommendations,
        and provides diagnostic context for system issues.

        Args:
            device: Specific device to analyze (optional, analyzes all devices if not specified)
            hours: Number of hours to analyze (1-168, default: 24)
            severity: Filter by error severity: "error", "critical", "warning" (optional)
            top_errors: Number of top error patterns to analyze (default: 15)
            
        Returns:
            Formatted markdown text containing:
            - Error overview and severity breakdown
            - Top error patterns and frequency analysis
            - Affected services and system components
            - Error timeline and peak period identification
            - Resolution recommendations and troubleshooting steps
            - Sample error messages with context
            - System health assessment
        """
        request_args = {
            "device": device,
            "hours": hours,
            "severity": severity,
            "top_errors": top_errors
        }
        log_mcp_request("error_analysis", request_args)
        
        try:
            if not (1 <= hours <= 168):
                error_msg = f"❌ **Invalid hours parameter:** {hours}\\n\\nHours must be between 1 and 168 (1 week)."
                log_mcp_response("error_analysis", False, error=error_msg)
                return error_msg
            
            if severity and severity.lower() not in ["error", "critical", "warning"]:
                error_msg = f"❌ **Invalid severity parameter:** {severity}\\n\\nSeverity must be 'error', 'critical', or 'warning'."
                log_mcp_response("error_analysis", False, error=error_msg)
                return error_msg
                
            if not (1 <= top_errors <= 50):
                error_msg = f"❌ **Invalid top_errors parameter:** {top_errors}\\n\\ntop_errors must be between 1 and 50."
                log_mcp_response("error_analysis", False, error=error_msg)
                return error_msg
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Calculate time range
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)
                
                # Build base query for error events
                base_query = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lte": end_time.isoformat()
                                    }
                                }
                            }
                        ],
                        "should": [
                            {"match_phrase": {"message": "error"}},
                            {"match_phrase": {"message": "failed"}},
                            {"match_phrase": {"message": "critical"}},
                            {"match_phrase": {"message": "exception"}},
                            {"match_phrase": {"message": "warning"}},
                            {"match_phrase": {"message": "fault"}},
                            {"match_phrase": {"message": "timeout"}},
                            {"match_phrase": {"message": "denied"}},
                            {"match_phrase": {"message": "refused"}},
                            {"match_phrase": {"message": "unable"}},
                            {"match_phrase": {"message": "cannot"}}
                        ],
                        "minimum_should_match": 1,
                        "filter": []
                    }
                }
                
                # Add device filter if specified
                if device:
                    base_query["bool"]["filter"].append({
                        "term": {"device.keyword": device}
                    })
                
                # Add severity filter if specified
                if severity:
                    severity_terms = {
                        "error": ["error", "err", "failed", "failure"],
                        "critical": ["critical", "fatal", "severe", "emergency"],
                        "warning": ["warning", "warn", "caution"]
                    }
                    severity_query = {
                        "bool": {
                            "should": [
                                {"match_phrase": {"message": term}}
                                for term in severity_terms.get(severity.lower(), [])
                            ],
                            "minimum_should_match": 1
                        }
                    }
                    base_query["bool"]["must"].append(severity_query)
                
                # Build aggregation for error analysis
                agg_query = {
                "query": base_query,
                "size": 0,
                "aggs": {
                    "error_patterns": {
                        "terms": {
                            "script": {
                                "source": """
                                    String msg = doc['message.keyword'].value.toLowerCase();
                                    
                                    // Extract error patterns
                                    if (msg.contains('failed to')) {
                                        int start = msg.indexOf('failed to');
                                        int end = Math.min(start + 50, msg.length());
                                        return 'Failed to: ' + msg.substring(start + 10, end);
                                    }
                                    
                                    if (msg.contains('error:') || msg.contains('error ')) {
                                        int start = msg.contains('error:') ? msg.indexOf('error:') : msg.indexOf('error ');
                                        int end = Math.min(start + 60, msg.length());
                                        return 'Error: ' + msg.substring(start + 6, end);
                                    }
                                    
                                    if (msg.contains('exception')) {
                                        int start = msg.indexOf('exception');
                                        int end = Math.min(start + 50, msg.length());
                                        return 'Exception: ' + msg.substring(start, end);
                                    }
                                    
                                    if (msg.contains('timeout')) {
                                        return 'Timeout errors';
                                    }
                                    
                                    if (msg.contains('denied') || msg.contains('refused')) {
                                        return 'Access denied/refused';
                                    }
                                    
                                    if (msg.contains('connection')) {
                                        return 'Connection issues';
                                    }
                                    
                                    // Generic error categorization
                                    String[] words = msg.split(' ');
                                    for (String word : words) {
                                        if (word.contains('error') || word.contains('failed') || word.contains('warning')) {
                                            return 'General: ' + word;
                                        }
                                    }
                                    
                                    return 'Uncategorized error';
                                """
                            },
                            "size": top_errors
                        },
                        "aggs": {
                            "sample_messages": {
                                "top_hits": {
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "size": 2,
                                    "_source": ["timestamp", "device", "message"]
                                }
                            }
                        }
                    },
                    "affected_services": {
                        "terms": {
                            "script": {
                                "source": """
                                    String msg = doc['message.keyword'].value.toLowerCase();
                                    
                                    // Extract service names from common log patterns
                                    if (msg.contains('systemd')) return 'systemd';
                                    if (msg.contains('kernel')) return 'kernel';
                                    if (msg.contains('sshd')) return 'sshd';
                                    if (msg.contains('cron')) return 'cron';
                                    if (msg.contains('apache') || msg.contains('httpd')) return 'apache/httpd';
                                    if (msg.contains('nginx')) return 'nginx';
                                    if (msg.contains('docker')) return 'docker';
                                    if (msg.contains('mysql') || msg.contains('mariadb')) return 'mysql/mariadb';
                                    if (msg.contains('postgresql') || msg.contains('postgres')) return 'postgresql';
                                    if (msg.contains('network')) return 'network';
                                    if (msg.contains('disk') || msg.contains('filesystem')) return 'filesystem';
                                    if (msg.contains('memory') || msg.contains('oom')) return 'memory';
                                    
                                    // Extract service names from brackets or colons
                                    String[] parts = msg.split('[\\\\[\\\\]:]+');
                                    if (parts.length > 1) {
                                        String service = parts[1].trim();
                                        if (service.length() > 0 && service.length() < 20) {
                                            return service;
                                        }
                                    }
                                    
                                    return 'unknown';
                                """
                            },
                            "size": 15
                        }
                    },
                    "error_timeline": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": start_time.isoformat(),
                                "max": end_time.isoformat()
                            }
                        }
                    },
                    "device_breakdown": {
                        "terms": {
                            "field": "device.keyword",
                            "size": 10
                        }
                    },
                    "sample_errors": {
                        "top_hits": {
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "size": 8,
                            "_source": ["timestamp", "device", "message"]
                        }
                    }
                }
                    }
            
                logger.debug(f"Executing error analysis query: {agg_query}")
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=agg_query,
                    timeout="30s"
                )
                
                # Extract data from response
                aggs = response.get("aggregations", {})
                error_patterns = aggs.get("error_patterns", {}).get("buckets", [])
                affected_services = aggs.get("affected_services", {}).get("buckets", [])
                error_timeline = aggs.get("error_timeline", {}).get("buckets", [])
                device_breakdown = aggs.get("device_breakdown", {}).get("buckets", [])
                sample_errors = aggs.get("sample_errors", {}).get("hits", {}).get("hits", [])
                total_errors = response.get("hits", {}).get("total", {}).get("value", 0)
                
                # Process error patterns with samples
                processed_patterns = []
                for pattern in error_patterns:
                    sample_msgs = pattern.get("sample_messages", {}).get("hits", {}).get("hits", [])
                    processed_patterns.append({
                        "type": pattern["key"],
                        "count": pattern["doc_count"],
                        "sample_message": sample_msgs[0]["_source"]["message"] if sample_msgs else ""
                    })
                
                # Process affected services
                processed_services = [
                    {"service": service["key"], "count": service["doc_count"]}
                    for service in affected_services
                    if service["key"] != "unknown"
                ]
                
                # Process timeline for peaks
                processed_timeline = [
                    {"timestamp": bucket["key_as_string"], "count": bucket["doc_count"]}
                    for bucket in error_timeline
                ]
                
                # Generate summary
                summary = _generate_error_analysis_summary(
                    device,
                    hours,
                    severity,
                    processed_patterns,
                    processed_timeline,
                    processed_services,
                    total_errors
                )
                
                log_mcp_response("error_analysis", True, {
                    "total_errors": total_errors,
                    "error_patterns": len(processed_patterns),
                    "affected_services": len(processed_services),
                    "device": device or "all"
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("error_analysis", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nDevice: {device or 'ALL'}"
            log_mcp_response("error_analysis", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nDevice: {device or 'ALL'}\\nPlease check server logs for details."
            logger.error("Error in error_analysis", extra={
                "error": str(e),
                "device": device,
                "hours": hours,
                "severity": severity,
                "top_errors": top_errors
            }, exc_info=True)
            log_mcp_response("error_analysis", False, error=error_msg)
            return error_msg

    @mcp.tool()
    async def search_by_timerange(
        start_time: str,
        end_time: str,
        device: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 100
    ) -> str:
        """
        Search logs within a specific time range with optional filtering.

        Provides focused log analysis for specific time periods with search capabilities,
        useful for investigating incidents or analyzing activity during specific timeframes.

        Args:
            start_time: Start of time range (ISO format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS)
            end_time: End of time range (ISO format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS)
            device: Specific device to search (optional, searches all devices if not specified)
            query: Text search query to match against log messages (optional)
            limit: Maximum number of log entries to return (1-1000, default: 100)
            
        Returns:
            Formatted markdown text containing:
            - Time range summary and search parameters
            - Total matching entries and time span analysis
            - Device activity breakdown for the period
            - Key events and notable activity patterns
            - Chronological log entries with timestamps
            - Activity frequency analysis
            - Search performance metrics
        """
        request_args = {
            "start_time": start_time,
            "end_time": end_time,
            "device": device,
            "query": query,
            "limit": limit
        }
        log_mcp_request("search_by_timerange", request_args)
        
        try:
            # Validate limit
            if not (1 <= limit <= 1000):
                error_msg = f"❌ **Invalid limit parameter:** {limit}\\n\\nLimit must be between 1 and 1000."
                log_mcp_response("search_by_timerange", False, error=error_msg)
                return error_msg
            
            # Parse and validate time strings
            def parse_time_string(time_str: str) -> datetime:
                # Handle different time formats
                formats = [
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M",
                    "%Y-%m-%d %H:%M",
                    "%Y-%m-%d"
                ]
                
                for fmt in formats:
                    try:
                        return datetime.strptime(time_str, fmt)
                    except ValueError:
                        continue
                
                # Try parsing ISO format with timezone
                try:
                    from dateutil import parser
                    return parser.isoparse(time_str).replace(tzinfo=None)
                except:
                    pass
                
                raise ValueError(f"Unable to parse time string: {time_str}")
            
            try:
                parsed_start = parse_time_string(start_time)
                parsed_end = parse_time_string(end_time)
            except ValueError as e:
                error_msg = f"❌ **Invalid time format:** {str(e)}\\n\\nUse ISO format: YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS"
                log_mcp_response("search_by_timerange", False, error=error_msg)
                return error_msg
            
            # Validate time range
            if parsed_start >= parsed_end:
                error_msg = f"❌ **Invalid time range:** Start time must be before end time.\\n\\nStart: {start_time}\\nEnd: {end_time}"
                log_mcp_response("search_by_timerange", False, error=error_msg)
                return error_msg
            
            # Check for reasonable time range (not more than 30 days)
            time_diff = parsed_end - parsed_start
            if time_diff.days > 30:
                error_msg = f"❌ **Time range too large:** Maximum 30 days allowed.\\n\\nRequested: {time_diff.days} days"
                log_mcp_response("search_by_timerange", False, error=error_msg)
                return error_msg
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Build base query
                base_query = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": parsed_start.isoformat(),
                                        "lte": parsed_end.isoformat()
                                    }
                                }
                            }
                        ],
                        "filter": []
                    }
                }
                
                # Add device filter if specified
                if device:
                    base_query["bool"]["filter"].append({
                        "term": {"device.keyword": device}
                    })
                
                # Add text query if specified
                if query:
                    base_query["bool"]["must"].append({
                        "bool": {
                            "should": [
                                {"match_phrase": {"message": query}},
                                {"wildcard": {"message": f"*{query}*"}},
                                {"match": {"message": query}}
                            ],
                            "minimum_should_match": 1
                        }
                    })
                
                # Build search query with aggregations
                search_query = {
                "query": base_query,
                "size": limit,
                "sort": [{"timestamp": {"order": "desc"}}],
                "_source": ["timestamp", "device", "message", "level"],
                "aggs": {
                    "device_breakdown": {
                        "terms": {
                            "field": "device.keyword",
                            "size": 15
                        }
                    },
                    "hourly_activity": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": parsed_start.isoformat(),
                                "max": parsed_end.isoformat()
                            }
                        }
                    },
                    "log_levels": {
                        "terms": {
                            "field": "level.keyword",
                            "size": 10
                        }
                    },
                    "message_patterns": {
                        "terms": {
                            "script": {
                                "source": """
                                    String msg = doc['message.keyword'].value.toLowerCase();
                                    
                                    // Extract key patterns
                                    if (msg.contains('failed')) return 'Failed operations';
                                    if (msg.contains('error')) return 'Error events';
                                    if (msg.contains('warning')) return 'Warning events';
                                    if (msg.contains('started') || msg.contains('stopped')) return 'Service state changes';
                                    if (msg.contains('login') || msg.contains('session')) return 'Authentication events';
                                    if (msg.contains('connection')) return 'Connection events';
                                    if (msg.contains('timeout')) return 'Timeout events';
                                    if (msg.contains('permission') || msg.contains('denied')) return 'Permission/Access events';
                                    
                                    // Extract first significant word
                                    String[] words = msg.split(' ');
                                    for (String word : words) {
                                        if (word.length() > 4 && !word.matches('.*\\\\d.*')) {
                                            return 'Other: ' + word;
                                        }
                                    }
                                    
                                    return 'Uncategorized';
                                """
                            },
                            "size": 10
                        }
                    }
                }
                    }
            
                logger.debug(f"Executing timerange search query: {search_query}")
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=search_query,
                    timeout="30s"
                )
                
                # Extract data from response
                hits = response.get("hits", {}).get("hits", [])
                total_results = response.get("hits", {}).get("total", {}).get("value", 0)
                aggs = response.get("aggregations", {})
                
                # Process aggregation data
                device_breakdown = aggs.get("device_breakdown", {}).get("buckets", [])
                hourly_activity = aggs.get("hourly_activity", {}).get("buckets", [])
                log_levels = aggs.get("log_levels", {}).get("buckets", [])
                message_patterns = aggs.get("message_patterns", {}).get("buckets", [])
                
                # Process log entries
                log_entries = []
                for hit in hits:
                    source = hit["_source"]
                    log_entries.append({
                        "timestamp": source.get("timestamp", ""),
                        "device": source.get("device", "unknown"),
                        "level": source.get("level", "info"),
                        "message": source.get("message", "")[:150]  # Truncate long messages
                    })
            
            # Generate summary
                    summary = _generate_timerange_search_summary(
                start_time,
                end_time,
                device,
                query,
                limit,
                total_results,
                log_entries,
                device_breakdown,
                hourly_activity,
                message_patterns,
                time_diff
                    )
            
                log_mcp_response("search_by_timerange", True, {
                    "total_results": total_results,
                    "returned_entries": len(log_entries),
                    "time_span_hours": time_diff.total_seconds() / 3600,
                    "devices_found": len(device_breakdown),
                    "query": query or "none"
                })
                
                return summary
                
            finally:
                await es_client.disconnect()
                
        except ElasticsearchConnectionError as e:
            error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nTime Range: {start_time} to {end_time}"
            log_mcp_response("search_by_timerange", False, error=error_msg)
            return error_msg
            
        except ElasticsearchQueryError as e:
            error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nTime Range: {start_time} to {end_time}"
            log_mcp_response("search_by_timerange", False, error=error_msg)
            return error_msg
            
        except Exception as e:
            error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nTime Range: {start_time} to {end_time}\\nPlease check server logs for details."
            logger.error("Error in search_by_timerange", extra={
                "error": str(e),
                "start_time": start_time,
                "end_time": end_time,
                "device": device,
                "query": query,
                "limit": limit
            }, exc_info=True)
            log_mcp_response("search_by_timerange", False, error=error_msg)
            return error_msg

    @mcp.tool()
    async def full_text_search(
        query: str,
        device: Optional[str] = None,
        hours: int = 24,
        limit: int = 50,
        search_type: str = "phrase"
    ) -> str:
        """
        Perform advanced full-text search across log messages with ranking and relevance.

        Provides comprehensive text search capabilities with multiple search modes,
        relevance ranking, and contextual analysis of matching log entries.

        Args:
            query: Search query text to find in log messages (required)
            device: Specific device to search (optional, searches all devices if not specified)
            hours: Number of hours to search back (1-168, default: 24)
            limit: Maximum number of results to return (1-500, default: 50)
            search_type: Search mode - "phrase", "fuzzy", "wildcard", "regex" (default: "phrase")
            
        Returns:
            Formatted markdown text containing:
            - Search parameters and query analysis
            - Total matches and relevance scoring
            - Top matching log entries with context
            - Device and time distribution of matches
            - Related keywords and terms found
            - Search performance and optimization tips
            - Pattern analysis of matching content
        """
        request_args = {
            "query": query,
            "device": device,
            "hours": hours,
            "limit": limit,
            "search_type": search_type
        }
        log_mcp_request("full_text_search", request_args)
        
        try:
            # Validate parameters
            if not query or len(query.strip()) < 2:
                error_msg = f"❌ **Invalid query:** Query must be at least 2 characters long."
                log_mcp_response("full_text_search", False, error=error_msg)
                return error_msg
            
            if not (1 <= hours <= 168):
                error_msg = f"❌ **Invalid hours parameter:** {hours}\\n\\nHours must be between 1 and 168 (1 week)."
                log_mcp_response("full_text_search", False, error=error_msg)
                return error_msg
            
            if not (1 <= limit <= 500):
                error_msg = f"❌ **Invalid limit parameter:** {limit}\\n\\nLimit must be between 1 and 500."
                log_mcp_response("full_text_search", False, error=error_msg)
                return error_msg
            
            valid_search_types = ["phrase", "fuzzy", "wildcard", "regex"]
            if search_type not in valid_search_types:
                error_msg = f"❌ **Invalid search_type:** {search_type}\\n\\nMust be one of: {', '.join(valid_search_types)}"
                log_mcp_response("full_text_search", False, error=error_msg)
                return error_msg
            
            # Get Elasticsearch client and connect
            es_client = ElasticsearchClient()
            
            try:
                await es_client.connect()
                
                # Calculate time range
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=hours)
                
                # Build search query based on search type
                search_clause = {}
                if search_type == "phrase":
                    search_clause = {"match_phrase": {"message": query}}
                elif search_type == "fuzzy":
                    search_clause = {"match": {"message": {"query": query, "fuzziness": "AUTO"}}}
                elif search_type == "wildcard":
                    # Escape special characters except * and ?
                    escaped_query = query.replace('\\', '\\\\').replace('"', '\\"')
                    search_clause = {"wildcard": {"message.keyword": f"*{escaped_query}*"}}
                elif search_type == "regex":
                    try:
                        # Basic regex validation
                        import re
                        re.compile(query)
                        search_clause = {"regexp": {"message.keyword": query}}
                    except re.error as e:
                        error_msg = f"❌ **Invalid regex pattern:** {str(e)}\\n\\nQuery: {query}"
                        log_mcp_response("full_text_search", False, error=error_msg)
                        return error_msg
                
                # Build base query
                base_query = {
                    "bool": {
                    "must": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        },
                        search_clause
                    ],
                    "filter": []
                }
                }
                
                # Add device filter if specified
                if device:
                    base_query["bool"]["filter"].append({
                        "term": {"device.keyword": device}
                    })
                
                # Build comprehensive search query
                search_query = {
                    "query": base_query,
                "size": limit,
                "sort": [
                    {"_score": {"order": "desc"}},
                    {"timestamp": {"order": "desc"}}
                ],
                "_source": ["timestamp", "device", "message", "level"],
                "highlight": {
                    "fields": {
                        "message": {
                            "pre_tags": ["**"],
                            "post_tags": ["**"],
                            "fragment_size": 150,
                            "number_of_fragments": 2
                        }
                    }
                },
                "aggs": {
                    "device_matches": {
                        "terms": {
                            "field": "device.keyword",
                            "size": 15
                        },
                        "aggs": {
                            "recent_matches": {
                                "top_hits": {
                                    "sort": [{"timestamp": {"order": "desc"}}],
                                    "size": 1,
                                    "_source": ["timestamp", "message"]
                                }
                            }
                        }
                    },
                    "time_distribution": {
                        "date_histogram": {
                            "field": "timestamp",
                            "fixed_interval": "1h",
                            "min_doc_count": 1
                        }
                    },
                    "log_levels": {
                        "terms": {
                            "field": "level.keyword",
                            "size": 10
                        }
                    },
                    "related_terms": {
                        "significant_text": {
                            "field": "message",
                            "size": 10,
                            "filter_duplicate_text": True
                        }
                    },
                    "message_length": {
                        "stats": {
                            "script": {
                                "source": "doc['message.keyword'].value.length()"
                            }
                        }
                    }
                }
                }
                
                logger.debug(f"Executing full text search query: {search_query}")
                response = await es_client._client.search(
                    index="syslog-ng",
                    body=search_query,
                    timeout="30s"
                )
            
            # Extract data from response
            hits = response.get("hits", {}).get("hits", [])
            total_results = response.get("hits", {}).get("total", {}).get("value", 0)
            max_score = response.get("hits", {}).get("max_score", 0)
            aggs = response.get("aggregations", {})
            
            # Process search results with highlights
            search_results = []
            for hit in hits:
                source = hit["_source"]
                score = hit.get("_score", 0)
                highlight = hit.get("highlight", {}).get("message", [])
                
                search_results.append({
                    "timestamp": source.get("timestamp", ""),
                    "device": source.get("device", "unknown"),
                    "level": source.get("level", "info"),
                    "message": source.get("message", "")[:200],
                    "score": score,
                    "highlight": highlight[0] if highlight else ""
                })
            
            # Process aggregation data
            device_matches = aggs.get("device_matches", {}).get("buckets", [])
            time_distribution = aggs.get("time_distribution", {}).get("buckets", [])
            log_levels = aggs.get("log_levels", {}).get("buckets", [])
            related_terms = aggs.get("related_terms", {}).get("buckets", [])
            message_stats = aggs.get("message_length", {})
            
            # Generate summary
            summary = _generate_full_text_search_summary(
                query,
                device,
                hours,
                limit,
                search_type,
                total_results,
                max_score,
                search_results,
                device_matches,
                time_distribution,
                related_terms,
                message_stats
            )
            
            log_mcp_response("full_text_search", True, {
                "total_matches": total_results,
                "returned_results": len(search_results),
                "max_relevance_score": max_score,
                "devices_with_matches": len(device_matches),
                "query": query,
                "search_type": search_type
            })
            
            return summary
            
        finally:
            await es_client.disconnect()
            
    except ElasticsearchConnectionError as e:
        error_msg = f"❌ **Connection Error**\\n\\nFailed to connect to Elasticsearch: {e.message}\\n\\nQuery: {query}"
        log_mcp_response("full_text_search", False, error=error_msg)
        return error_msg
        
    except ElasticsearchQueryError as e:
        error_msg = f"❌ **Query Error**\\n\\nElasticsearch query failed: {e.message}\\n\\nQuery: {query}"
        log_mcp_response("full_text_search", False, error=error_msg)
        return error_msg
        
    except Exception as e:
        error_msg = f"❌ **Internal Error**\\n\\nUnexpected error occurred: {str(e)}\\n\\nQuery: {query}\\nPlease check server logs for details."
        logger.error("Error in full_text_search", extra={
            "error": str(e),
            "query": query,
            "device": device,
            "hours": hours,
            "limit": limit,
            "search_type": search_type
        }, exc_info=True)
        log_mcp_response("full_text_search", False, error=error_msg)
        return error_msg