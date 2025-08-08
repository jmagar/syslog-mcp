"""
Summary generation helper functions for device analysis tools.

This module contains all the _generate_* helper functions that create
human-readable markdown summaries from Elasticsearch aggregation results.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


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