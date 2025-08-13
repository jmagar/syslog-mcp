"""
Security Analysis Prompts for Syslog MCP Server

This module provides structured prompts that guide users through
comprehensive security analysis workflows using our MCP tools.
"""


from fastmcp import FastMCP
from pydantic import Field


def register_security_analysis_prompts(mcp: FastMCP) -> None:
    """Register all security analysis prompts with the FastMCP server."""

    @mcp.prompt(
        name="investigate_security_incident",
        description="Guide through comprehensive security incident investigation",
        tags={"security", "incident", "investigation"},
        meta={"version": "1.0", "category": "security"}
    )
    def investigate_security_incident(
        device: str | None = Field(None, description="Target device to investigate (leave blank for all devices)"),
        time_window: int = Field(24, description="Time window in hours to analyze (default: 24)")
    ) -> str:
        """
        Provides a structured workflow for investigating potential security incidents
        using failed authentication analysis, suspicious activity detection, and IP reputation checks.
        """

        workflow = f"""# 🔍 Security Incident Investigation Workflow

**Target Device:** {'All devices' if not device else device}
**Analysis Period:** Last {time_window} hours

## Step 1: Failed Authentication Analysis
Start by analyzing failed authentication attempts to identify potential brute force attacks or unauthorized access attempts.

**Recommended MCP Tool:** `failed_auth_summary_tool`
```
failed_auth_summary_tool(hours={time_window}{f', device="{device}"' if device else ''})
```

## Step 2: Suspicious Activity Detection
Look for unusual system activities that could indicate compromise or malicious behavior.

**Recommended MCP Tool:** `suspicious_activity_tool`
```
suspicious_activity_tool(hours={time_window}{f', device="{device}"' if device else ''}, sensitivity="medium")
```

## Step 3: IP Reputation Analysis
Analyze source IP addresses from suspicious activities to identify known threats.

**Recommended MCP Tool:** `ip_reputation_tool`
```
ip_reputation_tool(hours={time_window}, top_ips=20)
```

## Step 4: Authentication Timeline
Create a timeline of authentication events to understand the attack pattern.

**Recommended MCP Tool:** `auth_timeline_tool`
```
auth_timeline_tool(hours={time_window}{f', device="{device}"' if device else ''}, interval="1h")
```

## Step 5: Event Correlation Analysis
Correlate events across multiple fields to identify attack patterns and relationships.

**Recommended MCP Tool:** `search_correlate_tool`
```
search_correlate_tool(
    primary_query="failed OR invalid OR unauthorized",
    correlation_fields="device,source_ip",
    time_window=60,
    hours={time_window}
)
```

## Step 6: Generate Investigation Report
Create a comprehensive report documenting your findings.

**Recommended MCP Tool:** `generate_daily_report_tool`
```
generate_daily_report_tool()
```

---
**Next Steps:** Based on findings, consider:
- Creating alert rules for similar patterns
- Implementing IP blocking for confirmed threats
- Reviewing authentication policies
- Escalating to security team if active compromise detected
"""

        return workflow

    @mcp.prompt(
        name="security_health_assessment",
        description="Comprehensive security health check for systems",
        tags={"security", "health", "assessment"},
        meta={"version": "1.0", "category": "security"}
    )
    def security_health_assessment(
        assessment_period: int = Field(7, description="Assessment period in days (default: 7 days)"),
        focus_device: str | None = Field(None, description="Specific device to focus assessment on")
    ) -> str:
        """
        Provides a systematic security health assessment workflow to evaluate
        overall system security posture and identify potential vulnerabilities.
        """

        hours = assessment_period * 24

        assessment = f"""# 🛡️ Security Health Assessment

**Assessment Period:** Last {assessment_period} days ({hours} hours)
**Focus Device:** {'All systems' if not focus_device else focus_device}

## Phase 1: Authentication Security Review

### 1.1 Failed Authentication Analysis
Review failed login attempts to identify attack patterns and frequency.

**Tool:** `failed_auth_summary_tool(hours={hours}{f', device="{focus_device}"' if focus_device else ''})`

### 1.2 Authentication Timeline Analysis
Analyze authentication patterns over time to identify anomalies.

**Tool:** `auth_timeline_tool(hours={hours}{f', device="{focus_device}"' if focus_device else ''}, interval="6h")`

## Phase 2: Threat Intelligence Analysis

### 2.1 IP Reputation Assessment
Evaluate IP addresses accessing your systems for known threats.

**Tool:** `ip_reputation_tool(hours={hours}, top_ips=50, min_attempts=1)`

### 2.2 Suspicious Activity Detection
Scan for unusual system behaviors that could indicate security issues.

**Tool:** `suspicious_activity_tool(hours={hours}{f', device="{focus_device}"' if focus_device else ''}, sensitivity="low")`

## Phase 3: System Integrity Review

### 3.1 Error Pattern Analysis
Review system errors that could indicate security issues or system compromise.

**Tool:** `error_analysis_tool(hours={hours}{f', device="{focus_device}"' if focus_device else ''}, severity="error")`

### 3.2 Log Search for Security Events
Search for specific security-related log entries.

**Tool:** `full_text_search_tool(query="security OR breach OR attack OR malware", hours={hours})`

## Phase 4: Alert Configuration Review

### 4.1 Review Current Alert Rules
Check existing alert configurations for completeness.

**Tool:** `alert_rules_tool()`

### 4.2 Test Alert System
Verify alert notification system is functioning.

**Tool:** `test_gotify_tool()`

## Phase 5: Comprehensive Report Generation

### 5.1 Generate Security Report
Create a comprehensive security assessment report.

**Tool:** `generate_daily_report_tool(target_date="{assessment_period} days ago")`

---
**Assessment Checklist:**
- [ ] No unusual authentication failure patterns
- [ ] All accessing IPs have good reputation scores
- [ ] No suspicious system activities detected
- [ ] Error patterns are within normal ranges
- [ ] Alert system is properly configured and functional
- [ ] No critical security events in logs
"""

        return assessment

    @mcp.prompt(
        name="threat_response_playbook",
        description="Step-by-step threat response and mitigation playbook",
        tags={"security", "threat", "response", "playbook"},
        meta={"version": "1.0", "category": "security"}
    )
    def threat_response_playbook(
        threat_type: str = Field("general", description="Type of threat (general, brute_force, malware, data_breach)"),
        urgency: str = Field("medium", description="Urgency level (low, medium, high, critical)")
    ) -> str:
        """
        Provides a structured threat response playbook with specific actions
        based on threat type and urgency level.
        """

        urgency_settings = {
            "low": {"hours": 72, "interval": "6h", "sensitivity": "low"},
            "medium": {"hours": 24, "interval": "2h", "sensitivity": "medium"},
            "high": {"hours": 8, "interval": "1h", "sensitivity": "high"},
            "critical": {"hours": 4, "interval": "30m", "sensitivity": "high"}
        }

        settings = urgency_settings.get(urgency, urgency_settings["medium"])

        playbook = f"""# 🚨 Threat Response Playbook

**Threat Type:** {threat_type.title()}
**Urgency Level:** {urgency.upper()}
**Response Window:** {settings['hours']} hours

## Immediate Response Actions ({urgency.upper()} Priority)

### 1. Threat Assessment & Evidence Collection

#### 1.1 Rapid Security Scan
**Tool:** `suspicious_activity_tool(hours={settings['hours']}, sensitivity="{settings['sensitivity']}")`

#### 1.2 Authentication Analysis
**Tool:** `failed_auth_summary_tool(hours={settings['hours']}, top_ips=10)`

#### 1.3 Timeline Construction
**Tool:** `auth_timeline_tool(hours={settings['hours']}, interval="{settings['interval']}")`

### 2. Threat Intelligence Gathering

#### 2.1 IP Reputation Check
**Tool:** `ip_reputation_tool(hours={settings['hours']}, top_ips=25, min_attempts=3)`

#### 2.2 Event Correlation Analysis
**Tool:** `search_correlate_tool(primary_query="error OR failed OR attack", correlation_fields="device,source_ip,program", hours={settings['hours']})`

### 3. Impact Assessment

#### 3.1 Affected Systems Analysis
**Tool:** `get_device_summary_tool(device="<affected_device>", hours={settings['hours']})`

#### 3.2 Error Impact Review
**Tool:** `error_analysis_tool(hours={settings['hours']}, top_errors=20)`

### 4. Evidence Preservation

#### 4.1 Export Threat-Related Logs
**Tool:** `export_logs_tool(query="threat OR attack OR breach OR unauthorized", hours={settings['hours']}, format_type="json")`

#### 4.2 Search Threat Indicators
**Tool:** `full_text_search_tool(query="<threat_indicators>", hours={settings['hours']})`

## Threat-Specific Actions

"""

        if threat_type == "brute_force":
            playbook += """### Brute Force Attack Response
- Focus on `failed_auth_summary_tool` for attack patterns
- Use `ip_reputation_tool` to identify attack sources
- Create alert rule: `create_alert_rule_tool(name="Brute Force Alert", query="failed password", threshold=20, time_window=30)`

"""
        elif threat_type == "malware":
            playbook += """### Malware Incident Response
- Search for malware indicators: `full_text_search_tool(query="virus OR malware OR trojan")`
- Check for unusual system activities: `suspicious_activity_tool(sensitivity="high")`
- Correlate across affected systems: `search_correlate_tool(primary_query="malware", correlation_fields="device,program")`

"""
        elif threat_type == "data_breach":
            playbook += """### Data Breach Response
- Immediate log export: `export_logs_tool(query="access OR download OR copy", format_type="json")`
- Timeline analysis: `auth_timeline_tool(interval="15m")` for detailed access patterns
- Full system correlation: `search_correlate_tool(primary_query="data OR file OR database", correlation_fields="device,user,program")`

"""

        playbook += f"""## Ongoing Monitoring & Alerts

### 5. Alert Configuration
**Tool:** `create_alert_rule_tool(name="{threat_type.title()} Monitor", query="related_indicators", threshold=5, severity="{urgency}")`

### 6. Continuous Monitoring
**Tool:** `check_alerts_tool()` - Run every {settings['interval']} during response

### 7. Response Documentation
**Tool:** `generate_daily_report_tool()` - Document incident response actions

---
**Post-Incident Actions:**
- Review and update alert rules based on findings
- Update threat response procedures
- Conduct lessons learned session
- Test alert system functionality: `test_gotify_tool()`
"""

        return playbook
