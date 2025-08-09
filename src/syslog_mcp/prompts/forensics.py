"""
Forensics Investigation Prompts for Syslog MCP Server

This module provides structured prompts that guide users through
detailed forensics investigations and root cause analysis workflows.
"""

from typing import Optional
from pydantic import Field
from fastmcp import FastMCP


def register_forensics_prompts(mcp: FastMCP) -> None:
    """Register all forensics investigation prompts with the FastMCP server."""
    
    @mcp.prompt(
        name="log_forensics_investigation",
        description="Comprehensive log forensics investigation workflow",
        tags={"forensics", "investigation", "analysis"},
        meta={"version": "1.0", "category": "forensics"}
    )
    def log_forensics_investigation(
        incident_time: str = Field(..., description="Incident timestamp or time range (e.g., '2025-01-15T10:30:00Z' or '2h ago')"),
        investigation_scope: str = Field("comprehensive", description="Investigation scope (focused, comprehensive, deep)"),
        target_device: Optional[str] = Field(None, description="Specific device to investigate")
    ) -> str:
        """
        Provides a structured forensics investigation workflow for analyzing
        security incidents, system compromises, and suspicious activities.
        """
        
        scope_settings = {
            "focused": {"hours": 4, "interval": "15m", "search_limit": 50},
            "comprehensive": {"hours": 12, "interval": "30m", "search_limit": 100}, 
            "deep": {"hours": 72, "interval": "1h", "search_limit": 200}
        }
        
        settings = scope_settings.get(investigation_scope, scope_settings["comprehensive"])
        
        investigation = f"""# 🔍 Log Forensics Investigation

**Incident Time:** {incident_time}
**Investigation Scope:** {investigation_scope.title()}
**Target Device:** {'All systems' if not target_device else target_device}
**Analysis Window:** {settings['hours']} hours

## Phase 1: Evidence Preservation & Initial Analysis

### 1.1 Export Critical Evidence
Immediately preserve relevant log data for forensic analysis.

**Tool:** `export_logs_tool(
    query="error OR failed OR unauthorized OR breach OR attack",
    {f'device="{target_device}", ' if target_device else ''}start_time="{incident_time}",
    hours={settings['hours']},
    format_type="json",
    limit={settings['search_limit']}
)`

### 1.2 Timeline Construction
Build a detailed timeline around the incident timeframe.

**Tool:** `auth_timeline_tool(
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    interval="{settings['interval']}"
)`

### 1.3 Initial Threat Assessment
Identify potential security indicators and suspicious activities.

**Tool:** `suspicious_activity_tool(
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    sensitivity="high"
)`

## Phase 2: Deep Forensic Analysis

### 2.1 Authentication Forensics
Analyze authentication events for signs of compromise or unauthorized access.

**Tool:** `failed_auth_summary_tool(
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    top_ips=25
)`

### 2.2 IP Address Investigation
Investigate source IP addresses for reputation and attack patterns.

**Tool:** `ip_reputation_tool(
    hours={settings['hours']},
    top_ips=50,
    min_attempts=1
)`

### 2.3 System Error Analysis
Review system errors that might indicate compromise or malicious activity.

**Tool:** `error_analysis_tool(
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    top_errors=25
)`

## Phase 3: Event Correlation & Pattern Analysis

### 3.1 Multi-Field Event Correlation
Correlate events across multiple dimensions to identify attack patterns.

**Tool:** `search_correlate_tool(
    primary_query="failed OR error OR unauthorized OR access OR login",
    correlation_fields="device,source_ip,user,program",
    {f'device="{target_device}", ' if target_device else ''}time_window=30,
    hours={settings['hours']},
    limit={settings['search_limit']}
)`

### 3.2 Advanced Pattern Search
Search for specific indicators of compromise and attack patterns.

**Tool:** `full_text_search_tool(
    query="malware OR virus OR trojan OR backdoor OR exploit OR shellcode",
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    limit={settings['search_limit']}
)`

### 3.3 Time-Range Evidence Analysis
Analyze logs within specific time windows around the incident.

**Tool:** `search_by_timerange_tool(
    start_time="{incident_time}",
    end_time="2h after {incident_time}",
    query="security OR breach OR compromise OR attack",
    {f'device="{target_device}", ' if target_device else ''}limit={settings['search_limit']}
)`

## Phase 4: Lateral Movement & Impact Analysis

### 4.1 Cross-System Analysis
Look for evidence of lateral movement or system-to-system propagation.

**Tool:** `search_correlate_tool(
    primary_query="connection OR network OR transfer OR copy",
    correlation_fields="device,destination_ip,source_ip",
    hours={settings['hours']},
    limit={settings['search_limit']}
)`

### 4.2 Data Access Investigation
Investigate potential data access or exfiltration attempts.

**Tool:** `full_text_search_tool(
    query="download OR copy OR transfer OR export OR backup OR archive",
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    limit={settings['search_limit']}
)`

### 4.3 Privilege Escalation Detection
Look for signs of privilege escalation or unauthorized elevation.

**Tool:** `full_text_search_tool(
    query="sudo OR admin OR root OR escalate OR privilege OR permission",
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    limit={settings['search_limit']}
)`

## Phase 5: Attribution & Intelligence Gathering

### 5.1 Attack Attribution Analysis
Gather intelligence on attack sources and methodologies.

**Tool:** `ip_reputation_tool(
    hours={settings['hours']},
    top_ips=100,
    min_attempts=1
)`

### 5.2 Threat Intelligence Correlation
Search for known threat indicators and attack signatures.

**Tool:** `full_text_search_tool(
    query="APT OR botnet OR ransomware OR phishing OR C2 OR command",
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    limit={settings['search_limit']}
)`

## Phase 6: Evidence Documentation & Reporting

### 6.1 Comprehensive Evidence Export
Export all relevant evidence for legal and remediation purposes.

**Tool:** `export_logs_tool(
    query="incident_related_indicators",
    {f'device="{target_device}", ' if target_device else ''}hours={settings['hours']},
    format_type="json",
    limit=1000
)`

### 6.2 Investigation Summary Report
Generate a comprehensive investigation summary.

**Tool:** `generate_daily_report_tool(
    target_date="{incident_time[:10] if 'T' in incident_time else 'today'}"
)`

---
## Forensics Investigation Checklist

**Evidence Preservation:**
- [ ] Critical log data exported and secured
- [ ] Chain of custody documented
- [ ] Timestamps verified and normalized
- [ ] Evidence integrity checksums created

**Timeline Analysis:**
- [ ] Detailed incident timeline constructed
- [ ] Pre-incident activity analyzed
- [ ] Post-incident activity tracked
- [ ] Activity correlations identified

**Threat Analysis:**
- [ ] Suspicious activities identified and categorized
- [ ] Attack vectors identified
- [ ] Compromise indicators documented
- [ ] Threat actor attribution assessed

**Impact Assessment:**
- [ ] Affected systems identified
- [ ] Data access attempts documented
- [ ] Lateral movement patterns traced
- [ ] Privilege escalation attempts analyzed

**Intelligence Gathering:**
- [ ] Source IP reputation analyzed
- [ ] Attack signatures identified
- [ ] Threat intelligence correlated
- [ ] Similar incident patterns researched

**Documentation:**
- [ ] Complete evidence package created
- [ ] Investigation report generated
- [ ] Remediation recommendations documented
- [ ] Lessons learned captured

**Follow-up Actions:**
- Create detection rules for identified patterns
- Implement security improvements
- Update incident response procedures
- Share threat intelligence with security community
"""
        
        return investigation

    @mcp.prompt(
        name="root_cause_analysis",
        description="Systematic root cause analysis for system failures and incidents",
        tags={"forensics", "root-cause", "analysis", "troubleshooting"},
        meta={"version": "1.0", "category": "forensics"}
    )
    def root_cause_analysis(
        problem_description: str = Field(..., description="Description of the problem or incident"),
        failure_time: str = Field(..., description="When the problem occurred (timestamp or relative time)"),
        affected_systems: Optional[str] = Field(None, description="Systems affected (device names, comma-separated)")
    ) -> str:
        """
        Provides a structured root cause analysis workflow to systematically
        investigate system failures and identify underlying causes.
        """
        
        systems_list = affected_systems.split(',') if affected_systems else ['all systems']
        systems_display = ', '.join(systems_list) if affected_systems else 'All systems'
        
        analysis = f"""# 🔬 Root Cause Analysis

**Problem:** {problem_description}
**Failure Time:** {failure_time}
**Affected Systems:** {systems_display}

## Phase 1: Problem Definition & Initial Assessment

### 1.1 System Status Assessment
Get current status of affected systems and identify immediate issues.

{"".join([f'''
**System: {system.strip()}**
**Tool:** `get_device_summary_tool(device="{system.strip()}", hours=24)`
''' for system in systems_list if system.strip() != 'all systems'])}

{'''**All Systems Overview:**
**Tool:** `generate_daily_report_tool()`''' if 'all systems' in systems_list else ''}

### 1.2 Error Pattern Analysis
Identify error patterns related to the problem timeframe.

**Tool:** `error_analysis_tool(hours=48, top_errors=20{f', device="{systems_list[0].strip()}"' if len(systems_list) == 1 and systems_list[0].strip() != 'all systems' else ''})`

### 1.3 Timeline Construction
Build a detailed timeline leading up to and following the failure.

**Tool:** `search_by_timerange_tool(
    start_time="6h before {failure_time}",
    end_time="2h after {failure_time}",
    query="error OR warning OR critical OR failed",
    limit=50
)`

## Phase 2: Event Correlation & Pattern Identification

### 2.1 Multi-System Event Correlation
Correlate events across affected systems to identify common causes.

**Tool:** `search_correlate_tool(
    primary_query="error OR failed OR timeout OR crash",
    correlation_fields="device,program,timestamp,level",
    hours=24,
    time_window=15,
    limit=100
)`

### 2.2 Service Dependency Analysis
Analyze service dependencies and potential cascade failures.

**Tool:** `full_text_search_tool(
    query="started OR stopped OR restarted OR dependency OR service",
    hours=24,
    limit=75
)`

### 2.3 Authentication System Impact
Check if authentication issues contributed to the problem.

**Tool:** `failed_auth_summary_tool(hours=24{f', device="{systems_list[0].strip()}"' if len(systems_list) == 1 and systems_list[0].strip() != 'all systems' else ''})`

## Phase 3: Resource & Performance Analysis

### 3.1 Resource Utilization Investigation
Investigate resource constraints that might have caused the failure.

**Tool:** `full_text_search_tool(
    query="memory OR disk OR cpu OR load OR space OR resource",
    hours=24,
    limit=50
)`

### 3.2 Performance Degradation Analysis
Look for performance issues leading up to the failure.

**Tool:** `search_correlate_tool(
    primary_query="slow OR timeout OR performance OR delay",
    correlation_fields="device,program,timestamp",
    hours=24,
    limit=50
)`

### 3.3 Network Connectivity Analysis
Analyze network-related issues that might have contributed.

**Tool:** `full_text_search_tool(
    query="network OR connection OR connectivity OR timeout OR unreachable",
    hours=24,
    limit=50
)`

## Phase 4: Configuration & Change Analysis

### 4.1 Configuration Change Detection
Look for configuration changes that might have caused the issue.

**Tool:** `full_text_search_tool(
    query="config OR configuration OR setting OR changed OR modified",
    hours=72,
    limit=50
)`

### 4.2 Software Update Impact Analysis
Check for software updates or changes that coincided with the failure.

**Tool:** `full_text_search_tool(
    query="update OR upgrade OR install OR patch OR version",
    hours=168,
    limit=50
)`

### 4.3 Security Event Correlation
Rule out security incidents as a contributing factor.

**Tool:** `suspicious_activity_tool(hours=24, sensitivity="medium")`

## Phase 5: External Factor Analysis

### 5.1 External Service Dependencies
Analyze external service issues that might have impacted systems.

**Tool:** `ip_reputation_tool(hours=24, top_ips=30, min_attempts=5)`

### 5.2 Time-Based Pattern Analysis
Look for time-based patterns (scheduled jobs, maintenance, etc.).

**Tool:** `auth_timeline_tool(hours=72, interval="1h"{f', device="{systems_list[0].strip()}"' if len(systems_list) == 1 and systems_list[0].strip() != 'all systems' else ''})`

## Phase 6: Evidence Compilation & Root Cause Determination

### 6.1 Comprehensive Evidence Export
Export all relevant evidence for detailed analysis.

**Tool:** `export_logs_tool(
    query="error OR failed OR critical OR warning",
    start_time="12h before {failure_time}",
    end_time="4h after {failure_time}",
    format_type="json",
    limit=500
)`

### 6.2 Pattern Summary Analysis
Search for specific patterns identified during investigation.

**Tool:** `full_text_search_tool(
    query="[insert specific patterns found during analysis]",
    hours=24,
    limit=100
)`

---
## Root Cause Analysis Framework

### 5 Whys Analysis
Work through these questions based on your findings:

1. **Why did the problem occur?**
   - Review error analysis results
   - Check timeline for immediate causes

2. **Why did that cause occur?**
   - Examine correlation analysis
   - Look at system dependencies  

3. **Why did that underlying cause occur?**
   - Review configuration changes
   - Check resource utilization

4. **Why did that systemic issue exist?**
   - Analyze monitoring gaps
   - Review preventive measures

5. **Why wasn't this prevented?**
   - Examine process failures
   - Review alerting systems

### Root Cause Categories

**Technical Causes:**
- [ ] Hardware failure
- [ ] Software bug or defect
- [ ] Configuration error
- [ ] Resource exhaustion
- [ ] Network connectivity issue
- [ ] Database or storage issue

**Process Causes:**
- [ ] Inadequate monitoring
- [ ] Missing alerting rules
- [ ] Insufficient testing
- [ ] Change management failure
- [ ] Documentation issues
- [ ] Training gaps

**Human Causes:**
- [ ] Operator error
- [ ] Miscommunication
- [ ] Inadequate procedures
- [ ] Time pressure
- [ ] Knowledge gaps
- [ ] Tool limitations

### Remediation Plan

**Immediate Actions:**
- [ ] Fix identified root cause
- [ ] Restore service functionality
- [ ] Verify system stability
- [ ] Monitor for recurrence

**Short-term Improvements:**
- [ ] Implement additional monitoring
- [ ] Create detection alerts
- [ ] Update procedures
- [ ] Add preventive measures

**Long-term Enhancements:**
- [ ] Architecture improvements
- [ ] Process enhancements
- [ ] Training programs  
- [ ] Tool upgrades
- [ ] Documentation updates

### Prevention Strategy

**Monitoring Enhancements:**
- Create alert rule: `create_alert_rule_tool(name="RCA Prevention", query="[pattern]", threshold=X)`
- Test alert system: `test_gotify_tool()`

**Process Improvements:**
- Update operational runbooks
- Enhance change management
- Improve testing procedures
- Schedule regular reviews
"""
        
        return analysis