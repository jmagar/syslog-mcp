"""
System Administration Prompts for Syslog MCP Server

This module provides structured prompts that guide system administrators through
device health checks, performance investigations, and daily operational tasks.
"""


from fastmcp import FastMCP
from pydantic import Field


def register_system_administration_prompts(mcp: FastMCP) -> None:
    """Register all system administration prompts with the FastMCP server."""

    @mcp.prompt(
        name="device_health_check",
        description="Comprehensive device health assessment workflow",
        tags={"administration", "health", "monitoring"},
        meta={"version": "1.0", "category": "administration"}
    )
    def device_health_check(
        device: str = Field(..., description="Device name to analyze"),
        assessment_hours: int = Field(24, description="Hours of data to analyze (default: 24)")
    ) -> str:
        """
        Provides a systematic device health check workflow to assess device status,
        identify issues, and recommend maintenance actions.
        """

        workflow = f"""# 🖥️ Device Health Check: {device}

**Assessment Period:** Last {assessment_hours} hours
**Target Device:** {device}

## Phase 1: Overall Health Assessment

### 1.1 Device Summary Analysis
Get a comprehensive overview of device status, activity, and health metrics.

**Tool:** `get_device_summary_tool(device="{device}", hours={assessment_hours})`

**Expected Outcomes:**
- Overall health status
- Activity levels and patterns
- Key performance indicators
- Initial health recommendations

## Phase 2: Error Analysis & Troubleshooting

### 2.1 System Error Analysis
Review error patterns to identify potential hardware or software issues.

**Tool:** `error_analysis_tool(device="{device}", hours={assessment_hours}, top_errors=15)`

**Look for:**
- Critical system errors
- Hardware failures
- Service failures
- Configuration issues

### 2.2 Authentication Health Check
Verify authentication system is working properly and identify access issues.

**Tool:** `failed_auth_summary_tool(device="{device}", hours={assessment_hours})`

**Check for:**
- Unusual authentication failures
- Potential security issues
- User access problems

## Phase 3: Performance Investigation

### 3.1 Search Performance Analysis
Test search performance and identify any log processing issues.

**Tool:** `search_by_timerange_tool(
    start_time="{assessment_hours}h ago",
    end_time="now",
    device="{device}",
    limit=10
)`

### 3.2 Full-Text Search Health
Verify log indexing and search functionality is working properly.

**Tool:** `full_text_search_tool(
    query="system OR service OR process",
    device="{device}",
    hours={assessment_hours},
    limit=10
)`

## Phase 4: Historical Analysis

### 4.1 Timeline Analysis
Review device activity patterns over time to identify trends or anomalies.

**Tool:** `auth_timeline_tool(device="{device}", hours={assessment_hours}, interval="4h")`

### 4.2 Event Correlation Check
Look for correlated events that might indicate systemic issues.

**Tool:** `search_correlate_tool(
    primary_query="error OR warning OR critical",
    correlation_fields="device,program,level",
    device="{device}",
    hours={assessment_hours}
)`

## Phase 5: Maintenance Recommendations

### 5.1 Generate Device Report
Create a comprehensive health report for documentation and tracking.

**Tool:** `export_logs_tool(
    device="{device}",
    query="level:error OR level:warning",
    hours={assessment_hours},
    format_type="json"
)`

---
## Health Check Checklist

**Device Status:**
- [ ] Device is active and responsive
- [ ] No critical system errors
- [ ] Authentication system functioning normally
- [ ] No unusual error patterns
- [ ] Performance metrics within normal ranges
- [ ] Log processing working correctly

**Recommended Actions:**
- Address any critical errors found
- Monitor identified warning patterns
- Schedule maintenance if hardware issues detected
- Update alert rules based on findings
- Document any configuration changes needed

**Follow-up:**
- Schedule next health check
- Create alerts for identified patterns
- Plan maintenance windows for any required fixes
"""

        return workflow

    @mcp.prompt(
        name="performance_investigation",
        description="Systematic performance analysis and optimization workflow",
        tags={"administration", "performance", "optimization"},
        meta={"version": "1.0", "category": "administration"}
    )
    def performance_investigation(
        scope: str = Field("system", description="Investigation scope (system, device, application, network)"),
        time_period: int = Field(24, description="Investigation time period in hours"),
        focus_device: str | None = Field(None, description="Specific device to focus investigation on")
    ) -> str:
        """
        Provides a structured approach to investigating system performance issues
        and identifying optimization opportunities.
        """

        investigation = f"""# ⚡ Performance Investigation

**Investigation Scope:** {scope.title()}
**Time Period:** Last {time_period} hours
**Focus Device:** {'All systems' if not focus_device else focus_device}

## Phase 1: Baseline Performance Assessment

### 1.1 System Activity Overview
Establish baseline system activity levels and identify any obvious performance issues.

**Tool:** `get_device_summary_tool({f'device="{focus_device}", ' if focus_device else ''}hours={time_period})`

### 1.2 Error Impact Analysis
Identify errors that might be impacting system performance.

**Tool:** `error_analysis_tool({f'device="{focus_device}", ' if focus_device else ''}hours={time_period}, top_errors=20)`

## Phase 2: Performance Pattern Analysis

### 2.1 Timeline Performance Analysis
Analyze performance patterns over time to identify peak usage and bottlenecks.

**Tool:** `auth_timeline_tool({f'device="{focus_device}", ' if focus_device else ''}hours={time_period}, interval="2h")`

### 2.2 Search Performance Testing
Test search and query performance to identify indexing or database issues.

**Tool:** `full_text_search_tool(
    query="process OR service OR system",
    {f'device="{focus_device}", ' if focus_device else ''}hours={time_period},
    limit=50
)`

## Phase 3: Resource Utilization Analysis

### 3.1 Suspicious Activity Detection
Identify activities that might be consuming excessive resources.

**Tool:** `suspicious_activity_tool({f'device="{focus_device}", ' if focus_device else ''}hours={time_period}, sensitivity="medium")`

### 3.2 Event Correlation Analysis
Find correlated events that might indicate resource contention.

**Tool:** `search_correlate_tool(
    primary_query="high OR load OR memory OR disk OR cpu",
    correlation_fields="device,program,timestamp",
    {f'device="{focus_device}", ' if focus_device else ''}hours={time_period}
)`

## Phase 4: Application Performance Review

### 4.1 Application Error Analysis
Focus on application-specific errors that might impact performance.

**Tool:** `search_by_timerange_tool(
    start_time="{time_period}h ago",
    end_time="now",
    query="application OR service OR timeout OR slow",
    {f'device="{focus_device}", ' if focus_device else ''}limit=25
)`

### 4.2 Service Availability Check
Verify critical services are running properly and responding.

**Tool:** `full_text_search_tool(
    query="started OR stopped OR restarted OR failed",
    {f'device="{focus_device}", ' if focus_device else ''}hours={time_period}
)`

## Phase 5: Network Performance Analysis

### 5.1 Connection Analysis
Review network connections for performance issues.

**Tool:** `ip_reputation_tool(hours={time_period}, top_ips=30, min_attempts=10)`

### 5.2 Authentication Performance
Check if authentication delays are impacting overall performance.

**Tool:** `failed_auth_summary_tool({f'device="{focus_device}", ' if focus_device else ''}hours={time_period})`

## Phase 6: Performance Report & Recommendations

### 6.1 Generate Performance Report
Document findings and performance metrics.

**Tool:** `generate_daily_report_tool()`

### 6.2 Export Performance Data
Export relevant performance data for further analysis.

**Tool:** `export_logs_tool(
    query="performance OR slow OR timeout OR error",
    {f'device="{focus_device}", ' if focus_device else ''}hours={time_period},
    format_type="json"
)`

---
## Performance Investigation Checklist

**System Performance:**
- [ ] Baseline performance metrics established
- [ ] Error patterns identified and categorized
- [ ] Peak usage periods documented
- [ ] Resource bottlenecks identified
- [ ] Application performance issues documented
- [ ] Network performance issues identified

**Optimization Opportunities:**
- [ ] Identified services consuming excessive resources
- [ ] Found inefficient processes or queries
- [ ] Documented configuration optimization opportunities
- [ ] Identified hardware upgrade requirements
- [ ] Found scheduling optimization opportunities

**Next Steps:**
- Implement identified optimizations
- Set up performance monitoring alerts
- Schedule regular performance reviews
- Plan capacity upgrades if needed
- Document performance baseline for future reference
"""

        return investigation

    @mcp.prompt(
        name="daily_operations_review",
        description="Daily operational health check and maintenance workflow",
        tags={"administration", "daily", "operations", "maintenance"},
        meta={"version": "1.0", "category": "administration"}
    )
    def daily_operations_review(
        review_date: str | None = Field(None, description="Date to review (YYYY-MM-DD format, defaults to today)"),
        include_alerts: bool = Field(True, description="Include alert system check in review")
    ) -> str:
        """
        Provides a structured daily operations review workflow to ensure
        systems are healthy and identify any issues requiring attention.
        """

        date_display = review_date if review_date else "today"

        review = f"""# 📋 Daily Operations Review - {date_display.title()}

**Review Date:** {date_display}
**Alert System Check:** {'Included' if include_alerts else 'Skipped'}

## Morning Health Check (Start of Day)

### 1.1 System Status Overview
Get a high-level view of overall system health.

**Tool:** `generate_daily_report_tool({f'target_date="{review_date}"' if review_date else ''})`

### 1.2 Critical Error Review
Check for any critical errors that occurred overnight.

**Tool:** `error_analysis_tool(hours=24, severity="error", top_errors=10)`

### 1.3 Security Status Check
Review security events from the past 24 hours.

**Tool:** `failed_auth_summary_tool(hours=24, top_ips=10)`

## System Health Verification

### 2.1 Device Health Check
Verify all monitored devices are functioning properly.

**Tool:** `suspicious_activity_tool(hours=24, sensitivity="low")`

### 2.2 Authentication System Health
Ensure authentication systems are working normally.

**Tool:** `auth_timeline_tool(hours=24, interval="6h")`

### 2.3 Search System Performance
Verify log processing and search functionality.

**Tool:** `full_text_search_tool(query="system", hours=24, limit=5)`

## Alert System Management

{"### 3.1 Alert Rules Review" if include_alerts else "# Alert System Checks (Skipped)"}
{"Check current alert configuration and status." if include_alerts else "Alert system checks were skipped for this review."}

{'**Tool:** `alert_rules_tool()`' if include_alerts else ''}

{"### 3.2 Test Alert System" if include_alerts else ""}
{"Verify alert notifications are working properly." if include_alerts else ""}

{'**Tool:** `test_gotify_tool()`' if include_alerts else ''}

{"### 3.3 Check Recent Alerts" if include_alerts else ""}
{"Review any triggered alerts from the past 24 hours." if include_alerts else ""}

{'**Tool:** `check_alerts_tool()`' if include_alerts else ''}

## Data Management & Housekeeping

### 4.1 Search Performance Check
Test search functionality across different time ranges.

**Tool:** `search_by_timerange_tool(
    start_time="24h ago",
    end_time="now",
    limit=10
)`

### 4.2 Event Correlation Health
Verify correlation analysis is working properly.

**Tool:** `search_correlate_tool(
    primary_query="system OR service",
    correlation_fields="device,program",
    hours=24,
    limit=10
)`

## Weekly Tasks (If Applicable)

### 5.1 Saved Searches Review (Weekly)
Review and clean up saved searches if it's been a week since last check.

**Tool:** `saved_searches_tool()`

### 5.2 Export System Logs (Weekly)
Export logs for archival if this is a weekly review.

**Tool:** `export_logs_tool(
    query="level:info OR level:warning OR level:error",
    hours=168,
    format_type="json"
)`

---
## Daily Operations Checklist

**System Health:**
- [ ] No critical errors in past 24 hours
- [ ] All devices responding normally
- [ ] Authentication system functioning
- [ ] Search and indexing working properly
- [ ] No security incidents detected

**Alert Management:**
{'- [ ] Alert rules are properly configured' if include_alerts else '- [ ] Alert system checks skipped'}
{'- [ ] Alert notifications working properly' if include_alerts else ''}
{'- [ ] No unresolved alerts requiring attention' if include_alerts else ''}

**Performance:**
- [ ] System performance within normal ranges
- [ ] No unusual activity patterns detected
- [ ] Log processing keeping up with volume
- [ ] Search queries executing efficiently

**Action Items:**
- [ ] Address any identified issues
- [ ] Update documentation if needed
- [ ] Schedule maintenance if required
- [ ] Review and update alert thresholds
- [ ] Plan capacity if growth detected

**End of Day Tasks:**
- [ ] Review daily report summary
- [ ] Document any issues found
- [ ] Schedule follow-up actions
- [ ] Update operational runbooks
- [ ] Prepare for next day operations
"""

        return review
