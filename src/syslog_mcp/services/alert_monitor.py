"""
Alert monitoring service that evaluates alert rules and sends notifications.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .elasticsearch_client import ElasticsearchClient
from .gotify_client import send_alert_notification
from ..utils.logging import get_logger

logger = get_logger(__name__)


class AlertMonitor:
    """Service for monitoring alert rules and triggering notifications."""
    
    def __init__(self):
        """Initialize alert monitor."""
        self.es_client = ElasticsearchClient()
        self.alert_states_file = Path.home() / ".syslog-mcp" / "alert_states.json"
        self.alert_states_file.parent.mkdir(parents=True, exist_ok=True)
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.es_client.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.es_client.disconnect()
    
    def load_alert_rules(self) -> List[Dict[str, Any]]:
        """Load alert rules from storage."""
        rules_file = Path.home() / ".syslog-mcp" / "alert_rules.json"
        
        if not rules_file.exists():
            return []
        
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                return data.get('rules', [])
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load alert rules: {e}")
            return []
    
    def load_alert_states(self) -> Dict[str, Any]:
        """Load alert states (last triggered times, etc.)."""
        if not self.alert_states_file.exists():
            return {}
        
        try:
            with open(self.alert_states_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load alert states: {e}")
            return {}
    
    def save_alert_states(self, states: Dict[str, Any]) -> None:
        """Save alert states to file."""
        try:
            with open(self.alert_states_file, 'w') as f:
                json.dump(states, f, indent=2)
        except IOError as e:
            logger.error(f"Failed to save alert states: {e}")
    
    async def evaluate_alert_rule(self, rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate a single alert rule against current data.
        
        Args:
            rule: Alert rule configuration
            
        Returns:
            Alert event if triggered, None otherwise
        """
        try:
            # Build Elasticsearch query for the rule
            time_window_minutes = rule.get('time_window', 60)
            threshold = rule.get('threshold', 1)
            query_string = rule.get('query', '')
            
            # Calculate time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(minutes=time_window_minutes)
            
            # Build Elasticsearch query
            search_query = {
                "query": {
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
                        ]
                    }
                },
                "size": 0,  # We only need the count
                "track_total_hits": True
            }
            
            # Add query string if provided
            if query_string.strip():
                search_query["query"]["bool"]["must"].append({
                    "query_string": {
                        "query": query_string,
                        "default_field": "message"
                    }
                })
            
            # Execute search
            response = await self.es_client._client.search(
                index="syslog-ng",
                body=search_query,
                timeout="10s"
            )
            
            # Get total hits
            total_hits = response["hits"]["total"]["value"]
            
            logger.debug(
                f"Alert rule '{rule['name']}' evaluation: {total_hits} hits, threshold: {threshold}",
                extra={"rule_name": rule["name"], "hits": total_hits, "threshold": threshold}
            )
            
            # Check if threshold exceeded
            if total_hits >= threshold:
                return {
                    "rule_name": rule["name"],
                    "rule_id": rule.get("id", rule["name"]),
                    "query": query_string,
                    "threshold": threshold,
                    "actual_count": total_hits,
                    "time_window_minutes": time_window_minutes,
                    "severity": rule.get("severity", "medium"),
                    "description": rule.get("description", ""),
                    "triggered_at": end_time.isoformat(),
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat()
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error evaluating alert rule '{rule.get('name', 'unknown')}': {e}")
            return None
    
    def should_send_alert(
        self,
        alert_event: Dict[str, Any],
        alert_states: Dict[str, Any]
    ) -> bool:
        """
        Determine if an alert should be sent based on cooldown and state.
        
        Args:
            alert_event: The triggered alert event
            alert_states: Current alert states
            
        Returns:
            True if alert should be sent, False otherwise
        """
        rule_id = alert_event["rule_id"]
        
        # Check if this rule has been triggered recently (cooldown)
        if rule_id in alert_states:
            last_triggered = datetime.fromisoformat(
                alert_states[rule_id]["last_triggered"].replace('Z', '+00:00')
            )
            
            # Default cooldown: 30 minutes
            cooldown_minutes = 30
            cooldown_delta = timedelta(minutes=cooldown_minutes)
            
            if datetime.now(timezone.utc) - last_triggered < cooldown_delta:
                logger.debug(
                    f"Alert rule '{rule_id}' in cooldown period",
                    extra={"rule_id": rule_id, "cooldown_minutes": cooldown_minutes}
                )
                return False
        
        return True
    
    async def send_alert(self, alert_event: Dict[str, Any]) -> bool:
        """
        Send alert notification via Gotify.
        
        Args:
            alert_event: Alert event data
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Format alert message
        severity_emoji = {
            "low": "🟡",
            "medium": "🟠", 
            "high": "🔴",
            "critical": "💀"
        }
        
        severity = alert_event["severity"].lower()
        emoji = severity_emoji.get(severity, "⚠️")
        
        title = f"{emoji} Syslog Alert: {alert_event['rule_name']}"
        
        message = f"""**Alert Triggered**

**Rule:** {alert_event['rule_name']}
**Severity:** {alert_event['severity'].upper()}
**Query:** {alert_event['query']}

**Event Count:** {alert_event['actual_count']} (threshold: {alert_event['threshold']})
**Time Window:** {alert_event['time_window_minutes']} minutes
**Period:** {alert_event['start_time']} to {alert_event['end_time']}

**Description:** {alert_event.get('description', 'No description')}

*Triggered at {alert_event['triggered_at']}*"""
        
        # Map severity to Gotify priority
        priority_map = {
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10
        }
        priority = priority_map.get(severity, 5)
        
        # Send notification
        success = await send_alert_notification(title, message, priority)
        
        if success:
            logger.info(
                f"Alert notification sent for rule '{alert_event['rule_name']}'",
                extra={"rule_name": alert_event["rule_name"], "severity": severity}
            )
        else:
            logger.error(
                f"Failed to send alert notification for rule '{alert_event['rule_name']}'",
                extra={"rule_name": alert_event["rule_name"]}
            )
        
        return success
    
    async def check_all_alerts(self) -> Dict[str, Any]:
        """
        Check all alert rules and send notifications if needed.
        
        Returns:
            Summary of alert check results
        """
        rules = self.load_alert_rules()
        alert_states = self.load_alert_states()
        
        if not rules:
            logger.debug("No alert rules configured")
            return {
                "total_rules": 0,
                "triggered_alerts": 0,
                "sent_notifications": 0,
                "errors": 0
            }
        
        logger.info(f"Checking {len(rules)} alert rules")
        
        results = {
            "total_rules": len(rules),
            "triggered_alerts": 0,
            "sent_notifications": 0,
            "errors": 0,
            "triggered_rules": []
        }
        
        for rule in rules:
            try:
                # Evaluate the rule
                alert_event = await self.evaluate_alert_rule(rule)
                
                if alert_event:
                    results["triggered_alerts"] += 1
                    results["triggered_rules"].append(alert_event["rule_name"])
                    
                    # Check if we should send notification
                    if self.should_send_alert(alert_event, alert_states):
                        # Send notification
                        success = await self.send_alert(alert_event)
                        
                        if success:
                            results["sent_notifications"] += 1
                            
                            # Update alert state
                            alert_states[alert_event["rule_id"]] = {
                                "last_triggered": alert_event["triggered_at"],
                                "last_count": alert_event["actual_count"]
                            }
                    
            except Exception as e:
                logger.error(f"Error processing alert rule '{rule.get('name', 'unknown')}': {e}")
                results["errors"] += 1
        
        # Save updated alert states
        self.save_alert_states(alert_states)
        
        logger.info(
            f"Alert check completed: {results['triggered_alerts']} triggered, "
            f"{results['sent_notifications']} notifications sent",
            extra=results
        )
        
        return results


async def check_alerts_once() -> Dict[str, Any]:
    """
    Convenience function to check alerts once.
    
    Returns:
        Alert check results
    """
    async with AlertMonitor() as monitor:
        return await monitor.check_all_alerts()


async def run_alert_monitor(interval_minutes: int = 5) -> None:
    """
    Run alert monitor continuously.
    
    Args:
        interval_minutes: Check interval in minutes
    """
    logger.info(f"Starting alert monitor with {interval_minutes}-minute intervals")
    
    while True:
        try:
            async with AlertMonitor() as monitor:
                await monitor.check_all_alerts()
        except Exception as e:
            logger.error(f"Alert monitor error: {e}")
        
        # Wait for next check
        await asyncio.sleep(interval_minutes * 60)


if __name__ == "__main__":
    # For testing - run a single alert check
    asyncio.run(check_alerts_once())