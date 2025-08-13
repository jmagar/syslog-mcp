"""
Alert monitoring service that evaluates alert rules and sends notifications.
"""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

from ..utils.logging import get_logger
from .elasticsearch_client import ElasticsearchClient
from .gotify_client import send_alert_notification

logger = get_logger(__name__)


class AlertMonitor:
    """Service for monitoring alert rules and triggering notifications."""

    def __init__(self) -> None:
        """Initialize alert monitor."""
        self.es_client = ElasticsearchClient()
        self.alert_states_file = Path.home() / ".syslog-mcp" / "alert_states.json"
        self.alert_states_file.parent.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        await self.es_client.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.es_client.disconnect()

    def load_alert_rules(self) -> list[dict[str, Any]]:
        """Load alert rules from storage."""
        rules_file = Path.home() / ".syslog-mcp" / "alert_rules.json"

        if not rules_file.exists():
            return []

        try:
            with rules_file.open('r') as f:
                data = json.load(f)
                rules_dict = data.get('rules', {})
                # Convert dictionary of rules to list
                if isinstance(rules_dict, dict):
                    return list(rules_dict.values())
                else:
                    return rules_dict if isinstance(rules_dict, list) else []
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load alert rules: {e}")
            return []

    def load_alert_states(self) -> dict[str, Any]:
        """Load alert states (last triggered times, etc.)."""
        if not self.alert_states_file.exists():
            return {}

        try:
            with self.alert_states_file.open('r') as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load alert states: {e}")
            return {}

    def save_alert_states(self, states: dict[str, Any]) -> None:
        """Save alert states to file."""
        try:
            with self.alert_states_file.open('w') as f:
                json.dump(states, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save alert states: {e}")

    async def evaluate_alert_rule(self, rule: dict[str, Any]) -> dict[str, Any] | None:
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
            end_time = datetime.now(UTC)
            start_time = end_time - timedelta(minutes=time_window_minutes)

            # Build Elasticsearch query
            search_query: dict[str, Any] = {
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

            # Execute search using public API
            response = await self.es_client.search_raw(
                query=search_query,
                timeout="10s"
            )

            # Get total hits
            total_hits = response["hits"]["total"]["value"]

            logger.debug(
                f"Alert rule '{rule.get('name', 'unknown')}' evaluation: {total_hits} hits, threshold: {threshold}",
                extra={"rule_name": rule.get("name", "unknown"), "hits": total_hits, "threshold": threshold}
            )

            # Check if threshold exceeded
            if total_hits >= threshold:
                rule_name = rule.get("name", "unknown")
                return {
                    "rule_name": rule_name,
                    "rule_id": rule.get("id", rule_name),
                    "query": query_string,
                    "threshold": threshold,
                    "actual_count": total_hits,
                    "time_window_minutes": time_window_minutes,
                    "cooldown_minutes": rule.get("cooldown_minutes", 30),
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
        alert_event: dict[str, Any],
        alert_states: dict[str, Any]
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

            # Get cooldown from alert event (per-rule configurable)
            cooldown_minutes = alert_event.get("cooldown_minutes", 30)
            cooldown_delta = timedelta(minutes=cooldown_minutes)

            if datetime.now(UTC) - last_triggered < cooldown_delta:
                logger.debug(
                    f"Alert rule '{rule_id}' in cooldown period",
                    extra={"rule_id": rule_id, "cooldown_minutes": cooldown_minutes}
                )
                return False

        return True

    async def send_alert(self, alert_event: dict[str, Any]) -> bool:
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

    async def check_all_alerts(self) -> dict[str, Any]:
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

        results: dict[str, Any] = {
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


async def check_alerts_once() -> dict[str, Any]:
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
