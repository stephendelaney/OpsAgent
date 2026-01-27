"""Notification module for alerting operations team."""

import asyncio
from datetime import datetime
from typing import Dict, Optional
import logging
import os
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)


class Notifier:
    """Handles sending notifications via Slack, PagerDuty, and email."""

    def __init__(self, config: Dict):
        """
        Initialize the Notifier.

        Args:
            config: Configuration dictionary containing notification settings
        """
        self.config = config
        self.notification_config = config.get('notifications', {})

        # Initialize Slack
        self.slack_enabled = self.notification_config.get('slack', {}).get('enabled', False)
        if self.slack_enabled:
            webhook_url_env = self.notification_config.get('slack', {}).get('webhook_url_env', 'SLACK_WEBHOOK_URL')
            self.slack_webhook = os.getenv(webhook_url_env)
            self.slack_channel = self.notification_config.get('slack', {}).get('channel', '#ops-alerts')
            self.slack_mention = self.notification_config.get('slack', {}).get('mention_on_failure', '@oncall')

        # Initialize PagerDuty
        self.pagerduty_enabled = self.notification_config.get('pagerduty', {}).get('enabled', False)
        if self.pagerduty_enabled:
            key_env = self.notification_config.get('pagerduty', {}).get('integration_key_env', 'PAGERDUTY_INTEGRATION_KEY')
            self.pagerduty_key = os.getenv(key_env)

    async def send_incident_alert(
        self,
        incident_summary: str,
        full_analysis: Dict,
        severity: str = 'critical',
        instance_info: Optional[Dict] = None
    ) -> Dict:
        """
        Send incident alert to configured channels.

        Args:
            incident_summary: Brief summary for notification
            full_analysis: Complete analysis results
            severity: Severity level (critical, high, medium, low)
            instance_info: EC2 instance information

        Returns:
            Dictionary with notification results
        """
        logger.info(f"Sending incident alerts with severity: {severity}")

        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'channels': {}
        }

        # Send to Slack
        if self.slack_enabled:
            slack_result = await self._send_slack_alert(
                incident_summary, full_analysis, severity, instance_info
            )
            results['channels']['slack'] = slack_result

        # Send to PagerDuty
        if self.pagerduty_enabled and severity in ['critical', 'high']:
            pd_result = await self._send_pagerduty_alert(
                incident_summary, full_analysis, severity, instance_info
            )
            results['channels']['pagerduty'] = pd_result

        return results

    async def _send_slack_alert(
        self,
        summary: str,
        analysis: Dict,
        severity: str,
        instance_info: Optional[Dict]
    ) -> Dict:
        """Send alert to Slack."""
        if not self.slack_webhook:
            logger.warning("Slack webhook URL not configured")
            return {'success': False, 'error': 'Webhook URL not configured'}

        try:
            # Build Slack message
            color = {
                'critical': '#FF0000',
                'high': '#FF6600',
                'medium': '#FFCC00',
                'low': '#00CC00'
            }.get(severity, '#808080')

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 Java Node Failure - {severity.upper()}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{self.slack_mention}\n\n*Incident Summary:*\n{summary}"
                    }
                }
            ]

            # Add instance info if available
            if instance_info:
                instance_text = f"*Instance:* {instance_info.get('instance_id', 'N/A')}\n"
                instance_text += f"*IP:* {instance_info.get('instance_ip', 'N/A')}\n"
                instance_text += f"*Service:* {instance_info.get('service', 'N/A')}"

                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": instance_text
                    }
                })

            # Add quick metrics if available
            metrics = analysis.get('context', {})
            if metrics:
                metrics_text = f"*Metrics:*\n"
                metrics_text += f"• Logs Collected: {metrics.get('logs_collected', 0)}\n"
                metrics_text += f"• Heap Dumps: {metrics.get('heap_dumps_collected', 0)}\n"
                metrics_text += f"• Severity: {metrics.get('metrics_severity', 'unknown')}"

                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": metrics_text
                    }
                })

            # Add divider and timestamp
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"Timestamp: {datetime.utcnow().isoformat()} | Analysis by {analysis.get('llm_model', 'N/A')}"
                }]
            })

            payload = {
                "channel": self.slack_channel,
                "username": "OpsAgent",
                "icon_emoji": ":robot_face:",
                "blocks": blocks,
                "attachments": [{
                    "color": color,
                    "text": f"Full analysis available in incident report",
                    "footer": "OpsAgent Incident Response"
                }]
            }

            # Send to Slack
            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info("Slack alert sent successfully")
                return {'success': True, 'channel': self.slack_channel}
            else:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return {'success': False, 'error': f"Status {response.status_code}"}

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}", exc_info=True)
            return {'success': False, 'error': str(e)}

    async def _send_pagerduty_alert(
        self,
        summary: str,
        analysis: Dict,
        severity: str,
        instance_info: Optional[Dict]
    ) -> Dict:
        """Send alert to PagerDuty."""
        if not self.pagerduty_key:
            logger.warning("PagerDuty integration key not configured")
            return {'success': False, 'error': 'Integration key not configured'}

        try:
            payload = {
                "routing_key": self.pagerduty_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"Java Node Failure: {summary[:100]}",
                    "severity": severity,
                    "source": instance_info.get('instance_id', 'unknown') if instance_info else 'unknown',
                    "component": "java-node",
                    "group": "operations",
                    "class": "node-failure",
                    "custom_details": {
                        "full_summary": summary,
                        "instance_ip": instance_info.get('instance_ip') if instance_info else None,
                        "analysis_timestamp": analysis.get('timestamp'),
                        "llm_model": analysis.get('llm_model')
                    }
                }
            }

            response = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=10
            )

            if response.status_code == 202:
                logger.info("PagerDuty alert sent successfully")
                dedup_key = response.json().get('dedup_key')
                return {'success': True, 'dedup_key': dedup_key}
            else:
                logger.error(f"PagerDuty API error: {response.status_code} - {response.text}")
                return {'success': False, 'error': f"Status {response.status_code}"}

        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {str(e)}", exc_info=True)
            return {'success': False, 'error': str(e)}

    async def send_recovery_notification(
        self,
        instance_info: Dict,
        recovery_result: Dict
    ) -> Dict:
        """Send notification about recovery attempt results."""
        if not recovery_result.get('attempted'):
            return {'success': True, 'message': 'No recovery attempted'}

        success = recovery_result.get('success', False)
        message = recovery_result.get('message', 'Unknown result')

        if self.slack_enabled and self.slack_webhook:
            try:
                color = "#00CC00" if success else "#FF6600"
                emoji = "✅" if success else "⚠️"

                payload = {
                    "channel": self.slack_channel,
                    "username": "OpsAgent",
                    "icon_emoji": ":robot_face:",
                    "attachments": [{
                        "color": color,
                        "title": f"{emoji} Recovery Attempt Result",
                        "text": message,
                        "fields": [
                            {
                                "title": "Instance",
                                "value": instance_info.get('instance_id', 'N/A'),
                                "short": True
                            },
                            {
                                "title": "Success",
                                "value": "Yes" if success else "No",
                                "short": True
                            },
                            {
                                "title": "Attempts",
                                "value": str(len(recovery_result.get('attempts', []))),
                                "short": True
                            }
                        ],
                        "footer": "OpsAgent Recovery",
                        "ts": int(datetime.utcnow().timestamp())
                    }]
                }

                response = requests.post(self.slack_webhook, json=payload, timeout=10)
                return {'success': response.status_code == 200}

            except Exception as e:
                logger.error(f"Failed to send recovery notification: {str(e)}")
                return {'success': False, 'error': str(e)}

        return {'success': True, 'message': 'Notifications disabled'}
