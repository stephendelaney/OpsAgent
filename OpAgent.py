#!/usr/bin/env python3
"""
OpsAgent - AI-Powered Java Node Incident Response Agent

This agent responds to Monit alerts for failed Java nodes by:
1. Collecting diagnostic data (logs, metrics, optional heap dumps)
2. Analyzing data with LLM to determine root cause
3. Alerting operations team with comprehensive analysis
4. Optionally attempting automated recovery (if enabled)
"""

import asyncio
import os
import sys
import yaml
import json
import logging
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path
from flask import Flask, request, jsonify

# Import components
from collectors import LogCollector, HeapDumpCollector, MetricsCollector
from analyzer import Analyzer
from recovery import NodeRecovery
from utils import setup_logger, Notifier

logger = logging.getLogger('ops-agent')


class OpAgent:
    """Main orchestrator for OpsAgent incident response."""

    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize OpsAgent.

        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)

        # Setup logging first
        global logger
        logger = setup_logger(self.config)

        logger.info("Initializing OpsAgent...")

        # Initialize components
        self.log_collector = LogCollector(self.config)
        self.heap_dump_collector = HeapDumpCollector(self.config)
        self.metrics_collector = MetricsCollector(self.config)
        self.analyzer = Analyzer(self.config)
        self.recovery = NodeRecovery(self.config)
        self.notifier = Notifier(self.config)

        # Get SSH key path
        self.ssh_key_path = self._get_ssh_key_path()

        logger.info("OpsAgent initialized successfully")

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            print(f"Error loading config from {config_path}: {e}", file=sys.stderr)
            sys.exit(1)

    def _get_ssh_key_path(self) -> str:
        """Get SSH key path from config or AWS Secrets Manager."""
        ssh_config = self.config.get('ec2', {}).get('ssh', {})
        key_path = ssh_config.get('key_path')

        # TODO: Implement AWS Secrets Manager integration if enabled
        secrets_config = self.config.get('aws', {}).get('secrets_manager', {})
        if secrets_config.get('enabled'):
            logger.info("AWS Secrets Manager enabled but not yet implemented in this version")
            # Would fetch SSH key from Secrets Manager here

        return key_path

    async def handle_alert(self, alert_data: Dict) -> Dict:
        """
        Main workflow to handle an incoming Monit alert.

        Args:
            alert_data: Parsed alert data from Monit

        Returns:
            Dictionary with incident response results
        """
        incident_id = f"incident-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        logger.info(f"===== Starting Incident Response: {incident_id} =====")
        logger.info(f"Alert: {alert_data}")

        response = {
            'incident_id': incident_id,
            'timestamp': datetime.utcnow().isoformat(),
            'alert': alert_data,
            'stages': {}
        }

        try:
            # Extract instance information
            instance_ip = alert_data.get('instance_ip')
            instance_id = alert_data.get('instance_id')

            if not instance_ip:
                raise ValueError("instance_ip is required in alert data")

            instance_info = {
                'instance_ip': instance_ip,
                'instance_id': instance_id or 'unknown',
                'service': alert_data.get('service', 'java-node')
            }

            # Prepare output directory for collected data
            output_dir = f"/tmp/ops-agent/{incident_id}"
            os.makedirs(output_dir, exist_ok=True)
            logger.info(f"Output directory: {output_dir}")

            # STAGE 1: Collect Current Metrics
            logger.info("STAGE 1: Collecting current system metrics...")
            metrics_data = await self.metrics_collector.collect_current_metrics(
                instance_ip,
                self.ssh_key_path
            )
            metrics_data['analysis'] = self.metrics_collector.analyze_metrics(metrics_data)
            response['stages']['metrics_collection'] = {
                'success': metrics_data.get('success', False),
                'timestamp': datetime.utcnow().isoformat()
            }
            logger.info(f"Metrics collected. Severity: {metrics_data['analysis'].get('severity')}")

            # STAGE 2: Collect Logs
            logger.info("STAGE 2: Collecting application and system logs...")
            logs_data = await self.log_collector.collect_logs(
                instance_ip,
                self.ssh_key_path,
                output_dir
            )

            # Quick log preview analysis
            if logs_data.get('success'):
                logs_data['preview_analysis'] = await self.log_collector.analyze_logs_preview(
                    logs_data.get('collected_files', [])
                )

            response['stages']['log_collection'] = {
                'success': logs_data.get('success', False),
                'files_collected': logs_data.get('total_files', 0),
                'timestamp': datetime.utcnow().isoformat()
            }
            logger.info(f"Logs collected: {logs_data.get('total_files', 0)} files")

            # STAGE 3: Collect Heap Dumps (Optional - only if critical memory issue detected)
            heap_dump_data = None
            collect_heap_dumps = False

            # Check if we should collect heap dumps
            if metrics_data['analysis'].get('severity') == 'critical':
                for issue in metrics_data['analysis'].get('issues', []):
                    if 'memory' in issue.get('type', '').lower():
                        collect_heap_dumps = True
                        break

            if logs_data.get('preview_analysis', {}).get('oom_indicators', 0) > 0:
                collect_heap_dumps = True

            if collect_heap_dumps:
                logger.info("STAGE 3: Collecting heap dumps (memory issue detected)...")
                heap_dump_data = await self.heap_dump_collector.collect_heap_dumps(
                    instance_ip,
                    self.ssh_key_path,
                    output_dir
                )
                response['stages']['heap_dump_collection'] = {
                    'success': heap_dump_data.get('success', False),
                    'files_collected': heap_dump_data.get('total_files', 0),
                    'timestamp': datetime.utcnow().isoformat()
                }
                logger.info(f"Heap dumps collected: {heap_dump_data.get('total_files', 0)}")
            else:
                logger.info("STAGE 3: Skipping heap dump collection (no critical memory issues)")
                response['stages']['heap_dump_collection'] = {
                    'skipped': True,
                    'reason': 'No critical memory issues detected'
                }

            # STAGE 4: LLM Analysis
            logger.info("STAGE 4: Performing comprehensive LLM analysis...")
            analysis_result = await self.analyzer.analyze_incident(
                logs_data=logs_data,
                metrics_data=metrics_data,
                heap_dump_data=heap_dump_data,
                alert_context=alert_data
            )
            response['stages']['analysis'] = {
                'success': analysis_result.get('success', False),
                'timestamp': datetime.utcnow().isoformat()
            }
            response['analysis'] = analysis_result
            logger.info("LLM analysis complete")

            # Generate executive summary for notifications
            exec_summary = await self.analyzer.generate_executive_summary(analysis_result)
            response['executive_summary'] = exec_summary

            # STAGE 5: Send Notifications
            logger.info("STAGE 5: Sending notifications to operations team...")
            notification_result = await self.notifier.send_incident_alert(
                incident_summary=exec_summary,
                full_analysis=analysis_result,
                severity=metrics_data['analysis'].get('severity', 'high'),
                instance_info=instance_info
            )
            response['stages']['notifications'] = notification_result
            logger.info("Notifications sent")

            # STAGE 6: Optional Recovery
            if self.recovery.is_recovery_enabled():
                logger.info("STAGE 6: Attempting automated recovery (enabled in config)...")
                recovery_result = await self.recovery.attempt_recovery(
                    instance_ip,
                    self.ssh_key_path
                )
                response['stages']['recovery'] = recovery_result

                # Send recovery notification
                await self.notifier.send_recovery_notification(
                    instance_info,
                    recovery_result
                )
                logger.info(f"Recovery attempted. Success: {recovery_result.get('success', False)}")
            else:
                logger.info("STAGE 6: Automated recovery disabled. Operations team will manually restart.")
                response['stages']['recovery'] = {
                    'attempted': False,
                    'reason': 'Automated recovery disabled in configuration',
                    'action_required': 'Operations team should manually restart node after reviewing analysis'
                }

            # Save incident report
            await self._save_incident_report(incident_id, response, output_dir)

            logger.info(f"===== Incident Response Complete: {incident_id} =====")
            return response

        except Exception as e:
            logger.error(f"Error during incident response: {str(e)}", exc_info=True)
            response['error'] = str(e)
            response['success'] = False
            return response

    async def _save_incident_report(self, incident_id: str, response: Dict, output_dir: str):
        """Save detailed incident report to file."""
        try:
            report_path = os.path.join(output_dir, f"{incident_id}-report.json")

            with open(report_path, 'w') as f:
                json.dump(response, f, indent=2, default=str)

            logger.info(f"Incident report saved: {report_path}")

            # Also save to configured incident report path
            incident_report_path = self.config.get('recovery', {}).get('incident_report_path')
            if incident_report_path:
                os.makedirs(incident_report_path, exist_ok=True)
                archive_path = os.path.join(incident_report_path, f"{incident_id}-report.json")
                with open(archive_path, 'w') as f:
                    json.dump(response, f, indent=2, default=str)
                logger.info(f"Incident report archived: {archive_path}")

        except Exception as e:
            logger.error(f"Error saving incident report: {str(e)}")


# Flask webhook handler
app = Flask(__name__)
agent = None


@app.route('/monit-webhook', methods=['POST'])
def monit_webhook():
    """Handle incoming webhooks from Monit."""
    try:
        # Parse Monit alert data
        if request.is_json:
            alert_data = request.get_json()
        else:
            # Monit might send form data
            alert_data = request.form.to_dict()

        logger.info(f"Received Monit webhook: {alert_data}")

        # Validate authentication if enabled
        auth_config = agent.config.get('alert_handler', {}).get('monit', {})
        if auth_config.get('authentication', False):
            auth_token_env = auth_config.get('auth_token_env', 'MONIT_AUTH_TOKEN')
            expected_token = os.getenv(auth_token_env)

            provided_token = request.headers.get('Authorization', '').replace('Bearer ', '')

            if expected_token and provided_token != expected_token:
                logger.warning("Unauthorized webhook attempt")
                return jsonify({'error': 'Unauthorized'}), 401

        # Trigger incident response asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        response = loop.run_until_complete(agent.handle_alert(alert_data))
        loop.close()

        return jsonify({
            'status': 'processing',
            'incident_id': response.get('incident_id'),
            'message': 'Incident response initiated'
        }), 202

    except Exception as e:
        logger.error(f"Error handling webhook: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'OpsAgent',
        'timestamp': datetime.utcnow().isoformat()
    })


def main():
    """Main entry point."""
    global agent

    # Load config path from environment or use default
    config_path = os.getenv('OPSAGENT_CONFIG', 'config.yaml')

    # Initialize agent
    agent = OpAgent(config_path)

    # Get webhook configuration
    webhook_config = agent.config.get('alert_handler', {}).get('monit', {})
    port = webhook_config.get('webhook_port', 8000)

    logger.info(f"Starting OpsAgent webhook server on port {port}")
    logger.info(f"Webhook endpoint: http://0.0.0.0:{port}/monit-webhook")
    logger.info(f"Auto-recovery enabled: {agent.recovery.is_recovery_enabled()}")

    # Run Flask app
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    main()
