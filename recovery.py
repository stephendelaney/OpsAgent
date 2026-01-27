"""Optional recovery module for automated Java node restart.

This module is disabled by default. Operations personnel should manually
restart nodes after reviewing the analysis. Enable via config if automation is desired.
"""

import asyncio
from datetime import datetime
from typing import Dict, Optional
import logging
import paramiko
import time

logger = logging.getLogger(__name__)


class NodeRecovery:
    """Handles automated restart and health checking of Java nodes (OPTIONAL)."""

    def __init__(self, config: Dict):
        """
        Initialize the NodeRecovery.

        Args:
            config: Configuration dictionary containing recovery settings
        """
        self.config = config
        self.recovery_config = config.get('recovery', {})
        self.ssh_config = config.get('ec2', {}).get('ssh', {})
        self.java_config = config.get('java_node', {})

        self.auto_restart_enabled = self.recovery_config.get('auto_restart', False)
        self.max_attempts = self.recovery_config.get('max_restart_attempts', 3)
        self.restart_delay = self.recovery_config.get('restart_delay', 30)

    async def attempt_recovery(
        self,
        instance_ip: str,
        ssh_key_path: str
    ) -> Dict:
        """
        Attempt to recover the failed Java node.

        Args:
            instance_ip: IP address of the EC2 instance
            ssh_key_path: Path to SSH private key

        Returns:
            Dictionary containing recovery results
        """
        if not self.auto_restart_enabled:
            logger.info("Auto-restart is disabled. Skipping recovery.")
            return {
                'attempted': False,
                'reason': 'Auto-restart disabled in configuration',
                'message': 'Manual restart required by operations team',
                'timestamp': datetime.utcnow().isoformat()
            }

        logger.info(f"Attempting automated recovery for instance {instance_ip}")

        result = {
            'attempted': True,
            'success': False,
            'attempts': [],
            'timestamp': datetime.utcnow().isoformat()
        }

        for attempt in range(1, self.max_attempts + 1):
            logger.info(f"Recovery attempt {attempt} of {self.max_attempts}")

            attempt_result = await self._restart_node(instance_ip, ssh_key_path)
            result['attempts'].append(attempt_result)

            if attempt_result.get('success'):
                # Check if node is healthy
                health_check = await self._check_node_health(instance_ip, ssh_key_path)
                attempt_result['health_check'] = health_check

                if health_check.get('healthy'):
                    result['success'] = True
                    result['message'] = f'Node successfully recovered on attempt {attempt}'
                    logger.info(f"Node recovered successfully on attempt {attempt}")
                    return result
                else:
                    logger.warning(f"Node restarted but health check failed on attempt {attempt}")
            else:
                logger.error(f"Restart failed on attempt {attempt}")

            # Wait before next attempt
            if attempt < self.max_attempts:
                logger.info(f"Waiting {self.restart_delay}s before next attempt")
                await asyncio.sleep(self.restart_delay)

        result['message'] = f'All {self.max_attempts} recovery attempts failed'
        logger.error(result['message'])
        return result

    async def _restart_node(
        self,
        instance_ip: str,
        ssh_key_path: str
    ) -> Dict:
        """Execute restart script on the node."""
        restart_result = {
            'timestamp': datetime.utcnow().isoformat(),
            'success': False
        }

        try:
            ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)

            restart_script = self.java_config.get('restart_script', '/opt/java-app/bin/restart.sh')
            command_timeout = self.config.get('ec2', {}).get('command_timeout', 300)

            logger.info(f"Executing restart script: {restart_script}")

            stdin, stdout, stderr = ssh_client.exec_command(
                restart_script,
                timeout=command_timeout
            )

            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            ssh_client.close()

            restart_result['exit_status'] = exit_status
            restart_result['output'] = output
            restart_result['error'] = error

            if exit_status == 0:
                restart_result['success'] = True
                restart_result['message'] = 'Restart script executed successfully'
                logger.info("Restart script completed successfully")
            else:
                restart_result['message'] = f'Restart script failed with exit code {exit_status}'
                logger.error(f"Restart script failed: {error}")

        except Exception as e:
            restart_result['error'] = str(e)
            restart_result['message'] = f'Error executing restart: {str(e)}'
            logger.error(f"Error during restart: {str(e)}", exc_info=True)

        return restart_result

    async def _check_node_health(
        self,
        instance_ip: str,
        ssh_key_path: str,
        max_wait_time: int = 300
    ) -> Dict:
        """
        Check if the node is healthy after restart.

        Args:
            instance_ip: IP address of the instance
            ssh_key_path: Path to SSH private key
            max_wait_time: Maximum time to wait for health (seconds)

        Returns:
            Health check results
        """
        health_result = {
            'healthy': False,
            'checks_performed': [],
            'timestamp': datetime.utcnow().isoformat()
        }

        check_interval = self.java_config.get('health_check_interval', 10)
        start_time = time.time()

        logger.info(f"Starting health checks (max wait: {max_wait_time}s)")

        while time.time() - start_time < max_wait_time:
            try:
                ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)

                # Check 1: Java process running
                java_check_cmd = "ps aux | grep '[j]ava' | wc -l"
                stdin, stdout, stderr = ssh_client.exec_command(java_check_cmd, timeout=10)
                java_count = int(stdout.read().decode('utf-8').strip())

                process_check = {
                    'type': 'java_process',
                    'healthy': java_count > 0,
                    'timestamp': datetime.utcnow().isoformat()
                }
                health_result['checks_performed'].append(process_check)

                if not process_check['healthy']:
                    logger.debug("Java process not running yet")
                    ssh_client.close()
                    await asyncio.sleep(check_interval)
                    continue

                # Check 2: Port listening (if specified)
                expected_port = self.java_config.get('expected_port')
                if expected_port:
                    port_check_cmd = f"ss -tln | grep ':{expected_port}' | wc -l"
                    stdin, stdout, stderr = ssh_client.exec_command(port_check_cmd, timeout=10)
                    port_listening = int(stdout.read().decode('utf-8').strip()) > 0

                    port_check = {
                        'type': 'port_listening',
                        'port': expected_port,
                        'healthy': port_listening,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    health_result['checks_performed'].append(port_check)

                    if not port_listening:
                        logger.debug(f"Port {expected_port} not listening yet")
                        ssh_client.close()
                        await asyncio.sleep(check_interval)
                        continue

                # Check 3: HTTP health endpoint (if configured)
                health_url = self.java_config.get('health_check_url')
                if health_url:
                    health_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {health_url}"
                    stdin, stdout, stderr = ssh_client.exec_command(health_cmd, timeout=10)
                    http_code = stdout.read().decode('utf-8').strip()

                    http_check = {
                        'type': 'http_health',
                        'url': health_url,
                        'http_code': http_code,
                        'healthy': http_code == '200',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    health_result['checks_performed'].append(http_check)

                    if http_code != '200':
                        logger.debug(f"Health endpoint returned {http_code}")
                        ssh_client.close()
                        await asyncio.sleep(check_interval)
                        continue

                # All checks passed
                ssh_client.close()
                health_result['healthy'] = True
                health_result['message'] = 'All health checks passed'
                logger.info("Node is healthy")
                return health_result

            except Exception as e:
                logger.debug(f"Health check error (will retry): {str(e)}")
                await asyncio.sleep(check_interval)

        # Timeout reached
        health_result['message'] = f'Health checks timed out after {max_wait_time}s'
        logger.warning(health_result['message'])
        return health_result

    def _create_ssh_client(self, instance_ip: str, ssh_key_path: str) -> paramiko.SSHClient:
        """Create and configure SSH client."""
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        username = self.ssh_config.get('username', 'ec2-user')
        port = self.ssh_config.get('port', 22)
        timeout = self.config.get('ec2', {}).get('connection_timeout', 30)

        ssh_client.connect(
            hostname=instance_ip,
            port=port,
            username=username,
            key_filename=ssh_key_path,
            timeout=timeout
        )

        return ssh_client

    def is_recovery_enabled(self) -> bool:
        """Check if automated recovery is enabled."""
        return self.auto_restart_enabled
