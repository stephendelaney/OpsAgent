"""Simplified metrics collection module - current state only."""

import asyncio
from datetime import datetime
from typing import Dict
import logging
import paramiko

logger = logging.getLogger(__name__)


class MetricsCollector:
    """Collects current system metrics from EC2 instances."""

    def __init__(self, config: Dict):
        """
        Initialize the MetricsCollector.

        Args:
            config: Configuration dictionary containing metrics settings
        """
        self.config = config
        self.ssh_config = config.get('ec2', {}).get('ssh', {})

    async def collect_current_metrics(
        self,
        instance_ip: str,
        ssh_key_path: str
    ) -> Dict[str, any]:
        """
        Collect current system state metrics.

        Args:
            instance_ip: IP address of the instance
            ssh_key_path: Path to SSH private key

        Returns:
            Dictionary containing current metrics
        """
        logger.info(f"Collecting current metrics from {instance_ip}")

        metrics = {
            'instance_ip': instance_ip,
            'timestamp': datetime.utcnow().isoformat(),
            'success': True
        }

        try:
            ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)

            # CPU usage
            cpu_cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
            cpu_result = await self._exec_command(ssh_client, cpu_cmd)
            metrics['cpu_percent'] = float(cpu_result) if cpu_result else None

            # Memory usage
            mem_cmd = "free | grep Mem | awk '{printf \"%.1f\", ($3/$2) * 100.0}'"
            mem_result = await self._exec_command(ssh_client, mem_cmd)
            metrics['memory_percent'] = float(mem_result) if mem_result else None

            # Disk usage
            disk_cmd = "df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1"
            disk_result = await self._exec_command(ssh_client, disk_cmd)
            metrics['disk_percent'] = float(disk_result) if disk_result else None

            # Load averages
            load_cmd = "cat /proc/loadavg | awk '{print $1,$2,$3}'"
            load_result = await self._exec_command(ssh_client, load_cmd)
            if load_result:
                loads = load_result.split()
                metrics['load_average'] = {
                    '1min': float(loads[0]) if len(loads) > 0 else None,
                    '5min': float(loads[1]) if len(loads) > 1 else None,
                    '15min': float(loads[2]) if len(loads) > 2 else None
                }

            # Java process status
            java_cmd = "ps aux | grep '[j]ava' | head -1 | awk '{print $2,$3,$4,$11}'"
            java_result = await self._exec_command(ssh_client, java_cmd)
            if java_result:
                parts = java_result.split(None, 3)
                metrics['java_process'] = {
                    'running': True,
                    'pid': parts[0] if len(parts) > 0 else None,
                    'cpu_percent': float(parts[1]) if len(parts) > 1 else None,
                    'memory_percent': float(parts[2]) if len(parts) > 2 else None,
                    'command': parts[3] if len(parts) > 3 else None
                }

                # Thread count for Java process
                if metrics['java_process']['pid']:
                    thread_cmd = f"ps -o nlwp {metrics['java_process']['pid']} | tail -1"
                    thread_result = await self._exec_command(ssh_client, thread_cmd)
                    metrics['java_process']['thread_count'] = int(thread_result) if thread_result else None
            else:
                metrics['java_process'] = {'running': False}

            # Network connections
            conn_cmd = "ss -tan state established | wc -l"
            conn_result = await self._exec_command(ssh_client, conn_cmd)
            metrics['established_connections'] = int(conn_result) - 1 if conn_result else None  # -1 for header

            # Uptime
            uptime_cmd = "uptime -p"
            uptime_result = await self._exec_command(ssh_client, uptime_cmd)
            metrics['uptime'] = uptime_result if uptime_result else None

            ssh_client.close()
            logger.info(f"Metrics collection complete for {instance_ip}")

        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}", exc_info=True)
            metrics['success'] = False
            metrics['error'] = str(e)

        return metrics

    async def _exec_command(
        self,
        ssh_client: paramiko.SSHClient,
        command: str,
        timeout: int = 10
    ) -> str:
        """Execute command and return output."""
        try:
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            if error and not output:
                logger.warning(f"Command error: {error}")
                return None

            return output if output else None

        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return None

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

    def analyze_metrics(self, metrics: Dict) -> Dict:
        """
        Quick analysis of metrics to identify critical issues.

        Args:
            metrics: Collected metrics dictionary

        Returns:
            Analysis with severity and issues found
        """
        issues = []
        severity = 'normal'

        if not metrics.get('success'):
            return {
                'severity': 'error',
                'issues': [{'type': 'collection_failed', 'message': metrics.get('error', 'Unknown error')}]
            }

        # Check CPU
        cpu = metrics.get('cpu_percent')
        if cpu and cpu > 90:
            issues.append({'type': 'critical_cpu', 'value': cpu, 'message': f'CPU at {cpu}%'})
            severity = 'critical'
        elif cpu and cpu > 75:
            issues.append({'type': 'high_cpu', 'value': cpu, 'message': f'CPU at {cpu}%'})
            if severity == 'normal':
                severity = 'warning'

        # Check Memory
        mem = metrics.get('memory_percent')
        if mem and mem > 90:
            issues.append({'type': 'critical_memory', 'value': mem, 'message': f'Memory at {mem}%'})
            severity = 'critical'
        elif mem and mem > 80:
            issues.append({'type': 'high_memory', 'value': mem, 'message': f'Memory at {mem}%'})
            if severity == 'normal':
                severity = 'warning'

        # Check Java process
        java = metrics.get('java_process', {})
        if not java.get('running'):
            issues.append({'type': 'java_not_running', 'message': 'Java process not found'})
            severity = 'critical'

        # Check disk
        disk = metrics.get('disk_percent')
        if disk and disk > 90:
            issues.append({'type': 'critical_disk', 'value': disk, 'message': f'Disk at {disk}%'})
            if severity != 'critical':
                severity = 'warning'

        return {
            'severity': severity,
            'issues_count': len(issues),
            'issues': issues
        }
