"""Log collection module for gathering application and system logs from EFS."""

import os
import glob
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
from pathlib import Path
import paramiko
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class LogCollector:
    """Collects log files from EFS-mounted directories on EC2 instances."""

    def __init__(self, config: Dict):
        """
        Initialize the LogCollector.

        Args:
            config: Configuration dictionary containing EFS and log collection settings
        """
        self.config = config
        self.efs_config = config.get('efs', {})
        self.log_config = config.get('log_collection', {})
        self.ssh_config = config.get('ec2', {}).get('ssh', {})
        self.max_log_size = self.efs_config.get('max_log_size_mb', 500) * 1024 * 1024
        self.collection_timeout = self.efs_config.get('collection_timeout', 600)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=60)
    )
    async def collect_logs(
        self,
        instance_ip: str,
        ssh_key_path: str,
        output_dir: str
    ) -> Dict[str, any]:
        """
        Collect logs from the remote EC2 instance.

        Args:
            instance_ip: IP address of the EC2 instance
            ssh_key_path: Path to SSH private key
            output_dir: Local directory to store collected logs

        Returns:
            Dictionary containing collection results and metadata
        """
        logger.info(f"Starting log collection from instance {instance_ip}")

        os.makedirs(output_dir, exist_ok=True)

        collected_files = []
        total_size = 0
        errors = []

        try:
            ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)
            sftp = ssh_client.open_sftp()

            # Collect application logs from EFS
            app_logs = await self._collect_application_logs(sftp, output_dir)
            collected_files.extend(app_logs['files'])
            total_size += app_logs['total_size']
            errors.extend(app_logs['errors'])

            # Collect system logs if enabled
            if self.log_config.get('include_system_logs', True):
                sys_logs = await self._collect_system_logs(sftp, output_dir)
                collected_files.extend(sys_logs['files'])
                total_size += sys_logs['total_size']
                errors.extend(sys_logs['errors'])

            sftp.close()
            ssh_client.close()

            result = {
                'success': True,
                'collected_files': collected_files,
                'total_files': len(collected_files),
                'total_size_mb': total_size / (1024 * 1024),
                'output_directory': output_dir,
                'errors': errors,
                'timestamp': datetime.utcnow().isoformat()
            }

            logger.info(f"Log collection complete: {len(collected_files)} files, "
                       f"{result['total_size_mb']:.2f} MB")
            return result

        except Exception as e:
            logger.error(f"Failed to collect logs: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'collected_files': collected_files,
                'timestamp': datetime.utcnow().isoformat()
            }

    async def _collect_application_logs(
        self,
        sftp: paramiko.SFTPClient,
        output_dir: str
    ) -> Dict:
        """Collect application logs from EFS."""
        logs_path = self.efs_config.get('logs_path', '/mnt/efs/logs')
        patterns = self.log_config.get('patterns', ['*.log'])
        exclude_patterns = self.log_config.get('exclude_patterns', [])
        max_age_days = self.log_config.get('max_age_days', 7)

        cutoff_time = datetime.now() - timedelta(days=max_age_days)

        collected_files = []
        total_size = 0
        errors = []

        try:
            logger.info(f"Scanning for logs in {logs_path}")

            # Get list of files matching patterns
            for pattern in patterns:
                try:
                    files = self._find_remote_files(sftp, logs_path, pattern, exclude_patterns)

                    for remote_file in files:
                        try:
                            # Check file age and size
                            file_stat = sftp.stat(remote_file)
                            file_mtime = datetime.fromtimestamp(file_stat.st_mtime)
                            file_size = file_stat.st_size

                            if file_mtime < cutoff_time:
                                logger.debug(f"Skipping old file: {remote_file}")
                                continue

                            if total_size + file_size > self.max_log_size:
                                logger.warning(f"Reached max log size limit, skipping: {remote_file}")
                                continue

                            # Download file
                            local_file = os.path.join(
                                output_dir,
                                'logs',
                                os.path.basename(remote_file)
                            )
                            os.makedirs(os.path.dirname(local_file), exist_ok=True)

                            sftp.get(remote_file, local_file)
                            collected_files.append({
                                'remote_path': remote_file,
                                'local_path': local_file,
                                'size': file_size,
                                'modified': file_mtime.isoformat()
                            })
                            total_size += file_size

                            logger.debug(f"Collected log: {remote_file} ({file_size} bytes)")

                        except Exception as e:
                            error_msg = f"Error collecting {remote_file}: {str(e)}"
                            logger.error(error_msg)
                            errors.append(error_msg)

                except Exception as e:
                    error_msg = f"Error scanning pattern {pattern}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)

        except Exception as e:
            error_msg = f"Error accessing logs path {logs_path}: {str(e)}"
            logger.error(error_msg)
            errors.append(error_msg)

        return {
            'files': collected_files,
            'total_size': total_size,
            'errors': errors
        }

    async def _collect_system_logs(
        self,
        sftp: paramiko.SFTPClient,
        output_dir: str
    ) -> Dict:
        """Collect system logs."""
        system_log_paths = self.log_config.get('system_log_paths', [])

        collected_files = []
        total_size = 0
        errors = []

        for log_path in system_log_paths:
            try:
                if self._remote_file_exists(sftp, log_path):
                    file_stat = sftp.stat(log_path)
                    file_size = file_stat.st_size

                    local_file = os.path.join(
                        output_dir,
                        'system_logs',
                        os.path.basename(log_path)
                    )
                    os.makedirs(os.path.dirname(local_file), exist_ok=True)

                    sftp.get(log_path, local_file)
                    collected_files.append({
                        'remote_path': log_path,
                        'local_path': local_file,
                        'size': file_size,
                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                    })
                    total_size += file_size

                    logger.debug(f"Collected system log: {log_path}")
                else:
                    logger.debug(f"System log not found: {log_path}")

            except Exception as e:
                error_msg = f"Error collecting system log {log_path}: {str(e)}"
                logger.error(error_msg)
                errors.append(error_msg)

        return {
            'files': collected_files,
            'total_size': total_size,
            'errors': errors
        }

    def _create_ssh_client(self, instance_ip: str, ssh_key_path: str) -> paramiko.SSHClient:
        """Create and configure SSH client."""
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        username = self.ssh_config.get('username', 'ec2-user')
        port = self.ssh_config.get('port', 22)
        timeout = self.config.get('ec2', {}).get('connection_timeout', 30)

        logger.info(f"Connecting to {instance_ip}:{port} as {username}")

        ssh_client.connect(
            hostname=instance_ip,
            port=port,
            username=username,
            key_filename=ssh_key_path,
            timeout=timeout
        )

        return ssh_client

    def _find_remote_files(
        self,
        sftp: paramiko.SFTPClient,
        base_path: str,
        pattern: str,
        exclude_patterns: List[str]
    ) -> List[str]:
        """Find files matching pattern on remote host."""
        matching_files = []

        try:
            # List all files in directory
            files = sftp.listdir(base_path)

            for file in files:
                full_path = os.path.join(base_path, file)

                # Check if matches include pattern
                if self._matches_pattern(file, pattern):
                    # Check if matches any exclude pattern
                    if not any(self._matches_pattern(file, excl) for excl in exclude_patterns):
                        matching_files.append(full_path)

        except Exception as e:
            logger.error(f"Error listing files in {base_path}: {str(e)}")

        return matching_files

    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches glob pattern."""
        from fnmatch import fnmatch
        return fnmatch(filename, pattern)

    def _remote_file_exists(self, sftp: paramiko.SFTPClient, path: str) -> bool:
        """Check if file exists on remote host."""
        try:
            sftp.stat(path)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    async def analyze_logs_preview(self, log_files: List[Dict]) -> Dict:
        """
        Perform quick analysis on collected logs for preview.

        Args:
            log_files: List of collected log file metadata

        Returns:
            Dictionary with preview analysis results
        """
        error_count = 0
        warning_count = 0
        exception_count = 0
        oom_indicators = 0

        for log_file in log_files:
            try:
                with open(log_file['local_path'], 'r', errors='ignore') as f:
                    # Read last 10000 lines for preview
                    lines = f.readlines()[-10000:]

                    for line in lines:
                        line_lower = line.lower()
                        if 'error' in line_lower:
                            error_count += 1
                        if 'warn' in line_lower:
                            warning_count += 1
                        if 'exception' in line_lower:
                            exception_count += 1
                        if 'outofmemory' in line_lower or 'java heap space' in line_lower:
                            oom_indicators += 1

            except Exception as e:
                logger.error(f"Error analyzing log preview {log_file['local_path']}: {str(e)}")

        return {
            'error_count': error_count,
            'warning_count': warning_count,
            'exception_count': exception_count,
            'oom_indicators': oom_indicators,
            'severity': 'critical' if oom_indicators > 0 or exception_count > 10 else 'warning'
        }
