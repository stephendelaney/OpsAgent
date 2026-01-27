"""Heap dump collection module for gathering Java heap dumps from EFS."""

import os
import asyncio
from datetime import datetime
from typing import List, Dict, Optional
import logging
import paramiko
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class HeapDumpCollector:
    """Collects Java heap dump files from EFS-mounted directories on EC2 instances."""

    def __init__(self, config: Dict):
        """
        Initialize the HeapDumpCollector.

        Args:
            config: Configuration dictionary containing EFS and heap dump settings
        """
        self.config = config
        self.efs_config = config.get('efs', {})
        self.heap_config = config.get('heap_dump_collection', {})
        self.ssh_config = config.get('ec2', {}).get('ssh', {})
        self.max_size = self.efs_config.get('max_heap_dump_size_mb', 2048) * 1024 * 1024
        self.collection_timeout = self.efs_config.get('collection_timeout', 600)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=5, max=60)
    )
    async def collect_heap_dumps(
        self,
        instance_ip: str,
        ssh_key_path: str,
        output_dir: str
    ) -> Dict[str, any]:
        """
        Collect heap dumps from the remote EC2 instance.

        Args:
            instance_ip: IP address of the EC2 instance
            ssh_key_path: Path to SSH private key
            output_dir: Local directory to store collected heap dumps

        Returns:
            Dictionary containing collection results and metadata
        """
        logger.info(f"Starting heap dump collection from instance {instance_ip}")

        os.makedirs(output_dir, exist_ok=True)

        collected_files = []
        total_size = 0
        errors = []

        try:
            ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)
            sftp = ssh_client.open_sftp()

            heap_dumps_path = self.efs_config.get('heap_dumps_path', '/mnt/efs/heap-dumps')
            patterns = self.heap_config.get('patterns', ['*.hprof', 'java_pid*.dump'])
            max_files = self.heap_config.get('max_files', 3)

            logger.info(f"Scanning for heap dumps in {heap_dumps_path}")

            # Find all heap dump files
            all_dumps = []
            for pattern in patterns:
                files = self._find_remote_files(sftp, heap_dumps_path, pattern)
                all_dumps.extend(files)

            # Sort by modification time (newest first) and limit
            sorted_dumps = sorted(
                all_dumps,
                key=lambda x: sftp.stat(x).st_mtime,
                reverse=True
            )[:max_files]

            # Collect heap dumps
            for remote_file in sorted_dumps:
                try:
                    file_stat = sftp.stat(remote_file)
                    file_size = file_stat.st_size

                    if file_size > self.max_size:
                        logger.warning(f"Heap dump exceeds max size, skipping: {remote_file}")
                        errors.append(f"File too large: {remote_file} ({file_size / (1024*1024):.2f} MB)")
                        continue

                    # Download heap dump
                    local_file = os.path.join(
                        output_dir,
                        'heap_dumps',
                        os.path.basename(remote_file)
                    )
                    os.makedirs(os.path.dirname(local_file), exist_ok=True)

                    logger.info(f"Downloading heap dump: {remote_file} ({file_size / (1024*1024):.2f} MB)")
                    sftp.get(remote_file, local_file)

                    collected_files.append({
                        'remote_path': remote_file,
                        'local_path': local_file,
                        'size': file_size,
                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                    })
                    total_size += file_size

                    logger.info(f"Successfully collected heap dump: {remote_file}")

                except Exception as e:
                    error_msg = f"Error collecting heap dump {remote_file}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)

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

            logger.info(f"Heap dump collection complete: {len(collected_files)} files, "
                       f"{result['total_size_mb']:.2f} MB")
            return result

        except Exception as e:
            logger.error(f"Failed to collect heap dumps: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'collected_files': collected_files,
                'timestamp': datetime.utcnow().isoformat()
            }

    async def generate_heap_dump_summary(self, heap_dump_path: str) -> Dict:
        """
        Generate a summary of heap dump using jmap (if available).

        Args:
            heap_dump_path: Path to the heap dump file

        Returns:
            Dictionary containing heap dump summary
        """
        logger.info(f"Generating heap dump summary for {heap_dump_path}")

        summary = {
            'file_path': heap_dump_path,
            'file_size_mb': os.path.getsize(heap_dump_path) / (1024 * 1024),
            'analysis_available': False
        }

        try:
            # Try to run jmap histogram (requires jmap to be installed)
            import subprocess

            # Check if jmap is available
            jmap_check = subprocess.run(
                ['which', 'jmap'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if jmap_check.returncode == 0:
                logger.info("Running jmap histogram analysis")

                # Run jmap histogram
                result = subprocess.run(
                    ['jmap', '-histo:live', heap_dump_path],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    summary['analysis_available'] = True
                    summary['histogram'] = self._parse_jmap_histogram(result.stdout)
                    logger.info("Heap dump histogram generated successfully")
                else:
                    logger.warning(f"jmap failed: {result.stderr}")
                    summary['error'] = result.stderr
            else:
                logger.info("jmap not available, skipping histogram analysis")
                summary['note'] = 'jmap not available for analysis'

        except subprocess.TimeoutExpired:
            logger.error("jmap analysis timed out")
            summary['error'] = 'Analysis timed out'
        except Exception as e:
            logger.error(f"Error generating heap dump summary: {str(e)}")
            summary['error'] = str(e)

        return summary

    def _parse_jmap_histogram(self, histogram_output: str) -> Dict:
        """Parse jmap histogram output."""
        lines = histogram_output.strip().split('\n')

        top_classes = []
        total_instances = 0
        total_bytes = 0

        # Skip header lines
        for line in lines:
            if line.strip().startswith('num') or line.strip().startswith('-'):
                continue

            parts = line.split()
            if len(parts) >= 4:
                try:
                    instances = int(parts[2].replace(',', ''))
                    bytes_used = int(parts[3].replace(',', ''))
                    class_name = parts[1]

                    total_instances += instances
                    total_bytes += bytes_used

                    # Keep top 20 classes
                    if len(top_classes) < 20:
                        top_classes.append({
                            'class': class_name,
                            'instances': instances,
                            'bytes': bytes_used,
                            'bytes_mb': bytes_used / (1024 * 1024)
                        })
                except (ValueError, IndexError):
                    continue

        return {
            'total_instances': total_instances,
            'total_bytes': total_bytes,
            'total_mb': total_bytes / (1024 * 1024),
            'top_classes': top_classes
        }

    async def extract_heap_dump_metadata(self, instance_ip: str, ssh_key_path: str) -> Dict:
        """
        Extract metadata about heap dumps without downloading them.

        Args:
            instance_ip: IP address of the EC2 instance
            ssh_key_path: Path to SSH private key

        Returns:
            Dictionary containing heap dump metadata
        """
        logger.info(f"Extracting heap dump metadata from {instance_ip}")

        try:
            ssh_client = self._create_ssh_client(instance_ip, ssh_key_path)
            sftp = ssh_client.open_sftp()

            heap_dumps_path = self.efs_config.get('heap_dumps_path', '/mnt/efs/heap-dumps')
            patterns = self.heap_config.get('patterns', ['*.hprof', 'java_pid*.dump'])

            all_dumps = []
            for pattern in patterns:
                files = self._find_remote_files(sftp, heap_dumps_path, pattern)
                for file in files:
                    try:
                        stat = sftp.stat(file)
                        all_dumps.append({
                            'path': file,
                            'size': stat.st_size,
                            'size_mb': stat.st_size / (1024 * 1024),
                            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'mtime': stat.st_mtime
                        })
                    except Exception as e:
                        logger.error(f"Error getting metadata for {file}: {str(e)}")

            # Sort by modification time
            all_dumps.sort(key=lambda x: x['mtime'], reverse=True)

            sftp.close()
            ssh_client.close()

            return {
                'success': True,
                'heap_dumps': all_dumps,
                'total_count': len(all_dumps),
                'total_size_mb': sum(d['size_mb'] for d in all_dumps),
                'newest': all_dumps[0] if all_dumps else None,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to extract heap dump metadata: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
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
        pattern: str
    ) -> List[str]:
        """Find files matching pattern on remote host."""
        matching_files = []

        try:
            files = sftp.listdir(base_path)

            for file in files:
                full_path = os.path.join(base_path, file)

                if self._matches_pattern(file, pattern):
                    matching_files.append(full_path)

        except Exception as e:
            logger.error(f"Error listing files in {base_path}: {str(e)}")

        return matching_files

    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """Check if filename matches glob pattern."""
        from fnmatch import fnmatch
        return fnmatch(filename, pattern)
