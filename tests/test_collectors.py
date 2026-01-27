"""Test suite for data collectors."""

import pytest
import asyncio
import os
import tempfile
from unittest.mock import Mock, MagicMock, patch, mock_open
from datetime import datetime

# Import collectors
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.log_collector import LogCollector
from collectors.heap_dump_collector import HeapDumpCollector
from collectors.metrics_collector import MetricsCollector


# Test Configuration
@pytest.fixture
def test_config():
    """Provide test configuration."""
    return {
        'ec2': {
            'connection_timeout': 30,
            'command_timeout': 300,
            'ssh': {
                'port': 22,
                'username': 'ec2-user'
            }
        },
        'efs': {
            'logs_path': '/mnt/efs/logs',
            'heap_dumps_path': '/mnt/efs/heap-dumps',
            'max_log_size_mb': 500,
            'max_heap_dump_size_mb': 2048,
            'collection_timeout': 600
        },
        'log_collection': {
            'patterns': ['*.log', 'catalina.out'],
            'exclude_patterns': ['*.gz'],
            'max_age_days': 7,
            'include_system_logs': True,
            'system_log_paths': ['/var/log/messages']
        },
        'heap_dump_collection': {
            'patterns': ['*.hprof'],
            'max_files': 3
        }
    }


class TestLogCollector:
    """Test cases for LogCollector."""

    @pytest.fixture
    def log_collector(self, test_config):
        """Create LogCollector instance."""
        return LogCollector(test_config)

    @pytest.mark.asyncio
    async def test_collect_logs_success(self, log_collector):
        """Test successful log collection."""
        with patch.object(log_collector, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.open_sftp.return_value = mock_sftp

            # Mock successful collection
            with patch.object(log_collector, '_collect_application_logs') as mock_app_logs:
                mock_app_logs.return_value = {
                    'files': [{'remote_path': '/test.log', 'local_path': '/tmp/test.log', 'size': 1024}],
                    'total_size': 1024,
                    'errors': []
                }

                with patch.object(log_collector, '_collect_system_logs') as mock_sys_logs:
                    mock_sys_logs.return_value = {
                        'files': [],
                        'total_size': 0,
                        'errors': []
                    }

                    with tempfile.TemporaryDirectory() as tmpdir:
                        result = await log_collector.collect_logs(
                            '10.0.0.1',
                            '/path/to/key.pem',
                            tmpdir
                        )

                        assert result['success'] is True
                        assert result['total_files'] == 1
                        assert result['total_size_mb'] > 0

    @pytest.mark.asyncio
    async def test_collect_logs_connection_failure(self, log_collector):
        """Test log collection with SSH connection failure."""
        with patch.object(log_collector, '_create_ssh_client') as mock_ssh:
            mock_ssh.side_effect = Exception("Connection refused")

            with tempfile.TemporaryDirectory() as tmpdir:
                result = await log_collector.collect_logs(
                    '10.0.0.1',
                    '/path/to/key.pem',
                    tmpdir
                )

                assert result['success'] is False
                assert 'Connection refused' in result['error']

    @pytest.mark.asyncio
    async def test_analyze_logs_preview(self, log_collector):
        """Test log preview analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sample log file
            log_file = os.path.join(tmpdir, 'test.log')
            with open(log_file, 'w') as f:
                f.write('ERROR: Connection failed\n')
                f.write('WARN: Retry attempt\n')
                f.write('Exception in thread main\n')
                f.write('OutOfMemoryError: Java heap space\n')

            log_files = [{'local_path': log_file}]
            result = await log_collector.analyze_logs_preview(log_files)

            assert result['error_count'] > 0
            assert result['warning_count'] > 0
            assert result['exception_count'] > 0
            assert result['oom_indicators'] > 0
            assert result['severity'] == 'critical'


class TestHeapDumpCollector:
    """Test cases for HeapDumpCollector."""

    @pytest.fixture
    def heap_collector(self, test_config):
        """Create HeapDumpCollector instance."""
        return HeapDumpCollector(test_config)

    @pytest.mark.asyncio
    async def test_collect_heap_dumps_success(self, heap_collector):
        """Test successful heap dump collection."""
        with patch.object(heap_collector, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.open_sftp.return_value = mock_sftp

            # Mock file finding
            with patch.object(heap_collector, '_find_remote_files') as mock_find:
                mock_find.return_value = ['/mnt/efs/heap-dumps/test.hprof']

                # Mock file stat
                mock_stat = MagicMock()
                mock_stat.st_size = 1024 * 1024  # 1MB
                mock_stat.st_mtime = datetime.now().timestamp()
                mock_sftp.stat.return_value = mock_stat

                # Mock file download
                mock_sftp.get = MagicMock()

                with tempfile.TemporaryDirectory() as tmpdir:
                    result = await heap_collector.collect_heap_dumps(
                        '10.0.0.1',
                        '/path/to/key.pem',
                        tmpdir
                    )

                    assert result['success'] is True
                    assert result['total_files'] == 1

    @pytest.mark.asyncio
    async def test_collect_heap_dumps_size_limit(self, heap_collector):
        """Test heap dump collection respects size limits."""
        with patch.object(heap_collector, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_sftp = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.open_sftp.return_value = mock_sftp

            with patch.object(heap_collector, '_find_remote_files') as mock_find:
                mock_find.return_value = ['/mnt/efs/heap-dumps/huge.hprof']

                # Mock huge file
                mock_stat = MagicMock()
                mock_stat.st_size = 5000 * 1024 * 1024  # 5GB - exceeds max
                mock_stat.st_mtime = datetime.now().timestamp()
                mock_sftp.stat.return_value = mock_stat

                with tempfile.TemporaryDirectory() as tmpdir:
                    result = await heap_collector.collect_heap_dumps(
                        '10.0.0.1',
                        '/path/to/key.pem',
                        tmpdir
                    )

                    assert result['success'] is True
                    assert result['total_files'] == 0  # File skipped due to size
                    assert len(result['errors']) > 0


class TestMetricsCollector:
    """Test cases for MetricsCollector."""

    @pytest.fixture
    def metrics_collector(self, test_config):
        """Create MetricsCollector instance."""
        return MetricsCollector(test_config)

    @pytest.mark.asyncio
    async def test_collect_current_metrics_success(self, metrics_collector):
        """Test successful metrics collection."""
        with patch.object(metrics_collector, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            # Mock command execution
            async def mock_exec(client, cmd, timeout=10):
                if 'Cpu' in cmd:
                    return '45.5'
                elif 'free' in cmd:
                    return '75.2'
                elif 'df' in cmd:
                    return '60'
                elif 'loadavg' in cmd:
                    return '1.5 2.0 1.8'
                elif 'java' in cmd:
                    return '12345 10.5 25.3 /usr/bin/java'
                elif 'nlwp' in cmd:
                    return '150'
                elif 'ss' in cmd:
                    return '250'
                elif 'uptime' in cmd:
                    return 'up 5 days'
                return ''

            with patch.object(metrics_collector, '_exec_command', side_effect=mock_exec):
                result = await metrics_collector.collect_current_metrics(
                    '10.0.0.1',
                    '/path/to/key.pem'
                )

                assert result['success'] is True
                assert result['cpu_percent'] == 45.5
                assert result['memory_percent'] == 75.2
                assert result['disk_percent'] == 60.0
                assert result['java_process']['running'] is True
                assert result['java_process']['pid'] == '12345'

    @pytest.mark.asyncio
    async def test_collect_metrics_java_not_running(self, metrics_collector):
        """Test metrics collection when Java process is not running."""
        with patch.object(metrics_collector, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            async def mock_exec(client, cmd, timeout=10):
                if 'java' in cmd:
                    return None  # Java process not found
                return '50'

            with patch.object(metrics_collector, '_exec_command', side_effect=mock_exec):
                result = await metrics_collector.collect_current_metrics(
                    '10.0.0.1',
                    '/path/to/key.pem'
                )

                assert result['success'] is True
                assert result['java_process']['running'] is False

    def test_analyze_metrics_critical(self, metrics_collector):
        """Test metrics analysis identifies critical issues."""
        metrics = {
            'success': True,
            'cpu_percent': 95.0,
            'memory_percent': 92.0,
            'disk_percent': 88.0,
            'java_process': {'running': False}
        }

        analysis = metrics_collector.analyze_metrics(metrics)

        assert analysis['severity'] == 'critical'
        assert analysis['issues_count'] >= 2
        assert any(issue['type'] == 'critical_cpu' for issue in analysis['issues'])
        assert any(issue['type'] == 'java_not_running' for issue in analysis['issues'])

    def test_analyze_metrics_normal(self, metrics_collector):
        """Test metrics analysis with normal values."""
        metrics = {
            'success': True,
            'cpu_percent': 45.0,
            'memory_percent': 60.0,
            'disk_percent': 50.0,
            'java_process': {'running': True}
        }

        analysis = metrics_collector.analyze_metrics(metrics)

        assert analysis['severity'] == 'normal'
        assert analysis['issues_count'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
