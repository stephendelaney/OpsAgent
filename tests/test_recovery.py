"""Test suite for the Recovery module."""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recovery import NodeRecovery


@pytest.fixture
def test_config_disabled():
    """Test configuration with recovery disabled."""
    return {
        'ec2': {
            'connection_timeout': 30,
            'command_timeout': 300,
            'ssh': {'port': 22, 'username': 'ec2-user'}
        },
        'java_node': {
            'restart_script': '/opt/java-app/bin/restart.sh',
            'expected_port': 8080,
            'health_check_url': 'http://localhost:8080/health',
            'health_check_interval': 10
        },
        'recovery': {
            'auto_restart': False,
            'max_restart_attempts': 3,
            'restart_delay': 30
        }
    }


@pytest.fixture
def test_config_enabled():
    """Test configuration with recovery enabled."""
    config = test_config_disabled()
    config['recovery']['auto_restart'] = True
    return config


class TestNodeRecovery:
    """Test cases for NodeRecovery."""

    def test_recovery_disabled_by_default(self, test_config_disabled):
        """Test that recovery is disabled by default."""
        recovery = NodeRecovery(test_config_disabled)

        assert recovery.is_recovery_enabled() is False
        assert recovery.auto_restart_enabled is False

    @pytest.mark.asyncio
    async def test_attempt_recovery_disabled(self, test_config_disabled):
        """Test recovery attempt when disabled."""
        recovery = NodeRecovery(test_config_disabled)

        result = await recovery.attempt_recovery('10.0.0.1', '/path/to/key.pem')

        assert result['attempted'] is False
        assert 'disabled' in result['reason'].lower()
        assert 'Manual restart required' in result['message']

    @pytest.mark.asyncio
    async def test_attempt_recovery_success(self, test_config_enabled):
        """Test successful recovery attempt."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_restart_node') as mock_restart:
            mock_restart.return_value = {
                'success': True,
                'exit_status': 0,
                'message': 'Restart successful'
            }

            with patch.object(recovery, '_check_node_health') as mock_health:
                mock_health.return_value = {
                    'healthy': True,
                    'checks_performed': [
                        {'type': 'java_process', 'healthy': True},
                        {'type': 'port_listening', 'healthy': True}
                    ]
                }

                result = await recovery.attempt_recovery('10.0.0.1', '/path/to/key.pem')

                assert result['attempted'] is True
                assert result['success'] is True
                assert len(result['attempts']) == 1

    @pytest.mark.asyncio
    async def test_attempt_recovery_multiple_attempts(self, test_config_enabled):
        """Test recovery with multiple failed attempts."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_restart_node') as mock_restart:
            # First two attempts fail, third succeeds
            mock_restart.side_effect = [
                {'success': False, 'message': 'Failed attempt 1'},
                {'success': False, 'message': 'Failed attempt 2'},
                {'success': True, 'exit_status': 0}
            ]

            with patch.object(recovery, '_check_node_health') as mock_health:
                mock_health.return_value = {'healthy': True}

                result = await recovery.attempt_recovery('10.0.0.1', '/path/to/key.pem')

                assert result['attempted'] is True
                assert len(result['attempts']) == 3
                assert mock_restart.call_count == 3

    @pytest.mark.asyncio
    async def test_restart_node_success(self, test_config_enabled):
        """Test successful node restart."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            # Mock command execution
            mock_channel = MagicMock()
            mock_channel.recv_exit_status.return_value = 0

            mock_stdout = MagicMock()
            mock_stdout.channel = mock_channel
            mock_stdout.read.return_value = b'Restart successful'

            mock_stderr = MagicMock()
            mock_stderr.read.return_value = b''

            mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

            result = await recovery._restart_node('10.0.0.1', '/path/to/key.pem')

            assert result['success'] is True
            assert result['exit_status'] == 0

    @pytest.mark.asyncio
    async def test_restart_node_script_failure(self, test_config_enabled):
        """Test node restart when script fails."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            mock_channel = MagicMock()
            mock_channel.recv_exit_status.return_value = 1

            mock_stdout = MagicMock()
            mock_stdout.channel = mock_channel
            mock_stdout.read.return_value = b''

            mock_stderr = MagicMock()
            mock_stderr.read.return_value = b'Script failed: command not found'

            mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

            result = await recovery._restart_node('10.0.0.1', '/path/to/key.pem')

            assert result['success'] is False
            assert result['exit_status'] == 1

    @pytest.mark.asyncio
    async def test_check_node_health_all_pass(self, test_config_enabled):
        """Test health check when all checks pass."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            # Mock successful health checks
            def mock_exec_command(cmd, timeout=10):
                stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
                if 'java' in cmd:
                    stdout.read.return_value = b'1'  # Java process running
                elif 'ss -tln' in cmd:
                    stdout.read.return_value = b'1'  # Port listening
                elif 'curl' in cmd:
                    stdout.read.return_value = b'200'  # Health endpoint OK
                return stdin, stdout, stderr

            mock_client.exec_command = mock_exec_command

            result = await recovery._check_node_health(
                '10.0.0.1',
                '/path/to/key.pem',
                max_wait_time=30
            )

            assert result['healthy'] is True
            assert len(result['checks_performed']) > 0

    @pytest.mark.asyncio
    async def test_check_node_health_java_not_running(self, test_config_enabled):
        """Test health check when Java process not running."""
        recovery = NodeRecovery(test_config_enabled)

        with patch.object(recovery, '_create_ssh_client') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client

            def mock_exec_command(cmd, timeout=10):
                stdin, stdout, stderr = MagicMock(), MagicMock(), MagicMock()
                stdout.read.return_value = b'0'  # No Java process
                return stdin, stdout, stderr

            mock_client.exec_command = mock_exec_command

            with patch('asyncio.sleep', return_value=None):
                result = await recovery._check_node_health(
                    '10.0.0.1',
                    '/path/to/key.pem',
                    max_wait_time=5
                )

                assert result['healthy'] is False
                assert 'timed out' in result.get('message', '').lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
