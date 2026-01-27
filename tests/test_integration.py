"""Integration tests for complete OpsAgent workflow."""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OpAgent import OpAgent


@pytest.fixture
def test_config():
    """Complete test configuration."""
    return {
        'aws': {
            'region': 'us-east-1',
            'secrets_manager': {'enabled': False}
        },
        'ec2': {
            'connection_timeout': 30,
            'ssh': {'port': 22, 'username': 'ec2-user', 'key_path': '/tmp/test-key.pem'}
        },
        'efs': {
            'logs_path': '/mnt/efs/logs',
            'heap_dumps_path': '/mnt/efs/heap-dumps',
            'max_log_size_mb': 500
        },
        'log_collection': {
            'patterns': ['*.log'],
            'exclude_patterns': ['*.gz'],
            'max_age_days': 7
        },
        'heap_dump_collection': {
            'patterns': ['*.hprof'],
            'max_files': 3
        },
        'java_node': {
            'restart_script': '/opt/java-app/bin/restart.sh',
            'expected_port': 8080
        },
        'llm': {
            'provider': 'anthropic',
            'anthropic': {
                'model': 'claude-sonnet-4-5-20250929',
                'api_key_env': 'ANTHROPIC_API_KEY',
                'max_tokens': 16000
            }
        },
        'alert_handler': {
            'monit': {'webhook_port': 8000, 'authentication': False}
        },
        'notifications': {
            'slack': {'enabled': False},
            'pagerduty': {'enabled': False}
        },
        'recovery': {
            'auto_restart': False,
            'create_incident_report': True,
            'incident_report_path': '/tmp/incidents'
        },
        'logging': {
            'level': 'INFO',
            'format': 'json',
            'console_output': True,
            'file': '/tmp/ops-agent.log'
        }
    }


@pytest.fixture
def sample_alert():
    """Sample Monit alert."""
    return {
        'service': 'java-app',
        'event': 'Does not exist',
        'description': 'Process is not running',
        'instance_ip': '10.0.1.50',
        'instance_id': 'i-1234567890abcdef0'
    }


class TestOpAgentIntegration:
    """Integration tests for OpsAgent."""

    @pytest.mark.asyncio
    async def test_full_workflow_without_recovery(self, test_config, sample_alert):
        """Test complete workflow without automated recovery."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(test_config, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
                agent = OpAgent(config_path)

                # Mock all collection methods
                async def mock_collect_metrics(ip, key):
                    return {
                        'success': True,
                        'cpu_percent': 85.0,
                        'memory_percent': 90.0,
                        'java_process': {'running': False},
                        'analysis': {
                            'severity': 'critical',
                            'issues': [{'type': 'java_not_running'}]
                        }
                    }

                async def mock_collect_logs(ip, key, output):
                    return {
                        'success': True,
                        'collected_files': [],
                        'total_files': 5,
                        'preview_analysis': {
                            'error_count': 10,
                            'oom_indicators': 2,
                            'severity': 'critical'
                        }
                    }

                async def mock_analyze(logs, metrics, heap=None, alert=None):
                    return {
                        'success': True,
                        'root_cause_analysis': 'Test analysis',
                        'context': {
                            'logs_collected': 5,
                            'metrics_severity': 'critical',
                            'heap_dumps_collected': 0
                        },
                        'llm_model': 'test-model'
                    }

                async def mock_summary(analysis):
                    return "Java node failed due to OOM"

                async def mock_notify(summary, analysis, severity, instance):
                    return {'channels': {}}

                agent.metrics_collector.collect_current_metrics = mock_collect_metrics
                agent.log_collector.collect_logs = mock_collect_logs
                agent.log_collector.analyze_logs_preview = lambda x: {}
                agent.analyzer.analyze_incident = mock_analyze
                agent.analyzer.generate_executive_summary = mock_summary
                agent.notifier.send_incident_alert = mock_notify

                result = await agent.handle_alert(sample_alert)

                assert 'incident_id' in result
                assert result['stages']['metrics_collection']['success'] is True
                assert result['stages']['log_collection']['success'] is True
                assert result['stages']['analysis']['success'] is True
                assert result['stages']['recovery']['attempted'] is False
                assert 'Manual' in result['stages']['recovery']['action_required']

        finally:
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_workflow_with_heap_dump_collection(self, test_config, sample_alert):
        """Test workflow that triggers heap dump collection."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(test_config, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
                agent = OpAgent(config_path)

                # Mock metrics showing high memory
                async def mock_collect_metrics(ip, key):
                    return {
                        'success': True,
                        'memory_percent': 95.0,
                        'java_process': {'running': False},
                        'analysis': {
                            'severity': 'critical',
                            'issues': [
                                {'type': 'critical_memory', 'value': 95.0}
                            ]
                        }
                    }

                async def mock_collect_logs(ip, key, output):
                    return {
                        'success': True,
                        'collected_files': [],
                        'total_files': 3,
                        'preview_analysis': {
                            'oom_indicators': 5,  # High OOM indicators
                            'severity': 'critical'
                        }
                    }

                async def mock_collect_heaps(ip, key, output):
                    return {
                        'success': True,
                        'collected_files': [{'size': 500000000}],
                        'total_files': 1
                    }

                agent.metrics_collector.collect_current_metrics = mock_collect_metrics
                agent.log_collector.collect_logs = mock_collect_logs
                agent.log_collector.analyze_logs_preview = lambda x: {}
                agent.heap_dump_collector.collect_heap_dumps = mock_collect_heaps
                agent.analyzer.analyze_incident = lambda **k: {
                    'success': True,
                    'root_cause_analysis': 'OOM',
                    'context': {}
                }
                agent.analyzer.generate_executive_summary = lambda x: "OOM issue"
                agent.notifier.send_incident_alert = lambda **k: {'channels': {}}

                result = await agent.handle_alert(sample_alert)

                assert result['stages']['heap_dump_collection']['success'] is True
                assert result['stages']['heap_dump_collection']['files_collected'] == 1

        finally:
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_workflow_with_automated_recovery(self, test_config, sample_alert):
        """Test workflow with automated recovery enabled."""
        # Enable recovery
        test_config['recovery']['auto_restart'] = True

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(test_config, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
                agent = OpAgent(config_path)

                # Mock all methods
                agent.metrics_collector.collect_current_metrics = lambda ip, key: {
                    'success': True,
                    'analysis': {'severity': 'critical', 'issues': []}
                }
                agent.log_collector.collect_logs = lambda ip, key, out: {
                    'success': True,
                    'collected_files': [],
                    'total_files': 1,
                    'preview_analysis': {}
                }
                agent.log_collector.analyze_logs_preview = lambda x: {}
                agent.analyzer.analyze_incident = lambda **k: {
                    'success': True,
                    'root_cause_analysis': 'Test',
                    'context': {}
                }
                agent.analyzer.generate_executive_summary = lambda x: "Test"
                agent.notifier.send_incident_alert = lambda **k: {'channels': {}}

                # Mock recovery
                async def mock_recovery(ip, key):
                    return {
                        'attempted': True,
                        'success': True,
                        'message': 'Recovery successful',
                        'attempts': [{'success': True}]
                    }

                agent.recovery.attempt_recovery = mock_recovery
                agent.notifier.send_recovery_notification = lambda **k: {}

                result = await agent.handle_alert(sample_alert)

                assert result['stages']['recovery']['attempted'] is True
                assert result['stages']['recovery']['success'] is True

        finally:
            os.unlink(config_path)

    @pytest.mark.asyncio
    async def test_workflow_handles_collection_failures(self, test_config, sample_alert):
        """Test that workflow continues even if some collectors fail."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(test_config, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
                agent = OpAgent(config_path)

                # Metrics fail
                agent.metrics_collector.collect_current_metrics = lambda ip, key: {
                    'success': False,
                    'error': 'Connection failed'
                }

                # Logs succeed
                agent.log_collector.collect_logs = lambda ip, key, out: {
                    'success': True,
                    'collected_files': [],
                    'total_files': 2,
                    'preview_analysis': {'severity': 'warning'}
                }
                agent.log_collector.analyze_logs_preview = lambda x: {}

                # Analysis still runs
                agent.analyzer.analyze_incident = lambda **k: {
                    'success': True,
                    'root_cause_analysis': 'Partial analysis',
                    'context': {}
                }
                agent.analyzer.generate_executive_summary = lambda x: "Issue detected"
                agent.notifier.send_incident_alert = lambda **k: {'channels': {}}

                result = await agent.handle_alert(sample_alert)

                # Workflow completes despite metrics failure
                assert result['stages']['metrics_collection']['success'] is False
                assert result['stages']['log_collection']['success'] is True
                assert result['stages']['analysis']['success'] is True

        finally:
            os.unlink(config_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
