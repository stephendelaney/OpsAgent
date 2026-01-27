"""Test suite for the Analyzer module."""

import pytest
import asyncio
import os
import tempfile
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import Analyzer


@pytest.fixture
def test_config():
    """Provide test configuration."""
    return {
        'llm': {
            'provider': 'anthropic',
            'anthropic': {
                'model': 'claude-sonnet-4-5-20250929',
                'api_key_env': 'ANTHROPIC_API_KEY',
                'max_tokens': 16000,
                'temperature': 0.3
            }
        }
    }


@pytest.fixture
def sample_logs_data():
    """Sample logs collection data."""
    return {
        'success': True,
        'collected_files': [
            {
                'remote_path': '/mnt/efs/logs/app.log',
                'local_path': '/tmp/test/app.log',
                'size': 1024000
            }
        ],
        'total_files': 1,
        'total_size_mb': 1.0,
        'preview_analysis': {
            'error_count': 25,
            'warning_count': 10,
            'exception_count': 5,
            'oom_indicators': 2,
            'severity': 'critical'
        }
    }


@pytest.fixture
def sample_metrics_data():
    """Sample metrics data."""
    return {
        'success': True,
        'cpu_percent': 85.0,
        'memory_percent': 92.0,
        'disk_percent': 65.0,
        'load_average': {'1min': 4.5, '5min': 3.2, '15min': 2.8},
        'java_process': {
            'running': False
        },
        'uptime': 'up 3 days',
        'analysis': {
            'severity': 'critical',
            'issues_count': 2,
            'issues': [
                {'type': 'critical_memory', 'value': 92.0, 'message': 'Memory at 92%'},
                {'type': 'java_not_running', 'message': 'Java process not found'}
            ]
        }
    }


@pytest.fixture
def sample_alert_context():
    """Sample Monit alert context."""
    return {
        'service': 'java-app',
        'event': 'Does not exist',
        'description': 'Process is not running',
        'timestamp': datetime.utcnow().isoformat(),
        'instance_ip': '10.0.1.50',
        'instance_id': 'i-1234567890abcdef0'
    }


class TestAnalyzer:
    """Test cases for Analyzer."""

    @pytest.fixture
    def analyzer(self, test_config):
        """Create Analyzer instance."""
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}):
            return Analyzer(test_config)

    @pytest.mark.asyncio
    async def test_analyze_incident_success(self, analyzer, sample_logs_data,
                                           sample_metrics_data, sample_alert_context):
        """Test successful incident analysis."""
        # Mock LLM response
        mock_analysis = """### 1. ROOT CAUSE ANALYSIS
The Java application experienced an OutOfMemoryError leading to process termination.

### 2. CONTRIBUTING FACTORS
- High memory usage (92%)
- Multiple error patterns in logs

### 3. EVIDENCE SUMMARY
- Logs show 2 OOM indicators
- Java process is not running
- Memory usage critically high

### 4. IMMEDIATE ACTIONS
1. Increase JVM heap size
2. Restart the application
3. Monitor memory usage

### 5. PREVENTIVE MEASURES
- Implement memory leak detection
- Add heap dump on OOM

### 6. SEVERITY ASSESSMENT
CRITICAL - Application down, immediate action required."""

        with patch.object(analyzer, '_call_llm', return_value=mock_analysis):
            # Create temp log file
            with tempfile.TemporaryDirectory() as tmpdir:
                log_file = os.path.join(tmpdir, 'app.log')
                with open(log_file, 'w') as f:
                    f.write('ERROR: OutOfMemoryError\n')
                    f.write('Exception in thread\n')

                sample_logs_data['collected_files'][0]['local_path'] = log_file

                result = await analyzer.analyze_incident(
                    logs_data=sample_logs_data,
                    metrics_data=sample_metrics_data,
                    heap_dump_data=None,
                    alert_context=sample_alert_context
                )

                assert result['success'] is True
                assert 'root_cause_analysis' in result
                assert 'OutOfMemoryError' in result['root_cause_analysis']
                assert result['llm_provider'] == 'anthropic'

    @pytest.mark.asyncio
    async def test_analyze_incident_llm_failure(self, analyzer, sample_logs_data,
                                               sample_metrics_data):
        """Test incident analysis when LLM call fails."""
        with patch.object(analyzer, '_call_llm', side_effect=Exception("API Error")):
            with tempfile.TemporaryDirectory() as tmpdir:
                log_file = os.path.join(tmpdir, 'app.log')
                with open(log_file, 'w') as f:
                    f.write('ERROR: Test error\n')

                sample_logs_data['collected_files'][0]['local_path'] = log_file

                result = await analyzer.analyze_incident(
                    logs_data=sample_logs_data,
                    metrics_data=sample_metrics_data
                )

                assert result['success'] is False
                assert 'error' in result

    def test_prepare_analysis_context(self, analyzer, sample_logs_data,
                                      sample_metrics_data, sample_alert_context):
        """Test analysis context preparation."""
        context = analyzer._prepare_analysis_context(
            sample_logs_data,
            sample_metrics_data,
            None,
            sample_alert_context
        )

        assert 'alert' in context
        assert 'metrics' in context
        assert 'logs_preview' in context
        assert context['metrics']['cpu_percent'] == 85.0
        assert context['metrics']['java_process']['running'] is False

    def test_extract_log_samples(self, analyzer, sample_logs_data):
        """Test log sample extraction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, 'app.log')
            with open(log_file, 'w') as f:
                f.write('INFO: Application started\n')
                f.write('ERROR: Connection failed\n')
                f.write('EXCEPTION: NullPointerException\n')
                f.write('FATAL: OutOfMemoryError\n')

            sample_logs_data['collected_files'][0]['local_path'] = log_file

            samples = analyzer._extract_log_samples(sample_logs_data, max_lines=10)

            assert len(samples) > 0
            assert any('ERROR' in sample for sample in samples)
            assert any('EXCEPTION' in sample for sample in samples)

    def test_build_analysis_prompt(self, analyzer, sample_alert_context):
        """Test analysis prompt generation."""
        context = {
            'alert': sample_alert_context,
            'metrics': {
                'cpu_percent': 85.0,
                'memory_percent': 92.0,
                'java_process': {'running': False},
                'analysis': {
                    'severity': 'critical',
                    'issues': [
                        {'type': 'java_not_running', 'message': 'Java process not found'}
                    ]
                }
            },
            'logs_preview': {
                'error_count': 25,
                'oom_indicators': 2
            },
            'log_samples': ['ERROR: OutOfMemoryError', 'Exception in thread main']
        }

        prompt = analyzer._build_analysis_prompt(context)

        assert 'ROOT CAUSE ANALYSIS' in prompt
        assert 'java-app' in prompt
        assert 'Memory Usage: 92.0%' in prompt
        assert 'Java Process Status' in prompt
        assert 'OOM Indicators: 2' in prompt

    @pytest.mark.asyncio
    async def test_generate_executive_summary(self, analyzer):
        """Test executive summary generation."""
        full_analysis = {
            'success': True,
            'root_cause_analysis': """### 1. ROOT CAUSE ANALYSIS
The Java application crashed due to OutOfMemoryError.

### 2. CONTRIBUTING FACTORS
High load and memory leak.

### 3. EVIDENCE SUMMARY
Logs show OOM errors.

### 4. IMMEDIATE ACTIONS
Restart with increased heap size.

### 5. PREVENTIVE MEASURES
Fix memory leak.

### 6. SEVERITY ASSESSMENT
CRITICAL"""
        }

        mock_summary = "Java app crashed due to OutOfMemoryError. Immediate restart required with increased heap size."

        with patch.object(analyzer, '_call_llm', return_value=mock_summary):
            summary = await analyzer.generate_executive_summary(full_analysis)

            assert 'OutOfMemoryError' in summary
            assert 'restart' in summary.lower()

    @pytest.mark.asyncio
    async def test_call_llm_anthropic(self, analyzer):
        """Test Anthropic LLM API call."""
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Test analysis response")]

        with patch.object(analyzer.client.messages, 'create', return_value=mock_response):
            result = await analyzer._call_llm("Test prompt")

            assert result == "Test analysis response"
            analyzer.client.messages.create.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyzer_with_heap_dumps(self, analyzer, sample_logs_data,
                                           sample_metrics_data):
        """Test analysis with heap dump data included."""
        heap_dump_data = {
            'success': True,
            'total_files': 2,
            'total_size_mb': 500.0,
            'collected_files': [
                {'remote_path': '/mnt/efs/heap-dumps/java_pid1234.hprof', 'size': 500000000}
            ]
        }

        mock_analysis = "Analysis with heap dump context"

        with patch.object(analyzer, '_call_llm', return_value=mock_analysis):
            with tempfile.TemporaryDirectory() as tmpdir:
                log_file = os.path.join(tmpdir, 'app.log')
                with open(log_file, 'w') as f:
                    f.write('ERROR: Test\n')

                sample_logs_data['collected_files'][0]['local_path'] = log_file

                result = await analyzer.analyze_incident(
                    logs_data=sample_logs_data,
                    metrics_data=sample_metrics_data,
                    heap_dump_data=heap_dump_data
                )

                assert result['success'] is True
                assert result['context']['heap_dumps_collected'] == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
