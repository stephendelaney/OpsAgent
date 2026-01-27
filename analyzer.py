"""Unified LLM analyzer for logs, metrics, and heap dumps."""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional
import logging
import os
import anthropic
import openai

logger = logging.getLogger(__name__)


class Analyzer:
    """LLM-powered analyzer for comprehensive root cause analysis."""

    def __init__(self, config: Dict):
        """
        Initialize the Analyzer.

        Args:
            config: Configuration dictionary containing LLM settings
        """
        self.config = config
        self.llm_config = config.get('llm', {})
        self.provider = self.llm_config.get('provider', 'anthropic')

        # Initialize LLM client
        if self.provider == 'anthropic':
            api_key = os.getenv(
                self.llm_config.get('anthropic', {}).get('api_key_env', 'ANTHROPIC_API_KEY')
            )
            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = self.llm_config.get('anthropic', {}).get('model', 'claude-sonnet-4-5-20250929')
            self.max_tokens = self.llm_config.get('anthropic', {}).get('max_tokens', 16000)
        elif self.provider == 'openai':
            api_key = os.getenv(
                self.llm_config.get('openai', {}).get('api_key_env', 'OPENAI_API_KEY')
            )
            self.client = openai.OpenAI(api_key=api_key)
            self.model = self.llm_config.get('openai', {}).get('model', 'gpt-4')
            self.max_tokens = self.llm_config.get('openai', {}).get('max_tokens', 8000)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

        self.temperature = self.llm_config.get(self.provider, {}).get('temperature', 0.3)

    async def analyze_incident(
        self,
        logs_data: Dict,
        metrics_data: Dict,
        heap_dump_data: Optional[Dict] = None,
        alert_context: Optional[Dict] = None
    ) -> Dict:
        """
        Perform comprehensive root cause analysis using LLM.

        Args:
            logs_data: Collected logs and preview analysis
            metrics_data: Current system metrics
            heap_dump_data: Heap dump information (optional)
            alert_context: Original alert context from Monit

        Returns:
            Dictionary containing root cause analysis and recommendations
        """
        logger.info("Starting comprehensive LLM analysis")

        try:
            # Prepare context for LLM
            analysis_context = self._prepare_analysis_context(
                logs_data, metrics_data, heap_dump_data, alert_context
            )

            # Generate analysis prompt
            prompt = self._build_analysis_prompt(analysis_context)

            # Call LLM
            analysis_result = await self._call_llm(prompt)

            # Structure the response
            result = {
                'success': True,
                'timestamp': datetime.utcnow().isoformat(),
                'root_cause_analysis': analysis_result,
                'context': {
                    'logs_collected': logs_data.get('total_files', 0),
                    'metrics_severity': metrics_data.get('analysis', {}).get('severity', 'unknown'),
                    'heap_dumps_collected': heap_dump_data.get('total_files', 0) if heap_dump_data else 0
                },
                'llm_provider': self.provider,
                'llm_model': self.model
            }

            logger.info("LLM analysis complete")
            return result

        except Exception as e:
            logger.error(f"Error during LLM analysis: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

    def _prepare_analysis_context(
        self,
        logs_data: Dict,
        metrics_data: Dict,
        heap_dump_data: Optional[Dict],
        alert_context: Optional[Dict]
    ) -> Dict:
        """Prepare structured context for LLM analysis."""
        context = {
            'alert': alert_context or {},
            'metrics': {},
            'logs_preview': {},
            'heap_dumps': {}
        }

        # Extract key metrics
        if metrics_data.get('success'):
            context['metrics'] = {
                'cpu_percent': metrics_data.get('cpu_percent'),
                'memory_percent': metrics_data.get('memory_percent'),
                'disk_percent': metrics_data.get('disk_percent'),
                'load_average': metrics_data.get('load_average'),
                'java_process': metrics_data.get('java_process'),
                'uptime': metrics_data.get('uptime'),
                'analysis': metrics_data.get('analysis', {})
            }

        # Extract log preview analysis
        if logs_data.get('success') and 'preview_analysis' in logs_data:
            context['logs_preview'] = logs_data['preview_analysis']

        # Add sample log excerpts if available
        context['log_samples'] = self._extract_log_samples(logs_data)

        # Heap dump summary
        if heap_dump_data:
            context['heap_dumps'] = {
                'available': heap_dump_data.get('success', False),
                'count': heap_dump_data.get('total_files', 0),
                'total_size_mb': heap_dump_data.get('total_size_mb', 0)
            }

        return context

    def _extract_log_samples(self, logs_data: Dict, max_lines: int = 200) -> List[str]:
        """Extract critical log lines for analysis."""
        samples = []

        if not logs_data.get('success'):
            return samples

        collected_files = logs_data.get('collected_files', [])

        for log_file in collected_files[:3]:  # Process first 3 log files
            try:
                local_path = log_file.get('local_path')
                if not local_path or not os.path.exists(local_path):
                    continue

                with open(local_path, 'r', errors='ignore') as f:
                    lines = f.readlines()

                    # Extract error/exception lines
                    critical_lines = [
                        line.strip() for line in lines
                        if any(keyword in line.lower() for keyword in [
                            'error', 'exception', 'fatal', 'outofmemory',
                            'stacktrace', 'caused by', 'java.lang.'
                        ])
                    ]

                    # Take last N critical lines
                    samples.extend(critical_lines[-max_lines:])

                    if len(samples) >= max_lines:
                        break

            except Exception as e:
                logger.error(f"Error extracting log samples: {str(e)}")

        return samples[:max_lines]

    def _build_analysis_prompt(self, context: Dict) -> str:
        """Build comprehensive analysis prompt for LLM."""
        prompt = """You are an expert Java application operations engineer analyzing a production incident where a Java node has failed or is experiencing issues.

## Alert Context
"""
        if context.get('alert'):
            alert = context['alert']
            prompt += f"""
- Service: {alert.get('service', 'N/A')}
- Event: {alert.get('event', 'N/A')}
- Description: {alert.get('description', 'N/A')}
- Time: {alert.get('timestamp', 'N/A')}
"""
        else:
            prompt += "No alert context available\n"

        prompt += "\n## Current System Metrics\n"
        metrics = context.get('metrics', {})
        if metrics:
            prompt += f"""
- CPU Usage: {metrics.get('cpu_percent', 'N/A')}%
- Memory Usage: {metrics.get('memory_percent', 'N/A')}%
- Disk Usage: {metrics.get('disk_percent', 'N/A')}%
- Load Average: {metrics.get('load_average', 'N/A')}
- System Uptime: {metrics.get('uptime', 'N/A')}

### Java Process Status
"""
            java = metrics.get('java_process', {})
            if java.get('running'):
                prompt += f"""
- Status: Running
- PID: {java.get('pid', 'N/A')}
- CPU: {java.get('cpu_percent', 'N/A')}%
- Memory: {java.get('memory_percent', 'N/A')}%
- Threads: {java.get('thread_count', 'N/A')}
"""
            else:
                prompt += "- Status: NOT RUNNING (This is likely the primary issue)\n"

            # Add metrics analysis
            analysis = metrics.get('analysis', {})
            if analysis.get('issues'):
                prompt += "\n### Detected Metrics Issues\n"
                for issue in analysis['issues']:
                    prompt += f"- {issue.get('type', 'unknown')}: {issue.get('message', 'N/A')}\n"
        else:
            prompt += "No metrics data available\n"

        prompt += "\n## Log Analysis Preview\n"
        logs_preview = context.get('logs_preview', {})
        if logs_preview:
            prompt += f"""
- Error Count: {logs_preview.get('error_count', 0)}
- Warning Count: {logs_preview.get('warning_count', 0)}
- Exception Count: {logs_preview.get('exception_count', 0)}
- OOM Indicators: {logs_preview.get('oom_indicators', 0)}
"""

        prompt += "\n## Sample Log Excerpts (Recent Errors/Exceptions)\n"
        log_samples = context.get('log_samples', [])
        if log_samples:
            prompt += "```\n"
            prompt += "\n".join(log_samples[:100])  # Include up to 100 lines
            prompt += "\n```\n"
        else:
            prompt += "No error log samples available\n"

        prompt += "\n## Heap Dump Information\n"
        heap_dumps = context.get('heap_dumps', {})
        if heap_dumps.get('available'):
            prompt += f"""
- Heap Dumps Collected: {heap_dumps.get('count', 0)}
- Total Size: {heap_dumps.get('total_size_mb', 0):.2f} MB
Note: Detailed heap dump analysis can be performed separately if needed.
"""
        else:
            prompt += "No heap dumps available\n"

        prompt += """

## Your Task

Based on the above information, provide a comprehensive analysis in the following format:

### 1. ROOT CAUSE ANALYSIS
Identify the most likely root cause(s) of the Java node failure. Be specific about what went wrong.

### 2. CONTRIBUTING FACTORS
List any secondary factors that may have contributed to the failure.

### 3. EVIDENCE SUMMARY
Summarize the key evidence from logs, metrics, and system state that supports your analysis.

### 4. IMMEDIATE ACTIONS
List specific actions the operations team should take right now (e.g., restart with specific flags, increase heap size, check network connectivity).

### 5. PREVENTIVE MEASURES
Suggest configuration changes, code improvements, or monitoring enhancements to prevent recurrence.

### 6. SEVERITY ASSESSMENT
Rate the severity as: CRITICAL, HIGH, MEDIUM, or LOW, with brief justification.

Be concise but thorough. Focus on actionable insights.
"""

        return prompt

    async def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM provider."""
        try:
            if self.provider == 'anthropic':
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{
                        "role": "user",
                        "content": prompt
                    }]
                )
                return response.content[0].text

            elif self.provider == 'openai':
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{
                        "role": "user",
                        "content": prompt
                    }]
                )
                return response.choices[0].message.content

        except Exception as e:
            logger.error(f"LLM API call failed: {str(e)}", exc_info=True)
            raise

    async def generate_executive_summary(self, full_analysis: Dict) -> str:
        """
        Generate a brief executive summary suitable for notifications.

        Args:
            full_analysis: Complete analysis result

        Returns:
            Brief summary string
        """
        if not full_analysis.get('success'):
            return f"Analysis failed: {full_analysis.get('error', 'Unknown error')}"

        analysis_text = full_analysis.get('root_cause_analysis', '')

        # Extract key sections for summary
        try:
            summary_prompt = f"""Summarize this incident analysis in 3-4 sentences suitable for a Slack alert:

{analysis_text[:2000]}

Format: Brief description of what happened, likely root cause, and immediate action needed."""

            summary = await self._call_llm(summary_prompt)
            return summary.strip()

        except Exception as e:
            logger.error(f"Failed to generate summary: {str(e)}")
            # Fallback to first few lines
            lines = analysis_text.split('\n')
            return ' '.join(lines[:3])
