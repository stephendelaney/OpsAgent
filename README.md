# OpsAgent - AI-Powered Java Node Incident Response

An intelligent operational agent that automatically responds to Java node failures on AWS EC2 instances by collecting diagnostic data, performing LLM-powered root cause analysis, and alerting operations teams.

## Overview

OpsAgent is triggered by Monit alerts when a Java node fails. It:
1. **Collects diagnostic data**: Logs from EFS, current system metrics, and optionally heap dumps
2. **Analyzes with AI**: Uses Claude/GPT to perform comprehensive root cause analysis
3. **Alerts ops team**: Sends detailed reports via Slack/PagerDuty
4. **Optionally restarts**: Can automatically restart nodes if enabled (disabled by default)

## Key Features

- 🤖 **LLM-Powered Analysis**: Comprehensive root cause diagnosis using Claude Sonnet or GPT-4
- 📊 **Smart Data Collection**: Collects only necessary data (heap dumps only for memory issues)
- 🎯 **Pragmatic Design**: Focuses on diagnosis, not code analysis (logs contain the answers)
- 🔒 **Safe by Default**: Automated recovery disabled - ops team makes restart decisions
- ⚡ **Fast Response**: Streamlined workflow for quick incident triage
- 🧪 **Fully Tested**: Comprehensive test suite with mocked components

## Architecture (Simplified)

```
OpsAgent/
├── OpAgent.py                      # Main orchestrator + Monit webhook
├── config.yaml                     # Configuration
├── requirements.txt                # Dependencies
├── collectors/                     # Data collection modules
│   ├── log_collector.py           # Gather logs from EFS
│   ├── metrics_collector.py       # Current system metrics
│   └── heap_dump_collector.py     # Optional heap dump collection
├── analyzer.py                     # Unified LLM analyzer
├── recovery.py                     # Optional automated restart
├── utils/                          # Supporting utilities
│   ├── logger.py                  # Structured logging
│   └── notifier.py                # Slack/PagerDuty alerts
└── tests/                          # Comprehensive test suite
```

## Workflow

```
┌─────────────┐
│ Monit Alert │
└──────┬──────┘
       │
       v
┌──────────────────────────────────┐
│ 1. Collect Current Metrics       │
│    - CPU, memory, disk, Java PID │
└──────┬───────────────────────────┘
       │
       v
┌──────────────────────────────────┐
│ 2. Collect Logs from EFS         │
│    - Application logs             │
│    - System logs                  │
│    - GC logs                      │
└──────┬───────────────────────────┘
       │
       v
┌──────────────────────────────────┐
│ 3. Collect Heap Dumps (Optional) │
│    - Only if OOM detected         │
└──────┬───────────────────────────┘
       │
       v
┌──────────────────────────────────┐
│ 4. LLM Analysis (Claude/GPT)     │
│    - Root cause identification    │
│    - Evidence correlation         │
│    - Actionable recommendations   │
└──────┬───────────────────────────┘
       │
       v
┌──────────────────────────────────┐
│ 5. Alert Operations Team         │
│    - Slack notification           │
│    - PagerDuty incident           │
│    - Detailed incident report     │
└──────┬───────────────────────────┘
       │
       v
┌──────────────────────────────────┐
│ 6. Optional: Automated Restart   │
│    - Disabled by default          │
│    - Ops team manually restarts   │
└──────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.8+
- AWS credentials configured
- SSH access to EC2 instances
- Anthropic or OpenAI API key

### Setup

```bash
# Clone the repository
git clone https://github.com/stephendelaney/OpsAgent.git
cd OpsAgent

# Install dependencies
pip install -r requirements.txt

# Copy and customize configuration
cp config.yaml.example config.yaml
vi config.yaml
# Update: SSH key path, EFS paths, instance details

# Configure API keys
export ANTHROPIC_API_KEY="your-api-key-here"
export SLACK_WEBHOOK_URL="your-slack-webhook-url"

# Run tests
pytest tests/ -v

# Start the agent
python OpAgent.py
```

## Configuration

### Key Configuration Options

```yaml
# Enable/disable automated recovery (DEFAULT: false)
recovery:
  auto_restart: false  # Ops team manually restarts by default

# EFS paths for log and heap dump collection
efs:
  logs_path: "/mnt/efs/logs"
  heap_dumps_path: "/mnt/efs/heap-dumps"

# LLM provider (anthropic or openai)
llm:
  provider: "anthropic"
  anthropic:
    model: "claude-sonnet-4-5-20250929"

# Notification channels
notifications:
  slack:
    enabled: true
    channel: "#ops-alerts"
```

See [config.yaml.example](config.yaml.example) for all options.

## Usage

### As a Webhook Service

Start the agent as a webhook service that listens for Monit alerts:

```bash
python OpAgent.py
```

The agent will listen on port 8000 (configurable) for incoming Monit webhooks.

### Configure Monit

Add webhook to your Monit configuration:

```
check process java-app with pidfile /var/run/java-app.pid
  start program = "/opt/java-app/bin/start.sh"
  stop program = "/opt/java-app/bin/stop.sh"
  if does not exist then exec "/usr/bin/curl -X POST http://ops-agent-host:8000/monit-webhook \
    -H 'Content-Type: application/json' \
    -d '{\"service\":\"java-app\",\"event\":\"Does not exist\",\"instance_ip\":\"INSTANCE_IP\",\"instance_id\":\"INSTANCE_ID\"}'"
```

### Manual Trigger (for testing)

```python
import asyncio
from OpAgent import OpAgent

agent = OpAgent('config.yaml')

alert_data = {
    'service': 'java-app',
    'event': 'Does not exist',
    'instance_ip': '10.0.1.50',
    'instance_id': 'i-1234567890abcdef0'
}

result = asyncio.run(agent.handle_alert(alert_data))
print(result)
```

## Testing

Comprehensive test suite with unit and integration tests:

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_collectors.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run integration tests only
pytest tests/test_integration.py -v
```

### Test Fixtures

Sample data files in `tests/fixtures/`:
- `sample_monit_alert.json`: Example Monit alert
- `sample_app.log`: Application log with OOM error
- `sample_gc.log`: GC log showing memory pressure
- `test_config.yaml`: Test configuration

## Why This Design?

### Logs > Code Analysis

**Decision**: Focus on log analysis, not code repository analysis.

**Rationale**:
- Java failures (OOM, deadlocks, connection issues) are evident in logs
- Stack traces point directly to problem areas
- Faster response without code checkout/parsing
- Less complexity, more reliability

### Manual Recovery by Default

**Decision**: Automated recovery disabled by default.

**Rationale**:
- Operations personnel review analysis before restarting
- Prevents restart loops
- Allows manual intervention for complex issues
- Safer in production environments

### Optional Heap Dumps

**Decision**: Collect heap dumps only when memory issues detected.

**Rationale**:
- Heap dumps are large (GBs) and slow to transfer
- Only needed for memory-related failures
- Most issues diagnosable from logs alone

## Security Considerations

- **SSH Keys**: Store in AWS Secrets Manager (recommended) or secure file system
- **API Keys**: Use environment variables, never commit to code
- **Webhook Authentication**: Enable token-based auth in production
- **Credential Redaction**: Sensitive data redacted before logging

## Troubleshooting

### Agent not receiving alerts

- Check Monit webhook configuration
- Verify network connectivity to agent
- Check agent logs: `/var/log/ops-agent/ops-agent.log`

### SSH connection failures

- Verify SSH key path in config
- Check EC2 security groups allow SSH from agent
- Test manual SSH: `ssh -i /path/to/key.pem ec2-user@instance-ip`

### LLM analysis fails

- Verify API key is set: `echo $ANTHROPIC_API_KEY`
- Check API rate limits
- Review LLM provider status page

### Heap dump collection slow

- Heap dumps can be several GB - this is normal
- Consider increasing `collection_timeout` in config
- Verify EFS mount performance

## Contributing

When adding new features:
1. Write tests first
2. Update configuration documentation
3. Add integration tests
4. Test with mock data before live testing

## License

[Add your license here]

## Support

For issues or questions:
- Check logs in `/var/log/ops-agent/`
- Review incident reports in `/tmp/ops-agent-incidents/`
- Enable DEBUG logging for verbose output

---

**Note**: This agent is designed for defensive security and incident response only. It does not perform code modification or offensive security operations.
