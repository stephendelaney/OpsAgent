# Test Fixtures

This directory contains sample data files for testing OpsAgent components.

## Files

- **sample_monit_alert.json**: Example Monit webhook payload for a Java process failure
- **sample_app.log**: Sample application log showing progression to OutOfMemoryError
- **sample_gc.log**: Sample garbage collection log showing memory pressure
- **test_config.yaml**: Complete test configuration for OpsAgent

## Usage

These fixtures are used by the test suite to simulate real-world incident scenarios without requiring actual EC2 instances or external services.

### Example

```python
import json

with open('tests/fixtures/sample_monit_alert.json') as f:
    alert_data = json.load(f)

# Use in tests
result = await agent.handle_alert(alert_data)
```
