# Malevolent-
Security learning tool to pinpoint leaks and weaknesses in your network and devices

## Features

### Security Stack System
A comprehensive security event tracking system with:
- **Event Tracking**: Monitor multiple security event types (scans, intrusions, vulnerabilities, exploits, etc.)
- **Backlogging**: Automatic overflow management that preserves complete event history
- **Trace Elements**: Detailed tracking with custom trace data for security hack analysis
- **Severity Classification**: Four-level severity system (LOW, MEDIUM, HIGH, CRITICAL)
- **Filtering & Analytics**: Query events by type, severity, source, and more
- **Export Capabilities**: JSON export for integration with other tools

## Quick Start

### Basic Usage

```python
from security_stack import SecurityStack, SecurityEvent, SecurityEventType, SeverityLevel

# Initialize the security stack
stack = SecurityStack(max_size=1000)

# Create and track a security event
event = SecurityEvent(
    event_type=SecurityEventType.INTRUSION_ATTEMPT,
    severity=SeverityLevel.HIGH,
    source_ip="192.168.1.100",
    target="10.0.0.50:443",
    description="SQL injection attempt detected",
    trace_data={'attack_vector': 'SQL Injection', 'blocked': True}
)

stack.push(event)

# View statistics
stats = stack.get_statistics()
print(f"Total events: {stats['total_events']}")
```

### Running Examples

```bash
# Run the example demonstration
python example_usage.py

# Run tests
python -m unittest test_security_stack.py -v
```

## Documentation

See [SECURITY_STACK_GUIDE.md](SECURITY_STACK_GUIDE.md) for comprehensive documentation on:
- Security event types and severity levels
- Backlogging system details
- Trace element usage
- Filtering and analytics
- Best practices
- Integration examples

## Supported Security Events

- Port Scans and Network Reconnaissance
- Intrusion Attempts
- Vulnerability Detection
- Exploit Attempts
- Network Anomalies
- Authentication Failures
- Privilege Escalation
- Data Exfiltration
- Malware Detection
- Brute Force Attacks

## Requirements

- Python 3.6+
- No external dependencies (uses Python standard library only)

## License

See [LICENSE](LICENSE) file for details.
