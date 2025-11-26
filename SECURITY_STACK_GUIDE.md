# Security Stack Feature Guide

## Overview

The Security Stack feature provides a comprehensive system for tracking, managing, and analyzing security events with built-in backlogging and detailed trace elements. This feature is designed to help identify, log, and respond to security threats, vulnerabilities, and attacks in your network and devices.

## Features

### 1. **Security Event Tracking**
- Track multiple types of security events (scans, intrusions, vulnerabilities, etc.)
- Assign severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Automatic timestamp tracking
- Unique event ID generation

### 2. **Backlogging System**
- Automatic overflow management
- When the stack reaches maximum capacity, oldest events are moved to backlog
- Preserves complete event history
- Efficient memory management

### 3. **Trace Elements**
- Detailed trace data for each event
- Custom trace fields for event-specific information
- Automatic timestamp tracking (ISO format and Unix timestamp)
- Stack position tracking
- Event count tracking

## Security Event Types

The system supports the following security event types:

1. **SCAN** - Port scans and network reconnaissance
2. **INTRUSION_ATTEMPT** - Unauthorized access attempts
3. **VULNERABILITY_DETECTED** - Security vulnerabilities found
4. **EXPLOIT_ATTEMPT** - Exploitation attempts
5. **NETWORK_ANOMALY** - Unusual network behavior
6. **AUTHENTICATION_FAILURE** - Failed login attempts
7. **PRIVILEGE_ESCALATION** - Unauthorized privilege elevation
8. **DATA_EXFILTRATION** - Unauthorized data transfer
9. **MALWARE_DETECTED** - Malware or virus detection
10. **BRUTE_FORCE_ATTACK** - Password guessing attacks

## Severity Levels

- **LOW (1)** - Minor issues, informational
- **MEDIUM (2)** - Moderate concern, should be reviewed
- **HIGH (3)** - Serious threat, requires attention
- **CRITICAL (4)** - Severe threat, immediate action required

## Usage

### Basic Usage

```python
from security_stack import SecurityStack, SecurityEvent, SecurityEventType, SeverityLevel

# Initialize the security stack
stack = SecurityStack(max_size=1000)

# Create a security event
event = SecurityEvent(
    event_type=SecurityEventType.INTRUSION_ATTEMPT,
    severity=SeverityLevel.HIGH,
    source_ip="192.168.1.100",
    target="10.0.0.50:443",
    description="SQL injection attempt detected",
    trace_data={
        'attack_vector': 'SQL Injection',
        'payload': "' OR '1'='1",
        'blocked': True
    }
)

# Push event to stack
stack.push(event)
```

### Adding Custom Trace Elements

```python
event = SecurityEvent(...)
event.add_trace('custom_field', 'custom_value')
event.add_trace('detected_by', 'IDS System')
```

### Viewing Events

```python
# Peek at most recent event
recent_event = stack.peek()

# Pop and remove most recent event
event = stack.pop()

# Get all events in stack
all_stack_events = stack.get_stack()

# Get backlog events
backlog_events = stack.get_backlog()

# Get all events (stack + backlog)
all_events = stack.get_all_events()
```

### Filtering Events

```python
# Filter by event type
scans = stack.filter_by_type(SecurityEventType.SCAN)

# Filter by minimum severity
critical_events = stack.filter_by_severity(SeverityLevel.HIGH)

# Filter by source IP
events_from_ip = stack.filter_by_source("192.168.1.100")
```

### Statistics and Analytics

```python
# Get comprehensive statistics
stats = stack.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"Events by type: {stats['events_by_type']}")
print(f"Events by severity: {stats['events_by_severity']}")

# Get trace summary
trace_summary = stack.get_trace_summary()
```

### Exporting Events

```python
# Export all events to JSON file
stack.export_to_json('/path/to/security_events.json')
```

### Managing the Stack

```python
# Clear only the active stack (preserves backlog)
stack.clear_stack()

# Clear only the backlog
stack.clear_backlog()

# Clear everything
stack.clear_all()

# Enable/disable tracing
stack.enable_tracing()
stack.disable_tracing()
```

## Example Scenarios

### 1. Tracking Port Scan

```python
scan_event = SecurityEvent(
    event_type=SecurityEventType.SCAN,
    severity=SeverityLevel.LOW,
    source_ip="192.168.1.100",
    target="10.0.0.50:80",
    description="Port scan detected on web server",
    trace_data={
        'ports_scanned': [80, 443, 8080, 8443],
        'scan_duration': 2.5,
        'tool_signature': 'nmap'
    }
)
stack.push(scan_event)
```

### 2. Tracking Brute Force Attack

```python
auth_event = SecurityEvent(
    event_type=SecurityEventType.BRUTE_FORCE_ATTACK,
    severity=SeverityLevel.HIGH,
    source_ip="203.0.113.45",
    target="ssh://admin@10.0.0.50:22",
    description="Multiple failed SSH login attempts",
    trace_data={
        'username': 'admin',
        'password_attempts': 50,
        'protocol': 'SSH',
        'port': 22
    }
)
stack.push(auth_event)
```

### 3. Tracking Vulnerability

```python
vuln_event = SecurityEvent(
    event_type=SecurityEventType.VULNERABILITY_DETECTED,
    severity=SeverityLevel.CRITICAL,
    source_ip="scanner.local",
    target="10.0.0.50",
    description="CVE-2024-1234: Critical buffer overflow",
    trace_data={
        'cve_id': 'CVE-2024-1234',
        'cvss_score': 9.8,
        'affected_service': 'apache',
        'patch_available': True
    }
)
stack.push(vuln_event)
```

## Best Practices

1. **Set Appropriate Stack Size**
   - Consider your monitoring volume
   - Larger stacks use more memory but preserve more active events
   - Events overflow to backlog automatically

2. **Use Meaningful Descriptions**
   - Clear, concise descriptions help during incident response
   - Include relevant context

3. **Leverage Trace Data**
   - Add custom trace fields for additional context
   - Include IOCs (Indicators of Compromise)
   - Track remediation actions

4. **Regular Monitoring**
   - Use filtering to focus on high-severity events
   - Export data regularly for long-term storage
   - Analyze statistics for trends

5. **Integration**
   - Integrate with existing security tools
   - Export to SIEM systems
   - Use for incident response workflows

## Performance Considerations

- Stack operations are O(1) for push, pop, and peek
- Filtering operations are O(n) where n is the number of events
- Backlog management is automatic and efficient
- JSON export is suitable for moderate event volumes

## Security Considerations

- Events contain sensitive information - protect access
- Export files should be secured
- Consider encryption for stored event data
- Implement access controls for production use

## File Structure

```
security_stack.py        - Core implementation
example_usage.py         - Usage examples
test_security_stack.py   - Unit tests
SECURITY_STACK_GUIDE.md  - This documentation
requirements.txt         - Dependencies (none for core)
```

## Running Tests

```bash
python -m unittest test_security_stack.py -v
```

## Running Examples

```bash
python example_usage.py
```

## Future Enhancements

Potential future additions:
- Real-time alerting
- Integration with external security tools
- Advanced analytics and ML-based anomaly detection
- Distributed stack support for multiple nodes
- Encryption for sensitive trace data
- Rate limiting and throttling
- Event correlation engine

## Support

For issues, questions, or contributions, please refer to the main repository documentation.

## License

See LICENSE file in the repository root.
