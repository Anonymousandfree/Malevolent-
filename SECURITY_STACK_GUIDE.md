# Security Stack Feature Guide

## Overview

The Security Stack feature provides a comprehensive system for tracking, managing, and analyzing security events with built-in backlogging, detailed trace elements, encryption, and forensic capabilities. This feature is designed to help identify, log, and respond to security threats, vulnerabilities, and attacks in your network and devices while providing complete forensic data for intruder prosecution and defense building.

## Features

### 1. **Security Event Tracking**
- Track 50+ comprehensive security event types across all system areas
- Assign severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Automatic timestamp tracking
- Unique event ID generation
- Complete forensic data capture for intruder tracking

### 2. **Backlogging System with Auto-Backup**
- Automatic overflow management
- When the stack reaches maximum capacity, oldest events are moved to backlog
- Preserves complete event history
- Efficient memory management
- Automatic backup to secure storage at configurable thresholds
- Encrypted backup support for compliance and security

### 3. **Complete Trace Elements and Forensic Data**
- Detailed trace data for each event
- Custom trace fields for event-specific information
- Automatic timestamp tracking (ISO format and Unix timestamp)
- Stack position tracking
- Event count tracking
- **Forensic data for prosecution**: Capture intruder methods, tools, identifiable information
- Complete attack pattern analysis and correlation

### 4. **Encryption and Secure Storage**
- Full encryption support for stored events using industry-standard cryptography
- Secure transfer capabilities with encrypted exports
- Password-protected encryption keys
- Encrypted mass storage options for large-scale deployments
- Compliance-ready secure data handling

### 5. **Leak Detection and Analysis**
- Automatic detection of data leak events
- Analysis of intrusion methods and attack patterns
- Correlation of attack sources and techniques
- Building secure defenses based on historical threat analysis

## Security Event Types

The system supports comprehensive security event types across all system areas:

### Network Events
1. **SCAN** - Port scans and network reconnaissance
2. **NETWORK_ANOMALY** - Unusual network behavior
3. **PACKET_ANALYSIS** - Deep packet inspection events
4. **DNS_POISONING** - DNS cache poisoning attacks
5. **ARP_SPOOFING** - ARP spoofing/poisoning attacks
6. **DDoS_ATTACK** - Distributed Denial of Service
7. **MAN_IN_THE_MIDDLE** - MITM attacks

### Access & Authentication Events
8. **INTRUSION_ATTEMPT** - Unauthorized access attempts
9. **AUTHENTICATION_FAILURE** - Failed login attempts
10. **BRUTE_FORCE_ATTACK** - Password guessing attacks
11. **CREDENTIAL_STUFFING** - Credential stuffing attacks
12. **SESSION_HIJACKING** - Session takeover attempts
13. **UNAUTHORIZED_ACCESS** - Successful unauthorized access

### System Events
14. **PRIVILEGE_ESCALATION** - Unauthorized privilege elevation
15. **ROOTKIT_DETECTED** - Rootkit detection
16. **SYSTEM_FILE_MODIFICATION** - System file tampering
17. **REGISTRY_MODIFICATION** - Windows registry changes
18. **KERNEL_EXPLOIT** - Kernel-level exploits
19. **PROCESS_INJECTION** - Code injection into processes

### Data Events
20. **DATA_EXFILTRATION** - Unauthorized data transfer
21. **DATA_LEAK** - Data leak detection
22. **SENSITIVE_DATA_ACCESS** - Access to sensitive data
23. **ENCRYPTION_BYPASS** - Encryption bypass attempts
24. **DATA_INTEGRITY_VIOLATION** - Data tampering

### Malware & Exploit Events
25. **MALWARE_DETECTED** - General malware detection
26. **RANSOMWARE_DETECTED** - Ransomware detection
27. **TROJAN_DETECTED** - Trojan detection
28. **WORM_DETECTED** - Worm detection
29. **SPYWARE_DETECTED** - Spyware detection
30. **EXPLOIT_ATTEMPT** - Exploitation attempts
31. **ZERO_DAY_EXPLOIT** - Zero-day exploits
32. **VULNERABILITY_DETECTED** - Security vulnerabilities found

### Application Events
33. **SQL_INJECTION** - SQL injection attacks
34. **XSS_ATTACK** - Cross-site scripting
35. **CSRF_ATTACK** - Cross-site request forgery
36. **COMMAND_INJECTION** - OS command injection
37. **PATH_TRAVERSAL** - Directory traversal attacks
38. **BUFFER_OVERFLOW** - Buffer overflow exploits

### Other Security Events
39. **PHISHING_ATTEMPT** - Phishing detection
40. **SOCIAL_ENGINEERING** - Social engineering attacks
41. **BACKDOOR_DETECTED** - Backdoor discovery
42. **SUSPICIOUS_BEHAVIOR** - Anomalous behavior
43. **POLICY_VIOLATION** - Security policy violations
44. **COMPLIANCE_BREACH** - Compliance violations

## Severity Levels

- **LOW (1)** - Minor issues, informational
- **MEDIUM (2)** - Moderate concern, should be reviewed
- **HIGH (3)** - Serious threat, requires attention
- **CRITICAL (4)** - Severe threat, immediate action required

## Usage

### Basic Usage with Encryption

```python
from security_stack import SecurityStack, SecurityEvent, SecurityEventType, SeverityLevel

# Initialize with encryption and auto-backup
stack = SecurityStack(
    max_size=1000,
    encryption_key="YourSecurePassword123!",
    enable_backup=True,
    backup_threshold=100
)

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

# Add comprehensive intruder tracking information for prosecution
event.add_intruder_info(
    method="SQL Injection - UNION-based",
    tools="sqlmap v1.7",
    user_agent="Mozilla/5.0 (X11; Linux x86_64) sqlmap/1.7",
    payload="' UNION SELECT username,password FROM users--",
    attack_pattern="Classic UNION injection",
    geolocation="Unknown (VPN suspected)",
    isp="CloudVPN Services Inc.",
    identifiable_info="Session originated from known botnet IP range"
)

# Push event to stack
stack.push(event)
```

### Adding Custom Trace Elements and Full Forensic Data

```python
event = SecurityEvent(...)
event.add_trace('custom_field', 'custom_value')
event.add_trace('detected_by', 'IDS System')

# Add forensic data for intruder prosecution
event.add_forensic_data('evidence_hash', 'sha256:abc123...')
event.add_forensic_data('capture_timestamp', '2025-12-16T02:00:00Z')
```

### Retrieving Full Information and Context

```python
# Get complete event data with all forensic information
full_data = stack.get_full_event_data()

# Get specific event by ID with complete context
specific_event = stack.get_full_event_data(event_id="SEC-1234567890")

# Each event includes:
# - All trace data
# - Complete forensic data
# - Full context (timestamps, hashes, classifications)
# - Source and target details
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

# Filter by maximum severity (NEW)
low_events = stack.filter_by_max_severity(SeverityLevel.MEDIUM)

# Filter by severity range (NEW)
medium_to_high = stack.filter_by_severity_range(SeverityLevel.MEDIUM, SeverityLevel.HIGH)

# Filter by source IP
events_from_ip = stack.filter_by_source("192.168.1.100")

# Detect data leaks (NEW)
leak_events = stack.detect_data_leaks()

# Analyze intrusion methods and build defenses (NEW)
analysis = stack.analyze_intrusion_methods()
print(f"Most common attack: {analysis['most_common_type']}")
print(f"Attack sources: {analysis['total_unique_sources']}")
print(f"Methods by source: {analysis['methods_by_source']}")
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

### Exporting Events with Encryption and Mass Storage

```python
# Export with encryption for secure storage/transfer
stack.export_to_json(
    '/path/to/security_events.json',
    encrypted=True,
    include_forensics=True
)

# Export to mass storage with chunking for large datasets
stack.export_to_mass_storage(
    base_path='/path/to/storage',
    chunk_size=1000,
    encrypted=True,
    include_forensics=True
)

# Regular export (unencrypted)
stack.export_to_json('/path/to/security_events.json')
```

### Auto-Backup and Storage Alerts

When auto-backup is enabled, the system automatically creates encrypted backups:

```python
# Initialize with auto-backup
stack = SecurityStack(
    max_size=1000,
    encryption_key="YourKey",
    enable_backup=True,
    backup_threshold=100  # Backup every 100 events
)

# Backups are automatically created in system temp directory
# Location: {temp}/security_stack_backups/auto_backup_{timestamp}.json
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

- Events contain sensitive information - protect access with encryption ✅ **IMPLEMENTED**
- Export files are secured with full encryption support ✅ **IMPLEMENTED**
- Encryption for stored event data ✅ **IMPLEMENTED**
- Implement access controls for production use
- All forensic data is captured for prosecution and compliance ✅ **IMPLEMENTED**
- Secure transfer with encrypted exports ✅ **IMPLEMENTED**
- Auto-backup with encryption for disaster recovery ✅ **IMPLEMENTED**

## File Structure

```
security_stack.py        - Core implementation with encryption & forensics
example_usage.py         - Basic usage examples
example_enhanced.py      - Enhanced examples with forensics & intruder tracking (NEW)
test_security_stack.py   - Comprehensive unit tests
SECURITY_STACK_GUIDE.md  - This documentation
requirements.txt         - Dependencies (cryptography for encryption)
```

## System Requirements

- Python 3.6+
- cryptography library (for encryption features)
- Sufficient storage for mass storage exports (configurable)
- Recommended: SSD for better performance with large event volumes

## Storage Options

### Local Storage
- Single file JSON exports
- Mass storage with chunked files
- Automatic backups to temp directory

### Encrypted Storage
- Full encryption with password-protected keys
- Secure transfer capabilities
- Compliance-ready encrypted backups

### Mass Storage Support
- Chunked exports for large datasets
- Configurable chunk sizes
- Encrypted chunk files
- Easy integration with distributed storage systems

## Running Tests

```bash
python -m unittest test_security_stack.py -v
```

## Running Examples

```bash
python example_usage.py
```

## Current Integrations

The following features are fully integrated and available now:

- ✅ **Encryption for sensitive trace data** - Full encryption support with cryptography library
- ✅ **Data leak detection and analysis** - Automatic leak detection with `detect_data_leaks()`
- ✅ **Intrusion method analysis** - Build defenses with `analyze_intrusion_methods()`
- ✅ **Complete forensic data capture** - Track intruder methods, tools, and identifiable information
- ✅ **Mass storage support** - Export to chunked files with encryption
- ✅ **Auto-backup with alerts** - Automatic encrypted backups at configurable thresholds
- ✅ **Comprehensive event types** - 50+ event types covering all system areas
- ✅ **Advanced filtering** - Filter by min/max severity, ranges, and data leaks
- ✅ **Full context retrieval** - Get complete event data with all forensic information

## Future Enhancements

Potential future additions:
- Real-time alerting system
- Advanced analytics and ML-based anomaly detection
- Distributed stack support for multiple nodes
- Rate limiting and throttling
- Event correlation engine with AI
- Integration APIs for SIEM systems
- Real-time dashboard and visualization

## Support

For issues, questions, or contributions, please refer to the main repository documentation.

## License

See LICENSE file in the repository root.
