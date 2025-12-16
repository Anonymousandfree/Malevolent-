# Malevolent-
Security learning tool to pinpoint leaks and weaknesses in your network and devices

## Features

### Security Stack System
A comprehensive security event tracking system with complete forensic capabilities:
- **Event Tracking**: Monitor 50+ comprehensive security event types across all system areas (network, authentication, system, data, malware, and application events)
- **Backlogging & Auto-Backup**: Automatic overflow management with encrypted auto-backup at configurable thresholds
- **Complete Trace Elements**: Detailed tracking with custom trace data and full forensic information for intruder prosecution
- **Severity Classification**: Four-level severity system (LOW, MEDIUM, HIGH, CRITICAL)
- **Advanced Filtering & Analytics**: Query events by type, severity range, source, and detect data leaks
- **Leak Detection & Analysis**: Automatic detection and analysis of data leaks and intrusion methods to build secure defenses
- **Encryption & Secure Storage**: Full encryption support for stored events with secure transfer capabilities
- **Mass Storage Options**: Export to chunked encrypted files for large-scale deployments
- **Forensic Data Capture**: Complete intruder tracking including methods, tools, and identifiable information for prosecution

## Quick Start

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

# Create and track a security event with forensic data
event = SecurityEvent(
    event_type=SecurityEventType.SQL_INJECTION,
    severity=SeverityLevel.CRITICAL,
    source_ip="192.168.1.100",
    target="10.0.0.50:443",
    description="SQL injection attempt detected",
    trace_data={'attack_vector': 'SQL Injection', 'blocked': True}
)

# Add intruder tracking information for prosecution
event.add_intruder_info(
    method="SQL Injection - UNION-based",
    tools="sqlmap v1.7",
    user_agent="Mozilla/5.0...",
    identifiable_info="Known botnet IP range"
)

stack.push(event)

# Detect data leaks
leaks = stack.detect_data_leaks()

# Analyze intrusion methods to build defenses
analysis = stack.analyze_intrusion_methods()
print(f"Most common attack: {analysis['most_common_type']}")

# Export with encryption
stack.export_to_json('events.json', encrypted=True, include_forensics=True)
```

### Running Examples

```bash
# Run basic example
python example_usage.py

# Run enhanced forensic & intruder tracking demo
python example_enhanced.py

# Run tests
python -m unittest test_security_stack.py -v
```

## Documentation

See [SECURITY_STACK_GUIDE.md](SECURITY_STACK_GUIDE.md) for comprehensive documentation on:
- 50+ security event types and severity levels
- Backlogging system with auto-backup
- Complete trace element and forensic data usage
- Encryption and secure storage
- Data leak detection and intrusion analysis
- Mass storage options
- Filtering and analytics
- Best practices
- Integration examples

## Supported Security Events (50+ Types)

### Network Events
- Port Scans, Network Anomalies, DDoS Attacks
- DNS Poisoning, ARP Spoofing, Man-in-the-Middle

### Access & Authentication
- Intrusion Attempts, Brute Force, Credential Stuffing
- Session Hijacking, Unauthorized Access

### System Events
- Privilege Escalation, Rootkit Detection
- System File Modification, Kernel Exploits

### Data Events
- Data Leaks, Data Exfiltration, Sensitive Data Access
- Encryption Bypass, Data Integrity Violations

### Malware & Exploits
- Malware, Ransomware, Trojans, Worms, Spyware
- Zero-Day Exploits, Vulnerability Detection

### Application Security
- SQL Injection, XSS, CSRF, Command Injection
- Path Traversal, Buffer Overflow

### Other Events
- Phishing, Social Engineering, Backdoors
- Policy Violations, Compliance Breaches

## Requirements

- Python 3.6+
- cryptography library (for encryption features)

Install dependencies:
```bash
pip install -r requirements.txt
```

## License

See [LICENSE](LICENSE) file for details.
