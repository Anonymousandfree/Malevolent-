"""
Example usage of the Security Stack feature
Demonstrates security event tracking, backlogging, and trace elements
"""

import tempfile
import os
from security_stack import (
    SecurityStack,
    SecurityEvent,
    SecurityEventType,
    SeverityLevel
)


def main():
    # Initialize security stack
    print("=" * 60)
    print("Malevolent Security Stack - Example Usage")
    print("=" * 60)
    print()
    
    # Create a security stack with max size of 10 for demonstration
    stack = SecurityStack(max_size=10)
    print(f"Initialized: {stack}")
    print()
    
    # Example 1: Track a port scan attempt
    print("1. Tracking port scan attempt...")
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
    print(f"   {scan_event}")
    print()
    
    # Example 2: Track authentication failures
    print("2. Tracking brute force authentication attempts...")
    for i in range(3):
        auth_event = SecurityEvent(
            event_type=SecurityEventType.BRUTE_FORCE_ATTACK,
            severity=SeverityLevel.HIGH,
            source_ip="203.0.113.45",
            target="ssh://admin@10.0.0.50:22",
            description=f"Failed SSH login attempt #{i+1}",
            trace_data={
                'username': 'admin',
                'password_attempts': i + 1,
                'protocol': 'SSH',
                'port': 22
            }
        )
        stack.push(auth_event)
        print(f"   {auth_event}")
    print()
    
    # Example 3: Track vulnerability detection
    print("3. Detecting vulnerability...")
    vuln_event = SecurityEvent(
        event_type=SecurityEventType.VULNERABILITY_DETECTED,
        severity=SeverityLevel.CRITICAL,
        source_ip="scanner.local",
        target="10.0.0.50",
        description="CVE-2024-1234: Critical buffer overflow in web service",
        trace_data={
            'cve_id': 'CVE-2024-1234',
            'cvss_score': 9.8,
            'affected_service': 'apache',
            'patch_available': True
        }
    )
    stack.push(vuln_event)
    print(f"   {vuln_event}")
    print()
    
    # Example 4: Track intrusion attempt
    print("4. Tracking intrusion attempt...")
    intrusion_event = SecurityEvent(
        event_type=SecurityEventType.INTRUSION_ATTEMPT,
        severity=SeverityLevel.CRITICAL,
        source_ip="198.51.100.78",
        target="10.0.0.50:443",
        description="SQL injection attempt detected",
        trace_data={
            'attack_vector': 'SQL Injection',
            'payload': "' OR '1'='1",
            'blocked': True,
            'waf_rule': 'SQLi-001'
        }
    )
    stack.push(intrusion_event)
    print(f"   {intrusion_event}")
    print()
    
    # Example 5: Track malware detection
    print("5. Detecting malware...")
    malware_event = SecurityEvent(
        event_type=SecurityEventType.MALWARE_DETECTED,
        severity=SeverityLevel.CRITICAL,
        source_ip="10.0.0.75",
        target="file://downloads/suspicious.exe",
        description="Trojan detected in downloaded file",
        trace_data={
            'malware_family': 'Trojan.Generic',
            'file_hash': 'a1b2c3d4e5f6...',
            'quarantined': True,
            'detection_engine': 'ClamAV'
        }
    )
    stack.push(malware_event)
    print(f"   {malware_event}")
    print()
    
    # Display current stack status
    print("=" * 60)
    print("Current Stack Status")
    print("=" * 60)
    print(f"Stack: {stack}")
    print(f"Total events processed: {stack.get_total_event_count()}")
    print()
    
    # Peek at the most recent event
    print("Most recent event:")
    recent = stack.peek()
    if recent:
        print(f"   {recent}")
        print(f"   Trace data: {recent.trace_data}")
    print()
    
    # Get statistics
    print("=" * 60)
    print("Security Event Statistics")
    print("=" * 60)
    stats = stack.get_statistics()
    print(f"Total events: {stats['total_events']}")
    print(f"Events by type:")
    for event_type, count in stats['events_by_type'].items():
        print(f"   {event_type}: {count}")
    print(f"Events by severity:")
    for severity, count in stats['events_by_severity'].items():
        print(f"   {severity}: {count}")
    print()
    
    # Filter by severity
    print("=" * 60)
    print("Critical and High Severity Events")
    print("=" * 60)
    critical_events = stack.filter_by_severity(SeverityLevel.HIGH)
    for event in critical_events:
        print(f"   {event}")
    print()
    
    # Filter by type
    print("=" * 60)
    print("Intrusion and Attack Events")
    print("=" * 60)
    attack_events = stack.filter_by_type(SecurityEventType.BRUTE_FORCE_ATTACK)
    for event in attack_events:
        print(f"   {event}")
    print()
    
    # Test backlog by adding more events than max_size
    print("=" * 60)
    print("Testing Backlog Feature")
    print("=" * 60)
    print(f"Adding {stack.max_size} more events to trigger backlog...")
    for i in range(stack.max_size):
        event = SecurityEvent(
            event_type=SecurityEventType.NETWORK_ANOMALY,
            severity=SeverityLevel.MEDIUM,
            source_ip=f"192.168.1.{i}",
            target="10.0.0.50",
            description=f"Network anomaly #{i+1}",
            trace_data={'anomaly_score': 0.75 + (i * 0.01)}
        )
        stack.push(event)
    
    print(f"Stack after overflow: {stack}")
    print(f"Backlog size: {len(stack.get_backlog())}")
    print()
    
    # Get trace summary
    print("=" * 60)
    print("Trace Summary")
    print("=" * 60)
    trace_summary = stack.get_trace_summary()
    for key, value in trace_summary.items():
        print(f"{key}: {value}")
    print()
    
    # Export to JSON
    print("=" * 60)
    print("Exporting Events")
    print("=" * 60)
    # Use platform-independent temporary directory
    export_file = os.path.join(tempfile.gettempdir(), "security_events.json")
    stack.export_to_json(export_file)
    print(f"Events exported to: {export_file}")
    print()
    
    print("=" * 60)
    print("Example Usage Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
