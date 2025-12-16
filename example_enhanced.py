"""
Enhanced Example Usage - Demonstrating Intruder Tracking and Forensic Features
Shows comprehensive security event tracking with encryption, leak detection, and forensics
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
    print("=" * 70)
    print("Enhanced Security Stack - Forensic & Intruder Tracking Demo")
    print("=" * 70)
    print()
    
    # Initialize security stack with encryption and auto-backup
    encryption_key = "SecurePassword123!"
    stack = SecurityStack(
        max_size=50,
        encryption_key=encryption_key,
        enable_backup=True,
        backup_threshold=10
    )
    print(f"Initialized: {stack}")
    print(f"Encryption: {'Enabled' if stack._encryption_enabled else 'Disabled'}")
    print(f"Auto-backup: {'Enabled' if stack._enable_backup else 'Disabled'}")
    print()
    
    # Example 1: Track SQL Injection with Full Forensics
    print("=" * 70)
    print("1. SQL Injection Attack with Intruder Tracking")
    print("=" * 70)
    sql_injection = SecurityEvent(
        event_type=SecurityEventType.SQL_INJECTION,
        severity=SeverityLevel.CRITICAL,
        source_ip="203.0.113.89",
        target="db.example.com:3306",
        description="SQL injection attempt on login form",
        trace_data={
            'endpoint': '/api/login',
            'request_method': 'POST',
            'blocked': True
        }
    )
    # Add comprehensive intruder information
    sql_injection.add_intruder_info(
        method="SQL Injection - UNION-based",
        tools="sqlmap v1.7",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) sqlmap/1.7",
        payload="' UNION SELECT username,password FROM users--",
        attack_pattern="Classic UNION injection",
        session_id="sess_89abc123def",
        geolocation="Unknown (VPN suspected)",
        isp="CloudVPN Services Inc.",
        fingerprint="Chrome 120.0.0.0 / Linux x64",
        identifiable_info="Session originated from known botnet IP range"
    )
    stack.push(sql_injection)
    print(f"   {sql_injection}")
    print(f"   Forensic Data Captured: {len(sql_injection.forensic_data)} fields")
    print()
    
    # Example 2: Data Leak Detection
    print("=" * 70)
    print("2. Data Leak Event")
    print("=" * 70)
    data_leak = SecurityEvent(
        event_type=SecurityEventType.DATA_LEAK,
        severity=SeverityLevel.CRITICAL,
        source_ip="internal-server-192.168.10.50",
        target="external-45.76.89.123:443",
        description="Sensitive customer data detected in outbound traffic",
        trace_data={
            'data_type': 'customer_records',
            'records_affected': 1250,
            'detected_by': 'DLP System'
        }
    )
    data_leak.add_intruder_info(
        method="Data Exfiltration via HTTPS",
        identifiable_info="Internal employee account compromised",
        attack_pattern="Slow exfiltration over encrypted channel"
    )
    stack.push(data_leak)
    print(f"   {data_leak}")
    print()
    
    # Example 3: Ransomware Detection
    print("=" * 70)
    print("3. Ransomware Attack")
    print("=" * 70)
    ransomware = SecurityEvent(
        event_type=SecurityEventType.RANSOMWARE_DETECTED,
        severity=SeverityLevel.CRITICAL,
        source_ip="workstation-192.168.10.105",
        target="file-server-192.168.10.200",
        description="WannaCry-like ransomware detected",
        trace_data={
            'files_encrypted': 5420,
            'encryption_type': 'AES-256',
            'ransom_note': 'YOUR_FILES_ARE_ENCRYPTED.txt',
            'quarantined': True
        }
    )
    ransomware.add_intruder_info(
        method="Ransomware - File encryption",
        tools="Modified WannaCry variant",
        attack_pattern="Lateral movement via SMB",
        payload="Encrypted executable with obfuscated code",
        identifiable_info="Attack originated from phishing email"
    )
    stack.push(ransomware)
    print(f"   {ransomware}")
    print()
    
    # Example 4: Zero-Day Exploit
    print("=" * 70)
    print("4. Zero-Day Exploit Attempt")
    print("=" * 70)
    zero_day = SecurityEvent(
        event_type=SecurityEventType.ZERO_DAY_EXPLOIT,
        severity=SeverityLevel.CRITICAL,
        source_ip="185.220.101.45",
        target="web-server-10.0.0.50:8080",
        description="Unknown exploit targeting web application framework",
        trace_data={
            'framework': 'CustomFramework v2.1',
            'exploit_type': 'Remote Code Execution',
            'patched': False
        }
    )
    zero_day.add_intruder_info(
        method="Zero-day RCE exploit",
        tools="Custom exploit toolkit",
        attack_pattern="Novel bypass technique",
        payload="Shellcode execution via buffer overflow",
        identifiable_info="APT group signature detected"
    )
    stack.push(zero_day)
    print(f"   {zero_day}")
    print()
    
    # Example 5: Multiple Attack Types for Analysis
    print("=" * 70)
    print("5. Adding Multiple Attack Events for Analysis")
    print("=" * 70)
    
    attack_events = [
        (SecurityEventType.BRUTE_FORCE_ATTACK, "198.51.100.45", "SSH brute force"),
        (SecurityEventType.XSS_ATTACK, "203.0.113.67", "Reflected XSS attempt"),
        (SecurityEventType.DDoS_ATTACK, "multiple-sources", "DDoS attack detected"),
        (SecurityEventType.PHISHING_ATTEMPT, "email-server", "Phishing email detected"),
        (SecurityEventType.DATA_EXFILTRATION, "192.168.1.100", "Unauthorized data transfer"),
    ]
    
    for event_type, source, desc in attack_events:
        event = SecurityEvent(
            event_type=event_type,
            severity=SeverityLevel.HIGH,
            source_ip=source,
            target="10.0.0.50",
            description=desc
        )
        event.add_intruder_info(
            method=event_type.value,
            identifiable_info=f"Tracked via {event_type.value}"
        )
        stack.push(event)
        print(f"   Added: {event_type.value}")
    print()
    
    # Analyze Intrusion Methods
    print("=" * 70)
    print("Intrusion Method Analysis")
    print("=" * 70)
    analysis = stack.analyze_intrusion_methods()
    print(f"Total Unique Attack Sources: {analysis['total_unique_sources']}")
    print(f"Most Common Attack Type: {analysis['most_common_type']}")
    print(f"Most Active Source: {analysis['most_active_source']}")
    print("\nAttack Distribution:")
    for attack_type, count in sorted(analysis['intrusion_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"   {attack_type}: {count}")
    print()
    
    # Detect Data Leaks
    print("=" * 70)
    print("Data Leak Detection")
    print("=" * 70)
    leaks = stack.detect_data_leaks()
    print(f"Total Data Leak Events Detected: {len(leaks)}")
    for leak in leaks:
        print(f"   - {leak.event_type.value}: {leak.description}")
    print()
    
    # Get Full Event Data with Complete Context
    print("=" * 70)
    print("Full Event Data Retrieval (First Event)")
    print("=" * 70)
    full_data = stack.get_full_event_data()
    if full_data:
        first_event = full_data[0]
        print(f"Event ID: {first_event['event_id']}")
        print(f"Classification: {first_event['full_context']['event_classification']}")
        print(f"Severity: {first_event['full_context']['severity_level']}")
        print(f"Timestamp: {first_event['full_context']['timestamp_readable']}")
        print(f"Source Hash: {first_event['full_context']['source_details']['hash'][:16]}...")
        print(f"Forensic Fields: {len(first_event.get('forensic_data', {}))}")
        if 'forensic_data' in first_event and 'method' in first_event['forensic_data']:
            print(f"Attack Method: {first_event['forensic_data']['method']}")
            if 'tools' in first_event['forensic_data']:
                print(f"Tools Used: {first_event['forensic_data']['tools']}")
    print()
    
    # Test New Filtering Options
    print("=" * 70)
    print("Enhanced Filtering")
    print("=" * 70)
    
    # Filter by maximum severity
    low_to_med = stack.filter_by_max_severity(SeverityLevel.MEDIUM)
    print(f"Events with severity ≤ MEDIUM: {len(low_to_med)}")
    
    # Filter by severity range
    high_to_critical = stack.filter_by_severity_range(SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    print(f"Events with HIGH to CRITICAL severity: {len(high_to_critical)}")
    print()
    
    # Export with Encryption
    print("=" * 70)
    print("Encrypted Export")
    print("=" * 70)
    export_file = os.path.join(tempfile.gettempdir(), "encrypted_security_events.json")
    stack.export_to_json(export_file, encrypted=True, include_forensics=True)
    print(f"Events exported with encryption to: {export_file}")
    print("Note: File contains encrypted data for secure storage/transfer")
    print()
    
    # Mass Storage Export
    print("=" * 70)
    print("Mass Storage Export")
    print("=" * 70)
    mass_storage_path = os.path.join(tempfile.gettempdir(), "security_mass_storage")
    stack.export_to_mass_storage(
        mass_storage_path,
        chunk_size=5,
        encrypted=True,
        include_forensics=True
    )
    import glob
    exported_files = glob.glob(os.path.join(mass_storage_path, "*.json"))
    print(f"Exported {len(exported_files)} encrypted chunk files to: {mass_storage_path}")
    for f in sorted(exported_files)[:3]:
        print(f"   - {os.path.basename(f)}")
    if len(exported_files) > 3:
        print(f"   ... and {len(exported_files) - 3} more files")
    print()
    
    print("=" * 70)
    print("Enhanced Demo Complete")
    print("=" * 70)
    print(f"\nTotal Events Processed: {stack.get_total_event_count()}")
    print("All security events include comprehensive forensic data for prosecution")
    print("and defense building against future threats.")


if __name__ == "__main__":
    main()
