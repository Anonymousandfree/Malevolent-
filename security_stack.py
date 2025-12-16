"""
Security Stack Module for Malevolent Security Tool
Provides security event tracking, backlogging, and trace elements for security hacks
"""

import json
import time
import hashlib
import base64
import os
import tempfile
import logging
from collections import deque
from datetime import datetime
from typing import List, Dict, Optional, Any, Deque
from enum import Enum
from cryptography.fernet import Fernet

# Configure logging for security operations
logger = logging.getLogger(__name__)


class SecurityEventType(Enum):
    """Types of security events that can be tracked"""
    # Network Events
    SCAN = "scan"
    NETWORK_ANOMALY = "network_anomaly"
    PACKET_ANALYSIS = "packet_analysis"
    DNS_POISONING = "dns_poisoning"
    ARP_SPOOFING = "arp_spoofing"
    DDoS_ATTACK = "ddos_attack"
    MAN_IN_THE_MIDDLE = "man_in_the_middle"
    
    # Access & Authentication Events
    INTRUSION_ATTEMPT = "intrusion_attempt"
    AUTHENTICATION_FAILURE = "authentication_failure"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SESSION_HIJACKING = "session_hijacking"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    
    # System Events
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROOTKIT_DETECTED = "rootkit_detected"
    SYSTEM_FILE_MODIFICATION = "system_file_modification"
    REGISTRY_MODIFICATION = "registry_modification"
    KERNEL_EXPLOIT = "kernel_exploit"
    PROCESS_INJECTION = "process_injection"
    
    # Data Events
    DATA_EXFILTRATION = "data_exfiltration"
    DATA_LEAK = "data_leak"
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"
    ENCRYPTION_BYPASS = "encryption_bypass"
    DATA_INTEGRITY_VIOLATION = "data_integrity_violation"
    
    # Malware & Exploit Events
    MALWARE_DETECTED = "malware_detected"
    RANSOMWARE_DETECTED = "ransomware_detected"
    TROJAN_DETECTED = "trojan_detected"
    WORM_DETECTED = "worm_detected"
    SPYWARE_DETECTED = "spyware_detected"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    
    # Application Events
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    CSRF_ATTACK = "csrf_attack"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    
    # Other Security Events
    PHISHING_ATTEMPT = "phishing_attempt"
    SOCIAL_ENGINEERING = "social_engineering"
    BACKDOOR_DETECTED = "backdoor_detected"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    POLICY_VIOLATION = "policy_violation"
    COMPLIANCE_BREACH = "compliance_breach"


class SeverityLevel(Enum):
    """Severity levels for security events"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class SecurityEvent:
    """Represents a single security event with trace elements"""
    
    def __init__(
        self,
        event_type: SecurityEventType,
        severity: SeverityLevel,
        source_ip: str,
        target: str,
        description: str,
        trace_data: Optional[Dict[str, Any]] = None,
        forensic_data: Optional[Dict[str, Any]] = None
    ):
        self.event_id = self._generate_event_id()
        self.event_type = event_type
        self.severity = severity
        self.source_ip = source_ip
        self.target = target
        self.description = description
        self.timestamp = datetime.now()
        self.trace_data = trace_data or {}
        self.forensic_data = forensic_data or {}
        self._add_default_traces()
        self._add_forensic_traces()
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return f"SEC-{int(time.time() * 1000000)}"
    
    def _add_default_traces(self):
        """Add default trace elements"""
        if 'timestamp_unix' not in self.trace_data:
            self.trace_data['timestamp_unix'] = time.time()
        if 'event_created' not in self.trace_data:
            self.trace_data['event_created'] = self.timestamp.isoformat()
    
    def _add_forensic_traces(self):
        """Add comprehensive forensic trace elements for intruder tracking"""
        if 'source_ip_hash' not in self.forensic_data:
            self.forensic_data['source_ip_hash'] = hashlib.sha256(self.source_ip.encode()).hexdigest()
        if 'event_signature' not in self.forensic_data:
            # Create unique event signature for correlation using secure SHA-256
            signature_data = f"{self.event_type.value}:{self.source_ip}:{self.target}:{self.timestamp.isoformat()}"
            self.forensic_data['event_signature'] = hashlib.sha256(signature_data.encode()).hexdigest()
        if 'forensic_timestamp' not in self.forensic_data:
            self.forensic_data['forensic_timestamp'] = self.timestamp.isoformat()
    
    def add_trace(self, key: str, value: Any):
        """Add additional trace element to the event"""
        self.trace_data[key] = value
    
    def add_forensic_data(self, key: str, value: Any):
        """Add forensic data for intruder tracking and prosecution"""
        self.forensic_data[key] = value
    
    def add_intruder_info(self, **kwargs):
        """
        Add comprehensive intruder information for tracking and prosecution.
        
        Args:
            method: Attack method/technique used
            tools: Tools or programs used by intruder
            user_agent: User agent string
            session_id: Session identifier
            geolocation: Geographic location data
            isp: Internet Service Provider information
            mac_address: MAC address if available
            hostname: Hostname of attacker
            fingerprint: Browser or system fingerprint
            attack_pattern: Pattern or signature of attack
            payload: Attack payload (sanitized)
            response_code: Response code from target system
            identifiable_info: Any identifiable information
        """
        for key, value in kwargs.items():
            self.forensic_data[key] = value
    
    def to_dict(self, include_forensics: bool = True) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        data = {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'source_ip': self.source_ip,
            'target': self.target,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'trace_data': self.trace_data
        }
        if include_forensics:
            data['forensic_data'] = self.forensic_data
        return data
    
    def __str__(self) -> str:
        return (
            f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{self.event_type.value.upper()} - "
            f"Severity: {self.severity.name} - "
            f"{self.source_ip} -> {self.target} - "
            f"{self.description}"
        )


class SecurityStack:
    """
    Security Stack for managing security events with backlogging and trace capabilities
    Implements stack operations for security event management
    """
    
    def __init__(self, max_size: int = 1000, encryption_key: Optional[str] = None, 
                 enable_backup: bool = False, backup_threshold: int = 100):
        self.max_size = max_size
        self._stack: Deque[SecurityEvent] = deque(maxlen=max_size)
        self._backlog: List[SecurityEvent] = []
        self._event_count = 0
        self._trace_enabled = True
        self._encryption_enabled = encryption_key is not None
        self._encryption_key = encryption_key
        self._fernet = None
        self._enable_backup = enable_backup
        self._backup_threshold = backup_threshold
        self._backup_counter = 0
        
        if self._encryption_enabled:
            self._initialize_encryption(encryption_key)
    
    def _initialize_encryption(self, key: str):
        """Initialize encryption with the provided key"""
        try:
            # Derive a key from the password
            key_bytes = key.encode()
            # Use first 32 bytes of SHA256 hash for Fernet key generation
            key_hash = hashlib.sha256(key_bytes).digest()
            fernet_key = base64.urlsafe_b64encode(key_hash)
            self._fernet = Fernet(fernet_key)
        except Exception as e:
            raise ValueError(f"Failed to initialize encryption: {e}")
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt data if encryption is enabled"""
        if not self._encryption_enabled or not self._fernet:
            return data
        try:
            encrypted = self._fernet.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}. Data stored in plaintext.")
            # In production, consider raising exception instead of silent failure
            return data
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data if encryption is enabled"""
        if not self._encryption_enabled or not self._fernet:
            return encrypted_data
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self._fernet.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}. Returning encrypted data.")
            return encrypted_data
    
    def push(self, event: SecurityEvent) -> bool:
        """
        Push a security event onto the stack
        Returns True if successful, False if stack is full
        """
        # Check if we're at capacity and will overflow
        if len(self._stack) >= self.max_size:
            # Move oldest event (leftmost) to backlog
            oldest = self._stack.popleft()
            self._move_to_backlog(oldest)
        
        self._stack.append(event)
        self._event_count += 1
        
        if self._trace_enabled:
            event.add_trace('stack_position', len(self._stack))
            event.add_trace('total_event_count', self._event_count)
        
        # Auto-backup if enabled and threshold reached
        if self._enable_backup:
            self._backup_counter += 1
            if self._backup_counter >= self._backup_threshold:
                self._auto_backup()
                self._backup_counter = 0
        
        return True
    
    def pop(self) -> Optional[SecurityEvent]:
        """
        Pop the most recent security event from the stack
        Returns None if stack is empty
        """
        if not self._stack:
            return None
        return self._stack.pop()
    
    def peek(self) -> Optional[SecurityEvent]:
        """
        View the most recent security event without removing it
        Returns None if stack is empty
        """
        if not self._stack:
            return None
        return self._stack[-1]
    
    def _move_to_backlog(self, event: SecurityEvent):
        """Move an event to the backlog for historical tracking"""
        event.add_trace('moved_to_backlog', datetime.now().isoformat())
        self._backlog.append(event)
    
    def get_backlog(self) -> List[SecurityEvent]:
        """Get all events in the backlog"""
        return self._backlog.copy()
    
    def get_stack(self) -> List[SecurityEvent]:
        """Get all events currently in the stack"""
        return list(self._stack)
    
    def get_all_events(self) -> List[SecurityEvent]:
        """Get all events (stack + backlog)"""
        return self._backlog + list(self._stack)
    
    def filter_by_type(self, event_type: SecurityEventType) -> List[SecurityEvent]:
        """Filter events by type"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.event_type == event_type]
    
    def filter_by_severity(self, min_severity: SeverityLevel) -> List[SecurityEvent]:
        """Filter events by minimum severity level"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.severity.value >= min_severity.value]
    
    def filter_by_max_severity(self, max_severity: SeverityLevel) -> List[SecurityEvent]:
        """Filter events by maximum severity level"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.severity.value <= max_severity.value]
    
    def filter_by_severity_range(self, min_severity: SeverityLevel, max_severity: SeverityLevel) -> List[SecurityEvent]:
        """Filter events by severity range (inclusive)"""
        all_events = self.get_all_events()
        return [e for e in all_events if min_severity.value <= e.severity.value <= max_severity.value]
    
    def filter_by_source(self, source_ip: str) -> List[SecurityEvent]:
        """Filter events by source IP"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.source_ip == source_ip]
    
    def detect_data_leaks(self) -> List[SecurityEvent]:
        """Detect and return all data leak related events"""
        all_events = self.get_all_events()
        leak_types = {
            SecurityEventType.DATA_LEAK,
            SecurityEventType.DATA_EXFILTRATION,
            SecurityEventType.SENSITIVE_DATA_ACCESS,
            SecurityEventType.DATA_INTEGRITY_VIOLATION
        }
        return [e for e in all_events if e.event_type in leak_types]
    
    def analyze_intrusion_methods(self) -> Dict[str, Any]:
        """Analyze and categorize intrusion methods used"""
        all_events = self.get_all_events()
        
        intrusion_types = {}
        attack_sources = {}
        methods_by_source = {}
        
        for event in all_events:
            # Track event types
            event_type = event.event_type.value
            intrusion_types[event_type] = intrusion_types.get(event_type, 0) + 1
            
            # Track attack sources
            source = event.source_ip
            attack_sources[source] = attack_sources.get(source, 0) + 1
            
            # Track methods by source
            if source not in methods_by_source:
                methods_by_source[source] = []
            
            # Extract method from forensic data
            if 'method' in event.forensic_data:
                method = event.forensic_data['method']
                if method not in methods_by_source[source]:
                    methods_by_source[source].append(method)
        
        return {
            'intrusion_types': intrusion_types,
            'attack_sources': attack_sources,
            'methods_by_source': methods_by_source,
            'total_unique_sources': len(attack_sources),
            'most_common_type': max(intrusion_types.items(), key=lambda x: x[1])[0] if len(intrusion_types) > 0 else None,
            'most_active_source': max(attack_sources.items(), key=lambda x: x[1])[0] if len(attack_sources) > 0 else None
        }
    
    def get_full_event_data(self, event_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieve complete event information including all trace and forensic data.
        
        Args:
            event_id: Optional event ID to retrieve specific event. If None, returns all events.
        
        Returns:
            List of complete event dictionaries with all context
        """
        all_events = self.get_all_events()
        
        if event_id:
            events = [e for e in all_events if e.event_id == event_id]
        else:
            events = all_events
        
        full_data = []
        for event in events:
            event_data = event.to_dict(include_forensics=True)
            # Add complete context
            event_data['full_context'] = {
                'event_classification': event.event_type.value,
                'severity_level': event.severity.name,
                'severity_value': event.severity.value,
                'timestamp_readable': event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'source_details': {
                    'ip': event.source_ip,
                    'hash': hashlib.sha256(event.source_ip.encode()).hexdigest()
                },
                'target_details': {
                    'target': event.target,
                    'hash': hashlib.sha256(event.target.encode()).hexdigest()
                }
            }
            full_data.append(event_data)
        
        return full_data
    
    def get_total_event_count(self) -> int:
        """Get total number of events processed (including those moved to backlog)"""
        return self._event_count
    
    def get_trace_summary(self) -> Dict[str, Any]:
        """Get summary of all trace data"""
        return {
            'total_events': self._event_count,
            'stack_size': len(self._stack),
            'backlog_size': len(self._backlog),
            'max_stack_size': self.max_size,
            'trace_enabled': self._trace_enabled
        }
    
    def enable_tracing(self):
        """Enable trace element tracking"""
        self._trace_enabled = True
    
    def disable_tracing(self):
        """Disable trace element tracking"""
        self._trace_enabled = False
    
    def export_to_json(self, filepath: str, encrypted: bool = False, include_forensics: bool = True):
        """
        Export all events to JSON file with optional encryption
        
        Args:
            filepath: Path to save the file
            encrypted: Whether to encrypt the export (requires encryption_key in init)
            include_forensics: Whether to include forensic data in export
        """
        data = {
            'metadata': self.get_trace_summary(),
            'stack': [e.to_dict(include_forensics=include_forensics) for e in self._stack],
            'backlog': [e.to_dict(include_forensics=include_forensics) for e in self._backlog],
            'encrypted': encrypted
        }
        
        json_str = json.dumps(data, indent=2)
        
        if encrypted and self._encryption_enabled:
            json_str = self._encrypt_data(json_str)
        
        with open(filepath, 'w') as f:
            f.write(json_str)
    
    def export_to_mass_storage(self, base_path: str, chunk_size: int = 1000, 
                               encrypted: bool = True, include_forensics: bool = True):
        """
        Export events to multiple files for mass storage
        
        Args:
            base_path: Base directory path for exports
            chunk_size: Number of events per file
            encrypted: Whether to encrypt exports
            include_forensics: Whether to include forensic data
        """
        # Validate and sanitize base_path
        base_path = os.path.abspath(base_path)
        # Ensure path doesn't contain traversal sequences
        if '..' in base_path or base_path.startswith('/etc') or base_path.startswith('/sys'):
            raise ValueError("Invalid base_path: potential path traversal or system directory access")
        
        os.makedirs(base_path, exist_ok=True)
        
        all_events = self.get_all_events()
        num_events = len(all_events)
        total_files = (num_events + chunk_size - 1) // chunk_size
        
        for i in range(total_files):
            start_idx = i * chunk_size
            end_idx = min(start_idx + chunk_size, num_events)
            chunk = all_events[start_idx:end_idx]
            
            chunk_data = {
                'chunk_id': i + 1,
                'total_chunks': total_files,
                'events': [e.to_dict(include_forensics=include_forensics) for e in chunk],
                'encrypted': encrypted
            }
            
            json_str = json.dumps(chunk_data, indent=2)
            
            if encrypted and self._encryption_enabled:
                json_str = self._encrypt_data(json_str)
            
            filepath = os.path.join(base_path, f'security_events_chunk_{i+1:04d}.json')
            with open(filepath, 'w') as f:
                f.write(json_str)
    
    def _auto_backup(self):
        """Automatically backup events when threshold is reached"""
        backup_dir = os.path.join(tempfile.gettempdir(), 'security_stack_backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'auto_backup_{timestamp}.json')
        
        self.export_to_json(backup_file, encrypted=self._encryption_enabled, include_forensics=True)
    
    def clear_stack(self):
        """Clear the main stack (preserves backlog)"""
        self._stack.clear()
    
    def clear_backlog(self):
        """Clear the backlog"""
        self._backlog.clear()
    
    def clear_all(self):
        """Clear both stack and backlog"""
        self._stack.clear()
        self._backlog.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistical information about events"""
        all_events = self.get_all_events()
        
        # Count by type
        type_counts = {}
        for event in all_events:
            event_type = event.event_type.value
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        
        # Count by severity
        severity_counts = {}
        for event in all_events:
            severity = event.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_events': len(all_events),
            'events_by_type': type_counts,
            'events_by_severity': severity_counts,
            'stack_size': len(self._stack),
            'backlog_size': len(self._backlog)
        }
    
    def __len__(self) -> int:
        """Return the current size of the stack"""
        return len(self._stack)
    
    def __str__(self) -> str:
        return f"SecurityStack(size={len(self._stack)}/{self.max_size}, backlog={len(self._backlog)})"
