"""
Security Stack Module for Malevolent Security Tool
Provides security event tracking, backlogging, and trace elements for security hacks
"""

import json
import time
from datetime import datetime
from typing import List, Dict, Optional, Any
from enum import Enum


class SecurityEventType(Enum):
    """Types of security events that can be tracked"""
    SCAN = "scan"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    NETWORK_ANOMALY = "network_anomaly"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE_DETECTED = "malware_detected"
    BRUTE_FORCE_ATTACK = "brute_force_attack"


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
        trace_data: Optional[Dict[str, Any]] = None
    ):
        self.event_id = self._generate_event_id()
        self.event_type = event_type
        self.severity = severity
        self.source_ip = source_ip
        self.target = target
        self.description = description
        self.timestamp = datetime.now()
        self.trace_data = trace_data or {}
        self._add_default_traces()
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return f"SEC-{int(time.time() * 1000000)}"
    
    def _add_default_traces(self):
        """Add default trace elements"""
        if 'timestamp_unix' not in self.trace_data:
            self.trace_data['timestamp_unix'] = time.time()
        if 'event_created' not in self.trace_data:
            self.trace_data['event_created'] = self.timestamp.isoformat()
    
    def add_trace(self, key: str, value: Any):
        """Add additional trace element to the event"""
        self.trace_data[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'source_ip': self.source_ip,
            'target': self.target,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'trace_data': self.trace_data
        }
    
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
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._stack: List[SecurityEvent] = []
        self._backlog: List[SecurityEvent] = []
        self._event_count = 0
        self._trace_enabled = True
    
    def push(self, event: SecurityEvent) -> bool:
        """
        Push a security event onto the stack
        Returns True if successful, False if stack is full
        """
        if len(self._stack) >= self.max_size:
            # Move oldest event to backlog
            self._move_to_backlog(self._stack.pop(0))
        
        self._stack.append(event)
        self._event_count += 1
        
        if self._trace_enabled:
            event.add_trace('stack_position', len(self._stack))
            event.add_trace('total_event_count', self._event_count)
        
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
        return self._stack.copy()
    
    def get_all_events(self) -> List[SecurityEvent]:
        """Get all events (stack + backlog)"""
        return self._backlog + self._stack
    
    def filter_by_type(self, event_type: SecurityEventType) -> List[SecurityEvent]:
        """Filter events by type"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.event_type == event_type]
    
    def filter_by_severity(self, min_severity: SeverityLevel) -> List[SecurityEvent]:
        """Filter events by minimum severity level"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.severity.value >= min_severity.value]
    
    def filter_by_source(self, source_ip: str) -> List[SecurityEvent]:
        """Filter events by source IP"""
        all_events = self.get_all_events()
        return [e for e in all_events if e.source_ip == source_ip]
    
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
    
    def export_to_json(self, filepath: str):
        """Export all events to JSON file"""
        data = {
            'metadata': self.get_trace_summary(),
            'stack': [e.to_dict() for e in self._stack],
            'backlog': [e.to_dict() for e in self._backlog]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
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
