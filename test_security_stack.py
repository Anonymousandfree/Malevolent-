"""
Unit tests for the Security Stack module
Tests security event tracking, backlogging, and trace elements
"""

import unittest
import json
import os
import tempfile
from datetime import datetime
from security_stack import (
    SecurityStack,
    SecurityEvent,
    SecurityEventType,
    SeverityLevel
)


class TestSecurityEvent(unittest.TestCase):
    """Test SecurityEvent class"""
    
    def test_event_creation(self):
        """Test basic event creation"""
        event = SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Test scan"
        )
        
        self.assertIsNotNone(event.event_id)
        self.assertEqual(event.event_type, SecurityEventType.SCAN)
        self.assertEqual(event.severity, SeverityLevel.LOW)
        self.assertEqual(event.source_ip, "192.168.1.1")
        self.assertEqual(event.target, "10.0.0.1")
        self.assertIsInstance(event.timestamp, datetime)
    
    def test_event_with_trace_data(self):
        """Test event with custom trace data"""
        trace_data = {'key1': 'value1', 'key2': 42}
        event = SecurityEvent(
            event_type=SecurityEventType.INTRUSION_ATTEMPT,
            severity=SeverityLevel.HIGH,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Test intrusion",
            trace_data=trace_data
        )
        
        self.assertIn('key1', event.trace_data)
        self.assertEqual(event.trace_data['key1'], 'value1')
        self.assertIn('timestamp_unix', event.trace_data)
    
    def test_add_trace(self):
        """Test adding trace elements"""
        event = SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Test scan"
        )
        
        event.add_trace('custom_field', 'custom_value')
        self.assertEqual(event.trace_data['custom_field'], 'custom_value')
    
    def test_event_to_dict(self):
        """Test event serialization to dictionary"""
        event = SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Test scan"
        )
        
        event_dict = event.to_dict()
        self.assertIn('event_id', event_dict)
        self.assertIn('event_type', event_dict)
        self.assertIn('severity', event_dict)
        self.assertIn('trace_data', event_dict)


class TestSecurityStack(unittest.TestCase):
    """Test SecurityStack class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.stack = SecurityStack(max_size=5)
    
    def test_stack_initialization(self):
        """Test stack initialization"""
        self.assertEqual(len(self.stack), 0)
        self.assertEqual(self.stack.max_size, 5)
        self.assertTrue(self.stack._trace_enabled)
    
    def test_push_event(self):
        """Test pushing events to stack"""
        event = self._create_test_event()
        result = self.stack.push(event)
        
        self.assertTrue(result)
        self.assertEqual(len(self.stack), 1)
    
    def test_pop_event(self):
        """Test popping events from stack"""
        event = self._create_test_event()
        self.stack.push(event)
        
        popped = self.stack.pop()
        self.assertIsNotNone(popped)
        self.assertEqual(popped.event_id, event.event_id)
        self.assertEqual(len(self.stack), 0)
    
    def test_pop_empty_stack(self):
        """Test popping from empty stack"""
        result = self.stack.pop()
        self.assertIsNone(result)
    
    def test_peek_event(self):
        """Test peeking at top event"""
        event = self._create_test_event()
        self.stack.push(event)
        
        peeked = self.stack.peek()
        self.assertIsNotNone(peeked)
        self.assertEqual(peeked.event_id, event.event_id)
        self.assertEqual(len(self.stack), 1)  # Stack should not change
    
    def test_stack_overflow_to_backlog(self):
        """Test that overflow moves events to backlog"""
        # Fill stack beyond max_size
        for i in range(7):
            event = SecurityEvent(
                event_type=SecurityEventType.SCAN,
                severity=SeverityLevel.LOW,
                source_ip=f"192.168.1.{i}",
                target="10.0.0.1",
                description=f"Test event {i}"
            )
            self.stack.push(event)
        
        self.assertEqual(len(self.stack), 5)  # Stack size limited
        backlog = self.stack.get_backlog()
        self.assertEqual(len(backlog), 2)  # 2 events moved to backlog
    
    def test_filter_by_type(self):
        """Test filtering events by type"""
        # Add different event types
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Scan"
        ))
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.INTRUSION_ATTEMPT,
            severity=SeverityLevel.HIGH,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Intrusion"
        ))
        
        scans = self.stack.filter_by_type(SecurityEventType.SCAN)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].event_type, SecurityEventType.SCAN)
    
    def test_filter_by_severity(self):
        """Test filtering events by severity"""
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Low severity"
        ))
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.INTRUSION_ATTEMPT,
            severity=SeverityLevel.CRITICAL,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Critical severity"
        ))
        
        critical_events = self.stack.filter_by_severity(SeverityLevel.CRITICAL)
        self.assertEqual(len(critical_events), 1)
        self.assertEqual(critical_events[0].severity, SeverityLevel.CRITICAL)
    
    def test_filter_by_source(self):
        """Test filtering events by source IP"""
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="From IP 1"
        ))
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.2",
            target="10.0.0.1",
            description="From IP 2"
        ))
        
        events_from_ip1 = self.stack.filter_by_source("192.168.1.1")
        self.assertEqual(len(events_from_ip1), 1)
        self.assertEqual(events_from_ip1[0].source_ip, "192.168.1.1")
    
    def test_get_statistics(self):
        """Test getting event statistics"""
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Scan"
        ))
        self.stack.push(SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.HIGH,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Another scan"
        ))
        
        stats = self.stack.get_statistics()
        self.assertEqual(stats['total_events'], 2)
        self.assertIn('scan', stats['events_by_type'])
        self.assertEqual(stats['events_by_type']['scan'], 2)
    
    def test_trace_summary(self):
        """Test getting trace summary"""
        self.stack.push(self._create_test_event())
        
        summary = self.stack.get_trace_summary()
        self.assertIn('total_events', summary)
        self.assertIn('stack_size', summary)
        self.assertIn('backlog_size', summary)
        self.assertTrue(summary['trace_enabled'])
    
    def test_export_to_json(self):
        """Test exporting events to JSON"""
        self.stack.push(self._create_test_event())
        
        # Use tempfile for cross-platform compatibility
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            filepath = tmp.name
        
        try:
            self.stack.export_to_json(filepath)
            
            self.assertTrue(os.path.exists(filepath))
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertIn('metadata', data)
            self.assertIn('stack', data)
            self.assertIn('backlog', data)
        finally:
            # Cleanup
            if os.path.exists(filepath):
                os.remove(filepath)
    
    def test_clear_operations(self):
        """Test clear operations"""
        # Add events
        for i in range(3):
            self.stack.push(self._create_test_event())
        
        # Test clear_stack
        self.stack.clear_stack()
        self.assertEqual(len(self.stack), 0)
        
        # Add more and overflow to backlog
        for i in range(7):
            self.stack.push(self._create_test_event())
        
        # Test clear_backlog
        backlog_size = len(self.stack.get_backlog())
        self.assertGreater(backlog_size, 0)
        self.stack.clear_backlog()
        self.assertEqual(len(self.stack.get_backlog()), 0)
        
        # Test clear_all
        self.stack.clear_all()
        self.assertEqual(len(self.stack), 0)
        self.assertEqual(len(self.stack.get_backlog()), 0)
    
    def test_trace_enable_disable(self):
        """Test enabling and disabling trace"""
        self.stack.disable_tracing()
        self.assertFalse(self.stack._trace_enabled)
        
        self.stack.enable_tracing()
        self.assertTrue(self.stack._trace_enabled)
    
    def _create_test_event(self):
        """Helper method to create a test event"""
        return SecurityEvent(
            event_type=SecurityEventType.SCAN,
            severity=SeverityLevel.LOW,
            source_ip="192.168.1.1",
            target="10.0.0.1",
            description="Test event"
        )


if __name__ == '__main__':
    unittest.main()
