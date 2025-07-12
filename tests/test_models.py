"""Tests for event models."""

import pytest
from datetime import datetime
from pydantic import ValidationError

from consultor_logs.models.events import (
    SecurityEvent, EventType, AnomalyDetection, AnomalyType, SeverityLevel
)


class TestSecurityEvent:
    """Test SecurityEvent model."""
    
    def test_valid_security_event(self):
        """Test creating a valid security event."""
        event = SecurityEvent(
            event_id=4624,
            event_type=EventType.LOGON,
            timestamp=datetime.now(),
            source="Security",
            computer_name="TEST-PC",
            username="testuser",
            description="User logged on successfully"
        )
        
        assert event.event_id == 4624
        assert event.event_type == EventType.LOGON
        assert event.username == "testuser"
        assert event.computer_name == "TEST-PC"
    
    def test_invalid_event_id(self):
        """Test that invalid event ID raises validation error."""
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id=0,  # Invalid: must be positive
                event_type=EventType.LOGON,
                timestamp=datetime.now(),
                source="Security",
                computer_name="TEST-PC",
                description="Test event"
            )
    
    def test_future_timestamp(self):
        """Test that future timestamp raises validation error."""
        future_time = datetime(2030, 1, 1)
        
        with pytest.raises(ValidationError):
            SecurityEvent(
                event_id=4624,
                event_type=EventType.LOGON,
                timestamp=future_time,
                source="Security",
                computer_name="TEST-PC",
                description="Test event"
            )
    
    def test_optional_fields(self):
        """Test that optional fields can be None."""
        event = SecurityEvent(
            event_id=4624,
            event_type=EventType.LOGON,
            timestamp=datetime.now(),
            source="Security",
            computer_name="TEST-PC",
            description="Test event",
            username=None,
            domain=None,
            process_name=None,
            process_id=None,
            ip_address=None
        )
        
        assert event.username is None
        assert event.domain is None
        assert event.process_name is None
        assert event.process_id is None
        assert event.ip_address is None


class TestAnomalyDetection:
    """Test AnomalyDetection model."""
    
    def test_valid_anomaly(self):
        """Test creating a valid anomaly detection."""
        event = SecurityEvent(
            event_id=4625,
            event_type=EventType.FAILED_LOGON,
            timestamp=datetime.now(),
            source="Security",
            computer_name="TEST-PC",
            description="Failed logon"
        )
        
        anomaly = AnomalyDetection(
            anomaly_id="test-123",
            anomaly_type=AnomalyType.MULTIPLE_FAILED_LOGONS,
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            events=[event],
            description="Multiple failed logon attempts detected"
        )
        
        assert anomaly.anomaly_id == "test-123"
        assert anomaly.anomaly_type == AnomalyType.MULTIPLE_FAILED_LOGONS
        assert anomaly.severity == SeverityLevel.HIGH
        assert anomaly.confidence == 0.85
        assert len(anomaly.events) == 1
    
    def test_invalid_confidence(self):
        """Test that invalid confidence raises validation error."""
        event = SecurityEvent(
            event_id=4625,
            event_type=EventType.FAILED_LOGON,
            timestamp=datetime.now(),
            source="Security",
            computer_name="TEST-PC",
            description="Failed logon"
        )
        
        with pytest.raises(ValidationError):
            AnomalyDetection(
                anomaly_id="test-123",
                anomaly_type=AnomalyType.MULTIPLE_FAILED_LOGONS,
                severity=SeverityLevel.HIGH,
                confidence=1.5,  # Invalid: must be <= 1.0
                events=[event],
                description="Test anomaly"
            )
    
    def test_empty_events_list(self):
        """Test that empty events list raises validation error."""
        with pytest.raises(ValidationError):
            AnomalyDetection(
                anomaly_id="test-123",
                anomaly_type=AnomalyType.MULTIPLE_FAILED_LOGONS,
                severity=SeverityLevel.HIGH,
                confidence=0.85,
                events=[],  # Invalid: must have at least one event
                description="Test anomaly"
            )
    
    def test_default_values(self):
        """Test default values are set correctly."""
        event = SecurityEvent(
            event_id=4625,
            event_type=EventType.FAILED_LOGON,
            timestamp=datetime.now(),
            source="Security",
            computer_name="TEST-PC",
            description="Failed logon"
        )
        
        anomaly = AnomalyDetection(
            anomaly_id="test-123",
            anomaly_type=AnomalyType.MULTIPLE_FAILED_LOGONS,
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            events=[event],
            description="Test anomaly"
        )
        
        assert isinstance(anomaly.detection_time, datetime)
        assert anomaly.recommendations == []
        assert anomaly.metadata == {}