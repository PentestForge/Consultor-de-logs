"""
Event models for Windows security log analysis.

This module contains Pydantic models for representing Windows security events
and anomaly detection results.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator


class EventType(str, Enum):
    """Types of security events."""
    
    LOGON = "logon"
    LOGOFF = "logoff"
    FAILED_LOGON = "failed_logon"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POLICY_CHANGE = "policy_change"
    ACCOUNT_MANAGEMENT = "account_management"
    PROCESS_CREATION = "process_creation"
    FILE_ACCESS = "file_access"
    SYSTEM_EVENT = "system_event"
    AUDIT_EVENT = "audit_event"
    OTHER = "other"


class SecurityEvent(BaseModel):
    """Model for Windows security events."""
    
    event_id: int = Field(..., description="Windows Event ID")
    event_type: EventType = Field(..., description="Type of security event")
    timestamp: datetime = Field(..., description="Event timestamp")
    source: str = Field(..., description="Event source/log name")
    computer_name: str = Field(..., description="Computer where event occurred")
    username: Optional[str] = Field(None, description="Associated username")
    domain: Optional[str] = Field(None, description="Domain name")
    process_name: Optional[str] = Field(None, description="Process name")
    process_id: Optional[int] = Field(None, description="Process ID")
    ip_address: Optional[str] = Field(None, description="IP address")
    description: str = Field(..., description="Event description")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw event data")
    
    @validator('event_id')
    def validate_event_id(cls, v):
        """Validate event ID is positive."""
        if v <= 0:
            raise ValueError('Event ID must be positive')
        return v
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        """Validate timestamp is not in the future."""
        if v > datetime.now():
            raise ValueError('Event timestamp cannot be in the future')
        return v
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AnomalyType(str, Enum):
    """Types of anomalies that can be detected."""
    
    MULTIPLE_FAILED_LOGONS = "multiple_failed_logons"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OFF_HOURS_ACCESS = "off_hours_access"
    UNUSUAL_PROCESS = "unusual_process"
    POLICY_CHANGES = "policy_changes"
    ACCOUNT_ANOMALY = "account_anomaly"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    FREQUENCY_ANOMALY = "frequency_anomaly"
    CORRELATION_ANOMALY = "correlation_anomaly"


class SeverityLevel(str, Enum):
    """Severity levels for anomalies."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyDetection(BaseModel):
    """Model for anomaly detection results."""
    
    anomaly_id: str = Field(..., description="Unique anomaly identifier")
    anomaly_type: AnomalyType = Field(..., description="Type of anomaly")
    severity: SeverityLevel = Field(..., description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    detection_time: datetime = Field(default_factory=datetime.now, description="Detection timestamp")
    events: List[SecurityEvent] = Field(..., description="Related security events")
    description: str = Field(..., description="Anomaly description")
    recommendations: List[str] = Field(default_factory=list, description="Mitigation recommendations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('confidence')
    def validate_confidence(cls, v):
        """Validate confidence is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v
    
    @validator('events')
    def validate_events(cls, v):
        """Validate at least one event is provided."""
        if not v:
            raise ValueError('At least one event must be provided')
        return v
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class EventPattern(BaseModel):
    """Model for event pattern matching."""
    
    pattern_id: str = Field(..., description="Pattern identifier")
    name: str = Field(..., description="Pattern name")
    description: str = Field(..., description="Pattern description")
    event_ids: List[int] = Field(..., description="Event IDs to match")
    time_window: int = Field(..., description="Time window in seconds")
    threshold: int = Field(..., description="Threshold for triggering")
    severity: SeverityLevel = Field(..., description="Severity level")
    enabled: bool = Field(True, description="Whether pattern is enabled")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class LogSource(BaseModel):
    """Model for log source configuration."""
    
    name: str = Field(..., description="Source name")
    log_name: str = Field(..., description="Windows log name")
    computer_name: Optional[str] = Field(None, description="Computer name")
    enabled: bool = Field(True, description="Whether source is enabled")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Event filters")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True