"""
Report models for Windows security log analysis.

This module contains Pydantic models for representing security reports
and analysis results.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, validator

from .events import AnomalyDetection, SecurityEvent, SeverityLevel


class ThreatLevel(str, Enum):
    """Threat levels for security assessment."""
    
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReportFormat(str, Enum):
    """Supported report formats."""
    
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    XML = "xml"


class ReportType(str, Enum):
    """Types of security reports."""
    
    FULL_ANALYSIS = "full_analysis"
    ANOMALY_SUMMARY = "anomaly_summary"
    THREAT_ASSESSMENT = "threat_assessment"
    COMPLIANCE_AUDIT = "compliance_audit"
    EXECUTIVE_SUMMARY = "executive_summary"
    FORENSIC_TIMELINE = "forensic_timeline"


class StatisticsSummary(BaseModel):
    """Model for event statistics summary."""
    
    total_events: int = Field(..., description="Total number of events")
    events_by_type: Dict[str, int] = Field(default_factory=dict, description="Events by type")
    events_by_severity: Dict[str, int] = Field(default_factory=dict, description="Events by severity")
    time_range: Dict[str, datetime] = Field(..., description="Time range analyzed")
    unique_users: int = Field(0, description="Number of unique users")
    unique_computers: int = Field(0, description="Number of unique computers")
    failed_logons: int = Field(0, description="Number of failed logon attempts")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ThreatIndicator(BaseModel):
    """Model for threat indicators."""
    
    indicator_id: str = Field(..., description="Unique indicator identifier")
    indicator_type: str = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    description: str = Field(..., description="Indicator description")
    severity: SeverityLevel = Field(..., description="Severity level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    first_seen: datetime = Field(..., description="First occurrence")
    last_seen: datetime = Field(..., description="Last occurrence")
    count: int = Field(1, description="Number of occurrences")
    
    @validator('confidence')
    def validate_confidence(cls, v):
        """Validate confidence is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class SecurityRecommendation(BaseModel):
    """Model for security recommendations."""
    
    recommendation_id: str = Field(..., description="Unique recommendation identifier")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Detailed description")
    priority: SeverityLevel = Field(..., description="Priority level")
    category: str = Field(..., description="Recommendation category")
    implementation_steps: List[str] = Field(default_factory=list, description="Implementation steps")
    resources: List[str] = Field(default_factory=list, description="Additional resources")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class SecurityReport(BaseModel):
    """Model for comprehensive security reports."""
    
    report_id: str = Field(..., description="Unique report identifier")
    report_type: ReportType = Field(..., description="Type of report")
    title: str = Field(..., description="Report title")
    description: str = Field(..., description="Report description")
    generated_at: datetime = Field(default_factory=datetime.now, description="Generation timestamp")
    analysis_period: Dict[str, datetime] = Field(..., description="Analysis time period")
    
    # Analysis results
    overall_threat_level: ThreatLevel = Field(..., description="Overall threat assessment")
    statistics: StatisticsSummary = Field(..., description="Event statistics")
    anomalies: List[AnomalyDetection] = Field(default_factory=list, description="Detected anomalies")
    threat_indicators: List[ThreatIndicator] = Field(default_factory=list, description="Threat indicators")
    recommendations: List[SecurityRecommendation] = Field(default_factory=list, description="Security recommendations")
    
    # Additional data
    high_risk_events: List[SecurityEvent] = Field(default_factory=list, description="High-risk events")
    compliance_status: Dict[str, Any] = Field(default_factory=dict, description="Compliance assessment")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('analysis_period')
    def validate_analysis_period(cls, v):
        """Validate analysis period has start and end times."""
        if 'start' not in v or 'end' not in v:
            raise ValueError('Analysis period must have start and end times')
        if v['start'] > v['end']:
            raise ValueError('Analysis start time must be before end time')
        return v
    
    def get_anomalies_by_severity(self, severity: SeverityLevel) -> List[AnomalyDetection]:
        """Get anomalies filtered by severity level."""
        return [anomaly for anomaly in self.anomalies if anomaly.severity == severity]
    
    def get_critical_anomalies(self) -> List[AnomalyDetection]:
        """Get critical severity anomalies."""
        return self.get_anomalies_by_severity(SeverityLevel.CRITICAL)
    
    def get_high_anomalies(self) -> List[AnomalyDetection]:
        """Get high severity anomalies."""
        return self.get_anomalies_by_severity(SeverityLevel.HIGH)
    
    def get_anomaly_count_by_type(self) -> Dict[str, int]:
        """Get count of anomalies by type."""
        counts = {}
        for anomaly in self.anomalies:
            anomaly_type = anomaly.anomaly_type
            counts[anomaly_type] = counts.get(anomaly_type, 0) + 1
        return counts
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ReportTemplate(BaseModel):
    """Model for report templates."""
    
    template_id: str = Field(..., description="Template identifier")
    name: str = Field(..., description="Template name")
    description: str = Field(..., description="Template description")
    format: ReportFormat = Field(..., description="Report format")
    template_path: str = Field(..., description="Template file path")
    variables: Dict[str, str] = Field(default_factory=dict, description="Template variables")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True


class ExportConfiguration(BaseModel):
    """Model for export configuration."""
    
    format: ReportFormat = Field(..., description="Export format")
    output_path: str = Field(..., description="Output file path")
    include_charts: bool = Field(True, description="Include charts in export")
    include_raw_data: bool = Field(False, description="Include raw event data")
    compress: bool = Field(False, description="Compress output file")
    encryption: Optional[str] = Field(None, description="Encryption method")
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True