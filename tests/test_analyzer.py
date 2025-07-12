"""Tests for security analyzer functionality."""

import pytest
from datetime import datetime, timedelta

from consultor_logs.core.analyzer import SecurityAnalyzer
from consultor_logs.models.events import SecurityEvent, EventType, AnomalyType, SeverityLevel


class TestSecurityAnalyzer:
    """Test SecurityAnalyzer functionality."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = SecurityAnalyzer()
        assert analyzer.config is not None
        assert analyzer.events_df is None
        assert analyzer.detected_anomalies == []
    
    def test_analyzer_with_custom_config(self):
        """Test analyzer with custom configuration."""
        custom_config = {
            'failed_logon_threshold': 10,
            'confidence_threshold': 0.8
        }
        analyzer = SecurityAnalyzer(custom_config)
        
        assert analyzer.config['failed_logon_threshold'] == 10
        assert analyzer.config['confidence_threshold'] == 0.8
    
    def test_load_empty_events(self):
        """Test loading empty events list."""
        analyzer = SecurityAnalyzer()
        analyzer.load_events([])
        
        assert analyzer.events_df is None
    
    def test_load_events(self):
        """Test loading events."""
        analyzer = SecurityAnalyzer()
        
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        events = [
            SecurityEvent(
                event_id=4624,
                event_type=EventType.LOGON,
                timestamp=base_time,
                source="Security",
                computer_name="TEST-PC",
                username="user1",
                description="Successful logon"
            ),
            SecurityEvent(
                event_id=4625,
                event_type=EventType.FAILED_LOGON,
                timestamp=base_time + timedelta(minutes=1),
                source="Security",
                computer_name="TEST-PC",
                username="user2",
                description="Failed logon"
            )
        ]
        
        analyzer.load_events(events)
        
        assert analyzer.events_df is not None
        assert len(analyzer.events_df) == 2
        assert 'event_type' in analyzer.events_df.columns
        assert 'username' in analyzer.events_df.columns
    
    def test_analyze_failed_logons(self):
        """Test failed logon analysis."""
        analyzer = SecurityAnalyzer()
        
        # Create multiple failed logon events for the same user
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        events = []
        
        for i in range(6):  # More than threshold (5)
            event = SecurityEvent(
                event_id=4625,
                event_type=EventType.FAILED_LOGON,
                timestamp=base_time + timedelta(seconds=i * 30),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                ip_address="192.168.1.100",
                description=f"Failed logon attempt {i+1}"
            )
            events.append(event)
        
        analyzer.load_events(events)
        anomalies = analyzer._analyze_failed_logons()
        
        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == AnomalyType.MULTIPLE_FAILED_LOGONS
        assert anomalies[0].severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_analyze_privilege_escalation(self):
        """Test privilege escalation analysis."""
        analyzer = SecurityAnalyzer()
        
        # Create privilege escalation events
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        events = [
            SecurityEvent(
                event_id=4672,
                event_type=EventType.PRIVILEGE_ESCALATION,
                timestamp=base_time,
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description="Special privileges assigned"
            ),
            SecurityEvent(
                event_id=4673,
                event_type=EventType.PRIVILEGE_ESCALATION,
                timestamp=base_time + timedelta(minutes=2),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description="Privileged service called"
            )
        ]
        
        analyzer.load_events(events)
        anomalies = analyzer._analyze_privilege_escalation()
        
        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == AnomalyType.PRIVILEGE_ESCALATION
    
    def test_off_hours_analysis(self):
        """Test off-hours activity analysis."""
        analyzer = SecurityAnalyzer()
        
        # Create events during off-hours (default: 22:00-06:00)
        yesterday = datetime.now() - timedelta(days=1)  # Use yesterday
        off_hours_time = yesterday.replace(hour=23, minute=30)  # 11:30 PM yesterday
        
        events = []
        for i in range(4):  # Significant off-hours activity
            event = SecurityEvent(
                event_id=4624,
                event_type=EventType.LOGON,
                timestamp=off_hours_time + timedelta(minutes=i * 10),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description=f"Off-hours logon {i+1}"
            )
            events.append(event)
        
        analyzer.load_events(events)
        anomalies = analyzer._analyze_off_hours_activity()
        
        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == AnomalyType.OFF_HOURS_ACCESS
    
    def test_suspicious_processes(self):
        """Test suspicious process analysis."""
        analyzer = SecurityAnalyzer()
        
        events = []
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        for i in range(4):  # Multiple suspicious process executions
            event = SecurityEvent(
                event_id=4688,
                event_type=EventType.PROCESS_CREATION,
                timestamp=base_time + timedelta(minutes=i),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                process_name="powershell.exe",
                description=f"PowerShell execution {i+1}"
            )
            events.append(event)
        
        analyzer.load_events(events)
        anomalies = analyzer._analyze_suspicious_processes()
        
        assert len(anomalies) > 0
        assert anomalies[0].anomaly_type == AnomalyType.UNUSUAL_PROCESS
    
    def test_analyze_all(self):
        """Test comprehensive analysis."""
        analyzer = SecurityAnalyzer()
        
        # Create a mix of events
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        events = [
            # Failed logons
            SecurityEvent(
                event_id=4625,
                event_type=EventType.FAILED_LOGON,
                timestamp=base_time,
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description="Failed logon 1"
            ),
            SecurityEvent(
                event_id=4625,
                event_type=EventType.FAILED_LOGON,
                timestamp=base_time + timedelta(seconds=30),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description="Failed logon 2"
            ),
            # Successful logon
            SecurityEvent(
                event_id=4624,
                event_type=EventType.LOGON,
                timestamp=base_time + timedelta(minutes=1),
                source="Security",
                computer_name="TEST-PC",
                username="testuser",
                description="Successful logon"
            )
        ]
        
        analyzer.load_events(events)
        anomalies = analyzer.analyze_all()
        
        assert isinstance(anomalies, list)
        # Should detect correlation anomaly (failed then success)
        
    def test_get_statistics(self):
        """Test getting analysis statistics."""
        analyzer = SecurityAnalyzer()
        
        base_time = datetime.now() - timedelta(hours=1)  # Use past time
        events = [
            SecurityEvent(
                event_id=4624,
                event_type=EventType.LOGON,
                timestamp=base_time,
                source="Security",
                computer_name="TEST-PC",
                username="user1",
                description="Logon"
            ),
            SecurityEvent(
                event_id=4625,
                event_type=EventType.FAILED_LOGON,
                timestamp=base_time + timedelta(minutes=1),
                source="Security",
                computer_name="TEST-PC",
                username="user2",
                description="Failed logon"
            )
        ]
        
        analyzer.load_events(events)
        stats = analyzer.get_statistics()
        
        assert isinstance(stats, dict)
        assert 'total_events' in stats
        assert 'unique_users' in stats
        assert 'unique_computers' in stats
        assert stats['total_events'] == 2
        assert stats['unique_users'] == 2
        assert stats['unique_computers'] == 1