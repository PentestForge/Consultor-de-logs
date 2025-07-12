"""Tests for log reader functionality."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from consultor_logs.core.log_reader import MockWindowsLogReader, create_log_reader
from consultor_logs.models.events import EventType


class TestMockWindowsLogReader:
    """Test MockWindowsLogReader functionality."""
    
    def test_create_mock_reader(self):
        """Test creating a mock log reader."""
        reader = MockWindowsLogReader()
        assert reader.computer_name == "localhost"
        assert reader.timeout == 30
    
    def test_connection_test(self):
        """Test connection test always succeeds for mock."""
        reader = MockWindowsLogReader()
        assert reader.test_connection() is True
    
    def test_get_available_logs(self):
        """Test getting available logs."""
        reader = MockWindowsLogReader()
        logs = reader.get_available_logs()
        
        assert isinstance(logs, list)
        assert "Security" in logs
        assert "System" in logs
        assert "Application" in logs
        assert len(logs) > 0
    
    def test_get_log_statistics(self):
        """Test getting log statistics."""
        reader = MockWindowsLogReader()
        stats = reader.get_log_statistics("Security")
        
        assert isinstance(stats, dict)
        assert "log_name" in stats
        assert "file_size" in stats
        assert "event_count" in stats
        assert stats["log_name"] == "Security"
    
    def test_read_events_basic(self):
        """Test basic event reading."""
        reader = MockWindowsLogReader()
        events = list(reader.read_events())
        
        assert len(events) > 0
        for event in events:
            assert hasattr(event, 'event_id')
            assert hasattr(event, 'event_type')
            assert hasattr(event, 'timestamp')
            assert hasattr(event, 'description')
    
    def test_read_events_with_filters(self):
        """Test event reading with filters."""
        reader = MockWindowsLogReader()
        
        # Test with specific event IDs
        events = list(reader.read_events(event_ids=[4624, 4625]))
        
        for event in events:
            assert event.event_id in [4624, 4625]
    
    def test_read_events_with_time_range(self):
        """Test event reading with time range."""
        reader = MockWindowsLogReader()
        
        start_time = datetime.now() - timedelta(hours=1)
        end_time = datetime.now()
        
        events = list(reader.read_events(
            start_time=start_time,
            end_time=end_time
        ))
        
        for event in events:
            assert start_time <= event.timestamp <= end_time
    
    def test_read_events_max_limit(self):
        """Test event reading respects max limit."""
        reader = MockWindowsLogReader()
        max_events = 2
        
        events = list(reader.read_events(max_events=max_events))
        
        assert len(events) <= max_events


class TestLogReaderFactory:
    """Test log reader factory function."""
    
    @patch('consultor_logs.core.log_reader.WINDOWS_AVAILABLE', False)
    def test_create_mock_when_windows_unavailable(self):
        """Test that mock reader is created when Windows libraries unavailable."""
        reader = create_log_reader()
        assert isinstance(reader, MockWindowsLogReader)
    
    def test_create_reader_with_custom_params(self):
        """Test creating reader with custom parameters."""
        reader = create_log_reader(computer_name="test-computer", timeout=60)
        assert reader.computer_name == "test-computer"
        assert reader.timeout == 60