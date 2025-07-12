"""
Windows log reader for accessing Windows Event Viewer logs.

This module provides functionality to read and parse Windows security logs
using the Windows API through pywin32 and WMI.
"""

import os
import sys
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Iterator, Union
from pathlib import Path

from loguru import logger
from pydantic import ValidationError

from ..models.events import SecurityEvent, EventType, LogSource
from ..utils.helpers import ValidationHelper, FormatHelper, TimeHelper

# Windows-specific imports (only available on Windows)
if os.name == 'nt':
    try:
        import win32evtlog
        import win32con
        import win32api
        import win32security
        import wmi
        WINDOWS_AVAILABLE = True
    except ImportError as e:
        logger.warning(f"Windows libraries not available: {e}")
        WINDOWS_AVAILABLE = False
else:
    WINDOWS_AVAILABLE = False


class WindowsLogReader:
    """Windows Event Log reader using Windows API."""
    
    def __init__(self, computer_name: str = "localhost", timeout: int = 30):
        """
        Initialize Windows log reader.
        
        Args:
            computer_name: Name of the computer to read logs from
            timeout: Query timeout in seconds
        """
        self.computer_name = computer_name
        self.timeout = timeout
        self._wmi_connection: Optional[Any] = None
        
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows libraries not available. Log reading will be limited.")
    
    def _get_wmi_connection(self) -> Any:
        """Get WMI connection, creating if needed."""
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("Windows libraries not available")
        
        if self._wmi_connection is None:
            try:
                if self.computer_name.lower() in ['localhost', '127.0.0.1', '.']:
                    self._wmi_connection = wmi.WMI()
                else:
                    self._wmi_connection = wmi.WMI(computer=self.computer_name)
                logger.info(f"Connected to WMI on {self.computer_name}")
            except Exception as e:
                logger.error(f"Failed to connect to WMI: {e}")
                raise
        
        return self._wmi_connection
    
    def _map_event_type(self, event_id: int, log_name: str) -> EventType:
        """Map Windows event ID to our event type enum."""
        # Security log event ID mappings
        security_mappings = {
            4624: EventType.LOGON,           # Successful logon
            4625: EventType.FAILED_LOGON,    # Failed logon
            4634: EventType.LOGOFF,          # Logoff
            4647: EventType.LOGOFF,          # User initiated logoff
            4672: EventType.PRIVILEGE_ESCALATION,  # Special privileges assigned
            4673: EventType.PRIVILEGE_ESCALATION,  # Privileged service called
            4674: EventType.PRIVILEGE_ESCALATION,  # Operation performed on privileged object
            4728: EventType.ACCOUNT_MANAGEMENT,    # Member added to security group
            4732: EventType.ACCOUNT_MANAGEMENT,    # Member added to security local group
            4756: EventType.ACCOUNT_MANAGEMENT,    # Member added to universal security group
            4688: EventType.PROCESS_CREATION,      # Process created
            4689: EventType.PROCESS_CREATION,      # Process terminated
            4656: EventType.FILE_ACCESS,           # Handle to object requested
            4658: EventType.FILE_ACCESS,           # Handle to object closed
            4719: EventType.POLICY_CHANGE,         # System audit policy changed
            4739: EventType.POLICY_CHANGE,         # Domain policy changed
            4713: EventType.POLICY_CHANGE,         # Kerberos policy changed
        }
        
        # System log mappings
        system_mappings = {
            7034: EventType.SYSTEM_EVENT,    # Service crashed
            7035: EventType.SYSTEM_EVENT,    # Service sent control
            7036: EventType.SYSTEM_EVENT,    # Service started/stopped
            1074: EventType.SYSTEM_EVENT,    # System shutdown
            6005: EventType.SYSTEM_EVENT,    # Event log service started
            6006: EventType.SYSTEM_EVENT,    # Event log service stopped
        }
        
        if log_name.lower() == 'security':
            return security_mappings.get(event_id, EventType.OTHER)
        elif log_name.lower() == 'system':
            return system_mappings.get(event_id, EventType.SYSTEM_EVENT)
        else:
            return EventType.OTHER
    
    def _parse_event_data(self, event: Any) -> Dict[str, Any]:
        """Parse WMI event object into dictionary."""
        try:
            # Extract basic event information
            event_data = {
                'event_id': int(event.EventCode) if event.EventCode else 0,
                'timestamp': self._parse_wmi_time(event.TimeGenerated),
                'computer_name': event.ComputerName or self.computer_name,
                'source': event.SourceName or 'Unknown',
                'log_name': event.LogFile or 'Unknown',
                'description': event.Message or '',
                'category': event.CategoryString or '',
                'user': event.User or '',
                'type': event.Type or 0,
                'raw_data': {}
            }
            
            # Extract additional fields if available
            if hasattr(event, 'EventIdentifier'):
                event_data['raw_data']['event_identifier'] = event.EventIdentifier
            
            if hasattr(event, 'InsertionStrings') and event.InsertionStrings:
                event_data['raw_data']['insertion_strings'] = list(event.InsertionStrings)
            
            if hasattr(event, 'Data') and event.Data:
                event_data['raw_data']['data'] = list(event.Data)
            
            return event_data
            
        except Exception as e:
            logger.error(f"Error parsing event data: {e}")
            return {}
    
    def _parse_wmi_time(self, wmi_time: str) -> datetime:
        """Parse WMI datetime string to Python datetime."""
        try:
            if not wmi_time:
                return datetime.now()
            
            # WMI time format: YYYYMMDDHHMMSS.mmmmmm+UUU
            # Extract the main part before the timezone offset
            time_part = wmi_time.split('.')[0]
            return datetime.strptime(time_part, '%Y%m%d%H%M%S')
            
        except (ValueError, AttributeError) as e:
            logger.warning(f"Error parsing WMI time '{wmi_time}': {e}")
            return datetime.now()
    
    def _extract_security_fields(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security-specific fields from event data."""
        security_fields = {}
        
        # Extract username from various sources
        username = None
        if event_data.get('user'):
            username = event_data['user']
        elif 'insertion_strings' in event_data.get('raw_data', {}):
            strings = event_data['raw_data']['insertion_strings']
            if strings and len(strings) > 1:
                username = strings[1]  # Often the second string is username
        
        if username:
            security_fields['username'] = username
            # Extract domain if present
            if '\\' in username:
                domain, user = username.split('\\', 1)
                security_fields['domain'] = domain
                security_fields['username'] = user
        
        # Extract IP address from insertion strings
        if 'insertion_strings' in event_data.get('raw_data', {}):
            strings = event_data['raw_data']['insertion_strings']
            for string in strings:
                if string and ValidationHelper.is_valid_ip(string):
                    security_fields['ip_address'] = string
                    break
        
        # Extract process information from description
        description = event_data.get('description', '')
        process_patterns = [
            r'Process Name:\s*(.+?)(?:\r?\n|$)',
            r'Process:\s*(.+?)(?:\r?\n|$)',
            r'Application:\s*(.+?)(?:\r?\n|$)'
        ]
        
        for pattern in process_patterns:
            import re
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                process_path = match.group(1).strip()
                if process_path and process_path != '-':
                    security_fields['process_name'] = Path(process_path).name
                    break
        
        # Extract process ID
        pid_patterns = [
            r'Process ID:\s*(\d+)',
            r'PID:\s*(\d+)',
            r'ProcessId:\s*(\d+)'
        ]
        
        for pattern in pid_patterns:
            import re
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                security_fields['process_id'] = int(match.group(1))
                break
        
        return security_fields
    
    def read_events(
        self,
        log_name: str = "Security",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_ids: Optional[List[int]] = None,
        max_events: int = 1000
    ) -> Iterator[SecurityEvent]:
        """
        Read security events from Windows Event Log.
        
        Args:
            log_name: Name of the Windows log (Security, System, Application)
            start_time: Start time for event filtering
            end_time: End time for event filtering
            event_ids: List of specific event IDs to filter
            max_events: Maximum number of events to return
            
        Yields:
            SecurityEvent objects
        """
        if not WINDOWS_AVAILABLE:
            logger.error("Cannot read Windows events: Windows libraries not available")
            return
        
        try:
            wmi_conn = self._get_wmi_connection()
            
            # Build WQL query
            query = f"SELECT * FROM Win32_NTLogEvent WHERE LogFile = '{log_name}'"
            
            # Add time filters
            if start_time:
                start_wmi = start_time.strftime('%Y%m%d%H%M%S.000000+000')
                query += f" AND TimeGenerated >= '{start_wmi}'"
            
            if end_time:
                end_wmi = end_time.strftime('%Y%m%d%H%M%S.000000+000')
                query += f" AND TimeGenerated <= '{end_wmi}'"
            
            # Add event ID filter
            if event_ids:
                id_filter = " OR ".join([f"EventCode = {eid}" for eid in event_ids])
                query += f" AND ({id_filter})"
            
            # Order by time (newest first)
            query += " ORDER BY TimeGenerated DESC"
            
            logger.info(f"Executing WMI query: {query}")
            
            # Execute query with timeout
            events = wmi_conn.query(query)
            
            count = 0
            for event in events:
                if count >= max_events:
                    break
                
                try:
                    # Parse event data
                    event_data = self._parse_event_data(event)
                    if not event_data:
                        continue
                    
                    # Extract security-specific fields
                    security_fields = self._extract_security_fields(event_data)
                    
                    # Create SecurityEvent object
                    security_event = SecurityEvent(
                        event_id=event_data['event_id'],
                        event_type=self._map_event_type(event_data['event_id'], log_name),
                        timestamp=event_data['timestamp'],
                        source=event_data['source'],
                        computer_name=event_data['computer_name'],
                        username=security_fields.get('username'),
                        domain=security_fields.get('domain'),
                        process_name=security_fields.get('process_name'),
                        process_id=security_fields.get('process_id'),
                        ip_address=security_fields.get('ip_address'),
                        description=FormatHelper.format_event_description(event_data['description']),
                        raw_data=event_data['raw_data']
                    )
                    
                    yield security_event
                    count += 1
                    
                except ValidationError as e:
                    logger.warning(f"Invalid event data: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
                    continue
            
            logger.info(f"Successfully read {count} events from {log_name} log")
            
        except Exception as e:
            logger.error(f"Error reading Windows events: {e}")
            raise
    
    def get_available_logs(self) -> List[str]:
        """Get list of available Windows event logs."""
        if not WINDOWS_AVAILABLE:
            logger.error("Cannot get log list: Windows libraries not available")
            return []
        
        try:
            wmi_conn = self._get_wmi_connection()
            logs = []
            
            # Query for available event logs
            log_files = wmi_conn.query("SELECT LogFileName FROM Win32_NTEventLogFile")
            
            for log_file in log_files:
                if log_file.LogFileName:
                    logs.append(log_file.LogFileName)
            
            logger.info(f"Found {len(logs)} available logs")
            return sorted(logs)
            
        except Exception as e:
            logger.error(f"Error getting available logs: {e}")
            return []
    
    def get_log_statistics(self, log_name: str = "Security") -> Dict[str, Any]:
        """Get statistics for a specific log."""
        if not WINDOWS_AVAILABLE:
            logger.error("Cannot get log statistics: Windows libraries not available")
            return {}
        
        try:
            wmi_conn = self._get_wmi_connection()
            
            # Get log file information
            log_query = f"SELECT * FROM Win32_NTEventLogFile WHERE LogFileName = '{log_name}'"
            log_files = list(wmi_conn.query(log_query))
            
            if not log_files:
                logger.warning(f"Log '{log_name}' not found")
                return {}
            
            log_file = log_files[0]
            
            # Get event count
            count_query = f"SELECT COUNT(*) FROM Win32_NTLogEvent WHERE LogFile = '{log_name}'"
            event_count = 0
            try:
                count_result = list(wmi_conn.query(count_query))
                if count_result:
                    event_count = getattr(count_result[0], 'COUNT(*)', 0) or 0
            except:
                logger.warning("Could not get event count")
            
            statistics = {
                'log_name': log_name,
                'file_size': getattr(log_file, 'FileSize', 0) or 0,
                'max_file_size': getattr(log_file, 'MaxFileSize', 0) or 0,
                'event_count': event_count,
                'last_accessed': getattr(log_file, 'LastAccessed', ''),
                'last_modified': getattr(log_file, 'LastModified', ''),
                'archive': getattr(log_file, 'Archive', False),
                'compressed': getattr(log_file, 'Compressed', False),
            }
            
            return statistics
            
        except Exception as e:
            logger.error(f"Error getting log statistics: {e}")
            return {}
    
    def test_connection(self) -> bool:
        """Test connection to Windows Event Log service."""
        if not WINDOWS_AVAILABLE:
            logger.error("Windows libraries not available")
            return False
        
        try:
            wmi_conn = self._get_wmi_connection()
            
            # Try a simple query
            test_query = "SELECT COUNT(*) FROM Win32_NTLogEvent WHERE LogFile = 'System'"
            list(wmi_conn.query(test_query))
            
            logger.success(f"Successfully connected to Windows Event Log on {self.computer_name}")
            return True
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def close(self) -> None:
        """Close WMI connection."""
        if self._wmi_connection:
            try:
                # WMI connections don't need explicit closing in most cases
                self._wmi_connection = None
                logger.info("WMI connection closed")
            except Exception as e:
                logger.warning(f"Error closing WMI connection: {e}")


class MockWindowsLogReader(WindowsLogReader):
    """Mock implementation for testing on non-Windows systems."""
    
    def __init__(self, computer_name: str = "localhost", timeout: int = 30):
        """Initialize mock log reader."""
        self.computer_name = computer_name
        self.timeout = timeout
        self._wmi_connection = None
        logger.info("Using mock Windows log reader for testing")
    
    def read_events(
        self,
        log_name: str = "Security",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_ids: Optional[List[int]] = None,
        max_events: int = 1000
    ) -> Iterator[SecurityEvent]:
        """Generate mock security events for testing."""
        logger.info(f"Generating mock events for {log_name} log")
        
        # Generate some sample events
        mock_events = [
            {
                'event_id': 4624,
                'event_type': EventType.LOGON,
                'username': 'testuser',
                'domain': 'TESTDOMAIN',
                'ip_address': '192.168.1.100',
                'description': 'An account was successfully logged on.'
            },
            {
                'event_id': 4625,
                'event_type': EventType.FAILED_LOGON,
                'username': 'baduser',
                'ip_address': '10.0.0.50',
                'description': 'An account failed to log on.'
            },
            {
                'event_id': 4672,
                'event_type': EventType.PRIVILEGE_ESCALATION,
                'username': 'admin',
                'description': 'Special privileges assigned to new logon.'
            }
        ]
        
        count = 0
        for mock_data in mock_events:
            if count >= max_events:
                break
            
            # Apply event ID filter if specified
            if event_ids and mock_data['event_id'] not in event_ids:
                continue
            
            # Create mock timestamp within the time range
            if start_time and end_time:
                # Generate timestamp within the specified range
                time_diff = (end_time - start_time).total_seconds()
                timestamp = start_time + timedelta(seconds=(time_diff * 0.5) - (count * 300))  # Spread events
            else:
                timestamp = datetime.now() - timedelta(minutes=count * 5)
            
            # Apply time filters
            if start_time and timestamp < start_time:
                continue
            if end_time and timestamp > end_time:
                continue
            
            try:
                event = SecurityEvent(
                    event_id=mock_data['event_id'],
                    event_type=mock_data['event_type'],
                    timestamp=timestamp,
                    source=f"Mock-{log_name}",
                    computer_name=self.computer_name,
                    username=mock_data.get('username'),
                    domain=mock_data.get('domain'),
                    ip_address=mock_data.get('ip_address'),
                    description=mock_data['description'],
                    raw_data={'mock': True}
                )
                
                yield event
                count += 1
                
            except ValidationError as e:
                logger.warning(f"Invalid mock event data: {e}")
                continue
    
    def get_available_logs(self) -> List[str]:
        """Return mock available logs."""
        return ["Security", "System", "Application", "Setup"]
    
    def get_log_statistics(self, log_name: str = "Security") -> Dict[str, Any]:
        """Return mock log statistics."""
        return {
            'log_name': log_name,
            'file_size': 1024000,
            'max_file_size': 20971520,
            'event_count': 500,
            'last_accessed': datetime.now().isoformat(),
            'last_modified': datetime.now().isoformat(),
            'archive': False,
            'compressed': False,
        }
    
    def test_connection(self) -> bool:
        """Mock connection test always succeeds."""
        logger.info("Mock connection test successful")
        return True


def create_log_reader(computer_name: str = "localhost", timeout: int = 30) -> WindowsLogReader:
    """
    Create appropriate log reader based on platform.
    
    Args:
        computer_name: Name of the computer to read logs from
        timeout: Query timeout in seconds
        
    Returns:
        WindowsLogReader or MockWindowsLogReader
    """
    if WINDOWS_AVAILABLE:
        return WindowsLogReader(computer_name, timeout)
    else:
        logger.warning("Windows libraries not available, using mock implementation")
        return MockWindowsLogReader(computer_name, timeout)