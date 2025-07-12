"""
Helper utilities for consultor_logs.

This module provides various utility functions for time handling, validation,
and data formatting.
"""

import re
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import ipaddress
from loguru import logger


class TimeHelper:
    """Helper class for time-related operations."""
    
    @staticmethod
    def parse_time_range(start_str: str, end_str: str) -> Dict[str, datetime]:
        """Parse time range strings into datetime objects."""
        try:
            start_time = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            
            if start_time > end_time:
                raise ValueError("Start time must be before end time")
            
            return {"start": start_time, "end": end_time}
            
        except ValueError as e:
            logger.error(f"Error parsing time range: {e}")
            raise
    
    @staticmethod
    def is_off_hours(timestamp: datetime, off_hours_start: int = 22, off_hours_end: int = 6) -> bool:
        """Check if timestamp falls within off-hours."""
        hour = timestamp.hour
        
        if off_hours_start > off_hours_end:
            # Crosses midnight (e.g., 22:00 to 06:00)
            return hour >= off_hours_start or hour <= off_hours_end
        else:
            # Same day (e.g., 13:00 to 14:00)
            return off_hours_start <= hour <= off_hours_end
    
    @staticmethod
    def is_weekend(timestamp: datetime) -> bool:
        """Check if timestamp falls on weekend."""
        return timestamp.weekday() >= 5  # Saturday = 5, Sunday = 6
    
    @staticmethod
    def get_time_buckets(start_time: datetime, end_time: datetime, bucket_size: int = 3600) -> List[datetime]:
        """Get time buckets for temporal analysis."""
        buckets = []
        current = start_time
        
        while current <= end_time:
            buckets.append(current)
            current += timedelta(seconds=bucket_size)
        
        return buckets
    
    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format duration in seconds to human-readable format."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        elif seconds < 86400:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d {hours}h"
    
    @staticmethod
    def get_relative_time(timestamp: datetime) -> str:
        """Get relative time description."""
        now = datetime.now()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "just now"


class ValidationHelper:
    """Helper class for data validation."""
    
    @staticmethod
    def is_valid_ip(ip_string: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 255:
            return False
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check for valid characters and structure
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, domain) is not None
    
    @staticmethod
    def is_valid_username(username: str) -> bool:
        """Validate username format."""
        if not username or len(username) > 256:
            return False
        
        # Basic validation - no control characters
        return not any(ord(c) < 32 for c in username)
    
    @staticmethod
    def is_suspicious_process(process_name: str, patterns: List[str]) -> bool:
        """Check if process name matches suspicious patterns."""
        if not process_name:
            return False
        
        process_lower = process_name.lower()
        return any(pattern.lower() in process_lower for pattern in patterns)
    
    @staticmethod
    def validate_event_id(event_id: int) -> bool:
        """Validate Windows event ID."""
        return 0 < event_id <= 65535
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe file operations."""
        # Remove invalid characters
        invalid_chars = r'[<>:"/\\|?*]'
        sanitized = re.sub(invalid_chars, '_', filename)
        
        # Remove leading/trailing whitespace and dots
        sanitized = sanitized.strip('. ')
        
        # Ensure filename is not empty
        if not sanitized:
            sanitized = "unnamed_file"
        
        return sanitized


class FormatHelper:
    """Helper class for data formatting."""
    
    @staticmethod
    def format_bytes(bytes_count: int) -> str:
        """Format bytes to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    
    @staticmethod
    def format_number(number: int) -> str:
        """Format number with thousand separators."""
        return f"{number:,}"
    
    @staticmethod
    def truncate_string(text: str, max_length: int = 100) -> str:
        """Truncate string to maximum length."""
        if len(text) <= max_length:
            return text
        return text[:max_length - 3] + "..."
    
    @staticmethod
    def format_event_description(description: str) -> str:
        """Format event description for display."""
        # Remove excessive whitespace
        formatted = re.sub(r'\s+', ' ', description.strip())
        
        # Truncate if too long
        if len(formatted) > 500:
            formatted = formatted[:497] + "..."
        
        return formatted
    
    @staticmethod
    def create_event_hash(event_data: Dict[str, Any]) -> str:
        """Create hash for event deduplication."""
        # Create a string representation of key event fields
        key_fields = [
            str(event_data.get('event_id', '')),
            str(event_data.get('computer_name', '')),
            str(event_data.get('username', '')),
            str(event_data.get('process_name', '')),
            str(event_data.get('description', ''))[:100],  # First 100 chars
        ]
        
        hash_input = '|'.join(key_fields)
        return hashlib.md5(hash_input.encode()).hexdigest()
    
    @staticmethod
    def format_confidence_score(confidence: float) -> str:
        """Format confidence score as percentage."""
        return f"{confidence * 100:.1f}%"
    
    @staticmethod
    def format_severity_badge(severity: str) -> str:
        """Format severity as colored badge (for HTML reports)."""
        colors = {
            'low': '#28a745',
            'medium': '#ffc107',
            'high': '#fd7e14',
            'critical': '#dc3545'
        }
        
        color = colors.get(severity.lower(), '#6c757d')
        return f'<span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">{severity.upper()}</span>'


class CryptoHelper:
    """Helper class for cryptographic operations."""
    
    @staticmethod
    def generate_secure_id(length: int = 16) -> str:
        """Generate secure random ID."""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: str = "") -> str:
        """Hash sensitive data for storage."""
        combined = data + salt
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @staticmethod
    def verify_hash(data: str, hash_value: str, salt: str = "") -> bool:
        """Verify hashed data."""
        expected_hash = CryptoHelper.hash_sensitive_data(data, salt)
        return hash_value == expected_hash


class FileHelper:
    """Helper class for file operations."""
    
    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> Path:
        """Ensure directory exists, create if needed."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @staticmethod
    def get_safe_filename(base_name: str, extension: str = "", timestamp: bool = True) -> str:
        """Generate safe filename with optional timestamp."""
        # Sanitize base name
        safe_name = ValidationHelper.sanitize_filename(base_name)
        
        # Add timestamp if requested
        if timestamp:
            now = datetime.now()
            timestamp_str = now.strftime("%Y%m%d_%H%M%S")
            safe_name = f"{safe_name}_{timestamp_str}"
        
        # Add extension
        if extension and not extension.startswith('.'):
            extension = '.' + extension
        
        return safe_name + extension
    
    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """Get file size in bytes."""
        return Path(file_path).stat().st_size
    
    @staticmethod
    def is_file_writable(file_path: Union[str, Path]) -> bool:
        """Check if file path is writable."""
        path = Path(file_path)
        
        if path.exists():
            return os.access(path, os.W_OK)
        else:
            # Check if parent directory is writable
            parent = path.parent
            return parent.exists() and os.access(parent, os.W_OK)


class NetworkHelper:
    """Helper class for network-related operations."""
    
    @staticmethod
    def is_private_ip(ip_string: str) -> bool:
        """Check if IP address is private."""
        try:
            ip = ipaddress.ip_address(ip_string)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_local_ip(ip_string: str) -> bool:
        """Check if IP address is local."""
        try:
            ip = ipaddress.ip_address(ip_string)
            return ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_info(ip_string: str) -> Dict[str, Any]:
        """Get information about IP address."""
        try:
            ip = ipaddress.ip_address(ip_string)
            return {
                'is_private': ip.is_private,
                'is_loopback': ip.is_loopback,
                'is_multicast': ip.is_multicast,
                'is_link_local': ip.is_link_local,
                'is_global': ip.is_global,
                'version': ip.version
            }
        except ValueError:
            return {'error': 'Invalid IP address'}