"""
Security analyzer for detecting anomalies and threats in Windows logs.

This module provides comprehensive anomaly detection capabilities including
pattern matching, statistical analysis, and behavioral analysis.
"""

import uuid
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
import pandas as pd
from loguru import logger

from ..models.events import SecurityEvent, AnomalyDetection, AnomalyType, SeverityLevel, EventType
from ..models.reports import ThreatIndicator
from ..utils.helpers import TimeHelper, ValidationHelper, CryptoHelper


class SecurityAnalyzer:
    """Security analyzer for detecting anomalies in Windows logs."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize security analyzer.
        
        Args:
            config: Analysis configuration parameters
        """
        self.config = config or self._get_default_config()
        self.events_df: Optional[pd.DataFrame] = None
        self.detected_anomalies: List[AnomalyDetection] = []
        self.threat_indicators: List[ThreatIndicator] = []
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default analysis configuration."""
        return {
            'failed_logon_threshold': 5,
            'failed_logon_window': 300,  # 5 minutes
            'off_hours_start': 22,
            'off_hours_end': 6,
            'privilege_escalation_events': [4672, 4673, 4674, 4728, 4732, 4756],
            'suspicious_process_patterns': ['powershell.exe', 'cmd.exe', 'wmic.exe', 'net.exe'],
            'confidence_threshold': 0.7,
            'max_events_per_analysis': 50000,
            'time_bucket_size': 3600,  # 1 hour
        }
    
    def load_events(self, events: List[SecurityEvent]) -> None:
        """
        Load security events for analysis.
        
        Args:
            events: List of security events to analyze
        """
        if not events:
            logger.warning("No events provided for analysis")
            return
        
        logger.info(f"Loading {len(events)} events for analysis")
        
        # Convert events to DataFrame for easier analysis
        event_dicts = []
        for event in events:
            event_dict = event.dict()
            # Flatten nested fields
            if event_dict.get('raw_data'):
                for key, value in event_dict['raw_data'].items():
                    event_dict[f'raw_{key}'] = value
            event_dicts.append(event_dict)
        
        self.events_df = pd.DataFrame(event_dicts)
        
        # Convert timestamp to datetime if it's not already
        if not self.events_df.empty:
            self.events_df['timestamp'] = pd.to_datetime(self.events_df['timestamp'])
            self.events_df = self.events_df.sort_values('timestamp')
        
        logger.success(f"Loaded {len(self.events_df)} events into analyzer")
    
    def analyze_all(self) -> List[AnomalyDetection]:
        """
        Run all anomaly detection algorithms.
        
        Returns:
            List of detected anomalies
        """
        if self.events_df is None or self.events_df.empty:
            logger.warning("No events loaded for analysis")
            return []
        
        logger.info("Starting comprehensive security analysis")
        
        self.detected_anomalies = []
        
        # Run different anomaly detection methods
        analysis_methods = [
            self._analyze_failed_logons,
            self._analyze_privilege_escalation,
            self._analyze_off_hours_activity,
            self._analyze_suspicious_processes,
            self._analyze_policy_changes,
            self._analyze_account_anomalies,
            self._analyze_frequency_anomalies,
            self._analyze_correlation_anomalies,
        ]
        
        for method in analysis_methods:
            try:
                method_name = method.__name__
                logger.info(f"Running {method_name}")
                anomalies = method()
                if anomalies:
                    self.detected_anomalies.extend(anomalies)
                    logger.info(f"{method_name} detected {len(anomalies)} anomalies")
            except Exception as e:
                logger.error(f"Error in {method.__name__}: {e}")
        
        # Remove duplicates and sort by severity
        self.detected_anomalies = self._deduplicate_anomalies(self.detected_anomalies)
        self.detected_anomalies.sort(key=lambda x: self._severity_score(x.severity), reverse=True)
        
        logger.success(f"Analysis complete. Detected {len(self.detected_anomalies)} total anomalies")
        return self.detected_anomalies
    
    def _analyze_failed_logons(self) -> List[AnomalyDetection]:
        """Detect multiple failed logon attempts."""
        threshold = self.config['failed_logon_threshold']
        window_seconds = self.config['failed_logon_window']
        
        failed_logons = self.events_df[
            self.events_df['event_type'] == EventType.FAILED_LOGON.value
        ].copy()
        
        if failed_logons.empty:
            return []
        
        anomalies = []
        
        # Group by username and analyze patterns
        for username in failed_logons['username'].dropna().unique():
            user_failures = failed_logons[failed_logons['username'] == username].copy()
            user_failures = user_failures.sort_values('timestamp')
            
            # Use sliding window to detect burst of failures
            for i, row in user_failures.iterrows():
                window_start = row['timestamp']
                window_end = window_start + timedelta(seconds=window_seconds)
                
                window_failures = user_failures[
                    (user_failures['timestamp'] >= window_start) &
                    (user_failures['timestamp'] <= window_end)
                ]
                
                if len(window_failures) >= threshold:
                    # Check if we already have an anomaly for this timeframe
                    existing = any(
                        a.anomaly_type == AnomalyType.MULTIPLE_FAILED_LOGONS and
                        username in a.description and
                        abs((a.detection_time - window_start).total_seconds()) < window_seconds
                        for a in anomalies
                    )
                    
                    if not existing:
                        # Determine severity based on count and frequency
                        count = len(window_failures)
                        if count >= threshold * 3:
                            severity = SeverityLevel.CRITICAL
                            confidence = 0.95
                        elif count >= threshold * 2:
                            severity = SeverityLevel.HIGH
                            confidence = 0.85
                        else:
                            severity = SeverityLevel.MEDIUM
                            confidence = 0.75
                        
                        # Get unique IP addresses involved
                        ip_addresses = window_failures['ip_address'].dropna().unique()
                        ip_info = f" from {len(ip_addresses)} IP(s)" if len(ip_addresses) > 0 else ""
                        
                        # Create anomaly detection
                        events_list = [
                            SecurityEvent(**row.to_dict()) 
                            for _, row in window_failures.iterrows()
                        ]
                        
                        anomaly = AnomalyDetection(
                            anomaly_id=CryptoHelper.generate_secure_id(),
                            anomaly_type=AnomalyType.MULTIPLE_FAILED_LOGONS,
                            severity=severity,
                            confidence=confidence,
                            detection_time=window_start,
                            events=events_list,
                            description=f"Multiple failed logon attempts detected for user '{username}': {count} failures in {window_seconds} seconds{ip_info}",
                            recommendations=[
                                "Investigate the user account for potential compromise",
                                "Check if the failed logons are from legitimate user activity",
                                "Consider implementing account lockout policies",
                                "Monitor for successful logons from the same sources",
                                "Review password policies and user training"
                            ],
                            metadata={
                                'username': username,
                                'failure_count': count,
                                'time_window': window_seconds,
                                'ip_addresses': list(ip_addresses)
                            }
                        )
                        
                        anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_privilege_escalation(self) -> List[AnomalyDetection]:
        """Detect privilege escalation attempts."""
        escalation_events = self.config['privilege_escalation_events']
        
        priv_events = self.events_df[
            self.events_df['event_id'].isin(escalation_events)
        ].copy()
        
        if priv_events.empty:
            return []
        
        anomalies = []
        
        # Group by user and look for patterns
        for username in priv_events['username'].dropna().unique():
            user_events = priv_events[priv_events['username'] == username].copy()
            user_events = user_events.sort_values('timestamp')
            
            # Look for rapid privilege escalation (multiple events in short time)
            for i, row in user_events.iterrows():
                window_start = row['timestamp']
                window_end = window_start + timedelta(minutes=10)
                
                window_events = user_events[
                    (user_events['timestamp'] >= window_start) &
                    (user_events['timestamp'] <= window_end)
                ]
                
                if len(window_events) >= 2:  # Multiple privilege events
                    # Determine severity based on event types and frequency
                    unique_event_ids = window_events['event_id'].nunique()
                    if unique_event_ids >= 3:
                        severity = SeverityLevel.HIGH
                        confidence = 0.85
                    else:
                        severity = SeverityLevel.MEDIUM
                        confidence = 0.75
                    
                    # Check if user typically has these privileges
                    is_admin = self._is_likely_admin_user(username)
                    if not is_admin:
                        severity = SeverityLevel.HIGH
                        confidence = 0.9
                    
                    events_list = [
                        SecurityEvent(**row.to_dict()) 
                        for _, row in window_events.iterrows()
                    ]
                    
                    anomaly = AnomalyDetection(
                        anomaly_id=CryptoHelper.generate_secure_id(),
                        anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                        severity=severity,
                        confidence=confidence,
                        detection_time=window_start,
                        events=events_list,
                        description=f"Potential privilege escalation detected for user '{username}': {len(window_events)} privilege events in 10 minutes",
                        recommendations=[
                            "Verify if the privilege escalation was authorized",
                            "Check if the user requires these elevated privileges",
                            "Review the specific privileged operations performed",
                            "Monitor subsequent activity from this user account",
                            "Consider implementing just-in-time admin access"
                        ],
                        metadata={
                            'username': username,
                            'event_count': len(window_events),
                            'unique_event_types': list(window_events['event_id'].unique()),
                            'is_likely_admin': is_admin
                        }
                    )
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_off_hours_activity(self) -> List[AnomalyDetection]:
        """Detect activity during off-hours."""
        off_hours_start = self.config['off_hours_start']
        off_hours_end = self.config['off_hours_end']
        
        # Filter events during off-hours
        off_hours_events = self.events_df[
            self.events_df['timestamp'].apply(
                lambda x: TimeHelper.is_off_hours(x, off_hours_start, off_hours_end)
            )
        ].copy()
        
        if off_hours_events.empty:
            return []
        
        anomalies = []
        
        # Focus on interactive logons and administrative activity during off-hours
        significant_events = off_hours_events[
            (off_hours_events['event_type'].isin([
                EventType.LOGON.value, 
                EventType.PRIVILEGE_ESCALATION.value,
                EventType.POLICY_CHANGE.value
            ])) |
            (off_hours_events['event_id'].isin([4624, 4672, 4719]))  # Logon, special privileges, policy change
        ].copy()
        
        if significant_events.empty:
            return []
        
        # Group by user and date
        for username in significant_events['username'].dropna().unique():
            user_events = significant_events[significant_events['username'] == username].copy()
            
            # Group by date
            user_events['date'] = user_events['timestamp'].dt.date
            daily_groups = user_events.groupby('date')
            
            for date, day_events in daily_groups:
                if len(day_events) >= 3:  # Significant off-hours activity
                    # Check if this user typically works off-hours
                    is_regular_off_hours = self._is_regular_off_hours_user(username)
                    
                    if is_regular_off_hours:
                        severity = SeverityLevel.LOW
                        confidence = 0.6
                    else:
                        severity = SeverityLevel.MEDIUM
                        confidence = 0.8
                    
                    # Check for weekend activity
                    if TimeHelper.is_weekend(day_events.iloc[0]['timestamp']):
                        severity = SeverityLevel.HIGH
                        confidence = min(confidence + 0.1, 0.95)
                    
                    events_list = [
                        SecurityEvent(**row.to_dict()) 
                        for _, row in day_events.iterrows()
                    ]
                    
                    anomaly = AnomalyDetection(
                        anomaly_id=CryptoHelper.generate_secure_id(),
                        anomaly_type=AnomalyType.OFF_HOURS_ACCESS,
                        severity=severity,
                        confidence=confidence,
                        detection_time=day_events.iloc[0]['timestamp'],
                        events=events_list,
                        description=f"Off-hours activity detected for user '{username}' on {date}: {len(day_events)} significant events",
                        recommendations=[
                            "Verify if the off-hours access was authorized",
                            "Check if the user was scheduled to work during this time",
                            "Review the specific activities performed",
                            "Consider implementing time-based access controls",
                            "Monitor for data exfiltration or unauthorized changes"
                        ],
                        metadata={
                            'username': username,
                            'date': str(date),
                            'event_count': len(day_events),
                            'is_weekend': TimeHelper.is_weekend(day_events.iloc[0]['timestamp']),
                            'is_regular_off_hours_user': is_regular_off_hours
                        }
                    )
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_suspicious_processes(self) -> List[AnomalyDetection]:
        """Detect suspicious process executions."""
        suspicious_patterns = self.config['suspicious_process_patterns']
        
        process_events = self.events_df[
            (self.events_df['event_type'] == EventType.PROCESS_CREATION.value) |
            (self.events_df['process_name'].notna())
        ].copy()
        
        if process_events.empty:
            return []
        
        anomalies = []
        
        # Check for suspicious process patterns
        for pattern in suspicious_patterns:
            matching_events = process_events[
                process_events['process_name'].str.contains(pattern, case=False, na=False)
            ].copy()
            
            if matching_events.empty:
                continue
            
            # Group by user and look for unusual usage
            for username in matching_events['username'].dropna().unique():
                user_events = matching_events[matching_events['username'] == username].copy()
                
                # Check frequency and timing
                if len(user_events) >= 3:  # Multiple suspicious process executions
                    # Check if user typically runs these processes
                    is_typical = self._is_typical_process_for_user(username, pattern)
                    
                    if not is_typical:
                        severity = SeverityLevel.MEDIUM
                        confidence = 0.7
                        
                        # Higher severity for administrative tools
                        if pattern in ['wmic.exe', 'net.exe', 'powershell.exe']:
                            severity = SeverityLevel.HIGH
                            confidence = 0.8
                        
                        events_list = [
                            SecurityEvent(**row.to_dict()) 
                            for _, row in user_events.iterrows()
                        ]
                        
                        anomaly = AnomalyDetection(
                            anomaly_id=CryptoHelper.generate_secure_id(),
                            anomaly_type=AnomalyType.UNUSUAL_PROCESS,
                            severity=severity,
                            confidence=confidence,
                            detection_time=user_events.iloc[0]['timestamp'],
                            events=events_list,
                            description=f"Unusual process execution detected for user '{username}': {len(user_events)} instances of '{pattern}'",
                            recommendations=[
                                "Investigate the purpose of the process executions",
                                "Check if the user has legitimate need for these tools",
                                "Review command-line arguments if available",
                                "Monitor for signs of lateral movement or data collection",
                                "Consider implementing application whitelisting"
                            ],
                            metadata={
                                'username': username,
                                'process_pattern': pattern,
                                'execution_count': len(user_events),
                                'is_typical_for_user': is_typical
                            }
                        )
                        
                        anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_policy_changes(self) -> List[AnomalyDetection]:
        """Detect suspicious policy changes."""
        policy_events = self.events_df[
            self.events_df['event_type'] == EventType.POLICY_CHANGE.value
        ].copy()
        
        if policy_events.empty:
            return []
        
        anomalies = []
        
        # Look for multiple policy changes by the same user
        for username in policy_events['username'].dropna().unique():
            user_events = policy_events[policy_events['username'] == username].copy()
            
            if len(user_events) >= 2:  # Multiple policy changes
                # Check if user is authorized to make policy changes
                is_authorized = self._is_authorized_for_policy_changes(username)
                
                if not is_authorized:
                    severity = SeverityLevel.HIGH
                    confidence = 0.9
                else:
                    severity = SeverityLevel.MEDIUM
                    confidence = 0.7
                
                events_list = [
                    SecurityEvent(**row.to_dict()) 
                    for _, row in user_events.iterrows()
                ]
                
                anomaly = AnomalyDetection(
                    anomaly_id=CryptoHelper.generate_secure_id(),
                    anomaly_type=AnomalyType.POLICY_CHANGES,
                    severity=severity,
                    confidence=confidence,
                    detection_time=user_events.iloc[0]['timestamp'],
                    events=events_list,
                    description=f"Multiple policy changes detected for user '{username}': {len(user_events)} policy modifications",
                    recommendations=[
                        "Verify if the policy changes were authorized",
                        "Review the specific policies that were modified",
                        "Check if the user has legitimate administrative rights",
                        "Monitor for additional unauthorized changes",
                        "Consider implementing change management processes"
                    ],
                    metadata={
                        'username': username,
                        'change_count': len(user_events),
                        'is_authorized': is_authorized,
                        'policy_event_ids': list(user_events['event_id'].unique())
                    }
                )
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_account_anomalies(self) -> List[AnomalyDetection]:
        """Detect account-related anomalies."""
        account_events = self.events_df[
            self.events_df['event_type'] == EventType.ACCOUNT_MANAGEMENT.value
        ].copy()
        
        if account_events.empty:
            return []
        
        anomalies = []
        
        # Look for account creation/modification patterns
        for username in account_events['username'].dropna().unique():
            user_events = account_events[account_events['username'] == username].copy()
            
            if len(user_events) >= 2:  # Multiple account management events
                # Analyze the pattern
                time_span = (user_events['timestamp'].max() - user_events['timestamp'].min()).total_seconds()
                
                if time_span < 3600:  # Multiple changes within an hour
                    severity = SeverityLevel.MEDIUM
                    confidence = 0.75
                    
                    events_list = [
                        SecurityEvent(**row.to_dict()) 
                        for _, row in user_events.iterrows()
                    ]
                    
                    anomaly = AnomalyDetection(
                        anomaly_id=CryptoHelper.generate_secure_id(),
                        anomaly_type=AnomalyType.ACCOUNT_ANOMALY,
                        severity=severity,
                        confidence=confidence,
                        detection_time=user_events.iloc[0]['timestamp'],
                        events=events_list,
                        description=f"Rapid account management activity detected for user '{username}': {len(user_events)} events in {TimeHelper.format_duration(int(time_span))}",
                        recommendations=[
                            "Verify if the account changes were authorized",
                            "Check if the user has legitimate administrative rights",
                            "Review the specific account modifications made",
                            "Monitor for suspicious activity from modified accounts",
                            "Consider implementing approval workflows for account changes"
                        ],
                        metadata={
                            'username': username,
                            'event_count': len(user_events),
                            'time_span_seconds': time_span
                        }
                    )
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_frequency_anomalies(self) -> List[AnomalyDetection]:
        """Detect frequency-based anomalies using statistical analysis."""
        if self.events_df.empty:
            return []
        
        anomalies = []
        
        # Analyze hourly event frequency for each user
        self.events_df['hour'] = self.events_df['timestamp'].dt.hour
        hourly_stats = self.events_df.groupby(['username', 'hour']).size().reset_index(name='count')
        
        # Calculate mean and standard deviation for each user
        user_stats = hourly_stats.groupby('username')['count'].agg(['mean', 'std']).reset_index()
        user_stats['std'] = user_stats['std'].fillna(0)
        
        # Find users with unusual activity spikes
        for _, user_stat in user_stats.iterrows():
            username = user_stat['username']
            if pd.isna(username):
                continue
                
            mean_activity = user_stat['mean']
            std_activity = user_stat['std']
            
            # Skip if not enough variation
            if std_activity == 0:
                continue
            
            # Get user's hourly activity
            user_hourly = hourly_stats[hourly_stats['username'] == username]
            
            # Find hours with activity significantly above normal
            threshold = mean_activity + (2 * std_activity)  # 2 standard deviations
            anomalous_hours = user_hourly[user_hourly['count'] > threshold]
            
            if not anomalous_hours.empty:
                severity = SeverityLevel.LOW
                confidence = 0.6
                
                # Higher severity if activity is extremely high
                max_count = anomalous_hours['count'].max()
                if max_count > mean_activity + (3 * std_activity):
                    severity = SeverityLevel.MEDIUM
                    confidence = 0.75
                
                # Get events from anomalous hours
                anomalous_events = []
                for _, hour_data in anomalous_hours.iterrows():
                    hour = hour_data['hour']
                    hour_events = self.events_df[
                        (self.events_df['username'] == username) &
                        (self.events_df['hour'] == hour)
                    ]
                    anomalous_events.extend([
                        SecurityEvent(**row.to_dict()) 
                        for _, row in hour_events.iterrows()
                    ])
                
                anomaly = AnomalyDetection(
                    anomaly_id=CryptoHelper.generate_secure_id(),
                    anomaly_type=AnomalyType.FREQUENCY_ANOMALY,
                    severity=severity,
                    confidence=confidence,
                    detection_time=datetime.now(),
                    events=anomalous_events[:50],  # Limit to first 50 events
                    description=f"Unusual activity frequency detected for user '{username}': activity spike during {len(anomalous_hours)} hour(s)",
                    recommendations=[
                        "Investigate the cause of increased activity",
                        "Check if the user was performing legitimate tasks",
                        "Review the types of activities performed during spike hours",
                        "Monitor for continued unusual patterns",
                        "Consider implementing activity baselines and alerting"
                    ],
                    metadata={
                        'username': username,
                        'mean_activity': mean_activity,
                        'std_activity': std_activity,
                        'max_hourly_count': max_count,
                        'anomalous_hours': list(anomalous_hours['hour'])
                    }
                )
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _analyze_correlation_anomalies(self) -> List[AnomalyDetection]:
        """Detect correlated suspicious events."""
        anomalies = []
        
        # Look for patterns like failed logon followed by successful logon
        failed_logons = self.events_df[
            self.events_df['event_type'] == EventType.FAILED_LOGON.value
        ].copy()
        
        successful_logons = self.events_df[
            self.events_df['event_type'] == EventType.LOGON.value
        ].copy()
        
        if failed_logons.empty or successful_logons.empty:
            return anomalies
        
        # For each failed logon, look for successful logon within time window
        for _, failed_event in failed_logons.iterrows():
            username = failed_event['username']
            if pd.isna(username):
                continue
            
            failed_time = failed_event['timestamp']
            window_end = failed_time + timedelta(minutes=30)
            
            # Find successful logons for same user within window
            matching_success = successful_logons[
                (successful_logons['username'] == username) &
                (successful_logons['timestamp'] > failed_time) &
                (successful_logons['timestamp'] <= window_end)
            ]
            
            if not matching_success.empty:
                # Check if there were multiple failed attempts before success
                window_start = failed_time - timedelta(minutes=10)
                window_failures = failed_logons[
                    (failed_logons['username'] == username) &
                    (failed_logons['timestamp'] >= window_start) &
                    (failed_logons['timestamp'] <= failed_time)
                ]
                
                if len(window_failures) >= 3:  # Multiple failures then success
                    severity = SeverityLevel.MEDIUM
                    confidence = 0.7
                    
                    # Get all related events
                    all_events = []
                    for _, row in window_failures.iterrows():
                        all_events.append(SecurityEvent(**row.to_dict()))
                    for _, row in matching_success.iterrows():
                        all_events.append(SecurityEvent(**row.to_dict()))
                    
                    anomaly = AnomalyDetection(
                        anomaly_id=CryptoHelper.generate_secure_id(),
                        anomaly_type=AnomalyType.CORRELATION_ANOMALY,
                        severity=severity,
                        confidence=confidence,
                        detection_time=failed_time,
                        events=all_events,
                        description=f"Suspicious logon pattern detected for user '{username}': {len(window_failures)} failed attempts followed by successful logon",
                        recommendations=[
                            "Investigate if the successful logon was legitimate",
                            "Check for password spraying or brute force attacks",
                            "Verify the source of the successful logon",
                            "Monitor subsequent activity from this account",
                            "Consider implementing account lockout mechanisms"
                        ],
                        metadata={
                            'username': username,
                            'failed_attempts': len(window_failures),
                            'successful_logons': len(matching_success),
                            'pattern': 'failed_then_success'
                        }
                    )
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _is_likely_admin_user(self, username: str) -> bool:
        """Check if user is likely an administrator based on activity patterns."""
        if not username:
            return False
        
        # Simple heuristics - in real implementation, this could check AD groups
        admin_indicators = ['admin', 'administrator', 'root', 'service']
        username_lower = username.lower()
        
        return any(indicator in username_lower for indicator in admin_indicators)
    
    def _is_regular_off_hours_user(self, username: str) -> bool:
        """Check if user regularly works during off-hours."""
        if not username or self.events_df is None:
            return False
        
        user_events = self.events_df[self.events_df['username'] == username]
        if user_events.empty:
            return False
        
        off_hours_count = len(user_events[
            user_events['timestamp'].apply(
                lambda x: TimeHelper.is_off_hours(x, 
                                                self.config['off_hours_start'], 
                                                self.config['off_hours_end'])
            )
        ])
        
        total_count = len(user_events)
        off_hours_ratio = off_hours_count / total_count
        
        return off_hours_ratio > 0.3  # More than 30% of activity is off-hours
    
    def _is_typical_process_for_user(self, username: str, process_pattern: str) -> bool:
        """Check if process is typical for the user."""
        if not username or self.events_df is None:
            return False
        
        # Simple heuristic - check if user frequently uses this process
        user_events = self.events_df[
            (self.events_df['username'] == username) &
            (self.events_df['process_name'].str.contains(process_pattern, case=False, na=False))
        ]
        
        return len(user_events) > 10  # Arbitrary threshold
    
    def _is_authorized_for_policy_changes(self, username: str) -> bool:
        """Check if user is authorized to make policy changes."""
        if not username:
            return False
        
        # Simple heuristic - check for admin patterns
        return self._is_likely_admin_user(username)
    
    def _deduplicate_anomalies(self, anomalies: List[AnomalyDetection]) -> List[AnomalyDetection]:
        """Remove duplicate anomalies based on type, user, and time proximity."""
        if not anomalies:
            return anomalies
        
        deduplicated = []
        seen_signatures = set()
        
        for anomaly in anomalies:
            # Create signature based on type, primary user, and rounded time
            primary_user = None
            if anomaly.events:
                primary_user = anomaly.events[0].username
            
            time_bucket = anomaly.detection_time.replace(minute=0, second=0, microsecond=0)
            signature = f"{anomaly.anomaly_type}_{primary_user}_{time_bucket}"
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                deduplicated.append(anomaly)
        
        return deduplicated
    
    def _severity_score(self, severity: SeverityLevel) -> int:
        """Convert severity to numeric score for sorting."""
        scores = {
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4
        }
        return scores.get(severity, 0)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        if self.events_df is None or self.events_df.empty:
            return {}
        
        stats = {
            'total_events': len(self.events_df),
            'unique_users': self.events_df['username'].nunique(),
            'unique_computers': self.events_df['computer_name'].nunique(),
            'event_types': self.events_df['event_type'].value_counts().to_dict(),
            'date_range': {
                'start': self.events_df['timestamp'].min().isoformat(),
                'end': self.events_df['timestamp'].max().isoformat()
            },
            'anomalies_detected': len(self.detected_anomalies),
            'anomalies_by_severity': {},
            'anomalies_by_type': {}
        }
        
        # Anomaly statistics
        if self.detected_anomalies:
            severity_counts = Counter(a.severity for a in self.detected_anomalies)
            stats['anomalies_by_severity'] = dict(severity_counts)
            
            type_counts = Counter(a.anomaly_type for a in self.detected_anomalies)
            stats['anomalies_by_type'] = dict(type_counts)
        
        return stats