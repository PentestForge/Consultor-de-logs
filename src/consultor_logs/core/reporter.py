"""
Security reporter for generating comprehensive security reports.

This module provides functionality to generate reports in multiple formats
including JSON, HTML, PDF, and CSV.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import base64
import io

from loguru import logger
from jinja2 import Environment, FileSystemLoader, Template
import pandas as pd

from ..models.events import SecurityEvent, AnomalyDetection
from ..models.reports import SecurityReport, ReportFormat, ThreatLevel, StatisticsSummary, ThreatIndicator, SecurityRecommendation
from ..utils.helpers import FileHelper, FormatHelper, CryptoHelper, TimeHelper

# Try to import optional dependencies
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logger.warning("Plotly not available. Charts will be disabled.")

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not available. PDF generation will be disabled.")


class SecurityReporter:
    """Security reporter for generating comprehensive reports."""
    
    def __init__(self, template_dir: Optional[str] = None, output_dir: Optional[str] = None):
        """
        Initialize security reporter.
        
        Args:
            template_dir: Directory containing report templates
            output_dir: Directory for output files
        """
        self.template_dir = Path(template_dir) if template_dir else Path("templates")
        self.output_dir = Path(output_dir) if output_dir else Path("reports")
        
        # Ensure directories exist
        FileHelper.ensure_directory(self.template_dir)
        FileHelper.ensure_directory(self.output_dir)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        
        # Add custom filters
        self._setup_jinja_filters()
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def _setup_jinja_filters(self) -> None:
        """Setup custom Jinja2 filters."""
        self.jinja_env.filters['format_datetime'] = lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if x else ''
        self.jinja_env.filters['format_date'] = lambda x: x.strftime('%Y-%m-%d') if x else ''
        self.jinja_env.filters['format_confidence'] = FormatHelper.format_confidence_score
        self.jinja_env.filters['format_severity'] = FormatHelper.format_severity_badge
        self.jinja_env.filters['truncate'] = FormatHelper.truncate_string
        self.jinja_env.filters['format_number'] = FormatHelper.format_number
    
    def _create_default_templates(self) -> None:
        """Create default HTML template if it doesn't exist."""
        html_template_path = self.template_dir / "security_report.html"
        
        if not html_template_path.exists():
            default_html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .summary-card { background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .number { font-size: 2em; font-weight: bold; color: #007bff; }
        .threat-level { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .threat-level.none { background-color: #28a745; }
        .threat-level.low { background-color: #ffc107; color: #212529; }
        .threat-level.medium { background-color: #fd7e14; }
        .threat-level.high { background-color: #dc3545; }
        .threat-level.critical { background-color: #6f42c1; }
        .section { margin-bottom: 30px; }
        .section h2 { border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .anomaly { border: 1px solid #ddd; margin-bottom: 15px; padding: 15px; border-radius: 5px; }
        .anomaly.critical { border-left: 5px solid #dc3545; }
        .anomaly.high { border-left: 5px solid #fd7e14; }
        .anomaly.medium { border-left: 5px solid #ffc107; }
        .anomaly.low { border-left: 5px solid #28a745; }
        .table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .table th, .table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .table th { background-color: #f8f9fa; }
        .recommendations { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .chart { text-align: center; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ report.title }}</h1>
        <p><strong>Generated:</strong> {{ report.generated_at | format_datetime }}</p>
        <p><strong>Analysis Period:</strong> {{ report.analysis_period.start | format_datetime }} to {{ report.analysis_period.end | format_datetime }}</p>
        <p><strong>Overall Threat Level:</strong> <span class="threat-level {{ report.overall_threat_level }}">{{ report.overall_threat_level.upper() }}</span></p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Total Events</h3>
            <div class="number">{{ report.statistics.total_events | format_number }}</div>
        </div>
        <div class="summary-card">
            <h3>Anomalies Detected</h3>
            <div class="number">{{ report.anomalies | length }}</div>
        </div>
        <div class="summary-card">
            <h3>Unique Users</h3>
            <div class="number">{{ report.statistics.unique_users }}</div>
        </div>
        <div class="summary-card">
            <h3>Unique Computers</h3>
            <div class="number">{{ report.statistics.unique_computers }}</div>
        </div>
    </div>

    {% if charts %}
    <div class="section">
        <h2>Analysis Charts</h2>
        {% for chart in charts %}
        <div class="chart">
            {{ chart | safe }}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    {% if report.anomalies %}
    <div class="section">
        <h2>Detected Anomalies</h2>
        {% for anomaly in report.anomalies %}
        <div class="anomaly {{ anomaly.severity }}">
            <h3>{{ anomaly.anomaly_type.replace('_', ' ').title() }}</h3>
            <p><strong>Severity:</strong> {{ anomaly.severity | format_severity | safe }}</p>
            <p><strong>Confidence:</strong> {{ anomaly.confidence | format_confidence }}</p>
            <p><strong>Description:</strong> {{ anomaly.description }}</p>
            <p><strong>Detection Time:</strong> {{ anomaly.detection_time | format_datetime }}</p>
            
            {% if anomaly.recommendations %}
            <div class="recommendations">
                <h4>Recommendations:</h4>
                <ul>
                {% for rec in anomaly.recommendations %}
                    <li>{{ rec }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <h4>Related Events ({{ anomaly.events | length }})</h4>
            <table class="table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Event ID</th>
                        <th>User</th>
                        <th>Computer</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                {% for event in anomaly.events[:10] %}
                    <tr>
                        <td>{{ event.timestamp | format_datetime }}</td>
                        <td>{{ event.event_id }}</td>
                        <td>{{ event.username or 'N/A' }}</td>
                        <td>{{ event.computer_name }}</td>
                        <td>{{ event.description | truncate(100) }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}
    </div>
    {% endif %}

    {% if report.recommendations %}
    <div class="section">
        <h2>Security Recommendations</h2>
        {% for rec in report.recommendations %}
        <div class="recommendations">
            <h3>{{ rec.title }}</h3>
            <p><strong>Priority:</strong> {{ rec.priority | format_severity | safe }}</p>
            <p><strong>Category:</strong> {{ rec.category }}</p>
            <p>{{ rec.description }}</p>
            {% if rec.implementation_steps %}
            <h4>Implementation Steps:</h4>
            <ol>
            {% for step in rec.implementation_steps %}
                <li>{{ step }}</li>
            {% endfor %}
            </ol>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <div class="section">
        <h2>Event Statistics</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Event Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
            {% for event_type, count in report.statistics.events_by_type.items() %}
                <tr>
                    <td>{{ event_type.replace('_', ' ').title() }}</td>
                    <td>{{ count | format_number }}</td>
                    <td>{{ ((count / report.statistics.total_events) * 100) | round(1) }}%</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
        <p>Report generated by Consultor de Logs - Windows Security Log Analyzer</p>
        <p>Generated on {{ report.generated_at | format_datetime }}</p>
    </footer>
</body>
</html>
            """.strip()
            
            with open(html_template_path, 'w', encoding='utf-8') as f:
                f.write(default_html_template)
            
            logger.info(f"Created default HTML template at {html_template_path}")
    
    def generate_report(
        self,
        events: List[SecurityEvent],
        anomalies: List[AnomalyDetection],
        analysis_period: Dict[str, datetime],
        format: ReportFormat = ReportFormat.HTML,
        title: str = "Security Analysis Report",
        include_charts: bool = True
    ) -> SecurityReport:
        """
        Generate comprehensive security report.
        
        Args:
            events: List of security events
            anomalies: List of detected anomalies
            analysis_period: Analysis time period
            format: Report format
            title: Report title
            include_charts: Whether to include charts
            
        Returns:
            SecurityReport object
        """
        logger.info(f"Generating security report with {len(events)} events and {len(anomalies)} anomalies")
        
        # Generate statistics
        statistics = self._generate_statistics(events, analysis_period)
        
        # Assess overall threat level
        threat_level = self._assess_threat_level(anomalies)
        
        # Generate threat indicators
        threat_indicators = self._generate_threat_indicators(events, anomalies)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(anomalies)
        
        # Create report object
        report = SecurityReport(
            report_id=CryptoHelper.generate_secure_id(),
            report_type="full_analysis",
            title=title,
            description=f"Comprehensive security analysis covering {len(events)} events over the period from {analysis_period['start']} to {analysis_period['end']}",
            analysis_period=analysis_period,
            overall_threat_level=threat_level,
            statistics=statistics,
            anomalies=anomalies,
            threat_indicators=threat_indicators,
            recommendations=recommendations,
            high_risk_events=self._get_high_risk_events(events),
            metadata={
                'format': format.value,
                'include_charts': include_charts,
                'generator': 'Consultor de Logs v1.0.0'
            }
        )
        
        logger.success("Security report generated successfully")
        return report
    
    def export_report(
        self,
        report: SecurityReport,
        format: ReportFormat,
        filename: Optional[str] = None,
        include_charts: bool = True
    ) -> Path:
        """
        Export report to specified format.
        
        Args:
            report: Security report to export
            format: Export format
            filename: Output filename (auto-generated if None)
            include_charts: Whether to include charts
            
        Returns:
            Path to exported file
        """
        if filename is None:
            filename = FileHelper.get_safe_filename(
                f"security_report_{report.report_id}",
                format.value
            )
        
        output_path = self.output_dir / filename
        
        logger.info(f"Exporting report to {output_path} in {format.value} format")
        
        if format == ReportFormat.JSON:
            return self._export_json(report, output_path)
        elif format == ReportFormat.HTML:
            return self._export_html(report, output_path, include_charts)
        elif format == ReportFormat.PDF:
            return self._export_pdf(report, output_path)
        elif format == ReportFormat.CSV:
            return self._export_csv(report, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _generate_statistics(
        self,
        events: List[SecurityEvent],
        analysis_period: Dict[str, datetime]
    ) -> StatisticsSummary:
        """Generate event statistics summary."""
        if not events:
            return StatisticsSummary(
                total_events=0,
                time_range=analysis_period,
                unique_users=0,
                unique_computers=0
            )
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame([event.dict() for event in events])
        
        # Count events by type
        events_by_type = df['event_type'].value_counts().to_dict()
        
        # Count events by severity (approximate based on event type)
        events_by_severity = self._categorize_events_by_severity(df)
        
        # Get unique counts
        unique_users = df['username'].nunique()
        unique_computers = df['computer_name'].nunique()
        
        # Count failed logons
        failed_logons = len(df[df['event_type'] == 'failed_logon'])
        
        return StatisticsSummary(
            total_events=len(events),
            events_by_type=events_by_type,
            events_by_severity=events_by_severity,
            time_range=analysis_period,
            unique_users=unique_users,
            unique_computers=unique_computers,
            failed_logons=failed_logons
        )
    
    def _categorize_events_by_severity(self, df: pd.DataFrame) -> Dict[str, int]:
        """Categorize events by approximate severity."""
        severity_mapping = {
            'failed_logon': 'medium',
            'privilege_escalation': 'high',
            'policy_change': 'high',
            'account_management': 'medium',
            'logon': 'low',
            'logoff': 'low',
            'process_creation': 'low',
            'file_access': 'low',
            'system_event': 'medium',
            'other': 'low'
        }
        
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for event_type, count in df['event_type'].value_counts().items():
            severity = severity_mapping.get(event_type, 'low')
            severity_counts[severity] += count
        
        return severity_counts
    
    def _assess_threat_level(self, anomalies: List[AnomalyDetection]) -> ThreatLevel:
        """Assess overall threat level based on anomalies."""
        if not anomalies:
            return ThreatLevel.NONE
        
        # Count anomalies by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for anomaly in anomalies:
            severity_counts[anomaly.severity] += 1
        
        # Determine overall threat level
        if severity_counts['critical'] > 0:
            return ThreatLevel.CRITICAL
        elif severity_counts['high'] >= 3:
            return ThreatLevel.CRITICAL
        elif severity_counts['high'] > 0:
            return ThreatLevel.HIGH
        elif severity_counts['medium'] >= 5:
            return ThreatLevel.HIGH
        elif severity_counts['medium'] > 0:
            return ThreatLevel.MEDIUM
        elif severity_counts['low'] > 0:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.NONE
    
    def _generate_threat_indicators(
        self,
        events: List[SecurityEvent],
        anomalies: List[AnomalyDetection]
    ) -> List[ThreatIndicator]:
        """Generate threat indicators from events and anomalies."""
        indicators = []
        
        if not events:
            return indicators
        
        # Extract IP addresses from failed logons
        failed_logon_ips = {}
        for event in events:
            if event.event_type == 'failed_logon' and event.ip_address:
                ip = event.ip_address
                if ip not in failed_logon_ips:
                    failed_logon_ips[ip] = {
                        'count': 0,
                        'first_seen': event.timestamp,
                        'last_seen': event.timestamp,
                        'users': set()
                    }
                
                failed_logon_ips[ip]['count'] += 1
                failed_logon_ips[ip]['last_seen'] = max(failed_logon_ips[ip]['last_seen'], event.timestamp)
                failed_logon_ips[ip]['first_seen'] = min(failed_logon_ips[ip]['first_seen'], event.timestamp)
                if event.username:
                    failed_logon_ips[ip]['users'].add(event.username)
        
        # Create indicators for suspicious IPs
        for ip, data in failed_logon_ips.items():
            if data['count'] >= 5:  # Threshold for suspicious activity
                severity = 'medium' if data['count'] < 20 else 'high'
                confidence = min(0.6 + (data['count'] / 100), 0.95)
                
                indicator = ThreatIndicator(
                    indicator_id=CryptoHelper.generate_secure_id(),
                    indicator_type='suspicious_ip',
                    value=ip,
                    description=f"IP address with {data['count']} failed logon attempts targeting {len(data['users'])} users",
                    severity=severity,
                    confidence=confidence,
                    first_seen=data['first_seen'],
                    last_seen=data['last_seen'],
                    count=data['count']
                )
                indicators.append(indicator)
        
        # Extract suspicious users from anomalies
        suspicious_users = {}
        for anomaly in anomalies:
            for event in anomaly.events:
                if event.username:
                    user = event.username
                    if user not in suspicious_users:
                        suspicious_users[user] = {
                            'anomaly_count': 0,
                            'severity_scores': [],
                            'first_seen': event.timestamp,
                            'last_seen': event.timestamp
                        }
                    
                    suspicious_users[user]['anomaly_count'] += 1
                    severity_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}[anomaly.severity]
                    suspicious_users[user]['severity_scores'].append(severity_score)
                    suspicious_users[user]['last_seen'] = max(suspicious_users[user]['last_seen'], event.timestamp)
        
        # Create indicators for suspicious users
        for user, data in suspicious_users.items():
            if data['anomaly_count'] >= 2:  # Multiple anomalies
                avg_severity = sum(data['severity_scores']) / len(data['severity_scores'])
                if avg_severity >= 3:
                    severity = 'high'
                elif avg_severity >= 2:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                confidence = min(0.5 + (data['anomaly_count'] / 10), 0.9)
                
                indicator = ThreatIndicator(
                    indicator_id=CryptoHelper.generate_secure_id(),
                    indicator_type='suspicious_user',
                    value=user,
                    description=f"User account involved in {data['anomaly_count']} security anomalies",
                    severity=severity,
                    confidence=confidence,
                    first_seen=data['first_seen'],
                    last_seen=data['last_seen'],
                    count=data['anomaly_count']
                )
                indicators.append(indicator)
        
        return indicators
    
    def _generate_recommendations(self, anomalies: List[AnomalyDetection]) -> List[SecurityRecommendation]:
        """Generate security recommendations based on anomalies."""
        recommendations = []
        
        if not anomalies:
            return recommendations
        
        # Count anomaly types
        anomaly_types = {}
        for anomaly in anomalies:
            anomaly_type = anomaly.anomaly_type
            if anomaly_type not in anomaly_types:
                anomaly_types[anomaly_type] = 0
            anomaly_types[anomaly_type] += 1
        
        # Generate specific recommendations based on anomaly patterns
        if 'multiple_failed_logons' in anomaly_types:
            rec = SecurityRecommendation(
                recommendation_id=CryptoHelper.generate_secure_id(),
                title="Implement Account Lockout Policies",
                description="Multiple failed logon attempts detected. Implement account lockout policies to prevent brute force attacks.",
                priority='high',
                category='Access Control',
                implementation_steps=[
                    "Configure account lockout threshold (recommend 5-10 attempts)",
                    "Set account lockout duration (recommend 15-30 minutes)",
                    "Implement progressive delays for failed attempts",
                    "Monitor and alert on locked accounts",
                    "Consider implementing CAPTCHA for web applications"
                ],
                resources=[
                    "Microsoft Security Compliance Toolkit",
                    "Account Lockout Policy Best Practices"
                ]
            )
            recommendations.append(rec)
        
        if 'privilege_escalation' in anomaly_types:
            rec = SecurityRecommendation(
                recommendation_id=CryptoHelper.generate_secure_id(),
                title="Implement Privileged Access Management",
                description="Privilege escalation activities detected. Implement strict controls for administrative access.",
                priority='critical',
                category='Privilege Management',
                implementation_steps=[
                    "Implement just-in-time (JIT) administrative access",
                    "Require multi-factor authentication for privileged accounts",
                    "Regular review of privileged account assignments",
                    "Implement privileged access workstations (PAWs)",
                    "Monitor and log all privileged operations"
                ]
            )
            recommendations.append(rec)
        
        if 'off_hours_access' in anomaly_types:
            rec = SecurityRecommendation(
                recommendation_id=CryptoHelper.generate_secure_id(),
                title="Implement Time-Based Access Controls",
                description="Off-hours access detected. Consider implementing time-based access restrictions.",
                priority='medium',
                category='Access Control',
                implementation_steps=[
                    "Define standard business hours for user access",
                    "Implement conditional access policies based on time",
                    "Require additional approval for off-hours access",
                    "Monitor and alert on unusual timing patterns",
                    "Create exceptions for legitimate shift workers"
                ]
            )
            recommendations.append(rec)
        
        # General recommendations based on overall security posture
        if len(anomalies) >= 10:
            rec = SecurityRecommendation(
                recommendation_id=CryptoHelper.generate_secure_id(),
                title="Enhance Security Monitoring and SIEM",
                description="High number of security anomalies detected. Consider enhancing security monitoring capabilities.",
                priority='high',
                category='Monitoring',
                implementation_steps=[
                    "Implement or enhance SIEM solution",
                    "Create automated alerting for security events",
                    "Establish security operations center (SOC) procedures",
                    "Implement user and entity behavior analytics (UEBA)",
                    "Regular security training for IT staff"
                ]
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _get_high_risk_events(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Get high-risk events from the event list."""
        high_risk_event_ids = [4625, 4672, 4673, 4719, 4739]  # Failed logon, privilege escalation, policy changes
        
        high_risk_events = [
            event for event in events
            if event.event_id in high_risk_event_ids
        ]
        
        # Sort by timestamp (most recent first) and limit to 100
        high_risk_events.sort(key=lambda x: x.timestamp, reverse=True)
        return high_risk_events[:100]
    
    def _generate_charts(self, report: SecurityReport) -> List[str]:
        """Generate charts for the report."""
        if not PLOTLY_AVAILABLE:
            logger.warning("Plotly not available. Skipping chart generation.")
            return []
        
        charts = []
        
        try:
            # Chart 1: Events by Type
            if report.statistics.events_by_type:
                fig = px.pie(
                    values=list(report.statistics.events_by_type.values()),
                    names=[name.replace('_', ' ').title() for name in report.statistics.events_by_type.keys()],
                    title="Events by Type"
                )
                fig.update_layout(height=400)
                charts.append(fig.to_html(include_plotlyjs='cdn', div_id=f"chart_events_by_type"))
            
            # Chart 2: Anomalies by Severity
            if report.anomalies:
                severity_counts = {}
                for anomaly in report.anomalies:
                    severity = anomaly.severity
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                colors_map = {
                    'low': '#28a745',
                    'medium': '#ffc107',
                    'high': '#fd7e14',
                    'critical': '#dc3545'
                }
                
                fig = go.Figure(data=[
                    go.Bar(
                        x=list(severity_counts.keys()),
                        y=list(severity_counts.values()),
                        marker_color=[colors_map.get(k, '#6c757d') for k in severity_counts.keys()]
                    )
                ])
                fig.update_layout(
                    title="Anomalies by Severity",
                    xaxis_title="Severity Level",
                    yaxis_title="Count",
                    height=400
                )
                charts.append(fig.to_html(include_plotlyjs='cdn', div_id=f"chart_anomalies_by_severity"))
            
            # Chart 3: Timeline of Events (if we have timestamp data)
            if hasattr(report.statistics, 'hourly_distribution'):
                # This would require additional data processing
                pass
            
            logger.success(f"Generated {len(charts)} charts")
            
        except Exception as e:
            logger.error(f"Error generating charts: {e}")
        
        return charts
    
    def _export_json(self, report: SecurityReport, output_path: Path) -> Path:
        """Export report as JSON."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report.dict(), f, indent=2, default=str, ensure_ascii=False)
            
            logger.success(f"JSON report exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting JSON report: {e}")
            raise
    
    def _export_html(self, report: SecurityReport, output_path: Path, include_charts: bool) -> Path:
        """Export report as HTML."""
        try:
            # Generate charts if requested
            charts = self._generate_charts(report) if include_charts else []
            
            # Load template
            template = self.jinja_env.get_template("security_report.html")
            
            # Render template
            html_content = template.render(
                report=report,
                charts=charts,
                generated_by="Consultor de Logs v1.0.0"
            )
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.success(f"HTML report exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting HTML report: {e}")
            raise
    
    def _export_pdf(self, report: SecurityReport, output_path: Path) -> Path:
        """Export report as PDF."""
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available. Cannot generate PDF report.")
            raise ImportError("ReportLab is required for PDF generation")
        
        try:
            doc = SimpleDocTemplate(str(output_path), pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=20,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            story.append(Paragraph(report.title, title_style))
            story.append(Spacer(1, 12))
            
            # Report metadata
            story.append(Paragraph(f"<b>Generated:</b> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"<b>Analysis Period:</b> {report.analysis_period['start'].strftime('%Y-%m-%d %H:%M:%S')} to {report.analysis_period['end'].strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph(f"<b>Overall Threat Level:</b> {report.overall_threat_level.upper()}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Summary statistics
            story.append(Paragraph("Summary Statistics", styles['Heading2']))
            summary_data = [
                ['Metric', 'Value'],
                ['Total Events', FormatHelper.format_number(report.statistics.total_events)],
                ['Anomalies Detected', str(len(report.anomalies))],
                ['Unique Users', str(report.statistics.unique_users)],
                ['Unique Computers', str(report.statistics.unique_computers)],
                ['Failed Logons', str(report.statistics.failed_logons)]
            ]
            
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Anomalies section
            if report.anomalies:
                story.append(Paragraph("Detected Anomalies", styles['Heading2']))
                
                for i, anomaly in enumerate(report.anomalies[:10]):  # Limit to first 10
                    story.append(Paragraph(f"<b>{i+1}. {anomaly.anomaly_type.replace('_', ' ').title()}</b>", styles['Heading3']))
                    story.append(Paragraph(f"<b>Severity:</b> {anomaly.severity.upper()}", styles['Normal']))
                    story.append(Paragraph(f"<b>Confidence:</b> {FormatHelper.format_confidence_score(anomaly.confidence)}", styles['Normal']))
                    story.append(Paragraph(f"<b>Description:</b> {anomaly.description}", styles['Normal']))
                    
                    if anomaly.recommendations:
                        story.append(Paragraph("<b>Recommendations:</b>", styles['Normal']))
                        for rec in anomaly.recommendations[:3]:  # Limit to first 3
                            story.append(Paragraph(f"• {rec}", styles['Normal']))
                    
                    story.append(Spacer(1, 12))
                    
                    # Add page break after every 3 anomalies
                    if (i + 1) % 3 == 0 and i < len(report.anomalies) - 1:
                        story.append(PageBreak())
            
            # Build PDF
            doc.build(story)
            
            logger.success(f"PDF report exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting PDF report: {e}")
            raise
    
    def _export_csv(self, report: SecurityReport, output_path: Path) -> Path:
        """Export report data as CSV."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write report metadata
                writer.writerow(['Report Metadata'])
                writer.writerow(['Title', report.title])
                writer.writerow(['Generated', report.generated_at.isoformat()])
                writer.writerow(['Analysis Start', report.analysis_period['start'].isoformat()])
                writer.writerow(['Analysis End', report.analysis_period['end'].isoformat()])
                writer.writerow(['Threat Level', report.overall_threat_level])
                writer.writerow([])
                
                # Write statistics
                writer.writerow(['Statistics'])
                writer.writerow(['Total Events', report.statistics.total_events])
                writer.writerow(['Unique Users', report.statistics.unique_users])
                writer.writerow(['Unique Computers', report.statistics.unique_computers])
                writer.writerow(['Failed Logons', report.statistics.failed_logons])
                writer.writerow([])
                
                # Write anomalies
                writer.writerow(['Anomalies'])
                writer.writerow(['ID', 'Type', 'Severity', 'Confidence', 'Detection Time', 'Description', 'Event Count'])
                
                for anomaly in report.anomalies:
                    writer.writerow([
                        anomaly.anomaly_id,
                        anomaly.anomaly_type,
                        anomaly.severity,
                        anomaly.confidence,
                        anomaly.detection_time.isoformat(),
                        anomaly.description,
                        len(anomaly.events)
                    ])
            
            logger.success(f"CSV report exported to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting CSV report: {e}")
            raise