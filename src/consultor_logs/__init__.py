"""
Consultor de Logs - Windows Security Log Analyzer and Anomaly Detection System.

A comprehensive Python-based security log analysis tool for Windows systems
that provides anomaly detection, threat identification, and detailed reporting.
"""

__version__ = "1.0.0"
__author__ = "Security Team"
__email__ = "security@pentestforge.com"

from .core.analyzer import SecurityAnalyzer
from .core.log_reader import WindowsLogReader
from .core.reporter import SecurityReporter
from .models.events import SecurityEvent, AnomalyDetection
from .models.reports import SecurityReport, ThreatLevel

__all__ = [
    "SecurityAnalyzer",
    "WindowsLogReader", 
    "SecurityReporter",
    "SecurityEvent",
    "AnomalyDetection",
    "SecurityReport",
    "ThreatLevel",
]