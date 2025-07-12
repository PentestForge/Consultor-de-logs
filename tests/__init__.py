"""Tests for consultor_logs package."""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from consultor_logs.models.events import SecurityEvent, EventType, AnomalyDetection, AnomalyType, SeverityLevel
from consultor_logs.models.reports import SecurityReport, ThreatLevel, ReportFormat
from consultor_logs.core.analyzer import SecurityAnalyzer
from consultor_logs.core.log_reader import MockWindowsLogReader
from consultor_logs.core.reporter import SecurityReporter
from consultor_logs.utils.config import ConfigManager
from consultor_logs.utils.helpers import TimeHelper, ValidationHelper