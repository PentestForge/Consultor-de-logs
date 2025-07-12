"""
Configuration management for consultor_logs.

This module provides configuration management functionality using YAML/JSON files.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, validator
from loguru import logger


class LoggingConfig(BaseModel):
    """Configuration for logging."""
    
    level: str = Field("INFO", description="Logging level")
    format: str = Field(
        "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        description="Log format"
    )
    file_path: Optional[str] = Field(None, description="Log file path")
    rotation: str = Field("10 MB", description="Log rotation size")
    retention: str = Field("30 days", description="Log retention period")
    
    @validator('level')
    def validate_level(cls, v):
        """Validate logging level."""
        valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Invalid logging level. Must be one of: {valid_levels}")
        return v.upper()


class WindowsLogConfig(BaseModel):
    """Configuration for Windows log access."""
    
    default_computer: str = Field("localhost", description="Default computer name")
    timeout: int = Field(30, description="Query timeout in seconds")
    max_events: int = Field(10000, description="Maximum events per query")
    log_sources: List[str] = Field(
        default_factory=lambda: ["Security", "System", "Application"],
        description="Default log sources"
    )


class AnalysisConfig(BaseModel):
    """Configuration for anomaly analysis."""
    
    failed_logon_threshold: int = Field(5, description="Failed logon threshold")
    failed_logon_window: int = Field(300, description="Failed logon time window (seconds)")
    off_hours_start: int = Field(22, description="Off hours start (24h format)")
    off_hours_end: int = Field(6, description="Off hours end (24h format)")
    privilege_escalation_events: List[int] = Field(
        default_factory=lambda: [4672, 4673, 4674, 4728, 4732, 4756],
        description="Privilege escalation event IDs"
    )
    suspicious_process_patterns: List[str] = Field(
        default_factory=lambda: ["powershell.exe", "cmd.exe", "wmic.exe", "net.exe"],
        description="Suspicious process name patterns"
    )
    confidence_threshold: float = Field(0.7, description="Minimum confidence for anomalies")
    
    @validator('off_hours_start', 'off_hours_end')
    def validate_hours(cls, v):
        """Validate hours are between 0 and 23."""
        if not 0 <= v <= 23:
            raise ValueError("Hours must be between 0 and 23")
        return v
    
    @validator('confidence_threshold')
    def validate_confidence(cls, v):
        """Validate confidence threshold."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
        return v


class ReportConfig(BaseModel):
    """Configuration for report generation."""
    
    default_format: str = Field("html", description="Default report format")
    output_directory: str = Field("./reports", description="Output directory")
    template_directory: str = Field("./templates", description="Template directory")
    include_charts: bool = Field(True, description="Include charts in reports")
    chart_width: int = Field(800, description="Chart width in pixels")
    chart_height: int = Field(600, description="Chart height in pixels")
    max_events_in_report: int = Field(1000, description="Maximum events in detailed reports")


class DatabaseConfig(BaseModel):
    """Configuration for database connections."""
    
    enabled: bool = Field(False, description="Enable database storage")
    connection_string: Optional[str] = Field(None, description="Database connection string")
    table_prefix: str = Field("consultor_", description="Table name prefix")
    retention_days: int = Field(90, description="Data retention in days")


class SecurityConfig(BaseModel):
    """Configuration for security settings."""
    
    encrypt_reports: bool = Field(False, description="Encrypt generated reports")
    encryption_key_path: Optional[str] = Field(None, description="Path to encryption key")
    audit_config_changes: bool = Field(True, description="Audit configuration changes")
    require_admin: bool = Field(True, description="Require administrator privileges")


class AppConfig(BaseModel):
    """Main application configuration."""
    
    app_name: str = Field("Consultor de Logs", description="Application name")
    version: str = Field("1.0.0", description="Application version")
    debug: bool = Field(False, description="Debug mode")
    
    # Sub-configurations
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    windows_logs: WindowsLogConfig = Field(default_factory=WindowsLogConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)


class ConfigManager:
    """Configuration manager for the application."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager."""
        self.config_path = Path(config_path) if config_path else self._get_default_config_path()
        self._config: Optional[AppConfig] = None
        self._load_config()
    
    def _get_default_config_path(self) -> Path:
        """Get default configuration file path."""
        # Try multiple locations for config file
        possible_paths = [
            Path("config/config.yaml"),
            Path("config/config.yml"),
            Path("config/config.json"),
            Path("./config.yaml"),
            Path("./config.yml"),
            Path("./config.json"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
        
        # Return default path if none exist
        return Path("config/config.yaml")
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            if self.config_path.exists():
                logger.info(f"Loading configuration from {self.config_path}")
                
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                        config_data = yaml.safe_load(f)
                    elif self.config_path.suffix.lower() == '.json':
                        config_data = json.load(f)
                    else:
                        raise ValueError(f"Unsupported config file format: {self.config_path.suffix}")
                
                self._config = AppConfig(**config_data)
                logger.success("Configuration loaded successfully")
            else:
                logger.warning(f"Configuration file not found at {self.config_path}, using defaults")
                self._config = AppConfig()
                self.save_config()  # Save default config
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            logger.info("Using default configuration")
            self._config = AppConfig()
    
    def save_config(self) -> None:
        """Save current configuration to file."""
        try:
            # Ensure config directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_dict = self._config.dict()
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                elif self.config_path.suffix.lower() == '.json':
                    json.dump(config_dict, f, indent=2)
                else:
                    # Default to YAML
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            logger.success(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            raise
    
    @property
    def config(self) -> AppConfig:
        """Get current configuration."""
        if self._config is None:
            self._load_config()
        return self._config
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values."""
        try:
            current_dict = self._config.dict()
            self._deep_update(current_dict, updates)
            self._config = AppConfig(**current_dict)
            self.save_config()
            logger.info("Configuration updated successfully")
            
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            raise
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """Deep update dictionary values."""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def get_log_sources(self) -> List[str]:
        """Get configured log sources."""
        return self.config.windows_logs.log_sources
    
    def get_analysis_patterns(self) -> Dict[str, Any]:
        """Get analysis configuration as dictionary."""
        return {
            "failed_logon_threshold": self.config.analysis.failed_logon_threshold,
            "failed_logon_window": self.config.analysis.failed_logon_window,
            "off_hours_start": self.config.analysis.off_hours_start,
            "off_hours_end": self.config.analysis.off_hours_end,
            "privilege_escalation_events": self.config.analysis.privilege_escalation_events,
            "suspicious_process_patterns": self.config.analysis.suspicious_process_patterns,
            "confidence_threshold": self.config.analysis.confidence_threshold,
        }
    
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        return self.config.debug
    
    def get_output_directory(self) -> Path:
        """Get configured output directory."""
        output_dir = Path(self.config.reports.output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir