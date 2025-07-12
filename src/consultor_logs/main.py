"""
Main CLI interface for Consultor de Logs.

This module provides the command-line interface using Click/Typer for
the Windows security log analyzer.
"""

import sys
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List

import click
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from .core.log_reader import create_log_reader
from .core.analyzer import SecurityAnalyzer
from .core.reporter import SecurityReporter
from .models.reports import ReportFormat
from .utils.config import ConfigManager
from .utils.helpers import TimeHelper

# Initialize rich console
console = Console()


def setup_logging(config_manager: ConfigManager) -> None:
    """Setup logging configuration."""
    log_config = config_manager.config.logging
    
    # Remove default logger
    logger.remove()
    
    # Add console logging
    logger.add(
        sys.stderr,
        level=log_config.level,
        format=log_config.format,
        colorize=True
    )
    
    # Add file logging if configured
    if log_config.file_path:
        log_path = Path(log_config.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            log_path,
            level=log_config.level,
            format=log_config.format,
            rotation=log_config.rotation,
            retention=log_config.retention
        )
    
    if config_manager.is_debug_mode():
        logger.info("Debug mode enabled")


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, config, debug, verbose):
    """
    Consultor de Logs - Windows Security Log Analyzer and Anomaly Detection System.
    
    A comprehensive tool for analyzing Windows security logs and detecting anomalies.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Initialize configuration manager
    try:
        config_manager = ConfigManager(config)
        if debug:
            config_manager.update_config({'debug': True})
        
        ctx.obj['config_manager'] = config_manager
        ctx.obj['verbose'] = verbose
        
        # Setup logging
        setup_logging(config_manager)
        
        if verbose:
            console.print(f"[green]✓[/green] Configuration loaded from {config_manager.config_path}")
            
    except Exception as e:
        console.print(f"[red]✗[/red] Error loading configuration: {e}")
        sys.exit(1)


@cli.command()
@click.option('--log-name', '-l', default='Security', help='Windows log name to read')
@click.option('--computer', '-c', default='localhost', help='Computer name')
@click.option('--start-time', '-s', help='Start time (ISO format)')
@click.option('--end-time', '-e', help='End time (ISO format)')
@click.option('--event-ids', help='Comma-separated list of event IDs')
@click.option('--max-events', '-m', type=int, default=1000, help='Maximum events to read')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default='json', help='Output format')
@click.pass_context
def read_logs(ctx, log_name, computer, start_time, end_time, event_ids, max_events, output, format):
    """Read Windows security logs and export to file."""
    
    config_manager = ctx.obj['config_manager']
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Parse time range
        time_range = None
        if start_time and end_time:
            time_range = TimeHelper.parse_time_range(start_time, end_time)
        
        # Parse event IDs
        event_id_list = None
        if event_ids:
            event_id_list = [int(eid.strip()) for eid in event_ids.split(',')]
        
        # Create log reader
        log_reader = create_log_reader(computer, config_manager.config.windows_logs.timeout)
        
        # Test connection
        console.print("[blue]Testing connection to Windows Event Log...[/blue]")
        if not log_reader.test_connection():
            console.print("[red]✗[/red] Failed to connect to Windows Event Log")
            sys.exit(1)
        
        console.print("[green]✓[/green] Connected to Windows Event Log")
        
        # Read events with progress bar
        events = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Reading events from {log_name} log...", total=None)
            
            for event in log_reader.read_events(
                log_name=log_name,
                start_time=time_range['start'] if time_range else None,
                end_time=time_range['end'] if time_range else None,
                event_ids=event_id_list,
                max_events=max_events
            ):
                events.append(event)
                if len(events) % 100 == 0:
                    progress.update(task, description=f"Reading events from {log_name} log... ({len(events)} events)")
        
        console.print(f"[green]✓[/green] Read {len(events)} events")
        
        # Export events
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'json':
                import json
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump([event.dict() for event in events], f, indent=2, default=str)
            elif format == 'csv':
                import pandas as pd
                df = pd.DataFrame([event.dict() for event in events])
                df.to_csv(output_path, index=False)
            
            console.print(f"[green]✓[/green] Events exported to {output_path}")
        else:
            # Display summary table
            if events:
                table = Table(title=f"Events from {log_name} Log")
                table.add_column("Event ID", style="cyan")
                table.add_column("Type", style="magenta")
                table.add_column("Time", style="yellow")
                table.add_column("User", style="green")
                table.add_column("Computer", style="blue")
                table.add_column("Description", style="white")
                
                for event in events[:20]:  # Show first 20 events
                    table.add_row(
                        str(event.event_id),
                        event.event_type.replace('_', ' ').title(),
                        event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        event.username or 'N/A',
                        event.computer_name,
                        event.description[:50] + '...' if len(event.description) > 50 else event.description
                    )
                
                console.print(table)
                
                if len(events) > 20:
                    console.print(f"[yellow]... and {len(events) - 20} more events[/yellow]")
        
        log_reader.close()
        
    except Exception as e:
        logger.error(f"Error reading logs: {e}")
        console.print(f"[red]✗[/red] Error reading logs: {e}")
        sys.exit(1)


@cli.command()
@click.option('--log-name', '-l', default='Security', help='Windows log name to analyze')
@click.option('--computer', '-c', default='localhost', help='Computer name')
@click.option('--start-time', '-s', help='Start time (ISO format)')
@click.option('--end-time', '-e', help='End time (ISO format)')
@click.option('--max-events', '-m', type=int, default=10000, help='Maximum events to analyze')
@click.option('--output-dir', '-o', help='Output directory for reports')
@click.option('--format', '-f', 
              type=click.Choice(['html', 'json', 'pdf', 'csv']), 
              default='html', 
              help='Report format')
@click.option('--include-charts', is_flag=True, default=True, help='Include charts in HTML reports')
@click.pass_context
def analyze(ctx, log_name, computer, start_time, end_time, max_events, output_dir, format, include_charts):
    """Analyze Windows security logs for anomalies and generate reports."""
    
    config_manager = ctx.obj['config_manager']
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Parse time range
        time_range = None
        if start_time and end_time:
            time_range = TimeHelper.parse_time_range(start_time, end_time)
        else:
            # Default to last 24 hours
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(hours=24)
            time_range = {'start': start_dt, 'end': end_dt}
        
        console.print(Panel.fit(
            f"[bold blue]Security Log Analysis[/bold blue]\n\n"
            f"Log: {log_name}\n"
            f"Computer: {computer}\n"
            f"Time Range: {time_range['start']} to {time_range['end']}\n"
            f"Max Events: {max_events:,}\n"
            f"Output Format: {format.upper()}"
        ))
        
        # Step 1: Read events
        console.print("[blue]Step 1: Reading security events...[/blue]")
        log_reader = create_log_reader(computer, config_manager.config.windows_logs.timeout)
        
        if not log_reader.test_connection():
            console.print("[red]✗[/red] Failed to connect to Windows Event Log")
            sys.exit(1)
        
        events = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Reading events...", total=None)
            
            for event in log_reader.read_events(
                log_name=log_name,
                start_time=time_range['start'],
                end_time=time_range['end'],
                max_events=max_events
            ):
                events.append(event)
                if len(events) % 100 == 0:
                    progress.update(task, description=f"Reading events... ({len(events)} events)")
        
        console.print(f"[green]✓[/green] Read {len(events)} events")
        log_reader.close()
        
        if not events:
            console.print("[yellow]⚠[/yellow] No events found in the specified time range")
            return
        
        # Step 2: Analyze for anomalies
        console.print("[blue]Step 2: Analyzing for security anomalies...[/blue]")
        analyzer = SecurityAnalyzer(config_manager.get_analysis_patterns())
        analyzer.load_events(events)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing events...", total=None)
            anomalies = analyzer.analyze_all()
        
        console.print(f"[green]✓[/green] Detected {len(anomalies)} anomalies")
        
        # Display anomaly summary
        if anomalies:
            severity_counts = {}
            for anomaly in anomalies:
                severity_counts[anomaly.severity] = severity_counts.get(anomaly.severity, 0) + 1
            
            table = Table(title="Anomaly Summary")
            table.add_column("Severity", style="bold")
            table.add_column("Count", style="cyan")
            table.add_column("Percentage", style="green")
            
            for severity in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                percentage = (count / len(anomalies)) * 100 if anomalies else 0
                
                color = {'critical': 'red', 'high': 'orange3', 'medium': 'yellow', 'low': 'green'}[severity]
                table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            console.print(table)
        
        # Step 3: Generate report
        console.print("[blue]Step 3: Generating security report...[/blue]")
        
        # Set output directory
        if output_dir:
            output_directory = Path(output_dir)
        else:
            output_directory = config_manager.get_output_directory()
        
        reporter = SecurityReporter(output_dir=str(output_directory))
        
        # Generate report
        report = reporter.generate_report(
            events=events,
            anomalies=anomalies,
            analysis_period=time_range,
            title=f"Security Analysis Report - {log_name} Log"
        )
        
        # Export report
        report_format = ReportFormat(format)
        output_file = reporter.export_report(
            report=report,
            format=report_format,
            include_charts=include_charts
        )
        
        console.print(f"[green]✓[/green] Report generated: {output_file}")
        
        # Display quick summary
        stats = analyzer.get_statistics()
        summary_panel = Panel.fit(
            f"[bold green]Analysis Complete![/bold green]\n\n"
            f"Events Analyzed: {stats.get('total_events', 0):,}\n"
            f"Anomalies Found: {len(anomalies)}\n"
            f"Unique Users: {stats.get('unique_users', 0)}\n"
            f"Unique Computers: {stats.get('unique_computers', 0)}\n"
            f"Report: {output_file}"
        )
        console.print(summary_panel)
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        console.print(f"[red]✗[/red] Error during analysis: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def list_logs(ctx):
    """List available Windows event logs."""
    
    config_manager = ctx.obj['config_manager']
    
    try:
        console.print("[blue]Connecting to Windows Event Log service...[/blue]")
        log_reader = create_log_reader()
        
        if not log_reader.test_connection():
            console.print("[red]✗[/red] Failed to connect to Windows Event Log")
            sys.exit(1)
        
        logs = log_reader.get_available_logs()
        log_reader.close()
        
        if logs:
            table = Table(title="Available Windows Event Logs")
            table.add_column("Log Name", style="cyan")
            table.add_column("Description", style="white")
            
            log_descriptions = {
                'Security': 'Security events and audit logs',
                'System': 'System events and errors',
                'Application': 'Application events and errors',
                'Setup': 'Setup and installation events',
                'ForwardedEvents': 'Events forwarded from other computers'
            }
            
            for log_name in logs:
                description = log_descriptions.get(log_name, 'Windows event log')
                table.add_row(log_name, description)
            
            console.print(table)
        else:
            console.print("[yellow]⚠[/yellow] No event logs found")
            
    except Exception as e:
        logger.error(f"Error listing logs: {e}")
        console.print(f"[red]✗[/red] Error listing logs: {e}")
        sys.exit(1)


@cli.command()
@click.option('--log-name', '-l', default='Security', help='Windows log name')
@click.option('--computer', '-c', default='localhost', help='Computer name')
@click.pass_context
def log_stats(ctx, log_name, computer):
    """Show statistics for a Windows event log."""
    
    config_manager = ctx.obj['config_manager']
    
    try:
        console.print(f"[blue]Getting statistics for {log_name} log...[/blue]")
        log_reader = create_log_reader(computer)
        
        if not log_reader.test_connection():
            console.print("[red]✗[/red] Failed to connect to Windows Event Log")
            sys.exit(1)
        
        stats = log_reader.get_log_statistics(log_name)
        log_reader.close()
        
        if stats:
            table = Table(title=f"{log_name} Log Statistics")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            
            table.add_row("Log Name", stats.get('log_name', 'N/A'))
            
            file_size = stats.get('file_size', 0)
            if file_size:
                from .utils.helpers import FormatHelper
                table.add_row("File Size", FormatHelper.format_bytes(file_size))
            
            max_size = stats.get('max_file_size', 0)
            if max_size:
                table.add_row("Max File Size", FormatHelper.format_bytes(max_size))
            
            event_count = stats.get('event_count', 0)
            if event_count:
                table.add_row("Event Count", f"{event_count:,}")
            
            table.add_row("Archive", "Yes" if stats.get('archive') else "No")
            table.add_row("Compressed", "Yes" if stats.get('compressed') else "No")
            
            console.print(table)
        else:
            console.print(f"[yellow]⚠[/yellow] Could not get statistics for {log_name} log")
            
    except Exception as e:
        logger.error(f"Error getting log statistics: {e}")
        console.print(f"[red]✗[/red] Error getting log statistics: {e}")
        sys.exit(1)


@cli.command()
@click.pass_context
def config_show(ctx):
    """Show current configuration."""
    
    config_manager = ctx.obj['config_manager']
    
    try:
        config_dict = config_manager.config.dict()
        
        # Create a formatted display of the configuration
        import json
        config_json = json.dumps(config_dict, indent=2, default=str)
        
        console.print(Panel.fit(
            f"[bold blue]Current Configuration[/bold blue]\n\n"
            f"Config File: {config_manager.config_path}\n\n"
            f"[dim]{config_json}[/dim]"
        ))
        
    except Exception as e:
        logger.error(f"Error showing configuration: {e}")
        console.print(f"[red]✗[/red] Error showing configuration: {e}")


@cli.command()
@click.option('--key', '-k', required=True, help='Configuration key (dot notation)')
@click.option('--value', '-v', required=True, help='New value')
@click.pass_context
def config_set(ctx, key, value):
    """Set configuration value."""
    
    config_manager = ctx.obj['config_manager']
    
    try:
        # Parse the key path
        key_parts = key.split('.')
        
        # Convert value to appropriate type
        try:
            # Try to parse as JSON (handles numbers, booleans, lists, etc.)
            import json
            parsed_value = json.loads(value)
        except json.JSONDecodeError:
            # If not JSON, treat as string
            parsed_value = value
        
        # Build the update dictionary
        update_dict = {}
        current = update_dict
        for part in key_parts[:-1]:
            current[part] = {}
            current = current[part]
        current[key_parts[-1]] = parsed_value
        
        # Update configuration
        config_manager.update_config(update_dict)
        
        console.print(f"[green]✓[/green] Configuration updated: {key} = {parsed_value}")
        
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        console.print(f"[red]✗[/red] Error updating configuration: {e}")


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information."""
    
    from . import __version__, __author__
    
    console.print(Panel.fit(
        f"[bold blue]Consultor de Logs[/bold blue]\n\n"
        f"Version: {__version__}\n"
        f"Author: {__author__}\n"
        f"Description: Windows Security Log Analyzer and Anomaly Detection System"
    ))


def main():
    """Main entry point for the CLI."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        console.print(f"[red]✗[/red] Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()