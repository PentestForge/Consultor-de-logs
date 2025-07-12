"""
Ejemplo de uso básico de Consultor de Logs.

Este script demuestra cómo usar las funcionalidades principales
del sistema de análisis de logs de seguridad.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

# Agregar el directorio src al path para importar el módulo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from consultor_logs.core.log_reader import create_log_reader
from consultor_logs.core.analyzer import SecurityAnalyzer
from consultor_logs.core.reporter import SecurityReporter
from consultor_logs.models.reports import ReportFormat
from consultor_logs.utils.config import ConfigManager


def main():
    """Función principal del ejemplo."""
    
    print("🔍 Consultor de Logs - Ejemplo de Uso")
    print("=" * 50)
    
    try:
        # 1. Inicializar configuración
        print("\n1. Inicializando configuración...")
        config_manager = ConfigManager()
        print(f"✓ Configuración cargada desde: {config_manager.config_path}")
        
        # 2. Crear lector de logs
        print("\n2. Conectando al Event Viewer...")
        log_reader = create_log_reader()
        
        if not log_reader.test_connection():
            print("✗ Error: No se pudo conectar al Event Viewer")
            print("  Nota: En sistemas no-Windows se usa un simulador")
        else:
            print("✓ Conectado al Event Viewer")
        
        # 3. Obtener logs disponibles
        print("\n3. Obteniendo logs disponibles...")
        available_logs = log_reader.get_available_logs()
        print(f"✓ Logs disponibles: {', '.join(available_logs)}")
        
        # 4. Leer eventos de ejemplo
        print("\n4. Leyendo eventos de seguridad...")
        
        # Definir rango de tiempo (última hora)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=1)
        
        print(f"   Rango: {start_time} a {end_time}")
        
        events = []
        for event in log_reader.read_events(
            log_name="Security",
            start_time=start_time,
            end_time=end_time,
            max_events=100
        ):
            events.append(event)
        
        print(f"✓ Se leyeron {len(events)} eventos")
        
        # 5. Mostrar algunos eventos de ejemplo
        if events:
            print("\n5. Eventos de ejemplo:")
            print("-" * 80)
            for i, event in enumerate(events[:3]):
                print(f"   Evento {i+1}:")
                print(f"     ID: {event.event_id}")
                print(f"     Tipo: {event.event_type}")
                print(f"     Tiempo: {event.timestamp}")
                print(f"     Usuario: {event.username or 'N/A'}")
                print(f"     Descripción: {event.description[:100]}...")
                print()
        
        # 6. Analizar anomalías
        print("6. Analizando anomalías de seguridad...")
        analyzer = SecurityAnalyzer(config_manager.get_analysis_patterns())
        analyzer.load_events(events)
        
        anomalies = analyzer.analyze_all()
        print(f"✓ Se detectaron {len(anomalies)} anomalías")
        
        # 7. Mostrar anomalías encontradas
        if anomalies:
            print("\n7. Anomalías detectadas:")
            print("-" * 80)
            for i, anomaly in enumerate(anomalies[:3]):
                print(f"   Anomalía {i+1}:")
                print(f"     Tipo: {anomaly.anomaly_type}")
                print(f"     Severidad: {anomaly.severity}")
                print(f"     Confianza: {anomaly.confidence:.2%}")
                print(f"     Descripción: {anomaly.description}")
                print(f"     Eventos relacionados: {len(anomaly.events)}")
                if anomaly.recommendations:
                    print(f"     Recomendaciones: {len(anomaly.recommendations)}")
                print()
        
        # 8. Generar reporte
        print("8. Generando reporte de seguridad...")
        
        # Crear directorio de reportes
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        reporter = SecurityReporter(output_dir=str(reports_dir))
        
        # Generar reporte
        report = reporter.generate_report(
            events=events,
            anomalies=anomalies,
            analysis_period={"start": start_time, "end": end_time},
            title="Reporte de Ejemplo - Análisis de Seguridad"
        )
        
        # Exportar en diferentes formatos
        formats_to_generate = [ReportFormat.JSON, ReportFormat.HTML]
        
        for report_format in formats_to_generate:
            try:
                output_file = reporter.export_report(
                    report=report,
                    format=report_format,
                    include_charts=True
                )
                print(f"✓ Reporte {report_format.value.upper()} generado: {output_file}")
            except Exception as e:
                print(f"✗ Error generando reporte {report_format.value.upper()}: {e}")
        
        # 9. Mostrar estadísticas finales
        print("\n9. Estadísticas del análisis:")
        print("-" * 50)
        stats = analyzer.get_statistics()
        
        print(f"   Total de eventos: {stats.get('total_events', 0):,}")
        print(f"   Usuarios únicos: {stats.get('unique_users', 0)}")
        print(f"   Computadoras únicas: {stats.get('unique_computers', 0)}")
        print(f"   Anomalías detectadas: {stats.get('anomalies_detected', 0)}")
        
        # Eventos por tipo
        if 'event_types' in stats:
            print("\n   Eventos por tipo:")
            for event_type, count in list(stats['event_types'].items())[:5]:
                print(f"     {event_type}: {count}")
        
        # 10. Cerrar conexiones
        log_reader.close()
        
        print("\n" + "=" * 50)
        print("✓ Ejemplo completado exitosamente")
        print(f"\nRevisar los reportes generados en: {reports_dir.absolute()}")
        
        # Mostrar próximos pasos
        print("\n📋 Próximos pasos:")
        print("   • Revisar los reportes HTML generados")
        print("   • Configurar umbrales de detección en config/config.yaml")
        print("   • Programar análisis automáticos")
        print("   • Integrar con sistemas de monitoreo existentes")
        
    except KeyboardInterrupt:
        print("\n\n⚠ Operación cancelada por el usuario")
    except Exception as e:
        print(f"\n✗ Error durante la ejecución: {e}")
        print("\nPara más información, ejecutar con modo debug:")
        print("python example_usage.py --debug")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())