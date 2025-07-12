# Consultor de Logs - Windows Security Log Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Un sistema completo en Python para consultar y analizar logs de seguridad de Windows, identificando anomalías y posibles amenazas de seguridad.

## 🚀 Características Principales

- **Lectura de Logs de Windows**: Acceso directo a Event Viewer usando WMI y pywin32
- **Detección de Anomalías**: Algoritmos avanzados para identificar patrones sospechosos
- **Múltiples Formatos de Reporte**: JSON, HTML, PDF, CSV
- **Interfaz CLI Profesional**: Comandos intuitivos con Rich UI
- **Configuración Flexible**: Archivos YAML/JSON para personalización
- **Análisis Temporal**: Detección de actividad fuera de horario
- **Correlación de Eventos**: Identificación de cadenas de eventos relacionados

## 📋 Tipos de Anomalías Detectadas

- ✅ Intentos de login fallidos múltiples
- ✅ Escalada de privilegios
- ✅ Accesos fuera de horario
- ✅ Cambios en políticas de seguridad
- ✅ Actividad de cuentas inusuales
- ✅ Procesos sospechosos
- ✅ Análisis de frecuencia y patrones temporales
- ✅ Correlación de eventos relacionados

## 🔧 Instalación

### Requisitos del Sistema

- **SO**: Windows 10/11 o Windows Server 2016+
- **Python**: 3.8 o superior
- **Privilegios**: Administrador (recomendado para acceso completo a logs)

### Instalación desde el Código Fuente

```bash
# Clonar el repositorio
git clone https://github.com/PentestForge/Consultor-de-logs.git
cd Consultor-de-logs

# Instalar dependencias
pip install -r requirements.txt

# Instalar el paquete
pip install -e .
```

### Instalación de Dependencias de Windows

```bash
# Instalar dependencias específicas de Windows
pip install pywin32 wmi
```

## 🚀 Uso Rápido

### Análisis Básico

```bash
# Analizar logs de seguridad de las últimas 24 horas
consultor-logs analyze

# Analizar con rango de tiempo específico
consultor-logs analyze --start-time "2024-01-01T00:00:00" --end-time "2024-01-02T00:00:00"

# Generar reporte en PDF
consultor-logs analyze --format pdf --output-dir ./reports
```

### Lectura de Logs

```bash
# Listar logs disponibles
consultor-logs list-logs

# Leer eventos específicos
consultor-logs read-logs --log-name Security --max-events 1000 --output events.json

# Obtener estadísticas de un log
consultor-logs log-stats --log-name Security
```

### Configuración

```bash
# Ver configuración actual
consultor-logs config-show

# Cambiar configuración
consultor-logs config-set --key analysis.failed_logon_threshold --value 10
```

## 📊 Ejemplo de Uso Programático

```python
from datetime import datetime, timedelta
from consultor_logs import WindowsLogReader, SecurityAnalyzer, SecurityReporter

# Crear lector de logs
log_reader = WindowsLogReader()

# Leer eventos de las últimas 24 horas
end_time = datetime.now()
start_time = end_time - timedelta(hours=24)

events = list(log_reader.read_events(
    log_name="Security",
    start_time=start_time,
    end_time=end_time,
    max_events=5000
))

# Analizar anomalías
analyzer = SecurityAnalyzer()
analyzer.load_events(events)
anomalies = analyzer.analyze_all()

# Generar reporte
reporter = SecurityReporter()
report = reporter.generate_report(
    events=events,
    anomalies=anomalies,
    analysis_period={"start": start_time, "end": end_time}
)

# Exportar reporte HTML
report_file = reporter.export_report(report, format="html")
print(f"Reporte generado: {report_file}")
```

## ⚙️ Configuración

### Archivo de Configuración (config/config.yaml)

```yaml
# Configuración de análisis
analysis:
  failed_logon_threshold: 5
  failed_logon_window: 300  # 5 minutos
  off_hours_start: 22       # 10 PM
  off_hours_end: 6          # 6 AM
  confidence_threshold: 0.7

# Configuración de reportes
reports:
  default_format: "html"
  output_directory: "./reports"
  include_charts: true

# Configuración de logging
logging:
  level: "INFO"
  file_path: "./logs/consultor_logs.log"
```

## 📈 Tipos de Reportes

### Reporte HTML Interactivo
- Gráficos interactivos con Plotly
- Tablas de eventos detalladas
- Resumen ejecutivo
- Recomendaciones de seguridad

### Reporte PDF Profesional
- Formato profesional para auditorías
- Gráficos estáticos
- Resumen de hallazgos
- Lista de recomendaciones

### Exportación de Datos
- **JSON**: Datos estructurados para integración
- **CSV**: Para análisis en Excel/herramientas de BI

## 🔍 Patrones de Anomalías Detectados

### 1. Ataques de Fuerza Bruta
```
Patrón: Múltiples eventos 4625 (Failed Logon) para el mismo usuario
Umbral: 5+ intentos en 5 minutos
Severidad: Media/Alta
```

### 2. Escalada de Privilegios
```
Eventos: 4672, 4673, 4674, 4728, 4732, 4756
Patrón: Múltiples eventos de privilegios en corto tiempo
Severidad: Alta/Crítica
```

### 3. Actividad Fuera de Horario
```
Horario: 22:00 - 06:00 (configurable)
Eventos: Logons, cambios de política, procesos administrativos
Severidad: Baja/Media
```

### 4. Procesos Sospechosos
```
Procesos: powershell.exe, cmd.exe, wmic.exe, net.exe
Patrón: Ejecución inusual por usuarios no administrativos
Severidad: Media/Alta
```

## 🛡️ Características de Seguridad

- **Validación de Datos**: Todos los datos de entrada son validados
- **Logging Seguro**: Logs detallados sin información sensible
- **Configuración Auditada**: Cambios de configuración registrados
- **Acceso Controlado**: Verificación de privilegios administrativos

## 🧪 Testing

```bash
# Ejecutar todos los tests
pytest

# Tests con cobertura
pytest --cov=src/consultor_logs --cov-report=html

# Tests específicos
pytest tests/test_analyzer.py -v
```

## 📁 Estructura del Proyecto

```
consultor_logs/
├── src/
│   └── consultor_logs/
│       ├── __init__.py
│       ├── main.py              # CLI principal
│       ├── core/                # Funcionalidad principal
│       │   ├── log_reader.py    # Lectura de logs de Windows
│       │   ├── analyzer.py      # Análisis de anomalías
│       │   └── reporter.py      # Generación de reportes
│       ├── models/              # Modelos de datos
│       │   ├── events.py        # Eventos de seguridad
│       │   └── reports.py       # Reportes y anomalías
│       └── utils/               # Utilidades
│           ├── config.py        # Gestión de configuración
│           └── helpers.py       # Funciones auxiliares
├── tests/                       # Tests unitarios
├── config/                      # Archivos de configuración
├── docs/                        # Documentación
└── reports/                     # Reportes generados
```

## 🤝 Contribución

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

## 🆘 Soporte

- **Issues**: [GitHub Issues](https://github.com/PentestForge/Consultor-de-logs/issues)
- **Documentación**: [Wiki del Proyecto](https://github.com/PentestForge/Consultor-de-logs/wiki)
- **Email**: security@pentestforge.com

## 🔄 Roadmap

- [ ] Interfaz Web (Dashboard)
- [ ] Integración con SIEM
- [ ] Análisis de logs de Linux
- [ ] Machine Learning para detección avanzada
- [ ] API REST
- [ ] Alertas en tiempo real
- [ ] Integración con Active Directory

---

**Desarrollado por PentestForge** - Herramientas de seguridad para profesionales
