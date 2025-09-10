# MeLiChallenge-SecurityIA: Network Session Anomaly Detection API

API FastAPI para detección de anomalías en sesiones de red y comportamiento de autenticación.

## **SOLUCIÓN AL RETO DE MELI - DETECCIÓN INTELIGENTE DE AMENAZAS**

Este proyecto representa mi solución al **Reto de Desarrollo y Seguridad de Mercado Libre (MELI)**, que busca implementar un módulo backend utilizando modelos de Inteligencia Artificial para la detección inteligente de comportamientos anómalos en registros de acceso. El desafío requiere conocimientos en redes, infraestructura, desarrollo de soluciones, IA y bases de datos, implementando una canalización de detección de anomalías con agentes inteligentes que procesen registros y sugieran acciones de seguridad como bloquear, alertar u otra.

## **Dataset de Network Session Anomaly Detection**

Este proyecto ha sido adaptado para trabajar con el dataset **"Cybersecurity Intrusion Detection Dataset"** de Kaggle, que contiene métricas de sesiones de red para la detección de intrusiones y amenazas de seguridad.

**[Acceder al Dataset en Kaggle](https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset/data)**

### **Características del Dataset:**
- **9,537 registros** de sesiones de red
- **2 clases**: Normal (0), Ataque (1)
- **3 tipos de protocolo**: TCP, UDP, ICMP
- **3 tipos de encriptación**: AES, DES, None
- **5 tipos de navegador**: Chrome, Firefox, Edge, Safari, Unknown
- **Métricas de comportamiento**: Autenticación, duración de sesión, reputación IP, tamaño de paquetes


## Ejecutar Localmente

```bash
# 1. Crear entorno virtual
python -m venv .venv
source .venv/bin/activate   # En Windows: .venv\\Scripts\\Activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Iniciar la API
python wsgi.py  # inicia uvicorn en reload
```

La API estará disponible en: `http://localhost:8000`

## Pruebas

El proyecto incluye pruebas automatizadas organizadas por tipo y alcance.

### **Tipos de Pruebas Disponibles**

| Tipo | Descripción | Comando |
|------|-------------|---------|
| **Unit** | Pruebas de componentes individuales | `python run_tests.py unit` | 
| **Integration** | Pruebas de interacción entre componentes | `python run_tests.py integration` | 
| **E2E** | Pruebas del flujo completo con datos reales | `python run_tests.py e2e` | 
| **All** | Ejecuta todos los tipos de pruebas | `python run_tests.py all` | 

### **Ejecutar Pruebas**

```bash
# Pruebas unitarias
python run_tests.py unit

# Pruebas de integración
python run_tests.py integration

# Pruebas End-to-End
python run_tests.py e2e

# Ejecutar toda la suite
python run_tests.py all

# Reporte de cobertura
python run_tests.py coverage
# Reportes generados en:
# - HTML: htmlcov/index.html
# - XML: coverage.xml
# - Terminal: resumen en consola
```

## **Análisis de Amenazas: STRIDE + MITRE ATT&CK**

Se realizó un **modelado de amenazas** aplicando frameworks de ciberseguridad estándar de la industria:

- **STRIDE**: Para categorización conceptual de amenazas
- **MITRE ATT&CK**: Para mapeo a técnicas reales de atacantes
- **IoC**: Indicadores de compromiso calculables del dataset

### Resultados Clave

- **9 amenazas mapeadas** a técnicas MITRE ATT&CK específicas
- **6 técnicas** identificadas (T1110, T1040, T1041, T1499, T1078, T1087)

### Matriz de Amenazas

| Feature (Dataset) | STRIDE (Categoría) | Amenaza Detectada | MITRE ATT&CK (Técnica) | IoC Propuesto | Estadísticas del Feature |
|-------------------|-------------------|-------------------|------------------------|---------------|--------------------------|
| `failed_logins` | **Spoofing** | Credential Stuffing / Brute Force | **T1110 - Brute Force** | >3 intentos fallidos por sesión | **Min:** 0.00, **Max:** 5.00, **P95:** 3.00 |
| `encryption_used` | **Information Disclosure** | Tráfico sin cifrar interceptado | **T1040 - Network Sniffing** | encryption_used = 'None' + tráfico > umbral | **Valores únicos:** AES: 4,706, DES: 2,865, None: 1,966 |
| `network_packet_size` | **Information Disclosure** | Exfiltración de datos | **T1041 - Exfiltration Over C2** | valores outlier sobre p95 | **Min:** 64.00, **Max:** 1,285.00, **P95:** 830.00 |
| `protocol_type` | **Denial of Service** | Flood de paquetes / Protocol Abuse | **T1499 - Endpoint DoS** | ICMP > 50% + packet_size > p95 | **Valores únicos:** TCP: 6,624, UDP: 2,406, ICMP: 507 |
| `login_attempts` | **Tampering** | Reconnaissance / Account Discovery | **T1087 - Account Discovery** | >5 intentos por sesión | **Min:** 1.00, **Max:** 13.00, **P95:** 7.00 |
| `session_duration` | **Tampering** | Session Hijacking / Persistence | **T1078 - Valid Accounts** | duración outlier sobre p95 o < p5 | **Min:** 0.50, **Max:** 7,190.39, **P95:** 2,312.48 |
| `ip_reputation_score` | **Spoofing** | IP Spoofing / Malicious Sources | **T1078 - Valid Accounts** | score < 0.3 (baja reputación) | **Min:** 0.00, **Max:** 0.92, **P95:** 0.65 |
| `browser_type` | **Spoofing** | User Agent Spoofing | **T1078 - Valid Accounts** | browser_type = 'Unknown' + otros indicadores | **Valores únicos:** Chrome: 5,137, Firefox: 1,944, Edge: 1,469 |
| `unusual_time_access` | **Spoofing** | Account Takeover / Temporal Anomaly | **T1078 - Valid Accounts** | unusual_time_access = 1 + otros indicadores | **Min:** 0.00, **Max:** 1.00, **P95:** 1.00 |

### Detección de Amenazas con IoCs

#### Metodología

Implementamos **Indicadores de Compromiso (IoC)** basados en las reglas de amenazas identificadas:

- **Detección de Fuerza Bruta**: >3 intentos fallidos por sesión
- **Detección de Exfiltración**: Valores outlier sobre percentil 95
- **Detección de Protocol Abuse**: ICMP con paquetes grandes
- **Detección de Reconnaissance**: >5 intentos de login por sesión
- **Detección de Session Hijacking**: Duración anómala de sesiones
- **Detección de IP Spoofing**: Reputación IP < 0.3
- **Detección de User Agent Spoofing**: Navegador desconocido
- **Detección de Temporal Anomaly**: Acceso en horarios inusuales

#### Rendimiento de IoCs

- **Precisión**: 100.0% (Cero falsos positivos)
- **Recall**: 77.8% (Detecta 77.8% de amenazas reales)
- **F1-Score**: 87.5% (Excelente balance)

**[Ver análisis completo y métricas detalladas](notebooks/Threat_Model.ipynb)**


## **ARQUITECTURA DEL PROYECTO**

Este proyecto implementa **Clean Architecture**, con cuatro capas y dependencias que apuntan hacia adentro.

### **Principios fundamentales**

-  **Dependencias apuntan hacia adentro**: Solo las capas externas dependen de las internas  
- **Inversión de dependencias**: Las capas internas definen interfaces, las externas las implementan  
- **Entidades independientes**:  El centro no conoce nada del exterior  
- **Casos de uso aislados**: La aplicación no conoce detalles de frameworks  
- **Interface Adapters**: Adaptadores conectan el interior con el exterior  
- **Frameworks externos**: Detalles técnicos en la capa más externa 

### **Diagrama de arquitectura**

```mermaid
graph TB
    %% Definición de estilos
    classDef entitiesLayer fill:#e8f5e8,stroke:#1b5e20,stroke-width:3px,color:#1b5e20
    classDef useCasesLayer fill:#f3e5f5,stroke:#4a148c,stroke-width:3px,color:#4a148c
    classDef adaptersLayer fill:#e1f5fe,stroke:#01579b,stroke-width:3px,color:#01579b
    classDef frameworksLayer fill:#fff3e0,stroke:#e65100,stroke-width:3px,color:#e65100
    
    %% Capa de Entidades
    subgraph ENTITIES ["ENTITIES"]
        E[Entidades de Negocio<br/>LogEntry, AnomalyResult<br/>DatasetConfig, DeviceType]
    end
    
    %% Capa de Casos de Uso
    subgraph USECASES ["USE CASES"]
        U[Casos de Uso<br/>AnalyzeLogs, TrainModel<br/>GetDatasetInfo, ExecutePipeline]
    end
    
    %% Capa de Adaptadores
    subgraph ADAPTERS ["INTERFACE ADAPTERS"]
        A[Adaptadores<br/>Controllers, Presenters<br/>Gateways, Repositories]
    end
    
    %% Capa de Frameworks
    subgraph FRAMEWORKS ["FRAMEWORKS & DRIVERS"]
        F[Frameworks<br/>FastAPI, ML Libraries<br/>External APIs, Database]
    end
    
    %% Flujo de dependencias
    F -->|"depende de"| A
    A -->|"depende de"| U
    U -->|"depende de"| E
    
    %% Aplicar estilos
    class E entitiesLayer
    class U useCasesLayer
    class A adaptersLayer
    class F frameworksLayer
```

### **Agentes**

Este proyecto implementa un sistema de **agentes inteligentes** para la **detección de intrusiones en ciberseguridad**, analizando **tráfico de red y comportamiento de usuario**.

### **Agentes Especializados**

1. **SupervisedAgent**  
   Detecta amenazas conocidas usando patrones y firmas predefinidas.
2. **UnsupervisedAgent**  
   Identifica anomalías no supervisadas aplicando técnicas de machine learning.
3. **DecisionAgent**  
   Toma decisiones de respuesta basadas en reglas dinámicas y confianza del modelo.
4. **ReportAgent**  
   Genera reportes finales con hallazgos, métricas y recomendaciones.

### **Pipeline de agentes**

```mermaid
graph TB
    %% Estilos para agentes
    classDef supervisedStyle fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    classDef unsupervisedStyle fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#e65100
    classDef decisionStyle fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    classDef reportStyle fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#4a148c
    
    %% Agentes especializados
    subgraph AGENTS ["Pipeline de Agentes Inteligentes"]
        A1[SupervisedAgent<br/>Detección de Amenazas Conocidas]
        A2[UnsupervisedAgent<br/>Detección de Anomalías]
        A3[DecisionAgent<br/>Toma de Decisiones]
        A4[ReportAgent<br/>Generación de Reportes]
    end
    
    %% Flujo principal con decisiones
    A1 -->|Ataque Conocido| A3
    A1 -->|Comportamiento Normal| A2
    A2 -->|Anomalía Detectada| A3
    A2 -->|Comportamiento Normal| A4
    A3 --> A4
    
    %% Aplicar estilos
    class A1 supervisedStyle
    class A2 unsupervisedStyle
    class A3 decisionStyle
    class A4 reportStyle

    %% Aplicar estilos
    class A1,A2,A4 agentStyle
    class A3 decisionStyle
```

## ENDPOINTS PRINCIPALES

### **Salud y Información**
- **GET** `/health` → Estado de salud de la API
- **GET** `/` → Información general del proyecto

### **Análisis de Amenazas**
- **POST** `/analyze` → Análisis completo de amenazas con pipeline de agentes inteligentes

### **Entrenamiento de Modelos**
- **POST** `/train/supervised` → Entrenamiento del modelo supervisado
- **POST** `/train/unsupervised` → Entrenamiento del modelo no supervisado

## 📱 Estructura de Datos IoT

### **Campos Requeridos:**
```json
{
  "timestamp": "2025-01-20 12:00:00",
  "device_id": "thermostat_001",
  "device_type": "thermostat",
  "cpu_usage": 75.5,
  "memory_usage": 60.2,
  "network_in_kb": 150,
  "network_out_kb": 300,
  "packet_rate": 450,
  "avg_response_time_ms": 250.0,
  "service_access_count": 5,
  "failed_auth_attempts": 2,
  "is_encrypted": 1,
  "geo_location_variation": 5.5
}
```

### **Tipos de Dispositivos Soportados:**
- **thermostat**: Termostatos inteligentes
- **smart**: Dispositivos inteligentes generales
- **sensor**: Sensores de monitoreo
- **camera**: Cámaras de seguridad
- **lock**: Cerraduras inteligentes
- **hub**: Hubs centrales
- **appliance**: Electrodomésticos inteligentes
- **wearable**: Dispositivos portátiles

## 🧪 Ejemplos de Uso

### **1. Entrenar el Modelo desde Kaggle**
```bash
curl -X POST http://localhost:8000/train/iot/kaggle
```

**Nota**: El dataset se divide automáticamente en:
- **80% sin etiquetas**: Para entrenamiento no supervisado
- **20% con etiquetas**: Para calibración y optimización de thresholds

**Respuesta:**
```json
{
  "status": "trained_from_kaggle",
  "samples": 1589,
  "model_path": "models/isoforest.joblib",
  "features": 11
}
```

### **2. Analizar Dispositivos IoT**
```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [{
      "timestamp": "2025-01-20 12:00:00",
      "device_id": "thermostat_001",
      "device_type": "thermostat",
      "cpu_usage": 75.5,
      "memory_usage": 60.2,
      "network_in_kb": 150,
      "network_out_kb": 300,
      "packet_rate": 450,
      "avg_response_time_ms": 250.0,
      "service_access_count": 5,
      "failed_auth_attempts": 2,
      "is_encrypted": 1,
      "geo_location_variation": 5.5
    }]
  }'
```

**Respuesta:**
```json
{
  "trace_id": "uuid-12345",
  "score": 0.8234,
  "decision": {
    "trace_id": "uuid-12345",
    "is_threat": true,
    "confidence": 0.85,
    "action_suggested": "alert",
    "explanation": "Decision based on anomaly score=0.8234 for batch of 1 logs"
  },
  "batch_size": 1
}
```

### **3. Obtener Información del Dataset**
```bash
curl http://localhost:8000/dataset/info
```

**Respuesta:**
```json
{
  "total_rows": 10000,
  "labeled_rows": 1589,
  "unlabeled_rows": 8411,
  "columns": ["timestamp", "device_id", ...],
  "label_distribution": {
    "Normal": 1263,
    "Anomaly_DoS": 109,
    "Anomaly_Injection": 109,
    "Anomaly_Spoofing": 108
  },
  "device_type_distribution": {...},
  "anomaly_ratio": 0.205
}
```

## 📸 **IMÁGENES DE LA APLICACIÓN FUNCIONANDO**

### **🎯 Capturas de Pantalla de la Aplicación en Acción**

> **Nota**: Las siguientes imágenes muestran la aplicación procesando datos, respondiendo a solicitudes y generando resultados esperados.

#### **🖥️ Interfaz Principal**
![Interfaz Principal](docs/images/main-interface.png)
*Vista principal de la aplicación FastAPI con endpoints disponibles*

#### **📊 Análisis de Datos IoT**
![Análisis IoT](docs/images/iot-analysis.png)
*Procesamiento de logs IoT y detección de anomalías en tiempo real*

#### **📋 Logs y Debugging**
![Logs](docs/images/application-logs.png)
*Logs de la aplicación mostrando el procesamiento de requests*


## SEGURIDAD Y DEPENDENCIAS

### **Integración con Snyk**

Este repositorio está integrado con **Snyk** para la revisión continua de dependencias y detección de vulnerabilidades de seguridad.

#### **Estado de la Integración:**
- **Repositorio enlazado** a cuenta de Snyk
- **Escaneo automático** de dependencias en cada push/PR
- **Detección de vulnerabilidades** conocidas en librerías Python
- **Recomendaciones de actualización** para paquetes vulnerables
- **Reportes de seguridad** detallados con niveles de severidad

## LICENCIA

Este proyecto está bajo la licencia especificada en el archivo [LICENSE](LICENSE).
