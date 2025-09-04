# Arquitectura de Orquestación de Agentes

## Resumen

Este documento describe la nueva arquitectura de orquestación de agentes implementada siguiendo los principios de Clean Architecture. La arquitectura permite crear, ejecutar y gestionar pipelines de agentes de manera modular y testeable.

## Estructura de Archivos

```
src/
├── domain/
│   ├── entities/
│   │   ├── agent.py              # Entidades de agentes y resultados
│   │   └── pipeline.py           # Entidades de pipelines y configuraciones
│   └── interfaces/
│       ├── agent_executor.py     # Interfaces para ejecución de agentes
│       └── pipeline_orchestrator.py  # Interfaces para orquestación
├── application/
│   └── use_cases/
│       └── execute_threat_detection_pipeline.py  # Casos de uso
├── infrastructure/
│   └── orchestration/
│       ├── factory.py                    # Factory para crear componentes
│       ├── langgraph_orchestrator.py     # Implementación con LangGraph
│       ├── agent_executors.py           # Implementaciones de agentes
│       ├── agent_registry.py            # Registro de agentes
│       └── pipeline_state_manager.py    # Manejo de estado
└── tests/
    └── orchestration/
        ├── test_langgraph_orchestrator.py
        └── test_pipeline_integration.py
```

## Componentes Principales

### 1. Domain Layer

#### Entidades (`domain/entities/`)

- **`agent.py`**: Define los tipos de agentes, contextos, resultados y outputs específicos
- **`pipeline.py`**: Define configuraciones de pipelines, estados y ejecuciones

#### Interfaces (`domain/interfaces/`)

- **`agent_executor.py`**: Contrato para ejecutores de agentes individuales
- **`pipeline_orchestrator.py`**: Contrato para orquestadores de pipelines

### 2. Application Layer

#### Casos de Uso (`application/use_cases/`)

- **`execute_threat_detection_pipeline.py`**: Caso de uso principal para detección de amenazas

### 3. Infrastructure Layer

#### Orquestación (`infrastructure/orchestration/`)

- **`factory.py`**: Factory pattern para crear componentes
- **`langgraph_orchestrator.py`**: Implementación del orquestador usando LangGraph
- **`agent_executors.py`**: Implementaciones concretas de cada agente
- **`agent_registry.py`**: Registro en memoria de agentes disponibles
- **`pipeline_state_manager.py`**: Manejo del estado de pipelines

## Tipos de Agentes

### 1. Ingestion Agent
- **Propósito**: Validar y sanitizar logs de entrada
- **Input**: Lista de logs raw
- **Output**: Logs validados y sanitizados

### 2. Analysis Agent
- **Propósito**: Ejecutar detección de anomalías
- **Input**: Logs sanitizados
- **Output**: Scores de anomalía y detección de amenazas

### 3. Decision Agent
- **Propósito**: Tomar decisiones basadas en análisis
- **Input**: Resultados de análisis
- **Output**: Decisiones y acciones recomendadas

### 4. Notification Agent
- **Propósito**: Enviar notificaciones
- **Input**: Decisiones tomadas
- **Output**: Confirmación de notificaciones enviadas

### 5. Remediation Agent
- **Propósito**: Ejecutar acciones de remediación
- **Input**: Decisiones y acciones recomendadas
- **Output**: Acciones ejecutadas y estado

## Uso de la Arquitectura

### Creación de un Pipeline Básico

```python
from src.infrastructure.orchestration.factory import OrchestrationFactory
from src.domain.entities.pipeline import PipelineConfig, PipelineType
from src.domain.entities.agent import AgentType

# Crear orquestador
orchestrator, agent_registry = OrchestrationFactory.create_threat_detection_pipeline()

# Crear configuración de pipeline
config = PipelineConfig(
    pipeline_type=PipelineType.THREAT_DETECTION,
    agent_sequence=[
        AgentType.INGESTION,
        AgentType.ANALYSIS,
        AgentType.DECISION
    ],
    timeout_seconds=300
)

# Ejecutar pipeline
result = orchestrator.execute_pipeline(config, logs)
```

### Uso con Casos de Uso

```python
from src.application.use_cases.execute_threat_detection_pipeline import ExecuteThreatDetectionPipeline

# Crear caso de uso
use_case = ExecuteThreatDetectionPipeline(orchestrator, agent_registry)

# Ejecutar pipeline
result = use_case.execute(logs, trace_id="custom-trace")
```

### Creación de Agentes Personalizados

```python
from src.domain.interfaces.agent_executor import AgentExecutor
from src.domain.entities.agent import AgentType, AgentStatus, AgentResult

class CustomAgentExecutor(AgentExecutor):
    def execute(self, agent_type, state, context):
        # Implementar lógica del agente
        return AgentResult(
            agent_type=agent_type,
            status=AgentStatus.COMPLETED,
            output={"custom": "result"},
            execution_time_ms=100.0
        )
    
    def can_handle(self, agent_type):
        return agent_type == AgentType.CUSTOM

# Registrar agente
agent_registry.register_agent(AgentType.CUSTOM, CustomAgentExecutor())
```

## Testing

### Testing de Agentes Individuales

```python
import pytest
from src.infrastructure.orchestration.agent_executors import IngestionAgentExecutor

def test_ingestion_agent():
    executor = IngestionAgentExecutor()
    state = {"logs": sample_logs}
    context = AgentContext(...)
    
    result = executor.execute(AgentType.INGESTION, state, context)
    
    assert result.status == AgentStatus.COMPLETED
    assert result.is_successful
```

### Testing de Pipelines Completos

```python
def test_pipeline_integration():
    orchestrator, registry = OrchestrationFactory.create_threat_detection_pipeline()
    config = PipelineConfig(...)
    
    result = orchestrator.execute_pipeline(config, sample_logs)
    
    assert result.status == PipelineStatus.COMPLETED
    assert len(result.agent_results) == 3
```

## Ventajas de la Arquitectura

### 1. **Separación de Responsabilidades**
- Cada capa tiene una responsabilidad específica
- Fácil de mantener y extender

### 2. **Testabilidad**
- Cada componente puede ser testeado independientemente
- Mocks y stubs fáciles de implementar

### 3. **Flexibilidad**
- Fácil agregar nuevos tipos de agentes
- Configuración flexible de pipelines

### 4. **Reutilización**
- Componentes reutilizables en diferentes contextos
- Factory pattern para creación consistente

### 5. **Mantenibilidad**
- Código organizado y documentado
- Interfaces claras entre componentes

## Migración desde la Arquitectura Anterior

### Antes (Código Monolítico)
```python
from src.orchestration.langgraph.graph import run_agents_pipeline

result = run_agents_pipeline(logs)
```

### Después (Clean Architecture)
```python
from src.application.use_cases.execute_threat_detection_pipeline import ExecuteThreatDetectionPipeline

use_case = ExecuteThreatDetectionPipeline(orchestrator, agent_registry)
result = use_case.execute(logs)
```

## Próximos Pasos

1. **Agregar más tipos de agentes** según necesidades específicas
2. **Implementar persistencia** para el estado de pipelines
3. **Agregar métricas y monitoreo** para pipelines
4. **Implementar pipelines paralelos** para mejor rendimiento
5. **Agregar validación de configuración** más robusta
