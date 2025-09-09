from typing import Any, Dict, List, Optional
from datetime import datetime
import uuid

from ...domain.entities.agent import AgentContext, AgentType
from ...domain.entities.pipeline import PipelineConfig, PipelineType, PipelineExecution, PipelineStatus
from ...domain.interfaces.pipeline_orchestrator import PipelineOrchestrator
from ...domain.interfaces.agent_executor import AgentRegistry


class ExecuteThreatDetectionPipeline:
    """Caso de uso para ejecutar el pipeline de detección de amenazas."""
    
    def __init__(
        self, 
        orchestrator: PipelineOrchestrator,
        agent_registry: AgentRegistry
    ):
        self.orchestrator = orchestrator
        self.agent_registry = agent_registry
    
    def execute(
        self, 
        logs: List[Dict[str, Any]], 
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ) -> PipelineExecution:
        """Ejecuta el pipeline de detección de amenazas."""
        
        # Crear contexto
        context = AgentContext(
            trace_id=trace_id or str(uuid.uuid4()),
            session_id=session_id or str(uuid.uuid4()),
            created_at=datetime.utcnow(),
            metadata=custom_config or {}
        )
        
        # Crear configuración del pipeline
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[
                AgentType.INGESTION,
                AgentType.ANALYSIS,
                AgentType.DECISION
            ],
            timeout_seconds=300,
            retry_attempts=3,
            parallel_execution=False,
            fail_fast=True,
            metadata={
                "description": "Pipeline estándar para detección de amenazas en logs IoT",
                "version": "1.0.0"
            }
        )
        
        # Validar configuración
        validation_errors = self.orchestrator.validate_pipeline_config(config)
        if validation_errors:
            raise ValueError(f"Configuración de pipeline inválida: {validation_errors}")
        
        # Ejecutar pipeline
        return self.orchestrator.execute_pipeline(config, logs, context)
    
    def execute_with_notification(
        self, 
        logs: List[Dict[str, Any]], 
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
        notification_channels: Optional[List[str]] = None
    ) -> PipelineExecution:
        """Ejecuta el pipeline de detección de amenazas con notificaciones."""
        
        # Crear configuración extendida
        config = PipelineConfig(
            pipeline_type=PipelineType.THREAT_DETECTION,
            agent_sequence=[
                AgentType.INGESTION,
                AgentType.ANALYSIS,
                AgentType.DECISION,
                AgentType.NOTIFICATION
            ],
            timeout_seconds=300,
            retry_attempts=3,
            parallel_execution=False,
            fail_fast=True,
            metadata={
                "description": "Pipeline de detección de amenazas con notificaciones",
                "version": "1.1.0",
                "notification_channels": notification_channels or ["email", "slack"]
            }
        )
        
        context = AgentContext(
            trace_id=trace_id or str(uuid.uuid4()),
            session_id=session_id or str(uuid.uuid4()),
            created_at=datetime.utcnow(),
            metadata={"notification_channels": notification_channels or []}
        )
        
        return self.orchestrator.execute_pipeline(config, logs, context)
    
    def execute_incident_response(
        self, 
        logs: List[Dict[str, Any]], 
        incident_id: str,
        trace_id: Optional[str] = None
    ) -> PipelineExecution:
        """Ejecuta el pipeline completo de respuesta a incidentes."""
        
        config = PipelineConfig(
            pipeline_type=PipelineType.INCIDENT_RESPONSE,
            agent_sequence=[
                AgentType.INGESTION,
                AgentType.ANALYSIS,
                AgentType.DECISION,
                AgentType.NOTIFICATION,
                AgentType.REMEDIATION
            ],
            timeout_seconds=600,  # Más tiempo para respuesta a incidentes
            retry_attempts=5,
            parallel_execution=False,
            fail_fast=False,  # No fallar rápido en incidentes
            metadata={
                "description": "Pipeline completo de respuesta a incidentes",
                "version": "1.0.0",
                "incident_id": incident_id
            }
        )
        
        context = AgentContext(
            trace_id=trace_id or str(uuid.uuid4()),
            session_id=incident_id,
            created_at=datetime.utcnow(),
            metadata={"incident_id": incident_id, "priority": "high"}
        )
        
        return self.orchestrator.execute_pipeline(config, logs, context)

