"""
Caso de uso para análisis de logs IoT.

Este caso de uso encapsula la lógica de negocio para analizar logs de dispositivos IoT
y detectar anomalías usando el pipeline de agentes.
"""

from typing import List, Dict, Any
from ...domain.entities.dto import IoTAnalyzeRequestDTO, IoTAnalyzeResponseDTO
from ...domain.entities.agent import AgentType
from ..interfaces.pipeline_orchestrator import PipelineOrchestrator
from ..interfaces.agent_executor import AgentRegistry


class AnalyzeIoTLogsUseCase:
    """Caso de uso para análisis de logs IoT."""
    
    def __init__(
        self, 
        orchestrator: PipelineOrchestrator,
        agent_registry: AgentRegistry
    ):
        self.orchestrator = orchestrator
        self.agent_registry = agent_registry
    
    def execute(self, request: IoTAnalyzeRequestDTO) -> IoTAnalyzeResponseDTO:
        """
        Ejecuta el análisis de logs IoT.
        
        Args:
            request: DTO con los logs a analizar
            
        Returns:
            DTO con el resultado del análisis
        """
        # Convertir DTOs a formato interno
        raw_logs = [item.model_dump() for item in request.logs]
        
        # Ejecutar pipeline de agentes
        execution_result = self.orchestrator.execute_pipeline(
            config=self._create_pipeline_config(),
            logs=raw_logs
        )
        
        # Extraer resultados de los agentes
        analysis_result = execution_result.get_agent_result(AgentType.ANALYSIS)
        decision_result = execution_result.get_agent_result(AgentType.DECISION)
        
        # Construir respuesta
        score = analysis_result.output.get("batch_score", 0.0) if analysis_result else 0.0
        decision = decision_result.output if decision_result else {}
        
        return IoTAnalyzeResponseDTO(
            trace_id=execution_result.context.trace_id,
            score=score,
            decision=decision,
            batch_size=len(request.logs)
        )
    
    def _create_pipeline_config(self):
        """Crea la configuración del pipeline para análisis."""
        from ...domain.entities.pipeline import PipelineConfig, PipelineType
        
        return PipelineConfig(
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
