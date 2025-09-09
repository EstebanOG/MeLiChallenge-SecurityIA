"""
Caso de uso para análisis de logs de threat intelligence.

Este caso de uso encapsula la lógica de negocio para analizar logs de sesiones de red
y detectar amenazas usando el pipeline de agentes LangGraph.
"""

from typing import List, Dict, Any
from ...domain.entities.dto import ThreatAnalyzeRequestDTO, ThreatAnalyzeResponseDTO
from ...domain.entities.agent import AgentType
from ..interfaces.pipeline_orchestrator import PipelineOrchestrator


class AnalyzeThreatLogsUseCase:
    """Caso de uso para análisis de logs de threat intelligence."""
    
    def __init__(self, orchestrator: PipelineOrchestrator):
        self.orchestrator = orchestrator
    
    def execute(self, request: ThreatAnalyzeRequestDTO) -> ThreatAnalyzeResponseDTO:
        """
        Ejecuta el análisis de logs de threat intelligence.
        
        Args:
            request: DTO con los logs a analizar
            
        Returns:
            DTO con el resultado del análisis
        """
        # Convertir DTOs a formato interno
        raw_logs = [item.model_dump() for item in request.logs]
        
        # Ejecutar pipeline de agentes LangGraph
        execution_result = self.orchestrator.execute_pipeline(logs=raw_logs)
        
        # Extraer resultados de los agentes
        supervised_result = execution_result.get_agent_result(AgentType.INGESTION)
        unsupervised_result = execution_result.get_agent_result(AgentType.ANALYSIS)
        decision_result = execution_result.get_agent_result(AgentType.DECISION)
        report_result = execution_result.get_agent_result(AgentType.NOTIFICATION)
        
        # Construir respuesta basada en los resultados
        threat_detected = supervised_result.output.get("decision") == "attack_known" if supervised_result else False
        anomaly_detected = unsupervised_result.output.get("decision") == "anomalous" if unsupervised_result else False
        action_taken = decision_result.output.get("action", "monitor") if decision_result else "monitor"
        confidence = decision_result.output.get("confidence", 0.0) if decision_result else 0.0
        
        # Calcular score de amenaza
        threat_score = 0.0
        if threat_detected:
            threat_score = 0.8
        elif anomaly_detected:
            threat_score = 0.6
        else:
            threat_score = 0.2
        
        return ThreatAnalyzeResponseDTO(
            trace_id=execution_result.context.trace_id,
            score=threat_score,
            decision={
                "action": action_taken,
                "confidence": confidence,
                "threat_detected": threat_detected,
                "anomaly_detected": anomaly_detected,
                "reasoning": decision_result.output.get("reasoning", "Análisis completado") if decision_result else "Análisis completado"
            },
            batch_size=len(request.logs)
        )
    
