"""
Caso de uso para análisis de logs de threat intelligence.

Este caso de uso encapsula la lógica de negocio para analizar logs de sesiones de red
y detectar amenazas usando el pipeline de agentes LangGraph.
"""

import os
import sys
from typing import List, Dict, Any
from ...domain.entities.dto import ThreatAnalyzeRequestDTO, ThreatAnalyzeResponseDTO
from ...domain.entities.agent import AgentType
from ..interfaces.pipeline_orchestrator import PipelineOrchestrator

from ..interfaces.supervised_model_interface import SupervisedModelInterface


class AnalyzeThreatLogsUseCase:
    """Caso de uso para análisis de logs de threat intelligence."""
    
    def __init__(self, orchestrator: PipelineOrchestrator, supervised_model: SupervisedModelInterface = None):
        self.orchestrator = orchestrator
        self.supervised_model = supervised_model
        self.supervised_model_path = "models/supervised_model.joblib"
    
    def execute(self, request: ThreatAnalyzeRequestDTO) -> ThreatAnalyzeResponseDTO:
        """
        Ejecuta el análisis de logs de threat intelligence.
        
        Args:
            request: DTO con los logs a analizar
            
        Returns:
            DTO con el resultado del análisis
        """
        # Verificar si el modelo supervisado está entrenado
        if not self._is_supervised_model_trained():
            raise ValueError(
                "El modelo supervisado no está entrenado. "
                "Por favor, entrena el modelo primero usando POST /train/supervised"
            )
        
        # Convertir DTOs a formato interno
        raw_logs = [item.model_dump() for item in request.logs]
        
        # Ejecutar pipeline de agentes LangGraph
        execution_result = self.orchestrator.execute_pipeline(logs=raw_logs)
        
        # Extraer resultados de los agentes
        supervised_result = execution_result.get_agent_result(AgentType.INGESTION)
        unsupervised_result = execution_result.get_agent_result(AgentType.ANALYSIS)
        decision_result = execution_result.get_agent_result(AgentType.DECISION)
        report_result = execution_result.get_agent_result(AgentType.NOTIFICATION)
        
        # Construir respuesta basada en los resultados del agente de decisión
        # Usar los valores del agente de decisión para mantener consistencia
        threat_detected = decision_result.output.get("threat_detected", False) if decision_result else False
        anomaly_detected = decision_result.output.get("anomaly_detected", False) if decision_result else False
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
    
    def _is_supervised_model_trained(self) -> bool:
        """
        Verifica si el modelo supervisado está entrenado.
        
        Returns:
            True si el modelo está entrenado, False en caso contrario
        """
        try:
            if not os.path.exists(self.supervised_model_path):
                return False
            
            if self.supervised_model:
                return self.supervised_model.is_trained()
            else:
                return False
            
        except Exception:
            return False
    
