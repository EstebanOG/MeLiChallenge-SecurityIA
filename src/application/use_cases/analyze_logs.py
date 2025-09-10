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
        threat_modeling = decision_result.output.get("threat_modeling", {}) if decision_result else {}
        
        # Calcular score de amenaza
        threat_score = 0.0
        if threat_detected:
            threat_score = 0.8
        elif anomaly_detected:
            threat_score = 0.6
        else:
            threat_score = 0.2
        
        # Obtener análisis detallado individual
        suspicious_logs = []
        individual_scores = []
        detailed_analysis = {}
        
        # Extraer scores individuales del agente de decisión (que los preserva de ambos agentes)
        if decision_result and 'individual_scores' in decision_result.output:
            individual_scores = decision_result.output['individual_scores']
        elif unsupervised_result and 'individual_scores' in unsupervised_result.output:
            individual_scores = unsupervised_result.output['individual_scores']
        elif supervised_result and 'individual_scores' in supervised_result.output:
            individual_scores = supervised_result.output['individual_scores']
        
        # Extraer logs sospechosos del agente de decisión (que los combina de ambos agentes)
        if decision_result and 'suspicious_logs' in decision_result.output:
            suspicious_logs = decision_result.output['suspicious_logs']
        else:
            # Fallback: generar logs sospechosos basados en scores individuales
            if individual_scores:
                threshold = 0.5  # Umbral para considerar un log como sospechoso
                for i, (log, score) in enumerate(zip(request.logs, individual_scores)):
                    if score > threshold:
                        suspicious_logs.append({
                            "index": i,
                            "session_id": log.session_id,
                            "anomaly_score": score,
                            "log_data": log.model_dump(),
                            "suspicion_reasons": self._get_suspicion_reasons(log, score)
                        })
        
        # Generar análisis detallado
        if suspicious_logs:
            detailed_analysis = {
                "total_suspicious": len(suspicious_logs),
                "suspicious_ratio": len(suspicious_logs) / len(request.logs),
                "highest_anomaly_score": max(individual_scores) if individual_scores else 0.0,
                "average_anomaly_score": sum(individual_scores) / len(individual_scores) if individual_scores else 0.0,
                "threat_patterns": self._identify_threat_patterns(suspicious_logs)
            }
        
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
            batch_size=len(request.logs),
            threat_modeling=threat_modeling,
            suspicious_logs=suspicious_logs,
            individual_scores=individual_scores,
            detailed_analysis=detailed_analysis
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
    
    def _get_suspicion_reasons(self, log, score: float) -> List[str]:
        """Identifica las razones específicas por las que un log es sospechoso."""
        reasons = []
        
        # Analizar características específicas del log
        if log.session_duration > 1500:
            reasons.append(f"Sesión anormalmente larga: {log.session_duration}s")
        if log.network_packet_size > 700:
            reasons.append(f"Paquete de red muy grande: {log.network_packet_size} bytes")
        if log.login_attempts > 5:
            reasons.append(f"Muchos intentos de login: {log.login_attempts}")
        if log.failed_logins > 3:
            reasons.append(f"Muchos logins fallidos: {log.failed_logins}")
        if log.ip_reputation_score < 0.3:
            reasons.append(f"IP con reputación muy baja: {log.ip_reputation_score}")
        if log.unusual_time_access == 1:
            reasons.append("Acceso en horario inusual")
        if log.browser_type == 'Unknown':
            reasons.append("Navegador desconocido")
        if log.encryption_used == 'DES':
            reasons.append("Uso de encriptación DES (insegura)")
        if log.protocol_type == 'UDP' and log.session_duration > 500:
            reasons.append("Protocolo UDP con sesión larga")
        
        # Agregar razón basada en el score de anomalía
        if score > 0.8:
            reasons.append(f"Score de anomalía muy alto: {score:.3f}")
        elif score > 0.6:
            reasons.append(f"Score de anomalía alto: {score:.3f}")
        else:
            reasons.append(f"Score de anomalía moderado: {score:.3f}")
        
        return reasons
    
    def _identify_threat_patterns(self, suspicious_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Identifica patrones de amenaza en los logs sospechosos."""
        if not suspicious_logs:
            return {}
        
        patterns = {
            "brute_force_attempts": 0,
            "suspicious_ips": set(),
            "unusual_browsers": set(),
            "high_failure_rates": 0,
            "long_sessions": 0,
            "low_reputation_ips": 0
        }
        
        for log_info in suspicious_logs:
            log_data = log_info["log_data"]
            
            # Patrones de fuerza bruta
            if log_data.get("failed_logins", 0) > 3 or log_data.get("login_attempts", 0) > 5:
                patterns["brute_force_attempts"] += 1
            
            # IPs sospechosas
            if log_data.get("ip_reputation_score", 1) < 0.4:
                patterns["suspicious_ips"].add(log_data.get("session_id", "unknown"))
                if log_data.get("ip_reputation_score", 1) < 0.2:
                    patterns["low_reputation_ips"] += 1
            
            # Navegadores inusuales
            if log_data.get("browser_type") == "Unknown":
                patterns["unusual_browsers"].add(log_data.get("browser_type"))
            
            # Altas tasas de fallo
            if log_data.get("failed_logins", 0) > 2:
                patterns["high_failure_rates"] += 1
            
            # Sesiones largas
            if log_data.get("session_duration", 0) > 1000:
                patterns["long_sessions"] += 1
        
        # Convertir sets a listas para serialización JSON
        patterns["suspicious_ips"] = list(patterns["suspicious_ips"])
        patterns["unusual_browsers"] = list(patterns["unusual_browsers"])
        
        return patterns
    
