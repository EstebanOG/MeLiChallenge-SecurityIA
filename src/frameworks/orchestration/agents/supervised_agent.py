"""
Agente Supervisado para detección de amenazas conocidas.

Este agente utiliza técnicas supervisadas para detectar ataques conocidos
usando el framework LangGraph.
"""

from typing import List, Dict, Any, Optional
from .base_agent import LangGraphAgentState, add_execution_step
from src.application.interfaces.threat_detector_interface import ThreatDetectorInterface


class SupervisedAgent:
    """Agente Supervisado - Detecta amenazas conocidas usando técnicas supervisadas."""
    
    def __init__(self, threat_detector: ThreatDetectorInterface):
        self.name = "supervised_agent"
        self.threat_detector = threat_detector
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente supervisado."""
        logs = state.get("logs", [])
        
        # Verificar si el modelo está entrenado
        if not self.threat_detector.is_ready():
            raise ValueError("El modelo ML no está entrenado. Entrena el modelo primero usando POST /train/supervised")
        
        # Analizar cada log individualmente
        individual_predictions = []
        individual_scores = []
        suspicious_logs = []
        
        for i, log in enumerate(logs):
            # Predecir cada log individualmente
            prediction = self.threat_detector.predict([log])
            
            individual_predictions.append(prediction)
            individual_scores.append(prediction['probability'])
            
            # Si el log es sospechoso, agregarlo a la lista
            if prediction['is_attack'] or prediction['probability'] > 0.3:
                suspicious_logs.append({
                    "index": i,
                    "session_id": log.get('session_id', f'log_{i}'),
                    "threat_score": prediction['probability'],
                    "is_attack": prediction['is_attack'],
                    "confidence": prediction['confidence'],
                    "log_data": log,
                    "threat_reasons": self._get_threat_reasons(log, prediction)
                })
        
        # Calcular predicción general del lote
        batch_probability = sum(individual_scores) / len(individual_scores) if individual_scores else 0.0
        is_attack = any(pred['is_attack'] for pred in individual_predictions) or batch_probability > 0.5
        confidence = max(pred['confidence'] for pred in individual_predictions) if individual_predictions else 0.0
        reasoning = f"Análisis de {len(logs)} logs: {len(suspicious_logs)} sospechosos detectados"
    
        if is_attack:
            threat_level = "high" if batch_probability > 0.8 else "medium"
            state = add_execution_step(state, self.name, {
                "decision": "attack_known",
                "confidence": confidence,
                "probability": batch_probability,
                "threat_level": threat_level,
                "reasoning": reasoning,
                "individual_scores": individual_scores,
                "suspicious_logs": suspicious_logs,
                "next_agent": "decision_agent"
            })
        else:
            state = add_execution_step(state, self.name, {
                "decision": "normal",
                "confidence": confidence,
                "probability": batch_probability,
                "threat_level": "low",
                "reasoning": reasoning,
                "individual_scores": individual_scores,
                "suspicious_logs": suspicious_logs,
                "next_agent": "unsupervised_agent"
            })
        
        return state
    
    def _get_threat_reasons(self, log: Dict[str, Any], prediction: Dict[str, Any]) -> List[str]:
        """Identifica las razones específicas por las que un log es considerado una amenaza."""
        reasons = []
        
        # Analizar características específicas del log
        if log.get('session_duration', 0) > 1500:
            reasons.append(f"Sesión anormalmente larga: {log['session_duration']}s")
        if log.get('network_packet_size', 0) > 700:
            reasons.append(f"Paquete de red muy grande: {log['network_packet_size']} bytes")
        if log.get('login_attempts', 0) > 5:
            reasons.append(f"Muchos intentos de login: {log['login_attempts']}")
        if log.get('failed_logins', 0) > 3:
            reasons.append(f"Muchos logins fallidos: {log['failed_logins']}")
        if log.get('ip_reputation_score', 1) < 0.3:
            reasons.append(f"IP con reputación muy baja: {log['ip_reputation_score']}")
        if log.get('unusual_time_access', 0) == 1:
            reasons.append("Acceso en horario inusual")
        if log.get('browser_type') == 'Unknown':
            reasons.append("Navegador desconocido")
        if log.get('encryption_used') == 'DES':
            reasons.append("Uso de encriptación DES (insegura)")
        if log.get('protocol_type') == 'UDP' and log.get('session_duration', 0) > 500:
            reasons.append("Protocolo UDP con sesión larga")
        
        # Agregar razón basada en la predicción del modelo
        probability = prediction.get('probability', 0.0)
        if prediction.get('is_attack', False):
            reasons.append(f"Modelo ML detectó ataque conocido (probabilidad: {probability:.3f})")
        elif probability > 0.7:
            reasons.append(f"Alta probabilidad de ataque: {probability:.3f}")
        elif probability > 0.5:
            reasons.append(f"Probabilidad moderada de ataque: {probability:.3f}")
        else:
            reasons.append(f"Probabilidad baja de ataque: {probability:.3f}")
        
        return reasons
    
